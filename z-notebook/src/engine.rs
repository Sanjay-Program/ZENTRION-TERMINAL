//! Notebook execution, audit records and exports.

use crate::model::{CellKind, Notebook, NotebookError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use uuid::Uuid;
use z_workflow::expr::{StepVars, Vars};
use z_workflow::{AuditRecord, ParamSpec};

const MAX_CELL_OUTPUT: usize = 4 * 1024 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcOutput {
    pub stdout: String,
    pub stderr: String,
    pub status: Option<i32>,
    pub timed_out: bool,
}

impl ProcOutput {
    pub fn success(&self) -> bool {
        self.status == Some(0) && !self.timed_out
    }
}

pub trait ShellExecutor: Send + Sync {
    fn run(&self, source: &str, cwd: &Path, timeout: Duration) -> Result<ProcOutput, String>;
}

pub trait AiExecutor: Send + Sync {
    fn ask(&self, prompt: &str, model: Option<&str>) -> Result<String, String>;
}

pub struct NoAi;

impl AiExecutor for NoAi {
    fn ask(&self, _prompt: &str, _model: Option<&str>) -> Result<String, String> {
        Err("AI cells are unavailable (no model router configured)".into())
    }
}

pub struct SystemShell {
    pub shell: String,
}

impl Default for SystemShell {
    fn default() -> Self {
        Self {
            shell: std::env::var("SHELL").unwrap_or_else(|_| {
                if cfg!(windows) {
                    "cmd.exe".into()
                } else {
                    "/bin/sh".into()
                }
            }),
        }
    }
}

impl ShellExecutor for SystemShell {
    fn run(&self, source: &str, cwd: &Path, timeout: Duration) -> Result<ProcOutput, String> {
        let mut command = std::process::Command::new(&self.shell);
        let name = Path::new(&self.shell)
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or(&self.shell)
            .to_ascii_lowercase();
        if name == "cmd" {
            command.arg("/C").arg(source);
        } else {
            command.arg("-c").arg(source);
        }
        command
            .current_dir(cwd)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("cannot start shell: {e}"))?;
        let stdout = child
            .stdout
            .take()
            .map(|reader| read_capped(reader, MAX_CELL_OUTPUT));
        let stderr = child
            .stderr
            .take()
            .map(|reader| read_capped(reader, MAX_CELL_OUTPUT));
        let deadline = Instant::now() + timeout;
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        timed_out = true;
                        #[cfg(unix)]
                        unsafe {
                            let pid = child.id() as i32;
                            libc::kill(-pid, libc::SIGKILL);
                        }
                        let _ = child.kill();
                        let _ = child.wait();
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => return Err(format!("cannot wait for shell: {error}")),
            }
        };
        let stdout = stdout
            .and_then(|handle| handle.join().ok())
            .unwrap_or_default();
        let stderr = stderr
            .and_then(|handle| handle.join().ok())
            .unwrap_or_default();
        Ok(ProcOutput {
            stdout: String::from_utf8_lossy(&stdout).to_string(),
            stderr: String::from_utf8_lossy(&stderr).to_string(),
            status: status.and_then(|status| status.code()),
            timed_out,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    pub params: BTreeMap<String, String>,
    pub workdir: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellStatus {
    Succeeded,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellResult {
    pub id: String,
    pub kind: String,
    pub status: CellStatus,
    pub output: String,
    pub stderr: String,
    pub error: Option<String>,
    pub duration_ms: u64,
    pub skipped_reason: Option<String>,
    pub redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunReport {
    pub run_id: String,
    pub notebook: String,
    pub status: RunStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub params: Vec<String>,
    pub cells: Vec<CellResult>,
    pub error: Option<String>,
    pub workdir: String,
    pub audit: Vec<AuditRecord>,
}

impl RunReport {
    pub fn succeeded(&self) -> bool {
        self.status == RunStatus::Succeeded
    }
}

/// Execute a notebook. Shell cells use `shell`; AI cells use `ai` (pass
/// [`NoAi`] to fail those cells explicitly).
pub fn run(
    notebook: &Notebook,
    notebook_path: &Path,
    options: RunOptions,
    shell: &dyn ShellExecutor,
    ai: &dyn AiExecutor,
) -> Result<RunReport, NotebookError> {
    let issues = notebook.validate();
    if !issues.is_empty() {
        return Err(NotebookError(issues));
    }
    let workdir = options
        .workdir
        .clone()
        .unwrap_or_else(|| notebook.resolved_working_dir(notebook_path));
    let workdir = workdir.canonicalize().map_err(|e| {
        NotebookError(vec![format!(
            "cannot resolve workdir {}: {e}",
            workdir.display()
        )])
    })?;
    let params = resolve_params(notebook, &options.params)?;
    let mut vars = Vars::default();
    for (name, value) in &params {
        vars.params.insert(name.clone(), value.clone());
    }
    let started_at = Utc::now();
    let mut report = RunReport {
        run_id: format!("nb_{}", Uuid::new_v4().simple()),
        notebook: notebook.name.clone(),
        status: RunStatus::Succeeded,
        started_at,
        finished_at: started_at,
        params: notebook.params.keys().cloned().collect(),
        cells: Vec::new(),
        error: None,
        workdir: workdir.display().to_string(),
        audit: Vec::new(),
    };
    let mut failed = false;
    for cell in &notebook.cells {
        if failed {
            report.cells.push(CellResult {
                id: cell.id.clone(),
                kind: kind_name(cell.kind).into(),
                status: CellStatus::Skipped,
                output: String::new(),
                stderr: String::new(),
                error: None,
                duration_ms: 0,
                skipped_reason: Some("a previous cell failed".into()),
                redacted: false,
            });
            continue;
        }
        let started = Instant::now();
        let mut secrets = Vec::new();
        let source = match z_workflow::render(&cell.source, &vars, &mut secrets) {
            Ok(source) => source,
            Err(error) => {
                let result = CellResult {
                    id: cell.id.clone(),
                    kind: kind_name(cell.kind).into(),
                    status: CellStatus::Failed,
                    output: String::new(),
                    stderr: String::new(),
                    error: Some(format!("template error: {error}")),
                    duration_ms: started.elapsed().as_millis() as u64,
                    skipped_reason: None,
                    redacted: false,
                };
                report.cells.push(result);
                failed = true;
                continue;
            }
        };
        let mut result = CellResult {
            id: cell.id.clone(),
            kind: kind_name(cell.kind).into(),
            status: CellStatus::Succeeded,
            output: String::new(),
            stderr: String::new(),
            error: None,
            duration_ms: 0,
            skipped_reason: None,
            redacted: false,
        };
        match cell.kind {
            CellKind::Markdown => {
                result.output = source;
                report.audit.push(audit(
                    "notebook.cell.markdown",
                    &cell.id,
                    "allow",
                    "ok",
                    "low",
                ));
            }
            CellKind::Shell => {
                let cwd = match cell_cwd(cell.cwd.as_deref(), &workdir) {
                    Ok(cwd) => cwd,
                    Err(error) => {
                        result.status = CellStatus::Failed;
                        result.error = Some(error);
                        finish_cell(&mut result, &mut report, &mut vars, started, &secrets);
                        failed = !cell.continue_on_error;
                        continue;
                    }
                };
                let timeout = cell
                    .timeout
                    .as_deref()
                    .and_then(z_workflow::parse_duration)
                    .unwrap_or(DEFAULT_TIMEOUT);
                match shell.run(&source, &cwd, timeout) {
                    Ok(output) => {
                        let (output_text, output_redacted) =
                            scrub_with_flag(&output.stdout, &secrets);
                        let (error_text, error_redacted) =
                            scrub_with_flag(&output.stderr, &secrets);
                        result.output = output_text;
                        result.stderr = error_text;
                        result.redacted = output_redacted || error_redacted;
                        if output.timed_out {
                            result.status = CellStatus::Failed;
                            result.error = Some("cell timed out and was killed".into());
                        } else if output.status != Some(0) {
                            result.status = CellStatus::Failed;
                            result.error = Some(format!("exited with {:?}", output.status));
                        }
                        report.audit.push(audit(
                            "notebook.cell.shell",
                            &cell.id,
                            "allow",
                            if output.success() { "ok" } else { "failed" },
                            "medium",
                        ));
                    }
                    Err(error) => {
                        result.status = CellStatus::Failed;
                        result.error = Some(error);
                        report.audit.push(audit(
                            "notebook.cell.shell",
                            &cell.id,
                            "deny",
                            "failed",
                            "medium",
                        ));
                    }
                }
            }
            CellKind::Ai => match ai.ask(&source, cell.model.as_deref()) {
                Ok(text) => {
                    let (output, redacted) = scrub_with_flag(&text, &secrets);
                    result.output = output;
                    result.redacted = redacted;
                    report
                        .audit
                        .push(audit("notebook.cell.ai", &cell.id, "allow", "ok", "medium"));
                }
                Err(error) => {
                    result.status = CellStatus::Failed;
                    result.error = Some(scrub(&error, &secrets));
                    report.audit.push(audit(
                        "notebook.cell.ai",
                        &cell.id,
                        "deny",
                        "failed",
                        "medium",
                    ));
                }
            },
        }
        let status = result.status;
        finish_cell(&mut result, &mut report, &mut vars, started, &secrets);
        if status == CellStatus::Failed && !cell.continue_on_error {
            failed = true;
        }
    }
    report.finished_at = Utc::now();
    report.status = if failed {
        RunStatus::Failed
    } else {
        RunStatus::Succeeded
    };
    if failed {
        report.error = Some("notebook stopped at the first failing cell".into());
    }
    Ok(report)
}

fn finish_cell(
    result: &mut CellResult,
    report: &mut RunReport,
    vars: &mut Vars,
    started: Instant,
    secrets: &[String],
) {
    result.duration_ms = started.elapsed().as_millis() as u64;
    result.output = scrub(&result.output, secrets);
    result.stderr = scrub(&result.stderr, secrets);
    if let Some(error) = &result.error {
        result.error = Some(scrub(error, secrets));
    }
    vars.steps.insert(
        result.id.clone(),
        StepVars {
            status: match result.status {
                CellStatus::Succeeded => "succeeded".into(),
                CellStatus::Failed => "failed".into(),
                CellStatus::Skipped => "skipped".into(),
            },
            exit_code: None,
            stdout: result.output.clone(),
            stderr: result.stderr.clone(),
            approved: false,
            error: result.error.clone(),
        },
    );
    report.cells.push(result.clone());
}

fn cell_cwd(cwd: Option<&str>, workdir: &Path) -> Result<PathBuf, String> {
    let Some(cwd) = cwd else {
        return Ok(workdir.to_path_buf());
    };
    let relative = crate::model::safe_relative(cwd)?;
    let path = workdir.join(relative);
    let canonical = path
        .canonicalize()
        .map_err(|e| format!("cannot resolve cwd {}: {e}", path.display()))?;
    if !canonical.starts_with(workdir) {
        return Err("cell cwd escapes the notebook workspace".into());
    }
    if !canonical.is_dir() {
        return Err("cell cwd is not a directory".into());
    }
    Ok(canonical)
}

fn resolve_params(
    notebook: &Notebook,
    provided: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, NotebookError> {
    let mut resolved = BTreeMap::new();
    let mut issues = Vec::new();
    for (name, spec) in &notebook.params {
        let value = if spec.secret {
            match z_identity::vault::get_secret(name) {
                Ok(Some(value)) => value,
                Ok(None) => {
                    issues.push(format!("secret parameter `{name}` is not in the vault"));
                    continue;
                }
                Err(error) => {
                    issues.push(format!("cannot read secret `{name}`: {error}"));
                    continue;
                }
            }
        } else if let Some(value) = provided.get(name) {
            value.clone()
        } else if let Some(default) = &spec.default {
            yaml_scalar(default)
        } else if spec.required {
            issues.push(format!("missing required parameter `{name}`"));
            continue;
        } else {
            String::new()
        };
        if let Err(error) = validate_param(name, spec, &value) {
            issues.push(error);
            continue;
        }
        resolved.insert(name.clone(), value);
    }
    for key in provided.keys() {
        if !notebook.params.contains_key(key) {
            issues.push(format!("unknown parameter `{key}`"));
        }
    }
    if issues.is_empty() {
        Ok(resolved)
    } else {
        Err(NotebookError(issues))
    }
}

fn validate_param(name: &str, spec: &ParamSpec, value: &str) -> Result<(), String> {
    match spec.kind.as_str() {
        "number" => {
            if value.parse::<f64>().is_err() {
                return Err(format!("parameter `{name}` must be a number"));
            }
        }
        "bool" | "boolean" => {
            if !matches!(value.to_ascii_lowercase().as_str(), "true" | "false") {
                return Err(format!("parameter `{name}` must be true or false"));
            }
        }
        "enum" => {
            if !spec.allowed.contains(&value.to_string()) {
                return Err(format!(
                    "parameter `{name}` must be one of: {}",
                    spec.allowed.join(", ")
                ));
            }
        }
        _ => {}
    }
    if !spec.allowed.is_empty() && !spec.allowed.contains(&value.to_string()) {
        return Err(format!(
            "parameter `{name}` must be one of: {}",
            spec.allowed.join(", ")
        ));
    }
    Ok(())
}

fn yaml_scalar(value: &serde_yaml::Value) -> String {
    match value {
        serde_yaml::Value::String(text) => text.clone(),
        serde_yaml::Value::Number(number) => number.to_string(),
        serde_yaml::Value::Bool(flag) => flag.to_string(),
        serde_yaml::Value::Null => String::new(),
        other => serde_yaml::to_string(other)
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}

fn kind_name(kind: CellKind) -> &'static str {
    match kind {
        CellKind::Markdown => "markdown",
        CellKind::Shell => "shell",
        CellKind::Ai => "ai",
    }
}

fn audit(action: &str, id: &str, decision: &str, result: &str, risk: &str) -> AuditRecord {
    AuditRecord {
        ts: Utc::now(),
        action: action.to_string(),
        resource: format!("notebook:{id}"),
        decision: decision.to_string(),
        result: result.to_string(),
        risk: risk.to_string(),
        metadata: serde_json::json!({"cell": id}),
    }
}

fn scrub(text: &str, secrets: &[String]) -> String {
    let mut out = text.to_string();
    for secret in secrets {
        if secret.len() >= 4 {
            out = out.replace(secret, "[REDACTED:secret]");
        }
    }
    let (redacted, found) = z_blocks::redact(&out);
    if found.is_empty() {
        out
    } else {
        redacted
    }
}

fn scrub_with_flag(text: &str, secrets: &[String]) -> (String, bool) {
    let mut redacted = secrets
        .iter()
        .any(|secret| secret.len() >= 4 && text.contains(secret));
    let mut out = text.to_string();
    for secret in secrets {
        if secret.len() >= 4 {
            out = out.replace(secret, "[REDACTED:secret]");
        }
    }
    let (scrubbed, found) = z_blocks::redact(&out);
    redacted |= !found.is_empty();
    (scrubbed, redacted)
}

fn read_capped(
    mut reader: impl Read + Send + 'static,
    max: usize,
) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if buffer.len() < max {
                        let take = (max - buffer.len()).min(n);
                        buffer.extend_from_slice(&chunk[..take]);
                    }
                }
                Err(_) => break,
            }
        }
        buffer
    })
}

pub fn save_run(report: &RunReport, dir: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{}.json", report.run_id));
    let text = serde_json::to_string_pretty(report).map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

pub fn export_markdown(notebook: &Notebook, report: &RunReport) -> String {
    let mut out = format!("# {}\n\n", notebook.name);
    if let Some(description) = &notebook.description {
        out.push_str(description);
        out.push_str("\n\n");
    }
    out.push_str(&format!(
        "Run `{}` · {:?} · {}\n\n",
        report.run_id, report.status, report.workdir
    ));
    for cell in &report.cells {
        out.push_str(&format!("## {} ({})\n\n", cell.id, cell.kind));
        if cell.kind == "markdown" {
            out.push_str(&cell.output);
            out.push_str("\n\n");
            continue;
        }
        if let Some(source) = notebook.cells.iter().find(|item| item.id == cell.id) {
            out.push_str("```");
            out.push_str(if cell.kind == "shell" { "sh" } else { "text" });
            out.push('\n');
            out.push_str(&source.source);
            out.push_str("\n```\n\n");
        }
        out.push_str(&format!(
            "**Status:** {:?}{}\n\n",
            cell.status,
            cell.error
                .as_deref()
                .map(|error| format!(" — {error}"))
                .unwrap_or_default()
        ));
        if !cell.output.is_empty() {
            out.push_str("```text\n");
            out.push_str(&cell.output);
            if !cell.output.ends_with('\n') {
                out.push('\n');
            }
            out.push_str("```\n\n");
        }
    }
    out
}

pub fn export_html(notebook: &Notebook, report: &RunReport) -> String {
    let mut out = String::from(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Notebook</title>\
         <style>body{font-family:ui-sans-serif,system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}pre{background:#f6f8fa;padding:1rem;overflow:auto}code{background:#f6f8fa}</style></head><body>",
    );
    out.push_str(&format!("<h1>{}</h1>", escape_html(&notebook.name)));
    if let Some(description) = &notebook.description {
        out.push_str(&format!("<p>{}</p>", escape_html(description)));
    }
    for cell in &report.cells {
        out.push_str(&format!(
            "<h2>{} <small>({})</small></h2>",
            escape_html(&cell.id),
            escape_html(&cell.kind)
        ));
        if let Some(source) = notebook.cells.iter().find(|item| item.id == cell.id) {
            if cell.kind == "markdown" {
                out.push_str(&format!("<p>{}</p>", escape_html(&cell.output)));
            } else {
                out.push_str(&format!(
                    "<pre><code>{}</code></pre>",
                    escape_html(&source.source)
                ));
            }
        }
        out.push_str(&format!(
            "<p><strong>Status:</strong> {:?}{}</p>",
            cell.status,
            cell.error
                .as_deref()
                .map(|error| format!(" — {}", escape_html(error)))
                .unwrap_or_default()
        ));
        if !cell.output.is_empty() && cell.kind != "markdown" {
            out.push_str(&format!("<pre>{}</pre>", escape_html(&cell.output)));
        }
    }
    out.push_str("</body></html>");
    out
}

fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Cell, Notebook};
    use std::sync::Mutex;

    struct MockShell {
        calls: Mutex<Vec<String>>,
    }

    impl ShellExecutor for MockShell {
        fn run(&self, source: &str, _cwd: &Path, _timeout: Duration) -> Result<ProcOutput, String> {
            self.calls.lock().unwrap().push(source.to_string());
            Ok(ProcOutput {
                stdout: format!("ran: {source}\n"),
                stderr: String::new(),
                status: Some(0),
                timed_out: false,
            })
        }
    }

    struct MockAi;

    impl AiExecutor for MockAi {
        fn ask(&self, prompt: &str, _model: Option<&str>) -> Result<String, String> {
            Ok(format!("ai answer for {prompt}"))
        }
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "znotebook-{}-{}-{}",
            name,
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn notebook() -> Notebook {
        let mut notebook = Notebook::new("test");
        notebook.params.insert(
            "who".into(),
            ParamSpec {
                kind: "string".into(),
                required: false,
                default: Some(serde_yaml::Value::String("world".into())),
                description: None,
                allowed: Vec::new(),
                secret: false,
            },
        );
        notebook.cells = vec![
            Cell {
                id: "md".into(),
                kind: CellKind::Markdown,
                source: "# Hello ${who}".into(),
                cwd: None,
                timeout: None,
                continue_on_error: false,
                model: None,
                tags: Vec::new(),
            },
            Cell {
                id: "sh".into(),
                kind: CellKind::Shell,
                source: "echo hi ${who}".into(),
                cwd: None,
                timeout: Some("10s".into()),
                continue_on_error: false,
                model: None,
                tags: Vec::new(),
            },
            Cell {
                id: "ai".into(),
                kind: CellKind::Ai,
                source: "explain ${who}".into(),
                cwd: None,
                timeout: None,
                continue_on_error: false,
                model: Some("mock".into()),
                tags: Vec::new(),
            },
        ];
        notebook
    }

    #[test]
    fn runs_cells_with_params_and_records_audit() {
        let dir = temp("run");
        let path = dir.join("nb.yaml");
        let notebook = notebook();
        let shell = MockShell {
            calls: Mutex::new(Vec::new()),
        };
        let report = run(&notebook, &path, RunOptions::default(), &shell, &MockAi).unwrap();
        assert_eq!(report.status, RunStatus::Succeeded);
        assert_eq!(report.cells.len(), 3);
        assert!(report.cells[0].output.contains("Hello world"));
        assert!(report.cells[1].output.contains("ran: echo hi world"));
        assert!(report.cells[2]
            .output
            .contains("ai answer for explain world"));
        assert!(!report.audit.is_empty());
        assert_eq!(shell.calls.lock().unwrap().len(), 1);
        let exported = export_markdown(&notebook, &report);
        assert!(exported.contains("# test"));
        assert!(exported.contains("ran: echo hi world"));
        let html = export_html(&notebook, &report);
        assert!(html.starts_with("<!doctype html>"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failing_cell_stops_unless_continue_on_error() {
        struct Failing;
        impl ShellExecutor for Failing {
            fn run(
                &self,
                _source: &str,
                _cwd: &Path,
                _timeout: Duration,
            ) -> Result<ProcOutput, String> {
                Ok(ProcOutput {
                    stdout: String::new(),
                    stderr: "boom".into(),
                    status: Some(2),
                    timed_out: false,
                })
            }
        }
        let dir = temp("fail");
        let mut notebook = notebook();
        notebook.cells[1].continue_on_error = false;
        let report = run(
            &notebook,
            &dir.join("nb.yaml"),
            RunOptions::default(),
            &Failing,
            &MockAi,
        )
        .unwrap();
        assert_eq!(report.status, RunStatus::Failed);
        assert_eq!(report.cells[1].status, CellStatus::Failed);
        assert_eq!(report.cells[2].status, CellStatus::Skipped);
        notebook.cells[1].continue_on_error = true;
        let report = run(
            &notebook,
            &dir.join("nb.yaml"),
            RunOptions::default(),
            &Failing,
            &MockAi,
        )
        .unwrap();
        assert_eq!(report.cells[2].status, CellStatus::Succeeded);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ai_output_is_redacted() {
        struct LeakyAi;
        impl AiExecutor for LeakyAi {
            fn ask(&self, _prompt: &str, _model: Option<&str>) -> Result<String, String> {
                Ok("key AKIAABCDEFGHIJKLMNOP leaked".into())
            }
        }
        let dir = temp("redact");
        let notebook = notebook();
        let report = run(
            &notebook,
            &dir.join("nb.yaml"),
            RunOptions::default(),
            &MockShell {
                calls: Mutex::new(Vec::new()),
            },
            &LeakyAi,
        )
        .unwrap();
        assert!(!report.cells[2].output.contains("AKIAABCDEFGHIJKLMNOP"));
        assert!(report.cells[2].redacted);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_required_parameter_is_an_error() {
        let dir = temp("params");
        let mut notebook = notebook();
        notebook.params.insert(
            "version".into(),
            ParamSpec {
                kind: "string".into(),
                required: true,
                default: None,
                description: None,
                allowed: Vec::new(),
                secret: false,
            },
        );
        let error = run(
            &notebook,
            &dir.join("nb.yaml"),
            RunOptions::default(),
            &MockShell {
                calls: Mutex::new(Vec::new()),
            },
            &MockAi,
        )
        .unwrap_err();
        assert!(error.to_string().contains("version"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

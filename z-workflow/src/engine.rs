//! Workflow execution.
//!
//! Every step is explicit: shell commands run through a chosen shell, approval
//! steps consult an [`Approver`], HTTP steps require an allowlist and are
//! resolved before connecting, artifacts are hashed, and every outcome produces
//! an audit record. Secrets are resolved from the encrypted vault, never stored
//! in the report and never written to the audit log.

use crate::expr::{self, StepVars, Vars};
use crate::schema::{
    parse_duration, parse_http_url, ArtifactStep, HttpStep, ParamSpec, Step, Workflow,
    WorkflowError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{IsTerminal, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const DEFAULT_MAX_OUTPUT: usize = 8 * 1024 * 1024;
pub const MAX_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowPolicy {
    pub allow_http: bool,
    pub http_allowlist: Vec<String>,
    pub default_timeout: Duration,
    pub max_output_bytes: usize,
    /// Refuse `cwd` outside the workflow working directory.
    pub restrict_to_workspace: bool,
}

impl Default for WorkflowPolicy {
    fn default() -> Self {
        Self {
            allow_http: false,
            http_allowlist: Vec::new(),
            default_timeout: Duration::from_secs(3_600),
            max_output_bytes: DEFAULT_MAX_OUTPUT,
            restrict_to_workspace: true,
        }
    }
}

/// Asks the user (or a policy) whether a step may run.
pub trait Approver: Send {
    fn approve(&mut self, step_id: &str, message: &str) -> bool;
}

pub struct DenyAll;

impl Approver for DenyAll {
    fn approve(&mut self, _step_id: &str, _message: &str) -> bool {
        false
    }
}

pub struct AllowAll;

impl Approver for AllowAll {
    fn approve(&mut self, _step_id: &str, _message: &str) -> bool {
        true
    }
}

/// Interactive terminal approval. Non-TTY callers should not use this.
pub struct PromptApprover;

impl Approver for PromptApprover {
    fn approve(&mut self, step_id: &str, message: &str) -> bool {
        if !std::io::stdin().is_terminal() {
            eprintln!("z workflow: no terminal for approval of `{step_id}`; denied");
            return false;
        }
        eprint!("Approve step `{step_id}`: {message} [y/N] ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return false;
        }
        matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    }
}

#[derive(Clone)]
pub struct RunOptions {
    pub params: BTreeMap<String, String>,
    pub policy: WorkflowPolicy,
    pub workdir: PathBuf,
    pub env: BTreeMap<String, String>,
    pub approver: Arc<Mutex<dyn Approver>>,
    pub run_id: String,
}

impl RunOptions {
    pub fn new(workdir: impl Into<PathBuf>) -> Self {
        Self {
            params: BTreeMap::new(),
            policy: WorkflowPolicy::default(),
            workdir: workdir.into(),
            env: BTreeMap::new(),
            approver: Arc::new(Mutex::new(DenyAll)),
            run_id: format!("run_{}", Uuid::new_v4().simple()),
        }
    }

    pub fn allow_all(mut self) -> Self {
        self.approver = Arc::new(Mutex::new(AllowAll));
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Succeeded,
    Failed,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Succeeded,
    Failed,
    Skipped,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub ts: DateTime<Utc>,
    pub action: String,
    pub resource: String,
    pub decision: String,
    pub result: String,
    pub risk: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub name: String,
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepResult {
    pub id: String,
    pub kind: String,
    pub status: StepStatus,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
    pub attempts: u32,
    pub duration_ms: u64,
    pub approved: bool,
    /// Template, never the resolved command (may contain secrets).
    pub input: Option<String>,
    pub artifacts: Vec<Artifact>,
    pub skipped_reason: Option<String>,
    pub redacted: bool,
    pub children: Vec<StepResult>,
}

impl StepResult {
    fn base(id: &str, kind: &str) -> Self {
        Self {
            id: id.to_string(),
            kind: kind.to_string(),
            status: StepStatus::Succeeded,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            error: None,
            attempts: 0,
            duration_ms: 0,
            approved: false,
            input: None,
            artifacts: Vec::new(),
            skipped_reason: None,
            redacted: false,
            children: Vec::new(),
        }
    }

    pub fn succeeded(&self) -> bool {
        self.status == StepStatus::Succeeded
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunReport {
    pub run_id: String,
    pub workflow: String,
    pub status: RunStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub steps: Vec<StepResult>,
    pub params: Vec<String>,
    pub error: Option<String>,
    pub audit: Vec<AuditRecord>,
    pub workdir: String,
}

impl RunReport {
    pub fn succeeded(&self) -> bool {
        self.status == RunStatus::Succeeded
    }
}

/// Run a validated workflow.
pub fn run(workflow: &Workflow, options: RunOptions) -> RunReport {
    let started_at = Utc::now();
    let mut audit = Vec::new();
    let mut report = RunReport {
        run_id: options.run_id.clone(),
        workflow: workflow.name.clone(),
        status: RunStatus::Failed,
        started_at,
        finished_at: started_at,
        steps: Vec::new(),
        params: options.params.keys().cloned().collect(),
        error: None,
        audit: Vec::new(),
        workdir: options.workdir.display().to_string(),
    };
    let issues = workflow.validate();
    if !issues.is_empty() {
        report.error = Some(format!("invalid workflow: {}", issues.join("; ")));
        return report;
    }
    let workdir = match options.workdir.canonicalize() {
        Ok(path) => path,
        Err(error) => {
            report.error = Some(format!(
                "cannot resolve working directory {}: {error}",
                options.workdir.display()
            ));
            return report;
        }
    };
    let params = match resolve_params(workflow, &options.params) {
        Ok(params) => params,
        Err(error) => {
            report.error = Some(error);
            return report;
        }
    };
    let mut vars = Vars::default();
    for param in &params {
        vars.params.insert(param.name.clone(), param.value.clone());
    }
    vars.env = workflow
        .env
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    for (key, value) in &options.env {
        vars.env.entry(key.clone()).or_insert_with(|| value.clone());
    }
    let mut rendered_env: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in &workflow.env {
        match render(value, &vars, &mut Vec::new()) {
            Ok(value) => {
                rendered_env.insert(key.clone(), value);
            }
            Err(error) => {
                report.error = Some(format!("workflow env `{key}`: {error}"));
                return report;
            }
        }
    }

    let secret_params: Vec<String> = params
        .iter()
        .filter(|param| param.secret)
        .map(|param| param.value.clone())
        .collect();
    let mut ctx = Context {
        policy: options.policy.clone(),
        workdir,
        approver: Arc::clone(&options.approver),
        max_output: options.policy.max_output_bytes,
        default_timeout: options.policy.default_timeout,
        workflow_env: rendered_env,
        run_id: options.run_id,
        secret_params,
    };

    if let Some(timeout) = &workflow.timeout {
        match parse_duration(timeout) {
            Some(duration) => {
                if duration < ctx.default_timeout {
                    ctx.default_timeout = duration;
                }
            }
            None => {
                report.error = Some(format!("invalid workflow timeout `{timeout}`"));
                return report;
            }
        }
    }

    let mut workflow_failed = false;
    let mut denied = false;
    for step in &workflow.steps {
        let (result, records) = execute_step(step, &mut vars, &ctx, 0);
        let step_failed = !result.succeeded() && result.status != StepStatus::Skipped;
        if result.status == StepStatus::Denied {
            denied = true;
        }
        audit.extend(records);
        report.steps.push(result);
        if step_failed {
            if step.continue_on_error && !denied {
                continue;
            }
            workflow_failed = true;
            break;
        }
    }
    report.status = if denied {
        RunStatus::Denied
    } else if workflow_failed {
        RunStatus::Failed
    } else {
        RunStatus::Succeeded
    };
    report.finished_at = Utc::now();
    report.audit = audit;
    if workflow_failed || denied {
        let failed: Vec<&str> = report
            .steps
            .iter()
            .filter(|step| !step.succeeded())
            .map(|step| step.id.as_str())
            .collect();
        report.error = Some(format!("workflow stopped at: {}", failed.join(", ")));
    }
    report
}

struct Context {
    policy: WorkflowPolicy,
    workdir: PathBuf,
    approver: Arc<Mutex<dyn Approver>>,
    max_output: usize,
    default_timeout: Duration,
    workflow_env: BTreeMap<String, String>,
    run_id: String,
    secret_params: Vec<String>,
}

fn resolve_params(
    workflow: &Workflow,
    provided: &BTreeMap<String, String>,
) -> Result<Vec<crate::schema::ParamValue>, String> {
    let mut resolved = Vec::new();
    for (name, spec) in &workflow.params {
        let value = if spec.secret {
            match z_identity::vault::get_secret(name) {
                Ok(Some(value)) => value,
                Ok(None) => {
                    return Err(format!(
                        "secret parameter `{name}` is not in the vault; set it with `z secrets set {name}`"
                    ))
                }
                Err(error) => return Err(format!("cannot read secret `{name}`: {error}")),
            }
        } else if let Some(value) = provided.get(name) {
            value.clone()
        } else if let Some(default) = &spec.default {
            yaml_scalar(default)
        } else if spec.required {
            return Err(format!("missing required parameter `{name}`"));
        } else {
            String::new()
        };
        validate_param(name, spec, &value)?;
        resolved.push(crate::schema::ParamValue {
            name: name.clone(),
            value,
            secret: spec.secret,
        });
    }
    for key in provided.keys() {
        if !workflow.params.contains_key(key) {
            return Err(format!(
                "unknown parameter `{key}` (declare it under `params:`)"
            ));
        }
    }
    Ok(resolved)
}

fn validate_param(name: &str, spec: &ParamSpec, value: &str) -> Result<(), String> {
    if spec.secret {
        if value.is_empty() {
            return Err(format!("secret parameter `{name}` is empty"));
        }
        return Ok(());
    }
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

/// Resolve `${...}` placeholders. Secrets are tracked so they can be scrubbed
/// from output before it reaches a report or an audit event.
pub fn render(
    template: &str,
    vars: &Vars,
    secret_values: &mut Vec<String>,
) -> Result<String, String> {
    let chars: Vec<char> = template.chars().collect();
    let mut out = String::with_capacity(template.len());
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '$' && chars.get(index + 1) == Some(&'{') {
            let mut end = index + 2;
            while end < chars.len() && chars[end] != '}' {
                end += 1;
            }
            if end >= chars.len() {
                return Err("unterminated `${...}` placeholder".into());
            }
            let key: String = chars[index + 2..end].iter().collect();
            let key = key.trim();
            if key.is_empty() {
                return Err("empty `${}` placeholder".into());
            }
            let value = lookup_placeholder(key, vars, secret_values)?;
            out.push_str(&value);
            index = end + 1;
            continue;
        }
        out.push(chars[index]);
        index += 1;
    }
    Ok(out)
}

fn lookup_placeholder(
    key: &str,
    vars: &Vars,
    secret_values: &mut Vec<String>,
) -> Result<String, String> {
    if let Some(name) = key.strip_prefix("secret:") {
        return match z_identity::vault::get_secret(name) {
            Ok(Some(value)) => {
                secret_values.push(value.clone());
                Ok(value)
            }
            Ok(None) => Err(format!("secret `{name}` is not set in the vault")),
            Err(error) => Err(format!("cannot read secret `{name}`: {error}")),
        };
    }
    if let Some(name) = key.strip_prefix("env:") {
        return std::env::var(name)
            .map_err(|_| format!("environment variable `{name}` is not set"));
    }
    if let Some(rest) = key.strip_prefix("steps.") {
        let mut parts = rest.splitn(2, '.');
        let id = parts.next().unwrap_or("");
        let field = parts.next().unwrap_or("stdout");
        let step = vars
            .steps
            .get(id)
            .ok_or_else(|| format!("unknown step `{id}` in placeholder"))?;
        return match field {
            "stdout" => Ok(step.stdout.clone()),
            "stderr" => Ok(step.stderr.clone()),
            "status" => Ok(step.status.clone()),
            "exit_code" => Ok(step.exit_code.map(|c| c.to_string()).unwrap_or_default()),
            "approved" => Ok(step.approved.to_string()),
            other => Err(format!("unknown step field `{other}`")),
        };
    }
    if let Some(name) = key.strip_prefix("params.") {
        return vars
            .params
            .get(name)
            .cloned()
            .ok_or_else(|| format!("unknown parameter `{name}`"));
    }
    if let Some(name) = key.strip_prefix("env.") {
        return vars
            .env
            .get(name)
            .cloned()
            .ok_or_else(|| format!("unknown workflow env `{name}`"));
    }
    vars.params
        .get(key)
        .cloned()
        .ok_or_else(|| format!("unknown placeholder `${{{key}}}`"))
}

fn execute_step(
    step: &Step,
    vars: &mut Vars,
    ctx: &Context,
    depth: usize,
) -> (StepResult, Vec<AuditRecord>) {
    let started = Instant::now();
    let mut audit = Vec::new();
    let kind = if step.run.is_some() {
        "run"
    } else if step.agent.is_some() {
        "agent"
    } else if step.approve.is_some() {
        "approve"
    } else if step.parallel.is_some() {
        "parallel"
    } else if step.http.is_some() {
        "http"
    } else {
        "artifact"
    };
    let mut result = StepResult::base(&step.id, kind);
    // Conditions.
    for expression in [&step.condition, &step.when].into_iter().flatten() {
        match expr::eval(expression, vars) {
            Ok(true) => {}
            Ok(false) => {
                result.status = StepStatus::Skipped;
                result.skipped_reason = Some(format!("condition `{expression}` is false"));
                result.duration_ms = started.elapsed().as_millis() as u64;
                audit.push(audit_record(
                    "workflow.step.skip",
                    &step.id,
                    "allow",
                    "skipped",
                    "low",
                    serde_json::json!({"run_id": ctx.run_id, "reason": expression}),
                ));
                return (result, audit);
            }
            Err(error) => {
                result.status = StepStatus::Failed;
                result.error = Some(format!("condition error: {error}"));
                result.duration_ms = started.elapsed().as_millis() as u64;
                audit.push(audit_record(
                    "workflow.step",
                    &step.id,
                    "deny",
                    "invalid-condition",
                    "medium",
                    serde_json::json!({"run_id": ctx.run_id}),
                ));
                return (result, audit);
            }
        }
    }

    if let Some(parallel) = &step.parallel {
        let (children, child_audit) = run_parallel(parallel, vars, ctx, depth);
        audit.extend(child_audit);
        let failed = children
            .iter()
            .any(|child| !child.succeeded() && child.status != StepStatus::Skipped);
        result.children = children;
        result.status = if failed {
            StepStatus::Failed
        } else {
            StepStatus::Succeeded
        };
        result.exit_code = if failed { Some(1) } else { Some(0) };
        result.stdout = result
            .children
            .iter()
            .map(|child| format!("[{}]\n{}", child.id, child.stdout))
            .collect::<Vec<_>>()
            .join("\n");
        result.stderr = result
            .children
            .iter()
            .filter(|child| !child.succeeded())
            .map(|child| format!("[{}] {}", child.id, child.error.clone().unwrap_or_default()))
            .collect::<Vec<_>>()
            .join("\n");
        result.duration_ms = started.elapsed().as_millis() as u64;
        if failed {
            result.error = Some("one or more parallel steps failed".into());
        }
        result.redacted = result.children.iter().any(|child| child.redacted);
        audit.push(audit_record(
            "workflow.parallel",
            &step.id,
            "allow",
            if failed { "failed" } else { "ok" },
            "medium",
            serde_json::json!({"run_id": ctx.run_id, "children": result.children.len()}),
        ));
        vars.steps.insert(step.id.clone(), step_vars(&result));
        return (result, audit);
    }

    let attempts = step.retries.saturating_add(1).max(1);
    let timeout = step
        .timeout
        .as_deref()
        .and_then(parse_duration)
        .unwrap_or(ctx.default_timeout);
    let mut last: Option<StepResult> = None;
    for attempt in 1..=attempts {
        let (mut attempt_result, mut records) = execute_once(step, vars, ctx, timeout, depth);
        attempt_result.attempts = attempt;
        last = Some(attempt_result);
        audit.append(&mut records);
        if last.as_ref().map(|r| r.succeeded()).unwrap_or(false) {
            break;
        }
        if attempt < attempts {
            std::thread::sleep(Duration::from_millis(250 * attempt as u64));
        }
    }
    let mut result = last.unwrap_or_else(|| StepResult::base(&step.id, kind));
    result.duration_ms = started.elapsed().as_millis() as u64;
    vars.steps.insert(step.id.clone(), step_vars(&result));
    (result, audit)
}

fn execute_once(
    step: &Step,
    vars: &Vars,
    ctx: &Context,
    timeout: Duration,
    depth: usize,
) -> (StepResult, Vec<AuditRecord>) {
    let started = Instant::now();
    let mut audit = Vec::new();
    let mut secrets: Vec<String> = ctx.secret_params.clone();
    let mut result = StepResult::base(
        &step.id,
        if step.run.is_some() {
            "run"
        } else if step.agent.is_some() {
            "agent"
        } else if step.approve.is_some() {
            "approve"
        } else if step.http.is_some() {
            "http"
        } else {
            "artifact"
        },
    );
    if step.run.is_some() {
        let template = step.run.clone().unwrap_or_default();
        result.input = Some(template.clone());
        let command = match render(&template, vars, &mut secrets) {
            Ok(command) => command,
            Err(error) => return fail(result, error, started, &mut audit, ctx),
        };
        let cwd = match resolve_cwd(step.cwd.as_deref(), vars, ctx, &mut secrets) {
            Ok(cwd) => cwd,
            Err(error) => return fail(result, error, started, &mut audit, ctx),
        };
        let mut env = ctx.workflow_env.clone();
        for (key, value) in &step.env {
            match render(value, vars, &mut secrets) {
                Ok(value) => {
                    env.insert(key.clone(), value);
                }
                Err(error) => return fail(result, error, started, &mut audit, ctx),
            }
        }
        env.insert("ZENTRION_WORKFLOW".into(), step.id.clone());
        env.insert("ZENTRION_RUN_ID".into(), ctx.run_id.clone());
        let shell = step
            .shell
            .clone()
            .or_else(|| std::env::var("SHELL").ok())
            .unwrap_or_else(|| {
                if cfg!(windows) {
                    "cmd.exe".into()
                } else {
                    "/bin/sh".into()
                }
            });
        let (program, args) = shell_command(&shell, &command);
        let outcome = run_process(&program, &args, &cwd, &env, timeout, None, ctx.max_output);
        apply_outcome(&mut result, outcome, &mut secrets);
        if result.succeeded() {
            audit.push(audit_record(
                "workflow.step.run",
                &step.id,
                "allow",
                "ok",
                "medium",
                serde_json::json!({"run_id": ctx.run_id, "exit_code": result.exit_code}),
            ));
        } else {
            audit.push(audit_record(
                "workflow.step.run",
                &step.id,
                "allow",
                "failed",
                "medium",
                serde_json::json!({"run_id": ctx.run_id, "exit_code": result.exit_code}),
            ));
        }
    } else if let Some(agent) = &step.agent {
        let prompt_template = agent.prompt().unwrap_or("");
        if prompt_template.trim().is_empty() {
            return fail(
                result,
                "agent step needs a prompt".into(),
                started,
                &mut audit,
                ctx,
            );
        }
        let prompt = match render(prompt_template, vars, &mut secrets) {
            Ok(prompt) => prompt,
            Err(error) => return fail(result, error, started, &mut audit, ctx),
        };
        let approved = ctx
            .approver
            .lock()
            .expect("approver lock")
            .approve(&step.id, &format!("start agent `{}`?", agent.agent()));
        result.approved = approved;
        if !approved {
            result.status = StepStatus::Denied;
            result.error = Some("agent start denied".into());
            audit.push(audit_record(
                "workflow.step.agent",
                &step.id,
                "deny",
                "denied",
                "high",
                serde_json::json!({"run_id": ctx.run_id, "agent": agent.agent()}),
            ));
            result.duration_ms = started.elapsed().as_millis() as u64;
            return (result, audit);
        }
        let cwd = match resolve_cwd(step.cwd.as_deref(), vars, ctx, &mut secrets) {
            Ok(cwd) => cwd,
            Err(error) => return fail(result, error, started, &mut audit, ctx),
        };
        let exe = match std::env::current_exe() {
            Ok(exe) => exe,
            Err(error) => {
                return fail(
                    result,
                    format!("cannot locate z executable: {error}"),
                    started,
                    &mut audit,
                    ctx,
                )
            }
        };
        let mut args = vec![
            "agent".to_string(),
            "run".to_string(),
            agent.agent().to_string(),
            "--prompt".to_string(),
            prompt.clone(),
        ];
        if let Some(model) = agent.model() {
            args.push("--model".into());
            args.push(model.to_string());
        }
        args.extend(agent.extra_args().iter().cloned());
        let mut env = ctx.workflow_env.clone();
        env.insert("ZENTRION_RUN_ID".into(), ctx.run_id.clone());
        let outcome = run_process(
            &exe.display().to_string(),
            &args,
            &cwd,
            &env,
            timeout,
            None,
            ctx.max_output,
        );
        apply_outcome(&mut result, outcome, &mut secrets);
        audit.push(audit_record(
            "workflow.step.agent",
            &step.id,
            "allow",
            if result.succeeded() { "ok" } else { "failed" },
            "high",
            serde_json::json!({
                "run_id": ctx.run_id,
                "agent": agent.agent(),
                "model": agent.model(),
            }),
        ));
    } else if let Some(message) = &step.approve {
        let rendered = match render(message, vars, &mut secrets) {
            Ok(message) => message,
            Err(error) => return fail(result, error, started, &mut audit, ctx),
        };
        let approved = ctx
            .approver
            .lock()
            .expect("approver lock")
            .approve(&step.id, &rendered);
        result.approved = approved;
        result.input = Some(message.clone());
        if approved {
            result.status = StepStatus::Succeeded;
            result.stdout = rendered;
            audit.push(audit_record(
                "workflow.step.approve",
                &step.id,
                "allow",
                "approved",
                "high",
                serde_json::json!({"run_id": ctx.run_id}),
            ));
        } else {
            result.status = StepStatus::Denied;
            result.error = Some("approval denied".into());
            audit.push(audit_record(
                "workflow.step.approve",
                &step.id,
                "deny",
                "denied",
                "high",
                serde_json::json!({"run_id": ctx.run_id}),
            ));
        }
    } else if let Some(http) = &step.http {
        match execute_http(http, vars, ctx, &mut secrets) {
            Ok((body, status)) => {
                result.stdout = body;
                result.exit_code = Some(0);
                result.stderr = format!("HTTP {status}");
                audit.push(audit_record(
                    "workflow.step.http",
                    &step.id,
                    "allow",
                    "ok",
                    "medium",
                    serde_json::json!({"run_id": ctx.run_id, "status": status}),
                ));
            }
            Err(error) => {
                result.status = StepStatus::Failed;
                result.error = Some(scrub(&error, &secrets));
                audit.push(audit_record(
                    "workflow.step.http",
                    &step.id,
                    "deny",
                    "failed",
                    "medium",
                    serde_json::json!({"run_id": ctx.run_id}),
                ));
            }
        }
    } else if let Some(artifact) = &step.artifact {
        match collect_artifact(artifact, vars, ctx, &mut secrets) {
            Ok(artifact) => {
                result.stdout = format!("{} ({})", artifact.path, artifact.sha256);
                result.artifacts.push(artifact);
                audit.push(audit_record(
                    "workflow.step.artifact",
                    &step.id,
                    "allow",
                    "ok",
                    "low",
                    serde_json::json!({
                        "run_id": ctx.run_id,
                        "sha256": result.artifacts[0].sha256,
                        "bytes": result.artifacts[0].bytes,
                    }),
                ));
            }
            Err(error) => return fail(result, error, started, &mut audit, ctx),
        }
    }
    result.duration_ms = started.elapsed().as_millis() as u64;
    scrub_result(&mut result, &secrets);
    let _ = depth;
    (result, audit)
}

fn run_parallel(
    steps: &[Step],
    vars: &mut Vars,
    ctx: &Context,
    depth: usize,
) -> (Vec<StepResult>, Vec<AuditRecord>) {
    let snapshot = vars.clone();
    let mut children: Vec<StepResult> = Vec::new();
    let mut audit = Vec::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for step in steps {
            let vars = snapshot.clone();
            handles.push(scope.spawn(move || {
                let mut vars = vars;
                execute_step(step, &mut vars, ctx, depth + 1)
            }));
        }
        for handle in handles {
            match handle.join() {
                Ok((result, records)) => {
                    audit.extend(records);
                    children.push(result);
                }
                Err(_) => children.push(StepResult {
                    id: "parallel".into(),
                    kind: "run".into(),
                    status: StepStatus::Failed,
                    exit_code: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    error: Some("parallel worker panicked".into()),
                    attempts: 1,
                    duration_ms: 0,
                    approved: false,
                    input: None,
                    artifacts: Vec::new(),
                    skipped_reason: None,
                    redacted: false,
                    children: Vec::new(),
                }),
            }
        }
    });
    (children, audit)
}

fn execute_http(
    http: &HttpStep,
    vars: &Vars,
    ctx: &Context,
    secrets: &mut Vec<String>,
) -> Result<(String, u16), String> {
    if !ctx.policy.allow_http {
        return Err(
            "HTTP steps are disabled (set [workflow] allow_http = true and add a host allowlist)"
                .into(),
        );
    }
    let url = render(&http.url, vars, secrets)?;
    let (scheme, host, _port) = parse_http_url(&url)?;
    if scheme != "http" && scheme != "https" {
        return Err("only http/https URLs are allowed".into());
    }
    let host_allowed = ctx
        .policy
        .http_allowlist
        .iter()
        .any(|allowed| host_matches(allowed, &host));
    if !host_allowed {
        return Err(format!("host `{host}` is not in [workflow] http_allowlist"));
    }
    let explicit_host = ctx
        .policy
        .http_allowlist
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&host));
    if !explicit_host {
        reject_private_host(&host)?;
    }
    let timeout = http
        .timeout
        .as_deref()
        .and_then(parse_duration)
        .unwrap_or(ctx.default_timeout);
    let agent = ureq::AgentBuilder::new()
        .timeout(timeout)
        .redirects(0)
        .build();
    let mut request = agent.request(&http.method.to_ascii_uppercase(), &url);
    for (key, value) in &http.headers {
        request = request.set(key, &render(value, vars, secrets)?);
    }
    let response = if let Some(body) = &http.body {
        let body = render(body, vars, secrets)?;
        request.send_string(&body)
    } else {
        request.call()
    };
    let (status, mut reader) = match response {
        Ok(response) => (response.status(), response.into_reader()),
        Err(ureq::Error::Status(status, response)) => (status, response.into_reader()),
        Err(ureq::Error::Transport(error)) => return Err(format!("HTTP transport error: {error}")),
    };
    let expected = if http.expect_status.is_empty() {
        (200..300).contains(&status)
    } else {
        http.expect_status.contains(&status)
    };
    let mut body = Vec::new();
    reader
        .by_ref()
        .take(ctx.max_output as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|e| format!("cannot read HTTP response: {e}"))?;
    if body.len() > ctx.max_output {
        body.truncate(ctx.max_output);
    }
    let text = String::from_utf8_lossy(&body).to_string();
    if !expected {
        return Err(format!("unexpected HTTP status {status}"));
    }
    Ok((text, status))
}

fn host_matches(allowed: &str, host: &str) -> bool {
    let allowed = allowed.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    if let Some(suffix) = allowed.strip_prefix("*.") {
        host.ends_with(&format!(".{suffix}")) || host == suffix
    } else {
        allowed == host
    }
}

/// Reject private/loopback targets for wildcard allowlist entries. An explicit
/// exact entry (for example `localhost`) is the deliberate override.
fn reject_private_host(host: &str) -> Result<(), String> {
    use std::net::ToSocketAddrs;
    if host.eq_ignore_ascii_case("localhost") {
        return Err("loopback hosts must be listed explicitly in http_allowlist".into());
    }
    let addresses = (host, 0)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve `{host}`: {e}"))?;
    for address in addresses {
        if is_private_ip(address.ip()) {
            return Err(format!(
                "`{host}` resolves to a private address; list it explicitly to allow it"
            ));
        }
    }
    Ok(())
}

fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
        }
        std::net::IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn collect_artifact(
    artifact: &ArtifactStep,
    vars: &Vars,
    ctx: &Context,
    secrets: &mut Vec<String>,
) -> Result<Artifact, String> {
    let path = render(&artifact.path, vars, secrets)?;
    let relative = Path::new(&path);
    for component in relative.components() {
        if matches!(component, Component::ParentDir) {
            return Err("artifact path must not contain `..`".into());
        }
    }
    let target = if relative.is_absolute() {
        relative.to_path_buf()
    } else {
        ctx.workdir.join(relative)
    };
    let canonical = target
        .canonicalize()
        .map_err(|e| format!("artifact {} cannot be read: {e}", target.display()))?;
    if !canonical.starts_with(&ctx.workdir) {
        return Err("artifact must live inside the workflow working directory".into());
    }
    let metadata = std::fs::metadata(&canonical)
        .map_err(|e| format!("artifact {} cannot be read: {e}", canonical.display()))?;
    if !metadata.is_file() {
        return Err(format!("artifact {} is not a file", canonical.display()));
    }
    if metadata.len() > MAX_ARTIFACT_BYTES {
        return Err("artifact is larger than 2 GiB".into());
    }
    let bytes = std::fs::read(&canonical)
        .map_err(|e| format!("artifact {} cannot be read: {e}", canonical.display()))?;
    let hash = format!("sha256:{}", hex(&Sha256::digest(&bytes)));
    let name = artifact
        .name
        .clone()
        .or_else(|| {
            canonical
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
        })
        .unwrap_or_else(|| "artifact".into());
    Ok(Artifact {
        name,
        path: canonical.display().to_string(),
        sha256: hash,
        bytes: bytes.len() as u64,
    })
}

struct ProcOutcome {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    timed_out: bool,
    error: Option<String>,
}

fn run_process(
    program: &str,
    args: &[String],
    cwd: &Path,
    env: &BTreeMap<String, String>,
    timeout: Duration,
    stdin_data: Option<&str>,
    max_output: usize,
) -> ProcOutcome {
    let mut command = std::process::Command::new(program);
    command
        .args(args)
        .current_dir(cwd)
        .envs(env)
        .stdin(if stdin_data.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // New process group so a timeout can kill the whole tree.
        command.process_group(0);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return ProcOutcome {
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                timed_out: false,
                error: Some(format!("cannot start `{program}`: {error}")),
            }
        }
    };
    if let Some(data) = stdin_data {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(data.as_bytes());
        }
    }
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let out_handle = stdout.map(|reader| read_limited(reader, max_output));
    let err_handle = stderr.map(|reader| read_limited(reader, max_output));
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    #[cfg(unix)]
                    {
                        // Kill the process group to catch grandchildren.
                        let pid = child.id() as i32;
                        unsafe {
                            libc::kill(-pid, libc::SIGKILL);
                        }
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => {
                return ProcOutcome {
                    exit_code: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    timed_out: false,
                    error: Some(format!("cannot wait for `{program}`: {error}")),
                }
            }
        }
    };
    let (stdout, stdout_truncated) = out_handle
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    let (stderr, stderr_truncated) = err_handle
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    let mut stderr = stderr;
    if stdout_truncated {
        stderr.push_str("\n[stdout truncated]");
    }
    if stderr_truncated {
        stderr.push_str("\n[stderr truncated]");
    }
    if timed_out {
        stderr.push_str(&format!("\n[killed after {:?}]", timeout));
    }
    ProcOutcome {
        exit_code: status.and_then(|status| status.code()),
        stdout,
        stderr,
        timed_out,
        error: None,
    }
}

fn read_limited(
    mut reader: impl Read + Send + 'static,
    max: usize,
) -> std::thread::JoinHandle<(String, bool)> {
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut truncated = false;
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if buffer.len() + n > max {
                        let take = max.saturating_sub(buffer.len());
                        buffer.extend_from_slice(&chunk[..take]);
                        truncated = true;
                        // Drain so the child never blocks on a full pipe.
                        continue;
                    }
                    buffer.extend_from_slice(&chunk[..n]);
                }
                Err(_) => break,
            }
        }
        (String::from_utf8_lossy(&buffer).to_string(), truncated)
    })
}

fn apply_outcome(result: &mut StepResult, outcome: ProcOutcome, secrets: &mut Vec<String>) {
    result.exit_code = outcome.exit_code;
    result.stdout = scrub(&outcome.stdout, secrets);
    result.stderr = scrub(&outcome.stderr, secrets);
    if outcome.timed_out {
        result.status = StepStatus::Failed;
        result.error = Some("step timed out and was killed".into());
    } else if let Some(error) = outcome.error {
        result.status = StepStatus::Failed;
        result.error = Some(scrub(&error, secrets));
    } else if outcome.exit_code != Some(0) {
        result.status = StepStatus::Failed;
        result.error = Some(format!(
            "exited with code {}",
            outcome
                .exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "unknown".into())
        ));
    } else {
        result.status = StepStatus::Succeeded;
    }
}

fn scrub_result(result: &mut StepResult, secrets: &[String]) {
    result.stdout = scrub(&result.stdout, secrets);
    result.stderr = scrub(&result.stderr, secrets);
    if let Some(error) = &result.error {
        result.error = Some(scrub(error, secrets));
    }
    let (_, redactions) = z_blocks::redact(&result.stdout);
    if !redactions.is_empty() {
        result.redacted = true;
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
    if !found.is_empty() {
        return redacted;
    }
    out
}

fn fail(
    mut result: StepResult,
    error: String,
    started: Instant,
    audit: &mut Vec<AuditRecord>,
    ctx: &Context,
) -> (StepResult, Vec<AuditRecord>) {
    result.status = StepStatus::Failed;
    result.error = Some(error);
    result.duration_ms = started.elapsed().as_millis() as u64;
    audit.push(audit_record(
        "workflow.step",
        &result.id,
        "deny",
        "failed",
        "medium",
        serde_json::json!({"run_id": ctx.run_id}),
    ));
    (result, std::mem::take(audit))
}

fn resolve_cwd(
    cwd: Option<&str>,
    vars: &Vars,
    ctx: &Context,
    secrets: &mut Vec<String>,
) -> Result<PathBuf, String> {
    let Some(cwd) = cwd else {
        return Ok(ctx.workdir.clone());
    };
    let cwd = render(cwd, vars, secrets)?;
    let path = Path::new(&cwd);
    let target = if path.is_absolute() {
        path.to_path_buf()
    } else {
        ctx.workdir.join(path)
    };
    let canonical = target
        .canonicalize()
        .map_err(|e| format!("cwd {} cannot be resolved: {e}", target.display()))?;
    if ctx.policy.restrict_to_workspace && !canonical.starts_with(&ctx.workdir) {
        return Err(format!(
            "cwd {} is outside the workflow workspace",
            canonical.display()
        ));
    }
    if !canonical.is_dir() {
        return Err(format!("cwd {} is not a directory", canonical.display()));
    }
    Ok(canonical)
}

fn shell_command(shell: &str, command: &str) -> (String, Vec<String>) {
    let name = Path::new(shell)
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or(shell)
        .to_ascii_lowercase();
    if name == "cmd" || name == "cmd.exe" {
        (shell.to_string(), vec!["/C".into(), command.to_string()])
    } else {
        (shell.to_string(), vec!["-c".into(), command.to_string()])
    }
}

fn step_vars(result: &StepResult) -> StepVars {
    StepVars {
        status: match result.status {
            StepStatus::Succeeded => "succeeded".into(),
            StepStatus::Failed => "failed".into(),
            StepStatus::Skipped => "skipped".into(),
            StepStatus::Denied => "denied".into(),
        },
        exit_code: result.exit_code,
        stdout: result.stdout.clone(),
        stderr: result.stderr.clone(),
        approved: result.approved,
        error: result.error.clone(),
    }
}

fn audit_record(
    action: &str,
    step: &str,
    decision: &str,
    result: &str,
    risk: &str,
    metadata: serde_json::Value,
) -> AuditRecord {
    let mut metadata = metadata;
    if let Some(map) = metadata.as_object_mut() {
        map.insert("step".into(), serde_json::Value::String(step.to_string()));
    }
    AuditRecord {
        ts: Utc::now(),
        action: action.to_string(),
        resource: format!("workflow:{step}"),
        decision: decision.to_string(),
        result: result.to_string(),
        risk: risk.to_string(),
        metadata,
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Persist a run report under `<dir>/<run_id>.json`.
pub fn save_run(report: &RunReport, dir: &Path) -> Result<PathBuf, WorkflowError> {
    std::fs::create_dir_all(dir)
        .map_err(|e| WorkflowError::Io(format!("{}: {e}", dir.display())))?;
    let path = dir.join(format!("{}.json", report.run_id));
    let text = serde_json::to_string_pretty(report)
        .map_err(|e| WorkflowError::Io(format!("cannot serialize run: {e}")))?;
    std::fs::write(&path, text)
        .map_err(|e| WorkflowError::Io(format!("{}: {e}", path.display())))?;
    Ok(path)
}

pub fn list_runs(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut runs: Vec<String> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                path.file_stem()
                    .map(|stem| stem.to_string_lossy().to_string())
            } else {
                None
            }
        })
        .collect();
    runs.sort();
    runs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::parse_workflow;

    fn workflow(yaml: &str) -> Workflow {
        parse_workflow(yaml).unwrap()
    }

    fn temp_workspace(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-workflow-{}-{}-{}",
            name,
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn run_workflow_with_approval_condition_and_parallel() {
        let dir = temp_workspace("run");
        std::fs::write(dir.join("artifact.txt"), "artifact\n").unwrap();
        let wf = workflow(
            r#"
name: demo
params:
  who: {type: string, default: world}
steps:
  - id: hello
    run: "echo hello ${who}"
  - id: gate
    approve: "Proceed with ${who}?"
  - id: after
    run: "echo after"
    when: "steps.gate.approved"
  - id: fan
    parallel:
      - id: a
        run: "echo a"
      - id: b
        run: "echo b"
  - id: art
    artifact: artifact.txt
"#,
        );
        let report = run(&wf, RunOptions::new(&dir).allow_all());
        assert_eq!(report.status, RunStatus::Succeeded, "{:?}", report.error);
        assert_eq!(report.steps.len(), 5);
        assert!(report.steps[0].stdout.contains("hello world"));
        assert!(report.steps[2].stdout.contains("after"));
        assert_eq!(report.steps[3].children.len(), 2);
        assert!(report.steps[4].artifacts[0].sha256.starts_with("sha256:"));
        assert!(report
            .audit
            .iter()
            .any(|a| a.action == "workflow.step.approve"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn denied_approval_stops_the_workflow() {
        let dir = temp_workspace("denied");
        let wf = workflow(
            r#"
name: denied
steps:
  - id: gate
    approve: "ship it?"
  - id: never
    run: "echo should-not-run"
"#,
        );
        let report = run(&wf, RunOptions::new(&dir));
        assert_eq!(report.status, RunStatus::Denied);
        assert_eq!(report.steps.len(), 1);
        assert!(!report.steps[0].approved);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn failed_step_stops_unless_continue_on_error() {
        let dir = temp_workspace("failure");
        let wf = workflow(
            r#"
name: failure
steps:
  - id: fail
    run: "exit 7"
  - id: never
    run: "echo no"
"#,
        );
        let report = run(&wf, RunOptions::new(&dir).allow_all());
        assert_eq!(report.status, RunStatus::Failed);
        assert_eq!(report.steps[0].exit_code, Some(7));
        assert_eq!(report.steps.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn timeouts_kill_the_step() {
        let dir = temp_workspace("timeout");
        let wf = workflow(
            r#"
name: timeout
steps:
  - id: slow
    run: "sleep 5"
    timeout: 100ms
"#,
        );
        let started = Instant::now();
        let report = run(&wf, RunOptions::new(&dir).allow_all());
        assert_eq!(report.status, RunStatus::Failed);
        assert!(report.steps[0]
            .error
            .as_deref()
            .unwrap()
            .contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(3));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn skipped_step_does_not_run() {
        let dir = temp_workspace("skip");
        let wf = workflow(
            r#"
name: skip
steps:
  - id: never
    run: "echo no"
    when: "false"
"#,
        );
        let report = run(&wf, RunOptions::new(&dir).allow_all());
        assert_eq!(report.status, RunStatus::Succeeded);
        assert_eq!(report.steps[0].status, StepStatus::Skipped);
        assert!(report.steps[0].stdout.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn unknown_placeholder_fails_closed() {
        let dir = temp_workspace("placeholder");
        let wf = workflow(
            r#"
name: placeholder
steps:
  - id: a
    run: "echo ${nope}"
"#,
        );
        let report = run(&wf, RunOptions::new(&dir).allow_all());
        assert_eq!(report.status, RunStatus::Failed);
        assert!(report.steps[0]
            .error
            .as_deref()
            .unwrap()
            .contains("unknown placeholder"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn http_is_disabled_by_default_and_allowlisted_explicitly() {
        let dir = temp_workspace("http");
        let wf = workflow(
            r#"
name: http
steps:
  - id: fetch
    http:
      url: "https://example.com/"
"#,
        );
        let report = run(&wf, RunOptions::new(&dir).allow_all());
        assert_eq!(report.status, RunStatus::Failed);
        assert!(report.steps[0]
            .error
            .as_deref()
            .unwrap()
            .contains("disabled"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn artifact_outside_workspace_is_rejected() {
        let dir = temp_workspace("artifact");
        let wf = workflow(
            r#"
name: artifact
steps:
  - id: art
    artifact: "../outside.txt"
"#,
        );
        let report = run(&wf, RunOptions::new(&dir).allow_all());
        assert_eq!(report.status, RunStatus::Failed);
        assert!(report.steps[0].error.as_deref().unwrap().contains(".."));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn runs_are_saved_and_listed() {
        let dir = temp_workspace("save");
        let wf = workflow(
            r#"
name: save
steps:
  - id: a
    run: "true"
"#,
        );
        let report = run(&wf, RunOptions::new(&dir).allow_all());
        let runs = dir.join("runs");
        let path = save_run(&report, &runs).unwrap();
        assert!(path.exists());
        assert_eq!(list_runs(&runs), vec![report.run_id.clone()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

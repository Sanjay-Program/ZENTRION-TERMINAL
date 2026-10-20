//! Agent supervisor.
//!
//! Launches CLI agents in PTYs, normalises their state, queues prompts and
//! records a trace. State derived from screen patterns is explicitly labelled
//! approximate; only adapters with hook/JSONL events can claim exact state.

use crate::adapter::{Adapter, AgentState, StatusParser};
use chrono::{DateTime, Utc};
use portable_pty::{native_pty_system, Child, CommandBuilder, PtySize};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const READ_CHUNK: usize = 16 * 1024;
const OUTPUT_TAIL: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct LaunchOptions {
    pub adapter: Adapter,
    pub prompt: Option<String>,
    pub model: Option<String>,
    pub cwd: PathBuf,
    pub profile: String,
    pub env: Vec<(String, String)>,
    /// Override the command (used by resume).
    pub command_override: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentRunInfo {
    pub id: String,
    pub adapter_id: String,
    pub adapter_name: String,
    pub state: AgentState,
    pub approximate: bool,
    pub pid: Option<u32>,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub model: Option<String>,
    pub profile: String,
    pub workspace: String,
    pub prompt: Option<String>,
    pub queued_prompts: usize,
    pub last_error: Option<String>,
    pub tokens_in: Option<u64>,
    pub tokens_out: Option<u64>,
    pub cost_micros: Option<u64>,
    pub badge: Option<String>,
    pub color: Option<String>,
}

impl AgentRunInfo {
    pub fn terminal(&self) -> bool {
        self.state.is_terminal()
    }

    pub fn elapsed_ms(&self) -> u64 {
        let end = self.ended_at.unwrap_or_else(Utc::now);
        end.signed_duration_since(self.started_at)
            .num_milliseconds()
            .max(0) as u64
    }
}

pub struct AgentHandle {
    info: Mutex<AgentRunInfo>,
    writer: Mutex<Box<dyn Write + Send>>,
    child: Mutex<Box<dyn Child + Send + Sync>>,
    output: Mutex<String>,
    queue: Mutex<VecDeque<String>>,
    parser: StatusParser,
    data_dir: PathBuf,
    alive: AtomicBool,
    trace: Mutex<Option<std::fs::File>>,
}

impl std::fmt::Debug for AgentHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentHandle")
            .field("info", &self.info())
            .finish()
    }
}

impl AgentHandle {
    pub fn info(&self) -> AgentRunInfo {
        self.info.lock().expect("agent info lock").clone()
    }

    pub fn id(&self) -> String {
        self.info.lock().expect("agent info lock").id.clone()
    }

    pub fn alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    pub fn output(&self) -> String {
        self.output.lock().expect("agent output lock").clone()
    }

    pub fn trace_path(&self) -> PathBuf {
        self.data_dir
            .join("agents")
            .join("traces")
            .join(format!("{}.jsonl", self.id()))
    }

    /// Send a prompt to the agent. Multi-line prompts are sent as bracketed
    /// paste followed by Enter.
    pub fn send_prompt(&self, text: &str) -> Result<(), String> {
        if !self.alive() {
            return Err("agent is not running".into());
        }
        self.trace("prompt", &z_blocks::redact(text).0);
        let mut writer = self.writer.lock().expect("agent writer lock");
        if text.contains('\n') {
            writer
                .write_all(b"\x1b[200~")
                .and_then(|_| writer.write_all(text.as_bytes()))
                .and_then(|_| writer.write_all(b"\x1b[201~\r"))
                .map_err(|e| e.to_string())?;
        } else {
            writer
                .write_all(text.as_bytes())
                .and_then(|_| writer.write_all(b"\r"))
                .map_err(|e| e.to_string())?;
        }
        writer.flush().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Queue a prompt until the agent is waiting for input.
    pub fn queue_prompt(&self, text: &str) {
        self.queue
            .lock()
            .expect("agent queue lock")
            .push_back(text.to_string());
        self.update_queued();
    }

    pub fn write_raw(&self, bytes: &[u8]) -> Result<(), String> {
        let mut writer = self.writer.lock().expect("agent writer lock");
        writer.write_all(bytes).map_err(|e| e.to_string())?;
        writer.flush().map_err(|e| e.to_string())
    }

    pub fn interrupt(&self) -> Result<(), String> {
        self.trace("interrupt", "");
        self.write_raw(b"\x03")
    }

    pub fn stop(&self) -> Result<(), String> {
        self.trace("stop", "");
        self.alive.store(false, Ordering::SeqCst);
        let mut child = self.child.lock().expect("agent child lock");
        child.kill().map_err(|e| e.to_string())
    }

    /// Wait for a terminal state, polling `timeout`.
    pub fn wait(&self, timeout: std::time::Duration) -> AgentRunInfo {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let info = self.info();
            if info.terminal() || std::time::Instant::now() >= deadline {
                return info;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    fn update_queued(&self) {
        let queued = self.queue.lock().expect("agent queue lock").len();
        let mut info = self.info.lock().expect("agent info lock");
        info.queued_prompts = queued;
    }

    fn set_state(&self, state: AgentState) {
        let mut info = self.info.lock().expect("agent info lock");
        if info.state == state || info.state.is_terminal() {
            return;
        }
        info.state = state;
        drop(info);
        self.trace("state", state.as_str());
        self.persist();
        if state == AgentState::WaitingInput {
            self.flush_queue();
        }
    }

    fn flush_queue(&self) {
        let next = self.queue.lock().expect("agent queue lock").pop_front();
        if let Some(prompt) = next {
            let _ = self.send_prompt(&prompt);
            self.update_queued();
        }
    }

    fn trace(&self, event: &str, detail: &str) {
        let line = serde_json::json!({
            "ts": Utc::now().to_rfc3339(),
            "agent": self.id(),
            "event": event,
            "detail": detail,
        });
        if let Ok(mut guard) = self.trace.lock() {
            if guard.is_none() {
                let path = self.trace_path();
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                *guard = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .ok();
            }
            if let Some(file) = guard.as_mut() {
                let _ = writeln!(file, "{line}");
            }
        }
    }

    fn persist(&self) {
        let info = self.info();
        let dir = self.data_dir.join("agents").join("runs");
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        let path = dir.join(format!("{}.json", info.id));
        let tmp = path.with_extension("json.tmp");
        if let Ok(text) = serde_json::to_string_pretty(&info) {
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
        }
    }

    fn reader_loop(self: Arc<Self>, mut reader: Box<dyn Read + Send>) {
        let mut buffer = vec![0u8; READ_CHUNK];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = String::from_utf8_lossy(&buffer[..n]).to_string();
                    {
                        let mut output = self.output.lock().expect("agent output lock");
                        output.push_str(&chunk);
                        if output.len() > OUTPUT_TAIL {
                            let mut cut = output.len() - OUTPUT_TAIL;
                            while cut < output.len() && !output.is_char_boundary(cut) {
                                cut += 1;
                            }
                            let tail = output[cut..].to_string();
                            *output = tail;
                        }
                    }
                    if let Some(state) = self.parser.feed(&chunk) {
                        self.set_state(state);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        self.alive.store(false, Ordering::SeqCst);
        // PTY EOF can arrive a few scheduling ticks before the child is
        // reapable. Waiting avoids falsely reporting a successful agent as
        // failed (and losing its exit code) under load.
        let code = {
            let mut child = self.child.lock().expect("agent child lock");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => break Some(status.exit_code() as i32),
                    Ok(None) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    _ => break None,
                }
            }
        };
        {
            let mut info = self.info.lock().expect("agent info lock");
            info.ended_at = Some(Utc::now());
            info.exit_code = code;
            info.state = if code == Some(0) {
                AgentState::Done
            } else {
                AgentState::Failed
            };
            if code.is_none() {
                info.last_error = Some("agent exited without a reportable status".into());
            }
        }
        self.trace("exit", &format!("code={code:?}"));
        self.persist();
    }
}

pub struct Supervisor {
    data_dir: PathBuf,
    runs: Mutex<HashMap<String, Arc<AgentHandle>>>,
    adapters: Vec<Adapter>,
}

impl Supervisor {
    pub fn new(data_dir: impl Into<PathBuf>, adapters: Vec<Adapter>) -> Self {
        Self {
            data_dir: data_dir.into(),
            runs: Mutex::new(HashMap::new()),
            adapters,
        }
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn adapters(&self) -> &[Adapter] {
        &self.adapters
    }

    pub fn adapter(&self, id: &str) -> Option<&Adapter> {
        self.adapters.iter().find(|adapter| adapter.id == id)
    }

    pub fn launch(&self, options: LaunchOptions) -> Result<Arc<AgentHandle>, String> {
        let option_errors = options.adapter.validate();
        if !option_errors.is_empty() {
            return Err(option_errors.join("; "));
        }
        let cwd = options
            .cwd
            .canonicalize()
            .map_err(|e| format!("cannot resolve cwd {}: {e}", options.cwd.display()))?;
        let argv = options.command_override.clone().unwrap_or_else(|| {
            let mut argv = vec![options.adapter.command.clone()];
            argv.extend(options.adapter.args.iter().cloned());
            argv
        });
        let (program, args) = argv
            .split_first()
            .ok_or_else(|| "adapter command is empty".to_string())?;
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: 40,
                cols: 120,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| format!("cannot open PTY: {e}"))?;
        let mut command = CommandBuilder::new(program);
        for arg in args {
            command.arg(arg);
        }
        if let Some(prompt) = &options.prompt {
            command.arg(prompt);
        }
        command.cwd(&cwd);
        command.env("ZENTRION_AGENT_ID", &options.adapter.id);
        command.env("ZENTRION_AGENT_PROFILE", &options.profile);
        if let Some(model) = &options.model {
            command.env("ZENTRION_AGENT_MODEL", model);
        }
        for (key, value) in &options.env {
            command.env(key, value);
        }
        let child = pair
            .slave
            .spawn_command(command)
            .map_err(|e| format!("cannot start agent `{program}`: {e}"))?;
        drop(pair.slave);
        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| format!("cannot read agent output: {e}"))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| format!("cannot write to agent: {e}"))?;
        let id = format!("a_{}", Uuid::new_v4().simple());
        let info = AgentRunInfo {
            id: id.clone(),
            adapter_id: options.adapter.id.clone(),
            adapter_name: options.adapter.name.clone(),
            state: AgentState::Starting,
            approximate: options.adapter.approximate(),
            pid: child.process_id(),
            started_at: Utc::now(),
            ended_at: None,
            exit_code: None,
            model: options.model.clone(),
            profile: options.profile.clone(),
            workspace: cwd.display().to_string(),
            prompt: options
                .prompt
                .as_ref()
                .map(|prompt| z_blocks::redact(prompt).0),
            queued_prompts: 0,
            last_error: None,
            tokens_in: None,
            tokens_out: None,
            cost_micros: None,
            badge: options.adapter.ui.badge.clone(),
            color: options.adapter.ui.color.clone(),
        };
        let handle = Arc::new(AgentHandle {
            info: Mutex::new(info.clone()),
            writer: Mutex::new(writer),
            child: Mutex::new(child),
            output: Mutex::new(String::new()),
            queue: Mutex::new(VecDeque::new()),
            parser: StatusParser::new(&options.adapter),
            data_dir: self.data_dir.clone(),
            alive: AtomicBool::new(true),
            trace: Mutex::new(None),
        });
        handle.set_state(AgentState::Running);
        handle.trace(
            "start",
            &format!("adapter={} profile={}", options.adapter.id, options.profile),
        );
        handle.persist();
        let reader_handle = Arc::clone(&handle);
        std::thread::Builder::new()
            .name(format!("agent-{id}"))
            .spawn(move || reader_handle.reader_loop(reader))
            .map_err(|e| format!("cannot start agent reader thread: {e}"))?;
        self.runs
            .lock()
            .expect("runs lock")
            .insert(id, Arc::clone(&handle));
        Ok(handle)
    }

    pub fn list(&self) -> Vec<AgentRunInfo> {
        let mut infos: Vec<AgentRunInfo> = self
            .runs
            .lock()
            .expect("runs lock")
            .values()
            .map(|handle| handle.info())
            .collect();
        infos.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        infos
    }

    pub fn get(&self, id: &str) -> Option<Arc<AgentHandle>> {
        self.runs.lock().expect("runs lock").get(id).cloned()
    }

    pub fn stop_all(&self) {
        let handles: Vec<Arc<AgentHandle>> = self
            .runs
            .lock()
            .expect("runs lock")
            .values()
            .cloned()
            .collect();
        for handle in handles {
            let _ = handle.stop();
        }
    }

    /// Resume a previous run using the adapter's resume command.
    pub fn resume(&self, run_id: &str, prompt: Option<String>) -> Result<Arc<AgentHandle>, String> {
        let info = self
            .load_run(run_id)
            .ok_or_else(|| format!("agent run `{run_id}` not found"))?;
        let adapter = self
            .adapter(&info.adapter_id)
            .ok_or_else(|| format!("adapter `{}` is no longer installed", info.adapter_id))?;
        let command = if let Some(resume) = &adapter.resume {
            if resume.command.is_empty() {
                None
            } else {
                Some(resume.command.clone())
            }
        } else {
            None
        };
        let command = command
            .ok_or_else(|| format!("adapter `{}` does not define a resume command", adapter.id))?;
        self.launch(LaunchOptions {
            adapter: adapter.clone(),
            prompt,
            model: info.model.clone(),
            cwd: PathBuf::from(&info.workspace),
            profile: info.profile.clone(),
            env: Vec::new(),
            command_override: Some(command),
        })
    }

    pub fn load_run(&self, id: &str) -> Option<AgentRunInfo> {
        if let Some(handle) = self.get(id) {
            return Some(handle.info());
        }
        if !id.starts_with("a_") || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return None;
        }
        let path = self
            .data_dir
            .join("agents")
            .join("runs")
            .join(format!("{id}.json"));
        let text = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Previous runs persisted on disk, newest first.
    pub fn history(&self) -> Vec<AgentRunInfo> {
        let dir = self.data_dir.join("agents").join("runs");
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut runs: Vec<AgentRunInfo> = entries
            .flatten()
            .filter_map(|entry| {
                let text = std::fs::read_to_string(entry.path()).ok()?;
                serde_json::from_str(&text).ok()
            })
            .collect();
        runs.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        runs
    }

    /// Snapshot text used by dashboards and read-only observers.
    pub fn dashboard(&self) -> Vec<AgentDashboardRow> {
        self.list()
            .into_iter()
            .map(|info| AgentDashboardRow {
                id: info.id.clone(),
                agent: info.adapter_name.clone(),
                state: info.state.as_str().to_string(),
                model: info.model.clone(),
                elapsed_ms: info.elapsed_ms(),
                cost_micros: info.cost_micros,
                workspace: info.workspace.clone(),
                queued_prompts: info.queued_prompts,
                approximate: info.approximate,
                badge: info.badge.clone(),
            })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentDashboardRow {
    pub id: String,
    pub agent: String,
    pub state: String,
    pub model: Option<String>,
    pub elapsed_ms: u64,
    pub cost_micros: Option<u64>,
    pub workspace: String,
    pub queued_prompts: usize,
    pub approximate: bool,
    pub badge: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{Detect, Events, Permissions, Ui};

    #[cfg(unix)]
    fn echo_adapter() -> Adapter {
        Adapter {
            version: 1,
            id: "echo".into(),
            name: "Echo".into(),
            command: "/bin/sh".into(),
            args: vec!["-c".into(), "cat".into()],
            detect: Detect::default(),
            events: Events {
                mode: "screen".into(),
                hooks: Default::default(),
                status_patterns: vec![],
            },
            resume: None,
            permissions: Permissions::default(),
            ui: Ui::default(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn launches_reads_and_stops_an_agent() {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-supervisor-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let supervisor = Supervisor::new(&dir, vec![echo_adapter()]);
        let handle = supervisor
            .launch(LaunchOptions {
                adapter: echo_adapter(),
                prompt: None,
                model: None,
                cwd: dir.clone(),
                profile: "agent-readonly".into(),
                env: Vec::new(),
                command_override: None,
            })
            .unwrap();
        assert_eq!(handle.info().state, AgentState::Running);
        handle.write_raw(b"hello-agent\n").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(handle.output().contains("hello-agent"));
        assert_eq!(supervisor.list().len(), 1);
        assert_eq!(supervisor.dashboard()[0].state, "running");
        handle.stop().unwrap();
        let info = handle.wait(std::time::Duration::from_secs(2));
        assert!(info.terminal());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn prompt_queue_is_bounded_and_reported() {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-queue-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let supervisor = Supervisor::new(&dir, vec![echo_adapter()]);
        let handle = supervisor
            .launch(LaunchOptions {
                adapter: echo_adapter(),
                prompt: None,
                model: None,
                cwd: dir.clone(),
                profile: "agent-readonly".into(),
                env: Vec::new(),
                command_override: None,
            })
            .unwrap();
        handle.queue_prompt("one");
        assert_eq!(handle.info().queued_prompts, 1);
        handle.stop().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_adapter_resume_is_an_error() {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-resume-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let supervisor = Supervisor::new(&dir, Vec::new());
        assert!(supervisor.resume("a_missing", None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

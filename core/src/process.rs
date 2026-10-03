//! Process abstraction (Phase 1 §10).
//!
//! Structured arguments only — never shell strings. Direct executable
//! invocation via `Command`; no shell unless explicitly requested by a safe
//! API (deliberately NOT provided in Phase 1).

use crate::error::{Area, ZenError, ZenResult};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ProcessRequest {
    /// Executable name or absolute path. Prefer absolute paths.
    pub program: String,
    /// Structured arguments (no shell interpretation).
    pub args: Vec<String>,
    pub working_dir: Option<PathBuf>,
    /// Additional environment variables (merged over inherited env).
    pub env: HashMap<String, String>,
    /// Environment variables to explicitly remove (secret hygiene).
    pub env_remove: Vec<String>,
    pub stdin: Option<String>,
    pub timeout: Option<Duration>,
}

impl ProcessRequest {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            working_dir: None,
            env: HashMap::new(),
            env_remove: Vec::new(),
            stdin: None,
            timeout: Some(Duration::from_secs(60)),
        }
    }

    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    pub fn args<I: IntoIterator<Item = S>, S: Into<String>>(mut self, args: I) -> Self {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn working_dir(mut self, d: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(d.into());
        self
    }

    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = Some(t);
        self
    }
}

#[derive(Debug)]
pub struct ProcessResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub duration: Duration,
}

/// Default secret hygiene: never pass these to child processes unless
/// explicitly overridden by the caller's env map.
const ALWAYS_REMOVE: &[&str] = &["ZENTRION_SECRET", "SSH_AUTH_SOCK"];

pub struct ProcessRunner;

impl ProcessRunner {
    /// Execute without a shell. Args are passed verbatim.
    pub fn run(req: &ProcessRequest) -> ZenResult<ProcessResult> {
        let start = Instant::now();

        let mut cmd = Command::new(&req.program);
        cmd.args(&req.args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.stdin(Stdio::null());

        if let Some(d) = &req.working_dir {
            if !d.is_dir() {
                return Err(ZenError::new(
                    Area::Pr,
                    5010,
                    format!("working directory does not exist: {}", d.display()),
                ));
            }
            cmd.current_dir(d);
        }

        // Secret hygiene: strip sensitive vars first, then apply additions.
        for var in ALWAYS_REMOVE {
            cmd.env_remove(var);
        }
        for var in &req.env_remove {
            cmd.env_remove(var);
        }
        for (k, v) in &req.env {
            cmd.env(k, v);
        }

        let mut child = cmd.spawn().map_err(|e| {
            ZenError::new(
                Area::Pr,
                5011,
                format!("failed to start {}: {e}", req.program),
            )
            .with_remediation("Check that the program exists and is executable.")
        })?;

        let timeout = req.timeout.unwrap_or(Duration::from_secs(60));

        // Take stdout/stderr handles so we can read after exit.
        let mut stdout_pipe = child.stdout.take();
        let mut stderr_pipe = child.stderr.take();

        // Poll for exit within timeout (std has no wait_timeout).
        let poll = Duration::from_millis(25);
        let mut exit_status = None;
        while start.elapsed() < timeout {
            match child.try_wait() {
                Ok(Some(st)) => {
                    exit_status = Some(st);
                    break;
                }
                Ok(None) => std::thread::sleep(poll),
                Err(e) => {
                    let _ = child.kill();
                    return Err(ZenError::new(Area::Pr, 5012, format!("process error: {e}")));
                }
            }
        }

        let (timed_out, exit_code) = match exit_status {
            Some(st) => (false, st.code().unwrap_or(-1)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                (true, -1)
            }
        };

        use std::io::Read;
        let mut out = String::new();
        if let Some(p) = &mut stdout_pipe {
            let _ = p.read_to_string(&mut out);
        }
        let mut err_out = String::new();
        if let Some(p) = &mut stderr_pipe {
            let _ = p.read_to_string(&mut err_out);
        }

        Ok(ProcessResult {
            exit_code,
            stdout: out,
            stderr: err_out,
            timed_out,
            duration: start.elapsed(),
        })
    }
}

impl ProcessResult {
    pub fn success(&self) -> bool {
        self.exit_code == 0 && !self.timed_out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_command() {
        let r = ProcessRunner::run(&ProcessRequest::new("echo").arg("hello")).unwrap();
        assert!(r.success());
        assert_eq!(r.stdout.trim(), "hello");
    }

    #[test]
    fn args_are_verbatim_no_shell_interpretation() {
        // If this went through a shell, `; echo pwned` would execute.
        let r = ProcessRunner::run(&ProcessRequest::new("echo").arg("hello; echo pwned")).unwrap();
        assert_eq!(r.stdout.trim(), "hello; echo pwned");
    }

    #[test]
    fn metacharacters_are_literal() {
        let r = ProcessRunner::run(&ProcessRequest::new("echo").arg("$HOME && rm -rf /")).unwrap();
        assert_eq!(r.stdout.trim(), "$HOME && rm -rf /");
    }

    #[test]
    fn quotes_newlines_unicode_preserved() {
        let r = ProcessRunner::run(
            &ProcessRequest::new("echo").arg("a \"quoted\" 'string'\nsecond line — ünïcode 日本語"),
        )
        .unwrap();
        assert!(r.stdout.contains("a \"quoted\" 'string'"));
        assert!(r.stdout.contains("second line — ünïcode 日本語"));
    }

    #[test]
    fn missing_program_errors() {
        assert!(
            ProcessRunner::run(&ProcessRequest::new("definitely-not-a-real-binary-xyz")).is_err()
        );
    }

    #[test]
    fn timeout_kills_process() {
        let r = ProcessRunner::run(
            &ProcessRequest::new("sleep")
                .arg("10")
                .timeout(Duration::from_millis(200)),
        )
        .unwrap();
        assert!(r.timed_out);
        assert!(!r.success());
    }

    #[test]
    fn exit_code_propagated() {
        if cfg!(not(target_os = "windows")) {
            let r = ProcessRunner::run(&ProcessRequest::new("false")).unwrap();
            assert_eq!(r.exit_code, 1);
        }
    }

    #[test]
    fn secret_env_stripped() {
        let mut req = ProcessRequest::new("sh")
            .arg("-c")
            .arg("echo ${ZENTRION_SECRET:-absent}");
        req.timeout = Some(Duration::from_secs(5));
        let r = ProcessRunner::run(&req).unwrap();
        assert!(r.stdout.contains("absent"));
    }

    #[test]
    fn explicit_env_applied() {
        let mut env = HashMap::new();
        env.insert("ZEN_TEST_VAR".to_string(), "zen-value".to_string());
        let mut req = ProcessRequest::new("sh")
            .arg("-c")
            .arg("echo $ZEN_TEST_VAR");
        req.env = env;
        req.timeout = Some(Duration::from_secs(5));
        let r = ProcessRunner::run(&req).unwrap();
        assert_eq!(r.stdout.trim(), "zen-value");
    }

    #[test]
    fn missing_working_dir_fails() {
        let req = ProcessRequest::new("echo").working_dir("/nonexistent-dir-xyz/..");
        assert!(ProcessRunner::run(&req).is_err());
    }
}

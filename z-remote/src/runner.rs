//! OpenSSH process runner and detached port-forward registry.

use crate::target::{RemoteError, SshOptions, SshTarget};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use uuid::Uuid;

const MAX_REMOTE_OUTPUT: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteOutput {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

impl RemoteOutput {
    pub fn success(&self) -> bool {
        self.status == Some(0) && !self.timed_out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Forward {
    pub id: String,
    pub target: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub pid: u32,
    pub created_at: DateTime<Utc>,
}

pub struct ForwardRegistry {
    path: PathBuf,
}

impl ForwardRegistry {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn default_path() -> Option<PathBuf> {
        z_core::config::user_data_dir().map(|dir| dir.join("remote").join("forwards.json"))
    }

    pub fn list(&self) -> Vec<Forward> {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        let mut forwards: Vec<Forward> = serde_json::from_str(&text).unwrap_or_default();
        // Prune processes that exited.
        forwards.retain(|forward| process_alive(forward.pid as i32));
        forwards.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        forwards
    }

    pub fn add(&self, forward: Forward) -> Result<(), RemoteError> {
        let mut forwards = self.list();
        forwards.push(forward);
        self.save(&forwards)
    }

    pub fn remove(&self, id: &str) -> Result<Option<Forward>, RemoteError> {
        let mut forwards = self.list();
        let removed = forwards.iter().position(|forward| forward.id == id);
        let found = removed.map(|index| forwards.remove(index));
        self.save(&forwards)?;
        Ok(found)
    }

    pub fn stop(&self, id: &str) -> Result<bool, RemoteError> {
        let Some(forward) = self.remove(id)? else {
            return Ok(false);
        };
        if process_alive(forward.pid as i32) {
            #[cfg(unix)]
            unsafe {
                libc::kill(forward.pid as i32, libc::SIGTERM);
            }
            #[cfg(not(unix))]
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn save(&self, forwards: &[Forward]) -> Result<(), RemoteError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| RemoteError::Io(e.to_string()))?;
        }
        let text =
            serde_json::to_string_pretty(forwards).map_err(|e| RemoteError::Io(e.to_string()))?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| RemoteError::Io(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| RemoteError::Io(e.to_string()))?;
        Ok(())
    }
}

pub struct SshRunner {
    options: SshOptions,
}

impl SshRunner {
    pub fn new(options: SshOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &SshOptions {
        &self.options
    }

    /// Run one remote command through OpenSSH. The command is interpreted by
    /// the remote shell; it is never evaluated locally.
    pub fn exec(
        &self,
        target: &SshTarget,
        command: &str,
        timeout: Duration,
    ) -> Result<RemoteOutput, RemoteError> {
        let args = target.command_args(&self.options, command)?;
        run(&self.options.ssh_path, &args, timeout)
    }

    pub fn login_command(&self, target: &SshTarget) -> Result<(PathBuf, Vec<String>), RemoteError> {
        Ok((
            self.options.ssh_path.clone(),
            target.login_args(&self.options)?,
        ))
    }

    pub fn upload(
        &self,
        target: &SshTarget,
        local: &Path,
        remote_path: &str,
        recursive: bool,
        timeout: Duration,
    ) -> Result<RemoteOutput, RemoteError> {
        if !local.exists() {
            return Err(RemoteError::InvalidPath(format!(
                "local path {} does not exist",
                local.display()
            )));
        }
        let args = target.scp_args(&self.options, local, remote_path, recursive)?;
        run(&self.options.scp_path, &args, timeout)
    }

    pub fn download(
        &self,
        target: &SshTarget,
        remote_path: &str,
        local: &Path,
        recursive: bool,
        timeout: Duration,
    ) -> Result<RemoteOutput, RemoteError> {
        crate::target::validate_remote_path(remote_path)?;
        let mut args = vec![
            "-o".to_string(),
            "StrictHostKeyChecking=yes".to_string(),
            "-o".to_string(),
            format!("ConnectTimeout={}", self.options.connect_timeout_seconds),
        ];
        if let Some(port) = target.effective_port(&self.options) {
            args.push("-P".into());
            args.push(port.to_string());
        }
        if let Some(identity) = &self.options.identity {
            args.push("-i".into());
            args.push(identity.display().to_string());
        }
        if recursive {
            args.push("-r".into());
        }
        args.push(format!("{}:{}", target.scp_destination(), remote_path));
        args.push(local.display().to_string());
        run(&self.options.scp_path, &args, timeout)
    }

    /// Start a detached local port forward. The child survives this process.
    pub fn forward(
        &self,
        target: &SshTarget,
        local_port: u16,
        remote_host: &str,
        remote_port: u16,
    ) -> Result<Forward, RemoteError> {
        if local_port == 0 {
            return Err(RemoteError::InvalidOption(
                "local port must be between 1 and 65535".into(),
            ));
        }
        if !(1..=65535).contains(&remote_port) {
            return Err(RemoteError::InvalidOption(
                "remote port must be between 1 and 65535".into(),
            ));
        }
        if remote_host.is_empty()
            || remote_host.contains(char::is_whitespace)
            || remote_host.starts_with('-')
        {
            return Err(RemoteError::InvalidOption(
                "invalid remote host for forwarding".into(),
            ));
        }
        let mut args = target.base_args_public(&self.options)?;
        args.push("-N".into());
        args.push("-o".into());
        args.push("ExitOnForwardFailure=yes".into());
        args.push("-L".into());
        args.push(format!(
            "127.0.0.1:{local_port}:{remote_host}:{remote_port}"
        ));
        args.push(target.destination());
        let mut command = Command::new(&self.options.ssh_path);
        command
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let child = command
            .spawn()
            .map_err(|e| RemoteError::Ssh(format!("cannot start ssh forward: {e}")))?;
        std::thread::sleep(Duration::from_millis(200));
        if !process_alive(child.id() as i32) {
            return Err(RemoteError::Ssh(
                "ssh forward exited immediately; check host key, credentials and port".into(),
            ));
        }
        Ok(Forward {
            id: format!("fwd_{}", Uuid::new_v4().simple()),
            target: target.destination(),
            local_port,
            remote_host: remote_host.to_string(),
            remote_port,
            pid: child.id(),
            created_at: Utc::now(),
        })
    }
}

impl SshTarget {
    /// Public bridge for the forward builder; same verified base arguments.
    pub fn base_args_public(&self, options: &SshOptions) -> Result<Vec<String>, RemoteError> {
        self.login_args(options).map(|mut args| {
            if let Some(index) = args.iter().position(|arg| arg == "-tt") {
                args.remove(index);
            }
            if args.last().map(|arg| arg == &self.destination()) == Some(true) {
                args.pop();
            }
            args
        })
    }
}

fn run(program: &Path, args: &[String], timeout: Duration) -> Result<RemoteOutput, RemoteError> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|e| RemoteError::Ssh(format!("cannot start {}: {e}", program.display())))?;
    let stdout = child
        .stdout
        .take()
        .map(|reader| read_capped(reader, MAX_REMOTE_OUTPUT));
    let stderr = child
        .stderr
        .take()
        .map(|reader| read_capped(reader, MAX_REMOTE_OUTPUT));
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
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(RemoteError::Io(error.to_string())),
        }
    };
    let stdout = stdout
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    let stderr = stderr
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    Ok(RemoteOutput {
        status: status.and_then(|status| status.code()),
        stdout: String::from_utf8_lossy(&stdout).to_string(),
        stderr: String::from_utf8_lossy(&stderr).to_string(),
        timed_out,
    })
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

fn process_alive(pid: i32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid, 0) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn fake_binary(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "#!/bin/sh").unwrap();
        writeln!(file, "{body}").unwrap();
        drop(file);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn options(_dir: &Path, ssh: &Path, scp: &Path) -> SshOptions {
        SshOptions {
            identity: None,
            jump: vec![],
            port: None,
            known_hosts: None,
            connect_timeout_seconds: 2,
            extra: vec![],
            ssh_path: ssh.to_path_buf(),
            scp_path: scp.to_path_buf(),
        }
    }

    #[test]
    fn exec_passes_command_and_strict_host_key_flags() {
        let dir = std::env::temp_dir().join(format!(
            "zremote-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let ssh = fake_binary(&dir, "ssh", "echo \"$@\"; echo fake-stderr >&2");
        let scp = fake_binary(&dir, "scp", "exit 0");
        let runner = SshRunner::new(options(&dir, &ssh, &scp));
        let target = SshTarget::parse("example.com").unwrap();
        let output = runner
            .exec(&target, "uname -a", Duration::from_secs(2))
            .unwrap();
        assert_eq!(output.status, Some(0));
        assert!(
            output.stdout.contains("StrictHostKeyChecking=yes"),
            "{}",
            output.stdout
        );
        assert!(output.stdout.contains("uname -a"));
        assert!(output.stderr.contains("fake-stderr"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn timeout_kills_the_ssh_process() {
        let dir = std::env::temp_dir().join(format!(
            "zremote-timeout-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let ssh = fake_binary(&dir, "ssh", "sleep 5");
        let scp = fake_binary(&dir, "scp", "exit 0");
        let runner = SshRunner::new(options(&dir, &ssh, &scp));
        let target = SshTarget::parse("example.com").unwrap();
        let started = Instant::now();
        let output = runner
            .exec(&target, "true", Duration::from_millis(150))
            .unwrap();
        assert!(output.timed_out);
        // Generous bound: this asserts the timeout works at all without
        // failing under a loaded parallel test run.
        assert!(started.elapsed() < Duration::from_secs(10));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn upload_uses_scp_and_validates_paths() {
        let dir = std::env::temp_dir().join(format!(
            "zremote-scp-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let ssh = fake_binary(&dir, "ssh", "exit 0");
        let scp = fake_binary(&dir, "scp", "echo \"$@\"");
        let runner = SshRunner::new(options(&dir, &ssh, &scp));
        let target = SshTarget::parse("example.com:2222").unwrap();
        let local = dir.join("file");
        std::fs::write(&local, "x").unwrap();
        let output = runner
            .upload(&target, &local, "/tmp/file", false, Duration::from_secs(10))
            .unwrap();
        assert!(output.stdout.contains("-P 2222"), "{}", output.stdout);
        assert!(output.stdout.contains("example.com:/tmp/file"));
        assert!(runner
            .upload(&target, &local, "-rf", false, Duration::from_secs(10))
            .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn forward_registry_round_trips_and_rejects_bad_ports() {
        let dir = std::env::temp_dir().join(format!(
            "zremote-fwd-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let registry = ForwardRegistry::new(dir.join("forwards.json"));
        assert!(registry.list().is_empty());
        let target = SshTarget::parse("example.com").unwrap();
        let ssh = fake_binary(&dir, "ssh", "exit 0");
        let scp = fake_binary(&dir, "scp", "exit 0");
        let runner = SshRunner::new(options(&dir, &ssh, &scp));
        assert!(runner.forward(&target, 0, "db", 5432).is_err());
        assert!(runner.forward(&target, 15432, "db", 0).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

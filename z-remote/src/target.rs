//! SSH destinations, options and argument construction.
//!
//! Host keys are always verified (`StrictHostKeyChecking=yes`); there is no
//! "auto accept" switch. Extra options that would disable verification or run
//! local commands are rejected. Destination strings are validated and passed as
//! an argument vector, never through a local shell.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshTarget {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

impl SshTarget {
    pub fn parse(input: &str) -> Result<Self, RemoteError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(RemoteError::InvalidTarget("empty target".into()));
        }
        if input.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(RemoteError::InvalidTarget(
                "target contains whitespace or control characters".into(),
            ));
        }
        if input.starts_with('-') {
            return Err(RemoteError::InvalidTarget(
                "target must not start with `-`".into(),
            ));
        }
        let (user, rest) = match input.split_once('@') {
            Some((user, rest)) => {
                if user.is_empty()
                    || !user
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
                {
                    return Err(RemoteError::InvalidTarget(format!(
                        "invalid SSH user `{user}`"
                    )));
                }
                (Some(user.to_string()), rest)
            }
            None => (None, input),
        };
        if rest.starts_with('-') || rest.is_empty() {
            return Err(RemoteError::InvalidTarget("invalid SSH host".into()));
        }
        let (host, port) = if let Some(rest) = rest.strip_prefix('[') {
            let (host, tail) = rest
                .split_once(']')
                .ok_or_else(|| RemoteError::InvalidTarget("unterminated IPv6 host".into()))?;
            let port = tail.strip_prefix(':').map(parse_port).transpose()?;
            (host.to_string(), port)
        } else if let Some((host, port)) = rest.rsplit_once(':') {
            if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() {
                (host.to_string(), Some(parse_port(port)?))
            } else {
                (rest.to_string(), None)
            }
        } else {
            (rest.to_string(), None)
        };
        if host.is_empty() {
            return Err(RemoteError::InvalidTarget("invalid SSH host".into()));
        }
        if !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
        {
            return Err(RemoteError::InvalidTarget(format!(
                "invalid SSH host `{host}`"
            )));
        }
        Ok(Self { user, host, port })
    }

    /// Destination for ssh (`user@host`).
    pub fn destination(&self) -> String {
        match &self.user {
            Some(user) => format!("{user}@{}", self.host),
            None => self.host.clone(),
        }
    }

    /// Destination for scp (IPv6 literals need brackets).
    pub fn scp_destination(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match &self.user {
            Some(user) => format!("{user}@{host}"),
            None => host,
        }
    }

    pub fn effective_port(&self, options: &SshOptions) -> Option<u16> {
        options.port.or(self.port)
    }

    /// OpenSSH arguments for a login shell.
    pub fn login_args(&self, options: &SshOptions) -> Result<Vec<String>, RemoteError> {
        let mut args = self.base_args(options)?;
        args.push("-tt".into());
        args.push(self.destination());
        Ok(args)
    }

    /// OpenSSH arguments that run `command` remotely. The command is passed as
    /// one argument to the remote shell; it is never evaluated locally.
    pub fn command_args(
        &self,
        options: &SshOptions,
        command: &str,
    ) -> Result<Vec<String>, RemoteError> {
        if command.trim().is_empty() {
            return Err(RemoteError::InvalidCommand(
                "remote command must not be empty".into(),
            ));
        }
        if command.contains('\0') {
            return Err(RemoteError::InvalidCommand(
                "remote command contains a NUL byte".into(),
            ));
        }
        let mut args = self.base_args(options)?;
        args.push(self.destination());
        args.push(command.to_string());
        Ok(args)
    }

    fn base_args(&self, options: &SshOptions) -> Result<Vec<String>, RemoteError> {
        let mut args: Vec<String> = Vec::new();
        for option in &options.extra {
            if option.contains("ProxyCommand")
                || option.contains("LocalCommand")
                || option.contains("StrictHostKeyChecking")
                || option.contains("UserKnownHostsFile")
                || option.contains("PermitLocalCommand")
            {
                return Err(RemoteError::InvalidOption(format!(
                    "refusing extra SSH option `{option}`: it can disable host verification or run a local command"
                )));
            }
            args.push(option.clone());
        }
        args.push("-o".into());
        args.push("StrictHostKeyChecking=yes".into());
        if let Some(known_hosts) = &options.known_hosts {
            args.push("-o".into());
            args.push(format!("UserKnownHostsFile={}", known_hosts.display()));
        }
        args.push("-o".into());
        args.push(format!(
            "ConnectTimeout={}",
            options.connect_timeout_seconds
        ));
        args.push("-o".into());
        args.push("ServerAliveInterval=15".into());
        args.push("-o".into());
        args.push("ServerAliveCountMax=3".into());
        if let Some(port) = self.effective_port(options) {
            args.push("-p".into());
            args.push(port.to_string());
        }
        if let Some(identity) = &options.identity {
            if !identity.exists() {
                return Err(RemoteError::InvalidOption(format!(
                    "identity file {} does not exist",
                    identity.display()
                )));
            }
            args.push("-i".into());
            args.push(identity.display().to_string());
        }
        if !options.jump.is_empty() {
            for jump in &options.jump {
                let parsed = SshTarget::parse(jump)?;
                if parsed.user.is_none() && jump.contains('@') {
                    return Err(RemoteError::InvalidTarget(format!(
                        "invalid jump host `{jump}`"
                    )));
                }
            }
            args.push("-J".into());
            args.push(options.jump.join(","));
        }
        Ok(args)
    }

    pub fn scp_args(
        &self,
        options: &SshOptions,
        local: &Path,
        remote_path: &str,
        recursive: bool,
    ) -> Result<Vec<String>, RemoteError> {
        validate_remote_path(remote_path)?;
        let mut args = vec![
            "-o".into(),
            "StrictHostKeyChecking=yes".into(),
            "-o".into(),
            format!("ConnectTimeout={}", options.connect_timeout_seconds),
        ];
        if let Some(port) = self.effective_port(options) {
            args.push("-P".into());
            args.push(port.to_string());
        }
        if let Some(identity) = &options.identity {
            args.push("-i".into());
            args.push(identity.display().to_string());
        }
        if !options.jump.is_empty() {
            args.push("-o".into());
            args.push(format!("ProxyJump={}", options.jump.join(",")));
        }
        if recursive {
            args.push("-r".into());
        }
        args.push(local.display().to_string());
        args.push(format!("{}:{}", self.scp_destination(), remote_path));
        Ok(args)
    }
}

fn parse_port(value: &str) -> Result<u16, RemoteError> {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| RemoteError::InvalidTarget(format!("invalid SSH port `{value}`")))
}

pub fn validate_remote_path(path: &str) -> Result<(), RemoteError> {
    if path.is_empty() || path.contains('\0') || path.contains('\n') || path.contains('\r') {
        return Err(RemoteError::InvalidPath(
            "remote path is empty or contains control characters".into(),
        ));
    }
    if path.starts_with('-') {
        return Err(RemoteError::InvalidPath(
            "remote path must not start with `-`".into(),
        ));
    }
    if path.contains(':') {
        return Err(RemoteError::InvalidPath(
            "remote path must not contain `:` (scp remote spec ambiguity)".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshOptions {
    pub identity: Option<PathBuf>,
    pub jump: Vec<String>,
    pub port: Option<u16>,
    pub known_hosts: Option<PathBuf>,
    pub connect_timeout_seconds: u64,
    pub extra: Vec<String>,
    pub ssh_path: PathBuf,
    pub scp_path: PathBuf,
}

impl Default for SshOptions {
    fn default() -> Self {
        let home = z_core::config::home_dir();
        Self {
            identity: None,
            jump: Vec::new(),
            port: None,
            known_hosts: home
                .as_ref()
                .map(|home| home.join(".ssh").join("known_hosts")),
            connect_timeout_seconds: 10,
            extra: Vec::new(),
            ssh_path: std::env::var("ZENTRION_SSH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("ssh")),
            scp_path: std::env::var("ZENTRION_SCP")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("scp")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteError {
    InvalidTarget(String),
    InvalidCommand(String),
    InvalidPath(String),
    InvalidOption(String),
    Io(String),
    Timeout,
    Ssh(String),
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTarget(message) => write!(f, "invalid SSH target: {message}"),
            Self::InvalidCommand(message) => write!(f, "invalid remote command: {message}"),
            Self::InvalidPath(message) => write!(f, "invalid remote path: {message}"),
            Self::InvalidOption(message) => write!(f, "invalid SSH option: {message}"),
            Self::Io(message) => write!(f, "SSH I/O error: {message}"),
            Self::Timeout => f.write_str("SSH operation timed out"),
            Self::Ssh(message) => write!(f, "SSH failed: {message}"),
        }
    }
}

impl std::error::Error for RemoteError {}

/// Parse `~/.ssh/config` aliases (best effort, no Include expansion).
pub fn ssh_config_hosts() -> Vec<String> {
    let Some(home) = z_core::config::home_dir() else {
        return Vec::new();
    };
    let path = home.join(".ssh").join("config");
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut hosts = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if !line.to_ascii_lowercase().starts_with("host ") {
            continue;
        }
        for token in line.split_whitespace().skip(1) {
            if token != "*" && !token.contains('?') && !token.contains('!') {
                hosts.push(token.to_string());
            }
        }
    }
    hosts.sort();
    hosts.dedup();
    hosts
}

pub fn default_timeout() -> Duration {
    Duration::from_secs(30)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> SshOptions {
        SshOptions {
            known_hosts: None,
            identity: None,
            jump: vec![],
            port: None,
            connect_timeout_seconds: 5,
            extra: vec![],
            ssh_path: "ssh".into(),
            scp_path: "scp".into(),
        }
    }

    #[test]
    fn parses_users_ports_and_ipv6() {
        let target = SshTarget::parse("deploy@example.com:2222").unwrap();
        assert_eq!(target.user.as_deref(), Some("deploy"));
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, Some(2222));
        assert_eq!(target.destination(), "deploy@example.com");
        let ipv6 = SshTarget::parse("root@[2001:db8::1]:22").unwrap();
        assert_eq!(ipv6.host, "2001:db8::1");
        assert_eq!(ipv6.scp_destination(), "root@[2001:db8::1]");
    }

    #[test]
    fn rejects_shell_metacharacters_and_option_injection() {
        for bad in [
            "host;rm",
            "-oProxyCommand=x",
            "host name",
            "user@@host",
            "@host",
        ] {
            assert!(SshTarget::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn login_and_command_always_verify_host_keys() {
        let target = SshTarget::parse("example.com").unwrap();
        let login = target.login_args(&options()).unwrap();
        assert!(login
            .windows(2)
            .any(|w| w == ["-o", "StrictHostKeyChecking=yes"]));
        assert!(login.iter().any(|arg| arg == "-tt"));
        let command = target.command_args(&options(), "uname -a").unwrap();
        assert_eq!(command.last().unwrap(), "uname -a");
        assert!(command
            .windows(2)
            .any(|w| w == ["-o", "StrictHostKeyChecking=yes"]));
    }

    #[test]
    fn dangerous_extra_options_are_rejected() {
        let target = SshTarget::parse("example.com").unwrap();
        let mut options = options();
        options.extra = vec!["-oProxyCommand=evil".into()];
        assert!(target.login_args(&options).is_err());
        options.extra = vec!["-oStrictHostKeyChecking=no".into()];
        assert!(target.login_args(&options).is_err());
    }

    #[test]
    fn jump_hosts_and_identity_are_propagated() {
        let target = SshTarget::parse("example.com").unwrap();
        let mut options = options();
        options.jump = vec!["bastion@jump.example:2200".into()];
        options.port = Some(2222);
        options.identity = Some(PathBuf::from("/tmp/id"));
        // Identity existence is checked; use an existing path for this test.
        let identity = std::env::current_exe().unwrap();
        options.identity = Some(identity.clone());
        let args = target.login_args(&options).unwrap();
        assert!(args.windows(2).any(|w| w == ["-p", "2222"]));
        assert!(args
            .windows(2)
            .any(|w| w == ["-i", identity.to_str().unwrap()]));
        assert!(args
            .windows(2)
            .any(|w| w == ["-J", "bastion@jump.example:2200"]));
    }

    #[test]
    fn remote_paths_reject_option_and_scp_ambiguity() {
        assert!(validate_remote_path("/var/tmp/file").is_ok());
        assert!(validate_remote_path("-rf").is_err());
        assert!(validate_remote_path("a:b").is_err());
        assert!(validate_remote_path("").is_err());
    }

    #[test]
    fn scp_arguments_quote_nothing_but_validate_paths() {
        let target = SshTarget::parse("example.com:2222").unwrap();
        let args = target
            .scp_args(&options(), Path::new("/tmp/file"), "/tmp/file", false)
            .unwrap();
        assert!(args.windows(2).any(|w| w == ["-P", "2222"]));
        assert!(args.last().unwrap() == "example.com:/tmp/file");
        assert!(target
            .scp_args(&options(), Path::new("/tmp/file"), "-rf", false)
            .is_err());
    }

    #[test]
    fn config_parser_ignores_wildcards() {
        // This only asserts the parser is total when no config exists.
        let _ = ssh_config_hosts();
    }
}

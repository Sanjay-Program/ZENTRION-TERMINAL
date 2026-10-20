//! Rust SDK for the Zentrion local daemon.
//!
//! The daemon speaks newline-delimited JSON over a loopback TCP socket. Every
//! request is policy-checked and audited server-side; the SDK cannot bypass
//! that path.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

pub const DEFAULT_ADDR: &str = "127.0.0.1:9099";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecRequest {
    #[serde(default)]
    pub id: Option<String>,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Sent automatically from ZENTRION_DAEMON_TOKEN when configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Metrics {
    #[serde(default)]
    pub cpu_usage: f64,
    #[serde(default)]
    pub memory_usage: u64,
    #[serde(default)]
    pub pid: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecResponse {
    pub status: String,
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub metrics: Option<Metrics>,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub error: Option<String>,
}

impl ExecResponse {
    pub fn is_ok(&self) -> bool {
        self.status == "ok" || self.status == "allowed"
    }
}

/// A client for the Zentrion daemon.
pub struct ZentrionClient {
    addr: String,
}

impl ZentrionClient {
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into() }
    }

    /// Default client (`127.0.0.1:9099`).
    pub fn local() -> Self {
        Self::new(DEFAULT_ADDR)
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Verify that a daemon is reachable and healthy.
    pub async fn connect(&self) -> Result<ExecResponse> {
        let response = self
            .send(ExecRequest {
                id: Some("sdk-connect".into()),
                command: "status".into(),
                args: Vec::new(),
                token: None,
            })
            .await
            .context("daemon is not reachable; start it with `z daemon start`")?;
        if !response.is_ok() {
            anyhow::bail!(
                "daemon health check failed: {}",
                response
                    .error
                    .clone()
                    .unwrap_or_else(|| response.status.clone())
            );
        }
        Ok(response)
    }

    /// Send one request. The connection is closed after the response, so a
    /// crashed daemon cannot leave a half-open stream behind.
    pub async fn send(&self, request: ExecRequest) -> Result<ExecResponse> {
        let request = ExecRequest {
            token: std::env::var("ZENTRION_DAEMON_TOKEN")
                .ok()
                .filter(|token| !token.is_empty())
                .or(request.token),
            ..request
        };
        let mut stream = TcpStream::connect(&self.addr)
            .await
            .with_context(|| format!("cannot connect to {}", self.addr))?;
        let mut data = serde_json::to_vec(&request)?;
        data.push(b'\n');
        stream.write_all(&data).await?;
        stream.flush().await?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            reader.read_line(&mut line),
        )
        .await
        .context("daemon request timed out")??;
        if read == 0 {
            anyhow::bail!("daemon closed the connection without a response");
        }
        let response: ExecResponse =
            serde_json::from_str(line.trim()).context("daemon returned invalid JSON")?;
        Ok(response)
    }

    /// Ask the daemon to stop accepting work and exit.
    pub async fn shutdown(&self) -> Result<ExecResponse> {
        self.send(ExecRequest {
            id: Some("sdk-shutdown".into()),
            command: "shutdown".into(),
            args: Vec::new(),
            token: None,
        })
        .await
    }

    /// Request brokered execution of `command`.
    pub async fn send_exec(&self, command: &str, args: &[String]) -> Result<ExecResponse> {
        self.send(ExecRequest {
            id: None,
            command: command.to_string(),
            args: args.to_vec(),
            token: None,
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_status_is_understood() {
        let response = ExecResponse {
            status: "ok".into(),
            request_id: "1".into(),
            metrics: None,
            stdout: String::new(),
            stderr: String::new(),
            exit_code: Some(0),
            error: None,
        };
        assert!(response.is_ok());
    }

    #[test]
    fn request_serializes_without_id() {
        let json = serde_json::to_string(&ExecRequest {
            id: None,
            command: "status".into(),
            args: vec![],
            token: None,
        })
        .unwrap();
        assert_eq!(json, r#"{"id":null,"command":"status","args":[]}"#);
    }
}

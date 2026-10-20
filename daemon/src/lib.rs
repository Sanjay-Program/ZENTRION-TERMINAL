//! Local IPC daemon for SDK clients.
//!
//! Requests are newline-delimited JSON. Execution is brokered exactly like the
//! CLI: identity -> policy -> risk -> broker -> audit. The daemon binds to
//! loopback only and never shells out.

use serde::{Deserialize, Serialize};

pub mod server;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    #[serde(default)]
    pub id: Option<String>,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Optional shared token. Required when ZENTRION_DAEMON_TOKEN is set.
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    pub cpu_usage: f64,
    pub memory_usage: u64,
    pub pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    pub status: String,
    pub request_id: String,
    pub metrics: Metrics,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub error: Option<String>,
}

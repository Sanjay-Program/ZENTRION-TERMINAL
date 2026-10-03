//! Execution Broker request/response types (29-API-SPEC v1).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    pub actor: ActorRef,
    /// e.g. "filesystem.write", "process.spawn", "network.connect"
    pub action: String,
    /// Scope expression: path glob, host:host:port, binary name...
    pub resource: String,
    /// Human-readable reason, shown in approval prompts and audit.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorRef {
    pub id: String,
    #[serde(rename = "type")]
    pub actor_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecStatus {
    Allowed,
    Denied,
    ApprovalRequired,
    Failed,
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    pub status: ExecStatus,
    pub request_id: String,
    pub audit_id: Option<String>,
    pub risk: String,
    pub reason: String,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub exit_code: Option<i32>,
    pub duration_ms: u128,
}

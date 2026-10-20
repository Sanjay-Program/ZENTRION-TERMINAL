//! Command block and session model.
//!
//! A block is the unit of command history, output, search, sharing, agent
//! context and audit. Every field has a deliberate source: shell integration
//! marks, the PTY, or the broker. Nothing is inferred from screen scraping
//! when hooks are available.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockStatus {
    /// Command line submitted, output not observed yet.
    Pending,
    Running,
    Ok,
    Failed,
    /// Interrupted (Ctrl+C) or the shell exited before reporting an exit code.
    Cancelled,
    /// Still running after the prompt returned (e.g. `cmd &`).
    Background,
}

impl BlockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Background => "background",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "pending" => Self::Pending,
            "running" => Self::Running,
            "ok" => Self::Ok,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            "background" => Self::Background,
            _ => return None,
        })
    }

    pub fn is_finished(self) -> bool {
        matches!(
            self,
            Self::Ok | Self::Failed | Self::Cancelled | Self::Background
        )
    }
}

impl std::fmt::Display for BlockStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub title: String,
    pub shell: String,
    pub cwd: String,
    pub created_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    pub status: String,
    pub workspace_id: Option<String>,
    pub agent_id: Option<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub id: String,
    pub session_id: String,
    pub seq: u64,
    pub command: String,
    pub cwd: String,
    pub shell: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub status: BlockStatus,
    pub duration_ms: Option<u64>,
    pub output_hash: Option<String>,
    pub output_bytes: Option<u64>,
    pub agent_id: Option<String>,
    pub policy_decision: Option<String>,
    pub approval_id: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub risk: Option<String>,
    pub parent_block_id: Option<String>,
}

impl Block {
    /// A stable, human-readable header: command · cwd · duration · exit.
    pub fn header(&self) -> String {
        let duration = self
            .duration_ms
            .map(|ms| {
                if ms >= 1000 {
                    format!("{:.1}s", ms as f64 / 1000.0)
                } else {
                    format!("{ms}ms")
                }
            })
            .unwrap_or_else(|| "running".to_string());
        let exit = match self.exit_code {
            Some(code) => format!("exit {code}"),
            None => self.status.to_string(),
        };
        format!("{} · {} · {} · {}", self.command, self.cwd, duration, exit)
    }

    pub fn is_failure(&self) -> bool {
        matches!(self.status, BlockStatus::Failed)
            || self.exit_code.map(|code| code != 0).unwrap_or(false)
    }
}

/// A block plus the matching text snippet from a full-text search.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockSearchHit {
    pub block: Block,
    pub snippet: String,
    pub rank: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockFilter {
    pub session_id: Option<String>,
    pub status: Option<BlockStatus>,
    pub exit_nonzero: bool,
    pub cwd: Option<String>,
    pub agent_id: Option<String>,
    pub tag: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreStats {
    pub sessions: u64,
    pub blocks: u64,
    pub output_bytes: u64,
    pub oldest: Option<DateTime<Utc>>,
    pub newest: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(status: BlockStatus, exit: Option<i32>) -> Block {
        Block {
            id: "b1".into(),
            session_id: "s1".into(),
            seq: 1,
            command: "cargo test".into(),
            cwd: "/repo".into(),
            shell: "bash".into(),
            started_at: Utc::now(),
            ended_at: None,
            exit_code: exit,
            status,
            duration_ms: Some(18422),
            output_hash: None,
            output_bytes: None,
            agent_id: None,
            policy_decision: None,
            approval_id: None,
            tags: vec![],
            risk: None,
            parent_block_id: None,
        }
    }

    #[test]
    fn header_is_informative() {
        let header = block(BlockStatus::Failed, Some(101)).header();
        assert!(header.contains("cargo test"));
        assert!(header.contains("18.4s"));
        assert!(header.contains("exit 101"));
    }

    #[test]
    fn failure_detection_uses_status_or_exit() {
        assert!(block(BlockStatus::Failed, Some(1)).is_failure());
        assert!(block(BlockStatus::Ok, Some(2)).is_failure());
        assert!(!block(BlockStatus::Ok, Some(0)).is_failure());
    }
}

use serde::{Deserialize, Serialize};

/// The Universal Result Format for all tools (Phase 2).
/// This allows AI models to predictably parse findings and evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniversalResult {
    pub tool: String,
    pub status: String,
    pub findings: Vec<serde_json::Value>,
    pub evidence: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_stdout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_stderr: Option<String>,
}

impl UniversalResult {
    pub fn new(tool: &str, status: &str) -> Self {
        Self {
            tool: tool.to_string(),
            status: status.to_string(),
            findings: Vec::new(),
            evidence: Vec::new(),
            raw_stdout: None,
            raw_stderr: None,
        }
    }

    pub fn with_stdout(mut self, stdout: &str) -> Self {
        self.raw_stdout = Some(stdout.to_string());
        self
    }

    pub fn with_stderr(mut self, stderr: &str) -> Self {
        self.raw_stderr = Some(stderr.to_string());
        self
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

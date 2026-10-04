use serde::{Deserialize, Serialize};

pub mod server;

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecRequest {
    pub command: String,
    pub args: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Metrics {
    pub cpu_usage: f64,
    pub memory_usage: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecResult {
    pub status: String,
    pub request_id: String,
    pub metrics: Metrics,
}

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ExecRequest {
    pub command: String,
    pub args: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ExecResponse {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

/// A client for connecting to the Zentrion daemon via local IPC 
/// (Unix domain sockets on Linux, Named Pipes on Windows).
pub struct ZentrionClient {
    #[allow(dead_code)]
    socket_path: String,
}

impl ZentrionClient {
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
        }
    }

    pub async fn connect(&self) -> Result<()> {
        // TODO: Implement actual connection (Unix Domain Socket / Named Pipe)
        Ok(())
    }

    pub async fn send_exec(&self, _req: ExecRequest) -> Result<ExecResponse> {
        // TODO: Implement actual sending of the request
        Ok(ExecResponse {
            status: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    }
}

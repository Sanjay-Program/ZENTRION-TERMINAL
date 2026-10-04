use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

pub struct McpGateway {
    child: Child,
}

impl McpGateway {
    pub fn connect(command: &str, args: &[String]) -> Result<Self> {
        let child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
            
        Ok(Self { child })
    }
    
    pub async fn send_request(&mut self, req: JsonRpcRequest) -> Result<()> {
        if let Some(stdin) = self.child.stdin.as_mut() {
            let mut data = serde_json::to_vec(&req)?;
            data.push(b'\n');
            stdin.write_all(&data).await?;
        }
        Ok(())
    }
    
    pub async fn receive_response(&mut self) -> Result<Option<JsonRpcResponse>> {
        if let Some(stdout) = self.child.stdout.as_mut() {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            let bytes_read = reader.read_line(&mut line).await?;
            if bytes_read == 0 {
                return Ok(None);
            }
            let res: JsonRpcResponse = serde_json::from_str(&line)?;
            return Ok(Some(res));
        }
        Ok(None)
    }
}

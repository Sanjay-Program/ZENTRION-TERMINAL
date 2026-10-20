//! Model Context Protocol client.
//!
//! Speaks newline-delimited JSON-RPC 2.0 over the server's stdio, performs the
//! `initialize` handshake and lists tools. Responses are matched by id, so
//! server notifications cannot be mistaken for a reply.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, rename = "inputSchema")]
    pub input_schema: Value,
}

pub struct McpGateway {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    next_id: u64,
}

impl McpGateway {
    /// Start an MCP server and prepare the JSON-RPC pipe.
    ///
    /// The child inherits stderr so server diagnostics remain visible to the
    /// user; stdout is reserved for protocol frames.
    pub fn connect(command: &str, args: &[String]) -> Result<Self> {
        if command.trim().is_empty() {
            return Err(anyhow!("MCP command cannot be empty"));
        }
        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("could not start MCP server `{command}`"))?;

        let stdin = child.stdin.take();
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("MCP server has no stdout"))?;
        let (tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name("zentrion-mcp-reader".into())
            .spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    match line {
                        Ok(line) if !line.trim().is_empty() => {
                            if tx.send(line).is_err() {
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            })
            .context("could not start the MCP reader thread")?;

        Ok(Self {
            child,
            stdin,
            lines: rx,
            next_id: 0,
        })
    }

    fn write_line(&mut self, value: &Value) -> Result<()> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("MCP server stdin is closed"))?;
        let mut data = serde_json::to_vec(value)?;
        data.push(b'\n');
        stdin.write_all(&data)?;
        stdin.flush()?;
        Ok(())
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<()> {
        self.write_line(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }))
    }

    /// Send a request and wait for the response with the matching id.
    pub fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        self.next_id += 1;
        let id = self.next_id;
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        self.write_line(&request)?;

        let deadline = Instant::now() + REQUEST_TIMEOUT;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| anyhow!("MCP request `{method}` timed out"))?;
            let line = self
                .lines
                .recv_timeout(remaining)
                .map_err(|_| anyhow!("MCP request `{method}` timed out"))?;
            let value: Value = serde_json::from_str(&line)
                .with_context(|| format!("MCP server sent invalid JSON: {line}"))?;

            // Ignore unrelated notifications and responses.
            if value.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(error) = value.get("error") {
                return Err(anyhow!("MCP error: {error}"));
            }
            return Ok(value.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    /// Perform the MCP initialize handshake and send `notifications/initialized`.
    pub fn initialize(&mut self, client_name: &str, version: &str) -> Result<Value> {
        let result = self.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": client_name, "version": version },
            }),
        )?;
        self.notify("notifications/initialized", json!({}))?;
        Ok(result)
    }

    pub fn list_tools(&mut self) -> Result<Vec<McpTool>> {
        let result = self.request("tools/list", json!({}))?;
        let tools = result
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        tools
            .into_iter()
            .map(|tool| {
                serde_json::from_value(tool).context("MCP server returned an invalid tool entry")
            })
            .collect()
    }

    /// Send a tools/call request.
    pub fn call_tool(&mut self, name: &str, arguments: Value) -> Result<Value> {
        self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        )
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for McpGateway {
    fn drop(&mut self) {
        // Closing stdin lets well-behaved servers exit; kill as a fallback.
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_command() {
        assert!(McpGateway::connect("", &[]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn handshake_and_tools_list_against_a_real_server() {
        let script = r#"
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    method = req.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "test-server", "version": "1.0"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "echo", "description": "Echo input", "inputSchema": {"type": "object"}}]}
    else:
        result = {}
    if "id" in req:
        print(json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": result}), flush=True)
"#;
        let mut gateway =
            McpGateway::connect("python3", &["-u".into(), "-c".into(), script.into()]).unwrap();
        let info = gateway.initialize("zentrion-test", "0.1.0").unwrap();
        assert_eq!(info["serverInfo"]["name"], "test-server");
        let tools = gateway.list_tools().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "echo");
        assert_eq!(tools[0].description, "Echo input");
    }
}

//! Local MCP server that proxies agent tool calls through the approval broker.
//!
//! Agents speak newline-delimited JSON-RPC 2.0 over stdio (`z mcp serve`).
//! Every filesystem or process operation is checked against policy and, when
//! required, approved. Tools are deny-by-default: an operation without a policy
//! grant returns an error to the agent, never a silent success.

use crate::broker::{ApprovalBroker, BrokerOutcome, BrokerRequest};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_TOOL_OUTPUT: usize = 1024 * 1024;
const MAX_FILE_BYTES: u64 = 1024 * 1024;

pub struct McpServer {
    broker: ApprovalBroker,
    approval_timeout: Duration,
    tool_timeout: Duration,
    auto_approve: bool,
    server_name: String,
}

#[derive(Debug, Clone)]
pub struct McpServerOptions {
    pub approval_timeout: Duration,
    pub tool_timeout: Duration,
    pub auto_approve: bool,
    pub server_name: String,
}

impl Default for McpServerOptions {
    fn default() -> Self {
        Self {
            approval_timeout: Duration::from_secs(300),
            tool_timeout: Duration::from_secs(60),
            auto_approve: false,
            server_name: "zentrion".into(),
        }
    }
}

impl McpServer {
    pub fn new(broker: ApprovalBroker, options: McpServerOptions) -> Self {
        Self {
            broker,
            approval_timeout: options.approval_timeout,
            tool_timeout: options.tool_timeout,
            auto_approve: options.auto_approve,
            server_name: options.server_name,
        }
    }

    pub fn serve_stdio(&mut self) -> Result<(), String> {
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let reader = stdin.lock();
        let mut writer = stdout.lock();
        self.serve(reader, &mut writer)
    }

    pub fn serve<R: BufRead, W: Write>(&mut self, reader: R, writer: &mut W) -> Result<(), String> {
        for line in reader.lines() {
            let line = line.map_err(|e| format!("cannot read MCP request: {e}"))?;
            if line.trim().is_empty() {
                continue;
            }
            let request: Value = match serde_json::from_str(&line) {
                Ok(request) => request,
                Err(error) => {
                    self.write(
                        writer,
                        &error_response(Value::Null, -32700, &format!("parse error: {error}")),
                    )?;
                    continue;
                }
            };
            let id = request.get("id").cloned().unwrap_or(Value::Null);
            let method = request.get("method").and_then(Value::as_str).unwrap_or("");
            let params = request.get("params").cloned().unwrap_or(Value::Null);
            if id.is_null() {
                // Notifications have no response.
                if method == "notifications/initialized" {
                    continue;
                }
                continue;
            }
            let response = match method {
                "initialize" => success_response(
                    id,
                    json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": self.server_name, "version": env!("CARGO_PKG_VERSION") },
                    }),
                ),
                "tools/list" => success_response(id, json!({ "tools": tool_definitions() })),
                "tools/call" => match self.handle_tool_call(&params) {
                    Ok(result) => success_response(id, result),
                    Err(error) => success_response(
                        id,
                        json!({
                            "content": [{"type":"text","text":error}],
                            "isError": true,
                        }),
                    ),
                },
                "ping" => success_response(id, json!({})),
                other => error_response(id, -32601, &format!("unknown method `{other}`")),
            };
            self.write(writer, &response)?;
        }
        Ok(())
    }

    fn write<W: Write>(&self, writer: &mut W, value: &Value) -> Result<(), String> {
        let mut text = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        text.push(b'\n');
        writer.write_all(&text).map_err(|e| e.to_string())?;
        writer.flush().map_err(|e| e.to_string())
    }

    fn handle_tool_call(&mut self, params: &Value) -> Result<Value, String> {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "missing tool name".to_string())?;
        let args = params.get("arguments").cloned().unwrap_or(json!({}));
        let tool = name
            .strip_prefix("zentrion/")
            .or_else(|| name.strip_prefix("zentrion."))
            .unwrap_or(name);
        self.approval_gate(
            "agent.tool.call",
            &format!("mcp:zentrion/{tool}"),
            &format!("Run tool `{tool}`"),
        )?;
        let text = match tool {
            "read_file" => self.read_file(&args)?,
            "list_dir" => self.list_dir(&args)?,
            "write_file" => self.write_file(&args)?,
            "delete_file" => self.delete_file(&args)?,
            "run_command" => self.run_command(&args)?,
            other => return Err(format!("unknown tool `{other}`")),
        };
        Ok(json!({
            "content": [{"type":"text","text":text}],
            "isError": false,
        }))
    }

    fn approval_gate(&self, action: &str, resource: &str, preview: &str) -> Result<(), String> {
        let outcome = self
            .broker
            .request(BrokerRequest::new(action, resource).preview(preview))?;
        match outcome {
            BrokerOutcome::Denied { reason } => Err(format!("denied by policy: {reason}")),
            BrokerOutcome::Allowed {
                request_id, nonce, ..
            } => self
                .broker
                .consume(&request_id, &nonce, action, resource)
                .map_err(|e| format!("capability rejected: {e}")),
            BrokerOutcome::Pending { request_id } => {
                if self.auto_approve {
                    let approved = self.broker.approve(&request_id, "auto-approve")?;
                    let nonce = approved
                        .token
                        .as_ref()
                        .map(|token| token.nonce.clone())
                        .ok_or_else(|| "approval has no token".to_string())?;
                    self.broker.consume(&request_id, &nonce, action, resource)?;
                    return Ok(());
                }
                let resolved = self.broker.wait(&request_id, self.approval_timeout)?;
                if resolved.status != crate::broker::ApprovalStatus::Approved {
                    return Err(format!(
                        "approval {} was denied; ask the operator to run `z agent approvals`",
                        resolved.id
                    ));
                }
                let nonce = resolved
                    .token
                    .as_ref()
                    .map(|token| token.nonce.clone())
                    .ok_or_else(|| "approval has no token".to_string())?;
                self.broker.consume(&request_id, &nonce, action, resource)?;
                Ok(())
            }
        }
    }

    fn resolve_path(&self, input: &str) -> Result<PathBuf, String> {
        let raw = Path::new(input);
        if raw
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err("paths must not contain `..`".into());
        }
        let candidate = if raw.is_absolute() {
            raw.to_path_buf()
        } else {
            self.broker.workspace().join(raw)
        };
        let root = self.broker.workspace();
        if candidate.exists() {
            let canonical = candidate
                .canonicalize()
                .map_err(|e| format!("cannot resolve {}: {e}", candidate.display()))?;
            if !canonical.starts_with(root) {
                return Err("path escapes the workspace".into());
            }
            return Ok(canonical);
        }
        let parent = candidate
            .parent()
            .ok_or_else(|| "path has no parent".to_string())?;
        let canonical_parent = parent
            .canonicalize()
            .map_err(|e| format!("cannot resolve parent {}: {e}", parent.display()))?;
        if !canonical_parent.starts_with(root) {
            return Err("path escapes the workspace".into());
        }
        let name = candidate
            .file_name()
            .ok_or_else(|| "path has no file name".to_string())?;
        Ok(canonical_parent.join(name))
    }

    fn read_file(&self, args: &Value) -> Result<String, String> {
        let path = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| "read_file requires `path`".to_string())?;
        let path = self.resolve_path(path)?;
        self.approval_gate(
            "agent.fs.read",
            &relative(&path, self.broker.workspace()),
            &format!("Read {}", path.display()),
        )?;
        let metadata = std::fs::metadata(&path).map_err(|e| format!("cannot read file: {e}"))?;
        if metadata.len() > MAX_FILE_BYTES {
            return Err(format!(
                "file is {} bytes; maximum readable is {}",
                metadata.len(),
                MAX_FILE_BYTES
            ));
        }
        let bytes = std::fs::read(&path).map_err(|e| format!("cannot read file: {e}"))?;
        if bytes.iter().take(8192).any(|byte| *byte == 0) {
            return Err("refusing to return binary content".into());
        }
        let text = String::from_utf8_lossy(&bytes).to_string();
        Ok(format!(
            "{} ({} bytes, sha256:{})\n{}",
            path.display(),
            bytes.len(),
            hex(&Sha256::digest(&bytes)),
            text
        ))
    }

    fn list_dir(&self, args: &Value) -> Result<String, String> {
        let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
        let path = self.resolve_path(path)?;
        self.approval_gate(
            "agent.fs.read",
            &relative(&path, self.broker.workspace()),
            &format!("List {}", path.display()),
        )?;
        let mut entries: Vec<String> = std::fs::read_dir(&path)
            .map_err(|e| format!("cannot list directory: {e}"))?
            .flatten()
            .take(1_000)
            .map(|entry| {
                let suffix = if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    "/"
                } else {
                    ""
                };
                format!("{}{}", entry.file_name().to_string_lossy(), suffix)
            })
            .collect();
        entries.sort();
        Ok(format!("{}\n{}", path.display(), entries.join("\n")))
    }

    fn write_file(&self, args: &Value) -> Result<String, String> {
        let path = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| "write_file requires `path`".to_string())?;
        let content = args
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| "write_file requires `content`".to_string())?;
        if content.len() as u64 > MAX_FILE_BYTES {
            return Err("content exceeds the 1 MiB tool limit".into());
        }
        let path = self.resolve_path(path)?;
        let relative_path = relative(&path, self.broker.workspace());
        self.approval_gate(
            "agent.fs.write",
            &relative_path,
            &format!("Write {} bytes to {relative_path}", content.len()),
        )?;
        let tmp = path.with_extension("zentrion-tool-tmp");
        std::fs::write(&tmp, content).map_err(|e| format!("cannot write file: {e}"))?;
        std::fs::rename(&tmp, &path).map_err(|e| format!("cannot replace file: {e}"))?;
        Ok(format!(
            "wrote {} bytes to {} (sha256:{})",
            content.len(),
            relative_path,
            hex(&Sha256::digest(content.as_bytes()))
        ))
    }

    fn delete_file(&self, args: &Value) -> Result<String, String> {
        let path = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| "delete_file requires `path`".to_string())?;
        let path = self.resolve_path(path)?;
        if path.is_dir() {
            return Err("delete_file refuses directories".into());
        }
        let relative_path = relative(&path, self.broker.workspace());
        self.approval_gate(
            "agent.fs.delete",
            &relative_path,
            &format!("Delete {relative_path}"),
        )?;
        std::fs::remove_file(&path).map_err(|e| format!("cannot delete file: {e}"))?;
        Ok(format!("deleted {relative_path}"))
    }

    fn run_command(&self, args: &Value) -> Result<String, String> {
        let program = args
            .get("program")
            .and_then(Value::as_str)
            .ok_or_else(|| "run_command requires `program`".to_string())?;
        let arguments: Vec<String> = args
            .get("args")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let shell = args.get("shell").and_then(Value::as_bool).unwrap_or(false);
        let cwd = args
            .get("cwd")
            .and_then(Value::as_str)
            .map(|cwd| self.resolve_path(cwd))
            .transpose()?
            .unwrap_or_else(|| self.broker.workspace().to_path_buf());
        if !cwd.starts_with(self.broker.workspace()) {
            return Err("cwd escapes the workspace".into());
        }
        let command_line = if shell {
            format!("{} {}", program, arguments.join(" "))
        } else {
            format!("{} {}", program, arguments.join(" "))
        };
        if shell {
            self.approval_gate(
                "agent.shell",
                &command_line,
                &format!("Run shell command: {command_line}"),
            )?;
        } else {
            self.approval_gate(
                "agent.exec",
                program,
                &format!("Run `{command_line}` in {}", cwd.display()),
            )?;
        }
        let mut command = if shell {
            let shell_program = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
            let mut command = std::process::Command::new(shell_program);
            command.arg("-c").arg(&command_line);
            command
        } else {
            let mut command = std::process::Command::new(program);
            command.args(&arguments);
            command
        };
        command
            .current_dir(&cwd)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("cannot start `{program}`: {e}"))?;
        let stdout = child
            .stdout
            .take()
            .map(|reader| read_capped(reader, MAX_TOOL_OUTPUT));
        let stderr = child
            .stderr
            .take()
            .map(|reader| read_capped(reader, MAX_TOOL_OUTPUT));
        let deadline = Instant::now() + self.tool_timeout;
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        timed_out = true;
                        #[cfg(unix)]
                        {
                            let pid = child.id() as i32;
                            unsafe {
                                libc::kill(-pid, libc::SIGKILL);
                            }
                        }
                        let _ = child.kill();
                        let _ = child.wait();
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => return Err(format!("cannot wait for process: {error}")),
            }
        };
        let stdout = stdout
            .and_then(|handle| handle.join().ok())
            .unwrap_or_default();
        let stderr = stderr
            .and_then(|handle| handle.join().ok())
            .unwrap_or_default();
        let code = status.and_then(|status| status.code());
        Ok(format!(
            "exit: {}\ntimed_out: {}\nstdout:\n{}\nstderr:\n{}",
            code.map(|code| code.to_string())
                .unwrap_or_else(|| "signal".into()),
            timed_out,
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        ))
    }
}

fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "zentrion/read_file",
            "description": "Read a UTF-8 file inside the workspace. Requires agent.fs.read policy.",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "Workspace-relative or absolute path"}},
                "required": ["path"]
            }
        }),
        json!({
            "name": "zentrion/list_dir",
            "description": "List a directory inside the workspace.",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": []
            }
        }),
        json!({
            "name": "zentrion/write_file",
            "description": "Write a UTF-8 file inside the workspace. Requires agent.fs.write policy (and approval when the profile requires it).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"}
                },
                "required": ["path", "content"]
            }
        }),
        json!({
            "name": "zentrion/delete_file",
            "description": "Delete a file inside the workspace. High risk; always policy-gated and normally approval-gated.",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"]
            }
        }),
        json!({
            "name": "zentrion/run_command",
            "description": "Run an allowlisted program (or an allowlisted shell command with shell=true) inside the workspace.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "program": {"type": "string"},
                    "args": {"type": "array", "items": {"type": "string"}},
                    "cwd": {"type": "string"},
                    "shell": {"type": "boolean"}
                },
                "required": ["program"]
            }
        }),
    ]
}

fn success_response(id: Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

fn relative(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn read_capped(
    mut reader: impl Read + Send + 'static,
    max: usize,
) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if buffer.len() < max {
                        let take = (max - buffer.len()).min(n);
                        buffer.extend_from_slice(&chunk[..take]);
                    }
                }
                Err(_) => break,
            }
        }
        buffer
    })
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::ApprovalBroker;
    use crate::profile::AgentProfile;
    use std::io::Cursor;

    #[cfg(unix)]
    fn server(name: &str, profile: &str) -> (McpServer, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-mcp-{}-{}-{}",
            name,
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let broker = ApprovalBroker::new(
            "mcp-test",
            AgentProfile::builtin(profile).unwrap(),
            z_policy::Policy::default(),
            &dir,
            &dir.join("approvals.json"),
            &dir.join("audit/events.jsonl"),
        )
        .unwrap();
        (
            McpServer::new(
                broker,
                McpServerOptions {
                    auto_approve: false,
                    approval_timeout: Duration::from_millis(200),
                    ..Default::default()
                },
            ),
            dir,
        )
    }

    #[cfg(unix)]
    fn call(server: &mut McpServer, requests: &[Value]) -> Vec<Value> {
        let mut input = String::new();
        for request in requests {
            input.push_str(&serde_json::to_string(request).unwrap());
            input.push('\n');
        }
        let mut output = Vec::new();
        server.serve(Cursor::new(input), &mut output).unwrap();
        String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[cfg(unix)]
    #[test]
    fn initialize_and_tools_list() {
        let (mut server, dir) = server("init", "agent-dev");
        let responses = call(
            &mut server,
            &[
                json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
            ],
        );
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["result"]["serverInfo"]["name"], "zentrion");
        assert!(responses[1]["result"]["tools"].as_array().unwrap().len() >= 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn policy_allowed_read_and_write_inside_workspace() {
        let (mut server, dir) = server("rw", "agent-dev");
        std::fs::write(dir.join("hello.txt"), "hello\n").unwrap();
        let responses = call(
            &mut server,
            &[
                json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
                    "name":"zentrion/read_file","arguments":{"path":"hello.txt"}}}),
                json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
                    "name":"zentrion/write_file","arguments":{"path":"new.txt","content":"new content\n"}}}),
            ],
        );
        assert_eq!(
            responses[0]["result"]["isError"], false,
            "{:?}",
            responses[0]
        );
        assert!(responses[0]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("hello"));
        assert_eq!(
            responses[1]["result"]["isError"], false,
            "{:?}",
            responses[1]
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("new.txt")).unwrap(),
            "new content\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn path_escape_is_rejected() {
        let (mut server, dir) = server("escape", "agent-dev");
        let responses = call(
            &mut server,
            &[
                json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
                "name":"zentrion/read_file","arguments":{"path":"../../etc/passwd"}}}),
            ],
        );
        assert_eq!(responses[0]["result"]["isError"], true);
        assert!(responses[0]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains(".."));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn readonly_denies_writes() {
        let (mut server, dir) = server("readonly", "agent-readonly");
        let responses = call(
            &mut server,
            &[
                json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
                "name":"zentrion/write_file","arguments":{"path":"x.txt","content":"no"}}}),
            ],
        );
        assert_eq!(responses[0]["result"]["isError"], true);
        assert!(!dir.join("x.txt").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn approval_required_returns_actionable_request_id() {
        let (mut server, dir) = server("approval", "agent-dev");
        let responses = call(
            &mut server,
            &[
                json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
                "name":"zentrion/run_command","arguments":{"program":"cargo","args":["--version"]}}}),
            ],
        );
        assert_eq!(responses[0]["result"]["isError"], true);
        assert!(responses[0]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("approval required"));
        // The approval exists and can be granted out-of-band.
        let pending = server.broker.pending();
        assert!(!pending.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

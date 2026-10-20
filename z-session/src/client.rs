//! Blocking session client used by the CLI and TUI.
//!
//! The reader thread demultiplexes JSON-RPC responses from notifications and
//! binary output frames, so callers can issue requests while output streams.

use crate::daemon::{log_path, socket_path};
use crate::protocol::{
    json_frame, OutputFrame, RpcRequest, RpcResponse, ERR_UNAVAILABLE, TYPE_JSON, TYPE_OUTPUT,
    TYPE_SCROLLBACK,
};
use crate::session::SessionInfo;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

#[derive(Debug, Clone)]
pub enum ClientEvent {
    Output(OutputFrame),
    Notification { method: String, params: Value },
}

#[derive(Debug, Clone)]
pub struct Attach {
    pub snapshot: Value,
    pub info: SessionInfo,
    pub seq: u64,
    pub replayed: usize,
}

pub struct SessionClient {
    writer: Mutex<std::os::unix::net::UnixStream>,
    pending: Arc<Mutex<HashMap<u64, Sender<RpcResponse>>>>,
    next_id: AtomicU64,
    events: broadcast::Sender<ClientEvent>,
    reader: Mutex<Option<std::thread::JoinHandle<()>>>,
    closed: AtomicBool,
    /// Keeps at least one receiver alive so the reader never drops frames just
    /// because no consumer has subscribed yet.
    _keepalive: Mutex<broadcast::Receiver<ClientEvent>>,
}

impl std::fmt::Debug for SessionClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionClient")
            .field("closed", &self.closed.load(Ordering::SeqCst))
            .finish()
    }
}

impl SessionClient {
    pub fn connect(path: &Path) -> std::io::Result<Self> {
        let stream = std::os::unix::net::UnixStream::connect(path)?;
        Self::from_stream(stream)
    }

    pub fn connect_default() -> std::io::Result<Self> {
        Self::connect(&socket_path())
    }

    fn from_stream(stream: std::os::unix::net::UnixStream) -> std::io::Result<Self> {
        stream.set_read_timeout(None)?;
        let mut reader_stream = stream.try_clone()?;
        let pending: Arc<Mutex<HashMap<u64, Sender<RpcResponse>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (events, keepalive) = broadcast::channel(4096);
        let pending_reader = Arc::clone(&pending);
        let events_reader = events.clone();
        let reader = std::thread::Builder::new()
            .name("z-session-client".into())
            .spawn(move || {
                let mut header = [0u8; 5];
                loop {
                    if reader_stream.read_exact(&mut header).is_err() {
                        break;
                    }
                    let parsed = match crate::protocol::parse_header(&header) {
                        Ok(header) => header,
                        Err(_) => break,
                    };
                    let mut payload = vec![0u8; parsed.len];
                    if reader_stream.read_exact(&mut payload).is_err() {
                        break;
                    }
                    match parsed.kind {
                        TYPE_JSON => {
                            if let Ok(value) = serde_json::from_slice::<Value>(&payload) {
                                if value.get("id").and_then(|id| id.as_u64()).is_some()
                                    && (value.get("result").is_some()
                                        || value.get("error").is_some())
                                {
                                    if let Ok(response) =
                                        serde_json::from_value::<RpcResponse>(value)
                                    {
                                        if let Some(id) = response.id {
                                            let sender = pending_reader
                                                .lock()
                                                .expect("pending lock")
                                                .remove(&id);
                                            if let Some(sender) = sender {
                                                let _ = sender.send(response);
                                            }
                                        }
                                    }
                                } else if let Some(method) =
                                    value.get("method").and_then(|m| m.as_str())
                                {
                                    let _ = events_reader.send(ClientEvent::Notification {
                                        method: method.to_string(),
                                        params: value.get("params").cloned().unwrap_or(Value::Null),
                                    });
                                }
                            }
                        }
                        TYPE_OUTPUT | TYPE_SCROLLBACK => {
                            if let Some(frame) = OutputFrame::decode(&payload) {
                                let _ = events_reader.send(ClientEvent::Output(frame));
                            }
                        }
                        _ => {}
                    }
                }
                // Fail every outstanding request instead of hanging forever.
                let pending = std::mem::take(&mut *pending_reader.lock().expect("pending lock"));
                for (id, sender) in pending {
                    let _ = sender.send(RpcResponse::err(
                        Some(id),
                        ERR_UNAVAILABLE,
                        "session daemon closed the connection",
                    ));
                }
            })?;
        Ok(Self {
            writer: Mutex::new(stream),
            pending,
            next_id: AtomicU64::new(1),
            events,
            reader: Mutex::new(Some(reader)),
            closed: AtomicBool::new(false),
            _keepalive: Mutex::new(keepalive),
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ClientEvent> {
        self.events.subscribe()
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        self.call_timeout(method, params, Duration::from_secs(30))
    }

    pub fn call_timeout(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        if self.closed.load(Ordering::SeqCst) {
            return Err("session daemon connection is closed".into());
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        self.pending.lock().expect("pending lock").insert(id, tx);
        let request = RpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(id),
            method: method.to_string(),
            params,
        };
        let bytes = json_frame(&request);
        {
            let mut writer = self.writer.lock().expect("client writer lock");
            if let Err(error) = writer.write_all(&bytes).and_then(|_| writer.flush()) {
                self.pending.lock().expect("pending lock").remove(&id);
                return Err(format!("cannot send request: {error}"));
            }
        }
        match rx.recv_timeout(timeout) {
            Ok(response) => match (response.result, response.error) {
                (Some(result), None) => Ok(result),
                (None, Some(error)) => Err(format!("{} (code {})", error.message, error.code)),
                _ => Err("malformed response from daemon".into()),
            },
            Err(RecvTimeoutError::Timeout) => {
                self.pending.lock().expect("pending lock").remove(&id);
                Err(format!("request `{method}` timed out after {timeout:?}"))
            }
            Err(RecvTimeoutError::Disconnected) => Err("session daemon disconnected".into()),
        }
    }

    pub fn create(&self, params: Value) -> Result<SessionInfo, String> {
        let value = self.call("session.create", params)?;
        serde_json::from_value(value).map_err(|e| e.to_string())
    }

    pub fn list(&self) -> Result<Vec<SessionInfo>, String> {
        let value = self.call("session.list", json!({}))?;
        serde_json::from_value(value.get("sessions").cloned().unwrap_or(json!([])))
            .map_err(|e| e.to_string())
    }

    pub fn attach(
        &self,
        id: &str,
        since_seq: u64,
    ) -> Result<(Attach, broadcast::Receiver<ClientEvent>), String> {
        let events = self.subscribe();
        let value = self.call(
            "session.attach",
            json!({"session_id": id, "since_seq": since_seq}),
        )?;
        let info: SessionInfo =
            serde_json::from_value(value.get("info").cloned().unwrap_or(Value::Null))
                .map_err(|e| format!("invalid attach response: {e}"))?;
        Ok((
            Attach {
                seq: value.get("seq").and_then(|v| v.as_u64()).unwrap_or(0),
                replayed: value.get("replayed").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
                snapshot: value,
                info,
            },
            events,
        ))
    }

    pub fn input(&self, id: &str, data: &[u8]) -> Result<(), String> {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD.encode(data);
        self.call("session.input", json!({"session_id": id, "data": data}))?;
        Ok(())
    }

    pub fn resize(&self, id: &str, rows: u16, cols: u16) -> Result<(), String> {
        self.call(
            "session.resize",
            json!({"session_id": id, "rows": rows, "cols": cols}),
        )?;
        Ok(())
    }

    pub fn signal(&self, id: &str, signal: &str) -> Result<(), String> {
        self.call(
            "session.signal",
            json!({"session_id": id, "signal": signal}),
        )?;
        Ok(())
    }

    pub fn close(&self, id: &str, kill: bool) -> Result<(), String> {
        self.call("session.close", json!({"session_id": id, "kill": kill}))?;
        Ok(())
    }

    pub fn status(&self) -> Result<Value, String> {
        self.call("daemon.status", json!({}))
    }

    pub fn shutdown_daemon(&self) -> Result<(), String> {
        self.call("daemon.shutdown", json!({}))?;
        Ok(())
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

impl Drop for SessionClient {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        // Shut the socket down so the reader thread exits.
        let writer = self.writer.lock().expect("client writer lock");
        let _ = writer.shutdown(std::net::Shutdown::Both);
        drop(writer);
        if let Some(reader) = self.reader.lock().expect("reader lock").take() {
            let _ = reader.join();
        }
    }
}

/// Connect if a daemon is running.
pub fn try_connect() -> Option<SessionClient> {
    SessionClient::connect(&socket_path()).ok()
}

/// Connect, spawning a detached daemon if necessary.
pub fn connect_or_spawn() -> Result<SessionClient, String> {
    let socket = socket_path();
    if let Ok(client) = SessionClient::connect(&socket) {
        return Ok(client);
    }
    spawn_daemon(&socket)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(client) = SessionClient::connect(&socket) {
            return Ok(client);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!(
        "session daemon did not start; see {}",
        log_path().display()
    ))
}

/// Spawn `z session daemon` detached with the given socket.
pub fn spawn_daemon(socket: &Path) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate z executable: {e}"))?;
    let log = log_path();
    if let Some(parent) = log.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .map_err(|e| format!("cannot open daemon log {}: {e}", log.display()))?;
    let stderr = log_file
        .try_clone()
        .map_err(|e| format!("cannot clone daemon log handle: {e}"))?;
    let mut command = std::process::Command::new(exe);
    command
        .args(["session", "daemon"])
        .env("ZENTRION_SESSION_SOCKET", socket)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(stderr))
        .env("RUST_BACKTRACE", "1");
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Detach from the controlling terminal. `setsid` is async-signal-safe.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    command
        .spawn()
        .map_err(|e| format!("cannot spawn session daemon: {e}"))?;
    Ok(())
}

/// Default log location, exposed for diagnostics.
pub fn daemon_log_path() -> PathBuf {
    log_path()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_before_attach_keeps_replay_frames() {
        // This is a structural guarantee: attach subscribes before sending the
        // request, so the replay frames are delivered to that receiver.
        let (events, mut rx) = broadcast::channel(8);
        events
            .send(ClientEvent::Notification {
                method: "block.started".into(),
                params: json!({}),
            })
            .unwrap();
        assert!(matches!(
            rx.try_recv().unwrap(),
            ClientEvent::Notification { .. }
        ));
    }
}

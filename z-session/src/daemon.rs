//! Session daemon: one per user, Unix socket, JSON-RPC + binary output.
//!
//! The daemon owns PTYs and blocks; UIs are clients. The socket is created
//! with mode 0600 and only loopback/Unix transport is supported, so there is no
//! inbound network exposure by default.

use crate::manager::{CreateParams, SessionManager};
use crate::protocol::{
    json_frame, notification, parse_frame, parse_json, OutputFrame, RpcRequest, RpcResponse,
    ERR_INVALID_PARAMS, ERR_METHOD_NOT_FOUND, ERR_NOT_FOUND, ERR_UNAVAILABLE, TYPE_JSON,
};
use crate::session::{SessionError, SessionEvent};
use base64::Engine;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, watch};
use z_agents::{AgentRunInfo, LaunchOptions, Supervisor};

#[derive(Debug, Default)]
pub struct DaemonState {
    pub shutdown: AtomicBool,
    pub started_at: std::sync::Mutex<Option<Instant>>,
    pub connections: AtomicU64,
}

#[derive(Clone)]
pub struct Daemon {
    manager: Arc<SessionManager>,
    supervisor: Arc<Supervisor>,
    state: Arc<DaemonState>,
    shutdown_tx: watch::Sender<bool>,
    socket: PathBuf,
}

/// Resolve the per-user session socket path.
pub fn socket_path() -> PathBuf {
    if let Ok(custom) = std::env::var("ZENTRION_SESSION_SOCKET") {
        if !custom.trim().is_empty() {
            return PathBuf::from(custom);
        }
    }
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        if !runtime.trim().is_empty() {
            return PathBuf::from(runtime).join("zentrion").join("session.sock");
        }
    }
    let base = z_core::config::user_data_dir().unwrap_or_else(std::env::temp_dir);
    base.join("run").join("session.sock")
}

pub fn pid_path(socket: &Path) -> PathBuf {
    socket.with_extension("pid")
}

pub fn log_path() -> PathBuf {
    z_core::config::user_data_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("daemon.log")
}

/// Run the daemon in the calling process, blocking until shutdown.
pub fn run(manager: SessionManager, socket: PathBuf) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .map_err(|e| format!("cannot start runtime: {e}"))?;
    runtime.block_on(async move {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut adapter_dirs = z_agents::default_dirs();
        for dir in &manager.config().agents.adapter_dirs {
            adapter_dirs.push(PathBuf::from(dir));
        }
        let adapters = z_agents::discover(&adapter_dirs);
        let supervisor = Arc::new(Supervisor::new(manager.data_dir(), adapters));
        let daemon = Daemon {
            manager: Arc::new(manager),
            supervisor,
            state: Arc::new(DaemonState::default()),
            shutdown_tx,
            socket: socket.clone(),
        };
        daemon.serve(shutdown_rx).await
    })
}

impl Daemon {
    async fn serve(&self, mut shutdown_rx: watch::Receiver<bool>) -> Result<(), String> {
        prepare_socket(&self.socket)?;
        let listener = UnixListener::bind(&self.socket)
            .map_err(|e| format!("cannot bind {}: {e}", self.socket.display()))?;
        secure_socket(&self.socket)?;
        write_pid(&self.socket);
        *self.state.started_at.lock().expect("state lock") = Some(Instant::now());

        #[cfg(unix)]
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|e| format!("cannot install SIGTERM handler: {e}"))?;

        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_ok() && *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    self.shutdown_tx.send(true).ok();
                }
                _ = terminate.recv() => {
                    self.shutdown_tx.send(true).ok();
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _addr)) => {
                            self.state.connections.fetch_add(1, Ordering::SeqCst);
                            let daemon = self.clone();
                            tokio::spawn(async move {
                                if let Err(error) = daemon.handle_connection(stream).await {
                                    if error.kind() != std::io::ErrorKind::UnexpectedEof
                                        && error.kind() != std::io::ErrorKind::ConnectionReset
                                    {
                                        eprintln!("z session: client error: {error}");
                                    }
                                }
                            });
                        }
                        Err(error) => {
                            eprintln!("z session: accept failed: {error}");
                        }
                    }
                }
            }
        }
        self.supervisor.stop_all();
        self.manager.shutdown();
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_file(pid_path(&self.socket));
        Ok(())
    }

    async fn handle_connection(&self, stream: UnixStream) -> std::io::Result<()> {
        let (mut reader, mut writer) = stream.into_split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let writer_task = tokio::spawn(async move {
            while let Some(bytes) = rx.recv().await {
                if writer.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            let _ = writer.shutdown().await;
        });

        let mut buffer: Vec<u8> = Vec::new();
        let mut read_buf = [0u8; 8192];
        let mut attached: Option<String> = None;
        let mut forward: Option<tokio::task::JoinHandle<()>> = None;

        loop {
            let n = reader.read(&mut read_buf).await?;
            if n == 0 {
                break;
            }
            buffer.extend_from_slice(&read_buf[..n]);
            loop {
                let parsed = match parse_frame(&buffer) {
                    Ok(Some(parsed)) => parsed,
                    Ok(None) => break,
                    Err(error) => {
                        let response = RpcResponse::err(None, ERR_INVALID_PARAMS, error);
                        let _ = tx.send(json_frame(&response));
                        buffer.clear();
                        break;
                    }
                };
                let (kind, payload, used) = parsed;
                buffer.drain(..used);
                if kind != TYPE_JSON {
                    // Clients do not send binary frames.
                    let response =
                        RpcResponse::err(None, ERR_INVALID_PARAMS, "binary frames are server-only");
                    let _ = tx.send(json_frame(&response));
                    continue;
                }
                let request: RpcRequest = match parse_json(&payload) {
                    Ok(request) => request,
                    Err(error) => {
                        let _ = tx.send(json_frame(&RpcResponse::err(
                            None,
                            ERR_INVALID_PARAMS,
                            format!("invalid JSON-RPC request: {error}"),
                        )));
                        continue;
                    }
                };
                let is_notification = request.id.is_none();
                let id = request.id;
                let attach = request.method == "session.attach";
                let outcome = self
                    .dispatch(&request, &tx, &mut attached, &mut forward)
                    .await;
                // `session.attach` sends its own response before the replay
                // frames, so the client sees the snapshot first.
                if !is_notification && !attach {
                    let response = match outcome {
                        Ok(result) => RpcResponse::ok(id, result),
                        Err((code, message)) => RpcResponse::err(id, code, message),
                    };
                    let _ = tx.send(json_frame(&response));
                }
            }
        }
        if let Some(forward) = forward {
            forward.abort();
        }
        drop(tx);
        let _ = writer_task.await;
        Ok(())
    }

    async fn dispatch(
        &self,
        request: &RpcRequest,
        tx: &mpsc::UnboundedSender<Vec<u8>>,
        attached: &mut Option<String>,
        forward: &mut Option<tokio::task::JoinHandle<()>>,
    ) -> std::result::Result<Value, (i64, String)> {
        match request.method.as_str() {
            "ping" => Ok(json!({"pong": true, "version": env!("CARGO_PKG_VERSION")})),
            "daemon.status" => {
                let sessions = self.manager.list();
                Ok(json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "socket": self.socket.display().to_string(),
                    "sessions": sessions.len(),
                    "uptime_seconds": self.state.started_at.lock().expect("state lock")
                        .map(|start| start.elapsed().as_secs()),
                    "blocks_error": self.manager.writer_error(),
                }))
            }
            "daemon.shutdown" => {
                self.shutdown_tx.send(true).ok();
                Ok(json!({"shutting_down": true}))
            }
            "session.create" => {
                let mut params: CreateParams = serde_json::from_value(request.params.clone())
                    .map_err(|e| (ERR_INVALID_PARAMS, format!("invalid params: {e}")))?;
                // Accept cwd as a string (PathBuf deserializes from a string).
                if let Some(cwd) = request.params.get("cwd").and_then(|v| v.as_str()) {
                    params.cwd = Some(PathBuf::from(cwd));
                }
                let info = self.manager.create(params).map_err(map_session_error)?;
                Ok(serde_json::to_value(info).unwrap_or(Value::Null))
            }
            "session.list" => Ok(json!({"sessions": self.manager.list()})),
            "session.get" => {
                let id = param_str(&request.params, "session_id")?;
                let info = self
                    .manager
                    .require(&id)
                    .map(|handle| handle.info())
                    .map_err(map_session_error)?;
                Ok(serde_json::to_value(info).unwrap_or(Value::Null))
            }
            "session.snapshot" => {
                let id = param_str(&request.params, "session_id")?;
                let snapshot = self.manager.snapshot(&id).map_err(map_session_error)?;
                Ok(json!({
                    "info": snapshot.info,
                    "seq": snapshot.seq,
                    "keyframe": snapshot.keyframe,
                    "contents": snapshot.contents,
                    "cwd": snapshot.cwd,
                    "title": snapshot.title,
                    "progress": snapshot.progress.map(|(state, pct)| json!({"state": state, "pct": pct})),
                    "running_block": snapshot.running_block,
                }))
            }
            "session.attach" => {
                let id = param_str(&request.params, "session_id")?;
                let since = request
                    .params
                    .get("since_seq")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let handle = self.manager.require(&id).map_err(map_session_error)?;
                // Subscribe before snapshotting so nothing is missed between the
                // replay and live streaming.
                let mut events = handle.subscribe();
                let snapshot = handle.snapshot();
                let replay = handle.replay_since(since);
                let blocks = self.manager.attach_blocks(&id);
                let last_replay = replay.last().map(|chunk| chunk.seq).unwrap_or(since);
                let (ring_oldest, _, ring_bytes) = handle.ring_stats();
                let response = json!({
                    "session_id": id,
                    "info": snapshot.info,
                    "seq": snapshot.seq,
                    "keyframe": snapshot.keyframe,
                    "contents": snapshot.contents,
                    "cwd": snapshot.cwd,
                    "title": snapshot.title,
                    "progress": snapshot.progress.map(|(state, pct)| json!({"state": state, "pct": pct})),
                    "running_block": snapshot.running_block,
                    "blocks": blocks,
                    "ring_oldest_seq": ring_oldest,
                    "ring_bytes": ring_bytes,
                    "replayed": replay.len(),
                });
                // Send the response first: the client reads it before frames.
                let _ = tx.send(json_frame(&RpcResponse::ok(request.id, response)));
                for chunk in replay {
                    let frame = OutputFrame {
                        seq: chunk.seq,
                        session_id: chunk.session_id,
                        data: chunk.data,
                    };
                    let _ = tx.send(frame.encode());
                }
                if let Some(previous) = forward.take() {
                    previous.abort();
                }
                *attached = Some(id.clone());
                let tx = tx.clone();
                let id_for_task = id.clone();
                *forward = Some(tokio::spawn(async move {
                    let mut last_seq = last_replay;
                    loop {
                        match events.recv().await {
                            Ok(SessionEvent::Output(chunk)) => {
                                if chunk.seq <= last_seq {
                                    continue;
                                }
                                last_seq = chunk.seq;
                                let frame = OutputFrame {
                                    seq: chunk.seq,
                                    session_id: chunk.session_id,
                                    data: chunk.data,
                                };
                                if tx.send(frame.encode()).is_err() {
                                    break;
                                }
                            }
                            Ok(event) => {
                                if let Some((method, params)) =
                                    event_notification(&id_for_task, &event)
                                {
                                    if tx.send(notification(method, params)).is_err() {
                                        break;
                                    }
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                let lag = json!({
                                    "session_id": id_for_task,
                                    "skipped": skipped,
                                });
                                if tx.send(notification("client.lagged", lag)).is_err() {
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }));
                // The response was sent above, before the replay frames.
                Ok(Value::Null)
            }
            "session.detach" => {
                if let Some(forward) = forward.take() {
                    forward.abort();
                }
                *attached = None;
                Ok(json!({"detached": true}))
            }
            "session.input" => {
                let id = param_str(&request.params, "session_id")?;
                let data = request
                    .params
                    .get("data")
                    .and_then(|v| v.as_str())
                    .ok_or((ERR_INVALID_PARAMS, "missing `data`".to_string()))?;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .map_err(|e| (ERR_INVALID_PARAMS, format!("data is not base64: {e}")))?;
                let handle = self.manager.require(&id).map_err(map_session_error)?;
                handle.input(&bytes).map_err(map_session_error)?;
                Ok(json!({"accepted": bytes.len()}))
            }
            "session.resize" => {
                let id = param_str(&request.params, "session_id")?;
                let rows = request
                    .params
                    .get("rows")
                    .and_then(|v| v.as_u64())
                    .ok_or((ERR_INVALID_PARAMS, "missing rows".to_string()))?
                    as u16;
                let cols = request
                    .params
                    .get("cols")
                    .and_then(|v| v.as_u64())
                    .ok_or((ERR_INVALID_PARAMS, "missing cols".to_string()))?
                    as u16;
                self.manager
                    .require(&id)
                    .map_err(map_session_error)?
                    .resize(rows, cols)
                    .map_err(map_session_error)?;
                Ok(json!({"rows": rows, "cols": cols}))
            }
            "session.signal" => {
                let id = param_str(&request.params, "session_id")?;
                let signal = param_str(&request.params, "signal")?;
                self.manager
                    .require(&id)
                    .map_err(map_session_error)?
                    .signal(&signal)
                    .map_err(map_session_error)?;
                Ok(json!({"signal": signal}))
            }
            "session.close" => {
                let id = param_str(&request.params, "session_id")?;
                let kill = request
                    .params
                    .get("kill")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                self.manager.close(&id, kill).map_err(map_session_error)?;
                Ok(json!({"closed": id}))
            }
            "session.remove" => {
                let id = param_str(&request.params, "session_id")?;
                let removed = self.manager.remove_closed(&id);
                if !removed {
                    return Err((ERR_UNAVAILABLE, format!("session `{id}` is still running")));
                }
                Ok(json!({"removed": id}))
            }
            "session.blocks" => {
                let id = param_str(&request.params, "session_id")?;
                Ok(json!({"blocks": self.manager.attach_blocks(&id)}))
            }
            "agent.start" => {
                let adapter_id = param_str(&request.params, "adapter")?;
                let adapter = self
                    .supervisor
                    .adapter(&adapter_id)
                    .cloned()
                    .ok_or_else(|| {
                        (
                            ERR_NOT_FOUND,
                            format!("agent adapter `{adapter_id}` not found"),
                        )
                    })?;
                let profile = request
                    .params
                    .get("profile")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| adapter.permissions.default_profile.clone());
                z_agents::AgentProfile::builtin(&profile).ok_or_else(|| {
                    (
                        ERR_INVALID_PARAMS,
                        format!("unknown agent profile `{profile}`"),
                    )
                })?;
                let cwd = request
                    .params
                    .get("cwd")
                    .and_then(Value::as_str)
                    .map(PathBuf::from)
                    .unwrap_or_else(|| {
                        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
                    });
                let env = request
                    .params
                    .get("env")
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(|value| {
                                Some((
                                    value.get("key")?.as_str()?.to_string(),
                                    value.get("value")?.as_str()?.to_string(),
                                ))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let info = self
                    .supervisor
                    .launch(LaunchOptions {
                        adapter,
                        prompt: request
                            .params
                            .get("prompt")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        model: request
                            .params
                            .get("model")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        cwd,
                        profile,
                        env,
                        command_override: None,
                    })
                    .map_err(|e| (crate::protocol::ERR_INTERNAL, e))?
                    .info();
                Ok(serde_json::to_value(info).unwrap_or(Value::Null))
            }
            "agent.list" | "agent.dashboard" => {
                let runs: Vec<AgentRunInfo> = self.supervisor.list();
                let dashboard = self.supervisor.dashboard();
                Ok(json!({
                    "agents": runs,
                    "dashboard": dashboard,
                    "adapters": self.supervisor.adapters(),
                }))
            }
            "agent.get" => {
                let id = param_str(&request.params, "agent_id")?;
                let handle = self
                    .supervisor
                    .get(&id)
                    .ok_or_else(|| (ERR_NOT_FOUND, format!("agent run `{id}` not found")))?;
                let info = handle.info();
                let output = handle.output();
                Ok(json!({
                    "info": info,
                    "output": output,
                    "output_len": output.len(),
                    "truncated": output.len() >= 64 * 1024,
                }))
            }
            "agent.input" => {
                let id = param_str(&request.params, "agent_id")?;
                let handle = self
                    .supervisor
                    .get(&id)
                    .ok_or_else(|| (ERR_NOT_FOUND, format!("agent run `{id}` not found")))?;
                if let Some(data) = request.params.get("data").and_then(Value::as_str) {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(data)
                        .map_err(|e| (ERR_INVALID_PARAMS, format!("invalid base64: {e}")))?;
                    let text = String::from_utf8_lossy(&bytes).to_string();
                    if request
                        .params
                        .get("mode")
                        .and_then(Value::as_str)
                        .unwrap_or("raw")
                        == "prompt"
                    {
                        handle
                            .send_prompt(&text)
                            .map_err(|e| (crate::protocol::ERR_INTERNAL, e))?;
                    } else {
                        handle
                            .write_raw(&bytes)
                            .map_err(|e| (crate::protocol::ERR_INTERNAL, e))?;
                    }
                } else if let Some(prompt) = request.params.get("prompt").and_then(Value::as_str) {
                    handle
                        .send_prompt(prompt)
                        .map_err(|e| (crate::protocol::ERR_INTERNAL, e))?;
                } else {
                    return Err((ERR_INVALID_PARAMS, "missing `data` or `prompt`".into()));
                }
                Ok(json!({"accepted": true}))
            }
            "agent.queue" => {
                let id = param_str(&request.params, "agent_id")?;
                let prompt = request
                    .params
                    .get("prompt")
                    .and_then(Value::as_str)
                    .ok_or_else(|| (ERR_INVALID_PARAMS, "missing prompt".into()))?;
                self.supervisor
                    .get(&id)
                    .ok_or_else(|| (ERR_NOT_FOUND, format!("agent run `{id}` not found")))?
                    .queue_prompt(prompt);
                Ok(json!({"queued": true}))
            }
            "agent.stop" => {
                let id = param_str(&request.params, "agent_id")?;
                self.supervisor
                    .get(&id)
                    .ok_or_else(|| (ERR_NOT_FOUND, format!("agent run `{id}` not found")))?
                    .stop()
                    .map_err(|e| (crate::protocol::ERR_INTERNAL, e))?;
                Ok(json!({"stopped": id}))
            }
            "agent.resume" => {
                let run_id = param_str(&request.params, "run_id")?;
                let info = self
                    .supervisor
                    .resume(
                        &run_id,
                        request
                            .params
                            .get("prompt")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                    )
                    .map_err(|e| (ERR_NOT_FOUND, e))?
                    .info();
                Ok(serde_json::to_value(info).unwrap_or(Value::Null))
            }
            "agent.fork" => {
                let run_id = param_str(&request.params, "run_id")?;
                let previous = self
                    .supervisor
                    .load_run(&run_id)
                    .ok_or_else(|| (ERR_NOT_FOUND, format!("agent run `{run_id}` not found")))?;
                let adapter = self
                    .supervisor
                    .adapter(&previous.adapter_id)
                    .cloned()
                    .ok_or_else(|| {
                        (
                            ERR_NOT_FOUND,
                            format!("adapter `{}` not found", previous.adapter_id),
                        )
                    })?;
                let info = self
                    .supervisor
                    .launch(LaunchOptions {
                        adapter,
                        prompt: request
                            .params
                            .get("prompt")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        model: previous.model.clone(),
                        cwd: PathBuf::from(&previous.workspace),
                        profile: previous.profile.clone(),
                        env: Vec::new(),
                        command_override: None,
                    })
                    .map_err(|e| (crate::protocol::ERR_INTERNAL, e))?
                    .info();
                Ok(serde_json::to_value(info).unwrap_or(Value::Null))
            }
            other => Err((ERR_METHOD_NOT_FOUND, format!("unknown method `{other}`"))),
        }
    }
}

fn event_notification(session_id: &str, event: &SessionEvent) -> Option<(&'static str, Value)> {
    match event {
        SessionEvent::Output(_) => None,
        SessionEvent::BlockStarted(block) => Some((
            "block.started",
            json!({"session_id": session_id, "block": block}),
        )),
        SessionEvent::BlockFinished(block) => Some((
            "block.finished",
            json!({"session_id": session_id, "block": block}),
        )),
        SessionEvent::CwdChanged(path) => Some((
            "cwd.changed",
            json!({"session_id": session_id, "path": path}),
        )),
        SessionEvent::TitleChanged(title) => Some((
            "title.changed",
            json!({"session_id": session_id, "title": title}),
        )),
        SessionEvent::Progress { state, pct } => Some((
            "progress",
            json!({"session_id": session_id, "state": state, "pct": pct}),
        )),
        SessionEvent::Notification { title, body } => Some((
            "notification",
            json!({"session_id": session_id, "title": title, "body": body}),
        )),
        SessionEvent::Exited { code } => Some((
            "session.exited",
            json!({"session_id": session_id, "code": code}),
        )),
    }
}

fn param_str(params: &Value, key: &str) -> std::result::Result<String, (i64, String)> {
    params
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| (ERR_INVALID_PARAMS, format!("missing `{key}`")))
}

fn map_session_error(error: SessionError) -> (i64, String) {
    let code = match error {
        SessionError::NotFound(_) => ERR_NOT_FOUND,
        SessionError::NotRunning(_) | SessionError::Unavailable(_) => ERR_UNAVAILABLE,
        _ => crate::protocol::ERR_INTERNAL,
    };
    (code, error.to_string())
}

fn prepare_socket(socket: &Path) -> Result<(), String> {
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let pid_file = pid_path(socket);
    if let Ok(pid) = std::fs::read_to_string(&pid_file) {
        if let Ok(pid) = pid.trim().parse::<i32>() {
            if process_alive(pid) {
                return Err(format!(
                    "another session daemon is already running (pid {pid}); socket {}",
                    socket.display()
                ));
            }
        }
    }
    let _ = std::fs::remove_file(socket);
    let _ = std::fs::remove_file(&pid_file);
    Ok(())
}

fn secure_socket(socket: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot secure socket: {e}"))?;
    }
    Ok(())
}

fn write_pid(socket: &Path) {
    let _ = std::fs::write(pid_path(socket), std::process::id().to_string());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(pid_path(socket), std::fs::Permissions::from_mode(0o600));
    }
}

#[cfg(unix)]
fn process_alive(pid: i32) -> bool {
    // Safety: signal 0 performs error checking only.
    unsafe { libc::kill(pid, 0) == 0 }
}

#[cfg(not(unix))]
fn process_alive(_pid: i32) -> bool {
    false
}

/// True when a daemon is accepting connections at `socket`.
pub fn is_running(socket: &Path) -> bool {
    if !socket.exists() {
        return false;
    }
    std::os::unix::net::UnixStream::connect(socket).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::SessionClient;
    use crate::manager::ManagerOptions;
    use z_config::Config;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-daemon-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn daemon_serves_create_input_attach_and_shutdown() {
        let dir = temp_dir("e2e");
        let socket = dir.join("session.sock");
        let manager = SessionManager::new(ManagerOptions::new(&dir, Config::default())).unwrap();
        let socket_for_daemon = socket.clone();
        let handle = std::thread::spawn(move || run(manager, socket_for_daemon));
        // Wait for the socket.
        let mut connected = None;
        for _ in 0..100 {
            if let Ok(client) = SessionClient::connect(&socket) {
                connected = Some(client);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let client = connected.expect("daemon did not start");
        let created = client
            .call(
                "session.create",
                json!({
                    "shell": "/bin/sh",
                    "cwd": dir.display().to_string(),
                    "rows": 24,
                    "cols": 80,
                    "integration": "off"
                }),
            )
            .expect("create");
        let id = created["id"].as_str().unwrap().to_string();
        assert!(created["integration"].as_bool() == Some(false));
        let input = base64::engine::general_purpose::STANDARD.encode(b"echo hello-daemon\n");
        client
            .call("session.input", json!({"session_id": id, "data": input}))
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let snapshot = client
            .call("session.snapshot", json!({"session_id": id}))
            .unwrap();
        assert!(snapshot["contents"]
            .as_str()
            .unwrap()
            .contains("hello-daemon"));
        assert!(!client.call("ping", json!({})).unwrap().is_null());
        client
            .call("session.close", json!({"session_id": id, "kill": true}))
            .unwrap();
        let _ = client.call("daemon.shutdown", json!({}));
        drop(client);
        let result = handle.join().unwrap();
        assert!(result.is_ok(), "{result:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_method_is_reported() {
        let dir = temp_dir("unknown");
        let socket = dir.join("session.sock");
        let manager = SessionManager::new(ManagerOptions::new(&dir, Config::default())).unwrap();
        let socket_for_daemon = socket.clone();
        let handle = std::thread::spawn(move || run(manager, socket_for_daemon));
        let client = loop {
            if let Ok(client) = SessionClient::connect(&socket) {
                break client;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        let error = client.call("does.not.exist", json!({})).unwrap_err();
        assert!(error.contains("unknown method"), "{error}");
        let _ = client.call("daemon.shutdown", json!({}));
        let _ = handle.join();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

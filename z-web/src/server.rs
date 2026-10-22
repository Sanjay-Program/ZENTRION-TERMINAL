//! Minimal HTTP/1.1 server and snapshot API.

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

const MAX_REQUEST: usize = 64 * 1024;
const MAX_INPUT: usize = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionSummary {
    pub id: String,
    pub title: String,
    pub shell: String,
    pub cwd: String,
    pub rows: u16,
    pub cols: u16,
    pub status: String,
    pub integration: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub id: String,
    pub title: String,
    pub cwd: String,
    pub seq: u64,
    pub contents: String,
    pub progress: Option<String>,
    pub blocks: Vec<BlockSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockSummary {
    pub command: String,
    pub status: String,
    pub exit_code: Option<i32>,
    pub id: String,
}

pub trait SessionProvider: Send + Sync {
    fn sessions(&self) -> Result<Vec<SessionSummary>, String>;
    fn snapshot(&self, id: &str) -> Result<SessionSnapshot, String>;
    fn input(&self, id: &str, data: &[u8]) -> Result<(), String>;
}

#[derive(Debug, Clone)]
pub struct WebConfig {
    pub bind: SocketAddr,
    pub read_token: String,
    /// `None` means the web client is strictly read-only.
    pub write_token: Option<String>,
    pub server_name: String,
}

impl WebConfig {
    pub fn new(bind: SocketAddr) -> Self {
        Self {
            bind,
            read_token: random_token(),
            write_token: None,
            server_name: "zentrion".into(),
        }
    }

    pub fn with_input(mut self) -> Self {
        self.write_token = Some(random_token());
        self
    }

    pub fn read_url(&self) -> String {
        format!("http://{}/?token={}", self.bind, self.read_token)
    }

    pub fn write_url(&self) -> Option<String> {
        self.write_token
            .as_ref()
            .map(|token| format!("http://{}/?token={token}", self.bind))
    }
}

pub fn random_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebError {
    Bind(String),
    Io(String),
    InvalidBind(String),
}

impl std::fmt::Display for WebError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind(message) => write!(f, "cannot bind web listener: {message}"),
            Self::Io(message) => write!(f, "web I/O error: {message}"),
            Self::InvalidBind(message) => write!(f, "invalid web bind: {message}"),
        }
    }
}

impl std::error::Error for WebError {}

/// Bind and serve until Ctrl+C. Refuses non-loopback addresses.
pub async fn serve(config: WebConfig, provider: Arc<dyn SessionProvider>) -> Result<(), WebError> {
    if !config.bind.ip().is_loopback() {
        return Err(WebError::InvalidBind(format!(
            "{} is not a loopback address; the web observer never binds publicly",
            config.bind
        )));
    }
    let listener = TcpListener::bind(config.bind)
        .await
        .map_err(|e| WebError::Bind(e.to_string()))?;
    let actual = listener
        .local_addr()
        .map_err(|e| WebError::Bind(e.to_string()))?;
    let config = WebConfig {
        bind: actual,
        ..config
    };
    let state = Arc::new(ServerState { config, provider });
    serve_listener(listener, state).await
}

struct ServerState {
    config: WebConfig,
    provider: Arc<dyn SessionProvider>,
}

async fn serve_listener(listener: TcpListener, state: Arc<ServerState>) -> Result<(), WebError> {
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _peer)) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            let _ = handle(stream, state).await;
                        });
                    }
                    Err(error) => {
                        eprintln!("z web: accept failed: {error}");
                    }
                }
            }
        }
    }
    Ok(())
}

/// Serve on an already-bound std listener (used by the CLI so the printed URL
/// always has the real port and there is no re-bind race).
pub async fn serve_on(
    listener: std::net::TcpListener,
    config: WebConfig,
    provider: Arc<dyn SessionProvider>,
) -> Result<(), WebError> {
    listener
        .set_nonblocking(true)
        .map_err(|e| WebError::Bind(e.to_string()))?;
    let listener = TcpListener::from_std(listener).map_err(|e| WebError::Bind(e.to_string()))?;
    let state = Arc::new(ServerState { config, provider });
    serve_listener(listener, state).await
}

/// Expose the listener's state constructor for tests and embedders.
#[cfg(test)]
fn state(config: WebConfig, provider: Arc<dyn SessionProvider>) -> Arc<ServerState> {
    Arc::new(ServerState { config, provider })
}

async fn handle(mut stream: TcpStream, state: Arc<ServerState>) -> std::io::Result<()> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&chunk[..n]);
        if buffer.len() > MAX_REQUEST {
            return respond(&mut stream, 413, "text/plain", "request too large").await;
        }
        if let Some(position) = find_header_end(&buffer) {
            break position;
        }
    };
    // The body may arrive in later TCP segments than the headers. Read until
    // the declared Content-Length is present, rather than assuming one read.
    let body_start = header_end + 4;
    let content_length = match content_length_from_headers(&buffer[..header_end]) {
        Ok(length) => length,
        Err(message) => return respond(&mut stream, 400, "text/plain", &message).await,
    };
    while buffer.len() < body_start + content_length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return respond(&mut stream, 400, "text/plain", "incomplete body").await;
        }
        buffer.extend_from_slice(&chunk[..n]);
        if buffer.len() > MAX_REQUEST {
            return respond(&mut stream, 413, "text/plain", "request too large").await;
        }
    }
    let request = match Request::parse(&buffer, header_end) {
        Ok(request) => request,
        Err(message) => {
            return respond(&mut stream, 400, "text/plain", &message).await;
        }
    };
    if request.method == "GET"
        && request.path.starts_with("/api/session/")
        && request.path.ends_with("/stream")
    {
        let read_ok = token_matches(request.token(), &state.config.read_token)
            || state
                .config
                .write_token
                .as_ref()
                .map(|token| token_matches(request.token(), token))
                .unwrap_or(false);
        if !read_ok {
            return respond(&mut stream, 401, "text/plain", "missing or invalid token").await;
        }
        let session_part = request
            .path
            .trim_start_matches("/api/session/")
            .trim_end_matches("/stream");
        let id = session_part.trim();
        if !valid_session_id(id) {
            return respond(&mut stream, 400, "text/plain", "invalid session id").await;
        }
        let sse_header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
        let mut last_seq = u64::MAX;
        let mut initial_data = String::new();
        if let Ok(snapshot) = state.provider.snapshot(id) {
            last_seq = snapshot.seq;
            let json_str = serde_json::to_string(&snapshot).unwrap_or_default();
            initial_data = format!("data: {json_str}\n\n");
        }
        let sse_payload = format!("{sse_header}{initial_data}");
        if stream.write_all(sse_payload.as_bytes()).await.is_err() {
            return Ok(());
        }
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
        loop {
            interval.tick().await;
            match state.provider.snapshot(id) {
                Ok(snapshot) => {
                    if snapshot.seq != last_seq {
                        last_seq = snapshot.seq;
                        let json_str = serde_json::to_string(&snapshot).unwrap_or_default();
                        let event = format!("data: {json_str}\n\n");
                        if stream.write_all(event.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                }
                Err(_) => {
                    let _ = stream
                        .write_all(b"event: error\ndata: session closed\n\n")
                        .await;
                    break;
                }
            }
        }
        return Ok(());
    }
    let response = route(&request, &state).await;
    match response {
        Ok((status, content_type, body)) => {
            respond(&mut stream, status, &content_type, &body).await
        }
        Err((status, message)) => respond(&mut stream, status, "text/plain", &message).await,
    }
}

/// Parse the Content-Length header from an already-read header block.
fn content_length_from_headers(head: &[u8]) -> Result<usize, String> {
    let head =
        std::str::from_utf8(head).map_err(|_| "request headers are not UTF-8".to_string())?;
    let mut length = 0usize;
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            length = value
                .trim()
                .parse()
                .map_err(|_| "invalid Content-Length".to_string())?;
        }
    }
    if length > MAX_REQUEST {
        return Err("request body too large".into());
    }
    Ok(length)
}

struct Request {
    method: String,
    path: String,
    query: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl Request {
    fn parse(buffer: &[u8], header_end: usize) -> Result<Self, String> {
        let head = std::str::from_utf8(&buffer[..header_end])
            .map_err(|_| "request headers are not UTF-8".to_string())?;
        let mut lines = head.split("\r\n");
        let request_line = lines.next().ok_or("missing request line")?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next().ok_or("missing method")?.to_string();
        let target = parts.next().ok_or("missing path")?.to_string();
        let version = parts.next().unwrap_or("");
        if !version.starts_with("HTTP/1.") {
            return Err("unsupported HTTP version".into());
        }
        if !matches!(method.as_str(), "GET" | "POST") {
            return Err("method not allowed".into());
        }
        let (path, raw_query) = target.split_once('?').unwrap_or((&target, ""));
        if path.contains("..") || path.contains('\0') {
            return Err("invalid path".into());
        }
        let query = parse_query(raw_query);
        let mut content_length = 0usize;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().map_err(|_| "invalid Content-Length")?;
            }
        }
        if content_length > MAX_REQUEST {
            return Err("request body too large".into());
        }
        let body_start = header_end + 4;
        if buffer.len() < body_start + content_length {
            return Err("incomplete body".into());
        }
        Ok(Self {
            method,
            path: path.to_string(),
            query,
            body: buffer[body_start..body_start + content_length].to_vec(),
        })
    }

    fn token(&self) -> &str {
        self.query.get("token").map(String::as_str).unwrap_or("")
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_query(query: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        values.insert(percent_decode(key), percent_decode(value));
    }
    values
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                if let Ok(byte) =
                    u8::from_str_radix(&String::from_utf8_lossy(&bytes[index + 1..index + 3]), 16)
                {
                    out.push(byte);
                    index += 3;
                    continue;
                }
                out.push(bytes[index]);
            }
            b'+' => out.push(b' '),
            byte => out.push(byte),
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

async fn route(
    request: &Request,
    state: &ServerState,
) -> Result<(u16, String, String), (u16, String)> {
    let read_ok = token_matches(request.token(), &state.config.read_token)
        || state
            .config
            .write_token
            .as_ref()
            .map(|token| token_matches(request.token(), token))
            .unwrap_or(false);
    let write_ok = state
        .config
        .write_token
        .as_ref()
        .map(|token| token_matches(request.token(), token))
        .unwrap_or(false);
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/api/health") => Ok((
            200,
            "application/json".into(),
            serde_json::json!({"ok": true, "server": state.config.server_name}).to_string(),
        )),
        ("GET", "/") => {
            if !read_ok {
                return Err((401, "missing or invalid token".into()));
            }
            Ok((200, "text/html; charset=utf-8".into(), app_html()))
        }
        ("GET", "/api/whoami") => {
            if !read_ok {
                return Err((401, "missing or invalid token".into()));
            }
            Ok((
                200,
                "application/json".into(),
                serde_json::json!({"read": true, "write": write_ok}).to_string(),
            ))
        }
        ("GET", "/api/sessions") => {
            if !read_ok {
                return Err((401, "missing or invalid token".into()));
            }
            match state.provider.sessions() {
                Ok(sessions) => Ok((
                    200,
                    "application/json".into(),
                    serde_json::to_string(&sessions).unwrap_or_else(|_| "[]".into()),
                )),
                Err(error) => Err((500, error)),
            }
        }
        ("GET", path) if path.starts_with("/api/session/") => {
            if !read_ok {
                return Err((401, "missing or invalid token".into()));
            }
            let id = path.trim_start_matches("/api/session/");
            if !valid_session_id(id) {
                return Err((400, "invalid session id".into()));
            }
            match state.provider.snapshot(id) {
                Ok(snapshot) => Ok((
                    200,
                    "application/json".into(),
                    serde_json::to_string(&snapshot).unwrap_or_else(|_| "{}".into()),
                )),
                Err(error) => Err((404, error)),
            }
        }
        ("POST", "/api/input") => {
            if !write_ok {
                return Err((403, "this token is read-only".into()));
            }
            let body: serde_json::Value = serde_json::from_slice(&request.body)
                .map_err(|e| (400, format!("invalid JSON: {e}")))?;
            let id = body
                .get("session_id")
                .and_then(|value| value.as_str())
                .ok_or((400, "missing session_id".to_string()))?;
            if !valid_session_id(id) {
                return Err((400, "invalid session id".into()));
            }
            let data = body
                .get("data")
                .and_then(|value| value.as_str())
                .ok_or((400, "missing data".to_string()))?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(data)
                .map_err(|e| (400, format!("data is not base64: {e}")))?;
            if bytes.len() > MAX_INPUT {
                return Err((413, "input too large".into()));
            }
            match state.provider.input(id, &bytes) {
                Ok(()) => Ok((
                    200,
                    "application/json".into(),
                    serde_json::json!({"accepted": bytes.len()}).to_string(),
                )),
                Err(error) => Err((400, error)),
            }
        }
        _ => Err((404, "not found".into())),
    }
}

fn valid_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() < 80
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn token_matches(candidate: &str, expected: &str) -> bool {
    if candidate.len() != expected.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in candidate.bytes().zip(expected.bytes()) {
        difference |= a ^ b;
    }
    difference == 0
}

async fn respond(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await.ok();
    Ok(())
}

fn app_html() -> String {
    r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Zentrion Terminal Observer</title>
<style>
:root {
  --bg: #090b10;
  --surface: #11151c;
  --border: #1e2633;
  --primary: #38bdf8;
  --accent: #f59e0b;
  --text: #e2e8f0;
  --muted: #64748b;
  --success: #10b981;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}
header {
  padding: .75rem 1.25rem;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  display: flex;
  gap: 1rem;
  align-items: center;
  flex-wrap: wrap;
}
.brand {
  font-weight: 700;
  font-size: 1.05rem;
  color: var(--primary);
  display: flex;
  align-items: center;
  gap: .5rem;
}
.traffic-lights {
  display: flex;
  gap: .35rem;
  margin-right: .5rem;
}
.dot { width: 10px; height: 10px; border-radius: 50%; }
.dot-red { background: #ef4444; }
.dot-yellow { background: #f59e0b; }
.dot-green { background: #10b981; }

select, button, input {
  background: #0f141d;
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: .4rem .75rem;
  font: inherit;
  font-size: .9rem;
  transition: border-color .15s;
}
select:focus, button:focus, input:focus {
  outline: none;
  border-color: var(--primary);
}
button { cursor: pointer; }
button:hover { background: #1a222e; }

.pill {
  font-size: .75rem;
  padding: .2rem .55rem;
  border-radius: 9999px;
  font-weight: 600;
}
.pill-active { background: rgba(16, 185, 129, .15); color: var(--success); border: 1px solid rgba(16, 185, 129, .3); }
.pill-warning { background: rgba(245, 158, 11, .15); color: var(--accent); border: 1px solid rgba(245, 158, 11, .3); }

main {
  flex: 1;
  padding: 1.25rem;
  display: flex;
  flex-direction: column;
  max-width: 1400px;
  width: 100%;
  margin: 0 auto;
}
.term-window {
  background: #080a0e;
  border: 1px solid var(--border);
  border-radius: 8px;
  box-shadow: 0 10px 25px -5px rgba(0,0,0,.5);
  display: flex;
  flex-direction: column;
  flex: 1;
  overflow: hidden;
}
.term-bar {
  padding: .5rem 1rem;
  background: #0d1117;
  border-bottom: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: .8rem;
  color: var(--muted);
}
#screen {
  margin: 0;
  padding: 1.25rem;
  white-space: pre-wrap;
  word-break: break-word;
  min-height: 55vh;
  flex: 1;
  overflow: auto;
  font-size: .92rem;
  line-height: 1.35;
}
.cursor {
  display: inline-block;
  width: 8px;
  height: 1.1em;
  background: var(--primary);
  vertical-align: text-bottom;
  animation: blink 1s step-start infinite;
}
@keyframes blink { 50% { opacity: 0; } }

#inputrow {
  display: none;
  gap: .5rem;
  padding: .75rem 1rem;
  background: #0d1117;
  border-top: 1px solid var(--border);
}
#inputrow input { flex: 1; }

/* ANSI Color Classes */
.ansi-bold { font-weight: bold; }
.ansi-dim { opacity: 0.65; }
.ansi-italic { font-style: italic; }
.ansi-underline { text-decoration: underline; }
.ansi-fg-black { color: #1e293b; }
.ansi-fg-red { color: #f87171; }
.ansi-fg-green { color: #34d399; }
.ansi-fg-yellow { color: #fbbf24; }
.ansi-fg-blue { color: #60a5fa; }
.ansi-fg-magenta { color: #c084fc; }
.ansi-fg-cyan { color: #38bdf8; }
.ansi-fg-white { color: #f1f5f9; }
.ansi-fg-bright-black { color: #64748b; }
.ansi-fg-bright-red { color: #ef4444; }
.ansi-fg-bright-green { color: #10b981; }
.ansi-fg-bright-yellow { color: #f59e0b; }
.ansi-fg-bright-blue { color: #3b82f6; }
.ansi-fg-bright-magenta { color: #a855f7; }
.ansi-fg-bright-cyan { color: #06b6d4; }
.ansi-fg-bright-white { color: #ffffff; }
.ansi-bg-red { background: #7f1d1d; }
.ansi-bg-green { background: #064e3b; }
.ansi-bg-blue { background: #1e3a8a; }
</style>
</head>
<body>
<header>
  <div class="brand">
    <div class="traffic-lights">
      <div class="dot dot-red"></div>
      <div class="dot dot-yellow"></div>
      <div class="dot dot-green"></div>
    </div>
    ZENTRION
  </div>
  <select id="sessions" title="Active session"></select>
  <button id="refresh" title="Reload sessions">↻ refresh</button>
  <button id="ctrlc" title="Send interrupt">^C Interrupt</button>
  <button id="copy" title="Copy output">📋 copy</button>
  <span id="stream-status" class="pill pill-active">⚡ Live</span>
  <span id="banner" class="pill pill-warning">connecting…</span>
</header>
<main>
  <div class="term-window">
    <div class="term-bar">
      <span id="term-title">Session: loading…</span>
      <span id="term-meta">seq: 0</span>
    </div>
    <div id="screen"></div>
    <div id="inputrow">
      <input id="input" placeholder="Type a command and press Enter…" autocomplete="off" spellcheck="false">
      <button id="send">Send</button>
    </div>
  </div>
</main>
<script>
const params = new URLSearchParams(location.search);
const token = params.get('token') || '';
const api = (path) => path + (path.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(token);
let current = null;
let write = false;
let sseSource = null;
let pollTimer = null;
let rawText = '';
const history = [];
let historyIndex = -1;

function ansiToHtml(text) {
  let out = '';
  let inSpan = false;
  let i = 0;
  while (i < text.length) {
    if (text[i] === '\x1b' && text[i + 1] === '[') {
      let mPos = text.indexOf('m', i + 2);
      if (mPos !== -1 && mPos - i <= 24) {
        let codes = text.substring(i + 2, mPos).split(';').map(c => parseInt(c, 10) || 0);
        i = mPos + 1;
        if (inSpan) { out += '</span>'; inSpan = false; }
        let classes = [];
        let style = '';
        for (let j = 0; j < codes.length; j++) {
          let code = codes[j];
          if (code === 0) { /* reset */ }
          else if (code === 1) classes.push('ansi-bold');
          else if (code === 2) classes.push('ansi-dim');
          else if (code === 3) classes.push('ansi-italic');
          else if (code === 4) classes.push('ansi-underline');
          else if (code >= 30 && code <= 37) classes.push('ansi-fg-' + ['black','red','green','yellow','blue','magenta','cyan','white'][code - 30]);
          else if (code >= 90 && code <= 97) classes.push('ansi-fg-bright-' + ['black','red','green','yellow','blue','magenta','cyan','white'][code - 90]);
          else if (code >= 40 && code <= 47) classes.push('ansi-bg-' + ['black','red','green','yellow','blue','magenta','cyan','white'][code - 40]);
          else if (code === 38 && codes[j + 1] === 5 && codes[j + 2] !== undefined) {
            style += `color: hsl(${codes[j + 2] * 1.4}, 75%, 65%);`;
            j += 2;
          }
        }
        if (classes.length > 0 || style.length > 0) {
          out += `<span class="${classes.join(' ')}" style="${style}">`;
          inSpan = true;
        }
        continue;
      }
    }
    let c = text[i];
    if (c === '&') out += '&amp;';
    else if (c === '<') out += '&lt;';
    else if (c === '>') out += '&gt;';
    else out += c;
    i++;
  }
  if (inSpan) out += '</span>';
  return out;
}

async function whoami() {
  try {
    const r = await fetch(api('/api/whoami'));
    if (!r.ok) throw new Error('token rejected');
    const j = await r.json();
    write = !!j.write;
    document.getElementById('inputrow').style.display = write ? 'flex' : 'none';
    document.getElementById('banner').textContent = write ? 'Read/Write Mode' : 'Read-Only Observer';
  } catch (e) {
    document.getElementById('banner').textContent = 'Unauthorized';
  }
}

async function loadSessions() {
  try {
    const r = await fetch(api('/api/sessions'));
    if (!r.ok) return;
    const sessions = await r.json();
    const select = document.getElementById('sessions');
    const prev = current;
    select.innerHTML = '';
    sessions.forEach(s => {
      const opt = document.createElement('option');
      opt.value = s.id;
      opt.textContent = `${s.title} · ${s.status}`;
      select.appendChild(opt);
    });
    if (prev && sessions.some(s => s.id === prev)) select.value = prev;
    current = select.value || null;
    connectSessionStream();
  } catch (_) {}
}

function connectSessionStream() {
  if (sseSource) {
    sseSource.close();
    sseSource = null;
  }
  if (!current) return;

  const streamUrl = api('/api/session/' + encodeURIComponent(current) + '/stream');
  try {
    sseSource = new EventSource(streamUrl);
    sseSource.onmessage = (e) => {
      document.getElementById('stream-status').textContent = '⚡ SSE Live';
      document.getElementById('stream-status').className = 'pill pill-active';
      const snap = JSON.parse(e.data);
      renderSnapshot(snap);
    };
    sseSource.onerror = () => {
      document.getElementById('stream-status').textContent = '↻ Polling';
      document.getElementById('stream-status').className = 'pill pill-warning';
      if (sseSource) { sseSource.close(); sseSource = null; }
      refreshSnapshot();
    };
  } catch (_) {
    refreshSnapshot();
  }
}

async function refreshSnapshot() {
  if (!current) return;
  try {
    const r = await fetch(api('/api/session/' + encodeURIComponent(current)));
    if (!r.ok) return;
    const snap = await r.json();
    renderSnapshot(snap);
  } catch (_) {}
}

function renderSnapshot(snap) {
  rawText = snap.contents;
  const screen = document.getElementById('screen');
  screen.innerHTML = ansiToHtml(snap.contents) + '<span class="cursor"></span>';
  screen.scrollTop = screen.scrollHeight;
  document.getElementById('term-title').textContent = `${snap.title} · ${snap.cwd}`;
  document.getElementById('term-meta').textContent = `seq: ${snap.seq}${snap.progress ? ' · ' + snap.progress : ''}`;
}

async function send(text) {
  if (!current || !write) return;
  const bytes = new TextEncoder().encode(text);
  let binary = '';
  bytes.forEach(b => binary += String.fromCharCode(b));
  const data = btoa(binary);
  await fetch(api('/api/input'), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ session_id: current, data })
  });
  setTimeout(refreshSnapshot, 60);
}

document.getElementById('sessions').addEventListener('change', e => {
  current = e.target.value;
  connectSessionStream();
});
document.getElementById('refresh').addEventListener('click', loadSessions);
document.getElementById('ctrlc').addEventListener('click', () => send('\u0003'));
document.getElementById('copy').addEventListener('click', () => {
  navigator.clipboard.writeText(rawText);
  document.getElementById('copy').textContent = '✓ copied!';
  setTimeout(() => document.getElementById('copy').textContent = '📋 copy', 1500);
});

const inputEl = document.getElementById('input');
document.getElementById('send').addEventListener('click', () => {
  if (inputEl.value) {
    history.push(inputEl.value);
    historyIndex = history.length;
    send(inputEl.value + '\r');
    inputEl.value = '';
  }
});
inputEl.addEventListener('keydown', e => {
  if (e.key === 'Enter') {
    document.getElementById('send').click();
  } else if (e.key === 'ArrowUp') {
    if (historyIndex > 0) {
      historyIndex--;
      inputEl.value = history[historyIndex] || '';
    }
  } else if (e.key === 'ArrowDown') {
    if (historyIndex < history.length - 1) {
      historyIndex++;
      inputEl.value = history[historyIndex] || '';
    } else {
      historyIndex = history.length;
      inputEl.value = '';
    }
  }
});

whoami().then(loadSessions);
pollTimer = setInterval(() => { if (!sseSource) refreshSnapshot(); }, 600);
window.addEventListener('beforeunload', () => {
  if (sseSource) sseSource.close();
  clearInterval(pollTimer);
});
</script>
</body>
</html>"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    struct FakeProvider {
        sessions: Vec<SessionSummary>,
        input: std::sync::Mutex<Vec<u8>>,
    }

    impl SessionProvider for FakeProvider {
        fn sessions(&self) -> Result<Vec<SessionSummary>, String> {
            Ok(self.sessions.clone())
        }
        fn snapshot(&self, id: &str) -> Result<SessionSnapshot, String> {
            if self.sessions.iter().any(|session| session.id == id) {
                Ok(SessionSnapshot {
                    id: id.to_string(),
                    title: "fake".into(),
                    cwd: "/tmp".into(),
                    seq: 7,
                    contents: "hello web\n".into(),
                    progress: None,
                    blocks: vec![],
                })
            } else {
                Err("not found".into())
            }
        }
        fn input(&self, _id: &str, data: &[u8]) -> Result<(), String> {
            self.input.lock().unwrap().extend_from_slice(data);
            Ok(())
        }
    }

    fn provider() -> Arc<FakeProvider> {
        Arc::new(FakeProvider {
            sessions: vec![SessionSummary {
                id: "s_test".into(),
                title: "test".into(),
                shell: "/bin/bash".into(),
                cwd: "/tmp".into(),
                rows: 24,
                cols: 80,
                status: "running".into(),
                integration: true,
            }],
            input: std::sync::Mutex::new(Vec::new()),
        })
    }

    async fn request(addr: SocketAddr, raw: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(raw.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn auth_scopes_and_snapshot_api() {
        let provider = provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = WebConfig::new(addr);
        config.write_token = Some("write-token".into());
        config.read_token = "read-token".into();
        let state = state(config, provider.clone());
        tokio::spawn(async move { serve_listener(listener, state).await });
        let health = request(addr, "GET /api/health HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(health.starts_with("HTTP/1.1 200"));
        let unauthorized = request(addr, "GET /api/sessions HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(unauthorized.starts_with("HTTP/1.1 401"), "{unauthorized}");
        let sessions = request(
            addr,
            "GET /api/sessions?token=read-token HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .await;
        assert!(sessions.starts_with("HTTP/1.1 200"));
        assert!(sessions.contains("s_test"));
        let snapshot = request(
            addr,
            "GET /api/session/s_test?token=read-token HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .await;
        assert!(snapshot.contains("hello web"));
        let body = "{\"session_id\":\"s_test\",\"data\":\"aGk=\"}";
        let denied_input = request(
            addr,
            &format!(
                "POST /api/input?token=read-token HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert!(denied_input.starts_with("HTTP/1.1 403"), "{denied_input}");
        let accepted = request(
            addr,
            &format!(
                "POST /api/input?token=write-token HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert!(accepted.starts_with("HTTP/1.1 200"), "{accepted}");
        assert_eq!(&provider.input.lock().unwrap()[..], b"hi");
    }

    #[tokio::test]
    async fn web_rejects_non_loopback_bind() {
        let config = WebConfig::new("0.0.0.0:0".parse().unwrap());
        let error = serve(config, provider()).await.unwrap_err();
        assert!(matches!(error, WebError::InvalidBind(_)));
    }

    #[tokio::test]
    async fn sse_streaming_endpoint_serves_events() {
        let provider = provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = WebConfig::new(addr);
        config.read_token = "stream-token".into();
        let state = state(config, provider.clone());
        tokio::spawn(async move { serve_listener(listener, state).await });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req = "GET /api/session/s_test/stream?token=stream-token HTTP/1.1\r\nHost: x\r\n\r\n";
        stream.write_all(req.as_bytes()).await.unwrap();

        let mut resp = String::new();
        let mut buf = [0u8; 1024];
        let started = std::time::Instant::now();
        while !resp.contains("data:") && started.elapsed() < std::time::Duration::from_secs(3) {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            resp.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("Content-Type: text/event-stream"));
        assert!(resp.contains("data:"));
        assert!(resp.contains("hello web"));
    }
}

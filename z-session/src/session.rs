//! PTY-backed sessions: reader thread, VT screen, shell marks, blocks, ring
//! buffer and event fan-out.
//!
//! A session outlives every UI client. The reader thread owns the PTY output
//! path; clients only subscribe to events. Block output is collected between
//! `OSC 133;C` and `OSC 133;D`, never scraped from the screen.

use crate::integration;
use chrono::{DateTime, Utc};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::sync::broadcast;
use uuid::Uuid;
use z_blocks::{Block, BlockRecorder, BlockStatus, RecorderUpdate};
use z_config::ShellIntegration;
use z_vt::{OscEvent, ProgressState, ShellIntegrationMeta, ShellMark, Terminal};

const READ_CHUNK: usize = 16 * 1024;
const RING_BYTES: usize = 8 * 1024 * 1024;
const MAX_MARK_BYTES: usize = 8 * 1024;

pub type BlockSink = Arc<dyn Fn(Block, Vec<u8>) + Send + Sync>;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("pty error: {0}")]
    Pty(String),
    #[error("session I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("session `{0}` not found")]
    NotFound(String),
    #[error("session `{0}` is not running")]
    NotRunning(String),
    #[error("session output is not available: {0}")]
    Unavailable(String),
}

pub type Result<T> = std::result::Result<T, SessionError>;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub title: String,
    pub shell: String,
    pub cwd: String,
    pub rows: u16,
    pub cols: u16,
    pub created_at: DateTime<Utc>,
    pub status: String,
    pub pid: Option<u32>,
    pub integration: bool,
    pub shell_kind: String,
}

#[derive(Debug, Clone)]
pub enum SessionEvent {
    Output(OutputChunk),
    BlockStarted(Block),
    BlockFinished(Block),
    CwdChanged(String),
    TitleChanged(String),
    Progress {
        state: ProgressState,
        pct: Option<u8>,
    },
    Notification {
        title: String,
        body: String,
    },
    Exited {
        code: Option<i32>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputChunk {
    pub seq: u64,
    pub session_id: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub info: SessionInfo,
    pub seq: u64,
    pub keyframe: String,
    pub contents: String,
    pub cwd: Option<String>,
    pub title: Option<String>,
    pub progress: Option<(ProgressState, Option<u8>)>,
    pub running_block: Option<Block>,
}

#[derive(Debug, Clone)]
pub struct SessionOptions {
    pub shell: String,
    pub cwd: PathBuf,
    pub env: Vec<(String, String)>,
    pub rows: u16,
    pub cols: u16,
    pub scrollback: usize,
    pub title: Option<String>,
    pub integration: ShellIntegration,
    pub integration_dir: Option<PathBuf>,
    pub command_file: PathBuf,
    pub login: bool,
    pub heuristic_blocks: bool,
}

impl SessionOptions {
    pub fn new(shell: impl Into<String>, cwd: impl Into<PathBuf>) -> Self {
        Self {
            shell: shell.into(),
            cwd: cwd.into(),
            env: Vec::new(),
            rows: 40,
            cols: 120,
            scrollback: 100_000,
            title: None,
            integration: ShellIntegration::Auto,
            integration_dir: integration::default_integration_dir(),
            command_file: std::env::temp_dir().join("zentrion-cmd"),
            login: false,
            heuristic_blocks: false,
        }
    }
}

/// Bounded output ring, indexed by monotonic sequence number.
#[derive(Debug)]
pub struct RingBuffer {
    chunks: VecDeque<OutputChunk>,
    bytes: usize,
    capacity: usize,
}

impl RingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            chunks: VecDeque::new(),
            bytes: 0,
            capacity: capacity.max(READ_CHUNK),
        }
    }

    pub fn push(&mut self, chunk: OutputChunk) {
        self.bytes += chunk.data.len();
        self.chunks.push_back(chunk);
        while self.bytes > self.capacity {
            if let Some(old) = self.chunks.pop_front() {
                self.bytes = self.bytes.saturating_sub(old.data.len());
            } else {
                break;
            }
        }
    }

    pub fn since(&self, seq: u64) -> Vec<&OutputChunk> {
        self.chunks.iter().filter(|chunk| chunk.seq > seq).collect()
    }

    pub fn latest_seq(&self) -> u64 {
        self.chunks.back().map(|chunk| chunk.seq).unwrap_or(0)
    }

    pub fn oldest_seq(&self) -> Option<u64> {
        self.chunks.front().map(|chunk| chunk.seq)
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    Prompt,
    Command,
    Output,
    Finished(Option<i32>),
}

/// A chunk of terminal bytes, optionally beginning at a shell mark.
#[derive(Debug, Clone)]
pub struct Segment {
    pub bytes: Vec<u8>,
    pub mark: Option<Mark>,
}

/// Splits a byte stream at `OSC 133` markers while preserving all bytes.
/// Partial markers are carried to the next chunk; an unterminated marker is
/// bounded so a hostile stream cannot grow memory without limit.
#[derive(Debug, Default)]
pub struct MarkerSplitter {
    carry: Vec<u8>,
}

const MARK_PREFIX: &[u8] = b"\x1b]133;";

impl MarkerSplitter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) -> Vec<Segment> {
        let mut buffer = std::mem::take(&mut self.carry);
        buffer.extend_from_slice(bytes);
        let mut segments = Vec::new();
        let mut pos = 0usize;
        loop {
            let Some(relative) = find(&buffer[pos..], MARK_PREFIX) else {
                // Keep a suffix that could be the start of a marker.
                let keep = partial_prefix_suffix(&buffer[pos..]);
                let end = buffer.len() - keep;
                if end > pos {
                    segments.push(Segment {
                        bytes: buffer[pos..end].to_vec(),
                        mark: None,
                    });
                }
                if keep > 0 {
                    self.carry = buffer[end..].to_vec();
                }
                break;
            };
            let start = pos + relative;
            if start > pos {
                segments.push(Segment {
                    bytes: buffer[pos..start].to_vec(),
                    mark: None,
                });
            }
            let content_start = start + MARK_PREFIX.len();
            let (content_end, next) = match find_terminator(&buffer[content_start..]) {
                Some((content_len, consumed)) => (
                    content_start + content_len,
                    content_start + content_len + consumed,
                ),
                None => {
                    if buffer.len() - start > MAX_MARK_BYTES {
                        // Malformed/hostile: emit as ordinary data.
                        segments.push(Segment {
                            bytes: buffer[start..].to_vec(),
                            mark: None,
                        });
                        break;
                    }
                    self.carry = buffer[start..].to_vec();
                    break;
                }
            };
            let payload = &buffer[content_start..content_end];
            let mark = parse_mark(payload);
            segments.push(Segment {
                bytes: buffer[start..next].to_vec(),
                mark,
            });
            pos = next;
        }
        segments
    }
}

fn parse_mark(payload: &[u8]) -> Option<Mark> {
    match payload.first().copied() {
        Some(b'A') => Some(Mark::Prompt),
        Some(b'B') => Some(Mark::Command),
        Some(b'C') => Some(Mark::Output),
        Some(b'D') => {
            let code = payload
                .strip_prefix(b"D;")
                .and_then(|rest| std::str::from_utf8(rest).ok())
                .and_then(|rest| rest.trim().parse::<i32>().ok());
            Some(Mark::Finished(code))
        }
        _ => None,
    }
}

/// Find the OSC terminator: BEL or ST (`ESC \`). Returns (content length,
/// terminator length).
fn find_terminator(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            0x07 => return Some((index, 1)),
            0x1b if bytes.get(index + 1) == Some(&b'\\') => return Some((index, 2)),
            _ => index += 1,
        }
    }
    None
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn partial_prefix_suffix(bytes: &[u8]) -> usize {
    let max = bytes.len().min(MARK_PREFIX.len().saturating_sub(1));
    for len in (1..=max).rev() {
        if bytes.ends_with(&MARK_PREFIX[..len]) {
            return len;
        }
    }
    0
}

struct Core {
    terminal: Terminal,
    recorder: BlockRecorder,
    ring: RingBuffer,
    splitter: MarkerSplitter,
    collecting: bool,
    title: Option<String>,
    progress: Option<(ProgressState, Option<u8>)>,
}

pub struct SessionHandle {
    info: Mutex<SessionInfo>,
    core: Mutex<Core>,
    seq: AtomicU64,
    master: Mutex<Box<dyn MasterPty + Send>>,
    writer: Mutex<Box<dyn Write + Send>>,
    child: Mutex<Box<dyn Child + Send + Sync>>,
    events: broadcast::Sender<SessionEvent>,
    alive: AtomicBool,
    command_file: PathBuf,
    block_sink: Option<BlockSink>,
    heuristic: bool,
    heuristic_line: Mutex<Vec<u8>>,
}

impl std::fmt::Debug for SessionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionHandle")
            .field("info", &self.info())
            .finish()
    }
}

impl SessionHandle {
    /// Spawn a shell in a new PTY and start the reader thread.
    pub fn spawn(options: SessionOptions, block_sink: Option<BlockSink>) -> Result<Arc<Self>> {
        let id = format!("s_{}", Uuid::new_v4().simple());
        let launch = integration::plan_launch(
            &options.shell,
            options.integration,
            options.integration_dir.as_deref(),
            &id,
            &options.command_file,
            &options.env,
            options.login,
        );
        let pty_system = native_pty_system();
        let size = PtySize {
            rows: options.rows.max(2),
            cols: options.cols.max(2),
            pixel_width: 0,
            pixel_height: 0,
        };
        let pair = pty_system
            .openpty(size)
            .map_err(|e| SessionError::Pty(e.to_string()))?;
        let mut command = CommandBuilder::new(&launch.program);
        for arg in &launch.args {
            command.arg(arg);
        }
        if options.cwd.exists() {
            command.cwd(&options.cwd);
        }
        for (key, value) in &launch.env {
            command.env(key, value);
        }
        let child = pair
            .slave
            .spawn_command(command)
            .map_err(|e| SessionError::Pty(e.to_string()))?;
        drop(pair.slave);
        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| SessionError::Pty(e.to_string()))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| SessionError::Pty(e.to_string()))?;

        let title = options.title.clone().unwrap_or_else(|| {
            options
                .cwd
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| format!("{} — {}", launch.shell.name(), name))
                .unwrap_or_else(|| launch.shell.name().to_string())
        });
        let pid = child.process_id();
        let info = SessionInfo {
            id: id.clone(),
            title,
            shell: options.shell.clone(),
            cwd: options.cwd.display().to_string(),
            rows: size.rows,
            cols: size.cols,
            created_at: Utc::now(),
            status: "running".into(),
            pid,
            integration: launch.integration,
            shell_kind: launch.shell.name().to_string(),
        };
        let (events, _) = broadcast::channel(1024);
        let session = Arc::new(Self {
            info: Mutex::new(info),
            core: Mutex::new(Core {
                terminal: Terminal::new(size.rows, size.cols, options.scrollback),
                recorder: BlockRecorder::new(
                    &id,
                    &options.shell,
                    options.cwd.display().to_string(),
                ),
                ring: RingBuffer::new(RING_BYTES),
                splitter: MarkerSplitter::new(),
                collecting: false,
                title: None,
                progress: None,
            }),
            seq: AtomicU64::new(0),
            master: Mutex::new(pair.master),
            writer: Mutex::new(writer),
            child: Mutex::new(child),
            events,
            alive: AtomicBool::new(true),
            command_file: options.command_file.clone(),
            block_sink,
            heuristic: options.heuristic_blocks && !launch.integration,
            heuristic_line: Mutex::new(Vec::new()),
        });
        let reader_session = Arc::clone(&session);
        std::thread::Builder::new()
            .name(format!("z-session-{id}"))
            .spawn(move || reader_session.reader_loop(reader))
            .map_err(|e| SessionError::Pty(format!("cannot start reader thread: {e}")))?;
        Ok(session)
    }

    pub fn info(&self) -> SessionInfo {
        self.info.lock().expect("session info lock").clone()
    }

    pub fn id(&self) -> String {
        self.info.lock().expect("session info lock").id.clone()
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SessionEvent> {
        self.events.subscribe()
    }

    pub fn latest_seq(&self) -> u64 {
        self.seq.load(Ordering::SeqCst)
    }

    pub fn snapshot(&self) -> SessionSnapshot {
        let core = self.core.lock().expect("session core lock");
        SessionSnapshot {
            info: self.info(),
            seq: self.seq.load(Ordering::SeqCst),
            keyframe: core.terminal.keyframe(),
            contents: core.terminal.contents(),
            cwd: core.terminal.cwd().map(str::to_string),
            title: core
                .title
                .clone()
                .or_else(|| core.terminal.title().map(str::to_string)),
            progress: core.progress.or_else(|| core.terminal.progress()),
            running_block: core.recorder.current().cloned(),
        }
    }

    /// Output chunks newer than `seq` from the live ring buffer.
    pub fn replay_since(&self, seq: u64) -> Vec<OutputChunk> {
        let core = self.core.lock().expect("session core lock");
        core.ring.since(seq).into_iter().cloned().collect()
    }

    pub fn ring_stats(&self) -> (Option<u64>, u64, usize) {
        let core = self.core.lock().expect("session core lock");
        (
            core.ring.oldest_seq(),
            core.ring.latest_seq(),
            core.ring.bytes(),
        )
    }

    pub fn input(&self, data: &[u8]) -> Result<()> {
        if !self.is_alive() {
            return Err(SessionError::NotRunning(self.id()));
        }
        let mut writer = self.writer.lock().expect("pty writer lock");
        writer.write_all(data)?;
        writer.flush()?;
        drop(writer);
        if self.heuristic {
            self.capture_heuristic(data);
        }
        Ok(())
    }

    /// Best-effort blocks for shells without OSC 133. The command line is
    /// visible because the user typed it; the exit code is explicitly unknown.
    fn capture_heuristic(&self, data: &[u8]) {
        let mut line = self.heuristic_line.lock().expect("heuristic lock");
        for byte in data {
            match byte {
                b'\r' | b'\n' => {
                    let command = String::from_utf8_lossy(&line).trim().to_string();
                    line.clear();
                    if command.is_empty() || !self.alive.load(Ordering::SeqCst) {
                        continue;
                    }
                    let mut core = self.core.lock().expect("session core lock");
                    if core.recorder.current().is_some() {
                        let now = Utc::now();
                        if let Some((block, output)) =
                            core.recorder
                                .finish_capture(None, BlockStatus::Cancelled, now)
                        {
                            if let Some(sink) = &self.block_sink {
                                sink(block.clone(), output);
                            }
                            let _ = self.events.send(SessionEvent::BlockFinished(block));
                        }
                    }
                    let now = Utc::now();
                    let block = core.recorder.begin_command(&command, now);
                    core.recorder.append_output(b""); // mark as running
                    core.collecting = true;
                    let _ = self.events.send(SessionEvent::BlockStarted(block));
                }
                0x7f => {
                    line.pop();
                }
                0x03 => line.clear(),
                byte if byte.is_ascii_graphic() || *byte == b' ' || *byte == b'\t' => {
                    if line.len() < integration::MAX_COMMAND_BYTES {
                        line.push(*byte);
                    }
                }
                _ => {}
            }
        }
    }

    pub fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        let rows = rows.max(2);
        let cols = cols.max(2);
        self.master
            .lock()
            .expect("pty master lock")
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| SessionError::Pty(e.to_string()))?;
        {
            let mut core = self.core.lock().expect("session core lock");
            core.terminal.resize(rows, cols);
        }
        let mut info = self.info.lock().expect("session info lock");
        info.rows = rows;
        info.cols = cols;
        Ok(())
    }

    pub fn signal(&self, signal: &str) -> Result<()> {
        match signal.to_ascii_uppercase().as_str() {
            "SIGINT" | "INT" => self.input(b"\x03"),
            "SIGQUIT" | "QUIT" => self.input(b"\x1c"),
            "SIGTSTP" | "TSTP" => self.input(b"\x1a"),
            other => {
                #[cfg(unix)]
                {
                    let pid = self.info().pid;
                    let Some(pid) = pid else {
                        return Err(SessionError::NotRunning(self.id()));
                    };
                    let number = match other {
                        "SIGHUP" | "HUP" => libc::SIGHUP,
                        "SIGTERM" | "TERM" => libc::SIGTERM,
                        "SIGKILL" | "KILL" => libc::SIGKILL,
                        _ => {
                            return Err(SessionError::Unavailable(format!(
                                "unknown signal `{signal}`"
                            )))
                        }
                    };
                    // Safety: kill(2) with a pid we spawned; failure is reported.
                    let rc = unsafe { libc::kill(pid as i32, number) };
                    if rc != 0 {
                        return Err(SessionError::Io(std::io::Error::last_os_error()));
                    }
                    Ok(())
                }
                #[cfg(not(unix))]
                {
                    let _ = other;
                    Err(SessionError::Unavailable(
                        "signals other than SIGINT are not supported on this platform".into(),
                    ))
                }
            }
        }
    }

    /// Close the session: SIGHUP, wait up to two seconds, then SIGKILL.
    pub fn close(&self, kill: bool) -> Result<()> {
        if !self.is_alive() {
            return Ok(());
        }
        if kill {
            let _ = self.signal("SIGKILL");
        } else {
            let _ = self.signal("SIGHUP");
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            {
                let mut child = self.child.lock().expect("child lock");
                if let Ok(Some(_)) = child.try_wait() {
                    break;
                }
            }
            if std::time::Instant::now() >= deadline {
                let _ = self.signal("SIGKILL");
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        self.alive.store(false, Ordering::SeqCst);
        self.info.lock().expect("info lock").status = "closed".into();
        Ok(())
    }

    fn reader_loop(self: Arc<Self>, mut reader: Box<dyn Read + Send>) {
        let mut buffer = vec![0u8; READ_CHUNK];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => self.on_output(&buffer[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let mut pending: Vec<SessionEvent> = Vec::new();
        {
            let mut core = self.core.lock().expect("session core lock");
            core.collecting = false;
            if let Some((block, output)) =
                core.recorder
                    .finish_capture(None, BlockStatus::Cancelled, Utc::now())
            {
                if !block.command.trim().is_empty() {
                    if let Some(sink) = &self.block_sink {
                        sink(block.clone(), output);
                    }
                    pending.push(SessionEvent::BlockFinished(block));
                }
            }
        }
        let code = {
            let mut child = self.child.lock().expect("child lock");
            match child.try_wait() {
                Ok(Some(status)) => Some(exit_code(status)),
                _ => None,
            }
        };
        self.alive.store(false, Ordering::SeqCst);
        {
            let mut info = self.info.lock().expect("session info lock");
            info.status = "exited".into();
        }
        for event in pending {
            let _ = self.events.send(event);
        }
        let _ = self.events.send(SessionEvent::Exited { code });
    }

    fn on_output(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let id = self.id();
        let mut derived: Vec<SessionEvent> = Vec::new();
        let mut finished: Vec<(Block, Vec<u8>)> = Vec::new();
        {
            let mut core = self.core.lock().expect("session core lock");
            core.ring.push(OutputChunk {
                seq,
                session_id: id.clone(),
                data: bytes.to_vec(),
            });
            let segments = core.splitter.push(bytes);
            for segment in segments {
                let events = core.terminal.process(&segment.bytes);
                if let Some(mark) = segment.mark {
                    self.apply_mark(mark, &mut core, &mut derived, &mut finished);
                } else if core.collecting {
                    core.recorder.append_output(&segment.bytes);
                }
                for event in events {
                    match event {
                        OscEvent::ShellMark(ShellMark::Cwd(path)) => {
                            core.recorder.on_event(
                                &OscEvent::ShellMark(ShellMark::Cwd(path.clone())),
                                Utc::now(),
                            );
                            derived.push(SessionEvent::CwdChanged(path));
                        }
                        OscEvent::ShellMark(ShellMark::Metadata(meta))
                            if meta.command.is_some() =>
                        {
                            core.recorder.on_event(
                                &OscEvent::ShellMark(ShellMark::Metadata(meta)),
                                Utc::now(),
                            );
                        }
                        OscEvent::Title(title) => {
                            core.title = Some(title.clone());
                            derived.push(SessionEvent::TitleChanged(title));
                        }
                        OscEvent::Progress { state, pct } => {
                            core.progress = Some((state, pct));
                            derived.push(SessionEvent::Progress { state, pct });
                        }
                        OscEvent::Notification { title, body } => {
                            derived.push(SessionEvent::Notification { title, body });
                        }
                        _ => {}
                    }
                }
            }
        }
        if let Some(sink) = &self.block_sink {
            for (block, output) in finished {
                sink(block.clone(), output);
                derived.push(SessionEvent::BlockFinished(block));
            }
        }
        let _ = self.events.send(SessionEvent::Output(OutputChunk {
            seq,
            session_id: id,
            data: bytes.to_vec(),
        }));
        for event in derived {
            let _ = self.events.send(event);
        }
    }

    fn apply_mark(
        &self,
        mark: Mark,
        core: &mut Core,
        derived: &mut Vec<SessionEvent>,
        finished: &mut Vec<(Block, Vec<u8>)>,
    ) {
        let now = Utc::now();
        match mark {
            Mark::Prompt => {
                core.collecting = false;
                let updates = core
                    .recorder
                    .on_event(&OscEvent::ShellMark(ShellMark::PromptStart), now);
                collect_updates(updates, derived);
            }
            Mark::Command => {
                // A previous block that never saw OSC 133;D is cancelled, not
                // left "running" forever.
                core.collecting = false;
                if core
                    .recorder
                    .current()
                    .map(|block| !block.status.is_finished())
                    .unwrap_or(false)
                {
                    if let Some((block, output)) =
                        core.recorder
                            .finish_capture(None, BlockStatus::Cancelled, now)
                    {
                        if !block.command.trim().is_empty() {
                            finished.push((block.clone(), output));
                            derived.push(SessionEvent::BlockFinished(block));
                        }
                    }
                }
                if let Some(command) = integration::read_captured_command(&self.command_file) {
                    core.recorder.on_event(
                        &OscEvent::ShellMark(ShellMark::Metadata(ShellIntegrationMeta {
                            command: Some(command),
                            ..Default::default()
                        })),
                        now,
                    );
                }
                let updates = core
                    .recorder
                    .on_event(&OscEvent::ShellMark(ShellMark::CommandStart), now);
                collect_updates(updates, derived);
            }
            Mark::Output => {
                core.collecting = true;
                let updates = core
                    .recorder
                    .on_event(&OscEvent::ShellMark(ShellMark::OutputStart), now);
                collect_updates(updates, derived);
            }
            Mark::Finished(code) => {
                core.collecting = false;
                let status = match code {
                    Some(0) => BlockStatus::Ok,
                    Some(_) => BlockStatus::Failed,
                    None => BlockStatus::Cancelled,
                };
                if let Some((block, output)) = core.recorder.finish_capture(code, status, now) {
                    if !block.command.trim().is_empty() {
                        finished.push((block.clone(), output));
                        // The caller emits the event after releasing the lock.
                        derived.push(SessionEvent::BlockFinished(block));
                    }
                }
            }
        }
    }
}

fn collect_updates(updates: Vec<RecorderUpdate>, derived: &mut Vec<SessionEvent>) {
    for update in updates {
        match update {
            RecorderUpdate::Started(block) => derived.push(SessionEvent::BlockStarted(block)),
            RecorderUpdate::Finished(block) => derived.push(SessionEvent::BlockFinished(block)),
            RecorderUpdate::CwdChanged(path) => derived.push(SessionEvent::CwdChanged(path)),
            RecorderUpdate::OutputAppended { .. } | RecorderUpdate::Ignored => {}
        }
    }
}

fn exit_code(status: portable_pty::ExitStatus) -> i32 {
    status.exit_code() as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split_all(splitter: &mut MarkerSplitter, bytes: &[u8]) -> Vec<Segment> {
        splitter.push(bytes)
    }

    #[test]
    fn marker_splitter_preserves_bytes_and_marks() {
        let mut splitter = MarkerSplitter::new();
        let segments = split_all(
            &mut splitter,
            b"prompt\x1b]133;A\x07$ \x1b]133;B\x07ls\r\n\x1b]133;C\x07a.txt\x1b]133;D;0\x07",
        );
        let data: Vec<u8> = segments
            .iter()
            .flat_map(|segment| segment.bytes.clone())
            .collect();
        assert_eq!(
            data,
            b"prompt\x1b]133;A\x07$ \x1b]133;B\x07ls\r\n\x1b]133;C\x07a.txt\x1b]133;D;0\x07"
        );
        let marks: Vec<Mark> = segments.iter().filter_map(|s| s.mark).collect();
        assert_eq!(
            marks,
            vec![
                Mark::Prompt,
                Mark::Command,
                Mark::Output,
                Mark::Finished(Some(0))
            ]
        );
    }

    #[test]
    fn marker_splitter_carries_partial_markers() {
        let mut splitter = MarkerSplitter::new();
        assert!(
            splitter.push(b"hello\x1b]13").is_empty()
                || !splitter
                    .push(b"")
                    .iter()
                    .any(|segment| segment.mark.is_some())
        );
        let first = splitter.push(b"hello\x1b]13");
        assert!(first.iter().all(|segment| segment.mark.is_none()));
        let second = splitter.push(b"3;C\x07data");
        assert_eq!(second[0].mark, Some(Mark::Output));
        assert!(second[1].bytes.ends_with(b"data"));
    }

    #[test]
    fn st_terminator_is_supported_and_exit_code_parsed() {
        let mut splitter = MarkerSplitter::new();
        let segments = splitter.push(b"\x1b]133;D;130\x1b\\done");
        assert_eq!(segments[0].mark, Some(Mark::Finished(Some(130))));
        assert_eq!(segments[1].bytes, b"done");
    }

    #[test]
    fn ring_buffer_is_bounded_and_ordered() {
        let mut ring = RingBuffer::new(64 * 1024);
        for seq in 1..=10 {
            ring.push(OutputChunk {
                seq,
                session_id: "s".into(),
                data: vec![b'x'; 10 * 1024],
            });
        }
        assert!(ring.bytes() <= 64 * 1024);
        let seqs: Vec<u64> = ring.since(0).iter().map(|chunk| chunk.seq).collect();
        assert_eq!(seqs, vec![5, 6, 7, 8, 9, 10]);
        assert_eq!(ring.since(9).len(), 1);
    }

    #[test]
    fn unterminated_marker_is_bounded_and_flushed() {
        let mut splitter = MarkerSplitter::new();
        let mut bytes = b"\x1b]133;".to_vec();
        bytes.extend(std::iter::repeat(b'x').take(MAX_MARK_BYTES + 10));
        let segments = splitter.push(&bytes);
        assert!(segments.iter().all(|segment| segment.mark.is_none()));
        assert!(segments
            .iter()
            .any(|segment| segment.bytes.len() > MAX_MARK_BYTES));
    }
}

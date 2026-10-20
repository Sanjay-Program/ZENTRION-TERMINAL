//! Real pseudo-terminal sessions.
//!
//! Each [`Session`] owns a PTY pair, a child shell (or arbitrary program), a
//! background reader thread, and a `vt100` screen parser. The UI never invents
//! terminal content: everything rendered in a pane comes from the child process.

use anyhow::{Context, Result};
use chrono::Utc;
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};
use vt100::Parser;
use z_blocks::{Block, BlockRecorder, BlockStatus, RecorderUpdate};
use z_vt::{OscEvent, ShellIntegrationMeta, ShellMark, VtScanner};

/// Maximum number of scrollback lines retained per session.
pub const SCROLLBACK_LINES: usize = 10_000;

/// Maximum bytes drained from a PTY per poll so one noisy process cannot
/// starve the UI thread.
const MAX_CHUNKS_PER_POLL: usize = 64;
const READ_BUFFER: usize = 16 * 1024;

pub struct Session {
    pub title: String,
    pub cwd: PathBuf,
    pub parser: Parser,
    /// Non-zero when the user has scrolled back into history.
    pub scroll_offset: usize,
    pub exit_status: Option<String>,
    pub last_activity: Instant,
    /// True when OSC 133 shell hooks are active for this session.
    pub integration: bool,
    /// Progress reported by OSC 9;4 (state label, percent).
    pub progress: Option<(String, Option<u8>)>,
    /// Last OSC 9 notification (title, body).
    pub notification: Option<(String, String)>,

    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn Child + Send + Sync>,
    output: Receiver<Vec<u8>>,
    size: (u16, u16),
    scanner: VtScanner,
    splitter: z_session::MarkerSplitter,
    recorder: BlockRecorder,
    collecting: bool,
    blocks: Vec<Block>,
    block_outputs: Vec<String>,
    finished_on_exit: bool,
    command_file: Option<PathBuf>,
}

impl Session {
    /// Spawn the user's shell in a new PTY.
    pub fn spawn(rows: u16, cols: u16) -> Result<Self> {
        let shell = default_shell();
        Self::spawn_command(&shell, &[], None, rows, cols)
    }

    /// Spawn an arbitrary program in a new PTY.
    pub fn spawn_command(
        program: &str,
        args: &[String],
        cwd: Option<PathBuf>,
        rows: u16,
        cols: u16,
    ) -> Result<Self> {
        let (rows, cols) = (rows.max(2), cols.max(2));
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("could not allocate a pseudo-terminal")?;

        let cwd = cwd
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        // Install shell integration when the program is a supported shell. This
        // is what turns output into authoritative command blocks.
        let session_id = format!(
            "ui_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let command_file = z_core::config::user_data_dir().map(|data| {
            let path = data
                .join("sessions")
                .join("cmd")
                .join(format!("{session_id}.cmd"));
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            path
        });
        let command_path = command_file
            .clone()
            .unwrap_or_else(|| std::env::temp_dir().join(format!("{session_id}.cmd")));
        let integration_dir = z_session::integration::default_integration_dir();
        let launch = z_session::integration::plan_launch(
            program,
            z_config::ShellIntegration::Auto,
            integration_dir.as_deref(),
            &session_id,
            &command_path,
            &[],
            false,
        );
        let mut cmd = CommandBuilder::new(program);
        for arg in args {
            cmd.arg(arg);
        }
        for arg in &launch.args {
            cmd.arg(arg);
        }
        for (key, value) in &launch.env {
            cmd.env(key, value);
        }
        cmd.cwd(&cwd);
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        cmd.env("TERM_PROGRAM", "zentrion");
        cmd.env("TERM_PROGRAM_VERSION", env!("CARGO_PKG_VERSION"));
        cmd.env("ZENTRION_TERMINAL", "1");

        let child = pair
            .slave
            .spawn_command(cmd)
            .with_context(|| format!("could not start {program}"))?;
        // The slave handle must be dropped in the parent once the child owns
        // it; otherwise the master never observes EOF.
        drop(pair.slave);

        let mut reader = pair
            .master
            .try_clone_reader()
            .context("could not read from the pseudo-terminal")?;
        let writer = pair
            .master
            .take_writer()
            .context("could not write to the pseudo-terminal")?;

        let (tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name("zentrion-pty-reader".into())
            .spawn(move || {
                let mut buf = [0u8; READ_BUFFER];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if tx.send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            })
            .context("could not spawn the PTY reader thread")?;

        let title = std::path::Path::new(program)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(program)
            .to_string();

        Ok(Self {
            title,
            cwd: cwd.clone(),
            parser: Parser::new(nonzero(rows), nonzero(cols), SCROLLBACK_LINES),
            scroll_offset: 0,
            exit_status: None,
            last_activity: Instant::now(),
            master: pair.master,
            writer,
            child,
            output: rx,
            size: (rows, cols),
            integration: launch.integration,
            progress: None,
            notification: None,
            scanner: VtScanner::new(z_vt::VtPolicy::default()),
            splitter: z_session::MarkerSplitter::new(),
            recorder: BlockRecorder::new(&session_id, program, cwd.display().to_string()),
            collecting: false,
            blocks: Vec::new(),
            block_outputs: Vec::new(),
            finished_on_exit: false,
            command_file: command_file.clone(),
        })
    }

    /// Drain pending output into the screen parser.
    pub fn poll(&mut self) {
        for _ in 0..MAX_CHUNKS_PER_POLL {
            match self.output.try_recv() {
                Ok(bytes) => {
                    self.parser.process(&bytes);
                    self.track_blocks(&bytes);
                    self.last_activity = Instant::now();
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }

        if self.exit_status.is_none() {
            if let Ok(Some(status)) = self.child.try_wait() {
                let text = status.to_string();
                self.exit_status = Some(if text.trim().is_empty() {
                    "exited".to_string()
                } else {
                    text
                });
                if !self.finished_on_exit {
                    self.finished_on_exit = true;
                    if let Some((block, output)) =
                        self.recorder
                            .finish_capture(None, BlockStatus::Cancelled, Utc::now())
                    {
                        self.push_block(block, output);
                    }
                }
            }
        }

        // Keep the viewport pinned where the user put it while new output
        // arrives in the background.
        if self.scroll_offset > 0 {
            let offset = self.scroll_offset.min(self.parser.screen().scrollback());
            if offset != self.scroll_offset {
                self.scroll_offset = offset;
            }
            self.parser.screen_mut().set_scrollback(self.scroll_offset);
        }
    }

    /// True once the child has exited and all buffered output was drained.
    pub fn is_dead(&self) -> bool {
        self.exit_status.is_some()
    }

    /// True when the child produced output recently (used for activity dots).
    pub fn is_busy(&self) -> bool {
        self.last_activity.elapsed() < Duration::from_millis(400)
    }

    pub fn write(&mut self, bytes: &[u8]) {
        if self.exit_status.is_some() {
            return;
        }
        if self.writer.write_all(bytes).is_err() {
            self.exit_status = Some("pty closed".to_string());
        }
        let _ = self.writer.flush();
    }

    /// Send a line of text followed by Enter.
    pub fn write_line(&mut self, text: &str) {
        self.write(text.as_bytes());
        self.write(b"\r");
    }

    /// Resize both the kernel PTY and the screen parser.
    pub fn resize(&mut self, rows: u16, cols: u16) {
        let (rows, cols) = (rows.max(2), cols.max(2));
        if (rows, cols) == self.size {
            return;
        }
        self.size = (rows, cols);
        let _ = self.master.resize(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        });
        self.parser.set_size(nonzero(rows), nonzero(cols));
    }

    pub fn size(&self) -> (u16, u16) {
        self.size
    }

    /// Scroll back by `rows`; 0 means the live screen.
    /// Command blocks derived from shell-integration marks.
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    pub fn block_outputs(&self) -> &[String] {
        &self.block_outputs
    }

    fn push_block(&mut self, block: Block, output: Vec<u8>) {
        if block.command.trim().is_empty() {
            return;
        }
        let plain = z_blocks::strip_ansi(&String::from_utf8_lossy(&output));
        self.blocks.push(block);
        self.block_outputs.push(plain);
        if self.blocks.len() > 500 {
            self.blocks.remove(0);
            self.block_outputs.remove(0);
        }
    }

    fn track_blocks(&mut self, bytes: &[u8]) {
        let segments = self.splitter.push(bytes);
        for segment in segments {
            let events = self.scanner.advance(&segment.bytes);
            if let Some(mark) = segment.mark {
                self.apply_mark(mark);
            } else if self.collecting {
                self.recorder.append_output(&segment.bytes);
            }
            for event in events {
                match event {
                    OscEvent::ShellMark(ShellMark::Cwd(path)) => {
                        let _ = self
                            .recorder
                            .on_event(&OscEvent::ShellMark(ShellMark::Cwd(path)), Utc::now());
                    }
                    OscEvent::ShellMark(ShellMark::Metadata(meta)) if meta.command.is_some() => {
                        let _ = self
                            .recorder
                            .on_event(&OscEvent::ShellMark(ShellMark::Metadata(meta)), Utc::now());
                    }
                    OscEvent::Progress { state, pct } => {
                        self.progress = Some((format!("{state:?}").to_lowercase(), pct));
                    }
                    OscEvent::Notification { title, body } => {
                        self.notification = Some((title, body));
                    }
                    OscEvent::Title(title) => {
                        if !title.is_empty() {
                            self.title = title.chars().take(80).collect();
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn apply_mark(&mut self, mark: z_session::Mark) {
        let now = Utc::now();
        match mark {
            z_session::Mark::Prompt => {
                self.collecting = false;
                let updates = self
                    .recorder
                    .on_event(&OscEvent::ShellMark(ShellMark::PromptStart), now);
                self.collect_updates(updates);
            }
            z_session::Mark::Command => {
                self.collecting = false;
                if self
                    .recorder
                    .current()
                    .map(|block| !block.status.is_finished())
                    .unwrap_or(false)
                {
                    if let Some((block, output)) =
                        self.recorder
                            .finish_capture(None, BlockStatus::Cancelled, now)
                    {
                        self.push_block(block, output);
                    }
                }
                if let Some(command) = self
                    .command_file
                    .as_deref()
                    .and_then(z_session::read_captured_command)
                {
                    let _ = self.recorder.on_event(
                        &OscEvent::ShellMark(ShellMark::Metadata(ShellIntegrationMeta {
                            command: Some(command),
                            ..Default::default()
                        })),
                        now,
                    );
                }
                let updates = self
                    .recorder
                    .on_event(&OscEvent::ShellMark(ShellMark::CommandStart), now);
                self.collect_updates(updates);
            }
            z_session::Mark::Output => {
                self.collecting = true;
                let updates = self
                    .recorder
                    .on_event(&OscEvent::ShellMark(ShellMark::OutputStart), now);
                self.collect_updates(updates);
            }
            z_session::Mark::Finished(code) => {
                self.collecting = false;
                let status = match code {
                    Some(0) => BlockStatus::Ok,
                    Some(_) => BlockStatus::Failed,
                    None => BlockStatus::Cancelled,
                };
                if let Some((block, output)) = self.recorder.finish_capture(code, status, now) {
                    self.push_block(block, output);
                }
            }
        }
    }

    fn collect_updates(&mut self, updates: Vec<RecorderUpdate>) {
        for update in updates {
            if let RecorderUpdate::Finished(block) = update {
                self.push_block(block, Vec::new());
            }
        }
    }

    pub fn scroll_up(&mut self, rows: usize) {
        let max = self.parser.screen().scrollback_len();
        self.scroll_offset = (self.scroll_offset + rows).min(max);
        self.parser.screen_mut().set_scrollback(self.scroll_offset);
    }

    pub fn scroll_down(&mut self, rows: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(rows);
        self.parser.screen_mut().set_scrollback(self.scroll_offset);
    }

    pub fn scroll_to_bottom(&mut self) {
        self.scroll_offset = 0;
        self.parser.screen_mut().set_scrollback(0);
    }

    /// True when the running program enabled a mouse protocol.
    pub fn mouse_enabled(&self) -> bool {
        !matches!(
            self.parser.screen().mouse_protocol_mode(),
            vt100::MouseProtocolMode::None
        )
    }

    /// True when the program is using the alternate screen (vim, less, htop).
    pub fn alternate_screen(&self) -> bool {
        self.parser.screen().alternate_screen()
    }

    /// Signal the child process. Used by the UI when closing a pane.
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if self.exit_status.is_none() {
            self.exit_status = Some("closed".to_string());
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Best-effort cleanup: never leave a stray shell behind when a pane or
        // the whole UI disappears.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn nonzero(value: u16) -> std::num::NonZeroU16 {
    std::num::NonZeroU16::new(value.max(1)).expect("value is clamped above zero")
}

/// The user's login shell, with a conservative platform fallback.
pub fn default_shell() -> String {
    if cfg!(windows) {
        std::env::var("COMSPEC").unwrap_or_else(|_| "powershell.exe".to_string())
    } else {
        std::env::var("SHELL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| {
                if std::path::Path::new("/bin/bash").exists() {
                    "/bin/bash".to_string()
                } else {
                    "/bin/sh".to_string()
                }
            })
    }
}

/// Encode a crossterm mouse event as an SGR mouse sequence.
///
/// Returns `None` for motion events a program would not understand, or when
/// the event is outside the pane.
pub fn encode_mouse(event: crossterm::event::MouseEvent) -> Option<Vec<u8>> {
    use crossterm::event::{MouseButton, MouseEventKind};

    let (button, release) = match event.kind {
        MouseEventKind::Down(button) => (
            match button {
                MouseButton::Left => 0,
                MouseButton::Middle => 1,
                MouseButton::Right => 2,
            },
            false,
        ),
        MouseEventKind::Up(button) => (
            match button {
                MouseButton::Left => 0,
                MouseButton::Middle => 1,
                MouseButton::Right => 2,
            },
            true,
        ),
        MouseEventKind::ScrollUp => (64, false),
        MouseEventKind::ScrollDown => (65, false),
        MouseEventKind::ScrollLeft => (66, false),
        MouseEventKind::ScrollRight => (67, false),
        MouseEventKind::Drag(button) => (
            match button {
                MouseButton::Left => 32,
                MouseButton::Middle => 33,
                MouseButton::Right => 34,
            },
            false,
        ),
        MouseEventKind::Moved => (35, false),
    };

    Some(
        format!(
            "\x1b[<{};{};{}{}",
            button,
            event.column + 1,
            event.row + 1,
            if release { 'm' } else { 'M' }
        )
        .into_bytes(),
    )
}

/// Encode a crossterm key event as the byte sequence a real terminal sends.
///
/// `application_cursor` mirrors DECCKM: full-screen programs such as `vim`
/// expect `ESC O A` rather than `ESC [ A` for arrow keys.
pub fn encode_key(key: crossterm::event::KeyEvent, application_cursor: bool) -> Option<Vec<u8>> {
    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};

    if key.kind == KeyEventKind::Release {
        return None;
    }

    let mods = key.modifiers;
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    let alt = mods.contains(KeyModifiers::ALT);
    let shift = mods.contains(KeyModifiers::SHIFT);

    let mut bytes: Vec<u8> = Vec::new();

    // Alt modifies a character with an ESC prefix (classic meta-send).
    if alt && !ctrl {
        if let KeyCode::Char(c) = key.code {
            bytes.push(0x1b);
            let mut buf = [0u8; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            return Some(bytes);
        }
    }

    match key.code {
        KeyCode::Char(c) if ctrl => {
            let byte = match c.to_ascii_lowercase() {
                'a'..='z' => Some(c.to_ascii_lowercase() as u8 - b'a' + 1),
                '@' | ' ' => Some(0),
                '[' => Some(27),
                '\\' => Some(28),
                ']' => Some(29),
                '^' => Some(30),
                '_' => Some(31),
                _ => None,
            }?;
            bytes.push(byte);
        }
        KeyCode::Char(c) => {
            let mut buf = [0u8; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
        KeyCode::Enter => bytes.push(b'\r'),
        KeyCode::Tab => bytes.push(b'\t'),
        KeyCode::BackTab => bytes.extend_from_slice(b"\x1b[Z"),
        KeyCode::Backspace => bytes.push(0x7f),
        KeyCode::Esc => bytes.push(0x1b),
        KeyCode::Delete => bytes.extend_from_slice(b"\x1b[3~"),
        KeyCode::Insert => bytes.extend_from_slice(b"\x1b[2~"),
        KeyCode::Home => bytes.extend_from_slice(if application_cursor {
            b"\x1bOH"
        } else {
            b"\x1b[H"
        }),
        KeyCode::End => bytes.extend_from_slice(if application_cursor {
            b"\x1bOF"
        } else {
            b"\x1b[F"
        }),
        KeyCode::PageUp => bytes.extend_from_slice(b"\x1b[5~"),
        KeyCode::PageDown => bytes.extend_from_slice(b"\x1b[6~"),
        KeyCode::Up => bytes.extend_from_slice(if application_cursor {
            b"\x1bOA"
        } else {
            b"\x1b[A"
        }),
        KeyCode::Down => bytes.extend_from_slice(if application_cursor {
            b"\x1bOB"
        } else {
            b"\x1b[B"
        }),
        KeyCode::Right => bytes.extend_from_slice(if application_cursor {
            b"\x1bOC"
        } else {
            b"\x1b[C"
        }),
        KeyCode::Left => bytes.extend_from_slice(if application_cursor {
            b"\x1bOD"
        } else {
            b"\x1b[D"
        }),
        KeyCode::F(n) => {
            let seq = match n {
                1 => b"\x1bOP".to_vec(),
                2 => b"\x1bOQ".to_vec(),
                3 => b"\x1bOR".to_vec(),
                4 => b"\x1bOS".to_vec(),
                5 => b"\x1b[15~".to_vec(),
                6 => b"\x1b[17~".to_vec(),
                7 => b"\x1b[18~".to_vec(),
                8 => b"\x1b[19~".to_vec(),
                9 => b"\x1b[20~".to_vec(),
                10 => b"\x1b[21~".to_vec(),
                11 => b"\x1b[23~".to_vec(),
                12 => b"\x1b[24~".to_vec(),
                _ => return None,
            };
            bytes.extend_from_slice(&seq);
        }
        _ => return None,
    }

    // Ctrl+Shift+<letter> is reserved for UI shortcuts and never reaches a
    // pane; the UI checks those chords before calling this function. If one
    // slips through, send the plain control byte.

    if shift && matches!(key.code, KeyCode::Char(_)) && !ctrl && !alt {
        // Uppercase is already produced by the terminal for Shift+char.
    }

    if bytes.is_empty() {
        None
    } else {
        Some(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, mods)
    }

    #[test]
    fn encodes_basic_keys() {
        assert_eq!(
            encode_key(key(KeyCode::Char('a'), KeyModifiers::NONE), false).unwrap(),
            b"a"
        );
        assert_eq!(
            encode_key(key(KeyCode::Enter, KeyModifiers::NONE), false).unwrap(),
            b"\r"
        );
        assert_eq!(
            encode_key(key(KeyCode::Backspace, KeyModifiers::NONE), false).unwrap(),
            vec![0x7f]
        );
    }

    #[test]
    fn encodes_control_and_meta() {
        assert_eq!(
            encode_key(key(KeyCode::Char('c'), KeyModifiers::CONTROL), false).unwrap(),
            vec![0x03]
        );
        assert_eq!(
            encode_key(key(KeyCode::Char('x'), KeyModifiers::ALT), false).unwrap(),
            b"\x1bx"
        );
    }

    #[cfg(unix)]
    #[test]
    fn real_pty_round_trip() {
        let mut session = Session::spawn_command("/bin/sh", &[], None, 24, 80).unwrap();
        session.write_line("echo ZT_PTY_ROUND_TRIP");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            session.poll();
            if session
                .parser
                .screen()
                .contents()
                .contains("ZT_PTY_ROUND_TRIP")
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            session
                .parser
                .screen()
                .contents()
                .contains("ZT_PTY_ROUND_TRIP"),
            "shell output was not captured"
        );

        session.resize(30, 100);
        assert_eq!(session.size(), (30, 100));
        session.write_line("exit");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            session.poll();
            if session.is_dead() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(session.is_dead(), "shell did not exit");
    }

    #[test]
    fn encodes_sgr_mouse_events() {
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
        let event = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 4,
            row: 9,
            modifiers: crossterm::event::KeyModifiers::NONE,
        };
        assert_eq!(encode_mouse(event).unwrap(), b"\x1b[<0;5;10M".to_vec());

        let wheel = MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 0,
            row: 0,
            modifiers: crossterm::event::KeyModifiers::NONE,
        };
        assert_eq!(encode_mouse(wheel).unwrap(), b"\x1b[<65;1;1M".to_vec());
    }

    #[test]
    fn arrows_follow_application_cursor_mode() {
        assert_eq!(
            encode_key(key(KeyCode::Up, KeyModifiers::NONE), false).unwrap(),
            b"\x1b[A"
        );
        assert_eq!(
            encode_key(key(KeyCode::Up, KeyModifiers::NONE), true).unwrap(),
            b"\x1bOA"
        );
    }
}

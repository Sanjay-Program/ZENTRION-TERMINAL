//! OSC/OSC-like control sequence handling with strict limits.
//!
//! The parser is deliberately a *data* parser. It never opens a URL, never
//! writes the clipboard, never spawns a process and never renders raw control
//! bytes. It returns typed [`OscEvent`]s and the caller applies policy.

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Maximum bytes we keep from a single OSC string that reaches the UI.
pub const MAX_TEXT_BYTES: usize = 4096;

/// Maximum clipboard payload we are willing to accept (OSC 52).
pub const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;

/// Progress state as reported by ConEmu-style `OSC 9;4`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressState {
    Hidden,
    Normal,
    Error,
    Indeterminate,
    Paused,
    Unknown(u8),
}

impl ProgressState {
    fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Hidden,
            1 => Self::Normal,
            2 => Self::Error,
            3 => Self::Indeterminate,
            4 => Self::Paused,
            other => Self::Unknown(other),
        }
    }
}

/// Shell-integration marks. `OSC 133` is the interoperable core; `OSC 9;9`
/// is accepted as a cwd fallback for shells that do not emit `OSC 7`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ShellMark {
    /// `OSC 133;A` — prompt started.
    PromptStart,
    /// `OSC 133;B` — user pressed Enter, command line submitted.
    CommandStart,
    /// `OSC 133;C` — command output started.
    OutputStart,
    /// `OSC 133;D[;exit]` — command finished.
    CommandFinished { exit_code: Option<i32> },
    /// `OSC 7` or `OSC 9;9` — current working directory changed.
    Cwd(String),
    /// `OSC 1337;Zentrion;<base64-json>` metadata emitted by our hooks.
    Metadata(ShellIntegrationMeta),
}

/// Namespaced metadata emitted by the generated shell hooks.
///
/// Command text is captured in the shell, never scraped from the screen.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellIntegrationMeta {
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub shell_pid: Option<u32>,
    #[serde(default)]
    pub history_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub event: Option<String>,
}

/// A parsed, policy-filtered terminal event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OscEvent {
    ShellMark(ShellMark),
    Title(String),
    IconTitle(String),
    /// OSC 8 hyperlink started (empty uri is reported as `HyperlinkEnd`).
    Hyperlink {
        uri: String,
        params: String,
    },
    HyperlinkEnd,
    /// OSC 9 desktop notification.
    Notification {
        title: String,
        body: String,
    },
    /// OSC 9;4 progress.
    Progress {
        state: ProgressState,
        pct: Option<u8>,
    },
    /// OSC 52 clipboard write. The value is only emitted when policy allows
    /// it; otherwise an `OscRejected` event is produced instead.
    Clipboard {
        selection: String,
        data: String,
    },
    OscRejected {
        code: u16,
        reason: String,
    },
    /// A sequence we intentionally ignore. Never contains raw payload.
    Ignored {
        code: u16,
    },
}

/// Security policy for terminal-originated events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtPolicy {
    /// Allow OSC 52 clipboard *writes*. Reads are never supported.
    pub allow_clipboard_write: bool,
    /// Maximum bytes accepted from OSC 52.
    pub clipboard_limit: usize,
    /// Allow OSC 9 desktop notifications.
    pub allow_notifications: bool,
    /// Schemes that may be opened from an OSC 8 hyperlink.
    pub hyperlink_schemes: Vec<String>,
    /// Maximum bytes retained for titles/notifications.
    pub max_text_bytes: usize,
    /// Maximum number of events buffered between advances.
    pub max_events: usize,
}

impl Default for VtPolicy {
    fn default() -> Self {
        Self {
            allow_clipboard_write: false,
            clipboard_limit: MAX_CLIPBOARD_BYTES,
            allow_notifications: true,
            hyperlink_schemes: vec![
                "https".to_string(),
                "http".to_string(),
                "mailto".to_string(),
            ],
            max_text_bytes: MAX_TEXT_BYTES,
            max_events: 256,
        }
    }
}

impl VtPolicy {
    /// Clipboard writes require an explicit opt-in.
    pub fn with_clipboard(mut self, allow: bool) -> Self {
        self.allow_clipboard_write = allow;
        self
    }
}

/// Incremental OSC scanner. Feed it the same bytes the screen parser sees.
///
/// The scanner is independent of the renderer; it only derives events.
pub struct VtScanner {
    parser: vte::Parser,
    policy: VtPolicy,
    events: VecDeque<OscEvent>,
}

impl Default for VtScanner {
    fn default() -> Self {
        Self::new(VtPolicy::default())
    }
}

impl VtScanner {
    pub fn new(policy: VtPolicy) -> Self {
        Self {
            parser: vte::Parser::new(),
            policy,
            events: VecDeque::new(),
        }
    }

    pub fn policy(&self) -> &VtPolicy {
        &self.policy
    }

    /// Feed bytes and return newly derived events.
    pub fn advance(&mut self, bytes: &[u8]) -> Vec<OscEvent> {
        let mut performer = Performer {
            policy: &self.policy,
            events: &mut self.events,
        };
        self.parser.advance(&mut performer, bytes);
        // Bound the queue so a hostile stream cannot grow memory without end.
        while self.events.len() > self.policy.max_events {
            self.events.pop_front();
        }
        self.events.drain(..).collect()
    }
}

struct Performer<'a> {
    policy: &'a VtPolicy,
    events: &'a mut VecDeque<OscEvent>,
}

impl Performer<'_> {
    fn push(&mut self, event: OscEvent) {
        if self.events.len() < self.policy.max_events.saturating_mul(4) {
            self.events.push_back(event);
        }
    }

    fn text(&self, raw: &[u8]) -> String {
        sanitize_text(raw, self.policy.max_text_bytes)
    }

    fn handle_osc(&mut self, params: &[&[u8]]) {
        let Some(code_raw) = params.first() else {
            return;
        };
        let code = parse_u16(code_raw);
        match code {
            Some(0) | Some(2) => {
                if let Some(rest) = params.get(1) {
                    self.push(OscEvent::Title(self.text(rest)));
                }
            }
            Some(1) => {
                if let Some(rest) = params.get(1) {
                    self.push(OscEvent::IconTitle(self.text(rest)));
                }
            }
            Some(7) => {
                if let Some(uri) = params.get(1) {
                    if let Some(path) = parse_file_uri(uri) {
                        self.push(OscEvent::ShellMark(ShellMark::Cwd(path)));
                    }
                }
            }
            Some(8) => {
                // OSC 8 ; params ; URI
                let uri = params.get(2).map(|v| self.text(v)).unwrap_or_default();
                let hyperlink_params = params.get(1).map(|v| self.text(v)).unwrap_or_default();
                if uri.is_empty() {
                    self.push(OscEvent::HyperlinkEnd);
                } else if crate::links::is_safe_scheme(&uri, &self.policy.hyperlink_schemes) {
                    self.push(OscEvent::Hyperlink {
                        uri,
                        params: hyperlink_params,
                    });
                } else {
                    self.push(OscEvent::OscRejected {
                        code: 8,
                        reason: "hyperlink scheme is not allowed".to_string(),
                    });
                }
            }
            Some(9) => {
                self.handle_osc9(params);
            }
            Some(52) => {
                self.handle_osc52(params);
            }
            Some(133) => {
                self.handle_osc133(params);
            }
            Some(1337) => {
                self.handle_osc1337(params);
            }
            Some(_) => {
                // Colour queries, dynamic colours, etc. are consumed by the
                // screen layer; no need to surface them as events.
                if let Some(code) = code {
                    self.push(OscEvent::Ignored { code });
                }
            }
            None => {}
        }
    }

    fn handle_osc9(&mut self, params: &[&[u8]]) {
        // OSC 9 ; body                 -> notification
        // OSC 9 ; 4 ; state [; pct]   -> progress
        if params.get(1).map(|p| *p) == Some(b"4") {
            let state = params
                .get(2)
                .and_then(|v| std::str::from_utf8(v).ok())
                .and_then(|v| v.parse::<u8>().ok())
                .map(ProgressState::from_code)
                .unwrap_or(ProgressState::Normal);
            let pct = params
                .get(3)
                .and_then(|v| std::str::from_utf8(v).ok())
                .and_then(|v| v.parse::<u8>().ok())
                .filter(|p| *p <= 100);
            self.push(OscEvent::Progress { state, pct });
            return;
        }
        if !self.policy.allow_notifications {
            self.push(OscEvent::OscRejected {
                code: 9,
                reason: "notifications are disabled".to_string(),
            });
            return;
        }
        let body = params.get(1).map(|v| self.text(v)).unwrap_or_default();
        let title = params.get(2).map(|v| self.text(v)).unwrap_or_default();
        self.push(OscEvent::Notification { title, body });
    }

    fn handle_osc52(&mut self, params: &[&[u8]]) {
        // OSC 52 ; selection ; base64-data
        // Reads (selection "?") are deliberately unsupported.
        if !self.policy.allow_clipboard_write {
            self.push(OscEvent::OscRejected {
                code: 52,
                reason: "clipboard writes are not enabled".to_string(),
            });
            return;
        }
        let selection = params
            .get(1)
            .map(|v| self.text(v))
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "c".to_string());
        let encoded = params.get(2).map(|v| *v).unwrap_or_default();
        if encoded.len() > self.policy.clipboard_limit.saturating_mul(2) {
            self.push(OscEvent::OscRejected {
                code: 52,
                reason: "clipboard payload exceeds the limit".to_string(),
            });
            return;
        }
        match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(bytes) => {
                if bytes.len() > self.policy.clipboard_limit {
                    self.push(OscEvent::OscRejected {
                        code: 52,
                        reason: "clipboard payload exceeds the limit".to_string(),
                    });
                    return;
                }
                // Clipboard contents are not terminal text; strip controls but
                // preserve newlines and tabs so multi-line copies work.
                let data = sanitize_clipboard(&bytes);
                self.push(OscEvent::Clipboard { selection, data });
            }
            Err(_) => self.push(OscEvent::OscRejected {
                code: 52,
                reason: "invalid base64 clipboard payload".to_string(),
            }),
        }
    }

    fn handle_osc133(&mut self, params: &[&[u8]]) {
        let Some(kind) = params.get(1).and_then(|v| std::str::from_utf8(v).ok()) else {
            return;
        };
        // Some terminals fold the exit code into the kind (e.g. "D;0").
        let (kind, inline_exit) = match kind.split_once(';') {
            Some((head, tail)) => (head, tail.parse::<i32>().ok()),
            None => (kind, None),
        };
        match kind {
            "A" => self.push(OscEvent::ShellMark(ShellMark::PromptStart)),
            "B" => self.push(OscEvent::ShellMark(ShellMark::CommandStart)),
            "C" => self.push(OscEvent::ShellMark(ShellMark::OutputStart)),
            "D" => {
                let exit = params
                    .get(2)
                    .and_then(|v| std::str::from_utf8(v).ok())
                    .and_then(|v| v.parse::<i32>().ok())
                    .or(inline_exit);
                self.push(OscEvent::ShellMark(ShellMark::CommandFinished {
                    exit_code: exit,
                }));
            }
            _ => self.push(OscEvent::Ignored { code: 133 }),
        }
    }

    fn handle_osc1337(&mut self, params: &[&[u8]]) {
        // OSC 1337 ; Zentrion ; <base64-json>
        let Some(namespace) = params.get(1).and_then(|v| std::str::from_utf8(v).ok()) else {
            return;
        };
        if !namespace.eq_ignore_ascii_case("Zentrion") {
            // iTerm2 image/user-var sequences are ignored by the text layer.
            self.push(OscEvent::Ignored { code: 1337 });
            return;
        }
        let Some(encoded) = params.get(2) else {
            return;
        };
        match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(bytes) => match serde_json::from_slice::<ShellIntegrationMeta>(&bytes) {
                Ok(mut meta) => {
                    meta.command = meta
                        .command
                        .map(|c| sanitize_text(c.as_bytes(), self.policy.max_text_bytes));
                    self.push(OscEvent::ShellMark(ShellMark::Metadata(meta)));
                }
                Err(_) => self.push(OscEvent::OscRejected {
                    code: 1337,
                    reason: "invalid Zentrion metadata".to_string(),
                }),
            },
            Err(_) => self.push(OscEvent::OscRejected {
                code: 1337,
                reason: "invalid base64 metadata".to_string(),
            }),
        }
    }
}

impl vte::Perform for Performer<'_> {
    fn osc_dispatch(&mut self, params: &[&[u8]], _bell_terminated: bool) {
        self.handle_osc(params);
    }

    fn print(&mut self, _c: char) {}
    fn execute(&mut self, _byte: u8) {}
    fn csi_dispatch(
        &mut self,
        _params: &vte::Params,
        _intermediates: &[u8],
        _ignore: bool,
        _action: char,
    ) {
    }
    fn esc_dispatch(&mut self, _intermediates: &[u8], _ignore: bool, _byte: u8) {}
}

fn parse_u16(raw: &[u8]) -> Option<u16> {
    std::str::from_utf8(raw).ok()?.parse().ok()
}

/// Sanitise terminal text before it reaches a title, notification or log.
///
/// Control characters are replaced with spaces, invalid UTF-8 is replaced, and
/// the value is truncated on a char boundary. Never returns raw ESC.
pub fn sanitize_text(raw: &[u8], max_bytes: usize) -> String {
    let text = String::from_utf8_lossy(raw);
    let mut out = String::new();
    for ch in text.chars() {
        let ch = if ch.is_control() {
            ' '
        } else if ch == '\u{1b}' {
            ' '
        } else {
            ch
        };
        if out.len() + ch.len_utf8() > max_bytes {
            break;
        }
        out.push(ch);
    }
    out.trim().to_string()
}

/// Clipboard text keeps tabs/newlines but rejects every other control byte.
pub fn sanitize_clipboard(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    text.chars()
        .filter(|c| *c == '\n' || *c == '\r' || *c == '\t' || !c.is_control())
        .collect()
}

/// Parse `file://host/path` or `file:///path`, percent-decoding the path.
fn parse_file_uri(raw: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(raw).ok()?.trim();
    let rest = text.strip_prefix("file://")?;
    // Skip an optional host component.
    let path = if let Some((_host, path)) = rest.split_once('/') {
        format!("/{path}")
    } else {
        rest.to_string()
    };
    Some(percent_decode(&path))
}

/// Minimal, strict percent-decoder for OSC 7 paths.
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &input[i + 1..i + 3];
            if let Ok(value) = u8::from_str_radix(hex, 16) {
                out.push(value);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(seq: &str) -> Vec<OscEvent> {
        VtScanner::default().advance(seq.as_bytes())
    }

    #[test]
    fn shell_marks_are_parsed() {
        let events = scan("\x1b]133;A\x07prompt\x1b]133;B\x07\x1b]133;C\x07out\x1b]133;D;7\x07");
        let marks: Vec<_> = events
            .into_iter()
            .filter_map(|e| match e {
                OscEvent::ShellMark(m) => Some(m),
                _ => None,
            })
            .collect();
        assert_eq!(
            marks,
            vec![
                ShellMark::PromptStart,
                ShellMark::CommandStart,
                ShellMark::OutputStart,
                ShellMark::CommandFinished { exit_code: Some(7) },
            ]
        );
    }

    #[test]
    fn command_finished_without_exit_is_none() {
        let events = scan("\x1b]133;D\x07");
        assert_eq!(
            events,
            vec![OscEvent::ShellMark(ShellMark::CommandFinished {
                exit_code: None
            })]
        );
    }

    #[test]
    fn osc7_cwd_is_percent_decoded() {
        let events = scan("\x1b]7;file://host/work/my%20repo\x07");
        assert_eq!(
            events,
            vec![OscEvent::ShellMark(ShellMark::Cwd(
                "/work/my repo".to_string()
            ))]
        );
    }

    #[test]
    fn osc9_progress_is_distinct_from_notification() {
        let events = scan("\x1b]9;4;1;42\x07");
        assert_eq!(
            events,
            vec![OscEvent::Progress {
                state: ProgressState::Normal,
                pct: Some(42)
            }]
        );
    }

    #[test]
    fn notification_is_bounded() {
        let long = "x".repeat(MAX_TEXT_BYTES * 2);
        let events = scan(&format!("\x1b]9;{long}\x07"));
        let OscEvent::Notification { body, .. } = &events[0] else {
            panic!("expected notification");
        };
        assert!(body.len() <= MAX_TEXT_BYTES);
    }

    #[test]
    fn clipboard_is_denied_by_default() {
        let events = scan("\x1b]52;c;aGVsbG8=\x07");
        assert!(matches!(events[0], OscEvent::OscRejected { code: 52, .. }));
    }

    #[test]
    fn clipboard_is_allowed_when_opted_in() {
        let mut scanner = VtScanner::new(VtPolicy::default().with_clipboard(true));
        let events = scanner.advance(b"\x1b]52;c;aGVsbG8=\x07");
        assert_eq!(
            events,
            vec![OscEvent::Clipboard {
                selection: "c".to_string(),
                data: "hello".to_string()
            }]
        );
    }

    #[test]
    fn clipboard_read_is_never_supported() {
        let mut scanner = VtScanner::new(VtPolicy::default().with_clipboard(true));
        let events = scanner.advance(b"\x1b]52;c;?\x07");
        assert!(matches!(events[0], OscEvent::OscRejected { .. }));
    }

    #[test]
    fn unsafe_hyperlink_scheme_is_rejected() {
        let events = scan("\x1b]8;;javascript:alert(1)\x07click\x1b]8;;\x07");
        assert!(matches!(events[0], OscEvent::OscRejected { code: 8, .. }));
        assert!(events.iter().any(|e| matches!(e, OscEvent::HyperlinkEnd)));
    }

    #[test]
    fn safe_hyperlink_is_reported_but_not_opened() {
        let events = scan("\x1b]8;;https://example.com\x07x\x1b]8;;\x07");
        assert!(matches!(
            events[0],
            OscEvent::Hyperlink { ref uri, .. } if uri == "https://example.com"
        ));
    }

    #[test]
    fn title_control_bytes_are_removed() {
        let events = scan("\x1b]2;evil\x1b[31mtitle\x07");
        let OscEvent::Title(title) = &events[0] else {
            panic!("expected title");
        };
        assert!(!title.contains('\u{1b}'));
    }

    #[test]
    fn namespaced_metadata_is_parsed() {
        let json = r#"{"command":"cargo test","shell_pid":42,"history_id":"7"}"#;
        let encoded = base64::engine::general_purpose::STANDARD.encode(json);
        let events = scan(&format!("\x1b]1337;Zentrion;{encoded}\x07"));
        let OscEvent::ShellMark(ShellMark::Metadata(meta)) = &events[0] else {
            panic!("expected metadata, got {:?}", events);
        };
        assert_eq!(meta.command.as_deref(), Some("cargo test"));
        assert_eq!(meta.shell_pid, Some(42));
    }

    #[test]
    fn malformed_osc_does_not_panic() {
        let mut scanner = VtScanner::default();
        for chunk in [
            b"\x1b]133;".as_slice(),
            b"\x1b]52;c;!!!!\x07",
            b"\x1b]1337;Zentrion;notbase64\x07",
            b"\x1b]8;;\x07\x1b]8;;https://ok.test\x07",
            b"\x1b]999;unknown\x07",
            &[0xff, 0xfe, 0x00],
        ] {
            let _ = scanner.advance(chunk);
        }
    }

    #[test]
    fn events_are_bounded() {
        let policy = VtPolicy {
            max_events: 4,
            ..VtPolicy::default()
        };
        let mut scanner = VtScanner::new(policy);
        let mut text = String::new();
        for _ in 0..100 {
            text.push_str("\x1b]0;t\x07");
        }
        let events = scanner.advance(text.as_bytes());
        assert!(events.len() <= 4);
    }
}

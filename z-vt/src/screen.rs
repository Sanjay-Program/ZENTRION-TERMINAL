//! A screen model that keeps the terminal parser and the OSC policy scanner in
//! lock-step.
//!
//! Byte streams are fed once to [`vt100`] for rendering and once to
//! [`VtScanner`] for policy events. The two parsers are independent so a
//! malformed sequence can never corrupt the screen, and the scanner never sees
//! a different byte order than the screen.

use crate::osc::{OscEvent, ProgressState, ShellMark, VtPolicy, VtScanner};
use crate::search::{SearchHit, SearchOptions, Selection};
use std::num::NonZeroU16;

pub struct Terminal {
    parser: vt100::Parser,
    scanner: VtScanner,
    marks: Vec<ShellMark>,
    title: Option<String>,
    cwd: Option<String>,
    progress: Option<(ProgressState, Option<u8>)>,
    last_hyperlink: Option<String>,
    size: (u16, u16),
}

impl Terminal {
    pub fn new(rows: u16, cols: u16, scrollback: usize) -> Self {
        let (rows, cols) = (rows.max(2), cols.max(2));
        Self {
            parser: vt100::Parser::new(nonzero(rows), nonzero(cols), scrollback),
            scanner: VtScanner::new(VtPolicy::default()),
            marks: Vec::new(),
            title: None,
            cwd: None,
            progress: None,
            last_hyperlink: None,
            size: (rows, cols),
        }
    }

    pub fn with_policy(mut self, policy: VtPolicy) -> Self {
        self.scanner = VtScanner::new(policy);
        self
    }

    /// Feed terminal output. Returns policy events in stream order.
    pub fn process(&mut self, bytes: &[u8]) -> Vec<OscEvent> {
        self.parser.process(bytes);
        let events = self.scanner.advance(bytes);
        for event in &events {
            self.observe(event);
        }
        events
    }

    fn observe(&mut self, event: &OscEvent) {
        match event {
            OscEvent::Title(title) => self.title = Some(title.clone()),
            OscEvent::ShellMark(mark) => {
                match mark {
                    ShellMark::Cwd(path) => self.cwd = Some(path.clone()),
                    ShellMark::Metadata(meta) => {
                        if let Some(command) = &meta.command {
                            self.title = Some(command.clone());
                        }
                    }
                    _ => {}
                }
                self.marks.push(mark.clone());
                // Marks are only useful relative to recent output; keep the
                // buffer bounded for long-lived sessions.
                if self.marks.len() > 4096 {
                    self.marks.drain(..1024);
                }
            }
            OscEvent::Progress { state, pct } => self.progress = Some((*state, *pct)),
            OscEvent::Hyperlink { uri, .. } => self.last_hyperlink = Some(uri.clone()),
            OscEvent::HyperlinkEnd => self.last_hyperlink = None,
            _ => {}
        }
    }

    pub fn screen(&self) -> &vt100::Screen {
        self.parser.screen()
    }

    pub fn screen_mut(&mut self) -> &mut vt100::Screen {
        self.parser.screen_mut()
    }

    pub fn resize(&mut self, rows: u16, cols: u16) {
        let (rows, cols) = (rows.max(2), cols.max(2));
        if (rows, cols) == self.size {
            return;
        }
        self.size = (rows, cols);
        self.parser.set_size(nonzero(rows), nonzero(cols));
    }

    pub fn size(&self) -> (u16, u16) {
        self.size
    }

    pub fn contents(&self) -> String {
        self.parser.screen().contents()
    }

    /// A self-contained ANSI keyframe suitable for a reattaching client.
    pub fn keyframe(&self) -> String {
        self.parser.screen().contents_formatted()
    }

    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    pub fn cwd(&self) -> Option<&str> {
        self.cwd.as_deref()
    }

    pub fn progress(&self) -> Option<(ProgressState, Option<u8>)> {
        self.progress
    }

    pub fn hyperlink(&self) -> Option<&str> {
        self.last_hyperlink.as_deref()
    }

    pub fn marks(&self) -> &[ShellMark] {
        &self.marks
    }

    pub fn search(&self, options: &SearchOptions) -> Result<Vec<SearchHit>, regex::Error> {
        crate::search::search_text(&self.contents(), options)
    }

    pub fn selection_text(&self, selection: &Selection) -> String {
        selection.text(self.parser.screen())
    }

    pub fn scrollback(&self) -> usize {
        self.parser.screen().scrollback()
    }

    pub fn set_scrollback(&mut self, lines: usize) {
        self.parser.screen_mut().set_scrollback(lines);
    }
}

fn nonzero(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value.max(1)).expect("clamped above zero")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screen_and_marks_stay_in_sync() {
        let mut terminal = Terminal::new(24, 80, 1000);
        let events = terminal.process(
            b"\x1b]133;A\x07$ \x1b]133;B\x07ls\r\n\x1b]133;C\x07a.txt\r\n\x1b]133;D;0\x07",
        );
        assert_eq!(events.len(), 4);
        assert_eq!(terminal.contents().contains("a.txt"), true);
        assert_eq!(terminal.marks().len(), 4);
    }

    #[test]
    fn cwd_and_title_are_tracked() {
        let mut terminal = Terminal::new(10, 40, 100);
        terminal.process(b"\x1b]7;file:///tmp/work\x07\x1b]2;cargo test\x07");
        assert_eq!(terminal.cwd(), Some("/tmp/work"));
        assert_eq!(terminal.title(), Some("cargo test"));
    }

    #[test]
    fn resize_and_scrollback() {
        let mut terminal = Terminal::new(4, 20, 100);
        for i in 0..20 {
            terminal.process(format!("line {i}\r\n").as_bytes());
        }
        terminal.resize(6, 30);
        assert_eq!(terminal.size(), (6, 30));
        terminal.set_scrollback(2);
        assert_eq!(terminal.scrollback(), 2);
    }
}

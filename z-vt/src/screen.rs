//! A screen model that keeps the terminal parser and the OSC policy scanner in
//! lock-step, integrating DECSET 2026 synchronized output, Kitty keyboard protocol,
//! Kitty/Sixel/iTerm2 graphics, styled underlines, and compressed scrollback.

use crate::graphics::{GraphicMedia, KittyGraphicsParser};
use crate::kitty_kbd::KittyKeyboardState;
use crate::osc::{OscEvent, ProgressState, ShellMark, VtPolicy, VtScanner};
use crate::scrollback::PageScrollback;
use crate::search::{SearchHit, SearchOptions, Selection};
use crate::sync::SynchronizedOutput;
use crate::underlines::StyledUnderline;
use std::num::NonZeroU16;

pub struct Terminal {
    parser: vt100::Parser,
    scanner: VtScanner,
    sync: SynchronizedOutput,
    kitty_kbd: KittyKeyboardState,
    kitty_graphics: KittyGraphicsParser,
    graphics: Vec<GraphicMedia>,
    scrollback_pages: PageScrollback,
    underline: StyledUnderline,
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
            sync: SynchronizedOutput::default(),
            kitty_kbd: KittyKeyboardState::new(),
            kitty_graphics: KittyGraphicsParser::new(),
            graphics: Vec::new(),
            scrollback_pages: PageScrollback::new(scrollback.max(10_000), 16),
            underline: StyledUnderline::default(),
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
        let mut events = Vec::new();

        // Check for Kitty graphics escape sequence: \x1b_G...;\x1b\
        if let Some(start) = bytes.windows(3).position(|w| w == b"\x1b_G") {
            if let Some(end) = bytes[start..].windows(2).position(|w| w == b"\x1b\\") {
                let seq = String::from_utf8_lossy(&bytes[start + 3..start + end]);
                if let Some(media) = self.kitty_graphics.parse(&seq) {
                    let media: GraphicMedia = media.clone();
                    events.push(OscEvent::Graphic(media.clone()));
                    self.graphics.push(media);
                }
            }
        }

        // Process through DECSET 2026 synchronized output engine
        let ready_bytes = self.sync.process_stream(bytes);
        if !ready_bytes.is_empty() {
            self.parser.process(&ready_bytes);
            let mut osc_events = self.scanner.advance(&ready_bytes);
            for event in &osc_events {
                self.observe(event);
            }
            events.append(&mut osc_events);

            // Record printed lines into compressed scrollback buffer
            let text = String::from_utf8_lossy(&ready_bytes);
            for line in text.lines() {
                self.scrollback_pages.push_line(line.to_string());
            }
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
                if self.marks.len() > 4096 {
                    self.marks.drain(..1024);
                }
            }
            OscEvent::Progress { state, pct } => self.progress = Some((*state, *pct)),
            OscEvent::Hyperlink { uri, .. } => self.last_hyperlink = Some(uri.clone()),
            OscEvent::HyperlinkEnd => self.last_hyperlink = None,
            OscEvent::Graphic(ref media) => self.graphics.push(media.clone()),
            OscEvent::Underline(ref u) => self.underline = *u,
            OscEvent::KittyKeyboard(ref seq) => {
                let _ = self.kitty_kbd.handle_csi(seq);
            }
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

    pub fn graphics(&self) -> &[GraphicMedia] {
        &self.graphics
    }

    pub fn sync(&self) -> &SynchronizedOutput {
        &self.sync
    }

    pub fn sync_mut(&mut self) -> &mut SynchronizedOutput {
        &mut self.sync
    }

    pub fn kitty_kbd(&self) -> &KittyKeyboardState {
        &self.kitty_kbd
    }

    pub fn kitty_kbd_mut(&mut self) -> &mut KittyKeyboardState {
        &mut self.kitty_kbd
    }

    pub fn scrollback_pages(&self) -> &PageScrollback {
        &self.scrollback_pages
    }

    pub fn scrollback_pages_mut(&mut self) -> &mut PageScrollback {
        &mut self.scrollback_pages
    }

    pub fn underline(&self) -> &StyledUnderline {
        &self.underline
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
    use base64::Engine as _;
    #[test]
    fn screen_and_marks_stay_in_sync() {
        let mut terminal = Terminal::new(24, 80, 1000);
        let events = terminal.process(
            b"\x1b]133;A\x07$ \x1b]133;B\x07ls\r\n\x1b]133;C\x07a.txt\r\n\x1b]133;D;0\x07",
        );
        assert_eq!(events.len(), 4);
        assert!(terminal.contents().contains("a.txt"));
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

    #[test]
    fn test_sync_output_in_terminal() {
        let mut terminal = Terminal::new(10, 40, 100);
        // Begin synchronized update, feed bytes, then end
        terminal.process(b"\x1b[?2026h");
        assert!(terminal.sync().is_active());
        terminal.process(b"Synchronized text payload\x1b[?2026l");
        assert!(!terminal.sync().is_active());
        assert!(terminal.contents().contains("Synchronized text payload"));
    }

    #[test]
    fn test_sgr_styled_underline_detection() {
        let mut terminal = Terminal::new(10, 40, 100);
        terminal.process(b"\x1b[4:3;58;2;255;128;0mUnderlined Text");
        assert_eq!(terminal.underline().style, crate::underlines::UnderlineStyle::Curly);
        assert_eq!(
            terminal.underline().color,
            crate::underlines::UnderlineColor::Rgb(255, 128, 0)
        );
    }

    #[test]
    fn test_iterm2_image_event() {
        let mut terminal = Terminal::new(10, 40, 100);
        let base64_data = base64::engine::general_purpose::STANDARD.encode(b"PNG_SAMPLE");
        let osc = format!("\x1b]1337;File=inline=1;width=100;height=100:{}\x07", base64_data);
        let events = terminal.process(osc.as_bytes());

        assert!(events.iter().any(|e| matches!(e, OscEvent::Graphic(_))));
        assert_eq!(terminal.graphics().len(), 1);
        assert_eq!(terminal.graphics()[0].payload, b"PNG_SAMPLE");
    }
}

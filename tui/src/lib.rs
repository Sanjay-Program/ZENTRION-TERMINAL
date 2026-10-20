//! ZENTRION Terminal UI.
//!
//! The UI is a real terminal multiplexer: each pane owns a PTY running the
//! user's shell, rendered through a `vt100` screen buffer. Dashboards, the
//! editor, copilot and LAN chat sit on top of the same runtime.

mod chat;
mod copilot;
mod editor;
mod research;
mod session;
mod theme;
mod views;
mod widget;

pub use session::Session;
pub use theme::Theme;

use anyhow::Result;
use crossterm::{
    event::{
        self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
        Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEvent, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use editor::Editor;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Tabs, Wrap},
    Frame, Terminal,
};
use std::io::{stdout, Stdout};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use sysinfo::System;

const TICK: Duration = Duration::from_millis(33);
const SYSTEM_REFRESH: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Terminal,
    Home,
    Workflows,
    Tools,
    Agents,
    Ai,
    Security,
    Storage,
    Docs,
    Research,
    Chat,
}

impl View {
    fn dashboard_index(self) -> Option<usize> {
        match self {
            View::Terminal => None,
            View::Home => Some(0),
            View::Workflows => Some(1),
            View::Tools => Some(2),
            View::Agents => Some(3),
            View::Ai => Some(4),
            View::Security => Some(5),
            View::Storage => Some(6),
            View::Docs => Some(7),
            View::Research => Some(8),
            View::Chat => Some(9),
        }
    }

    fn from_dashboard_index(index: usize) -> Self {
        match index {
            0 => View::Home,
            1 => View::Workflows,
            2 => View::Tools,
            3 => View::Agents,
            4 => View::Ai,
            5 => View::Security,
            6 => View::Storage,
            7 => View::Docs,
            8 => View::Research,
            _ => View::Chat,
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "terminal" | "term" | "shell" => Some(View::Terminal),
            "home" => Some(View::Home),
            "workflows" | "workflow" => Some(View::Workflows),
            "tools" | "tool" => Some(View::Tools),
            "agents" | "agent" => Some(View::Agents),
            "ai" | "copilot" => Some(View::Ai),
            "security" | "sec" => Some(View::Security),
            "storage" => Some(View::Storage),
            "docs" | "help" => Some(View::Docs),
            "research" => Some(View::Research),
            "chat" | "lan" => Some(View::Chat),
            _ => None,
        }
    }

    fn title(self) -> &'static str {
        match self {
            View::Terminal => "Terminal",
            View::Home => "Home",
            View::Workflows => "Workflows",
            View::Tools => "Tools",
            View::Agents => "Agents",
            View::Ai => "AI",
            View::Security => "Security",
            View::Storage => "Storage",
            View::Docs => "Docs",
            View::Research => "Research",
            View::Chat => "LAN Chat",
        }
    }
}

struct Tab {
    sessions: Vec<Session>,
    focus: usize,
}

impl Tab {
    fn title(&self) -> String {
        let active = self
            .sessions
            .get(self.focus)
            .or_else(|| self.sessions.first());
        let name = active.map(|s| s.title.as_str()).unwrap_or("shell");
        if self.sessions.len() > 1 {
            format!("{name} +{}", self.sessions.len() - 1)
        } else {
            name.to_string()
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

pub struct App {
    tabs: Vec<Tab>,
    active_tab: usize,
    view: View,
    dashboard_index: usize,
    theme: Theme,
    sys: System,
    last_system_refresh: Instant,
    running: bool,

    show_palette: bool,
    palette_input: String,
    palette_hint: String,

    editor: Option<Editor>,
    editor_close_armed: bool,
    show_sysmon: bool,

    show_copilot: bool,
    copilot_focus: bool,
    copilot: copilot::Copilot,

    chat: chat::ChatState,
    research: research::ResearchState,

    proficiency: views::Proficiency,
    shell: String,
    cwd: String,
    platform: String,
    data_dir: PathBuf,
    config_dir: PathBuf,
    startup_error: Option<String>,
    pane_rects: Vec<Rect>,
    last_pane_size: (u16, u16),
}

impl App {
    pub fn new() -> Self {
        let theme = Theme::load();
        let cwd = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| ".".into());
        let config_dir = z_core::config::user_config_dir().unwrap_or_else(|| PathBuf::from("."));
        let data_dir = z_core::config::user_data_dir().unwrap_or_else(|| PathBuf::from("."));
        let mut app = Self {
            tabs: Vec::new(),
            active_tab: 0,
            view: View::Terminal,
            dashboard_index: 0,
            theme,
            sys: System::new_all(),
            last_system_refresh: Instant::now() - SYSTEM_REFRESH,
            running: true,
            show_palette: false,
            palette_input: String::new(),
            palette_hint: String::new(),
            editor: None,
            editor_close_armed: false,
            show_sysmon: false,
            show_copilot: false,
            copilot_focus: false,
            copilot: copilot::Copilot::default(),
            chat: chat::ChatState::default(),
            research: research::ResearchState::default(),
            proficiency: views::Proficiency::Professional,
            shell: session::default_shell(),
            cwd,
            platform: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
            data_dir,
            config_dir,
            startup_error: None,
            pane_rects: Vec::new(),
            last_pane_size: (40, 120),
        };
        app.sys.refresh_all();
        app.new_tab();
        app
    }

    pub fn run(&mut self, terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
        while self.running {
            self.poll_backgrounds();

            terminal.draw(|frame| self.draw(frame))?;
            self.resize_sessions();

            if !self.running {
                break;
            }

            if event::poll(TICK)? {
                match event::read()? {
                    Event::Key(key) => self.handle_key(key)?,
                    Event::Mouse(mouse) => self.handle_mouse(mouse),
                    Event::Paste(text) => self.handle_paste(&text),
                    Event::Resize(_, _) => {}
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn poll_backgrounds(&mut self) {
        for tab in &mut self.tabs {
            for session in &mut tab.sessions {
                session.poll();
            }
        }
        self.copilot.poll();
        self.research.poll();
        if self.chat_started() {
            self.chat.poll();
        }
        if self.last_system_refresh.elapsed() >= SYSTEM_REFRESH {
            self.sys.refresh_all();
            self.last_system_refresh = Instant::now();
        }
    }

    fn chat_started(&self) -> bool {
        self.chat.has_bridge()
    }

    fn resize_sessions(&mut self) {
        if self.view != View::Terminal || self.show_sysmon || self.editor.is_some() {
            return;
        }
        let rects = self.pane_rects.clone();
        let Some(tab) = self.tabs.get_mut(self.active_tab) else {
            return;
        };
        for (index, rect) in rects.iter().enumerate() {
            if let Some(session) = tab.sessions.get_mut(index) {
                if rect.width > 2 && rect.height > 2 {
                    session.resize(rect.height - 2, rect.width - 2);
                }
            }
        }
        if let Some(rect) = rects.first() {
            if rect.width > 2 && rect.height > 2 {
                self.last_pane_size = (rect.height - 2, rect.width - 2);
            }
        }
    }

    fn new_tab(&mut self) {
        let (rows, cols) = self.last_pane_size;
        match Session::spawn(rows, cols) {
            Ok(session) => {
                self.tabs.push(Tab {
                    sessions: vec![session],
                    focus: 0,
                });
                self.active_tab = self.tabs.len() - 1;
                self.view = View::Terminal;
            }
            Err(e) => {
                self.startup_error = Some(format!("{e:#}"));
            }
        }
    }

    fn split_pane(&mut self) {
        let (rows, cols) = self.last_pane_size;
        let Some(tab) = self.tabs.get_mut(self.active_tab) else {
            return;
        };
        if tab.sessions.len() >= 4 {
            self.palette_hint = "A tab can hold at most four panes".into();
            return;
        }
        match Session::spawn(rows / 2, cols / 2) {
            Ok(session) => {
                tab.sessions.push(session);
                tab.focus = tab.sessions.len() - 1;
            }
            Err(e) => self.startup_error = Some(format!("{e:#}")),
        }
    }

    fn close_focused(&mut self) {
        let tab_count = self.tabs.len();
        let close_tab = {
            let Some(tab) = self.tabs.get(self.active_tab) else {
                return;
            };
            if tab.sessions.is_empty() {
                return;
            }
            // A one-pane tab closes as a tab when another tab exists. Closing
            // the last pane of the last tab replaces it with a fresh shell
            // instead of leaving the UI empty.
            tab.sessions.len() == 1 && tab_count > 1
        };
        if close_tab {
            self.tabs.remove(self.active_tab);
            self.active_tab = self.active_tab.min(self.tabs.len() - 1);
            return;
        }
        let Some(tab) = self.tabs.get_mut(self.active_tab) else {
            return;
        };
        tab.sessions.remove(tab.focus);
        if tab.sessions.is_empty() {
            // Never leave the UI without a usable terminal. Replace the last
            // pane with a fresh shell rather than showing an empty screen.
            let (rows, cols) = self.last_pane_size;
            if let Ok(session) = Session::spawn(rows, cols) {
                tab.sessions.push(session);
                tab.focus = 0;
            } else {
                self.tabs.remove(self.active_tab);
                if self.tabs.is_empty() {
                    self.running = false;
                } else {
                    self.active_tab = self.active_tab.min(self.tabs.len() - 1);
                }
                return;
            }
        }
        tab.focus = tab.focus.min(tab.sessions.len().saturating_sub(1));
    }

    fn cycle_pane(&mut self) {
        if let Some(tab) = self.tabs.get_mut(self.active_tab) {
            if !tab.sessions.is_empty() {
                tab.focus = (tab.focus + 1) % tab.sessions.len();
            }
        }
    }

    fn active_session_mut(&mut self) -> Option<&mut Session> {
        self.tabs
            .get_mut(self.active_tab)
            .and_then(|tab| tab.sessions.get_mut(tab.focus))
    }

    fn send_to_terminal(&mut self, bytes: &[u8]) {
        if let Some(session) = self.active_session_mut() {
            session.write(bytes);
        }
    }

    fn handle_mouse(&mut self, event: MouseEvent) {
        if self.view != View::Terminal || self.editor.is_some() || self.show_sysmon {
            return;
        }
        let focus = self
            .tabs
            .get(self.active_tab)
            .map(|tab| tab.focus)
            .unwrap_or(0);
        let Some(rect) = self.pane_rects.get(focus).copied() else {
            return;
        };
        // Reject events on the border or outside this pane.
        if event.column <= rect.x
            || event.row <= rect.y
            || event.column + 1 >= rect.x + rect.width
            || event.row + 1 >= rect.y + rect.height
        {
            return;
        }
        // crossterm coordinates are 0-based and global; the PTY wants 1-based
        // coordinates relative to the pane's content area.
        let mut local = event;
        local.column = event.column - rect.x - 1;
        local.row = event.row - rect.y - 1;

        let Some(session) = self.active_session_mut() else {
            return;
        };
        if session.mouse_enabled() {
            if let Some(bytes) = session::encode_mouse(local) {
                session.write(&bytes);
            }
            return;
        }
        // No mouse protocol: use the wheel for scrollback, ignore clicks.
        match event.kind {
            MouseEventKind::ScrollUp => session.scroll_up(3),
            MouseEventKind::ScrollDown => session.scroll_down(3),
            _ => {}
        }
    }

    fn handle_paste(&mut self, text: &str) {
        if self.show_palette {
            self.palette_input.push_str(text);
            return;
        }
        if let Some(editor) = self.editor.as_mut() {
            if editor.prompt.is_some() {
                for c in text.chars() {
                    editor.handle_key(KeyCode::Char(c));
                }
            } else {
                editor.insert_str(text);
            }
            return;
        }
        if self.copilot_focus && self.show_copilot {
            self.copilot.input.push_str(text);
            return;
        }
        match self.view {
            View::Terminal => {
                // Wrap in bracketed-paste markers so the shell inserts the text
                // literally instead of executing each newline.
                let mut payload = Vec::with_capacity(text.len() + 12);
                payload.extend_from_slice(b"\x1b[200~");
                payload.extend_from_slice(text.as_bytes());
                payload.extend_from_slice(b"\x1b[201~");
                self.send_to_terminal(&payload);
            }
            View::Chat => self.chat.input.push_str(text),
            View::Research => self.research.query.push_str(text),
            _ => {}
        }
    }

    fn set_view(&mut self, view: View) {
        self.view = view;
        if let Some(index) = view.dashboard_index() {
            self.dashboard_index = index;
        }
        if view == View::Chat && !self.chat.passphrase_needed() {
            self.chat.start();
        }
    }

    fn cycle_dashboard(&mut self, backwards: bool) {
        let count = views::DASHBOARD_VIEWS.len();
        self.dashboard_index = if backwards {
            (self.dashboard_index + count - 1) % count
        } else {
            (self.dashboard_index + 1) % count
        };
        self.view = View::from_dashboard_index(self.dashboard_index);
    }

    fn draw(&mut self, f: &mut Frame) {
        let area = f.area();
        if area.width < 20 || area.height < 8 {
            f.render_widget(
                Paragraph::new("Terminal too small — resize the window")
                    .alignment(Alignment::Center),
                area,
            );
            return;
        }

        let theme = self.theme.clone();
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(3),
                Constraint::Length(3),
            ])
            .split(area);

        self.draw_header(f, outer[0], &theme);
        let body = outer[1];
        let (main_body, copilot_area) = if self.show_copilot {
            let split = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
                .split(body);
            (split[0], Some(split[1]))
        } else {
            (body, None)
        };
        let mut pane_rects = Vec::new();

        if self.view == View::Terminal {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(2), Constraint::Min(2)])
                .split(main_body);
            self.draw_tab_bar(f, chunks[0], &theme);
            let terminal_area = chunks[1];

            if let Some(tab) = self.tabs.get_mut(self.active_tab) {
                let rects = pane_areas(terminal_area, tab.sessions.len());
                for (index, rect) in rects.iter().copied().enumerate() {
                    if let Some(session) = tab.sessions.get_mut(index) {
                        let focused = index == tab.focus && !self.copilot_focus;
                        widget::render_session(f, rect, session, &theme, focused);
                        pane_rects.push(rect);
                    }
                }
            }
            if let Some(error) = &self.startup_error {
                if pane_rects.is_empty() {
                    widget::render_terminal_error(f, terminal_area, error, &theme);
                }
            }
        } else {
            match self.view {
                View::Chat => self.chat.render(f, main_body, &theme, true),
                View::Research => self.research.render(f, main_body, &theme, true),
                other => {
                    let index = other.dashboard_index().unwrap_or(0);
                    let sessions: usize = self.tabs.iter().map(|t| t.sessions.len()).sum();
                    let info = views::DashboardInfo {
                        shell: &self.shell,
                        cwd: &self.cwd,
                        theme: &self.theme.name,
                        sessions,
                        platform: &self.platform,
                        data_dir: self.data_dir.clone(),
                        config_dir: self.config_dir.clone(),
                        proficiency: self.proficiency,
                    };
                    views::render_dashboard(f, main_body, index, &info, &theme);
                }
            }
        }

        if let Some(area) = copilot_area {
            self.copilot
                .render(f, area, &theme, self.copilot_focus && self.show_copilot);
        }

        self.pane_rects = pane_rects;

        if self.show_sysmon {
            let popup = centered_rect(body, 90, 80);
            f.render_widget(Clear, popup);
            views::render_sysmon(f, popup, &self.sys, &theme);
        }

        if let Some(editor) = self.editor.as_mut() {
            let popup = centered_rect(body, 90, 85);
            f.render_widget(Clear, popup);
            editor.render(f, popup, &theme);
        }

        if self.show_palette {
            self.draw_palette(f, body, &theme);
        }

        self.draw_footer(f, outer[2], &theme);
    }

    fn draw_header(&self, f: &mut Frame, area: Rect, theme: &Theme) {
        let sessions: usize = self.tabs.iter().map(|t| t.sessions.len()).sum();
        let header = Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    " ZENTRION ",
                    Style::default()
                        .fg(theme.primary)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("TERMINAL ", Style::default().fg(theme.text)),
                Span::styled(
                    format!("v{}", env!("CARGO_PKG_VERSION")),
                    Style::default().fg(theme.secondary),
                ),
                Span::styled(
                    format!(
                        "  ·  theme {}  ·  {} panes  ·  {}",
                        theme.name, sessions, self.platform
                    ),
                    Style::default().fg(theme.secondary),
                ),
            ]),
            Line::from(vec![
                Span::styled(" cwd ", Style::default().fg(theme.accent)),
                Span::raw(self.cwd.as_str()),
                Span::styled("   view ", Style::default().fg(theme.accent)),
                Span::raw(self.view.title()),
                Span::styled(
                    "   local-first · no telemetry",
                    Style::default().fg(theme.secondary),
                ),
            ]),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.secondary)),
        );
        f.render_widget(header, area);
    }

    fn draw_tab_bar(&self, f: &mut Frame, area: Rect, theme: &Theme) {
        let titles: Vec<Line> = self
            .tabs
            .iter()
            .enumerate()
            .map(|(index, tab)| {
                let dead = tab.sessions.iter().all(|s| s.is_dead());
                let marker = if dead { "×" } else { "" };
                Line::from(format!(" {}{} {} ", index + 1, marker, tab.title()))
            })
            .collect();
        let tabs = Tabs::new(titles)
            .select(self.active_tab)
            .style(Style::default().fg(theme.secondary))
            .highlight_style(
                Style::default()
                    .fg(theme.primary)
                    .add_modifier(Modifier::BOLD),
            )
            .divider(Span::styled("│", Style::default().fg(theme.secondary)))
            .block(
                Block::default()
                    .borders(Borders::TOP | Borders::BOTTOM)
                    .border_style(Style::default().fg(theme.secondary)),
            );
        f.render_widget(tabs, area);
    }

    fn draw_footer(&self, f: &mut Frame, area: Rect, theme: &Theme) {
        let hint = if self.show_palette {
            "Palette: type a shell command or :action · Enter runs · Esc closes".to_string()
        } else if let Some(editor) = &self.editor {
            format!(
                "Editor: Ctrl+S save · Ctrl+O open · Esc close · {}",
                editor.status
            )
        } else if self.show_sysmon {
            "System monitor: Esc closes".to_string()
        } else if self.view == View::Terminal {
            "F7 tab · F8 split · F9 close · F2 palette · F3 editor · F4 AI · F5 monitor · F6 chat · Alt+V dashboard · F10 quit"
                .to_string()
        } else {
            "1-0 views · Tab next · Alt+1..0 jump · Alt+H home · Alt+V terminal · F2 palette · F10 quit".to_string()
        };
        let footer = Paragraph::new(vec![
            Line::from(Span::styled(hint, Style::default().fg(theme.secondary))),
            Line::from(vec![
                Span::styled(" Alt+1..9", Style::default().fg(theme.accent)),
                Span::raw(" tab  "),
                Span::styled("Alt+O", Style::default().fg(theme.accent)),
                Span::raw(" pane  "),
                Span::styled("Shift+PgUp/PgDn", Style::default().fg(theme.accent)),
                Span::raw(" scroll  "),
                Span::styled("Alt+←/→", Style::default().fg(theme.accent)),
                Span::raw(" prev/next  "),
                Span::styled("Alt+P", Style::default().fg(theme.accent)),
                Span::raw(" proficiency"),
            ]),
        ])
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(theme.secondary)),
        );
        f.render_widget(footer, area);
    }

    fn draw_palette(&self, f: &mut Frame, body: Rect, theme: &Theme) {
        let popup = centered_rect(body, 70, 50);
        f.render_widget(Clear, popup);

        let suggestions = [
            ":theme cyberpunk",
            ":theme dracula",
            ":theme nord",
            ":theme matrix",
            ":new",
            ":split",
            ":close",
            ":view security",
            ":e README.md",
            ":ai explain this error",
            "z doctor",
            "z status",
            "z bundle list",
            "z scan .",
            "git status",
            "cargo test",
        ];
        let needle = self.palette_input.to_ascii_lowercase();
        let mut lines = vec![
            Line::from(vec![
                Span::styled("› ", Style::default().fg(theme.accent)),
                Span::raw(self.palette_input.as_str()),
                Span::styled("▏", Style::default().fg(theme.accent)),
            ]),
            Line::from(""),
        ];
        for suggestion in suggestions {
            if needle.is_empty() || suggestion.to_ascii_lowercase().contains(&needle) {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(suggestion, Style::default().fg(theme.text)),
                ]));
            }
        }
        if !self.palette_hint.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                self.palette_hint.clone(),
                Style::default().fg(theme.warning),
            )));
        }

        let palette = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.accent))
                .title(" Command Palette "),
        );
        f.render_widget(palette, popup);
        f.set_cursor_position((
            popup.x + 3 + self.palette_input.chars().count() as u16,
            popup.y + 1,
        ));
    }

    fn handle_key(&mut self, key: KeyEvent) -> Result<()> {
        if key.kind == KeyEventKind::Release {
            return Ok(());
        }
        let mods = key.modifiers;
        let ctrl = mods.contains(KeyModifiers::CONTROL);
        let shift = mods.contains(KeyModifiers::SHIFT);
        let alt = mods.contains(KeyModifiers::ALT);
        // Only bindings a terminal can actually distinguish are used here:
        // function keys and Alt+<key>. Most terminals encode Ctrl+Shift+<letter>
        // identically to Ctrl+<letter>, so such chords would either be
        // unreachable or steal keystrokes from the shell.
        //
        // The palette is modal.
        if self.show_palette {
            if key.code == KeyCode::F(2) {
                self.show_palette = false;
                return Ok(());
            }
            self.handle_palette_key(key);
            return Ok(());
        }

        if key.code == KeyCode::F(10) {
            self.running = false;
            return Ok(());
        }
        if key.code == KeyCode::F(2) {
            self.show_palette = true;
            self.palette_input.clear();
            self.palette_hint.clear();
            return Ok(());
        }
        if key.code == KeyCode::F(7) {
            self.new_tab();
            return Ok(());
        }
        if key.code == KeyCode::F(9) {
            self.close_focused();
            return Ok(());
        }
        if key.code == KeyCode::F(8) {
            self.split_pane();
            self.set_view(View::Terminal);
            return Ok(());
        }
        if key.code == KeyCode::F(3) {
            self.toggle_editor();
            return Ok(());
        }
        if key.code == KeyCode::F(5) {
            self.show_sysmon = !self.show_sysmon;
            return Ok(());
        }
        if key.code == KeyCode::F(4) {
            self.show_copilot = !self.show_copilot;
            self.copilot_focus = self.show_copilot;
            return Ok(());
        }
        if key.code == KeyCode::F(6) {
            self.set_view(View::Chat);
            return Ok(());
        }

        if key.code == KeyCode::F(1) {
            if self.view == View::Terminal {
                self.set_view(View::Home);
            } else {
                self.set_view(View::Terminal);
            }
            return Ok(());
        }

        if alt {
            if let KeyCode::Char(c) = key.code {
                if c.is_ascii_digit() {
                    let index = if c == '0' {
                        9
                    } else {
                        c as usize - '1' as usize
                    };
                    if self.view == View::Terminal {
                        if index < self.tabs.len() {
                            self.active_tab = index;
                        }
                    } else if index < views::DASHBOARD_VIEWS.len() {
                        self.dashboard_index = index;
                        self.set_view(View::from_dashboard_index(index));
                    }
                    return Ok(());
                }
                if c.eq_ignore_ascii_case(&'h') {
                    self.dashboard_index = 0;
                    self.set_view(View::Home);
                    return Ok(());
                }
                if c.eq_ignore_ascii_case(&'v') {
                    if self.view == View::Terminal {
                        self.set_view(View::from_dashboard_index(self.dashboard_index));
                    } else {
                        self.set_view(View::Terminal);
                    }
                    return Ok(());
                }
                if c.eq_ignore_ascii_case(&'o') {
                    self.cycle_pane();
                    return Ok(());
                }
                if c.eq_ignore_ascii_case(&'p') {
                    self.proficiency = match self.proficiency {
                        views::Proficiency::Beginner => views::Proficiency::Professional,
                        views::Proficiency::Professional => views::Proficiency::Expert,
                        views::Proficiency::Expert => views::Proficiency::Beginner,
                    };
                    return Ok(());
                }
            }
            if key.code == KeyCode::Left {
                if !self.tabs.is_empty() {
                    self.active_tab = (self.active_tab + self.tabs.len() - 1) % self.tabs.len();
                    self.set_view(View::Terminal);
                }
                return Ok(());
            }
            if key.code == KeyCode::Right {
                if !self.tabs.is_empty() {
                    self.active_tab = (self.active_tab + 1) % self.tabs.len();
                    self.set_view(View::Terminal);
                }
                return Ok(());
            }
        }

        if self.show_sysmon {
            if key.code == KeyCode::Esc {
                self.show_sysmon = false;
            }
            return Ok(());
        }

        if let Some(editor) = self.editor.as_mut() {
            if ctrl && !shift {
                match key.code {
                    KeyCode::Char('s') | KeyCode::Char('S') => {
                        editor.save();
                        return Ok(());
                    }
                    KeyCode::Char('o') | KeyCode::Char('O') => {
                        editor.open_prompt();
                        return Ok(());
                    }
                    _ => {}
                }
            }
            if key.code == KeyCode::Esc {
                if editor.prompt.is_some() {
                    editor.handle_key(KeyCode::Esc);
                    return Ok(());
                }
                if editor.dirty && !self.editor_close_armed {
                    self.editor_close_armed = true;
                    editor.status = "Unsaved changes — Ctrl+S saves, Esc again discards".into();
                    return Ok(());
                }
                self.editor = None;
                self.editor_close_armed = false;
                return Ok(());
            }
            if !editor.handle_key(key.code) {
                self.editor = None;
            }
            self.editor_close_armed = false;
            return Ok(());
        }

        if self.copilot_focus && self.show_copilot {
            match key.code {
                KeyCode::Esc => {
                    self.copilot_focus = false;
                    return Ok(());
                }
                KeyCode::Enter => {
                    self.copilot.submit();
                    return Ok(());
                }
                KeyCode::Backspace => {
                    self.copilot.input.pop();
                    return Ok(());
                }
                KeyCode::PageUp => {
                    self.copilot.scroll = self.copilot.scroll.saturating_sub(5);
                    return Ok(());
                }
                KeyCode::PageDown => {
                    self.copilot.scroll = self.copilot.scroll.saturating_add(5);
                    return Ok(());
                }
                KeyCode::Char('u') if ctrl => {
                    self.copilot.input.clear();
                    return Ok(());
                }
                KeyCode::Char(c) if !ctrl && !alt => {
                    self.copilot.input.push(c);
                    return Ok(());
                }
                _ => return Ok(()),
            }
        }

        match self.view {
            View::Terminal => {
                if shift {
                    match key.code {
                        KeyCode::PageUp => {
                            if let Some(session) = self.active_session_mut() {
                                session.scroll_up(10);
                            }
                            return Ok(());
                        }
                        KeyCode::PageDown => {
                            if let Some(session) = self.active_session_mut() {
                                session.scroll_down(10);
                            }
                            return Ok(());
                        }
                        KeyCode::Home => {
                            if let Some(session) = self.active_session_mut() {
                                session.scroll_up(usize::MAX / 2);
                            }
                            return Ok(());
                        }
                        KeyCode::End => {
                            if let Some(session) = self.active_session_mut() {
                                session.scroll_to_bottom();
                            }
                            return Ok(());
                        }
                        _ => {}
                    }
                }
                if let Some(session) = self.active_session_mut() {
                    let app_cursor = session.parser.screen().application_cursor();
                    if let Some(bytes) = session::encode_key(key, app_cursor) {
                        session.write(&bytes);
                    }
                }
            }
            View::Chat => match key.code {
                KeyCode::Esc => self.set_view(View::Terminal),
                KeyCode::Tab => self.cycle_dashboard(false),
                KeyCode::BackTab => self.cycle_dashboard(true),
                KeyCode::Enter => self.chat.send(),
                KeyCode::Backspace => self.chat.backspace(),
                KeyCode::PageUp => self.chat.scroll_up(),
                KeyCode::PageDown => self.chat.scroll_down(),
                KeyCode::Char('u') if ctrl => self.chat.clear_input(),
                KeyCode::Char(c) if !ctrl && !alt => self.chat.handle_char(c),
                _ => {}
            },
            View::Research => match key.code {
                KeyCode::Esc => self.set_view(View::Terminal),
                KeyCode::Tab => self.cycle_dashboard(false),
                KeyCode::BackTab => self.cycle_dashboard(true),
                KeyCode::Enter => self.research.submit(),
                KeyCode::Backspace => {
                    self.research.query.pop();
                }
                KeyCode::PageUp => self.research.scroll = self.research.scroll.saturating_sub(5),
                KeyCode::PageDown => self.research.scroll = self.research.scroll.saturating_add(5),
                KeyCode::Char(c) if !ctrl && !alt => self.research.query.push(c),
                _ => {}
            },
            _ => match key.code {
                KeyCode::Esc => self.set_view(View::Terminal),
                KeyCode::Tab => self.cycle_dashboard(false),
                KeyCode::BackTab => self.cycle_dashboard(true),
                KeyCode::Char(c) if !ctrl && !alt => {
                    if let Some(digit) = c.to_digit(10) {
                        let index = if digit == 0 { 9 } else { digit as usize - 1 };
                        self.dashboard_index = index;
                        self.set_view(View::from_dashboard_index(index));
                    }
                }
                _ => {}
            },
        }

        Ok(())
    }

    fn toggle_editor(&mut self) {
        if self.editor.is_some() {
            self.editor = None;
            self.editor_close_armed = false;
            return;
        }
        let editor = if std::path::Path::new("README.md").exists() {
            Editor::open("README.md")
        } else {
            Editor::default()
        };
        self.editor = Some(editor);
        self.editor_close_armed = false;
    }

    fn handle_palette_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.show_palette = false;
            }
            KeyCode::Enter => {
                let text = self.palette_input.trim().to_string();
                self.palette_input.clear();
                if text.is_empty() {
                    self.show_palette = false;
                    return;
                }
                self.execute_palette(&text);
            }
            KeyCode::Backspace => {
                self.palette_input.pop();
            }
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.palette_input.push(c);
            }
            _ => {}
        }
    }

    fn execute_palette(&mut self, text: &str) {
        if let Some(action) = text.strip_prefix(':') {
            let mut parts = action.splitn(2, char::is_whitespace);
            let command = parts.next().unwrap_or("").to_ascii_lowercase();
            let argument = parts.next().unwrap_or("").trim().to_string();
            match command.as_str() {
                "new" | "tab" => {
                    self.new_tab();
                    self.show_palette = false;
                }
                "split" => {
                    self.split_pane();
                    self.set_view(View::Terminal);
                    self.show_palette = false;
                }
                "close" => {
                    self.close_focused();
                    self.show_palette = false;
                }
                "theme" => match Theme::named(&argument) {
                    Some(theme) => {
                        let persisted = Theme::persist(&argument);
                        self.theme = theme;
                        self.palette_hint = match persisted {
                            Ok(()) => format!("Theme set to {argument}"),
                            Err(e) => format!("Theme applied for this session only: {e}"),
                        };
                        self.show_palette = false;
                    }
                    None => {
                        self.palette_hint = format!(
                            "Unknown theme `{argument}`. Try: {}",
                            Theme::available().join(", ")
                        );
                    }
                },
                "view" => match View::from_name(&argument) {
                    Some(view) => {
                        self.set_view(view);
                        self.show_palette = false;
                    }
                    None => self.palette_hint = format!("Unknown view `{argument}`"),
                },
                "e" | "edit" => {
                    if argument.is_empty() {
                        self.toggle_editor();
                    } else {
                        let path = PathBuf::from(&argument);
                        self.editor = Some(if path.exists() {
                            Editor::open(&path)
                        } else {
                            Editor {
                                path: Some(path.clone()),
                                dirty: true,
                                status: format!("New file {}", path.display()),
                                ..Editor::default()
                            }
                        });
                    }
                    self.show_palette = false;
                }
                "ai" => {
                    self.show_copilot = true;
                    self.copilot_focus = true;
                    if !argument.is_empty() {
                        self.copilot.input = argument;
                        self.copilot.submit();
                    }
                    self.show_palette = false;
                }
                "chat" => {
                    self.set_view(View::Chat);
                    self.show_palette = false;
                }
                "sysmon" | "monitor" => {
                    self.show_sysmon = true;
                    self.show_palette = false;
                }
                "quit" | "q" => {
                    self.running = false;
                }
                "help" => {
                    self.set_view(View::Docs);
                    self.show_palette = false;
                }
                other => {
                    self.palette_hint = format!(
                        "Unknown action `:{other}`. Try :new, :split, :close, :theme, :view, :e, :ai, :chat, :quit"
                    );
                }
            }
            return;
        }

        self.set_view(View::Terminal);
        if let Some(session) = self.active_session_mut() {
            session.write_line(text);
        }
        self.show_palette = false;
    }
}

fn pane_areas(area: Rect, count: usize) -> Vec<Rect> {
    match count {
        0 => vec![],
        1 => vec![area],
        2 => Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area)
            .to_vec(),
        3 => {
            let outer = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(area);
            let right = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(outer[1]);
            vec![outer[0], right[0], right[1]]
        }
        _ => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(area);
            let top = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(rows[0]);
            let bottom = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(rows[1]);
            vec![top[0], top[1], bottom[0], bottom[1]]
        }
    }
}

fn centered_rect(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        execute!(
            stdout(),
            EnterAlternateScreen,
            EnableBracketedPaste,
            EnableMouseCapture
        )?;

        let original = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = disable_raw_mode();
            let _ = execute!(
                stdout(),
                LeaveAlternateScreen,
                DisableBracketedPaste,
                DisableMouseCapture,
                crossterm::cursor::Show
            );
            original(info);
        }));

        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            stdout(),
            LeaveAlternateScreen,
            DisableBracketedPaste,
            DisableMouseCapture,
            crossterm::cursor::Show
        );
    }
}

/// Launch the interactive UI. Blocks until the user quits.
pub fn start_tui() -> Result<()> {
    let guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new();
    let result = app.run(&mut terminal);
    drop(terminal);
    drop(guard);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pane_layouts_cover_the_area() {
        let area = Rect::new(0, 0, 120, 40);
        for count in 1..=4 {
            let panes = pane_areas(area, count);
            assert_eq!(panes.len(), count);
            for pane in panes {
                assert!(pane.width > 0 && pane.height > 0);
            }
        }
    }

    #[test]
    fn view_names_round_trip() {
        for name in ["terminal", "home", "security", "chat", "docs"] {
            assert!(View::from_name(name).is_some());
        }
        assert!(View::from_name("nope").is_none());
    }

    #[test]
    fn centered_rect_stays_inside() {
        let area = Rect::new(0, 0, 100, 40);
        let popup = centered_rect(area, 70, 50);
        assert!(popup.x + popup.width <= area.width);
        assert!(popup.y + popup.height <= area.height);
    }
}

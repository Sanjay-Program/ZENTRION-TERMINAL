//! Model-synthesized research reports, saved as markdown.

use crate::copilot::request;
use crate::theme::Theme;
use ai::models::ChatMessage;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

type ResearchResult = Result<(String, Option<PathBuf>), String>;

pub struct ResearchState {
    pub query: String,
    pub output: String,
    pub status: String,
    pub pending: bool,
    pub scroll: u16,
    pub report_path: Option<PathBuf>,
    rx: Option<Receiver<ResearchResult>>,
}

impl Default for ResearchState {
    fn default() -> Self {
        Self {
            query: String::new(),
            output: String::new(),
            status: "Type a question and press Enter. Reports are saved under the data directory."
                .into(),
            pending: false,
            scroll: 0,
            report_path: None,
            rx: None,
        }
    }
}

impl ResearchState {
    pub fn submit(&mut self) {
        let query = self.query.trim().to_string();
        if query.is_empty() || self.pending {
            return;
        }
        self.pending = true;
        self.output.clear();
        self.status = "Researching…".into();
        self.scroll = 0;
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);

        thread::Builder::new()
            .name("zentrion-research".into())
            .spawn(move || {
                let system = "You are a careful research analyst. Produce a structured \
                    markdown report with: summary, key points, tradeoffs, practical \
                    recommendations, and open questions. Do not fabricate URLs, \
                    citations, statistics, or quotes. When you are uncertain, say so \
                    explicitly. The reader is a developer or security engineer.";
                let messages = vec![ChatMessage {
                    role: "user".into(),
                    content: query.clone(),
                }];
                let result = request(system, messages).map(|text| {
                    let path = save_report(&query, &text);
                    (text, path)
                });
                let _ = tx.send(result);
            })
            .ok();
    }

    pub fn poll(&mut self) {
        let Some(rx) = self.rx.as_ref() else {
            return;
        };
        match rx.try_recv() {
            Ok(Ok((text, path))) => {
                self.output = text;
                self.report_path = path.clone();
                self.status = match path {
                    Some(path) => format!("Saved {}", path.display()),
                    None => "Report generated (could not save file)".into(),
                };
                self.pending = false;
                self.rx = None;
            }
            Ok(Err(e)) => {
                self.status = format!("Research failed: {e}");
                self.pending = false;
                self.rx = None;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.pending = false;
                self.rx = None;
                self.status = "Research worker stopped unexpectedly".into();
            }
        }
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, theme: &Theme, focused: bool) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(3),
                Constraint::Length(2),
            ])
            .split(area);

        let input = Paragraph::new(Line::from(vec![
            Span::styled("› ", Style::default().fg(theme.accent)),
            Span::raw(self.query.as_str()),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if focused {
                    theme.accent
                } else {
                    theme.secondary
                }))
                .title(if self.pending {
                    " Researching… "
                } else {
                    " Research question (Enter) "
                }),
        );
        f.render_widget(input, rows[0]);
        if focused {
            f.set_cursor_position((
                rows[0].x + 3 + self.query.chars().count() as u16,
                rows[0].y + 1,
            ));
        }

        let body = Paragraph::new(if self.output.is_empty() {
            vec![
                Line::from(Span::styled(
                    "Model-synthesized research, no web access.",
                    Style::default().fg(theme.secondary),
                )),
                Line::from(""),
                Line::from("Reports are saved to the Zentrion data directory under research/."),
                Line::from("Verify claims before acting on them."),
            ]
        } else {
            self.output.lines().map(Line::from).collect()
        })
        .wrap(Wrap { trim: false })
        .scroll((self.scroll, 0))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.secondary))
                .title(" Report "),
        );
        f.render_widget(body, rows[1]);

        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                self.status.as_str(),
                Style::default()
                    .fg(theme.secondary)
                    .add_modifier(Modifier::empty()),
            )))
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::TOP)),
            rows[2],
        );
    }
}

fn save_report(query: &str, text: &str) -> Option<PathBuf> {
    let dir = z_core::config::user_data_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("research");
    std::fs::create_dir_all(&dir).ok()?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = dir.join(format!("research-{stamp}.md"));
    let slug = query.lines().next().unwrap_or("research");
    let contents = format!("# Zentrion research\n\n**Question:** {slug}\n\n{text}\n");
    std::fs::write(&path, contents).ok()?;
    Some(path)
}

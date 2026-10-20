//! Real AI copilot sidebar backed by the gateway/provider layer.

use crate::theme::Theme;
use ai::gateway::AIGateway;
use ai::models::{ChatMessage, ChatRequest};
use ai::provider::provider_from_env;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

const MAX_HISTORY: usize = 24;

pub struct Copilot {
    pub messages: Vec<ChatMessage>,
    pub input: String,
    pub pending: bool,
    pub status: String,
    pub scroll: u16,
    rx: Option<Receiver<Result<String, String>>>,
}

impl Default for Copilot {
    fn default() -> Self {
        Self {
            messages: vec![ChatMessage {
                role: "assistant".into(),
                content: "Copilot ready. Ask about the current terminal, an error, your project, or a command. \
                          I never run commands for you; I propose them for review."
                    .into(),
            }],
            input: String::new(),
            pending: false,
            status: "Powered by ZENTRION_AI_PROVIDER (local Ollama by default)".into(),
            scroll: 0,
            rx: None,
        }
    }
}

impl Copilot {
    pub fn submit(&mut self) {
        let prompt = self.input.trim().to_string();
        if prompt.is_empty() || self.pending {
            return;
        }
        self.input.clear();
        self.messages.push(ChatMessage {
            role: "user".into(),
            content: prompt,
        });
        self.pending = true;
        self.status = "Thinking…".into();
        self.scroll = 0;

        let history: Vec<ChatMessage> = {
            let start = self.messages.len().saturating_sub(MAX_HISTORY);
            self.messages[start..].to_vec()
        };
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);

        thread::Builder::new()
            .name("zentrion-copilot".into())
            .spawn(move || {
                let system = "You are Zentrion's terminal copilot. You help with software \
                      development, DevOps and authorized security work. Be concise and \
                      concrete. Prefer real commands, explain risk, and never claim you \
                      executed anything. If a task needs a host action, provide the exact \
                      command for the user to run.";
                let result = request(system, history);
                let _ = tx.send(result);
            })
            .ok();
    }

    pub fn poll(&mut self) {
        let Some(rx) = self.rx.as_ref() else {
            return;
        };
        match rx.try_recv() {
            Ok(result) => {
                self.pending = false;
                self.rx = None;
                match result {
                    Ok(text) => {
                        self.messages.push(ChatMessage {
                            role: "assistant".into(),
                            content: text,
                        });
                        self.status = "Ready".into();
                    }
                    Err(e) => {
                        self.messages.push(ChatMessage {
                            role: "assistant".into(),
                            content: format!("AI request failed: {e}"),
                        });
                        self.status = format!("Error: {e}");
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.pending = false;
                self.rx = None;
                self.status = "AI worker stopped unexpectedly".into();
            }
        }
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, theme: &Theme, focused: bool) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(4),
                Constraint::Length(4),
                Constraint::Length(2),
            ])
            .split(area);

        let border = if focused {
            theme.accent
        } else {
            theme.secondary
        };
        let mut lines: Vec<Line> = Vec::new();
        for message in &self.messages {
            let (label, color) = match message.role.as_str() {
                "user" => ("You", theme.primary),
                "assistant" => ("Zentrion", theme.accent),
                _ => (&message.role[..], theme.secondary),
            };
            lines.push(Line::from(Span::styled(
                format!("{label}:"),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            )));
            for line in message.content.lines() {
                lines.push(Line::from(format!("  {line}")));
            }
            lines.push(Line::from(""));
        }
        let conversation = Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((self.scroll, 0))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border))
                    .title(" AI Copilot "),
            );
        f.render_widget(conversation, chunks[0]);

        let input = Paragraph::new(Line::from(vec![
            Span::styled("› ", Style::default().fg(theme.accent)),
            Span::raw(self.input.as_str()),
        ]))
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border))
                .title(if self.pending {
                    " Sending… "
                } else {
                    " Message (Enter to send) "
                }),
        );
        f.render_widget(input, chunks[1]);
        if focused {
            let input_line = 1 + (self.input.chars().count() / area.width.max(1) as usize) as u16;
            let y = chunks[1].y + 1 + input_line.min(chunks[1].height.saturating_sub(2));
            let x = chunks[1].x + 3 + (self.input.chars().count() as u16 % area.width.max(1));
            f.set_cursor_position((x.min(chunks[1].x + chunks[1].width.saturating_sub(2)), y));
        }

        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                self.status.as_str(),
                Style::default().fg(theme.secondary),
            )))
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::TOP)),
            chunks[2],
        );
    }
}

/// Send a system prompt plus conversation history to the configured provider.
/// Runs on a private current-thread runtime so the TUI loop never blocks.
pub(crate) fn request(system: &str, history: Vec<ChatMessage>) -> Result<String, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start AI runtime: {e}"))?;

    let system = system.to_string();
    runtime.block_on(async move {
        let provider = provider_from_env().map_err(|e| e.to_string())?;
        let gateway = AIGateway::new(provider);
        let model =
            std::env::var("ZENTRION_AI_MODEL").unwrap_or_else(|_| "qwen2.5-coder:7b".to_string());
        let mut messages = vec![ChatMessage {
            role: "system".into(),
            content: system,
        }];
        messages.extend(history);
        let response = gateway
            .chat(ChatRequest {
                model,
                messages,
                temperature: Some(0.2),
            })
            .await
            .map_err(|e| e.to_string())?;
        response
            .choices
            .into_iter()
            .next()
            .map(|choice| choice.message.content)
            .ok_or_else(|| "the provider returned an empty response".to_string())
    })
}

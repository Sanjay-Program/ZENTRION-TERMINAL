//! Live P2P chat panel bridging the async network into the TUI thread.

use crate::theme::Theme;
use p2p::chat::{ChatMessage, P2pCommand, P2pConfig, P2pEvent, PeerInfo};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Bridge {
    events: Receiver<P2pEvent>,
    commands: tokio::sync::mpsc::UnboundedSender<P2pCommand>,
    pub tcp_port: u16,
    pub fingerprint: String,
}

pub struct ChatState {
    pub messages: Vec<ChatMessage>,
    pub peers: Vec<PeerInfo>,
    pub input: String,
    pub status: String,
    pub passphrase_needed: bool,
    pub scroll: usize,
    bridge: Option<Bridge>,
    username: String,
}

impl Default for ChatState {
    fn default() -> Self {
        let username = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "zentrion".into());
        let passphrase_needed = std::env::var("ZENTRION_P2P_KEY")
            .map(|k| k.trim().is_empty())
            .unwrap_or(true);
        Self {
            messages: Vec::new(),
            peers: Vec::new(),
            input: String::new(),
            status: if passphrase_needed {
                "Enter a shared passphrase to join the LAN, or set ZENTRION_P2P_KEY.".into()
            } else {
                "Ready — Enter starts encrypted discovery.".into()
            },
            passphrase_needed,
            scroll: 0,
            bridge: None,
            username,
        }
    }
}

impl ChatState {
    pub fn has_bridge(&self) -> bool {
        self.bridge.is_some()
    }

    pub fn passphrase_needed(&self) -> bool {
        self.passphrase_needed
    }

    pub fn clear_input(&mut self) {
        self.input.clear();
    }

    pub fn scroll_up(&mut self) {
        self.scroll = (self.scroll + 5).min(self.messages.len());
    }

    pub fn scroll_down(&mut self) {
        self.scroll = self.scroll.saturating_sub(5);
    }

    pub fn start(&mut self) {
        if self.bridge.is_some() {
            return;
        }
        let passphrase = std::env::var("ZENTRION_P2P_KEY")
            .ok()
            .filter(|k| !k.trim().is_empty())
            .unwrap_or_else(|| self.input.clone());
        if passphrase.trim().is_empty() {
            self.passphrase_needed = true;
            self.status = "A shared passphrase is required.".into();
            return;
        }
        self.input.clear();

        let tcp_port = std::env::var("ZENTRION_P2P_PORT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(p2p::chat::DEFAULT_TCP_PORT);
        let discovery_port = std::env::var("ZENTRION_P2P_DISCOVERY_PORT")
            .ok()
            .and_then(|value| {
                if value.eq_ignore_ascii_case("off") || value == "0" {
                    Some(None)
                } else {
                    value.parse::<u16>().ok().map(Some)
                }
            })
            .unwrap_or(Some(p2p::chat::DEFAULT_DISCOVERY_PORT));
        let mut config = P2pConfig::new(self.username.clone(), passphrase);
        config.tcp_port = tcp_port;
        config.discovery_port = discovery_port;
        let (event_tx, event_rx) = mpsc::channel();
        let (command_tx, mut command_rx) = tokio::sync::mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = mpsc::channel();

        thread::Builder::new()
            .name("zentrion-p2p".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(e) => {
                        let _ = ready_tx.send(Err(format!("runtime: {e}")));
                        return;
                    }
                };
                runtime.block_on(async move {
                    match p2p::chat::start(config).await {
                        Ok(handle) => {
                            let port = handle.tcp_port;
                            let fingerprint = handle.fingerprint.clone();
                            let _ = ready_tx.send(Ok((port, fingerprint)));
                            let commands = handle.commands.clone();
                            let mut events = handle.events;
                            loop {
                                tokio::select! {
                                    event = events.recv() => {
                                        match event {
                                            Ok(event) => {
                                                if event_tx.send(event).is_err() {
                                                    break;
                                                }
                                            }
                                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                                            Err(_) => break,
                                        }
                                    }
                                    command = command_rx.recv() => {
                                        match command {
                                            Some(command) => {
                                                if commands.send(command).is_err() {
                                                    break;
                                                }
                                            }
                                            None => break,
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            let _ = ready_tx.send(Err(e.to_string()));
                        }
                    }
                });
            })
            .ok();

        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok((port, fingerprint))) => {
                self.bridge = Some(Bridge {
                    events: event_rx,
                    commands: command_tx,
                    tcp_port: port,
                    fingerprint: fingerprint.clone(),
                });
                self.passphrase_needed = false;
                self.status = format!("Listening on TCP {port} · key {fingerprint}");
            }
            Ok(Err(e)) => {
                self.status = format!("Could not start chat: {e}");
            }
            Err(_) => {
                self.status = "Could not start chat: timed out".into();
            }
        }
    }

    pub fn poll(&mut self) {
        if self.bridge.is_none() {
            return;
        }
        let mut disconnected = false;
        let bridge = self.bridge.as_ref().expect("checked above");
        loop {
            match bridge.events.try_recv() {
                Ok(P2pEvent::Ready {
                    tcp_port,
                    fingerprint,
                    ..
                }) => {
                    self.status = format!("Listening on TCP {tcp_port} · key {fingerprint}");
                }
                Ok(P2pEvent::PeerJoined(peer)) => {
                    if !self.peers.iter().any(|p| p.id == peer.id) {
                        self.peers.push(peer);
                    }
                    self.status = format!("{} peers online", self.peers.len());
                }
                Ok(P2pEvent::PeerLeft(id)) => {
                    self.peers.retain(|p| p.id != id);
                }
                Ok(P2pEvent::Message(message)) => {
                    self.messages.push(message);
                    if self.messages.len() > 500 {
                        self.messages.drain(..100);
                    }
                    if self.scroll > 0 {
                        self.scroll = self.scroll.saturating_sub(1);
                    }
                }
                Ok(P2pEvent::Error(e)) => {
                    self.messages.push(ChatMessage {
                        sender: "system".into(),
                        content: e.clone(),
                        timestamp: now(),
                    });
                    self.status = e;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        if disconnected {
            self.status = "Chat worker stopped".into();
            self.bridge = None;
        }
    }

    pub fn send(&mut self) {
        let text = self.input.trim().to_string();
        if text.is_empty() {
            return;
        }
        if self.bridge.is_none() {
            self.start();
            return;
        }
        self.input.clear();
        if let Some(bridge) = self.bridge.as_ref() {
            let _ = bridge.commands.send(P2pCommand::Broadcast(text.clone()));
        }
        self.messages.push(ChatMessage {
            sender: format!("{} (you)", self.username),
            content: text,
            timestamp: now(),
        });
        self.scroll = 0;
    }

    pub fn handle_char(&mut self, c: char) {
        self.input.push(c);
    }

    pub fn backspace(&mut self) {
        self.input.pop();
    }

    pub fn peer_label(&self) -> String {
        match self.bridge.as_ref() {
            Some(bridge) => format!(
                "{} · port {} · key {}",
                self.peers.len(),
                bridge.tcp_port,
                bridge.fingerprint
            ),
            None => "not connected".into(),
        }
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect, theme: &Theme, focused: bool) {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(72), Constraint::Percentage(28)])
            .split(area);

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(4),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .split(columns[0]);

        let border = if focused {
            theme.accent
        } else {
            theme.secondary
        };
        let end = self.messages.len().saturating_sub(self.scroll);
        let start = end.saturating_sub(60);
        let lines: Vec<Line> = self.messages[start..end]
            .iter()
            .flat_map(|message| {
                let stamp = format_timestamp(message.timestamp);
                let color = if message.sender.ends_with("(you)") {
                    theme.primary
                } else if message.sender == "system" {
                    theme.warning
                } else {
                    theme.success
                };
                vec![
                    Line::from(Span::styled(
                        format!("[{stamp}] {}", message.sender),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(format!("  {}", message.content)),
                ]
            })
            .collect();

        let chat = Paragraph::new(if lines.is_empty() {
            vec![
                Line::from(Span::styled(
                    "No messages yet.",
                    Style::default().fg(theme.secondary),
                )),
                Line::from(""),
                Line::from("Start the network, then type below. Everything is"),
                Line::from("encrypted with AES-256-GCM using your shared key."),
            ]
        } else {
            lines
        })
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border))
                .title(format!(" Secure LAN Chat · {} ", self.peer_label())),
        );
        f.render_widget(chat, rows[0]);

        let prompt = if self.passphrase_needed {
            " Passphrase (hidden) "
        } else {
            " Message (Enter sends to all peers) "
        };
        let display = if self.passphrase_needed {
            "•".repeat(self.input.chars().count())
        } else {
            self.input.clone()
        };
        let input = Paragraph::new(Line::from(vec![
            Span::styled("› ", Style::default().fg(theme.accent)),
            Span::raw(display),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border))
                .title(prompt),
        );
        f.render_widget(input, rows[1]);
        if focused {
            f.set_cursor_position((
                rows[1].x + 3 + self.input.chars().count() as u16,
                rows[1].y + 1,
            ));
        }

        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                self.status.as_str(),
                Style::default().fg(theme.secondary),
            )))
            .wrap(Wrap { trim: true }),
            rows[2],
        );

        let items: Vec<ListItem> = if self.peers.is_empty() {
            vec![ListItem::new(Span::styled(
                "waiting for peers…",
                Style::default().fg(theme.secondary),
            ))]
        } else {
            self.peers
                .iter()
                .map(|peer| {
                    ListItem::new(vec![
                        Line::from(Span::styled(
                            peer.name.clone(),
                            Style::default().fg(theme.success),
                        )),
                        Line::from(Span::styled(
                            peer.addr.to_string(),
                            Style::default().fg(theme.secondary),
                        )),
                    ])
                })
                .collect()
        };
        let peers = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.secondary))
                .title(" Peers "),
        );
        f.render_widget(peers, columns[1]);
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn format_timestamp(seconds: u64) -> String {
    // Render HH:MM in UTC without pulling in a date library.
    let minutes = (seconds / 60) % (24 * 60);
    format!("{:02}:{:02}", minutes / 60, minutes % 60)
}

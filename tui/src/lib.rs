use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Tabs, Wrap},
    Terminal,
};
use std::io::stdout;
use std::time::Duration;

pub async fn start_tui() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut tab = 0usize;
    let tabs = ["Ops", "Tools", "Agents", "Docs"];

    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints(
                    [
                        Constraint::Length(3),
                        Constraint::Min(0),
                        Constraint::Length(3),
                    ]
                    .as_ref(),
                )
                .split(f.area());

            let header = Paragraph::new(vec![
                Line::from(vec![
                    Span::styled(
                        "ZENTRION",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" Terminal Platform"),
                    Span::styled(
                        "  local-first secure runtime",
                        Style::default().fg(Color::DarkGray),
                    ),
                ]),
                Line::from(
                    "Brokered tools, AI agents, policy, audit and native scans in one shell.",
                ),
            ])
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Command Center"),
            );
            f.render_widget(header, chunks[0]);

            let body = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(
                    [
                        Constraint::Length(28),
                        Constraint::Min(40),
                        Constraint::Length(34),
                    ]
                    .as_ref(),
                )
                .split(chunks[1]);

            render_nav(f, body[0], tab);
            render_main(f, body[1], tab);
            render_status(f, body[2]);

            let footer = Paragraph::new(Line::from(vec![
                Span::styled(
                    "q",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" quit  "),
                Span::styled(
                    "Tab",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" next view  "),
                Span::styled(
                    "1-4",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" switch"),
            ]))
            .block(Block::default().borders(Borders::ALL));
            f.render_widget(footer, chunks[2]);
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Tab => tab = (tab + 1) % tabs.len(),
                    KeyCode::BackTab => tab = (tab + tabs.len() - 1) % tabs.len(),
                    KeyCode::Char('1') => tab = 0,
                    KeyCode::Char('2') => tab = 1,
                    KeyCode::Char('3') => tab = 2,
                    KeyCode::Char('4') => tab = 3,
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn render_nav(f: &mut ratatui::Frame, area: Rect, tab: usize) {
    let titles = ["Ops", "Tools", "Agents", "Docs"]
        .iter()
        .map(|t| Line::from(Span::raw(*t)))
        .collect::<Vec<_>>();
    let nav_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
        .split(area);
    let tabs = Tabs::new(titles)
        .select(tab)
        .style(Style::default().fg(Color::Gray))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL).title("Views"));
    f.render_widget(tabs, nav_chunks[0]);

    let items = [
        ListItem::new("doctor: offline host check"),
        ListItem::new("status: project + policy"),
        ListItem::new("bundle: curated tool packs"),
        ListItem::new("scan: native assessment"),
        ListItem::new("ai: analysis foundation"),
        ListItem::new("audit: immutable event chain"),
    ];
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Workflow"))
        .style(Style::default().fg(Color::White));
    f.render_widget(list, nav_chunks[1]);
}

fn render_main(f: &mut ratatui::Frame, area: Rect, tab: usize) {
    match tab {
        0 => render_ops(f, area),
        1 => render_tools(f, area),
        2 => render_agents(f, area),
        _ => render_docs(f, area),
    }
}

fn render_status(f: &mut ratatui::Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(7),
                Constraint::Length(7),
                Constraint::Min(6),
            ]
            .as_ref(),
        )
        .split(area);
    let posture = Paragraph::new(vec![
        Line::from("Mode: local-first"),
        Line::from("Registry: bundled"),
        Line::from("Tools: 36 curated"),
        Line::from("Approvals: explicit"),
    ])
    .block(Block::default().borders(Borders::ALL).title("Platform"));
    f.render_widget(posture, chunks[0]);

    let agents = Paragraph::new(vec![
        Line::from("Planner: ready"),
        Line::from("Reviewer: guardrails"),
        Line::from("Operator: brokered"),
        Line::from("Trace: enabled"),
    ])
    .block(Block::default().borders(Borders::ALL).title("Agents"));
    f.render_widget(agents, chunks[1]);

    let commands = List::new([
        ListItem::new("z bundle list"),
        ListItem::new("z bundle plan recon"),
        ListItem::new("z search devsecops"),
        ListItem::new("z doctor"),
        ListItem::new("z status"),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Next Commands"),
    );
    f.render_widget(commands, chunks[2]);
}

fn render_ops(f: &mut ratatui::Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(6),
                Constraint::Length(5),
                Constraint::Min(6),
            ]
            .as_ref(),
        )
        .split(area);
    let health = Paragraph::new(vec![
        Line::from("Runtime: local-only    Broker: enabled    Network: explicit"),
        Line::from("Policy: active         Secrets: hidden     Audit: chain verified"),
        Line::from("Suggested next: z doctor, z status, z bundle list"),
    ])
    .block(Block::default().borders(Borders::ALL).title("Operations"));
    f.render_widget(health, chunks[0]);
    f.render_widget(
        Gauge::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Security Posture"),
            )
            .gauge_style(Style::default().fg(Color::Green))
            .percent(82),
        chunks[1],
    );
    let activity = List::new([
        ListItem::new("tool.install previews require checksum and trust review"),
        ListItem::new("raw program execution routes through identity, policy and broker"),
        ListItem::new("doctor remains offline by design"),
        ListItem::new("bundle plans print reviewable install commands"),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Recent Signals"),
    );
    f.render_widget(activity, chunks[2]);
}

fn render_tools(f: &mut ratatui::Frame, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(area);
    let bundles = List::new([
        ListItem::new("kali-top10: core security tools"),
        ListItem::new("web: proxy, crawler, fuzzer, scanner"),
        ListItem::new("recon: DNS, network, attack surface"),
        ListItem::new("devsecops: SAST, secrets, SBOM"),
        ListItem::new("reverse: binary and firmware analysis"),
        ListItem::new("forensics: memory and incident triage"),
    ])
    .block(Block::default().borders(Borders::ALL).title("Bundles"));
    f.render_widget(bundles, columns[0]);
    let tools = Paragraph::new("36 curated registry entries\n\nSearch:\n  z search scanner\n  z search --category cybersecurity web\n\nPlan:\n  z bundle plan web\n  z bundle plan security-lab\n\nInstall after review:\n  z install nmap --approve")
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title("Tool Commands"));
    f.render_widget(tools, columns[1]);
}

fn render_agents(f: &mut ratatui::Frame, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Min(8)].as_ref())
        .split(area);
    let summary = Paragraph::new(vec![
        Line::from("Profiles: planner, operator, security-reviewer, documenter"),
        Line::from("Controls: max iterations, tool allowlist, approval gates"),
        Line::from("Trace: plan -> handoff -> tool call -> observation -> final"),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Agent Runtime"),
    );
    f.render_widget(summary, rows[0]);
    let guardrails = List::new([
        ListItem::new("Input guardrail: classify intent and required permissions"),
        ListItem::new("Tool guardrail: deny destructive or unapproved host effects"),
        ListItem::new("Output guardrail: require evidence and next-action clarity"),
        ListItem::new("Handoff: specialist agents inherit trace context"),
    ])
    .block(Block::default().borders(Borders::ALL).title("Guardrails"));
    f.render_widget(guardrails, rows[1]);
}

fn render_docs(f: &mut ratatui::Frame, area: Rect) {
    let docs = Paragraph::new("docs/tools/README.md\n  Tool lifecycle, bundles and registry commands\n\ndocs/agents.md\n  Agent profiles, handoffs, guardrails and traces\n\ndocs/terminal.md\n  Shell-first platform and TUI overview\n\ndocs/SECURITY_MODEL.md\n  Broker, policy, audit and local-first guarantees")
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title("Documentation Map"));
    f.render_widget(docs, area);
}

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use sysinfo::System;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Tabs, Wrap},
    Terminal,
};

#[derive(Clone, Copy)]
pub struct Theme {
    pub primary: Color,
    pub secondary: Color,
    pub accent: Color,
    pub background: Color,
    pub error: Color,
}

impl Theme {
    pub fn default() -> Self {
        Self {
            primary: Color::Cyan,
            secondary: Color::DarkGray,
            accent: Color::Yellow,
            background: Color::Reset,
            error: Color::Red,
        }
    }

    pub fn cyberpunk() -> Self {
        Self {
            primary: Color::Magenta,
            secondary: Color::Cyan,
            accent: Color::Yellow,
            background: Color::Black,
            error: Color::Red,
        }
    }
    
    pub fn dracula() -> Self {
        Self {
            primary: Color::Rgb(189, 147, 249),
            secondary: Color::Rgb(98, 114, 164),
            accent: Color::Rgb(255, 121, 198),
            background: Color::Rgb(40, 42, 54),
            error: Color::Rgb(255, 85, 85),
        }
    }
}
use std::io::stdout;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UserProficiency {
    Beginner,
    Professional,
    Expert,
}

pub async fn start_tui() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut tab = 0usize;
    let mut proficiency = UserProficiency::Professional;
    let tabs = [
        "Home",
        "Workflows",
        "Tools",
        "Agents",
        "AI",
        "Security",
        "Storage",
        "Docs",
        "Research",
        "LAN Chat",
    ];

    let mut show_palette = false;
    let mut show_copilot = false;
    let mut show_sysmon = false;
    let mut show_editor = false;
    let mut editor_content = String::from("fn main() {\n    println!(\"Hello Zentrion!\");\n}\n");
    let mut palette_input = String::new();
    let mut sys = System::new_all();
    
    // For now, load default theme. In the future this comes from config.
    let theme = Theme::default();

    loop {
        sys.refresh_all();
        terminal.draw(|f| {
            // Base layer: split between main app and AI Copilot sidebar if active
            let base_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(if show_copilot {
                    vec![Constraint::Percentage(70), Constraint::Percentage(30)]
                } else {
                    vec![Constraint::Percentage(100)]
                })
                .split(f.area());

            let app_area = base_chunks[0];

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
                .split(app_area);

            let header = Paragraph::new(vec![
                Line::from(vec![
                    Span::styled(
                        "ZENTRION",
                        Style::default()
                            .fg(theme.primary)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" Terminal Platform"),
                    Span::styled(
                        "  local-first secure runtime",
                        Style::default().fg(theme.secondary),
                    ),
                ]),
                Line::from(
                    "Brokered tools, AI agents, policy, audit and native scans in one shell.",
                ),
            ])
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Command Center")
                    .style(Style::default().bg(theme.background)),
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
            
            // Multiplexing inside the main view: if Expert, show split panes (simulated)
            if show_sysmon {
                render_sysmon(f, body[1], &sys);
            } else if show_editor {
                render_editor(f, body[1], &editor_content, theme);
            } else if proficiency == UserProficiency::Expert && tab == 0 {
                let main_splits = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(body[1]);
                render_main(f, main_splits[0], tab, proficiency);
                
                let lower_splits = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(main_splits[1]);
                
                let process_pane = Paragraph::new("top - 20:30:45 up 5 days\nTasks: 130 total\n%Cpu(s): 2.5 us").block(Block::default().borders(Borders::ALL).title("Pane 2 (Process)"));
                let tail_pane = Paragraph::new("tail -f /var/log/syslog\nSystem healthy.").block(Block::default().borders(Borders::ALL).title("Pane 3 (Logs)"));
                f.render_widget(process_pane, lower_splits[0]);
                f.render_widget(tail_pane, lower_splits[1]);
            } else {
                render_main(f, body[1], tab, proficiency);
            }

            render_status(f, body[2], proficiency);

            let footer = Paragraph::new(Line::from(vec![
                Span::styled("Ctrl+Q", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
                Span::raw(" quit  "),
                Span::styled("Alt+S", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
                Span::raw(" sysmon  "),
                Span::styled("Alt+C", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
                Span::raw(" copilot  "),
                Span::styled("Alt+E", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
                Span::raw(" editor  "),
                Span::styled("Ctrl+P", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
                Span::raw(" palette  "),
                Span::styled("Tab", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
                Span::raw(" next  "),
            ]))
            .block(Block::default().borders(Borders::ALL).style(Style::default().bg(theme.background)));
            f.render_widget(footer, chunks[2]);

            // Render AI Copilot Sidebar if active
            if show_copilot {
                let copilot_area = base_chunks[1];
                let copilot = Paragraph::new(vec![
                    Line::from(Span::styled("Zentrion Copilot", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD))),
                    Line::from(""),
                    Line::from("> Analyzing current layout..."),
                    Line::from("> How can I assist you with your terminal workflows today?"),
                    Line::from(""),
                    Line::from(Span::styled("Try asking:", Style::default().fg(Color::DarkGray))),
                    Line::from("  - 'How do I secure my project?'"),
                    Line::from("  - 'Explain this nmap error'"),
                ])
                .block(Block::default().borders(Borders::ALL).title("AI Copilot (Warp Style)"));
                f.render_widget(copilot, copilot_area);
            }

            // Render Command Palette overlay if active
            if show_palette {
                let palette_area = ratatui::layout::Rect::new(
                    app_area.width / 4,
                    app_area.height / 3,
                    app_area.width / 2,
                    10,
                );
                
                let palette_text = format!("> {}\n\nSuggested:\n  z do secure my project\n  z bundle plan kali-top10\n  z ai analyze", palette_input);
                
                let palette = Paragraph::new(palette_text)
                    .block(Block::default().borders(Borders::ALL).title("Command Palette (Type to search)").style(Style::default().bg(Color::Black)));
                
                f.render_widget(ratatui::widgets::Clear, palette_area); // clear background
                f.render_widget(palette, palette_area);
            }
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if show_palette {
                    match key.code {
                        KeyCode::Esc => show_palette = false,
                        KeyCode::Enter => {
                            show_palette = false;
                            palette_input.clear();
                        }
                        KeyCode::Backspace => {
                            palette_input.pop();
                        }
                        KeyCode::Char(c) if !key.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) => {
                            palette_input.push(c);
                        }
                        _ => {}
                    }
                    if key.modifiers.is_empty() {
                        continue;
                    }
                }

                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') => break,
                        KeyCode::Char('p') | KeyCode::Char('P') => show_palette = !show_palette,
                        _ => {}
                    }
                } else if key.modifiers.contains(KeyModifiers::ALT) {
                    match key.code {
                        KeyCode::Char('s') | KeyCode::Char('S') => show_sysmon = !show_sysmon,
                        KeyCode::Char('c') | KeyCode::Char('C') => show_copilot = !show_copilot,
                        KeyCode::Char('p') | KeyCode::Char('P') => show_palette = !show_palette,
                        KeyCode::Char('e') | KeyCode::Char('E') => show_editor = !show_editor,
                        _ => {}
                    }
                } else if show_editor {
                    match key.code {
                        KeyCode::Char(c) => editor_content.push(c),
                        KeyCode::Enter => editor_content.push('\n'),
                        KeyCode::Backspace => { editor_content.pop(); }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('p') => {
                            proficiency = match proficiency {
                                UserProficiency::Beginner => UserProficiency::Professional,
                                UserProficiency::Professional => UserProficiency::Expert,
                                UserProficiency::Expert => UserProficiency::Beginner,
                            };
                        }
                        KeyCode::Tab => tab = (tab + 1) % tabs.len(),
                        KeyCode::BackTab => tab = (tab + tabs.len() - 1) % tabs.len(),
                        KeyCode::Char('1') => tab = 0,
                        KeyCode::Char('2') => tab = 1,
                        KeyCode::Char('3') => tab = 2,
                        KeyCode::Char('4') => tab = 3,
                        KeyCode::Char('5') => tab = 4,
                        KeyCode::Char('6') => tab = 5,
                        KeyCode::Char('7') => tab = 6,
                        KeyCode::Char('8') => tab = 7,
                        KeyCode::Char('9') => tab = 8,
                        KeyCode::Char('0') => tab = 9,
                        _ => {}
                    }
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
    let titles = [
        "Home",
        "Workflows",
        "Tools",
        "Agents",
        "AI",
        "Security",
        "Storage",
        "Docs",
        "Research",
        "LAN Chat",
    ]
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
        ListItem::new("1 Home: health + next steps"),
        ListItem::new("2 Workflows: daily roles"),
        ListItem::new("3 Tools: bundles + registry"),
        ListItem::new("4 Agents: safe automation"),
        ListItem::new("5 AI: local/API models"),
        ListItem::new("6 Security: scans + audit"),
        ListItem::new("7 Storage: durable data"),
        ListItem::new("8 Docs: learning map"),
        ListItem::new("9 Research: deep agentic scraping"),
        ListItem::new("0 LAN Chat: P2P secure comms"),
    ];
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Workflow"))
        .style(Style::default().fg(Color::White));
    f.render_widget(list, nav_chunks[1]);
}

fn render_main(f: &mut ratatui::Frame, area: Rect, tab: usize, _proficiency: UserProficiency) {
    match tab {
        0 => render_home(f, area),
        1 => render_workflows(f, area),
        2 => render_tools(f, area),
        3 => render_agents(f, area),
        4 => render_ai(f, area),
        5 => render_security(f, area),
        6 => render_storage(f, area),
        7 => render_docs(f, area),
        8 => render_research(f, area),
        _ => render_chat(f, area),
    }
}

fn render_status(f: &mut ratatui::Frame, area: Rect, proficiency: UserProficiency) {
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
        Line::from(format!("Mode: local-first | Proficiency: {:?}", proficiency)),
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

    let cmd_list = match proficiency {
        UserProficiency::Beginner => vec![
            ListItem::new("z bundle plan web"),
            ListItem::new("z docs workflows"),
            ListItem::new("z do secure my project"),
        ],
        UserProficiency::Professional => vec![
            ListItem::new("z bundle list"),
            ListItem::new("z profile list"),
            ListItem::new("z bundle plan recon"),
            ListItem::new("z search devsecops"),
            ListItem::new("z doctor"),
        ],
        UserProficiency::Expert => vec![
            ListItem::new("z policy validate"),
            ListItem::new("z scan ."),
            ListItem::new("z finding list"),
            ListItem::new("z report latest"),
            ListItem::new("z audit verify"),
            ListItem::new("z storage show"),
        ],
    };

    let commands = List::new(cmd_list)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Next Commands"),
    );
    f.render_widget(commands, chunks[2]);
}

fn render_home(f: &mut ratatui::Frame, area: Rect) {
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
        Line::from("Suggested next: z setup, z profile list, z bundle list"),
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
        ListItem::new("storage survives upgrade and normal uninstall"),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Recent Signals"),
    );
    f.render_widget(activity, chunks[2]);
}

fn render_workflows(f: &mut ratatui::Frame, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(area);
    let personas = List::new([
        ListItem::new("developer: git, build, test, run"),
        ListItem::new("ai-developer: local/API models + agents"),
        ListItem::new("cybersecurity: scope, scan, evidence"),
        ListItem::new("devsecops: SAST, secrets, SBOM"),
        ListItem::new("cloud: IaC and config review"),
        ListItem::new("student: guided safe commands"),
        ListItem::new("everything: full command-center mode"),
    ])
    .block(Block::default().borders(Borders::ALL).title("Profiles"));
    f.render_widget(personas, columns[0]);

    let commands = Paragraph::new("Start:\n  z profile list\n  z profile show developer\n  z profile apply ai-developer\n\nDaily:\n  z commands <query>\n  z docs <topic>\n  z project --check\n  z scan .\n\nReusable workflow idea:\n  z bundle plan devsecops\n  z ai privacy\n  z audit tail")
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title("Command Palette"));
    f.render_widget(commands, columns[1]);
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

fn render_ai(f: &mut ratatui::Frame, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(area);
    let providers = List::new([
        ListItem::new("ollama: local-first default"),
        ListItem::new("qwen: DashScope-compatible API"),
        ListItem::new("openai: OpenAI API"),
        ListItem::new("openai-compatible: LM Studio, llama.cpp, routers"),
    ])
    .block(Block::default().borders(Borders::ALL).title("Providers"));
    f.render_widget(providers, columns[0]);

    let setup = Paragraph::new("Local Qwen:\n  ollama pull qwen2.5-coder:7b\n  ZENTRION_AI_PROVIDER=ollama\n  ZENTRION_AI_MODEL=qwen2.5-coder:7b\n\nAPI Qwen:\n  ZENTRION_AI_PROVIDER=qwen\n  DASHSCOPE_API_KEY=...\n\nCustom endpoint:\n  ZENTRION_AI_PROVIDER=openai-compatible\n  ZENTRION_AI_BASE_URL=http://127.0.0.1:8080/v1")
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title("Setup"));
    f.render_widget(setup, columns[1]);
}

fn render_security(f: &mut ratatui::Frame, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(8)].as_ref())
        .split(area);
    let posture = Paragraph::new(vec![
        Line::from("Identity -> policy -> capability -> approval -> broker -> audit"),
        Line::from("Tool installs: checksum, trust gate, transactional store"),
        Line::from("AI actions: guardrails and allowlists before host effects"),
        Line::from("Storage: persistent audit and evidence by default"),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Security Model"),
    );
    f.render_widget(posture, rows[0]);

    let commands = List::new([
        ListItem::new("z policy validate"),
        ListItem::new("z scan ."),
        ListItem::new("z finding list"),
        ListItem::new("z report latest"),
        ListItem::new("z audit verify"),
        ListItem::new("z ai privacy"),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Security Commands"),
    );
    f.render_widget(commands, rows[1]);
}

fn render_storage(f: &mut ratatui::Frame, area: Rect) {
    let text = Paragraph::new("Durable by default:\n  config\n  audit\n  installed tools\n  sessions/history\n  agent and project memory\n  scan reports\n\nCommands:\n  z setup\n  z storage show\n  z storage doctor\n  z storage policy\n\nRetention:\n  survives upgrades\n  survives binary deletion\n  normal uninstall preserves user data\n  cache is disposable")
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title("Local Storage"));
    f.render_widget(text, area);
}

fn render_docs(f: &mut ratatui::Frame, area: Rect) {
    let docs = Paragraph::new("docs/getting-started.md\n  First 10 minutes\n\ndocs/terminal.md\n  Shell-first platform and TUI overview\n\ndocs/workflows.md\n  Persona profiles and workflow commands\n\ndocs/tools/README.md\n  Tool lifecycle, bundles and registry commands\n\ndocs/agents.md\n  Agent profiles, handoffs, guardrails and traces\n\ndocs/STORAGE.md\n  Durable local storage\n\ndocs/SECURITY_MODEL.md\n  Broker, policy, audit and local-first guarantees")
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title("Documentation Map"));
    f.render_widget(docs, area);
}

fn render_sysmon(f: &mut ratatui::Frame, area: Rect, sys: &System) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(10)].as_ref())
        .split(area);

    let total_mem = sys.total_memory() as f64 / 1_048_576.0;
    let used_mem = sys.used_memory() as f64 / 1_048_576.0;
    let mem_pct = if total_mem > 0.0 { (used_mem / total_mem) * 100.0 } else { 0.0 };
    
    let cpu_usage = sys.global_cpu_info().cpu_usage();

    let gauges = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(chunks[0]);

    let cpu_gauge = Gauge::default()
        .block(Block::default().title("CPU Usage").borders(Borders::ALL))
        .gauge_style(Style::default().fg(if cpu_usage > 80.0 { Color::Red } else { Color::Green }))
        .percent(cpu_usage as u16);
    f.render_widget(cpu_gauge, gauges[0]);

    let mem_gauge = Gauge::default()
        .block(Block::default().title(format!("Memory ({:.1}MB / {:.1}MB)", used_mem, total_mem)).borders(Borders::ALL))
        .gauge_style(Style::default().fg(if mem_pct > 80.0 { Color::Red } else { Color::Cyan }))
        .percent(mem_pct as u16);
    f.render_widget(mem_gauge, gauges[1]);

    let mut procs: Vec<_> = sys.processes().values().collect();
    procs.sort_by(|a, b| b.cpu_usage().partial_cmp(&a.cpu_usage()).unwrap_or(std::cmp::Ordering::Equal));
    
    let mut items = vec![ListItem::new(Span::styled(format!("{:<8} | {:<25} | {:<10} | {:<10}", "PID", "NAME", "CPU %", "MEM (MB)"), Style::default().add_modifier(Modifier::BOLD)))];
    
    for p in procs.iter().take(20) {
        let mem_mb = p.memory() as f64 / 1_048_576.0;
        let line = format!("{:<8} | {:<25} | {:<10.1} | {:<10.1}", p.pid(), p.name(), p.cpu_usage(), mem_mb);
        items.push(ListItem::new(line));
    }
    
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Top Processes (Alt+S to close)"));
    f.render_widget(list, chunks[1]);
}

fn render_research(f: &mut ratatui::Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(10)].as_ref())
        .split(area);
        
    let input = Paragraph::new("> Search query: How does Landlock compare to Seccomp-BPF?\n\n[ Enter to Start Deep Research ]")
        .block(Block::default().borders(Borders::ALL).title("Agentic Deep Research"));
    f.render_widget(input, chunks[0]);
    
    let logs = List::new([
        ListItem::new("[10:00:01] Starting Deep Research Agent..."),
        ListItem::new("[10:00:02] Querying search engines for 'Landlock vs Seccomp-BPF'"),
        ListItem::new("[10:00:05] Scraping 5 target URLs..."),
        ListItem::new("[10:00:08] Synthesizing differences..."),
        ListItem::new("[10:00:10] Generating markdown report (draft saved to ~/.zentrion/research/)"),
    ]).block(Block::default().borders(Borders::ALL).title("Agent Activity"));
    f.render_widget(logs, chunks[1]);
}

fn render_chat(f: &mut ratatui::Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)].as_ref())
        .split(area);
        
    let msg_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(3)].as_ref())
        .split(chunks[0]);
        
    let chat = List::new([
        ListItem::new("ZENTRION_SYS: Listening on 0.0.0.0:7777 for UDP Broadcasts..."),
        ListItem::new("ZENTRION_SYS: TCP Secure server bound to port 8080."),
        ListItem::new("Alice [192.168.1.45]: Hey team, has anyone reviewed the new security policy?"),
        ListItem::new("Bob [192.168.1.50]: Looking at it now. The explicit approval flag looks good."),
    ]).block(Block::default().borders(Borders::ALL).title("Secure P2P LAN Chat (AES-256-GCM)"));
    f.render_widget(chat, msg_chunks[0]);
    
    let input = Paragraph::new("> Send message to all peers...")
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(input, msg_chunks[1]);
    
    let peers = List::new([
        ListItem::new(Span::styled("Alice (192.168.1.45)", Style::default().fg(Color::Green))),
        ListItem::new(Span::styled("Bob (192.168.1.50)", Style::default().fg(Color::Green))),
        ListItem::new(Span::styled("Charlie (offline)", Style::default().fg(Color::DarkGray))),
    ]).block(Block::default().borders(Borders::ALL).title("Discovered Peers"));
    f.render_widget(peers, chunks[1]);
}

fn render_editor(f: &mut ratatui::Frame, area: Rect, content: &str, theme: Theme) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(1)].as_ref())
        .split(area);
        
    let editor = Paragraph::new(content)
        .block(Block::default().borders(Borders::ALL).title("Mini IDE (Alt+E to close)").style(Style::default().bg(theme.background).fg(theme.primary)));
    f.render_widget(editor, chunks[0]);
    
    // Simulate AI overlay
    let ai_status = Paragraph::new(Span::styled(" AI Auto-Complete Ready (Press Tab to accept)", Style::default().fg(theme.accent)))
        .block(Block::default().style(Style::default().bg(theme.background)));
    f.render_widget(ai_status, chunks[1]);
}


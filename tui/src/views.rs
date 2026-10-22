//! Dashboard views and the live system monitor.

use crate::theme::Theme;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Tabs, Wrap},
    Frame,
};
use std::path::PathBuf;
use sysinfo::System;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proficiency {
    Beginner,
    Professional,
    Expert,
}

pub const DASHBOARD_VIEWS: [&str; 10] = [
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

pub struct DashboardInfo<'a> {
    pub shell: &'a str,
    pub cwd: &'a str,
    pub theme: &'a str,
    pub sessions: usize,
    pub platform: &'a str,
    pub data_dir: PathBuf,
    pub config_dir: PathBuf,
    pub proficiency: Proficiency,
}

pub fn render_dashboard(
    f: &mut Frame,
    area: Rect,
    view: usize,
    info: &DashboardInfo,
    theme: &Theme,
) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(30),
            Constraint::Min(30),
            Constraint::Length(34),
        ])
        .split(area);

    render_nav(f, columns[0], view, theme, info);
    match view {
        0 => render_home(f, columns[1], info, theme),
        1 => render_workflows(f, columns[1], theme),
        2 => render_tools(f, columns[1], theme),
        3 => render_agents(f, columns[1], info, theme),
        4 => render_ai(f, columns[1], theme),
        5 => render_security(f, columns[1], theme),
        6 => render_storage(f, columns[1], info, theme),
        7 => render_docs(f, columns[1], theme),
        8 => render_research(f, columns[1], theme),
        _ => render_chat_help(f, columns[1], theme),
    }
    render_commands(f, columns[2], view, info, theme);
}

fn render_nav(f: &mut Frame, area: Rect, view: usize, theme: &Theme, info: &DashboardInfo) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);
    let titles: Vec<Line> = DASHBOARD_VIEWS
        .iter()
        .map(|title| Line::from(Span::raw(*title)))
        .collect();
    let tabs = Tabs::new(titles)
        .select(view.min(DASHBOARD_VIEWS.len() - 1))
        .style(Style::default().fg(theme.secondary))
        .highlight_style(
            Style::default()
                .fg(theme.primary)
                .add_modifier(Modifier::BOLD),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.secondary))
                .title(" Views "),
        );
    f.render_widget(tabs, chunks[0]);

    let items: Vec<ListItem> = DASHBOARD_VIEWS
        .iter()
        .enumerate()
        .map(|(index, name)| {
            let key = if index == 9 {
                "0".to_string()
            } else {
                (index + 1).to_string()
            };
            let style = if index == view {
                Style::default().fg(theme.primary)
            } else {
                Style::default().fg(theme.text)
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{key} "), Style::default().fg(theme.accent)),
                Span::styled(*name, style),
            ]))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" Dashboard "),
    );
    f.render_widget(list, chunks[1]);

    let _ = info;
}

fn render_home(f: &mut Frame, area: Rect, info: &DashboardInfo, theme: &Theme) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),
            Constraint::Length(5),
            Constraint::Min(6),
        ])
        .split(area);

    let health = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Shell: ", Style::default().fg(theme.secondary)),
            Span::raw(info.shell),
            Span::raw("   "),
            Span::styled("Panes: ", Style::default().fg(theme.secondary)),
            Span::raw(info.sessions.to_string()),
        ]),
        Line::from(vec![
            Span::styled("CWD: ", Style::default().fg(theme.secondary)),
            Span::raw(info.cwd),
        ]),
        Line::from(vec![
            Span::styled("Theme: ", Style::default().fg(theme.secondary)),
            Span::raw(info.theme),
            Span::raw("   "),
            Span::styled("Platform: ", Style::default().fg(theme.secondary)),
            Span::raw(info.platform),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "This is a real terminal: every pane is a live PTY running your shell.",
            Style::default().fg(theme.success),
        )),
    ])
    .wrap(Wrap { trim: true })
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" Runtime "),
    );
    f.render_widget(health, chunks[0]);

    f.render_widget(
        Gauge::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(theme.secondary))
                    .title(" Local-first posture "),
            )
            .gauge_style(Style::default().fg(theme.success))
            .percent(100)
            .label("no telemetry · policy broker · offline by default"),
        chunks[1],
    );

    let commands = Paragraph::new(vec![
        Line::from(Span::styled(
            "Start typing in the terminal — that is the product.",
            Style::default().fg(theme.text),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("F7", Style::default().fg(theme.accent)),
            Span::raw("  new tab     "),
            Span::styled("F8", Style::default().fg(theme.accent)),
            Span::raw("  split     "),
            Span::styled("F9", Style::default().fg(theme.accent)),
            Span::raw("  close"),
        ]),
        Line::from(vec![
            Span::styled("F2", Style::default().fg(theme.accent)),
            Span::raw("  palette     "),
            Span::styled("F3", Style::default().fg(theme.accent)),
            Span::raw("  editor     "),
            Span::styled("F4", Style::default().fg(theme.accent)),
            Span::raw("  copilot"),
        ]),
        Line::from(vec![
            Span::styled("F5", Style::default().fg(theme.accent)),
            Span::raw("  monitor     "),
            Span::styled("F6", Style::default().fg(theme.accent)),
            Span::raw("  LAN chat"),
        ]),
        Line::from(vec![
            Span::styled("Alt+V", Style::default().fg(theme.accent)),
            Span::raw("  terminal/dashboard     "),
            Span::styled("F10", Style::default().fg(theme.accent)),
            Span::raw("  quit"),
        ]),
    ])
    .wrap(Wrap { trim: true })
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" Keys "),
    );
    f.render_widget(commands, chunks[2]);
}

fn render_workflows(f: &mut Frame, area: Rect, theme: &Theme) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
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
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" Profiles "),
    );
    f.render_widget(personas, columns[0]);

    let commands = Paragraph::new(
        "z profile list\n\
         z profile show developer\n\
         z profile apply ai-developer\n\n\
         z code status\n\
         z code test\n\
         z network dns example.com\n\
         z security scan .\n\
         z do secure my project",
    )
    .wrap(Wrap { trim: true })
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" Commands "),
    );
    f.render_widget(commands, columns[1]);
}

fn render_tools(f: &mut Frame, area: Rect, theme: &Theme) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    let bundles = List::new([
        ListItem::new("kali-top10: core security tools"),
        ListItem::new("web: proxy, crawler, fuzzer, scanner"),
        ListItem::new("recon: DNS, network, attack surface"),
        ListItem::new("devsecops: SAST, secrets, SBOM"),
        ListItem::new("reverse: binary and firmware analysis"),
        ListItem::new("forensics: memory and incident triage"),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" Bundles "),
    );
    f.render_widget(bundles, columns[0]);
    let tools = Paragraph::new(
        "Search:\n  z search scanner\n  z search --category cybersecurity web\n\n\
         Plan:\n  z bundle list\n  z bundle show web\n  z bundle plan web\n\n\
         Install after review:\n  z install nmap\n  z install nmap --approve\n\n\
         Installed:\n  z list --installed\n  z which nmap",
    )
    .wrap(Wrap { trim: true })
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" Tool Commands "),
    );
    f.render_widget(tools, columns[1]);
}

fn render_agents(f: &mut Frame, area: Rect, info: &DashboardInfo, theme: &Theme) {
    let supervisor = z_agents::Supervisor::new(&info.data_dir, Vec::new());
    let mut runs = supervisor.list();
    let is_live = !runs.is_empty();
    if runs.is_empty() {
        runs = supervisor.history();
    }
    let pending_approvals = {
        let broker_path = info.data_dir.join("agents").join("approvals.json");
        if broker_path.exists() {
            std::fs::read_to_string(&broker_path)
                .ok()
                .and_then(|t| serde_json::from_str::<Vec<z_agents::ApprovalRequest>>(&t).ok())
                .map(|v: Vec<z_agents::ApprovalRequest>| {
                    v.into_iter()
                        .filter(|r| matches!(r.status, z_agents::ApprovalStatus::Pending))
                        .count()
                })
                .unwrap_or(0)
        } else {
            0
        }
    };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(10),
            Constraint::Length(5),
        ])
        .split(area);

    let status_line = if is_live {
        format!("Live: {} active daemon run(s)", runs.len())
    } else if !runs.is_empty() {
        format!("Idle ({} historical run(s) recorded)", runs.len())
    } else {
        "Idle — no agent runs recorded yet".to_string()
    };

    let header_lines = vec![
        Line::from(vec![
            Span::styled("Agent Supervisor: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(
                status_line,
                Style::default().fg(if is_live { theme.success } else { theme.secondary }),
            ),
            Span::raw(" · "),
            Span::styled(
                format!("{pending_approvals} pending approvals"),
                if pending_approvals > 0 {
                    Style::default().fg(theme.warning).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme.secondary)
                },
            ),
            Span::raw(" (Alt+A to review)"),
        ]),
        Line::from(vec![
            Span::styled("Policy Guardrails: ", Style::default().fg(theme.primary)),
            Span::raw("deny-by-default · single-use tokens · Ed25519 audit chain · sandbox check"),
        ]),
        Line::from(vec![
            Span::styled("Adapters: ", Style::default().fg(theme.secondary)),
            Span::raw("claude-code, codex, gemini, opencode, aider · Built-in: planner, operator, security-reviewer, documenter"),
        ]),
    ];

    let header = Paragraph::new(header_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" Agent Runtime & Supervisor "),
    );
    f.render_widget(header, rows[0]);

    if runs.is_empty() {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rows[1]);

        let guardrails = List::new([
            ListItem::new("Input guardrail: classify intent and required permissions"),
            ListItem::new("Tool guardrail: deny destructive or unapproved host effects"),
            ListItem::new("Approval broker: single-use cryptographic tokens"),
            ListItem::new("Output guardrail: require evidence and next-action clarity"),
            ListItem::new("Rollback: content-addressed checkpoints before edits"),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.secondary))
                .title(" Active Guardrails "),
        );
        f.render_widget(guardrails, columns[0]);

        let instructions = Paragraph::new(
            "Start an agent:\n  z agent run <adapter> --prompt \"...\"\n\n\
             List available adapters:\n  z agent adapters\n\n\
             Review pending approvals:\n  Alt+A (or `z agent approvals`)\n\n\
             View agent traces:\n  z agent trace <run-id>\n\n\
             Profiles:\n  planner · operator · security-reviewer · documenter",
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.secondary))
                .title(" Quick Actions "),
        );
        f.render_widget(instructions, columns[1]);
    } else {
        let mut list_items = Vec::new();
        list_items.push(ListItem::new(Line::from(vec![Span::styled(
            format!(
                "{:<24} {:<12} {:<14} {:<10} {:>10}  WORKSPACE",
                "RUN ID", "AGENT", "STATE", "PROFILE", "ELAPSED"
            ),
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(theme.secondary),
        )])));

        for run in &runs {
            let state_style = match run.state.as_str() {
                "running" => Style::default().fg(theme.success),
                "waiting_input" => Style::default()
                    .fg(theme.warning)
                    .add_modifier(Modifier::BOLD),
                "completed" => Style::default().fg(theme.primary),
                "failed" => Style::default().fg(theme.error),
                _ => Style::default().fg(theme.secondary),
            };

            let approx_str = if run.approximate { " [approx]" } else { "" };
            let line = Line::from(vec![
                Span::styled(format!("{:<24} ", run.id), Style::default().fg(theme.text)),
                Span::styled(
                    format!("{:<12} ", run.adapter_id),
                    Style::default().fg(theme.primary),
                ),
                Span::styled(format!("{:<14} ", run.state.as_str()), state_style),
                Span::styled(
                    format!("{:<10} ", run.profile),
                    Style::default().fg(theme.secondary),
                ),
                Span::styled(
                    format!("{:>8}ms  ", run.elapsed_ms()),
                    Style::default().fg(theme.text),
                ),
                Span::styled(
                    format!("{}{}", run.workspace, approx_str),
                    Style::default().fg(theme.secondary),
                ),
            ]);
            list_items.push(ListItem::new(line));
        }

        let run_list = List::new(list_items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if is_live {
                    theme.primary
                } else {
                    theme.secondary
                }))
                .title(if is_live {
                    " Live Agent Runs "
                } else {
                    " Recent Agent Runs "
                }),
        );
        f.render_widget(run_list, rows[1]);
    }

    let footer = Paragraph::new(vec![
        Line::from("z agent run <adapter> --prompt \"...\"  ·  Alt+A: Approvals inbox  ·  F11: Search blocks"),
        Line::from("Every agent tool call is audited to ~/.local/share/zentrion/audit/events.jsonl"),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" Host Effect Governance "),
    );
    f.render_widget(footer, rows[2]);
}

fn render_ai(f: &mut Frame, area: Rect, theme: &Theme) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    let providers = List::new([
        ListItem::new("ollama: local-first default"),
        ListItem::new("openai: OpenAI API"),
        ListItem::new("qwen: DashScope-compatible API"),
        ListItem::new("openai-compatible: LM Studio, llama.cpp, routers"),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" Providers "),
    );
    f.render_widget(providers, columns[0]);

    let setup = Paragraph::new(
        "Local Qwen:\n  ollama pull qwen2.5-coder:7b\n  export ZENTRION_AI_PROVIDER=ollama\n  export ZENTRION_AI_MODEL=qwen2.5-coder:7b\n\n\
         OpenAI:\n  export ZENTRION_AI_PROVIDER=openai\n  export OPENAI_API_KEY=...\n\n\
         Custom endpoint:\n  export ZENTRION_AI_PROVIDER=openai-compatible\n  export ZENTRION_AI_BASE_URL=http://127.0.0.1:8080/v1\n\n\
         Secrets are redacted by the AI gateway before outbound calls.",
    )
    .wrap(Wrap { trim: true })
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" Setup "),
    );
    f.render_widget(setup, columns[1]);
}

fn render_security(f: &mut Frame, area: Rect, theme: &Theme) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(8)])
        .split(area);
    let posture = Paragraph::new(vec![
        Line::from("Identity -> policy -> capability -> approval -> broker -> audit"),
        Line::from("Tool installs: checksum, trust gate, transactional store"),
        Line::from("AI actions: guardrails and allowlists before host effects"),
        Line::from("Scans and findings are stored locally under the data directory."),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" Security Model "),
    );
    f.render_widget(posture, rows[0]);

    let commands = List::new([
        ListItem::new("z security posture"),
        ListItem::new("z security scan ."),
        ListItem::new("z security findings"),
        ListItem::new("z security report"),
        ListItem::new("z audit verify"),
        ListItem::new("z policy validate"),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" Security Commands "),
    );
    f.render_widget(commands, rows[1]);
}

fn render_storage(f: &mut Frame, area: Rect, info: &DashboardInfo, theme: &Theme) {
    let text = Paragraph::new(vec![
        Line::from(Span::styled("Config", Style::default().fg(theme.accent))),
        Line::from(format!("  {}", info.config_dir.display())),
        Line::from(Span::styled("Data", Style::default().fg(theme.accent))),
        Line::from(format!("  {}", info.data_dir.display())),
        Line::from(""),
        Line::from("Durable by default: config, audit, tools, sessions,"),
        Line::from("history, agent memory and scan reports."),
        Line::from(""),
        Line::from("z storage show"),
        Line::from("z storage doctor"),
        Line::from("z storage init"),
        Line::from(""),
        Line::from("Normal uninstall preserves user data. Cache is disposable."),
    ])
    .wrap(Wrap { trim: true })
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" Local Storage "),
    );
    f.render_widget(text, area);
}

fn render_docs(f: &mut Frame, area: Rect, theme: &Theme) {
    let docs = Paragraph::new(
        "docs/getting-started.md\n  First 10 minutes\n\n\
         docs/terminal.md\n  Shell-first platform and TUI overview\n\n\
         docs/workflows.md\n  Persona profiles and workflow commands\n\n\
         docs/tools/README.md\n  Tool lifecycle, bundles and registry commands\n\n\
         docs/agents.md\n  Agent profiles, handoffs, guardrails and traces\n\n\
         docs/STORAGE.md\n  Durable local storage\n\n\
         docs/SECURITY_MODEL.md\n  Broker, policy, audit and local-first guarantees\n\n\
         Use `z docs <topic>` in any pane to search the bundled docs.",
    )
    .wrap(Wrap { trim: true })
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" Documentation Map "),
    );
    f.render_widget(docs, area);
}

fn render_research(f: &mut Frame, area: Rect, theme: &Theme) {
    let text = Paragraph::new(
        "AI research writes a markdown report from the configured model.\n\
         Web crawling is not enabled, so reports are model-synthesized and\n\
         should be verified before use.\n\n\
         Press Alt+V to return to the terminal, then use:\n\
           z ai research \"your question\"\n\n\
         Or open the Research dashboard tab and press Enter to run a query.\n\n\
         Reports are stored under the Zentrion data directory (research/).",
    )
    .wrap(Wrap { trim: true })
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" Research "),
    );
    f.render_widget(text, area);
}

fn render_chat_help(f: &mut Frame, area: Rect, theme: &Theme) {
    let text = Paragraph::new(
        "Secure P2P LAN chat is available in this dashboard tab.\n\n\
         - AES-256-GCM with a shared passphrase\n\
         - UDP broadcast discovery on port 7777\n\
         - Direct TCP messages on port 7778\n\
         - No server, no account, no telemetry\n\n\
         Open this tab and type a passphrase to start. Share it out of band\n\
         with peers on the same network. All peers must use the same value.\n\n\
         Prefer environment configuration:\n\
           export ZENTRION_P2P_KEY='long shared passphrase'\n\
           z ui\n\n\
         Treat the passphrase like a group password: anyone who knows it can\n\
         read and send messages on that LAN.",
    )
    .wrap(Wrap { trim: true })
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" LAN Chat "),
    );
    f.render_widget(text, area);
}

fn render_commands(f: &mut Frame, area: Rect, view: usize, info: &DashboardInfo, theme: &Theme) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(9), Constraint::Min(4)])
        .split(area);

    let posture = Paragraph::new(vec![
        Line::from(format!("Shell  {}", info.shell)),
        Line::from(format!("Panes  {}", info.sessions)),
        Line::from(format!("Theme  {}", info.theme)),
        Line::from("Policy active"),
        Line::from("Audit local"),
        Line::from("Telemetry off"),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" Platform "),
    );
    f.render_widget(posture, chunks[0]);

    let commands: Vec<ListItem> = match info.proficiency {
        Proficiency::Beginner => vec![
            ListItem::new("z doctor"),
            ListItem::new("z bundle list"),
            ListItem::new("z docs"),
        ],
        Proficiency::Professional => vec![
            ListItem::new("z status"),
            ListItem::new("z bundle plan recon"),
            ListItem::new("z scan ."),
            ListItem::new("z search scanner"),
            ListItem::new("z doctor"),
        ],
        Proficiency::Expert => vec![
            ListItem::new("z policy validate"),
            ListItem::new("z security scan ."),
            ListItem::new("z audit verify"),
            ListItem::new("z report latest"),
            ListItem::new("z sbom"),
            ListItem::new("z agent run"),
        ],
    };
    let _ = view;
    let list = List::new(commands).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" Suggested "),
    );
    f.render_widget(list, chunks[1]);
}

pub fn render_sysmon(f: &mut Frame, area: Rect, sys: &System, theme: &Theme) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(6)])
        .split(area);

    let total_mem = sys.total_memory() as f64 / 1_048_576.0;
    let used_mem = sys.used_memory() as f64 / 1_048_576.0;
    let mem_pct = if total_mem > 0.0 {
        (used_mem / total_mem) * 100.0
    } else {
        0.0
    };
    let cpu_usage = sys.global_cpu_info().cpu_usage();

    let gauges = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[0]);

    f.render_widget(
        Gauge::default()
            .block(
                Block::default()
                    .title(" CPU ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(theme.secondary)),
            )
            .gauge_style(Style::default().fg(if cpu_usage > 80.0 {
                theme.error
            } else {
                theme.success
            }))
            .percent(cpu_usage.min(100.0) as u16),
        gauges[0],
    );
    f.render_widget(
        Gauge::default()
            .block(
                Block::default()
                    .title(format!(" Memory · {used_mem:.0} / {total_mem:.0} MB "))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(theme.secondary)),
            )
            .gauge_style(Style::default().fg(if mem_pct > 80.0 {
                theme.error
            } else {
                theme.primary
            }))
            .percent(mem_pct.min(100.0) as u16),
        gauges[1],
    );

    let mut processes: Vec<_> = sys.processes().values().collect();
    processes.sort_by(|a, b| {
        b.cpu_usage()
            .partial_cmp(&a.cpu_usage())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut items = vec![ListItem::new(Span::styled(
        format!(
            "{:<8} {:<28} {:>7} {:>10}",
            "PID", "NAME", "CPU %", "MEM (MB)"
        ),
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD),
    ))];
    for process in processes.iter().take(40) {
        let memory = process.memory() as f64 / 1_048_576.0;
        items.push(ListItem::new(format!(
            "{:<8} {:<28} {:>7.1} {:>10.1}",
            process.pid(),
            process.name(),
            process.cpu_usage(),
            memory
        )));
    }
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.secondary))
            .title(" Top Processes · Esc closes "),
    );
    f.render_widget(list, chunks[1]);
}

#[allow(dead_code)]
fn color_for(theme: &Theme) -> Color {
    theme.primary
}

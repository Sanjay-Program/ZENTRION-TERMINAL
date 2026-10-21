//! `z session` and `z workspace`.

use super::*;
use crossterm::event::{poll, read, Event, KeyCode, KeyEvent, KeyModifiers};
use serde_json::json;
use std::io::{IsTerminal, Write};
use std::time::Duration;
use z_session::{plan_restore, PaneAction, SessionClient, Workspace, WorkspaceStore};

pub fn session(args: &[String], json_out: bool) -> ZenResult<()> {
    let parsed = Parsed::parse(
        args,
        &[
            "--socket",
            "--shell",
            "--cwd",
            "--rows",
            "--cols",
            "--title",
            "--since",
            "--signal",
            "--data",
            "--profile",
        ],
    );
    match parsed.command("status") {
        "daemon" => {
            let config = load_config()?.config;
            let data = data_dir()?;
            let socket = parsed
                .value("--socket")
                .map(PathBuf::from)
                .unwrap_or_else(z_session::socket_path);
            let manager =
                z_session::SessionManager::new(z_session::ManagerOptions::new(&data, config))
                    .map_err(|e| map_err("cannot create session manager", e))?;
            if !json_out {
                println!("Zentrion session daemon");
                println!("  socket: {}", socket.display());
                println!("  data:   {}", data.display());
                println!("  press Ctrl+C to stop");
            }
            z_session::daemon::run(manager, socket).map_err(|e| map_err("session daemon failed", e))
        }
        "socket" => {
            let socket = parsed
                .value("--socket")
                .map(PathBuf::from)
                .unwrap_or_else(z_session::socket_path);
            if json_out {
                print_json(&json!({"socket": socket.display().to_string()}))
            } else {
                println!("{}", socket.display());
                Ok(())
            }
        }
        "list" => {
            let client = z_session::connect_or_spawn()
                .map_err(|e| map_err("cannot reach session daemon", e))?;
            let sessions = client.list().map_err(|e| map_err("cannot list sessions", e))?;
            if json_out {
                print_json(&json!({"sessions": sessions}))
            } else if sessions.is_empty() {
                println!("No sessions.");
                Ok(())
            } else {
                println!(
                    "{:<24} {:<10} {:<8} {:<20} CWD",
                    "ID", "STATUS", "PID", "SHELL"
                );
                for session in sessions {
                    println!(
                        "{:<24} {:<10} {:<8} {:<20} {}",
                        session.id,
                        session.status,
                        session
                            .pid
                            .map(|pid: u32| pid.to_string())
                            .unwrap_or_else(|| "-".into()),
                        session.shell,
                        session.cwd
                    );
                }
                Ok(())
            }
        }
        "status" => {
            let client = z_session::connect_or_spawn()
                .map_err(|e| map_err("cannot reach session daemon", e))?;
            let status = client.status().map_err(|e| map_err("cannot query daemon", e))?;
            if json_out {
                print_json(&status)
            } else {
                println!("Zentrion session daemon");
                println!("  socket:  {}", status["socket"].as_str().unwrap_or("-"));
                println!("  version: {}", status["version"].as_str().unwrap_or("-"));
                println!("  sessions: {}", status["sessions"]);
                println!(
                    "  uptime:  {}s",
                    status["uptime_seconds"].as_u64().unwrap_or(0)
                );
                if let Some(error) = status["blocks_error"].as_str() {
                    println!("  blocks:  ERROR {error}");
                }
                Ok(())
            }
        }
        "create" => {
            let mut params = json!({});
            if let Some(value) = parsed.value("--shell") {
                params["shell"] = json!(value);
            }
            if let Some(value) = parsed.value("--cwd") {
                params["cwd"] = json!(value);
            }
            if let Some(value) = parsed.value("--rows") {
                params["rows"] = json!(value.parse::<u16>().unwrap_or(40));
            }
            if let Some(value) = parsed.value("--cols") {
                params["cols"] = json!(value.parse::<u16>().unwrap_or(120));
            }
            if let Some(value) = parsed.value("--title") {
                params["title"] = json!(value);
            }
            if let Some(value) = parsed.value("--profile") {
                params["profile"] = json!(value);
            }
            let client = z_session::connect_or_spawn()
                .map_err(|e| map_err("cannot reach session daemon", e))?;
            let info = client
                .create(params)
                .map_err(|e| map_err("cannot create session", e))?;
            if json_out {
                print_json(&serde_json::to_value(&info).unwrap_or(json!({})))
            } else {
                println!("{}", info.id);
                eprintln!(
                    "session {} started ({}, {}x{})",
                    info.id, info.shell, info.cols, info.rows
                );
                Ok(())
            }
        }
        "attach" => attach(parsed.rest(), parsed.value("--since").and_then(|v| v.parse().ok()), json_out),
        "replay" => replay(parsed.rest(), json_out, parsed.flag("--plain")),
        "blocks" => {
            let id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z session blocks <session-id>"))?;
            let client = SessionClient::connect_default().map_err(|e| map_err("cannot connect", e))?;
            let value = client
                .call("session.blocks", json!({"session_id": id}))
                .map_err(|e| map_err("cannot read session blocks", e))?;
            if json_out {
                print_json(&value)
            } else {
                let blocks = value["blocks"].as_array().cloned().unwrap_or_default();
                if blocks.is_empty() {
                    println!("No blocks recorded for {id}.");
                }
                for block in blocks {
                    println!(
                        "{}  {}  {}",
                        block["id"].as_str().unwrap_or("-"),
                        block["status"].as_str().unwrap_or("-"),
                        block["command"].as_str().unwrap_or("")
                    );
                }
                Ok(())
            }
        }
        "input" => {
            let id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z session input <id> <text>"))?;
            let data = if let Some(data) = parsed.value("--data") {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .map_err(|e| map_err("invalid --data base64", e))?
            } else {
                let mut text = parsed.rest()[1..].join(" ");
                if parsed.flag("--enter") || !text.ends_with('\n') {
                    text.push('\n');
                }
                text.into_bytes()
            };
            let client = z_session::connect_or_spawn()
                .map_err(|e| map_err("cannot reach session daemon", e))?;
            client
                .input(id, &data)
                .map_err(|e| map_err("cannot send input", e))?;
            Ok(())
        }
        "resize" => {
            let rest = parsed.rest();
            let id = rest
                .first()
                .ok_or_else(|| fail("usage: z session resize <id> <rows> <cols>"))?;
            let rows = rest
                .get(1)
                .and_then(|v| v.parse::<u16>().ok())
                .ok_or_else(|| fail("invalid rows"))?;
            let cols = rest
                .get(2)
                .and_then(|v| v.parse::<u16>().ok())
                .ok_or_else(|| fail("invalid cols"))?;
            let client = z_session::connect_or_spawn()
                .map_err(|e| map_err("cannot reach session daemon", e))?;
            client
                .resize(id, rows, cols)
                .map_err(|e| map_err("cannot resize", e))
        }
        "signal" => {
            let rest = parsed.rest();
            let id = rest
                .first()
                .ok_or_else(|| fail("usage: z session signal <id> <signal>"))?;
            let signal = parsed
                .value("--signal")
                .or_else(|| rest.get(1).map(String::as_str))
                .ok_or_else(|| fail("missing signal"))?;
            let client = z_session::connect_or_spawn()
                .map_err(|e| map_err("cannot reach session daemon", e))?;
            client
                .signal(id, signal)
                .map_err(|e| map_err("cannot signal session", e))?;
            if !json_out {
                println!("sent {signal} to {id}");
            }
            Ok(())
        }
        "close" | "kill" => {
            let id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z session close <id> [--force]"))?;
            let client = z_session::connect_or_spawn()
                .map_err(|e| map_err("cannot reach session daemon", e))?;
            client
                .close(id, parsed.flag("--force") || parsed.flag("--kill"))
                .map_err(|e| map_err("cannot close session", e))?;
            if !json_out {
                println!("closed {id}");
            }
            Ok(())
        }
        "stop" | "shutdown" => {
            let client = SessionClient::connect_default().map_err(|e| map_err("no daemon running", e))?;
            client
                .shutdown_daemon()
                .map_err(|e| map_err("cannot stop daemon", e))?;
            if !json_out {
                println!("session daemon shutting down");
            }
            Ok(())
        }
        other => Err(fail(format!(
            "unknown session subcommand `{other}` (list|create|attach|replay|blocks|input|resize|signal|close|status|stop|daemon)"
        ))),
    }
}

fn attach(rest: &[String], since: Option<u64>, json_out: bool) -> ZenResult<()> {
    let id = rest
        .first()
        .ok_or_else(|| fail("usage: z session attach <id> [--since N]"))?;
    let client =
        z_session::connect_or_spawn().map_err(|e| map_err("cannot reach session daemon", e))?;
    attach_to(&client, id, since.unwrap_or(0), json_out)
}

pub(crate) fn attach_to(
    client: &z_session::SessionClient,
    id: &str,
    since: u64,
    json_out: bool,
) -> ZenResult<()> {
    let (attach, mut events) = client
        .attach(id, since)
        .map_err(|e| map_err("cannot attach", e))?;
    if json_out {
        return print_json(&attach.snapshot);
    }
    let mut stdout = std::io::stdout();
    write!(
        stdout,
        "\x1b[2J\x1b[H{}",
        attach.snapshot["keyframe"].as_str().unwrap_or("")
    )
    .map_err(|e| map_err("cannot render screen", e))?;
    stdout.flush().map_err(|e| map_err("cannot flush", e))?;
    if !std::io::stdin().is_terminal() {
        // Non-interactive: show the snapshot and return without stealing stdin.
        eprintln!(
            "attached snapshot {}x{} seq {} (non-interactive; use `z session replay` for scripts)",
            attach.info.cols, attach.info.rows, attach.seq
        );
        return Ok(());
    }
    let _raw = RawMode::enable()?;
    loop {
        while let Ok(event) = events.try_recv() {
            match event {
                z_session::ClientEvent::Output(frame) => {
                    stdout
                        .write_all(&frame.data)
                        .map_err(|e| map_err("cannot write output", e))?;
                    stdout.flush().ok();
                }
                z_session::ClientEvent::Notification { method, params } => {
                    if method == "session.exited" {
                        eprintln!("\r\n[session exited: {}]", params["code"]);
                        let _ = crossterm::terminal::disable_raw_mode();
                        return Ok(());
                    }
                    if method == "client.lagged" {
                        eprintln!("\r\n[client lagged, skipped {} frames]", params["skipped"]);
                    }
                }
            }
        }
        if poll(Duration::from_millis(20)).map_err(|e| map_err("input poll failed", e))? {
            match read().map_err(|e| map_err("input read failed", e))? {
                Event::Key(key) if key.kind != crossterm::event::KeyEventKind::Release => {
                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        && matches!(key.code, KeyCode::Char(']'))
                    {
                        break;
                    }
                    let bytes = key_bytes(&key);
                    if !bytes.is_empty() {
                        client
                            .input(id, &bytes)
                            .map_err(|e| map_err("cannot send input", e))?;
                    }
                }
                Event::Resize(cols, rows) => {
                    let _ = client.resize(id, rows, cols);
                }
                Event::Paste(text) => {
                    let _ = client.input(id, text.as_bytes());
                }
                _ => {}
            }
        }
    }
    eprintln!("\r\n[detached from {id}; the process keeps running]");
    Ok(())
}

fn replay(rest: &[String], json_out: bool, plain: bool) -> ZenResult<()> {
    let id = rest
        .first()
        .ok_or_else(|| fail("usage: z session replay <id>"))?;
    let client =
        z_session::connect_or_spawn().map_err(|e| map_err("cannot reach session daemon", e))?;
    let (attach, _events) = client
        .attach(id, 0)
        .map_err(|e| map_err("cannot attach", e))?;
    if json_out {
        print_json(&attach.snapshot)
    } else if plain {
        // Screen-reader / script friendly: no ANSI, just the visible screen.
        println!("{}", attach.snapshot["contents"].as_str().unwrap_or(""));
        Ok(())
    } else {
        let mut stdout = std::io::stdout();
        write!(
            stdout,
            "\x1b[2J\x1b[H{}",
            attach.snapshot["keyframe"].as_str().unwrap_or("")
        )
        .map_err(|e| map_err("cannot render screen", e))?;
        println!("\n--- session {} seq {} ---", attach.info.id, attach.seq);
        if let Some(blocks) = attach.snapshot["blocks"].as_array() {
            for block in blocks {
                println!(
                    "{}  {}  {}",
                    block["id"].as_str().unwrap_or("-"),
                    block["status"].as_str().unwrap_or("-"),
                    block["command"].as_str().unwrap_or("")
                );
            }
        }
        Ok(())
    }
}

pub(crate) struct RawMode;

impl RawMode {
    pub(crate) fn enable() -> ZenResult<Self> {
        crossterm::terminal::enable_raw_mode().map_err(|e| map_err("cannot enable raw mode", e))?;
        Ok(Self)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

pub(crate) fn key_bytes(key: &KeyEvent) -> Vec<u8> {
    use KeyCode::*;
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    let mut bytes = match key.code {
        Char(c) => {
            if ctrl {
                let lower = c.to_ascii_lowercase();
                if lower.is_ascii_alphabetic() {
                    vec![(lower as u8) - b'a' + 1]
                } else {
                    match c {
                        '[' => vec![0x1b],
                        '\\' => vec![0x1c],
                        ']' => vec![0x1d],
                        '^' => vec![0x1e],
                        '_' => vec![0x1f],
                        '@' => vec![0x00],
                        _ => c.to_string().into_bytes(),
                    }
                }
            } else {
                c.to_string().into_bytes()
            }
        }
        Enter => vec![b'\r'],
        Tab => vec![b'\t'],
        Backspace => vec![0x7f],
        Esc => vec![0x1b],
        Up => b"\x1b[A".to_vec(),
        Down => b"\x1b[B".to_vec(),
        Right => b"\x1b[C".to_vec(),
        Left => b"\x1b[D".to_vec(),
        Home => b"\x1b[H".to_vec(),
        End => b"\x1b[F".to_vec(),
        PageUp => b"\x1b[5~".to_vec(),
        PageDown => b"\x1b[6~".to_vec(),
        Insert => b"\x1b[2~".to_vec(),
        Delete => b"\x1b[3~".to_vec(),
        F(n) => match n {
            1 => b"\x1bOP".to_vec(),
            2 => b"\x1bOQ".to_vec(),
            3 => b"\x1bOR".to_vec(),
            4 => b"\x1bOS".to_vec(),
            5 => b"\x1b[15~".to_vec(),
            6 => b"\x1b[17~".to_vec(),
            7 => b"\x1b[18~".to_vec(),
            8 => b"\x1b[19~".to_vec(),
            9 => b"\x1b[20~".to_vec(),
            10 => b"\x1b[21~".to_vec(),
            11 => b"\x1b[23~".to_vec(),
            12 => b"\x1b[24~".to_vec(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    };
    if alt && !bytes.is_empty() {
        bytes.insert(0, 0x1b);
    }
    bytes
}

fn workspace_store() -> ZenResult<WorkspaceStore> {
    let dir = WorkspaceStore::default_dir()
        .ok_or_else(|| fail("cannot determine workspace directory"))?;
    Ok(WorkspaceStore::new(dir))
}

fn load_workspace(store: &WorkspaceStore, name_or_path: &str) -> ZenResult<Workspace> {
    let path = std::path::Path::new(name_or_path);
    if path.is_file() {
        store
            .load_path(path)
            .map_err(|e| map_err("cannot load workspace", e))
    } else {
        store
            .load(name_or_path)
            .map_err(|e| map_err("cannot load workspace", e))
    }
}

pub fn workspace(args: &[String], json_out: bool) -> ZenResult<()> {
    let parsed = Parsed::parse(args, &["--restore", "--name"]);
    let store = workspace_store()?;
    match parsed.command("list") {
        "list" => {
            let workspaces = store
                .list()
                .map_err(|e| map_err("cannot list workspaces", e))?;
            if json_out {
                print_json(&json!({"workspaces": workspaces}))
            } else if workspaces.is_empty() {
                println!("No saved workspaces in {}.", store.dir().display());
                Ok(())
            } else {
                println!("{:<20} {:>6} {:>6}  PATH", "NAME", "TABS", "PANES");
                for workspace in workspaces {
                    println!(
                        "{:<20} {:>6} {:>6}  {}",
                        workspace.name, workspace.tabs, workspace.panes, workspace.path
                    );
                }
                Ok(())
            }
        }
        "show" => {
            let name = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z workspace show <name|file>"))?;
            let workspace = load_workspace(&store, name)?;
            if json_out {
                print_json(&serde_json::to_value(&workspace).unwrap_or(json!({})))
            } else {
                println!("{}", serde_yaml::to_string(&workspace).unwrap_or_default());
                Ok(())
            }
        }
        "save" => {
            let file = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z workspace save <file.yaml>"))?;
            let workspace = load_workspace(&store, file)?;
            let path = store
                .save(&workspace)
                .map_err(|e| map_err("cannot save workspace", e))?;
            if !json_out {
                println!("saved {} to {}", workspace.name, path.display());
            }
            Ok(())
        }
        "delete" => {
            let name = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z workspace delete <name>"))?;
            store
                .delete(name)
                .map_err(|e| map_err("cannot delete workspace", e))?;
            if !json_out {
                println!("deleted {name}");
            }
            Ok(())
        }
        "restore" => restore_workspace(&store, parsed.rest(), &parsed, json_out),
        other => Err(fail(format!(
            "unknown workspace subcommand `{other}` (list|show|save|delete|restore)"
        ))),
    }
}

fn restore_workspace(
    store: &WorkspaceStore,
    rest: &[String],
    parsed: &Parsed,
    json_out: bool,
) -> ZenResult<()> {
    let name = rest
        .first()
        .ok_or_else(|| fail("usage: z workspace restore <name> [--dry-run] [--approve]"))?;
    let mut workspace = load_workspace(store, name)?;
    if let Some(policy) = parsed.value("--restore") {
        workspace.restore = serde_yaml::from_str(&format!("\"{policy}\""))
            .map_err(|_| fail(format!("unknown restore policy `{policy}`")))?;
    }
    let config = load_config()?.config;
    let policy = config.session.restore;
    let plan = plan_restore(&workspace, policy, parsed.flag("--approve"));
    if parsed.flag("--dry-run") || json_out {
        let value = json!({
            "workspace": workspace.name,
            "restore": policy,
            "actions": plan.actions.iter().map(|action| json!({
                "tab": action.tab,
                "pane": action.pane_index,
                "action": format!("{:?}", action.action),
                "requires_approval": action.requires_approval,
                "reason": action.reason,
            })).collect::<Vec<_>>(),
            "pending_approval": plan.pending_approval.len(),
            "warnings": plan.warnings,
            "dry_run": parsed.flag("--dry-run"),
        });
        if json_out {
            return print_json(&value);
        }
        println!("Workspace: {} (restore: {:?})", workspace.name, policy);
        for action in &plan.actions {
            println!(
                "  [{}:{}] {} (approval: {})",
                action.tab,
                action.pane_index,
                action.reason.as_deref().unwrap_or("restore"),
                action.requires_approval
            );
        }
        for pending in &plan.pending_approval {
            println!(
                "  PENDING [{}:{}] {:?} — {}",
                pending.tab,
                pending.pane_index,
                pending.action,
                pending.reason.as_deref().unwrap_or("needs approval")
            );
        }
        for warning in &plan.warnings {
            println!("  warning: {warning}");
        }
        return Ok(());
    }
    let client =
        z_session::connect_or_spawn().map_err(|e| map_err("cannot reach session daemon", e))?;
    let mut spawned = Vec::new();
    let mut agent_skipped = Vec::new();
    for action in &plan.actions {
        match &action.action {
            PaneAction::Shell { cwd } => {
                let info = client
                    .create(json!({
                        "cwd": cwd,
                        "rows": 40,
                        "cols": 120,
                        "title": format!("{}:{}", action.tab, action.pane_index),
                    }))
                    .map_err(|e| map_err("cannot create pane session", e))?;
                spawned.push(json!({
                    "session_id": info.id,
                    "tab": action.tab,
                    "pane": action.pane_index,
                    "action": "shell",
                    "cwd": info.cwd,
                }));
            }
            PaneAction::Command { command, cwd } => {
                let info = client
                    .create(json!({
                        "cwd": cwd,
                        "rows": 40,
                        "cols": 120,
                        "title": format!("{}:{}", action.tab, action.pane_index),
                    }))
                    .map_err(|e| map_err("cannot create pane session", e))?;
                client
                    .input(&info.id, format!("{command}\r").as_bytes())
                    .map_err(|e| map_err("cannot start command", e))?;
                spawned.push(json!({
                    "session_id": info.id,
                    "tab": action.tab,
                    "pane": action.pane_index,
                    "action": "command",
                    "command": command,
                }));
            }
            PaneAction::Agent { agent, .. } => {
                agent_skipped.push(json!({
                    "tab": action.tab,
                    "pane": action.pane_index,
                    "agent": agent,
                    "hint": format!("start with `z agent run {agent}`"),
                }));
            }
        }
    }
    for warning in &plan.warnings {
        eprintln!("warning: {warning}");
    }
    if !json_out {
        println!(
            "Restored {} pane(s) from {}.",
            spawned.len(),
            workspace.name
        );
        for pane in &spawned {
            println!(
                "  {}:{} → {} ({})",
                pane["tab"].as_str().unwrap_or(""),
                pane["pane"],
                pane["session_id"].as_str().unwrap_or(""),
                pane["action"].as_str().unwrap_or("")
            );
        }
        for skipped in &agent_skipped {
            println!(
                "  {}:{} agent `{}` not auto-started; {}",
                skipped["tab"].as_str().unwrap_or(""),
                skipped["pane"],
                skipped["agent"].as_str().unwrap_or(""),
                skipped["hint"].as_str().unwrap_or("")
            );
        }
    }
    write_audit(
        "user",
        "user",
        "workspace.restore",
        &workspace.name,
        "allow",
        "ok",
        "low",
    )?;
    Ok(())
}

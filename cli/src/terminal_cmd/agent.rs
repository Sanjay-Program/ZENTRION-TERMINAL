//! `z agent` and `z mcp serve`.

use super::*;
use serde_json::json;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;
use z_agents::{
    AgentProfile, ApprovalBroker, LaunchOptions, McpServer, McpServerOptions, Supervisor,
};

fn load_adapters() -> Vec<z_agents::Adapter> {
    let mut dirs = z_agents::default_dirs();
    if let Ok(loaded) = load_config() {
        for dir in &loaded.config.agents.adapter_dirs {
            dirs.push(PathBuf::from(dir));
        }
    }
    z_agents::discover(&dirs)
}

fn broker(
    agent_id: &str,
    profile_name: &str,
    workspace: &std::path::Path,
) -> ZenResult<ApprovalBroker> {
    let profile = AgentProfile::builtin(profile_name)
        .ok_or_else(|| fail(format!("unknown agent profile `{profile_name}`")))?;
    let data = data_dir()?;
    let store_path = data.join("agents").join("approvals.json");
    let audit = data.join("audit").join("events.jsonl");
    ApprovalBroker::new(
        agent_id,
        profile,
        z_policy::Policy::default(),
        workspace,
        &store_path,
        &audit,
    )
    .map_err(|e| map_err("cannot create approval broker", e))
}

fn default_workspace(parsed: &Parsed) -> ZenResult<PathBuf> {
    Ok(parsed
        .value("--workspace")
        .or_else(|| parsed.value("--cwd"))
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))))
}

pub fn agent(args: &[String], json_out: bool) -> ZenResult<()> {
    let parsed = Parsed::parse(
        args,
        &[
            "--profile",
            "--model",
            "--cwd",
            "--workspace",
            "--prompt",
            "--timeout",
            "--agent",
            "--approval-timeout",
            "--tool-timeout",
            "--name",
        ],
    );
    let adapters = load_adapters();
    let data = data_dir()?;
    match parsed.command("list") {
        "adapters" => {
            if json_out {
                return print_json(&json!({"adapters": adapters}));
            }
            println!(
                "{:<16} {:<18} {:<10} {:<28} {}",
                "ID", "NAME", "DETECTED", "EVENT MODE", "PROFILE"
            );
            for adapter in &adapters {
                println!(
                    "{:<16} {:<18} {:<10} {:<28} {}",
                    adapter.id,
                    adapter.name,
                    if adapter.detected() { "yes" } else { "no" },
                    adapter.events.mode,
                    adapter.permissions.default_profile
                );
            }
            Ok(())
        }
        "validate-adapter" => {
            let file = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z agent validate-adapter <file.yaml>"))?;
            let adapter = z_agents::load_adapter(std::path::Path::new(file))
                .map_err(|e| map_err("invalid adapter", e))?;
            let issues = adapter.validate();
            if json_out {
                print_json(&json!({"adapter": adapter, "valid": issues.is_empty(), "issues": issues}))
            } else if issues.is_empty() {
                println!("valid: {} ({})", adapter.id, adapter.name);
                Ok(())
            } else {
                for issue in &issues {
                    println!("- {issue}");
                }
                Err(fail("adapter is invalid"))
            }
        }
        "profiles" | "policies" => {
            let profiles: Vec<serde_json::Value> = AgentProfile::builtin_names()
                .iter()
                .filter_map(|name| AgentProfile::builtin(name))
                .map(|profile| profile.to_json())
                .collect();
            if json_out {
                print_json(&json!({"profiles": profiles}))
            } else {
                for profile in profiles {
                    println!(
                        "{} — {}",
                        profile["name"].as_str().unwrap_or(""),
                        profile["description"].as_str().unwrap_or("")
                    );
                    println!(
                        "  write: {:?}  exec: {:?}",
                        profile["write"], profile["exec"]
                    );
                }
                Ok(())
            }
        }
        "list" | "dashboard" | "status" => {
            let supervisor = Supervisor::new(&data, adapters);
            let mut runs = supervisor.list();
            if runs.is_empty() {
                runs = supervisor.history();
            }
            if json_out {
                return print_json(&json!({"runs": runs, "dashboard": supervisor.dashboard()}));
            }
            if runs.is_empty() {
                println!("No agent runs yet. Start one with `z agent run <adapter> --prompt ...`.");
                return Ok(());
            }
            println!(
                "{:<26} {:<14} {:<18} {:<10} {:>9}  {}",
                "RUN", "AGENT", "STATE", "PROFILE", "ELAPSED", "WORKSPACE"
            );
            for run in runs {
                println!(
                    "{:<26} {:<14} {:<18} {:<10} {:>8}ms  {}{}",
                    run.id,
                    run.adapter_id,
                    run.state.as_str(),
                    run.profile,
                    run.elapsed_ms(),
                    run.workspace,
                    if run.approximate { "  [approx]" } else { "" }
                );
            }
            Ok(())
        }
        "run" => {
            let adapter_id = parsed
                .value("--agent")
                .or_else(|| parsed.rest().first().map(String::as_str))
                .ok_or_else(|| fail("usage: z agent run <adapter> [--prompt <text>] [--profile <name>]"))?;
            let adapter = adapters
                .iter()
                .find(|adapter| adapter.id == adapter_id)
                .cloned()
                .ok_or_else(|| {
                    fail(format!(
                        "agent adapter `{adapter_id}` not found; see `z agent adapters`"
                    ))
                })?;
            if !adapter.detected() {
                eprintln!(
                    "warning: `{}` was not detected on PATH; launch may fail",
                    adapter.command
                );
            }
            let profile = parsed
                .value("--profile")
                .map(str::to_string)
                .unwrap_or_else(|| adapter.permissions.default_profile.clone());
            AgentProfile::builtin(&profile)
                .ok_or_else(|| fail(format!("unknown agent profile `{profile}`")))?;
            let workspace = parsed
                .value("--cwd")
                .map(PathBuf::from)
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let supervisor = Supervisor::new(&data, adapters.clone());
            let handle = supervisor
                .launch(LaunchOptions {
                    adapter: adapter.clone(),
                    prompt: parsed.value("--prompt").map(str::to_string),
                    model: parsed.value("--model").map(str::to_string),
                    cwd: workspace,
                    profile,
                    env: Vec::new(),
                    command_override: None,
                })
                .map_err(|e| map_err("cannot launch agent", e))?;
            let info = handle.info();
            let _ = write_audit(
                "user",
                "user",
                "agent.launch",
                &format!("agent:{}", info.adapter_id),
                "allow",
                "ok",
                "high",
            );
            if !json_out {
                println!("{}", info.id);
                eprintln!(
                    "agent `{}` started ({}), state {}{}",
                    info.adapter_name,
                    info.id,
                    info.state.as_str(),
                    if info.approximate {
                        " [state detection is approximate]"
                    } else {
                        ""
                    }
                );
            }
            if parsed.flag("--detach") {
                return Err(fail(
                    "detached agent runs are not available in-process; run in the foreground or use the session daemon",
                ));
            }
            let interactive = std::io::stdin().is_terminal()
                && parsed.value("--prompt").is_none()
                && !parsed.flag("--wait");
            if interactive {
                stream_interactive(&handle)?;
            } else {
                let timeout = parsed
                    .value("--timeout")
                    .and_then(parse_timeout)
                    .unwrap_or(Duration::from_secs(30 * 60));
                stream_until_done(&handle, timeout, json_out)?;
            }
            let info = handle.info();
            if json_out {
                print_json(&serde_json::to_value(&info).unwrap_or(json!({})))
            } else {
                println!(
                    "\nfinished: state {}, exit {:?}, duration {}ms",
                    info.state.as_str(),
                    info.exit_code,
                    info.elapsed_ms()
                );
                if info.state == z_agents::AgentState::Failed {
                    return Err(fail("agent run failed"));
                }
                Ok(())
            }
        }
        "resume" => {
            let run_id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z agent resume <run-id>"))?;
            let supervisor = Supervisor::new(&data, adapters);
            let handle = supervisor
                .resume(run_id, parsed.value("--prompt").map(str::to_string))
                .map_err(|e| map_err("cannot resume agent", e))?;
            if !json_out {
                println!("{}", handle.info().id);
            }
            stream_until_done(
                &handle,
                parsed
                    .value("--timeout")
                    .and_then(parse_timeout)
                    .unwrap_or(Duration::from_secs(30 * 60)),
                json_out,
            )?;
            Ok(())
        }
        "fork" => {
            let run_id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z agent fork <run-id> --prompt <text>"))?;
            let supervisor = Supervisor::new(&data, adapters.clone());
            let previous = supervisor
                .load_run(run_id)
                .ok_or_else(|| fail(format!("agent run `{run_id}` not found")))?;
            let adapter = adapters
                .iter()
                .find(|adapter| adapter.id == previous.adapter_id)
                .cloned()
                .ok_or_else(|| fail(format!("adapter `{}` not found", previous.adapter_id)))?;
            let handle = supervisor
                .launch(LaunchOptions {
                    adapter,
                    prompt: parsed.value("--prompt").map(str::to_string),
                    model: previous.model.clone(),
                    cwd: PathBuf::from(&previous.workspace),
                    profile: previous.profile.clone(),
                    env: Vec::new(),
                    command_override: None,
                })
                .map_err(|e| map_err("cannot fork agent", e))?;
            if !json_out {
                println!("{}", handle.info().id);
            }
            stream_until_done(
                &handle,
                parsed
                    .value("--timeout")
                    .and_then(parse_timeout)
                    .unwrap_or(Duration::from_secs(30 * 60)),
                json_out,
            )?;
            Ok(())
        }
        "approvals" => {
            let profile = parsed.value("--profile").unwrap_or("agent-dev");
            let workspace = default_workspace(&parsed)?;
            let broker = broker("approvals", profile, &workspace)?;
            let pending = broker.pending();
            if json_out {
                print_json(&json!({"approvals": pending}))
            } else if pending.is_empty() {
                println!("No pending agent approvals.");
                Ok(())
            } else {
                for request in pending {
                    println!(
                        "{}  {:<18} {:<28} {:>8}  {}",
                        request.id,
                        request.action,
                        request.resource,
                        request.risk,
                        request.summary()
                    );
                    if !request.preview.is_empty() {
                        println!("    preview: {}", request.preview);
                    }
                }
                println!("\nApprove with `z agent approve <id>`; deny with `z agent deny <id>`.");
                Ok(())
            }
        }
        "approve" => {
            let id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z agent approve <approval-id>"))?;
            let broker = broker(
                "approval-cli",
                parsed.value("--profile").unwrap_or("agent-dev"),
                &default_workspace(&parsed)?,
            )?;
            let request = broker
                .approve(id, &std::env::var("USER").unwrap_or_else(|_| "local-user".into()))
                .map_err(|e| map_err("cannot approve", e))?;
            if json_out {
                print_json(&serde_json::to_value(&request).unwrap_or(json!({})))
            } else {
                println!("approved {}", request.id);
                Ok(())
            }
        }
        "deny" => {
            let id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z agent deny <approval-id>"))?;
            let broker = broker(
                "approval-cli",
                parsed.value("--profile").unwrap_or("agent-dev"),
                &default_workspace(&parsed)?,
            )?;
            let request = broker
                .deny(id, &std::env::var("USER").unwrap_or_else(|_| "local-user".into()))
                .map_err(|e| map_err("cannot deny", e))?;
            if json_out {
                print_json(&serde_json::to_value(&request).unwrap_or(json!({})))
            } else {
                println!("denied {}", request.id);
                Ok(())
            }
        }
        "trace" => {
            let id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z agent trace <run-id>"))?;
            if !id.starts_with("a_")
                || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return Err(fail("invalid run id"));
            }
            let path = data.join("agents").join("traces").join(format!("{id}.jsonl"));
            let text = std::fs::read_to_string(&path)
                .map_err(|e| map_err("cannot read agent trace", e))?;
            if json_out {
                let events: Vec<serde_json::Value> = text
                    .lines()
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect();
                print_json(&json!({"trace": events}))
            } else {
                print!("{text}");
                Ok(())
            }
        }
        other => Err(fail(format!(
            "unknown agent subcommand `{other}` (adapters|validate-adapter|profiles|list|dashboard|run|resume|fork|approvals|approve|deny|trace)"
        ))),
    }
}

fn stream_until_done(
    handle: &z_agents::AgentHandle,
    timeout: Duration,
    quiet: bool,
) -> ZenResult<()> {
    let deadline = std::time::Instant::now() + timeout;
    let mut written = 0usize;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    loop {
        let info = handle.info();
        let output = handle.output();
        if output.len() > written {
            if !quiet {
                lock.write_all(output[written..].as_bytes())
                    .map_err(|e| map_err("cannot write agent output", e))?;
                lock.flush().ok();
            }
            written = output.len();
        } else if output.len() < written {
            written = output.len();
        }
        if info.terminal() {
            if !quiet && output.len() > written {
                let _ = lock.write_all(output[written..].as_bytes());
            }
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            eprintln!("agent still running; detach with `z agent list` to inspect it later");
            return Err(fail("agent run timed out waiting for completion"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn stream_interactive(handle: &z_agents::AgentHandle) -> ZenResult<()> {
    let _raw = super::session::RawMode::enable()?;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let mut written = 0usize;
    loop {
        let info = handle.info();
        let output = handle.output();
        if output.len() > written {
            lock.write_all(output[written..].as_bytes())
                .map_err(|e| map_err("cannot write agent output", e))?;
            lock.flush().ok();
            written = output.len();
        } else if output.len() < written {
            written = output.len();
        }
        if info.terminal() {
            return Ok(());
        }
        if crossterm::event::poll(Duration::from_millis(20))
            .map_err(|e| map_err("input poll failed", e))?
        {
            match crossterm::event::read().map_err(|e| map_err("input read failed", e))? {
                crossterm::event::Event::Key(key)
                    if key.kind != crossterm::event::KeyEventKind::Release =>
                {
                    if key
                        .modifiers
                        .contains(crossterm::event::KeyModifiers::CONTROL)
                        && matches!(key.code, crossterm::event::KeyCode::Char(']'))
                    {
                        eprintln!("\r\n[detaching; stopping agent to avoid an orphan]");
                        let _ = handle.stop();
                        return Ok(());
                    }
                    let bytes = super::session::key_bytes(&key);
                    if !bytes.is_empty() {
                        handle
                            .write_raw(&bytes)
                            .map_err(|e| map_err("cannot send input", e))?;
                    }
                }
                crossterm::event::Event::Paste(text) => {
                    handle
                        .write_raw(text.as_bytes())
                        .map_err(|e| map_err("cannot send paste", e))?;
                }
                _ => {}
            }
        }
    }
}

fn parse_timeout(value: &str) -> Option<Duration> {
    if let Some(seconds) = value.strip_suffix('s') {
        seconds.parse().ok().map(Duration::from_secs)
    } else if let Some(minutes) = value.strip_suffix('m') {
        minutes
            .parse()
            .ok()
            .map(|minutes: u64| Duration::from_secs(minutes * 60))
    } else {
        value.parse().ok().map(Duration::from_secs)
    }
}

pub fn mcp_serve(args: &[String], _json_out: bool) -> ZenResult<()> {
    let parsed = Parsed::parse(
        args,
        &[
            "--agent",
            "--profile",
            "--workspace",
            "--cwd",
            "--approval-timeout",
            "--tool-timeout",
        ],
    );
    let agent_id = parsed.value("--agent").unwrap_or("mcp");
    let profile = parsed.value("--profile").unwrap_or("agent-readonly");
    AgentProfile::builtin(profile)
        .ok_or_else(|| fail(format!("unknown agent profile `{profile}`")))?;
    let workspace = parsed
        .value("--workspace")
        .or_else(|| parsed.value("--cwd"))
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let broker = broker(agent_id, profile, &workspace)?;
    let options = McpServerOptions {
        approval_timeout: parsed
            .value("--approval-timeout")
            .and_then(parse_timeout)
            .unwrap_or(Duration::from_secs(300)),
        tool_timeout: parsed
            .value("--tool-timeout")
            .and_then(parse_timeout)
            .unwrap_or(Duration::from_secs(60)),
        auto_approve: parsed.flag("--auto-approve"),
        server_name: format!("zentrion-{agent_id}"),
    };
    eprintln!(
        "zentrion MCP server: agent={agent_id} profile={profile} workspace={} (stdout is protocol; approvals via `z agent approvals`)",
        workspace.display()
    );
    let mut server = McpServer::new(broker, options);
    server
        .serve_stdio()
        .map_err(|e| map_err("MCP server failed", e))?;
    Ok(())
}

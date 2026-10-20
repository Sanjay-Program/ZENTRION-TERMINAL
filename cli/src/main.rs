//! Zentrion CLI entry point (`z`). See 05-CLI-SPEC.
//!
//! Design constraints (Phase 1 §7): proper exit codes, readable errors,
//! `--help`/`--version`, low startup overhead, no network calls by default,
//! no telemetry, no account required, works fully offline.

mod commands;
mod context;
mod docs_cmd;
mod native_engines;
mod phase3_cmd;
mod subsystems_cmd;
mod terminal_cmd;
mod tools_cmd;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use z_core::error::ZenError;

#[derive(Parser, Debug)]
#[command(
    name = "z",
    version,
    about = "Zentrion — secure developer, AI and security runtime",
    long_about = "Zentrion is a local-first runtime. Every host effect passes \
through the execution broker: identity, policy, capability, risk, audit.",
    disable_help_subcommand = true
)]
struct Cli {
    /// Emit machine-readable JSON output
    #[arg(long, global = true)]
    json: bool,

    /// Use this project directory instead of discovering the nearest one
    #[arg(long, global = true, value_name = "PATH")]
    project: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Show version, platform, architecture and build type
    Version,

    /// Check host, configuration and project health (offline)
    Doctor,

    /// Show runtime, project, policy and audit status
    Status,

    /// Create and inspect durable local storage used across upgrades
    Setup,

    /// Inspect local storage paths, retention and health
    Storage {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Show adaptable user profiles and recommended workflows
    Profile {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Layered configuration, keybindings, profiles and importers
    Config {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Initialize a new Zentrion project
    Init {
        /// Target directory (default: current directory)
        path: Option<PathBuf>,
        /// Project name (default: derived from the directory name)
        #[arg(long)]
        name: Option<String>,
    },

    /// Show or validate the current project
    Project {
        /// Validate manifests instead of displaying them
        #[arg(long)]
        check: bool,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Show, validate or dry-run the effective policy
    Policy {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Inspect the local audit log
    Audit {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Run a program through the execution broker (no shell)
    Run {
        /// Program to execute (must be permitted by the project policy)
        program: String,
        /// Arguments passed verbatim — never interpreted by a shell
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
        /// Confirm an action that requires approval (HIGH/CRITICAL risk)
        #[arg(long)]
        approve: bool,
    },

    /// Emergency stop — reports state (agent control arrives in Phase 3)
    Lockdown,

    /// Open and search the bundled documentation
    Docs {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Show support and troubleshooting entry points
    Support,

    /// Searchable index of Zentrion commands
    #[command(name = "commands")]
    CommandIndex {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Search the tool registry
    Search {
        /// Search terms (name, description, tags)
        query: Vec<String>,
        /// Restrict to one category
        #[arg(long)]
        category: Option<String>,
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },

    /// Explore curated Kali-style and developer tool bundles
    Bundle {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Show details for a tool
    Info {
        tool: String,
        /// Specific version
        #[arg(long)]
        version: Option<String>,
    },

    /// Install a tool
    Install {
        tool: String,
        /// Version requirement: 1.2.3, >=1.2, ^1.2, ~1.2, *
        #[arg(long)]
        version: Option<String>,
        /// Show what would happen without changing anything
        #[arg(long)]
        dry_run: bool,
        /// Refuse to use the network (cache only)
        #[arg(long)]
        offline: bool,
        /// Confirm permissions, an unverified publisher, or a risky action
        #[arg(long)]
        approve: bool,
        /// Explicitly delegate to the OS package manager for a name that is
        /// not in the curated registry
        #[arg(long)]
        os_package: bool,
    },

    /// List installed tools
    List {
        #[arg(long)]
        installed: bool,
        /// Only tools with a newer version available
        #[arg(long)]
        outdated: bool,
    },

    /// Remove a tool
    Remove {
        tool: String,
        #[arg(long)]
        version: Option<String>,
    },
    /// Alias for `remove`
    #[command(name = "uninstall", hide = true)]
    Uninstall {
        tool: String,
        #[arg(long)]
        version: Option<String>,
    },

    /// Update one tool, or all tools
    Update {
        tool: Option<String>,
        #[arg(long)]
        approve: bool,
    },

    /// Roll back a tool to its previous version
    Rollback { tool: String },

    /// Select which installed version of a tool is active
    Use { spec: String },

    /// Check an installed tool for corruption or missing files
    Verify { tool: String },

    /// Show where a tool is installed
    Which { tool: String },

    /// Show per-platform support for a tool
    Compatibility { tool: String },

    /// Report platform, architecture and native capabilities
    Platform,

    /// List and inspect native engines
    Engine {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Run a native scan and store a report locally
    Scan {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Show the most recent findings
    Finding {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Render a report from the latest scan
    Report {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Inspect the latest asset graph
    Asset {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Emit a runtime SBOM, or dependency SBOM with --deps
    Sbom {
        /// Read Cargo.toml/package.json and emit a dependency SBOM
        #[arg(long)]
        deps: bool,
    },

    /// AI analysis foundation for the most recent scan
    Ai {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Inspect the artifact cache
    Cache {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Serve brokered MCP tools or connect to an MCP server
    Mcp {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Validate and inspect WASM plugins (no execution)
    Plugin {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Enterprise fleet integration (login, sync, telemetry)
    Enterprise {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Check, verify and install updates
    Upgrade {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// List, show or set ZENTRION themes
    Theme {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Start or query the local IPC daemon for SDK clients
    Daemon {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Launch the interactive Terminal UI (TUI)
    Ui,

    /// Detect and run project toolchains through the broker
    Code {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Scans, findings, engagements, evidence and signed reports
    Security {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// DNS, TCP probe, latency and plain-HTTP diagnostics
    Network {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Static cloud/IaC configuration review
    Cloud {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Host and supervise CLI agents; approvals, traces and profiles
    Agent {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Natural language intent router (e.g. z do secure my project)
    Do {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        intent: Vec<String>,
    },

    /// Durable PTY sessions: list, create, attach, replay, close
    Session {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Saved command blocks: list, search, show, export, verify
    Blocks {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Named workspaces, layouts and restore plans
    Workspace {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Local repository index, symbols and agent context packs
    Context {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Content-addressed workspace snapshots, diff and rollback
    Checkpoint {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Parameterized workflows with approvals and conditions
    Workflow {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Authorized security engagements, evidence and signed reports
    Engagement {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Model registry, routing, budgets, usage and brokered completions
    #[command(name = "models")]
    Models {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// SSH remote execution, shells, transfers and port forwarding
    Remote {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Loopback web observer with read-only and write tokens
    Web {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Executable shell/markdown/AI notebooks
    Notebook {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn main() {
    // Behave like a Unix tool when piped into `head`: do not panic on EPIPE.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let cli = Cli::parse();

    let result = match cli.command {
        None => {
            print_banner();
            Ok(())
        }
        Some(Commands::Version) => commands::version(cli.json),
        Some(Commands::Doctor) => commands::doctor(cli.json, cli.project.clone()),
        Some(Commands::Status) => commands::status(cli.json, cli.project.clone()),
        Some(Commands::Setup) => commands::setup(cli.json),
        Some(Commands::Storage { args }) => commands::storage(&args, cli.json),
        Some(Commands::Profile { args }) => commands::profile(&args, cli.json),
        Some(Commands::Config { args }) => terminal_cmd::config(&args, cli.json),
        Some(Commands::Init { path, name }) => commands::init(path, name, cli.json),
        Some(Commands::Project { check, args }) => {
            commands::project(check, &args, cli.project.clone(), cli.json)
        }
        Some(Commands::Policy { args }) => commands::policy(&args, cli.project.clone(), cli.json),
        Some(Commands::Audit { args }) => commands::audit(&args, cli.json),
        Some(Commands::Run {
            program,
            args,
            approve,
        }) => {
            // `z run <name> [args]` is the unified entry point. If `name` is an
            // installed tool, run it through the tool path (which resolves the
            // store location and applies the tool policy). Otherwise fall back
            // to the Phase 1 raw-program path, which is gated by
            // `process.spawn` and never invokes a shell.
            let is_installed_tool = z_tool::ToolStore::open()
                .ok()
                .and_then(|st| st.active_version(&program).ok().flatten())
                .is_some();

            if is_installed_tool {
                tools_cmd::run_tool(&program, args, approve, cli.json, cli.project.clone())
            } else {
                commands::run(program, args, approve, cli.project.clone(), cli.json)
            }
        }
        Some(Commands::Lockdown) => handle_lockdown(cli.json),
        Some(Commands::Docs { args }) => docs_cmd::docs(&args, cli.json),
        Some(Commands::Support) => docs_cmd::support(cli.json),
        Some(Commands::CommandIndex { args }) => docs_cmd::commands(cli.json, &args),
        Some(Commands::Search {
            query,
            category,
            json,
        }) => tools_cmd::search(&query, category, cli.json || json, cli.project.clone()),
        Some(Commands::Bundle { args }) => {
            tools_cmd::bundle_cmd(&args, cli.json, cli.project.clone())
        }
        Some(Commands::Info { tool, version }) => {
            tools_cmd::info(&tool, version, cli.json, cli.project.clone())
        }
        Some(Commands::Install {
            tool,
            version,
            dry_run,
            offline,
            approve,
            os_package,
        }) => {
            if os_package {
                tools_cmd::install_os_package(&tool, cli.json)
            } else {
                tools_cmd::install_tool(
                    &tool,
                    version,
                    dry_run,
                    offline,
                    approve,
                    cli.json,
                    cli.project.clone(),
                )
            }
        }
        Some(Commands::List {
            installed,
            outdated,
        }) => tools_cmd::list_tools(installed, outdated, cli.json, cli.project.clone()),
        Some(Commands::Remove { tool, version }) => {
            tools_cmd::remove_tool(&tool, version, cli.json)
        }
        Some(Commands::Uninstall { tool, version }) => {
            tools_cmd::remove_tool(&tool, version, cli.json)
        }
        Some(Commands::Update { tool, approve }) => match tool {
            Some(t) => tools_cmd::install_tool(
                &t,
                None,
                false,
                false,
                approve,
                cli.json,
                cli.project.clone(),
            ),
            None => tools_cmd::update_all(approve, cli.json, cli.project.clone()),
        },
        Some(Commands::Rollback { tool }) => tools_cmd::rollback_tool(&tool, cli.json),
        Some(Commands::Use { spec }) => tools_cmd::use_spec(&spec, cli.json),
        Some(Commands::Verify { tool }) => tools_cmd::verify_tool(&tool, cli.json),
        Some(Commands::Which { tool }) => tools_cmd::which_tool(&tool, cli.json),
        Some(Commands::Compatibility { tool }) => {
            tools_cmd::compatibility(&tool, cli.json, cli.project.clone())
        }
        Some(Commands::Platform) => tools_cmd::platform_report(cli.json),
        Some(Commands::Engine { args }) => phase3_cmd::engine(&args, cli.json),
        Some(Commands::Scan { args }) => phase3_cmd::scan(&args, cli.json, cli.project.clone()),
        Some(Commands::Finding { args }) => phase3_cmd::finding(&args, cli.json),
        Some(Commands::Report { args }) => phase3_cmd::report(&args, cli.json),
        Some(Commands::Asset { args }) => phase3_cmd::asset(&args, cli.json),
        Some(Commands::Sbom { deps }) => {
            if deps {
                phase3_cmd::sbom_deps(cli.json)
            } else {
                phase3_cmd::sbom(cli.json)
            }
        }
        Some(Commands::Ai { args }) => phase3_cmd::ai(&args, cli.json),
        Some(Commands::Cache { args }) => tools_cmd::cache_cmd(&args, cli.json),
        Some(Commands::Mcp { args }) => handle_mcp(&args, cli.json, cli.project.clone()),
        Some(Commands::Plugin { args }) => handle_plugin(&args, cli.json),
        Some(Commands::Enterprise { args }) => handle_enterprise(&args, cli.json),
        Some(Commands::Upgrade { args }) => handle_upgrade(&args, cli.json),
        Some(Commands::Theme { args }) => subsystems_cmd::theme(&args, cli.json),
        Some(Commands::Daemon { args }) => handle_daemon(&args, cli.json),
        Some(Commands::Ui) => tui::start_tui().map_err(|e| {
            z_core::error::ZenError::new(
                z_core::error::Area::Cor,
                200,
                format!("terminal UI failed: {e:#}"),
            )
        }),
        Some(Commands::Code { args }) => subsystems_cmd::code(&args, cli.project.clone(), cli.json),
        Some(Commands::Security { args }) => {
            if matches!(
                args.first().map(|s| s.as_str()),
                Some("engagement") | Some("engagements")
            ) {
                terminal_cmd::engagement(&args[1..], cli.json)
            } else {
                subsystems_cmd::security(&args, cli.project.clone(), cli.json)
            }
        }
        Some(Commands::Network { args }) => {
            subsystems_cmd::network(&args, cli.project.clone(), cli.json)
        }
        Some(Commands::Cloud { args }) => {
            subsystems_cmd::cloud(&args, cli.project.clone(), cli.json)
        }
        Some(Commands::Agent { args }) => terminal_cmd::agent(&args, cli.json),
        Some(Commands::Session { args }) => terminal_cmd::session(&args, cli.json),
        Some(Commands::Blocks { args }) => terminal_cmd::blocks(&args, cli.json),
        Some(Commands::Workspace { args }) => terminal_cmd::workspace(&args, cli.json),
        Some(Commands::Context { args }) => terminal_cmd::context(&args, cli.json),
        Some(Commands::Checkpoint { args }) => terminal_cmd::checkpoint(&args, cli.json),
        Some(Commands::Workflow { args }) => terminal_cmd::workflow(&args, cli.json),
        Some(Commands::Engagement { args }) => terminal_cmd::engagement(&args, cli.json),
        Some(Commands::Models { args }) => terminal_cmd::models(&args, cli.json),
        Some(Commands::Remote { args }) => terminal_cmd::remote(&args, cli.json),
        Some(Commands::Web { args }) => terminal_cmd::web(&args, cli.json),
        Some(Commands::Notebook { args }) => terminal_cmd::notebook(&args, cli.json),
        Some(Commands::Do { intent }) => {
            subsystems_cmd::do_intent(&intent, cli.project.clone(), cli.json)
        }
    };

    match result {
        Ok(()) => {}
        Err(e) => {
            report_error(&e, cli.json);
            std::process::exit(e.exit_code());
        }
    }
}

fn handle_lockdown(json_out: bool) -> z_core::error::ZenResult<()> {
    let runtime = tokio::runtime::Runtime::new().map_err(|e| {
        z_core::error::ZenError::new(
            z_core::error::Area::Cor,
            121,
            format!("cannot start async runtime: {e}"),
        )
    })?;
    let client = sdk::ZentrionClient::local();
    let stopped = matches!(
        runtime.block_on(client.shutdown()),
        Ok(response) if response.is_ok()
    );
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "daemon_stopped": stopped,
                "note": if stopped { "local IPC daemon stopped" } else { "no daemon was running" },
            }))
            .unwrap_or_default()
        );
    } else if stopped {
        println!("Lockdown complete: local IPC daemon stopped.");
        println!("  CLI agent runs are synchronous, so no background agent needed termination.");
        println!("  New brokered commands still require policy approval as configured.");
    } else {
        println!("Lockdown: no local daemon was running.");
        println!("  CLI agent runs are synchronous, so no background agent needed termination.");
    }
    Ok(())
}

fn handle_enterprise(args: &[String], json_out: bool) -> z_core::error::ZenResult<()> {
    match args.first().map(|s| s.as_str()) {
        Some("login") => match args.get(1) {
            None => Err(z_core::error::ZenError::new(
                z_core::error::Area::Cfg,
                106,
                "usage: z enterprise login <team>",
            )),
            Some(team) => {
                let token = enterprise::sso::login(team).map_err(|e| {
                    z_core::error::ZenError::new(
                        z_core::error::Area::Cfg,
                        105,
                        format!("enterprise login failed: {e:#}"),
                    )
                    .with_remediation("Set ZENTRION_ENTERPRISE_URL to your control plane.")
                })?;
                if json_out {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "ok",
                            "team": team,
                            "token_stored": true,
                            "token_length": token.len(),
                            "token_displayed": false,
                        }))
                        .unwrap_or_default()
                    );
                } else {
                    println!("Authenticated with the enterprise control plane.");
                    println!("  team:  {team}");
                    println!("  token: stored in the encrypted vault (never displayed)");
                }
                Ok(())
            }
        },
        Some("sync") => {
            println!("Fetching fleet policy...");
            let policy = enterprise::sync::sync_policy().map_err(|e| {
                z_core::error::ZenError::new(
                    z_core::error::Area::Cfg,
                    107,
                    format!("enterprise sync failed: {e:#}"),
                )
            })?;
            println!(
                "Fleet policy saved under the data directory:\n{}",
                serde_json::to_string_pretty(&policy).unwrap_or_default()
            );
            Ok(())
        }
        Some("fleet-status") => {
            println!("Forwarding audit events to the enterprise collector...");
            let count = enterprise::telemetry::forward_audit_logs().map_err(|e| {
                z_core::error::ZenError::new(
                    z_core::error::Area::Cfg,
                    108,
                    format!("enterprise telemetry failed: {e:#}"),
                )
            })?;
            println!("Forwarded {count} audit event(s).");
            Ok(())
        }
        Some("status") | None => {
            let base = std::env::var("ZENTRION_ENTERPRISE_URL")
                .unwrap_or_else(|_| "not configured".into());
            let token = enterprise::client::stored_token().is_some();
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "url": base,
                        "token_present": token,
                        "token_displayed": false,
                    }))
                    .unwrap_or_default()
                );
            } else {
                println!("ZENTRION enterprise");
                println!("  url:   {base}");
                println!(
                    "  token: {}",
                    if token {
                        "present (hidden)"
                    } else {
                        "not logged in"
                    }
                );
            }
            Ok(())
        }
        Some(other) => Err(z_core::error::ZenError::new(
            z_core::error::Area::Cfg,
            109,
            format!("unknown enterprise subcommand `{other}`"),
        )
        .with_remediation("Usage: z enterprise [login|sync|fleet-status|status]")),
    }
}

fn handle_upgrade(args: &[String], json_out: bool) -> z_core::error::ZenResult<()> {
    let json_out = json_out || args.iter().any(|arg| arg == "--json");
    let args: Vec<String> = args
        .iter()
        .filter(|arg| arg.as_str() != "--json")
        .cloned()
        .collect();
    match args.first().map(|s| s.as_str()) {
        Some("check") => match update::engine::check_update() {
            Ok(Some(info)) => {
                if json_out {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "update_available": true,
                            "current": info.current,
                            "latest": info.manifest.version,
                            "url": info.manifest.url,
                            "sha256": info.manifest.sha256,
                        }))
                        .unwrap_or_default()
                    );
                } else {
                    println!("Update available");
                    println!("  current:  {}", info.current);
                    println!("  latest:   {}", info.manifest.version);
                    if let Some(notes) = &info.manifest.notes {
                        println!("  notes:    {notes}");
                    }
                    println!("  artifact: {}", info.manifest.url);
                    println!("  sha256:   {}", info.manifest.sha256);
                }
                Ok(())
            }
            Ok(None) => {
                if json_out {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "update_available": false,
                            "current": update::engine::current_version(),
                        }))
                        .unwrap_or_default()
                    );
                } else {
                    println!(
                        "ZENTRION is up to date ({}).",
                        update::engine::current_version()
                    );
                }
                Ok(())
            }
            Err(e) => Err(z_core::error::ZenError::new(
                z_core::error::Area::Cfg,
                111,
                format!("update check failed: {e:#}"),
            )
            .with_remediation(
                "Set ZENTRION_UPDATE_MANIFEST to a manifest JSON file or HTTPS URL.",
            )),
        },
        Some("apply") => match update::engine::apply_update() {
            Ok(version) => {
                if json_out {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "installed",
                            "version": version,
                        }))
                        .unwrap_or_default()
                    );
                } else {
                    println!("Update verified and installed: {version}");
                    println!("Restart `z` to run the new build.");
                }
                Ok(())
            }
            Err(e) => Err(z_core::error::ZenError::new(
                z_core::error::Area::Cfg,
                112,
                format!("update apply failed: {e:#}"),
            )),
        },
        Some("rollback") => match update::engine::rollback() {
            Ok(version) => {
                if json_out {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "rolled_back",
                            "version": version,
                        }))
                        .unwrap_or_default()
                    );
                } else {
                    println!("Rolled back to the previous binary ({version}).");
                }
                Ok(())
            }
            Err(e) => Err(z_core::error::ZenError::new(
                z_core::error::Area::Cfg,
                113,
                format!("update rollback failed: {e:#}"),
            )),
        },
        _ => Err(z_core::error::ZenError::new(
            z_core::error::Area::Cfg,
            115,
            "usage: z upgrade <check|apply|rollback>",
        )),
    }
}

fn handle_daemon(args: &[String], json_out: bool) -> z_core::error::ZenResult<()> {
    let port = args
        .iter()
        .position(|arg| arg == "--port")
        .and_then(|index| args.get(index + 1))
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(9099);
    match args.first().map(|s| s.as_str()) {
        Some("start") => {
            let once = args.iter().any(|arg| arg == "--once");
            let runtime = tokio::runtime::Runtime::new().map_err(|e| {
                z_core::error::ZenError::new(
                    z_core::error::Area::Cor,
                    118,
                    format!("cannot start async runtime: {e}"),
                )
            })?;
            runtime
                .block_on(daemon::server::start_daemon(port, once))
                .map_err(|e| {
                    z_core::error::ZenError::new(
                        z_core::error::Area::Cfg,
                        116,
                        format!("daemon failed: {e:#}"),
                    )
                })
        }
        Some("stop") | Some("shutdown") => {
            let runtime = tokio::runtime::Runtime::new().map_err(|e| {
                z_core::error::ZenError::new(
                    z_core::error::Area::Cor,
                    118,
                    format!("cannot start async runtime: {e}"),
                )
            })?;
            let client = sdk::ZentrionClient::new(format!("127.0.0.1:{port}"));
            let response = runtime.block_on(client.shutdown()).map_err(|e| {
                z_core::error::ZenError::new(
                    z_core::error::Area::Net,
                    120,
                    format!("daemon stop failed on 127.0.0.1:{port}: {e:#}"),
                )
            })?;
            println!("{}", response.stdout.trim());
            Ok(())
        }
        Some("status") | Some("ping") | None => {
            let runtime = tokio::runtime::Runtime::new().map_err(|e| {
                z_core::error::ZenError::new(
                    z_core::error::Area::Cor,
                    118,
                    format!("cannot start async runtime: {e}"),
                )
            })?;
            let client = sdk::ZentrionClient::new(format!("127.0.0.1:{port}"));
            let response = runtime.block_on(client.connect()).map_err(|e| {
                z_core::error::ZenError::new(
                    z_core::error::Area::Net,
                    119,
                    format!("daemon not reachable on 127.0.0.1:{port}: {e:#}"),
                )
                .with_remediation("Start it with `z daemon start`.")
            })?;
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&response).unwrap_or_default()
                );
            } else {
                print!("{}", response.stdout);
                if let Some(metrics) = &response.metrics {
                    println!(
                        "  cpu: {:.1}%  memory: {} bytes  pid: {}",
                        metrics.cpu_usage, metrics.memory_usage, metrics.pid
                    );
                }
            }
            Ok(())
        }
        Some(other) => Err(z_core::error::ZenError::new(
            z_core::error::Area::Cfg,
            117,
            format!("unknown daemon subcommand `{other}`"),
        )
        .with_remediation("Usage: z daemon <start|status|stop> [--port N] [--once]")),
    }
}

fn handle_mcp(
    args: &[String],
    json_out: bool,
    project: Option<std::path::PathBuf>,
) -> z_core::error::ZenResult<()> {
    if matches!(args.first().map(|s| s.as_str()), Some("serve")) {
        return terminal_cmd::mcp_serve(&args[1..], json_out);
    }
    match args.first().map(|s| s.as_str()) {
        Some("connect") => {
            let allow = args.iter().any(|arg| arg == "--allow");
            let cleaned: Vec<&String> = args
                .iter()
                .skip(1)
                .filter(|arg| arg.as_str() != "--allow")
                .collect();
            let cmd = cleaned.first().ok_or_else(|| {
                z_core::error::ZenError::new(
                    z_core::error::Area::Cfg,
                    101,
                    "usage: z mcp connect [--allow] <command> [args...]",
                )
                .with_remediation(
                    "Example: z mcp connect --allow npx -y @modelcontextprotocol/server-filesystem /tmp",
                )
            })?;
            let mcp_args: Vec<String> = cleaned.iter().skip(1).map(|arg| (*arg).clone()).collect();
            subsystems_cmd::require_process(&project, cmd, allow)?;
            println!("Starting MCP server: {} {}", cmd, mcp_args.join(" "));
            let mut gateway = mcp::gateway::McpGateway::connect(cmd, &mcp_args).map_err(|e| {
                z_core::error::ZenError::new(
                    z_core::error::Area::Cfg,
                    104,
                    format!("MCP connect failed: {e:#}"),
                )
            })?;
            println!("  pid: {}", gateway.pid());
            let info = gateway
                .initialize("zentrion", env!("CARGO_PKG_VERSION"))
                .map_err(|e| {
                    z_core::error::ZenError::new(
                        z_core::error::Area::Cfg,
                        104,
                        format!("MCP initialize failed: {e:#}"),
                    )
                })?;
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&info).unwrap_or_default()
                );
            } else {
                let name = info
                    .get("serverInfo")
                    .and_then(|s| s.get("name"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");
                let version = info
                    .get("serverInfo")
                    .and_then(|s| s.get("version"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");
                let protocol = info
                    .get("protocolVersion")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");
                println!("  server:   {name} {version}");
                println!("  protocol: {protocol}");
            }
            let tools = gateway.list_tools().map_err(|e| {
                z_core::error::ZenError::new(
                    z_core::error::Area::Cfg,
                    104,
                    format!("MCP tools/list failed: {e:#}"),
                )
            })?;
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&tools).unwrap_or_default()
                );
            } else {
                println!("  tools:    {}", tools.len());
                for tool in &tools {
                    println!("    - {:<24} {}", tool.name, tool.description);
                }
            }
            Ok(())
        }
        _ => Err(z_core::error::ZenError::new(
            z_core::error::Area::Cfg,
            101,
            "usage: z mcp connect [--allow] <command> [args...]",
        )),
    }
}

fn handle_plugin(args: &[String], json_out: bool) -> z_core::error::ZenResult<()> {
    match args.first().map(|s| s.as_str()) {
        Some("load") | Some("inspect") => {
            let path = args.get(1).ok_or_else(|| {
                z_core::error::ZenError::new(
                    z_core::error::Area::Cfg,
                    103,
                    "usage: z plugin inspect <path.wasm>",
                )
            })?;
            match plugin::manager::validate_plugin(std::path::Path::new(path)) {
                Ok(validated) => {
                    if json_out {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "path": validated.path.display().to_string(),
                                "manifest": validated.manifest,
                                "sha256": validated.sha256,
                                "size": validated.size,
                                "executed": false,
                                "note": "validated only; this build has no WASM runtime",
                            }))
                            .unwrap_or_default()
                        );
                    } else {
                        println!("Validated plugin {}", validated.path.display());
                        println!("  name:        {}", validated.manifest.name);
                        println!("  version:     {}", validated.manifest.version);
                        println!("  entrypoint:  {}", validated.manifest.entrypoint);
                        println!(
                            "  permissions: {}",
                            if validated.manifest.permissions.is_empty() {
                                "none declared".to_string()
                            } else {
                                validated.manifest.permissions.join(", ")
                            }
                        );
                        println!("  sha256:      {}", validated.sha256);
                        println!("  size:        {} bytes", validated.size);
                        println!();
                        println!("  Not executed: this build validates plugins but does not embed a WASM runtime.");
                    }
                    Ok(())
                }
                Err(e) => Err(z_core::error::ZenError::new(
                    z_core::error::Area::Cfg,
                    102,
                    format!("plugin validation failed: {e:#}"),
                )
                .with_remediation("A plugin must be a valid WASM module; an optional sibling <file>.wasm.json manifest is supported.")),
            }
        }
        Some("list") => {
            let dir = args.get(1).map(std::path::PathBuf::from);
            let mut manager = match dir {
                Some(dir) => plugin::manager::PluginManager::with_dir(dir),
                None => plugin::manager::PluginManager::new(),
            };
            let loaded = manager.load_all().map_err(|e| {
                z_core::error::ZenError::new(
                    z_core::error::Area::Cfg,
                    105,
                    format!("plugin list failed: {e:#}"),
                )
            })?;
            if json_out {
                let entries: Vec<_> = loaded
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "path": p.path.display().to_string(),
                            "name": p.manifest.name,
                            "version": p.manifest.version,
                            "sha256": p.sha256,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&entries).unwrap_or_default()
                );
            } else {
                println!(
                    "Plugins in {}",
                    manager
                        .dir()
                        .map(|d| d.display().to_string())
                        .unwrap_or_else(|| "n/a".into())
                );
                if loaded.is_empty() {
                    println!("  (none)");
                } else {
                    for p in &loaded {
                        println!(
                            "  {:<20} {:<8} {}",
                            p.manifest.name,
                            p.manifest.version,
                            p.path.display()
                        );
                    }
                }
            }
            Ok(())
        }
        _ => Err(z_core::error::ZenError::new(
            z_core::error::Area::Cfg,
            103,
            "usage: z plugin <load|inspect|list> [path]",
        )),
    }
}

fn print_banner() {
    println!("Zentrion v{}", env!("CARGO_PKG_VERSION"));
    println!("A local-first, capability-secured developer, AI and security runtime.");
    println!();
    println!("Common commands:");
    println!("  z doctor            check host and configuration health");
    println!("  z setup             initialize durable local storage");
    println!("  z storage show      show storage paths and retention");
    println!("  z profile list      show adaptable workflow profiles");
    println!("  z init <dir>        create a new project");
    println!("  z status            runtime and project status");
    println!("  z project --check   validate the current project");
    println!("  z policy validate   validate the effective policy");
    println!("  z run <cmd> [args]  run a permitted program through the broker");
    println!("  z search <term>     search the tool registry");
    println!("  z bundle list       show curated tool bundles");
    println!("  z install <tool>    install a tool (verified)");
    println!("  z list              list installed tools");
    println!("  z platform          report native platform capabilities");
    println!("  z engine list       list native engines");
    println!("  z scan <target>     run a native scan and store a report");
    println!("  z audit tail        show recent security-relevant events");
    println!();
    println!("Run `z help <command>` or `z <command> --help` for details.");
}

/// Render an error per the security-UX template (06 §6.5): plain language
/// first, machine code second.
fn report_error(e: &ZenError, json: bool) {
    if json {
        let obj = serde_json::json!({
            "error": {
                "code": e.code,
                "message": e.human,
                "remediation": e.remediation(),
                "exit_code": e.exit_code(),
            }
        });
        eprintln!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
        return;
    }
    eprintln!("✗ {}", e.human);
    if let Some(r) = e.remediation() {
        eprintln!("  Suggested action: {r}");
    }
    if let Some(c) = e.cause() {
        eprintln!("  Caused by: {c}");
    }
    eprintln!("  ({})", e.code);
}

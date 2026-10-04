//! Zentrion CLI entry point (`z`). See 05-CLI-SPEC.
//!
//! Design constraints (Phase 1 §7): proper exit codes, readable errors,
//! `--help`/`--version`, low startup overhead, no network calls by default,
//! no telemetry, no account required, works fully offline.

mod commands;
mod docs_cmd;
mod context;
mod native_engines;
mod phase3_cmd;
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

    /// Inspect or modify configuration (never secrets)
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
    CommandsIndex {
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

    /// Emit a runtime SBOM-like JSON summary
    Sbom,

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

    /// Connect to a Model Context Protocol server
    Mcp {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Load or manage WASM plugins
    Plugin {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Enterprise fleet integration (login, sync, telemetry)
    Enterprise {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Upgrade ZENTRION OTA
    Upgrade {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Start the local IPC daemon for SDK clients
    Daemon {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Launch the interactive Terminal UI (TUI)
    Ui,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        None => {
            print_banner();
            Ok(())
        }
        Some(Commands::Version) => commands::version(cli.json),
        Some(Commands::Doctor) => commands::doctor(cli.json, cli.project.clone()),
        Some(Commands::Status) => commands::status(cli.json, cli.project.clone()),
        Some(Commands::Config { args }) => commands::config(&args, cli.json),
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
        Some(Commands::Lockdown) => commands::lockdown(cli.json),
        Some(Commands::Docs { args }) => docs_cmd::docs(&args, cli.json),
        Some(Commands::Support) => docs_cmd::support(cli.json),
        Some(Commands::CommandsIndex { args }) => docs_cmd::commands(cli.json, &args),
        Some(Commands::Search {
            query,
            category,
            json,
        }) => tools_cmd::search(&query, category, cli.json || json, cli.project.clone()),
        Some(Commands::Info { tool, version }) => {
            tools_cmd::info(&tool, version, cli.json, cli.project.clone())
        }
        Some(Commands::Install {
            tool,
            version,
            dry_run,
            offline,
            approve,
        }) => tools_cmd::install_tool(
            &tool,
            version,
            dry_run,
            offline,
            approve,
            cli.json,
            cli.project.clone(),
        ),
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
        Some(Commands::Scan { args }) => phase3_cmd::scan(&args, cli.json),
        Some(Commands::Finding { args }) => phase3_cmd::finding(&args, cli.json),
        Some(Commands::Report { args }) => phase3_cmd::report(&args, cli.json),
        Some(Commands::Asset { args }) => phase3_cmd::asset(&args, cli.json),
        Some(Commands::Sbom) => phase3_cmd::sbom(cli.json),
        Some(Commands::Ai { args }) => phase3_cmd::ai(&args, cli.json),
        Some(Commands::Cache { args }) => tools_cmd::cache_cmd(&args, cli.json),
        Some(Commands::Mcp { args }) => {
            if let Some("connect") = args.first().map(|s| s.as_str()) {
                if let Some(cmd) = args.get(1) {
                    println!("Connecting to MCP server via: {}", cmd);
                    let mcp_args: Vec<String> = args.iter().skip(2).cloned().collect();
                    match mcp::gateway::McpGateway::connect(cmd, &mcp_args) {
                        Ok(_) => {
                            println!("Successfully connected to MCP Server.");
                            Ok(())
                        }
                        Err(e) => Err(z_core::error::ZenError::new(z_core::error::Area::Cfg, 104, format!("mcp connect failed: {}", e))),
                    }
                } else {
                    Err(z_core::error::ZenError::new(z_core::error::Area::Cfg, 101, "usage: z mcp connect <command>"))
                }
            } else {
                Err(z_core::error::ZenError::new(z_core::error::Area::Cfg, 101, "usage: z mcp connect <command>"))
            }
        }
        Some(Commands::Plugin { args }) => {
            if let Some("load") = args.first().map(|s| s.as_str()) {
                if let Some(path) = args.get(1) {
                    let mut manager = plugin::manager::PluginManager::new();
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    match rt.block_on(manager.load(path)) {
                        Ok(_) => {
                            println!("Successfully loaded plugin from {}", path);
                            Ok(())
                        }
                        Err(e) => Err(z_core::error::ZenError::new(z_core::error::Area::Cfg, 102, format!("plugin load failed: {}", e))),
                    }
                } else {
                    Err(z_core::error::ZenError::new(z_core::error::Area::Cfg, 103, "usage: z plugin load <path>"))
                }
            } else {
                Err(z_core::error::ZenError::new(z_core::error::Area::Cfg, 103, "usage: z plugin load <path>"))
            }
        }
        Some(Commands::Enterprise { args }) => {
            if let Some(cmd) = args.first().map(|s| s.as_str()) {
                match cmd {
                    "login" => {
                        if let Some(team) = args.get(1) {
                            println!("Initiating enterprise SSO login for team: {}", team);
                            match enterprise::sso::login(team) {
                                Ok(token) => {
                                    let display_len = std::cmp::min(10, token.len());
                                    println!("SSO Login Successful! Token: {}...", &token[0..display_len]);
                                    Ok(())
                                }
                                Err(e) => Err(z_core::error::ZenError::new(z_core::error::Area::Cfg, 105, format!("login failed: {}", e))),
                            }
                        } else {
                            Err(z_core::error::ZenError::new(z_core::error::Area::Cfg, 106, "usage: z enterprise login <team>"))
                        }
                    }
                    "sync" => {
                        println!("Syncing enterprise fleet policies...");
                        match enterprise::sync::sync_policy("mock-token") {
                            Ok(policy) => {
                                println!("Successfully downloaded fleet policy:\n{}", serde_json::to_string_pretty(&policy).unwrap_or_default());
                                Ok(())
                            }
                            Err(e) => Err(z_core::error::ZenError::new(z_core::error::Area::Cfg, 107, format!("sync failed: {}", e))),
                        }
                    }
                    "fleet-status" => {
                        println!("Forwarding local telemetry and audit logs to SIEM...");
                        match enterprise::telemetry::forward_audit_logs("mock-token") {
                            Ok(_) => {
                                println!("Fleet status and SIEM telemetry synchronized successfully.");
                                Ok(())
                            }
                            Err(e) => Err(z_core::error::ZenError::new(z_core::error::Area::Cfg, 108, format!("telemetry failed: {}", e))),
                        }
                    }
                    _ => Err(z_core::error::ZenError::new(z_core::error::Area::Cfg, 109, "unknown enterprise subcommand")),
                }
            } else {
                Err(z_core::error::ZenError::new(z_core::error::Area::Cfg, 110, "usage: z enterprise <login|sync|fleet-status>"))
            }
        }
        Some(Commands::Upgrade { args }) => {
            if let Some(cmd) = args.first().map(|s| s.as_str()) {
                match cmd {
                    "check" => {
                        println!("Checking CDN for signed release manifests...");
                        match update::engine::check_updates() {
                            Ok(true) => {
                                println!("Update available! Run 'z upgrade apply' to download.");
                                Ok(())
                            }
                            Ok(false) => {
                                println!("ZENTRION is up to date.");
                                Ok(())
                            }
                            Err(e) => Err(z_core::error::ZenError::new(z_core::error::Area::Cfg, 111, format!("upgrade check failed: {}", e))),
                        }
                    }
                    "apply" => {
                        println!("Staging incoming verified binary...");
                        match update::engine::apply_update() {
                            Ok(version) => {
                                println!("Successfully activated version: {}", version);
                                Ok(())
                            }
                            Err(e) => Err(z_core::error::ZenError::new(z_core::error::Area::Cfg, 112, format!("upgrade apply failed: {}", e))),
                        }
                    }
                    "rollback" => {
                        println!("Rolling back to previous verified binary state...");
                        match update::engine::rollback() {
                            Ok(version) => {
                                println!("Successfully restored previous version: {}", version);
                                Ok(())
                            }
                            Err(e) => Err(z_core::error::ZenError::new(z_core::error::Area::Cfg, 113, format!("upgrade rollback failed: {}", e))),
                        }
                    }
                    _ => Err(z_core::error::ZenError::new(z_core::error::Area::Cfg, 114, "unknown upgrade subcommand")),
                }
            } else {
                Err(z_core::error::ZenError::new(z_core::error::Area::Cfg, 115, "usage: z upgrade <check|apply|rollback>"))
            }
        }
        Some(Commands::Daemon { args }) => {
            if let Some("start") = args.first().map(|s| s.as_str()) {
                println!("Starting ZENTRION IPC Daemon on port 9099...");
                let rt = tokio::runtime::Runtime::new().unwrap();
                if let Err(e) = rt.block_on(daemon::server::start_daemon(9099)) {
                    Err(z_core::error::ZenError::new(z_core::error::Area::Cfg, 116, format!("daemon failed: {}", e)))
                } else {
                    println!("Daemon shutdown successfully.");
                    Ok(())
                }
            } else {
                Err(z_core::error::ZenError::new(z_core::error::Area::Cfg, 117, "usage: z daemon start"))
            }
        }
        Some(Commands::Ui) => {
            // Start the async TUI inside a tokio runtime
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                if let Err(e) = tui::start_tui().await {
                    eprintln!("TUI Error: {}", e);
                }
            });
            Ok(())
        },
    };

    match result {
        Ok(()) => {}
        Err(e) => {
            report_error(&e, cli.json);
            std::process::exit(e.exit_code());
        }
    }
}

fn print_banner() {
    println!("Zentrion v{}", env!("CARGO_PKG_VERSION"));
    println!("A local-first, capability-secured developer, AI and security runtime.");
    println!();
    println!("Common commands:");
    println!("  z doctor            check host and configuration health");
    println!("  z init <dir>        create a new project");
    println!("  z status            runtime and project status");
    println!("  z project --check   validate the current project");
    println!("  z policy validate   validate the effective policy");
    println!("  z run <cmd> [args]  run a permitted program through the broker");
    println!("  z search <term>     search the tool registry");
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

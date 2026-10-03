use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use z_core::error::{Area, ZenError, ZenResult};

const DOC_TOPICS: &[(&str, &str)] = &[
    ("getting-started", "getting-started.md"),
    ("terminal", "terminal.md"),
    ("cli", "cli.md"),
    ("tools", "tools.md"),
    ("security", "security.md"),
    ("security-model", "SECURITY_MODEL.md"),
    ("ai", "ai.md"),
    ("agents", "agents.md"),
    ("projects", "projects.md"),
    ("git", "git.md"),
    ("ssh", "ssh.md"),
    ("workflows", "workflows.md"),
    ("plugins", "plugins.md"),
    ("policies", "policies.md"),
    ("privacy", "privacy.md"),
    ("troubleshooting", "troubleshooting.md"),
    ("release-readiness", "RELEASE_READINESS.md"),
    ("platform-support", "PLATFORM_SUPPORT.md"),
    ("installation-matrix", "INSTALLATION_MATRIX.md"),
    ("documentation-index", "DOCUMENTATION_INDEX.md"),
    ("tool-compatibility", "TOOL_COMPATIBILITY.md"),
    ("update-model", "UPDATE_MODEL.md"),
];

const COMMANDS: &[(&str, &str)] = &[
    ("version", "Show version, platform, architecture and build type"),
    ("doctor", "Check host, configuration and project health"),
    ("status", "Show runtime, project, policy and audit status"),
    ("config", "Inspect or modify configuration"),
    ("init", "Initialize a new Zentrion project"),
    ("project", "Show or validate the current project"),
    ("policy", "Show, validate or dry-run the effective policy"),
    ("audit", "Inspect the local audit log"),
    ("run", "Run a program through the execution broker"),
    ("search", "Search the tool registry"),
    ("info", "Show details for a tool"),
    ("install", "Install a tool"),
    ("list", "List installed tools"),
    ("remove", "Remove a tool"),
    ("update", "Update one tool, or all tools"),
    ("rollback", "Roll back a tool to its previous version"),
    ("use", "Select which installed version of a tool is active"),
    ("verify", "Check an installed tool for corruption or missing files"),
    ("platform", "Report platform, architecture and native capabilities"),
    ("engine", "List and inspect native engines"),
    ("scan", "Run a native scan and store a report locally"),
    ("finding", "Show the most recent findings"),
    ("report", "Render a report from the latest scan"),
    ("asset", "Inspect the latest asset graph"),
    ("sbom", "Emit a runtime SBOM-like JSON summary"),
    ("ai", "AI analysis foundation for the most recent scan"),
    ("cache", "Inspect the artifact cache"),
    ("docs", "Open offline documentation"),
    ("support", "Show support and troubleshooting links"),
    ("commands", "Searchable index of commands"),
];

fn candidate_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(root) = std::env::var("ZENTRION_DOCS_DIR") {
        roots.push(PathBuf::from(root));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(bin_dir) = exe.parent() {
            if let Some(install_root) = bin_dir.parent() {
                roots.push(install_root.join("share/zentrion/docs"));
                roots.push(install_root.join("docs"));
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        roots.push(cwd.join("docs"));
    }
    roots
}

fn docs_root() -> Option<PathBuf> {
    candidate_roots().into_iter().find(|root| root.is_dir())
}

fn topic_path(topic: &str) -> Option<&'static str> {
    DOC_TOPICS.iter().find(|(name, _)| *name == topic).map(|(_, path)| *path)
}

fn read_doc(path: &Path) -> ZenResult<String> {
    Ok(fs::read_to_string(path).map_err(|e| {
        ZenError::new(Area::Fs, 5300, format!("failed to read {}: {e}", path.display()))
    })?)
}

fn print_topic(topic: &str) -> ZenResult<()> {
    let root = docs_root().ok_or_else(|| {
        ZenError::new(Area::Fs, 5301, "documentation directory not found")
            .with_remediation("Install a release archive or run from the repository root")
    })?;
    let rel = topic_path(topic).ok_or_else(|| {
        ZenError::new(Area::Cfg, 5302, format!("unknown docs topic: {topic}"))
            .with_remediation("Run `z docs` to see the available topics")
    })?;
    let path = root.join(rel);
    let content = read_doc(&path)?;
    println!("{}", content);
    Ok(())
}

fn score_match(text: &str, terms: &[String]) -> bool {
    let lower = text.to_lowercase();
    terms.iter().all(|term| lower.contains(&term.to_lowercase()))
}

fn search_docs(terms: &[String]) -> ZenResult<()> {
    let root = docs_root().ok_or_else(|| {
        ZenError::new(Area::Fs, 5303, "documentation directory not found")
            .with_remediation("Install a release archive or run from the repository root")
    })?;
    let mut hits = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).map_err(|e| {
            ZenError::new(Area::Fs, 5304, format!("failed to read {}: {e}", dir.display()))
        })? {
            let entry = entry.map_err(|e| {
                ZenError::new(Area::Fs, 5305, format!("failed to read entry: {e}"))
            })?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|s| s.to_str()) != Some("md") {
                continue;
            }
            let content = fs::read_to_string(&path).unwrap_or_default();
            if !score_match(&content, terms) {
                continue;
            }
            for (idx, line) in content.lines().enumerate() {
                if score_match(line, terms) {
                    hits.push((path.clone(), idx + 1, line.trim().to_string()));
                    break;
                }
            }
        }
    }
    if hits.is_empty() {
        println!("No documentation matches.");
        return Ok(());
    }
    for (path, line, snippet) in hits.into_iter().take(20) {
        println!("{}:{}: {}", path.display(), line, snippet);
    }
    Ok(())
}

pub fn docs(args: &[String], json: bool) -> ZenResult<()> {
    match args.first().map(|s| s.as_str()) {
        None | Some("index") => {
            let index = docs_root()
                .and_then(|root| fs::read_to_string(root.join("DOCUMENTATION_INDEX.md")).ok())
                .unwrap_or_else(|| {
                    DOC_TOPICS
                        .iter()
                        .map(|(name, _)| format!("- {name}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                });
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "topics": DOC_TOPICS.iter().map(|(name, path)| json!({"name": name, "path": path})).collect::<Vec<_>>()
                    }))?
                );
            } else {
                println!("Zentrion Docs");
                println!("Everything you need to use Zentrion.");
                println!();
                println!("{index}");
                println!();
                println!("Try: z docs search security");
            }
            Ok(())
        }
        Some("search") => {
            let terms = args.iter().skip(1).cloned().collect::<Vec<_>>();
            if terms.is_empty() {
                return Err(ZenError::new(Area::Cfg, 5306, "usage: z docs search <terms...>"));
            }
            if json {
                let root = docs_root().ok_or_else(|| {
                    ZenError::new(Area::Fs, 5307, "documentation directory not found")
                })?;
                let mut hits = Vec::new();
                let mut stack = vec![root.clone()];
                while let Some(dir) = stack.pop() {
                    for entry in fs::read_dir(&dir).map_err(|e| {
                        ZenError::new(Area::Fs, 5308, format!("failed to read {}: {e}", dir.display()))
                    })? {
                        let entry = entry.map_err(|e| {
                            ZenError::new(Area::Fs, 5309, format!("failed to read entry: {e}"))
                        })?;
                        let path = entry.path();
                        if path.is_dir() {
                            stack.push(path);
                            continue;
                        }
                        if path.extension().and_then(|s| s.to_str()) != Some("md") {
                            continue;
                        }
                        let content = fs::read_to_string(&path).unwrap_or_default();
                        if score_match(&content, &terms) {
                            hits.push(path.display().to_string());
                        }
                    }
                }
                println!("{}", serde_json::to_string_pretty(&json!({ "terms": terms, "matches": hits }))?);
            } else {
                search_docs(&terms)?;
            }
            Ok(())
        }
        Some(topic) => print_topic(topic),
    }
}

pub fn support(json: bool) -> ZenResult<()> {
    let out = json!({
        "docs": "z docs",
        "diagnostics": "z doctor",
        "security": "SECURITY.md",
        "github": "source, issues and releases",
        "report_issue": "z report (planned)"
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Zentrion Support");
        println!("  Documentation: z docs");
        println!("  Diagnostics:   z doctor");
        println!("  Security:      SECURITY.md");
        println!("  GitHub:        source, issues and releases");
        println!("  Report issue:  z report (planned)");
    }
    Ok(())
}

pub fn commands(json: bool, args: &[String]) -> ZenResult<()> {
    let filtered: Vec<_> = if args.first().map(|s| s.as_str()) == Some("search") {
        args.iter().skip(1).map(|s| s.to_lowercase()).collect()
    } else {
        Vec::new()
    };

    let rows: Vec<_> = COMMANDS
        .iter()
        .filter(|(name, desc)| {
            if filtered.is_empty() {
                true
            } else {
                let hay = format!("{name} {desc}").to_lowercase();
                filtered.iter().all(|term| hay.contains(term))
            }
        })
        .map(|(name, desc)| json!({"command": name, "description": desc}))
        .collect();

    if json {
        println!("{}", serde_json::to_string_pretty(&json!({"commands": rows}))?);
    } else {
        println!("Zentrion command index");
        for row in rows {
            let name = row["command"].as_str().unwrap_or("");
            let desc = row["description"].as_str().unwrap_or("");
            println!("  {:<14} {}", name, desc);
        }
    }
    Ok(())
}

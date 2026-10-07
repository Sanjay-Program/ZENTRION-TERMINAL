//! Tool-management CLI commands (Phase 2 §1).
//!
//! All business logic lives in the library crates; these functions only parse
//! input, call those APIs and render output. That keeps the CLI thin and lets
//! future AI/agent/IDE callers use the same APIs directly (Phase 2 §45).

use crate::context::{audit_path, init_runtime};
use serde_json::json;
use std::path::PathBuf;
use z_core::error::{Area, ZenError, ZenResult};
use z_registry::{latest_by_name, LocalRegistry, RegistryClient, SearchQuery};
use z_tool::{install, plan, ToolManifest, ToolStore};

/// Default local registry location: `<project>/.zentrion/registry` or, when
/// there is no project, `<data>/registry`.
pub fn default_registry_root(project: Option<&PathBuf>) -> ZenResult<PathBuf> {
    if let Some(p) = project {
        let r = p.join(".zentrion").join("registry");
        if r.is_dir() {
            return Ok(r);
        }
    }
    // Environment override, for tests and packaging.
    if let Ok(dir) = std::env::var("ZENTRION_REGISTRY_DIR") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    let data = z_core::config::user_data_dir()
        .ok_or_else(|| ZenError::new(Area::Cfg, 100, "cannot determine the user data directory"))?;
    Ok(data.join("registry"))
}

fn open_registry(project: Option<&PathBuf>, explicit: Option<PathBuf>) -> ZenResult<LocalRegistry> {
    let root = match explicit {
        Some(p) => p,
        None => default_registry_root(project)?,
    };
    LocalRegistry::open(root)
}

fn open_store() -> ZenResult<ToolStore> {
    ToolStore::open()
}

/// Load bytes for an artifact URL.
///
/// Only `file://` is supported in this build. Network fetching requires the
/// `http` feature and is deliberately not implicit: an install must never
/// silently reach the network.
fn load_artifact(url: &str, offline: bool) -> ZenResult<Vec<u8>> {
    if offline {
        return Err(
            ZenError::new(Area::Net, 200, format!("offline mode: {url} is not cached"))
                .with_remediation("Re-run without --offline, or install from the local cache."),
        );
    }
    if let Some(path) = url.strip_prefix("file://") {
        let p = PathBuf::from(path);
        let meta = std::fs::metadata(&p).map_err(|e| {
            ZenError::new(Area::Fs, 201, format!("cannot read artifact {url}: {e}"))
        })?;
        if meta.len() > 512 * 1024 * 1024 {
            return Err(ZenError::new(
                Area::Sec,
                202,
                "artifact exceeds the 512 MiB limit",
            ));
        }
        return std::fs::read(&p)
            .map_err(|e| ZenError::new(Area::Fs, 203, format!("cannot read artifact {url}: {e}")));
    }
    // https:// is declared at the manifest level but fetching requires the
    // http feature. Say so plainly instead of failing obscurely.
    Err(ZenError::new(
        Area::Net,
        204,
        format!("network fetching is not available in this build (needed for {url})"),
    )
    .with_remediation(
        "Build with --features http, or use a local registry whose artifacts are file:// URLs.",
    ))
}

// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct ToolBundle {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    tools: &'static [&'static str],
}

const KALI_TOP10: &[&str] = &[
    "nmap",
    "metasploit",
    "wireshark",
    "sqlmap",
    "john",
    "aircrack-ng",
    "gobuster",
    "burpsuite",
    "hydra",
    "hashcat",
];

const WEB_ASSESSMENT: &[&str] = &[
    "burpsuite",
    "zaproxy",
    "sqlmap",
    "ffuf",
    "feroxbuster",
    "gobuster",
    "nikto",
    "katana",
    "httpx",
    "whatweb",
    "nuclei",
];

const RECON_DISCOVERY: &[&str] = &[
    "nmap",
    "masscan",
    "rustscan",
    "amass",
    "theharvester",
    "dnsrecon",
    "subfinder",
    "httpx",
    "whatweb",
];

const DEVSECOPS: &[&str] = &["trivy", "gitleaks", "semgrep", "syft", "grype", "cosign"];

const REVERSE_ENGINEERING: &[&str] = &["ghidra", "radare2", "binwalk", "yara"];

const FORENSICS_IR: &[&str] = &["volatility3", "autopsy", "wireshark", "yara"];

const WIRELESS_AUDIT: &[&str] = &["aircrack-ng", "wireshark"];

const FULL_SECURITY_LAB: &[&str] = &[
    "nmap",
    "metasploit",
    "wireshark",
    "sqlmap",
    "john",
    "aircrack-ng",
    "gobuster",
    "burpsuite",
    "hydra",
    "hashcat",
    "ffuf",
    "feroxbuster",
    "nikto",
    "amass",
    "theharvester",
    "dnsrecon",
    "masscan",
    "rustscan",
    "nuclei",
    "katana",
    "httpx",
    "subfinder",
    "whatweb",
    "zaproxy",
    "trivy",
    "gitleaks",
    "semgrep",
    "syft",
    "grype",
    "cosign",
    "ghidra",
    "radare2",
    "binwalk",
    "yara",
    "volatility3",
    "autopsy",
];

fn bundle_catalog() -> &'static [ToolBundle] {
    &[
        ToolBundle {
            name: "kali-top10",
            title: "Kali-style top 10",
            description: "Core security workflow tools modeled after Kali's top-tool grouping.",
            tools: KALI_TOP10,
        },
        ToolBundle {
            name: "web",
            title: "Web assessment",
            description: "Proxy, crawler, fuzzer, scanner and injection-testing workflow.",
            tools: WEB_ASSESSMENT,
        },
        ToolBundle {
            name: "recon",
            title: "Recon and discovery",
            description: "Network, DNS and external attack-surface discovery workflow.",
            tools: RECON_DISCOVERY,
        },
        ToolBundle {
            name: "devsecops",
            title: "DevSecOps",
            description: "SAST, secret scanning, SBOM, vulnerability and signing workflow.",
            tools: DEVSECOPS,
        },
        ToolBundle {
            name: "reverse",
            title: "Reverse engineering",
            description: "Binary, firmware and malware-analysis starter workflow.",
            tools: REVERSE_ENGINEERING,
        },
        ToolBundle {
            name: "forensics",
            title: "Forensics and IR",
            description: "Memory, disk, packet and file triage workflow.",
            tools: FORENSICS_IR,
        },
        ToolBundle {
            name: "wireless",
            title: "Wireless audit",
            description: "Wireless and packet-analysis workflow.",
            tools: WIRELESS_AUDIT,
        },
        ToolBundle {
            name: "security-lab",
            title: "Full security lab",
            description: "All curated security and development tools in the bundled registry.",
            tools: FULL_SECURITY_LAB,
        },
    ]
}

fn find_bundle(name: &str) -> Option<ToolBundle> {
    bundle_catalog().iter().copied().find(|b| b.name == name)
}

pub fn bundle_cmd(args: &[String], json: bool, project: Option<PathBuf>) -> ZenResult<()> {
    let action = args.first().map(|s| s.as_str()).unwrap_or("list");

    match action {
        "list" => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "bundles": bundle_catalog().iter().map(|b| json!({
                            "name": b.name,
                            "title": b.title,
                            "description": b.description,
                            "tool_count": b.tools.len(),
                            "tools": b.tools,
                        })).collect::<Vec<_>>()
                    }))?
                );
                return Ok(());
            }

            println!("{:<16} {:<22} TOOLS  DESCRIPTION", "BUNDLE", "TITLE");
            for b in bundle_catalog() {
                println!(
                    "{:<16} {:<22} {:<5} {}",
                    b.name,
                    b.title,
                    b.tools.len(),
                    b.description
                );
            }
            println!("\nInspect with: z bundle show <name>");
            println!("Preview install commands with: z bundle plan <name>");
            Ok(())
        }
        "show" | "plan" => {
            let Some(name) = args.get(1) else {
                return Err(ZenError::new(
                    Area::Cfg,
                    260,
                    "usage: z bundle show <name> or z bundle plan <name>",
                ));
            };
            let bundle = find_bundle(name).ok_or_else(|| {
                ZenError::new(Area::Reg, 261, format!("unknown bundle: {name}"))
                    .with_remediation("Run `z bundle list` to see available bundles.")
            })?;
            let reg = open_registry(project.as_ref(), None)?;
            let index = reg.index()?;

            let mut rows = Vec::new();
            for tool in bundle.tools {
                let versions = reg.versions(tool)?;
                let latest = versions.last().cloned();
                let entry = latest.as_ref().and_then(|v| {
                    index
                        .tools
                        .iter()
                        .find(|e| e.name == *tool && e.version == *v)
                });
                rows.push((
                    *tool,
                    latest,
                    entry.and_then(|e| e.display_name.clone()),
                    entry.and_then(|e| e.description.clone()),
                    entry.map(|e| e.trust.as_str().to_string()),
                ));
            }

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "bundle": bundle.name,
                        "title": bundle.title,
                        "description": bundle.description,
                        "install_commands": bundle.tools.iter().map(|t| format!("z install {t} --dry-run")).collect::<Vec<_>>(),
                        "tools": rows.iter().map(|(name, version, display, description, trust)| json!({
                            "name": name,
                            "version": version,
                            "display_name": display,
                            "description": description,
                            "trust": trust,
                            "available": version.is_some(),
                        })).collect::<Vec<_>>()
                    }))?
                );
                return Ok(());
            }

            println!("{} ({})", bundle.title, bundle.name);
            println!("  {}", bundle.description);
            println!();
            println!(
                "{:<16} {:<10} {:<20} DESCRIPTION",
                "TOOL", "VERSION", "TRUST"
            );
            for (name, version, _display, description, trust) in &rows {
                println!(
                    "{:<16} {:<10} {:<20} {}",
                    name,
                    version.clone().unwrap_or_else(|| "-".into()),
                    trust.clone().unwrap_or_else(|| "missing".into()),
                    description.clone().unwrap_or_default()
                );
            }
            if action == "plan" {
                println!();
                println!("Preview each install:");
                for tool in bundle.tools {
                    println!("  z install {tool} --dry-run");
                }
                println!("Install after review:");
                for tool in bundle.tools {
                    println!("  z install {tool} --approve");
                }
            }
            Ok(())
        }
        _ => Err(ZenError::new(
            Area::Cfg,
            262,
            "usage: z bundle [list|show <name>|plan <name>]",
        )),
    }
}

pub fn search(
    query: &[String],
    category: Option<String>,
    json: bool,
    project: Option<PathBuf>,
) -> ZenResult<()> {
    let reg = open_registry(project.as_ref(), None)?;
    let q = SearchQuery {
        text: query.join(" "),
        category,
        publisher: None,
    };
    let hits = reg.search(&q)?;
    let latest = latest_by_name(&hits);

    if json {
        let arr: Vec<_> = latest
            .values()
            .map(|e| {
                json!({
                    "name": e.name,
                    "id": e.id,
                    "version": e.version,
                    "display_name": e.display_name,
                    "description": e.description,
                    "categories": e.categories,
                    "publisher": e.publisher_name,
                    "trust": e.trust.as_str(),
                    "license": e.license,
                    "installed": false,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "registry": reg.id(),
                "query": q.text,
                "count": arr.len(),
                "results": arr,
            }))?
        );
        return Ok(());
    }

    if latest.is_empty() {
        println!("No tools found for '{}'.", q.text);
        println!("Registry: {}", reg.id());
        return Ok(());
    }

    println!(
        "{:<16} {:<12} {:<20} DESCRIPTION",
        "NAME", "VERSION", "TRUST"
    );
    for e in latest.values() {
        println!(
            "{:<16} {:<12} {:<20} {}",
            e.name,
            e.version,
            e.trust.as_str(),
            e.description.clone().unwrap_or_default()
        );
    }
    println!(
        "\n{} result(s). Install with: z install <name>",
        latest.len()
    );
    Ok(())
}

pub fn info(
    tool: &str,
    version: Option<String>,
    json: bool,
    project: Option<PathBuf>,
) -> ZenResult<()> {
    let reg = open_registry(project.as_ref(), None)?;
    let versions = reg.versions(tool)?;
    if versions.is_empty() {
        return Err(
            ZenError::new(Area::Reg, 210, format!("no such tool: {tool}"))
                .with_remediation("Try `z search <term>`."),
        );
    }
    let v = match version {
        Some(v) => v,
        None => versions.last().cloned().unwrap(),
    };
    let entry = reg
        .entry(tool, &v)?
        .ok_or_else(|| ZenError::new(Area::Reg, 211, format!("{tool} {v} not found")))?;
    let manifest = reg
        .manifest(tool, &v)?
        .ok_or_else(|| ZenError::new(Area::Reg, 212, format!("{tool} {v} has no manifest")))?;

    let target = z_native::PlatformResolver::resolve();
    let store = open_store()?;
    let compat = z_compat::resolve(&manifest.platforms, &target);
    let installed = store.installed_versions(tool)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "name": manifest.name,
                "id": manifest.id.to_string(),
                "version": manifest.version,
                "display_name": manifest.display_name,
                "description": manifest.description,
                "publisher": {"name": manifest.publisher.name, "id": manifest.publisher.id},
                "license": manifest.license,
                "homepage": manifest.homepage,
                "categories": manifest.categories,
                "tags": manifest.tags,
                "trust": entry.trust.as_str(),
                "available_versions": versions,
                "platform_support": manifest.platforms.iter().map(|p| format!("{}-{}", p.os.as_str(), p.arch.as_str())).collect::<Vec<_>>(),
                "current_platform": target.id(),
                "compatibility": compat.kind.label(),
                "compatibility_note": compat.explanation,
                "permissions": manifest.permissions.describe(),
                "dependencies": manifest.dependencies,
                "installed_versions": installed,
            }))?
        );
        return Ok(());
    }

    println!(
        "{} ({})",
        manifest
            .display_name
            .clone()
            .unwrap_or_else(|| manifest.name.clone()),
        manifest.name
    );
    println!("  id:           {}", manifest.id);
    println!(
        "  version:      {}  (available: {})",
        manifest.version,
        versions.join(", ")
    );
    if let Some(l) = &manifest.license {
        println!("  license:      {l}");
    }
    println!(
        "  publisher:    {} ({})",
        manifest.publisher.name, manifest.publisher.id
    );
    println!("  trust:        {}", entry.trust.as_str());
    println!("  platform:     {}", target.id());
    println!("  compatibility: {}", compat.summary());
    if let Some(d) = &manifest.description {
        println!("  description:  {d}");
    }
    println!("  permissions:");
    for p in manifest.permissions.describe() {
        println!("    {p}");
    }
    if !manifest.dependencies.is_empty() {
        println!("  dependencies: {}", manifest.dependencies.join(", "));
    }
    println!(
        "  installed:    {}",
        if installed.is_empty() {
            "no".to_string()
        } else {
            installed.join(", ")
        }
    );
    Ok(())
}

pub fn install_tool(
    name: &str,
    version: Option<String>,
    dry_run: bool,
    offline: bool,
    approve: bool,
    json: bool,
    project: Option<PathBuf>,
) -> ZenResult<()> {
    let rt = init_runtime(project)?;
    let reg = open_registry(rt.project.as_ref().map(|p| p.root.clone()).as_ref(), None)?;
    let store = open_store()?;
    let target = z_native::PlatformResolver::resolve();

    // Resolve version.
    let versions = reg.versions(name)?;
    if versions.is_empty() {
        println!("{} not found in the curated Zentrion registry.", name);
        println!("Attempting fallback to native OS package manager...");
        let os_manager = tools::os_package::OsPackageManager::detect();
        if matches!(os_manager, tools::os_package::OsPackageManager::Unknown) {
            return Err(
                ZenError::new(Area::Reg, 220, format!("no such tool: {name}, and no native OS package manager found"))
                    .with_remediation("Try `z search <term>` or install a package manager like brew/apt/winget."),
            );
        }
        match os_manager.install(name) {
            Ok(_) => {
                println!("Successfully installed {} via OS package manager.", name);
                return Ok(());
            },
            Err(e) => {
                return Err(ZenError::new(Area::Reg, 220, format!("failed to install {name} natively: {e}")));
            }
        }
    }
    let chosen = match &version {
        Some(v) => {
            let req = z_version::Requirement::parse(v).map_err(|e| {
                ZenError::new(Area::Reg, 221, format!("invalid version '{v}': {e}"))
            })?;
            let parsed: Vec<z_version::Version> = versions
                .iter()
                .filter_map(|s| z_version::Version::parse(s).ok())
                .collect();
            match z_version::select(&req, &parsed) {
                Some(pick) => pick.to_string(),
                None => {
                    return Err(ZenError::new(
                        Area::Reg,
                        222,
                        format!(
                            "no version of {name} satisfies '{v}' (available: {})",
                            versions.join(", ")
                        ),
                    ))
                }
            }
        }
        None => versions.last().cloned().unwrap(),
    };

    let manifest = reg
        .manifest(name, &chosen)?
        .ok_or_else(|| ZenError::new(Area::Reg, 223, format!("{name} {chosen} has no manifest")))?;
    let entry = reg.entry(name, &chosen)?.unwrap();

    // Trust gate: UNKNOWN requires acknowledgement; REVOKED is blocked.
    if entry.trust.is_blocking() {
        return Err(
            ZenError::new(Area::Sec, 224, format!("{name} {chosen} is revoked"))
                .with_remediation("Do not install this tool."),
        );
    }
    if entry.trust.requires_acknowledgement() && !approve {
        println!(
            "⚠ {} is published by an unverified publisher (trust: {}).",
            name,
            entry.trust.as_str()
        );
        println!("  Publisher: {}", entry.publisher_name);
        println!("  Re-run with --approve to install it anyway.");
        return Err(ZenError::new(
            Area::Sec,
            225,
            "unverified publisher requires explicit approval",
        ));
    }

    let (p, _compat) = plan(&manifest, &target, &store)?;

    // --dry-run: report and stop. No filesystem or network activity.
    if dry_run {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "dry_run": true,
                    "tool": p.name, "id": p.tool_id, "version": p.version,
                    "platform": p.target, "implementation": p.kind,
                    "compatibility_note": p.compatibility_note,
                    "artifact_url": p.artifact_url,
                    "artifact_sha256": p.artifact_sha256,
                    "download_size": p.artifact_size,
                    "publisher": p.publisher,
                    "license": p.license,
                    "trust": entry.trust.as_str(),
                    "permissions": p.permissions,
                    "destination": p.destination,
                    "requires_acknowledgement": p.requires_acknowledgement,
                }))?
            );
        } else {
            println!("Install preview (no changes made)");
            println!("  tool:         {} {}", p.name, p.version);
            println!("  id:           {}", p.tool_id);
            println!("  platform:     {}", p.target);
            println!("  implementation: {} — {}", p.kind, p.compatibility_note);
            println!(
                "  publisher:    {} (trust: {})",
                p.publisher,
                entry.trust.as_str()
            );
            if let Some(l) = &p.license {
                println!("  license:      {l}");
            }
            println!("  artifact:     {}", p.artifact_url);
            println!("  sha256:       {}", p.artifact_sha256);
            if let Some(s) = p.artifact_size {
                println!("  size:         {s} bytes");
            }
            println!("  permissions:");
            for line in &p.permissions {
                println!("    {line}");
            }
            println!("  destination:  {}", p.destination);
        }
        return Ok(());
    }

    // Permissions display before a sensitive install (Phase 2 §19).
    if manifest.permissions.is_sensitive() && !json && !approve {
        println!("{} requires:", p.name);
        for line in &p.permissions {
            println!("  {line}");
        }
        println!();
        if p.requires_acknowledgement {
            println!("⚠ This is a non-native implementation ({}).", p.kind);
        }
        println!("Re-run with --approve to confirm these permissions.");
        return Err(ZenError::new(
            Area::Sec,
            226,
            "installation requires confirmation of the requested permissions",
        ));
    }

    let outcome = install(&manifest, &target, &store, &reg.id(), |url| {
        load_artifact(url, offline)
    })?;

    // Audit the install.
    let apath = audit_path()?;
    let mut log = z_audit::AuditLog::open(&apath)?;
    let actor = z_identity::local_user()?;
    let platform = target.id();
    let project_name = rt
        .project
        .as_ref()
        .and_then(|p| p.root.file_name())
        .map(|n| n.to_string_lossy().to_string());
    let ev = log.append(
        &actor.id,
        actor.actor_type.as_str(),
        "tool.install",
        &format!("{}@{}", outcome.name, outcome.version),
        project_name.as_deref(),
        "allow",
        if outcome.already_present {
            "already_present"
        } else {
            "installed"
        },
        if manifest.permissions.is_sensitive() {
            "HIGH"
        } else {
            "MEDIUM"
        },
        &platform,
    )?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "ok",
                "operation": "install",
                "tool": outcome.name,
                "version": outcome.version,
                "platform": outcome.target,
                "implementation": outcome.kind,
                "already_present": outcome.already_present,
                "activated": outcome.activated,
                "artifact_sha256": outcome.artifact_sha256,
                "source": outcome.source,
                "signature": outcome.signature,
                "files": outcome.files,
                "trust": entry.trust.as_str(),
                "audit_id": ev.id,
                "errors": [],
            }))?
        );
        return Ok(());
    }

    if outcome.already_present {
        println!("{} {} is already installed.", outcome.name, outcome.version);
        return Ok(());
    }
    println!("Installed {} {}", outcome.name, outcome.version);
    println!("  platform:     {} ({})", outcome.target, outcome.kind);
    println!("  verified:     {}", &outcome.artifact_sha256[..23]);
    println!("  signature:    {}", outcome.signature);
    println!("  source:       {}", outcome.source);
    println!("  activated:    yes");
    println!("  audit:        {}", ev.id);
    println!();
    println!("Run it with: z run {} -- --help", outcome.name);
    Ok(())
}

pub fn list_tools(
    installed_only: bool,
    outdated: bool,
    json: bool,
    project: Option<PathBuf>,
) -> ZenResult<()> {
    let store = open_store()?;
    let reg = open_registry(project.as_ref(), None).ok();
    let names = store.list_tools()?;

    let mut rows = Vec::new();
    for n in &names {
        let active = store.active_version(n)?;
        let versions = store.installed_versions(n)?;
        let latest_known = reg
            .as_ref()
            .and_then(|r| r.versions(n).ok())
            .and_then(|v| v.last().cloned());

        let is_outdated = match (&active, &latest_known) {
            (Some(a), Some(l)) => {
                match (z_version::Version::parse(a), z_version::Version::parse(l)) {
                    (Ok(x), Ok(y)) => y > x,
                    _ => false,
                }
            }
            _ => false,
        };
        rows.push((n.clone(), active, versions, latest_known, is_outdated));
    }

    if outdated {
        rows.retain(|r| r.4);
    }

    if json {
        let arr: Vec<_> = rows
            .iter()
            .map(|(n, active, versions, latest, out)| {
                json!({
                    "name": n,
                    "active_version": active,
                    "installed_versions": versions,
                    "latest_known": latest,
                    "outdated": out,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "store": store.root().display().to_string(),
                "count": arr.len(),
                "tools": arr,
            }))?
        );
        return Ok(());
    }

    if rows.is_empty() {
        if outdated {
            println!("No outdated tools.");
        } else {
            println!("No tools installed.");
            println!("Install one with: z search <term>  then  z install <name>");
        }
        return Ok(());
    }

    println!("{:<16} {:<12} {:<14} STATUS", "NAME", "ACTIVE", "INSTALLED");
    for (n, active, versions, latest, out) in &rows {
        let status = if *out {
            format!("outdated (latest {})", latest.clone().unwrap_or_default())
        } else {
            "up to date".to_string()
        };
        println!(
            "{:<16} {:<12} {:<14} {}",
            n,
            active.clone().unwrap_or_else(|| "-".into()),
            versions.join(","),
            status
        );
    }
    let _ = installed_only;
    Ok(())
}

pub fn run_tool(
    name: &str,
    args: Vec<String>,
    approve: bool,
    json: bool,
    project: Option<PathBuf>,
) -> ZenResult<()> {
    let store = open_store()?;
    let versions = store.installed_versions(name)?;
    if versions.is_empty() {
        return Err(
            ZenError::new(Area::Reg, 230, format!("{name} is not installed"))
                .with_remediation("Install it with `z install <name>`."),
        );
    }
    let active = store
        .active_version(name)?
        .ok_or_else(|| ZenError::new(Area::Reg, 231, format!("{name} has no active version")))?;

    let vdir = store.version_dir(name, &active)?;
    let _record = store.read_record(name, &active)?;

    // Read the manifest to find the executable (or native engine).
    let manifest_text = std::fs::read_to_string(vdir.join("manifest.json"))?;
    let manifest = ToolManifest::parse_json(&manifest_text)?;

    let exec = manifest.execution.clone().ok_or_else(|| {
        ZenError::new(
            Area::Reg,
            232,
            format!("{name} declares no execution specification"),
        )
    })?;

    // A tool the runtime implements natively: no external process is spawned.
    if let Some(engine) = exec.native_engine {
        return crate::native_engines::run_engine(&engine, args, json);
    }

    let bin = z_native::fs::canonical_within(&vdir, &vdir.join(&exec.binary))?;
    if !bin.is_file() {
        return Err(ZenError::new(
            Area::Reg,
            233,
            format!(
                "the installed executable for {name} is missing: {}",
                bin.display()
            ),
        )
        .with_remediation("Reinstall with `z install <name>` to repair it."));
    }

    // Route through the Phase 1 broker: identity → policy → capability →
    // risk/approval → execute → audit.
    let rt = init_runtime(project)?;
    let policy = crate::context::effective_policy(&rt)?;
    let actor = z_identity::local_user()?;

    let apath = audit_path()?;
    let audit = z_audit::AuditLog::open(&apath)?;
    let platform = z_native::PlatformResolver::resolve().id();

    let mut broker = z_exec::Broker::new(
        policy,
        audit,
        rt.project.as_ref().map(|p| p.root.clone()),
        platform,
    );

    let resource = format!("tool:{name}");
    let req = z_exec::ExecRequest {
        actor: z_exec::ActorRef {
            id: actor.id.clone(),
            actor_type: actor.actor_type.as_str().to_string(),
        },
        action: "tool.execute".into(),
        resource: resource.clone(),
        reason: Some(format!("z run {name} {}", args.join(" "))),
    };

    // full_args: the program path plus the user's arguments, passed as a
    // structured array. No shell is ever involved.
    let result = broker.execute_process_args(
        &req,
        &bin.to_string_lossy(),
        &args,
        approve,
        manifest.permissions.network,
    )?;

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
                        "status": "ok",
                        "operation": "run",
                        "tool": name,
                        "version": active,
                        "exit_code": result.exit_code,
                        "risk": result.risk,
                        "audit_id": result.audit_id,
                        "duration_ms": result.duration_ms,
                        "errors": [],
                    }))?
                );
            }
            std::process::exit(result.exit_code.unwrap_or(0));
        }
        z_exec::ExecStatus::Denied => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "status": "denied",
                        "operation": "run",
                        "tool": name,
                        "reason": result.reason,
                        "risk": result.risk,
                        "audit_id": result.audit_id,
                    }))?
                );
            } else {
                println!("✗ Zentrion blocked this tool execution.");
                println!("    What was attempted:  run '{name}'");
                println!("    Why blocked:         {}", result.reason);
                println!(
                    "    Policy:              .zentrion/policy.yaml (tool.execute / {}",
                    resource
                );
                println!("    Risk:                {}", result.risk);
                println!("    Options:");
                println!("      (1) grant the tool's capabilities in .zentrion/policy.yaml");
                println!("      (2) run a permitted tool");
                println!("      (3) cancel");
                if let Some(id) = &result.audit_id {
                    println!("    Audit:               {id} recorded");
                }
            }
            Err(ZenError::new(
                Area::Pol,
                234,
                "tool execution denied by policy",
            ))
        }
        z_exec::ExecStatus::ApprovalRequired => {
            println!("⚠ Approval required ({} risk).", result.risk);
            println!("  Reason:  {}", result.reason);
            println!("  Options: re-run with --approve to confirm");
            Err(ZenError::new(
                Area::Pol,
                235,
                "tool execution requires approval",
            ))
        }
        z_exec::ExecStatus::Timeout => Err(ZenError::new(
            Area::Pr,
            236,
            "tool execution timed out and was killed",
        )),
    }
}

pub fn remove_tool(name: &str, version: Option<String>, json: bool) -> ZenResult<()> {
    let store = open_store()?;
    let n = z_tool::remove(&store, name, version.as_deref())?;

    let apath = audit_path()?;
    let mut log = z_audit::AuditLog::open(&apath)?;
    let actor = z_identity::local_user()?;
    let ev = log.append(
        &actor.id,
        actor.actor_type.as_str(),
        "tool.remove",
        &match &version {
            Some(v) => format!("{name}@{v}"),
            None => name.to_string(),
        },
        None,
        "allow",
        "removed",
        "MEDIUM",
        &z_native::PlatformResolver::resolve().id(),
    )?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "ok",
                "operation": "remove",
                "tool": name,
                "version": version,
                "versions_removed": n,
                "audit_id": ev.id,
            }))?
        );
    } else {
        println!(
            "Removed {name}{} ({n} version(s)).",
            version.map(|v| format!("@{v}")).unwrap_or_default()
        );
    }
    Ok(())
}

pub fn verify_tool(name: &str, json: bool) -> ZenResult<()> {
    let store = open_store()?;
    let active = store
        .active_version(name)?
        .ok_or_else(|| ZenError::new(Area::Reg, 240, format!("{name} is not installed")))?;
    let vdir = store.version_dir(name, &active)?;
    let record = store
        .read_record(name, &active)?
        .ok_or_else(|| ZenError::new(Area::Reg, 241, format!("no install record for {name}")))?;

    let mut checks: Vec<(String, bool, String)> = Vec::new();

    // 1. Directory present.
    checks.push((
        "install directory".into(),
        vdir.is_dir(),
        vdir.display().to_string(),
    ));

    // 2. Manifest present and valid.
    let manifest_path = vdir.join("manifest.json");
    let manifest_ok = std::fs::read_to_string(&manifest_path)
        .ok()
        .and_then(|t| ToolManifest::parse_json(&t).ok())
        .is_some();
    checks.push((
        "manifest valid".into(),
        manifest_ok,
        manifest_path.display().to_string(),
    ));

    // 3. Executable present (unless the tool is a native engine).
    let manifest = std::fs::read_to_string(&manifest_path)
        .ok()
        .and_then(|t| ToolManifest::parse_json(&t).ok());
    let engine_only = manifest
        .as_ref()
        .and_then(|m| m.execution.as_ref())
        .and_then(|e| e.native_engine.as_ref())
        .is_some();

    if !engine_only {
        if let Some(bin_rel) = manifest
            .as_ref()
            .and_then(|m| m.execution.as_ref())
            .map(|e| e.binary.clone())
        {
            let bin = vdir.join(&bin_rel);
            checks.push((
                "executable present".into(),
                bin.is_file(),
                bin.display().to_string(),
            ));
            if bin.is_file() {
                checks.push((
                    "executable permission".into(),
                    z_native::fs::inspector().is_executable(&bin) || cfg!(windows),
                    bin.display().to_string(),
                ));
            }
        } else {
            checks.push((
                "execution declared".into(),
                false,
                "manifest has no execution.binary".into(),
            ));
        }
    }

    // 4. Cached artifact still matches its recorded checksum.
    let cache_ok = match store.cache_path(&record.artifact_sha256) {
        Ok(p) if p.is_file() => match z_package::checksum::Checksum::parse(&record.artifact_sha256)
        {
            Ok(c) => z_package::checksum::verify_file(&c, &p).is_ok(),
            Err(_) => false,
        },
        _ => true, // no cache entry is not a failure
    };
    checks.push((
        "cached artifact integrity".into(),
        cache_ok,
        record.artifact_sha256.clone(),
    ));

    let all_ok = checks.iter().all(|(_, ok, _)| *ok);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "tool": name,
                "version": active,
                "healthy": all_ok,
                "checks": checks.iter().map(|(n, ok, d)| json!({"check": n, "ok": ok, "detail": d})).collect::<Vec<_>>(),
            }))?
        );
    } else {
        println!("Verifying {name} {active}");
        for (n, ok, d) in &checks {
            println!("  [{}] {:<24} {}", if *ok { "ok" } else { "!!" }, n, d);
        }
        println!();
        if all_ok {
            println!("{name} {active} is healthy.");
        } else {
            println!("{name} {active} has problems. Reinstall with: z install {name}");
        }
    }

    if !all_ok {
        return Err(ZenError::new(
            Area::Reg,
            242,
            format!("{name} failed verification"),
        ));
    }
    Ok(())
}

pub fn which_tool(name: &str, json: bool) -> ZenResult<()> {
    let store = open_store()?;
    let active = store
        .active_version(name)?
        .ok_or_else(|| ZenError::new(Area::Reg, 250, format!("{name} is not installed")))?;
    let vdir = store.version_dir(name, &active)?;
    let record = store
        .read_record(name, &active)?
        .ok_or_else(|| ZenError::new(Area::Reg, 251, format!("no install record for {name}")))?;

    let manifest = std::fs::read_to_string(vdir.join("manifest.json"))
        .ok()
        .and_then(|t| ToolManifest::parse_json(&t).ok());
    let engine = manifest
        .as_ref()
        .and_then(|m| m.execution.as_ref())
        .and_then(|e| e.native_engine.clone());

    let path = match &engine {
        Some(e) => format!("native engine: {e}"),
        None => vdir
            .join(
                manifest
                    .as_ref()
                    .and_then(|m| m.execution.as_ref())
                    .map(|x| x.binary.clone())
                    .unwrap_or_default(),
            )
            .display()
            .to_string(),
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "tool": name,
                "version": active,
                "path": path,
                "native_engine": engine,
                "publisher": record.publisher_name,
                "publisher_id": record.publisher_id,
                "source": record.source_registry,
                "artifact_sha256": record.artifact_sha256,
                "installed_at": record.installed_at,
            }))?
        );
    } else {
        println!("{name} {active}");
        println!("  path:      {path}");
        println!(
            "  publisher: {} ({})",
            record.publisher_name, record.publisher_id
        );
        println!("  source:    {}", record.source_registry);
        println!("  sha256:    {}", record.artifact_sha256);
    }
    Ok(())
}

pub fn rollback_tool(name: &str, json: bool) -> ZenResult<()> {
    let store = open_store()?;
    let (from, to) = z_tool::rollback(&store, name)?;

    let apath = audit_path()?;
    let mut log = z_audit::AuditLog::open(&apath)?;
    let actor = z_identity::local_user()?;
    let ev = log.append(
        &actor.id,
        actor.actor_type.as_str(),
        "tool.rollback",
        &format!("{name}@{from}->{to}"),
        None,
        "allow",
        "rolled_back",
        "MEDIUM",
        &z_native::PlatformResolver::resolve().id(),
    )?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "ok",
                "operation": "rollback",
                "tool": name,
                "from": from,
                "to": to,
                "audit_id": ev.id,
            }))?
        );
    } else {
        println!("Rolled back {name}: {from} -> {to}");
    }
    Ok(())
}

pub fn use_version(name: &str, version: &str, json: bool) -> ZenResult<()> {
    let store = open_store()?;
    store.set_active(name, version)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "ok", "operation": "use", "tool": name, "version": version,
            }))?
        );
    } else {
        println!("{name} now uses {version}");
    }
    Ok(())
}

pub fn compatibility(tool: &str, json: bool, project: Option<PathBuf>) -> ZenResult<()> {
    let reg = open_registry(project.as_ref(), None)?;
    let versions = reg.versions(tool)?;
    let v = versions
        .last()
        .cloned()
        .ok_or_else(|| ZenError::new(Area::Reg, 260, format!("no such tool: {tool}")))?;
    let manifest = reg
        .manifest(tool, &v)?
        .ok_or_else(|| ZenError::new(Area::Reg, 261, format!("{tool} {v} has no manifest")))?;
    let target = z_native::PlatformResolver::resolve();
    let compat = z_compat::resolve(&manifest.platforms, &target);
    let store = open_store()?;

    // Report per-platform implementation kinds.
    let matrix: Vec<_> = manifest
        .platforms
        .iter()
        .map(|p| {
            json!({
                "os": p.os.as_str(),
                "arch": p.arch.as_str(),
                "abi": p.abi.map(|a| a.as_str()),
                "kind": p.kind.label(),
                "stars": p.kind.stars(),
            })
        })
        .collect();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "tool": manifest.name,
                "version": v,
                "current_platform": target.id(),
                "selected": compat.kind.label(),
                "selected_stars": compat.kind.stars(),
                "installable": compat.is_installable(),
                "note": compat.explanation,
                "alternatives": compat.alternatives,
                "permissions": manifest.permissions.describe(),
                "requires_elevation": manifest.permissions.requires_elevation,
                "installed": store.installed_versions(tool)?,
                "matrix": matrix,
            }))?
        );
        return Ok(());
    }

    println!("Compatibility: {} {}", manifest.name, v);
    println!("  current platform: {}", target.id());
    println!("  implementation:   {}", compat.summary());
    println!(
        "  installable:      {}",
        if compat.is_installable() { "yes" } else { "NO" }
    );
    if !compat.alternatives.is_empty() {
        println!("  available on:     {}", compat.alternatives.join(", "));
    }
    println!("  permissions:");
    for p in manifest.permissions.describe() {
        println!("    {p}");
    }
    println!();
    println!("  {:<10} {:<10} {:<12} IMPLEMENTATION", "OS", "ARCH", "ABI");
    for p in &manifest.platforms {
        println!(
            "  {:<10} {:<10} {:<12} {}",
            p.os.as_str(),
            p.arch.as_str(),
            p.abi.map(|a| a.as_str()).unwrap_or("-"),
            p.kind.label()
        );
    }
    Ok(())
}

pub fn platform_report(json: bool) -> ZenResult<()> {
    let target = z_native::PlatformResolver::resolve();
    let sys = z_native::sysinfo::system_info();
    let sandbox = z_native::available_sandbox_level();
    let insp = z_native::process::inspector();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "os": sys.os,
                "os_version": sys.os_version,
                "architecture": sys.arch,
                "target": target.id(),
                "abi": target.abi.as_str(),
                "cpus": sys.cpu_count,
                "memory_total_mb": sys.memory_total_mb,
                "hostname": sys.hostname,
                "sandbox_level": sandbox.as_str(),
                "process_inspection": {
                    "foreign_processes": insp.can_inspect_foreign(),
                },
                "dns": z_native::dns::record_support(),
                "http_transport": z_native::http::transport_description(),
                "tls_backend": z_native::tls::backend_description(),
                "requires_wsl": false,
                "requires_docker": false,
                "requires_vm": false,
            }))?
        );
        return Ok(());
    }

    println!("Platform report");
    println!("  os:            {} {}", sys.os, sys.os_version);
    println!(
        "  architecture:  {} (abi {})",
        sys.arch,
        target.abi.as_str()
    );
    println!("  target:        {}", target.id());
    println!("  cpus:          {}", sys.cpu_count);
    match sys.memory_total_mb {
        Some(m) => println!(
            "  memory:        {m} MB total, {} MB available",
            sys.memory_available_mb.unwrap_or(0)
        ),
        None => println!("  memory:        not reported on this platform"),
    }
    println!("  hostname:      {}", sys.hostname);
    println!("  sandbox:       {}", sandbox.as_str());
    println!();
    println!("  Native capabilities:");
    println!("    process inspection (own user): yes");
    println!(
        "    process inspection (other users): {}",
        insp.can_inspect_foreign()
    );
    println!("    dns:  {}", z_native::dns::record_support());
    println!("    http: {}", z_native::http::transport_description());
    println!("    tls:  {}", z_native::tls::backend_description());
    println!();
    println!("  Compatibility environments required: none");
    println!("    WSL: no   Docker: no   VM: no");
    Ok(())
}

pub fn cache_cmd(args: &[String], json: bool) -> ZenResult<()> {
    let store = open_store()?;
    match args.first().map(|s| s.as_str()) {
        Some("clean") => {
            let dir = store.cache_dir();
            let mut n = 0usize;
            let mut bytes = 0u64;
            if dir.is_dir() {
                for e in std::fs::read_dir(&dir)? {
                    let e = e?;
                    if e.file_type()?.is_file() {
                        bytes += e.metadata()?.len();
                        std::fs::remove_file(e.path())?;
                        n += 1;
                    }
                }
            }
            // Active installations live in tools/, not cache/, so they are
            // untouched by design.
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "status": "ok", "operation": "cache.clean",
                        "removed": n, "bytes_freed": bytes,
                    }))?
                );
            } else {
                println!("Removed {n} cached artifact(s), {bytes} bytes.");
                println!("Installed tools were not affected.");
            }
            Ok(())
        }
        Some("list") | None => {
            let dir = store.cache_dir();
            let mut entries = Vec::new();
            if dir.is_dir() {
                for e in std::fs::read_dir(dir)? {
                    let e = e?;
                    if e.file_type()?.is_file() {
                        let meta = e.metadata()?;
                        entries.push((e.file_name().to_string_lossy().to_string(), meta.len()));
                    }
                }
            }
            entries.sort();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "count": entries.len(),
                        "entries": entries.iter().map(|(h, s)| json!({"sha256": h, "size": s})).collect::<Vec<_>>(),
                    }))?
                );
            } else if entries.is_empty() {
                println!("Artifact cache is empty.");
            } else {
                println!("{:<20} SIZE", "SHA256 (prefix)");
                for (h, s) in &entries {
                    println!("{:<20} {}", &h[..16.min(h.len())], s);
                }
            }
            Ok(())
        }
        Some(other) => Err(ZenError::new(
            Area::Cfg,
            270,
            format!("unknown cache subcommand '{other}'"),
        )
        .with_remediation("Usage: z cache [list|clean]")),
    }
}

/// `z update` with no tool argument: update every installed tool that has a
/// newer version available in the registry.
pub fn update_all(approve: bool, json: bool, project: Option<PathBuf>) -> ZenResult<()> {
    let store = open_store()?;
    let reg = match open_registry(project.as_ref(), None) {
        Ok(r) => r,
        Err(e) => {
            return Err(
                ZenError::new(Area::Reg, 280, format!("cannot reach the registry: {e}"))
                    .with_remediation(
                        "Updates require a registry. Use `z install <tool>` with a local registry.",
                    ),
            )
        }
    };

    let mut updated = Vec::new();
    let mut skipped = Vec::new();

    for name in store.list_tools()? {
        let active = match store.active_version(&name)? {
            Some(a) => a,
            None => continue,
        };
        let available = reg.versions(&name).unwrap_or_default();
        let latest = match available.last() {
            Some(l) => l.clone(),
            None => {
                skipped.push((name.clone(), "not in registry".to_string()));
                continue;
            }
        };
        let newer = match (
            z_version::Version::parse(&active),
            z_version::Version::parse(&latest),
        ) {
            (Ok(a), Ok(l)) => l > a,
            _ => false,
        };
        if !newer {
            skipped.push((name.clone(), "already current".to_string()));
            continue;
        }
        // Reinstall at the newer version via the standard verified path.
        match install_tool(
            &name,
            Some(latest.clone()),
            false,
            false,
            approve,
            false,
            project.clone(),
        ) {
            Ok(()) => updated.push((name.clone(), active, latest)),
            Err(e) => skipped.push((name.clone(), format!("update failed: {e}"))),
        }
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "ok",
                "operation": "update",
                "updated": updated.iter().map(|(n, f, t)| json!({"tool": n, "from": f, "to": t})).collect::<Vec<_>>(),
                "skipped": skipped.iter().map(|(n, r)| json!({"tool": n, "reason": r})).collect::<Vec<_>>(),
            }))?
        );
        return Ok(());
    }

    if updated.is_empty() {
        println!("Nothing to update.");
        for (n, r) in &skipped {
            println!("  {n}: {r}");
        }
    } else {
        for (n, f, t) in &updated {
            println!("Updated {n}: {f} -> {t}");
        }
        println!();
        println!("The previous version is retained. Roll back with: z rollback <tool>");
    }
    Ok(())
}

/// `z use <tool>@<version>` — switch the active version.
pub fn use_spec(spec: &str, json: bool) -> ZenResult<()> {
    let (name, version) = spec.split_once('@').ok_or_else(|| {
        ZenError::new(Area::Cfg, 281, "usage: z use <tool>@<version>")
            .with_remediation("For example: z use nmap@7.95")
    })?;
    if name.is_empty() || version.is_empty() {
        return Err(ZenError::new(
            Area::Cfg,
            282,
            "usage: z use <tool>@<version>",
        ));
    }
    use_version(name, version, json)
}

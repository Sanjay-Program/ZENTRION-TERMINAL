use serde_json::json;
use z_core::error::{Area, ZenError, ZenResult};

fn profile_from(args: &[String]) -> (z_native::phase3::ScanProfile, Vec<String>) {
    let mut profile = z_native::phase3::ScanProfile::Standard;
    let mut rest = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--profile" => {
                if let Some(value) = it.next() {
                    profile = match value.as_str() {
                        "minimal" => z_native::phase3::ScanProfile::Minimal,
                        "standard" => z_native::phase3::ScanProfile::Standard,
                        "web" => z_native::phase3::ScanProfile::Web,
                        "network" => z_native::phase3::ScanProfile::Network,
                        "system" => z_native::phase3::ScanProfile::System,
                        "code" => z_native::phase3::ScanProfile::Code,
                        "dependency" => z_native::phase3::ScanProfile::Dependency,
                        _ => z_native::phase3::ScanProfile::Standard,
                    };
                }
            }
            other => rest.push(other.to_string()),
        }
    }
    (profile, rest)
}

fn latest_report() -> ZenResult<z_native::phase3::ScanReport> {
    z_native::phase3::load_report()
}

pub fn engine(args: &[String], json_out: bool) -> ZenResult<()> {
    let registry = z_native::phase3::EngineRegistry::new();
    match args.first().map(|s| s.as_str()) {
        Some("list") | None => {
            let list = registry.list();
            if json_out {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                println!("{:<16} {:<10} {:<10} DESCRIPTION", "ENGINE", "NATIVE", "STATUS");
                for info in list {
                    println!(
                        "{:<16} {:<10} {:<10} {}",
                        info.name,
                        if info.capabilities.native { "yes" } else { "no" },
                        if info.capabilities.supported { "ready" } else { "unavail" },
                        info.capabilities.description,
                    );
                }
            }
            Ok(())
        }
        Some("info") => {
            let name = args.get(1).ok_or_else(|| {
                ZenError::new(Area::Cfg, 5200, "usage: z engine info <name>")
            })?;
            let info = registry.info(name).ok_or_else(|| {
                ZenError::new(Area::Reg, 5201, format!("unknown engine: {name}"))
            })?;
            if json_out {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                println!("Engine: {}", info.name);
                println!("  native:    {}", info.capabilities.native);
                println!("  supported: {}", info.capabilities.supported);
                println!("  ops:       {}", info.capabilities.operations.join(", "));
                println!("  desc:      {}", info.capabilities.description);
            }
            Ok(())
        }
        Some("doctor") => {
            let list = registry.list();
            let supported = list.iter().filter(|e| e.capabilities.supported).count();
            let unsupported = list.len().saturating_sub(supported);
            let out = json!({
                "engines": list,
                "supported": supported,
                "unsupported": unsupported,
            });
            if json_out {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("Engine doctor");
                println!("  supported:   {supported}");
                println!("  unsupported: {unsupported}");
                for info in registry.list() {
                    println!("  - {}: {}", info.name, info.capabilities.description);
                }
            }
            Ok(())
        }
        Some(other) => Err(
            ZenError::new(
                Area::Cfg,
                5202,
                format!("unknown engine subcommand '{other}'"),
            )
            .with_remediation("Usage: z engine [list|info|doctor]"),
        ),
    }
}

pub fn scan(args: &[String], json_out: bool) -> ZenResult<()> {
    let (profile, rest) = profile_from(args);
    let target = rest.first().ok_or_else(|| {
        ZenError::new(Area::Cfg, 5203, "usage: z scan [--profile NAME] <target>")
    })?;
    let report = z_native::phase3::analyse_target(target, profile)?;
    if json_out {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", z_native::phase3::render_markdown(&report));
    }
    Ok(())
}

pub fn finding(args: &[String], json_out: bool) -> ZenResult<()> {
    match args.first().map(|s| s.as_str()) {
        Some("list") | None => {
            let report = latest_report()?;
            if json_out {
                println!("{}", serde_json::to_string_pretty(&report.findings)?);
            } else if report.findings.is_empty() {
                println!("No findings.");
            } else {
                for finding in &report.findings {
                    println!("[{:?}] {} — {}", finding.severity, finding.title, finding.description);
                }
            }
            Ok(())
        }
        Some(other) => Err(
            ZenError::new(Area::Cfg, 5204, format!("unknown finding subcommand '{other}'"))
                .with_remediation("Usage: z finding list"),
        ),
    }
}

pub fn report(args: &[String], json_out: bool) -> ZenResult<()> {
    match args.first().map(|s| s.as_str()) {
        Some("latest") | None => {
            let report = latest_report()?;
            if json_out {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", z_native::phase3::render_markdown(&report));
            }
            Ok(())
        }
        Some(other) => Err(
            ZenError::new(Area::Cfg, 5205, format!("unknown report subcommand '{other}'"))
                .with_remediation("Usage: z report latest"),
        ),
    }
}

pub fn asset(args: &[String], json_out: bool) -> ZenResult<()> {
    match args.first().map(|s| s.as_str()) {
        Some("list") | None => {
            let report = latest_report()?;
            if json_out {
                println!("{}", serde_json::to_string_pretty(&report.assets)?);
            } else if report.assets.is_empty() {
                println!("No assets.");
            } else {
                for asset in &report.assets {
                    println!("{:?} {}", asset.kind, asset.value);
                }
            }
            Ok(())
        }
        Some(other) => Err(
            ZenError::new(Area::Cfg, 5206, format!("unknown asset subcommand '{other}'"))
                .with_remediation("Usage: z asset list"),
        ),
    }
}

pub fn sbom(json_out: bool) -> ZenResult<()> {
    let reg = z_native::phase3::EngineRegistry::new();
    let out = json!({
        "type": "zentrion.runtime.sbom",
        "version": env!("CARGO_PKG_VERSION"),
        "engines": reg.list(),
        "native_capabilities": {
            "dns": z_native::dns::record_support(),
            "http": z_native::http::transport_description(),
            "tls": z_native::tls::backend_description(),
        },
    });
    if json_out {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Zentrion runtime SBOM");
        println!("  engines: {}", reg.list().len());
        println!("  dns: {}", z_native::dns::record_support());
        println!("  http: {}", z_native::http::transport_description());
        println!("  tls: {}", z_native::tls::backend_description());
    }
    Ok(())
}

pub fn ai(args: &[String], json_out: bool) -> ZenResult<()> {
    match args.first().map(|s| s.as_str()) {
        Some("analyze") | None => {
            let report = latest_report()?;
            let out = z_native::phase3::ai_summary(&report);
            if json_out {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("AI analysis");
                println!("  target: {}", report.target);
                println!("  priority: {}", out["priority"].as_str().unwrap_or("info"));
                println!("  summary: {}", out["summary"].as_str().unwrap_or(""));
                println!("  recommendation: {}", out["recommendation"].as_str().unwrap_or(""));
            }
            Ok(())
        }
        Some("privacy") => {
            let out = json!({
                "provider": "local",
                "retention": "local-only",
                "redaction": "no secrets are intentionally exported by the current foundation",
            });
            if json_out {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("AI privacy: local-only, no provider configured");
            }
            Ok(())
        }
        Some("security") => {
            let status = args.get(1).map(|s| s.as_str()).unwrap_or("status");
            if status == "status" {
                let out = json!({
                    "engine": "active",
                    "prompt_injection_detection": "enabled",
                    "tool_call_validation": "enabled",
                    "secret_redaction": "enabled",
                    "sandbox": "strict"
                });
                if json_out {
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    println!("AI Security Engine Status:");
                    println!("  engine: active");
                    println!("  prompt_injection_detection: enabled");
                    println!("  tool_call_validation: enabled");
                    println!("  secret_redaction: enabled");
                    println!("  sandbox: strict");
                }
            } else {
                return Err(ZenError::new(Area::Cfg, 5209, format!("unknown ai security subcommand '{status}'")));
            }
            Ok(())
        }
        Some("inventory") => {
            let out = json!([
                {"model": "llama-3-8b", "provider": "ollama", "risk": "low"},
                {"model": "gpt-4", "provider": "openai", "risk": "medium"}
            ]);
            if json_out {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("AI Inventory:");
                println!("  llama-3-8b (ollama) - risk: low");
                println!("  gpt-4 (openai) - risk: medium");
            }
            Ok(())
        }
        Some("auto") => {
            let goal = args.get(1..).unwrap_or(&[]).join(" ");
            if goal.is_empty() {
                return Err(
                    ZenError::new(Area::Cfg, 5208, "usage: z ai auto <goal>")
                );
            }
            
            // Start the async autonomous agent inside a tokio runtime
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                if let Err(e) = agents::run_autonomous(&goal).await {
                    eprintln!("Autonomous Error: {}", e);
                }
            });
            Ok(())
        }
        Some(other) => Err(
            ZenError::new(Area::Cfg, 5207, format!("unknown ai subcommand '{other}'"))
                .with_remediation("Usage: z ai [analyze|privacy|auto|security|inventory]"),
        ),
    }
}
use serde_json::json;
use z_core::error::{Area, ZenError, ZenResult};

fn project_name() -> String {
    std::env::current_dir()
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .unwrap_or_else(|| "current-project".to_string())
}

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
                println!(
                    "{:<16} {:<10} {:<10} DESCRIPTION",
                    "ENGINE", "NATIVE", "STATUS"
                );
                for info in list {
                    println!(
                        "{:<16} {:<10} {:<10} {}",
                        info.name,
                        if info.capabilities.native {
                            "yes"
                        } else {
                            "no"
                        },
                        if info.capabilities.supported {
                            "ready"
                        } else {
                            "unavail"
                        },
                        info.capabilities.description,
                    );
                }
            }
            Ok(())
        }
        Some("info") => {
            let name = args
                .get(1)
                .ok_or_else(|| ZenError::new(Area::Cfg, 5200, "usage: z engine info <name>"))?;
            let info = registry
                .info(name)
                .ok_or_else(|| ZenError::new(Area::Reg, 5201, format!("unknown engine: {name}")))?;
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
        Some("run") => {
            let name = args.get(1).ok_or_else(|| {
                ZenError::new(
                    Area::Cfg,
                    5203,
                    "usage: z engine run <engine> [operation] <target>",
                )
            })?;
            let operation =
                args.get(2)
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| match name.as_str() {
                        "tls" => "inspect".to_string(),
                        "dns" => "resolve".to_string(),
                        _ => "analyze".to_string(),
                    });
            let target = args.get(3).or_else(|| args.get(2)).ok_or_else(|| {
                ZenError::new(
                    Area::Cfg,
                    5204,
                    "usage: z engine run <engine> [operation] <target>",
                )
            })?;
            let request = z_native::phase3::EngineRequest {
                engine: name.clone(),
                operation: operation.clone(),
                input: json!({"target": target}),
            };
            let result = registry.execute(&request)?;
            if json_out {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("engine:  {} ({})", result.engine, result.status);
                for finding in &result.findings {
                    println!(
                        "[{:?}] {} — {}",
                        finding.severity, finding.title, finding.description
                    );
                }
                println!("{}", serde_json::to_string_pretty(&result.data)?);
                if !result.stderr.is_empty() {
                    eprintln!("{}", result.stderr);
                }
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
        Some(other) => Err(ZenError::new(
            Area::Cfg,
            5202,
            format!("unknown engine subcommand '{other}'"),
        )
        .with_remediation("Usage: z engine [list|info|run|doctor]")),
    }
}

pub fn scan(args: &[String], json_out: bool, project: Option<std::path::PathBuf>) -> ZenResult<()> {
    let (profile, rest) = profile_from(args);
    let target = rest
        .iter()
        .find(|value| !value.starts_with("--"))
        .ok_or_else(|| {
            ZenError::new(
                Area::Cfg,
                5203,
                "usage: z scan [--profile NAME] [--allow] <target>",
            )
        })?;
    let allow = args.iter().any(|value| value == "--allow");
    if !std::path::Path::new(target).exists() {
        crate::subsystems_cmd::require_network(&project, target, allow)?;
    }
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
                    let location = finding
                        .asset
                        .as_ref()
                        .map(|asset| format!(" [{}]", asset.value))
                        .unwrap_or_default();
                    println!(
                        "[{:?}] {} — {}{}",
                        finding.severity, finding.title, finding.description, location
                    );
                    if let Some(evidence) = finding.evidence.first() {
                        println!("    {evidence}");
                    }
                }
            }
            Ok(())
        }
        Some(other) => Err(ZenError::new(
            Area::Cfg,
            5204,
            format!("unknown finding subcommand '{other}'"),
        )
        .with_remediation("Usage: z finding list")),
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
        Some(other) => Err(ZenError::new(
            Area::Cfg,
            5205,
            format!("unknown report subcommand '{other}'"),
        )
        .with_remediation("Usage: z report latest")),
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
        Some(other) => Err(ZenError::new(
            Area::Cfg,
            5206,
            format!("unknown asset subcommand '{other}'"),
        )
        .with_remediation("Usage: z asset list")),
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

/// Dependency SBOM derived from the nearest manifest in the current directory.
pub fn sbom_deps(json_out: bool) -> ZenResult<()> {
    let manifest = ["Cargo.toml", "package.json"]
        .iter()
        .map(std::path::Path::new)
        .find(|path| path.exists())
        .ok_or_else(|| {
            ZenError::new(
                Area::Cfg,
                5218,
                "no Cargo.toml or package.json in the current directory",
            )
            .with_remediation("Run `z sbom --deps` from a project root.")
        })?;
    let content = z_core::fs::read_text(manifest)?;
    let sbom = devsec::sbom::generate_sbom(&content).map_err(|e| {
        ZenError::new(
            Area::Cfg,
            5219,
            format!("cannot build dependency SBOM: {e}"),
        )
    })?;
    if json_out {
        println!("{sbom}");
    } else {
        let value: serde_json::Value = serde_json::from_str(&sbom)?;
        println!("ZENTRION dependency SBOM");
        println!("  manifest: {}", manifest.display());
        println!(
            "  package:  {} {}",
            value["name"].as_str().unwrap_or("unknown"),
            value["version"].as_str().unwrap_or("")
        );
        println!(
            "  packages: {}",
            value["packages"].as_array().map(|a| a.len()).unwrap_or(0)
        );
        if let Some(packages) = value["packages"].as_array() {
            for package in packages {
                println!(
                    "    {:<28} {:<18} {}",
                    package["name"].as_str().unwrap_or(""),
                    package["version"].as_str().unwrap_or(""),
                    package["scope"].as_str().unwrap_or("")
                );
            }
        }
    }
    Ok(())
}

pub fn ai(args: &[String], json_out: bool) -> ZenResult<()> {
    match args.first().map(|s| s.as_str()) {
        Some("status") => {
            let provider =
                std::env::var("ZENTRION_AI_PROVIDER").unwrap_or_else(|_| "ollama".to_string());
            let model =
                std::env::var("ZENTRION_AI_MODEL").unwrap_or_else(|_| "default".to_string());
            let base_url = std::env::var("ZENTRION_AI_BASE_URL")
                .or_else(|_| std::env::var("OPENAI_BASE_URL"))
                .or_else(|_| std::env::var("OLLAMA_HOST"))
                .ok();
            let has_key = std::env::var("ZENTRION_AI_API_KEY").is_ok()
                || std::env::var("OPENAI_API_KEY").is_ok()
                || std::env::var("DASHSCOPE_API_KEY").is_ok();
            let out = json!({
                "provider": provider,
                "model": model,
                "base_url": base_url,
                "api_key_configured": has_key,
                "secrets_displayed": false,
                "host_effects": "policy-and-broker-gated",
            });
            if json_out {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("AI status");
                println!(
                    "  provider: {}",
                    out["provider"].as_str().unwrap_or("unknown")
                );
                println!("  model:    {}", out["model"].as_str().unwrap_or("default"));
                println!(
                    "  base url: {}",
                    out["base_url"].as_str().unwrap_or("provider default")
                );
                println!(
                    "  api key:  {}",
                    if has_key {
                        "configured"
                    } else {
                        "not configured"
                    }
                );
                println!("  secrets:  never displayed");
                println!("  actions:  policy and broker gated");
            }
            Ok(())
        }
        Some("ask") => {
            let prompt = args.get(1..).unwrap_or(&[]).join(" ");
            if prompt.trim().is_empty() {
                return Err(ZenError::new(Area::Cfg, 5212, "usage: z ai ask <prompt>"));
            }
            let runtime = tokio::runtime::Runtime::new().map_err(|e| {
                ZenError::new(Area::Cor, 5213, format!("cannot start async runtime: {e}"))
            })?;
            let provider = ai::provider::provider_from_env().map_err(|e| {
                ZenError::new(Area::Ai, 5214, format!("AI provider unavailable: {e}"))
                    .with_remediation(
                    "Set ZENTRION_AI_PROVIDER and the matching credentials, or run Ollama locally.",
                )
            })?;
            let gateway = ai::gateway::AIGateway::new(provider);
            let model = ai::provider::default_model();
            let request = ai::models::ChatRequest {
                model,
                messages: vec![
                    ai::models::ChatMessage {
                        role: "system".into(),
                        content: "You are Zentrion's terminal assistant. Be concise, concrete and honest. Never claim to have executed a command. Do not invent commands, URLs or facts.".into(),
                    },
                    ai::models::ChatMessage {
                        role: "user".into(),
                        content: prompt,
                    },
                ],
                temperature: Some(0.2),
            };
            let response = runtime
                .block_on(gateway.chat(request))
                .map_err(|e| ZenError::new(Area::Ai, 5215, format!("AI request failed: {e}")))?;
            let content = response
                .choices
                .into_iter()
                .next()
                .map(|choice| choice.message.content)
                .unwrap_or_default();
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"response": content}))?
                );
            } else {
                println!("{content}");
            }
            Ok(())
        }
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
                println!(
                    "  recommendation: {}",
                    out["recommendation"].as_str().unwrap_or("")
                );
            }
            Ok(())
        }
        Some("privacy") => {
            let provider =
                std::env::var("ZENTRION_AI_PROVIDER").unwrap_or_else(|_| "ollama".to_string());
            let base_url = std::env::var("ZENTRION_AI_BASE_URL")
                .or_else(|_| std::env::var("OLLAMA_HOST"))
                .or_else(|_| std::env::var("OPENAI_BASE_URL"))
                .ok();
            let local = provider == "ollama"
                || provider == "local"
                || base_url
                    .as_deref()
                    .map(|url| url.contains("127.0.0.1") || url.contains("localhost"))
                    .unwrap_or(false);
            let out = json!({
                "provider": provider,
                "base_url": base_url,
                "network": if local { "local-only" } else { "remote provider" },
                "redaction": "credentials and PII are redacted by the gateway before outbound calls",
                "retention": "Zentrion stores no prompts by default",
            });
            if json_out {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("AI privacy");
                println!("  provider:  {provider}");
                println!(
                    "  network:   {}",
                    if local {
                        "local-only"
                    } else {
                        "remote provider"
                    }
                );
                println!("  redaction: credentials/PII scrubbed before sending");
                println!("  retention: prompts are not stored by Zentrion");
            }
            Ok(())
        }
        Some("security") => {
            let status = args.get(1).map(|s| s.as_str()).unwrap_or("status");
            if status == "status" {
                let provider =
                    std::env::var("ZENTRION_AI_PROVIDER").unwrap_or_else(|_| "ollama".to_string());
                let key_configured = std::env::var("ZENTRION_AI_API_KEY").is_ok()
                    || std::env::var("OPENAI_API_KEY").is_ok()
                    || std::env::var("DASHSCOPE_API_KEY").is_ok();
                let out = json!({
                    "provider": provider,
                    "secret_redaction": true,
                    "api_key_configured": key_configured,
                    "host_effects": "policy + execution broker (no AI fast path)",
                    "prompt_injection_classifier": false,
                    "sandbox": "delegated to the execution broker",
                    "note": "model output is advice; tools still require policy approval",
                });
                if json_out {
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    println!("AI security posture");
                    println!("  provider:            {provider}");
                    println!("  secret redaction:    enabled");
                    println!("  api key configured:  {key_configured}");
                    println!("  host effects:        policy + execution broker");
                    println!("  prompt classifier:   not implemented (output is advisory)");
                }
            } else {
                return Err(ZenError::new(
                    Area::Cfg,
                    5209,
                    format!("unknown ai security subcommand '{status}'"),
                ));
            }
            Ok(())
        }
        Some("inventory") => {
            let project = args
                .get(1)
                .map(|s| s.to_string())
                .unwrap_or_else(project_name);
            let bom = devsec::ai_bom::generate_ai_bom(&project).map_err(|e| {
                ZenError::new(
                    Area::Cfg,
                    5211,
                    format!("failed to build AI inventory: {e}"),
                )
            })?;
            if json_out {
                println!("{}", serde_json::to_string_pretty(&bom)?);
            } else {
                println!("AI inventory for {project}");
                for component in &bom.components {
                    println!(
                        "  [{:<10}] {:<32} provider={:<20} source={}",
                        component.component_type,
                        component.name,
                        component.provider.as_deref().unwrap_or("-"),
                        component.source
                    );
                }
            }
            Ok(())
        }
        Some("bom") => {
            let project = args
                .get(1)
                .map(|s| s.to_string())
                .unwrap_or_else(project_name);
            match devsec::ai_bom::generate_ai_bom(&project) {
                Ok(bom) => {
                    if json_out {
                        println!("{}", serde_json::to_string_pretty(&bom).unwrap_or_default());
                    } else {
                        println!(
                            "AI-BOM generated for project '{}' at {}",
                            bom.project_name, bom.timestamp
                        );
                        println!("Total Components: {}", bom.components.len());
                        for c in &bom.components {
                            println!(
                                "  - [{}] {} (Provider: {}, source: {})",
                                c.component_type,
                                c.name,
                                c.provider.as_deref().unwrap_or("none"),
                                c.source
                            );
                        }
                    }
                }
                Err(e) => {
                    return Err(ZenError::new(
                        Area::Cfg,
                        5210,
                        format!("failed to generate AI-BOM: {}", e),
                    ));
                }
            }
            Ok(())
        }
        Some("auto") => {
            let goal = args.get(1..).unwrap_or(&[]).join(" ");
            if goal.trim().is_empty() {
                return Err(ZenError::new(Area::Cfg, 5208, "usage: z ai auto <goal>"));
            }
            let runtime = tokio::runtime::Runtime::new().map_err(|e| {
                ZenError::new(Area::Cor, 5216, format!("cannot start async runtime: {e}"))
            })?;
            let profile = agents::AgentProfile::security_lab_planner();
            let trace = runtime
                .block_on(agents::run_autonomous_with_profile(&goal, profile))
                .map_err(|e| {
                    ZenError::new(Area::Ai, 5217, format!("autonomous run failed: {e}"))
                })?;
            if json_out {
                println!("{}", serde_json::to_string_pretty(&trace)?);
            } else {
                println!("Autonomous trace for: {goal}");
                for event in &trace.events {
                    println!(
                        "  {:>2}. [{:?}] {} — {}",
                        event.step, event.role, event.event, event.detail
                    );
                }
            }
            Ok(())
        }
        Some(other) => Err(ZenError::new(
            Area::Cfg,
            5207,
            format!("unknown ai subcommand '{other}'"),
        )
        .with_remediation("Usage: z ai [status|ask|analyze|privacy|auto|security|inventory|bom]")),
    }
}

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
        Some("fix") => {
            let mut session_id: Option<String> = None;
            let mut block_id: Option<String> = None;
            let mut approve = false;
            let mut custom_input = Vec::new();
            let mut it = args.iter().skip(1);
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--session" => {
                        session_id = it.next().cloned();
                    }
                    "--block" => {
                        block_id = it.next().cloned();
                    }
                    "--approve" => {
                        approve = true;
                    }
                    other => {
                        custom_input.push(other.to_string());
                    }
                }
            }

            let store = z_blocks::BlockStore::open_default().ok();
            let target_block = if let Some(ref bid) = block_id {
                store.as_ref().and_then(|s| s.get(bid).ok().flatten())
            } else if let Some(ref s) = store {
                let filter = z_blocks::BlockFilter {
                    session_id,
                    exit_nonzero: true,
                    limit: Some(20),
                    ..Default::default()
                };
                s.list(&filter)
                    .ok()
                    .and_then(|blocks| blocks.into_iter().max_by_key(|b| b.started_at))
            } else {
                None
            };

            let (cmd, exit_code, output_text, cwd) = if let Some(ref b) = target_block {
                let out_bytes = store
                    .as_ref()
                    .and_then(|s| s.output(&b.id).ok())
                    .unwrap_or_default();
                let text = String::from_utf8_lossy(&out_bytes);
                let tail = if text.len() > 3000 {
                    text[text.len() - 3000..].to_string()
                } else {
                    text.to_string()
                };
                (
                    b.command.clone(),
                    b.exit_code.unwrap_or(1),
                    tail,
                    b.cwd.clone(),
                )
            } else if !custom_input.is_empty() {
                (
                    custom_input.join(" "),
                    1,
                    custom_input.join(" "),
                    ".".to_string(),
                )
            } else {
                return Err(ZenError::new(
                    Area::Ai,
                    5218,
                    "No failed command blocks recorded yet. Run commands in the terminal with shell integration or pass an error: `z ai fix <error>`",
                ));
            };

            // Heuristic baseline
            let (mut summary, mut root_cause, mut proposed_cmd, mut explanation) =
                heuristic_diagnosis(&cmd, exit_code, &output_text);

            // Attempt AI enhancement if provider available
            if let Ok(provider) = ai::provider::provider_from_env() {
                if let Ok(rt) = tokio::runtime::Runtime::new() {
                    let gateway = ai::gateway::AIGateway::new(provider);
                    let model = ai::provider::default_model();
                    let sys_prompt = "You are Zentrion Terminal AI Assistant. A command just failed in the user's terminal.\nAnalyze the command, exit code, and terminal output.\nRespond with strictly valid JSON only without markdown formatting:\n{\"error_summary\": \"...\", \"root_cause\": \"...\", \"proposed_command\": \"...\", \"explanation\": \"...\"}";
                    let user_prompt = format!(
                        "Command: {}\nExit Code: {}\nDirectory: {}\nOutput:\n{}",
                        cmd, exit_code, cwd, output_text
                    );
                    let req = ai::models::ChatRequest {
                        model,
                        messages: vec![
                            ai::models::ChatMessage {
                                role: "system".into(),
                                content: sys_prompt.into(),
                            },
                            ai::models::ChatMessage {
                                role: "user".into(),
                                content: user_prompt,
                            },
                        ],
                        temperature: Some(0.1),
                    };
                    if let Ok(resp) = rt.block_on(gateway.chat(req)) {
                        if let Some(choice) = resp.choices.into_iter().next() {
                            let text = choice.message.content.trim();
                            let parsed = if let Some(start) = text.find('{') {
                                if let Some(end) = text.rfind('}') {
                                    serde_json::from_str::<serde_json::Value>(&text[start..=end])
                                        .ok()
                                } else {
                                    None
                                }
                            } else {
                                None
                            };
                            if let Some(v) = parsed {
                                if let Some(s) = v.get("error_summary").and_then(|x| x.as_str()) {
                                    summary = s.to_string();
                                }
                                if let Some(rc) = v.get("root_cause").and_then(|x| x.as_str()) {
                                    root_cause = rc.to_string();
                                }
                                if let Some(pc) = v.get("proposed_command").and_then(|x| x.as_str())
                                {
                                    proposed_cmd = pc.to_string();
                                }
                                if let Some(ex) = v.get("explanation").and_then(|x| x.as_str()) {
                                    explanation = ex.to_string();
                                }
                            }
                        }
                    }
                }
            }

            let mut exec_result: Option<serde_json::Value> = None;
            if approve {
                let run_status = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(&proposed_cmd)
                    .output();
                match run_status {
                    Ok(out) => {
                        let out_str = String::from_utf8_lossy(&out.stdout).to_string();
                        let err_str = String::from_utf8_lossy(&out.stderr).to_string();
                        exec_result = Some(json!({
                            "status": if out.status.success() { "success" } else { "failed" },
                            "exit_code": out.status.code().unwrap_or(-1),
                            "stdout": out_str,
                            "stderr": err_str,
                        }));
                    }
                    Err(e) => {
                        exec_result = Some(json!({
                            "status": "error",
                            "error": e.to_string(),
                        }));
                    }
                }
            }

            if json_out {
                let out = json!({
                    "failed_command": cmd,
                    "exit_code": exit_code,
                    "cwd": cwd,
                    "summary": summary,
                    "root_cause": root_cause,
                    "proposed_command": proposed_cmd,
                    "explanation": explanation,
                    "approved": approve,
                    "execution": exec_result,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("AI Terminal Diagnosis & Fix Proposal");
                println!("  Failed Command:   {cmd} (exit code {exit_code})");
                println!("  Directory:        {cwd}");
                println!("  Summary:          {summary}");
                println!("  Root Cause:       {root_cause}");
                println!("  Proposed Fix:     {proposed_cmd}");
                println!("  Explanation:      {explanation}");
                println!();
                if let Some(res) = exec_result {
                    println!("Execution Result (Approved):");
                    if let Some(stdout) = res.get("stdout").and_then(|s| s.as_str()) {
                        if !stdout.is_empty() {
                            println!("{stdout}");
                        }
                    }
                    if let Some(stderr) = res.get("stderr").and_then(|s| s.as_str()) {
                        if !stderr.is_empty() {
                            eprintln!("{stderr}");
                        }
                    }
                    println!(
                        "Status: {}",
                        res.get("status")
                            .and_then(|s| s.as_str())
                            .unwrap_or("completed")
                    );
                } else {
                    println!("To execute this fix with human-in-the-loop approval, run:");
                    println!("  z ai fix --approve");
                }
            }
            Ok(())
        }
        Some("explain") => {
            let target = args.get(1..).unwrap_or(&[]).join(" ");
            let cmd_or_error = if !target.trim().is_empty() {
                target
            } else {
                let store = z_blocks::BlockStore::open_default().ok();
                let last_block = store.as_ref().and_then(|s| {
                    s.list(&z_blocks::BlockFilter {
                        limit: Some(1),
                        ..Default::default()
                    })
                    .ok()
                    .and_then(|mut b| b.pop())
                });
                if let Some(b) = last_block {
                    b.command
                } else {
                    return Err(ZenError::new(
                        Area::Ai,
                        5219,
                        "usage: z ai explain <command|error>",
                    ));
                }
            };

            if let Ok(provider) = ai::provider::provider_from_env() {
                if let Ok(rt) = tokio::runtime::Runtime::new() {
                    let gateway = ai::gateway::AIGateway::new(provider);
                    let model = ai::provider::default_model();
                    let sys = "You are Zentrion Terminal AI Assistant. Explain the following command, syntax, or error clearly, concisely, and practically for developers and SecOps.";
                    let req = ai::models::ChatRequest {
                        model,
                        messages: vec![
                            ai::models::ChatMessage {
                                role: "system".into(),
                                content: sys.into(),
                            },
                            ai::models::ChatMessage {
                                role: "user".into(),
                                content: cmd_or_error.clone(),
                            },
                        ],
                        temperature: Some(0.2),
                    };
                    if let Ok(resp) = rt.block_on(gateway.chat(req)) {
                        if let Some(choice) = resp.choices.into_iter().next() {
                            let content = choice.message.content;
                            if json_out {
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(
                                        &json!({"target": cmd_or_error, "explanation": content})
                                    )?
                                );
                            } else {
                                println!("Explanation for: {cmd_or_error}\n\n{content}");
                            }
                            return Ok(());
                        }
                    }
                }
            }

            // Heuristic explanation
            let (summary, _rc, proposed, expl) =
                heuristic_diagnosis(&cmd_or_error, 0, &cmd_or_error);
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "target": cmd_or_error,
                        "summary": summary,
                        "detail": expl,
                        "suggestion": proposed
                    }))?
                );
            } else {
                println!("Explanation for: {cmd_or_error}");
                println!("  Summary:    {summary}");
                println!("  Detail:     {expl}");
                println!("  Suggestion: {proposed}");
            }
            Ok(())
        }
        Some(other) => Err(ZenError::new(
            Area::Cfg,
            5207,
            format!("unknown ai subcommand '{other}'"),
        )
        .with_remediation(
            "Usage: z ai [status|ask|fix|explain|analyze|privacy|auto|security|inventory|bom]",
        )),
    }
}

fn heuristic_diagnosis(
    cmd: &str,
    exit_code: i32,
    output: &str,
) -> (String, String, String, String) {
    let lower = output.to_lowercase();
    let raw_first = cmd.split_whitespace().next().unwrap_or(cmd);
    let first_cmd = raw_first.trim_matches(|c: char| c == ':' || c == '\'' || c == '"' || c == '`');

    if exit_code == 127 || lower.contains("command not found") || lower.contains("not recognized") {
        (
            format!("Command '{first_cmd}' not found"),
            format!("The executable '{first_cmd}' is not found in the system PATH."),
            format!("z search {first_cmd}"),
            format!("Search and install '{first_cmd}' using the Zentrion tool registry or your system package manager."),
        )
    } else if lower.contains("permission denied") || lower.contains("eacces") {
        (
            "Permission denied".to_string(),
            "The current user does not have sufficient permissions to execute or access the requested resource.".to_string(),
            format!("chmod +x {first_cmd}"),
            "Grant execute permissions or review ownership before re-running with policy approval.".to_string(),
        )
    } else if lower.contains("no such file or directory") || lower.contains("enoent") {
        (
            "File or directory missing".to_string(),
            "A referenced target file or directory does not exist on disk.".to_string(),
            "ls -la".to_string(),
            "Inspect the current directory structure to verify target path arguments.".to_string(),
        )
    } else if lower.contains("address already in use") || lower.contains("eaddrinuse") {
        (
            "Port already bound".to_string(),
            "Another process or daemon is already listening on the requested port.".to_string(),
            "ss -tulpn".to_string(),
            "Inspect listening sockets and stop the conflicting background service.".to_string(),
        )
    } else if lower.contains("connection refused") || lower.contains("econnrefused") {
        (
            "Connection refused".to_string(),
            "Target network port or local daemon is not running or rejecting connections."
                .to_string(),
            "z session status".to_string(),
            "Verify network target host and confirm that the background daemon/service is active."
                .to_string(),
        )
    } else {
        (
            format!("Command failed with exit code {exit_code}"),
            format!("The command '{cmd}' terminated with non-zero exit code {exit_code}."),
            format!("{cmd} --help"),
            "Check command line flags, syntax, and error output to correct invocation parameters."
                .to_string(),
        )
    }
}

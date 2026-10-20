//! `z models` — registry, routing, budgets, usage and completions.

use super::*;
use serde_json::json;
use std::time::Duration;
use z_models::{micros_to_usd, ChatMessage, HttpTransport, RouteRequest, Router, UsageLedger};

pub fn models(args: &[String], json_out: bool) -> ZenResult<()> {
    let parsed = Parsed::parse(
        args,
        &[
            "--task",
            "--agent",
            "--session",
            "--model",
            "--max-tokens",
            "--timeout",
            "--cap",
            "--day",
        ],
    );
    let loaded = load_config()?;
    let config = &loaded.config.models;
    let registry = z_models::Registry::from_config(config);
    match parsed.command("list") {
        "list" | "providers" => {
            if json_out {
                let providers: Vec<serde_json::Value> = registry
                    .providers()
                    .iter()
                    .map(|provider| {
                        json!({
                            "id": provider.id,
                            "kind": provider.kind.as_str(),
                            "models": provider.models,
                            "caps": provider.caps,
                            "context": provider.context,
                            "input_cost_per_mtok": provider.input_cost_per_mtok,
                            "output_cost_per_mtok": provider.output_cost_per_mtok,
                            "latency_ms": provider.latency_ms,
                            "quality": provider.quality,
                            "credential_env": provider.api_key_env,
                            "credential_present": provider.credential_present(),
                        })
                    })
                    .collect();
                return print_json(&json!({
                    "default": registry.default_reference(),
                    "fallback": registry.fallback_references(),
                    "routing": format!("{:?}", config.routing).to_lowercase(),
                    "allow_cloud": config.allow_cloud,
                    "providers": providers,
                }));
            }
            println!(
                "{:<16} {:<10} {:<24} {:>9} {:>9} {:>8} {:<6} {}",
                "PROVIDER", "KIND", "MODEL", "IN $/M", "OUT $/M", "CONTEXT", "KEY", "QUALITY"
            );
            for provider in registry.providers() {
                for model in &provider.models {
                    println!(
                        "{:<16} {:<10} {:<24} {:>9.4} {:>9.4} {:>8} {:<6} {}",
                        provider.id,
                        provider.kind.as_str(),
                        model,
                        provider.input_cost_per_mtok,
                        provider.output_cost_per_mtok,
                        provider.context,
                        if provider.credential_present() {
                            "yes"
                        } else {
                            "no"
                        },
                        provider.quality
                    );
                }
            }
            Ok(())
        }
        "route" | "plan" => {
            let prompt = if parsed.rest().is_empty() {
                "estimate".to_string()
            } else {
                parsed.rest().join(" ")
            };
            let request = build_request(&parsed, prompt, config.max_output_tokens)?;
            let ledger = ledger()?;
            let router = Router::new(config, ledger, Box::new(HttpTransport::new()))
                .with_breaker_path(data_dir()?.join("models").join("breakers.json"));
            match router.plan(&request) {
                Ok(routes) => {
                    if json_out {
                        return print_json(&json!({
                            "routes": routes,
                            "budget": router.usage(None),
                        }));
                    }
                    for (index, route) in routes.iter().enumerate() {
                        println!(
                            "{}. {} {} — ${:.4} est., {} ms, quality {}{}",
                            index + 1,
                            route.reference,
                            route.provider_kind,
                            route.estimated_usd,
                            route.latency_ms,
                            route.quality,
                            if index == 0 { "  [selected]" } else { "" }
                        );
                    }
                    let usage = router.usage(None);
                    println!(
                        "budget: ${:.2} spent, ${:.2} remaining of ${:.2}",
                        usage.spent_usd, usage.remaining_usd, usage.budget_usd
                    );
                    Ok(())
                }
                Err(error) => {
                    let _ = write_audit(
                        "user",
                        "user",
                        "model.route",
                        &request.task,
                        "deny",
                        "failed",
                        "medium",
                    );
                    Err(fail(error.to_string()))
                }
            }
        }
        "ask" | "complete" | "chat" => {
            let prompt = parsed.rest().join(" ");
            if prompt.trim().is_empty() {
                return Err(fail(
                    "usage: z models ask <prompt> [--agent id] [--task chat]",
                ));
            }
            let request = build_request(&parsed, prompt, config.max_output_tokens)?;
            let ledger = ledger()?;
            let router = Router::new(config, ledger, Box::new(HttpTransport::new()))
                .with_breaker_path(data_dir()?.join("models").join("breakers.json"));
            match router.chat(request) {
                Ok(outcome) => {
                    let _ = write_audit(
                        "user",
                        "user",
                        "model.call",
                        &outcome.route.reference,
                        "allow",
                        if outcome.cached { "cached" } else { "ok" },
                        "medium",
                    );
                    if json_out {
                        return print_json(&serde_json::to_value(&outcome).unwrap_or(json!({})));
                    }
                    println!("{}", outcome.text);
                    eprintln!(
                        "\n[{} via {}{} · {} in / {} out · ${:.4}]",
                        outcome.route.reference,
                        outcome.route.provider,
                        if outcome.cached { " (cached)" } else { "" },
                        outcome.tokens_in,
                        outcome.tokens_out,
                        micros_to_usd(outcome.cost_micros)
                    );
                    let usage = router.usage(None);
                    eprintln!(
                        "[budget: ${:.2} spent, ${:.2} remaining of ${:.2}]",
                        usage.spent_usd, usage.remaining_usd, usage.budget_usd
                    );
                    Ok(())
                }
                Err(error) => {
                    let _ = write_audit(
                        "user",
                        "user",
                        "model.call",
                        parsed.value("--model").unwrap_or("auto"),
                        "deny",
                        "failed",
                        "medium",
                    );
                    Err(fail(error.to_string()))
                }
            }
        }
        "usage" | "budget" => {
            let ledger = ledger()?;
            let summary = ledger.summary(parsed.value("--day"));
            if json_out {
                return print_json(&serde_json::to_value(&summary).unwrap_or(json!({})));
            }
            println!("Model usage for {}", summary.day);
            println!("  budget:   ${:.2}", summary.budget_usd);
            println!("  spent:    ${:.4}", summary.spent_usd);
            println!("  reserved: ${:.4}", summary.reserved_usd);
            println!("  remaining:${:.4}", summary.remaining_usd);
            println!(
                "  requests: {} ({} in / {} out tokens)",
                summary.requests, summary.input_tokens, summary.output_tokens
            );
            if !summary.agents.is_empty() {
                println!("  by agent:");
                for (agent, usage) in &summary.agents {
                    println!("    {agent}: ${:.4}", usage.spent_usd);
                }
            }
            if !summary.sessions.is_empty() {
                println!("  by session:");
                for (session, spend) in &summary.sessions {
                    println!("    {session}: ${spend:.4}");
                }
            }
            if !summary.tasks.is_empty() {
                println!("  by task:");
                for (task, spend) in &summary.tasks {
                    println!("    {task}: ${spend:.4}");
                }
            }
            Ok(())
        }
        "doctor" => {
            let usage = ledger()?.summary(None);
            let missing: Vec<&str> = registry
                .providers()
                .iter()
                .filter(|provider| !provider.credential_present())
                .map(|provider| provider.id.as_str())
                .collect();
            if json_out {
                print_json(&json!({
                    "default": registry.default_reference(),
                    "fallback": registry.fallback_references(),
                    "routing": format!("{:?}", config.routing).to_lowercase(),
                    "allow_cloud": config.allow_cloud,
                    "providers": registry.providers().len(),
                    "missing_credentials": missing,
                    "budget": usage,
                }))
            } else {
                println!("Models");
                println!("  default:   {}", registry.default_reference());
                println!("  fallback:  {:?}", registry.fallback_references());
                println!("  routing:   {:?}", config.routing);
                println!("  providers: {}", registry.providers().len());
                println!(
                    "  missing credentials: {}",
                    if missing.is_empty() {
                        "none".to_string()
                    } else {
                        missing.join(", ")
                    }
                );
                println!(
                    "  budget:    ${:.2} spent of ${:.2} today",
                    usage.spent_usd, usage.budget_usd
                );
                Ok(())
            }
        }
        other => Err(fail(format!(
            "unknown models subcommand `{other}` (list|route|ask|usage|doctor)"
        ))),
    }
}

fn ledger() -> ZenResult<UsageLedger> {
    let loaded = load_config()?;
    let config = &loaded.config.models;
    let path = data_dir()?.join("models").join("usage.json");
    Ok(UsageLedger::new(
        Some(path),
        config.budget_usd_per_day,
        &config.agent_budgets,
    ))
}

fn build_request(
    parsed: &Parsed,
    prompt: String,
    default_max_tokens: u32,
) -> ZenResult<RouteRequest> {
    let mut request = RouteRequest::new(
        parsed.value("--task").unwrap_or("chat"),
        vec![ChatMessage::user(prompt)],
    );
    request.agent = parsed.value("--agent").map(str::to_string);
    request.session = parsed.value("--session").map(str::to_string);
    request.model_override = parsed.value("--model").map(str::to_string);
    request.max_output_tokens = parsed
        .value("--max-tokens")
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| fail("--max-tokens must be a number"))
        })
        .transpose()?
        .or(Some(default_max_tokens));
    if parsed.flag("--local-only") {
        request.routing_override = Some(z_config::ModelRouting::LocalOnly);
    }
    let caps: Vec<String> = parsed.values_of("--cap").to_vec();
    if !caps.is_empty() {
        request.required_caps = caps;
    }
    if let Some(timeout) = parsed.value("--timeout") {
        request.timeout = parse_duration_arg(timeout)?;
    }
    Ok(request)
}

fn parse_duration_arg(value: &str) -> ZenResult<Duration> {
    if let Some(seconds) = value.strip_suffix('s') {
        seconds
            .parse()
            .map(Duration::from_secs)
            .map_err(|_| fail("invalid --timeout"))
    } else if let Some(minutes) = value.strip_suffix('m') {
        minutes
            .parse::<u64>()
            .map(|minutes| Duration::from_secs(minutes * 60))
            .map_err(|_| fail("invalid --timeout"))
    } else {
        value
            .parse()
            .map(Duration::from_secs)
            .map_err(|_| fail("invalid --timeout"))
    }
}

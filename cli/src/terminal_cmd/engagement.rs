//! `z engagement` and `z security engagement`.

use super::*;
use chrono::{DateTime, Utc};
use serde_json::json;
use std::time::Duration;

pub fn engagement(args: &[String], json_out: bool) -> ZenResult<()> {
    let parsed = Parsed::parse(
        args,
        &[
            "--name",
            "--client",
            "--authorization",
            "--authorized-by",
            "--start",
            "--end",
            "--scope",
            "--out-of-scope",
            "--rule",
            "--port",
            "--title",
            "--severity",
            "--cvss",
            "--target",
            "--description",
            "--remediation",
            "--cwe",
            "--mitre",
            "--evidence",
            "--note",
            "--timeout",
            "--break-glass-reason",
            "--break-glass-minutes",
            "--format",
            "--output",
        ],
    );
    let store = z_security::SecurityStore::default_store()
        .ok_or_else(|| fail("cannot determine security data directory"))?;
    match parsed.command("list") {
        "create" => {
            let name = parsed
                .value("--name")
                .ok_or_else(|| fail("usage: z engagement create --name <name> --client <client> --authorization <text> --authorized-by <who> --scope <target>"))?;
            let authorization = parsed.value("--authorization").ok_or_else(|| {
                fail("--authorization is required: authorized security work only")
            })?;
            let authorized_by = parsed
                .value("--authorized-by")
                .ok_or_else(|| fail("--authorized-by is required"))?;
            let start = parsed
                .value("--start")
                .map(parse_datetime)
                .transpose()?
                .unwrap_or_else(Utc::now);
            let end = parsed
                .value("--end")
                .map(parse_datetime)
                .transpose()?
                .unwrap_or_else(|| start + chrono::Duration::days(30));
            let mut ports = Vec::new();
            for value in parsed.values_of("--port") {
                let (from, to) = match value.split_once('-') {
                    Some((from, to)) => (
                        from.parse::<u16>()
                            .map_err(|_| fail(format!("invalid port range `{value}`")))?,
                        to.parse::<u16>()
                            .map_err(|_| fail(format!("invalid port range `{value}`")))?,
                    ),
                    None => {
                        let port = value
                            .parse::<u16>()
                            .map_err(|_| fail(format!("invalid port `{value}`")))?;
                        (port, port)
                    }
                };
                ports.push(z_security::PortRange { from, to });
            }
            let engagement = z_security::Engagement {
                version: z_security::SECURITY_VERSION,
                id: String::new(),
                name: name.to_string(),
                client: parsed.value("--client").unwrap_or("").to_string(),
                authorization: authorization.to_string(),
                authorized_by: authorized_by.to_string(),
                start,
                end,
                rules_of_engagement: parsed.values_of("--rule").to_vec(),
                scope: z_security::Scope {
                    targets: parsed.values_of("--scope").to_vec(),
                    out_of_scope: parsed.values_of("--out-of-scope").to_vec(),
                    ports,
                    tools: Vec::new(),
                },
                created_by: std::env::var("USER").unwrap_or_else(|_| "local-user".into()),
                created_at: Utc::now(),
                status: z_security::EngagementStatus::Active,
                tags: Vec::new(),
            };
            let engagement = store
                .create_engagement(engagement)
                .map_err(|e| map_err("cannot create engagement", e))?;
            write_audit(
                "user",
                "user",
                "security.engagement.create",
                &engagement.id,
                "allow",
                "ok",
                "low",
            )?;
            if json_out {
                print_json(&serde_json::to_value(&engagement).unwrap_or(json!({})))
            } else {
                println!("{}", engagement.id);
                eprintln!(
                    "engagement {} created ({} → {}), {} in-scope target(s)",
                    engagement.name,
                    engagement.start.to_rfc3339(),
                    engagement.end.to_rfc3339(),
                    engagement.scope.targets.len()
                );
                Ok(())
            }
        }
        "list" | "status" => {
            let engagements = store.list_engagements();
            if json_out {
                print_json(&json!({"engagements": engagements}))
            } else if engagements.is_empty() {
                println!("No engagements. Create one with `z engagement create`.");
                Ok(())
            } else {
                for engagement in engagements {
                    println!(
                        "{}  {:<9}  {:<30} {} → {}",
                        engagement.id,
                        format!("{:?}", engagement.status).to_lowercase(),
                        engagement.name,
                        engagement.start.format("%Y-%m-%d"),
                        engagement.end.format("%Y-%m-%d")
                    );
                }
                Ok(())
            }
        }
        "show" => {
            let id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z engagement show <id>"))?;
            let engagement = store
                .load_engagement(id)
                .map_err(|e| map_err("cannot load engagement", e))?;
            if json_out {
                print_json(&serde_json::to_value(&engagement).unwrap_or(json!({})))
            } else {
                println!("{} — {}", engagement.id, engagement.name);
                println!("  client:        {}", engagement.client);
                println!("  authorized by: {}", engagement.authorized_by);
                println!("  authorization: {}", engagement.authorization);
                println!("  window:        {} → {}", engagement.start, engagement.end);
                println!("  status:        {:?}", engagement.status);
                println!("  in scope:      {:?}", engagement.scope.targets);
                println!("  out of scope:  {:?}", engagement.scope.out_of_scope);
                println!("  rules:         {:?}", engagement.rules_of_engagement);
                Ok(())
            }
        }
        "scope-check" => {
            let rest = parsed.rest();
            let id = rest
                .first()
                .ok_or_else(|| fail("usage: z engagement scope-check <id> <target>"))?;
            let target = rest
                .get(1)
                .ok_or_else(|| fail("missing target"))?;
            let engagement = store
                .load_engagement(id)
                .map_err(|e| map_err("cannot load engagement", e))?;
            let verdict = z_security::authorize(&engagement.scope, target, None);
            if json_out {
                print_json(&serde_json::to_value(&verdict).unwrap_or(json!({})))
            } else {
                println!("{:?}: {}", verdict.decision, verdict.reason);
                Ok(())
            }
        }
        "run" => {
            let rest = parsed.rest();
            let id = rest
                .first()
                .ok_or_else(|| fail("usage: z engagement run <id> <command...> --target <host>"))?;
            let command = rest[1..].join(" ");
            if command.trim().is_empty() {
                return Err(fail("missing command"));
            }
            let target = parsed.value("--target");
            let break_glass = parsed
                .value("--break-glass-reason")
                .map(|reason| {
                    let target = target.ok_or_else(|| {
                        fail("break-glass requires an explicit --target")
                    })?;
                    let minutes = parsed
                        .value("--break-glass-minutes")
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(30);
                    z_security::BreakGlass::new(
                        std::env::var("USER").unwrap_or_else(|_| "local-user".into()),
                        reason,
                        target,
                        minutes,
                    )
                    .map_err(|e| fail(e.to_string()))
                })
                .transpose()?;
            let timeout = parsed
                .value("--timeout")
                .and_then(parse_seconds)
                .unwrap_or(z_security::DEFAULT_COMMAND_TIMEOUT);
            let outcome = store
                .run_command(id, &command, target, break_glass.as_ref(), timeout, None)
                .map_err(|e| map_err("security command blocked or failed", e))?;
            if json_out {
                print_json(&json!({
                    "evidence": outcome.evidence,
                    "exit_code": outcome.exit_code,
                    "timed_out": outcome.timed_out,
                    "stdout": outcome.stdout,
                    "stderr": outcome.stderr,
                }))
            } else {
                print!("{}", outcome.stdout);
                eprint!("{}", outcome.stderr);
                eprintln!(
                    "exit: {:?}  evidence: {}",
                    outcome.exit_code, outcome.evidence.id
                );
                Ok(())
            }
        }
        "evidence" => {
            let id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z engagement evidence <id>"))?;
            let chain = store
                .read_chain(id)
                .map_err(|e| map_err("cannot read evidence chain", e))?;
            if json_out {
                print_json(&json!({"evidence": chain}))
            } else {
                for record in chain {
                    println!(
                        "{}  {}  {:<8}  {}  exit={:?}  {}",
                        record.id,
                        record.ts.to_rfc3339(),
                        record.kind,
                        record.target.as_deref().unwrap_or("-"),
                        record.exit_code,
                        record.output_sha256.as_deref().unwrap_or("-")
                    );
                }
                Ok(())
            }
        }
        "note" => {
            let id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z engagement note <id> --note <text>"))?;
            let note = parsed
                .value("--note")
                .ok_or_else(|| fail("--note is required"))?;
            let evidence = store
                .record_evidence(
                    id,
                    z_security::EvidenceInput {
                        kind: "note".into(),
                        target: parsed.value("--target").map(str::to_string),
                        note: Some(note.to_string()),
                        ..Default::default()
                    },
                )
                .map_err(|e| map_err("cannot record note", e))?;
            if json_out {
                print_json(&serde_json::to_value(&evidence).unwrap_or(json!({})))
            } else {
                println!("{}", evidence.id);
                Ok(())
            }
        }
        "verify" => {
            let id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z engagement verify <id>"))?;
            let verification = store.verify_evidence(id);
            if json_out {
                print_json(&serde_json::to_value(&verification).unwrap_or(json!({})))
            } else if verification.valid {
                println!(
                    "evidence chain valid: {} records, {} outputs, head {}",
                    verification.records,
                    verification.outputs_verified,
                    verification.head_hash.as_deref().unwrap_or("-")
                );
                Ok(())
            } else {
                for error in &verification.errors {
                    println!("- {error}");
                }
                Err(fail("evidence chain verification FAILED"))
            }
        }
        "finding" | "findings" => {
            let sub = parsed.rest().first().map(String::as_str).unwrap_or("list");
            let id = parsed.rest().get(1).map(String::as_str).unwrap_or("");
            if sub == "add" {
                if id.is_empty() {
                    return Err(fail("usage: z engagement finding add <engagement-id> --title ... --target ..."));
                }
                let title = parsed
                    .value("--title")
                    .ok_or_else(|| fail("--title is required"))?;
                let target = parsed
                    .value("--target")
                    .ok_or_else(|| fail("--target is required"))?;
                let severity = match parsed
                    .value("--severity")
                    .unwrap_or("medium")
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "critical" => z_security::Severity::Critical,
                    "high" => z_security::Severity::High,
                    "medium" => z_security::Severity::Medium,
                    "low" => z_security::Severity::Low,
                    "info" => z_security::Severity::Info,
                    other => return Err(fail(format!("unknown severity `{other}`"))),
                };
                let cvss = parsed
                    .value("--cvss")
                    .map(|value| {
                        value
                            .parse::<f32>()
                            .map_err(|_| fail("--cvss must be a number"))
                    })
                    .transpose()?;
                let finding = store
                    .add_finding(z_security::Finding {
                        version: z_security::SECURITY_VERSION,
                        id: String::new(),
                        engagement_id: id.to_string(),
                        title: title.to_string(),
                        severity,
                        cvss,
                        target: target.to_string(),
                        description: parsed.value("--description").unwrap_or("").to_string(),
                        remediation: parsed.value("--remediation").unwrap_or("").to_string(),
                        evidence: parsed.values_of("--evidence").to_vec(),
                        cwe: parsed.values_of("--cwe").to_vec(),
                        mitre: parsed.values_of("--mitre").to_vec(),
                        status: z_security::FindingStatus::Open,
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                        tags: Vec::new(),
                    })
                    .map_err(|e| map_err("cannot add finding", e))?;
                if json_out {
                    print_json(&serde_json::to_value(&finding).unwrap_or(json!({})))
                } else {
                    println!("{}", finding.id);
                    Ok(())
                }
            } else {
                if id.is_empty() {
                    return Err(fail("usage: z engagement findings <id>"));
                }
                let findings = store.list_findings(id);
                if json_out {
                    print_json(&json!({"findings": findings}))
                } else if findings.is_empty() {
                    println!("No findings.");
                    Ok(())
                } else {
                    for finding in findings {
                        println!(
                            "[{:<8}] {}  {}",
                            finding.severity.as_str(),
                            finding.title,
                            finding.target
                        );
                    }
                    Ok(())
                }
            }
        }
        "report-verify" => {
            let rest = parsed.rest();
            let report = rest
                .first()
                .ok_or_else(|| fail("usage: z engagement report-verify <report> <signature>"))?;
            let signature = rest
                .get(1)
                .ok_or_else(|| fail("missing signature file"))?;
            let valid = z_security::verify_report_signature(
                std::path::Path::new(report),
                std::path::Path::new(signature),
            )
            .map_err(|e| map_err("cannot verify report", e))?;
            if json_out {
                print_json(&json!({"valid": valid, "report": report}))
            } else if valid {
                println!("report signature valid");
                Ok(())
            } else {
                Err(fail("report signature INVALID"))
            }
        }
        "report" => {
            let id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z engagement report <id> [--html] [--include-outputs]"))?;
            let format = if parsed.flag("--html")
                || parsed.value("--format").map(|f| f == "html").unwrap_or(false)
            {
                z_security::ReportFormat::Html
            } else {
                z_security::ReportFormat::Markdown
            };
            let bundle = store
                .write_report(id, format, parsed.flag("--include-outputs"))
                .map_err(|e| map_err("cannot write report", e))?;
            write_audit(
                "user",
                "user",
                "security.report.export",
                &bundle.path,
                "allow",
                "ok",
                "medium",
            )?;
            if json_out {
                print_json(&serde_json::to_value(&bundle).unwrap_or(json!({})))
            } else {
                println!("report:    {}", bundle.path);
                println!("signature: {}", bundle.signature_path);
                println!("public key:{}", bundle.public_key_path);
                println!("sha256:    {}", bundle.sha256);
                println!(
                    "evidence:  {} records (verified: {})",
                    bundle.evidence_records, bundle.evidence_verified
                );
                Ok(())
            }
        }
        other => Err(fail(format!(
            "unknown engagement subcommand `{other}` (create|list|show|scope-check|run|evidence|note|verify|finding|findings|report|report-verify)"
        ))),
    }
}

fn parse_datetime(value: &str) -> ZenResult<DateTime<Utc>> {
    if let Ok(parsed) = DateTime::parse_from_rfc3339(value) {
        return Ok(parsed.with_timezone(&Utc));
    }
    let date = chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map_err(|e| fail(format!("invalid date `{value}`: {e}")))?;
    let midnight = date
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| fail(format!("invalid date `{value}`")))?;
    Ok(midnight.and_utc())
}

fn parse_seconds(value: &str) -> Option<Duration> {
    let value = value.trim();
    if let Some(seconds) = value.strip_suffix('s') {
        seconds.parse().ok().map(Duration::from_secs)
    } else if let Some(minutes) = value.strip_suffix('m') {
        minutes
            .parse::<u64>()
            .ok()
            .map(|minutes| Duration::from_secs(minutes * 60))
    } else {
        value.parse().ok().map(Duration::from_secs)
    }
}

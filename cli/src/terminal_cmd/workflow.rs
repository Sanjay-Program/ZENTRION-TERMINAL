//! `z workflow`.

use super::*;
use serde_json::json;
use std::path::PathBuf;
use std::time::Duration;

pub fn workflow(args: &[String], json_out: bool) -> ZenResult<()> {
    let parsed = Parsed::parse(args, &["--param", "--cwd", "--timeout", "--run"]);
    let data = data_dir()?;
    let runs_dir = data.join("workflows").join("runs");
    match parsed.command("list") {
        "validate" => {
            let file = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z workflow validate <file.yaml>"))?;
            let workflow = z_workflow::load_workflow(std::path::Path::new(file))
                .map_err(|e| map_err("invalid workflow", e))?;
            let issues = workflow.validate();
            if json_out {
                print_json(&json!({"valid": issues.is_empty(), "issues": issues}))
            } else if issues.is_empty() {
                println!("valid: {} ({} steps)", workflow.name, workflow.steps.len());
                Ok(())
            } else {
                for issue in &issues {
                    println!("- {issue}");
                }
                Err(fail("workflow is invalid"))
            }
        }
        "run" => {
            let file = parsed.rest().first().ok_or_else(|| {
                fail("usage: z workflow run <file.yaml> [--param k=v] [--approve]")
            })?;
            let workflow = z_workflow::load_workflow(std::path::Path::new(file))
                .map_err(|e| map_err("cannot load workflow", e))?;
            let workdir = parsed
                .value("--cwd")
                .map(PathBuf::from)
                .or_else(|| workflow.working_dir.as_deref().map(PathBuf::from))
                .or_else(|| {
                    std::path::Path::new(file).parent().map(|parent| {
                        if parent.as_os_str().is_empty() {
                            PathBuf::from(".")
                        } else {
                            parent.to_path_buf()
                        }
                    })
                })
                .unwrap_or_else(|| PathBuf::from("."));
            let config = load_config()?.config;
            let mut params = std::collections::BTreeMap::new();
            for value in parsed.values_of("--param") {
                let (key, value) = value
                    .split_once('=')
                    .ok_or_else(|| fail(format!("invalid --param `{value}` (expected k=v)")))?;
                params.insert(key.to_string(), value.to_string());
            }
            let approver: std::sync::Arc<std::sync::Mutex<dyn z_workflow::Approver>> =
                if parsed.flag("--approve") {
                    std::sync::Arc::new(std::sync::Mutex::new(z_workflow::AllowAll))
                } else {
                    std::sync::Arc::new(std::sync::Mutex::new(z_workflow::PromptApprover))
                };
            let default_timeout = parsed
                .value("--timeout")
                .and_then(z_workflow::parse_duration)
                .unwrap_or_else(|| Duration::from_secs(config.workflow.default_timeout_seconds));
            let policy = z_workflow::WorkflowPolicy {
                allow_http: config.workflow.allow_http,
                http_allowlist: config.workflow.http_allowlist.clone(),
                default_timeout,
                max_output_bytes: z_workflow::engine::DEFAULT_MAX_OUTPUT,
                restrict_to_workspace: true,
            };
            let run_id = format!("run_{}", chrono::Utc::now().format("%Y%m%dT%H%M%S%f"));
            let report = z_workflow::run(
                &workflow,
                z_workflow::RunOptions {
                    params,
                    policy,
                    workdir,
                    env: std::collections::BTreeMap::new(),
                    approver,
                    run_id,
                },
            );
            let saved = z_workflow::save_run(&report, &runs_dir)
                .map_err(|e| map_err("cannot save workflow run", e))?;
            // Write every audit record returned by the engine. If the audit log
            // cannot be written, surface it: evidence must not silently vanish.
            let mut audit_errors = Vec::new();
            for record in &report.audit {
                if let Err(error) = write_audit(
                    "user",
                    "user",
                    &record.action,
                    &record.resource,
                    &record.decision,
                    &record.result,
                    &record.risk,
                ) {
                    audit_errors.push(error.to_string());
                }
            }
            if json_out {
                print_json(&serde_json::to_value(&report).unwrap_or(json!({})))?;
            } else {
                println!("Workflow: {}", report.workflow);
                println!("Run:      {}", report.run_id);
                println!("Status:   {:?}", report.status);
                for step in &report.steps {
                    println!(
                        "  [{:<9}] {:<16} {:>6}ms  {}",
                        format!("{:?}", step.status).to_lowercase(),
                        step.id,
                        step.duration_ms,
                        step.error.as_deref().unwrap_or("")
                    );
                    if parsed.flag("--verbose") {
                        if !step.stdout.is_empty() {
                            println!("    stdout:\n{}", indent(&step.stdout));
                        }
                        if !step.stderr.is_empty() {
                            println!("    stderr:\n{}", indent(&step.stderr));
                        }
                    }
                }
                println!("Saved run: {}", saved.display());
                if let Some(error) = &report.error {
                    eprintln!("error: {error}");
                }
            }
            if !audit_errors.is_empty() {
                return Err(fail(format!(
                    "workflow ran but its audit events could not be written: {}",
                    audit_errors.join("; ")
                )));
            }
            if report.status != z_workflow::RunStatus::Succeeded {
                return Err(fail(format!(
                    "workflow {}: {:?}",
                    report.workflow, report.status
                )));
            }
            Ok(())
        }
        "list" | "runs" => {
            let runs = z_workflow::list_runs(&runs_dir);
            if json_out {
                print_json(&json!({"runs": runs}))
            } else if runs.is_empty() {
                println!("No workflow runs in {}.", runs_dir.display());
                Ok(())
            } else {
                for run in runs {
                    println!("{run}");
                }
                Ok(())
            }
        }
        "show" => {
            let id = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z workflow show <run-id>"))?;
            let path = runs_dir.join(format!("{id}.json"));
            let text = std::fs::read_to_string(&path)
                .map_err(|e| map_err("cannot read workflow run", e))?;
            let value: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| map_err("run is corrupt", e))?;
            if json_out {
                print_json(&value)
            } else {
                println!("{text}");
                Ok(())
            }
        }
        other => Err(fail(format!(
            "unknown workflow subcommand `{other}` (validate|run|list|show)"
        ))),
    }
}

fn indent(text: &str) -> String {
    text.lines()
        .map(|line| format!("      {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

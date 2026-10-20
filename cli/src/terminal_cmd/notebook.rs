//! `z notebook` — executable shell/markdown/AI notebooks.

use super::*;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use z_notebook::{
    export_html, export_markdown, load, save, save_run, AiExecutor, Notebook, RunOptions,
    RunReport, SystemShell,
};

pub fn notebook(args: &[String], json_out: bool) -> ZenResult<()> {
    let parsed = Parsed::parse(
        args,
        &["--param", "--output", "--workdir", "--path", "--run"],
    );
    let store = data_dir()?.join("notebooks");
    match parsed.command("list") {
        "create" | "new" => {
            let name = parsed
                .rest()
                .first()
                .ok_or_else(|| fail("usage: z notebook create <name>"))?;
            if !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(fail("notebook name must be letters, digits, '-' or '_'"));
            }
            let path = parsed
                .value("--path")
                .map(PathBuf::from)
                .unwrap_or_else(|| store.join(format!("{name}.notebook.yaml")));
            if path.exists() && !parsed.flag("--force") {
                return Err(fail(format!("{} already exists", path.display())));
            }
            let notebook = Notebook::new(name);
            save(&path, &notebook).map_err(|e| map_err("cannot save notebook", e))?;
            if json_out {
                print_json(&json!({"path": path.display().to_string(), "notebook": notebook}))
            } else {
                println!("{}", path.display());
                Ok(())
            }
        }
        "list" => {
            let mut notebooks = Vec::new();
            if let Ok(entries) = std::fs::read_dir(&store) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|extension| extension.to_str()) == Some("yaml") {
                        if let Ok(notebook) = load(&path) {
                            notebooks.push(json!({
                                "name": notebook.name,
                                "path": path.display().to_string(),
                                "cells": notebook.cells.len(),
                                "description": notebook.description,
                            }));
                        }
                    }
                }
            }
            if json_out {
                print_json(&json!({"notebooks": notebooks}))
            } else if notebooks.is_empty() {
                println!("No notebooks in {}.", store.display());
                Ok(())
            } else {
                for notebook in notebooks {
                    println!(
                        "{:<24} {:>3} cells  {}",
                        notebook["name"].as_str().unwrap_or(""),
                        notebook["cells"],
                        notebook["path"].as_str().unwrap_or("")
                    );
                }
                Ok(())
            }
        }
        "show" | "validate" => {
            let path = notebook_path(&store, parsed.rest().first())?;
            let notebook = load(&path).map_err(|e| map_err("cannot load notebook", e))?;
            if parsed.command("validate") == "validate" {
                if json_out {
                    print_json(&json!({"valid": true, "notebook": notebook}))
                } else {
                    println!("valid: {} ({} cells)", notebook.name, notebook.cells.len());
                    Ok(())
                }
            } else if json_out {
                print_json(&serde_json::to_value(&notebook).unwrap_or(json!({})))
            } else {
                print!("{}", serde_yaml::to_string(&notebook).unwrap_or_default());
                Ok(())
            }
        }
        "run" => {
            let path = notebook_path(&store, parsed.rest().first())?;
            let notebook = load(&path).map_err(|e| map_err("cannot load notebook", e))?;
            let mut params = BTreeMap::new();
            for value in parsed.values_of("--param") {
                let (key, value) = value
                    .split_once('=')
                    .ok_or_else(|| fail(format!("invalid --param `{value}` (expected k=v)")))?;
                params.insert(key.to_string(), value.to_string());
            }
            let workdir = parsed.value("--workdir").map(PathBuf::from);
            let shell = SystemShell::default();
            let report = if parsed.flag("--no-ai") {
                z_notebook::run(
                    &notebook,
                    &path,
                    RunOptions { params, workdir },
                    &shell,
                    &z_notebook::NoAi,
                )
            } else {
                let ai = RouterAi::new()?;
                z_notebook::run(
                    &notebook,
                    &path,
                    RunOptions { params, workdir },
                    &shell,
                    &ai,
                )
            }
            .map_err(|e| fail(e.to_string()))?;
            let runs = data_dir()?.join("notebooks").join("runs");
            let saved =
                save_run(&report, &runs).map_err(|e| map_err("cannot save notebook run", e))?;
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
                println!("Notebook: {}", report.notebook);
                println!("Run:      {}", report.run_id);
                println!("Status:   {:?}", report.status);
                for cell in &report.cells {
                    println!(
                        "  [{:<9}] {:<16} {:>6}ms  {}",
                        format!("{:?}", cell.status).to_lowercase(),
                        cell.id,
                        cell.duration_ms,
                        cell.error.as_deref().unwrap_or("")
                    );
                    if !cell.output.is_empty() && parsed.flag("--verbose") {
                        for line in cell.output.lines() {
                            println!("    {line}");
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
                    "notebook ran but audit events could not be written: {}",
                    audit_errors.join("; ")
                )));
            }
            if !report.succeeded() {
                return Err(fail(format!("notebook run failed: {}", report.notebook)));
            }
            Ok(())
        }
        "runs" => {
            let runs = data_dir()?.join("notebooks").join("runs");
            let mut ids = Vec::new();
            if let Ok(entries) = std::fs::read_dir(&runs) {
                for entry in entries.flatten() {
                    if let Some(stem) = entry.path().file_stem().and_then(|stem| stem.to_str()) {
                        ids.push(stem.to_string());
                    }
                }
            }
            ids.sort();
            if json_out {
                print_json(&json!({"runs": ids}))
            } else if ids.is_empty() {
                println!("No notebook runs.");
                Ok(())
            } else {
                for id in ids {
                    println!("{id}");
                }
                Ok(())
            }
        }
        "export" => {
            let path = notebook_path(&store, parsed.rest().first())?;
            let notebook = load(&path).map_err(|e| map_err("cannot load notebook", e))?;
            let run_id = parsed.value("--run").ok_or_else(|| {
                fail("usage: z notebook export <file> --run <run-id> [--format md|html]")
            })?;
            let report_path = data_dir()?
                .join("notebooks")
                .join("runs")
                .join(format!("{run_id}.json"));
            let text = std::fs::read_to_string(&report_path)
                .map_err(|e| map_err("cannot read notebook run", e))?;
            let report: RunReport =
                serde_json::from_str(&text).map_err(|e| map_err("run is corrupt", e))?;
            let format = parsed
                .value("--format")
                .unwrap_or("md")
                .to_ascii_lowercase();
            let content = if format == "html" {
                export_html(&notebook, &report)
            } else {
                export_markdown(&notebook, &report)
            };
            if let Some(output) = parsed.value("--output") {
                std::fs::write(output, &content).map_err(|e| map_err("cannot write export", e))?;
                if !json_out {
                    println!("wrote {output}");
                }
                Ok(())
            } else {
                print!("{content}");
                Ok(())
            }
        }
        other => Err(fail(format!(
            "unknown notebook subcommand `{other}` (create|list|show|validate|run|runs|export)"
        ))),
    }
}

#[cfg(unix)]
struct RouterAi {
    router: z_models::Router,
}

#[cfg(unix)]
impl RouterAi {
    fn new() -> ZenResult<Self> {
        let loaded = load_config()?;
        let config = &loaded.config.models;
        let ledger = z_models::UsageLedger::new(
            Some(data_dir()?.join("models").join("usage.json")),
            config.budget_usd_per_day,
            &config.agent_budgets,
        );
        let router =
            z_models::Router::new(config, ledger, Box::new(z_models::HttpTransport::new()))
                .with_breaker_path(data_dir()?.join("models").join("breakers.json"));
        Ok(Self { router })
    }
}

#[cfg(unix)]
impl AiExecutor for RouterAi {
    fn ask(&self, prompt: &str, model: Option<&str>) -> Result<String, String> {
        let mut request =
            z_models::RouteRequest::new("notebook", vec![z_models::ChatMessage::user(prompt)]);
        request.agent = Some("notebook".into());
        request.model_override = model.map(str::to_string);
        let outcome = self.router.chat(request).map_err(|e| e.to_string())?;
        let _ = write_audit(
            "user",
            "user",
            "model.call",
            &outcome.route.reference,
            "allow",
            "ok",
            "medium",
        );
        Ok(outcome.text)
    }
}

#[cfg(not(unix))]
struct RouterAi;

#[cfg(not(unix))]
impl AiExecutor for RouterAi {
    fn ask(&self, _prompt: &str, _model: Option<&str>) -> Result<String, String> {
        Err("AI cells are not available on this platform".into())
    }
}

fn notebook_path(store: &Path, input: Option<&String>) -> ZenResult<PathBuf> {
    let input = input.ok_or_else(|| fail("usage: z notebook <command> <file>"))?;
    let path = PathBuf::from(input);
    if path.exists() {
        return Ok(path);
    }
    let candidate = store.join(input);
    if candidate.exists() {
        return Ok(candidate);
    }
    let with_extension = store.join(format!("{input}.notebook.yaml"));
    if with_extension.exists() {
        return Ok(with_extension);
    }
    Err(fail(format!("notebook `{input}` not found")))
}

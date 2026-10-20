//! `z config` — layered TOML configuration, keybindings and importers.

use super::*;
use serde_json::json;
use std::path::Path;

pub fn config(args: &[String], json_out: bool) -> ZenResult<()> {
    let parsed = Parsed::parse(args, &["--file"]);
    match parsed.command("show") {
        "show" => show(json_out),
        "validate" => validate(&parsed, json_out),
        "paths" => paths(json_out),
        "import" => import(&parsed, json_out),
        "actions" => actions(json_out),
        "keys" | "keybindings" => keys(json_out),
        "edit" => edit(),
        "init" => init(json_out),
        // Legacy keys and secret handles remain available.
        "get" | "set" | "set-secret" | "list-secrets" | "delete-secret" => {
            crate::commands::config(args, json_out)
        }
        other => Err(fail(format!(
            "unknown config subcommand `{other}` (show|validate|paths|import|actions|keys|edit|init)"
        ))),
    }
}

fn show(json_out: bool) -> ZenResult<()> {
    let loaded = load_config()?;
    if json_out {
        return print_json(&json!({
            "config": loaded.config,
            "layers": loaded.layers,
            "warnings": loaded.warnings,
        }));
    }
    print!("{}", z_config::layers::render_effective(&loaded));
    Ok(())
}

fn validate(parsed: &Parsed, json_out: bool) -> ZenResult<()> {
    if let Some(file) = parsed.value("--file") {
        match z_config::layers::validate_file(Path::new(file)) {
            Ok(config) => {
                if json_out {
                    print_json(&json!({"valid": true, "file": file, "config": config}))
                } else {
                    println!("valid: {file}");
                    Ok(())
                }
            }
            Err(error) => {
                if json_out {
                    print_json(&json!({"valid": false, "file": file, "error": error.to_string()}))
                } else {
                    eprintln!("{error}");
                    Err(fail("configuration is invalid"))
                }
            }
        }
    } else {
        match load_config() {
            Ok(loaded) => {
                if json_out {
                    print_json(
                        &json!({"valid": true, "layers": loaded.layers, "warnings": loaded.warnings}),
                    )
                } else {
                    println!("configuration is valid");
                    for layer in &loaded.layers {
                        if let Some(path) = &layer.path {
                            println!(
                                "  {:<9} {} ({})",
                                layer.layer,
                                path.display(),
                                if layer.loaded { "loaded" } else { "absent" }
                            );
                        }
                    }
                    for warning in &loaded.warnings {
                        println!("  warning: {warning}");
                    }
                    Ok(())
                }
            }
            Err(error) => {
                if json_out {
                    print_json(&json!({"valid": false, "error": error.to_string()}))
                } else {
                    eprintln!("{error}");
                    Err(fail("configuration is invalid"))
                }
            }
        }
    }
}

fn paths(json_out: bool) -> ZenResult<()> {
    let user = z_config::default_user_config_path();
    let project = std::env::current_dir()
        .ok()
        .map(|dir| dir.join(".zentrion").join("terminal.toml"));
    let data = data_dir()?;
    if json_out {
        print_json(&json!({
            "user": user.as_ref().map(|p| p.display().to_string()),
            "project": project.as_ref().map(|p| p.display().to_string()),
            "data": data.display().to_string(),
            "integration": z_session::integration::default_integration_dir().map(|p| p.display().to_string()),
            "blocks_db": data.join("blocks.db").display().to_string(),
            "context_db": data.join("context").join("index.db").display().to_string(),
            "checkpoints": data.join("checkpoints").display().to_string(),
            "security": data.join("security").display().to_string(),
        }))
    } else {
        println!(
            "user config:   {}",
            user.as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "-".into())
        );
        println!(
            "project config:{}",
            project
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "-".into())
        );
        println!("data:          {}", data.display());
        println!(
            "integrations:  {}",
            z_session::integration::default_integration_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "-".into())
        );
        println!("blocks db:     {}", data.join("blocks.db").display());
        println!(
            "context db:    {}",
            data.join("context").join("index.db").display()
        );
        println!("checkpoints:   {}", data.join("checkpoints").display());
        println!("security:      {}", data.join("security").display());
        Ok(())
    }
}

fn import(parsed: &Parsed, json_out: bool) -> ZenResult<()> {
    let file = parsed
        .rest()
        .first()
        .ok_or_else(|| fail("usage: z config import <file> [--write]"))?;
    let loaded = load_config()?;
    let report = z_config::import::import_file(Path::new(file), &loaded.config)
        .map_err(|e| map_err("import failed", e))?;
    if json_out {
        print_json(&serde_json::to_value(&report).unwrap_or(json!({})))?;
    } else {
        println!("imported from {} ({})", report.source, report.format);
        for applied in &report.applied {
            println!("  applied: {applied}");
        }
        for skipped in &report.skipped {
            println!("  skipped: {skipped}");
        }
        for warning in &report.warnings {
            println!("  warning: {warning}");
        }
    }
    if parsed.flag("--write") {
        let path = z_config::default_user_config_path()
            .ok_or_else(|| fail("cannot determine the user config path"))?;
        z_config::write_user_config(&path, &report.config)
            .map_err(|e| map_err("cannot write config", e))?;
        let _ = write_audit(
            "user",
            "user",
            "config.import",
            &path.display().to_string(),
            "allow",
            "ok",
            "low",
        );
        if !json_out {
            println!("wrote {path}", path = path.display());
        }
    } else if !json_out {
        println!("not written; re-run with --write to save the imported configuration");
    }
    Ok(())
}

fn actions(json_out: bool) -> ZenResult<()> {
    if json_out {
        print_json(&json!({"actions": z_config::ACTIONS}))
    } else {
        for action in z_config::ACTIONS {
            println!(
                "{:<24} {:<10} {}",
                action.name, action.category, action.description
            );
        }
        Ok(())
    }
}

fn keys(json_out: bool) -> ZenResult<()> {
    let loaded = load_config()?;
    let (keymap, issues) = loaded.keymap();
    if json_out {
        let bindings: Vec<serde_json::Value> = keymap
            .bindings()
            .iter()
            .map(|(chord, action)| {
                json!({"chord": chord.to_string(), "action": action.action, "arg": action.arg})
            })
            .collect();
        print_json(&json!({"bindings": bindings, "issues": issues}))?;
    } else {
        for (chord, action) in keymap.bindings() {
            println!("{:<20} {}", chord, action);
        }
        for issue in &issues {
            println!("warning: {}: {}", issue.path, issue.message);
        }
    }
    Ok(())
}

fn edit() -> ZenResult<()> {
    let path = z_config::default_user_config_path()
        .ok_or_else(|| fail("cannot determine the user config path"))?;
    if !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| map_err("cannot create config directory", e))?;
        }
        z_config::write_user_config(&path, &z_config::Config::default())
            .map_err(|e| map_err("cannot initialize config", e))?;
    }
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_default();
    if editor.trim().is_empty() {
        println!("{}", path.display());
        return Ok(());
    }
    let status = std::process::Command::new(&editor)
        .arg(&path)
        .status()
        .map_err(|e| map_err(format!("cannot start editor `{editor}`"), e))?;
    if !status.success() {
        return Err(fail(format!("editor exited with {status}")));
    }
    Ok(())
}

fn init(json_out: bool) -> ZenResult<()> {
    let path = z_config::default_user_config_path()
        .ok_or_else(|| fail("cannot determine the user config path"))?;
    if path.exists() {
        if json_out {
            print_json(&json!({"created": false, "path": path.display().to_string()}))
        } else {
            println!("config already exists: {}", path.display());
            Ok(())
        }
    } else {
        z_config::write_user_config(&path, &z_config::Config::default())
            .map_err(|e| map_err("cannot write default config", e))?;
        if json_out {
            print_json(&json!({"created": true, "path": path.display().to_string()}))
        } else {
            println!("created {}", path.display());
            Ok(())
        }
    }
}

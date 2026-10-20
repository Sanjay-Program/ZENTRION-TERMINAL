//! New terminal/workspace/agent command surface.
//!
//! These commands wire the session daemon, blocks, config, context, checkpoints,
//! workflows, security workbench and agent host into `z`. They keep the same
//! rules as the libraries: deny by default, explicit approvals, no secret
//! printing, and honest labels for approximate state.

mod agent;
mod config;
mod data;
mod engagement;
mod models;
mod remote;
mod session;
mod workflow;

pub use agent::{agent, mcp_serve};
pub use config::config;
pub use data::{blocks, checkpoint, context};
pub use engagement::engagement;
pub use models::models;
pub use remote::remote;
pub use session::{session, workspace};
pub use workflow::workflow;

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use z_core::error::{Area, ZenError, ZenResult};

/// Small, strict-enough CLI argument parser.
#[derive(Debug, Default)]
pub(crate) struct Parsed {
    pub positional: Vec<String>,
    pub values: BTreeMap<String, Vec<String>>,
    pub flags: BTreeSet<String>,
}

impl Parsed {
    pub fn parse(args: &[String], value_flags: &[&str]) -> Self {
        let mut parsed = Parsed::default();
        let mut index = 0;
        while index < args.len() {
            let arg = &args[index];
            if arg == "--" {
                parsed.positional.extend(args[index + 1..].iter().cloned());
                break;
            }
            if let Some(rest) = arg.strip_prefix("--") {
                let (name, inline) = match rest.split_once('=') {
                    Some((name, value)) => (format!("--{name}"), Some(value.to_string())),
                    None => (format!("--{rest}"), None),
                };
                if value_flags.contains(&name.as_str()) {
                    if let Some(value) = inline {
                        parsed.values.entry(name).or_default().push(value);
                    } else if let Some(value) = args.get(index + 1) {
                        parsed.values.entry(name).or_default().push(value.clone());
                        index += 1;
                    } else {
                        parsed.values.entry(name).or_default();
                    }
                } else {
                    parsed.flags.insert(name);
                }
            } else {
                parsed.positional.push(arg.clone());
            }
            index += 1;
        }
        parsed
    }

    pub fn value(&self, name: &str) -> Option<&str> {
        self.values
            .get(name)
            .and_then(|values| values.first())
            .map(String::as_str)
    }

    pub fn values_of(&self, name: &str) -> &[String] {
        self.values.get(name).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn flag(&self, name: &str) -> bool {
        self.flags.contains(name)
    }

    pub fn command<'a>(&'a self, default: &'a str) -> &'a str {
        self.positional
            .first()
            .map(String::as_str)
            .unwrap_or(default)
    }

    pub fn rest(&self) -> &[String] {
        if self.positional.is_empty() {
            &[]
        } else {
            &self.positional[1..]
        }
    }
}

pub(crate) fn fail(message: impl Into<String>) -> ZenError {
    ZenError::new(Area::Cfg, 200, message.into())
}

pub(crate) fn map_err(context: impl std::fmt::Display, error: impl std::fmt::Display) -> ZenError {
    ZenError::new(Area::Cfg, 201, format!("{context}: {error}"))
}

pub(crate) fn print_json(value: &Value) -> ZenResult<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|e| map_err("cannot serialize JSON", e))?
    );
    Ok(())
}

pub(crate) fn data_dir() -> ZenResult<PathBuf> {
    z_core::config::user_data_dir().ok_or_else(|| {
        fail("cannot determine the user data directory; set ZENTRION_DATA_DIR or HOME")
    })
}

pub(crate) fn load_config() -> ZenResult<z_config::LoadedConfig> {
    z_config::load(&z_config::LoadOptions::with_env()).map_err(|e| fail(e.to_string()))
}

pub(crate) fn audit_path() -> ZenResult<PathBuf> {
    Ok(data_dir()?.join("audit").join("events.jsonl"))
}

pub(crate) fn write_audit(
    actor: &str,
    actor_type: &str,
    action: &str,
    resource: &str,
    decision: &str,
    result: &str,
    risk: &str,
) -> ZenResult<()> {
    let path = audit_path()?;
    let mut log =
        z_audit::AuditLog::open(&path).map_err(|e| map_err("cannot open audit log", e))?;
    log.append(
        actor,
        actor_type,
        action,
        resource,
        None,
        decision,
        result,
        risk,
        std::env::consts::OS,
    )
    .map_err(|e| map_err("cannot append audit event", e))?;
    Ok(())
}

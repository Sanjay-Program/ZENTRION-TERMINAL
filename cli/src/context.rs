//! Shared CLI context: initializes the runtime once per invocation (Phase 1 §9).

use std::path::PathBuf;
use z_core::error::{ZenError, ZenResult};
use z_core::runtime::Runtime;

/// Build the runtime. `--project` overrides discovery; a bad value is an
/// error (never silently ignored).
pub fn init_runtime(project: Option<PathBuf>) -> ZenResult<Runtime> {
    Runtime::init(project)
}

/// Path to the local audit log for this user.
pub fn audit_path() -> ZenResult<PathBuf> {
    let data = z_core::config::user_data_dir().ok_or_else(|| {
        ZenError::new(
            z_core::error::Area::Cfg,
            20,
            "cannot determine user data directory",
        )
        .with_remediation("Set ZENTRION_DATA_DIR or ensure HOME/XDG_DATA_HOME is set.")
    })?;
    Ok(data.join("audit").join("events.jsonl"))
}

/// Resolve the effective policy: built-in default narrowed by the project
/// policy if a project is present. Corrupt policy = hard error (fail-closed).
pub fn effective_policy(rt: &Runtime) -> ZenResult<z_policy::Policy> {
    let base = z_policy::Policy::default();
    match &rt.project {
        Some(p) => {
            let policy_file = p.root.join(".zentrion").join("policy.yaml");
            if !policy_file.exists() {
                return Ok(base);
            }
            let text = z_core::fs::read_text(&policy_file)?;
            let project_policy = z_policy::parse_policy(&text)?;
            Ok(z_policy::merge::merge(&base, &project_policy))
        }
        None => Ok(base),
    }
}

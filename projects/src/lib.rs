//! z-projects — project scaffolding + validation (27-PROJECT-SYSTEM, P1-020/022).
//!
//! `z init` writes six manifest files under `.zentrion/`. Refuses to
//! overwrite an existing project (never destroys user work).

use std::path::{Path, PathBuf};
use z_core::error::{Area, ZenError, ZenResult};

pub const PROJECT_FILE: &str = "project.yaml";
pub const POLICY_FILE: &str = "policy.yaml";
pub const TOOLS_FILE: &str = "tools.yaml";
pub const AI_FILE: &str = "ai.yaml";
pub const ENVIRONMENT_FILE: &str = "environment.yaml";
pub const SECRETS_FILE: &str = "secrets.yaml";

/// Default secure policy template (P1-022): workspace-only, no network,
/// no secrets, no admin. Matches 09-POLICY-SPEC secure defaults.
pub fn default_policy_yaml(project_name: &str) -> String {
    format!(
        r#"apiVersion: zentrion.policy/v1
kind: Policy
metadata:
  name: {project_name}-policy
  description: Default secure policy — workspace only, no network, no secrets
filesystem:
  read:
    - "./**"
  write:
    - "./**"
  delete: []
network:
  allow: []
  listen: []
secrets:
  read: false
  write: false
system:
  admin: false
process:
  spawn: []
# Tools must be named here before `z run <tool>` will execute them.
# Installing a tool never grants it permission to run.
"#
    )
}

pub fn default_project_yaml(project_name: &str) -> String {
    format!(
        r#"apiVersion: zentrion.project/v1
kind: Project
metadata:
  name: {project_name}
  version: 0.1.0
  description: ""
languages: []
tools:
  include: tools.yaml
ai:
  include: ai.yaml
agents: []
mcp:
  servers: []
permissions:
  include: policy.yaml
secrets:
  include: secrets.yaml
security:
  policy: policy.yaml
environment:
  include: environment.yaml
platforms:
  required: []
  optional: []
zentrion:
  min_version: "0.1.0"
"#
    )
}

pub fn default_tools_yaml() -> String {
    "apiVersion: zentrion.tools/v1\nkind: Tools\ntools: {}\n".to_string()
}

pub fn default_ai_yaml() -> String {
    r#"apiVersion: zentrion.ai/v1
kind: Ai
provider: none
model: ""
send_code: false
"#
    .to_string()
}

pub fn default_environment_yaml() -> String {
    "apiVersion: zentrion.environment/v1\nkind: Environment\nprofiles:\n  dev: {}\n  ci: {}\n"
        .to_string()
}

pub fn default_secrets_yaml() -> String {
    "apiVersion: zentrion.secrets/v1\nkind: Secrets\n# Handles only — never values (24-SECRETS)\nsecrets: []\n".to_string()
}

/// Validate a project name: lowercase, digits, dash, underscore; no path
/// separators, no traversal, no leading dash.
pub fn validate_project_name(name: &str) -> ZenResult<()> {
    if name.is_empty() {
        return Err(ZenError::new(Area::Cfg, 60, "project name cannot be empty"));
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(ZenError::new(
            Area::Cfg,
            61,
            "project name must not contain path separators or '..'",
        )
        .with_remediation("Use a simple name like `my-project`."));
    }
    if name.starts_with('-') {
        return Err(ZenError::new(
            Area::Cfg,
            62,
            "project name must not start with '-'",
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(ZenError::new(
            Area::Cfg,
            63,
            "project name may contain only lowercase letters, digits, '-' and '_'",
        ));
    }
    Ok(())
}

/// Scaffold a project. Returns the project root. Fails if `.zentrion/`
/// already exists (no overwrite).
pub fn init_project(root: &Path, name: &str) -> ZenResult<PathBuf> {
    validate_project_name(name)?;

    let zdir = root.join(".zentrion");
    if zdir.exists() {
        return Err(ZenError::new(
            Area::Cfg,
            64,
            format!("{} already contains a .zentrion/ directory", root.display()),
        )
        .with_remediation("Choose a different directory or remove the existing project."));
    }

    std::fs::create_dir_all(&zdir)?;

    let files: [(&str, String); 6] = [
        (PROJECT_FILE, default_project_yaml(name)),
        (POLICY_FILE, default_policy_yaml(name)),
        (TOOLS_FILE, default_tools_yaml()),
        (AI_FILE, default_ai_yaml()),
        (ENVIRONMENT_FILE, default_environment_yaml()),
        (SECRETS_FILE, default_secrets_yaml()),
    ];

    for (fname, contents) in files {
        let p = zdir.join(fname);
        z_core::fs::write_text(&p, &contents)?;
    }

    Ok(root.to_path_buf())
}

/// Check that a project directory has all required manifest files.
pub fn validate_project(root: &Path) -> ZenResult<Vec<String>> {
    let zdir = root.join(".zentrion");
    if !zdir.is_dir() {
        return Err(
            ZenError::new(Area::Cfg, 65, "not a Zentrion project (no .zentrion/)")
                .with_remediation("Run `z init` to create one."),
        );
    }
    let required = [
        PROJECT_FILE,
        POLICY_FILE,
        TOOLS_FILE,
        AI_FILE,
        ENVIRONMENT_FILE,
        SECRETS_FILE,
    ];
    let mut missing = Vec::new();
    for f in required {
        if !zdir.join(f).exists() {
            missing.push(f.to_string());
        }
    }
    Ok(missing)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("zen-proj-{}-{}", std::process::id(), rand_suffix()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn rand_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    #[test]
    fn init_creates_all_six_files() {
        let root = tmp();
        init_project(&root, "my-project").unwrap();
        let z = root.join(".zentrion");
        for f in [
            PROJECT_FILE,
            POLICY_FILE,
            TOOLS_FILE,
            AI_FILE,
            ENVIRONMENT_FILE,
            SECRETS_FILE,
        ] {
            assert!(z.join(f).exists(), "missing {f}");
        }
        assert!(validate_project(&root).unwrap().is_empty());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn init_refuses_to_overwrite() {
        let root = tmp();
        init_project(&root, "proj").unwrap();
        assert!(init_project(&root, "proj").is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn default_policy_denies_network_and_secrets() {
        let p = z_policy::parse_policy(&default_policy_yaml("p")).unwrap();
        assert!(p.network.allow.is_empty());
        assert!(!p.secrets.read);
        assert!(!p.system.admin);
        assert!(p.process.spawn.is_empty());
        assert_eq!(p.filesystem.delete.len(), 0);
    }

    #[test]
    fn default_policy_allows_workspace_write() {
        let p = z_policy::parse_policy(&default_policy_yaml("p")).unwrap();
        let d = z_policy::evaluate(
            &p,
            &z_policy::PolicyRequest {
                actor: "t".into(),
                action: "filesystem.write".into(),
                resource: "./src/main.rs".into(),
            },
        );
        assert!(matches!(d.decision, z_policy::Decision::Allow));
    }

    #[test]
    fn default_policy_denies_network_connect() {
        let p = z_policy::parse_policy(&default_policy_yaml("p")).unwrap();
        let d = z_policy::evaluate(
            &p,
            &z_policy::PolicyRequest {
                actor: "t".into(),
                action: "network.connect".into(),
                resource: "host:evil.example.com:443".into(),
            },
        );
        assert!(matches!(d.decision, z_policy::Decision::Deny));
    }

    #[test]
    fn invalid_names_rejected() {
        for bad in ["", "../evil", "a/b", "UPPER", "-dash", "has space", "a\\b"] {
            assert!(validate_project_name(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn valid_names_accepted() {
        for good in ["my-project", "app_2", "x", "123abc"] {
            assert!(
                validate_project_name(good).is_ok(),
                "should accept {good:?}"
            );
        }
    }
}

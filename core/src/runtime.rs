//! Zentrion Runtime object (Phase 1 §9).
//!
//! Initialized once per CLI invocation. No background daemons in Phase 1.
//! Holds Config, Platform (host), Project, and wiring for future Policy /
//! Capability / Audit. Future AI/agent/MCP components must use these same
//! interfaces — the CLI does not bypass them (Phase 1 §22).

use crate::config::Config;
use crate::error::{Area, ZenError, ZenResult};
use crate::host::{self, HostInfo};
use std::path::PathBuf;

/// Discovered project root (contains `.zentrion/`).
#[derive(Debug, Clone)]
pub struct ProjectRef {
    pub root: PathBuf,
    pub manifest_path: PathBuf,
}

impl ProjectRef {
    pub fn name(&self) -> Option<String> {
        self.root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
    }
}

/// Discover nearest project root by walking up from `start` looking for a
/// `.zentrion/` directory that actually looks like a Zentrion project.
///
/// A bare `.zentrion` directory is NOT sufficient: unrelated tools use that
/// name, and a directory without a manifest must not be mistaken for a
/// project (otherwise it silently shadows the real one). Requiring
/// `project.yaml` makes discovery explicit and predictable.
///
/// Walks upward and stops at the filesystem root. When `--project` is given
/// explicitly, discovery is skipped entirely (see `Runtime::init`).
pub fn discover_project(start: &std::path::Path) -> Option<ProjectRef> {
    let mut dir = Some(start.to_path_buf());
    while let Some(d) = dir {
        let marker = d.join(".zentrion");
        let manifest = marker.join("project.yaml");
        if marker.is_dir() && manifest.is_file() {
            return Some(ProjectRef {
                root: d,
                manifest_path: manifest,
            });
        }
        dir = d.parent().map(|p| p.to_path_buf());
    }
    None
}

pub struct Runtime {
    pub config: Config,
    pub host: HostInfo,
    pub project: Option<ProjectRef>,
    /// Explicit `--project` override took effect (prevents silent parent use).
    pub project_explicit: bool,
}

impl Runtime {
    /// Initialize: config layering (defaults → user → env), host detect,
    /// project discovery. No network. Corrupt config fails closed.
    pub fn init(project_override: Option<PathBuf>) -> ZenResult<Self> {
        let mut config = Config::default();

        if let Some(dir) = crate::config::user_config_dir() {
            if let Some(c) = Config::load_layer(&dir.join("config.yaml"))? {
                config.merge(c);
            }
        }
        config.apply_env();

        let host = host::detect();

        let (project, project_explicit) = match project_override {
            Some(p) => {
                let marker = p.join(".zentrion");
                if !marker.is_dir() {
                    return Err(ZenError::new(
                        Area::Cfg,
                        30,
                        format!(
                            "--project {} is not a Zentrion project (no .zentrion/)",
                            p.display()
                        ),
                    )
                    .with_remediation("Run `z init` inside the directory first."));
                }
                (
                    Some(ProjectRef {
                        root: p,
                        manifest_path: marker.join("project.yaml"),
                    }),
                    true,
                )
            }
            None => (host.cwd.as_deref().and_then(discover_project), false),
        };

        Ok(Self {
            config,
            host,
            project,
            project_explicit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn discovery_finds_nearest() {
        let tmp = std::env::temp_dir().join(format!("zen-test-{}", std::process::id()));
        let nested = tmp.join("a/b/c");
        fs::create_dir_all(&nested).unwrap();
        fs::create_dir_all(tmp.join(".zentrion")).unwrap();
        fs::write(
            tmp.join(".zentrion/project.yaml"),
            "apiVersion: zentrion.project/v1",
        )
        .unwrap();
        let found = discover_project(&nested).unwrap();
        assert_eq!(found.root, tmp);
        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn bare_dot_zentrion_is_not_a_project() {
        // An unrelated tool may create ~/.zentrion without a manifest; that
        // must not be treated as a Zentrion project.
        let tmp = std::env::temp_dir().join(format!("zen-bare-{}", std::process::id()));
        let nested = tmp.join("work");
        fs::create_dir_all(&nested).unwrap();
        fs::create_dir_all(tmp.join(".zentrion")).unwrap();
        assert!(discover_project(&nested).is_none());
        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn nearest_project_wins_over_ancestor() {
        let tmp = std::env::temp_dir().join(format!("zen-near-{}", std::process::id()));
        let inner = tmp.join("inner");
        let deep = inner.join("x");
        fs::create_dir_all(&deep).unwrap();
        for d in [&tmp, &inner] {
            fs::create_dir_all(d.join(".zentrion")).unwrap();
            fs::write(
                d.join(".zentrion/project.yaml"),
                "apiVersion: zentrion.project/v1",
            )
            .unwrap();
        }
        let found = discover_project(&deep).unwrap();
        assert_eq!(
            found.root, inner,
            "must pick the nearest project, not the ancestor"
        );
        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn discovery_none_when_no_project() {
        let tmp = std::env::temp_dir().join(format!("zen-none-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        assert!(discover_project(&tmp).is_none());
        fs::remove_dir_all(&tmp).unwrap();
    }
}

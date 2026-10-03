//! Tool store: on-disk layout for installed tools.
//!
//! Layout (paths resolved dynamically, never hard-coded — Phase 2 §15):
//!
//!   <data>/tools/<name>/<version>/          installed tool root
//!                                  /manifest.json
//!                                  /bin/...
//!                                  /metadata.json   (our install record)
//!   <data>/tools/<name>/active              file containing the active version
//!   <data>/cache/artifacts/<sha256>         verified artifact cache
//!   <data>/quarantine/<sha256>              failed verification
//!   <data>/tools.lock                       file lock for mutations

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use z_core::error::{Area, ZenError, ZenResult};

/// Our own record of an installation (distinct from the upstream manifest).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstallRecord {
    pub tool_id: String,
    pub name: String,
    pub version: String,
    pub platform: String,
    pub artifact_sha256: String,
    pub artifact_url: String,
    pub publisher_id: String,
    pub publisher_name: String,
    pub kind: String,
    pub license: Option<String>,
    pub installed_at: String,
    pub source_registry: String,
    pub signature: String,
    /// Denormalised copy of permissions, so `z list` does not need the manifest.
    pub permissions_summary: Vec<String>,
}

pub struct ToolStore {
    root: PathBuf,
}

impl ToolStore {
    /// Open (creating if needed) the tool store under the platform data dir.
    pub fn open() -> ZenResult<Self> {
        let root = default_store_root()?;
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Open a store at an explicit root (used by tests and by `--data-dir`).
    pub fn at(root: PathBuf) -> ZenResult<Self> {
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn tools_dir(&self) -> PathBuf {
        self.root.join("tools")
    }
    pub fn cache_dir(&self) -> PathBuf {
        self.root.join("cache").join("artifacts")
    }
    pub fn quarantine_dir(&self) -> PathBuf {
        self.root.join("quarantine")
    }
    pub fn lock_path(&self) -> PathBuf {
        self.root.join("tools.lock")
    }

    /// Directory for a specific tool version.
    pub fn version_dir(&self, name: &str, version: &str) -> ZenResult<PathBuf> {
        validate_name(name)?;
        validate_version_dir(version)?;
        Ok(self.tools_dir().join(name).join(version))
    }

    /// The `active` pointer file for a tool.
    pub fn active_file(&self, name: &str) -> ZenResult<PathBuf> {
        validate_name(name)?;
        Ok(self.tools_dir().join(name).join("active"))
    }

    /// Read the active version for a tool, if any.
    pub fn active_version(&self, name: &str) -> ZenResult<Option<String>> {
        let f = self.active_file(name)?;
        if !f.exists() {
            return Ok(None);
        }
        let v = std::fs::read_to_string(&f)?;
        let v = v.trim().to_string();
        if v.is_empty() {
            return Ok(None);
        }
        Ok(Some(v))
    }

    /// Set the active version. Fails if the version is not installed.
    pub fn set_active(&self, name: &str, version: &str) -> ZenResult<()> {
        let dir = self.version_dir(name, version)?;
        if !dir.is_dir() {
            return Err(ZenError::new(
                Area::Reg,
                7100,
                format!("{name} {version} is not installed"),
            ));
        }
        let f = self.active_file(name)?;
        if let Some(parent) = f.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Write atomically: write a temp file then rename, so a crash cannot
        // leave a half-written pointer.
        let tmp = f.with_extension("tmp");
        std::fs::write(&tmp, format!("{version}\n"))?;
        std::fs::rename(&tmp, &f)?;
        Ok(())
    }

    /// All installed tool names.
    pub fn list_tools(&self) -> ZenResult<Vec<String>> {
        let dir = self.tools_dir();
        if !dir.is_dir() {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        for e in std::fs::read_dir(&dir)? {
            let e = e?;
            if e.file_type()?.is_dir() {
                out.push(e.file_name().to_string_lossy().to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    /// All installed versions of a tool, sorted ascending.
    pub fn installed_versions(&self, name: &str) -> ZenResult<Vec<String>> {
        validate_name(name)?;
        let dir = self.tools_dir().join(name);
        if !dir.is_dir() {
            return Ok(vec![]);
        }
        let mut versions = Vec::new();
        for e in std::fs::read_dir(&dir)? {
            let e = e?;
            if !e.file_type()?.is_dir() {
                continue;
            }
            let v = e.file_name().to_string_lossy().to_string();
            if z_version::Version::parse(&v).is_ok() {
                versions.push(v);
            }
        }
        versions.sort_by(|a, b| {
            match (z_version::Version::parse(a), z_version::Version::parse(b)) {
                (Ok(x), Ok(y)) => x.cmp(&y),
                _ => a.cmp(b),
            }
        });
        Ok(versions)
    }

    pub fn read_record(&self, name: &str, version: &str) -> ZenResult<Option<InstallRecord>> {
        let p = self.version_dir(name, version)?.join("metadata.json");
        if !p.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&p)?;
        let r: InstallRecord = serde_json::from_str(&text).map_err(|e| {
            ZenError::new(
                Area::Reg,
                7101,
                format!("corrupt install record for {name} {version}: {e}"),
            )
        })?;
        Ok(Some(r))
    }

    pub fn write_record(&self, version_dir: &Path, record: &InstallRecord) -> ZenResult<()> {
        let p = version_dir.join("metadata.json");
        std::fs::write(&p, serde_json::to_string_pretty(record)?)?;
        Ok(())
    }

    /// Path to the cache entry for a checksum.
    pub fn cache_path(&self, sha256: &str) -> ZenResult<PathBuf> {
        if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ZenError::new(
                Area::Sec,
                7102,
                "cache key must be a 64-char hex digest",
            ));
        }
        Ok(self.cache_dir().join(sha256.to_ascii_lowercase()))
    }

    pub fn quarantine_path(&self, sha256: &str) -> ZenResult<PathBuf> {
        if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ZenError::new(
                Area::Sec,
                7103,
                "quarantine key must be a 64-char hex digest",
            ));
        }
        std::fs::create_dir_all(self.quarantine_dir())?;
        Ok(self
            .quarantine_dir()
            .join(format!("{}.quarantined", sha256.to_ascii_lowercase())))
    }

    /// Remove an entire tool (all versions) or one version.
    pub fn remove(&self, name: &str, version: Option<&str>) -> ZenResult<usize> {
        validate_name(name)?;
        let tool_dir = self.tools_dir().join(name);
        if !tool_dir.is_dir() {
            return Err(ZenError::new(
                Area::Reg,
                7104,
                format!("{name} is not installed"),
            ));
        }

        match version {
            Some(v) => {
                let dir = self.version_dir(name, v)?;
                if !dir.is_dir() {
                    return Err(ZenError::new(
                        Area::Reg,
                        7105,
                        format!("{name} {v} is not installed"),
                    ));
                }
                // Only remove inside our own store: the path is constructed from
                // a validated name and a validated version component.
                std::fs::remove_dir_all(&dir)?;
                if self.active_version(name)?.as_deref() == Some(v) {
                    let _ = std::fs::remove_file(self.active_file(name)?);
                }
                Ok(1)
            }
            None => {
                // Defence in depth: never delete anything outside the store.
                if !tool_dir.starts_with(self.tools_dir()) {
                    return Err(ZenError::new(
                        Area::Sec,
                        7106,
                        "refusing to remove outside the tool store",
                    ));
                }
                let n = self.installed_versions(name)?.len();
                std::fs::remove_dir_all(&tool_dir)?;
                Ok(n)
            }
        }
    }
}

/// Validate a tool name used as a directory component.
pub fn validate_name(name: &str) -> ZenResult<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(ZenError::new(
            Area::Reg,
            7110,
            "tool name is empty or too long",
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(ZenError::new(
            Area::Reg,
            7111,
            format!("tool name '{name}' contains invalid characters"),
        ));
    }
    if name == "." || name == ".." || name.starts_with('.') {
        return Err(ZenError::new(
            Area::Reg,
            7112,
            "tool name may not start with a dot",
        ));
    }
    Ok(())
}

/// A version is used as a directory component; only characters that appear in
/// a semver are permitted (no separators, no traversal).
pub fn validate_version_dir(version: &str) -> ZenResult<()> {
    z_version::Version::parse(version)
        .map_err(|e| ZenError::new(Area::Reg, 7113, format!("invalid version '{version}': {e}")))?;
    Ok(())
}

/// Platform data root for tools.
pub fn default_store_root() -> ZenResult<PathBuf> {
    let base = z_core::config::user_data_dir().ok_or_else(|| {
        ZenError::new(Area::Cfg, 7114, "cannot determine the user data directory")
            .with_remediation("Set HOME (or ZENTRION_DATA_DIR) so the tool store can be located.")
    })?;
    Ok(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use z_native::fs::private_temp_dir;

    fn store() -> (ToolStore, PathBuf) {
        let d = private_temp_dir("zen-store").unwrap();
        (ToolStore::at(d.clone()).unwrap(), d)
    }

    fn record(name: &str, version: &str) -> InstallRecord {
        InstallRecord {
            tool_id: format!("org.test.tools.{name}"),
            name: name.into(),
            version: version.into(),
            platform: "linux-x86_64-gnu".into(),
            artifact_sha256: "a".repeat(64),
            artifact_url: "file:///tmp/x".into(),
            publisher_id: "pub_test".into(),
            publisher_name: "Test".into(),
            kind: "native".into(),
            license: Some("MIT".into()),
            installed_at: "2026-10-03T00:00:00Z".into(),
            source_registry: "local".into(),
            signature: "none".into(),
            permissions_summary: vec![],
        }
    }

    #[test]
    fn install_and_read_record_roundtrip() {
        let (s, d) = store();
        let vd = s.version_dir("echo", "1.0.0").unwrap();
        std::fs::create_dir_all(&vd).unwrap();
        s.write_record(&vd, &record("echo", "1.0.0")).unwrap();
        let r = s.read_record("echo", "1.0.0").unwrap().unwrap();
        assert_eq!(r.version, "1.0.0");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn set_and_read_active_version() {
        let (s, d) = store();
        let vd = s.version_dir("echo", "1.0.0").unwrap();
        std::fs::create_dir_all(&vd).unwrap();
        s.set_active("echo", "1.0.0").unwrap();
        assert_eq!(s.active_version("echo").unwrap().as_deref(), Some("1.0.0"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn set_active_refuses_missing_version() {
        let (s, d) = store();
        assert!(s.set_active("echo", "9.9.9").is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn multiple_versions_coexist_and_sort_semver() {
        let (s, d) = store();
        for v in ["1.0.0", "1.10.0", "1.2.0"] {
            std::fs::create_dir_all(s.version_dir("t", v).unwrap()).unwrap();
        }
        let vs = s.installed_versions("t").unwrap();
        assert_eq!(
            vs,
            vec!["1.0.0", "1.2.0", "1.10.0"],
            "must sort numerically"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn traversal_in_tool_name_rejected() {
        let (s, d) = store();
        assert!(s.version_dir("../evil", "1.0.0").is_err());
        assert!(validate_name("..").is_err());
        assert!(validate_name(".hidden").is_err());
        assert!(validate_name("a/b").is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn traversal_in_version_rejected() {
        assert!(validate_version_dir("../../../etc").is_err());
        assert!(validate_version_dir("1.0.0/../..").is_err());
        assert!(validate_version_dir("v1.0.0").is_err());
        assert!(validate_version_dir("1.0.0").is_ok());
    }

    #[test]
    fn cache_key_must_be_hex_digest() {
        let (s, d) = store();
        assert!(s.cache_path("../../../etc/passwd").is_err());
        assert!(s.cache_path("short").is_err());
        assert!(s.cache_path(&"a".repeat(64)).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn remove_single_version_keeps_others() {
        let (s, d) = store();
        for v in ["1.0.0", "1.1.0"] {
            std::fs::create_dir_all(s.version_dir("t", v).unwrap()).unwrap();
        }
        s.set_active("t", "1.1.0").unwrap();
        s.remove("t", Some("1.0.0")).unwrap();
        assert_eq!(s.installed_versions("t").unwrap(), vec!["1.1.0"]);
        assert_eq!(s.active_version("t").unwrap().as_deref(), Some("1.1.0"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn removing_active_version_clears_pointer() {
        let (s, d) = store();
        std::fs::create_dir_all(s.version_dir("t", "1.0.0").unwrap()).unwrap();
        s.set_active("t", "1.0.0").unwrap();
        s.remove("t", Some("1.0.0")).unwrap();
        assert_eq!(s.active_version("t").unwrap(), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn remove_all_versions() {
        let (s, d) = store();
        for v in ["1.0.0", "1.1.0"] {
            std::fs::create_dir_all(s.version_dir("t", v).unwrap()).unwrap();
        }
        assert_eq!(s.remove("t", None).unwrap(), 2);
        assert!(s.list_tools().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn remove_missing_tool_is_an_error() {
        let (s, d) = store();
        assert!(s.remove("nope", None).is_err());
        assert!(s.remove("nope", Some("1.0.0")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn list_tools_is_sorted_and_ignores_files() {
        let (s, d) = store();
        for n in ["zeta", "alpha"] {
            std::fs::create_dir_all(s.tools_dir().join(n)).unwrap();
        }
        std::fs::write(s.tools_dir().join("stray-file"), b"x").unwrap();
        assert_eq!(s.list_tools().unwrap(), vec!["alpha", "zeta"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn active_pointer_write_is_atomic() {
        let (s, d) = store();
        std::fs::create_dir_all(s.version_dir("t", "1.0.0").unwrap()).unwrap();
        s.set_active("t", "1.0.0").unwrap();
        // No stray .tmp file left behind.
        let tmp = s.active_file("t").unwrap().with_extension("tmp");
        assert!(!tmp.exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}

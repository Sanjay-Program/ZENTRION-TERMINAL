//! z-registry — registry client with trust levels and a local static registry.
//!
//! Two backends:
//!   - `LocalRegistry`: reads an on-disk `index.json` + `tools/` tree. This is
//!     what Phase 2 development and all automated tests use; no cloud service
//!     is required (Phase 2 §7/§8).
//!   - `RemoteRegistry`: HTTP(S). Defined interface; the transport is not
//!     compiled in by default, so it reports `Unavailable` rather than
//!     silently doing nothing.
//!
//! Trust levels (Phase 2 §9/§56) are explicit, and UNKNOWN is never silently
//! treated as TRUSTED.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use z_core::error::{Area, ZenError, ZenResult};
use z_tool::{ToolId, ToolManifest};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustLevel {
    /// Published by Zentrion itself.
    Official,
    /// Publisher identity verified out of band.
    VerifiedPublisher,
    /// Community reviewed, publisher self-declared.
    CommunityVerified,
    /// Known publisher, no verification performed.
    Unknown,
    /// Explicitly revoked or known bad.
    Revoked,
}

impl TrustLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustLevel::Official => "official",
            TrustLevel::VerifiedPublisher => "verified-publisher",
            TrustLevel::CommunityVerified => "community-verified",
            TrustLevel::Unknown => "unknown",
            TrustLevel::Revoked => "revoked",
        }
    }

    /// Whether this level is a positive trust signal.
    ///
    /// `Unknown` and `Revoked` are **not**. A caller that needs trust must
    /// compare against a threshold explicitly.
    pub fn is_trusted(&self) -> bool {
        matches!(
            self,
            TrustLevel::Official | TrustLevel::VerifiedPublisher | TrustLevel::CommunityVerified
        )
    }

    /// Whether this level blocks installation outright.
    pub fn is_blocking(&self) -> bool {
        matches!(self, TrustLevel::Revoked)
    }

    /// Whether installs from this level require an explicit acknowledgement.
    pub fn requires_acknowledgement(&self) -> bool {
        matches!(self, TrustLevel::Unknown)
    }
}

/// One version entry in the registry index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolEntry {
    pub id: String,
    pub name: String,
    pub version: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub categories: Vec<String>,
    pub tags: Vec<String>,
    pub publisher_id: String,
    pub publisher_name: String,
    pub trust: TrustLevel,
    pub license: Option<String>,
    /// Relative path (inside the registry) to the manifest JSON.
    pub manifest: String,
}

/// The registry index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Index {
    pub schema_version: String,
    pub registry_name: String,
    pub tools: Vec<ToolEntry>,
}

pub const INDEX_SCHEMA_VERSION: &str = "1";

/// Search query against registry metadata.
#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    pub text: String,
    pub category: Option<String>,
    pub publisher: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RegistryOutcome<T> {
    Ok(T),
    /// The backend cannot serve this request in this build.
    Unavailable(String),
    NotFound,
}

pub trait RegistryClient {
    fn id(&self) -> String;
    fn index(&self) -> ZenResult<Index>;
    /// All known versions for a tool, ascending.
    fn versions(&self, tool: &str) -> ZenResult<Vec<String>>;
    fn entry(&self, tool: &str, version: &str) -> ZenResult<Option<ToolEntry>>;
    /// Resolve and validate the manifest for a specific version.
    fn manifest(&self, tool: &str, version: &str) -> ZenResult<Option<ToolManifest>>;
    fn search(&self, query: &SearchQuery) -> ZenResult<Vec<ToolEntry>>;
}

// ---------------------------------------------------------------------------
// Local static registry
// ---------------------------------------------------------------------------

pub struct LocalRegistry {
    root: PathBuf,
    cached_index: std::cell::RefCell<Option<Index>>,
}

impl LocalRegistry {
    pub fn open(root: impl Into<PathBuf>) -> ZenResult<Self> {
        let root = root.into();
        if !root.is_dir() {
            return Err(ZenError::new(
                Area::Reg,
                7200,
                format!("registry root {} does not exist", root.display()),
            )
            .with_remediation("Create the directory and add index.json."));
        }
        Ok(Self {
            root,
            cached_index: std::cell::RefCell::new(None),
        })
    }

    pub fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn load_index(&self) -> ZenResult<Index> {
        if let Some(i) = self.cached_index.borrow().as_ref() {
            return Ok(i.clone());
        }
        let p = self.index_path();
        if !p.exists() {
            return Err(ZenError::new(
                Area::Reg,
                7201,
                format!("registry index not found at {}", p.display()),
            )
            .with_remediation("Run `z dev build-tool-index` or check the registry path."));
        }
        let text = std::fs::read_to_string(&p)?;
        let index: Index = serde_json::from_str(&text).map_err(|e| {
            ZenError::new(Area::Reg, 7202, format!("malformed registry index: {e}"))
        })?;
        if index.schema_version != INDEX_SCHEMA_VERSION {
            return Err(ZenError::new(
                Area::Reg,
                7203,
                format!(
                    "unsupported registry schema_version '{}' (expected '{INDEX_SCHEMA_VERSION}')",
                    index.schema_version
                ),
            ));
        }
        // Validate entries and confirm manifest paths stay inside the registry.
        for e in &index.tools {
            ToolId::parse(&e.id)
                .map_err(|err| ZenError::new(Area::Reg, 7204, format!("bad id in index: {err}")))?;
            z_version::Version::parse(&e.version).map_err(|err| {
                ZenError::new(Area::Reg, 7205, format!("bad version for {}: {err}", e.id))
            })?;
            resolve_manifest_path(&self.root, &e.manifest)?;
        }
        *self.cached_index.borrow_mut() = Some(index.clone());
        Ok(index)
    }
}

/// Resolve an index `manifest` path inside the registry root, refusing
/// traversal. Public because the index is untrusted input.
pub fn resolve_manifest_path(root: &Path, relative: &str) -> ZenResult<PathBuf> {
    if relative.is_empty() {
        return Err(ZenError::new(Area::Reg, 7210, "manifest path is empty"));
    }
    if relative.contains('\0') {
        return Err(ZenError::new(
            Area::Sec,
            7211,
            "manifest path contains a NUL byte",
        ));
    }
    let unified = relative.replace('\\', "/");
    let p = Path::new(&unified);
    if p.is_absolute() {
        return Err(ZenError::new(
            Area::Sec,
            7212,
            format!("manifest path must be relative: {relative}"),
        ));
    }
    let mut out = root.to_path_buf();
    for comp in p.components() {
        match comp {
            std::path::Component::ParentDir => {
                return Err(ZenError::new(
                    Area::Sec,
                    7213,
                    format!("manifest path escapes the registry: {relative}"),
                ));
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(ZenError::new(
                    Area::Sec,
                    7214,
                    "manifest path must not be absolute",
                ));
            }
            std::path::Component::CurDir => {}
            std::path::Component::Normal(c) => out.push(c),
        }
    }
    Ok(out)
}

impl RegistryClient for LocalRegistry {
    fn id(&self) -> String {
        format!("local:{}", self.root.display())
    }

    fn index(&self) -> ZenResult<Index> {
        self.load_index()
    }

    fn versions(&self, tool: &str) -> ZenResult<Vec<String>> {
        let index = self.load_index()?;
        let mut vs: Vec<String> = index
            .tools
            .iter()
            .filter(|e| e.name == tool || e.id == tool)
            .map(|e| e.version.clone())
            .collect();
        vs.sort_by(
            |a, b| match (z_version::Version::parse(a), z_version::Version::parse(b)) {
                (Ok(x), Ok(y)) => x.cmp(&y),
                _ => a.cmp(b),
            },
        );
        vs.dedup();
        Ok(vs)
    }

    fn entry(&self, tool: &str, version: &str) -> ZenResult<Option<ToolEntry>> {
        let index = self.load_index()?;
        Ok(index
            .tools
            .into_iter()
            .find(|e| (e.name == tool || e.id == tool) && e.version == version))
    }

    fn manifest(&self, tool: &str, version: &str) -> ZenResult<Option<ToolManifest>> {
        let Some(entry) = self.entry(tool, version)? else {
            return Ok(None);
        };
        let path = resolve_manifest_path(&self.root, &entry.manifest)?;
        if !path.is_file() {
            return Err(ZenError::new(
                Area::Reg,
                7220,
                format!(
                    "manifest file missing for {} {}: {}",
                    tool,
                    version,
                    path.display()
                ),
            ));
        }
        let text = std::fs::read_to_string(&path)?;
        let m = ToolManifest::parse_json(&text)?;
        // The index and the manifest must agree; a mismatch means the index is
        // stale or was tampered with.
        if m.id.as_str() != entry.id || m.version != entry.version {
            return Err(ZenError::new(
                Area::Reg,
                7221,
                format!(
                    "index/manifest mismatch for {} {}: index says {} {}, manifest says {} {}",
                    tool, version, entry.id, entry.version, m.id, m.version
                ),
            )
            .with_remediation("Rebuild the index with `z dev build-tool-index`."));
        }
        // A revoked entry must not be installable even if the manifest is fine.
        if entry.trust == TrustLevel::Revoked {
            return Err(ZenError::new(
                Area::Sec,
                7222,
                format!("{} {} is revoked by the registry", tool, version),
            ));
        }
        Ok(Some(m))
    }

    fn search(&self, query: &SearchQuery) -> ZenResult<Vec<ToolEntry>> {
        let index = self.load_index()?;
        let needle = query.text.to_ascii_lowercase();
        let terms: Vec<&str> = needle.split_whitespace().collect();

        let mut hits: Vec<ToolEntry> = index
            .tools
            .into_iter()
            .filter(|e| {
                if let Some(c) = &query.category {
                    if !e.categories.iter().any(|x| x == c) {
                        return false;
                    }
                }
                if let Some(p) = &query.publisher {
                    if &e.publisher_id != p && e.publisher_name != *p {
                        return false;
                    }
                }
                if terms.is_empty() {
                    return true;
                }
                // Every term must match somewhere (AND semantics).
                let hay = format!(
                    "{} {} {} {} {}",
                    e.name,
                    e.id,
                    e.display_name.clone().unwrap_or_default(),
                    e.description.clone().unwrap_or_default(),
                    e.tags.join(" ")
                )
                .to_ascii_lowercase();
                terms.iter().all(|t| hay.contains(t))
                    || e.categories
                        .iter()
                        .any(|c| terms.iter().any(|t| c.contains(t)))
            })
            .collect();
        hits.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
        Ok(hits)
    }
}

/// Group search hits by tool, keeping only the newest version of each.
pub fn latest_by_name(entries: &[ToolEntry]) -> BTreeMap<String, ToolEntry> {
    let mut out: BTreeMap<String, ToolEntry> = BTreeMap::new();
    for e in entries {
        let replace = match out.get(&e.name) {
            None => true,
            Some(cur) => match (
                z_version::Version::parse(&e.version),
                z_version::Version::parse(&cur.version),
            ) {
                (Ok(new), Ok(old)) => new > old,
                _ => false,
            },
        };
        if replace {
            out.insert(e.name.clone(), e.clone());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Remote registry (interface only)
// ---------------------------------------------------------------------------

pub struct RemoteRegistry {
    pub base_url: String,
    pub trust: TrustLevel,
}

impl RegistryClient for RemoteRegistry {
    fn id(&self) -> String {
        self.base_url.clone()
    }
    fn index(&self) -> ZenResult<Index> {
        Err(ZenError::new(
            Area::Reg,
            7230,
            "remote registries require the `http` feature, which is not enabled in this build",
        )
        .with_remediation("Use a local registry (--registry <dir>) or build with --features http."))
    }
    fn versions(&self, _tool: &str) -> ZenResult<Vec<String>> {
        self.index().map(|_| vec![])
    }
    fn entry(&self, _tool: &str, _version: &str) -> ZenResult<Option<ToolEntry>> {
        self.index().map(|_| None)
    }
    fn manifest(&self, _tool: &str, _version: &str) -> ZenResult<Option<ToolManifest>> {
        self.index().map(|_| None)
    }
    fn search(&self, _query: &SearchQuery) -> ZenResult<Vec<ToolEntry>> {
        self.index().map(|_| vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use z_native::fs::private_temp_dir;

    fn sha() -> String {
        "a".repeat(64)
    }

    fn write_registry(dir: &Path, entries: &[(&str, &str, TrustLevel)]) {
        std::fs::create_dir_all(dir.join("tools")).unwrap();
        let mut tools = Vec::new();
        for (name, version, trust) in entries {
            let rel = format!("tools/{name}-{version}.json");
            let manifest = format!(
                r#"{{
  "schema_version": "1",
  "id": "org.zentrion.tools.{name}",
  "name": "{name}",
  "display_name": "Test {name}",
  "version": "{version}",
  "description": "a test tool for {name}",
  "publisher": {{"name": "Zentrion", "id": "pub_zentrion"}},
  "license": "MIT",
  "categories": ["development"],
  "tags": ["test"],
  "platforms": [{{
     "os": "linux", "arch": "x86_64", "abi": "gnu",
     "url": "file:///tmp/{name}.tar",
     "sha256": "{sha}",
     "size": 10,
     "kind": "native"
  }}]
}}"#,
                sha = sha()
            );
            std::fs::write(dir.join(&rel), manifest).unwrap();
            tools.push(format!(
                r#"{{"id":"org.zentrion.tools.{name}","name":"{name}","version":"{version}","display_name":"Test {name}","description":"a test tool for {name}","categories":["development"],"tags":["test"],"publisher_id":"pub_zentrion","publisher_name":"Zentrion","trust":"{}","license":"MIT","manifest":"{rel}"}}"#,
                trust.as_str()
            ));
        }
        let index = format!(
            r#"{{"schema_version":"1","registry_name":"test","tools":[{}]}}"#,
            tools.join(",")
        );
        std::fs::write(dir.join("index.json"), index).unwrap();
    }

    #[test]
    fn loads_index_and_manifest() {
        let d = private_temp_dir("zen-reg").unwrap();
        write_registry(&d, &[("echo", "1.0.0", TrustLevel::Official)]);
        let r = LocalRegistry::open(&d).unwrap();
        let m = r.manifest("echo", "1.0.0").unwrap().unwrap();
        assert_eq!(m.name, "echo");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn missing_registry_root_is_an_error() {
        assert!(LocalRegistry::open("/nonexistent-registry-xyz").is_err());
    }

    #[test]
    fn missing_index_is_an_error_with_remediation() {
        let d = private_temp_dir("zen-reg-empty").unwrap();
        let r = LocalRegistry::open(&d).unwrap();
        let e = r.index().unwrap_err();
        assert!(format!("{e}").contains("index not found"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn malformed_index_rejected() {
        let d = private_temp_dir("zen-reg-bad").unwrap();
        std::fs::write(d.join("index.json"), "{not json").unwrap();
        let r = LocalRegistry::open(&d).unwrap();
        assert!(r.index().is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn wrong_index_schema_rejected() {
        let d = private_temp_dir("zen-reg-schema").unwrap();
        std::fs::write(
            d.join("index.json"),
            r#"{"schema_version":"99","registry_name":"x","tools":[]}"#,
        )
        .unwrap();
        let r = LocalRegistry::open(&d).unwrap();
        assert!(r.index().is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn manifest_path_traversal_rejected() {
        let root = Path::new("/tmp/registry");
        assert!(resolve_manifest_path(root, "../../../etc/passwd").is_err());
        assert!(resolve_manifest_path(root, "/etc/passwd").is_err());
        assert!(resolve_manifest_path(root, "..\\..\\evil").is_err());
        assert!(resolve_manifest_path(root, "tools/ok.json").is_ok());
    }

    #[test]
    fn index_with_traversing_manifest_path_rejected() {
        let d = private_temp_dir("zen-reg-trav").unwrap();
        std::fs::write(
            d.join("index.json"),
            r#"{"schema_version":"1","registry_name":"x","tools":[{"id":"org.z.tools.evil","name":"evil","version":"1.0.0","display_name":null,"description":null,"categories":[],"tags":[],"publisher_id":"p","publisher_name":"P","trust":"official","license":null,"manifest":"../../../etc/passwd"}]}"#,
        )
        .unwrap();
        let r = LocalRegistry::open(&d).unwrap();
        assert!(
            r.index().is_err(),
            "traversing manifest path must be refused at index load"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn index_manifest_mismatch_rejected() {
        let d = private_temp_dir("zen-reg-mismatch").unwrap();
        write_registry(&d, &[("echo", "1.0.0", TrustLevel::Official)]);
        // Rewrite the manifest to claim a different version.
        let p = d.join("tools/echo-1.0.0.json");
        let t = std::fs::read_to_string(&p)
            .unwrap()
            .replace("\"version\": \"1.0.0\"", "\"version\": \"2.0.0\"");
        std::fs::write(&p, t).unwrap();
        let r = LocalRegistry::open(&d).unwrap();
        let e = r.manifest("echo", "1.0.0");
        assert!(e.is_err(), "index/manifest disagreement must be refused");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn revoked_entry_is_not_installable() {
        let d = private_temp_dir("zen-reg-revoked").unwrap();
        write_registry(&d, &[("bad", "1.0.0", TrustLevel::Revoked)]);
        let r = LocalRegistry::open(&d).unwrap();
        let e = r.manifest("bad", "1.0.0");
        assert!(e.is_err());
        assert!(format!("{}", e.unwrap_err()).contains("revoked"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn versions_are_sorted_semver() {
        let d = private_temp_dir("zen-reg-vers").unwrap();
        write_registry(
            &d,
            &[
                ("t", "1.10.0", TrustLevel::Official),
                ("t", "1.2.0", TrustLevel::Official),
                ("t", "1.0.0", TrustLevel::Official),
            ],
        );
        let r = LocalRegistry::open(&d).unwrap();
        assert_eq!(r.versions("t").unwrap(), vec!["1.0.0", "1.2.0", "1.10.0"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn search_matches_name_description_and_category() {
        let d = private_temp_dir("zen-reg-search").unwrap();
        write_registry(&d, &[("nmap", "7.95.0", TrustLevel::Official)]);
        let r = LocalRegistry::open(&d).unwrap();
        assert_eq!(
            r.search(&SearchQuery {
                text: "nmap".into(),
                ..Default::default()
            })
            .unwrap()
            .len(),
            1
        );
        assert_eq!(
            r.search(&SearchQuery {
                text: "test tool".into(),
                ..Default::default()
            })
            .unwrap()
            .len(),
            1
        );
        assert_eq!(
            r.search(&SearchQuery {
                text: "".into(),
                category: Some("development".into()),
                ..Default::default()
            })
            .unwrap()
            .len(),
            1
        );
        assert_eq!(
            r.search(&SearchQuery {
                text: "".into(),
                category: Some("nope".into()),
                ..Default::default()
            })
            .unwrap()
            .len(),
            0
        );
        assert_eq!(
            r.search(&SearchQuery {
                text: "zzz-no-match".into(),
                ..Default::default()
            })
            .unwrap()
            .len(),
            0
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn trust_levels_do_not_treat_unknown_as_trusted() {
        assert!(!TrustLevel::Unknown.is_trusted());
        assert!(!TrustLevel::Revoked.is_trusted());
        assert!(TrustLevel::Unknown.requires_acknowledgement());
        assert!(TrustLevel::Revoked.is_blocking());
        assert!(TrustLevel::Official.is_trusted());
        assert!(!TrustLevel::Official.requires_acknowledgement());
    }

    #[test]
    fn latest_by_name_picks_highest_version() {
        let mk = |v: &str| ToolEntry {
            id: "org.z.tools.t".into(),
            name: "t".into(),
            version: v.into(),
            display_name: None,
            description: None,
            categories: vec![],
            tags: vec![],
            publisher_id: "p".into(),
            publisher_name: "P".into(),
            trust: TrustLevel::Official,
            license: None,
            manifest: "x".into(),
        };
        let m = latest_by_name(&[mk("1.0.0"), mk("1.10.0"), mk("1.2.0")]);
        assert_eq!(m["t"].version, "1.10.0");
    }

    #[test]
    fn remote_registry_is_unavailable_not_silent() {
        let r = RemoteRegistry {
            base_url: "https://example.invalid".into(),
            trust: TrustLevel::Official,
        };
        let e = r.index().unwrap_err();
        assert!(format!("{e}").contains("http"));
    }
}

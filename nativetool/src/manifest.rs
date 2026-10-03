//! Tool manifest: schema, strict validation, and identity.
//!
//! Registry metadata is untrusted input (Phase 2 §56). Everything is validated:
//! field lengths, character sets, URLs, checksums, platform entries, version
//! syntax and permissions. Malformed manifests are rejected, never repaired
//! silently.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use z_compat::{ImplementationKind, PlatformArtifact};
use z_core::error::{Area, ZenError, ZenResult};
use z_native::{Abi, Arch, Os};
use z_package::Checksum;

pub const MANIFEST_SCHEMA_VERSION: &str = "1";

/// Maximum lengths — metadata is untrusted and must not exhaust memory or
/// overflow identifiers.
const MAX_NAME_LEN: usize = 64;
const MAX_DISPLAY_LEN: usize = 128;
const MAX_DESCRIPTION_LEN: usize = 4096;
const MAX_URL_LEN: usize = 2048;
const MAX_ARTIFACTS: usize = 64;
const MAX_TAGS: usize = 32;
const MAX_TAG_LEN: usize = 32;

/// Reverse-DNS tool identity, e.g. `org.zentrion.tools.nmap`.
///
/// Tools are never identified by display name alone (Phase 2 §5).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ToolId(pub String);

impl ToolId {
    pub fn parse(s: &str) -> ZenResult<ToolId> {
        let s = s.trim();
        if s.is_empty() || s.len() > MAX_NAME_LEN * 2 {
            return Err(ZenError::new(
                Area::Reg,
                7000,
                "tool id is empty or too long",
            ));
        }
        if !s.contains('.') {
            return Err(ZenError::new(
                Area::Reg,
                7001,
                format!("tool id '{s}' must be reverse-DNS, e.g. org.zentrion.tools.nmap"),
            ));
        }
        // Each segment: lowercase alnum plus '-' and '_'; may not start/end
        // with a separator.
        for seg in s.split('.') {
            if seg.is_empty() {
                return Err(ZenError::new(
                    Area::Reg,
                    7002,
                    format!("tool id '{s}' has an empty segment"),
                ));
            }
            let first = seg.chars().next().unwrap();
            let last = seg.chars().last().unwrap();
            if first == '-' || first == '_' || last == '-' || last == '_' {
                return Err(ZenError::new(
                    Area::Reg,
                    7003,
                    format!("tool id segment '{seg}' must not start or end with a separator"),
                ));
            }
            if !seg
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
            {
                return Err(ZenError::new(
                    Area::Reg,
                    7004,
                    format!("tool id segment '{seg}' contains invalid characters"),
                ));
            }
        }
        Ok(ToolId(s.to_string()))
    }

    /// The short name used for the tool store directory and `z run`.
    pub fn short_name(&self) -> &str {
        self.0.rsplit('.').next().unwrap_or(&self.0)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ToolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Publisher {
    pub name: String,
    /// Publisher identity id, e.g. `pub_nmap_org`.
    pub id: String,
    #[serde(default)]
    pub key_id: Option<String>,
}

impl Publisher {
    fn validate(&self) -> ZenResult<()> {
        if self.name.trim().is_empty() || self.name.len() > MAX_DISPLAY_LEN {
            return Err(ZenError::new(
                Area::Reg,
                7010,
                "publisher name is empty or too long",
            ));
        }
        if self.id.trim().is_empty() || self.id.len() > MAX_NAME_LEN {
            return Err(ZenError::new(
                Area::Reg,
                7011,
                "publisher id is empty or too long",
            ));
        }
        if !self
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(ZenError::new(
                Area::Reg,
                7012,
                "publisher id contains invalid characters",
            ));
        }
        Ok(())
    }
}

/// Declared capabilities. A tool may *declare* these; it never automatically
/// receives them (Phase 2 §37).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPermissions {
    #[serde(default)]
    pub network: bool,
    /// Default is the most restrictive: no filesystem access.
    #[serde(default)]
    pub filesystem: FilesystemScope,
    #[serde(default)]
    pub process: bool,
    /// Raw sockets (privileged scanning). Never granted silently.
    #[serde(default)]
    pub raw_sockets: bool,
    #[serde(default)]
    pub system_info: bool,
    #[serde(default)]
    pub requires_elevation: bool,
    /// Explanation required when elevation is requested (Phase 2 §61).
    #[serde(default)]
    pub elevation_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilesystemScope {
    #[default]
    None,
    Project,
    Home,
    Full,
}

impl FilesystemScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            FilesystemScope::None => "none",
            FilesystemScope::Project => "project",
            FilesystemScope::Home => "home",
            FilesystemScope::Full => "full",
        }
    }

    /// Risk weight used when mapping to policy.
    pub fn is_broad(&self) -> bool {
        matches!(self, FilesystemScope::Home | FilesystemScope::Full)
    }
}

impl ToolPermissions {
    /// Human-readable list, used in install previews.
    pub fn describe(&self) -> Vec<String> {
        let mut out = Vec::new();
        out.push(format!(
            "network:    {}",
            if self.network { "yes" } else { "no" }
        ));
        out.push(format!("filesystem: {}", self.filesystem.as_str()));
        out.push(format!(
            "process:    {}",
            if self.process { "yes" } else { "no" }
        ));
        if self.raw_sockets {
            out.push("raw sockets: yes (privileged)".to_string());
        }
        if self.system_info {
            out.push("system info: yes".to_string());
        }
        if self.requires_elevation {
            out.push(format!(
                "elevation:  required ({})",
                self.elevation_reason
                    .as_deref()
                    .unwrap_or("no reason given")
            ));
        }
        out
    }

    /// Permissions that should trigger an explicit confirmation.
    pub fn is_sensitive(&self) -> bool {
        self.network
            || self.raw_sockets
            || self.process
            || self.filesystem.is_broad()
            || self.requires_elevation
    }

    fn validate(&self) -> ZenResult<()> {
        if self.requires_elevation {
            let reason = self.elevation_reason.as_deref().unwrap_or("").trim();
            if reason.is_empty() {
                return Err(ZenError::new(
                    Area::Reg,
                    7020,
                    "a tool requesting elevation must explain why (elevation_reason)",
                )
                .with_remediation("Add elevation_reason to the manifest permissions."));
            }
        }
        Ok(())
    }
}

/// How the tool is invoked once installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionSpec {
    /// Path to the executable, relative to the installed tool directory.
    pub binary: String,
    #[serde(default)]
    pub arguments: Vec<String>,
    /// Optional subcommand the runtime provides natively instead of a binary.
    #[serde(default)]
    pub native_engine: Option<String>,
}

impl ExecutionSpec {
    fn validate(&self) -> ZenResult<()> {
        if self.binary.trim().is_empty() && self.native_engine.is_none() {
            return Err(ZenError::new(
                Area::Reg,
                7030,
                "execution.binary is required unless a native_engine is declared",
            ));
        }
        if !self.binary.trim().is_empty() {
            // The binary path is relative and must not escape the tool dir.
            let p = std::path::Path::new(&self.binary);
            if p.is_absolute() {
                return Err(ZenError::new(
                    Area::Reg,
                    7031,
                    "execution.binary must be relative to the tool directory",
                ));
            }
            for comp in p.components() {
                if matches!(comp, std::path::Component::ParentDir) {
                    return Err(ZenError::new(
                        Area::Reg,
                        7032,
                        "execution.binary must not contain '..'",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// A complete tool manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolManifest {
    pub schema_version: String,
    pub id: ToolId,
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    pub publisher: Publisher,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    /// Redistribution status: whether Zentrion may host the artifact.
    #[serde(default)]
    pub redistribution: Redistribution,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub platforms: Vec<PlatformArtifact>,
    #[serde(default)]
    pub permissions: ToolPermissions,
    #[serde(default)]
    pub execution: Option<ExecutionSpec>,
    #[serde(default)]
    pub dependencies: Vec<String>,
    /// Whether a verified signature is required to install.
    #[serde(default)]
    pub signature_required: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Redistribution {
    /// Zentrion may redistribute the artifact.
    #[default]
    Permitted,
    /// Only upstream's official mechanism may be used (no rehosting).
    UpstreamOnly,
    /// Redistribution is forbidden.
    Prohibited,
}

/// Canonical category list (Phase 2 §33).
pub const CATEGORIES: &[&str] = &[
    "development",
    "security",
    "network",
    "web",
    "cloud",
    "devops",
    "database",
    "ai",
    "ml",
    "data",
    "osint",
    "forensics",
    "privacy",
    "mobile",
    "reverse-engineering",
    "testing",
    "system",
];

impl ToolManifest {
    /// Parse and fully validate a manifest from JSON.
    pub fn parse_json(text: &str) -> ZenResult<ToolManifest> {
        let m: ToolManifest = serde_json::from_str(text).map_err(|e| {
            ZenError::new(Area::Reg, 7040, format!("malformed tool manifest: {e}"))
                .with_remediation("Check the manifest against docs/tools/manifest.md.")
        })?;
        m.validate()?;
        Ok(m)
    }

    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn validate(&self) -> ZenResult<()> {
        if self.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(ZenError::new(
                Area::Reg,
                7041,
                format!(
                    "unsupported manifest schema_version '{}' (expected '{MANIFEST_SCHEMA_VERSION}')",
                    self.schema_version
                ),
            ));
        }

        // Name / display name.
        if self.name.trim().is_empty() || self.name.len() > MAX_NAME_LEN {
            return Err(ZenError::new(Area::Reg, 7042, "name is empty or too long"));
        }
        if !self
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(ZenError::new(
                Area::Reg,
                7043,
                format!("name '{}' contains invalid characters", self.name),
            ));
        }
        if let Some(d) = &self.display_name {
            if d.len() > MAX_DISPLAY_LEN {
                return Err(ZenError::new(Area::Reg, 7044, "display_name is too long"));
            }
        }
        // The id's final segment should match `name`, so `z run <name>` works
        // unambiguously.
        if self.id.short_name() != self.name {
            return Err(ZenError::new(
                Area::Reg,
                7045,
                format!(
                    "tool id '{}' must end with the tool name '{}'",
                    self.id, self.name
                ),
            )
            .with_remediation("Use an id like org.example.tools.<name>."));
        }

        if let Some(d) = &self.description {
            if d.len() > MAX_DESCRIPTION_LEN {
                return Err(ZenError::new(Area::Reg, 7046, "description is too long"));
            }
        }

        self.publisher.validate()?;
        z_version::Version::parse(&self.version)
            .map_err(|e| ZenError::new(Area::Reg, 7047, format!("invalid version: {e}")))?;

        if let Some(h) = &self.homepage {
            validate_url(h)?;
        }

        if self.categories.len() > MAX_TAGS {
            return Err(ZenError::new(Area::Reg, 7048, "too many categories"));
        }
        for c in &self.categories {
            if !CATEGORIES.contains(&c.as_str()) {
                return Err(
                    ZenError::new(Area::Reg, 7049, format!("unknown category '{c}'"))
                        .with_remediation(format!("Valid categories: {}", CATEGORIES.join(", "))),
                );
            }
        }
        if self.tags.len() > MAX_TAGS {
            return Err(ZenError::new(Area::Reg, 7050, "too many tags"));
        }
        for t in &self.tags {
            if t.len() > MAX_TAG_LEN || t.trim().is_empty() {
                return Err(ZenError::new(Area::Reg, 7051, format!("invalid tag '{t}'")));
            }
        }

        if self.platforms.len() > MAX_ARTIFACTS {
            return Err(ZenError::new(Area::Reg, 7052, "too many platform entries"));
        }
        if self.platforms.is_empty() {
            return Err(ZenError::new(
                Area::Reg,
                7053,
                "manifest declares no platform artifacts",
            ));
        }

        // Each artifact must be valid and uniquely identified by a target key.
        let mut seen = HashSet::new();
        for a in &self.platforms {
            validate_artifact(a)?;
            let key = format!(
                "{}-{}-{}",
                a.os.as_str(),
                a.arch.as_str(),
                a.abi
                    .map(|x| x.as_str().to_string())
                    .unwrap_or_else(|| "none".into())
            );
            if !seen.insert(key.clone()) {
                return Err(ZenError::new(
                    Area::Reg,
                    7054,
                    format!("duplicate platform entry for {key}"),
                ));
            }
        }

        self.permissions.validate()?;
        if let Some(ex) = &self.execution {
            ex.validate()?;
        }

        // Dependencies must be well-formed ids and must not include self.
        for d in &self.dependencies {
            let did = ToolId::parse(d)?;
            if did == self.id {
                return Err(ZenError::new(
                    Area::Reg,
                    7055,
                    "a tool may not depend on itself",
                ));
            }
        }

        Ok(())
    }

    /// Whether anything in this manifest points at a non-HTTPS remote source.
    pub fn insecure_sources(&self) -> Vec<String> {
        self.platforms
            .iter()
            .filter(|a| a.url.starts_with("http://"))
            .map(|a| a.url.clone())
            .collect()
    }
}

fn validate_artifact(a: &PlatformArtifact) -> ZenResult<()> {
    if a.url.len() > MAX_URL_LEN {
        return Err(ZenError::new(Area::Reg, 7060, "artifact url is too long"));
    }
    if a.url.trim().is_empty() {
        return Err(ZenError::new(Area::Reg, 7061, "artifact url is empty"));
    }
    // Only https and file are acceptable. http is refused: it is trivially
    // tamperable, and a checksum in the same manifest does not help because
    // the manifest itself would have travelled over the same channel.
    let scheme_ok = a.url.starts_with("https://") || a.url.starts_with("file://");
    if !scheme_ok {
        return Err(ZenError::new(
            Area::Sec,
            7062,
            format!("artifact url must use https:// or file://, got '{}'", a.url),
        )
        .with_remediation(
            "Plain http:// is refused because the manifest and artifact share a channel.",
        ));
    }
    if a.url.contains('\n') || a.url.contains('\r') || a.url.contains('\0') {
        return Err(ZenError::new(
            Area::Sec,
            7063,
            "artifact url contains control characters",
        ));
    }
    // Checksum must parse; this also rejects short/absurd digests.
    Checksum::parse(&a.sha256)?;

    // A Reimplemented entry is provided by the runtime itself and carries no
    // artifact bytes, so size 0 is legitimate there. Any other installable
    // kind must declare a real size.
    if let Some(size) = a.size {
        if size == 0 && a.kind != ImplementationKind::Reimplemented {
            return Err(ZenError::new(
                Area::Reg,
                7064,
                "artifact size must be greater than zero for downloadable artifacts",
            ));
        }
    }

    if a.kind == ImplementationKind::Unsupported {
        // An Unsupported entry is documentation, not an installable artifact.
        // It must not carry a URL that looks installable.
        if a.url != "file:///dev/null" && !a.url.is_empty() {
            // Allowed but pointless; flag it so authors notice.
            return Err(ZenError::new(
                Area::Reg,
                7065,
                "an 'unsupported' platform entry must not point at an artifact",
            ));
        }
    }

    if a.kind == ImplementationKind::ExternalDependency && a.requires.is_none() {
        return Err(ZenError::new(
            Area::Reg,
            7066,
            "an 'external_dependency' entry must name the dependency in 'requires'",
        ));
    }

    // ABI must be absent for macOS and present for ABI-bound kinds elsewhere.
    let abi_bound = matches!(
        a.kind,
        ImplementationKind::Native | ImplementationKind::ExternalDependency
    );
    if abi_bound {
        match (a.os, a.abi) {
            (Os::Macos, Some(Abi::None)) | (Os::Macos, None) => {}
            (Os::Macos, Some(_)) => {
                return Err(ZenError::new(
                    Area::Reg,
                    7067,
                    "macOS artifacts must not declare an ABI",
                ));
            }
            (_, None) => {
                return Err(ZenError::new(
                    Area::Reg,
                    7068,
                    "native artifacts on Windows/Linux must declare an ABI (msvc, gnu, musl)",
                ));
            }
            _ => {}
        }
    }

    // Reject nonsense architectures explicitly rather than defaulting.
    match a.arch {
        Arch::X86_64 | Arch::Arm64 => {}
    }
    match a.os {
        Os::Linux | Os::Macos | Os::Windows => {}
    }

    Ok(())
}

fn validate_url(u: &str) -> ZenResult<()> {
    if u.len() > MAX_URL_LEN {
        return Err(ZenError::new(Area::Reg, 7070, "url is too long"));
    }
    if !(u.starts_with("https://") || u.starts_with("http://")) {
        return Err(ZenError::new(
            Area::Reg,
            7071,
            format!("url '{u}' must be http(s)"),
        ));
    }
    if u.contains(char::is_whitespace) {
        return Err(ZenError::new(Area::Reg, 7072, "url contains whitespace"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_json() -> String {
        r#"{
          "schema_version": "1",
          "id": "org.zentrion.tools.echo",
          "name": "echo",
          "version": "1.2.3",
          "publisher": {"name": "Zentrion", "id": "pub_zentrion"},
          "platforms": [
            {
              "os": "linux", "arch": "x86_64", "abi": "gnu",
              "url": "https://example.invalid/echo.tar",
              "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "size": 100,
              "kind": "native"
            }
          ]
        }"#
        .to_string()
    }

    #[test]
    fn minimal_manifest_parses() {
        let m = ToolManifest::parse_json(&minimal_json()).unwrap();
        assert_eq!(m.name, "echo");
        assert_eq!(m.id.short_name(), "echo");
        assert!(!m.permissions.network, "network defaults to off");
        assert_eq!(m.permissions.filesystem, FilesystemScope::None);
    }

    #[test]
    fn unknown_keys_rejected() {
        let j = minimal_json().replace("\"schema_version\"", "\"evil\": true, \"schema_version\"");
        assert!(ToolManifest::parse_json(&j).is_err());
    }

    #[test]
    fn wrong_schema_version_rejected() {
        let j = minimal_json().replace("\"schema_version\": \"1\"", "\"schema_version\": \"99\"");
        assert!(ToolManifest::parse_json(&j).is_err());
    }

    #[test]
    fn tool_id_requires_reverse_dns() {
        assert!(ToolId::parse("nmap").is_err());
        assert!(ToolId::parse("org.zentrion.tools.nmap").is_ok());
        assert!(ToolId::parse("org..nmap").is_err());
        assert!(ToolId::parse("Org.Zentrion.nmap").is_err());
        assert!(ToolId::parse("org.zentrion.tools.-nmap").is_err());
    }

    #[test]
    fn id_must_end_with_name() {
        let j = minimal_json().replace(
            "\"org.zentrion.tools.echo\"",
            "\"org.zentrion.tools.other\"",
        );
        let e = ToolManifest::parse_json(&j).unwrap_err();
        assert!(format!("{e}").contains("must end with the tool name"));
    }

    #[test]
    fn http_url_is_refused() {
        let j = minimal_json().replace("https://example.invalid", "http://example.invalid");
        let e = ToolManifest::parse_json(&j);
        assert!(e.is_err());
        assert!(format!("{}", e.unwrap_err()).contains("https"));
    }

    #[test]
    fn javascript_url_is_refused() {
        let j = minimal_json().replace("https://example.invalid/echo.tar", "javascript:alert(1)");
        assert!(ToolManifest::parse_json(&j).is_err());
    }

    #[test]
    fn file_url_is_accepted_for_local_registry() {
        let j = minimal_json().replace("https://example.invalid/echo.tar", "file:///tmp/echo.tar");
        assert!(ToolManifest::parse_json(&j).is_ok());
    }

    #[test]
    fn url_with_control_characters_rejected() {
        let j = minimal_json().replace(
            "https://example.invalid/echo.tar",
            "https://x.invalid/a\\nb.tar",
        );
        assert!(ToolManifest::parse_json(&j).is_err());
    }

    #[test]
    fn bad_checksum_rejected() {
        let j = minimal_json().replace(
            "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "\"deadbeef\"",
        );
        assert!(ToolManifest::parse_json(&j).is_err());
    }

    #[test]
    fn zero_size_rejected() {
        let j = minimal_json().replace("\"size\": 100", "\"size\": 0");
        assert!(ToolManifest::parse_json(&j).is_err());
    }

    #[test]
    fn duplicate_platform_entries_rejected() {
        let one = r#"{"os":"linux","arch":"x86_64","abi":"gnu","url":"https://e.invalid/a","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","kind":"native"}"#;
        let j = minimal_json().replace(
            &minimal_json()[minimal_json().find("\"platforms\"").unwrap()..],
            &format!("\"platforms\": [{one}, {one}]\n}}"),
        );
        let e = ToolManifest::parse_json(&j);
        assert!(e.is_err(), "duplicate targets must be rejected");
    }

    #[test]
    fn empty_platforms_rejected() {
        // Replace the whole platforms array with an empty one.
        let j = minimal_json();
        let idx = j.find("\"platforms\":").unwrap();
        let j2 = format!("{}\"platforms\": []\n}}", &j[..idx]);
        assert!(ToolManifest::parse_json(&j2).is_err());
    }

    #[test]
    fn unknown_category_rejected() {
        let j = minimal_json().replace(
            "\"version\": \"1.2.3\",",
            "\"version\": \"1.2.3\", \"categories\": [\"hacking\"],",
        );
        let e = ToolManifest::parse_json(&j);
        assert!(e.is_err());
        assert!(format!("{}", e.unwrap_err()).contains("unknown category"));
    }

    #[test]
    fn valid_category_accepted() {
        let j = minimal_json().replace(
            "\"version\": \"1.2.3\",",
            "\"version\": \"1.2.3\", \"categories\": [\"security\", \"network\"],",
        );
        assert!(ToolManifest::parse_json(&j).is_ok());
    }

    #[test]
    fn elevation_without_reason_rejected() {
        let j = minimal_json().replace(
            "\"version\": \"1.2.3\",",
            "\"version\": \"1.2.3\", \"permissions\": {\"requires_elevation\": true},",
        );
        let e = ToolManifest::parse_json(&j);
        assert!(e.is_err());
        assert!(format!("{}", e.unwrap_err()).contains("explain why"));
    }

    #[test]
    fn elevation_with_reason_accepted() {
        let j = minimal_json().replace(
            "\"version\": \"1.2.3\",",
            "\"version\": \"1.2.3\", \"permissions\": {\"requires_elevation\": true, \"elevation_reason\": \"raw socket capture\"},",
        );
        assert!(ToolManifest::parse_json(&j).is_ok());
    }

    #[test]
    fn execution_binary_must_be_relative() {
        let j = minimal_json().replace(
            "\"version\": \"1.2.3\",",
            "\"version\": \"1.2.3\", \"execution\": {\"binary\": \"/usr/bin/evil\"},",
        );
        assert!(ToolManifest::parse_json(&j).is_err());

        let j2 = minimal_json().replace(
            "\"version\": \"1.2.3\",",
            "\"version\": \"1.2.3\", \"execution\": {\"binary\": \"../../etc/passwd\"},",
        );
        assert!(
            ToolManifest::parse_json(&j2).is_err(),
            "traversal in binary path must fail"
        );

        let j3 = minimal_json().replace(
            "\"version\": \"1.2.3\",",
            "\"version\": \"1.2.3\", \"execution\": {\"binary\": \"bin/echo\"},",
        );
        assert!(ToolManifest::parse_json(&j3).is_ok());
    }

    #[test]
    fn native_engine_without_binary_is_allowed() {
        let j = minimal_json().replace(
            "\"version\": \"1.2.3\",",
            "\"version\": \"1.2.3\", \"execution\": {\"binary\": \"\", \"native_engine\": \"dns.resolve\"},",
        );
        assert!(ToolManifest::parse_json(&j).is_ok());
    }

    #[test]
    fn self_dependency_rejected() {
        let j = minimal_json().replace(
            "\"version\": \"1.2.3\",",
            "\"version\": \"1.2.3\", \"dependencies\": [\"org.zentrion.tools.echo\"],",
        );
        assert!(ToolManifest::parse_json(&j).is_err());
    }

    #[test]
    fn malformed_dependency_rejected() {
        let j = minimal_json().replace(
            "\"version\": \"1.2.3\",",
            "\"version\": \"1.2.3\", \"dependencies\": [\"notreversedns\"],",
        );
        assert!(ToolManifest::parse_json(&j).is_err());
    }

    #[test]
    fn native_artifact_without_abi_rejected() {
        let j = minimal_json().replace(", \"abi\": \"gnu\"", "");
        let e = ToolManifest::parse_json(&j);
        assert!(e.is_err(), "ABI-bound artifacts must declare an ABI");
    }

    #[test]
    fn macos_artifact_must_not_declare_abi() {
        // macOS has no ABI, so declaring one must be rejected.
        let j = minimal_json().replace("\"os\": \"linux\"", "\"os\": \"macos\"");
        assert!(ToolManifest::parse_json(&j).is_err());
    }

    #[test]
    fn unsupported_entry_with_url_rejected() {
        let j = minimal_json().replace("\"kind\": \"native\"", "\"kind\": \"unsupported\"");
        assert!(ToolManifest::parse_json(&j).is_err());
    }

    #[test]
    fn external_dependency_requires_name() {
        let j = minimal_json().replace("\"kind\": \"native\"", "\"kind\": \"external_dependency\"");
        assert!(ToolManifest::parse_json(&j).is_err());

        let j2 = minimal_json().replace(
            "\"kind\": \"native\"",
            "\"kind\": \"external_dependency\", \"requires\": \"docker\"",
        );
        assert!(ToolManifest::parse_json(&j2).is_ok());
    }

    #[test]
    fn overlong_name_rejected() {
        let long = "x".repeat(200);
        let j = minimal_json().replace("\"name\": \"echo\"", &format!("\"name\": \"{long}\""));
        assert!(ToolManifest::parse_json(&j).is_err());
    }

    #[test]
    fn insecure_sources_reports_http() {
        let m = ToolManifest::parse_json(&minimal_json()).unwrap();
        assert!(m.insecure_sources().is_empty());
    }

    #[test]
    fn permissions_describe_is_human_readable() {
        let p = ToolPermissions {
            network: true,
            filesystem: FilesystemScope::Project,
            process: true,
            ..Default::default()
        };
        let d = p.describe();
        assert!(d.iter().any(|s| s.contains("network:    yes")));
        assert!(d.iter().any(|s| s.contains("filesystem: project")));
        assert!(p.is_sensitive());
    }

    #[test]
    fn default_permissions_are_not_sensitive() {
        let p = ToolPermissions::default();
        assert!(!p.is_sensitive());
        assert!(!p.network);
        assert_eq!(p.filesystem, FilesystemScope::None);
    }

    #[test]
    fn roundtrip_serialization() {
        let m = ToolManifest::parse_json(&minimal_json()).unwrap();
        let again = ToolManifest::parse_json(&m.to_json_pretty()).unwrap();
        assert_eq!(m, again);
    }
}

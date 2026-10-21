//! WASM plugin discovery and validation.
//!
//! This crate validates plugin artifacts and their manifests, records their
//! SHA-256 digest, and keeps a registry. Execution lives in [`crate::runtime`],
//! which runs a module in wasmtime with explicit capability grants, fuel and
//! memory limits. Validation alone never executes anything.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const WASM_MAGIC: &[u8; 4] = b"\0asm";
const WASM_VERSION: [u8; 4] = [1, 0, 0, 0];

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginType {
    Wasm,
    Native,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub plugin_type: PluginType,
    pub entrypoint: String,
    /// Capabilities the plugin declares it needs. Validation does not grant
    /// them; a future runtime must mediate each one.
    #[serde(default)]
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ValidatedPlugin {
    pub manifest: PluginManifest,
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
}

pub struct PluginManager {
    plugins: Vec<ValidatedPlugin>,
    dir: Option<PathBuf>,
}

impl PluginManager {
    pub fn new() -> Self {
        let dir = z_core::config::user_data_dir().map(|base| base.join("plugins"));
        Self {
            plugins: Vec::new(),
            dir,
        }
    }

    pub fn with_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            plugins: Vec::new(),
            dir: Some(dir.into()),
        }
    }

    pub fn plugins(&self) -> &[ValidatedPlugin] {
        &self.plugins
    }

    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }

    /// Validate a `.wasm` file and register it (no execution).
    pub fn load<P: AsRef<Path>>(&mut self, wasm_path: P) -> Result<ValidatedPlugin> {
        let plugin = validate_plugin(wasm_path.as_ref())?;
        if self
            .plugins
            .iter()
            .any(|existing| existing.path == plugin.path)
        {
            return Err(anyhow!("plugin already loaded: {}", plugin.path.display()));
        }
        self.plugins.push(plugin.clone());
        Ok(plugin)
    }

    /// Scan the plugin directory for valid modules.
    pub fn load_all(&mut self) -> Result<Vec<ValidatedPlugin>> {
        let Some(dir) = self.dir.clone() else {
            return Ok(Vec::new());
        };
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut loaded = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("wasm") {
                if let Ok(plugin) = validate_plugin(&path) {
                    loaded.push(plugin);
                }
            }
        }
        self.plugins.extend(loaded.iter().cloned());
        Ok(loaded)
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate the WASM header and optional sidecar manifest.
///
/// A sidecar is `<file>.json` (for `foo.wasm`, `foo.wasm.json`). If present it
/// must be a valid manifest; if absent, a conservative manifest is derived from
/// the filename and the plugin is marked as having no declared permissions.
pub fn validate_plugin(path: &Path) -> Result<ValidatedPlugin> {
    if !path.exists() {
        return Err(anyhow!("plugin does not exist: {}", path.display()));
    }
    if path.extension().and_then(|e| e.to_str()) != Some("wasm") {
        return Err(anyhow!("plugin must be a .wasm file: {}", path.display()));
    }
    let bytes =
        std::fs::read(path).with_context(|| format!("cannot read plugin {}", path.display()))?;
    if bytes.len() < 8 || &bytes[..4] != WASM_MAGIC {
        return Err(anyhow!(
            "{} is not a WebAssembly module (bad magic)",
            path.display()
        ));
    }
    if bytes[4..8] != WASM_VERSION {
        return Err(anyhow!(
            "{} uses an unsupported WASM version: {:?}",
            path.display(),
            &bytes[4..8]
        ));
    }

    let digest = Sha256::digest(&bytes);
    let sha256 = hex::encode(digest);

    let sidecar = path.with_extension("wasm.json");
    let manifest = if sidecar.exists() {
        let text = std::fs::read_to_string(&sidecar)
            .with_context(|| format!("cannot read manifest {}", sidecar.display()))?;
        let mut manifest: PluginManifest = serde_json::from_str(&text)
            .with_context(|| format!("invalid manifest {}", sidecar.display()))?;
        if manifest.name.trim().is_empty() {
            return Err(anyhow!("manifest name cannot be empty"));
        }
        if manifest.entrypoint.trim().is_empty() {
            manifest.entrypoint = "_start".into();
        }
        manifest
    } else {
        PluginManifest {
            name: path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            version: "0.0.0".into(),
            plugin_type: PluginType::Wasm,
            entrypoint: "_start".into(),
            permissions: Vec::new(),
        }
    };

    Ok(ValidatedPlugin {
        manifest,
        path: path.to_path_buf(),
        sha256,
        size: bytes.len() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-plugin-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn rand_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    fn minimal_wasm() -> Vec<u8> {
        let mut bytes = b"\0asm".to_vec();
        bytes.extend_from_slice(&WASM_VERSION);
        bytes
    }

    #[test]
    fn accepts_valid_header_and_derives_manifest() {
        let dir = temp_dir();
        let path = dir.join("hello.wasm");
        std::fs::write(&path, minimal_wasm()).unwrap();
        let plugin = validate_plugin(&path).unwrap();
        assert_eq!(plugin.manifest.name, "hello");
        assert_eq!(plugin.manifest.permissions.len(), 0);
        assert_eq!(plugin.sha256.len(), 64);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_non_wasm_file() {
        let dir = temp_dir();
        let path = dir.join("evil.wasm");
        std::fs::write(&path, b"#!/bin/sh\necho pwned").unwrap();
        assert!(validate_plugin(&path).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sidecar_manifest_is_parsed() {
        let dir = temp_dir();
        let path = dir.join("plugin.wasm");
        std::fs::write(&path, minimal_wasm()).unwrap();
        std::fs::write(
            path.with_extension("wasm.json"),
            r#"{"name":"demo","version":"1.2.0","plugin_type":"wasm","entrypoint":"run","permissions":["network"]}"#,
        )
        .unwrap();
        let plugin = validate_plugin(&path).unwrap();
        assert_eq!(plugin.manifest.name, "demo");
        assert_eq!(plugin.manifest.version, "1.2.0");
        assert_eq!(plugin.manifest.permissions, vec!["network".to_string()]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn manager_load_is_idempotent_checked() {
        let dir = temp_dir();
        let path = dir.join("one.wasm");
        std::fs::write(&path, minimal_wasm()).unwrap();
        let mut manager = PluginManager::with_dir(&dir);
        assert!(manager.load(&path).is_ok());
        assert!(manager.load(&path).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}

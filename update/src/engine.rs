//! Update engine: manifest check, SHA-256 verification, atomic replacement and
//! rollback.
//!
//! A manifest is JSON:
//! ```json
//! { "version": "1.2.0", "url": "https://example.com/z", "sha256": "…", "notes": "…" }
//! ```
//!
//! The URL may be `https://`, `file://` or an absolute path. Plain `http://`
//! is refused unless `ZENTRION_ALLOW_INSECURE_UPDATE=1` is set.
//!
//! Integrity model: the manifest pins the SHA-256 of the artifact. Transport
//! security (HTTPS) protects the manifest itself. Signed manifests are not
//! implemented yet, so a compromised update host remains in the trust path.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_ARTIFACT: u64 = 200 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub version: String,
    pub url: String,
    pub sha256: String,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpdateInfo {
    pub current: String,
    pub manifest: UpdateManifest,
}

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn manifest_source() -> Result<String> {
    std::env::var("ZENTRION_UPDATE_MANIFEST")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            anyhow!(
                "no update channel configured; set ZENTRION_UPDATE_MANIFEST to a manifest path or HTTPS URL"
            )
        })
}

fn allow_insecure() -> bool {
    matches!(
        std::env::var("ZENTRION_ALLOW_INSECURE_UPDATE").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn load_manifest() -> Result<UpdateManifest> {
    let source = manifest_source()?;
    let bytes = if source.starts_with("https://") {
        http_get(&source)?
    } else if source.starts_with("http://") {
        if !allow_insecure() {
            bail!(
                "refusing plain HTTP manifest; use HTTPS or set ZENTRION_ALLOW_INSECURE_UPDATE=1"
            );
        }
        http_get(&source)?
    } else if let Some(path) = source.strip_prefix("file://") {
        std::fs::read(path).with_context(|| format!("cannot read manifest {path}"))?
    } else {
        std::fs::read(&source).with_context(|| format!("cannot read manifest {source}"))?
    };
    let manifest: UpdateManifest = serde_json::from_slice(&bytes)
        .context("update manifest is not valid JSON with version/url/sha256")?;
    if manifest.version.trim().is_empty() {
        bail!("update manifest has an empty version");
    }
    if manifest.sha256.len() != 64 || !manifest.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("update manifest must pin a 64-character SHA-256 digest");
    }
    Ok(manifest)
}

pub fn check_update() -> Result<Option<UpdateInfo>> {
    let manifest = load_manifest()?;
    let current = current_version();
    if version_is_newer(&manifest.version, current)? {
        Ok(Some(UpdateInfo {
            current: current.to_string(),
            manifest,
        }))
    } else {
        Ok(None)
    }
}

pub fn check_updates() -> Result<bool> {
    Ok(check_update()?.is_some())
}

/// Download, verify and activate the update. Returns the version now on disk.
pub fn apply_update() -> Result<String> {
    let Some(info) = check_update()? else {
        return Err(anyhow!(
            "already up to date (current {})",
            current_version()
        ));
    };
    let bytes = fetch_artifact(&info.manifest.url)?;
    let actual = hex::encode(Sha256::digest(&bytes));
    if !actual.eq_ignore_ascii_case(&info.manifest.sha256) {
        bail!(
            "artifact checksum mismatch: expected {}, got {}",
            info.manifest.sha256,
            actual
        );
    }
    let target = target_executable()?;
    stage_and_install(&target, &bytes)?;
    Ok(info.manifest.version)
}

/// Restore the previous binary, if one was saved by `apply_update`.
pub fn rollback() -> Result<String> {
    let target = target_executable()?;
    let backup = backup_path(&target);
    if !backup.exists() {
        return Err(anyhow!(
            "no previous version to roll back to ({})",
            backup.display()
        ));
    }
    #[cfg(unix)]
    {
        let failed = target.with_extension("failed");
        if target.exists() {
            std::fs::rename(&target, &failed)
                .context("cannot move the current binary aside for rollback")?;
        }
        if let Err(e) = std::fs::rename(&backup, &target) {
            // Try to restore the moved binary so the installation still works.
            let _ = std::fs::rename(&failed, &target);
            return Err(anyhow!("rollback failed: {e}"));
        }
        let _ = std::fs::remove_file(&failed);
    }
    #[cfg(not(unix))]
    {
        return Err(anyhow!(
            "in-place rollback is not supported on this platform; restore {} manually",
            backup.display()
        ));
    }
    Ok(current_version().to_string())
}

fn target_executable() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("ZENTRION_UPDATE_TARGET") {
        if !path.trim().is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    std::env::current_exe().context("cannot determine the current executable")
}

fn backup_path(target: &Path) -> PathBuf {
    target.with_extension("old")
}

fn stage_and_install(target: &Path, bytes: &[u8]) -> Result<()> {
    let staged = target.with_extension("new");
    std::fs::write(&staged, bytes)
        .with_context(|| format!("cannot stage update at {}", staged.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
    }

    #[cfg(unix)]
    {
        let backup = backup_path(target);
        if target.exists() {
            let _ = std::fs::remove_file(&backup);
            std::fs::rename(target, &backup).with_context(|| {
                format!("cannot save the current binary to {}", backup.display())
            })?;
        }
        if let Err(e) = std::fs::rename(&staged, target) {
            let _ = std::fs::rename(&backup, target);
            return Err(anyhow!("cannot activate the staged update: {e}"));
        }
    }
    #[cfg(not(unix))]
    {
        // Windows cannot replace a running executable. Leave the verified
        // artifact next to it and let the installer finish after exit.
        let _ = target;
    }
    Ok(())
}

fn fetch_artifact(url: &str) -> Result<Vec<u8>> {
    if url.starts_with("https://") {
        return http_get(url);
    }
    if url.starts_with("http://") {
        if !allow_insecure() {
            bail!("refusing plain HTTP artifact; use HTTPS");
        }
        return http_get(url);
    }
    if let Some(path) = url.strip_prefix("file://") {
        return read_limited(Path::new(path));
    }
    read_limited(Path::new(url))
}

fn read_limited(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("cannot stat update artifact {}", path.display()))?;
    if metadata.len() > MAX_ARTIFACT {
        bail!("artifact is larger than the {} byte limit", MAX_ARTIFACT);
    }
    let bytes = std::fs::read(path)
        .with_context(|| format!("cannot read update artifact {}", path.display()))?;
    Ok(bytes)
}

fn http_get(url: &str) -> Result<Vec<u8>> {
    let response = ureq::get(url)
        .timeout(std::time::Duration::from_secs(60))
        .call()
        .with_context(|| format!("GET {url} failed"))?;
    let status = response.status();
    if !(200..300).contains(&status) {
        bail!("GET {url} returned {status}");
    }
    if let Some(length) = response.header("content-length") {
        if let Ok(length) = length.parse::<u64>() {
            if length > MAX_ARTIFACT {
                bail!("artifact is larger than the {} byte limit", MAX_ARTIFACT);
            }
        }
    }
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_ARTIFACT + 1)
        .read_to_end(&mut bytes)
        .context("reading the update artifact failed")?;
    if bytes.len() as u64 > MAX_ARTIFACT {
        bail!("artifact exceeded the {} byte limit", MAX_ARTIFACT);
    }
    Ok(bytes)
}

fn version_is_newer(candidate: &str, current: &str) -> Result<bool> {
    let parse = |value: &str| -> Result<(u64, u64, u64)> {
        let core = value
            .trim()
            .trim_start_matches('v')
            .split(['-', '+'])
            .next()
            .unwrap_or(value);
        let mut parts = core.split('.');
        let major = parts.next().unwrap_or("0").parse().unwrap_or(0);
        let minor = parts.next().unwrap_or("0").parse().unwrap_or(0);
        let patch = parts.next().unwrap_or("0").parse().unwrap_or(0);
        Ok((major, minor, patch))
    };
    Ok(parse(candidate)? > parse(current)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-update-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_fixture(dir: &Path, artifact: &[u8], wrong_sum: bool) -> (PathBuf, PathBuf) {
        let target = dir.join("z");
        std::fs::write(&target, b"old-binary").unwrap();
        let artifact_path = dir.join("z-new");
        std::fs::write(&artifact_path, artifact).unwrap();
        let digest = if wrong_sum {
            "0".repeat(64)
        } else {
            hex::encode(Sha256::digest(artifact))
        };
        let manifest = dir.join("manifest.json");
        std::fs::write(
            &manifest,
            serde_json::to_vec(&serde_json::json!({
                "version": "9.9.9",
                "url": format!("file://{}", artifact_path.display()),
                "sha256": digest,
            }))
            .unwrap(),
        )
        .unwrap();
        (manifest, target)
    }

    #[test]
    fn newer_versions_compare_correctly() {
        assert!(version_is_newer("1.2.0", "1.1.9").unwrap());
        assert!(!version_is_newer("1.1.9", "1.2.0").unwrap());
        assert!(!version_is_newer("1.0.0", "1.0.0").unwrap());
        assert!(version_is_newer("v2.0.0-beta", "1.9.9").unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn applies_verified_update_and_rolls_back() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = temp_dir();
        let (manifest, target) = write_fixture(&dir, b"new-binary", false);
        std::env::set_var("ZENTRION_UPDATE_MANIFEST", &manifest);
        std::env::set_var("ZENTRION_UPDATE_TARGET", &target);

        let version = apply_update().unwrap();
        assert_eq!(version, "9.9.9");
        assert_eq!(std::fs::read(&target).unwrap(), b"new-binary");
        assert_eq!(std::fs::read(backup_path(&target)).unwrap(), b"old-binary");

        rollback().unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"old-binary");

        std::env::remove_var("ZENTRION_UPDATE_MANIFEST");
        std::env::remove_var("ZENTRION_UPDATE_TARGET");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn checksum_mismatch_leaves_target_untouched() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = temp_dir();
        let (manifest, target) = write_fixture(&dir, b"evil", true);
        std::env::set_var("ZENTRION_UPDATE_MANIFEST", &manifest);
        std::env::set_var("ZENTRION_UPDATE_TARGET", &target);

        assert!(apply_update().is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"old-binary");

        std::env::remove_var("ZENTRION_UPDATE_MANIFEST");
        std::env::remove_var("ZENTRION_UPDATE_TARGET");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_channel_is_an_error_not_a_fake_success() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("ZENTRION_UPDATE_MANIFEST");
        assert!(check_update().is_err());
    }
}

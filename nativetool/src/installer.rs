//! Transactional tool installation.
//!
//! Flow (Phase 2 §17/§49):
//!   prepare → resolve → fetch → verify checksum → verify signature →
//!   stage (extract) → validate executable → activate → audit
//!
//! Nothing is marked active until every verification step has passed. On any
//! failure the staging area is removed, keeping any previous installation
//! intact. A failed artifact is quarantined so it cannot be retried blindly.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use z_compat::{resolve, Compatibility};
use z_core::error::{Area, ZenError, ZenResult};
use z_native::fs as nfs;
use z_native::PlatformTarget;
use z_package::extract::{extract_archive, ArchiveFormat, ExtractionLimits};
use z_package::signature::{self, SignatureOutcome};
use z_package::Checksum;

use crate::manifest::ToolManifest;
use crate::store::{InstallRecord, ToolStore};

/// Where an artifact came from. Kept explicit so the audit trail and the
/// install record can state the true origin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactSource {
    /// Read from the local filesystem (file:// or a local registry path).
    LocalFile(PathBuf),
    /// Already present in the verified artifact cache.
    Cache(PathBuf),
    /// Fetched over the network.
    Remote(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallPlan {
    pub tool_id: String,
    pub name: String,
    pub version: String,
    pub target: String,
    pub kind: String,
    pub artifact_url: String,
    pub artifact_sha256: String,
    pub artifact_size: Option<u64>,
    pub publisher: String,
    pub license: Option<String>,
    pub permissions: Vec<String>,
    pub requires_acknowledgement: bool,
    pub quarantined_first_run: bool,
    pub destination: String,
    pub compatibility_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallOutcome {
    pub name: String,
    pub version: String,
    pub target: String,
    pub kind: String,
    pub artifact_sha256: String,
    pub source: String,
    pub signature: String,
    pub files: Vec<String>,
    pub activated: bool,
    pub already_present: bool,
}

/// Compute the full plan for an install without touching the filesystem.
pub fn plan(
    manifest: &ToolManifest,
    target: &PlatformTarget,
    store: &ToolStore,
) -> ZenResult<(InstallPlan, Compatibility)> {
    let compat = resolve(&manifest.platforms, target);
    if !compat.is_installable() {
        return Err(ZenError::new(
            Area::Reg,
            7300,
            format!("{} is not available on {}", manifest.name, target.id()),
        )
        .with_remediation(if compat.alternatives.is_empty() {
            "No implementation exists for this platform.".to_string()
        } else {
            format!("Available on: {}", compat.alternatives.join(", "))
        }));
    }

    let artifact = compat
        .artifact
        .as_ref()
        .ok_or_else(|| ZenError::new(Area::Reg, 7301, "internal: installable but no artifact"))?;

    let dest = store.version_dir(&manifest.name, &manifest.version)?;

    Ok((
        InstallPlan {
            tool_id: manifest.id.to_string(),
            name: manifest.name.clone(),
            version: manifest.version.clone(),
            target: target.id(),
            kind: format!("{:?}", compat.kind).to_lowercase(),
            artifact_url: artifact.url.clone(),
            artifact_sha256: artifact.sha256.clone(),
            artifact_size: artifact.size,
            publisher: manifest.publisher.name.clone(),
            license: manifest.license.clone(),
            permissions: manifest.permissions.describe(),
            requires_acknowledgement: compat.kind.requires_notice(),
            quarantined_first_run: true,
            destination: dest.display().to_string(),
            compatibility_note: compat.explanation.clone(),
        },
        compat,
    ))
}

/// Install a tool from a manifest.
///
/// `artifact_loader` supplies the bytes for a URL. It is injected so that
/// tests run fully offline and so the network path is explicit, not implicit.
pub fn install<F>(
    manifest: &ToolManifest,
    target: &PlatformTarget,
    store: &ToolStore,
    source_registry: &str,
    artifact_loader: F,
) -> ZenResult<InstallOutcome>
where
    F: Fn(&str) -> ZenResult<Vec<u8>>,
{
    let (plan, compat) = plan(manifest, target, store)?;
    let artifact = compat.artifact.as_ref().unwrap();

    // Idempotence: if this exact version is already installed, say so rather
    // than reinstalling over it.
    let dest = store.version_dir(&manifest.name, &manifest.version)?;
    if dest.is_dir()
        && store
            .read_record(&manifest.name, &manifest.version)?
            .is_some()
    {
        return Ok(InstallOutcome {
            name: manifest.name.clone(),
            version: manifest.version.clone(),
            target: plan.target,
            kind: plan.kind,
            artifact_sha256: plan.artifact_sha256,
            source: "already installed".into(),
            signature: "n/a".into(),
            files: vec![],
            activated: store.active_version(&manifest.name)?.as_deref() == Some(&manifest.version),
            already_present: true,
        });
    }

    // --- 1. Signature policy check (before any bytes are fetched) ----------
    let sig_outcome = if manifest.signature_required {
        // No verified signature can be produced in this build, so a tool that
        // requires one must fail closed here rather than install anyway.
        SignatureOutcome::Unsupported {
            reason: "no signature backend is compiled in Phase 2".to_string(),
        }
    } else {
        SignatureOutcome::Missing
    };
    if let Err(e) = signature::satisfies(manifest.signature_required, &sig_outcome) {
        return Err(ZenError::new(
            Area::Sec,
            7302,
            format!("signature requirement not met: {e}"),
        )
        .with_remediation(
            "This artifact requires a verified signature, which this build cannot check.",
        ));
    }

    // --- 2. Fetch bytes (cache first) --------------------------------------
    let expected = Checksum::parse(&artifact.sha256)?;
    let cache_path = store.cache_path(&expected.hex)?;

    let (bytes, source_desc) = if cache_path.is_file() {
        // A cached artifact is only trusted after re-verification. A poisoned
        // cache must not be usable.
        let b = z_package::extract::read_bounded(&cache_path, 512 * 1024 * 1024)?;
        (b, format!("cache {}", cache_path.display()))
    } else {
        let b = artifact_loader(&artifact.url)?;
        // Record the download size limit check.
        if let Some(size) = artifact.size {
            if b.len() as u64 != size {
                return Err(ZenError::new(
                    Area::Sec,
                    7303,
                    format!(
                        "artifact size mismatch: manifest says {size} bytes, got {}",
                        b.len()
                    ),
                ));
            }
        }
        (b, artifact.url.clone())
    };

    // --- 3. Verify checksum BEFORE anything is written or extracted --------
    if let Err(e) = z_package::checksum::verify_bytes(&expected, &bytes) {
        quarantine(store, &bytes, &expected.hex, &artifact.url);
        return Err(e);
    }

    // Cache the verified artifact.
    if !cache_path.is_file() {
        std::fs::create_dir_all(store.cache_dir())?;
        let tmp = cache_path.with_extension("partial");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &cache_path)?;
    }

    // --- 4. Stage -----------------------------------------------------------
    let staging = nfs::private_temp_dir("zen-install-stage")?;
    let result = (|| -> ZenResult<Vec<String>> {
        let files = match manifest
            .execution
            .as_ref()
            .and_then(|e| e.native_engine.as_ref())
        {
            Some(_engine) => {
                // A native-engine tool has no artifact to unpack; we only
                // record the installation. `files` stays empty.
                Vec::new()
            }
            None => {
                let bytes = if archive_magic(&bytes) {
                    let format = if bytes.starts_with(&[0x1f, 0x8b]) {
                        ArchiveFormat::TarGz
                    } else {
                        ArchiveFormat::Tar
                    };
                    extract_archive(&bytes, format, &staging, &ExtractionLimits::default())?.files
                } else {
                    // A bare executable: write it directly under bin/.
                    std::fs::create_dir_all(staging.join("bin"))?;
                    let name = binary_basename(
                        manifest
                            .execution
                            .as_ref()
                            .map(|e| e.binary.as_str())
                            .unwrap_or(""),
                        &manifest.name,
                    );
                    std::fs::write(staging.join("bin").join(&name), &bytes)?;
                    vec![format!("bin/{name}")]
                };
                bytes
            }
        };
        Ok(files)
    })();

    let files = match result {
        Ok(f) => f,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e);
        }
    };

    // --- 5. Validate the expected executable exists -------------------------
    let exec_rel = manifest.execution.as_ref().map(|e| e.binary.clone());
    let has_native_engine = manifest
        .execution
        .as_ref()
        .and_then(|e| e.native_engine.as_ref())
        .is_some();

    if !has_native_engine {
        let bin_rel = exec_rel.clone().ok_or_else(|| {
            ZenError::new(Area::Reg, 7304, "manifest declares no execution.binary")
        })?;
        let bin_abs = nfs::ensure_within(&staging, Path::new(&bin_rel))?;
        if !bin_abs.is_file() {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(ZenError::new(
                Area::Reg,
                7305,
                format!("expected executable '{bin_rel}' is not present in the artifact"),
            )
            .with_remediation("The artifact does not match the manifest."));
        }
        // Make it executable on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&bin_abs, std::fs::Permissions::from_mode(0o755));
        }
        // Defence in depth: an artifact that unpacks a symlink at the binary
        // path is exactly what we refuse.
        let meta = std::fs::symlink_metadata(&bin_abs)?;
        if meta.file_type().is_symlink() {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(ZenError::new(
                Area::Sec,
                7306,
                "the declared executable is a symlink, which is not permitted",
            ));
        }
    }

    // --- 6. Move staging into place ----------------------------------------
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Remove a partial leftover at the destination (a previous failed install)
    // before renaming. The previous *version* is a different directory, so it
    // is untouched.
    if dest.exists() {
        std::fs::remove_dir_all(&dest)?;
    }
    if let Err(e) = std::fs::rename(&staging, &dest) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(ZenError::new(
            Area::Fs,
            7307,
            format!("could not activate the installation: {e}"),
        ));
    }

    // --- 7. Write the manifest and our install record ----------------------
    std::fs::write(dest.join("manifest.json"), manifest.to_json_pretty())?;

    let record = InstallRecord {
        tool_id: manifest.id.to_string(),
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        platform: plan.target.clone(),
        artifact_sha256: artifact.sha256.clone(),
        artifact_url: artifact.url.clone(),
        publisher_id: manifest.publisher.id.clone(),
        publisher_name: manifest.publisher.name.clone(),
        kind: plan.kind.clone(),
        license: manifest.license.clone(),
        installed_at: chrono::Utc::now().to_rfc3339(),
        source_registry: source_registry.to_string(),
        signature: sig_outcome.summary(),
        permissions_summary: plan.permissions.clone(),
    };
    store.write_record(&dest, &record)?;

    // --- 8. Activate --------------------------------------------------------
    let _previously_active = store.active_version(&manifest.name)?;
    store.set_active(&manifest.name, &manifest.version)?;

    Ok(InstallOutcome {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        target: plan.target,
        kind: plan.kind,
        artifact_sha256: artifact.sha256.clone(),
        source: source_desc,
        signature: sig_outcome.summary(),
        files,
        activated: true,
        already_present: false,
        // `previously_active` is reported by the caller via the record if needed.
    })
}

/// Move a failed artifact to quarantine so it cannot be silently retried.
fn quarantine(store: &ToolStore, bytes: &[u8], sha: &str, url: &str) {
    if let Ok(p) = store.quarantine_path(sha) {
        let mut body = format!(
            "# quarantined artifact\n# sha256: {sha}\n# url: {url}\n# reason: checksum mismatch\n\n"
        )
        .into_bytes();
        body.extend_from_slice(bytes);
        let _ = std::fs::write(&p, body);
    }
}

fn archive_magic(bytes: &[u8]) -> bool {
    (bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b)
        || (bytes.len() >= 265 && &bytes[257..262] == b"ustar")
}

fn binary_basename(declared: &str, fallback: &str) -> String {
    let name = if declared.is_empty() {
        fallback
    } else {
        declared
    };
    Path::new(name)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| fallback.to_string())
}

/// Remove an installed version, keeping other versions intact.
pub fn remove(store: &ToolStore, name: &str, version: Option<&str>) -> ZenResult<usize> {
    store.remove(name, version)
}

/// Roll back to the highest other installed version.
pub fn rollback(store: &ToolStore, name: &str) -> ZenResult<(String, String)> {
    let versions = store.installed_versions(name)?;
    if versions.is_empty() {
        return Err(ZenError::new(
            Area::Reg,
            7310,
            format!("{name} is not installed"),
        ));
    }
    let current = store.active_version(name)?;
    let target = versions
        .iter()
        .filter(|v| Some(v.as_str()) != current.as_deref())
        .max_by(
            |a, b| match (z_version::Version::parse(a), z_version::Version::parse(b)) {
                (Ok(x), Ok(y)) => x.cmp(&y),
                _ => a.cmp(b),
            },
        )
        .cloned();

    match target {
        Some(v) => {
            store.set_active(name, &v)?;
            Ok((current.unwrap_or_else(|| "none".into()), v))
        }
        None => Err(ZenError::new(
            Area::Reg,
            7311,
            format!("{name} has no other installed version to roll back to"),
        )
        .with_remediation("Install an earlier version first.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::ToolManifest;
    use z_native::fs::private_temp_dir;
    use z_package::checksum::sha256_hex;

    const TARGET: &str = "linux-x86_64-gnu";

    fn target() -> PlatformTarget {
        PlatformTarget::current()
    }

    fn tar_with(name: &str, data: &[u8]) -> Vec<u8> {
        let mut h = [0u8; 512];
        h[..name.len().min(100)].copy_from_slice(&name.as_bytes()[..name.len().min(100)]);
        h[100..108].copy_from_slice(b"0000755\0");
        h[108..116].copy_from_slice(b"0000000\0");
        h[116..124].copy_from_slice(b"0000000\0");
        h[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        h[136..148].copy_from_slice(b"00000000000\0");
        h[148..156].copy_from_slice(b"        ");
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        let mut out = h.to_vec();
        out.extend_from_slice(data);
        let pad = (512 - (data.len() % 512)) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
        out.extend(std::iter::repeat_n(0u8, 1024));
        out
    }

    fn manifest_for(name: &str, version: &str, artifact: &[u8], binary: &str) -> ToolManifest {
        let sha = sha256_hex(artifact);
        let json = format!(
            r#"{{
  "schema_version": "1",
  "id": "org.zentrion.tools.{name}",
  "name": "{name}",
  "version": "{version}",
  "publisher": {{"name": "Zentrion", "id": "pub_zentrion"}},
  "license": "MIT",
  "categories": ["development"],
  "platforms": [{{
     "os": "{}", "arch": "{}", "abi": "{}",
     "url": "file:///tmp/{name}.tar",
     "sha256": "{sha}",
     "size": {size},
     "kind": "native"
  }}],
  "permissions": {{"network": false, "filesystem": "project", "process": true}},
  "execution": {{"binary": "{binary}"}}
}}"#,
            target().os.as_str(),
            target().arch.as_str(),
            match target().abi {
                z_native::Abi::Gnu => "gnu",
                z_native::Abi::Musl => "musl",
                z_native::Abi::Msvc => "msvc",
                z_native::Abi::Wingnu => "wingnu",
                z_native::Abi::None => "none",
            },
            size = artifact.len(),
        );
        ToolManifest::parse_json(&json).unwrap()
    }

    fn loader(bytes: Vec<u8>) -> impl Fn(&str) -> ZenResult<Vec<u8>> {
        move |_url: &str| Ok(bytes.clone())
    }

    #[test]
    fn plan_reports_unsupported_for_other_platform() {
        let d = private_temp_dir("zen-inst-unsup").unwrap();
        let store = ToolStore::at(d.clone()).unwrap();
        let art = tar_with("bin/echo", b"#!/bin/sh\n");
        let m = manifest_for("echo", "1.0.0", &art, "bin/echo");
        // Resolve against a platform the manifest does not cover.
        let other = PlatformTarget::new(
            z_native::Os::Windows,
            z_native::Arch::X86_64,
            z_native::Abi::Msvc,
        );
        let e = plan(&m, &other, &store);
        assert!(e.is_err());
        assert!(format!("{}", e.unwrap_err()).contains("not available"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn install_extracts_and_activates() {
        let d = private_temp_dir("zen-inst-ok").unwrap();
        let store = ToolStore::at(d.clone()).unwrap();
        let art = tar_with("bin/echo", b"#!/bin/sh\necho hi\n");
        let m = manifest_for("echo", "1.0.0", &art, "bin/echo");
        let out = install(&m, &target(), &store, "test", loader(art)).unwrap();
        assert!(out.activated);
        assert!(!out.already_present);
        let vd = store.version_dir("echo", "1.0.0").unwrap();
        assert!(vd.join("bin/echo").is_file());
        assert!(vd.join("manifest.json").is_file());
        assert!(vd.join("metadata.json").is_file());
        assert_eq!(
            store.active_version("echo").unwrap().as_deref(),
            Some("1.0.0")
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn installed_binary_is_executable_on_unix() {
        let d = private_temp_dir("zen-inst-exec").unwrap();
        let store = ToolStore::at(d.clone()).unwrap();
        let art = tar_with("bin/run", b"#!/bin/sh\n");
        let m = manifest_for("run", "1.0.0", &art, "bin/run");
        install(&m, &target(), &store, "test", loader(art)).unwrap();
        let bin = store.version_dir("run", "1.0.0").unwrap().join("bin/run");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&bin).unwrap().permissions().mode();
            assert!(mode & 0o111 != 0, "installed binary must be executable");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn checksum_mismatch_is_refused_and_quarantined() {
        let d = private_temp_dir("zen-inst-bad").unwrap();
        let store = ToolStore::at(d.clone()).unwrap();
        let art = tar_with("bin/echo", b"good");
        let m = manifest_for("echo", "1.0.0", &art, "bin/echo");
        // Supply different bytes than the manifest describes.
        let tampered = tar_with("bin/echo", b"EVIL");
        let e = install(&m, &target(), &store, "test", loader(tampered));
        assert!(e.is_err());
        assert!(format!("{}", e.unwrap_err()).contains("checksum mismatch"));
        // Nothing activated.
        assert_eq!(store.active_version("echo").unwrap(), None);
        assert!(!store.version_dir("echo", "1.0.0").unwrap().exists());
        // Quarantine file created.
        let q = store.quarantine_dir();
        assert!(q.is_dir() && std::fs::read_dir(&q).unwrap().count() == 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn size_mismatch_is_refused() {
        let d = private_temp_dir("zen-inst-size").unwrap();
        let store = ToolStore::at(d.clone()).unwrap();
        let art = tar_with("bin/echo", b"abc");
        let mut m = manifest_for("echo", "1.0.0", &art, "bin/echo");
        // Lie about the size in the manifest.
        m.platforms[0].size = Some(art.len() as u64 + 100);
        let e = install(&m, &target(), &store, "test", loader(art));
        assert!(e.is_err());
        assert!(format!("{}", e.unwrap_err()).contains("size mismatch"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn missing_declared_executable_is_refused() {
        let d = private_temp_dir("zen-inst-noexec").unwrap();
        let store = ToolStore::at(d.clone()).unwrap();
        let art = tar_with("bin/other", b"x");
        let m = manifest_for("echo", "1.0.0", &art, "bin/echo"); // declares bin/echo
        let e = install(&m, &target(), &store, "test", loader(art));
        assert!(e.is_err());
        assert!(format!("{}", e.unwrap_err()).contains("not present"));
        assert_eq!(store.active_version("echo").unwrap(), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn malicious_archive_is_refused_during_install() {
        let d = private_temp_dir("zen-inst-trav").unwrap();
        let store = ToolStore::at(d.clone()).unwrap();
        let art = tar_with("../../../etc/evil", b"pwn");
        let m = manifest_for("echo", "1.0.0", &art, "bin/echo");
        let e = install(&m, &target(), &store, "test", loader(art));
        assert!(e.is_err(), "traversal archive must not install");
        assert_eq!(store.active_version("echo").unwrap(), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn bare_executable_artifact_is_installed() {
        let d = private_temp_dir("zen-inst-raw").unwrap();
        let store = ToolStore::at(d.clone()).unwrap();
        let art = b"#!/bin/sh\necho raw\n".to_vec();
        let m = manifest_for("raw", "1.0.0", &art, "bin/raw");
        let out = install(&m, &target(), &store, "test", loader(art)).unwrap();
        assert!(out.activated);
        assert!(store
            .version_dir("raw", "1.0.0")
            .unwrap()
            .join("bin/raw")
            .is_file());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn reinstall_of_same_version_is_idempotent() {
        let d = private_temp_dir("zen-inst-idem").unwrap();
        let store = ToolStore::at(d.clone()).unwrap();
        let art = tar_with("bin/echo", b"x");
        let m = manifest_for("echo", "1.0.0", &art, "bin/echo");
        install(&m, &target(), &store, "test", loader(art.clone())).unwrap();
        let second = install(&m, &target(), &store, "test", loader(art)).unwrap();
        assert!(
            second.already_present,
            "second install must report idempotence"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn cache_is_used_and_reverified() {
        let d = private_temp_dir("zen-inst-cache").unwrap();
        let store = ToolStore::at(d.clone()).unwrap();
        let art = tar_with("bin/echo", b"cached");
        let m = manifest_for("echo", "1.0.0", &art, "bin/echo");
        install(&m, &target(), &store, "test", loader(art.clone())).unwrap();
        // Remove the installed copy but keep the cache; a loader that fails
        // proves the cache was used.
        store.remove("echo", Some("1.0.0")).unwrap();
        let failing = |_u: &str| -> ZenResult<Vec<u8>> {
            Err(ZenError::new(Area::Net, 1, "network must not be used"))
        };
        let out = install(&m, &target(), &store, "test", failing).unwrap();
        assert!(out.source.contains("cache"), "got {}", out.source);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn poisoned_cache_is_rejected() {
        let d = private_temp_dir("zen-inst-poison").unwrap();
        let store = ToolStore::at(d.clone()).unwrap();
        let art = tar_with("bin/echo", b"real");
        let m = manifest_for("echo", "1.0.0", &art, "bin/echo");
        // Plant a cache entry with the right name but wrong contents.
        let sha = m.platforms[0].sha256.clone();
        let cp = store.cache_path(&sha).unwrap();
        std::fs::create_dir_all(cp.parent().unwrap()).unwrap();
        std::fs::write(&cp, tar_with("bin/echo", b"POISONED")).unwrap();

        let e = install(&m, &target(), &store, "test", loader(art));
        assert!(e.is_err(), "a poisoned cache must not install");
        assert!(format!("{}", e.unwrap_err()).contains("checksum mismatch"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn signature_required_tool_fails_closed() {
        let d = private_temp_dir("zen-inst-sig").unwrap();
        let store = ToolStore::at(d.clone()).unwrap();
        let art = tar_with("bin/echo", b"x");
        let mut m = manifest_for("echo", "1.0.0", &art, "bin/echo");
        m.signature_required = true;
        let e = install(&m, &target(), &store, "test", loader(art));
        assert!(
            e.is_err(),
            "a signature-required tool must not install without one"
        );
        assert!(format!("{}", e.unwrap_err()).contains("signature"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn multiple_versions_coexist_and_selection_works() {
        let d = private_temp_dir("zen-inst-multi").unwrap();
        let store = ToolStore::at(d.clone()).unwrap();
        for v in ["1.0.0", "1.1.0"] {
            let art = tar_with("bin/echo", format!("v{v}").as_bytes());
            let m = manifest_for("echo", v, &art, "bin/echo");
            install(&m, &target(), &store, "test", loader(art)).unwrap();
        }
        assert_eq!(
            store.installed_versions("echo").unwrap(),
            vec!["1.0.0", "1.1.0"]
        );
        assert_eq!(
            store.active_version("echo").unwrap().as_deref(),
            Some("1.1.0")
        );
        store.set_active("echo", "1.0.0").unwrap();
        assert_eq!(
            store.active_version("echo").unwrap().as_deref(),
            Some("1.0.0")
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rollback_moves_to_previous_version() {
        let d = private_temp_dir("zen-inst-rb").unwrap();
        let store = ToolStore::at(d.clone()).unwrap();
        for v in ["1.0.0", "2.0.0"] {
            let art = tar_with("bin/echo", v.as_bytes());
            let m = manifest_for("echo", v, &art, "bin/echo");
            install(&m, &target(), &store, "test", loader(art)).unwrap();
        }
        let (from, to) = rollback(&store, "echo").unwrap();
        assert_eq!(from, "2.0.0");
        assert_eq!(to, "1.0.0");
        assert_eq!(
            store.active_version("echo").unwrap().as_deref(),
            Some("1.0.0")
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rollback_without_alternative_fails() {
        let d = private_temp_dir("zen-inst-rb1").unwrap();
        let store = ToolStore::at(d.clone()).unwrap();
        let art = tar_with("bin/echo", b"x");
        let m = manifest_for("echo", "1.0.0", &art, "bin/echo");
        install(&m, &target(), &store, "test", loader(art)).unwrap();
        assert!(rollback(&store, "echo").is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn native_engine_tool_installs_without_artifact_files() {
        let d = private_temp_dir("zen-inst-engine").unwrap();
        let store = ToolStore::at(d.clone()).unwrap();
        // Empty bytes; the checksum is over nothing.
        let art: Vec<u8> = vec![];
        let json = format!(
            r#"{{
  "schema_version": "1",
  "id": "org.zentrion.tools.dnsx",
  "name": "dnsx",
  "version": "1.0.0",
  "publisher": {{"name": "Zentrion", "id": "pub_zentrion"}},
  "categories": ["network"],
  "platforms": [{{
     "os": "{}", "arch": "{}", "abi": "{}",
     "url": "file:///dev/null",
     "sha256": "{}",
     "kind": "native"
  }}],
  "execution": {{"binary": "", "native_engine": "dns.resolve"}}
}}"#,
            target().os.as_str(),
            target().arch.as_str(),
            match target().abi {
                z_native::Abi::Gnu => "gnu",
                z_native::Abi::Musl => "musl",
                z_native::Abi::Msvc => "msvc",
                z_native::Abi::Wingnu => "wingnu",
                z_native::Abi::None => "none",
            },
            sha256_hex(&art),
        );
        let m = ToolManifest::parse_json(&json).unwrap();
        let out = install(&m, &target(), &store, "test", loader(art)).unwrap();
        assert!(out.activated);
        assert!(out.files.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn remove_keeps_other_versions() {
        let d = private_temp_dir("zen-inst-rm").unwrap();
        let store = ToolStore::at(d.clone()).unwrap();
        for v in ["1.0.0", "2.0.0"] {
            let art = tar_with("bin/echo", v.as_bytes());
            let m = manifest_for("echo", v, &art, "bin/echo");
            install(&m, &target(), &store, "test", loader(art)).unwrap();
        }
        remove(&store, "echo", Some("1.0.0")).unwrap();
        assert_eq!(store.installed_versions("echo").unwrap(), vec!["2.0.0"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn failed_install_does_not_disturb_existing_version() {
        let d = private_temp_dir("zen-inst-safe").unwrap();
        let store = ToolStore::at(d.clone()).unwrap();
        let good = tar_with("bin/echo", b"good");
        let m1 = manifest_for("echo", "1.0.0", &good, "bin/echo");
        install(&m1, &target(), &store, "test", loader(good)).unwrap();

        // Attempt a broken 2.0.0.
        let art2 = tar_with("bin/echo", b"v2");
        let m2 = manifest_for("echo", "2.0.0", &art2, "bin/echo");
        let tampered = tar_with("bin/echo", b"TAMPERED");
        assert!(install(&m2, &target(), &store, "test", loader(tampered)).is_err());

        // 1.0.0 must still be installed and active.
        assert_eq!(
            store.active_version("echo").unwrap().as_deref(),
            Some("1.0.0")
        );
        assert!(store
            .version_dir("echo", "1.0.0")
            .unwrap()
            .join("bin/echo")
            .is_file());
        assert!(!store.version_dir("echo", "2.0.0").unwrap().exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn archive_magic_detection() {
        assert!(archive_magic(&[0x1f, 0x8b, 0, 0]));
        assert!(!archive_magic(b"#!/bin/sh\n"));
        assert!(!archive_magic(&[]));
    }

    #[test]
    fn binary_basename_extraction() {
        assert_eq!(binary_basename("bin/echo", "fallback"), "echo");
        assert_eq!(binary_basename("", "fallback"), "fallback");
        assert_eq!(binary_basename("run.exe", "fallback"), "run.exe");
    }

    #[test]
    fn install_record_denormalises_permissions() {
        let d = private_temp_dir("zen-inst-rec").unwrap();
        let store = ToolStore::at(d.clone()).unwrap();
        let art = tar_with("bin/echo", b"x");
        let m = manifest_for("echo", "1.0.0", &art, "bin/echo");
        install(&m, &target(), &store, "test", loader(art)).unwrap();
        let r = store.read_record("echo", "1.0.0").unwrap().unwrap();
        assert!(r.permissions_summary.iter().any(|s| s.contains("network:")));
        assert_eq!(r.platform, TARGET);
        let _ = std::fs::remove_dir_all(&d);
    }
}

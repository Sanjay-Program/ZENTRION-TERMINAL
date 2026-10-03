//! Native filesystem inspection and safe operations.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path, PathBuf};
use z_core::error::{Area, ZenError, ZenResult};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileInfo {
    pub path: PathBuf,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub readonly: bool,
}

pub trait FilesystemInspector {
    fn inspect(&self, path: &Path) -> ZenResult<FileInfo>;
    fn is_executable(&self, path: &Path) -> bool;
    fn temp_dir(&self) -> PathBuf;
}

pub fn inspector() -> Box<dyn FilesystemInspector + Send + Sync> {
    Box::new(PortableFilesystem)
}

/// Portable implementation using `std::fs` plus Unix permission bits where
/// available. This is genuinely native on all three platforms (std maps to
/// `stat`/`GetFileAttributes`/`stat`).
pub struct PortableFilesystem;

impl FilesystemInspector for PortableFilesystem {
    fn inspect(&self, path: &Path) -> ZenResult<FileInfo> {
        let meta = fs::symlink_metadata(path).map_err(|e| {
            ZenError::new(
                Area::Fs,
                4100,
                format!("cannot inspect {}: {e}", path.display()),
            )
        })?;
        Ok(FileInfo {
            path: path.to_path_buf(),
            is_dir: meta.is_dir(),
            is_symlink: meta.file_type().is_symlink(),
            size: meta.len(),
            readonly: meta.permissions().readonly(),
        })
    }

    fn is_executable(&self, path: &Path) -> bool {
        if !path.is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(path)
                .map(|m| m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        }
        #[cfg(not(unix))]
        {
            // Windows: no executable bit; extension determines executability.
            path.extension()
                .map(|e| {
                    let e = e.to_string_lossy().to_ascii_lowercase();
                    e == "exe" || e == "cmd" || e == "bat" || e == "com"
                })
                .unwrap_or(false)
        }
    }

    fn temp_dir(&self) -> PathBuf {
        std::env::temp_dir()
    }
}

/// Refuse a path that escapes `root` after lexical normalization.
///
/// Note: this is a *lexical* check. It does not resolve symlinks — a symlink
/// inside the tree can still point outside. Callers that extract archives
/// must use the archive-specific checks in `z-package`, which reject symlink
/// entries outright.
pub fn ensure_within(root: &Path, candidate: &Path) -> ZenResult<PathBuf> {
    if candidate.is_absolute() {
        return Err(ZenError::new(
            Area::Fs,
            4101,
            format!("absolute path not allowed: {}", candidate.display()),
        ));
    }
    let mut out = root.to_path_buf();
    for comp in candidate.components() {
        match comp {
            Component::ParentDir => {
                return Err(ZenError::new(
                    Area::Fs,
                    4102,
                    "path traversal '..' is not allowed",
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(ZenError::new(
                    Area::Fs,
                    4103,
                    "path prefix/root not allowed",
                ));
            }
            Component::Normal(part) => {
                if part.to_string_lossy().contains('\0') {
                    return Err(ZenError::new(Area::Fs, 4104, "NUL byte in path"));
                }
                out.push(part);
            }
            Component::CurDir => {}
        }
    }
    Ok(out)
}

/// Canonicalize and verify the result stays within `root` (resolves symlinks).
/// Use this before *acting on* an existing path; `ensure_within` is for
/// constructing new paths.
pub fn canonical_within(root: &Path, candidate: &Path) -> ZenResult<PathBuf> {
    let root_c = root.canonicalize().map_err(|e| {
        ZenError::new(
            Area::Fs,
            4105,
            format!("cannot canonicalize root {}: {e}", root.display()),
        )
    })?;
    let cand_c = candidate.canonicalize().map_err(|e| {
        ZenError::new(
            Area::Fs,
            4106,
            format!("cannot canonicalize {}: {e}", candidate.display()),
        )
    })?;
    if !cand_c.starts_with(&root_c) {
        return Err(ZenError::new(
            Area::Fs,
            4107,
            format!("{} resolves outside {}", cand_c.display(), root_c.display()),
        )
        .with_remediation("Symlinks pointing outside the workspace are not permitted."));
    }
    Ok(cand_c)
}

/// Create a private temporary directory (0700 on Unix).
pub fn private_temp_dir(prefix: &str) -> ZenResult<PathBuf> {
    let base = std::env::temp_dir();
    let unique = format!(
        "{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let dir = base.join(unique);
    fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_refused() {
        let root = Path::new("/tmp/root");
        assert!(ensure_within(root, Path::new("../etc/passwd")).is_err());
        assert!(ensure_within(root, Path::new("a/../../b")).is_err());
        assert!(ensure_within(root, Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn valid_path_joined() {
        let root = Path::new("/tmp/root");
        assert_eq!(
            ensure_within(root, Path::new("a/b.txt")).unwrap(),
            Path::new("/tmp/root/a/b.txt")
        );
    }

    #[test]
    fn nul_byte_refused() {
        let root = Path::new("/tmp/root");
        assert!(ensure_within(root, Path::new("a\u{0}b")).is_err());
    }

    #[test]
    fn canonical_within_detects_escape() {
        let base = private_temp_dir("zen-fs-test").unwrap();
        let inside = base.join("ok.txt");
        fs::write(&inside, b"x").unwrap();
        assert!(canonical_within(&base, &inside).is_ok());

        #[cfg(unix)]
        {
            let link = base.join("escape");
            let _ = std::os::unix::fs::symlink("/etc", &link);
            if link.exists() {
                assert!(
                    canonical_within(&base, &link.join("hosts")).is_err(),
                    "symlink escaping the root must be refused"
                );
            }
        }
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn executable_bit_detection() {
        let d = private_temp_dir("zen-exec-test").unwrap();
        let f = d.join("prog");
        fs::write(&f, b"#!/bin/sh\n").unwrap();
        let insp = inspector();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(insp.is_executable(&f));
            fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(!insp.is_executable(&f));
        }
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn private_temp_dir_is_private() {
        let d = private_temp_dir("zen-priv").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&d).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "temp dir must be 0700");
        }
        let _ = fs::remove_dir_all(&d);
    }
}

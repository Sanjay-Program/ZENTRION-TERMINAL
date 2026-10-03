//! Filesystem abstraction with security-conscious path handling.
//!
//! Provides safe path joins (anti-traversal), safe writes, and safe temp dirs.
//! Does NOT claim sandboxing — that is the Phase 2 sandbox layer.

use crate::error::{Area, ZenError, ZenResult};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

/// Check that `candidate`, joined relative to `base`, cannot escape `base`
/// via `..`, absolute components, or Windows prefixes.
pub fn ensure_within(base: &Path, candidate: &Path) -> ZenResult<PathBuf> {
    if candidate.is_absolute() {
        return Err(ZenError::new(
            Area::Fs,
            4001,
            format!("absolute path not allowed here: {}", candidate.display()),
        ));
    }
    for comp in candidate.components() {
        match comp {
            Component::ParentDir => {
                return Err(ZenError::new(
                    Area::Fs,
                    4002,
                    "path traversal '..' is not allowed".to_string(),
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(ZenError::new(
                    Area::Fs,
                    4003,
                    "path prefix/root components are not allowed".to_string(),
                ));
            }
            Component::Normal(_) | Component::CurDir => {}
        }
    }
    let joined = base.join(candidate);
    Ok(joined)
}

/// Read a file (used by config, project loading).
pub fn read_text(path: &Path) -> ZenResult<String> {
    fs::read_to_string(path).map_err(|e| {
        ZenError::new(
            Area::Fs,
            4010,
            format!("cannot read {}: {e}", path.display()),
        )
        .with_remediation("Check that the file exists and is readable.")
    })
}

/// Write a file, creating parent directories. Refuses to follow through if a
/// parent is not a directory.
pub fn write_text(path: &Path, contents: &str) -> ZenResult<()> {
    if let Some(parent) = path.parent() {
        if parent.exists() && !parent.is_dir() {
            return Err(ZenError::new(
                Area::Fs,
                4011,
                format!("parent is not a directory: {}", parent.display()),
            ));
        }
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::File::create(path)?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}

/// Create a directory (no error if it already exists).
pub fn create_dir_all(path: &Path) -> ZenResult<()> {
    fs::create_dir_all(path).map_err(|e| {
        ZenError::new(
            Area::Fs,
            4012,
            format!("cannot create {}: {e}", path.display()),
        )
    })
}

/// Check writability by attempting to create and remove a probe file.
pub fn is_writable(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    let probe = path.join(".z-writable-probe");
    match fs::write(&probe, b"") {
        Ok(()) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// List of files in a directory (non-recursive).
pub fn list_dir(path: &Path) -> ZenResult<Vec<PathBuf>> {
    Ok(fs::read_dir(path)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_rejected() {
        let base = Path::new("/tmp/project");
        assert!(ensure_within(base, Path::new("../etc/passwd")).is_err());
        assert!(ensure_within(base, Path::new("a/../../b")).is_err());
    }

    #[test]
    fn absolute_rejected() {
        let base = Path::new("/tmp/project");
        assert!(ensure_within(base, Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn valid_relative_ok() {
        let base = Path::new("/tmp/project");
        let p = ensure_within(base, Path::new("src/main.rs")).unwrap();
        assert_eq!(p, Path::new("/tmp/project/src/main.rs"));
    }

    #[test]
    fn unicode_and_spaces_ok() {
        let base = Path::new("/tmp/pro ject");
        assert!(ensure_within(base, Path::new("файл test.rs")).is_ok());
    }
}

//! `z-checkpoint` — content-addressed workspace snapshots, diff review and
//! byte-for-byte rollback.
//!
//! A snapshot records every regular file (path, SHA-256, mode, mtime) and
//! stores gzip-compressed blobs by hash. Identical content is stored once.
//! Ignored and secret-shaped paths are never read. Snapshots are serialized per
//! workspace with a lock file so concurrent agent edits cannot interleave.
//!
//! Manifests can be signed with the local Ed25519 key ([`z_identity::signing`]);
//! signatures make tampering detectable, but a local attacker who can read the
//! private key can re-sign. The private key stays `0600`.

use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use similar::{ChangeTag, TextDiff};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;
use z_identity::signing::{verify, SigningKey};

pub const CHECKPOINT_VERSION: u32 = 1;
pub const MAX_FILE_BYTES: u64 = 50 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const MAX_DIFF_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_DIFF_LINES: usize = 4_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointOptions {
    pub include_hidden: bool,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub ignore: Vec<String>,
    pub sign: bool,
    pub created_by: String,
    /// Skip symbolic links (default). Following them can escape the workspace.
    pub follow_symlinks: bool,
}

impl Default for CheckpointOptions {
    fn default() -> Self {
        Self {
            include_hidden: false,
            max_file_bytes: MAX_FILE_BYTES,
            max_total_bytes: MAX_TOTAL_BYTES,
            ignore: default_ignore(),
            sign: false,
            created_by: std::env::var("USER").unwrap_or_else(|_| "local-user".into()),
            follow_symlinks: false,
        }
    }
}

pub fn default_ignore() -> Vec<String> {
    [
        ".git",
        "target",
        "node_modules",
        ".venv",
        "venv",
        "dist",
        "build",
        "__pycache__",
        ".next",
        ".idea",
        ".vscode",
        ".env",
        ".env.*",
        "*.pem",
        "*.key",
        "*.p12",
        "*.pfx",
        "id_rsa*",
        "id_ed25519*",
        "credentials*",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestFile {
    pub path: String,
    pub hash: String,
    pub size: u64,
    pub mode: Option<u32>,
    pub mtime: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signature {
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub version: u32,
    pub id: String,
    pub repo: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub base_commit: Option<String>,
    pub tree_hash: String,
    pub files: Vec<ManifestFile>,
    pub ignored_patterns: Vec<String>,
    pub skipped_files: usize,
    pub total_bytes: u64,
    pub signature: Option<Signature>,
    pub metadata: serde_json::Value,
}

impl Manifest {
    /// Deterministic bytes covered by the signature.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.signature = None;
        serde_json::to_vec(&unsigned).unwrap_or_default()
    }

    pub fn file(&self, path: &str) -> Option<&ManifestFile> {
        self.files.iter().find(|file| file.path == path)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestSummary {
    pub id: String,
    pub repo: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub files: usize,
    pub total_bytes: u64,
    pub base_commit: Option<String>,
    pub signed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    Added,
    Modified,
    Removed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffLine {
    /// `+`, `-` or ` `.
    pub kind: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hunk {
    pub old_start: usize,
    pub old_lines: usize,
    pub new_start: usize,
    pub new_lines: usize,
    pub lines: Vec<DiffLine>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileDiff {
    pub path: String,
    pub status: FileStatus,
    pub old_hash: Option<String>,
    pub new_hash: Option<String>,
    pub additions: usize,
    pub deletions: usize,
    pub binary: bool,
    pub truncated: bool,
    pub hunks: Vec<Hunk>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CheckpointDiff {
    pub files: Vec<FileDiff>,
    pub total_additions: usize,
    pub total_deletions: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreReport {
    pub restored: usize,
    pub deleted: usize,
    pub verified: usize,
    pub bytes: u64,
    pub signature_valid: Option<bool>,
}

/// One file's selected hunks, using indices from
/// [`CheckpointStore::diff_current`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HunkSelection {
    pub path: String,
    pub hunks: Vec<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HunkRestoreReport {
    pub files: usize,
    pub hunks: usize,
    pub deleted: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GcReport {
    pub manifests_removed: usize,
    pub blobs_removed: usize,
    pub bytes_reclaimed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointError {
    pub message: String,
}

impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CheckpointError {}

impl From<std::io::Error> for CheckpointError {
    fn from(error: std::io::Error) -> Self {
        Self {
            message: error.to_string(),
        }
    }
}

type Result<T> = std::result::Result<T, CheckpointError>;

fn err(message: impl Into<String>) -> CheckpointError {
    CheckpointError {
        message: message.into(),
    }
}

pub struct CheckpointStore {
    root: PathBuf,
    blobs: PathBuf,
    manifests: PathBuf,
    locks: PathBuf,
    key_dir: PathBuf,
}

impl CheckpointStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            blobs: root.join("blobs"),
            manifests: root.join("manifests"),
            locks: root.join("locks"),
            key_dir: root.join("keys"),
            root,
        }
    }

    pub fn default_store() -> Option<Self> {
        z_core::config::user_data_dir().map(|dir| Self::new(dir.join("checkpoints")))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn ensure_dirs(&self) -> Result<()> {
        for dir in [&self.blobs, &self.manifests, &self.locks] {
            std::fs::create_dir_all(dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        Ok(())
    }

    /// Snapshot a workspace. Returns the manifest (already persisted).
    pub fn snapshot(&self, workspace: &Path, options: &CheckpointOptions) -> Result<Manifest> {
        self.ensure_dirs()?;
        let root = workspace
            .canonicalize()
            .map_err(|e| err(format!("cannot resolve {}: {e}", workspace.display())))?;
        if !root.is_dir() {
            return Err(err(format!("{} is not a directory", root.display())));
        }
        let _lock = WorkspaceLock::acquire(&self.locks, &root)?;
        let scanned = scan(&root, options)?;
        let mut files = Vec::with_capacity(scanned.files.len());
        let mut total_bytes = 0u64;
        for file in &scanned.files {
            let bytes = std::fs::read(&file.absolute)
                .map_err(|e| err(format!("cannot read {}: {e}", file.relative)))?;
            let hash = sha256_hex(&bytes);
            if hash != file.hash {
                return Err(err(format!(
                    "workspace changed while snapshotting {}; retry",
                    file.relative
                )));
            }
            self.put_blob(&hash, &bytes)?;
            total_bytes += bytes.len() as u64;
            files.push(ManifestFile {
                path: file.relative.clone(),
                hash,
                size: bytes.len() as u64,
                mode: file.mode,
                mtime: file.mtime,
            });
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let tree_hash = tree_hash(&files);
        let id = format!("cp_{}", Uuid::new_v4().simple());
        let mut manifest = Manifest {
            version: CHECKPOINT_VERSION,
            id,
            repo: root.display().to_string(),
            created_at: Utc::now(),
            created_by: options.created_by.clone(),
            base_commit: git_head(&root),
            tree_hash,
            files,
            ignored_patterns: options.ignore.clone(),
            skipped_files: scanned.skipped,
            total_bytes,
            signature: None,
            metadata: serde_json::json!({
                "follow_symlinks": options.follow_symlinks,
                "include_hidden": options.include_hidden,
            }),
        };
        if options.sign {
            let key = SigningKey::load_or_create(&self.key_dir).map_err(|e| err(e.to_string()))?;
            let signature = key.sign_hex(&manifest.signable_bytes());
            manifest.signature = Some(Signature {
                algorithm: "ed25519".into(),
                public_key: key.public_key_hex(),
                signature,
            });
        }
        self.write_manifest(&manifest)?;
        Ok(manifest)
    }

    /// Add or replace the Ed25519 signature on an existing manifest.
    pub fn sign_manifest(&self, id: &str) -> Result<Manifest> {
        let mut manifest = self.load(id)?;
        let key = SigningKey::load_or_create(&self.key_dir).map_err(|e| err(e.to_string()))?;
        let signature = key.sign_hex(&manifest.signable_bytes());
        manifest.signature = Some(Signature {
            algorithm: "ed25519".into(),
            public_key: key.public_key_hex(),
            signature,
        });
        self.write_manifest(&manifest)?;
        Ok(manifest)
    }

    /// Verify the manifest signature. `None` when the manifest is unsigned.
    pub fn signature_valid(&self, manifest: &Manifest) -> Option<bool> {
        manifest.signature.as_ref().map(|signature| {
            signature.algorithm == "ed25519"
                && verify(
                    &signature.public_key,
                    &manifest.signable_bytes(),
                    &signature.signature,
                )
        })
    }

    pub fn load(&self, id: &str) -> Result<Manifest> {
        validate_id(id)?;
        let path = self.manifests.join(format!("{id}.json"));
        let text = std::fs::read_to_string(&path)
            .map_err(|e| err(format!("cannot read checkpoint {id}: {e}")))?;
        let manifest: Manifest = serde_json::from_str(&text)
            .map_err(|e| err(format!("checkpoint {id} is corrupt: {e}")))?;
        if manifest.id != id {
            return Err(err(format!(
                "checkpoint file {id} contains id {}",
                manifest.id
            )));
        }
        Ok(manifest)
    }

    pub fn list(&self) -> Result<Vec<ManifestSummary>> {
        let mut summaries = Vec::new();
        if !self.manifests.exists() {
            return Ok(summaries);
        }
        for entry in std::fs::read_dir(&self.manifests)?.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(manifest) = serde_json::from_str::<Manifest>(&text) else {
                continue;
            };
            summaries.push(ManifestSummary {
                id: manifest.id.clone(),
                repo: manifest.repo.clone(),
                created_at: manifest.created_at,
                created_by: manifest.created_by.clone(),
                files: manifest.files.len(),
                total_bytes: manifest.total_bytes,
                base_commit: manifest.base_commit.clone(),
                signed: manifest.signature.is_some(),
            });
        }
        summaries.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(summaries)
    }

    /// Diff a checkpoint against the current workspace.
    pub fn diff_current(&self, id: &str, workspace: &Path) -> Result<CheckpointDiff> {
        let manifest = self.load(id)?;
        let root = workspace
            .canonicalize()
            .map_err(|e| err(format!("cannot resolve {}: {e}", workspace.display())))?;
        let options = CheckpointOptions {
            ignore: manifest.ignored_patterns.clone(),
            ..Default::default()
        };
        let current = scan(&root, &options)?;
        self.diff_against(&manifest, &current)
    }

    /// Diff two checkpoints.
    pub fn diff_between(&self, old_id: &str, new_id: &str) -> Result<CheckpointDiff> {
        let old = self.load(old_id)?;
        let new = self.load(new_id)?;
        let mut diff = CheckpointDiff::default();
        let old_map: BTreeMap<&str, &ManifestFile> = old
            .files
            .iter()
            .map(|file| (file.path.as_str(), file))
            .collect();
        let new_map: BTreeMap<&str, &ManifestFile> = new
            .files
            .iter()
            .map(|file| (file.path.as_str(), file))
            .collect();
        for (path, old_file) in &old_map {
            match new_map.get(path) {
                None => diff.files.push(FileDiff {
                    path: path.to_string(),
                    status: FileStatus::Removed,
                    old_hash: Some(old_file.hash.clone()),
                    new_hash: None,
                    additions: 0,
                    deletions: old_file.size as usize,
                    binary: false,
                    truncated: false,
                    hunks: Vec::new(),
                }),
                Some(new_file) if new_file.hash != old_file.hash => {
                    let old_text = self.read_blob_text(&old_file.hash);
                    let new_text = self.read_blob_text(&new_file.hash);
                    diff.files.push(text_diff(
                        path,
                        FileStatus::Modified,
                        old_text.as_deref(),
                        new_text.as_deref(),
                        Some(&old_file.hash),
                        Some(&new_file.hash),
                    ));
                }
                Some(_) => {}
            }
        }
        for (path, new_file) in &new_map {
            if old_map.contains_key(path) {
                continue;
            }
            let new_text = self.read_blob_text(&new_file.hash);
            diff.files.push(text_diff(
                path,
                FileStatus::Added,
                None,
                new_text.as_deref(),
                None,
                Some(&new_file.hash),
            ));
        }
        diff.files.sort_by(|a, b| a.path.cmp(&b.path));
        diff.total_additions = diff.files.iter().map(|file| file.additions).sum();
        diff.total_deletions = diff.files.iter().map(|file| file.deletions).sum();
        Ok(diff)
    }

    fn diff_against(&self, manifest: &Manifest, current: &Scanned) -> Result<CheckpointDiff> {
        let checked: HashMap<&str, &ManifestFile> = manifest
            .files
            .iter()
            .map(|file| (file.path.as_str(), file))
            .collect();
        let current_map: HashMap<&str, &ScannedFile> = current
            .files
            .iter()
            .map(|file| (file.relative.as_str(), file))
            .collect();
        let mut diff = CheckpointDiff::default();
        for file in manifests_sorted(manifest) {
            match current_map.get(file.path.as_str()) {
                None => diff.files.push(FileDiff {
                    path: file.path.clone(),
                    status: FileStatus::Removed,
                    old_hash: Some(file.hash.clone()),
                    new_hash: None,
                    additions: 0,
                    deletions: 0,
                    binary: false,
                    truncated: false,
                    hunks: Vec::new(),
                }),
                Some(current_file) if current_file.hash != file.hash => {
                    let old_text = self.read_blob_text(&file.hash);
                    let new_text = read_limited(&current_file.absolute);
                    diff.files.push(text_diff(
                        &file.path,
                        FileStatus::Modified,
                        old_text.as_deref(),
                        new_text.as_deref(),
                        Some(&file.hash),
                        Some(&current_file.hash),
                    ));
                }
                Some(_) => {}
            }
        }
        for file in &current.files {
            if checked.contains_key(file.relative.as_str()) {
                continue;
            }
            let text = read_limited(&file.absolute);
            diff.files.push(text_diff(
                &file.relative,
                FileStatus::Added,
                None,
                text.as_deref(),
                None,
                Some(&file.hash),
            ));
        }
        diff.files.sort_by(|a, b| a.path.cmp(&b.path));
        diff.total_additions = diff.files.iter().map(|file| file.additions).sum();
        diff.total_deletions = diff.files.iter().map(|file| file.deletions).sum();
        Ok(diff)
    }

    /// Restore a checkpoint byte-for-byte. New files created since the
    /// snapshot are deleted; ignored paths are left untouched.
    pub fn restore(&self, id: &str, workspace: &Path) -> Result<RestoreReport> {
        self.restore_inner(id, workspace, None, false)
    }

    /// Restore only specific files from a checkpoint (accept file).
    pub fn restore_files(
        &self,
        id: &str,
        workspace: &Path,
        paths: &[String],
    ) -> Result<RestoreReport> {
        self.restore_inner(id, workspace, Some(paths), false)
    }

    /// Revert only selected hunks to their checkpoint content, leaving other
    /// edits in the same file untouched.
    ///
    /// Hunk indices come from [`Self::diff_current`]. All selections are
    /// validated before anything is written; a file with all of its hunks
    /// selected is verified against the checkpoint blob.
    pub fn restore_hunks(
        &self,
        id: &str,
        workspace: &Path,
        selections: &[HunkSelection],
    ) -> Result<HunkRestoreReport> {
        if selections.is_empty() {
            return Err(err("no hunks selected"));
        }
        let manifest = self.load(id)?;
        if self.signature_valid(&manifest) == Some(false) {
            return Err(err(format!(
                "checkpoint {id} signature is invalid; refusing to restore hunks"
            )));
        }
        let root = workspace
            .canonicalize()
            .map_err(|e| err(format!("cannot resolve {}: {e}", workspace.display())))?;
        if root.display().to_string() != manifest.repo {
            return Err(err(format!(
                "checkpoint belongs to {} not {}",
                manifest.repo,
                root.display()
            )));
        }
        let _lock = WorkspaceLock::acquire(&self.locks, &root)?;
        let diff = self.diff_current(id, &root)?;
        let by_path: BTreeMap<&str, &FileDiff> = diff
            .files
            .iter()
            .map(|file| (file.path.as_str(), file))
            .collect();

        // Validate every selection before writing anything.
        for selection in selections {
            let file = by_path.get(selection.path.as_str()).ok_or_else(|| {
                err(format!(
                    "{} is not different from checkpoint {id}",
                    selection.path
                ))
            })?;
            if file.binary || file.truncated {
                return Err(err(format!(
                    "{} cannot be restored hunk-by-hunk (binary or truncated diff)",
                    selection.path
                )));
            }
            if selection.hunks.is_empty() {
                return Err(err(format!("no hunks selected for {}", selection.path)));
            }
            let mut seen = BTreeSet::new();
            for index in &selection.hunks {
                if *index >= file.hunks.len() {
                    return Err(err(format!(
                        "hunk {index} does not exist for {} (only {} hunks)",
                        selection.path,
                        file.hunks.len()
                    )));
                }
                if !seen.insert(*index) {
                    return Err(err(format!(
                        "hunk {index} selected twice for {}",
                        selection.path
                    )));
                }
            }
        }

        let mut report = HunkRestoreReport::default();
        for selection in selections {
            let file = by_path[selection.path.as_str()];
            let target = root.join(safe_relative(&selection.path)?);
            if file.status == FileStatus::Removed {
                let entry = manifest.file(&selection.path).ok_or_else(|| {
                    err(format!(
                        "{} is missing from the checkpoint manifest",
                        selection.path
                    ))
                })?;
                let bytes = self.get_blob(&entry.hash)?;
                if sha256_hex(&bytes) != entry.hash {
                    return Err(err(format!(
                        "blob for {} is corrupt (hash mismatch)",
                        selection.path
                    )));
                }
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&target, &bytes)?;
                report.files += 1;
                report.hunks += selection.hunks.len();
                report.bytes += bytes.len() as u64;
                continue;
            }

            let text = std::fs::read_to_string(&target).map_err(|e| {
                err(format!(
                    "{} is not a readable UTF-8 text file: {e}",
                    selection.path
                ))
            })?;
            let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();
            let mut indices = selection.hunks.clone();
            indices.sort_unstable();
            for index in indices.into_iter().rev() {
                let hunk = &file.hunks[index];
                let start = hunk.new_start.checked_sub(1).ok_or_else(|| {
                    err(format!(
                        "hunk {index} for {} has no location in the current file",
                        selection.path
                    ))
                })?;
                let end = start.checked_add(hunk.new_lines).ok_or_else(|| {
                    err(format!(
                        "hunk {index} for {} overflows the line range",
                        selection.path
                    ))
                })?;
                if end > lines.len() {
                    return Err(err(format!(
                        "hunk {index} for {} is outside the current file ({} lines)",
                        selection.path,
                        lines.len()
                    )));
                }
                let replacement: Vec<String> = hunk
                    .lines
                    .iter()
                    .filter(|line| line.kind != "+")
                    .map(|line| line.text.clone())
                    .collect();
                lines.splice(start..end, replacement);
                report.hunks += 1;
            }

            let all_selected = selection.hunks.len() == file.hunks.len();
            let result = lines.join("\n");
            if file.status == FileStatus::Added && result.is_empty() {
                if target.is_file() {
                    std::fs::remove_file(&target)?;
                    report.deleted += 1;
                }
                report.files += 1;
                continue;
            }
            if all_selected && file.status == FileStatus::Modified {
                let entry = manifest.file(&selection.path).ok_or_else(|| {
                    err(format!(
                        "{} is missing from the checkpoint manifest",
                        selection.path
                    ))
                })?;
                if sha256_hex(result.as_bytes()) != entry.hash {
                    return Err(err(format!(
                        "restoring all hunks of {} did not reproduce the checkpoint content",
                        selection.path
                    )));
                }
            }
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let tmp = target.with_extension("zentrion-hunk-tmp");
            std::fs::write(&tmp, result.as_bytes())?;
            std::fs::rename(&tmp, &target)?;
            report.files += 1;
            report.bytes += result.len() as u64;
        }
        Ok(report)
    }

    /// Restore allowing the workspace to have moved.
    pub fn restore_relocated(&self, id: &str, workspace: &Path) -> Result<RestoreReport> {
        self.restore_inner(id, workspace, None, true)
    }

    fn restore_inner(
        &self,
        id: &str,
        workspace: &Path,
        only: Option<&[String]>,
        allow_relocated: bool,
    ) -> Result<RestoreReport> {
        let manifest = self.load(id)?;
        let signature_valid = self.signature_valid(&manifest);
        if signature_valid == Some(false) {
            return Err(err(format!(
                "checkpoint {id} signature is invalid; refusing to restore"
            )));
        }
        let root = workspace
            .canonicalize()
            .map_err(|e| err(format!("cannot resolve {}: {e}", workspace.display())))?;
        if !allow_relocated && root.display().to_string() != manifest.repo {
            return Err(err(format!(
                "checkpoint belongs to {} not {}; use a relocated restore to override",
                manifest.repo,
                root.display()
            )));
        }
        let _lock = WorkspaceLock::acquire(&self.locks, &root)?;
        let selected: BTreeSet<&str> = match only {
            Some(paths) => paths.iter().map(String::as_str).collect(),
            None => manifest
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect(),
        };
        let mut report = RestoreReport {
            restored: 0,
            deleted: 0,
            verified: 0,
            bytes: 0,
            signature_valid,
        };
        for file in &manifest.files {
            if !selected.contains(file.path.as_str()) {
                continue;
            }
            let relative = safe_relative(&file.path)?;
            let target = root.join(&relative);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let bytes = self.get_blob(&file.hash)?;
            let hash = sha256_hex(&bytes);
            if hash != file.hash {
                return Err(err(format!(
                    "blob for {} is corrupt (hash mismatch)",
                    file.path
                )));
            }
            let tmp = target.with_extension("zentrion-restore-tmp");
            std::fs::write(&tmp, &bytes)?;
            #[cfg(unix)]
            if let Some(mode) = file.mode {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode));
            }
            std::fs::rename(&tmp, &target)?;
            let written = std::fs::read(&target)?;
            if sha256_hex(&written) != file.hash {
                return Err(err(format!(
                    "verification failed after restoring {}",
                    file.path
                )));
            }
            report.restored += 1;
            report.verified += 1;
            report.bytes += bytes.len() as u64;
        }
        // Delete files that did not exist at snapshot time. Only within the
        // checkpoint's ignore rules, so ignored secrets are never touched.
        let manifest_paths: BTreeSet<&str> = manifest
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        if only.is_none() {
            let options = CheckpointOptions {
                ignore: manifest.ignored_patterns.clone(),
                ..Default::default()
            };
            let current = scan(&root, &options)?;
            for file in current.files {
                if manifest_paths.contains(file.relative.as_str()) {
                    continue;
                }
                let target = root.join(&file.relative);
                if target.is_file() {
                    std::fs::remove_file(&target)?;
                    report.deleted += 1;
                }
            }
        }
        Ok(report)
    }

    /// Remove manifests older than `days`, then unreferenced blobs.
    pub fn gc(&self, days: u32) -> Result<GcReport> {
        self.ensure_dirs()?;
        let mut report = GcReport {
            manifests_removed: 0,
            blobs_removed: 0,
            bytes_reclaimed: 0,
        };
        let cutoff = Utc::now() - chrono::Duration::days(days as i64);
        if self.manifests.exists() {
            for entry in std::fs::read_dir(&self.manifests)?.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                let Ok(manifest) = serde_json::from_str::<Manifest>(&text) else {
                    continue;
                };
                if manifest.created_at < cutoff {
                    std::fs::remove_file(&path)?;
                    report.manifests_removed += 1;
                }
            }
        }
        let mut referenced = HashSet::new();
        if self.manifests.exists() {
            for entry in std::fs::read_dir(&self.manifests)?.flatten() {
                let Ok(text) = std::fs::read_to_string(entry.path()) else {
                    continue;
                };
                if let Ok(manifest) = serde_json::from_str::<Manifest>(&text) {
                    for file in manifest.files {
                        referenced.insert(file.hash);
                    }
                }
            }
        }
        if self.blobs.exists() {
            for entry in walkdir::WalkDir::new(&self.blobs).into_iter().flatten() {
                if !entry.file_type().is_file() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_string();
                let Some(hash) = name.strip_suffix(".gz") else {
                    continue;
                };
                if referenced.contains(hash) {
                    continue;
                }
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                std::fs::remove_file(entry.path())?;
                report.blobs_removed += 1;
                report.bytes_reclaimed += size;
            }
        }
        Ok(report)
    }

    pub fn blob_count(&self) -> usize {
        walkdir::WalkDir::new(&self.blobs)
            .into_iter()
            .flatten()
            .filter(|entry| entry.file_type().is_file())
            .count()
    }

    fn write_manifest(&self, manifest: &Manifest) -> Result<()> {
        self.ensure_dirs()?;
        validate_id(&manifest.id)?;
        let text = serde_json::to_string_pretty(manifest)
            .map_err(|e| err(format!("cannot serialize manifest: {e}")))?;
        let path = self.manifests.join(format!("{}.json", manifest.id));
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn blob_path(&self, hash: &str) -> Result<PathBuf> {
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(err(format!("invalid blob hash `{hash}`")));
        }
        Ok(self.blobs.join(&hash[..2]).join(format!("{hash}.gz")))
    }

    fn put_blob(&self, hash: &str, bytes: &[u8]) -> Result<bool> {
        let path = self.blob_path(hash)?;
        if path.exists() {
            return Ok(false);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(bytes)?;
        let compressed = encoder.finish()?;
        let tmp = path.with_extension("gz.tmp");
        std::fs::write(&tmp, compressed)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &path)?;
        Ok(true)
    }

    fn get_blob(&self, hash: &str) -> Result<Vec<u8>> {
        let path = self.blob_path(hash)?;
        let compressed =
            std::fs::read(&path).map_err(|e| err(format!("blob {hash} is missing: {e}")))?;
        let mut decoder = GzDecoder::new(compressed.as_slice());
        let mut bytes = Vec::new();
        decoder.read_to_end(&mut bytes)?;
        if sha256_hex(&bytes) != hash {
            return Err(err(format!("blob {hash} is corrupt")));
        }
        Ok(bytes)
    }

    fn read_blob_text(&self, hash: &str) -> Option<String> {
        let bytes = self.get_blob(hash).ok()?;
        if is_binary(&bytes) {
            return None;
        }
        Some(String::from_utf8_lossy(&bytes).to_string())
    }
}

struct Scanned {
    files: Vec<ScannedFile>,
    skipped: usize,
}

struct ScannedFile {
    relative: String,
    absolute: PathBuf,
    hash: String,
    mode: Option<u32>,
    mtime: Option<i64>,
}

fn scan(root: &Path, options: &CheckpointOptions) -> Result<Scanned> {
    let mut files = Vec::new();
    let mut skipped = 0usize;
    let mut total = 0u64;
    for entry in walkdir::WalkDir::new(root)
        .follow_links(options.follow_symlinks)
        .into_iter()
        .filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            let name = entry.file_name().to_string_lossy();
            if entry.file_type().is_symlink() && !options.follow_symlinks {
                return false;
            }
            if entry.file_type().is_dir() {
                if !options.include_hidden && name.starts_with('.') && name != ".github" {
                    return false;
                }
                return !is_ignored_dir(&name, options);
            }
            true
        })
        .flatten()
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = match entry.path().strip_prefix(root) {
            Ok(relative) => relative.to_string_lossy().replace('\\', "/"),
            Err(_) => continue,
        };
        if is_ignored(&relative, options) {
            skipped += 1;
            continue;
        }
        let metadata = match std::fs::metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        if metadata.len() > options.max_file_bytes {
            skipped += 1;
            continue;
        }
        if total + metadata.len() > options.max_total_bytes {
            skipped += 1;
            continue;
        }
        let bytes = match std::fs::read(entry.path()) {
            Ok(bytes) => bytes,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        total += bytes.len() as u64;
        let mode = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                Some(metadata.mode() & 0o777)
            }
            #[cfg(not(unix))]
            {
                None
            }
        };
        let mtime = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_millis() as i64);
        files.push(ScannedFile {
            relative,
            absolute: entry.path().to_path_buf(),
            hash: sha256_hex(&bytes),
            mode,
            mtime,
        });
    }
    files.sort_by(|a, b| a.relative.cmp(&b.relative));
    Ok(Scanned { files, skipped })
}

fn is_ignored_dir(name: &str, options: &CheckpointOptions) -> bool {
    options
        .ignore
        .iter()
        .any(|pattern| !pattern.contains('*') && !pattern.contains('.') && pattern == name)
}

fn is_ignored(relative: &str, options: &CheckpointOptions) -> bool {
    let name = relative.rsplit('/').next().unwrap_or(relative);
    let lower = name.to_ascii_lowercase();
    if !options.include_hidden
        && relative.split('/').any(|part| {
            part.starts_with('.') && part != ".github" && !relative.starts_with(".github/")
        })
    {
        return true;
    }
    if lower == ".env"
        || lower.starts_with(".env.")
        || lower.ends_with(".pem")
        || lower.ends_with(".key")
        || lower.ends_with(".p12")
        || lower.ends_with(".pfx")
        || lower.starts_with("id_rsa")
        || lower.starts_with("id_ed25519")
        || lower.contains("credentials")
    {
        return true;
    }
    options.ignore.iter().any(|pattern| {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            lower.ends_with(&format!(".{}", suffix.to_ascii_lowercase()))
        } else if let Some(prefix) = pattern.strip_suffix('*') {
            lower.starts_with(&prefix.to_ascii_lowercase())
        } else {
            relative == pattern
                || relative.starts_with(&format!("{pattern}/"))
                || relative.split('/').any(|part| part == pattern)
        }
    })
}

fn tree_hash(files: &[ManifestFile]) -> String {
    let mut hasher = Sha256::new();
    for file in files {
        hasher.update(file.path.as_bytes());
        hasher.update([0u8]);
        hasher.update(file.hash.as_bytes());
        hasher.update([0u8]);
        hasher.update(file.mode.unwrap_or(0).to_be_bytes());
        hasher.update([0u8]);
    }
    format!("sha256:{}", hex(&hasher.finalize()))
}

fn manifests_sorted(manifest: &Manifest) -> Vec<&ManifestFile> {
    let mut files: Vec<&ManifestFile> = manifest.files.iter().collect();
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files
}

fn safe_relative(path: &str) -> Result<PathBuf> {
    let relative = Path::new(path);
    if relative.is_absolute() {
        return Err(err(format!("manifest path `{path}` is absolute")));
    }
    for component in relative.components() {
        match component {
            Component::Normal(_) => {}
            _ => {
                return Err(err(format!(
                    "manifest path `{path}` contains an unsafe component"
                )))
            }
        }
    }
    Ok(relative.to_path_buf())
}

fn validate_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 80
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(err(format!("invalid checkpoint id `{id}`")));
    }
    Ok(())
}

fn git_head(root: &Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "HEAD"])
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn is_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|byte| *byte == 0)
}

fn read_limited(path: &Path) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() as usize > MAX_DIFF_BYTES {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    if is_binary(&bytes) {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).to_string())
}

fn text_diff(
    path: &str,
    status: FileStatus,
    old: Option<&str>,
    new: Option<&str>,
    old_hash: Option<&str>,
    new_hash: Option<&str>,
) -> FileDiff {
    let mut file_diff = FileDiff {
        path: path.to_string(),
        status,
        old_hash: old_hash.map(str::to_string),
        new_hash: new_hash.map(str::to_string),
        additions: 0,
        deletions: 0,
        binary: false,
        truncated: false,
        hunks: Vec::new(),
    };
    match (old, new) {
        (Some(old), Some(new)) => {
            let diff = TextDiff::from_lines(old, new);
            for group in diff.grouped_ops(3) {
                let Some(first) = group.first() else {
                    continue;
                };
                let last = group.last().expect("non-empty group");
                let old_start = first.old_range().start + 1;
                let new_start = first.new_range().start + 1;
                let old_lines = last.old_range().end.saturating_sub(first.old_range().start);
                let new_lines = last.new_range().end.saturating_sub(first.new_range().start);
                let mut hunk = Hunk {
                    old_start,
                    old_lines,
                    new_start,
                    new_lines,
                    lines: Vec::new(),
                };
                for op in &group {
                    for change in diff.iter_changes(op) {
                        if file_diff.hunks.iter().map(|h| h.lines.len()).sum::<usize>()
                            >= MAX_DIFF_LINES
                        {
                            file_diff.truncated = true;
                            break;
                        }
                        match change.tag() {
                            ChangeTag::Delete => file_diff.deletions += 1,
                            ChangeTag::Insert => file_diff.additions += 1,
                            ChangeTag::Equal => {}
                        }
                        hunk.lines.push(DiffLine {
                            kind: match change.tag() {
                                ChangeTag::Delete => "-".into(),
                                ChangeTag::Insert => "+".into(),
                                ChangeTag::Equal => " ".into(),
                            },
                            text: change.value().trim_end_matches('\n').to_string(),
                        });
                    }
                    if file_diff.truncated {
                        break;
                    }
                }
                file_diff.hunks.push(hunk);
                if file_diff.truncated {
                    break;
                }
            }
        }
        (None, Some(new)) => {
            let mut hunk = Hunk {
                old_start: 0,
                old_lines: 0,
                new_start: 1,
                new_lines: new.lines().count(),
                lines: Vec::new(),
            };
            for (index, line) in new.lines().enumerate() {
                if index >= MAX_DIFF_LINES {
                    file_diff.truncated = true;
                    break;
                }
                file_diff.additions += 1;
                hunk.lines.push(DiffLine {
                    kind: "+".into(),
                    text: line.to_string(),
                });
            }
            file_diff.hunks.push(hunk);
        }
        (Some(old), None) => {
            let mut hunk = Hunk {
                old_start: 1,
                old_lines: old.lines().count(),
                new_start: 0,
                new_lines: 0,
                lines: Vec::new(),
            };
            for (index, line) in old.lines().enumerate() {
                if index >= MAX_DIFF_LINES {
                    file_diff.truncated = true;
                    break;
                }
                file_diff.deletions += 1;
                hunk.lines.push(DiffLine {
                    kind: "-".into(),
                    text: line.to_string(),
                });
            }
            file_diff.hunks.push(hunk);
        }
        (None, None) => {
            file_diff.binary = true;
        }
    }
    file_diff
}

struct WorkspaceLock {
    path: PathBuf,
}

impl WorkspaceLock {
    fn acquire(lock_dir: &Path, workspace: &Path) -> Result<Self> {
        std::fs::create_dir_all(lock_dir)?;
        let key = sha256_hex(workspace.display().to_string().as_bytes());
        let path = lock_dir.join(format!("{}.lock", &key[..16]));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    let _ = writeln!(file, "{}", std::process::id());
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let stale = std::fs::read_to_string(&path)
                        .ok()
                        .and_then(|text| text.trim().parse::<i32>().ok())
                        .map(|pid| !process_alive(pid))
                        .unwrap_or(true);
                    if stale {
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    if std::time::Instant::now() >= deadline {
                        return Err(err(format!(
                            "workspace is locked by another checkpoint operation ({}); retry",
                            path.display()
                        )));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(error) => {
                    return Err(err(format!(
                        "cannot acquire workspace lock {}: {error}",
                        path.display()
                    )))
                }
            }
        }
    }
}

impl Drop for WorkspaceLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn process_alive(pid: i32) -> bool {
    #[cfg(unix)]
    {
        // Safety: signal 0 only checks existence/permission.
        unsafe { libc::kill(pid, 0) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-checkpoint-{}-{}-{}",
            name,
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            "fn main() {\n    println!(\"hi\");\n}\n",
        )
        .unwrap();
        std::fs::write(dir.join("README.md"), "# Demo\n").unwrap();
        std::fs::write(dir.join(".env"), "TOKEN=super-secret\n").unwrap();
        dir
    }

    fn store(name: &str) -> (CheckpointStore, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "zentrion-checkpoint-store-{}-{}-{}",
            name,
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&base).unwrap();
        (CheckpointStore::new(&base), base)
    }

    #[test]
    fn snapshot_diff_and_rollback_are_byte_identical() {
        let ws = workspace("rollback");
        let (store, base) = store("rollback");
        let manifest = store.snapshot(&ws, &CheckpointOptions::default()).unwrap();
        assert_eq!(manifest.files.len(), 2);
        let original = std::fs::read(ws.join("src/lib.rs")).unwrap();

        std::fs::write(ws.join("src/lib.rs"), "fn main() { evil(); }\n").unwrap();
        std::fs::write(ws.join("NEW.md"), "new file\n").unwrap();
        let diff = store.diff_current(&manifest.id, &ws).unwrap();
        assert!(diff
            .files
            .iter()
            .any(|f| f.path == "src/lib.rs" && f.status == FileStatus::Modified));
        assert!(diff
            .files
            .iter()
            .any(|f| f.path == "NEW.md" && f.status == FileStatus::Added));

        let report = store.restore(&manifest.id, &ws).unwrap();
        assert!(report.deleted >= 1);
        assert_eq!(std::fs::read(ws.join("src/lib.rs")).unwrap(), original);
        assert!(!ws.join("NEW.md").exists());
        // Ignored secrets are never captured and never deleted.
        assert!(ws.join(".env").exists());
        assert!(manifest.files.iter().all(|f| !f.path.contains(".env")));
        let _ = std::fs::remove_dir_all(&ws);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn identical_content_is_deduplicated() {
        let ws = workspace("dedupe");
        std::fs::write(ws.join("a.txt"), "same content\n").unwrap();
        std::fs::write(ws.join("b.txt"), "same content\n").unwrap();
        let (store, base) = store("dedupe");
        let manifest = store.snapshot(&ws, &CheckpointOptions::default()).unwrap();
        assert_eq!(manifest.files.len(), 4);
        assert_eq!(store.blob_count(), 3);
        let _ = std::fs::remove_dir_all(&ws);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn signed_manifests_verify_and_tampering_is_detected() {
        let ws = workspace("sign");
        let (store, base) = store("sign");
        let manifest = store
            .snapshot(
                &ws,
                &CheckpointOptions {
                    sign: true,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(store.signature_valid(&manifest), Some(true));
        let mut tampered = manifest.clone();
        tampered.files[0].hash = "0".repeat(64);
        assert_eq!(store.signature_valid(&tampered), Some(false));
        let _ = std::fs::remove_dir_all(&ws);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn manifest_path_traversal_is_rejected() {
        assert!(safe_relative("../etc/passwd").is_err());
        assert!(safe_relative("/etc/passwd").is_err());
        assert!(safe_relative("src/lib.rs").is_ok());
    }

    #[test]
    fn gc_removes_unreferenced_blobs() {
        let ws = workspace("gc");
        let (store, base) = store("gc");
        let first = store.snapshot(&ws, &CheckpointOptions::default()).unwrap();
        std::fs::write(ws.join("src/lib.rs"), "fn changed() {}\n").unwrap();
        let second = store.snapshot(&ws, &CheckpointOptions::default()).unwrap();
        assert!(store.blob_count() >= 3);
        std::fs::remove_file(store.manifests.join(format!("{}.json", first.id))).unwrap();
        std::fs::remove_file(store.manifests.join(format!("{}.json", second.id))).unwrap();
        let report = store.gc(30).unwrap();
        assert_eq!(report.manifests_removed, 0);
        assert!(report.blobs_removed >= 2);
        assert_eq!(store.blob_count(), 0);
        let _ = std::fs::remove_dir_all(&ws);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn restores_only_selected_hunks_and_all_hunks_reproduce_the_blob() {
        let ws = workspace("hunks");
        let original: String = (1..=20).map(|i| format!("line{i:02}\n")).collect();
        std::fs::write(ws.join("src/numbers.txt"), &original).unwrap();
        let (store, base) = store("hunks");
        let manifest = store.snapshot(&ws, &CheckpointOptions::default()).unwrap();
        let modified = original
            .replace("line02", "CHANGED02")
            .replace("line19", "CHANGED19");
        std::fs::write(ws.join("src/numbers.txt"), &modified).unwrap();
        let diff = store.diff_current(&manifest.id, &ws).unwrap();
        let file = diff
            .files
            .iter()
            .find(|file| file.path == "src/numbers.txt")
            .expect("diff for numbers.txt");
        assert!(file.hunks.len() >= 2, "expected two hunks: {file:?}");

        // Accept only the first hunk: line02 reverts, line19 stays changed.
        let report = store
            .restore_hunks(
                &manifest.id,
                &ws,
                &[HunkSelection {
                    path: "src/numbers.txt".into(),
                    hunks: vec![0],
                }],
            )
            .unwrap();
        assert_eq!(report.hunks, 1);
        let after = std::fs::read_to_string(ws.join("src/numbers.txt")).unwrap();
        assert!(after.contains("line02"), "{after}");
        assert!(!after.contains("CHANGED02"), "{after}");
        assert!(after.contains("CHANGED19"), "{after}");

        // Accept the remaining hunk; the file must be byte-identical to the
        // snapshot (the implementation verifies this against the blob).
        let diff = store.diff_current(&manifest.id, &ws).unwrap();
        let file = diff
            .files
            .iter()
            .find(|file| file.path == "src/numbers.txt")
            .unwrap();
        let indices: Vec<usize> = (0..file.hunks.len()).collect();
        store
            .restore_hunks(
                &manifest.id,
                &ws,
                &[HunkSelection {
                    path: "src/numbers.txt".into(),
                    hunks: indices,
                }],
            )
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(ws.join("src/numbers.txt")).unwrap(),
            original
        );
        let _ = std::fs::remove_dir_all(&ws);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn accepts_an_added_file_by_removing_it() {
        let ws = workspace("hunk-added");
        let (store, base) = store("hunk-added");
        let manifest = store.snapshot(&ws, &CheckpointOptions::default()).unwrap();
        std::fs::write(ws.join("NEW.md"), "brand new\n").unwrap();
        store
            .restore_hunks(
                &manifest.id,
                &ws,
                &[HunkSelection {
                    path: "NEW.md".into(),
                    hunks: vec![0],
                }],
            )
            .unwrap();
        assert!(!ws.join("NEW.md").exists());
        let _ = std::fs::remove_dir_all(&ws);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn invalid_hunk_selection_writes_nothing() {
        let ws = workspace("hunk-invalid");
        let (store, base) = store("hunk-invalid");
        let manifest = store.snapshot(&ws, &CheckpointOptions::default()).unwrap();
        std::fs::write(ws.join("src/lib.rs"), "fn changed() {}\n").unwrap();
        std::fs::write(ws.join("README.md"), "# changed\n").unwrap();
        let before = std::fs::read_to_string(ws.join("src/lib.rs")).unwrap();
        let error = store
            .restore_hunks(
                &manifest.id,
                &ws,
                &[
                    HunkSelection {
                        path: "src/lib.rs".into(),
                        hunks: vec![0],
                    },
                    HunkSelection {
                        path: "README.md".into(),
                        hunks: vec![99],
                    },
                ],
            )
            .unwrap_err();
        assert!(error.to_string().contains("hunk 99"), "{error}");
        assert_eq!(
            std::fs::read_to_string(ws.join("src/lib.rs")).unwrap(),
            before
        );
        let _ = std::fs::remove_dir_all(&ws);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn restore_files_only_touches_requested_paths() {
        let ws = workspace("files");
        let (store, base) = store("files");
        let manifest = store.snapshot(&ws, &CheckpointOptions::default()).unwrap();
        std::fs::write(ws.join("src/lib.rs"), "modified\n").unwrap();
        std::fs::write(ws.join("README.md"), "also modified\n").unwrap();
        store
            .restore_files(&manifest.id, &ws, &["src/lib.rs".into()])
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(ws.join("src/lib.rs")).unwrap(),
            "fn main() {\n    println!(\"hi\");\n}\n"
        );
        assert_eq!(
            std::fs::read_to_string(ws.join("README.md")).unwrap(),
            "also modified\n"
        );
        let _ = std::fs::remove_dir_all(&ws);
        let _ = std::fs::remove_dir_all(&base);
    }
}

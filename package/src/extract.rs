//! Safe archive extraction.
//!
//! This is the highest-risk code in Phase 2: an archive is untrusted input.
//! Every entry is validated *before* anything touches the filesystem:
//!
//!   - absolute paths          rejected
//!   - `..` traversal          rejected
//!   - symlinks / hardlinks    rejected (this is how extraction escapes)
//!   - device/fifo entries     rejected
//!   - too many entries        rejected (file-count bomb)
//!   - expansion too large     rejected (compression bomb)
//!   - NUL bytes / bad names   rejected
//!   - every path must stay inside the destination root
//!
//! Extraction is two-phase: first a full *plan* is built and validated, then
//! the plan is executed. Nothing is written if any entry fails validation.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use z_core::error::{Area, ZenError, ZenResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArchiveFormat {
    /// Uncompressed tar.
    Tar,
    /// gzip-compressed tar.
    TarGz,
    /// zstd-compressed tar.
    TarZst,
    /// Plain single file (no container).
    Raw,
    /// Zip container (stored and deflate entries; ZIP64 is refused).
    Zip,
}

impl ArchiveFormat {
    /// Guess from a filename. Conservative: unknown extensions become `Raw`
    /// and are treated as opaque files, never as archives.
    pub fn from_filename(name: &str) -> ArchiveFormat {
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
            ArchiveFormat::TarGz
        } else if lower.ends_with(".tar.zst") || lower.ends_with(".tzst") {
            ArchiveFormat::TarZst
        } else if lower.ends_with(".tar") {
            ArchiveFormat::Tar
        } else if lower.ends_with(".zip") {
            ArchiveFormat::Zip
        } else {
            ArchiveFormat::Raw
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionLimits {
    /// Maximum number of entries.
    pub max_entries: usize,
    /// Maximum total uncompressed bytes.
    pub max_total_bytes: u64,
    /// Maximum size of any single entry.
    pub max_entry_bytes: u64,
    /// Maximum path depth.
    pub max_depth: usize,
    /// Maximum length of a single path component.
    pub max_component_len: usize,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            // 1 GiB of expansion is generous for a CLI tool but finite.
            max_total_bytes: 1024 * 1024 * 1024,
            max_entry_bytes: 512 * 1024 * 1024,
            max_depth: 32,
            max_component_len: 255,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionReport {
    pub format: ArchiveFormat,
    pub entries: usize,
    pub total_bytes: u64,
    /// Files written, relative to the destination root.
    pub files: Vec<String>,
}

/// A validated entry, ready to be written.
#[derive(Debug, Clone)]
struct PlannedEntry {
    relative: PathBuf,
    size: u64,
    is_dir: bool,
}

/// Validate a single entry path lexically.
fn validate_entry_path(
    raw: &str,
    limits: &ExtractionLimits,
    seen: &mut HashSet<String>,
) -> ZenResult<PathBuf> {
    if raw.is_empty() {
        return Err(ZenError::new(
            Area::Sec,
            6100,
            "archive contains an empty entry name",
        ));
    }
    if raw.contains('\0') {
        return Err(ZenError::new(
            Area::Sec,
            6101,
            "archive entry contains a NUL byte",
        ));
    }
    // Normalize backslashes so a Windows-authored archive cannot smuggle
    // traversal past a forward-slash-only check.
    let unified = raw.replace('\\', "/");
    if unified.starts_with('/') {
        return Err(ZenError::new(
            Area::Sec,
            6102,
            format!("archive entry uses an absolute path: {raw}"),
        ));
    }
    // Windows drive letters / UNC prefixes.
    if unified.len() >= 2 && unified.as_bytes()[1] == b':' {
        return Err(ZenError::new(
            Area::Sec,
            6103,
            format!("archive entry uses a drive-letter path: {raw}"),
        ));
    }

    let path = Path::new(&unified);
    let mut out = PathBuf::new();
    let mut depth = 0usize;

    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                return Err(ZenError::new(
                    Area::Sec,
                    6104,
                    format!("archive entry attempts path traversal: {raw}"),
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(ZenError::new(
                    Area::Sec,
                    6105,
                    format!("archive entry has an absolute component: {raw}"),
                ));
            }
            Component::CurDir => {}
            Component::Normal(part) => {
                let s = part.to_string_lossy();
                if s.len() > limits.max_component_len {
                    return Err(ZenError::new(
                        Area::Sec,
                        6106,
                        format!(
                            "archive entry name component is too long ({} bytes)",
                            s.len()
                        ),
                    ));
                }
                depth += 1;
                if depth > limits.max_depth {
                    return Err(ZenError::new(
                        Area::Sec,
                        6107,
                        format!("archive entry exceeds maximum depth ({})", limits.max_depth),
                    ));
                }
                out.push(part);
            }
        }
    }

    if out.as_os_str().is_empty() {
        return Err(ZenError::new(
            Area::Sec,
            6108,
            format!("archive entry resolves to nothing: {raw}"),
        ));
    }

    let key = out.to_string_lossy().to_string();
    if !seen.insert(key.clone()) {
        return Err(ZenError::new(
            Area::Sec,
            6109,
            format!("archive contains a duplicate entry: {key}"),
        )
        .with_remediation(
            "Duplicate entries are ambiguous and can be used to overwrite trusted files.",
        ));
    }

    Ok(out)
}

/// Build and validate an extraction plan from raw tar entries.
///
/// This does not write anything. Symlinks, hardlinks and special files are
/// rejected outright — they are the classic escape vector.
fn plan_tar(entries: &[TarEntry], limits: &ExtractionLimits) -> ZenResult<Vec<PlannedEntry>> {
    if entries.len() > limits.max_entries {
        return Err(ZenError::new(
            Area::Sec,
            6110,
            format!(
                "archive has {} entries, above the {} limit",
                entries.len(),
                limits.max_entries
            ),
        ));
    }

    let mut seen = HashSet::new();
    let mut plan = Vec::new();
    let mut total: u64 = 0;

    for e in entries {
        match e.kind {
            TarEntryKind::File | TarEntryKind::Directory => {}
            TarEntryKind::Symlink => {
                return Err(ZenError::new(
                    Area::Sec,
                    6111,
                    format!(
                        "archive contains a symlink ({}), which is not permitted",
                        e.name
                    ),
                )
                .with_remediation("Symlinks can escape the extraction directory."));
            }
            TarEntryKind::Hardlink => {
                return Err(ZenError::new(
                    Area::Sec,
                    6112,
                    format!(
                        "archive contains a hardlink ({}), which is not permitted",
                        e.name
                    ),
                ));
            }
            TarEntryKind::Other => {
                return Err(ZenError::new(
                    Area::Sec,
                    6113,
                    format!(
                        "archive contains a special file ({}), which is not permitted",
                        e.name
                    ),
                ));
            }
        }

        let relative = validate_entry_path(&e.name, limits, &mut seen)?;

        if e.size > limits.max_entry_bytes {
            return Err(ZenError::new(
                Area::Sec,
                6114,
                format!(
                    "archive entry {} is {} bytes, above the per-entry limit",
                    e.name, e.size
                ),
            ));
        }
        total = total.saturating_add(e.size);
        if total > limits.max_total_bytes {
            return Err(ZenError::new(
                Area::Sec,
                6115,
                format!(
                    "archive expands beyond the {} byte limit",
                    limits.max_total_bytes
                ),
            )
            .with_remediation("This may be a decompression bomb."));
        }

        plan.push(PlannedEntry {
            relative,
            size: e.size,
            is_dir: e.kind == TarEntryKind::Directory,
        });
    }

    Ok(plan)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarEntryKind {
    File,
    Directory,
    Symlink,
    Hardlink,
    Other,
}

#[derive(Debug, Clone)]
pub struct TarEntry {
    pub name: String,
    pub size: u64,
    pub kind: TarEntryKind,
    pub data: Vec<u8>,
}

/// Parse a minimal ustar archive.
///
/// Only the POSIX ustar header subset is supported; anything with an extended
/// header is refused rather than misinterpreted.
pub fn parse_tar(bytes: &[u8]) -> ZenResult<Vec<TarEntry>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut zero_blocks = 0;
    let mut terminated = false;

    while off + 512 <= bytes.len() {
        let header = &bytes[off..off + 512];

        // Two consecutive zero blocks terminate the archive.
        if header.iter().all(|b| *b == 0) {
            zero_blocks += 1;
            off += 512;
            if zero_blocks >= 2 {
                terminated = true;
                break;
            }
            continue;
        }
        zero_blocks = 0;

        let name = read_str(&header[0..100]);
        let size_octal = read_str(&header[124..136]);
        let typeflag = header[156];
        let prefix = read_str(&header[345..500]);

        let full_name = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };

        let size = parse_octal(size_octal.trim()).ok_or_else(|| {
            ZenError::new(
                Area::Sec,
                6120,
                format!("invalid size field in archive entry: {full_name}"),
            )
        })?;

        let kind = match typeflag {
            0 | b'0' | b'7' => TarEntryKind::File,
            b'5' => TarEntryKind::Directory,
            b'2' => TarEntryKind::Symlink,
            b'1' => TarEntryKind::Hardlink,
            // 'x'/'g' extended headers and anything else: refuse.
            _ => TarEntryKind::Other,
        };

        off += 512;
        let data_len = size as usize;
        if off + data_len > bytes.len() {
            return Err(ZenError::new(
                Area::Sec,
                6121,
                format!("archive is truncated: entry {full_name} declares {size} bytes that are not present"),
            ));
        }
        let data = if kind == TarEntryKind::File {
            bytes[off..off + data_len].to_vec()
        } else {
            Vec::new()
        };
        off += data_len;
        // Entries are padded to a 512-byte boundary.
        if !data_len.is_multiple_of(512) {
            off += 512 - (data_len % 512);
        }

        let is_extended = typeflag == b'x' || typeflag == b'g';
        if is_extended {
            return Err(
                ZenError::new(Area::Sec, 6122, "extended tar headers are not supported")
                    .with_remediation("Repackage the artifact as a plain ustar archive."),
            );
        }

        out.push(TarEntry {
            name: full_name,
            size,
            kind,
            data,
        });
    }

    // A well-formed tar ends with two zero blocks. A stream that simply runs
    // out is a *truncated* download, which must never be treated as complete:
    // otherwise a partial artifact could be installed.
    if !terminated {
        return Err(ZenError::new(
            Area::Sec,
            6123,
            "archive is truncated: missing end-of-archive marker",
        )
        .with_remediation("The artifact was not fully downloaded or is corrupt."));
    }

    Ok(out)
}

fn read_str(b: &[u8]) -> String {
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).trim().to_string()
}

fn parse_octal(s: &str) -> Option<u64> {
    if s.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(s.trim_matches('\0').trim(), 8).ok()
}

/// Extract `bytes` into `dest_root`. Returns a report of what was written.
///
/// Nothing is written unless the whole archive validates first.
pub fn extract_archive(
    bytes: &[u8],
    format: ArchiveFormat,
    dest_root: &Path,
    limits: &ExtractionLimits,
) -> ZenResult<ExtractionReport> {
    match format {
        ArchiveFormat::Raw => {
            // A raw artifact is not an archive; the caller installs it directly.
            Err(ZenError::new(
                Area::Sec,
                6130,
                "raw artifacts are installed directly, not extracted",
            ))
        }
        ArchiveFormat::Tar => {
            let entries = parse_tar(bytes)?;
            write_plan(&entries, dest_root, limits, format)
        }
        ArchiveFormat::TarGz => {
            let tar_bytes = gunzip(bytes, limits)?;
            let entries = parse_tar(&tar_bytes)?;
            write_plan(&entries, dest_root, limits, format)
        }
        ArchiveFormat::TarZst => {
            let tar_bytes = unzstd(bytes, limits)?;
            let entries = parse_tar(&tar_bytes)?;
            write_plan(&entries, dest_root, limits, format)
        }
        ArchiveFormat::Zip => {
            let entries = parse_zip(bytes, limits)?;
            write_plan(&entries, dest_root, limits, format)
        }
    }
}

fn write_plan(
    entries: &[TarEntry],
    dest_root: &Path,
    limits: &ExtractionLimits,
    format: ArchiveFormat,
) -> ZenResult<ExtractionReport> {
    // Phase 1 of extraction: validate everything.
    let plan = plan_tar(entries, limits)?;

    // Phase 2: create the destination and write.
    std::fs::create_dir_all(dest_root)?;
    let root = dest_root.canonicalize().map_err(|e| {
        ZenError::new(
            Area::Fs,
            6133,
            format!("cannot resolve destination {}: {e}", dest_root.display()),
        )
    })?;

    let mut files = Vec::new();
    let mut total = 0u64;

    for (entry, planned) in entries.iter().zip(plan.iter()) {
        if planned.is_dir {
            continue;
        }
        let target = root.join(&planned.relative);

        // Defence in depth: re-check the joined path lexically and make sure
        // the parent directory we are about to use is still inside the root.
        if !target.starts_with(&root) {
            return Err(ZenError::new(
                Area::Sec,
                6134,
                format!(
                    "refusing to write outside the destination: {}",
                    target.display()
                ),
            ));
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
            // After creating parents, verify the canonical parent is inside.
            let cparent = parent.canonicalize().map_err(|e| {
                ZenError::new(
                    Area::Fs,
                    6135,
                    format!("cannot resolve {}: {e}", parent.display()),
                )
            })?;
            if !cparent.starts_with(&root) {
                return Err(ZenError::new(
                    Area::Sec,
                    6136,
                    format!(
                        "parent directory escapes the destination: {}",
                        cparent.display()
                    ),
                ));
            }
        }

        std::fs::write(&target, &entry.data)?;
        total += entry.data.len() as u64;
        files.push(planned.relative.to_string_lossy().to_string());
    }

    // Cross-check the planned size against what we actually wrote. A
    // disagreement means an entry header lied about its length, which would
    // indicate a malformed or crafted archive.
    let planned_total: u64 = plan.iter().map(|p| p.size).sum();
    if planned_total != total {
        return Err(ZenError::new(
            Area::Sec,
            6137,
            format!(
                "archive size inconsistency: headers declared {planned_total} bytes, extracted {total}"
            ),
        )
        .with_remediation("The archive is malformed; do not install it."));
    }

    Ok(ExtractionReport {
        format,
        entries: plan.len(),
        total_bytes: total,
        files,
    })
}

/// Read a little-endian u16 at `at`, or `None` on a short buffer.
fn u16le(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

/// Read a little-endian u32 at `at`, or `None` on a short buffer.
fn u32le(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn zip_error(code: u16, message: impl Into<String>) -> ZenError {
    ZenError::new(Area::Sec, code, message.into())
}

/// Parse a ZIP archive into the same `TarEntry` shape used by the tar path, so
/// that one hardened writer validates and writes both formats.
///
/// Only stored (0) and deflate (8) entries are supported. Encrypted entries,
/// ZIP64 archives, symlinks, hardlinks and special files are refused rather
/// than guessed at. Sizes are checked against the limits *before* any
/// decompression, and every entry's CRC-32 is verified after decompression.
fn parse_zip(bytes: &[u8], limits: &ExtractionLimits) -> ZenResult<Vec<TarEntry>> {
    const EOCD_SIG: u32 = 0x0605_4b50;
    const CENTRAL_SIG: u32 = 0x0201_4b50;
    const LOCAL_SIG: u32 = 0x0403_4b50;

    if bytes.len() < 22 {
        return Err(zip_error(
            6150,
            "zip stream is too short to contain a directory",
        ));
    }
    // The EOCD record sits at the end, optionally followed by a comment of up
    // to 64 KiB. Search backwards for a signature whose comment length makes
    // it line up exactly with the end of the stream.
    let floor = bytes.len().saturating_sub(22 + 0xffff);
    let mut eocd = None;
    let mut at = bytes.len() - 22;
    loop {
        if u32le(bytes, at) == Some(EOCD_SIG) {
            let comment_len = u16le(bytes, at + 20).unwrap_or(0) as usize;
            if at + 22 + comment_len == bytes.len() {
                eocd = Some(at);
                break;
            }
        }
        if at == floor {
            break;
        }
        at -= 1;
    }
    let eocd = eocd.ok_or_else(|| {
        zip_error(
            6151,
            "zip is missing its end-of-central-directory record (truncated or not a zip)",
        )
    })?;

    let disk = u16le(bytes, eocd + 4).unwrap_or(0);
    let cd_disk = u16le(bytes, eocd + 6).unwrap_or(0);
    let on_disk = u16le(bytes, eocd + 8).unwrap_or(0) as usize;
    let count = u16le(bytes, eocd + 10).unwrap_or(0) as usize;
    let cd_size = u32le(bytes, eocd + 12).unwrap_or(0) as usize;
    let cd_offset = u32le(bytes, eocd + 16).unwrap_or(0) as usize;

    if disk != 0 || cd_disk != 0 || on_disk != count {
        return Err(zip_error(6152, "multi-disk zip archives are not supported"));
    }
    if count == 0xffff || cd_size == u32::MAX as usize || cd_offset == u32::MAX as usize {
        return Err(zip_error(
            6153,
            "ZIP64 archives are not supported; repackage without ZIP64",
        ));
    }
    if count > limits.max_entries {
        return Err(zip_error(
            6154,
            format!(
                "zip has {count} entries, above the {} limit",
                limits.max_entries
            ),
        ));
    }
    let cd_end = cd_offset
        .checked_add(cd_size)
        .ok_or_else(|| zip_error(6155, "zip central directory offset overflows"))?;
    if cd_end > eocd {
        return Err(zip_error(
            6156,
            "zip central directory extends past the end record",
        ));
    }

    let mut out = Vec::with_capacity(count.min(1024));
    let mut pos = cd_offset;
    let mut total: u64 = 0;

    for index in 0..count {
        if pos + 46 > cd_end {
            return Err(zip_error(
                6157,
                format!("zip central directory is truncated at entry {index}"),
            ));
        }
        if u32le(bytes, pos) != Some(CENTRAL_SIG) {
            return Err(zip_error(
                6158,
                format!("zip central directory entry {index} has a bad signature"),
            ));
        }
        let flags = u16le(bytes, pos + 8).unwrap_or(0);
        let method = u16le(bytes, pos + 10).unwrap_or(0);
        let crc = u32le(bytes, pos + 16).unwrap_or(0);
        let comp_size = u32le(bytes, pos + 20).unwrap_or(0) as usize;
        let uncomp_size = u32le(bytes, pos + 24).unwrap_or(0) as usize;
        let name_len = u16le(bytes, pos + 28).unwrap_or(0) as usize;
        let extra_len = u16le(bytes, pos + 30).unwrap_or(0) as usize;
        let comment_len = u16le(bytes, pos + 32).unwrap_or(0) as usize;
        let disk_start = u16le(bytes, pos + 34).unwrap_or(0);
        let external = u32le(bytes, pos + 38).unwrap_or(0);
        let local_off = u32le(bytes, pos + 42).unwrap_or(0) as usize;

        if comp_size == u32::MAX as usize
            || uncomp_size == u32::MAX as usize
            || local_off == u32::MAX as usize
        {
            return Err(zip_error(
                6159,
                "ZIP64 entry sizes are not supported; repackage without ZIP64",
            ));
        }
        if flags & 0x0001 != 0 {
            return Err(zip_error(
                6160,
                "zip entry is encrypted; encrypted archives are not supported",
            ));
        }
        if disk_start != 0 {
            return Err(zip_error(6161, "multi-disk zip entries are not supported"));
        }

        let name_bytes = bytes
            .get(pos + 46..pos + 46 + name_len)
            .ok_or_else(|| zip_error(6162, "zip entry name runs past the directory"))?;
        let name = std::str::from_utf8(name_bytes).map_err(|_| {
            zip_error(
                6163,
                "zip entry name is not valid UTF-8; repackage with UTF-8 names",
            )
        })?;

        // Unix mode lives in the high half of the external attributes. A mode
        // of zero means the archive was written by a system without POSIX
        // types, so fall back to the trailing-slash directory convention.
        let mode = ((external >> 16) & 0xffff) as u32;
        let file_type = mode & 0o170000;
        let is_dir = name.ends_with('/') || name.ends_with('\\') || file_type == 0o040000;
        if file_type != 0 && file_type != 0o100000 && file_type != 0o040000 {
            return Err(zip_error(
                6164,
                format!("zip contains a non-regular entry ({name}); symlinks and devices are not permitted"),
            ));
        }

        if uncomp_size as u64 > limits.max_entry_bytes {
            return Err(zip_error(
                6165,
                format!("zip entry {name} is {uncomp_size} bytes, above the per-entry limit"),
            ));
        }
        total = total.saturating_add(uncomp_size as u64);
        if total > limits.max_total_bytes {
            return Err(zip_error(
                6166,
                format!(
                    "zip expands beyond the {} byte limit",
                    limits.max_total_bytes
                ),
            ));
        }

        // Validate the local header too: a mismatch between the two headers is
        // a classic way to smuggle different data past a scanner.
        if local_off + 30 > bytes.len() {
            return Err(zip_error(
                6167,
                format!("zip entry {name} has a bad local header offset"),
            ));
        }
        if u32le(bytes, local_off) != Some(LOCAL_SIG) {
            return Err(zip_error(
                6168,
                format!("zip entry {name} has a bad local header signature"),
            ));
        }
        let local_flags = u16le(bytes, local_off + 6).unwrap_or(0);
        let local_method = u16le(bytes, local_off + 8).unwrap_or(0);
        let local_name_len = u16le(bytes, local_off + 26).unwrap_or(0) as usize;
        let local_extra_len = u16le(bytes, local_off + 28).unwrap_or(0) as usize;
        if local_flags != flags || local_method != method {
            return Err(zip_error(
                6169,
                format!("zip entry {name} local header disagrees with the central directory"),
            ));
        }
        let local_name = bytes
            .get(local_off + 30..local_off + 30 + local_name_len)
            .ok_or_else(|| zip_error(6170, format!("zip entry {name} local name is truncated")))?;
        if local_name != name_bytes {
            return Err(zip_error(
                6171,
                format!("zip entry name mismatch between headers for {name}"),
            ));
        }
        let data_start = local_off
            .checked_add(30)
            .and_then(|v| v.checked_add(local_name_len))
            .and_then(|v| v.checked_add(local_extra_len))
            .ok_or_else(|| zip_error(6172, format!("zip entry {name} data offset overflows")))?;
        let data_end = data_start
            .checked_add(comp_size)
            .ok_or_else(|| zip_error(6173, format!("zip entry {name} data size overflows")))?;
        if data_end > bytes.len() {
            return Err(zip_error(
                6174,
                format!("zip entry {name} data is truncated"),
            ));
        }
        let compressed = &bytes[data_start..data_end];

        let data = if is_dir {
            Vec::new()
        } else {
            match method {
                0 => {
                    if comp_size != uncomp_size {
                        return Err(zip_error(
                            6175,
                            format!("stored zip entry {name} has inconsistent sizes"),
                        ));
                    }
                    compressed.to_vec()
                }
                8 => inflate_zip_entry(compressed, uncomp_size, name)?,
                other => {
                    return Err(zip_error(
                        6176,
                        format!(
                            "zip entry {name} uses unsupported compression method {other} (only stored and deflate are supported)"
                        ),
                    ))
                }
            }
        };

        if !is_dir {
            if data.len() != uncomp_size {
                return Err(zip_error(
                    6177,
                    format!(
                        "zip entry {name} expanded to {} bytes, header declared {uncomp_size}",
                        data.len()
                    ),
                ));
            }
            let mut actual = flate2::Crc::new();
            actual.update(&data);
            if actual.sum() != crc {
                return Err(zip_error(
                    6178,
                    format!("zip entry {name} failed its CRC-32 check"),
                ));
            }
        }

        out.push(TarEntry {
            name: name.to_string(),
            size: uncomp_size as u64,
            kind: if is_dir {
                TarEntryKind::Directory
            } else {
                TarEntryKind::File
            },
            data,
        });
        pos += 46 + name_len + extra_len + comment_len;
    }

    Ok(out)
}

/// Inflate one deflate-compressed zip entry, bounded to its declared size.
fn inflate_zip_entry(compressed: &[u8], expected: usize, name: &str) -> ZenResult<Vec<u8>> {
    let decoder = flate2::read::DeflateDecoder::new(compressed);
    let mut out = Vec::with_capacity(expected.min(1024 * 1024));
    decoder
        .take(expected as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| zip_error(6179, format!("zip entry {name} could not be inflated: {e}")))?;
    if out.len() != expected {
        return Err(zip_error(
            6180,
            format!(
                "zip entry {name} inflated to {} bytes, header declared {expected}",
                out.len()
            ),
        ));
    }
    Ok(out)
}

/// Decompress a zstd stream, bounded by the archive's total-expansion limit.
fn unzstd(bytes: &[u8], limits: &ExtractionLimits) -> ZenResult<Vec<u8>> {
    let decoder = zstd::stream::read::Decoder::new(bytes)
        .map_err(|e| ZenError::new(Area::Sec, 6181, format!("invalid zstd stream: {e}")))?;
    let mut out = Vec::new();
    decoder
        .take(limits.max_total_bytes + 1)
        .read_to_end(&mut out)
        .map_err(|e| ZenError::new(Area::Sec, 6182, format!("zstd decompression failed: {e}")))?;
    if out.len() as u64 > limits.max_total_bytes {
        return Err(ZenError::new(
            Area::Sec,
            6183,
            format!(
                "zstd stream expands beyond the {} byte limit",
                limits.max_total_bytes
            ),
        )
        .with_remediation("This may be a decompression bomb."));
    }
    Ok(out)
}

/// Minimal gzip (RFC 1952) decompressor: deflate stored + fixed + dynamic
/// Huffman blocks. Bounded by `limits.max_total_bytes`.
fn gunzip(bytes: &[u8], limits: &ExtractionLimits) -> ZenResult<Vec<u8>> {
    if bytes.len() < 18 {
        return Err(ZenError::new(Area::Sec, 6140, "gzip stream is too short"));
    }
    if bytes[0] != 0x1f || bytes[1] != 0x8b {
        return Err(ZenError::new(
            Area::Sec,
            6141,
            "not a gzip stream (bad magic)",
        ));
    }
    let method = bytes[2];
    if method != 8 {
        return Err(ZenError::new(
            Area::Sec,
            6142,
            format!("unsupported gzip compression method {method}"),
        ));
    }
    let flg = bytes[3];
    let mut off = 10usize;

    if flg & 0x04 != 0 {
        // FEXTRA
        if off + 2 > bytes.len() {
            return Err(ZenError::new(Area::Sec, 6143, "truncated gzip extra field"));
        }
        let xlen = u16::from_le_bytes([bytes[off], bytes[off + 1]]) as usize;
        off += 2 + xlen;
    }
    if flg & 0x08 != 0 {
        while off < bytes.len() && bytes[off] != 0 {
            off += 1;
        }
        off += 1;
    }
    if flg & 0x10 != 0 {
        while off < bytes.len() && bytes[off] != 0 {
            off += 1;
        }
        off += 1;
    }
    if flg & 0x02 != 0 {
        off += 2; // FHCRC
    }
    if off >= bytes.len() {
        return Err(ZenError::new(
            Area::Sec,
            6144,
            "gzip header overruns the stream",
        ));
    }

    inflate(&bytes[off..], limits)
}

// ---------------------------------------------------------------------------
// Inflate (RFC 1951), bounded output.
// ---------------------------------------------------------------------------

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bit: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bit: 0,
        }
    }
    fn bit(&mut self) -> ZenResult<u32> {
        if self.pos >= self.data.len() {
            return Err(ZenError::new(
                Area::Sec,
                6150,
                "unexpected end of deflate stream",
            ));
        }
        let b = (self.data[self.pos] >> self.bit) & 1;
        self.bit += 1;
        if self.bit == 8 {
            self.bit = 0;
            self.pos += 1;
        }
        Ok(b as u32)
    }
    fn bits(&mut self, n: u32) -> ZenResult<u32> {
        let mut v = 0u32;
        for i in 0..n {
            v |= self.bit()? << i;
        }
        Ok(v)
    }
    fn align(&mut self) {
        if self.bit != 0 {
            self.bit = 0;
            self.pos += 1;
        }
    }
}

struct Huffman {
    /// (code_length, symbol) pairs sorted by canonical order.
    symbols: Vec<(u8, u16)>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Self {
        let mut symbols: Vec<(u8, u16)> = lengths
            .iter()
            .enumerate()
            .filter(|(_, l)| **l > 0)
            .map(|(s, l)| (*l, s as u16))
            .collect();
        symbols.sort_by_key(|(l, s)| (*l, *s));
        Self { symbols }
    }

    fn decode(&self, r: &mut BitReader) -> ZenResult<u16> {
        let mut code = 0u32;
        let mut first = 0u32;
        let mut index = 0usize;
        for len in 1..=15u32 {
            code |= r.bit()?;
            let count = self
                .symbols
                .iter()
                .filter(|(l, _)| *l as u32 == len)
                .count() as u32;
            if code < first + count {
                let i = index + (code - first) as usize;
                return self
                    .symbols
                    .get(i)
                    .map(|(_, s)| *s)
                    .ok_or_else(|| ZenError::new(Area::Sec, 6151, "invalid huffman symbol"));
            }
            index += count as usize;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(ZenError::new(
            Area::Sec,
            6152,
            "huffman code exceeds maximum length",
        ))
    }
}

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

fn inflate(data: &[u8], limits: &ExtractionLimits) -> ZenResult<Vec<u8>> {
    let mut r = BitReader::new(data);
    let mut out: Vec<u8> = Vec::new();
    let cap = limits.max_total_bytes as usize;

    loop {
        let last = r.bits(1)?;
        let btype = r.bits(2)?;
        match btype {
            0 => {
                r.align();
                if r.pos + 4 > r.data.len() {
                    return Err(ZenError::new(
                        Area::Sec,
                        6153,
                        "truncated stored block header",
                    ));
                }
                let len = u16::from_le_bytes([r.data[r.pos], r.data[r.pos + 1]]) as usize;
                let nlen = u16::from_le_bytes([r.data[r.pos + 2], r.data[r.pos + 3]]) as usize;
                if len != (!nlen & 0xffff) {
                    return Err(ZenError::new(
                        Area::Sec,
                        6154,
                        "stored block length check failed",
                    ));
                }
                r.pos += 4;
                if r.pos + len > r.data.len() {
                    return Err(ZenError::new(Area::Sec, 6155, "truncated stored block"));
                }
                if out.len() + len > cap {
                    return Err(ZenError::new(
                        Area::Sec,
                        6156,
                        "decompressed output exceeds the limit",
                    )
                    .with_remediation("Possible decompression bomb."));
                }
                out.extend_from_slice(&r.data[r.pos..r.pos + len]);
                r.pos += len;
            }
            1 | 2 => {
                let (lit, dist) = if btype == 1 {
                    let mut lit_len = [0u8; 288];
                    for (i, l) in lit_len.iter_mut().enumerate() {
                        *l = if i < 144 {
                            8
                        } else if i < 256 {
                            9
                        } else if i < 280 {
                            7
                        } else {
                            8
                        };
                    }
                    (Huffman::new(&lit_len), Huffman::new(&[5u8; 30]))
                } else {
                    let hlit = r.bits(5)? as usize + 257;
                    let hdist = r.bits(5)? as usize + 1;
                    let hclen = r.bits(4)? as usize + 4;
                    const ORDER: [usize; 19] = [
                        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                    ];
                    let mut cl = [0u8; 19];
                    for i in 0..hclen {
                        cl[ORDER[i]] = r.bits(3)? as u8;
                    }
                    let cl_huff = Huffman::new(&cl);
                    let mut lengths = vec![0u8; hlit + hdist];
                    let mut i = 0usize;
                    while i < hlit + hdist {
                        let sym = cl_huff.decode(&mut r)?;
                        match sym {
                            0..=15 => {
                                lengths[i] = sym as u8;
                                i += 1;
                            }
                            16 => {
                                if i == 0 {
                                    return Err(ZenError::new(
                                        Area::Sec,
                                        6157,
                                        "invalid repeat in code lengths",
                                    ));
                                }
                                let prev = lengths[i - 1];
                                let rep = 3 + r.bits(2)? as usize;
                                for _ in 0..rep {
                                    if i >= lengths.len() {
                                        break;
                                    }
                                    lengths[i] = prev;
                                    i += 1;
                                }
                            }
                            17 => {
                                let rep = 3 + r.bits(3)? as usize;
                                i += rep;
                            }
                            18 => {
                                let rep = 11 + r.bits(7)? as usize;
                                i += rep;
                            }
                            _ => {
                                return Err(ZenError::new(
                                    Area::Sec,
                                    6158,
                                    "invalid code length symbol",
                                ))
                            }
                        }
                    }
                    if i > lengths.len() {
                        return Err(ZenError::new(Area::Sec, 6159, "code length overrun"));
                    }
                    (
                        Huffman::new(&lengths[..hlit]),
                        Huffman::new(&lengths[hlit..]),
                    )
                };

                loop {
                    let sym = lit.decode(&mut r)?;
                    match sym {
                        0..=255 => {
                            if out.len() >= cap {
                                return Err(ZenError::new(
                                    Area::Sec,
                                    6160,
                                    "output exceeds the limit",
                                ));
                            }
                            out.push(sym as u8);
                        }
                        256 => break,
                        257..=285 => {
                            let li = (sym - 257) as usize;
                            let len = LENGTH_BASE[li] as usize
                                + r.bits(LENGTH_EXTRA[li] as u32)? as usize;
                            let dsym = dist.decode(&mut r)? as usize;
                            if dsym >= DIST_BASE.len() {
                                return Err(ZenError::new(
                                    Area::Sec,
                                    6161,
                                    "invalid distance symbol",
                                ));
                            }
                            let distance = DIST_BASE[dsym] as usize
                                + r.bits(DIST_EXTRA[dsym] as u32)? as usize;
                            if distance == 0 || distance > out.len() {
                                return Err(ZenError::new(
                                    Area::Sec,
                                    6162,
                                    "invalid back-reference distance",
                                ));
                            }
                            if out.len() + len > cap {
                                return Err(ZenError::new(
                                    Area::Sec,
                                    6163,
                                    "output exceeds the limit",
                                )
                                .with_remediation("Possible decompression bomb."));
                            }
                            let start = out.len() - distance;
                            for k in 0..len {
                                let b = out[start + k];
                                out.push(b);
                            }
                        }
                        _ => {
                            return Err(ZenError::new(
                                Area::Sec,
                                6164,
                                "invalid literal/length symbol",
                            ))
                        }
                    }
                }
            }
            _ => return Err(ZenError::new(Area::Sec, 6165, "invalid deflate block type")),
        }

        if last == 1 {
            break;
        }
    }

    Ok(out)
}

/// A helper used by tests and callers who just want "is this a plausible
/// archive" without extracting.
pub fn sniff_format(bytes: &[u8]) -> ArchiveFormat {
    if bytes.starts_with(&[0x1f, 0x8b]) {
        ArchiveFormat::TarGz
    } else if bytes.starts_with(b"PK\x03\x04") {
        ArchiveFormat::Zip
    } else if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        ArchiveFormat::TarZst
    } else if bytes.len() >= 265 && &bytes[257..262] == b"ustar" {
        ArchiveFormat::Tar
    } else {
        ArchiveFormat::Raw
    }
}

/// Read a whole file into memory (bounded by the caller's limits).
pub fn read_bounded(path: &Path, max: u64) -> ZenResult<Vec<u8>> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > max {
        return Err(ZenError::new(
            Area::Sec,
            6170,
            format!(
                "{} is {} bytes, above the {} byte limit",
                path.display(),
                meta.len(),
                max
            ),
        ));
    }
    let mut f = std::fs::File::open(path)?;
    let mut buf = Vec::with_capacity(meta.len() as usize);
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use z_native::fs::private_temp_dir;

    fn tmp() -> PathBuf {
        private_temp_dir("zen-extract").unwrap()
    }

    // --- tar building helpers (test-only) -----------------------------------

    fn tar_header(name: &str, size: u64, typeflag: u8) -> [u8; 512] {
        let mut h = [0u8; 512];
        h[..name.len().min(100)].copy_from_slice(&name.as_bytes()[..name.len().min(100)]);
        h[100..108].copy_from_slice(b"0000644\0");
        h[108..116].copy_from_slice(b"0000000\0");
        h[116..124].copy_from_slice(b"0000000\0");
        let size_str = format!("{size:011o}\0");
        h[124..136].copy_from_slice(size_str.as_bytes());
        h[136..148].copy_from_slice(b"00000000000\0");
        h[148..156].copy_from_slice(b"        ");
        h[156] = typeflag;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h
    }

    fn tar_with(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, flag, data) in entries {
            out.extend_from_slice(&tar_header(name, data.len() as u64, *flag));
            out.extend_from_slice(data);
            let pad = (512 - (data.len() % 512)) % 512;
            out.extend(std::iter::repeat_n(0u8, pad));
        }
        out.extend(std::iter::repeat_n(0u8, 1024));
        out
    }

    // --- zip building helpers (test-only) -----------------------------------

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = flate2::Crc::new();
        crc.update(data);
        crc.sum()
    }

    fn deflate(data: &[u8]) -> Vec<u8> {
        use flate2::write::DeflateEncoder;
        use std::io::Write;
        let mut encoder = DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// Build a zip with `(name, data, deflate, unix_mode)` entries.
    fn zip_with(entries: &[(&str, &[u8], bool, u32)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data, compressed_flag, mode) in entries {
            let offset = out.len() as u32;
            let compressed = if *compressed_flag {
                deflate(data)
            } else {
                data.to_vec()
            };
            let method: u16 = if *compressed_flag { 8 } else { 0 };
            let crc = crc32(data);

            out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&0x0800u16.to_le_bytes());
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&compressed);

            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            central.extend_from_slice(&0x031eu16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0x0800u16.to_le_bytes());
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&(mode << 16).to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        out.extend_from_slice(&central);
        let cd_size = out.len() as u32 - cd_offset;
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    // --- traversal / absolute path -----------------------------------------

    #[test]
    fn rejects_parent_traversal() {
        let t = tar_with(&[("../../../../startup", b'0', b"evil")]);
        let d = tmp();
        let e = extract_archive(&t, ArchiveFormat::Tar, &d, &ExtractionLimits::default());
        assert!(e.is_err());
        assert!(format!("{}", e.unwrap_err()).contains("traversal"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_absolute_path() {
        let t = tar_with(&[("/etc/cron.d/evil", b'0', b"x")]);
        let d = tmp();
        assert!(extract_archive(&t, ArchiveFormat::Tar, &d, &ExtractionLimits::default()).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_backslash_traversal() {
        let t = tar_with(&[("..\\..\\evil", b'0', b"x")]);
        let d = tmp();
        assert!(extract_archive(&t, ArchiveFormat::Tar, &d, &ExtractionLimits::default()).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_drive_letter_path() {
        let t = tar_with(&[("C:/Windows/evil.exe", b'0', b"x")]);
        let d = tmp();
        assert!(extract_archive(&t, ArchiveFormat::Tar, &d, &ExtractionLimits::default()).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_nul_in_name() {
        // A NUL inside a tar header name field terminates the C string, so an
        // archive cannot actually carry one. The guard matters for the
        // validator itself (e.g. callers passing raw strings), so test it
        // directly.
        let mut seen = HashSet::new();
        let r = validate_entry_path("ok\0/../../evil", &ExtractionLimits::default(), &mut seen);
        assert!(r.is_err());
        assert!(format!("{}", r.unwrap_err()).contains("NUL"));
    }

    // --- symlink / hardlink / special --------------------------------------

    #[test]
    fn rejects_symlink_entry() {
        let t = tar_with(&[("link", b'2', b"")]);
        let d = tmp();
        let e = extract_archive(&t, ArchiveFormat::Tar, &d, &ExtractionLimits::default());
        assert!(e.is_err());
        assert!(format!("{}", e.unwrap_err()).contains("symlink"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_hardlink_entry() {
        let t = tar_with(&[("link", b'1', b"")]);
        let d = tmp();
        assert!(extract_archive(&t, ArchiveFormat::Tar, &d, &ExtractionLimits::default()).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_special_file_entry() {
        let t = tar_with(&[("dev", b'3', b"")]);
        let d = tmp();
        assert!(extract_archive(&t, ArchiveFormat::Tar, &d, &ExtractionLimits::default()).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_extended_headers() {
        let t = tar_with(&[("x", b'x', b"")]);
        let d = tmp();
        assert!(extract_archive(&t, ArchiveFormat::Tar, &d, &ExtractionLimits::default()).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    // --- bombs --------------------------------------------------------------

    #[test]
    fn rejects_too_many_entries() {
        let entries: Vec<(&str, u8, &[u8])> = (0..50).map(|_| ("f", b'0', b"x" as &[u8])).collect();
        // Duplicate names would trip the duplicate check first; use distinct names.
        let names: Vec<String> = (0..50).map(|i| format!("f{i}")).collect();
        let refs: Vec<(&str, u8, &[u8])> = names
            .iter()
            .map(|n| (n.as_str(), b'0', b"x" as &[u8]))
            .collect();
        let _ = entries;
        let t = tar_with(&refs);
        let d = tmp();
        let limits = ExtractionLimits {
            max_entries: 10,
            ..Default::default()
        };
        let e = extract_archive(&t, ArchiveFormat::Tar, &d, &limits);
        assert!(e.is_err());
        assert!(format!("{}", e.unwrap_err()).contains("entries"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_duplicate_entries() {
        let t = tar_with(&[("same", b'0', b"a"), ("same", b'0', b"b")]);
        let d = tmp();
        let e = extract_archive(&t, ArchiveFormat::Tar, &d, &ExtractionLimits::default());
        assert!(e.is_err());
        assert!(format!("{}", e.unwrap_err()).contains("duplicate"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_entry_above_size_limit() {
        let data = vec![0u8; 2048];
        let t = tar_with(&[("big", b'0', &data)]);
        let d = tmp();
        let limits = ExtractionLimits {
            max_entry_bytes: 1024,
            ..Default::default()
        };
        assert!(extract_archive(&t, ArchiveFormat::Tar, &d, &limits).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_total_expansion_above_limit() {
        let data = vec![0u8; 1024];
        let t = tar_with(&[("a", b'0', &data), ("b", b'0', &data), ("c", b'0', &data)]);
        let d = tmp();
        let limits = ExtractionLimits {
            max_total_bytes: 2048,
            ..Default::default()
        };
        let e = extract_archive(&t, ArchiveFormat::Tar, &d, &limits);
        assert!(e.is_err());
        assert!(format!("{}", e.unwrap_err()).contains("expands beyond"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_deep_nesting() {
        let deep = "a/".repeat(50) + "f";
        let t = tar_with(&[(deep.as_str(), b'0', b"x")]);
        let d = tmp();
        assert!(extract_archive(&t, ArchiveFormat::Tar, &d, &ExtractionLimits::default()).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_overlong_component() {
        // The ustar header stores a single name in 100 bytes and a prefix in
        // 155, so a component longer than the limit must be built by using the
        // prefix field with a short name and a tight component limit instead.
        let t = tar_with(&[("shortname", b'0', b"y")]);
        let d = tmp();
        let limits = ExtractionLimits {
            max_component_len: 5,
            ..Default::default()
        };
        let e = extract_archive(&t, ArchiveFormat::Tar, &d, &limits);
        assert!(
            e.is_err(),
            "component longer than the limit must be refused"
        );
        assert!(format!("{}", e.unwrap_err()).contains("too long"));
        let _ = std::fs::remove_dir_all(&d);
    }

    // --- malformed ----------------------------------------------------------

    #[test]
    fn rejects_truncated_archive() {
        // Cut the end-of-archive marker off: the stream runs out mid-archive.
        let t = tar_with(&[("f", b'0', b"hello")]);
        let t = &t[..t.len() - 1024];
        let d = tmp();
        let e = extract_archive(t, ArchiveFormat::Tar, &d, &ExtractionLimits::default());
        assert!(e.is_err(), "missing end-of-archive marker must be refused");
        assert!(format!("{}", e.unwrap_err()).contains("truncated"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_archive_cut_mid_header() {
        let t = tar_with(&[("f", b'0', b"hello")]);
        let t = &t[..300]; // inside the first header
        let d = tmp();
        assert!(extract_archive(t, ArchiveFormat::Tar, &d, &ExtractionLimits::default()).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_archive_whose_entry_data_is_cut() {
        let t = tar_with(&[("f", b'0', &vec![b'x'; 2048])]);
        let t = &t[..1024]; // header ok, data incomplete
        let d = tmp();
        assert!(extract_archive(t, ArchiveFormat::Tar, &d, &ExtractionLimits::default()).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_empty_name() {
        let t = tar_with(&[("", b'0', b"x")]);
        let d = tmp();
        assert!(extract_archive(&t, ArchiveFormat::Tar, &d, &ExtractionLimits::default()).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_bad_gzip_magic() {
        let d = tmp();
        assert!(extract_archive(
            b"not gzip at all!!!",
            ArchiveFormat::TarGz,
            &d,
            &ExtractionLimits::default()
        )
        .is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn malformed_zip_and_zstd_are_rejected() {
        let d = tmp();
        assert!(extract_archive(
            b"PK\x03\x04",
            ArchiveFormat::Zip,
            &d,
            &ExtractionLimits::default()
        )
        .is_err());
        assert!(extract_archive(
            b"\x28\xb5\x2f\xfd",
            ArchiveFormat::TarZst,
            &d,
            &ExtractionLimits::default()
        )
        .is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    // --- zip ----------------------------------------------------------------

    #[test]
    fn extracts_zip_stored_and_deflated_entries() {
        let z = zip_with(&[
            ("bin/tool", b"#!/bin/sh\necho hi\n", true, 0o100755),
            ("plain.txt", b"stored payload", false, 0o100644),
            ("empty/", b"", false, 0o040755),
        ]);
        let d = tmp();
        let r = extract_archive(&z, ArchiveFormat::Zip, &d, &ExtractionLimits::default()).unwrap();
        assert_eq!(r.entries, 3);
        assert_eq!(
            std::fs::read_to_string(d.join("bin/tool")).unwrap(),
            "#!/bin/sh\necho hi\n"
        );
        assert_eq!(
            std::fs::read_to_string(d.join("plain.txt")).unwrap(),
            "stored payload"
        );
        assert!(!d.join("empty").exists() || d.join("empty").is_dir());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn zip_rejects_parent_traversal() {
        let z = zip_with(&[("../evil.txt", b"bad", false, 0o100644)]);
        let d = tmp();
        let e = extract_archive(&z, ArchiveFormat::Zip, &d, &ExtractionLimits::default());
        assert!(e.is_err());
        assert!(!d.join("evil.txt").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn zip_rejects_symlink_entries() {
        let z = zip_with(&[("link", b"/etc/passwd", false, 0o120777)]);
        let d = tmp();
        let e = extract_archive(&z, ArchiveFormat::Zip, &d, &ExtractionLimits::default());
        assert!(e.is_err());
        assert!(format!("{}", e.unwrap_err()).contains("non-regular"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn zip_rejects_entry_above_size_limit_before_writing() {
        let z = zip_with(&[("big", b"0123456789", false, 0o100644)]);
        let d = tmp();
        let limits = ExtractionLimits {
            max_entry_bytes: 4,
            ..Default::default()
        };
        assert!(extract_archive(&z, ArchiveFormat::Zip, &d, &limits).is_err());
        assert!(!d.join("big").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn zip_rejects_crc_mismatch() {
        let mut z = zip_with(&[("file.txt", b"payload", false, 0o100644)]);
        // The stored payload appears once in the local data area; corrupting
        // it must be caught by the CRC check, not written.
        let pos = z
            .windows(b"payload".len())
            .position(|w| w == b"payload")
            .unwrap();
        z[pos] ^= 0xff;
        let d = tmp();
        let e = extract_archive(&z, ArchiveFormat::Zip, &d, &ExtractionLimits::default());
        assert!(e.is_err());
        assert!(format!("{}", e.unwrap_err()).contains("CRC"));
        assert!(!d.join("file.txt").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn zip_rejects_multi_disk_and_zip64_markers() {
        let mut z = zip_with(&[("f", b"x", false, 0o100644)]);
        let eocd = z.len() - 22;
        z[eocd + 4] = 1; // disk number
        let d = tmp();
        assert!(extract_archive(&z, ArchiveFormat::Zip, &d, &ExtractionLimits::default()).is_err());

        let mut z = zip_with(&[("f", b"x", false, 0o100644)]);
        let eocd = z.len() - 22;
        z[eocd + 10..eocd + 12].copy_from_slice(&0xffffu16.to_le_bytes());
        assert!(extract_archive(&z, ArchiveFormat::Zip, &d, &ExtractionLimits::default()).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    // --- zstd ---------------------------------------------------------------

    #[test]
    fn extracts_tar_zst() {
        let t = tar_with(&[("hello.txt", b'0', b"hello zstd")]);
        let z = zstd::stream::encode_all(t.as_slice(), 3).unwrap();
        let d = tmp();
        let r =
            extract_archive(&z, ArchiveFormat::TarZst, &d, &ExtractionLimits::default()).unwrap();
        assert_eq!(r.entries, 1);
        assert_eq!(
            std::fs::read_to_string(d.join("hello.txt")).unwrap(),
            "hello zstd"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn zstd_expansion_is_bounded() {
        let t = tar_with(&[("big", b'0', &vec![b'a'; 4096])]);
        let z = zstd::stream::encode_all(t.as_slice(), 3).unwrap();
        let d = tmp();
        let limits = ExtractionLimits {
            max_total_bytes: 1024,
            ..Default::default()
        };
        assert!(extract_archive(&z, ArchiveFormat::TarZst, &d, &limits).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    // --- happy path ---------------------------------------------------------

    #[test]
    fn extracts_valid_archive() {
        let t = tar_with(&[
            ("bin/tool", b'0', b"#!/bin/sh\necho hi\n"),
            ("LICENSE", b'0', b"MIT"),
        ]);
        let d = tmp();
        let r = extract_archive(&t, ArchiveFormat::Tar, &d, &ExtractionLimits::default()).unwrap();
        assert_eq!(r.entries, 2);
        assert!(d.join("bin/tool").exists());
        assert!(d.join("LICENSE").exists());
        assert_eq!(std::fs::read_to_string(d.join("LICENSE")).unwrap(), "MIT");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn nothing_written_when_any_entry_invalid() {
        // A valid entry followed by a traversal entry: the whole extraction
        // must be refused and no file left behind.
        let t = tar_with(&[("good.txt", b'0', b"ok"), ("../evil.txt", b'0', b"bad")]);
        let d = tmp();
        assert!(extract_archive(&t, ArchiveFormat::Tar, &d, &ExtractionLimits::default()).is_err());
        assert!(
            !d.join("good.txt").exists(),
            "no partial extraction is permitted"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn sniff_detects_formats() {
        assert_eq!(sniff_format(b"\x1f\x8b\x08\x00"), ArchiveFormat::TarGz);
        assert_eq!(sniff_format(b"PK\x03\x04"), ArchiveFormat::Zip);
        assert_eq!(sniff_format(b"random bytes here"), ArchiveFormat::Raw);
    }

    #[test]
    fn format_from_filename() {
        assert_eq!(
            ArchiveFormat::from_filename("x.tar.gz"),
            ArchiveFormat::TarGz
        );
        assert_eq!(ArchiveFormat::from_filename("x.tgz"), ArchiveFormat::TarGz);
        assert_eq!(ArchiveFormat::from_filename("x.tar"), ArchiveFormat::Tar);
        assert_eq!(ArchiveFormat::from_filename("x.zip"), ArchiveFormat::Zip);
        assert_eq!(ArchiveFormat::from_filename("x.bin"), ArchiveFormat::Raw);
        assert_eq!(
            ArchiveFormat::from_filename("x.TAR.GZ"),
            ArchiveFormat::TarGz
        );
    }

    // --- inflate ------------------------------------------------------------

    #[test]
    fn inflate_stored_block_roundtrip() {
        // 0x01 (final, stored) + len + ~len + data
        let payload = b"hello world";
        let mut z = vec![0x01u8];
        z.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        z.extend_from_slice(&(!(payload.len() as u16)).to_le_bytes());
        z.extend_from_slice(payload);
        let out = inflate(&z, &ExtractionLimits::default()).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn inflate_respects_output_limit() {
        let payload = vec![b'a'; 4096];
        let mut z = vec![0x01u8];
        z.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        z.extend_from_slice(&(!(payload.len() as u16)).to_le_bytes());
        z.extend_from_slice(&payload);
        let limits = ExtractionLimits {
            max_total_bytes: 100,
            ..Default::default()
        };
        assert!(inflate(&z, &limits).is_err());
    }

    #[test]
    fn inflate_rejects_stored_length_mismatch() {
        let mut z = vec![0x01u8];
        z.extend_from_slice(&10u16.to_le_bytes());
        z.extend_from_slice(&999u16.to_le_bytes());
        z.extend_from_slice(b"0123456789");
        assert!(inflate(&z, &ExtractionLimits::default()).is_err());
    }

    #[test]
    fn inflate_rejects_truncation() {
        assert!(inflate(&[0x01], &ExtractionLimits::default()).is_err());
        assert!(inflate(&[], &ExtractionLimits::default()).is_err());
    }
}

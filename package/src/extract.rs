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
    /// Zip. Not implemented in Phase 2.
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
        ArchiveFormat::TarZst => Err(ZenError::new(
            Area::Sec,
            6131,
            "zstd extraction is not implemented in this build",
        )
        .with_remediation("Use a .tar.gz or .tar artifact.")),
        ArchiveFormat::Zip => Err(ZenError::new(
            Area::Sec,
            6132,
            "zip extraction is not implemented in this build",
        )
        .with_remediation("Use a .tar.gz or .tar artifact.")),
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
    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        ArchiveFormat::TarGz
    } else if bytes.len() >= 4 && &bytes[0..4] == b"PK\x03\x04" {
        ArchiveFormat::Zip
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
    fn zip_and_zstd_are_refused_not_silently_accepted() {
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

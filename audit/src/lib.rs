//! z-audit — local, hash-chained and optionally Ed25519-signed audit log
//! (25-AUDIT, Phase 1 §19).
//!
//! Append-only events with a SHA-256 hash chain so tampering is detectable
//! via `z audit verify`. When a signing key exists next to the log (created by
//! `z audit key`), every new event is also signed with Ed25519; the signature
//! covers the event's chain hash and is itself excluded from the chain, so
//! old unsigned logs still verify. Secrets are never recorded: the event
//! schema deliberately carries only handles/scopes, never values.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use z_core::error::{Area, ZenError, ZenResult};
use z_identity::signing::{verify as verify_signature, SigningKey};

/// Domain separation for audit signatures, so a signature made for another
/// purpose can never be replayed as an audit signature.
const SIGNATURE_DOMAIN: &str = "zentrion-audit-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: String,
    pub ts: DateTime<Utc>,
    pub actor: String,
    pub actor_type: String,
    pub action: String,
    pub resource: String,
    pub project: Option<String>,
    pub decision: String,
    pub result: String,
    pub risk: String,
    pub platform: String,
    pub prev_hash: String,
    pub hash: String,
    /// Ed25519 signature over `SIGNATURE_DOMAIN:hash`, when signing is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Public key that produced `signature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

/// Fields used to compute the chain hash (excludes `hash` itself).
fn compute_hash(prev_hash: &str, ev: &AuditEvent) -> String {
    let payload = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        prev_hash,
        ev.id,
        ev.ts.to_rfc3339(),
        ev.actor,
        ev.actor_type,
        ev.action,
        ev.resource,
        ev.project.clone().unwrap_or_default(),
        ev.decision,
        ev.result,
        ev.risk,
        ev.platform,
    );
    sha256_hex(payload.as_bytes())
}

pub struct AuditLog {
    path: PathBuf,
    last_hash: String,
    counter: u64,
    signer: Option<SigningKey>,
}

/// Directory that holds the audit signing key for a given log.
pub fn signing_key_dir(log_path: &Path) -> PathBuf {
    log_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("audit-keys")
}

/// Path of the Ed25519 key that signs `log_path`, if it has been created.
pub fn signing_key_path(log_path: &Path) -> PathBuf {
    signing_key_dir(log_path).join("signing.key")
}

impl AuditLog {
    /// Open (or create) the audit log, recovering the last hash from disk.
    ///
    /// If a signing key exists at [`signing_key_path`], new events are signed.
    /// A key that exists but cannot be loaded is an error: silently falling
    /// back to unsigned events would be a security regression.
    pub fn open(path: &Path) -> ZenResult<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut last_hash = "genesis".to_string();
        let mut counter = 0u64;
        if path.exists() {
            if let Ok(events) = read_events(path) {
                if let Some(last) = events.last() {
                    last_hash = last.hash.clone();
                    counter = events.len() as u64;
                }
            }
        }
        let key_path = signing_key_path(path);
        let signer = if key_path.exists() {
            Some(SigningKey::load(&key_path)?)
        } else {
            None
        };
        Ok(Self {
            path: path.to_path_buf(),
            last_hash,
            counter,
            signer,
        })
    }

    /// Restrict the audit file to the current user (Unix).
    fn secure_permissions(&self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600));
        }
    }

    /// Append an event, chaining it to the previous hash.
    ///
    /// The wide signature mirrors the audit event schema (25-AUDIT); callers
    /// pass the fields explicitly so a value can never be "forgotten" back
    /// into a permissive default.
    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &mut self,
        actor: &str,
        actor_type: &str,
        action: &str,
        resource: &str,
        project: Option<&str>,
        decision: &str,
        result: &str,
        risk: &str,
        platform: &str,
    ) -> ZenResult<AuditEvent> {
        self.counter += 1;
        let mut ev = AuditEvent {
            id: format!("ev_{:08x}", self.counter),
            ts: Utc::now(),
            actor: actor.to_string(),
            actor_type: actor_type.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            project: project.map(|s| s.to_string()),
            decision: decision.to_string(),
            result: result.to_string(),
            risk: risk.to_string(),
            platform: platform.to_string(),
            prev_hash: self.last_hash.clone(),
            hash: String::new(),
            signature: None,
            signer: None,
        };
        ev.hash = compute_hash(&self.last_hash, &ev);
        if let Some(signer) = &self.signer {
            let payload = signature_payload(&ev.hash);
            ev.signature = Some(signer.sign_hex(payload.as_bytes()));
            ev.signer = Some(signer.public_key_hex());
        }
        self.last_hash = ev.hash.clone();
        self.secure_permissions();

        let line = serde_json::to_string(&ev)?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{line}")?;
        f.sync_all().ok();
        self.secure_permissions();
        Ok(ev)
    }

    pub fn tail(&self, n: usize) -> ZenResult<Vec<AuditEvent>> {
        let all = read_events(&self.path)?;
        let start = all.len().saturating_sub(n);
        Ok(all[start..].to_vec())
    }
}

pub fn read_events(path: &Path) -> ZenResult<Vec<AuditEvent>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let text = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let ev: AuditEvent = serde_json::from_str(line).map_err(|e| {
            ZenError::new(Area::Aud, 3010, format!("corrupt audit line: {e}"))
                .with_remediation("The audit log may be truncated; restore from backup.")
        })?;
        out.push(ev);
    }
    Ok(out)
}

/// Verify the hash chain. Returns the index of the first broken link, if any.
pub fn verify(path: &Path) -> ZenResult<Result<usize, usize>> {
    let events = read_events(path)?;
    let mut prev = "genesis".to_string();
    for (i, ev) in events.iter().enumerate() {
        if ev.prev_hash != prev {
            return Ok(Err(i));
        }
        let expect = compute_hash(&prev, ev);
        if expect != ev.hash {
            return Ok(Err(i));
        }
        prev = ev.hash.clone();
    }
    Ok(Ok(events.len()))
}

fn signature_payload(hash: &str) -> String {
    format!("{SIGNATURE_DOMAIN}:{hash}")
}

/// Result of checking event signatures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureReport {
    pub total: usize,
    pub signed: usize,
    pub unsigned: usize,
    pub valid: bool,
    /// Index of the first event whose signature did not verify.
    pub first_invalid: Option<usize>,
    /// Public key the log was checked against, if one was available.
    pub public_key: Option<String>,
    /// True when signed events exist but the key file is missing.
    pub key_missing: bool,
}

/// Verify Ed25519 signatures on a log whose key lives at [`signing_key_path`].
///
/// Returns `None` when the log has no signed events (a legacy log). Chain
/// verification is separate: call [`verify`] first.
pub fn verify_signatures(path: &Path) -> ZenResult<Option<SignatureReport>> {
    let events = read_events(path)?;
    let total = events.len();
    let signed = events.iter().filter(|ev| ev.signature.is_some()).count();
    if signed == 0 {
        return Ok(None);
    }
    let key_path = signing_key_path(path);
    if !key_path.exists() {
        return Ok(Some(SignatureReport {
            total,
            signed,
            unsigned: total - signed,
            valid: false,
            first_invalid: None,
            public_key: None,
            key_missing: true,
        }));
    }
    let key = SigningKey::load(&key_path)?;
    let public_key = key.public_key_hex();
    let mut first_invalid = None;
    for (index, ev) in events.iter().enumerate() {
        let Some(signature) = ev.signature.as_deref() else {
            continue;
        };
        if ev.signer.as_deref() != Some(public_key.as_str()) {
            first_invalid = Some(index);
            break;
        }
        let payload = signature_payload(&ev.hash);
        if !verify_signature(&public_key, payload.as_bytes(), signature) {
            first_invalid = Some(index);
            break;
        }
    }
    Ok(Some(SignatureReport {
        total,
        signed,
        unsigned: total - signed,
        valid: first_invalid.is_none(),
        first_invalid,
        public_key: Some(public_key),
        key_missing: false,
    }))
}

// ---------------------------------------------------------------------------
// Minimal SHA-256 (FIPS 180-4). Used only for audit chain integrity.
// ---------------------------------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_log(name: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("zen-audit-{}-{}.jsonl", name, std::process::id()));
        let _ = fs::remove_file(&p);
        p
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn append_and_verify_chain() {
        let p = tmp_log("chain");
        let mut log = AuditLog::open(&p).unwrap();
        log.append(
            "usr_1",
            "user",
            "filesystem.read",
            "./a",
            Some("proj"),
            "allow",
            "ok",
            "LOW",
            "linux-x64",
        )
        .unwrap();
        log.append(
            "usr_1",
            "user",
            "filesystem.write",
            "./b",
            Some("proj"),
            "allow",
            "ok",
            "MEDIUM",
            "linux-x64",
        )
        .unwrap();
        let v = verify(&p).unwrap();
        assert_eq!(v, Ok(2));
        fs::remove_file(&p).unwrap();
    }

    #[test]
    fn tampering_detected() {
        let p = tmp_log("tamper");
        let mut log = AuditLog::open(&p).unwrap();
        log.append(
            "u",
            "user",
            "filesystem.read",
            "./a",
            None,
            "allow",
            "ok",
            "LOW",
            "linux-x64",
        )
        .unwrap();
        log.append(
            "u",
            "user",
            "filesystem.read",
            "./b",
            None,
            "allow",
            "ok",
            "LOW",
            "linux-x64",
        )
        .unwrap();
        // Tamper: rewrite the first line's resource field.
        let text = fs::read_to_string(&p).unwrap();
        let tampered = text.replacen("\"./a\"", "\"/etc/passwd\"", 1);
        fs::write(&p, tampered).unwrap();
        assert!(verify(&p).unwrap().is_err());
        fs::remove_file(&p).unwrap();
    }

    #[test]
    fn no_secret_values_in_events() {
        let p = tmp_log("nosecret");
        let mut log = AuditLog::open(&p).unwrap();
        // The API has no place to put a secret value; resource is a handle.
        let ev = log
            .append(
                "u",
                "user",
                "secret.read",
                "secret:db_password",
                None,
                "deny",
                "blocked",
                "CRITICAL",
                "linux-x64",
            )
            .unwrap();
        let serialized = serde_json::to_string(&ev).unwrap();
        assert!(serialized.contains("db_password")); // handle is fine
        assert!(!serialized.contains("password="));
        fs::remove_file(&p).unwrap();
    }

    #[test]
    fn persists_across_reopen() {
        let p = tmp_log("persist");
        {
            let mut log = AuditLog::open(&p).unwrap();
            log.append(
                "u",
                "user",
                "filesystem.read",
                "./a",
                None,
                "allow",
                "ok",
                "LOW",
                "linux-x64",
            )
            .unwrap();
        }
        let mut log2 = AuditLog::open(&p).unwrap();
        log2.append(
            "u",
            "user",
            "filesystem.read",
            "./b",
            None,
            "allow",
            "ok",
            "LOW",
            "linux-x64",
        )
        .unwrap();
        assert_eq!(verify(&p).unwrap(), Ok(2));
        fs::remove_file(&p).unwrap();
    }

    #[test]
    fn signed_events_verify_and_are_excluded_from_the_chain() {
        let dir = std::env::temp_dir().join(format!(
            "zen-audit-signed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("events.jsonl");
        let key = SigningKey::load_or_create(&signing_key_dir(&p)).unwrap();
        {
            let mut log = AuditLog::open(&p).unwrap();
            let ev = log
                .append(
                    "u",
                    "user",
                    "filesystem.read",
                    "./a",
                    None,
                    "allow",
                    "ok",
                    "LOW",
                    "linux-x64",
                )
                .unwrap();
            assert!(ev.signature.is_some());
            assert_eq!(ev.signer.as_deref(), Some(key.public_key_hex().as_str()));
            log.append(
                "u",
                "user",
                "filesystem.write",
                "./b",
                None,
                "deny",
                "blocked",
                "HIGH",
                "linux-x64",
            )
            .unwrap();
        }
        // The hash chain is computed without the signature field, so it still
        // verifies even though signatures are present.
        assert_eq!(verify(&p).unwrap(), Ok(2));
        let report = verify_signatures(&p).unwrap().unwrap();
        assert!(report.valid);
        assert_eq!(report.signed, 2);
        assert_eq!(report.total, 2);
        assert!(report.public_key.is_some());

        // Editing a signature must be detected.
        let text = fs::read_to_string(&p).unwrap();
        let tampered = text.replacen("\"signature\":\"", "\"signature\":\"00", 1);
        fs::write(&p, tampered).unwrap();
        let report = verify_signatures(&p).unwrap().unwrap();
        assert!(!report.valid);
        assert_eq!(report.first_invalid, Some(0));

        // Losing the key is reported, not treated as "unsigned, therefore ok".
        fs::remove_file(signing_key_path(&p)).unwrap();
        let report = verify_signatures(&p).unwrap().unwrap();
        assert!(report.key_missing);
        assert!(!report.valid);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unsigned_logs_report_no_signatures() {
        let p = tmp_log("unsigned");
        let mut log = AuditLog::open(&p).unwrap();
        log.append(
            "u",
            "user",
            "filesystem.read",
            "./a",
            None,
            "allow",
            "ok",
            "LOW",
            "linux-x64",
        )
        .unwrap();
        assert!(verify_signatures(&p).unwrap().is_none());
        fs::remove_file(&p).unwrap();
    }
}

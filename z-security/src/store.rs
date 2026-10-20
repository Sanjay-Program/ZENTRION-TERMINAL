//! Engagement store: scope-enforced command execution, tamper-evident evidence
//! and findings.
//!
//! Evidence is an append-only hash chain in JSONL; captured output lives in a
//! separate gzip file whose SHA-256 is recorded in the chain. Every record is
//! signed with the local Ed25519 key. Verification recomputes the chain,
//! signatures and output hashes.

use crate::model::{
    valid_id, Engagement, EngagementStatus, Evidence, Finding, FindingStatus, Signature,
    SECURITY_VERSION,
};
use crate::scope::{authorize, extract_targets, BreakGlass, ScopeDecision};
use chrono::Utc;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use uuid::Uuid;
use z_identity::signing::{verify, SigningKey};

pub const MAX_EVIDENCE_BYTES: usize = 50 * 1024 * 1024;
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone)]
pub struct SecurityStore {
    root: PathBuf,
    keys: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct EvidenceInput {
    pub kind: String,
    pub command: Option<String>,
    pub target: Option<String>,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub note: Option<String>,
    pub break_glass: Option<BreakGlass>,
}

#[derive(Debug)]
pub struct CommandOutcome {
    pub evidence: Evidence,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceVerification {
    pub engagement_id: String,
    pub valid: bool,
    pub records: usize,
    pub outputs_verified: usize,
    pub head_hash: Option<String>,
    pub trusted_signer: bool,
    pub errors: Vec<String>,
}

impl SecurityStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            keys: root.join("keys"),
            root,
        }
    }

    pub fn default_store() -> Option<Self> {
        z_core::config::user_data_dir().map(|dir| Self::new(dir.join("security")))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn ensure(&self) -> Result<(), String> {
        for dir in [
            self.root.clone(),
            self.root.join("engagements"),
            self.root.join("findings"),
            self.root.join("evidence"),
            self.root.join("reports"),
            self.root.join("locks"),
        ] {
            std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        Ok(())
    }

    pub(crate) fn signing_key(&self) -> Result<SigningKey, String> {
        self.ensure()?;
        SigningKey::load_or_create(&self.keys).map_err(|e| e.to_string())
    }

    pub fn public_key(&self) -> Result<String, String> {
        Ok(self.signing_key()?.public_key_hex())
    }

    fn engagement_path(&self, id: &str) -> Result<PathBuf, String> {
        if !valid_id(id) || !id.starts_with("eng_") {
            return Err(format!("invalid engagement id `{id}`"));
        }
        Ok(self.root.join("engagements").join(format!("{id}.json")))
    }

    pub fn create_engagement(&self, mut engagement: Engagement) -> Result<Engagement, String> {
        self.ensure()?;
        if engagement.id.is_empty() {
            engagement.id = format!("eng_{}", Uuid::new_v4().simple());
        }
        engagement.version = SECURITY_VERSION;
        engagement = engagement.checked()?;
        let path = self.engagement_path(&engagement.id)?;
        if path.exists() {
            return Err(format!("engagement `{}` already exists", engagement.id));
        }
        self.write_json(&path, &engagement)?;
        Ok(engagement)
    }

    pub fn save_engagement(&self, engagement: &Engagement) -> Result<(), String> {
        let engagement = engagement.clone().checked()?;
        self.ensure()?;
        self.write_json(&self.engagement_path(&engagement.id)?, &engagement)
    }

    pub fn load_engagement(&self, id: &str) -> Result<Engagement, String> {
        let path = self.engagement_path(id)?;
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read engagement {id}: {e}"))?;
        let engagement: Engagement =
            serde_json::from_str(&text).map_err(|e| format!("engagement {id} is corrupt: {e}"))?;
        engagement.checked()
    }

    pub fn list_engagements(&self) -> Vec<Engagement> {
        let mut engagements = Vec::new();
        let Ok(entries) = std::fs::read_dir(self.root.join("engagements")) else {
            return engagements;
        };
        for entry in entries.flatten() {
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            if let Ok(engagement) = serde_json::from_str::<Engagement>(&text) {
                if engagement.validate().is_empty() {
                    engagements.push(engagement);
                }
            }
        }
        engagements.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        engagements
    }

    /// Add a finding. The finding target must be in scope.
    pub fn add_finding(&self, mut finding: Finding) -> Result<Finding, String> {
        self.ensure()?;
        let engagement = self.load_engagement(&finding.engagement_id)?;
        let verdict = authorize(&engagement.scope, &finding.target, None);
        if verdict.decision == ScopeDecision::Denied {
            return Err(format!(
                "finding target `{}` is out of scope: {}",
                finding.target, verdict.reason
            ));
        }
        if finding.id.is_empty() {
            finding.id = format!("f_{}", Uuid::new_v4().simple());
        }
        if !valid_id(&finding.id) {
            return Err("invalid finding id".into());
        }
        finding.version = SECURITY_VERSION;
        if finding.created_at.timestamp() == 0 {
            finding.created_at = Utc::now();
        }
        finding.updated_at = Utc::now();
        if let Some(cvss) = finding.cvss {
            if finding.severity == crate::model::Severity::Info && cvss > 0.0 {
                finding.severity = crate::model::Severity::from_cvss(cvss);
            }
        }
        let issues = finding.validate();
        if !issues.is_empty() {
            return Err(issues.join("; "));
        }
        // Referenced evidence must exist in this engagement's chain.
        if !finding.evidence.is_empty() {
            let chain = self.read_chain(&finding.engagement_id)?;
            for id in &finding.evidence {
                if !chain.iter().any(|record| record.id == *id) {
                    return Err(format!("evidence `{id}` is not in this engagement"));
                }
            }
        }
        let dir = self.root.join("findings").join(&finding.engagement_id);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        self.write_json(&dir.join(format!("{}.json", finding.id)), &finding)?;
        Ok(finding)
    }

    pub fn list_findings(&self, engagement_id: &str) -> Vec<Finding> {
        let dir = self.root.join("findings").join(engagement_id);
        let mut findings = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return findings;
        };
        for entry in entries.flatten() {
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            if let Ok(finding) = serde_json::from_str::<Finding>(&text) {
                findings.push(finding);
            }
        }
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.title.cmp(&b.title))
                .then_with(|| a.id.cmp(&b.id))
        });
        findings
    }

    pub fn update_finding_status(
        &self,
        engagement_id: &str,
        finding_id: &str,
        status: FindingStatus,
    ) -> Result<Finding, String> {
        if !valid_id(finding_id) {
            return Err("invalid finding id".into());
        }
        let path = self
            .root
            .join("findings")
            .join(engagement_id)
            .join(format!("{finding_id}.json"));
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read finding {finding_id}: {e}"))?;
        let mut finding: Finding =
            serde_json::from_str(&text).map_err(|e| format!("finding is corrupt: {e}"))?;
        finding.status = status;
        finding.updated_at = Utc::now();
        self.write_json(&path, &finding)?;
        Ok(finding)
    }

    /// Record evidence without running a command (for example scanner output).
    pub fn record_evidence(
        &self,
        engagement_id: &str,
        input: EvidenceInput,
    ) -> Result<Evidence, String> {
        self.ensure()?;
        let engagement = self.load_engagement(engagement_id)?;
        let mut decision = "allow".to_string();
        if let Some(target) = &input.target {
            let verdict = authorize(&engagement.scope, target, input.break_glass.as_ref());
            match verdict.decision {
                ScopeDecision::Allowed => {}
                ScopeDecision::AllowedBreakGlass => {
                    decision = "break_glass".into();
                }
                ScopeDecision::Denied => {
                    self.append_denial(
                        &engagement,
                        input.command.as_deref(),
                        Some(target),
                        &verdict.reason,
                    )?;
                    return Err(format!(
                        "refusing to record evidence for out-of-scope target: {}",
                        verdict.reason
                    ));
                }
            }
        }
        let command = input.command.as_ref().map(|command| {
            let (redacted, _) = z_blocks::redact(command);
            redacted
        });
        let command_sha256 = input
            .command
            .as_ref()
            .map(|command| format!("sha256:{}", sha256_hex(command.as_bytes())));
        let mut output = input.stdout;
        if !input.stderr.is_empty() {
            output.extend_from_slice(b"\n--- stderr ---\n");
            output.extend_from_slice(&input.stderr);
        }
        let truncated = output.len() > MAX_EVIDENCE_BYTES;
        if truncated {
            output.truncate(MAX_EVIDENCE_BYTES);
        }
        let output_sha256 = Some(format!("sha256:{}", sha256_hex(&output)));
        let output_bytes = Some(output.len() as u64);
        let id = format!("ev_{}", Uuid::new_v4().simple());
        let output_file = if output.is_empty() {
            None
        } else {
            let relative = format!("evidence/{engagement_id}/outputs/{id}.gz");
            let path = self.root.join(&relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
            encoder.write_all(&output).map_err(|e| e.to_string())?;
            let compressed = encoder.finish().map_err(|e| e.to_string())?;
            let tmp = path.with_extension("gz.tmp");
            std::fs::write(&tmp, compressed).map_err(|e| e.to_string())?;
            secure_file(&tmp);
            std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
            Some(relative)
        };
        let note = match (input.note, truncated) {
            (Some(note), true) => Some(format!("{note} [output truncated]")),
            (Some(note), false) => Some(note),
            (None, true) => Some("[output truncated]".into()),
            (None, false) => None,
        };
        if let Some(glass) = &input.break_glass {
            if decision != "break_glass" {
                return Err("break-glass supplied but not needed for an in-scope target".into());
            }
            if !glass.valid_for(
                &crate::scope::Target::parse(input.target.as_deref().unwrap_or(""))
                    .map_err(|e| e)?,
            ) {
                return Err("break-glass does not cover this target".into());
            }
        }
        let record = Evidence {
            version: SECURITY_VERSION,
            id,
            engagement_id: engagement_id.to_string(),
            ts: Utc::now(),
            kind: if input.kind.trim().is_empty() {
                "manual".into()
            } else {
                input.kind
            },
            command,
            command_sha256,
            target: input.target,
            operator: operator(),
            host: hostname(),
            exit_code: input.exit_code,
            output_sha256,
            output_bytes,
            output_file,
            decision,
            note,
            prev_hash: String::new(),
            hash: String::new(),
            signature: None,
        };
        self.append_chain(&engagement, record)
    }

    /// Run a command only after scope authorization, then record evidence.
    pub fn run_command(
        &self,
        engagement_id: &str,
        command: &str,
        target: Option<&str>,
        break_glass: Option<&BreakGlass>,
        timeout: Duration,
        shell: Option<&str>,
    ) -> Result<CommandOutcome, String> {
        if command.trim().is_empty() {
            return Err("command must not be empty".into());
        }
        let engagement = self.load_engagement(engagement_id)?;
        if engagement.status != EngagementStatus::Active || !engagement.active() {
            return Err(format!(
                "engagement `{engagement_id}` is not active for the current date"
            ));
        }
        let targets: Vec<String> = match target {
            Some(target) => vec![target.to_string()],
            None => {
                let extracted = extract_targets(command);
                if extracted.is_empty() {
                    return Err(
                        "no target: pass --target (bare hostnames in commands are not guessed)"
                            .into(),
                    );
                }
                extracted
            }
        };
        for target in &targets {
            let verdict = authorize(&engagement.scope, target, break_glass);
            if !verdict.allowed() {
                self.append_denial(&engagement, Some(command), Some(target), &verdict.reason)?;
                return Err(format!(
                    "blocked before execution: target `{target}` is out of scope ({})",
                    verdict.reason
                ));
            }
        }
        let shell = shell
            .map(str::to_string)
            .or_else(|| std::env::var("SHELL").ok())
            .unwrap_or_else(|| {
                if cfg!(windows) {
                    "cmd.exe".into()
                } else {
                    "/bin/sh".into()
                }
            });
        let started = Instant::now();
        let outcome = run_shell(&shell, command, timeout);
        let mut note = format!("started by {} in {}", operator(), hostname());
        if outcome.timed_out {
            note.push_str(&format!("; killed after {:?}", started.elapsed()));
        }
        if let Some(error) = &outcome.error {
            note.push_str(&format!("; {error}"));
        }
        let evidence = self.record_evidence(
            engagement_id,
            EvidenceInput {
                kind: "command".into(),
                command: Some(command.to_string()),
                target: targets.first().cloned(),
                exit_code: outcome.exit_code,
                stdout: outcome.stdout.clone(),
                stderr: outcome.stderr.clone(),
                note: Some(note),
                break_glass: break_glass.cloned(),
            },
        )?;
        Ok(CommandOutcome {
            evidence,
            stdout: String::from_utf8_lossy(&outcome.stdout).to_string(),
            stderr: String::from_utf8_lossy(&outcome.stderr).to_string(),
            exit_code: outcome.exit_code,
            timed_out: outcome.timed_out,
        })
    }

    fn append_denial(
        &self,
        engagement: &Engagement,
        command: Option<&str>,
        target: Option<&str>,
        reason: &str,
    ) -> Result<(), String> {
        let record = Evidence {
            version: SECURITY_VERSION,
            id: format!("ev_{}", Uuid::new_v4().simple()),
            engagement_id: engagement.id.clone(),
            ts: Utc::now(),
            kind: "denied".into(),
            command: command.map(|command| z_blocks::redact(command).0),
            command_sha256: command
                .map(|command| format!("sha256:{}", sha256_hex(command.as_bytes()))),
            target: target.map(str::to_string),
            operator: operator(),
            host: hostname(),
            exit_code: None,
            output_sha256: None,
            output_bytes: None,
            output_file: None,
            decision: "deny".into(),
            note: Some(reason.to_string()),
            prev_hash: String::new(),
            hash: String::new(),
            signature: None,
        };
        self.append_chain(engagement, record).map(|_| ())
    }

    fn append_chain(
        &self,
        engagement: &Engagement,
        mut record: Evidence,
    ) -> Result<Evidence, String> {
        let _lock = StoreLock::acquire(&self.root.join("locks"), &engagement.id)?;
        let chain_path = self.chain_path(&engagement.id);
        if let Some(parent) = chain_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let previous = self
            .read_chain(&engagement.id)?
            .last()
            .map(|record| record.hash.clone())
            .unwrap_or_else(|| "genesis".to_string());
        record.prev_hash = previous.clone();
        let key = self.signing_key()?;
        let signable = record.signable_bytes();
        record.hash = chain_hash(&previous, &signable);
        record.signature = Some(Signature {
            algorithm: "ed25519".into(),
            public_key: key.public_key_hex(),
            signature: key.sign_hex(&signable),
        });
        let line = serde_json::to_string(&record)
            .map_err(|e| format!("cannot serialize evidence: {e}"))?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&chain_path)
            .map_err(|e| format!("{}: {e}", chain_path.display()))?;
        writeln!(file, "{line}").map_err(|e| e.to_string())?;
        file.sync_all().ok();
        secure_file(&chain_path);
        Ok(record)
    }

    fn chain_path(&self, engagement_id: &str) -> PathBuf {
        self.root
            .join("evidence")
            .join(engagement_id)
            .join("chain.jsonl")
    }

    pub fn read_chain(&self, engagement_id: &str) -> Result<Vec<Evidence>, String> {
        if !valid_id(engagement_id) {
            return Err("invalid engagement id".into());
        }
        let path = self.chain_path(engagement_id);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read evidence chain: {e}"))?;
        let mut records = Vec::new();
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let record: Evidence = serde_json::from_str(line)
                .map_err(|e| format!("evidence line {} is corrupt: {e}", index + 1))?;
            records.push(record);
        }
        Ok(records)
    }

    pub fn verify_evidence(&self, engagement_id: &str) -> EvidenceVerification {
        let mut result = EvidenceVerification {
            engagement_id: engagement_id.to_string(),
            valid: false,
            records: 0,
            outputs_verified: 0,
            head_hash: None,
            trusted_signer: true,
            errors: Vec::new(),
        };
        let records = match self.read_chain(engagement_id) {
            Ok(records) => records,
            Err(error) => {
                result.errors.push(error);
                return result;
            }
        };
        let local_key = self.signing_key().ok().map(|key| key.public_key_hex());
        let mut previous = "genesis".to_string();
        for (index, record) in records.iter().enumerate() {
            result.records += 1;
            let signable = record.signable_bytes();
            let expected = chain_hash(&previous, &signable);
            if record.prev_hash != previous {
                result
                    .errors
                    .push(format!("record {}: prev_hash mismatch", index + 1));
            }
            if record.hash != expected {
                result
                    .errors
                    .push(format!("record {}: hash mismatch", index + 1));
            }
            match &record.signature {
                Some(signature) => {
                    let valid = signature.algorithm == "ed25519"
                        && verify(&signature.public_key, &signable, &signature.signature);
                    if !valid {
                        result
                            .errors
                            .push(format!("record {}: signature invalid", index + 1));
                    }
                    if let Some(local) = &local_key {
                        if &signature.public_key != local {
                            result.trusted_signer = false;
                            result
                                .errors
                                .push(format!("record {}: signed by an unknown key", index + 1));
                        }
                    }
                }
                None => result
                    .errors
                    .push(format!("record {}: unsigned", index + 1)),
            }
            if let (Some(file), Some(hash)) = (&record.output_file, &record.output_sha256) {
                match std::fs::read(self.root.join(file)) {
                    Ok(compressed) => {
                        let mut decoder = GzDecoder::new(compressed.as_slice());
                        let mut bytes = Vec::new();
                        if decoder.read_to_end(&mut bytes).is_ok() {
                            let actual = format!("sha256:{}", sha256_hex(&bytes));
                            if &actual == hash {
                                result.outputs_verified += 1;
                            } else {
                                result.errors.push(format!(
                                    "record {}: captured output hash mismatch",
                                    index + 1
                                ));
                            }
                        } else {
                            result
                                .errors
                                .push(format!("record {}: output cannot be decoded", index + 1));
                        }
                    }
                    Err(_) => result
                        .errors
                        .push(format!("record {}: output file missing", index + 1)),
                }
            }
            previous = record.hash.clone();
        }
        result.head_hash = Some(previous);
        result.valid = result.errors.is_empty();
        result
    }

    pub fn read_output(&self, record: &Evidence) -> Option<Vec<u8>> {
        let file = record.output_file.as_ref()?;
        let compressed = std::fs::read(self.root.join(file)).ok()?;
        let mut decoder = GzDecoder::new(compressed.as_slice());
        let mut bytes = Vec::new();
        decoder.read_to_end(&mut bytes).ok()?;
        Some(bytes)
    }

    pub fn chain_head(&self, engagement_id: &str) -> Option<String> {
        self.read_chain(engagement_id)
            .ok()
            .and_then(|records| records.last().map(|record| record.hash.clone()))
    }

    fn write_json<T: Serialize>(&self, path: &Path, value: &T) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| e.to_string())?;
        secure_file(&tmp);
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
        Ok(())
    }
}

struct ProcOutcome {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: Option<i32>,
    timed_out: bool,
    error: Option<String>,
}

fn run_shell(shell: &str, command: &str, timeout: Duration) -> ProcOutcome {
    let mut builder = std::process::Command::new(shell);
    let name = Path::new(shell)
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or(shell)
        .to_ascii_lowercase();
    if name == "cmd" {
        builder.arg("/C").arg(command);
    } else {
        builder.arg("-c").arg(command);
    }
    builder
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        builder.process_group(0);
    }
    let mut child = match builder.spawn() {
        Ok(child) => child,
        Err(error) => {
            return ProcOutcome {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code: None,
                timed_out: false,
                error: Some(format!("cannot start `{shell}`: {error}")),
            }
        }
    };
    let stdout = child
        .stdout
        .take()
        .map(|reader| read_capped(reader, MAX_EVIDENCE_BYTES));
    let stderr = child
        .stderr
        .take()
        .map(|reader| read_capped(reader, MAX_EVIDENCE_BYTES));
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    #[cfg(unix)]
                    {
                        let pid = child.id() as i32;
                        unsafe {
                            libc::kill(-pid, libc::SIGKILL);
                        }
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(30));
            }
            Err(error) => {
                return ProcOutcome {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    exit_code: None,
                    timed_out: false,
                    error: Some(format!("cannot wait: {error}")),
                }
            }
        }
    };
    let stdout = stdout
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    let stderr = stderr
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    ProcOutcome {
        stdout,
        stderr,
        exit_code: status.and_then(|status| status.code()),
        timed_out,
        error: None,
    }
}

fn read_capped(
    mut reader: impl Read + Send + 'static,
    max: usize,
) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if buffer.len() < max {
                        let take = (max - buffer.len()).min(n);
                        buffer.extend_from_slice(&chunk[..take]);
                    }
                }
                Err(_) => break,
            }
        }
        buffer
    })
}

fn operator() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "local-user".into())
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "local-host".into())
}

fn chain_hash(previous: &str, signable: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(previous.as_bytes());
    hasher.update([0u8]);
    hasher.update(signable);
    format!("sha256:{}", hex(&hasher.finalize()))
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

fn secure_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

struct StoreLock {
    path: PathBuf,
}

impl StoreLock {
    fn acquire(lock_dir: &Path, name: &str) -> Result<Self, String> {
        std::fs::create_dir_all(lock_dir).map_err(|e| e.to_string())?;
        let path = lock_dir.join(format!("{name}.lock"));
        let deadline = Instant::now() + Duration::from_secs(10);
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
                    if Instant::now() >= deadline {
                        return Err("evidence store is locked by another process".into());
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(error) => return Err(format!("cannot lock evidence store: {error}")),
            }
        }
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn process_alive(pid: i32) -> bool {
    #[cfg(unix)]
    {
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
    use crate::model::{EngagementStatus, Finding, Severity};
    use crate::scope::{PortRange, Scope};

    fn temp_store(name: &str) -> (SecurityStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-security-{}-{}-{}",
            name,
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        (SecurityStore::new(&dir), dir)
    }

    fn engagement() -> Engagement {
        Engagement {
            version: SECURITY_VERSION,
            id: "eng_demo".into(),
            name: "Demo engagement".into(),
            client: "Acme".into(),
            authorization: "Signed statement of work dated 2026-10-01".into(),
            authorized_by: "security@acme.example".into(),
            start: Utc::now() - chrono::Duration::hours(1),
            end: Utc::now() + chrono::Duration::days(7),
            rules_of_engagement: vec!["No DoS testing".into()],
            scope: Scope {
                targets: vec!["example.com".into(), "127.0.0.1".into()],
                out_of_scope: vec!["admin.example.com".into()],
                ports: vec![PortRange { from: 1, to: 65535 }],
                tools: vec![],
            },
            created_by: "tester".into(),
            created_at: Utc::now(),
            status: EngagementStatus::Active,
            tags: vec![],
        }
    }

    fn store_with_engagement(name: &str) -> (SecurityStore, PathBuf) {
        let (store, dir) = temp_store(name);
        store.create_engagement(engagement()).unwrap();
        (store, dir)
    }

    #[test]
    fn create_list_and_scope_enforced_findings() {
        let (store, dir) = store_with_engagement("findings");
        assert_eq!(store.list_engagements().len(), 1);
        let finding = Finding {
            version: SECURITY_VERSION,
            id: String::new(),
            engagement_id: "eng_demo".into(),
            title: "SQL injection in login".into(),
            severity: Severity::High,
            cvss: Some(8.2),
            target: "example.com".into(),
            description: "The login form reflects input.".into(),
            remediation: "Parameterize queries.".into(),
            evidence: vec![],
            cwe: vec!["CWE-89".into()],
            mitre: vec!["T1190".into()],
            status: FindingStatus::Open,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            tags: vec![],
        };
        let saved = store.add_finding(finding).unwrap();
        assert_eq!(store.list_findings("eng_demo").len(), 1);
        assert!(saved.id.starts_with("f_"));
        let mut out_of_scope = saved.clone();
        out_of_scope.id.clear();
        out_of_scope.target = "admin.example.com".into();
        assert!(store.add_finding(out_of_scope).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_chain_verifies_and_detects_tampering() {
        let (store, dir) = store_with_engagement("evidence");
        let first = store
            .record_evidence(
                "eng_demo",
                EvidenceInput {
                    kind: "scan".into(),
                    command: Some("nmap -sV example.com".into()),
                    target: Some("example.com".into()),
                    exit_code: Some(0),
                    stdout: b"80/tcp open http\n".to_vec(),
                    ..Default::default()
                },
            )
            .unwrap();
        let second = store
            .record_evidence(
                "eng_demo",
                EvidenceInput {
                    kind: "note".into(),
                    note: Some("Reviewed output".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(second.prev_hash, first.hash);
        let verification = store.verify_evidence("eng_demo");
        assert!(verification.valid, "{:?}", verification.errors);
        assert!(verification.outputs_verified >= 1);
        assert_eq!(verification.records, 2);
        assert_eq!(store.read_output(&first).unwrap(), b"80/tcp open http\n");

        // Tamper with the first record's command.
        let chain = store.chain_path("eng_demo");
        let text = std::fs::read_to_string(&chain).unwrap();
        let tampered = text.replacen("nmap -sV example.com", "nmap -sV evil.example", 1);
        std::fs::write(&chain, tampered).unwrap();
        let verification = store.verify_evidence("eng_demo");
        assert!(!verification.valid);
        assert!(verification
            .errors
            .iter()
            .any(|e| e.contains("hash mismatch")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn out_of_scope_evidence_is_denied_and_recorded() {
        let (store, dir) = store_with_engagement("deny");
        let error = store
            .record_evidence(
                "eng_demo",
                EvidenceInput {
                    kind: "scan".into(),
                    target: Some("admin.example.com".into()),
                    ..Default::default()
                },
            )
            .unwrap_err();
        assert!(error.contains("out-of-scope"));
        let chain = store.read_chain("eng_demo").unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].kind, "denied");
        assert_eq!(chain[0].decision, "deny");
        let verification = store.verify_evidence("eng_demo");
        assert!(verification.valid);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn run_command_blocks_out_of_scope_before_execution() {
        let (store, dir) = store_with_engagement("runblock");
        let marker = dir.join("marker");
        let command = format!("touch {}", marker.display());
        let error = store
            .run_command(
                "eng_demo",
                &command,
                Some("evil.example"),
                None,
                Duration::from_secs(5),
                Some("/bin/sh"),
            )
            .unwrap_err();
        assert!(error.contains("blocked before execution"));
        assert!(!marker.exists());
        let chain = store.read_chain("eng_demo").unwrap();
        assert_eq!(chain.last().unwrap().kind, "denied");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn run_command_captures_evidence_for_in_scope_target() {
        let (store, dir) = store_with_engagement("runok");
        let outcome = store
            .run_command(
                "eng_demo",
                "echo hello-evidence",
                Some("example.com"),
                None,
                Duration::from_secs(5),
                Some("/bin/sh"),
            )
            .unwrap();
        assert_eq!(outcome.exit_code, Some(0));
        assert!(outcome.stdout.contains("hello-evidence"));
        let verification = store.verify_evidence("eng_demo");
        assert!(verification.valid);
        let chain = store.read_chain("eng_demo").unwrap();
        assert_eq!(chain.last().unwrap().kind, "command");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn break_glass_allows_one_target_and_is_audited() {
        let (store, dir) = store_with_engagement("glass");
        let glass = BreakGlass::new(
            "tester",
            "client asked us to check admin during the call",
            "admin.example.com",
            30,
        )
        .unwrap();
        let evidence = store
            .record_evidence(
                "eng_demo",
                EvidenceInput {
                    kind: "manual".into(),
                    target: Some("admin.example.com".into()),
                    break_glass: Some(glass),
                    note: Some("authorized override".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(evidence.decision, "break_glass");
        assert_eq!(store.verify_evidence("eng_demo").valid, true);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn engagement_ids_cannot_traverse_paths() {
        let (store, dir) = temp_store("ids");
        assert!(store.load_engagement("../etc/passwd").is_err());
        assert!(store
            .create_engagement(Engagement {
                id: "../evil".into(),
                ..engagement()
            })
            .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

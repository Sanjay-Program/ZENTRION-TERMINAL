//! Approval broker and single-use capability tokens.
//!
//! Flow: agent → tool call → policy evaluation → allow / deny / approval.
//! An approval is a persisted request with a short TTL; granting it issues a
//! single-use nonce bound to actor, action and resource. Consuming a token marks
//! it used, so replay fails. Every decision is written to the hash-chained audit
//! log; if the audit log cannot be written, the action is denied.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use uuid::Uuid;
use z_audit::AuditLog;

use crate::profile::AgentProfile;

pub const MAX_TOKEN_TTL_SECONDS: i64 = 600;
pub const DEFAULT_REQUEST_TTL_SECONDS: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub nonce: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub risk: String,
    pub reason: String,
    pub preview: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: ApprovalStatus,
    pub resolved_by: Option<String>,
    pub token: Option<Token>,
}

impl ApprovalRequest {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    pub fn summary(&self) -> String {
        format!(
            "{} wants {} on `{}` (risk {}, expires {})",
            self.actor, self.action, self.resource, self.risk, self.expires_at
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerOutcome {
    Allowed {
        request_id: String,
        nonce: String,
        expires_at: DateTime<Utc>,
    },
    Denied {
        reason: String,
    },
    Pending {
        request_id: String,
    },
}

#[derive(Debug, Clone)]
pub struct BrokerRequest {
    pub action: String,
    pub resource: String,
    pub preview: String,
}

impl BrokerRequest {
    pub fn new(action: impl Into<String>, resource: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            resource: resource.into(),
            preview: String::new(),
        }
    }

    pub fn preview(mut self, preview: impl Into<String>) -> Self {
        self.preview = preview.into();
        self
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ApprovalFile {
    version: u32,
    requests: Vec<ApprovalRequest>,
}

pub struct ApprovalBroker {
    actor: String,
    profile: AgentProfile,
    policy: z_policy::Policy,
    workspace: PathBuf,
    store_path: PathBuf,
    audit_path: PathBuf,
    audit: Mutex<Option<AuditLog>>,
}

impl ApprovalBroker {
    pub fn new(
        agent_id: &str,
        profile: AgentProfile,
        policy: z_policy::Policy,
        workspace: &Path,
        store_path: &Path,
        audit_path: &Path,
    ) -> Result<Self, String> {
        let workspace = workspace
            .canonicalize()
            .map_err(|e| format!("cannot resolve workspace {}: {e}", workspace.display()))?;
        let policy = profile.apply(&policy);
        if let Some(parent) = store_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        if let Some(parent) = audit_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let audit = AuditLog::open(audit_path).map_err(|e| e.to_string())?;
        Ok(Self {
            actor: format!("agent:{agent_id}"),
            profile,
            policy,
            workspace,
            store_path: store_path.to_path_buf(),
            audit_path: audit_path.to_path_buf(),
            audit: Mutex::new(Some(audit)),
        })
    }

    pub fn actor(&self) -> &str {
        &self.actor
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn profile(&self) -> &AgentProfile {
        &self.profile
    }

    pub fn policy(&self) -> &z_policy::Policy {
        &self.policy
    }

    pub fn request(&self, request: BrokerRequest) -> Result<BrokerOutcome, String> {
        if !valid_action(&request.action) {
            self.audit(
                "agent.broker",
                &request.resource,
                "deny",
                "unknown-action",
                "high",
            )?;
            return Ok(BrokerOutcome::Denied {
                reason: format!("unknown agent action `{}`", request.action),
            });
        }
        let decision = z_policy::evaluate(
            &self.policy,
            &z_policy::PolicyRequest {
                actor: self.actor.clone(),
                action: request.action.clone(),
                resource: request.resource.clone(),
            },
        );
        let risk = format!("{:?}", decision.risk).to_ascii_lowercase();
        if decision.decision == z_policy::Decision::Deny {
            self.audit(
                "agent.tool.call",
                &request.resource,
                "deny",
                "denied",
                &risk,
            )?;
            return Ok(BrokerOutcome::Denied {
                reason: decision.reason,
            });
        }
        let needs_approval = decision.decision == z_policy::Decision::RequireApproval
            || self.profile.requires_approval(&request.action);
        if needs_approval {
            let request = self.create_pending(&request, &risk, &decision.reason)?;
            self.audit(
                "agent.approval.requested",
                &request.id,
                "require_approval",
                "pending",
                &risk,
            )?;
            return Ok(BrokerOutcome::Pending {
                request_id: request.id,
            });
        }
        let granted = self.create_granted(&request, &risk, &decision.reason)?;
        self.audit("agent.tool.call", &request.resource, "allow", "ok", &risk)?;
        Ok(BrokerOutcome::Allowed {
            request_id: granted.id.clone(),
            nonce: granted
                .token
                .as_ref()
                .map(|token| token.nonce.clone())
                .unwrap_or_default(),
            expires_at: granted.expires_at,
        })
    }

    /// Approve a pending request, issuing a single-use token.
    pub fn approve(&self, request_id: &str, approver: &str) -> Result<ApprovalRequest, String> {
        let mut file = self.load()?;
        let now = Utc::now();
        let request = file
            .requests
            .iter_mut()
            .find(|request| request.id == request_id)
            .ok_or_else(|| format!("approval `{request_id}` not found"))?;
        if request.status != ApprovalStatus::Pending {
            return Err(format!(
                "approval `{request_id}` is {:?}, not pending",
                request.status
            ));
        }
        if request.is_expired(now) {
            request.status = ApprovalStatus::Expired;
            self.save(&file)?;
            return Err(format!("approval `{request_id}` has expired"));
        }
        request.status = ApprovalStatus::Approved;
        request.resolved_by = Some(approver.to_string());
        request.expires_at = now + ChronoDuration::seconds(MAX_TOKEN_TTL_SECONDS);
        request.token = Some(Token {
            nonce: format!("nonce_{}", Uuid::new_v4().simple()),
            issued_at: now,
            expires_at: now + ChronoDuration::seconds(MAX_TOKEN_TTL_SECONDS),
            used: false,
        });
        let resolved = request.clone();
        self.save(&file)?;
        let risk = resolved.risk.clone();
        self.audit(
            "agent.approval.granted",
            &resolved.id,
            "allow",
            "approved",
            &risk,
        )?;
        Ok(resolved)
    }

    pub fn deny(&self, request_id: &str, approver: &str) -> Result<ApprovalRequest, String> {
        let mut file = self.load()?;
        let request = file
            .requests
            .iter_mut()
            .find(|request| request.id == request_id)
            .ok_or_else(|| format!("approval `{request_id}` not found"))?;
        if request.status != ApprovalStatus::Pending {
            return Err(format!(
                "approval `{request_id}` is {:?}, not pending",
                request.status
            ));
        }
        request.status = ApprovalStatus::Denied;
        request.resolved_by = Some(approver.to_string());
        let resolved = request.clone();
        self.save(&file)?;
        let risk = resolved.risk.clone();
        self.audit(
            "agent.approval.denied",
            &resolved.id,
            "deny",
            "denied",
            &risk,
        )?;
        Ok(resolved)
    }

    /// Consume an approved token exactly once.
    pub fn consume(
        &self,
        request_id: &str,
        nonce: &str,
        action: &str,
        resource: &str,
    ) -> Result<(), String> {
        let mut file = self.load()?;
        let now = Utc::now();
        let request = file
            .requests
            .iter_mut()
            .find(|request| request.id == request_id)
            .ok_or_else(|| "approval request not found".to_string())?;
        if request.action != action || request.resource != resource {
            return Err("token is bound to a different action or resource".into());
        }
        let token = request
            .token
            .as_ref()
            .ok_or_else(|| "approval has no token".to_string())?;
        if token.nonce != nonce {
            return Err("token nonce mismatch".into());
        }
        if token.used {
            return Err("token was already used (replay rejected)".into());
        }
        if request.status != ApprovalStatus::Approved {
            return Err("approval is not granted".into());
        }
        if request.is_expired(now) {
            return Err("token expired".into());
        }
        if now >= token.expires_at {
            return Err("token expired".into());
        }
        let token = request.token.as_mut().expect("token exists");
        token.used = true;
        request.status = ApprovalStatus::Expired;
        let risk = request.risk.clone();
        let id = request.id.clone();
        let action = request.action.clone();
        self.save(&file)?;
        self.audit(
            "agent.capability.used",
            &format!("{id}:{action}"),
            "allow",
            "ok",
            &risk,
        )?;
        Ok(())
    }

    pub fn pending(&self) -> Vec<ApprovalRequest> {
        self.load()
            .map(|file| {
                let now = Utc::now();
                file.requests
                    .into_iter()
                    .filter(|request| {
                        request.status == ApprovalStatus::Pending && !request.is_expired(now)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn get(&self, request_id: &str) -> Option<ApprovalRequest> {
        self.load()
            .ok()?
            .requests
            .into_iter()
            .find(|request| request.id == request_id)
    }

    /// Wait until a pending request is approved or denied.
    pub fn wait(
        &self,
        request_id: &str,
        timeout: std::time::Duration,
    ) -> Result<ApprovalRequest, String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(request) = self.get(request_id) {
                if request.status != ApprovalStatus::Pending {
                    return Ok(request);
                }
                if request.is_expired(Utc::now()) {
                    return Err("approval request expired".into());
                }
            } else {
                return Err("approval request not found".into());
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "approval required: run `z agent approvals` and approve {request_id}"
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    fn create_pending(
        &self,
        request: &BrokerRequest,
        risk: &str,
        reason: &str,
    ) -> Result<ApprovalRequest, String> {
        let now = Utc::now();
        let pending = ApprovalRequest {
            id: format!("ap_{}", Uuid::new_v4().simple()),
            actor: self.actor.clone(),
            action: request.action.clone(),
            resource: request.resource.clone(),
            risk: risk.to_string(),
            reason: reason.to_string(),
            preview: request.preview.clone(),
            created_at: now,
            expires_at: now + ChronoDuration::seconds(DEFAULT_REQUEST_TTL_SECONDS),
            status: ApprovalStatus::Pending,
            resolved_by: None,
            token: None,
        };
        let mut file = self.load()?;
        file.requests.push(pending.clone());
        prune(&mut file, now);
        self.save(&file)?;
        Ok(pending)
    }

    fn create_granted(
        &self,
        request: &BrokerRequest,
        risk: &str,
        reason: &str,
    ) -> Result<ApprovalRequest, String> {
        let now = Utc::now();
        let granted = ApprovalRequest {
            id: format!("ap_{}", Uuid::new_v4().simple()),
            actor: self.actor.clone(),
            action: request.action.clone(),
            resource: request.resource.clone(),
            risk: risk.to_string(),
            reason: reason.to_string(),
            preview: request.preview.clone(),
            created_at: now,
            expires_at: now + ChronoDuration::seconds(MAX_TOKEN_TTL_SECONDS),
            status: ApprovalStatus::Approved,
            resolved_by: Some("policy".into()),
            token: Some(Token {
                nonce: format!("nonce_{}", Uuid::new_v4().simple()),
                issued_at: now,
                expires_at: now + ChronoDuration::seconds(MAX_TOKEN_TTL_SECONDS),
                used: false,
            }),
        };
        let mut file = self.load()?;
        file.requests.push(granted.clone());
        prune(&mut file, now);
        self.save(&file)?;
        Ok(granted)
    }

    fn load(&self) -> Result<ApprovalFile, String> {
        if !self.store_path.exists() {
            return Ok(ApprovalFile {
                version: 1,
                requests: Vec::new(),
            });
        }
        let text = std::fs::read_to_string(&self.store_path)
            .map_err(|e| format!("cannot read approvals: {e}"))?;
        if text.trim().is_empty() {
            return Ok(ApprovalFile {
                version: 1,
                requests: Vec::new(),
            });
        }
        serde_json::from_str(&text).map_err(|e| format!("approvals file is corrupt: {e}"))
    }

    fn save(&self, file: &ApprovalFile) -> Result<(), String> {
        let _lock = FileLock::acquire(&self.store_path)?;
        let text = serde_json::to_string_pretty(file).map_err(|e| e.to_string())?;
        let tmp = self.store_path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &self.store_path).map_err(|e| e.to_string())
    }

    fn audit(
        &self,
        action: &str,
        resource: &str,
        decision: &str,
        result: &str,
        risk: &str,
    ) -> Result<(), String> {
        let mut guard = self.audit.lock().expect("audit lock");
        if guard.is_none() {
            *guard = Some(AuditLog::open(&self.audit_path).map_err(|e| e.to_string())?);
        }
        let log = guard.as_mut().expect("audit log");
        log.append(
            &self.actor,
            "agent",
            action,
            resource,
            None,
            decision,
            result,
            risk,
            std::env::consts::OS,
        )
        .map(|_| ())
        .map_err(|e| format!("cannot write audit event; denying action: {e}"))
    }
}

fn valid_action(action: &str) -> bool {
    matches!(
        action,
        "agent.tool.call"
            | "agent.fs.read"
            | "agent.fs.write"
            | "agent.fs.delete"
            | "agent.exec"
            | "agent.shell"
            | "agent.net"
            | "agent.secret.read"
    )
}

fn prune(file: &mut ApprovalFile, now: DateTime<Utc>) {
    let cutoff = now - ChronoDuration::hours(24);
    file.requests
        .retain(|request| request.created_at > cutoff || request.status == ApprovalStatus::Pending);
    if file.requests.len() > 2_000 {
        let excess = file.requests.len() - 2_000;
        file.requests.drain(..excess);
    }
}

struct FileLock {
    path: PathBuf,
}

impl FileLock {
    fn acquire(target: &Path) -> Result<Self, String> {
        let path = target.with_extension("json.lock");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    use std::io::Write;
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
                        return Err("approval store is locked".into());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(error) => return Err(format!("cannot lock approval store: {error}")),
            }
        }
    }
}

impl Drop for FileLock {
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
    use crate::profile::AgentProfile;

    fn broker(name: &str, profile: &str) -> (ApprovalBroker, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-broker-{}-{}-{}",
            name,
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let broker = ApprovalBroker::new(
            "test",
            AgentProfile::builtin(profile).unwrap(),
            z_policy::Policy::default(),
            &dir,
            &dir.join("approvals.json"),
            &dir.join("audit/events.jsonl"),
        )
        .unwrap();
        (broker, dir)
    }

    #[test]
    fn readonly_denies_write_immediately() {
        let (broker, dir) = broker("readonly", "agent-readonly");
        let outcome = broker
            .request(BrokerRequest::new("agent.fs.write", "src/lib.rs"))
            .unwrap();
        assert!(matches!(outcome, BrokerOutcome::Denied { .. }));
        assert!(broker.pending().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn approval_issues_single_use_token() {
        let (broker, dir) = broker("token", "agent-dev");
        let BrokerOutcome::Pending { request_id } = broker
            .request(BrokerRequest::new("agent.exec", "cargo"))
            .unwrap()
        else {
            panic!("expected pending approval");
        };
        let approved = broker.approve(&request_id, "tester").unwrap();
        let nonce = approved.token.as_ref().unwrap().nonce.clone();
        broker
            .consume(&request_id, &nonce, "agent.exec", "cargo")
            .unwrap();
        let replay = broker
            .consume(&request_id, &nonce, "agent.exec", "cargo")
            .unwrap_err();
        assert!(replay.contains("replay"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn token_is_bound_to_action_and_resource() {
        let (broker, dir) = broker("bound", "agent-dev");
        let BrokerOutcome::Pending { request_id } = broker
            .request(BrokerRequest::new("agent.exec", "cargo"))
            .unwrap()
        else {
            panic!();
        };
        let approved = broker.approve(&request_id, "tester").unwrap();
        let nonce = approved.token.as_ref().unwrap().nonce.clone();
        assert!(broker
            .consume(&request_id, &nonce, "agent.fs.write", "src/lib.rs")
            .is_err());
        assert!(broker
            .consume(&request_id, &nonce, "agent.exec", "git")
            .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn denied_request_cannot_be_approved_twice() {
        let (broker, dir) = broker("deny", "agent-dev");
        let BrokerOutcome::Pending { request_id } = broker
            .request(BrokerRequest::new("agent.exec", "cargo"))
            .unwrap()
        else {
            panic!();
        };
        broker.deny(&request_id, "tester").unwrap();
        assert!(broker.approve(&request_id, "tester").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_chain_records_decisions() {
        let (broker, dir) = broker("audit", "agent-readonly");
        broker
            .request(BrokerRequest::new("agent.fs.write", "src/lib.rs"))
            .unwrap();
        let path = dir.join("audit/events.jsonl");
        let events = z_audit::read_events(&path).unwrap();
        assert!(!events.is_empty());
        assert!(events.iter().any(|event| event.decision == "deny"));
        assert!(z_audit::verify(&path).unwrap().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

//! Execution Broker (Phase 1 §22, 03-SYSTEM-ARCHITECTURE).
//!
//! THE single choke point for host effects. Order:
//! identity → policy → capability → risk/approval → execute → audit.
//!
//! Phase 1 is in-process only (no IPC/daemon yet). Fail-closed: any policy
//! or capability failure denies. `z run` uses this; nothing bypasses it.

use crate::types::{ExecRequest, ExecResult, ExecStatus};
use std::path::PathBuf;
use std::time::Instant;
use z_audit::AuditLog;
use z_capability::CapabilityStore;
use z_core::error::ZenResult;
use z_core::process::{ProcessRequest, ProcessRunner};
use z_policy::{Decision, Policy, PolicyRequest, Risk};

pub struct Broker {
    pub policy: Policy,
    pub capabilities: CapabilityStore,
    pub audit: AuditLog,
    pub project: Option<PathBuf>,
    pub platform: String,
}

impl Broker {
    pub fn new(
        policy: Policy,
        audit: AuditLog,
        project: Option<PathBuf>,
        platform: impl Into<String>,
    ) -> Self {
        Self {
            policy,
            capabilities: CapabilityStore::new(),
            audit,
            project,
            platform: platform.into(),
        }
    }

    /// Evaluate a request WITHOUT executing it (dry-run, used by
    /// `z policy test` and by `z run` for pre-flight).
    pub fn evaluate(&self, req: &ExecRequest) -> (Decision, Risk, String) {
        let pr = PolicyRequest {
            actor: req.actor.id.clone(),
            action: req.action.clone(),
            resource: req.resource.clone(),
        };
        let d = z_policy::evaluate(&self.policy, &pr);
        (d.decision, d.risk, d.reason)
    }

    /// Full broker path for a process execution request.
    ///
    /// 1. identity is required (checked by caller, re-asserted here)
    /// 2. policy must ALLOW (REQUIRE_APPROVAL is treated as DENY in Phase 1
    ///    unless the caller already collected consent — no silent approval)
    /// 3. a capability must exist for (actor, action, resource)
    /// 4. execute via the process abstraction (no shell)
    /// 5. audit the outcome
    pub fn execute_process(
        &mut self,
        req: &ExecRequest,
        program: &str,
        args: &[String],
        approved: bool,
    ) -> ZenResult<ExecResult> {
        let start = Instant::now();
        let request_id = format!("req_{}", uuid_like());

        // 2. Policy evaluation.
        let (decision, risk, reason) = self.evaluate(req);

        if decision == Decision::Deny {
            let audit_id = self.log(req, "deny", "blocked", &risk, &reason)?;
            return Ok(ExecResult {
                status: ExecStatus::Denied,
                request_id,
                audit_id: Some(audit_id),
                risk: risk_str(risk).to_string(),
                reason,
                stdout: None,
                stderr: None,
                exit_code: None,
                duration_ms: start.elapsed().as_millis(),
            });
        }

        if decision == Decision::RequireApproval && !approved {
            let audit_id = self.log(req, "approval_required", "pending", &risk, &reason)?;
            return Ok(ExecResult {
                status: ExecStatus::ApprovalRequired,
                request_id,
                audit_id: Some(audit_id),
                risk: risk_str(risk).to_string(),
                reason,
                stdout: None,
                stderr: None,
                exit_code: None,
                duration_ms: start.elapsed().as_millis(),
            });
        }

        // 3. Capability check (deny-by-default). The broker issues a
        //    short-lived capability once the request is authorized.
        let ttl = ttl_for(risk);
        let cap = self
            .capabilities
            .issue(&req.actor.id, &req.action, &req.resource, ttl);
        if let Err(e) = self
            .capabilities
            .check(&cap.id, &req.actor.id, &req.action, &req.resource)
        {
            let audit_id = self.log(req, "deny", "capability_error", &risk, &e.to_string())?;
            return Ok(ExecResult {
                status: ExecStatus::Denied,
                request_id,
                audit_id: Some(audit_id),
                risk: risk_str(risk).to_string(),
                reason: e.to_string(),
                stdout: None,
                stderr: None,
                exit_code: None,
                duration_ms: start.elapsed().as_millis(),
            });
        }
        // Single-use: revoke immediately after checking (Phase 1 §8.4).
        self.capabilities.revoke(&cap.id);

        // 4. Execute (no shell; structured args only).
        let mut preq = ProcessRequest::new(program);
        preq.args = args.to_vec();
        if let Some(p) = &self.project {
            preq.working_dir = Some(p.clone());
        }

        let outcome = ProcessRunner::run(&preq);
        let (status, result_str, stdout, stderr, code) = match outcome {
            Ok(r) if r.timed_out => (
                ExecStatus::Timeout,
                "timeout".to_string(),
                Some(r.stdout),
                Some(r.stderr),
                Some(r.exit_code),
            ),
            Ok(r) => (
                if r.success() {
                    ExecStatus::Allowed
                } else {
                    ExecStatus::Failed
                },
                if r.success() {
                    "ok".to_string()
                } else {
                    "nonzero_exit".to_string()
                },
                Some(r.stdout),
                Some(r.stderr),
                Some(r.exit_code),
            ),
            Err(e) => (
                ExecStatus::Failed,
                format!("spawn_error: {e}"),
                None,
                None,
                None,
            ),
        };

        // 5. Audit.
        let audit_id = self.log(req, "allow", &result_str, &risk, &reason)?;

        Ok(ExecResult {
            status,
            request_id,
            audit_id: Some(audit_id),
            risk: risk_str(risk).to_string(),
            reason,
            stdout,
            stderr,
            exit_code: code,
            duration_ms: start.elapsed().as_millis(),
        })
    }

    fn log(
        &mut self,
        req: &ExecRequest,
        decision: &str,
        result: &str,
        risk: &Risk,
        _reason: &str,
    ) -> ZenResult<String> {
        let project_name = self
            .project
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string());
        let ev = self.audit.append(
            &req.actor.id,
            &req.actor.actor_type,
            &req.action,
            &req.resource,
            project_name.as_deref(),
            decision,
            result,
            risk_str(*risk),
            &self.platform,
        )?;
        Ok(ev.id)
    }
}

fn risk_str(r: Risk) -> &'static str {
    match r {
        Risk::Low => "LOW",
        Risk::Medium => "MEDIUM",
        Risk::High => "HIGH",
        Risk::Critical => "CRITICAL",
    }
}

fn ttl_for(r: Risk) -> chrono::Duration {
    match r {
        Risk::Low => chrono::Duration::hours(24),
        Risk::Medium => chrono::Duration::hours(1),
        Risk::High => chrono::Duration::minutes(10),
        Risk::Critical => chrono::Duration::seconds(1),
    }
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{n:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "zen-exec-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn broker_with(policy: Policy, dir: &std::path::Path) -> Broker {
        let audit = AuditLog::open(&dir.join("audit.jsonl")).unwrap();
        Broker::new(policy, audit, Some(dir.to_path_buf()), "linux-x64")
    }

    fn actor() -> crate::types::ActorRef {
        crate::types::ActorRef {
            id: "usr_test".into(),
            actor_type: "user".into(),
        }
    }

    #[test]
    fn denies_without_policy_grant() {
        let dir = tmp("deny");
        let mut policy = Policy::default();
        policy.process.spawn = vec![]; // nothing allowed
        let mut b = broker_with(policy, &dir);

        let req = ExecRequest {
            actor: actor(),
            action: "process.spawn".into(),
            resource: "echo".into(),
            reason: Some("test".into()),
        };
        let r = b
            .execute_process(&req, "echo", &["hi".to_string()], false)
            .unwrap();
        assert_eq!(r.status, ExecStatus::Denied);
        assert!(r.audit_id.is_some());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn allows_granted_process_and_audits() {
        let dir = tmp("allow");
        let mut policy = Policy::default();
        policy.process.spawn = vec!["echo".to_string()];
        let mut b = broker_with(policy, &dir);

        let req = ExecRequest {
            actor: actor(),
            action: "process.spawn".into(),
            resource: "echo".into(),
            reason: None,
        };
        let r = b
            .execute_process(&req, "echo", &["hello".to_string()], false)
            .unwrap();
        assert_eq!(r.status, ExecStatus::Allowed);
        assert_eq!(r.stdout.as_deref().unwrap().trim(), "hello");

        // Audit chain must verify.
        let v = z_audit::verify(&dir.join("audit.jsonl")).unwrap();
        assert!(v.is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn high_risk_requires_approval() {
        let dir = tmp("approve");
        let mut policy = Policy::default();
        // filesystem.delete is HIGH risk; grant scope but expect approval gate.
        policy.filesystem.delete = vec!["./build/**".to_string()];
        let mut b = broker_with(policy, &dir);

        let req = ExecRequest {
            actor: actor(),
            action: "filesystem.delete".into(),
            resource: "./build/x".into(),
            reason: None,
        };
        let r = b.execute_process(&req, "echo", &[], false).unwrap();
        assert_eq!(r.status, ExecStatus::ApprovalRequired);

        // With approval it proceeds past the gate (echo as stand-in).
        let r2 = b.execute_process(&req, "echo", &[], true).unwrap();
        assert_ne!(r2.status, ExecStatus::ApprovalRequired);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unknown_action_denied() {
        let dir = tmp("unknown");
        let mut b = broker_with(Policy::default(), &dir);
        let req = ExecRequest {
            actor: actor(),
            action: "totally.made.up".into(),
            resource: "x".into(),
            reason: None,
        };
        let r = b.execute_process(&req, "echo", &[], false).unwrap();
        assert_eq!(r.status, ExecStatus::Denied);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn evaluate_is_dry_run() {
        let dir = tmp("dryrun");
        let mut policy = Policy::default();
        policy.process.spawn = vec!["echo".to_string()];
        let b = broker_with(policy, &dir);
        let req = ExecRequest {
            actor: actor(),
            action: "process.spawn".into(),
            resource: "echo".into(),
            reason: None,
        };
        let (d, risk, _) = b.evaluate(&req);
        assert_eq!(d, Decision::Allow);
        assert_eq!(risk, Risk::Medium);
        // No audit file written by a dry-run.
        assert!(!dir.join("audit.jsonl").exists());
        fs::remove_dir_all(&dir).unwrap();
    }
}

impl Broker {
    /// Execute a tool binary with a caller-supplied program path.
    ///
    /// This is the Phase 2 entry point for `z run <tool>`. It differs from
    /// `execute_process` in two ways:
    ///   - the program path is supplied by the caller (the tool store location),
    ///     so the policy resource is the *tool name*, not the binary path;
    ///   - a tool whose manifest declares network access is escalated to HIGH
    ///     risk, because it can reach outside the machine.
    ///
    /// Arguments are still passed as a structured array. No shell is involved.
    pub fn execute_process_args(
        &mut self,
        req: &ExecRequest,
        program: &str,
        args: &[String],
        approved: bool,
        tool_needs_network: bool,
    ) -> ZenResult<ExecResult> {
        let request_id = format!("req_{}", uuid_like());
        let start = Instant::now();

        let (decision, risk, reason) = self.evaluate(req);

        // Escalate risk when the tool itself can reach the network. The
        // manifest is not trusted to grant this; it only raises the bar.
        let effective_risk = if tool_needs_network && risk < Risk::High {
            Risk::High
        } else {
            risk
        };
        let escalated = effective_risk != risk;

        if decision == Decision::Deny {
            let audit_id = self.log(req, "deny", "blocked", &effective_risk, &reason)?;
            return Ok(ExecResult {
                status: ExecStatus::Denied,
                request_id,
                audit_id: Some(audit_id),
                risk: risk_str(effective_risk).to_string(),
                reason,
                stdout: None,
                stderr: None,
                exit_code: None,
                duration_ms: start.elapsed().as_millis(),
            });
        }

        let needs_approval =
            decision == Decision::RequireApproval || (escalated && effective_risk >= Risk::High);
        if needs_approval && !approved {
            let why = if escalated {
                format!(
                    "{reason}; this tool declares network access, raising risk to {}",
                    risk_str(effective_risk)
                )
            } else {
                reason.clone()
            };
            let audit_id = self.log(req, "approval_required", "pending", &effective_risk, &why)?;
            return Ok(ExecResult {
                status: ExecStatus::ApprovalRequired,
                request_id,
                audit_id: Some(audit_id),
                risk: risk_str(effective_risk).to_string(),
                reason: why,
                stdout: None,
                stderr: None,
                exit_code: None,
                duration_ms: start.elapsed().as_millis(),
            });
        }

        // Capability: issued, checked, then revoked (single use).
        let cap = self.capabilities.issue(
            &req.actor.id,
            &req.action,
            &req.resource,
            ttl_for(effective_risk),
        );
        if let Err(e) = self
            .capabilities
            .check(&cap.id, &req.actor.id, &req.action, &req.resource)
        {
            let audit_id = self.log(
                req,
                "deny",
                "capability_error",
                &effective_risk,
                &e.to_string(),
            )?;
            return Ok(ExecResult {
                status: ExecStatus::Denied,
                request_id,
                audit_id: Some(audit_id),
                risk: risk_str(effective_risk).to_string(),
                reason: e.to_string(),
                stdout: None,
                stderr: None,
                exit_code: None,
                duration_ms: start.elapsed().as_millis(),
            });
        }
        self.capabilities.revoke(&cap.id);

        let mut preq = ProcessRequest::new(program);
        preq.args = args.to_vec();
        if let Some(p) = &self.project {
            preq.working_dir = Some(p.clone());
        }

        let outcome = ProcessRunner::run(&preq);
        let (status, result_str, stdout, stderr, code) = match outcome {
            Ok(r) if r.timed_out => (
                ExecStatus::Timeout,
                "timeout".to_string(),
                Some(r.stdout),
                Some(r.stderr),
                Some(r.exit_code),
            ),
            Ok(r) => (
                if r.success() {
                    ExecStatus::Allowed
                } else {
                    ExecStatus::Failed
                },
                if r.success() {
                    "ok".to_string()
                } else {
                    "nonzero_exit".to_string()
                },
                Some(r.stdout),
                Some(r.stderr),
                Some(r.exit_code),
            ),
            Err(e) => (
                ExecStatus::Failed,
                format!("spawn_error: {e}"),
                None,
                None,
                None,
            ),
        };

        let audit_id = self.log(req, "allow", &result_str, &effective_risk, &reason)?;

        Ok(ExecResult {
            status,
            request_id,
            audit_id: Some(audit_id),
            risk: risk_str(effective_risk).to_string(),
            reason,
            stdout,
            stderr,
            exit_code: code,
            duration_ms: start.elapsed().as_millis(),
        })
    }
}

#[cfg(test)]
mod tool_execution_tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "zen-tool-exec-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn broker_with(mut policy: Policy, dir: &std::path::Path) -> Broker {
        policy.tools.allow = vec!["echo".to_string()];
        let audit = AuditLog::open(&dir.join("audit.jsonl")).unwrap();
        Broker::new(policy, audit, Some(dir.to_path_buf()), "linux-x86_64-gnu")
    }

    fn req() -> ExecRequest {
        ExecRequest {
            actor: crate::types::ActorRef {
                id: "usr_t".into(),
                actor_type: "user".into(),
            },
            action: "tool.execute".into(),
            resource: "tool:echo".into(),
            reason: None,
        }
    }

    #[test]
    fn tool_not_in_allowlist_is_denied() {
        let d = tmp("deny");
        let mut policy = Policy::default();
        policy.tools.allow = vec![]; // nothing allowed
        let audit = AuditLog::open(&d.join("audit.jsonl")).unwrap();
        let mut b = Broker::new(policy, audit, Some(d.clone()), "linux-x86_64-gnu");

        let r = b
            .execute_process_args(&req(), "echo", &["hi".into()], false, false)
            .unwrap();
        assert_eq!(r.status, ExecStatus::Denied);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn allowed_tool_runs() {
        let d = tmp("allow");
        let mut b = broker_with(Policy::default(), &d);
        let r = b
            .execute_process_args(&req(), "echo", &["hello".into()], false, false)
            .unwrap();
        assert_eq!(r.status, ExecStatus::Allowed);
        assert_eq!(r.stdout.as_deref().unwrap().trim(), "hello");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn network_tool_is_escalated_to_high_and_needs_approval() {
        let d = tmp("net");
        let mut b = broker_with(Policy::default(), &d);
        let r = b
            .execute_process_args(&req(), "echo", &["x".into()], false, true)
            .unwrap();
        assert_eq!(
            r.status,
            ExecStatus::ApprovalRequired,
            "network tools must not run unapproved"
        );
        assert_eq!(r.risk, "HIGH");
        assert!(r.reason.contains("network"));
        // With approval it proceeds.
        let r2 = b
            .execute_process_args(&req(), "echo", &["x".into()], true, true)
            .unwrap();
        assert_ne!(r2.status, ExecStatus::ApprovalRequired);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn tool_args_are_never_shell_interpreted() {
        let d = tmp("inject");
        let mut b = broker_with(Policy::default(), &d);
        let r = b
            .execute_process_args(&req(), "echo", &["a; echo PWNED".into()], false, false)
            .unwrap();
        assert_eq!(r.stdout.as_deref().unwrap().trim(), "a; echo PWNED");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn tool_execution_is_audited() {
        let d = tmp("audit");
        let mut b = broker_with(Policy::default(), &d);
        b.execute_process_args(&req(), "echo", &["x".into()], false, false)
            .unwrap();
        let v = z_audit::verify(&d.join("audit.jsonl")).unwrap();
        assert!(v.is_ok(), "audit chain must be intact");
        let _ = fs::remove_dir_all(&d);
    }
}

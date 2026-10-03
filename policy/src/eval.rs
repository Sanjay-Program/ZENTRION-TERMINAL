//! Policy evaluation (Phase 1 §17): ALLOW | DENY | REQUIRE_APPROVAL.

use crate::model::Policy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    RequireApproval,
}

/// Risk ordering is meaningful: `Low < Medium < High < Critical`. Callers
/// rely on this to escalate (never to de-escalate) a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRequest {
    pub actor: String,
    pub action: String, // "filesystem.read" | "network.connect" | "process.spawn" | ...
    pub resource: String, // path glob, host, tool name...
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub risk: Risk,
    pub reason: String,
}

fn glob_match(pattern: &str, path: &str) -> bool {
    // Normalize both sides: strip a leading "./" so patterns like "./src/**"
    // match resources like "src/main.rs".
    let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
    let path = path.strip_prefix("./").unwrap_or(path);
    // Minimal glob: '**' matches any chars incl '/', '*' any chars excl '/'.
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = path.chars().collect();
    fn m(p: &[char], t: &[char]) -> bool {
        if p.is_empty() {
            return t.is_empty();
        }
        if p[0] == '*' {
            if p.len() > 1 && p[1] == '*' {
                // '**' — try consume 0..n chars
                for i in 0..=t.len() {
                    if m(&p[2..], &t[i..]) {
                        return true;
                    }
                }
                return false;
            }
            for i in 0..=t.len() {
                if i > 0 && t[i - 1] == '/' {
                    break;
                }
                if m(&p[1..], &t[i..]) {
                    return true;
                }
            }
            return false;
        }
        if t.is_empty() {
            return false;
        }
        if p[0] == '?' || p[0] == t[0] {
            return m(&p[1..], &t[1..]);
        }
        false
    }
    m(&pat, &txt)
}

/// Evaluate a request against a policy. Deny-by-default.
/// HIGH/CRITICAL-risk allowed actions still require approval per 08 §8.4.
pub fn evaluate(policy: &Policy, req: &PolicyRequest) -> PolicyDecision {
    let (allowed, reason) = match req.action.as_str() {
        "filesystem.read" => {
            let hit = policy
                .filesystem
                .read
                .iter()
                .any(|g| glob_match(g, req.resource.trim_start_matches("./")));
            (
                hit,
                format!("filesystem.read scope {:?}", policy.filesystem.read),
            )
        }
        "filesystem.write" => {
            let hit = policy
                .filesystem
                .write
                .iter()
                .any(|g| glob_match(g, req.resource.trim_start_matches("./")));
            (
                hit,
                format!("filesystem.write scope {:?}", policy.filesystem.write),
            )
        }
        "filesystem.delete" => {
            let hit = policy
                .filesystem
                .delete
                .iter()
                .any(|g| glob_match(g, req.resource.trim_start_matches("./")));
            (
                hit,
                format!("filesystem.delete scope {:?}", policy.filesystem.delete),
            )
        }
        "network.connect" => {
            let hit = policy.network.allow.iter().any(|h| h == &req.resource);
            (hit, format!("network.allow {:?}", policy.network.allow))
        }
        "network.listen" => {
            let hit = policy.network.listen.iter().any(|h| h == &req.resource);
            (hit, format!("network.listen {:?}", policy.network.listen))
        }
        "secret.read" => (
            policy.secrets.read,
            format!("secrets.read={}", policy.secrets.read),
        ),
        "secret.write" => (
            policy.secrets.write,
            format!("secrets.write={}", policy.secrets.write),
        ),
        "system.admin" => (
            policy.system.admin,
            format!("system.admin={}", policy.system.admin),
        ),
        "process.spawn" => {
            let hit = policy
                .process
                .spawn
                .iter()
                .any(|s| req.resource.starts_with(s.as_str()));
            (hit, format!("process.spawn {:?}", policy.process.spawn))
        }
        // Tool execution is gated on the *tool allowlist*, not the raw binary
        // list, so a permitted tool cannot be swapped for another binary.
        "tool.execute" => {
            let name = req.resource.strip_prefix("tool:").unwrap_or(&req.resource);
            let hit = policy.tools.allow.iter().any(|t| t == name);
            (hit, format!("tools.allow {:?}", policy.tools.allow))
        }
        "tool.install" => (
            policy.tools.install,
            format!("tools.install={}", policy.tools.install),
        ),
        other => (false, format!("unknown action '{other}' — deny by default")),
    };

    if !allowed {
        return PolicyDecision {
            decision: Decision::Deny,
            risk: classify_risk(req),
            reason,
        };
    }

    let risk = classify_risk(req);
    // Risk gating (08 §8.4): HIGH/CRITICAL always require explicit approval.
    let decision = match risk {
        Risk::Critical | Risk::High => Decision::RequireApproval,
        _ => Decision::Allow,
    };
    PolicyDecision {
        decision,
        risk,
        reason,
    }
}

/// Risk classification (Phase 1 §risk table / 08 §8.4 defaults).
pub fn classify_risk(req: &PolicyRequest) -> Risk {
    match req.action.as_str() {
        "filesystem.read" => Risk::Low,
        "filesystem.write" => Risk::Medium,
        "filesystem.delete" => Risk::High,
        "network.connect" | "network.listen" => Risk::Medium,
        "secret.read" => Risk::Critical,
        "secret.write" => Risk::High,
        "system.admin" => Risk::Critical,
        "process.spawn" => Risk::Medium,
        "tool.execute" | "tool.install" => Risk::Medium,
        _ => Risk::High, // unknown actions treated conservatively
    }
}

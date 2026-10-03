//! z-capability — capability store (08-CAPABILITY-MODEL, Phase 1 §18).
//!
//! Phase 1: in-memory, deny-by-default. Issued capabilities expire and are
//! revocable. This does NOT provide isolation by itself — it gates
//! authorization; the sandbox layer (Phase 2) provides confinement.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use z_core::error::{Area, ZenError, ZenResult};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    pub id: String,
    pub actor_id: String,
    pub action: String,
    pub resource: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revocation: Revocation,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Revocation {
    Immediate,
    OnSessionEnd,
    OnProjectClose,
}

impl Capability {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}

/// In-memory capability store. Deny-by-default: an unknown capability fails.
#[derive(Default)]
pub struct CapabilityStore {
    caps: HashMap<String, Capability>,
    revoked: Vec<String>,
    counter: u64,
}

impl CapabilityStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a capability with a TTL. Never grants more than requested scope.
    pub fn issue(
        &mut self,
        actor_id: &str,
        action: &str,
        resource: &str,
        ttl: ChronoDuration,
    ) -> Capability {
        self.counter += 1;
        let now = Utc::now();
        let cap = Capability {
            id: format!("cap_{:06x}", self.counter),
            actor_id: actor_id.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            issued_at: now,
            expires_at: now + ttl,
            revocation: Revocation::OnSessionEnd,
        };
        self.caps.insert(cap.id.clone(), cap.clone());
        cap
    }

    /// Check that a capability exists, matches actor/action/resource, and is
    /// neither expired nor revoked.
    pub fn check(
        &self,
        cap_id: &str,
        actor_id: &str,
        action: &str,
        resource: &str,
    ) -> ZenResult<()> {
        if self.revoked.iter().any(|r| r == cap_id) {
            return Err(ZenError::new(Area::Cap, 20, "capability has been revoked"));
        }
        let cap = self.caps.get(cap_id).ok_or_else(|| {
            ZenError::new(Area::Cap, 21, "unknown capability")
                .with_remediation("Request the action again so a capability can be issued.")
        })?;
        if cap.is_expired(Utc::now()) {
            return Err(ZenError::new(Area::Cap, 22, "capability has expired"));
        }
        if cap.actor_id != actor_id {
            return Err(ZenError::new(Area::Cap, 23, "capability actor mismatch"));
        }
        if cap.action != action {
            return Err(ZenError::new(Area::Cap, 24, "capability action mismatch"));
        }
        if cap.resource != resource {
            return Err(ZenError::new(
                Area::Cap,
                25,
                "capability resource out of scope",
            ));
        }
        Ok(())
    }

    pub fn revoke(&mut self, cap_id: &str) {
        self.revoked.push(cap_id.to_string());
    }

    pub fn revoke_all_for_actor(&mut self, actor_id: &str) {
        let ids: Vec<String> = self
            .caps
            .iter()
            .filter(|(_, c)| c.actor_id == actor_id)
            .map(|(k, _)| k.clone())
            .collect();
        self.revoked.extend(ids);
    }

    pub fn active_count(&self) -> usize {
        self.caps
            .values()
            .filter(|c| !c.is_expired(Utc::now()) && !self.revoked.contains(&c.id))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_check_roundtrip() {
        let mut s = CapabilityStore::new();
        let cap = s.issue(
            "agt_1",
            "filesystem.read",
            "./src/**",
            ChronoDuration::minutes(5),
        );
        assert!(s
            .check(&cap.id, "agt_1", "filesystem.read", "./src/**")
            .is_ok());
    }

    #[test]
    fn unknown_capability_denied() {
        let s = CapabilityStore::new();
        assert!(s.check("cap_nope", "a", "filesystem.read", "./x").is_err());
    }

    #[test]
    fn actor_mismatch_denied() {
        let mut s = CapabilityStore::new();
        let cap = s.issue(
            "agt_1",
            "filesystem.read",
            "./src/**",
            ChronoDuration::minutes(5),
        );
        assert!(s
            .check(&cap.id, "agt_2", "filesystem.read", "./src/**")
            .is_err());
    }

    #[test]
    fn action_mismatch_denied() {
        let mut s = CapabilityStore::new();
        let cap = s.issue(
            "agt_1",
            "filesystem.read",
            "./src/**",
            ChronoDuration::minutes(5),
        );
        assert!(s
            .check(&cap.id, "agt_1", "filesystem.write", "./src/**")
            .is_err());
    }

    #[test]
    fn resource_out_of_scope_denied() {
        let mut s = CapabilityStore::new();
        let cap = s.issue(
            "agt_1",
            "filesystem.read",
            "./src/**",
            ChronoDuration::minutes(5),
        );
        assert!(s
            .check(&cap.id, "agt_1", "filesystem.read", "/etc/passwd")
            .is_err());
    }

    #[test]
    fn expired_denied() {
        let mut s = CapabilityStore::new();
        let cap = s.issue(
            "agt_1",
            "filesystem.read",
            "./src/**",
            ChronoDuration::seconds(-1),
        );
        assert!(s
            .check(&cap.id, "agt_1", "filesystem.read", "./src/**")
            .is_err());
    }

    #[test]
    fn revocation_immediate() {
        let mut s = CapabilityStore::new();
        let cap = s.issue(
            "agt_1",
            "filesystem.read",
            "./src/**",
            ChronoDuration::minutes(5),
        );
        s.revoke(&cap.id);
        assert!(s
            .check(&cap.id, "agt_1", "filesystem.read", "./src/**")
            .is_err());
    }

    #[test]
    fn revoke_all_for_actor() {
        let mut s = CapabilityStore::new();
        let c1 = s.issue(
            "agt_1",
            "filesystem.read",
            "./src/**",
            ChronoDuration::minutes(5),
        );
        let c2 = s.issue(
            "agt_1",
            "filesystem.write",
            "./src/**",
            ChronoDuration::minutes(5),
        );
        s.revoke_all_for_actor("agt_1");
        assert!(s
            .check(&c1.id, "agt_1", "filesystem.read", "./src/**")
            .is_err());
        assert!(s
            .check(&c2.id, "agt_1", "filesystem.write", "./src/**")
            .is_err());
    }

    #[test]
    fn active_count_tracks_live_caps() {
        let mut s = CapabilityStore::new();
        s.issue("a", "filesystem.read", "./x", ChronoDuration::minutes(5));
        s.issue("a", "filesystem.read", "./y", ChronoDuration::seconds(-1));
        assert_eq!(s.active_count(), 1);
    }
}

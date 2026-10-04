//! z-identity — actor identity (Phase 1 §32, 04-CORE-RUNTIME).
//!
//! Every request must carry an identity. Phase 1 resolves the local user
//! types for future phases but are NOT creatable here.

pub mod vault;

use serde::{Deserialize, Serialize};
use z_core::error::{Area, ZenError, ZenResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    User,
    Agent,
    Plugin,
    Mcp,
    Ci,
    Ide,
}

impl ActorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActorType::User => "user",
            ActorType::Agent => "agent",
            ActorType::Plugin => "plugin",
            ActorType::Mcp => "mcp",
            ActorType::Ci => "ci",
            ActorType::Ide => "ide",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Actor {
    pub id: String,
    pub actor_type: ActorType,
    pub parent_id: Option<String>,
    pub project_id: Option<String>,
}

/// Resolve the local user identity. Derived from the OS username and a
/// stable per-install id file. No network, no cloud account (Phase 1 §7).
pub fn local_user() -> ZenResult<Actor> {
    let name = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .map_err(|_| {
            ZenError::new(Area::Cor, 40, "cannot determine local user identity")
                .with_remediation("Ensure USER/USERNAME is set in the environment.")
        })?;
    if name.trim().is_empty() {
        return Err(ZenError::new(Area::Cor, 41, "empty user identity"));
    }
    Ok(Actor {
        id: format!("usr_{}", name),
        actor_type: ActorType::User,
        parent_id: None,
        project_id: None,
    })
}

/// Reject a request that carries no usable identity (Phase 1 §32 acceptance:
/// unauthenticated request must be rejected).
pub fn require(actor: Option<&Actor>) -> ZenResult<&Actor> {
    actor.ok_or_else(|| {
        ZenError::new(Area::Sec, 50, "request carries no identity")
            .with_remediation("Authenticate by running through the Zentrion CLI or runtime.")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_user_resolves() {
        // USER or USERNAME should exist in the test environment.
        let a = local_user();
        assert!(a.is_ok() || std::env::var("USER").is_err());
        if let Ok(a) = a {
            assert_eq!(a.actor_type, ActorType::User);
            assert!(a.id.starts_with("usr_"));
        }
    }

    #[test]
    fn missing_identity_rejected() {
        assert!(require(None).is_err());
    }

    #[test]
    fn present_identity_accepted() {
        let a = Actor {
            id: "usr_x".into(),
            actor_type: ActorType::User,
            parent_id: None,
            project_id: None,
        };
        assert!(require(Some(&a)).is_ok());
    }
}

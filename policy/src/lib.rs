//! z-policy — declarative policy engine (09-POLICY-SPEC).
//!
//! Deny-by-default. Strict parsing (unknown keys rejected). Layers merge so
//! that higher layers can only NARROW scopes, never widen (intersection rule).

pub mod eval;
pub mod merge;
pub mod model;
pub mod parser;

pub use eval::evaluate;
pub use model::*;
pub use parser::parse_policy;
// Re-export eval types at crate root for ergonomic use.
pub use crate::eval::{Decision, PolicyDecision, PolicyRequest, Risk};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval::{classify_risk, Decision, PolicyRequest, Risk};
    use crate::merge::merge;
    use crate::parser::parse_policy;

    fn base() -> Policy {
        Policy::default()
    }

    #[test]
    fn process_grant_is_exact_not_prefix() {
        let mut policy = Policy::default();
        policy.process.spawn = vec!["cargo".to_string()];
        let allow = evaluate(
            &policy,
            &PolicyRequest {
                actor: "test".into(),
                action: "process.spawn".into(),
                resource: "cargo".into(),
            },
        );
        assert_eq!(allow.decision, Decision::Allow);
        let path_allow = evaluate(
            &policy,
            &PolicyRequest {
                actor: "test".into(),
                action: "process.spawn".into(),
                resource: "/usr/bin/cargo".into(),
            },
        );
        assert_eq!(path_allow.decision, Decision::Allow);
        let evil = evaluate(
            &policy,
            &PolicyRequest {
                actor: "test".into(),
                action: "process.spawn".into(),
                resource: "cargo-evil".into(),
            },
        );
        assert_eq!(evil.decision, Decision::Deny);
    }

    #[test]
    fn deny_by_default_for_unknown_action() {
        let d = evaluate(
            &base(),
            &PolicyRequest {
                actor: "test".into(),
                action: "something.else".into(),
                resource: "./x".into(),
            },
        );
        assert_eq!(d.decision, Decision::Deny);
    }

    #[test]
    fn default_allows_workspace_read() {
        let d = evaluate(
            &base(),
            &PolicyRequest {
                actor: "test".into(),
                action: "filesystem.read".into(),
                resource: "./src/main.rs".into(),
            },
        );
        assert_eq!(d.decision, Decision::Allow);
        assert_eq!(d.risk, Risk::Low);
    }

    #[test]
    fn default_denies_secrets_and_admin() {
        for action in ["secret.read", "system.admin"] {
            let d = evaluate(
                &base(),
                &PolicyRequest {
                    actor: "t".into(),
                    action: action.into(),
                    resource: "x".into(),
                },
            );
            assert_eq!(d.decision, Decision::Deny, "{action}");
        }
    }

    #[test]
    fn delete_is_high_risk_requires_approval() {
        let mut p = base();
        p.filesystem.delete = vec!["./build/**".into()];
        let d = evaluate(
            &p,
            &PolicyRequest {
                actor: "t".into(),
                action: "filesystem.delete".into(),
                resource: "./build/out.txt".into(),
            },
        );
        assert_eq!(d.decision, Decision::RequireApproval);
        assert_eq!(d.risk, Risk::High);
    }

    #[test]
    fn secret_read_critical() {
        assert_eq!(
            classify_risk(&PolicyRequest {
                actor: "t".into(),
                action: "secret.read".into(),
                resource: "x".into()
            }),
            Risk::Critical
        );
    }

    #[test]
    fn strict_parse_rejects_unknown_keys() {
        let yaml = "apiVersion: zentrion.policy/v1\nkind: Policy\nmetadata:\n  name: t\nsneaky:\n  admin: true\n";
        assert!(parse_policy(yaml).is_err());
    }

    #[test]
    fn parse_rejects_wrong_api_version() {
        let yaml = "apiVersion: zentrion.policy/v99\nkind: Policy\nmetadata:\n  name: t\n";
        assert!(parse_policy(yaml).is_err());
    }

    #[test]
    fn parse_rejects_absolute_paths() {
        let yaml = "apiVersion: zentrion.policy/v1\nkind: Policy\nmetadata:\n  name: t\nfilesystem:\n  read:\n    - /etc/**\n";
        assert!(parse_policy(yaml).is_err());
    }

    #[test]
    fn parse_rejects_bad_network_scope() {
        let yaml = "apiVersion: zentrion.policy/v1\nkind: Policy\nmetadata:\n  name: t\nnetwork:\n  allow:\n    - evil.example.com\n";
        assert!(parse_policy(yaml).is_err());
    }

    #[test]
    fn valid_policy_parses() {
        let yaml = "apiVersion: zentrion.policy/v1\nkind: Policy\nmetadata:\n  name: t\nfilesystem:\n  read:\n    - \"./src/**\"\nnetwork:\n  allow:\n    - \"host:api.example.com:443\"\n";
        let p = parse_policy(yaml).unwrap();
        assert_eq!(p.metadata.name, "t");
    }

    #[test]
    fn merge_cannot_widen() {
        let mut user = base();
        user.filesystem.read = vec!["./**".to_string()];
        let mut project = base();
        project.filesystem.read = vec!["./src/**".to_string()];
        let eff = merge(&user, &project);
        assert_eq!(eff.filesystem.read, vec!["./src/**".to_string()]);
    }

    #[test]
    fn merge_deny_wins_for_secrets() {
        let mut lower = base();
        lower.secrets.read = true;
        let higher = base();
        let eff = merge(&lower, &higher);
        assert!(!eff.secrets.read);
    }

    #[test]
    fn glob_semanics() {
        assert!(
            evaluate(
                &base(),
                &PolicyRequest {
                    actor: "t".into(),
                    action: "filesystem.read".into(),
                    resource: "./a/b/c.txt".into()
                }
            )
            .decision
                == Decision::Allow
        );
        let mut p = base();
        p.filesystem.read = vec!["./src/**".to_string()];
        assert!(
            evaluate(
                &p,
                &PolicyRequest {
                    actor: "t".into(),
                    action: "filesystem.read".into(),
                    resource: "./src/x.rs".into()
                }
            )
            .decision
                == Decision::Allow
        );
        assert!(
            evaluate(
                &p,
                &PolicyRequest {
                    actor: "t".into(),
                    action: "filesystem.read".into(),
                    resource: "./tests/x.rs".into()
                }
            )
            .decision
                == Decision::Deny
        );
    }
}

#[cfg(test)]
mod agent_policy_tests {
    use super::*;
    use crate::eval::{Decision, PolicyRequest, Risk};

    fn policy() -> Policy {
        let mut policy = Policy::default();
        policy.agent.read = vec!["./**".into()];
        policy.agent.write = vec!["./src/**".into()];
        policy.agent.delete = vec!["./tmp/**".into()];
        policy.agent.exec = vec!["cargo".into()];
        policy.agent.net = vec!["api.example.com".into()];
        policy.agent.tools = vec!["github/create_issue".into()];
        policy
    }

    #[test]
    fn agent_actions_are_scoped_and_deny_by_default() {
        let p = policy();
        let write = evaluate(
            &p,
            &PolicyRequest {
                actor: "agent:test".into(),
                action: "agent.fs.write".into(),
                resource: "src/main.rs".into(),
            },
        );
        assert_eq!(write.decision, Decision::Allow);
        let outside = evaluate(
            &p,
            &PolicyRequest {
                actor: "agent:test".into(),
                action: "agent.fs.write".into(),
                resource: "docs/readme.md".into(),
            },
        );
        assert_eq!(outside.decision, Decision::Deny);
        let unknown = evaluate(
            &p,
            &PolicyRequest {
                actor: "agent:test".into(),
                action: "agent.fs.chmod".into(),
                resource: "src/main.rs".into(),
            },
        );
        assert_eq!(unknown.decision, Decision::Deny);
    }

    #[test]
    fn agent_delete_is_high_risk_and_requires_approval() {
        let decision = evaluate(
            &policy(),
            &PolicyRequest {
                actor: "agent:test".into(),
                action: "agent.fs.delete".into(),
                resource: "tmp/out.bin".into(),
            },
        );
        assert_eq!(decision.decision, Decision::RequireApproval);
        assert_eq!(decision.risk, Risk::High);
    }

    #[test]
    fn agent_secret_read_is_critical_and_denied_without_grant() {
        let decision = evaluate(
            &policy(),
            &PolicyRequest {
                actor: "agent:test".into(),
                action: "agent.secret.read".into(),
                resource: "OPENAI_API_KEY".into(),
            },
        );
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.risk, Risk::Critical);
    }

    #[test]
    fn agent_tool_and_exec_matching_is_exact() {
        let p = policy();
        let exact = evaluate(
            &p,
            &PolicyRequest {
                actor: "agent:test".into(),
                action: "agent.exec".into(),
                resource: "/usr/bin/cargo".into(),
            },
        );
        assert_eq!(exact.decision, Decision::Allow);
        let lookalike = evaluate(
            &p,
            &PolicyRequest {
                actor: "agent:test".into(),
                action: "agent.exec".into(),
                resource: "cargo-evil".into(),
            },
        );
        assert_eq!(lookalike.decision, Decision::Deny);
        let tool = evaluate(
            &p,
            &PolicyRequest {
                actor: "agent:test".into(),
                action: "agent.tool.call".into(),
                resource: "mcp:github/create_issue".into(),
            },
        );
        assert_eq!(tool.decision, Decision::Allow);
        let other_tool = evaluate(
            &p,
            &PolicyRequest {
                actor: "agent:test".into(),
                action: "agent.tool.call".into(),
                resource: "mcp:github/delete_repo".into(),
            },
        );
        assert_eq!(other_tool.decision, Decision::Deny);
    }
}

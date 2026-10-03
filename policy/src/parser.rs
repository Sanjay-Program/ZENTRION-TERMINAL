//! Strict YAML policy parser. Unknown keys and wrong apiVersion are errors.

use crate::model::{Policy, POLICY_API_VERSION};
use z_core::error::{Area, ZenError, ZenResult};

pub fn parse_policy(text: &str) -> ZenResult<Policy> {
    let p: Policy = serde_yaml::from_str(text).map_err(|e| {
        ZenError::new(Area::Pol, 10, format!("invalid policy: {e}")).with_remediation(
            "Check policy syntax against schemas/policy-v1.json; run `z policy validate`.",
        )
    })?;
    if p.api_version != POLICY_API_VERSION {
        return Err(ZenError::new(
            Area::Pol,
            11,
            format!(
                "unsupported policy apiVersion '{}' (expected '{POLICY_API_VERSION}')",
                p.api_version
            ),
        ));
    }
    if p.kind != "Policy" {
        return Err(ZenError::new(
            Area::Pol,
            12,
            format!("unexpected policy kind '{}'", p.kind),
        ));
    }
    validate_scopes(&p)?;
    Ok(p)
}

fn validate_scopes(p: &Policy) -> ZenResult<()> {
    for (list, kind) in [
        (&p.filesystem.read, "read"),
        (&p.filesystem.write, "write"),
        (&p.filesystem.delete, "delete"),
    ] {
        for g in list {
            if g.starts_with('/') {
                return Err(ZenError::new(
                    Area::Pol,
                    13,
                    format!(
                        "filesystem.{kind}: absolute path '{g}' in project policy is not allowed"
                    ),
                )
                .with_remediation("Use workspace-relative globs like './src/**'."));
            }
        }
    }
    for h in p.network.allow.iter().chain(p.network.listen.iter()) {
        let ok = h.starts_with("host:") || h.starts_with("cidr:") || h.starts_with("port:");
        if !ok {
            return Err(ZenError::new(
                Area::Pol,
                14,
                format!("network scope '{h}' must start with host:, cidr:, or port:"),
            ));
        }
    }
    Ok(())
}

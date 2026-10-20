//! Engagement scope parsing and authorization.
//!
//! Scope entries are URLs, hosts, host:port, wildcards (`*.example.com`),
//! IP addresses and CIDRs. Explicit `out_of_scope` entries always deny, even
//! when a wildcard would allow. Break-glass is a short-lived, explicit,
//! reasoned override — never a silent widening of scope.

use chrono::{DateTime, Duration, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Scope {
    pub targets: Vec<String>,
    #[serde(default)]
    pub out_of_scope: Vec<String>,
    #[serde(default)]
    pub ports: Vec<PortRange>,
    #[serde(default)]
    pub tools: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub from: u16,
    pub to: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.from && port <= self.to
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub host: String,
    pub port: Option<u16>,
    pub scheme: Option<String>,
}

impl Target {
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        if input.is_empty() {
            return Err("empty target".into());
        }
        if input.contains(char::is_whitespace) {
            return Err(format!("target `{input}` contains whitespace"));
        }
        let (scheme, rest) = match input.split_once("://") {
            Some((scheme, rest)) => (Some(scheme.to_ascii_lowercase()), rest),
            None => (None, input),
        };
        if let Some(scheme) = &scheme {
            if !matches!(scheme.as_str(), "http" | "https" | "ssh" | "ftp" | "smtp") {
                return Err(format!("unsupported scheme `{scheme}`"));
            }
        }
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        if authority.is_empty() {
            return Err("target has no host".into());
        }
        if authority.contains('@') {
            return Err("targets must not contain credentials".into());
        }
        let (host, port) = split_host_port(authority)?;
        if host.is_empty() {
            return Err("target has no host".into());
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
            scheme,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }
}

fn split_host_port(authority: &str) -> Result<(String, Option<u16>), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| "unterminated IPv6 literal".to_string())?;
        let port = rest
            .strip_prefix(':')
            .map(|port| port.parse::<u16>().map_err(|_| "invalid port".to_string()))
            .transpose()?;
        return Ok((host.to_string(), port));
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() {
            return Ok((
                host.to_string(),
                Some(
                    port.parse::<u16>()
                        .map_err(|_| "invalid port".to_string())?,
                ),
            ));
        }
    }
    Ok((authority.to_string(), None))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeDecision {
    Allowed,
    AllowedBreakGlass,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeVerdict {
    pub decision: ScopeDecision,
    pub reason: String,
    pub matched: Option<String>,
}

impl ScopeVerdict {
    pub fn allowed(&self) -> bool {
        self.decision != ScopeDecision::Denied
    }
}

/// A short-lived, reasoned override for one target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakGlass {
    pub actor: String,
    pub reason: String,
    pub target: String,
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approved_by: Option<String>,
}

impl BreakGlass {
    pub fn new(
        actor: impl Into<String>,
        reason: impl Into<String>,
        target: impl Into<String>,
        minutes: i64,
    ) -> Result<Self, String> {
        let reason = reason.into();
        if reason.trim().len() < 10 {
            return Err("break-glass reason must explain why (at least 10 characters)".into());
        }
        if minutes <= 0 || minutes > 240 {
            return Err("break-glass duration must be between 1 and 240 minutes".into());
        }
        let target = target.into();
        Target::parse(&target)?;
        let now = Utc::now();
        Ok(Self {
            actor: actor.into(),
            reason,
            target,
            granted_at: now,
            expires_at: now + Duration::minutes(minutes),
            approved_by: None,
        })
    }

    pub fn valid_for(&self, target: &Target) -> bool {
        if Utc::now() > self.expires_at {
            return false;
        }
        let Ok(override_target) = Target::parse(&self.target) else {
            return false;
        };
        override_target.host == target.host
            && (override_target.port.is_none() || override_target.port == target.port)
    }
}

/// Check a target against scope.
pub fn authorize(
    scope: &Scope,
    target_input: &str,
    break_glass: Option<&BreakGlass>,
) -> ScopeVerdict {
    let target = match Target::parse(target_input) {
        Ok(target) => target,
        Err(error) => {
            return ScopeVerdict {
                decision: ScopeDecision::Denied,
                reason: format!("invalid target: {error}"),
                matched: None,
            }
        }
    };
    // Break-glass is the deliberate, audited override for an out-of-scope
    // target; it is checked before the explicit deny list.
    if let Some(glass) = break_glass {
        if glass.valid_for(&target) {
            return ScopeVerdict {
                decision: ScopeDecision::AllowedBreakGlass,
                reason: format!("break-glass by {}: {}", glass.actor, glass.reason),
                matched: Some(glass.target.clone()),
            };
        }
    }
    for denied in &scope.out_of_scope {
        if entry_matches(denied, &target) {
            return ScopeVerdict {
                decision: ScopeDecision::Denied,
                reason: format!("`{}` is explicitly out of scope", denied),
                matched: Some(denied.clone()),
            };
        }
    }
    for allowed in &scope.targets {
        if entry_matches(allowed, &target) {
            if let Some(port) = target.port {
                if !scope.ports.is_empty() && !scope.ports.iter().any(|range| range.contains(port))
                {
                    return ScopeVerdict {
                        decision: ScopeDecision::Denied,
                        reason: format!("port {port} is not in the engagement's allowed ports"),
                        matched: Some(allowed.clone()),
                    };
                }
            }
            return ScopeVerdict {
                decision: ScopeDecision::Allowed,
                reason: format!("covered by `{allowed}`"),
                matched: Some(allowed.clone()),
            };
        }
    }
    ScopeVerdict {
        decision: ScopeDecision::Denied,
        reason: format!("`{}` is not in engagement scope", target.host),
        matched: None,
    }
}

fn entry_matches(entry: &str, target: &Target) -> bool {
    let entry = entry.trim();
    if entry.is_empty() {
        return false;
    }
    // CIDR.
    if let Ok(network) = entry.parse::<IpNet>() {
        if let Ok(ip) = target.host.parse::<IpAddr>() {
            return network.contains(&ip);
        }
        return false;
    }
    // Wildcard domain.
    if let Some(suffix) = entry.strip_prefix("*.") {
        let suffix = suffix.to_ascii_lowercase();
        // A wildcard covers subdomains, never the apex. List the apex separately.
        return target.host.ends_with(&format!(".{suffix}"));
    }
    // URL / host / host:port.
    let Ok(scope_target) = Target::parse(entry) else {
        return false;
    };
    if scope_target.host != target.host {
        return false;
    }
    if let Some(port) = scope_target.port {
        if Some(port) != target.port {
            return false;
        }
    }
    true
}

/// Extract explicit network targets from a command line. Only URLs and IP
/// literals are extracted; bare domain names are ambiguous (a filename can look
/// like one), so callers must pass `--target` for those.
pub fn extract_targets(command: &str) -> Vec<String> {
    let mut targets = Vec::new();
    for token in command.split_whitespace() {
        let token = token.trim_matches(|c: char| {
            matches!(
                c,
                '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '<' | '>'
            )
        });
        if token.is_empty() || token.starts_with('-') {
            continue;
        }
        let candidate = token
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_start_matches("ftp://");
        let host_part = candidate.split('/').next().unwrap_or(candidate);
        let host_part = host_part.split(':').next().unwrap_or(host_part);
        if token.contains("://") || token.parse::<IpAddr>().is_ok() {
            targets.push(token.to_string());
        } else if host_part.parse::<IpAddr>().is_ok() || token.contains('/') && token.contains('.')
        {
            // path-looking tokens are not hosts
        } else if token.contains('.') && !token.contains('/') && !token.contains('=') {
            // Do not guess domains from a bare token; leave it to --target.
        }
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> Scope {
        Scope {
            targets: vec![
                "example.com".into(),
                "*.example.org".into(),
                "10.0.0.0/24".into(),
                "api.test:8443".into(),
            ],
            out_of_scope: vec!["admin.example.com".into()],
            ports: vec![PortRange { from: 80, to: 443 }],
            tools: vec!["nmap".into()],
        }
    }

    #[test]
    fn exact_wildcard_and_cidr_match() {
        assert!(authorize(&scope(), "example.com", None).allowed());
        assert!(authorize(&scope(), "https://example.com/path", None).allowed());
        assert!(authorize(&scope(), "sub.example.org", None).allowed());
        assert!(!authorize(&scope(), "example.org", None).allowed());
        assert!(authorize(&scope(), "a.b.example.org", None).allowed());
        assert!(authorize(&scope(), "10.0.0.7", None).allowed());
        assert!(authorize(&scope(), "10.0.1.7", None).allowed() == false);
    }

    #[test]
    fn explicit_out_of_scope_wins_over_wildcard() {
        let verdict = authorize(&scope(), "admin.example.com", None);
        assert_eq!(verdict.decision, ScopeDecision::Denied);
        assert!(verdict.reason.contains("explicitly out of scope"));
    }

    #[test]
    fn ports_are_checked_when_restrictions_exist() {
        assert_eq!(
            authorize(&scope(), "example.com:443", None).decision,
            ScopeDecision::Allowed
        );
        assert_eq!(
            authorize(&scope(), "example.com:22", None).decision,
            ScopeDecision::Denied
        );
    }

    #[test]
    fn wildcard_does_not_match_prefix_lookalike() {
        assert!(!authorize(&scope(), "notexample.com", None).allowed());
        assert!(!authorize(&scope(), "evil-example.org", None).allowed());
    }

    #[test]
    fn break_glass_is_bounded_and_reasoned() {
        assert!(BreakGlass::new("tester", "short", "example.net", 10).is_err());
        let glass =
            BreakGlass::new("tester", "authorized by client call", "example.net", 10).unwrap();
        assert_eq!(
            authorize(&scope(), "example.net", Some(&glass)).decision,
            ScopeDecision::AllowedBreakGlass
        );
        assert!(!authorize(&scope(), "other.net", Some(&glass)).allowed());
        let mut expired = glass.clone();
        expired.expires_at = Utc::now() - Duration::minutes(1);
        assert!(!authorize(&scope(), "example.net", Some(&expired)).allowed());
    }

    #[test]
    fn target_parsing_rejects_credentials_and_bad_ports() {
        assert!(Target::parse("https://user:pass@example.com").is_err());
        assert!(Target::parse("example.com:99999").is_err());
        assert_eq!(
            Target::parse("https://Example.COM:8443/x").unwrap().host,
            "example.com"
        );
        assert!(Target::parse(" ").is_err());
    }

    #[test]
    fn command_target_extraction_only_takes_explicit_hosts() {
        let targets = extract_targets("nmap -sV http://example.com 10.0.0.5 --script foo.txt");
        assert!(targets.iter().any(|t| t.contains("example.com")));
        assert!(targets.iter().any(|t| t == "10.0.0.5"));
        assert!(!targets.iter().any(|t| t == "foo.txt"));
    }

    #[test]
    fn empty_scope_denies_everything() {
        assert!(!authorize(&Scope::default(), "example.com", None).allowed());
    }
}

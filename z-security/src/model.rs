//! Engagement, evidence and finding data model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const SECURITY_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Engagement {
    pub version: u32,
    pub id: String,
    pub name: String,
    pub client: String,
    pub authorization: String,
    pub authorized_by: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub rules_of_engagement: Vec<String>,
    pub scope: crate::scope::Scope,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub status: EngagementStatus,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngagementStatus {
    Draft,
    Active,
    Closed,
}

impl Engagement {
    pub fn validate(&self) -> Vec<String> {
        let mut issues = Vec::new();
        if self.version != SECURITY_VERSION {
            issues.push(format!("unsupported engagement version {}", self.version));
        }
        if self.name.trim().is_empty() {
            issues.push("engagement name must not be empty".into());
        }
        if self.authorization.trim().len() < 10 {
            issues.push(
                "authorization note must describe the signed authorization (at least 10 characters)"
                    .into(),
            );
        }
        if self.authorized_by.trim().is_empty() {
            issues.push("authorized_by must name who authorized the work".into());
        }
        if self.end < self.start {
            issues.push("engagement end date precedes its start date".into());
        }
        if self.scope.targets.is_empty() {
            issues.push("engagement scope has no targets".into());
        }
        if self.rules_of_engagement.is_empty() {
            issues.push("rules of engagement must not be empty".into());
        }
        for target in &self.scope.targets {
            if let Err(error) = crate::scope::Target::parse(target) {
                issues.push(format!("invalid scope target `{target}`: {error}"));
            }
        }
        for target in &self.scope.out_of_scope {
            if let Err(error) = crate::scope::Target::parse(target) {
                issues.push(format!("invalid out-of-scope target `{target}`: {error}"));
            }
        }
        for range in &self.scope.ports {
            if range.from == 0 || range.to < range.from {
                issues.push(format!("invalid port range {}-{}", range.from, range.to));
            }
        }
        issues
    }

    pub fn checked(self) -> Result<Self, String> {
        let issues = self.validate();
        if issues.is_empty() {
            Ok(self)
        } else {
            Err(issues.join("; "))
        }
    }

    pub fn active(&self) -> bool {
        self.status == EngagementStatus::Active
            && Utc::now() >= self.start
            && Utc::now() <= self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub version: u32,
    pub id: String,
    pub engagement_id: String,
    pub ts: DateTime<Utc>,
    pub kind: String,
    /// Redacted command text. The original hash is stored in `command_sha256`.
    pub command: Option<String>,
    pub command_sha256: Option<String>,
    pub target: Option<String>,
    pub operator: String,
    pub host: String,
    pub exit_code: Option<i32>,
    pub output_sha256: Option<String>,
    pub output_bytes: Option<u64>,
    pub output_file: Option<String>,
    pub decision: String,
    pub note: Option<String>,
    pub prev_hash: String,
    pub hash: String,
    pub signature: Option<Signature>,
}

impl Evidence {
    /// Bytes covered by the chain hash and signature: everything except the
    /// hash and signature fields, in a stable order.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut copy = self.clone();
        copy.hash.clear();
        copy.signature = None;
        serde_json::to_vec(&copy).unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn from_cvss(score: f32) -> Self {
        match score {
            s if s >= 9.0 => Self::Critical,
            s if s >= 7.0 => Self::High,
            s if s >= 4.0 => Self::Medium,
            s if s > 0.0 => Self::Low,
            _ => Self::Info,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Confirmed,
    FalsePositive,
    Remediated,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub version: u32,
    pub id: String,
    pub engagement_id: String,
    pub title: String,
    pub severity: Severity,
    pub cvss: Option<f32>,
    pub target: String,
    pub description: String,
    pub remediation: String,
    pub evidence: Vec<String>,
    pub cwe: Vec<String>,
    pub mitre: Vec<String>,
    pub status: FindingStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub tags: Vec<String>,
}

impl Finding {
    pub fn validate(&self) -> Vec<String> {
        let mut issues = Vec::new();
        if self.title.trim().is_empty() {
            issues.push("finding title must not be empty".into());
        }
        if self.target.trim().is_empty() {
            issues.push("finding target must not be empty".into());
        }
        if let Some(cvss) = self.cvss {
            if !(0.0..=10.0).contains(&cvss) {
                issues.push("CVSS must be between 0 and 10".into());
            }
        }
        for id in &self.evidence {
            if !valid_id(id) {
                issues.push(format!("invalid evidence id `{id}`"));
            }
        }
        issues
    }
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 80
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::{PortRange, Scope};

    fn engagement() -> Engagement {
        Engagement {
            version: SECURITY_VERSION,
            id: "eng_test".into(),
            name: "Q4 external test".into(),
            client: "Acme".into(),
            authorization: "Signed statement of work dated 2026-10-01".into(),
            authorized_by: "security@acme.example".into(),
            start: Utc::now() - chrono::Duration::days(1),
            end: Utc::now() + chrono::Duration::days(7),
            rules_of_engagement: vec!["No denial-of-service testing".into()],
            scope: Scope {
                targets: vec!["example.com".into()],
                out_of_scope: vec![],
                ports: vec![PortRange { from: 80, to: 443 }],
                tools: vec![],
            },
            created_by: "tester".into(),
            created_at: Utc::now(),
            status: EngagementStatus::Active,
            tags: vec![],
        }
    }

    #[test]
    fn engagement_requires_authorization_and_scope() {
        let mut engagement = engagement();
        assert!(engagement.validate().is_empty());
        engagement.authorization = "ok".into();
        engagement.scope.targets.clear();
        let issues = engagement.validate();
        assert!(issues.iter().any(|issue| issue.contains("authorization")));
        assert!(issues.iter().any(|issue| issue.contains("scope")));
    }

    #[test]
    fn severity_follows_cvss() {
        assert_eq!(Severity::from_cvss(9.8), Severity::Critical);
        assert_eq!(Severity::from_cvss(7.5), Severity::High);
        assert_eq!(Severity::from_cvss(5.0), Severity::Medium);
        assert_eq!(Severity::from_cvss(0.1), Severity::Low);
        assert_eq!(Severity::from_cvss(0.0), Severity::Info);
    }

    #[test]
    fn ids_cannot_be_paths() {
        assert!(valid_id("f_abc123"));
        assert!(!valid_id("../etc/passwd"));
        assert!(!valid_id("a/b"));
        assert!(!valid_id(""));
    }
}

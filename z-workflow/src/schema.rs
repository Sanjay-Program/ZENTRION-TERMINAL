//! Workflow YAML schema.
//!
//! Exactly one action per step. Unknown keys are rejected so a typo cannot
//! silently remove a timeout, an approval or a condition.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ParamSpec {
    #[serde(rename = "type", default = "default_type")]
    pub kind: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub default: Option<serde_yaml::Value>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, rename = "enum")]
    pub allowed: Vec<String>,
    /// Resolve from the local encrypted vault instead of the command line.
    #[serde(default)]
    pub secret: bool,
}

fn default_type() -> String {
    "string".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Workflow {
    pub name: String,
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub params: BTreeMap<String, ParamSpec>,
    pub steps: Vec<Step>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub timeout: Option<String>,
    #[serde(default)]
    pub working_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub run: Option<String>,
    #[serde(default)]
    pub agent: Option<AgentSpec>,
    #[serde(default)]
    pub approve: Option<String>,
    #[serde(default)]
    pub parallel: Option<Vec<Step>>,
    #[serde(default, rename = "if")]
    pub condition: Option<String>,
    #[serde(default)]
    pub when: Option<String>,
    #[serde(default)]
    pub http: Option<HttpStep>,
    #[serde(default)]
    pub artifact: Option<ArtifactStep>,
    #[serde(default)]
    pub timeout: Option<String>,
    #[serde(default)]
    pub retries: u32,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub continue_on_error: bool,
    #[serde(default)]
    pub shell: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum AgentSpec {
    Name(String),
    Config {
        agent: String,
        #[serde(default)]
        prompt: Option<String>,
        #[serde(default)]
        model: Option<String>,
        #[serde(default)]
        args: Vec<String>,
    },
}

impl AgentSpec {
    pub fn agent(&self) -> &str {
        match self {
            Self::Name(name) => name,
            Self::Config { agent, .. } => agent,
        }
    }

    pub fn prompt(&self) -> Option<&str> {
        match self {
            Self::Name(_) => None,
            Self::Config { prompt, .. } => prompt.as_deref(),
        }
    }

    pub fn model(&self) -> Option<&str> {
        match self {
            Self::Name(_) => None,
            Self::Config { model, .. } => model.as_deref(),
        }
    }

    pub fn extra_args(&self) -> &[String] {
        match self {
            Self::Name(_) => &[],
            Self::Config { args, .. } => args,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpStep {
    #[serde(default = "default_method")]
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub expect_status: Vec<u16>,
    #[serde(default)]
    pub timeout: Option<String>,
}

fn default_method() -> String {
    "GET".into()
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ArtifactStep {
    pub path: String,
    pub name: Option<String>,
}

impl<'de> Deserialize<'de> for ArtifactStep {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Path(String),
            Config {
                path: String,
                #[serde(default)]
                name: Option<String>,
            },
        }
        match Raw::deserialize(deserializer)? {
            Raw::Path(path) => Ok(Self { path, name: None }),
            Raw::Config { path, name } => Ok(Self { path, name }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamValue {
    pub name: String,
    pub value: String,
    pub secret: bool,
}

impl Workflow {
    pub fn validate(&self) -> Vec<String> {
        let mut issues = Vec::new();
        if self.name.trim().is_empty() {
            issues.push("workflow name must not be empty".into());
        }
        if self.steps.is_empty() {
            issues.push("workflow must have at least one step".into());
        }
        if let Some(version) = self.version {
            if version != 1 {
                issues.push(format!("unsupported workflow version {version}"));
            }
        }
        validate_params(&self.params, &mut issues);
        let mut ids = std::collections::BTreeSet::new();
        let mut step_count = 0usize;
        validate_steps(
            &self.steps,
            &mut ids,
            &mut step_count,
            0,
            false,
            &mut issues,
        );
        if step_count > 500 {
            issues.push(format!("workflow has {step_count} steps (maximum 500)"));
        }
        if let Some(timeout) = &self.timeout {
            if parse_duration(timeout).is_none() {
                issues.push(format!("invalid workflow timeout `{timeout}`"));
            }
        }
        for (name, spec) in &self.params {
            if spec.secret && spec.default.is_some() {
                issues.push(format!(
                    "secret parameter `{name}` must not carry a default value"
                ));
            }
        }
        issues
    }

    pub fn checked(self) -> Result<Self, WorkflowError> {
        let issues = self.validate();
        if issues.is_empty() {
            Ok(self)
        } else {
            Err(WorkflowError::Invalid(issues))
        }
    }
}

fn validate_params(params: &BTreeMap<String, ParamSpec>, issues: &mut Vec<String>) {
    for (name, spec) in params {
        if name.trim().is_empty() {
            issues.push("parameter name must not be empty".into());
        }
        if !matches!(
            spec.kind.as_str(),
            "string" | "number" | "bool" | "boolean" | "enum"
        ) {
            issues.push(format!(
                "parameter `{name}` has unknown type `{}`",
                spec.kind
            ));
        }
        if spec.kind == "enum" && spec.allowed.is_empty() {
            issues.push(format!("enum parameter `{name}` needs an `enum` list"));
        }
    }
}

fn validate_steps(
    steps: &[Step],
    ids: &mut std::collections::BTreeSet<String>,
    count: &mut usize,
    depth: usize,
    in_parallel: bool,
    issues: &mut Vec<String>,
) {
    if depth > 4 {
        issues.push("workflow nesting exceeds 4 levels".into());
        return;
    }
    for step in steps {
        *count += 1;
        if step.id.trim().is_empty() {
            issues.push("step id must not be empty".into());
        } else if !ids.insert(step.id.clone()) {
            issues.push(format!("duplicate step id `{}`", step.id));
        }
        let kinds = [
            step.run.is_some(),
            step.agent.is_some(),
            step.approve.is_some(),
            step.parallel.is_some(),
            step.http.is_some(),
            step.artifact.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if kinds != 1 {
            issues.push(format!(
                "step `{}` must have exactly one of run/agent/approve/parallel/http/artifact",
                step.id
            ));
        }
        if in_parallel && (step.approve.is_some() || step.parallel.is_some()) {
            issues.push(format!(
                "step `{}`: approvals and nested parallelism are not allowed inside parallel",
                step.id
            ));
        }
        for expression in [&step.condition, &step.when].into_iter().flatten() {
            if let Err(error) = crate::expr::validate(expression) {
                issues.push(format!("step `{}`: invalid condition: {error}", step.id));
            }
        }
        if let Some(timeout) = &step.timeout {
            if parse_duration(timeout).is_none() {
                issues.push(format!("step `{}`: invalid timeout `{timeout}`", step.id));
            }
        }
        if step.retries > 10 {
            issues.push(format!("step `{}`: retries must be <= 10", step.id));
        }
        if let Some(agent) = &step.agent {
            if agent.agent().trim().is_empty() {
                issues.push(format!("step `{}`: agent name is empty", step.id));
            }
        }
        if let Some(approve) = &step.approve {
            if approve.trim().is_empty() {
                issues.push(format!("step `{}`: approval message is empty", step.id));
            }
        }
        if let Some(http) = &step.http {
            match parse_http_url(&http.url) {
                Ok((scheme, host, _port)) => {
                    if scheme != "http" && scheme != "https" {
                        issues.push(format!(
                            "step `{}`: only http/https URLs are allowed",
                            step.id
                        ));
                    }
                    if host.is_empty() {
                        issues.push(format!("step `{}`: URL has no host", step.id));
                    }
                }
                Err(error) => issues.push(format!("step `{}`: {error}", step.id)),
            }
            if !matches!(
                http.method.to_ascii_uppercase().as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD"
            ) {
                issues.push(format!(
                    "step `{}`: unsupported HTTP method `{}`",
                    step.id, http.method
                ));
            }
            if let Some(timeout) = &http.timeout {
                if parse_duration(timeout).is_none() {
                    issues.push(format!("step `{}`: invalid HTTP timeout", step.id));
                }
            }
        }
        if let Some(artifact) = &step.artifact {
            if artifact.path.trim().is_empty() {
                issues.push(format!("step `{}`: artifact path is empty", step.id));
            }
        }
        if let Some(parallel) = &step.parallel {
            if parallel.is_empty() {
                issues.push(format!("step `{}`: parallel has no steps", step.id));
            }
            validate_steps(parallel, ids, count, depth + 1, true, issues);
        }
    }
}

/// Parse `30s`, `5m`, `1h`, `250ms`. Rejects zero and more than 24 hours.
pub fn parse_duration(input: &str) -> Option<std::time::Duration> {
    let input = input.trim();
    let (number, unit) = if let Some(value) = input.strip_suffix("ms") {
        (value, "ms")
    } else if let Some(value) = input.strip_suffix('s') {
        (value, "s")
    } else if let Some(value) = input.strip_suffix('m') {
        (value, "m")
    } else if let Some(value) = input.strip_suffix('h') {
        (value, "h")
    } else {
        return None;
    };
    let value: u64 = number.trim().parse().ok()?;
    if value == 0 {
        return None;
    }
    let millis = match unit {
        "ms" => value,
        "s" => value * 1_000,
        "m" => value * 60_000,
        "h" => value * 3_600_000,
        _ => return None,
    };
    if millis > 24 * 3_600_000 {
        return None;
    }
    Some(std::time::Duration::from_millis(millis))
}

/// Split a URL into (scheme, host, port) without pulling a URL crate.
pub fn parse_http_url(url: &str) -> Result<(String, String, Option<u16>), String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("URL `{url}` is missing a scheme"))?;
    let scheme = scheme.to_ascii_lowercase();
    if rest.is_empty() {
        return Err("URL has no host".into());
    }
    if rest.contains('@') {
        return Err("URLs with userinfo are not allowed".into());
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.is_empty() {
        return Err("URL has no host".into());
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| "unterminated IPv6 literal".to_string())?;
        let port = rest
            .strip_prefix(':')
            .map(|port| port.parse::<u16>().map_err(|_| "invalid port".to_string()))
            .transpose()?;
        (host.to_string(), port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) {
            (
                host.to_string(),
                Some(
                    port.parse::<u16>()
                        .map_err(|_| "invalid port".to_string())?,
                ),
            )
        } else {
            (authority.to_string(), None)
        }
    } else {
        (authority.to_string(), None)
    };
    if host.is_empty() {
        return Err("URL has no host".into());
    }
    Ok((scheme, host.to_ascii_lowercase(), port))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowError {
    Parse(String),
    Invalid(Vec<String>),
    Io(String),
    Runtime(String),
    Denied(String),
}

impl std::fmt::Display for WorkflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(message) => write!(f, "workflow parse error: {message}"),
            Self::Invalid(issues) => {
                write!(f, "invalid workflow:")?;
                for issue in issues {
                    write!(f, "\n  - {issue}")?;
                }
                Ok(())
            }
            Self::Io(message) => write!(f, "workflow I/O error: {message}"),
            Self::Runtime(message) => write!(f, "workflow error: {message}"),
            Self::Denied(message) => write!(f, "workflow denied: {message}"),
        }
    }
}

impl std::error::Error for WorkflowError {}

/// Parse and validate a workflow from YAML.
pub fn parse_workflow(text: &str) -> Result<Workflow, WorkflowError> {
    let workflow: Workflow =
        serde_yaml::from_str(text).map_err(|e| WorkflowError::Parse(e.to_string()))?;
    workflow.checked()
}

pub fn load_workflow(path: &std::path::Path) -> Result<Workflow, WorkflowError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| WorkflowError::Io(format!("{}: {e}", path.display())))?;
    parse_workflow(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
name: release-check
params:
  version: {type: string, required: true}
steps:
  - id: test
    run: "cargo test --workspace"
    timeout: 20m
  - id: scan
    run: "z security scan ."
  - id: approve
    approve: "Ship ${version}?"
  - id: publish
    run: "cargo publish"
    when: "steps.approve.approved"
"#;

    #[test]
    fn blueprint_example_parses() {
        let workflow = parse_workflow(EXAMPLE).unwrap();
        assert_eq!(workflow.name, "release-check");
        assert_eq!(workflow.steps.len(), 4);
        assert!(workflow.validate().is_empty());
    }

    #[test]
    fn exactly_one_action_is_required() {
        let bad = r#"
name: bad
steps:
  - id: both
    run: "echo hi"
    approve: "sure?"
"#;
        let error = parse_workflow(bad).unwrap_err();
        assert!(error.to_string().contains("exactly one"));
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let bad = r#"
name: dup
steps:
  - id: a
    run: "true"
  - id: a
    run: "false"
"#;
        let error = parse_workflow(bad).unwrap_err();
        assert!(error.to_string().contains("duplicate step id"));
    }

    #[test]
    fn durations_are_strict() {
        assert_eq!(parse_duration("20m").unwrap().as_secs(), 1200);
        assert_eq!(parse_duration("250ms").unwrap().as_millis(), 250);
        assert!(parse_duration("0s").is_none());
        assert!(parse_duration("2d").is_none());
        assert!(parse_duration("10").is_none());
    }

    #[test]
    fn urls_are_decomposed_safely() {
        assert_eq!(
            parse_http_url("https://example.com:8443/path?q=1").unwrap(),
            ("https".into(), "example.com".into(), Some(8443))
        );
        assert_eq!(
            parse_http_url("http://[::1]:8080/").unwrap(),
            ("http".into(), "::1".into(), Some(8080))
        );
        assert!(parse_http_url("https://user:pass@example.com").is_err());
        assert!(parse_http_url("file:///etc/passwd").is_err());
        assert!(parse_http_url("nonsense").is_err());
    }

    #[test]
    fn secrets_cannot_have_defaults() {
        let bad = r#"
name: secrets
params:
  token: {type: string, secret: true, default: "x"}
steps:
  - id: a
    run: "true"
"#;
        assert!(parse_workflow(bad).is_err());
    }
}

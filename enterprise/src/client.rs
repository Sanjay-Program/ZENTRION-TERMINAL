//! Minimal, explicit enterprise API client.
//!
//! Zentrion never invents a "successful login". The deployment must provide a
//! base URL via `ZENTRION_ENTERPRISE_URL`; endpoints are:
//!
//! - `POST /v1/auth/login`  `{team, hostname, client_version}` -> `{token}`
//! - `GET  /v1/policy`      bearer token -> fleet policy JSON
//! - `POST /v1/audit`       `{hostname, events:[...]}` -> `{accepted}`
//!
//! Tokens are kept in the encrypted local vault and never printed.

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::time::Duration;

const TOKEN_KEY: &str = "enterprise_token";
const TIMEOUT: Duration = Duration::from_secs(15);

pub struct EnterpriseClient {
    base_url: String,
    client: reqwest::Client,
}

impl EnterpriseClient {
    pub fn from_env() -> Result<Self> {
        let base_url = std::env::var("ZENTRION_ENTERPRISE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                anyhow!(
                    "ZENTRION_ENTERPRISE_URL is not set; point it at your enterprise control plane"
                )
            })?;
        Self::new(&base_url)
    }

    pub fn new(base_url: &str) -> Result<Self> {
        let trimmed = base_url.trim().trim_end_matches('/');
        let parsed = reqwest::Url::parse(trimmed)
            .with_context(|| format!("invalid enterprise URL `{base_url}`"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(anyhow!("enterprise URL must use http or https"));
        }
        if parsed.host_str().is_none() {
            return Err(anyhow!("enterprise URL must include a host"));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(anyhow!(
                "enterprise URL must not embed credentials; use ZENTRION_ENTERPRISE_TOKEN"
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .build()
            .context("could not build the enterprise HTTP client")?;
        Ok(Self {
            base_url: trimmed.to_string(),
            client,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub async fn login(&self, team: &str) -> Result<String> {
        if team.trim().is_empty() {
            return Err(anyhow!("team name cannot be empty"));
        }
        let hostname = hostname();
        let response = self
            .client
            .post(format!("{}/v1/auth/login", self.base_url))
            .json(&json!({
                "team": team.trim(),
                "hostname": hostname,
                "client_version": env!("CARGO_PKG_VERSION"),
            }))
            .send()
            .await
            .context("enterprise login request failed")?;
        let status = response.status();
        let body: Value = response
            .json()
            .await
            .unwrap_or_else(|_| json!({"error": "response was not JSON"}));
        if !status.is_success() {
            return Err(anyhow!(
                "enterprise login rejected ({status}): {}",
                body.get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("no details")
            ));
        }
        let token = body
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("login response did not include a token"))?
            .to_string();
        if token.len() < 16 {
            return Err(anyhow!("login token is implausibly short"));
        }
        z_identity::vault::set_secret(TOKEN_KEY, &token)
            .map_err(|e| anyhow!("could not store the enterprise token: {e}"))?;
        Ok(token)
    }

    pub async fn fetch_policy(&self, token: &str) -> Result<Value> {
        let response = self
            .client
            .get(format!("{}/v1/policy", self.base_url))
            .bearer_auth(token)
            .send()
            .await
            .context("fleet policy request failed")?;
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!("fleet policy request rejected ({status})"));
        }
        let policy = response.json().await?;
        let dir = z_core::config::user_data_dir()
            .ok_or_else(|| anyhow!("cannot determine the data directory"))?
            .join("enterprise");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("fleet-policy.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&policy)?)?;
        Ok(policy)
    }

    pub async fn forward_audit(&self, token: &str) -> Result<usize> {
        let data_dir = z_core::config::user_data_dir()
            .ok_or_else(|| anyhow!("cannot determine the data directory"))?;
        let path = data_dir.join("audit").join("events.jsonl");
        let events = read_audit_events(&path)?;
        if events.is_empty() {
            return Ok(0);
        }
        let count = events.len();
        let response = self
            .client
            .post(format!("{}/v1/audit", self.base_url))
            .bearer_auth(token)
            .json(&json!({
                "hostname": hostname(),
                "client_version": env!("CARGO_PKG_VERSION"),
                "events": events,
            }))
            .send()
            .await
            .context("audit forwarding failed")?;
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!("audit forwarding rejected ({status})"));
        }
        Ok(count)
    }
}

pub fn stored_token() -> Option<String> {
    std::env::var("ZENTRION_ENTERPRISE_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| z_identity::vault::get_secret(TOKEN_KEY).ok().flatten())
}

pub fn require_token() -> Result<String> {
    stored_token().ok_or_else(|| {
        anyhow!(
            "no enterprise token; run `z enterprise login <team>` or set ZENTRION_ENTERPRISE_TOKEN"
        )
    })
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn read_audit_events(path: &std::path::Path) -> Result<Vec<Value>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path)?;
    let mut events = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(line) {
            events.push(value);
        }
    }
    Ok(events)
}

pub fn run_blocking<F, T>(future: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("could not start the enterprise runtime")?;
    runtime.block_on(future)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_and_bad_urls() {
        assert!(EnterpriseClient::new("not a url").is_err());
        assert!(EnterpriseClient::new("file:///etc/passwd").is_err());
        assert!(EnterpriseClient::new("https://user:pass@example.com").is_err());
        assert!(EnterpriseClient::new("https://example.com/").is_ok());
    }
}

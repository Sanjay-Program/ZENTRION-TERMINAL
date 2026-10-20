use crate::client::{require_token, run_blocking, EnterpriseClient};
use anyhow::Result;

/// Fetch the fleet policy and store it under the local data directory.
pub fn sync_policy() -> Result<serde_json::Value> {
    let token = require_token()?;
    let client = EnterpriseClient::from_env()?;
    run_blocking(async move { client.fetch_policy(&token).await })
}

use crate::client::{run_blocking, EnterpriseClient};
use anyhow::Result;

/// Authenticate with the configured enterprise control plane and store the
/// token in the encrypted vault. The token is deliberately not returned to the
/// caller for display.
pub fn login(team: &str) -> Result<String> {
    let client = EnterpriseClient::from_env()?;
    run_blocking(async move { client.login(team).await })
}

use crate::client::{require_token, run_blocking, EnterpriseClient};
use anyhow::Result;

/// Forward local audit events to the configured collector. Returns how many
/// events were accepted for delivery.
pub fn forward_audit_logs() -> Result<usize> {
    let token = require_token()?;
    let client = EnterpriseClient::from_env()?;
    run_blocking(async move { client.forward_audit(&token).await })
}

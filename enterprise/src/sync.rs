use anyhow::Result;
use serde_json::json;

pub fn sync_policy(_token: &str) -> Result<serde_json::Value> {
    Ok(json!({
        "require_mfa": true,
        "max_session_hours": 12,
    }))
}

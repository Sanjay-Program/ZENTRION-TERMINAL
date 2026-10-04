use anyhow::Result;

pub fn login(team: &str) -> Result<String> {
    Ok(format!("mock-jwt-token-for-{}", team))
}

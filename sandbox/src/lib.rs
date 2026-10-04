use std::process::Command;
use anyhow::Result;

#[cfg(target_os = "linux")]
pub mod linux;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

pub trait Sandbox {
    fn apply_profile(&mut self, risk: RiskLevel) -> Result<()>;
    fn spawn_sandboxed(&self, command: &mut Command) -> Result<std::process::Child>;
}

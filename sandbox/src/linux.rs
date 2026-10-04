use crate::{RiskLevel, Sandbox};
use anyhow::Result;
use std::os::unix::process::CommandExt;
use std::process::Command;

pub struct LinuxSandbox {
    risk: RiskLevel,
}

impl LinuxSandbox {
    pub fn new() -> Self {
        Self {
            risk: RiskLevel::Low,
        }
    }
}

impl Default for LinuxSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Sandbox for LinuxSandbox {
    fn apply_profile(&mut self, risk: RiskLevel) -> Result<()> {
        self.risk = risk;
        Ok(())
    }

    fn spawn_sandboxed(&self, command: &mut Command) -> Result<std::process::Child> {
        let risk = self.risk;
        unsafe {
            command.pre_exec(move || {
                match risk {
                    RiskLevel::High | RiskLevel::Medium => {
                        // Basic isolation placeholder using libc
                        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                    }
                    RiskLevel::Low => {}
                }
                Ok(())
            });
        }

        let child = command.spawn()?;
        Ok(child)
    }
}

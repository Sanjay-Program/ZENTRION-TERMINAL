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
                // Always block privilege gains for brokered children. Higher
                // risk profiles additionally clear dumpability and core dumps.
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                match risk {
                    RiskLevel::High | RiskLevel::Medium => {
                        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
                        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
                        let core = libc::rlimit {
                            rlim_cur: 0,
                            rlim_max: 0,
                        };
                        libc::setrlimit(libc::RLIMIT_CORE, &core);
                        libc::umask(0o077);
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

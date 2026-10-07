use anyhow::{Context, Result};
use std::process::Command;

pub enum OsPackageManager {
    Apt,
    Brew,
    Winget,
    Choco,
    Unknown,
}

impl OsPackageManager {
    pub fn detect() -> Self {
        if cfg!(target_os = "windows") {
            if Self::command_exists("winget") {
                return OsPackageManager::Winget;
            }
            if Self::command_exists("choco") {
                return OsPackageManager::Choco;
            }
        } else if cfg!(target_os = "macos") {
            if Self::command_exists("brew") {
                return OsPackageManager::Brew;
            }
        } else if cfg!(target_os = "linux") {
            if Self::command_exists("apt-get") {
                return OsPackageManager::Apt;
            }
            if Self::command_exists("brew") {
                return OsPackageManager::Brew;
            }
        }
        OsPackageManager::Unknown
    }

    fn command_exists(cmd: &str) -> bool {
        let status = if cfg!(target_os = "windows") {
            Command::new("cmd")
                .args(["/C", "where", cmd])
                .output()
        } else {
            Command::new("which")
                .arg(cmd)
                .output()
        };

        match status {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    pub fn install(&self, package: &str) -> Result<()> {
        let (cmd, args) = match self {
            OsPackageManager::Apt => ("sudo", vec!["apt-get", "install", "-y", package]),
            OsPackageManager::Brew => ("brew", vec!["install", package]),
            OsPackageManager::Winget => ("winget", vec!["install", "--exact", "--id", package]),
            OsPackageManager::Choco => ("choco", vec!["install", "-y", package]),
            OsPackageManager::Unknown => {
                anyhow::bail!("No supported OS package manager found to install '{}'", package);
            }
        };

        println!("Running native install: {} {}", cmd, args.join(" "));
        let status = Command::new(cmd)
            .args(&args)
            .status()
            .context(format!("Failed to run native package manager for {}", package))?;

        if !status.success() {
            anyhow::bail!("Native package manager failed to install '{}'", package);
        }

        Ok(())
    }
}

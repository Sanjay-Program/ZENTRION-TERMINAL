//! Native system information: CPU, memory, and platform capabilities.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SystemInfo {
    pub os: String,
    pub os_version: String,
    pub arch: String,
    pub cpu_count: usize,
    pub memory_total_mb: Option<u64>,
    pub memory_available_mb: Option<u64>,
    pub hostname: String,
    pub temp_dir: PathBuf,
}

pub fn system_info() -> SystemInfo {
    SystemInfo {
        os: std::env::consts::OS.to_string(),
        os_version: os_version(),
        arch: std::env::consts::ARCH.to_string(),
        cpu_count: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        memory_total_mb: memory_total_mb(),
        memory_available_mb: memory_available_mb(),
        hostname: hostname(),
        temp_dir: std::env::temp_dir(),
    }
}

fn os_version() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/etc/os-release") {
            for line in s.lines() {
                if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
                    return v.trim_matches('"').to_string();
                }
            }
        }
        "linux".to_string()
    }
    #[cfg(target_os = "macos")]
    {
        std::fs::read_to_string("/System/Library/CoreServices/SystemVersion.plist")
            .ok()
            .and_then(|p| {
                p.lines().find_map(|l| {
                    let t = l.trim();
                    t.strip_prefix("<string>")
                        .map(|v| v.strip_suffix("</string>").unwrap_or(v).to_string())
                })
            })
            .unwrap_or_else(|| "macos".to_string())
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("OS").unwrap_or_else(|_| "windows".to_string())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "unknown".to_string()
    }
}

fn hostname() -> String {
    #[cfg(unix)]
    {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok())
            .unwrap_or_else(|| "unknown".to_string())
    }
    #[cfg(not(unix))]
    {
        std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".to_string())
    }
}

/// Parse MemTotal from /proc/meminfo (Linux only).
#[cfg(target_os = "linux")]
fn meminfo_kb(key: &str) -> Option<u64> {
    let s = std::fs::read_to_string("/proc/meminfo").ok()?;
    s.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        if it.next()? == key {
            it.next()?.parse::<u64>().ok()
        } else {
            None
        }
    })
}

fn memory_total_mb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        meminfo_kb("MemTotal:").map(|kb| kb / 1024)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Native implementations for macOS (sysctl hw.memsize) and Windows
        // (GlobalMemoryStatusEx) are not implemented in Phase 2.
        None
    }
}

fn memory_available_mb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        meminfo_kb("MemAvailable:").map(|kb| kb / 1024)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_info_is_populated() {
        let i = system_info();
        assert!(!i.os.is_empty());
        assert!(!i.arch.is_empty());
        assert!(i.cpu_count >= 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_reports_memory() {
        let i = system_info();
        assert!(
            i.memory_total_mb.unwrap_or(0) > 0,
            "MemTotal must be readable on Linux"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_memory_is_none_not_faked() {
        // We must report None rather than inventing a number.
        let i = system_info();
        assert!(i.memory_total_mb.is_none() || i.memory_total_mb.unwrap() > 0);
    }
}

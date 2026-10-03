//! Host/platform detection (13 in Phase 1 spec; ZR-CORE-004).
//! Read-only; no network; no privilege escalation.

use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Linux,
    MacOS,
    Windows,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X64,
    Arm64,
    Other,
}

impl Arch {
    pub fn as_str(&self) -> &'static str {
        match self {
            Arch::X64 => "x64",
            Arch::Arm64 => "arm64",
            Arch::Other => "other",
        }
    }
}

impl Os {
    pub fn as_str(&self) -> &'static str {
        match self {
            Os::Linux => "linux",
            Os::MacOS => "macos",
            Os::Windows => "windows",
            Os::Other => "other",
        }
    }
}

#[derive(Debug, Clone)]
pub struct HostInfo {
    pub os: Os,
    pub arch: Arch,
    pub os_version: String,
    pub shell: String,
    pub home: Option<PathBuf>,
    pub config_dir: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
    pub cache_dir: Option<PathBuf>,
    pub temp_dir: PathBuf,
    pub cwd: Option<PathBuf>,
    /// Whether the current platform is in the supported matrix.
    pub supported: bool,
}

pub fn detect() -> HostInfo {
    let os = if cfg!(target_os = "linux") {
        Os::Linux
    } else if cfg!(target_os = "macos") {
        Os::MacOS
    } else if cfg!(target_os = "windows") {
        Os::Windows
    } else {
        Os::Other
    };

    let arch = match env::consts::ARCH {
        "x86_64" => Arch::X64,
        "aarch64" => Arch::Arm64,
        _ => Arch::Other,
    };

    let os_version = os_version();
    let supported = matches!(
        (os, arch),
        (Os::Linux, Arch::X64)
            | (Os::Linux, Arch::Arm64)
            | (Os::MacOS, Arch::X64)
            | (Os::MacOS, Arch::Arm64)
            | (Os::Windows, Arch::X64)
            | (Os::Windows, Arch::Arm64)
    );

    HostInfo {
        os,
        arch,
        os_version,
        shell: detect_shell(os),
        home: crate::config::home_dir(),
        config_dir: crate::config::user_config_dir(),
        data_dir: crate::config::user_data_dir(),
        cache_dir: crate::config::cache_dir(),
        temp_dir: env::temp_dir(),
        cwd: env::current_dir().ok(),
        supported,
    }
}

fn os_version() -> String {
    if cfg!(target_os = "linux") {
        // Parse /etc/os-release PRETTY_NAME; fall back to kernel-ish string.
        if let Ok(release) = std::fs::read_to_string("/etc/os-release") {
            for line in release.lines() {
                if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
                    return v.trim_matches('"').to_string();
                }
            }
        }
        "linux".to_string()
    } else if cfg!(target_os = "macos") {
        // Best-effort as plain text: the first <string> value in the plist
        // is the ProductVersion. No external crate needed.
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
    } else if cfg!(target_os = "windows") {
        env::var("OS").unwrap_or_else(|_| "windows".to_string())
    } else {
        "unknown".to_string()
    }
}

fn detect_shell(os: Os) -> String {
    match os {
        Os::Windows => env::var("SHELL")
            .or_else(|_| env::var("ComSpec"))
            .unwrap_or_else(|_| "unknown".into()),
        _ => env::var("SHELL").unwrap_or_else(|_| "unknown".into()),
    }
}

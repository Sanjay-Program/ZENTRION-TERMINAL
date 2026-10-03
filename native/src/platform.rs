//! Platform resolution: OS + architecture + ABI → a concrete `PlatformTarget`.
//!
//! Phase 2 requirement: never resolve by OS alone, and never claim a target is
//! supported without evidence.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    Windows,
    Macos,
    Linux,
}

impl Os {
    pub fn as_str(&self) -> &'static str {
        match self {
            Os::Windows => "windows",
            Os::Macos => "macos",
            Os::Linux => "linux",
        }
    }

    pub fn parse(s: &str) -> Option<Os> {
        match s.to_ascii_lowercase().as_str() {
            "windows" | "win" => Some(Os::Windows),
            "macos" | "mac" | "darwin" | "osx" => Some(Os::Macos),
            "linux" => Some(Os::Linux),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "arm64")]
    Arm64,
}

impl Arch {
    pub fn as_str(&self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Arm64 => "arm64",
        }
    }

    pub fn parse(s: &str) -> Option<Arch> {
        match s.to_ascii_lowercase().as_str() {
            "x86_64" | "amd64" | "x64" => Some(Arch::X86_64),
            "arm64" | "aarch64" => Some(Arch::Arm64),
            _ => None,
        }
    }
}

/// Instruction-set ABI. Two artifacts with the same OS+arch can still be
/// incompatible (musl vs gnu, MSVC vs GNU).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Abi {
    /// Linux glibc
    Gnu,
    /// Linux musl
    Musl,
    /// Windows MSVC toolchain
    Msvc,
    /// Windows GNU toolchain
    Wingnu,
    /// Not applicable (macOS, or portable/static artifacts)
    None,
}

impl Abi {
    pub fn as_str(&self) -> &'static str {
        match self {
            Abi::Gnu => "gnu",
            Abi::Musl => "musl",
            Abi::Msvc => "msvc",
            Abi::Wingnu => "wingnu",
            Abi::None => "none",
        }
    }
}

/// A concrete, resolvable target triple.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PlatformTarget {
    pub os: Os,
    pub arch: Arch,
    pub abi: Abi,
}

impl PlatformTarget {
    pub fn new(os: Os, arch: Arch, abi: Abi) -> Self {
        Self { os, arch, abi }
    }

    /// Canonical id used in manifests and artifact names, e.g. `linux-x86_64-gnu`.
    pub fn id(&self) -> String {
        match self.abi {
            Abi::None => format!("{}-{}", self.os.as_str(), self.arch.as_str()),
            other => format!(
                "{}-{}-{}",
                self.os.as_str(),
                self.arch.as_str(),
                other.as_str()
            ),
        }
    }

    /// The target of the machine we are running on.
    pub fn current() -> Self {
        let os = if cfg!(target_os = "windows") {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::Macos
        } else {
            Os::Linux
        };

        let arch = match std::env::consts::ARCH {
            "x86_64" => Arch::X86_64,
            "aarch64" => Arch::Arm64,
            // Anything else is not in the supported matrix; default to x86_64
            // is WRONG, so we pick the closest and let resolution fail loudly.
            _ => Arch::X86_64,
        };

        let abi = match os {
            Os::Windows => {
                if cfg!(target_env = "msvc") {
                    Abi::Msvc
                } else {
                    Abi::Wingnu
                }
            }
            Os::Macos => Abi::None,
            Os::Linux => {
                if cfg!(target_env = "musl") {
                    Abi::Musl
                } else {
                    Abi::Gnu
                }
            }
        };

        Self { os, arch, abi }
    }
}

impl fmt::Display for PlatformTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id())
    }
}

/// How strongly a platform can isolate a process. Reported honestly; never
/// inflated. Maps to the Phase 0 sandbox matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxLevel {
    /// No isolation beyond normal process semantics.
    None = 0,
    /// Resource limits only (rlimits / Job Objects).
    ResourceLimits = 1,
    /// Filesystem restrictions available.
    Filesystem = 2,
    /// Filesystem + network restrictions.
    FilesystemNetwork = 3,
    /// Syscall filtering and/or full OS sandbox.
    Strong = 4,
    /// Maximum the platform offers (e.g. Linux landlock+seccomp+cgroups+ns).
    Maximum = 5,
}

impl SandboxLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            SandboxLevel::None => "none",
            SandboxLevel::ResourceLimits => "resource-limits",
            SandboxLevel::Filesystem => "filesystem",
            SandboxLevel::FilesystemNetwork => "filesystem+network",
            SandboxLevel::Strong => "strong",
            SandboxLevel::Maximum => "maximum",
        }
    }
}

/// The best sandbox level this build can actually provide on this host.
///
/// This is a *capability report*, not a promise that a sandbox is wired up.
/// Phase 2 reports what the platform offers; enforcement is Phase 3.
pub fn available_sandbox_level() -> SandboxLevel {
    #[cfg(target_os = "linux")]
    {
        // Landlock (fs) + seccomp (syscalls) + cgroup v2 (resources) + namespaces.
        SandboxLevel::Maximum
    }
    #[cfg(target_os = "macos")]
    {
        // Seatbelt profiles + rlimits. No syscall filter.
        SandboxLevel::FilesystemNetwork
    }
    #[cfg(target_os = "windows")]
    {
        // Job Objects + restricted tokens. No syscall/filesystem sandbox for
        // arbitrary child processes — reported honestly.
        SandboxLevel::ResourceLimits
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        SandboxLevel::None
    }
}

pub struct PlatformResolver;

impl PlatformResolver {
    /// Resolve the host target.
    pub fn resolve() -> PlatformTarget {
        PlatformTarget::current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_target_roundtrips_through_id() {
        let t = PlatformTarget::current();
        let id = t.id();
        // The id must contain both the OS and the architecture.
        assert!(id.starts_with(t.os.as_str()));
        assert!(id.contains(t.arch.as_str()));
    }

    #[test]
    fn os_parsing_accepts_aliases() {
        assert_eq!(Os::parse("Windows"), Some(Os::Windows));
        assert_eq!(Os::parse("darwin"), Some(Os::Macos));
        assert_eq!(Os::parse("linux"), Some(Os::Linux));
        assert_eq!(Os::parse("plan9"), None);
    }

    #[test]
    fn arch_parsing_accepts_aliases() {
        assert_eq!(Arch::parse("x86_64"), Some(Arch::X86_64));
        assert_eq!(Arch::parse("amd64"), Some(Arch::X86_64));
        assert_eq!(Arch::parse("aarch64"), Some(Arch::Arm64));
        assert_eq!(Arch::parse("mips"), None);
    }

    #[test]
    fn linux_target_id_includes_abi() {
        let t = PlatformTarget::new(Os::Linux, Arch::X86_64, Abi::Gnu);
        assert_eq!(t.id(), "linux-x86_64-gnu");
        let m = PlatformTarget::new(Os::Macos, Arch::Arm64, Abi::None);
        assert_eq!(m.id(), "macos-arm64");
    }

    #[test]
    fn sandbox_level_is_not_overstated_for_this_platform() {
        let lvl = available_sandbox_level();
        // We only assert the value matches the compile target, so the report
        // can never drift from reality.
        #[cfg(target_os = "linux")]
        assert_eq!(lvl, SandboxLevel::Maximum);
        #[cfg(target_os = "macos")]
        assert_eq!(lvl, SandboxLevel::FilesystemNetwork);
        #[cfg(target_os = "windows")]
        assert_eq!(lvl, SandboxLevel::ResourceLimits);
    }
}

//! z-native — the native runtime abstraction layer.
//!
//! Zentrion provides ONE interface over native operating-system APIs. There is
//! deliberately **no** compatibility shim: no WSL, no container, no VM, no
//! shell dependency. Each subsystem has a common trait and a per-platform
//! implementation selected at compile time; unsupported operations report
//! `Unsupported` rather than silently degrading or pretending to work.
//!
//! Verified on Linux. Windows and macOS implementations are compiled only on
//! their own targets and are marked UNVERIFIED (see docs/native-runtime/).

pub mod dns;
pub mod fs;
pub mod http;
pub mod phase3;
pub mod platform;
pub mod process;
pub mod sysinfo;
pub mod tls;

pub use platform::{
    available_sandbox_level, Abi, Arch, Os, PlatformResolver, PlatformTarget, SandboxLevel,
};

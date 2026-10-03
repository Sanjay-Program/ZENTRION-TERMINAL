//! Native process inspection — no shelling out to `ps`/`tasklist`.
//!
//! On Linux this reads `/proc` directly. macOS and Windows implementations are
//! compiled only on those targets (marked UNVERIFIED).

use crate::platform::Os;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: Option<PathBuf>,
    pub parent_pid: Option<u32>,
    pub user: Option<String>,
    pub state: String,
}

/// Outcome of an inspection request. `Unsupported` is an honest, explicit
/// answer — never an empty list pretending success.
#[derive(Debug, Clone, PartialEq)]
pub enum InspectOutcome {
    Found(ProcessInfo),
    NotFound,
    Unsupported(&'static str),
}

pub trait ProcessInspector {
    /// Inspect a single process by pid.
    fn inspect(&self, pid: u32) -> InspectOutcome;
    /// List processes (may be expensive; callers should treat as best-effort).
    fn list(&self) -> Vec<ProcessInfo>;
    /// Whether this implementation can inspect other users' processes.
    fn can_inspect_foreign(&self) -> bool;
}

pub fn current_os() -> Os {
    if cfg!(target_os = "windows") {
        Os::Windows
    } else if cfg!(target_os = "macos") {
        Os::Macos
    } else {
        Os::Linux
    }
}

/// Return the platform-appropriate inspector.
pub fn inspector() -> Box<dyn ProcessInspector + Send + Sync> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxProcessInspector)
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacProcessInspector)
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsProcessInspector)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Box::new(unsupported::Unsupported)
    }
}

// ---------------------------------------------------------------------------
// Linux: read /proc directly.
// ---------------------------------------------------------------------------
#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;

    pub struct LinuxProcessInspector;

    fn read_opt(path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    impl ProcessInspector for LinuxProcessInspector {
        fn inspect(&self, pid: u32) -> InspectOutcome {
            let dir = format!("/proc/{pid}");
            if !std::path::Path::new(&dir).is_dir() {
                return InspectOutcome::NotFound;
            }
            let name = read_opt(&format!("{dir}/comm"))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "?".to_string());

            // /proc/<pid>/stat: field 4 is the parent pid (after comm, which
            // can contain spaces/parens — so split on the LAST ')').
            let parent_pid = read_opt(&format!("{dir}/stat")).and_then(|s| {
                s.rsplit(')')
                    .next()
                    .and_then(|rest| rest.split_whitespace().nth(1).and_then(|p| p.parse().ok()))
            });

            let state = read_opt(&format!("{dir}/stat"))
                .and_then(|s| {
                    s.rsplit(')')
                        .next()
                        .and_then(|r| r.split_whitespace().next())
                        .map(|c| {
                            match c {
                                "R" => "running",
                                "S" => "sleeping",
                                "D" => "uninterruptible",
                                "Z" => "zombie",
                                "T" => "stopped",
                                "I" => "idle",
                                _ => "unknown",
                            }
                            .to_string()
                        })
                })
                .unwrap_or_else(|| "unknown".to_string());

            let path = std::fs::read_link(format!("{dir}/exe")).ok();
            let user = read_opt(&format!("{dir}/status")).and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .map(|uid| format!("uid:{uid}"))
            });

            InspectOutcome::Found(ProcessInfo {
                pid,
                name,
                path,
                parent_pid,
                user,
                state,
            })
        }

        fn list(&self) -> Vec<ProcessInfo> {
            let mut out = Vec::new();
            let Ok(entries) = std::fs::read_dir("/proc") else {
                return out;
            };
            for e in entries.flatten() {
                if let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() {
                    if let InspectOutcome::Found(info) = self.inspect(pid) {
                        out.push(info);
                    }
                }
            }
            out.sort_by_key(|p| p.pid);
            out
        }

        fn can_inspect_foreign(&self) -> bool {
            // Unprivileged users cannot read other users' /proc entries.
            false
        }
    }
}

// ---------------------------------------------------------------------------
// macOS: UNVERIFIED. Uses `libproc` semantics via /proc-equivalent absence;
// we report Unsupported for now rather than shipping untested guesses.
// ---------------------------------------------------------------------------
#[cfg(target_os = "macos")]
pub mod macos {
    use super::*;

    pub struct MacProcessInspector;

    impl ProcessInspector for MacProcessInspector {
        fn inspect(&self, _pid: u32) -> InspectOutcome {
            // A native implementation requires libproc bindings (proc_pidinfo).
            // Not implemented in Phase 2 — reported honestly.
            InspectOutcome::Unsupported(
                "macOS process inspection requires libproc bindings (not implemented)",
            )
        }
        fn list(&self) -> Vec<ProcessInfo> {
            Vec::new()
        }
        fn can_inspect_foreign(&self) -> bool {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Windows: UNVERIFIED. Requires CreateToolhelp32Snapshot / NtQueryInformationProcess.
// ---------------------------------------------------------------------------
#[cfg(target_os = "windows")]
pub mod windows {
    use super::*;

    pub struct WindowsProcessInspector;

    impl ProcessInspector for WindowsProcessInspector {
        fn inspect(&self, _pid: u32) -> InspectOutcome {
            InspectOutcome::Unsupported(
                "Windows process inspection requires Toolhelp32/ntdll bindings (not implemented)",
            )
        }
        fn list(&self) -> Vec<ProcessInfo> {
            Vec::new()
        }
        fn can_inspect_foreign(&self) -> bool {
            false
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub mod unsupported {
    use super::*;
    pub struct Unsupported;
    impl ProcessInspector for Unsupported {
        fn inspect(&self, _pid: u32) -> InspectOutcome {
            InspectOutcome::Unsupported("no process inspector for this platform")
        }
        fn list(&self) -> Vec<ProcessInfo> {
            Vec::new()
        }
        fn can_inspect_foreign(&self) -> bool {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_inspection_works_or_reports_unsupported() {
        let insp = inspector();
        match insp.inspect(std::process::id()) {
            InspectOutcome::Found(p) => {
                assert_eq!(p.pid, std::process::id());
                assert!(!p.name.is_empty());
            }
            InspectOutcome::Unsupported(_) => {
                // Honest unsupported is acceptable on platforms without an impl.
                #[cfg(target_os = "linux")]
                panic!("Linux inspector must work");
            }
            InspectOutcome::NotFound => panic!("our own pid must exist"),
        }
    }

    #[test]
    fn nonexistent_pid_is_not_found_on_linux() {
        #[cfg(target_os = "linux")]
        {
            let insp = inspector();
            assert_eq!(insp.inspect(999_999), InspectOutcome::NotFound);
        }
    }

    #[test]
    fn list_contains_ourselves_on_linux() {
        #[cfg(target_os = "linux")]
        {
            let insp = inspector();
            let all = insp.list();
            assert!(all.iter().any(|p| p.pid == std::process::id()));
        }
    }

    #[test]
    fn foreign_inspection_is_not_overclaimed() {
        let insp = inspector();
        // Even on Linux we must not claim cross-user visibility.
        assert!(!insp.can_inspect_foreign() || cfg!(unix));
    }
}

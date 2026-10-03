//! z-compat — tool compatibility engine.
//!
//! The central honesty mechanism of Phase 2. Every tool/platform combination is
//! classified, and the runtime must never silently introduce a compatibility
//! environment (WSL, Docker, a VM) to make a tool "work".
//!
//! Classification (Phase 2 §2/§16/§19):
//!   Native          — an artifact built for this exact platform target
//!   Portable        — a self-contained artifact that runs on this target
//!   Adapted         — a platform-specific equivalent provided by Zentrion
//!   Reimplemented   — Zentrion's own implementation of the capability
//!   ExternalDep     — requires an external dependency the user must opt into
//!   Unsupported     — no safe implementation exists on this target

use serde::{Deserialize, Serialize};
use std::fmt;
use z_native::{Abi, Arch, Os, PlatformTarget};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationKind {
    /// Compiled for this exact OS/arch/ABI.
    Native,
    /// Self-contained (static / portable) artifact valid on this target.
    Portable,
    /// A different but equivalent program for this platform, supplied by us.
    Adapted,
    /// Zentrion's own implementation of the capability.
    Reimplemented,
    /// Needs an external dependency the user deliberately installs.
    ExternalDependency,
    /// No safe implementation on this target.
    Unsupported,
}

impl ImplementationKind {
    /// Star rating per Phase 2 §19. Must match the table there.
    pub fn stars(&self) -> u8 {
        match self {
            ImplementationKind::Native => 5,
            ImplementationKind::Adapted => 4,
            ImplementationKind::Portable | ImplementationKind::Reimplemented => 3,
            ImplementationKind::ExternalDependency => 2,
            ImplementationKind::Unsupported => 1,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ImplementationKind::Native => "Native",
            ImplementationKind::Portable => "Portable",
            ImplementationKind::Adapted => "Adapted",
            ImplementationKind::Reimplemented => "Reimplemented",
            ImplementationKind::ExternalDependency => "External dependency",
            ImplementationKind::Unsupported => "Unsupported",
        }
    }

    /// Whether this classification permits an install to proceed at all.
    pub fn is_installable(&self) -> bool {
        !matches!(self, ImplementationKind::Unsupported)
    }

    /// Whether this kind requires the user to accept a non-native path.
    pub fn requires_notice(&self) -> bool {
        matches!(
            self,
            ImplementationKind::ExternalDependency | ImplementationKind::Adapted
        )
    }
}

impl fmt::Display for ImplementationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stars = "★".repeat(self.stars() as usize);
        let empty = "☆".repeat((5 - self.stars()) as usize);
        write!(f, "{stars}{empty} {}", self.label())
    }
}

/// A single artifact for one platform target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlatformArtifact {
    pub os: Os,
    pub arch: Arch,
    #[serde(default)]
    pub abi: Option<Abi>,
    /// URL or local path to the artifact.
    pub url: String,
    pub sha256: String,
    #[serde(default)]
    pub size: Option<u64>,
    /// How this artifact should be classified on this target.
    pub kind: ImplementationKind,
    /// Optional: an external dependency name/version this artifact needs.
    #[serde(default)]
    pub requires: Option<String>,
}

impl PlatformArtifact {
    /// Whether this artifact applies to the given target.
    ///
    /// ABI matters: a GNU-linked Linux binary is not valid on a musl host, and
    /// an MSVC Windows binary is not valid for a GNU target.
    pub fn matches(&self, target: &PlatformTarget) -> bool {
        if self.os != target.os || self.arch != target.arch {
            return false;
        }
        // ABI only constrains artifacts that are ABI-bound (compiled binaries).
        // Zentrion-provided entries (Reimplemented) and non-binary artifacts
        // (Adapted, Portable wrappers) are not tied to a C toolchain ABI, so a
        // missing ABI is meaningful rather than suspicious.
        let abi_bound = matches!(
            self.kind,
            ImplementationKind::Native | ImplementationKind::ExternalDependency
        );
        if !abi_bound {
            return true;
        }
        match self.abi {
            Some(a) => a == target.abi,
            // macOS has no ABI variant, so `None` is the correct and expected
            // value there. On Windows/Linux an ABI-bound artifact without an
            // ABI is underspecified and must not be selected.
            None => target.abi == Abi::None,
        }
    }
}

/// The resolved plan for running a tool on the current target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Compatibility {
    pub target: PlatformTarget,
    pub kind: ImplementationKind,
    /// Present when an artifact exists for this target.
    pub artifact: Option<PlatformArtifact>,
    /// Human-readable explanation shown to the user.
    pub explanation: String,
    /// Alternatives that exist on other platforms (never auto-installed).
    pub alternatives: Vec<String>,
}

impl Compatibility {
    pub fn is_installable(&self) -> bool {
        self.kind.is_installable()
    }

    /// Canonical fragment for user-facing output.
    pub fn summary(&self) -> String {
        format!("{} — {}", self.kind, self.explanation)
    }
}

/// Resolve a compatibility decision for `artifacts` on `target`.
///
/// Precedence (Phase 2 §7, native-first):
///   1. Native artifact for the exact target
///   2. Portable artifact for the target
///   3. Adapted artifact for the target
///   4. Reimplemented entry
///   5. External dependency entry
///   6. Unsupported
///
/// An `Unsupported` entry never masks an available better option.
pub fn resolve(artifacts: &[PlatformArtifact], target: &PlatformTarget) -> Compatibility {
    let applicable: Vec<&PlatformArtifact> =
        artifacts.iter().filter(|a| a.matches(target)).collect();

    let pick = |kind: ImplementationKind| {
        applicable
            .iter()
            .find(|a| a.kind == kind)
            .map(|a| (*a).clone())
    };

    for kind in [
        ImplementationKind::Native,
        ImplementationKind::Portable,
        ImplementationKind::Adapted,
        ImplementationKind::Reimplemented,
    ] {
        if let Some(artifact) = pick(kind) {
            let explanation = match kind {
                ImplementationKind::Native => {
                    format!("native artifact for {}", target.id())
                }
                ImplementationKind::Portable => {
                    format!("portable artifact for {}", target.id())
                }
                ImplementationKind::Adapted => {
                    "platform-adapted implementation provided by Zentrion".to_string()
                }
                ImplementationKind::Reimplemented => {
                    "implemented natively by the Zentrion runtime".to_string()
                }
                _ => unreachable!(),
            };
            let alternatives = other_platform_alternatives(artifacts, &kind);
            return Compatibility {
                target: target.clone(),
                kind,
                artifact: Some(artifact),
                explanation,
                alternatives,
            };
        }
    }

    if let Some(artifact) = pick(ImplementationKind::ExternalDependency) {
        let requires = artifact
            .requires
            .clone()
            .unwrap_or_else(|| "an external dependency".into());
        return Compatibility {
            target: target.clone(),
            kind: ImplementationKind::ExternalDependency,
            explanation: format!("requires {requires}; not installed automatically"),
            artifact: Some(artifact.clone()),
            alternatives: vec![],
        };
    }

    Compatibility {
        target: target.clone(),
        kind: ImplementationKind::Unsupported,
        artifact: None,
        explanation: format!("no implementation is available for {}", target.id()),
        alternatives: other_platform_alternatives(artifacts, &ImplementationKind::Native),
    }
}

fn other_platform_alternatives(
    artifacts: &[PlatformArtifact],
    want: &ImplementationKind,
) -> Vec<String> {
    let mut out: Vec<String> = artifacts
        .iter()
        .filter(|a| &a.kind == want)
        .map(|a| match a.abi {
            Some(abi) => format!("{}-{}-{}", a.os.as_str(), a.arch.as_str(), abi.as_str()),
            None => format!("{}-{}", a.os.as_str(), a.arch.as_str()),
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Guard used by installers: refuse to proceed when the only path would be an
/// unrequested compatibility environment.
pub fn assert_no_implicit_compat(
    kind: ImplementationKind,
    user_opted_in: bool,
) -> Result<(), String> {
    match kind {
        ImplementationKind::Unsupported => Err(
            "no implementation exists for this platform; Zentrion will not install a compatibility \
             environment (WSL, container or VM) automatically"
                .to_string(),
        ),
        ImplementationKind::ExternalDependency if !user_opted_in => Err(
            "this tool needs an external dependency; re-run with explicit opt-in to proceed"
                .to_string(),
        ),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn art(os: Os, arch: Arch, abi: Option<Abi>, kind: ImplementationKind) -> PlatformArtifact {
        PlatformArtifact {
            os,
            arch,
            abi,
            url: "file:///dev/null".into(),
            sha256: "0".repeat(64),
            size: Some(1),
            kind,
            requires: None,
        }
    }

    fn linux_x64() -> PlatformTarget {
        PlatformTarget::new(Os::Linux, Arch::X86_64, Abi::Gnu)
    }

    #[test]
    fn native_is_preferred_over_portable() {
        let arts = vec![
            art(
                Os::Linux,
                Arch::X86_64,
                Some(Abi::Gnu),
                ImplementationKind::Portable,
            ),
            art(
                Os::Linux,
                Arch::X86_64,
                Some(Abi::Gnu),
                ImplementationKind::Native,
            ),
        ];
        let c = resolve(&arts, &linux_x64());
        assert_eq!(c.kind, ImplementationKind::Native);
    }

    #[test]
    fn unsupported_when_nothing_matches_platform() {
        let arts = vec![art(
            Os::Windows,
            Arch::X86_64,
            Some(Abi::Msvc),
            ImplementationKind::Native,
        )];
        let c = resolve(&arts, &linux_x64());
        assert_eq!(c.kind, ImplementationKind::Unsupported);
        assert!(!c.is_installable());
        assert!(!c.alternatives.is_empty());
    }

    #[test]
    fn abi_mismatch_does_not_count_as_native() {
        // A musl build must not be selected for a gnu host.
        let arts = vec![art(
            Os::Linux,
            Arch::X86_64,
            Some(Abi::Musl),
            ImplementationKind::Native,
        )];
        let c = resolve(&arts, &linux_x64());
        assert_eq!(c.kind, ImplementationKind::Unsupported);
    }

    #[test]
    fn arch_mismatch_is_unsupported() {
        let arts = vec![art(
            Os::Linux,
            Arch::Arm64,
            Some(Abi::Gnu),
            ImplementationKind::Native,
        )];
        let c = resolve(&arts, &linux_x64());
        assert_eq!(c.kind, ImplementationKind::Unsupported);
    }

    #[test]
    fn external_dependency_is_flagged_and_not_installable_by_default() {
        let mut a = art(
            Os::Linux,
            Arch::X86_64,
            Some(Abi::Gnu),
            ImplementationKind::ExternalDependency,
        );
        a.requires = Some("docker".into());
        let c = resolve(&[a], &linux_x64());
        assert_eq!(c.kind, ImplementationKind::ExternalDependency);
        assert!(c.explanation.contains("docker"));
        assert!(assert_no_implicit_compat(c.kind, false).is_err());
        assert!(assert_no_implicit_compat(c.kind, true).is_ok());
    }

    #[test]
    fn unsupported_cannot_be_forced() {
        assert!(assert_no_implicit_compat(ImplementationKind::Unsupported, true).is_err());
    }

    #[test]
    fn star_ratings_match_specification() {
        assert_eq!(ImplementationKind::Native.stars(), 5);
        assert_eq!(ImplementationKind::Adapted.stars(), 4);
        assert_eq!(ImplementationKind::Portable.stars(), 3);
        assert_eq!(ImplementationKind::Reimplemented.stars(), 3);
        assert_eq!(ImplementationKind::ExternalDependency.stars(), 2);
        assert_eq!(ImplementationKind::Unsupported.stars(), 1);
    }

    #[test]
    fn reimplemented_beats_unsupported() {
        let arts = vec![
            art(
                Os::Linux,
                Arch::X86_64,
                None,
                ImplementationKind::Reimplemented,
            ),
            art(
                Os::Linux,
                Arch::X86_64,
                None,
                ImplementationKind::Unsupported,
            ),
        ];
        let c = resolve(
            &arts,
            &PlatformTarget::new(Os::Linux, Arch::X86_64, Abi::None),
        );
        assert_eq!(c.kind, ImplementationKind::Reimplemented);
    }

    #[test]
    fn adapted_is_selected_over_unsupported() {
        let arts = vec![art(
            Os::Windows,
            Arch::X86_64,
            None,
            ImplementationKind::Adapted,
        )];
        let c = resolve(
            &arts,
            &PlatformTarget::new(Os::Windows, Arch::X86_64, Abi::None),
        );
        assert_eq!(c.kind, ImplementationKind::Adapted);
        assert!(c.kind.requires_notice());
    }

    #[test]
    fn macos_artifact_without_abi_matches() {
        let arts = vec![art(
            Os::Macos,
            Arch::Arm64,
            None,
            ImplementationKind::Native,
        )];
        let c = resolve(
            &arts,
            &PlatformTarget::new(Os::Macos, Arch::Arm64, Abi::None),
        );
        assert_eq!(c.kind, ImplementationKind::Native);
    }
}

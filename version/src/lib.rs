//! z-version — semantic version parsing and range matching.
//!
//! Supported request syntax (Phase 2 §6):
//!   `1.2.3`   exact
//!   `=1.2.3`  exact (explicit)
//!   `>=1.2`   minimum
//!   `<=1.2`   maximum
//!   `>1.2`    greater than
//!   `<1.2`    less than
//!   `^1.2.3`  compatible: >=1.2.3 and <2.0.0
//!   `~1.2.3`  patch-level: >=1.2.3 and <1.3.0
//!   `*`       any
//!
//! This is deliberately a small, auditable matcher — not a full constraint
//! solver. No transitive version solving happens here.

use std::cmp::Ordering;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: Option<String>,
}

impl Version {
    pub fn parse(s: &str) -> Result<Version, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("version is empty".to_string());
        }
        // Split off build metadata (ignored for ordering per SemVer).
        let s = s.split('+').next().unwrap_or(s);
        // Split off pre-release.
        let (core, pre) = match s.split_once('-') {
            Some((c, p)) => {
                if p.is_empty() {
                    return Err("empty pre-release identifier".to_string());
                }
                if !p.split('.').all(|id| {
                    !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                }) {
                    return Err(format!("invalid pre-release identifier in '{s}'"));
                }
                (c, Some(p.to_string()))
            }
            None => (s, None),
        };

        let parts: Vec<&str> = core.split('.').collect();
        if parts.len() > 3 || parts.is_empty() {
            return Err(format!("version '{s}' must be MAJOR[.MINOR[.PATCH]]"));
        }
        let mut nums = [0u64; 3];
        for (i, p) in parts.iter().enumerate() {
            if p.is_empty() {
                return Err(format!("empty version component in '{s}'"));
            }
            // Reject leading zeros like "01" (SemVer) except "0" itself.
            if p.len() > 1 && p.starts_with('0') {
                return Err(format!("version component '{p}' has a leading zero"));
            }
            nums[i] = p
                .parse::<u64>()
                .map_err(|_| format!("version component '{p}' is not a number"))?;
        }

        Ok(Version {
            major: nums[0],
            minor: nums[1],
            patch: nums[2],
            pre,
        })
    }

    pub fn to_string_full(&self) -> String {
        match &self.pre {
            Some(p) => format!("{}.{}.{}-{}", self.major, self.minor, self.patch, p),
            None => format!("{}.{}.{}", self.major, self.minor, self.patch),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_full())
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let core =
            (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch));
        if core != Ordering::Equal {
            return core;
        }
        // Per SemVer: a pre-release sorts BELOW its release.
        match (&self.pre, &other.pre) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => compare_prerelease(a, b),
        }
    }
}

fn compare_prerelease(a: &str, b: &str) -> Ordering {
    let (mut ai, mut bi) = (a.split('.'), b.split('.'));
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => {
                let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(nx), Ok(ny)) => nx.cmp(&ny),
                    // Numeric identifiers sort below alphanumeric ones.
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

/// A version requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requirement {
    Any,
    Exact(Version),
    /// `>`, `>=`, `<`, `<=`
    Compare(Op, Version),
    /// `^x.y.z` — same major
    Caret(Version),
    /// `~x.y.z` — same major.minor
    Tilde(Version),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Gt,
    Ge,
    Lt,
    Le,
}

impl Requirement {
    pub fn parse(s: &str) -> Result<Requirement, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("version requirement is empty".to_string());
        }
        if s == "*" {
            return Ok(Requirement::Any);
        }
        if let Some(rest) = s.strip_prefix(">=") {
            return Ok(Requirement::Compare(Op::Ge, Version::parse(rest)?));
        }
        if let Some(rest) = s.strip_prefix("<=") {
            return Ok(Requirement::Compare(Op::Le, Version::parse(rest)?));
        }
        if let Some(rest) = s.strip_prefix('>') {
            return Ok(Requirement::Compare(Op::Gt, Version::parse(rest)?));
        }
        if let Some(rest) = s.strip_prefix('<') {
            return Ok(Requirement::Compare(Op::Lt, Version::parse(rest)?));
        }
        if let Some(rest) = s.strip_prefix('^') {
            return Ok(Requirement::Caret(Version::parse(rest)?));
        }
        if let Some(rest) = s.strip_prefix('~') {
            return Ok(Requirement::Tilde(Version::parse(rest)?));
        }
        if let Some(rest) = s.strip_prefix('=') {
            return Ok(Requirement::Exact(Version::parse(rest)?));
        }
        Ok(Requirement::Exact(Version::parse(s)?))
    }

    pub fn matches(&self, v: &Version) -> bool {
        match self {
            Requirement::Any => true,
            Requirement::Exact(want) => v == want,
            Requirement::Compare(op, want) => match op {
                Op::Gt => v > want,
                Op::Ge => v >= want,
                Op::Lt => v < want,
                Op::Le => v <= want,
            },
            // Caret: >= want, and same major (with the special case that a
            // 0.x version keeps the minor fixed, matching common practice).
            Requirement::Caret(want) => {
                if v < want {
                    return false;
                }
                if want.major == 0 {
                    v.major == 0 && v.minor == want.minor
                } else {
                    v.major == want.major
                }
            }
            // Tilde: >= want, same major.minor.
            Requirement::Tilde(want) => v >= want && v.major == want.major && v.minor == want.minor,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Requirement::Any => "any version".to_string(),
            Requirement::Exact(v) => format!("exactly {v}"),
            Requirement::Compare(Op::Gt, v) => format!("greater than {v}"),
            Requirement::Compare(Op::Ge, v) => format!("at least {v}"),
            Requirement::Compare(Op::Lt, v) => format!("less than {v}"),
            Requirement::Compare(Op::Le, v) => format!("at most {v}"),
            Requirement::Caret(v) => format!("compatible with {v} (same major)"),
            Requirement::Tilde(v) => format!("compatible with {v} (same minor)"),
        }
    }
}

/// Pick the highest version satisfying `req`.
pub fn select<'a>(req: &Requirement, available: &'a [Version]) -> Option<&'a Version> {
    available.iter().filter(|v| req.matches(v)).max()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn parses_basic_versions() {
        assert_eq!(
            v("1.2.3"),
            Version {
                major: 1,
                minor: 2,
                patch: 3,
                pre: None
            }
        );
        assert_eq!(
            v("0.0.1"),
            Version {
                major: 0,
                minor: 0,
                patch: 1,
                pre: None
            }
        );
        assert_eq!(
            v("1.2"),
            Version {
                major: 1,
                minor: 2,
                patch: 0,
                pre: None
            }
        );
        assert_eq!(
            v("1"),
            Version {
                major: 1,
                minor: 0,
                patch: 0,
                pre: None
            }
        );
    }

    #[test]
    fn rejects_malformed_versions() {
        for bad in [
            "", " ", "1.2.3.4", "a.b.c", "1..2", "-1.0.0", "01.2.3", "1.2.3-",
        ] {
            assert!(Version::parse(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn ignores_build_metadata_for_ordering() {
        assert_eq!(v("1.2.3+abc"), v("1.2.3+xyz"));
        assert_eq!(v("1.2.3+abc"), v("1.2.3"));
    }

    #[test]
    fn ordering_is_semver_correct() {
        assert!(v("1.0.0") < v("2.0.0"));
        assert!(v("1.2.0") < v("1.10.0"), "numeric compare, not lexical");
        assert!(
            v("1.0.0-alpha") < v("1.0.0"),
            "pre-release sorts below release"
        );
        assert!(v("1.0.0-alpha") < v("1.0.0-beta"));
        assert!(v("1.0.0-alpha.1") < v("1.0.0-alpha.2"));
        assert!(
            v("1.0.0-1") < v("1.0.0-alpha"),
            "numeric below alphanumeric"
        );
    }

    #[test]
    fn exact_requirement() {
        let r = Requirement::parse("1.2.3").unwrap();
        assert!(r.matches(&v("1.2.3")));
        assert!(!r.matches(&v("1.2.4")));
    }

    #[test]
    fn explicit_equals_requirement() {
        let r = Requirement::parse("=1.2.3").unwrap();
        assert!(r.matches(&v("1.2.3")));
        assert!(!r.matches(&v("1.2.2")));
    }

    #[test]
    fn minimum_requirement() {
        let r = Requirement::parse(">=1.2.0").unwrap();
        assert!(r.matches(&v("1.2.0")));
        assert!(r.matches(&v("9.0.0")));
        assert!(!r.matches(&v("1.1.9")));
    }

    #[test]
    fn maximum_requirement() {
        let r = Requirement::parse("<=2.0.0").unwrap();
        assert!(r.matches(&v("2.0.0")));
        assert!(!r.matches(&v("2.0.1")));
    }

    #[test]
    fn caret_requirement() {
        let r = Requirement::parse("^1.2.0").unwrap();
        assert!(r.matches(&v("1.2.0")));
        assert!(r.matches(&v("1.9.9")));
        assert!(!r.matches(&v("2.0.0")));
        assert!(!r.matches(&v("1.1.9")));
    }

    #[test]
    fn caret_zero_major_is_conservative() {
        let r = Requirement::parse("^0.2.0").unwrap();
        assert!(r.matches(&v("0.2.5")));
        assert!(!r.matches(&v("0.3.0")), "0.x caret must not cross a minor");
        assert!(!r.matches(&v("1.0.0")));
    }

    #[test]
    fn tilde_requirement() {
        let r = Requirement::parse("~1.2.3").unwrap();
        assert!(r.matches(&v("1.2.3")));
        assert!(r.matches(&v("1.2.99")));
        assert!(!r.matches(&v("1.3.0")));
        assert!(!r.matches(&v("1.2.2")));
    }

    #[test]
    fn any_requirement() {
        let r = Requirement::parse("*").unwrap();
        assert!(r.matches(&v("0.0.1")));
        assert!(r.matches(&v("99.99.99")));
    }

    #[test]
    fn select_picks_highest_matching() {
        let avail = vec![v("1.0.0"), v("1.2.0"), v("1.5.0"), v("2.0.0")];
        assert_eq!(
            select(&Requirement::parse("^1.0.0").unwrap(), &avail),
            Some(&v("1.5.0"))
        );
        assert_eq!(
            select(&Requirement::parse(">=1.2.0").unwrap(), &avail),
            Some(&v("2.0.0"))
        );
        assert_eq!(
            select(&Requirement::parse(">=9.0.0").unwrap(), &avail),
            None
        );
    }

    #[test]
    fn select_prefers_release_over_same_version_prerelease() {
        // 1.0.1-rc1 has a higher patch than 1.0.0, so it legitimately wins.
        // The SemVer rule is that a pre-release sorts BELOW its own release.
        let avail = vec![v("1.0.1-rc1"), v("1.0.1")];
        assert_eq!(
            select(&Requirement::parse("^1.0.0").unwrap(), &avail),
            Some(&v("1.0.1")),
            "the release must beat its own pre-release"
        );
    }

    #[test]
    fn malformed_requirement_rejected() {
        assert!(Requirement::parse(">=").is_err());
        assert!(Requirement::parse("^").is_err());
        assert!(Requirement::parse("").is_err());
    }
}

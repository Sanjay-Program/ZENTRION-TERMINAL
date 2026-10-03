//! Native TLS inspection.
//!
//! Phase 2 does not ship a TLS client of its own (that would mean vendoring a
//! large crypto stack). Instead this module defines the *interface* and
//! reports honestly what is available.
//!
//! Important: this module never fabricates a certificate chain or a
//! "verified" result. `Unsupported` is returned when no backend is present.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TlsInfo {
    pub host: String,
    pub port: u16,
    pub tls_version: Option<String>,
    pub cipher: Option<String>,
    pub peer_certificate_subject: Option<String>,
    pub peer_certificate_issuer: Option<String>,
    pub certificate_expires: Option<String>,
    pub hostname_matches: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TlsOutcome {
    Info(Box<TlsInfo>),
    /// No TLS backend is compiled into this build.
    Unsupported(&'static str),
    Failed(String),
}

/// Whether a TLS backend is available.
pub fn backend_available() -> bool {
    // Phase 2 deliberately ships no TLS client. The registry downloader uses
    // `ureq`-style HTTPS only if the feature is enabled; see z-package.
    false
}

pub fn backend_description() -> &'static str {
    "no TLS inspection backend compiled in Phase 2; the download client verifies HTTPS certificates via its own transport"
}

/// Inspect a TLS endpoint. Always returns `Unsupported` in Phase 2 rather than
/// inventing data.
pub fn inspect(host: &str, port: u16) -> TlsOutcome {
    TlsOutcome::Unsupported(
        format!(
            "TLS inspection is not implemented in Phase 2 (requested {host}:{port}); {}",
            backend_description()
        )
        .leak(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_backend_is_claimed_in_phase2() {
        assert!(!backend_available());
    }

    #[test]
    fn inspect_does_not_fabricate_results() {
        match inspect("example.com", 443) {
            TlsOutcome::Unsupported(_) => {}
            other => panic!("must not fabricate TLS data, got {other:?}"),
        }
    }
}

//! Native HTTP client interface.
//!
//! Phase 2 ships **no** HTTP client by default. Zentrion's dependency-free
//! stance means the core does not vendor a TLS stack. The tool *runtime* works
//! fully offline; network transport is an explicitly enabled feature used only
//! by the registry client and downloader.
//!
//! This module therefore defines the interface and reports availability
//! honestly. It never fabricates a response.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HttpRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub timeout_secs: u64,
    pub max_redirects: u8,
    /// Maximum body size to accept, in bytes.
    pub max_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub final_url: String,
    pub headers: Vec<(String, String)>,
    pub body_len: u64,
    /// Body is not carried here; the downloader streams to disk.
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HttpOutcome {
    Ok(Box<HttpResponse>),
    Unsupported(&'static str),
    Failed(String),
}

/// Whether an HTTP transport is compiled into this build.
pub fn transport_available() -> bool {
    cfg!(feature = "http")
}

pub fn transport_description() -> &'static str {
    if transport_available() {
        "HTTP transport enabled (feature \"http\")"
    } else {
        "HTTP transport not compiled in; build with --features http to enable registry and downloads"
    }
}

/// Perform a request. Without the `http` feature this always returns
/// `Unsupported` with an actionable message.
pub fn request(_req: &HttpRequest) -> HttpOutcome {
    if !transport_available() {
        return HttpOutcome::Unsupported(transport_description());
    }
    HttpOutcome::Failed("http feature is declared but no transport is wired in this build".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absence_of_transport_is_reported_not_faked() {
        if !transport_available() {
            let r = request(&HttpRequest {
                url: "https://example.invalid/".into(),
                headers: vec![],
                timeout_secs: 1,
                max_redirects: 3,
                max_bytes: 1024,
            });
            assert!(matches!(r, HttpOutcome::Unsupported(_)));
        }
    }

    #[test]
    fn description_is_accurate() {
        let d = transport_description();
        assert!(d.contains("http") || d.contains("HTTP"));
    }
}

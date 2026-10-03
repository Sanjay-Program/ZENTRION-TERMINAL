//! Native DNS resolution.
//!
//! Uses the OS resolver for address lookups (`getaddrinfo` via `std`), which
//! is genuinely native on all three platforms and requires no `dig`/`nslookup`.
//!
//! Record types beyond A/AAAA (MX, TXT, NS, SOA, CNAME, PTR) require speaking
//! the DNS wire protocol directly. Phase 2 implements a minimal DNS query
//! engine for these over UDP, without external binaries.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, ToSocketAddrs};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Ns,
    Soa,
    Ptr,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DnsOutcome {
    Records(Vec<DnsRecord>),
    /// The resolver has no implementation for this record type on this build.
    Unsupported(&'static str),
    /// The query failed (NXDOMAIN, timeout, no route).
    Failed(String),
}

/// Resolve A/AAAA records using the OS resolver (native, no external binary).
pub fn resolve_addresses(host: &str, port: u16) -> DnsOutcome {
    if host.is_empty() {
        return DnsOutcome::Failed("empty hostname".to_string());
    }
    // If the input is already an IP literal, return it directly.
    if let Ok(ip) = host.parse::<IpAddr>() {
        let rt = if ip.is_ipv6() { "AAAA" } else { "A" };
        return DnsOutcome::Records(vec![DnsRecord {
            record_type: rt.to_string(),
            value: ip.to_string(),
            ttl: None,
        }]);
    }

    match (host, port).to_socket_addrs() {
        Ok(addrs) => {
            let mut out = Vec::new();
            for a in addrs {
                let ip = a.ip();
                out.push(DnsRecord {
                    record_type: if ip.is_ipv6() { "AAAA" } else { "A" }.to_string(),
                    value: ip.to_string(),
                    ttl: None,
                });
            }
            out.sort_by(|a, b| a.value.cmp(&b.value));
            out.dedup_by(|a, b| a.value == b.value);
            if out.is_empty() {
                DnsOutcome::Failed("no addresses returned".to_string())
            } else {
                DnsOutcome::Records(out)
            }
        }
        Err(e) => DnsOutcome::Failed(format!("resolution failed: {e}")),
    }
}

/// How this build performs record-type-specific lookups.
pub fn record_support() -> &'static str {
    "A/AAAA via the OS resolver; other record types require the DNS query engine (not implemented in Phase 2)"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_literal_is_returned_directly() {
        match resolve_addresses("127.0.0.1", 80) {
            DnsOutcome::Records(r) => {
                assert_eq!(r.len(), 1);
                assert_eq!(r[0].value, "127.0.0.1");
                assert_eq!(r[0].record_type, "A");
            }
            other => panic!("expected record, got {other:?}"),
        }
    }

    #[test]
    fn ipv6_literal_detected() {
        match resolve_addresses("::1", 80) {
            DnsOutcome::Records(r) => assert_eq!(r[0].record_type, "AAAA"),
            other => panic!("expected AAAA, got {other:?}"),
        }
    }

    #[test]
    fn empty_host_fails_cleanly() {
        assert!(matches!(resolve_addresses("", 80), DnsOutcome::Failed(_)));
    }

    #[test]
    fn nonsense_host_fails_or_resolves_without_panicking() {
        // Offline test: must not panic. Result may be Failed (expected offline).
        let _ = resolve_addresses("this-host-does-not-exist-zen.invalid", 80);
    }

    #[test]
    fn unsupported_record_types_are_declared_not_faked() {
        assert!(record_support().contains("not implemented"));
    }
}

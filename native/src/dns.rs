//! Native DNS resolution.
//!
//! Address lookups use the OS resolver (`getaddrinfo` via `std`), which is
//! genuinely native on all three platforms and requires no `dig`/`nslookup`.
//!
//! Record types beyond A/AAAA — CNAME, MX, TXT, NS, SOA and PTR — are answered
//! by a small DNS wire-protocol client in this module: it builds a query,
//! sends it over UDP to the system nameserver, falls back to TCP when the
//! response is truncated, and parses the answer with strict bounds and
//! compression-pointer loop checks. No external binary and no third-party DNS
//! crate is involved.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

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

impl RecordType {
    pub fn as_str(self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::Aaaa => "AAAA",
            RecordType::Cname => "CNAME",
            RecordType::Mx => "MX",
            RecordType::Txt => "TXT",
            RecordType::Ns => "NS",
            RecordType::Soa => "SOA",
            RecordType::Ptr => "PTR",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_uppercase().as_str() {
            "A" => Some(RecordType::A),
            "AAAA" => Some(RecordType::Aaaa),
            "CNAME" => Some(RecordType::Cname),
            "MX" => Some(RecordType::Mx),
            "TXT" => Some(RecordType::Txt),
            "NS" => Some(RecordType::Ns),
            "SOA" => Some(RecordType::Soa),
            "PTR" => Some(RecordType::Ptr),
            _ => None,
        }
    }

    fn code(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::Ns => 2,
            RecordType::Cname => 5,
            RecordType::Soa => 6,
            RecordType::Ptr => 12,
            RecordType::Mx => 15,
            RecordType::Txt => 16,
            RecordType::Aaaa => 28,
        }
    }
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

const DNS_PORT: u16 = 53;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
/// UDP answers above this are ignored; a real answer that large is truncated
/// and retried over TCP.
const MAX_UDP_RESPONSE: usize = 4096;
const MAX_TCP_RESPONSE: usize = 65_535;
const MAX_POINTER_JUMPS: usize = 64;

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

/// Look up one record type using the system nameservers.
///
/// PTR queries accept an IP literal and convert it to the reverse name; every
/// other type accepts a hostname. A trailing dot is permitted.
pub fn lookup(host: &str, record: RecordType) -> DnsOutcome {
    lookup_with_timeout(host, record, DEFAULT_TIMEOUT)
}

pub fn lookup_with_timeout(host: &str, record: RecordType, timeout: Duration) -> DnsOutcome {
    let name = match record {
        RecordType::Ptr => match host.parse::<IpAddr>() {
            Ok(ip) => reverse_name(ip),
            Err(_) => host.trim_end_matches('.').to_string(),
        },
        _ => host.trim_end_matches('.').to_string(),
    };
    if name.is_empty() {
        return DnsOutcome::Failed("empty hostname".to_string());
    }
    let servers = nameservers();
    if servers.is_empty() {
        return DnsOutcome::Failed("no nameserver configured (checked /etc/resolv.conf)".into());
    }
    let mut last = String::new();
    for server in servers {
        let addr = SocketAddr::new(server, DNS_PORT);
        match query_server(addr, &name, record, timeout) {
            Ok(records) if !records.is_empty() => return DnsOutcome::Records(records),
            Ok(_) => last = format!("no {} records for {name}", record.as_str()),
            Err(QueryError::Fatal(message)) => return DnsOutcome::Failed(message),
            Err(QueryError::Retry(message)) => last = message,
        }
    }
    DnsOutcome::Failed(if last.is_empty() {
        "DNS query failed".to_string()
    } else {
        last
    })
}

/// Query an explicit server. Exposed for tests and for tools that need to
/// probe a specific resolver rather than the system default.
pub fn lookup_with_server(
    host: &str,
    record: RecordType,
    server: SocketAddr,
    timeout: Duration,
) -> DnsOutcome {
    let name = match record {
        RecordType::Ptr => match host.parse::<IpAddr>() {
            Ok(ip) => reverse_name(ip),
            Err(_) => host.trim_end_matches('.').to_string(),
        },
        _ => host.trim_end_matches('.').to_string(),
    };
    if name.is_empty() {
        return DnsOutcome::Failed("empty hostname".to_string());
    }
    match query_server(server, &name, record, timeout) {
        Ok(records) if records.is_empty() => DnsOutcome::Failed(format!(
            "no {} records for {name}",
            record.as_str()
        )),
        Ok(records) => DnsOutcome::Records(records),
        Err(QueryError::Fatal(message)) | Err(QueryError::Retry(message)) => {
            DnsOutcome::Failed(message)
        }
    }
}

/// How this build performs record-type-specific lookups.
pub fn record_support() -> &'static str {
    "A/AAAA via the OS resolver; CNAME/MX/TXT/NS/SOA/PTR via the built-in DNS query engine (UDP, TCP fallback)"
}

enum QueryError {
    /// Another nameserver might succeed (timeout, malformed response).
    Retry(String),
    /// The answer is authoritative (NXDOMAIN, REFUSED, bad query).
    Fatal(String),
}

fn nameservers() -> Vec<IpAddr> {
    let mut servers = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix("nameserver") else {
                continue;
            };
            if !rest.starts_with(char::is_whitespace) {
                continue;
            }
            let Some(token) = rest.split_whitespace().next() else {
                continue;
            };
            // Ignore a trailing "#port" suffix: the client always uses 53.
            let token = token.split('#').next().unwrap_or(token);
            if let Ok(ip) = token.parse::<IpAddr>() {
                if !servers.contains(&ip) {
                    servers.push(ip);
                }
            }
        }
    }
    // Deterministic fallbacks for platforms without resolv.conf.
    if servers.is_empty() {
        if let Ok(ip) = "1.1.1.1".parse() {
            servers.push(ip);
        }
    }
    servers.truncate(3);
    servers
}

fn query_server(
    server: SocketAddr,
    name: &str,
    record: RecordType,
    timeout: Duration,
) -> Result<Vec<DnsRecord>, QueryError> {
    let id = query_id();
    let request = build_query(id, name, record.code()).map_err(QueryError::Fatal)?;
    let started = Instant::now();
    let response = udp_exchange(server, &request, timeout)?;
    if response.len() < 4 {
        return Err(QueryError::Retry(
            "DNS response is shorter than its header".into(),
        ));
    }
    let truncated = response[2] & 0x02 != 0;
    if truncated {
        let remaining = timeout.saturating_sub(started.elapsed());
        let response = tcp_exchange(server, &request, remaining)?;
        return parse_response(id, &response, record).map_err(classify);
    }
    parse_response(id, &response, record).map_err(classify)
}

fn classify(message: String) -> QueryError {
    if message.starts_with("NXDOMAIN") || message.starts_with("REFUSED") {
        QueryError::Fatal(message)
    } else {
        QueryError::Retry(message)
    }
}

fn query_id() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos ^ (std::process::id() << 8)) as u16
}

fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        return Err("empty DNS name".into());
    }
    let mut out = Vec::with_capacity(64 + name.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());

    let mut wire_len = 1usize;
    for label in name.split('.') {
        if label.is_empty() {
            return Err(format!("invalid DNS name `{name}`: empty label"));
        }
        if label.len() > 63 {
            return Err(format!(
                "invalid DNS name `{name}`: label is longer than 63 bytes"
            ));
        }
        wire_len += 1 + label.len();
        if wire_len > 255 {
            return Err(format!("invalid DNS name `{name}`: longer than 255 bytes"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    Ok(out)
}

fn udp_exchange(
    server: SocketAddr,
    request: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, QueryError> {
    let bind = if server.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let socket = UdpSocket::bind(bind)
        .map_err(|e| QueryError::Retry(format!("cannot open UDP socket: {e}")))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| QueryError::Retry(format!("cannot set DNS timeout: {e}")))?;
    socket
        .connect(server)
        .map_err(|e| QueryError::Retry(format!("cannot reach DNS server {server}: {e}")))?;
    socket
        .send(request)
        .map_err(|e| QueryError::Retry(format!("DNS send failed: {e}")))?;
    let mut buf = [0u8; MAX_UDP_RESPONSE];
    let n = socket
        .recv(&mut buf)
        .map_err(|e| QueryError::Retry(format!("DNS query to {server} failed: {e}")))?;
    Ok(buf[..n].to_vec())
}

fn tcp_exchange(
    server: SocketAddr,
    request: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, QueryError> {
    let timeout = if timeout.is_zero() {
        Duration::from_secs(1)
    } else {
        timeout
    };
    let mut stream = TcpStream::connect_timeout(&server, timeout)
        .map_err(|e| QueryError::Retry(format!("DNS TCP connect to {server} failed: {e}")))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|_| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| QueryError::Retry(format!("cannot set DNS TCP timeout: {e}")))?;
    let len = u16::try_from(request.len())
        .map_err(|_| QueryError::Fatal("DNS query is too large for TCP".into()))?;
    stream
        .write_all(&len.to_be_bytes())
        .and_then(|_| stream.write_all(request))
        .map_err(|e| QueryError::Retry(format!("DNS TCP send failed: {e}")))?;
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| QueryError::Retry(format!("DNS TCP response header failed: {e}")))?;
    let total = u16::from_be_bytes(len_buf) as usize;
    if total > MAX_TCP_RESPONSE {
        return Err(QueryError::Fatal(
            "DNS TCP response is unreasonably large".into(),
        ));
    }
    let mut out = vec![0u8; total];
    stream
        .read_exact(&mut out)
        .map_err(|e| QueryError::Retry(format!("DNS TCP response was truncated: {e}")))?;
    Ok(out)
}

fn parse_response(
    expected_id: u16,
    message: &[u8],
    want: RecordType,
) -> Result<Vec<DnsRecord>, String> {
    if message.len() < 12 {
        return Err("DNS response is shorter than its header".into());
    }
    let id = u16::from_be_bytes([message[0], message[1]]);
    if id != expected_id {
        return Err("DNS response ID does not match the query".into());
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    if flags & 0x8000 == 0 {
        return Err("DNS response is not marked as a response".into());
    }
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Err(match rcode {
            1 => "FORMERR: the server could not interpret the query".to_string(),
            2 => "SERVFAIL: the server failed to resolve the name".to_string(),
            3 => "NXDOMAIN: the name does not exist".to_string(),
            4 => "NOTIMP: the server does not implement this query".to_string(),
            5 => "REFUSED: the server refused the query".to_string(),
            other => format!("DNS error code {other}"),
        });
    }
    let qdcount = u16::from_be_bytes([message[4], message[5]]) as usize;
    let ancount = u16::from_be_bytes([message[6], message[7]]) as usize;
    let mut pos = 12usize;
    for _ in 0..qdcount {
        let (_name, next) = read_name(message, pos)?;
        pos = next;
        if pos + 4 > message.len() {
            return Err("DNS question section is truncated".into());
        }
        pos += 4;
    }

    let mut out = Vec::new();
    for _ in 0..ancount {
        let (_owner, next) = read_name(message, pos)?;
        pos = next;
        if pos + 10 > message.len() {
            return Err("DNS answer is truncated".into());
        }
        let rtype = u16::from_be_bytes([message[pos], message[pos + 1]]);
        let class = u16::from_be_bytes([message[pos + 2], message[pos + 3]]);
        let ttl = u32::from_be_bytes([
            message[pos + 4],
            message[pos + 5],
            message[pos + 6],
            message[pos + 7],
        ]);
        let rdlen = u16::from_be_bytes([message[pos + 8], message[pos + 9]]) as usize;
        let rdata_start = pos + 10;
        let rdata_end = rdata_start
            .checked_add(rdlen)
            .ok_or_else(|| "DNS answer length overflows".to_string())?;
        if rdata_end > message.len() {
            return Err("DNS answer data is truncated".into());
        }
        pos = rdata_end;
        // Only Internet-class records are meaningful here.
        if class != 1 && class != 255 {
            continue;
        }
        let record_type = match rtype {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            _ => continue,
        };
        // Keep the requested type plus the CNAME chain that leads to it.
        if record_type != want.as_str() && record_type != "CNAME" {
            continue;
        }
        let value = decode_rdata(message, rdata_start, rdata_end, rtype)?;
        out.push(DnsRecord {
            record_type: record_type.to_string(),
            value,
            ttl: Some(ttl),
        });
    }
    Ok(out)
}

fn decode_rdata(message: &[u8], start: usize, end: usize, rtype: u16) -> Result<String, String> {
    let rdata = &message[start..end];
    match rtype {
        1 => {
            if rdata.len() != 4 {
                return Err("A record has the wrong length".into());
            }
            Ok(format!(
                "{}.{}.{}.{}",
                rdata[0], rdata[1], rdata[2], rdata[3]
            ))
        }
        28 => {
            if rdata.len() != 16 {
                return Err("AAAA record has the wrong length".into());
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            Ok(std::net::Ipv6Addr::from(octets).to_string())
        }
        2 | 5 | 12 => {
            let (name, _) = read_name(message, start)?;
            Ok(name)
        }
        15 => {
            if rdata.len() < 3 {
                return Err("MX record is too short".into());
            }
            let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
            let (exchange, _) = read_name(message, start + 2)?;
            Ok(format!("{preference} {exchange}"))
        }
        16 => {
            let mut text = String::new();
            let mut at = start;
            while at < end {
                let len = message[at] as usize;
                at += 1;
                if at + len > end {
                    return Err("TXT record has a truncated character-string".into());
                }
                text.push_str(&String::from_utf8_lossy(&message[at..at + len]));
                at += len;
            }
            Ok(text)
        }
        6 => {
            let (mname, next) = read_name(message, start)?;
            let (rname, next) = read_name(message, next)?;
            if next + 20 > end {
                return Err("SOA record is truncated".into());
            }
            let mut numbers = [0u32; 5];
            for (index, item) in numbers.iter_mut().enumerate() {
                let at = next + index * 4;
                *item = u32::from_be_bytes([
                    message[at],
                    message[at + 1],
                    message[at + 2],
                    message[at + 3],
                ]);
            }
            Ok(format!(
                "{mname} {rname} {} {} {} {} {}",
                numbers[0], numbers[1], numbers[2], numbers[3], numbers[4]
            ))
        }
        _ => Err("unsupported record type".into()),
    }
}

/// Read a possibly-compressed DNS name. Returns the decoded name and the
/// offset just past the name at its original position.
fn read_name(message: &[u8], start: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut next = start;
    let mut jumped = false;
    let mut jumps = 0usize;
    let mut wire_len = 1usize;

    loop {
        if offset >= message.len() {
            return Err("DNS name runs past the end of the message".into());
        }
        let len = message[offset];
        if len == 0 {
            if !jumped {
                next = offset + 1;
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            if offset + 1 >= message.len() {
                return Err("DNS compression pointer is truncated".into());
            }
            let pointer = (((len & 0x3f) as usize) << 8) | message[offset + 1] as usize;
            if !jumped {
                next = offset + 2;
                jumped = true;
            }
            jumps += 1;
            if jumps > MAX_POINTER_JUMPS {
                return Err("DNS compression pointer loop detected".into());
            }
            if pointer >= message.len() {
                return Err("DNS compression pointer points outside the message".into());
            }
            offset = pointer;
            continue;
        }
        if len & 0xc0 != 0 {
            return Err("DNS name uses reserved label bits".into());
        }
        let label_len = len as usize;
        if offset + 1 + label_len > message.len() {
            return Err("DNS label is truncated".into());
        }
        wire_len += 1 + label_len;
        if wire_len > 255 {
            return Err("DNS name is longer than 255 bytes".into());
        }
        let label = &message[offset + 1..offset + 1 + label_len];
        labels.push(String::from_utf8_lossy(label).to_string());
        offset += 1 + label_len;
        if !jumped {
            next = offset;
        }
    }
    Ok((labels.join("."), next))
}

fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut out = String::with_capacity(72);
            for byte in v6.octets().iter().rev() {
                out.push_str(&format!("{:x}.{:x}.", byte & 0x0f, byte >> 4));
            }
            out.push_str("ip6.arpa");
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::thread;

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
        assert!(matches!(
            lookup("", RecordType::Mx),
            DnsOutcome::Failed(_)
        ));
    }

    #[test]
    fn nonsense_host_fails_or_resolves_without_panicking() {
        // Offline test: must not panic. Result may be Failed (expected offline).
        let _ = resolve_addresses("this-host-does-not-exist-zen.invalid", 80);
    }

    #[test]
    fn record_types_round_trip() {
        for rt in [
            RecordType::A,
            RecordType::Aaaa,
            RecordType::Cname,
            RecordType::Mx,
            RecordType::Txt,
            RecordType::Ns,
            RecordType::Soa,
            RecordType::Ptr,
        ] {
            assert_eq!(RecordType::parse(rt.as_str()), Some(rt));
            assert_eq!(RecordType::parse(&rt.as_str().to_lowercase()), Some(rt));
        }
        assert_eq!(RecordType::parse("SRV"), None);
    }

    #[test]
    fn support_is_declared_and_complete() {
        let support = record_support();
        assert!(support.contains("MX"));
        assert!(support.contains("SOA"));
        assert!(!support.contains("not implemented"));
    }

    #[test]
    fn query_encoding_is_correct() {
        let q = build_query(0x1234, "example.com", 15).unwrap();
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1);
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"example");
        assert_eq!(q[20], 3);
        assert_eq!(&q[21..24], b"com");
        assert_eq!(q[24], 0);
        assert_eq!(u16::from_be_bytes([q[25], q[26]]), 15);
        assert_eq!(u16::from_be_bytes([q[27], q[28]]), 1);
    }

    #[test]
    fn query_encoding_rejects_bad_names() {
        assert!(build_query(1, "", 1).is_err());
        assert!(build_query(1, "a..b", 1).is_err());
        assert!(build_query(1, &"a".repeat(64), 1).is_err());
        assert!(build_query(
            1,
            &(0..60).map(|_| "abcd").collect::<Vec<_>>().join("."),
            1
        )
        .is_err());
    }

    #[test]
    fn reverse_names_are_correct() {
        assert_eq!(
            reverse_name("192.0.2.10".parse().unwrap()),
            "10.2.0.192.in-addr.arpa"
        );
        let v6 = reverse_name("2001:db8::1".parse().unwrap());
        assert!(v6.ends_with(".ip6.arpa"));
        assert!(v6.starts_with("1.0.0.0."));
    }

    // --- synthetic packets ---------------------------------------------------

    fn response_with_answer(name: &str, rtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let query = build_query(0x4242, name, rtype).unwrap();
        let mut msg = query.clone();
        msg[2] = 0x81;
        msg[3] = 0x80;
        msg[6..8].copy_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&[0xc0, 0x0c]); // pointer to the question name
        msg.extend_from_slice(&rtype.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&ttl.to_be_bytes());
        msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        msg.extend_from_slice(rdata);
        msg
    }

    #[test]
    fn parses_an_a_answer() {
        let msg = response_with_answer("example.com", 1, 300, &[93, 184, 216, 34]);
        let records = parse_response(0x4242, &msg, RecordType::A).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value, "93.184.216.34");
        assert_eq!(records[0].ttl, Some(300));
    }

    #[test]
    fn parses_mx_txt_soa_and_aaaa() {
        let mut mx = vec![0, 10];
        mx.push(4);
        mx.extend_from_slice(b"mail");
        mx.extend_from_slice(&[0xc0, 0x0c]);
        let msg = response_with_answer("example.com", 15, 60, &mx);
        let records = parse_response(0x4242, &msg, RecordType::Mx).unwrap();
        assert_eq!(records[0].value, "10 mail.example.com");

        let txt = [
            5u8, b'h', b'e', b'l', b'l', b'o', 5, b'w', b'o', b'r', b'l', b'd',
        ];
        let msg = response_with_answer("example.com", 16, 60, &txt);
        let records = parse_response(0x4242, &msg, RecordType::Txt).unwrap();
        assert_eq!(records[0].value, "helloworld");

        let mut soa = vec![0xc0, 0x0c, 0xc0, 0x0c];
        for n in [1u32, 3600, 600, 86_400, 300] {
            soa.extend_from_slice(&n.to_be_bytes());
        }
        let msg = response_with_answer("example.com", 6, 60, &soa);
        let records = parse_response(0x4242, &msg, RecordType::Soa).unwrap();
        assert_eq!(
            records[0].value,
            "example.com example.com 1 3600 600 86400 300"
        );

        let msg = response_with_answer(
            "example.com",
            28,
            60,
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        );
        let records = parse_response(0x4242, &msg, RecordType::Aaaa).unwrap();
        assert_eq!(records[0].value, "2001:db8::1");
    }

    #[test]
    fn rejects_nxdomain() {
        let mut msg = build_query(7, "missing.example", 1).unwrap();
        msg[2] = 0x81;
        msg[3] = 0x83; // NXDOMAIN
        let err = parse_response(7, &msg, RecordType::A).unwrap_err();
        assert!(err.contains("NXDOMAIN"));
    }

    #[test]
    fn rejects_pointer_loops_and_out_of_bounds_names() {
        // Header with one answer whose owner name points at itself.
        let mut msg = vec![0u8; 12];
        msg[1] = 1;
        msg[2] = 0x81;
        msg[3] = 0x80;
        msg[6..8].copy_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&[0xc0, 0x0c]); // points to itself (offset 12)
        msg.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
        let err = parse_response(1, &msg, RecordType::A).unwrap_err();
        assert!(err.contains("loop"), "unexpected error: {err}");

        let mut msg = vec![0u8; 12];
        msg[2] = 0x81;
        msg[3] = 0x80;
        msg[4..6].copy_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&[0xc0, 0xff]);
        assert!(parse_response(0, &msg, RecordType::A).is_err());
    }

    #[test]
    fn rejects_mismatched_id_and_non_response() {
        let msg = response_with_answer("example.com", 1, 1, &[1, 2, 3, 4]);
        assert!(parse_response(0x1111, &msg, RecordType::A).is_err());
        let mut not_response = msg.clone();
        not_response[2] = 0x01;
        assert!(parse_response(0x4242, &not_response, RecordType::A).is_err());
    }

    #[test]
    fn lookup_via_udp_server_end_to_end() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, peer) = server.recv_from(&mut buf).unwrap();
            let query = &buf[..n];
            let id = u16::from_be_bytes([query[0], query[1]]);
            let mut msg = query.to_vec();
            msg[2] = 0x81;
            msg[3] = 0x80;
            msg[6..8].copy_from_slice(&1u16.to_be_bytes());
            msg.extend_from_slice(&[0xc0, 0x0c]);
            msg.extend_from_slice(&1u16.to_be_bytes()); // A
            msg.extend_from_slice(&1u16.to_be_bytes()); // IN
            msg.extend_from_slice(&120u32.to_be_bytes());
            msg.extend_from_slice(&4u16.to_be_bytes());
            msg.extend_from_slice(&[203, 0, 113, 7]);
            assert_eq!(u16::from_be_bytes([msg[0], msg[1]]), id);
            server.send_to(&msg, peer).unwrap();
        });
        match lookup_with_server("example.test", RecordType::A, addr, Duration::from_secs(2)) {
            DnsOutcome::Records(records) => {
                assert_eq!(records[0].value, "203.0.113.7");
                assert_eq!(records[0].ttl, Some(120));
            }
            other => panic!("expected records, got {other:?}"),
        }
        handle.join().unwrap();
    }
}

//! Native TLS inspection.
//!
//! A small rustls client inspects an endpoint and reports the negotiated
//! version/cipher and the peer certificate's subject, issuer, SANs and expiry.
//! It performs a normal verifying handshake first; if that fails (self-signed,
//! expired, wrong host), it reconnects without verification *only* to report
//! the certificate, and marks it `certificate_trusted: false`. It never
//! reports an untrusted certificate as verified and never transmits
//! application data.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use x509_parser::prelude::*;

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
    /// SAN entries as text (DNS names and IP addresses).
    #[serde(default)]
    pub subject_alt_names: Vec<String>,
    /// `Some(true)` only when the normal verifying handshake succeeded.
    #[serde(default)]
    pub certificate_trusted: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TlsOutcome {
    Info(Box<TlsInfo>),
    /// No TLS backend is compiled into this build.
    Unsupported(&'static str),
    Failed(String),
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether a TLS backend is available.
pub fn backend_available() -> bool {
    true
}

pub fn backend_description() -> &'static str {
    "rustls (ring) with OS trust roots and a webpki-roots fallback; untrusted certificates are reported as untrusted, never as verified"
}

/// Inspect a TLS endpoint.
pub fn inspect(host: &str, port: u16) -> TlsOutcome {
    if host.is_empty() {
        return TlsOutcome::Failed("empty hostname".into());
    }
    let addrs: Vec<SocketAddr> = match (host, port).to_socket_addrs() {
        Ok(addrs) => addrs.collect(),
        Err(error) => {
            return TlsOutcome::Failed(format!("cannot resolve {host}:{port}: {error}"));
        }
    };
    if addrs.is_empty() {
        return TlsOutcome::Failed(format!("{host}:{port} resolved to no addresses"));
    }

    match handshake(host, &addrs, verified_config()) {
        Ok(connection) => match info_from(&connection, host, port, true) {
            Ok(info) => TlsOutcome::Info(Box::new(info)),
            Err(error) => TlsOutcome::Failed(error),
        },
        Err(HandshakeError::Connect(error)) => TlsOutcome::Failed(error),
        Err(HandshakeError::Tls(verify_error)) => {
            match handshake(host, &addrs, inspection_config()) {
                Ok(connection) => match info_from(&connection, host, port, false) {
                    Ok(info) => TlsOutcome::Info(Box::new(info)),
                    Err(error) => TlsOutcome::Failed(format!(
                        "{error} (trusted handshake failed: {verify_error})"
                    )),
                },
                Err(HandshakeError::Connect(error)) | Err(HandshakeError::Tls(error)) => {
                    TlsOutcome::Failed(format!(
                        "TLS handshake with {host}:{port} failed: {error} (trusted handshake failed: {verify_error})"
                    ))
                }
            }
        }
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    // Installing is idempotent; a previous install (or another crate) wins.
    let _ = rustls::crypto::ring::default_provider().install_default();
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Normal, certificate-verifying client configuration. Cached because loading
/// native roots is the expensive part of a short inspection.
fn verified_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = RootCertStore::empty();
            let native = rustls_native_certs::load_native_certs();
            for cert in native.certs {
                let _ = roots.add(cert);
            }
            if roots.is_empty() {
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }
            let config = ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .expect("ring provider supports the default protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

/// Configuration used only to read a certificate that failed verification.
/// The returned data is labelled `certificate_trusted: false`; no application
/// data is sent over this connection.
fn inspection_config() -> Arc<ClientConfig> {
    let provider = provider();
    let schemes = provider
        .signature_verification_algorithms
        .supported_schemes();
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InspectionVerifier { schemes }))
        .with_no_client_auth();
    Arc::new(config)
}

enum HandshakeError {
    /// The TCP connection could not be established; retrying TLS is pointless.
    Connect(String),
    /// TCP connected but the TLS handshake failed (certificate, protocol, ...).
    Tls(String),
}

fn handshake(
    host: &str,
    addrs: &[SocketAddr],
    config: Arc<ClientConfig>,
) -> Result<ClientConnection, HandshakeError> {
    let server_name = match host.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(host.to_string())
            .map_err(|_| HandshakeError::Connect(format!("invalid TLS server name `{host}`")))?,
    };
    let mut connection = ClientConnection::new(config, server_name)
        .map_err(|error| HandshakeError::Tls(format!("cannot start TLS: {error}")))?;
    let mut socket = connect_any(addrs).map_err(HandshakeError::Connect)?;
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|_| socket.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|error| HandshakeError::Tls(format!("cannot set socket timeout: {error}")))?;
    while connection.is_handshaking() {
        connection
            .complete_io(&mut socket)
            .map_err(|error| HandshakeError::Tls(format!("TLS handshake failed: {error}")))?;
    }
    Ok(connection)
}

fn connect_any(addrs: &[SocketAddr]) -> Result<TcpStream, String> {
    let mut last = String::new();
    for addr in addrs {
        match TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(error) => last = format!("{addr}: {error}"),
        }
    }
    Err(format!("cannot connect: {last}"))
}

fn info_from(
    connection: &ClientConnection,
    host: &str,
    port: u16,
    trusted: bool,
) -> Result<TlsInfo, String> {
    let certificates = connection
        .peer_certificates()
        .ok_or_else(|| "server presented no certificate".to_string())?;
    let leaf = certificates
        .first()
        .ok_or_else(|| "server certificate chain is empty".to_string())?;
    let summary = certificate_summary(leaf)?;
    Ok(TlsInfo {
        host: host.to_string(),
        port,
        tls_version: connection.protocol_version().map(version_name),
        cipher: connection
            .negotiated_cipher_suite()
            .map(|suite| format!("{:?}", suite.suite())),
        peer_certificate_subject: Some(summary.subject),
        peer_certificate_issuer: Some(summary.issuer),
        certificate_expires: Some(summary.not_after),
        hostname_matches: Some(hostname_matches(
            host,
            &summary.sans,
            summary.common_name.as_deref(),
        )),
        subject_alt_names: summary.sans,
        certificate_trusted: Some(trusted),
    })
}

fn version_name(version: rustls::ProtocolVersion) -> String {
    match version {
        rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".into(),
        rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".into(),
        other => format!("{other:?}"),
    }
}

struct CertificateSummary {
    subject: String,
    issuer: String,
    not_after: String,
    sans: Vec<String>,
    common_name: Option<String>,
}

fn certificate_summary(der: &CertificateDer<'_>) -> Result<CertificateSummary, String> {
    let (_, certificate) = X509Certificate::from_der(der.as_ref())
        .map_err(|error| format!("cannot parse peer certificate: {error}"))?;
    let common_name = certificate
        .subject()
        .iter_common_name()
        .next()
        .and_then(|name| name.as_str().ok())
        .map(str::to_string);
    let mut sans = Vec::new();
    if let Ok(Some(extension)) = certificate.subject_alternative_name() {
        for name in &extension.value.general_names {
            match name {
                GeneralName::DNSName(dns) => sans.push((*dns).to_string()),
                GeneralName::IPAddress(bytes) => {
                    if bytes.len() == 4 {
                        sans.push(format!(
                            "{}.{}.{}.{}",
                            bytes[0], bytes[1], bytes[2], bytes[3]
                        ));
                    } else if bytes.len() == 16 {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(bytes);
                        sans.push(std::net::Ipv6Addr::from(octets).to_string());
                    }
                }
                _ => {}
            }
        }
    }
    let not_after = certificate.validity().not_after.to_datetime();
    Ok(CertificateSummary {
        subject: certificate.subject().to_string(),
        issuer: certificate.issuer().to_string(),
        not_after: format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            not_after.year(),
            u8::from(not_after.month()),
            not_after.day(),
            not_after.hour(),
            not_after.minute(),
            not_after.second()
        ),
        sans,
        common_name,
    })
}

/// RFC 6125-style matching: exact names, or a single-label `*.` wildcard.
fn hostname_matches(host: &str, sans: &[String], common_name: Option<&str>) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if let Ok(ip) = host.parse::<IpAddr>() {
        return sans
            .iter()
            .filter_map(|name| name.parse::<IpAddr>().ok())
            .any(|candidate| candidate == ip);
    }
    let dns_sans: Vec<&str> = sans
        .iter()
        .map(String::as_str)
        .filter(|name| name.parse::<IpAddr>().is_err())
        .collect();
    if !dns_sans.is_empty() {
        return dns_sans
            .iter()
            .any(|pattern| dns_name_matches(&host, pattern));
    }
    common_name
        .map(|name| dns_name_matches(&host, name))
        .unwrap_or(false)
}

fn dns_name_matches(host: &str, pattern: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host
            .split_once('.')
            .map(|(label, rest)| !label.is_empty() && rest == suffix)
            .unwrap_or(false);
    }
    host == pattern
}

/// A verifier used only for read-only inspection of a certificate that failed
/// normal validation. It never accepts a connection on behalf of application
/// traffic, and the resulting [`TlsInfo`] records `certificate_trusted: false`.
#[derive(Debug)]
struct InspectionVerifier {
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for InspectionVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivateKeyDer;
    use std::net::TcpListener;
    use std::sync::mpsc;

    #[test]
    fn backend_is_claimed_and_described() {
        assert!(backend_available());
        assert!(backend_description().contains("rustls"));
    }

    #[test]
    fn hostname_matching_rules() {
        assert!(dns_name_matches("example.com", "example.com"));
        assert!(dns_name_matches("example.com", "EXAMPLE.COM."));
        assert!(dns_name_matches("api.example.com", "*.example.com"));
        assert!(!dns_name_matches("example.com", "*.example.com"));
        assert!(!dns_name_matches("a.b.example.com", "*.example.com"));
        assert!(!dns_name_matches("evil-example.com", "*.example.com"));
        assert!(hostname_matches("example.com", &[], Some("example.com")));
        assert!(!hostname_matches("example.com", &[], None));
    }

    #[test]
    fn san_takes_priority_over_common_name() {
        let sans = vec!["api.example.com".to_string()];
        assert!(hostname_matches(
            "api.example.com",
            &sans,
            Some("other.test")
        ));
        assert!(!hostname_matches("other.test", &sans, Some("other.test")));
    }

    #[test]
    fn ip_sans_are_matched_exactly() {
        let sans = vec!["127.0.0.1".to_string(), "::1".to_string()];
        assert!(hostname_matches("127.0.0.1", &sans, None));
        assert!(hostname_matches("::1", &sans, None));
        assert!(!hostname_matches("127.0.0.2", &sans, None));
    }

    #[test]
    fn parses_generated_certificate_fields() {
        let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let der = key.cert.der();
        let summary = certificate_summary(der).unwrap();
        assert!(
            summary.subject.contains("rcgen self signed cert"),
            "{}",
            summary.subject
        );
        assert_eq!(
            summary.common_name.as_deref(),
            Some("rcgen self signed cert")
        );
        assert!(summary.sans.iter().any(|name| name == "localhost"));
        assert!(summary.not_after.contains('T'));
        assert!(hostname_matches(
            "localhost",
            &summary.sans,
            summary.common_name.as_deref()
        ));
    }

    #[test]
    fn inspects_a_local_tls_server_and_marks_it_untrusted() {
        let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = key.cert.der().clone();
        let private_key = PrivateKeyDer::Pkcs8(key.signing_key.serialize_der().into());
        let provider = provider();
        let server_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], private_key)
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let config = Arc::new(server_config);
            loop {
                if stop_rx.try_recv().is_ok() {
                    break;
                }
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        let _ = socket.set_nonblocking(false);
                        let _ = socket.set_read_timeout(Some(Duration::from_secs(2)));
                        if let Ok(mut connection) = rustls::ServerConnection::new(config.clone()) {
                            while connection.is_handshaking() {
                                if connection.complete_io(&mut socket).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        let outcome = inspect("localhost", port);
        let _ = stop_tx.send(());
        handle.join().unwrap();
        match outcome {
            TlsOutcome::Info(info) => {
                assert_eq!(info.certificate_trusted, Some(false));
                assert_eq!(info.hostname_matches, Some(true));
                assert!(info
                    .subject_alt_names
                    .iter()
                    .any(|name| name == "localhost"));
                assert!(info.peer_certificate_subject.is_some());
                assert!(info.tls_version.is_some());
                assert!(info.cipher.is_some());
            }
            other => panic!("expected TLS info, got {other:?}"),
        }
    }

    #[test]
    fn unreachable_endpoint_fails_without_fabricating() {
        // Port 1 on loopback should refuse quickly on every supported OS.
        match inspect("127.0.0.1", 1) {
            TlsOutcome::Failed(_) => {}
            other => panic!("must not fabricate TLS data, got {other:?}"),
        }
    }
}

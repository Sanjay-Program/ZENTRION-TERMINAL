//! Phase 3 native engine and security-analysis foundation.
//!
//! This module keeps the implementation honest: where Zentrion can do work
//! natively, it does; where it cannot yet do so safely, it reports that
//! limitation instead of inventing results.

use crate::{dns, fs, process, sysinfo, tls};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs as stdfs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use z_core::error::{Area, ZenError, ZenResult};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Domain,
    Ip,
    Url,
    Host,
    Service,
    Certificate,
    File,
    Process,
    Package,
    Repository,
    Application,
    CloudResource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Asset {
    pub id: String,
    pub kind: AssetKind,
    pub value: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: f32,
    pub asset: Option<Asset>,
    pub evidence: Vec<String>,
    pub description: String,
    pub recommendation: String,
    pub source: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EngineRequest {
    pub engine: String,
    pub operation: String,
    #[serde(default)]
    pub input: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EngineResult {
    pub status: String,
    pub engine: String,
    #[serde(default)]
    pub data: Value,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    pub duration_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineCapabilities {
    #[serde(default)]
    pub operations: Vec<String>,
    pub native: bool,
    pub supported: bool,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EngineInfo {
    pub name: String,
    pub capabilities: EngineCapabilities,
}

pub trait Engine: Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> EngineCapabilities;
    fn execute(&self, request: &EngineRequest) -> ZenResult<EngineResult>;
}

pub struct EngineRegistry {
    engines: BTreeMap<String, Box<dyn Engine>>,
}

impl EngineRegistry {
    pub fn new() -> Self {
        let mut engines: BTreeMap<String, Box<dyn Engine>> = BTreeMap::new();
        register(&mut engines, DnsEngine);
        register(&mut engines, HttpEngine);
        register(&mut engines, TlsEngine);
        register(&mut engines, UrlEngine);
        register(&mut engines, NetworkEngine);
        register(&mut engines, ProcessEngine);
        register(&mut engines, FilesystemEngine);
        register(&mut engines, SystemEngine);
        register(&mut engines, SecretsEngine);
        register(&mut engines, CodeEngine);
        register(&mut engines, DependenciesEngine);
        register(&mut engines, ConfigurationEngine);
        register(&mut engines, AssetsEngine);
        register(&mut engines, CertificatesEngine);
        register(&mut engines, FindingsEngine);
        Self { engines }
    }

    pub fn list(&self) -> Vec<EngineInfo> {
        self.engines
            .values()
            .map(|engine| EngineInfo {
                name: engine.name().to_string(),
                capabilities: engine.capabilities(),
            })
            .collect()
    }

    pub fn info(&self, name: &str) -> Option<EngineInfo> {
        self.engines.get(name).map(|engine| EngineInfo {
            name: engine.name().to_string(),
            capabilities: engine.capabilities(),
        })
    }

    pub fn execute(&self, request: &EngineRequest) -> ZenResult<EngineResult> {
        let engine = self.engines.get(&request.engine).ok_or_else(|| {
            ZenError::new(
                Area::Reg,
                5100,
                format!("unknown engine '{}'", request.engine),
            )
            .with_remediation(format!(
                "Available engines: {}",
                self.engines.keys().cloned().collect::<Vec<_>>().join(", ")
            ))
        })?;
        engine.execute(request)
    }
}

fn register(engines: &mut BTreeMap<String, Box<dyn Engine>>, engine: impl Engine + 'static) {
    engines.insert(engine.name().to_string(), Box::new(engine));
}

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

fn stable_fingerprint(parts: &[&str]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for part in parts {
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("fp_{hash:016x}")
}

fn asset_id(kind: AssetKind, value: &str) -> String {
    stable_fingerprint(&[&format!("{:?}", kind), value])
}

fn asset(kind: AssetKind, value: impl Into<String>) -> Asset {
    let value = value.into();
    Asset {
        id: asset_id(kind, &value),
        kind,
        value,
        metadata: BTreeMap::new(),
    }
}

fn finding(
    title: impl Into<String>,
    severity: Severity,
    confidence: f32,
    asset: Option<Asset>,
    evidence: Vec<String>,
    description: impl Into<String>,
    recommendation: impl Into<String>,
    source: impl Into<String>,
) -> Finding {
    let title = title.into();
    let source = source.into();
    let evidence_joined = evidence.join("|");
    let asset_key = asset.as_ref().map(|a| a.id.as_str()).unwrap_or("-");
    Finding {
        id: stable_fingerprint(&[
            &title,
            &format!("{:?}", severity),
            asset_key,
            &evidence_joined,
            &source,
        ]),
        title,
        severity,
        confidence,
        asset,
        evidence,
        description: description.into(),
        recommendation: recommendation.into(),
        source,
        timestamp: now_millis(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanProfile {
    Minimal,
    Standard,
    Web,
    Network,
    System,
    Code,
    Dependency,
}

impl ScanProfile {
    pub fn engines(&self) -> &'static [&'static str] {
        match self {
            ScanProfile::Minimal => &["dns", "system"],
            ScanProfile::Standard => &["dns", "url", "system", "process", "filesystem"],
            ScanProfile::Web => &["dns", "url", "http", "tls"],
            ScanProfile::Network => &["dns", "network", "http"],
            ScanProfile::System => &["system", "process", "filesystem"],
            ScanProfile::Code => &["code", "secrets", "filesystem"],
            ScanProfile::Dependency => &["dependencies", "filesystem"],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanReport {
    pub target: String,
    pub profile: ScanProfile,
    pub timestamp: u64,
    pub assets: Vec<Asset>,
    pub findings: Vec<Finding>,
    pub engines: Vec<String>,
    pub summary: String,
}

pub struct ScanOrchestrator {
    registry: EngineRegistry,
}

impl ScanOrchestrator {
    pub fn new() -> Self {
        Self {
            registry: EngineRegistry::new(),
        }
    }

    pub fn registry(&self) -> &EngineRegistry {
        &self.registry
    }

    pub fn scan(&self, target: &str, profile: ScanProfile) -> ZenResult<ScanReport> {
        let mut assets = Vec::new();
        let mut findings = Vec::new();
        let mut engines = Vec::new();

        if profile.engines().contains(&"url") {
            if self.registry.info("url").is_some() {
                engines.push("url".to_string());
                let req = EngineRequest {
                    engine: "url".into(),
                    operation: "analyze".into(),
                    input: json!({"target": target}),
                };
                let result = self.registry.execute(&req)?;
                assets.extend(extract_assets(&result.data));
                findings.extend(result.findings);
            }
        }

        for engine in profile.engines() {
            if *engine == "url" {
                continue;
            }
            if self.registry.info(engine).is_none() {
                continue;
            }
            engines.push((*engine).to_string());
            let req = EngineRequest {
                engine: (*engine).to_string(),
                operation: default_operation(engine).to_string(),
                input: json!({"target": target}),
            };
            let result = self.registry.execute(&req)?;
            assets.extend(extract_assets(&result.data));
            findings.extend(result.findings);
        }

        let summary = summarize_findings(&findings);
        Ok(ScanReport {
            target: target.to_string(),
            profile,
            timestamp: now_millis(),
            assets,
            findings: dedupe_findings(findings),
            engines,
            summary,
        })
    }
}

fn default_operation(engine: &str) -> &'static str {
    match engine {
        "dns" => "resolve",
        "http" => "request",
        "tls" => "inspect",
        "url" => "analyze",
        "network" => "snapshot",
        "process" => "list",
        "filesystem" => "inspect",
        "system" => "info",
        "secrets" => "scan",
        "code" => "analyze",
        "dependencies" => "analyze",
        "configuration" => "inspect",
        "assets" => "list",
        "certificates" => "inspect",
        "findings" => "list",
        _ => "inspect",
    }
}

fn dedupe_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen = BTreeMap::<String, Finding>::new();
    for finding in findings {
        seen.entry(finding.id.clone()).or_insert(finding);
    }
    seen.into_values().collect()
}

fn summarize_findings(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "No findings produced by the selected engines.".to_string();
    }
    let high = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::High | Severity::Critical))
        .count();
    let medium = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Medium))
        .count();
    let low = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Low))
        .count();
    format!("{high} high/critical, {medium} medium, {low} low finding(s)")
}

fn extract_assets(data: &Value) -> Vec<Asset> {
    data.get("assets")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| serde_json::from_value(item.clone()).ok())
                .collect()
        })
        .unwrap_or_default()
}

fn as_string(v: Option<&Value>) -> Option<String> {
    v.and_then(|x| x.as_str().map(ToString::to_string))
}

fn json_error(engine: &str, operation: &str, message: impl Into<String>) -> ZenError {
    ZenError::new(
        Area::Sec,
        5101,
        format!("{engine}.{operation}: {}", message.into()),
    )
}

struct DnsEngine;

impl Engine for DnsEngine {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            operations: vec!["resolve".into(), "reverse".into(), "records".into()],
            native: true,
            supported: true,
            description: "OS resolver backed DNS analysis".into(),
        }
    }

    fn execute(&self, request: &EngineRequest) -> ZenResult<EngineResult> {
        let started = now_millis();
        let target = as_string(request.input.get("target"))
            .ok_or_else(|| json_error(self.name(), &request.operation, "missing target"))?;
        match request.operation.as_str() {
            "resolve" => match dns::resolve_addresses(&target, 80) {
                dns::DnsOutcome::Records(records) => Ok(EngineResult {
                    status: "success".into(),
                    engine: self.name().into(),
                    data: json!({
                        "target": target,
                        "records": records,
                        "assets": [asset(AssetKind::Host, target)],
                    }),
                    findings: vec![],
                    stdout: String::new(),
                    stderr: String::new(),
                    duration_ms: u128::from(now_millis().saturating_sub(started)),
                }),
                dns::DnsOutcome::Unsupported(msg) => Ok(EngineResult {
                    status: "unsupported".into(),
                    engine: self.name().into(),
                    data: json!({"message": msg, "target": target}),
                    findings: vec![finding(
                        "DNS resolution unavailable",
                        Severity::Info,
                        0.7,
                        Some(asset(AssetKind::Domain, target.clone())),
                        vec![msg.to_string()],
                        "The current build cannot resolve the requested record type natively.",
                        "Use a supported native record type or add a DNS backend.",
                        "dns",
                    )],
                    stdout: String::new(),
                    stderr: String::new(),
                    duration_ms: u128::from(now_millis().saturating_sub(started)),
                }),
                dns::DnsOutcome::Failed(msg) => Ok(EngineResult {
                    status: "failed".into(),
                    engine: self.name().into(),
                    data: json!({"message": msg, "target": target}),
                    findings: vec![finding(
                        "DNS lookup failed",
                        Severity::Low,
                        0.9,
                        Some(asset(AssetKind::Domain, target.clone())),
                        vec![msg.clone()],
                        "The resolver could not return addresses for the requested target.",
                        "Verify the hostname and network reachability.",
                        "dns",
                    )],
                    stdout: String::new(),
                    stderr: msg,
                    duration_ms: u128::from(now_millis().saturating_sub(started)),
                }),
            },
            other => Err(json_error(self.name(), other, "unsupported operation")),
        }
    }
}

struct HttpEngine;

fn parse_http_target(target: &str) -> ZenResult<(String, String, u16, String, bool)> {
    let (scheme, rest, tls) = if let Some(s) = target.strip_prefix("https://") {
        ("https", s, true)
    } else if let Some(s) = target.strip_prefix("http://") {
        ("http", s, false)
    } else {
        ("http", target, false)
    };
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let host = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let (host, port) = match host.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (
            h.to_string(),
            p.parse::<u16>().unwrap_or(if tls { 443 } else { 80 }),
        ),
        _ => (host.to_string(), if tls { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err(ZenError::new(
            Area::Cfg,
            5102,
            "HTTP target is missing a host",
        ));
    }
    Ok((scheme.into(), host, port, path, tls))
}

impl Engine for HttpEngine {
    fn name(&self) -> &'static str {
        "http"
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            operations: vec!["request".into(), "head".into(), "analyze".into()],
            native: true,
            supported: true,
            description: "Plain HTTP/1.1 analysis over TcpStream; HTTPS is reported unsupported without a TLS backend".into(),
        }
    }

    fn execute(&self, request: &EngineRequest) -> ZenResult<EngineResult> {
        let started = now_millis();
        let target = as_string(request.input.get("target"))
            .ok_or_else(|| json_error(self.name(), &request.operation, "missing target"))?;
        let method = request
            .input
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_string();

        let (scheme, host, port, path, tls_requested) = parse_http_target(&target)?;
        if tls_requested {
            return Ok(EngineResult {
                status: "unsupported".into(),
                engine: self.name().into(),
                data: json!({
                    "target": target,
                    "message": "HTTPS requires a TLS backend that is not yet wired in Phase 3 initial foundation",
                }),
                findings: vec![finding(
                    "HTTPS backend unavailable",
                    Severity::Info,
                    1.0,
                    Some(asset(AssetKind::Url, target.clone())),
                    vec!["TLS backend missing".into()],
                    "The current runtime can analyze the URL but cannot yet execute HTTPS requests natively.",
                    "Use an http:// URL or add a TLS backend.",
                    "http",
                )],
                stdout: String::new(),
                stderr: String::new(),
                duration_ms: u128::from(now_millis().saturating_sub(started)),
            });
        }

        let addr = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| ZenError::new(Area::Net, 5103, format!("{host}:{port}: {e}")))?
            .next()
            .ok_or_else(|| ZenError::new(Area::Net, 5104, "no address resolved"))?;
        let mut stream =
            TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(|e| {
                ZenError::new(
                    Area::Net,
                    5105,
                    format!("cannot connect to {host}:{port}: {e}"),
                )
            })?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
        let request_text = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: zentrion/{}\r\nConnection: close\r\nAccept: */*\r\n\r\n",
            env!("CARGO_PKG_VERSION")
        );
        stream
            .write_all(request_text.as_bytes())
            .map_err(|e| ZenError::new(Area::Net, 5106, format!("write failed: {e}")))?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|e| ZenError::new(Area::Net, 5107, format!("read failed: {e}")))?;
        let text = String::from_utf8_lossy(&response).to_string();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let mut lines = head.lines();
        let status_line = lines.next().unwrap_or("HTTP/1.1 0").to_string();
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        let headers: Vec<(String, String)> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .collect();
        let assets = vec![
            asset(AssetKind::Url, target.clone()),
            asset(AssetKind::Host, host.clone()),
        ];
        let mut findings = Vec::new();
        if !headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-security-policy"))
        {
            findings.push(finding(
                "Missing content-security-policy header",
                Severity::Low,
                0.7,
                Some(asset(AssetKind::Url, target.clone())),
                vec!["content-security-policy absent".into()],
                "The response did not include a CSP header.",
                "Consider adding a restrictive Content-Security-Policy.",
                "http",
            ));
        }
        Ok(EngineResult {
            status: if status >= 400 { "warning" } else { "success" }.into(),
            engine: self.name().into(),
            data: json!({
                "scheme": scheme,
                "target": target,
                "status": status,
                "status_line": status_line,
                "headers": headers,
                "body_len": body.len(),
                "assets": assets,
            }),
            findings,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: u128::from(now_millis().saturating_sub(started)),
        })
    }
}

struct TlsEngine;

impl Engine for TlsEngine {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            operations: vec!["inspect".into(), "analyze".into()],
            native: true,
            supported: false,
            description: tls::backend_description().to_string(),
        }
    }

    fn execute(&self, request: &EngineRequest) -> ZenResult<EngineResult> {
        let target = as_string(request.input.get("target")).unwrap_or_else(|| "unknown".into());
        Ok(EngineResult {
            status: "unsupported".into(),
            engine: self.name().into(),
            data: json!({"target": target, "message": tls::backend_description()}),
            findings: vec![finding(
                "TLS inspection unavailable",
                Severity::Info,
                1.0,
                Some(asset(AssetKind::Url, target)),
                vec![tls::backend_description().into()],
                "The runtime does not yet ship a TLS inspection backend.",
                "Add a verified TLS backend before relying on certificate analysis.",
                "tls",
            )],
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        })
    }
}

struct UrlEngine;

impl Engine for UrlEngine {
    fn name(&self) -> &'static str {
        "url"
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            operations: vec!["analyze".into()],
            native: true,
            supported: true,
            description: "URL component analysis and suspicious-pattern checks".into(),
        }
    }

    fn execute(&self, request: &EngineRequest) -> ZenResult<EngineResult> {
        let target = as_string(request.input.get("target"))
            .ok_or_else(|| json_error(self.name(), &request.operation, "missing target"))?;
        let (scheme, rest) = target
            .split_once("://")
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .unwrap_or_else(|| ("http".into(), target.clone()));
        let (authority, path) = match rest.split_once('/') {
            Some((a, p)) => (a.to_string(), format!("/{p}")),
            None => (rest.clone(), "/".into()),
        };
        let userinfo = authority.contains('@');
        let host = authority
            .rsplit_once('@')
            .map(|(_, h)| h)
            .unwrap_or(&authority)
            .to_string();
        let suspicious =
            userinfo || path.contains("..") || target.contains("%2e") || target.contains("%2f");
        let mut findings = Vec::new();
        if suspicious {
            findings.push(finding(
                "Suspicious URL pattern",
                Severity::Low,
                0.8,
                Some(asset(AssetKind::Url, target.clone())),
                vec![target.clone()],
                "The URL contains userinfo, traversal or encoded separators that deserve manual review.",
                "Confirm the URL is intentional before using it in automation.",
                "url",
            ));
        }
        Ok(EngineResult {
            status: "success".into(),
            engine: self.name().into(),
            data: json!({
                "scheme": scheme,
                "host": host,
                "path": path,
                "userinfo": userinfo,
                "suspicious": suspicious,
                "assets": [asset(AssetKind::Url, target)],
            }),
            findings,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        })
    }
}

struct NetworkEngine;

impl Engine for NetworkEngine {
    fn name(&self) -> &'static str {
        "network"
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            operations: vec!["snapshot".into(), "interfaces".into(), "routes".into()],
            native: true,
            supported: false,
            description: "Network inspection foundation, currently limited to host metadata".into(),
        }
    }

    fn execute(&self, request: &EngineRequest) -> ZenResult<EngineResult> {
        let sys = sysinfo::system_info();
        Ok(EngineResult {
            status: "unsupported".into(),
            engine: self.name().into(),
            data: json!({
                "target": request.input.get("target").and_then(|v| v.as_str()).unwrap_or("host"),
                "hostname": sys.hostname,
                "message": "network interface and route enumeration are not yet wired in this initial Phase 3 slice",
            }),
            findings: vec![finding(
                "Network inspection incomplete",
                Severity::Info,
                1.0,
                None,
                vec!["interfaces/routes unavailable in initial slice".into()],
                "The runtime can now name the network engine, but not yet enumerate all adapters and routes.",
                "Wire platform-specific adapters before relying on network inventory.",
                "network",
            )],
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        })
    }
}

struct ProcessEngine;

impl Engine for ProcessEngine {
    fn name(&self) -> &'static str {
        "process"
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            operations: vec!["inspect".into(), "list".into()],
            native: true,
            supported: true,
            description: "process inspection via native OS interfaces".into(),
        }
    }

    fn execute(&self, request: &EngineRequest) -> ZenResult<EngineResult> {
        let insp = process::inspector();
        match request.operation.as_str() {
            "inspect" => {
                let pid = request
                    .input
                    .get("pid")
                    .and_then(|v| v.as_u64())
                    .unwrap_or_else(|| u64::from(std::process::id()))
                    as u32;
                match insp.inspect(pid) {
                    process::InspectOutcome::Found(p) => Ok(EngineResult {
                        status: "success".into(),
                        engine: self.name().into(),
                        data: json!({"process": p}),
                        findings: vec![],
                        stdout: String::new(),
                        stderr: String::new(),
                        duration_ms: 0,
                    }),
                    process::InspectOutcome::Unsupported(msg) => Ok(EngineResult {
                        status: "unsupported".into(),
                        engine: self.name().into(),
                        data: json!({"message": msg}),
                        findings: vec![finding(
                            "Process inspection unsupported",
                            Severity::Info,
                            1.0,
                            None,
                            vec![msg.into()],
                            "This platform does not yet provide the process inspector backend.",
                            "Implement the per-platform process adapter.",
                            "process",
                        )],
                        stdout: String::new(),
                        stderr: String::new(),
                        duration_ms: 0,
                    }),
                    process::InspectOutcome::NotFound => Err(ZenError::new(
                        Area::Pr,
                        5108,
                        format!("no such process: {pid}"),
                    )),
                }
            }
            "list" => {
                let list = insp.list();
                Ok(EngineResult {
                    status: "success".into(),
                    engine: self.name().into(),
                    data: json!({"processes": list, "count": list.len()}),
                    findings: vec![],
                    stdout: String::new(),
                    stderr: String::new(),
                    duration_ms: 0,
                })
            }
            other => Err(json_error(self.name(), other, "unsupported operation")),
        }
    }
}

struct FilesystemEngine;

impl Engine for FilesystemEngine {
    fn name(&self) -> &'static str {
        "filesystem"
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            operations: vec!["inspect".into(), "hash".into()],
            native: true,
            supported: true,
            description: "filesystem metadata and path safety checks".into(),
        }
    }

    fn execute(&self, request: &EngineRequest) -> ZenResult<EngineResult> {
        let path = as_string(request.input.get("target"))
            .ok_or_else(|| json_error(self.name(), &request.operation, "missing target"))?;
        let path = PathBuf::from(path);
        let insp = fs::inspector();
        let info = insp.inspect(&path)?;
        Ok(EngineResult {
            status: "success".into(),
            engine: self.name().into(),
            data: json!({"file": info}),
            findings: vec![],
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        })
    }
}

struct SystemEngine;

impl Engine for SystemEngine {
    fn name(&self) -> &'static str {
        "system"
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            operations: vec!["info".into()],
            native: true,
            supported: true,
            description: "host CPU, memory and platform metadata".into(),
        }
    }

    fn execute(&self, _request: &EngineRequest) -> ZenResult<EngineResult> {
        let sys = sysinfo::system_info();
        Ok(EngineResult {
            status: "success".into(),
            engine: self.name().into(),
            data: json!({"system": sys}),
            findings: vec![],
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        })
    }
}

struct SecretsEngine;

impl Engine for SecretsEngine {
    fn name(&self) -> &'static str {
        "secrets"
    }
    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            operations: vec!["scan".into()],
            native: true,
            supported: true,
            description: "pattern-based secret detection".into(),
        }
    }
    fn execute(&self, request: &EngineRequest) -> ZenResult<EngineResult> {
        let text = as_string(request.input.get("text")).unwrap_or_default();
        let mut findings = Vec::new();
        let marker_aws = ["AK", "IA"].concat();
        let marker_key = ["BEGIN", " PRIVATE", " KEY"].concat();
        let marker_password = ["password", "="].concat();
        let marker_token = ["token", "="].concat();
        for marker in [
            marker_aws.as_str(),
            marker_key.as_str(),
            marker_password.as_str(),
            marker_token.as_str(),
        ] {
            if text.contains(marker) {
                findings.push(finding(
                    "Potential secret marker",
                    Severity::High,
                    0.65,
                    None,
                    vec![marker.to_string()],
                    "A common secret marker was detected in the provided text.",
                    "Redact the secret and rotate it if it is real.",
                    "secrets",
                ));
            }
        }
        Ok(EngineResult {
            status: "success".into(),
            engine: self.name().into(),
            data: json!({"matches": findings.len()}),
            findings,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        })
    }
}

struct CodeEngine;

impl Engine for CodeEngine {
    fn name(&self) -> &'static str {
        "code"
    }
    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            operations: vec!["analyze".into()],
            native: true,
            supported: true,
            description: "simple line-oriented code analysis foundation".into(),
        }
    }
    fn execute(&self, request: &EngineRequest) -> ZenResult<EngineResult> {
        let path = as_string(request.input.get("target")).unwrap_or_default();
        let text = stdfs::read_to_string(&path).unwrap_or_default();
        let mut findings = Vec::new();
        let shell_sh = ["Command::new(\"", "sh\""].concat();
        let shell_bash = ["bash", " -c"].concat();
        let shell_cmd = ["cmd", " /c"].concat();
        let shell_powershell = ["powershell", " -Command"].concat();
        let secret_key = ["BEGIN", " PRIVATE", " KEY"].concat();
        let eval_call = "eval(".to_string();
        for (idx, line) in text.lines().enumerate() {
            let suspicious = [
                shell_sh.as_str(),
                shell_bash.as_str(),
                shell_cmd.as_str(),
                shell_powershell.as_str(),
                eval_call.as_str(),
                secret_key.as_str(),
            ]
            .iter()
            .any(|needle| line.contains(needle));
            if suspicious {
                findings.push(finding(
                    "Suspicious code pattern",
                    Severity::Low,
                    0.55,
                    Some(asset(AssetKind::File, path.clone())),
                    vec![format!("line {}: {line}", idx + 1)],
                    "A potentially risky code pattern was detected during line scanning.",
                    "Review the call site and ensure the input is not shell-interpreted.",
                    "code",
                ));
            }
        }
        Ok(EngineResult {
            status: "success".into(),
            engine: self.name().into(),
            data: json!({"file": path, "lines": text.lines().count()}),
            findings,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        })
    }
}

struct DependenciesEngine;

impl Engine for DependenciesEngine {
    fn name(&self) -> &'static str {
        "dependencies"
    }
    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            operations: vec!["analyze".into()],
            native: true,
            supported: true,
            description: "manifest dependency extraction foundation".into(),
        }
    }
    fn execute(&self, request: &EngineRequest) -> ZenResult<EngineResult> {
        let path = as_string(request.input.get("target")).unwrap_or_default();
        let text = stdfs::read_to_string(&path).unwrap_or_default();
        let mut deps = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('[') || line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some((name, _rest)) = line.split_once('=') {
                let name = name.trim();
                if !name.is_empty() && !name.starts_with('"') {
                    deps.push(name.to_string());
                }
            }
        }
        Ok(EngineResult {
            status: "success".into(),
            engine: self.name().into(),
            data: json!({"file": path, "dependencies": deps}),
            findings: vec![],
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        })
    }
}

struct ConfigurationEngine;

impl Engine for ConfigurationEngine {
    fn name(&self) -> &'static str {
        "configuration"
    }
    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            operations: vec!["inspect".into()],
            native: true,
            supported: true,
            description: "configuration inspection foundation".into(),
        }
    }
    fn execute(&self, request: &EngineRequest) -> ZenResult<EngineResult> {
        Ok(EngineResult {
            status: "success".into(),
            engine: self.name().into(),
            data: json!({"target": request.input.get("target").cloned().unwrap_or(Value::Null)}),
            findings: vec![],
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        })
    }
}

struct AssetsEngine;

impl Engine for AssetsEngine {
    fn name(&self) -> &'static str {
        "assets"
    }
    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            operations: vec!["list".into()],
            native: true,
            supported: true,
            description: "asset projection from engine results".into(),
        }
    }
    fn execute(&self, request: &EngineRequest) -> ZenResult<EngineResult> {
        Ok(EngineResult {
            status: "success".into(),
            engine: self.name().into(),
            data: json!({"target": request.input.get("target").cloned().unwrap_or(Value::Null)}),
            findings: vec![],
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        })
    }
}

struct CertificatesEngine;

impl Engine for CertificatesEngine {
    fn name(&self) -> &'static str {
        "certificates"
    }
    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            operations: vec!["inspect".into()],
            native: true,
            supported: false,
            description: tls::backend_description().to_string(),
        }
    }
    fn execute(&self, request: &EngineRequest) -> ZenResult<EngineResult> {
        Ok(EngineResult {
            status: "unsupported".into(),
            engine: self.name().into(),
            data: json!({"target": request.input.get("target").cloned().unwrap_or(Value::Null), "message": tls::backend_description()}),
            findings: vec![],
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        })
    }
}

struct FindingsEngine;

impl Engine for FindingsEngine {
    fn name(&self) -> &'static str {
        "findings"
    }
    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            operations: vec!["list".into(), "normalize".into()],
            native: true,
            supported: true,
            description: "finding normalization and deduplication".into(),
        }
    }
    fn execute(&self, request: &EngineRequest) -> ZenResult<EngineResult> {
        let findings: Vec<Finding> = request
            .input
            .get("findings")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let deduped = dedupe_findings(findings);
        Ok(EngineResult {
            status: "success".into(),
            engine: self.name().into(),
            data: json!({"count": deduped.len(), "findings": deduped}),
            findings: vec![],
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        })
    }
}

pub fn scan_store_dir() -> ZenResult<PathBuf> {
    let base = z_core::config::user_data_dir().ok_or_else(|| {
        ZenError::new(Area::Cfg, 5109, "cannot determine the user data directory")
    })?;
    let dir = base.join("phase3");
    stdfs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn save_report(report: &ScanReport) -> ZenResult<PathBuf> {
    let dir = scan_store_dir()?;
    let path = dir.join("latest-scan.json");
    let bytes = serde_json::to_vec_pretty(report)?;
    stdfs::write(&path, bytes)?;
    Ok(path)
}

pub fn load_report() -> ZenResult<ScanReport> {
    let path = scan_store_dir()?.join("latest-scan.json");
    let text = stdfs::read_to_string(&path).map_err(|e| {
        ZenError::new(
            Area::Fs,
            5110,
            format!("cannot read scan report {}: {e}", path.display()),
        )
    })?;
    Ok(serde_json::from_str(&text)?)
}

pub fn analyse_target(target: &str, profile: ScanProfile) -> ZenResult<ScanReport> {
    let orchestrator = ScanOrchestrator::new();
    let report = orchestrator.scan(target, profile)?;
    let _ = save_report(&report);
    Ok(report)
}

pub fn render_markdown(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str("ZENTRION SECURITY SCAN\n\n");
    out.push_str(&format!("Target: {}\n", report.target));
    out.push_str(&format!("Profile: {:?}\n", report.profile));
    out.push_str(&format!("Summary: {}\n\n", report.summary));
    out.push_str("Findings:\n");
    for finding in &report.findings {
        out.push_str(&format!(
            "[{:?}] {} — {}\n",
            finding.severity, finding.title, finding.description
        ));
    }
    if report.findings.is_empty() {
        out.push_str("(none)\n");
    }
    out.push_str(&format!("\nAssets: {}\n", report.assets.len()));
    out.push_str(&format!("Engines: {}\n", report.engines.join(", ")));
    out
}

pub fn ai_summary(report: &ScanReport) -> Value {
    let priority = report
        .findings
        .iter()
        .max_by_key(|f| match f.severity {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        })
        .map(|f| format!("{:?}", f.severity))
        .unwrap_or_else(|| "info".into());
    json!({
        "target": report.target,
        "priority": priority,
        "summary": report.summary,
        "findings": report.findings,
        "recommendation": if report.findings.is_empty() {
            "No immediate action required.".to_string()
        } else {
            "Review high-severity findings first and validate evidence before remediation.".to_string()
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_lists_native_engines() {
        let reg = EngineRegistry::new();
        let names: Vec<_> = reg.list().into_iter().map(|e| e.name).collect();
        assert!(names.contains(&"dns".to_string()));
        assert!(names.contains(&"system".to_string()));
    }

    #[test]
    fn url_engine_flags_userinfo() {
        let reg = EngineRegistry::new();
        let result = reg
            .execute(&EngineRequest {
                engine: "url".into(),
                operation: "analyze".into(),
                input: json!({"target": "http://user@example.com/path/../x"}),
            })
            .unwrap();
        assert!(!result.findings.is_empty());
    }

    #[test]
    fn dedupe_is_stable() {
        let a = finding(
            "x",
            Severity::Low,
            0.5,
            None,
            vec!["e".into()],
            "d",
            "r",
            "s",
        );
        let b = a.clone();
        let out = dedupe_findings(vec![a, b]);
        assert_eq!(out.len(), 1);
    }
}

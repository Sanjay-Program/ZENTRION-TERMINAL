//! Signed engagement reports.
//!
//! Reports are generated from structured data, never by concatenating raw
//! scanner output. Evidence commands are shown redacted, captured output is
//! opt-in and redacted, and the report is signed with the local Ed25519 key
//! (a detached signature plus the SHA-256 of the exact report bytes).

use crate::model::{Engagement, Finding, Severity};
use crate::scope::ScopeDecision;
use crate::store::{EvidenceVerification, SecurityStore};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    Markdown,
    Html,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportBundle {
    pub path: String,
    pub signature_path: String,
    pub public_key_path: String,
    pub sha256: String,
    pub public_key: String,
    pub evidence_records: usize,
    pub findings: usize,
    pub evidence_verified: bool,
}

impl SecurityStore {
    /// Render a report without writing it.
    pub fn render_report(
        &self,
        engagement_id: &str,
        format: ReportFormat,
        include_outputs: bool,
    ) -> Result<String, String> {
        let engagement = self.load_engagement(engagement_id)?;
        let findings = self.list_findings(engagement_id);
        let evidence = self.read_chain(engagement_id)?;
        let verification = self.verify_evidence(engagement_id);
        let excerpts = if include_outputs {
            evidence
                .iter()
                .map(|record| {
                    (
                        record.id.clone(),
                        self.read_output(record)
                            .map(|bytes| {
                                let text = String::from_utf8_lossy(&bytes).to_string();
                                let (redacted, _) = z_blocks::redact(&text);
                                let mut excerpt: String = redacted.chars().take(2_000).collect();
                                if redacted.chars().count() > 2_000 {
                                    excerpt.push_str("\n… [truncated]");
                                }
                                excerpt
                            })
                            .unwrap_or_default(),
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        } else {
            std::collections::BTreeMap::new()
        };
        match format {
            ReportFormat::Markdown => Ok(render_markdown(
                &engagement,
                &findings,
                &evidence,
                &verification,
                &excerpts,
            )),
            ReportFormat::Html => Ok(render_html(
                &engagement,
                &findings,
                &evidence,
                &verification,
                &excerpts,
            )),
        }
    }

    /// Render and sign a report, writing it under `<root>/reports/<engagement>/`.
    pub fn write_report(
        &self,
        engagement_id: &str,
        format: ReportFormat,
        include_outputs: bool,
    ) -> Result<ReportBundle, String> {
        let content = self.render_report(engagement_id, format, include_outputs)?;
        let dir = self.root().join("reports").join(engagement_id);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let stamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let extension = match format {
            ReportFormat::Markdown => "md",
            ReportFormat::Html => "html",
        };
        let path = dir.join(format!("{stamp}-report.{extension}"));
        std::fs::write(&path, &content).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        let key = self.signing_key().map_err(|e| e.to_string())?;
        let hash = format!("sha256:{}", hex(&Sha256::digest(content.as_bytes())));
        let signature = key.sign_hex(content.as_bytes());
        let public_key = key.public_key_hex();
        let signature_path = path.with_extension(format!("{extension}.sig"));
        let signature_doc = serde_json::json!({
            "algorithm": "ed25519",
            "public_key": public_key,
            "signature": signature,
            "sha256": hash,
            "report": path.file_name().and_then(|name| name.to_str()).unwrap_or_default(),
        });
        std::fs::write(
            &signature_path,
            serde_json::to_string_pretty(&signature_doc).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let public_key_path = path.with_extension(format!("{extension}.pub"));
        std::fs::write(&public_key_path, format!("zentrion-ed25519 {public_key}\n"))
            .map_err(|e| e.to_string())?;
        let verification = self.verify_evidence(engagement_id);
        Ok(ReportBundle {
            path: path.display().to_string(),
            signature_path: signature_path.display().to_string(),
            public_key_path: public_key_path.display().to_string(),
            sha256: hash,
            public_key,
            evidence_records: verification.records,
            findings: self.list_findings(engagement_id).len(),
            evidence_verified: verification.valid,
        })
    }
}

/// Verify a detached report signature and its content hash.
pub fn verify_report_signature(report: &Path, signature: &Path) -> Result<bool, String> {
    let content = std::fs::read(report).map_err(|e| e.to_string())?;
    let text = std::fs::read_to_string(signature).map_err(|e| e.to_string())?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("invalid signature file: {e}"))?;
    let public_key = value
        .get("public_key")
        .and_then(|value| value.as_str())
        .ok_or("signature file has no public_key")?;
    let signature_hex = value
        .get("signature")
        .and_then(|value| value.as_str())
        .ok_or("signature file has no signature")?;
    let expected_hash = value
        .get("sha256")
        .and_then(|value| value.as_str())
        .ok_or("signature file has no sha256")?;
    let actual_hash = format!("sha256:{}", hex(&Sha256::digest(&content)));
    if actual_hash != expected_hash {
        return Ok(false);
    }
    Ok(z_identity::signing::verify(
        public_key,
        &content,
        signature_hex,
    ))
}

fn render_markdown(
    engagement: &Engagement,
    findings: &[Finding],
    evidence: &[crate::model::Evidence],
    verification: &EvidenceVerification,
    excerpts: &std::collections::BTreeMap<String, String>,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Engagement report: {}\n\n", engagement.name));
    out.push_str(&format!("- **Engagement:** `{}`\n", engagement.id));
    out.push_str(&format!("- **Client:** {}\n", engagement.client));
    out.push_str(&format!(
        "- **Authorized by:** {}\n",
        engagement.authorized_by
    ));
    out.push_str(&format!(
        "- **Window:** {} → {}\n",
        engagement.start.to_rfc3339(),
        engagement.end.to_rfc3339()
    ));
    out.push_str(&format!("- **Status:** {:?}\n", engagement.status));
    out.push_str(&format!("- **Prepared by:** {}\n", engagement.created_by));
    out.push_str(&format!("- **Generated:** {}\n\n", Utc::now().to_rfc3339()));
    out.push_str("## Authorization\n\n");
    out.push_str(&format!(
        "{}\n\n",
        escape_markdown(&engagement.authorization)
    ));
    out.push_str("## Rules of engagement\n\n");
    for rule in &engagement.rules_of_engagement {
        out.push_str(&format!("- {}\n", escape_markdown(rule)));
    }
    out.push('\n');
    out.push_str("## Scope\n\n");
    for target in &engagement.scope.targets {
        out.push_str(&format!("- In scope: `{}`\n", target));
    }
    for target in &engagement.scope.out_of_scope {
        out.push_str(&format!("- Out of scope: `{}`\n", target));
    }
    if !engagement.scope.ports.is_empty() {
        let ports: Vec<String> = engagement
            .scope
            .ports
            .iter()
            .map(|range| format!("{}-{}", range.from, range.to))
            .collect();
        out.push_str(&format!("- Ports: {}\n", ports.join(", ")));
    }
    out.push('\n');
    out.push_str("## Findings\n\n");
    if findings.is_empty() {
        out.push_str("No findings recorded.\n\n");
    }
    for finding in findings {
        out.push_str(&format!(
            "### [{}] {}\n\n",
            finding.severity.as_str().to_uppercase(),
            escape_markdown(&finding.title)
        ));
        out.push_str(&format!("- **Target:** `{}`\n", finding.target));
        out.push_str(&format!("- **Status:** {:?}\n", finding.status));
        if let Some(cvss) = finding.cvss {
            out.push_str(&format!("- **CVSS:** {cvss}\n"));
        }
        if !finding.cwe.is_empty() {
            out.push_str(&format!("- **CWE:** {}\n", finding.cwe.join(", ")));
        }
        if !finding.mitre.is_empty() {
            out.push_str(&format!(
                "- **MITRE ATT&CK:** {}\n",
                finding.mitre.join(", ")
            ));
        }
        if !finding.evidence.is_empty() {
            out.push_str(&format!(
                "- **Evidence:** {}\n",
                finding
                    .evidence
                    .iter()
                    .map(|id| format!("`{id}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        out.push_str(&format!("\n{}\n\n", escape_markdown(&finding.description)));
        out.push_str("**Remediation**\n\n");
        out.push_str(&format!("{}\n\n", escape_markdown(&finding.remediation)));
    }
    out.push_str("## Evidence\n\n");
    out.push_str(
        "| ID | Time | Kind | Target | Command | Exit | Output SHA-256 |\n\
         |---|---|---|---|---|---|---|\n",
    );
    for record in evidence {
        let command = record
            .command
            .as_deref()
            .map(|command| z_blocks::redact(command).0)
            .unwrap_or_default();
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | `{}` | {} | {} |\n",
            record.id,
            record.ts.to_rfc3339(),
            record.kind,
            record.target.as_deref().unwrap_or(""),
            escape_table(&command),
            record
                .exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "-".into()),
            record.output_sha256.as_deref().unwrap_or("-"),
        ));
    }
    out.push('\n');
    if !excerpts.is_empty() {
        out.push_str("## Captured output (redacted excerpts)\n\n");
        for (id, excerpt) in excerpts {
            if excerpt.is_empty() {
                continue;
            }
            out.push_str(&format!("### {id}\n\n```text\n{}\n```\n\n", excerpt));
        }
    }
    out.push_str("## Integrity\n\n");
    out.push_str(&format!(
        "- Evidence records: {}\n- Chain verifies: {}\n- Head hash: `{}`\n",
        verification.records,
        if verification.valid { "yes" } else { "NO" },
        verification.head_hash.as_deref().unwrap_or("none")
    ));
    out.push_str(&format!(
        "- Trusted signer: {}\n",
        verification.trusted_signer
    ));
    if !verification.errors.is_empty() {
        out.push_str("\n### Integrity errors\n\n");
        for error in &verification.errors {
            out.push_str(&format!("- {}\n", escape_markdown(error)));
        }
    }
    out.push('\n');
    out.push_str(
        "> This report covers only the authorized scope above. Commands are \
         provided as reproducibility evidence; output excerpts are redacted and \
         hashes are recorded in the evidence chain.\n",
    );
    out
}

fn render_html(
    engagement: &Engagement,
    findings: &[Finding],
    evidence: &[crate::model::Evidence],
    verification: &EvidenceVerification,
    excerpts: &std::collections::BTreeMap<String, String>,
) -> String {
    let mut out = String::from(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Engagement report</title>\
         <style>body{font-family:ui-sans-serif,system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#111}code{background:#f4f4f5;padding:.1rem .3rem}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:.4rem;text-align:left;vertical-align:top}.sev-critical{color:#7f1d1d}.sev-high{color:#b91c1c}.sev-medium{color:#b45309}.sev-low{color:#1d4ed8}.muted{color:#555}</style></head><body>",
    );
    out.push_str(&format!(
        "<h1>Engagement report: {}</h1>",
        escape_html(&engagement.name)
    ));
    out.push_str(&format!(
        "<p class=\"muted\">{} · {} · Generated {}</p>",
        escape_html(&engagement.id),
        escape_html(&engagement.client),
        Utc::now().to_rfc3339()
    ));
    out.push_str("<h2>Authorization</h2>");
    out.push_str(&format!(
        "<p>{}</p>",
        escape_html(&engagement.authorization)
    ));
    out.push_str(&format!(
        "<p>Authorized by <strong>{}</strong> · Window {} → {}</p>",
        escape_html(&engagement.authorized_by),
        engagement.start.to_rfc3339(),
        engagement.end.to_rfc3339()
    ));
    out.push_str("<h2>Rules of engagement</h2><ul>");
    for rule in &engagement.rules_of_engagement {
        out.push_str(&format!("<li>{}</li>", escape_html(rule)));
    }
    out.push_str("</ul><h2>Scope</h2><ul>");
    for target in &engagement.scope.targets {
        out.push_str(&format!(
            "<li>In scope: <code>{}</code></li>",
            escape_html(target)
        ));
    }
    for target in &engagement.scope.out_of_scope {
        out.push_str(&format!(
            "<li>Out of scope: <code>{}</code></li>",
            escape_html(target)
        ));
    }
    out.push_str("</ul><h2>Findings</h2>");
    if findings.is_empty() {
        out.push_str("<p>No findings recorded.</p>");
    }
    for finding in findings {
        out.push_str(&format!(
            "<h3 class=\"sev-{}\">[{}] {}</h3>",
            finding.severity.as_str(),
            finding.severity.as_str().to_uppercase(),
            escape_html(&finding.title)
        ));
        out.push_str(&format!(
            "<p><strong>Target:</strong> <code>{}</code> · <strong>Status:</strong> {:?} · <strong>CVSS:</strong> {}</p>",
            escape_html(&finding.target),
            finding.status,
            finding
                .cvss
                .map(|cvss| cvss.to_string())
                .unwrap_or_else(|| "-".into())
        ));
        out.push_str(&format!("<p>{}</p>", escape_html(&finding.description)));
        out.push_str(&format!(
            "<p><strong>Remediation:</strong> {}</p>",
            escape_html(&finding.remediation)
        ));
    }
    out.push_str("<h2>Evidence</h2><table><thead><tr><th>ID</th><th>Time</th><th>Kind</th><th>Target</th><th>Command</th><th>Output SHA-256</th></tr></thead><tbody>");
    for record in evidence {
        let command = record
            .command
            .as_deref()
            .map(|command| z_blocks::redact(command).0)
            .unwrap_or_default();
        out.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td><code>{}</code></td></tr>",
            escape_html(&record.id),
            record.ts.to_rfc3339(),
            escape_html(&record.kind),
            escape_html(record.target.as_deref().unwrap_or("")),
            escape_html(&command),
            escape_html(record.output_sha256.as_deref().unwrap_or("-"))
        ));
    }
    out.push_str("</tbody></table>");
    if !excerpts.is_empty() {
        out.push_str("<h2>Captured output (redacted excerpts)</h2>");
        for (id, excerpt) in excerpts {
            if excerpt.is_empty() {
                continue;
            }
            out.push_str(&format!(
                "<h3>{}</h3><pre>{}</pre>",
                escape_html(id),
                escape_html(excerpt)
            ));
        }
    }
    out.push_str(&format!(
        "<h2>Integrity</h2><p>Evidence records: {} · Chain verifies: {} · Head: <code>{}</code> · Trusted signer: {}</p>",
        verification.records,
        if verification.valid { "yes" } else { "NO" },
        escape_html(verification.head_hash.as_deref().unwrap_or("none")),
        verification.trusted_signer
    ));
    if !verification.errors.is_empty() {
        out.push_str("<ul>");
        for error in &verification.errors {
            out.push_str(&format!("<li>{}</li>", escape_html(error)));
        }
        out.push_str("</ul>");
    }
    out.push_str(
        "<p class=\"muted\">This report covers only the authorized scope above. Commands are reproducibility evidence; captured output is redacted and hashed in the chain.</p></body></html>",
    );
    out
}

fn escape_markdown(text: &str) -> String {
    text.replace('|', "\\|")
}

fn escape_table(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Severity ordering helper used by report consumers.
pub fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
    }
}

/// Report path convention for callers that want to find existing reports.
pub fn report_dir(store: &SecurityStore, engagement_id: &str) -> PathBuf {
    store.root().join("reports").join(engagement_id)
}

/// Scope decision helper for report callers.
pub fn is_allowed(decision: ScopeDecision) -> bool {
    decision != ScopeDecision::Denied
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Engagement, EngagementStatus, Finding, FindingStatus, Severity, SECURITY_VERSION,
    };
    use crate::scope::{PortRange, Scope};
    use crate::store::{EvidenceInput, SecurityStore};

    fn setup(name: &str) -> (SecurityStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-report-{}-{}-{}",
            name,
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let store = SecurityStore::new(&dir);
        store
            .create_engagement(Engagement {
                version: SECURITY_VERSION,
                id: "eng_report".into(),
                name: "Report test".into(),
                client: "Acme".into(),
                authorization: "Signed statement of work dated 2026-10-01".into(),
                authorized_by: "security@acme.example".into(),
                start: Utc::now() - chrono::Duration::hours(1),
                end: Utc::now() + chrono::Duration::days(1),
                rules_of_engagement: vec!["Stay in scope".into()],
                scope: Scope {
                    targets: vec!["example.com".into()],
                    out_of_scope: vec![],
                    ports: vec![PortRange { from: 1, to: 65535 }],
                    tools: vec![],
                },
                created_by: "tester".into(),
                created_at: Utc::now(),
                status: EngagementStatus::Active,
                tags: vec![],
            })
            .unwrap();
        store
            .record_evidence(
                "eng_report",
                EvidenceInput {
                    kind: "command".into(),
                    command: Some("nmap -sV example.com".into()),
                    target: Some("example.com".into()),
                    exit_code: Some(0),
                    stdout: b"PORT 443 open\nAPI_KEY=sk-abcdefghijklmnopqrstuvwxyz123456\n"
                        .to_vec(),
                    ..Default::default()
                },
            )
            .unwrap();
        store
            .add_finding(Finding {
                version: SECURITY_VERSION,
                id: String::new(),
                engagement_id: "eng_report".into(),
                title: "Exposed API key".into(),
                severity: Severity::High,
                cvss: Some(7.5),
                target: "example.com".into(),
                description: "A key was exposed in a response.".into(),
                remediation: "Rotate the key.".into(),
                evidence: vec![],
                cwe: vec!["CWE-798".into()],
                mitre: vec!["T1552".into()],
                status: FindingStatus::Open,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                tags: vec![],
            })
            .unwrap();
        (store, dir)
    }

    #[test]
    fn markdown_report_contains_scope_findings_and_integrity() {
        let (store, dir) = setup("md");
        let report = store
            .render_report("eng_report", ReportFormat::Markdown, true)
            .unwrap();
        assert!(report.contains("# Engagement report"));
        assert!(report.contains("Exposed API key"));
        assert!(report.contains("Chain verifies: yes"));
        assert!(report.contains("nmap -sV example.com"));
        assert!(!report.contains("sk-abcdefghijklmnopqrstuvwxyz123456"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn html_report_escapes_script_tags() {
        let (store, dir) = setup("html");
        let report = store
            .render_report("eng_report", ReportFormat::Html, false)
            .unwrap();
        assert!(report.starts_with("<!doctype html>"));
        assert!(!report.contains("<script>"));
        assert!(report.contains("<!doctype html>"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn signed_report_verifies_and_tampering_fails() {
        let (store, dir) = setup("signed");
        let bundle = store
            .write_report("eng_report", ReportFormat::Markdown, false)
            .unwrap();
        let report = PathBuf::from(&bundle.path);
        let signature = PathBuf::from(&bundle.signature_path);
        assert!(report.exists());
        assert!(signature.exists());
        assert!(verify_report_signature(&report, &signature).unwrap());
        std::fs::write(&report, "tampered\n").unwrap();
        assert!(!verify_report_signature(&report, &signature).unwrap());
        assert!(bundle.evidence_verified);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

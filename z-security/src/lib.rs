//! `z-security` — authorized security engagement workbench.
//!
//! Scope is enforced before network I/O by [`SecurityStore::run_command`];
//! evidence is an append-only, Ed25519-signed hash chain with captured output
//! stored by hash; findings are scoped; reports are structured, redacted and
//! signed. Break-glass is explicit, reasoned and short-lived.
//!
//! This crate is for authorized testing only. It does not provide scanning
//! engines; it governs and records the tools you run.

pub mod model;
pub mod report;
pub mod scope;
pub mod store;

pub use model::{
    Engagement, EngagementStatus, Evidence, Finding, FindingStatus, Severity, Signature,
    SECURITY_VERSION,
};
pub use report::{
    is_allowed, report_dir, severity_rank, verify_report_signature, ReportBundle, ReportFormat,
};
pub use scope::{
    authorize, extract_targets, BreakGlass, PortRange, Scope, ScopeDecision, ScopeVerdict, Target,
};
pub use store::{
    CommandOutcome, EvidenceInput, EvidenceVerification, SecurityStore, DEFAULT_COMMAND_TIMEOUT,
    MAX_EVIDENCE_BYTES,
};

//! `z-workflow` — parameterized YAML workflows with approvals, conditions,
//! parallel steps, policy-gated HTTP and hashed artifacts.
//!
//! Workflows are code: running one is an explicit user action. Every step
//! produces an audit record (no secret values), shell steps are bounded by
//! timeouts, HTTP requires an explicit allowlist, and approvals are consulted
//! through a pluggable [`Approver`]. There is no scheduler in this crate yet;
//! `z workflow run` executes synchronously.

pub mod engine;
pub mod expr;
pub mod schema;

pub use engine::{
    list_runs, render, run, save_run, AllowAll, Approver, Artifact, AuditRecord, DenyAll,
    PromptApprover, RunOptions, RunReport, RunStatus, StepResult, StepStatus, WorkflowPolicy,
};
pub use schema::{
    load_workflow, parse_duration, parse_http_url, parse_workflow, AgentSpec, ArtifactStep,
    HttpStep, ParamSpec, Step, Workflow, WorkflowError,
};

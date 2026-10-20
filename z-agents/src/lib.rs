//! `z-agents` — host any CLI agent under the same policy/approval/audit path as
//! a human command.
//!
//! * [`adapter`] discovers and validates agent manifests.
//! * [`profile`] defines the built-in agent profiles (readonly/dev/security/ci).
//! * [`broker`] evaluates policy, queues approvals and issues single-use tokens.
//! * [`supervisor`] launches agents in PTYs, detects state and records traces.
//! * [`mcp_server`] exposes a local MCP server whose tools go through the broker.
//!
//! Screen-pattern state is labelled approximate. Nothing here claims an agent
//! is sandboxed: policy gates host effects, and the sandbox roadmap is separate.

pub mod adapter;
pub mod broker;
pub mod mcp_server;
pub mod profile;
pub mod supervisor;

pub use adapter::{
    builtins, default_dirs, discover, load_adapter, Adapter, AgentState, StatusParser,
};
pub use broker::{
    ApprovalBroker, ApprovalRequest, ApprovalStatus, BrokerOutcome, BrokerRequest, Token,
};
pub use mcp_server::{McpServer, McpServerOptions};
pub use profile::AgentProfile;
pub use supervisor::{AgentDashboardRow, AgentHandle, AgentRunInfo, LaunchOptions, Supervisor};

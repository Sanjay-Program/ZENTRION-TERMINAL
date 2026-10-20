//! `z-models` — local-first model registry, policy router, budgets and usage.
//!
//! Routing policies: manual, local-only, local-first, cost, latency, quality.
//! Successful calls are reserved against a durable daily ledger *before* the
//! provider is contacted, so a configured budget cannot be silently exceeded.
//! Fallback is ordered by policy; repeated failures open a circuit breaker.
//! Responses are cached only when the prompt contains no detected secrets.

pub mod ledger;
pub mod registry;
pub mod router;
pub mod transport;

pub use ledger::{
    estimate_micros, micros_to_usd, usd_to_micros, AgentUsage, LedgerError, Reservation,
    UsageLedger, UsageSummary,
};
pub use registry::{ProviderKind, ProviderSpec, Registry};
pub use router::{Attempt, ChatOutcome, Route, RouteRequest, Router, RouterError};
pub use transport::{ChatMessage, ChatOutput, HttpTransport, Transport, TransportError};

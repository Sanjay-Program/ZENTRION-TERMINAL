//! z-core — Zentrion core runtime library (04-CORE-RUNTIME).
//!
//! Contains the error model, layered configuration, host/platform probing,
//! filesystem and process abstractions, and the Runtime object.
//! Per ADR-001 this is Rust. Security stance: fail-closed, no network,
//! no telemetry by default.

pub mod config;
pub mod error;
pub mod fs;
pub mod host;
pub mod process;
pub mod runtime;

pub use error::{ZenError, ZenResult};

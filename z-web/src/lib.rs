//! `z-web` — a small, loopback-only web observer for live sessions.
//!
//! The client renders a plain-text screen snapshot (no ANSI), lists sessions
//! and can send input only when a write-scoped token is presented. It is not a
//! full terminal emulator and does not claim colors/cursor fidelity. There is
//! no TLS or inbound exposure: the listener refuses non-loopback addresses.
//!
//! Tokens are random 256-bit URL-safe strings; read and write tokens are
//! separate so an observer link cannot type into a session.

pub mod server;

pub use server::{
    serve, serve_on, SessionProvider, SessionSnapshot, SessionSummary, WebConfig, WebError,
};

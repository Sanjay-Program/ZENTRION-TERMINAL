//! `z-remote` — SSH destinations, remote execution, transfers and forwarding.
//!
//! The backend is the system OpenSSH client (honestly documented as such, not
//! a native SSH implementation). Host keys are always verified; extra options
//! that could disable verification or execute a local command are rejected.
//! Commands are passed as argument vectors — never through a local shell.
//!
//! Durable remote sessions (a remote `z-session` daemon over an SSH stream-local
//! tunnel) are not implemented yet.

pub mod runner;
pub mod target;

pub use runner::{Forward, ForwardRegistry, RemoteOutput, SshRunner};
pub use target::{
    default_timeout, ssh_config_hosts, validate_remote_path, RemoteError, SshOptions, SshTarget,
};

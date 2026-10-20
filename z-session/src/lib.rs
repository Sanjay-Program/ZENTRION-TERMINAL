//! `z-session` — durable PTY sessions, blocks, shell integration and the
//! per-user session daemon.
//!
//! A session is owned by the daemon, not by a UI. Clients attach over a Unix
//! socket, request a replay from a sequence number, and then receive live
//! binary output frames. Block lifecycle is driven by authoritative shell marks
//! (`OSC 133`); the terminal never scrapes the screen when hooks are present.
//!
//! Security posture: the socket is `0600`, there is no inbound network
//! listener, terminal output is parsed as data only, and every frame length is
//! bounded ([`protocol::MAX_FRAME`]).

pub mod daemon;
pub mod integration;
pub mod manager;
pub mod protocol;
pub mod session;
pub mod workspace;

#[cfg(unix)]
pub mod client;

#[cfg(unix)]
pub use client::{connect_or_spawn, spawn_daemon, try_connect, Attach, ClientEvent, SessionClient};
pub use daemon::{is_running, socket_path};
pub use integration::{
    ensure_scripts, plan_launch, read_captured_command, Launch, Manifest, ShellKind,
};
pub use manager::{resolve_shell, CreateParams, ManagerOptions, SessionManager};
pub use protocol::{OutputFrame, RpcRequest, RpcResponse, MAX_FRAME};
pub use session::{
    BlockSink, Mark, MarkerSplitter, OutputChunk, RingBuffer, Segment, SessionError, SessionEvent,
    SessionHandle, SessionInfo, SessionOptions, SessionSnapshot,
};
pub use workspace::{
    plan_restore, Direction, Layout, Pane, PaneAction, PanePlan, RestorePlan, Tab, Workspace,
    WorkspaceError, WorkspaceStore, WORKSPACE_VERSION,
};

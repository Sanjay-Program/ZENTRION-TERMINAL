//! `z-blocks` — command blocks, persistence, search and safe sharing.
//!
//! A block is created from authoritative shell-integration marks and owns its
//! command, cwd, timing, exit code, output, policy decision and agent
//! attribution. Output is stored gzip-chunked in SQLite (WAL) and indexed with
//! FTS5; sharing always redacts credential-shaped strings.

pub mod model;
pub mod recorder;
pub mod share;
pub mod store;

pub use model::{Block, BlockFilter, BlockSearchHit, BlockStatus, Session, StoreStats};
pub use recorder::{BlockRecorder, RecorderUpdate, MAX_BLOCK_OUTPUT};
pub use share::{block_to_html, block_to_markdown, redact, strip_ansi, Redaction, ShareOptions};
pub use store::{BlockStore, StoreError};

//! `z-context` — local repository index, symbol extraction and deterministic
//! context packs for agents.
//!
//! The index is SQLite (WAL + FTS5). It is incremental (hash based), honours
//! git's own ignore rules when available, skips symlinks and secret-shaped
//! files, and never sends anything that was not indexed. Symbol extraction is
//! lexer-level and labelled approximate; it does not claim tree-sitter accuracy.

pub mod index;
pub mod pack;
pub mod symbols;

pub use index::{
    fts_expression, FileEntry, IndexOptions, IndexStats, IndexStatus, RepoIndex, SearchHit,
};
pub use pack::{
    build_context, estimate_tokens, git_summary, ContextItem, ContextPack, ContextQuery, PackError,
    RedactionCount,
};
pub use symbols::{extract_symbols, language_for, Symbol};

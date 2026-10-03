//! z-tool — the Zentrion tool manager.

pub mod installer;
pub mod manifest;
pub mod store;

pub use installer::{install, plan, remove, rollback, InstallOutcome, InstallPlan};
pub use manifest::{
    ExecutionSpec, FilesystemScope, Publisher, Redistribution, ToolId, ToolManifest,
    ToolPermissions, CATEGORIES, MANIFEST_SCHEMA_VERSION,
};
pub use store::{InstallRecord, ToolStore};

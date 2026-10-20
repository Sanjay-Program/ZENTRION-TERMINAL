//! `z-notebook` — executable shell/markdown/AI notebooks.
//!
//! Cells run in order with parameter and previous-output interpolation, bounded
//! timeouts, output caps and secret redaction. Notebook runs produce the same
//! kind of audit records as workflows. AI cells go through an injected
//! [`AiExecutor`] (the CLI uses the model router); the library never calls a
//! model itself.

pub mod engine;
pub mod model;

pub use engine::{
    export_html, export_markdown, run, save_run, AiExecutor, CellResult, CellStatus, NoAi,
    ProcOutput, RunOptions, RunReport, RunStatus, ShellExecutor, SystemShell,
};
pub use model::{load, save, Cell, CellKind, Notebook, NotebookError, NOTEBOOK_VERSION};

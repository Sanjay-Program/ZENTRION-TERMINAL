//! `z-vt` — terminal parsing policy surface.
//!
//! [`vt100`] provides the screen model; this crate owns the *policy* around
//! terminal control sequences:
//!
//! * Shell integration marks (OSC 133), cwd (OSC 7/9;9), titles (OSC 0/2),
//!   notifications (OSC 9), progress (OSC 9;4), hyperlinks (OSC 8),
//!   clipboard (OSC 52) and the namespaced `OSC 1337;Zentrion` metadata.
//! * Strict size/scheme limits, no execution of output, and sanitisation of
//!   anything that reaches the UI.
//! * Screen search, copy-mode selections and link detection.
//!
//! Terminal output is untrusted data. Parsing never executes or opens
//! anything; the UI decides, through policy, whether an action is allowed.

pub mod links;
pub mod osc;
pub mod screen;
pub mod search;

pub use links::{detect_links, is_safe_scheme, DetectedLink, LinkKind};
pub use osc::{OscEvent, ProgressState, ShellIntegrationMeta, ShellMark, VtPolicy, VtScanner};
pub use screen::Terminal;
pub use search::{search_text, SearchHit, SearchOptions, Selection};

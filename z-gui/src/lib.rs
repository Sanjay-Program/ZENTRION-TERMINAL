//! `z-gui` — GPU-accelerated windowing backend for Zentrion Terminal.
//!
//! Architecture:
//! ```text
//!  ┌─────────────────────────────────────────┐
//!  │  winit EventLoop (platform window)       │
//!  │   └─ App (handles WindowEvent)           │
//!  │       ├─ GpuContext  (wgpu device/queue) │
//!  │       ├─ GlyphAtlas  (cosmic-text+swash) │
//!  │       ├─ Renderer    (wgpu pipelines)    │
//!  │       ├─ DropDown    (Quake animation)   │
//!  │       └─ ConfigWatcher (hot-reload)      │
//!  └─────────────────────────────────────────┘
//! ```
//!
//! The crate is intentionally layered so unit tests can exercise
//! `GlyphAtlas` and `DropDown` without a real GPU device.

pub mod atlas;
pub mod config_watch;
pub mod ctx;
pub mod dropdown;
pub mod renderer;
pub mod run;
pub mod vertex;

pub use atlas::GlyphAtlas;
pub use ctx::GpuContext;
pub use dropdown::DropDown;
pub use renderer::Renderer;
pub use run::launch;

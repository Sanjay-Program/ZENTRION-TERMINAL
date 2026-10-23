//! `launch` — top-level winit event-loop entry point.
//!
//! This is the only module that touches `winit` directly.  It creates the
//! window, initialises wgpu via [`crate::ctx::GpuContext`], sets up the
//! [`crate::renderer::Renderer`] and [`crate::atlas::GlyphAtlas`], and drives
//! the per-frame logic:
//!
//! 1. Poll config-hot-reload events.
//! 2. Advance the drop-down animation via [`crate::dropdown::DropDown::tick`].
//! 3. Layout glyphs from the current terminal screen using `cosmic-text`.
//! 4. Emit quads to the renderer and present.
//!
//! The drop-down toggle is bound to **F12** by default.

use crate::{
    atlas::{GlyphAtlas, GlyphKey},
    config_watch::ConfigWatcher,
    ctx::GpuContext,
    dropdown::DropDown,
    renderer::Renderer,
    vertex::{quad, GlyphVertex},
};
use anyhow::Result;
use cosmic_text::{Attrs, Buffer, FontSystem, Metrics, Shaping, SwashCache};
use std::{sync::Arc, time::Duration};
use winit::{
    application::ApplicationHandler,
    event::{ElementState, KeyEvent, WindowEvent},
    event_loop::{ActiveEventLoop, ControlFlow, EventLoop},
    keyboard::{Key, NamedKey},
    window::{Window, WindowId},
};

/// Configuration for the GPU window.
pub struct WindowConfig {
    pub title: String,
    pub width: u32,
    pub height: u32,
    /// Height of the Quake-style dropdown as a fraction of the screen.
    pub dropdown_fraction: f32,
    /// Animation duration for the dropdown.
    pub animation_duration: Duration,
    /// Path to the Zentrion config file (for hot-reload).
    pub config_path: Option<std::path::PathBuf>,
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            title: "Zentrion Terminal".into(),
            width: 1280,
            height: 720,
            dropdown_fraction: 0.5,
            animation_duration: Duration::from_millis(180),
            config_path: None,
        }
    }
}

/// Launch the GPU window and run until the user closes it.
///
/// This function **blocks** the calling thread until the window is closed.
pub fn launch(cfg: WindowConfig) -> Result<()> {
    let event_loop = EventLoop::new()?;
    event_loop.set_control_flow(ControlFlow::Poll);

    let mut app = App::new(cfg);
    event_loop.run_app(&mut app)?;
    Ok(())
}

// ── Internal app state ────────────────────────────────────────────────────────

struct GpuState {
    window:   Arc<Window>,
    renderer: Renderer,
    atlas:    GlyphAtlas,
    font_sys: FontSystem,
    #[allow(dead_code)]
    swash:    SwashCache,
}

struct App {
    cfg:      WindowConfig,
    gpu:      Option<GpuState>,
    dropdown: DropDown,
    watcher:  Option<ConfigWatcher>,
    last_frame: std::time::Instant,
}

impl App {
    fn new(cfg: WindowConfig) -> Self {
        let dropdown = DropDown::new(cfg.animation_duration);
        Self {
            cfg,
            gpu: None,
            dropdown,
            watcher: None,
            last_frame: std::time::Instant::now(),
        }
    }
}

impl ApplicationHandler for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        // Create window.
        let attrs = Window::default_attributes()
            .with_title(&self.cfg.title)
            .with_inner_size(winit::dpi::PhysicalSize::new(self.cfg.width, self.cfg.height));

        let window = Arc::new(
            event_loop
                .create_window(attrs)
                .expect("failed to create window"),
        );

        // Bootstrap the async GPU context on the current thread using a
        // one-shot Tokio runtime.
        let ctx = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("tokio runtime")
            .block_on(async {
                // Safety: surface must outlive the instance, which lives in GpuContext.
                let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
                    backends: wgpu::Backends::all(),
                    ..Default::default()
                });
                // SAFETY: window lives inside Arc and outlives the surface.
                let surface = instance
                    .create_surface(window.clone())
                    .expect("failed to create wgpu surface");
                GpuContext::new(Some(&surface)).await.expect("GpuContext")
            });

        let size = window.inner_size();
        let atlas_size = 2048_u32.min(ctx.max_texture_size());
        let atlas = GlyphAtlas::new(atlas_size.min(2048));

        // Re-create the surface (we need to own it now).
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: wgpu::Backends::all(),
            ..Default::default()
        });
        // SAFETY: window Arc is alive for the lifetime of Renderer.
        let surface: wgpu::Surface<'static> = unsafe {
            // winit 0.30 / wgpu 0.20 provide this via rwh_06 feature.
            instance
                .create_surface_unsafe(wgpu::SurfaceTargetUnsafe::from_window(window.as_ref())
                    .expect("surface target"))
                .expect("surface")
        };

        let renderer = Renderer::new(
            ctx,
            Arc::new(surface),
            size.width,
            size.height,
            atlas_size.min(2048),
        )
        .expect("Renderer::new");

        // Start config hot-reload watcher.
        if let Some(ref path) = self.cfg.config_path {
            match ConfigWatcher::new(path) {
                Ok(w) => self.watcher = Some(w),
                Err(e) => log::warn!("config watcher failed: {e}"),
            }
        }

        self.gpu = Some(GpuState {
            window,
            renderer,
            atlas,
            font_sys: FontSystem::new(),
            swash: SwashCache::new(),
        });
        self.last_frame = std::time::Instant::now();
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        event: WindowEvent,
    ) {
        let Some(gpu) = self.gpu.as_mut() else { return };

        match event {
            WindowEvent::CloseRequested => {
                event_loop.exit();
            }

            WindowEvent::Resized(size) => {
                gpu.renderer.resize(size.width, size.height);
                gpu.window.request_redraw();
            }

            WindowEvent::KeyboardInput {
                event:
                    KeyEvent {
                        logical_key: Key::Named(NamedKey::F12),
                        state: ElementState::Pressed,
                        ..
                    },
                ..
            } => {
                self.dropdown.toggle();
                gpu.window.request_redraw();
            }

            WindowEvent::RedrawRequested => {
                // Poll config watcher.
                if let Some(ref watcher) = self.watcher {
                    for ev in watcher.poll() {
                        log::info!("config changed: {:?}", ev);
                        // TODO: re-read and apply the config here.
                    }
                }

                // Advance drop-down animation.
                let now = std::time::Instant::now();
                let dt = now.duration_since(self.last_frame).as_secs_f32();
                self.last_frame = now;
                let still_animating = self.dropdown.tick(dt);

                // ── Glyph layout (demo) ────────────────────────────────────
                // In production this would be driven by the terminal screen
                // model from `z-vt::Terminal`.  For now we render a banner.
                let mut vertices: Vec<GlyphVertex> = Vec::new();
                let size = gpu.window.inner_size();
                let _y_offset = self.dropdown.y_offset_px(size.height);

                let text = "Zentrion  //  GPU terminal  (F12 to toggle)";
                let metrics = Metrics::new(16.0, 20.0);
                let attrs = Attrs::new();
                let mut buffer = Buffer::new(&mut gpu.font_sys, metrics);
                buffer.set_size(&mut gpu.font_sys, Some(size.width as f32), Some(size.height as f32));
                buffer.set_text(&mut gpu.font_sys, text, attrs, Shaping::Advanced);
                buffer.shape_until_scroll(&mut gpu.font_sys, false);

                let fg = [1.0_f32, 0.85, 0.35, 1.0]; // amber accent
                let max_tex = gpu.atlas.width;

                for run in buffer.layout_runs() {
                    for glyph in run.glyphs.iter() {
                        let physical = glyph.physical((0.0, 0.0), 1.0);
                        let key = GlyphKey { cache_key: physical.cache_key };
                        if let Some(slot) = gpu.atlas.get_or_insert(
                            key,
                            &physical,
                            max_tex,
                        ) {
                            let r = slot.rect;
                            let uv = slot.uv;
                            let gw = (r.max.x - r.min.x) as f32;
                            let gh = (r.max.y - r.min.y) as f32;
                            let px = physical.x as f32;
                            let py = run.line_y + physical.y as f32;
                            let q = quad(px, py, gw, gh, uv[0], uv[1], uv[2], uv[3], fg);
                            for v in &q { vertices.push(*v); }
                        }
                    }
                }

                // Render.
                if let Err(e) = gpu.renderer.render(&mut gpu.atlas, &vertices) {
                    log::error!("render error: {e}");
                }

                if still_animating {
                    gpu.window.request_redraw();
                }
            }

            _ => {}
        }
    }

    fn about_to_wait(&mut self, _event_loop: &ActiveEventLoop) {
        if let Some(gpu) = self.gpu.as_ref() {
            gpu.window.request_redraw();
        }
    }
}

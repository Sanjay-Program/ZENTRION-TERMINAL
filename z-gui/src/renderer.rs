//! `Renderer` — wgpu render pipeline.
//!
//! Responsibilities:
//! * Maintain the swap-chain / surface texture.
//! * Keep the glyph atlas texture in sync with [`crate::atlas::GlyphAtlas`].
//! * Accept a per-frame list of [`crate::vertex::GlyphVertex`] quads and
//!   upload + draw them in a single render pass.
//! * Expose a `resize()` method called from the `winit` resize event.
//!
//! The WGSL shader is embedded directly in this file to avoid any file-system
//! dependency at runtime.

use crate::atlas::GlyphAtlas;
use crate::ctx::GpuContext;
use crate::vertex::{GlyphVertex, QUAD_INDICES};
use anyhow::{Context, Result};
use std::sync::Arc;

/// Compile-time embedded WGSL shader source.
const SHADER_SRC: &str = r#"
// ── Uniforms ──────────────────────────────────────────────────────────────
struct Globals {
    screen_size: vec2<f32>,     // in physical pixels
};
@group(0) @binding(0)
var<uniform> globals: Globals;

// ── Texture & sampler ─────────────────────────────────────────────────────
@group(1) @binding(0)
var t_atlas: texture_2d<f32>;
@group(1) @binding(1)
var s_atlas: sampler;

// ── Vertex stage ──────────────────────────────────────────────────────────
struct VertexIn {
    @location(0) position : vec2<f32>,
    @location(1) tex_coord: vec2<f32>,
    @location(2) color    : vec4<f32>,
};

struct VertexOut {
    @builtin(position) clip_pos: vec4<f32>,
    @location(0)       tex_coord: vec2<f32>,
    @location(1)       color    : vec4<f32>,
};

@vertex
fn vs_main(in: VertexIn) -> VertexOut {
    // Convert from pixel-space to clip-space [-1, 1].
    let clip = vec2<f32>(
         2.0 * in.position.x / globals.screen_size.x - 1.0,
        -2.0 * in.position.y / globals.screen_size.y + 1.0,
    );
    var out: VertexOut;
    out.clip_pos  = vec4<f32>(clip, 0.0, 1.0);
    out.tex_coord = in.tex_coord;
    out.color     = in.color;
    return out;
}

// ── Fragment stage ────────────────────────────────────────────────────────
@fragment
fn fs_main(in: VertexOut) -> @location(0) vec4<f32> {
    let mask = textureSample(t_atlas, s_atlas, in.tex_coord).a;
    return vec4<f32>(in.color.rgb, in.color.a * mask);
}
"#;

/// Per-frame uniform block.
#[repr(C)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
struct GlobalsUniform {
    screen_size: [f32; 2],
    _pad: [f32; 2],
}

/// The full GPU render pipeline for Zentrion's GPU window.
pub struct Renderer {
    ctx:           GpuContext,
    surface:       Arc<wgpu::Surface<'static>>,
    surface_cfg:   wgpu::SurfaceConfiguration,
    pipeline:      wgpu::RenderPipeline,
    vertex_buf:    wgpu::Buffer,
    index_buf:     wgpu::Buffer,
    uniform_buf:   wgpu::Buffer,
    globals_bg:    wgpu::BindGroup,
    atlas_tex:     wgpu::Texture,
    atlas_view:    wgpu::TextureView,
    atlas_sampler: wgpu::Sampler,
    atlas_bg:      wgpu::BindGroup,
    #[allow(dead_code)]
    atlas_bg_layout: wgpu::BindGroupLayout,
    atlas_size:    u32,
    max_vertices:  usize,
}

impl Renderer {
    /// Maximum number of quads that can be batched in a single frame.
    /// Each quad = 4 vertices.
    const INITIAL_QUAD_CAPACITY: usize = 8192;

    /// Create the renderer and all its GPU resources.
    pub fn new(
        ctx: GpuContext,
        surface: Arc<wgpu::Surface<'static>>,
        width: u32,
        height: u32,
        atlas_size: u32,
    ) -> Result<Self> {
        let device = &ctx.device;
        let queue  = &ctx.queue;

        // ── Surface format ────────────────────────────────────────────────
        let surface_caps = surface.get_capabilities(&ctx.adapter);
        // Prefer sRGB if available.
        let format = surface_caps
            .formats
            .iter()
            .copied()
            .find(|f| f.is_srgb())
            .unwrap_or(surface_caps.formats[0]);

        let surface_cfg = ctx.surface_config(format, width, height);
        surface.configure(device, &surface_cfg);

        // ── Shader ────────────────────────────────────────────────────────
        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("z-gui shader"),
            source: wgpu::ShaderSource::Wgsl(SHADER_SRC.into()),
        });

        // ── Uniform buffer (screen size) ──────────────────────────────────
        let uniform_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("globals uniform"),
            size: std::mem::size_of::<GlobalsUniform>() as u64,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let globals_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("globals layout"),
            entries: &[wgpu::BindGroupLayoutEntry {
                binding: 0,
                visibility: wgpu::ShaderStages::VERTEX,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Uniform,
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            }],
        });

        let globals_bg = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("globals bg"),
            layout: &globals_layout,
            entries: &[wgpu::BindGroupEntry {
                binding: 0,
                resource: uniform_buf.as_entire_binding(),
            }],
        });

        // ── Atlas texture ─────────────────────────────────────────────────
        let (atlas_tex, atlas_view, atlas_sampler, atlas_bg, atlas_bg_layout) =
            Self::create_atlas_resources(device, atlas_size);

        // ── Vertex / index buffers ─────────────────────────────────────────
        let max_vertices = Self::INITIAL_QUAD_CAPACITY * 4;
        let vertex_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("vertex buffer"),
            size: (max_vertices * std::mem::size_of::<GlyphVertex>()) as u64,
            usage: wgpu::BufferUsages::VERTEX | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let max_indices = Self::INITIAL_QUAD_CAPACITY * 6;
        let index_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("index buffer"),
            size: (max_indices * std::mem::size_of::<u16>()) as u64,
            usage: wgpu::BufferUsages::INDEX | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        // Build the static index buffer once (repeating QUAD_INDICES pattern).
        let indices: Vec<u16> = (0..Self::INITIAL_QUAD_CAPACITY as u16)
            .flat_map(|q| QUAD_INDICES.map(|i| i + q * 4))
            .collect();
        queue.write_buffer(&index_buf, 0, bytemuck::cast_slice(&indices));

        // ── Pipeline ──────────────────────────────────────────────────────
        let pipeline_layout =
            device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
                label: Some("z-gui pipeline layout"),
                bind_group_layouts: &[&globals_layout, &atlas_bg_layout],
                push_constant_ranges: &[],
            });

        let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("z-gui pipeline"),
            layout: Some(&pipeline_layout),
            vertex: wgpu::VertexState {
                module: &shader,
                entry_point: "vs_main",
                buffers: &[GlyphVertex::buffer_layout()],
                compilation_options: Default::default(),
            },
            primitive: wgpu::PrimitiveState {
                topology: wgpu::PrimitiveTopology::TriangleList,
                ..Default::default()
            },
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: "fs_main",
                targets: &[Some(wgpu::ColorTargetState {
                    format,
                    blend: Some(wgpu::BlendState::ALPHA_BLENDING),
                    write_mask: wgpu::ColorWrites::ALL,
                })],
                compilation_options: Default::default(),
            }),
            multiview: None,
        });

        // Write initial uniform.
        Self::write_globals(queue, &uniform_buf, width, height);

        Ok(Self {
            ctx,
            surface: surface.clone(),
            surface_cfg,
            pipeline,
            vertex_buf,
            index_buf,
            uniform_buf,
            globals_bg,
            atlas_tex,
            atlas_view,
            atlas_sampler,
            atlas_bg,
            atlas_bg_layout,
            atlas_size,
            max_vertices,
        })
    }

    /// Handle window resize.
    pub fn resize(&mut self, width: u32, height: u32) {
        self.surface_cfg.width  = width;
        self.surface_cfg.height = height;
        self.surface.configure(&self.ctx.device, &self.surface_cfg);
        Self::write_globals(&self.ctx.queue, &self.uniform_buf, width, height);
    }

    /// Upload atlas pixels to GPU if dirty, then render `vertices` to the
    /// current swap-chain frame.
    pub fn render(&mut self, atlas: &mut GlyphAtlas, vertices: &[GlyphVertex]) -> Result<()> {
        // Sync atlas texture if the CPU-side pixels changed.
        if atlas.dirty {
            // Recreate the texture if the atlas grew.
            if atlas.width != self.atlas_size {
                let (tex, view, sampler, bg, _) =
                    Self::create_atlas_resources(&self.ctx.device, atlas.width);
                self.atlas_tex     = tex;
                self.atlas_view    = view;
                self.atlas_sampler = sampler;
                self.atlas_bg      = bg;
                self.atlas_size    = atlas.width;
            }
            self.ctx.queue.write_texture(
                wgpu::ImageCopyTexture {
                    texture: &self.atlas_tex,
                    mip_level: 0,
                    origin: wgpu::Origin3d::ZERO,
                    aspect: wgpu::TextureAspect::All,
                },
                &atlas.pixels,
                wgpu::ImageDataLayout {
                    offset: 0,
                    bytes_per_row: Some(atlas.width * 4),
                    rows_per_image: Some(atlas.height),
                },
                wgpu::Extent3d {
                    width: atlas.width,
                    height: atlas.height,
                    depth_or_array_layers: 1,
                },
            );
            atlas.dirty = false;
        }

        // Upload vertices (grow buffer if needed).
        let n_quads = vertices.len() / 4;
        if vertices.len() > self.max_vertices {
            self.grow_buffers(vertices.len(), n_quads * 6)?;
        }
        self.ctx.queue.write_buffer(&self.vertex_buf, 0, bytemuck::cast_slice(vertices));

        // Acquire swap-chain frame.
        let output = self
            .surface
            .get_current_texture()
            .context("failed to acquire swap-chain texture")?;
        let view = output
            .texture
            .create_view(&wgpu::TextureViewDescriptor::default());

        // Build and submit command buffer.
        let mut encoder = self.ctx.device.create_command_encoder(
            &wgpu::CommandEncoderDescriptor { label: Some("frame encoder") },
        );
        {
            let mut pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("main pass"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &view,
                    resolve_target: None,
                    ops: wgpu::Operations {
                        load: wgpu::LoadOp::Clear(wgpu::Color {
                            r: 0.05, g: 0.05, b: 0.08, a: 1.0,
                        }),
                        store: wgpu::StoreOp::Store,
                    },
                })],
                depth_stencil_attachment: None,
                timestamp_writes: None,
                occlusion_query_set: None,
            });

            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, &self.globals_bg, &[]);
            pass.set_bind_group(1, &self.atlas_bg, &[]);
            pass.set_vertex_buffer(0, self.vertex_buf.slice(..));
            pass.set_index_buffer(self.index_buf.slice(..), wgpu::IndexFormat::Uint16);
            pass.draw_indexed(0..((n_quads * 6) as u32), 0, 0..1);
        }
        self.ctx.queue.submit(std::iter::once(encoder.finish()));
        output.present();
        Ok(())
    }

    // ── helpers ───────────────────────────────────────────────────────────

    fn write_globals(
        queue: &wgpu::Queue,
        buf: &wgpu::Buffer,
        width: u32,
        height: u32,
    ) {
        let uniforms = GlobalsUniform {
            screen_size: [width as f32, height as f32],
            _pad: [0.0; 2],
        };
        queue.write_buffer(buf, 0, bytemuck::bytes_of(&uniforms));
    }

    fn create_atlas_resources(
        device: &wgpu::Device,
        size: u32,
    ) -> (
        wgpu::Texture,
        wgpu::TextureView,
        wgpu::Sampler,
        wgpu::BindGroup,
        wgpu::BindGroupLayout,
    ) {
        let tex = device.create_texture(&wgpu::TextureDescriptor {
            label: Some("glyph atlas"),
            size: wgpu::Extent3d { width: size, height: size, depth_or_array_layers: 1 },
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: wgpu::TextureFormat::Rgba8UnormSrgb,
            usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
            view_formats: &[],
        });
        let view = tex.create_view(&wgpu::TextureViewDescriptor::default());
        let sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            label: Some("atlas sampler"),
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            ..Default::default()
        });

        let layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("atlas layout"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Texture {
                        multisampled: false,
                        view_dimension: wgpu::TextureViewDimension::D2,
                        sample_type: wgpu::TextureSampleType::Float { filterable: true },
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering),
                    count: None,
                },
            ],
        });

        let bg = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("atlas bg"),
            layout: &layout,
            entries: &[
                wgpu::BindGroupEntry { binding: 0, resource: wgpu::BindingResource::TextureView(&view) },
                wgpu::BindGroupEntry { binding: 1, resource: wgpu::BindingResource::Sampler(&sampler) },
            ],
        });

        (tex, view, sampler, bg, layout)
    }

    fn grow_buffers(&mut self, need_verts: usize, need_indices: usize) -> Result<()> {
        let device = &self.ctx.device;
        let queue  = &self.ctx.queue;

        self.max_vertices = need_verts.next_power_of_two();
        self.vertex_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("vertex buffer (grown)"),
            size: (self.max_vertices * std::mem::size_of::<GlyphVertex>()) as u64,
            usage: wgpu::BufferUsages::VERTEX | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let n_quads = self.max_vertices / 4;
        let indices: Vec<u16> = (0..n_quads as u16)
            .flat_map(|q| QUAD_INDICES.map(|i| i + q * 4))
            .collect();
        self.index_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("index buffer (grown)"),
            size: (need_indices.next_power_of_two() * std::mem::size_of::<u16>()) as u64,
            usage: wgpu::BufferUsages::INDEX | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        queue.write_buffer(&self.index_buf, 0, bytemuck::cast_slice(&indices));
        Ok(())
    }
}

//! Shared vertex types for the wgpu render pipeline.
//!
//! Every draw call (glyph quads, cursor, selection highlight, scrollbar) shares
//! this single vertex format so we can batch everything into one vertex buffer
//! per frame without pipeline switches.

use bytemuck::{Pod, Zeroable};

/// A single textured, coloured vertex for instanced glyph quads.
///
/// Layout (matches the WGSL `@vertex` entry):
/// ```wgsl
/// struct Vertex {
///     @location(0) position : vec2<f32>,  // screen-space px
///     @location(1) tex_coord: vec2<f32>,  // atlas UV [0,1]
///     @location(2) color    : vec4<f32>,  // RGBA linear
/// }
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct GlyphVertex {
    /// Screen-space pixel position (origin = top-left).
    pub position: [f32; 2],
    /// Normalised atlas UV coordinate.
    pub tex_coord: [f32; 2],
    /// RGBA colour (linear, pre-multiplied alpha).
    pub color: [f32; 4],
}

impl GlyphVertex {
    /// `wgpu::VertexBufferLayout` describing this struct for pipeline creation.
    pub fn buffer_layout() -> wgpu::VertexBufferLayout<'static> {
        use std::mem;
        wgpu::VertexBufferLayout {
            array_stride: mem::size_of::<Self>() as wgpu::BufferAddress,
            step_mode: wgpu::VertexStepMode::Vertex,
            attributes: &[
                wgpu::VertexAttribute {
                    offset: 0,
                    shader_location: 0,
                    format: wgpu::VertexFormat::Float32x2,
                },
                wgpu::VertexAttribute {
                    offset: 8,
                    shader_location: 1,
                    format: wgpu::VertexFormat::Float32x2,
                },
                wgpu::VertexAttribute {
                    offset: 16,
                    shader_location: 2,
                    format: wgpu::VertexFormat::Float32x4,
                },
            ],
        }
    }
}

/// One quad = two triangles = 6 indices.
pub const QUAD_INDICES: [u16; 6] = [0, 1, 2, 0, 2, 3];

/// Build the 4 vertices for a textured quad.
///
/// * `x`, `y`  — top-left corner in pixels
/// * `w`, `h`  — width / height in pixels
/// * `u0..v1`  — atlas UV extents
/// * `color`   — RGBA linear colour
#[allow(clippy::too_many_arguments)]
pub fn quad(
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    u0: f32,
    v0: f32,
    u1: f32,
    v1: f32,
    color: [f32; 4],
) -> [GlyphVertex; 4] {
    [
        GlyphVertex { position: [x,     y    ], tex_coord: [u0, v0], color },
        GlyphVertex { position: [x + w, y    ], tex_coord: [u1, v0], color },
        GlyphVertex { position: [x + w, y + h], tex_coord: [u1, v1], color },
        GlyphVertex { position: [x,     y + h], tex_coord: [u0, v1], color },
    ]
}

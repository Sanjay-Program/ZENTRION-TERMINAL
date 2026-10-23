//! GPU glyph atlas — rasterize with `swash` + `cosmic-text`, pack with
//! `guillotiere`, upload to a `wgpu::Texture`.
//!
//! The atlas is a 2-D grayscale or RGBA texture.  Glyphs are rasterized on the
//! CPU via `swash` and placed into the texture via `guillotiere`'s shelf-packer
//! which guarantees O(1) allocation.  When the atlas is full it is automatically
//! doubled in size (up to the device's `max_texture_dimension_2d`).

use anyhow::{bail, Result};
use cosmic_text::{FontSystem, SwashCache};
use guillotiere::{size2, Allocation, AtlasAllocator};
use std::collections::HashMap;

/// Uniquely identifies a rasterized glyph in the cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GlyphKey {
    /// `cosmic-text` cache key (encodes font id + size + sub-pixel shift).
    pub cache_key: cosmic_text::CacheKey,
}

/// The UV rectangle of a placed glyph inside the atlas texture.
#[derive(Clone, Copy, Debug)]
pub struct AtlasSlot {
    /// Pixel rectangle inside the atlas.
    pub rect: guillotiere::Rectangle,
    /// Pre-computed normalised UVs (u0, v0, u1, v1).
    pub uv: [f32; 4],
}

/// In-memory atlas state.  The actual GPU texture lives in [`crate::renderer::Renderer`]
/// to avoid passing around `wgpu` types throughout the glyph pipeline.
pub struct GlyphAtlas {
    allocator: AtlasAllocator,
    cache: HashMap<GlyphKey, AtlasSlot>,
    pub width: u32,
    pub height: u32,
    /// Raw RGBA pixels that mirror the GPU texture.
    pub pixels: Vec<u8>,
    /// `true` when pixels have changed since the last GPU upload.
    pub dirty: bool,
    font_system: FontSystem,
    swash_cache: SwashCache,
}

impl GlyphAtlas {
    /// Create a new atlas with the given initial size.
    ///
    /// `initial_size` should be a power-of-two (e.g. 1024, 2048).
    pub fn new(initial_size: u32) -> Self {
        let sz = initial_size as i32;
        Self {
            allocator: AtlasAllocator::new(size2(sz, sz)),
            cache: HashMap::new(),
            width: initial_size,
            height: initial_size,
            pixels: vec![0u8; (initial_size * initial_size * 4) as usize],
            dirty: true,
            font_system: FontSystem::new(),
            swash_cache: SwashCache::new(),
        }
    }

    /// Return the `AtlasSlot` for a glyph, rasterizing it if not already cached.
    ///
    /// Returns `None` when the glyph has no visible pixels (space, control
    /// characters, etc.) or when the atlas cannot grow large enough.
    pub fn get_or_insert(
        &mut self,
        key: GlyphKey,
        physical_glyph: &cosmic_text::PhysicalGlyph,
        max_texture_size: u32,
    ) -> Option<&AtlasSlot> {
        if self.cache.contains_key(&key) {
            return self.cache.get(&key);
        }

        // Rasterize via swash.
        let image = self
            .swash_cache
            .get_image(&mut self.font_system, physical_glyph.cache_key)
            .clone()?;

        let glyph_w = image.placement.width as i32;
        let glyph_h = image.placement.height as i32;
        if glyph_w == 0 || glyph_h == 0 {
            return None;
        }

        // Allocate a slot, growing the atlas if needed.
        let alloc = self
            .allocate(glyph_w, glyph_h, max_texture_size)
            .ok()?;

        // Blit pixels into the CPU-side mirror.
        self.blit(&image.data, image.content, alloc.rectangle, glyph_w as u32, glyph_h as u32);
        self.dirty = true;

        let aw = self.width as f32;
        let ah = self.height as f32;
        let r = alloc.rectangle;
        let uv = [
            r.min.x as f32 / aw,
            r.min.y as f32 / ah,
            r.max.x as f32 / aw,
            r.max.y as f32 / ah,
        ];

        let slot = AtlasSlot { rect: r, uv };
        self.cache.insert(key, slot);
        self.cache.get(&key)
    }

    // ── internals ────────────────────────────────────────────────────────────

    fn allocate(
        &mut self,
        w: i32,
        h: i32,
        max_size: u32,
    ) -> Result<Allocation> {
        if let Some(a) = self.allocator.allocate(size2(w, h)) {
            return Ok(a);
        }

        // Atlas full — double until we fit or hit the device limit.
        let new_size = (self.width * 2).min(max_size);
        if new_size == self.width {
            bail!("glyph atlas exhausted (max_texture_size={})", max_size);
        }

        let sz = new_size as i32;
        self.allocator = AtlasAllocator::new(size2(sz, sz));
        self.cache.clear();
        self.width = new_size;
        self.height = new_size;
        self.pixels = vec![0u8; (new_size * new_size * 4) as usize];
        self.dirty = true;

        self.allocator
            .allocate(size2(w, h))
            .ok_or_else(|| anyhow::anyhow!("glyph ({w}×{h}) too large for atlas {new_size}"))
    }

    fn blit(
        &mut self,
        data: &[u8],
        content: cosmic_text::SwashContent,
        rect: guillotiere::Rectangle,
        glyph_w: u32,
        glyph_h: u32,
    ) {
        let atlas_w = self.width as usize;
        let dst_x = rect.min.x as usize;
        let dst_y = rect.min.y as usize;

        match content {
            cosmic_text::SwashContent::Mask => {
                // 1-byte-per-pixel grayscale mask → RGBA
                for row in 0..glyph_h as usize {
                    for col in 0..glyph_w as usize {
                        let src_a = data[row * glyph_w as usize + col];
                        let dst_idx = ((dst_y + row) * atlas_w + (dst_x + col)) * 4;
                        self.pixels[dst_idx]     = 255;
                        self.pixels[dst_idx + 1] = 255;
                        self.pixels[dst_idx + 2] = 255;
                        self.pixels[dst_idx + 3] = src_a;
                    }
                }
            }
            cosmic_text::SwashContent::SubpixelMask | cosmic_text::SwashContent::Color => {
                // Already RGBA
                for row in 0..glyph_h as usize {
                    let src_start = row * glyph_w as usize * 4;
                    let src_end   = src_start + glyph_w as usize * 4;
                    let dst_start = ((dst_y + row) * atlas_w + dst_x) * 4;
                    let dst_end   = dst_start + glyph_w as usize * 4;
                    self.pixels[dst_start..dst_end]
                        .copy_from_slice(&data[src_start..src_end]);
                }
            }
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atlas_allocates_and_grows() {
        let mut atlas = GlyphAtlas::new(64);
        assert_eq!(atlas.width, 64);
        assert_eq!(atlas.pixels.len(), 64 * 64 * 4);

        // Simulate atlas full → force growth by exhausting the 64×64 space.
        // We'll call allocate() directly at the private level via a white-box path.
        // Allocate a 60×60 block to nearly fill it.
        let a = atlas.allocate(60, 60, 4096);
        assert!(a.is_ok(), "first allocation should succeed");

        // Allocate another 60×60 — won't fit in 64×64 remainder, should grow.
        let b = atlas.allocate(60, 60, 4096);
        assert!(b.is_ok(), "second allocation should succeed after atlas grows");
        // After growth the atlas should be 128
        assert_eq!(atlas.width, 128);
    }
}

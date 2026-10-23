//! `GpuContext` — owns the `wgpu` instance, adapter, device, and queue.
//!
//! Stores the `Arc<wgpu::Adapter>` so the Renderer can call
//! `surface.get_capabilities(&adapter)` without creating a second adapter.

use anyhow::{Context, Result};
use std::sync::Arc;

/// Shared, cheaply cloneable GPU context.
#[derive(Clone)]
pub struct GpuContext {
    pub adapter: Arc<wgpu::Adapter>,
    pub device:  Arc<wgpu::Device>,
    pub queue:   Arc<wgpu::Queue>,
    pub adapter_info: wgpu::AdapterInfo,
}

impl GpuContext {
    /// Create an adapter + device + queue, preferring a discrete GPU when
    /// available and falling back to any available adapter.
    ///
    /// `compatible_surface` must be `Some` when a real window is present so
    /// wgpu selects an adapter that can present to it.
    pub async fn new(compatible_surface: Option<&wgpu::Surface<'_>>) -> Result<Self> {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: wgpu::Backends::all(),
            ..Default::default()
        });

        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                compatible_surface,
                force_fallback_adapter: false,
            })
            .await
            .context("no suitable GPU adapter found")?;

        let adapter_info = adapter.get_info();
        log::info!(
            "GPU adapter: {} ({:?})",
            adapter_info.name,
            adapter_info.backend
        );

        let (device, queue) = adapter
            .request_device(
                &wgpu::DeviceDescriptor {
                    label: Some("z-gui device"),
                    required_features: wgpu::Features::empty(),
                    required_limits: wgpu::Limits::downlevel_webgl2_defaults()
                        .using_resolution(adapter.limits()),
                },
                None,
            )
            .await
            .context("failed to acquire wgpu device")?;

        Ok(Self {
            adapter: Arc::new(adapter),
            device:  Arc::new(device),
            queue:   Arc::new(queue),
            adapter_info,
        })
    }

    /// Maximum texture dimension supported by this adapter.
    pub fn max_texture_size(&self) -> u32 {
        self.device.limits().max_texture_dimension_2d
    }

    /// Surface configuration suitable for the given window size.
    pub fn surface_config(
        &self,
        format: wgpu::TextureFormat,
        width: u32,
        height: u32,
    ) -> wgpu::SurfaceConfiguration {
        wgpu::SurfaceConfiguration {
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            format,
            width,
            height,
            present_mode: wgpu::PresentMode::Mailbox,
            alpha_mode: wgpu::CompositeAlphaMode::Opaque,
            view_formats: vec![],
            desired_maximum_frame_latency: 2,
        }
    }
}

#[cfg(test)]
mod tests {
    /// GPU context tests require a real adapter and are therefore
    /// marked `#[ignore]` so CI passes without a display server.
    #[test]
    #[ignore]
    fn gpu_context_smoke() {
        // Would require a Vulkan/Metal/DX12 adapter available in the test env.
    }
}

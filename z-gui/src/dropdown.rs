//! Quake-style drop-down terminal animation.
//!
//! The `DropDown` state machine tracks a y-offset in the range `[0.0, 1.0]`
//! where `0.0` = fully hidden and `1.0` = fully visible.  The caller advances
//! time via [`DropDown::tick`] and reads back the current translated pixel
//! offset via [`DropDown::y_offset_px`].
//!
//! The easing function is a cubic "ease-out" curve, giving the classic Quake
//! feel of fast fall + gentle settle.
//!
//! # Integration with the winit event loop
//!
//! ```rust,ignore
//! // On toggle hotkey (e.g. F12):
//! dropdown.toggle();
//!
//! // Inside the RedrawRequested handler, before rendering:
//! let dt = last_frame.elapsed().as_secs_f32();
//! dropdown.tick(dt);
//!
//! // Translate the window or the render scissor rect:
//! let y = dropdown.y_offset_px(window_height);
//! ```

use std::time::Duration;

/// Animation direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropState {
    Hidden,
    Dropping,
    Visible,
    Raising,
}

/// Quake-style drop-down controller.
#[derive(Debug)]
pub struct DropDown {
    /// Current animation progress in [0.0, 1.0].
    progress: f32,
    state: DropState,
    /// Seconds to fully open or close.
    animation_secs: f32,
}

impl DropDown {
    /// Create a `DropDown` that completes its animation in `duration`.
    pub fn new(duration: Duration) -> Self {
        Self {
            progress: 0.0,
            state: DropState::Hidden,
            animation_secs: duration.as_secs_f32().max(0.001),
        }
    }

    /// Toggle visibility — starts the animation in the opposite direction.
    pub fn toggle(&mut self) {
        self.state = match self.state {
            DropState::Hidden | DropState::Raising => DropState::Dropping,
            DropState::Visible | DropState::Dropping => DropState::Raising,
        };
    }

    /// Advance animation by `dt` seconds.
    ///
    /// Returns `true` if the window still needs to be redrawn (animation in
    /// progress).
    pub fn tick(&mut self, dt: f32) -> bool {
        match self.state {
            DropState::Hidden | DropState::Visible => false,
            DropState::Dropping => {
                self.progress = (self.progress + dt / self.animation_secs).min(1.0);
                if self.progress >= 1.0 {
                    self.state = DropState::Visible;
                    false
                } else {
                    true
                }
            }
            DropState::Raising => {
                self.progress = (self.progress - dt / self.animation_secs).max(0.0);
                if self.progress <= 0.0 {
                    self.state = DropState::Hidden;
                    false
                } else {
                    true
                }
            }
        }
    }

    /// Whether the terminal window should currently be shown at all.
    pub fn is_visible(&self) -> bool {
        self.progress > 0.0
    }

    /// Current animation progress (0 = hidden, 1 = fully open), eased.
    pub fn eased(&self) -> f32 {
        ease_out_cubic(self.progress)
    }

    /// Y pixel offset (negative = off-screen above).
    ///
    /// At `eased = 0.0` the window is entirely above the screen.
    /// At `eased = 1.0` the window occupies the top `height_px` of the screen.
    pub fn y_offset_px(&self, height_px: u32) -> i32 {
        let h = height_px as f32;
        let offset = (1.0 - self.eased()) * h;
        -(offset as i32)
    }

    /// Raw progress (not eased), useful for tests.
    pub fn progress(&self) -> f32 {
        self.progress
    }

    /// Current state.
    pub fn state(&self) -> DropState {
        self.state
    }
}

/// Cubic ease-out: `1 - (1-t)³`
fn ease_out_cubic(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    1.0 - (1.0 - t).powi(3)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_by_default() {
        let dd = DropDown::new(Duration::from_millis(200));
        assert_eq!(dd.state(), DropState::Hidden);
        assert!(!dd.is_visible());
    }

    #[test]
    fn toggle_starts_dropping() {
        let mut dd = DropDown::new(Duration::from_millis(200));
        dd.toggle();
        assert_eq!(dd.state(), DropState::Dropping);
    }

    #[test]
    fn tick_advances_progress() {
        let mut dd = DropDown::new(Duration::from_millis(200));
        dd.toggle();
        let still_animating = dd.tick(0.1); // 100 ms out of 200 ms
        assert!(still_animating);
        assert!((dd.progress() - 0.5).abs() < 0.001);
    }

    #[test]
    fn full_cycle_hidden_to_visible() {
        let mut dd = DropDown::new(Duration::from_millis(200));
        dd.toggle(); // start dropping
        dd.tick(1.0); // advance well past the end
        assert_eq!(dd.state(), DropState::Visible);
        assert!((dd.progress() - 1.0).abs() < 0.001);
    }

    #[test]
    fn raise_returns_to_hidden() {
        let mut dd = DropDown::new(Duration::from_millis(200));
        dd.toggle(); dd.tick(1.0);            // fully open
        dd.toggle(); dd.tick(1.0);            // fully close
        assert_eq!(dd.state(), DropState::Hidden);
        assert!((dd.progress()).abs() < 0.001);
    }

    #[test]
    fn y_offset_at_full_open_is_zero() {
        let mut dd = DropDown::new(Duration::from_millis(200));
        dd.toggle(); dd.tick(1.0);
        assert_eq!(dd.y_offset_px(600), 0);
    }

    #[test]
    fn y_offset_at_fully_hidden_is_negative_height() {
        let dd = DropDown::new(Duration::from_millis(200));
        assert_eq!(dd.y_offset_px(600), -600);
    }

    #[test]
    fn ease_out_cubic_endpoints() {
        assert!((super::ease_out_cubic(0.0)).abs() < 1e-6);
        assert!((super::ease_out_cubic(1.0) - 1.0).abs() < 1e-6);
    }
}

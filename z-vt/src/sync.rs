//! DECSET 2026 — Synchronized output with safety timeout.
//!
//! Synchronized output pauses terminal screen rendering until an application
//! finishes a batch update (`CSI ? 2026 h` to begin, `CSI ? 2026 l` to end).
//! To prevent hung or crashed applications from freezing the terminal display,
//! a safety timeout (default ~100 ms) automatically flushes queued output.

use std::time::{Duration, Instant};

/// Safety timeout after which synchronized output automatically flushes.
pub const DEFAULT_SYNC_TIMEOUT: Duration = Duration::from_millis(100);

/// DECSET 2026 synchronized output controller.
#[derive(Debug)]
pub struct SynchronizedOutput {
    active: bool,
    start_time: Option<Instant>,
    timeout: Duration,
    buffer: Vec<u8>,
}

impl Default for SynchronizedOutput {
    fn default() -> Self {
        Self::new(DEFAULT_SYNC_TIMEOUT)
    }
}

impl SynchronizedOutput {
    pub fn new(timeout: Duration) -> Self {
        Self {
            active: false,
            start_time: None,
            timeout,
            buffer: Vec::new(),
        }
    }

    /// Check whether synchronized output is currently active (and not timed out).
    pub fn is_active(&self) -> bool {
        if !self.active {
            return false;
        }
        if let Some(start) = self.start_time {
            start.elapsed() < self.timeout
        } else {
            false
        }
    }

    /// Explicitly begin synchronized output mode (`CSI ? 2026 h`).
    pub fn begin_sync(&mut self) {
        self.active = true;
        self.start_time = Some(Instant::now());
    }

    /// Explicitly end synchronized output mode (`CSI ? 2026 l`), returning buffered bytes.
    pub fn end_sync(&mut self) -> Vec<u8> {
        self.active = false;
        self.start_time = None;
        std::mem::take(&mut self.buffer)
    }

    /// Check if the safety timeout has expired while sync is active.
    /// If expired, auto-flushes the buffer and resets sync mode.
    pub fn check_timeout(&mut self) -> Option<Vec<u8>> {
        if self.active {
            if let Some(start) = self.start_time {
                if start.elapsed() >= self.timeout {
                    self.active = false;
                    self.start_time = None;
                    if !self.buffer.is_empty() {
                        return Some(std::mem::take(&mut self.buffer));
                    }
                }
            }
        }
        None
    }

    /// Process incoming bytes. Inspects for `\x1b[?2026h` (begin) and `\x1b[?2026l` (end).
    /// Returns any bytes that are ready to be dispatched to the screen.
    pub fn process_stream(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();

        // Check safety timeout first
        if let Some(mut timed_out_bytes) = self.check_timeout() {
            out.append(&mut timed_out_bytes);
        }

        let mut i = 0;
        let len = input.len();

        while i < len {
            // Check for CSI ? 2026 h (b"\x1b[?2026h") or CSI ? 2026 l (b"\x1b[?2026l")
            if i + 8 <= len && &input[i..i + 8] == b"\x1b[?2026h" {
                self.begin_sync();
                i += 8;
                continue;
            } else if i + 8 <= len && &input[i..i + 8] == b"\x1b[?2026l" {
                let mut flushed = self.end_sync();
                out.append(&mut flushed);
                i += 8;
                continue;
            }

            if self.is_active() {
                self.buffer.push(input[i]);
            } else {
                out.push(input[i]);
            }
            i += 1;
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_output_normal_lifecycle() {
        let mut sync = SynchronizedOutput::default();

        let stream = b"Hello \x1b[?2026hWorld!\x1b[?2026l Done";
        let out = sync.process_stream(stream);

        // When ended with 2026l, all bytes are flushed in order
        assert_eq!(String::from_utf8_lossy(&out), "Hello World! Done");
    }

    #[test]
    fn test_sync_output_buffering_while_active() {
        let mut sync = SynchronizedOutput::default();

        let chunk1 = sync.process_stream(b"Normal \x1b[?2026hBuffered");
        assert_eq!(String::from_utf8_lossy(&chunk1), "Normal ");
        assert!(sync.is_active());

        let chunk2 = sync.process_stream(b" MoreBuffered");
        assert!(chunk2.is_empty());
        assert!(sync.is_active());

        let chunk3 = sync.process_stream(b"\x1b[?2026l Flushed");
        assert_eq!(String::from_utf8_lossy(&chunk3), "Buffered MoreBuffered Flushed");
        assert!(!sync.is_active());
    }

    #[test]
    fn test_sync_output_safety_timeout() {
        // Fast timeout for unit test
        let mut sync = SynchronizedOutput::new(Duration::from_millis(20));

        let _ = sync.process_stream(b"\x1b[?2026hFrozenContent");
        assert!(sync.is_active());

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(30));

        assert!(!sync.is_active());
        let timed_out = sync.check_timeout().unwrap_or_default();
        assert_eq!(String::from_utf8_lossy(&timed_out), "FrozenContent");
    }
}

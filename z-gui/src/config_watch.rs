//! Hot-reload watcher for Zentrion's config file.
//!
//! Wraps `notify` (the cross-platform file-system event library) and sends
//! change notifications over an async channel.  The GUI event loop polls this
//! channel at the start of every frame and re-reads the config when a change
//! is detected.
//!
//! # Design
//! * Only one `ConfigWatcher` should exist per process.
//! * The watcher thread is a Tokio task so it integrates cleanly with the
//!   rest of the async runtime.
//! * We de-bounce rapid saves (common with editors that write atomically)
//!   using a 50 ms delay before forwarding the event.

use anyhow::Result;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::{
    path::{Path, PathBuf},
    sync::mpsc,
    time::{Duration, Instant},
};

/// Events emitted by the config watcher.
#[derive(Debug, Clone)]
pub enum ConfigEvent {
    /// The config file was modified.  The caller should re-read and apply it.
    Modified(PathBuf),
    /// The watcher encountered an error (log and continue).
    Error(String),
}

/// Hot-reload watcher.  Drop it to stop watching.
pub struct ConfigWatcher {
    _watcher: RecommendedWatcher,
    pub rx: mpsc::Receiver<ConfigEvent>,
}

impl ConfigWatcher {
    /// Start watching `config_path` for modifications.
    pub fn new(config_path: impl AsRef<Path>) -> Result<Self> {
        let config_path = config_path.as_ref().to_path_buf();
        let (tx, rx) = mpsc::channel::<ConfigEvent>();

        let tx_err = tx.clone();
        let debounce = Duration::from_millis(50);
        let mut last_event: Option<Instant> = None;
        let watch_path = config_path.clone();

        let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            match res {
                Ok(event) => {
                    let is_write = matches!(
                        event.kind,
                        EventKind::Modify(_) | EventKind::Create(_)
                    );
                    if is_write {
                        let now = Instant::now();
                        // De-bounce: skip if another event fired within 50 ms.
                        if last_event.map_or(true, |t| now.duration_since(t) >= debounce) {
                            last_event = Some(now);
                            let _ = tx.send(ConfigEvent::Modified(watch_path.clone()));
                        }
                    }
                }
                Err(e) => {
                    let _ = tx_err.send(ConfigEvent::Error(e.to_string()));
                }
            }
        })?;

        // Watch the parent directory (handles atomic-rename writes).
        let watch_dir = config_path.parent().unwrap_or(Path::new("."));
        watcher.watch(watch_dir, RecursiveMode::NonRecursive)?;

        Ok(Self { _watcher: watcher, rx })
    }

    /// Drain all pending events.  Returns the events accumulated since last poll.
    pub fn poll(&self) -> Vec<ConfigEvent> {
        let mut events = Vec::new();
        while let Ok(ev) = self.rx.try_recv() {
            events.push(ev);
        }
        events
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::Write};
    use tempfile::NamedTempFile;

    #[test]
    fn watcher_fires_on_write() -> anyhow::Result<()> {
        let mut file = NamedTempFile::new()?;
        let path = file.path().to_path_buf();

        let watcher = ConfigWatcher::new(&path)?;
        std::thread::sleep(Duration::from_millis(50)); // let watcher settle

        writeln!(file, "font_size = 14")?;
        file.flush()?;
        std::thread::sleep(Duration::from_millis(150)); // wait for event

        let events = watcher.poll();
        assert!(
            events.iter().any(|e| matches!(e, ConfigEvent::Modified(_))),
            "expected a Modified event, got: {:?}",
            events
        );
        Ok(())
    }
}

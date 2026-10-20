//! Block lifecycle state machine driven by shell-integration marks.
//!
//! ```text
//! OSC 133;A  prompt ──▶ idle
//! OSC 133;B  submit ──▶ pending
//! OSC 133;C  output ──▶ running
//! OSC 133;D  exit   ──▶ ok | failed | cancelled
//! ```
//!
//! Hooks are authoritative. Callers that have no hooks (unsupported shell) may
//! use [`BlockRecorder::begin_command`]/[`BlockRecorder::finish`] and must
//! label the block as heuristic in the UI. The recorder itself never scrapes
//! the screen.

use crate::model::{Block, BlockStatus};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use z_vt::{OscEvent, ShellIntegrationMeta, ShellMark};

/// Output retained per block in memory before the block is handed to the
/// store. Larger output is truncated in the live recorder; the store keeps the
/// same cap to bound disk use.
pub const MAX_BLOCK_OUTPUT: usize = 8 * 1024 * 1024;

/// Commands longer than this are truncated in the header; the store keeps the
/// capped value.
pub const MAX_COMMAND_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecorderUpdate {
    Started(Block),
    OutputAppended { block_id: String, bytes: usize },
    Finished(Block),
    CwdChanged(String),
    Ignored,
}

#[derive(Debug, Clone)]
struct Draft {
    block: Block,
    output: Vec<u8>,
    output_truncated: bool,
    saw_output: bool,
}

#[derive(Debug, Clone)]
pub struct BlockRecorder {
    session_id: String,
    shell: String,
    cwd: String,
    seq: u64,
    current: Option<Draft>,
    /// Command captured by hooks before `OSC 133;B` arrives.
    pending_command: Option<String>,
    max_output: usize,
}

impl BlockRecorder {
    pub fn new(
        session_id: impl Into<String>,
        shell: impl Into<String>,
        cwd: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            shell: shell.into(),
            cwd: cwd.into(),
            seq: 0,
            current: None,
            pending_command: None,
            max_output: MAX_BLOCK_OUTPUT,
        }
    }

    pub fn with_max_output(mut self, max: usize) -> Self {
        self.max_output = max.max(1024);
        self
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    pub fn current(&self) -> Option<&Block> {
        self.current.as_ref().map(|draft| &draft.block)
    }

    pub fn current_output(&self) -> &[u8] {
        self.current
            .as_ref()
            .map(|draft| draft.output.as_slice())
            .unwrap_or(&[])
    }

    /// Apply a parsed terminal event. Unknown events are ignored.
    pub fn on_event(&mut self, event: &OscEvent, now: DateTime<Utc>) -> Vec<RecorderUpdate> {
        match event {
            OscEvent::ShellMark(mark) => self.on_mark(mark, now),
            _ => Vec::new(),
        }
    }

    fn on_mark(&mut self, mark: &ShellMark, now: DateTime<Utc>) -> Vec<RecorderUpdate> {
        match mark {
            ShellMark::PromptStart => {
                // A prompt after a running block without OSC 133;D means the
                // shell was interrupted or the hook was lost. Close it as
                // cancelled rather than leaving a phantom "running" block.
                if let Some(block) = self.current.as_ref().map(|d| d.block.status) {
                    if !block.is_finished() {
                        return self
                            .close_current(None, BlockStatus::Cancelled, now)
                            .map(RecorderUpdate::Finished)
                            .into_iter()
                            .collect();
                    }
                }
                Vec::new()
            }
            ShellMark::CommandStart => {
                let mut updates = Vec::new();
                if let Some(draft) = &self.current {
                    if !draft.block.status.is_finished() {
                        updates.extend(
                            self.close_current(None, BlockStatus::Cancelled, now)
                                .map(RecorderUpdate::Finished),
                        );
                    }
                }
                let command = self.pending_command.take().unwrap_or_default();
                let block = self.start_block(command, now);
                updates.push(RecorderUpdate::Started(block));
                updates
            }
            ShellMark::OutputStart => {
                if self.current.is_none() {
                    let command = self.pending_command.take().unwrap_or_default();
                    let block = self.start_block(command, now);
                    let update = RecorderUpdate::Started(block);
                    self.mark_running();
                    return vec![update];
                }
                self.mark_running();
                Vec::new()
            }
            ShellMark::CommandFinished { exit_code } => {
                if self.current.is_none() {
                    return Vec::new();
                }
                let status = match exit_code {
                    Some(0) => BlockStatus::Ok,
                    Some(_) => BlockStatus::Failed,
                    None => BlockStatus::Cancelled,
                };
                self.close_current(*exit_code, status, now)
                    .map(RecorderUpdate::Finished)
                    .into_iter()
                    .collect()
            }
            ShellMark::Cwd(path) => {
                self.cwd = path.clone();
                vec![RecorderUpdate::CwdChanged(path.clone())]
            }
            ShellMark::Metadata(meta) => self.apply_metadata(meta),
        }
    }

    fn apply_metadata(&mut self, meta: &ShellIntegrationMeta) -> Vec<RecorderUpdate> {
        let Some(command) = &meta.command else {
            return Vec::new();
        };
        let command = cap_text(command, MAX_COMMAND_BYTES);
        match &mut self.current {
            Some(draft) if draft.block.command.is_empty() => {
                draft.block.command = command.clone();
            }
            Some(draft) => {
                // A second metadata event for the same block is a correction
                // only if the current value was empty; never silently rewrite.
                if draft.block.command != command && draft.block.command.is_empty() {
                    draft.block.command = command.clone();
                }
            }
            None => self.pending_command = Some(command),
        }
        Vec::new()
    }

    fn start_block(&mut self, command: String, now: DateTime<Utc>) -> Block {
        self.seq += 1;
        let block = Block {
            id: format!("b_{}", Uuid::new_v4().simple()),
            session_id: self.session_id.clone(),
            seq: self.seq,
            command: cap_text(&command, MAX_COMMAND_BYTES),
            cwd: self.cwd.clone(),
            shell: self.shell.clone(),
            started_at: now,
            ended_at: None,
            exit_code: None,
            status: BlockStatus::Pending,
            duration_ms: None,
            output_hash: None,
            output_bytes: None,
            agent_id: None,
            policy_decision: None,
            approval_id: None,
            tags: Vec::new(),
            risk: None,
            parent_block_id: None,
        };
        self.current = Some(Draft {
            block: block.clone(),
            output: Vec::new(),
            output_truncated: false,
            saw_output: false,
        });
        block
    }

    fn mark_running(&mut self) {
        if let Some(draft) = &mut self.current {
            if draft.block.status == BlockStatus::Pending {
                draft.block.status = BlockStatus::Running;
            }
        }
    }

    /// Start a block explicitly when shell hooks are unavailable. Callers must
    /// label this as heuristic in the UI.
    pub fn begin_command(&mut self, command: &str, now: DateTime<Utc>) -> Block {
        if let Some(draft) = &self.current {
            if !draft.block.status.is_finished() {
                let _ = self.close_current(None, BlockStatus::Cancelled, now);
            }
        }
        self.pending_command = None;
        self.start_block(command.to_string(), now);
        self.mark_running();
        self.current
            .as_ref()
            .map(|draft| draft.block.clone())
            .expect("block was just created")
    }

    /// Append output to the current block. Returns bytes actually retained.
    pub fn append_output(&mut self, bytes: &[u8]) -> usize {
        match &mut self.current {
            Some(draft) => {
                if !draft.saw_output {
                    draft.saw_output = true;
                    if draft.block.status == BlockStatus::Pending {
                        draft.block.status = BlockStatus::Running;
                    }
                }
                let remaining = self.max_output.saturating_sub(draft.output.len());
                if remaining == 0 {
                    draft.output_truncated = true;
                    return 0;
                }
                let take = remaining.min(bytes.len());
                draft.output.extend_from_slice(&bytes[..take]);
                if take < bytes.len() {
                    draft.output_truncated = true;
                }
                take
            }
            None => 0,
        }
    }

    /// Close the current block explicitly (heuristic path or shell exit).
    pub fn finish(
        &mut self,
        exit_code: Option<i32>,
        status: BlockStatus,
        now: DateTime<Utc>,
    ) -> Option<Block> {
        self.close_current(exit_code, status, now)
    }

    /// Finish the current block and hand back exactly the bytes the recorder
    /// retained, so a store can persist the same output that was hashed.
    pub fn finish_capture(
        &mut self,
        exit_code: Option<i32>,
        status: BlockStatus,
        now: DateTime<Utc>,
    ) -> Option<(Block, Vec<u8>)> {
        self.close_capture(exit_code, status, now)
    }

    pub fn on_shell_exit(&mut self, now: DateTime<Utc>) -> Option<Block> {
        self.pending_command = None;
        self.close_current(None, BlockStatus::Cancelled, now)
    }

    fn close_current(
        &mut self,
        exit_code: Option<i32>,
        status: BlockStatus,
        now: DateTime<Utc>,
    ) -> Option<Block> {
        self.close_capture(exit_code, status, now)
            .map(|(block, _)| block)
    }

    fn close_capture(
        &mut self,
        exit_code: Option<i32>,
        status: BlockStatus,
        now: DateTime<Utc>,
    ) -> Option<(Block, Vec<u8>)> {
        let draft = self.current.take()?;
        let mut block = draft.block;
        block.ended_at = Some(now);
        block.exit_code = exit_code;
        block.status = if block.status == BlockStatus::Pending && exit_code.is_none() {
            BlockStatus::Cancelled
        } else {
            status
        };
        block.duration_ms = Some(
            now.signed_duration_since(block.started_at)
                .num_milliseconds()
                .max(0) as u64,
        );
        block.output_bytes = Some(draft.output.len() as u64);
        block.output_hash = Some(format!("sha256:{}", hex(&draft.output)));
        if draft.output_truncated {
            block.tags.push("output-truncated".to_string());
        }
        Some((block, draft.output))
    }
}

fn cap_text(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

fn hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(ms: u64) -> DateTime<Utc> {
        Utc.timestamp_millis_opt(ms as i64).unwrap()
    }

    fn event(mark: ShellMark) -> OscEvent {
        OscEvent::ShellMark(mark)
    }

    #[test]
    fn happy_path_produces_one_finished_block() {
        let mut recorder = BlockRecorder::new("s1", "bash", "/repo");
        recorder.on_event(&event(ShellMark::PromptStart), at(1000));
        recorder.on_event(&event(ShellMark::CommandStart), at(1100));
        let meta = ShellIntegrationMeta {
            command: Some("cargo test".into()),
            ..Default::default()
        };
        recorder.on_event(&event(ShellMark::Metadata(meta)), at(1100));
        recorder.on_event(&event(ShellMark::OutputStart), at(1200));
        assert_eq!(recorder.append_output(b"running tests\n"), 14);
        let updates = recorder.on_event(
            &event(ShellMark::CommandFinished { exit_code: Some(0) }),
            at(3500),
        );
        let RecorderUpdate::Finished(block) = &updates[0] else {
            panic!("expected finish");
        };
        assert_eq!(block.command, "cargo test");
        assert_eq!(block.status, BlockStatus::Ok);
        assert_eq!(block.exit_code, Some(0));
        assert_eq!(block.duration_ms, Some(2400));
        assert!(block.output_hash.as_deref().unwrap().starts_with("sha256:"));
        assert_eq!(block.output_bytes, Some(14));
    }

    #[test]
    fn non_zero_exit_is_failed() {
        let mut recorder = BlockRecorder::new("s1", "zsh", "/repo");
        recorder.on_event(&event(ShellMark::CommandStart), at(0));
        let updates = recorder.on_event(
            &event(ShellMark::CommandFinished {
                exit_code: Some(101),
            }),
            at(10),
        );
        let RecorderUpdate::Finished(block) = &updates[0] else {
            panic!();
        };
        assert_eq!(block.status, BlockStatus::Failed);
        assert!(block.is_failure());
    }

    #[test]
    fn missing_exit_is_cancelled() {
        let mut recorder = BlockRecorder::new("s1", "fish", "/repo");
        recorder.on_event(&event(ShellMark::CommandStart), at(0));
        let updates = recorder.on_event(
            &event(ShellMark::CommandFinished { exit_code: None }),
            at(1),
        );
        let RecorderUpdate::Finished(block) = &updates[0] else {
            panic!();
        };
        assert_eq!(block.status, BlockStatus::Cancelled);
    }

    #[test]
    fn prompt_without_finish_closes_as_cancelled() {
        let mut recorder = BlockRecorder::new("s1", "bash", "/repo");
        recorder.on_event(&event(ShellMark::CommandStart), at(0));
        recorder.on_event(&event(ShellMark::OutputStart), at(1));
        let updates = recorder.on_event(&event(ShellMark::PromptStart), at(2));
        assert!(matches!(updates[0], RecorderUpdate::Finished(_)));
        assert!(recorder.current().is_none());
    }

    #[test]
    fn output_is_capped() {
        let mut recorder = BlockRecorder::new("s1", "bash", "/repo").with_max_output(1024);
        recorder.on_event(&event(ShellMark::CommandStart), at(0));
        assert_eq!(recorder.append_output(&vec![b'x'; 2048]), 1024);
        let updates = recorder.on_event(
            &event(ShellMark::CommandFinished { exit_code: Some(0) }),
            at(1),
        );
        let RecorderUpdate::Finished(block) = &updates[0] else {
            panic!();
        };
        assert!(block.tags.contains(&"output-truncated".to_string()));
        assert_eq!(block.output_bytes, Some(1024));
    }

    #[test]
    fn cwd_is_tracked_for_the_next_block() {
        let mut recorder = BlockRecorder::new("s1", "bash", "/repo");
        recorder.on_event(&event(ShellMark::Cwd("/repo/src".into())), at(0));
        recorder.on_event(&event(ShellMark::CommandStart), at(1));
        assert_eq!(recorder.current().unwrap().cwd, "/repo/src");
    }

    #[test]
    fn heuristic_begin_and_finish_work_without_hooks() {
        let mut recorder = BlockRecorder::new("s1", "sh", "/");
        let block = recorder.begin_command("echo hi", at(0));
        assert_eq!(block.status, BlockStatus::Running);
        recorder.append_output(b"hi\n");
        let block = recorder.finish(Some(0), BlockStatus::Ok, at(5)).unwrap();
        assert_eq!(block.duration_ms, Some(5));
    }

    #[test]
    fn metadata_before_command_start_is_used() {
        let mut recorder = BlockRecorder::new("s1", "bash", "/");
        recorder.on_event(
            &event(ShellMark::Metadata(ShellIntegrationMeta {
                command: Some("ls -la".into()),
                ..Default::default()
            })),
            at(0),
        );
        recorder.on_event(&event(ShellMark::CommandStart), at(1));
        assert_eq!(recorder.current().unwrap().command, "ls -la");
    }
}

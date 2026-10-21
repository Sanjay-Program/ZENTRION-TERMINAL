//! Session registry, PTY lifecycle, block persistence and metadata.
//!
//! The manager owns every live session. Blocks are handed to a dedicated
//! writer thread so the PTY reader never waits on SQLite.

use crate::integration;
use crate::session::{
    BlockSink, Result, SessionError, SessionHandle, SessionInfo, SessionOptions, SessionSnapshot,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, RwLock};
use z_blocks::{Block, BlockStore, Session as StoredSession};
use z_config::{Config, RestorePolicy, ShellIntegration};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Metadata {
    version: u32,
    updated_at: chrono::DateTime<Utc>,
    sessions: Vec<SessionInfo>,
}

#[derive(Debug, Clone)]
pub struct ManagerOptions {
    pub data_dir: PathBuf,
    pub config: Config,
    pub blocks_db: Option<PathBuf>,
    pub integration_dir: Option<PathBuf>,
    pub restore: RestorePolicy,
}

impl ManagerOptions {
    pub fn new(data_dir: impl Into<PathBuf>, config: Config) -> Self {
        let data_dir = data_dir.into();
        Self {
            blocks_db: Some(data_dir.join("blocks.db")),
            integration_dir: Some(data_dir.join("shell-integration").join("v1")),
            restore: config.session.restore,
            data_dir,
            config,
        }
    }

    pub fn default_paths() -> Option<Self> {
        let data = z_core::config::user_data_dir()?;
        let config = z_config::load(&z_config::LoadOptions::with_env())
            .map(|loaded| loaded.config)
            .unwrap_or_default();
        Some(Self::new(data, config))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CreateParams {
    pub shell: Option<String>,
    pub cwd: Option<PathBuf>,
    pub rows: Option<u16>,
    pub cols: Option<u16>,
    pub title: Option<String>,
    pub profile: Option<String>,
    pub env: Vec<(String, String)>,
    pub integration: Option<ShellIntegration>,
    pub login: bool,
    /// Run an argv directly instead of resolving a shell (SSH/remote domains).
    pub command: Option<Vec<String>>,
}

enum WriterMessage {
    Block(Block, Vec<u8>),
    Session(StoredSession),
    Shutdown,
}

pub struct SessionManager {
    options: ManagerOptions,
    sessions: RwLock<HashMap<String, Arc<SessionHandle>>>,
    block_tx: Option<Sender<WriterMessage>>,
    writer: Mutex<Option<std::thread::JoinHandle<()>>>,
    writer_error: Arc<Mutex<Option<String>>>,
    metadata_path: PathBuf,
    command_dir: PathBuf,
    shutting_down: AtomicBool,
}

impl SessionManager {
    pub fn new(options: ManagerOptions) -> Result<Self> {
        std::fs::create_dir_all(&options.data_dir)?;
        let command_dir = options.data_dir.join("sessions").join("cmd");
        std::fs::create_dir_all(&command_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(&options.data_dir, std::fs::Permissions::from_mode(0o700));
        }
        let metadata_path = options.data_dir.join("sessions.json");
        let (block_tx, writer, writer_error) = match &options.blocks_db {
            Some(path) => {
                let (tx, rx) = mpsc::channel::<WriterMessage>();
                let error_slot = Arc::new(Mutex::new(None::<String>));
                let slot = Arc::clone(&error_slot);
                let path = path.clone();
                let handle = std::thread::Builder::new()
                    .name("z-session-blocks".into())
                    .spawn(move || block_writer(path, rx, slot))
                    .map_err(|e| SessionError::Pty(format!("cannot start block writer: {e}")))?;
                (Some(tx), Some(handle), error_slot)
            }
            None => (None, None, Arc::new(Mutex::new(None))),
        };
        Ok(Self {
            options,
            sessions: RwLock::new(HashMap::new()),
            block_tx,
            writer: Mutex::new(writer),
            writer_error,
            metadata_path,
            command_dir,
            shutting_down: AtomicBool::new(false),
        })
    }

    pub fn config(&self) -> &Config {
        &self.options.config
    }

    pub fn data_dir(&self) -> &Path {
        &self.options.data_dir
    }

    pub fn create(&self, params: CreateParams) -> Result<SessionInfo> {
        if self.shutting_down.load(Ordering::SeqCst) {
            return Err(SessionError::Unavailable("daemon is shutting down".into()));
        }
        let profile = params
            .profile
            .as_deref()
            .and_then(|name| self.options.config.profiles.get(name));
        let requested_shell = params
            .shell
            .clone()
            .or_else(|| profile.and_then(|profile| profile.shell.clone()))
            .unwrap_or_else(|| self.options.config.shell.default.clone());
        let shell = if let Some(command) = &params.command {
            command
                .first()
                .cloned()
                .ok_or_else(|| SessionError::Pty("command is empty".into()))?
        } else {
            resolve_shell(&requested_shell)?
        };
        let cwd = params
            .cwd
            .clone()
            .or_else(|| {
                profile
                    .and_then(|profile| profile.cwd.clone())
                    .map(PathBuf::from)
            })
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("/"));
        let cwd = if cwd.is_dir() {
            cwd
        } else {
            return Err(SessionError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("working directory {} does not exist", cwd.display()),
            )));
        };
        let mut env = profile
            .map(|profile| {
                profile
                    .env
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        env.extend(params.env.iter().cloned());

        let command_file = self
            .command_dir
            .join(format!("{}.cmd", uuid::Uuid::new_v4().simple()));
        let rows = params.rows.unwrap_or(40).clamp(2, 1000);
        let cols = params.cols.unwrap_or(120).clamp(2, 2000);
        let options = SessionOptions {
            shell: shell.clone(),
            cwd,
            env,
            rows,
            cols,
            scrollback: self.options.config.session.scrollback_lines,
            title: params.title,
            integration: params
                .integration
                .unwrap_or(self.options.config.shell.integration),
            integration_dir: self.options.integration_dir.clone(),
            command_file: command_file.clone(),
            login: params.login,
            heuristic_blocks: false,
            command: params.command.clone(),
            scrollback_dir: Some(self.options.data_dir.join("scrollback")),
        };
        let tx = self.block_tx.clone();
        let sink: Option<BlockSink> = tx.map(|tx| {
            Arc::new(move |block: Block, output: Vec<u8>| {
                let _ = tx.send(WriterMessage::Block(block, output));
            }) as BlockSink
        });
        let handle = SessionHandle::spawn(options, sink)?;
        let info = handle.info();
        // Record the session up front so blocks have a parent row.
        if let Some(tx) = &self.block_tx {
            let _ = tx.send(WriterMessage::Session(StoredSession {
                id: info.id.clone(),
                title: info.title.clone(),
                shell: info.shell.clone(),
                cwd: info.cwd.clone(),
                created_at: info.created_at,
                closed_at: None,
                status: info.status.clone(),
                workspace_id: None,
                agent_id: None,
                metadata: serde_json::json!({
                    "pid": info.pid,
                    "integration": info.integration,
                    "shell_kind": info.shell_kind,
                }),
            }));
        }
        self.sessions
            .write()
            .expect("sessions lock")
            .insert(info.id.clone(), handle);
        self.persist_metadata();
        Ok(info)
    }

    pub fn list(&self) -> Vec<SessionInfo> {
        let mut infos: Vec<SessionInfo> = self
            .sessions
            .read()
            .expect("sessions lock")
            .values()
            .map(|session| session.info())
            .collect();
        infos.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        infos
    }

    pub fn get(&self, id: &str) -> Option<Arc<SessionHandle>> {
        self.sessions
            .read()
            .expect("sessions lock")
            .get(id)
            .cloned()
    }

    pub fn require(&self, id: &str) -> Result<Arc<SessionHandle>> {
        self.get(id)
            .ok_or_else(|| SessionError::NotFound(id.to_string()))
    }

    pub fn snapshot(&self, id: &str) -> Result<SessionSnapshot> {
        Ok(self.require(id)?.snapshot())
    }

    pub fn replay(&self, id: &str, since: u64) -> Result<Vec<crate::session::OutputChunk>> {
        Ok(self.require(id)?.replay_since(since))
    }

    pub fn attach_blocks(&self, id: &str) -> Vec<Block> {
        let Some(path) = &self.options.blocks_db else {
            return Vec::new();
        };
        match BlockStore::open(path) {
            Ok(store) => store.session_blocks(id).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    pub fn close(&self, id: &str, kill: bool) -> Result<()> {
        let handle = self.require(id)?;
        handle.close(kill)?;
        self.persist_metadata();
        Ok(())
    }

    pub fn remove_closed(&self, id: &str) -> bool {
        let mut sessions = self.sessions.write().expect("sessions lock");
        let closed = sessions
            .get(id)
            .map(|session| !session.is_alive())
            .unwrap_or(false);
        if closed {
            sessions.remove(id);
        }
        closed
    }

    pub fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        let sessions: Vec<Arc<SessionHandle>> = self
            .sessions
            .read()
            .expect("sessions lock")
            .values()
            .cloned()
            .collect();
        for session in sessions {
            let _ = session.close(false);
        }
        if let Some(tx) = &self.block_tx {
            let _ = tx.send(WriterMessage::Shutdown);
        }
        if let Some(handle) = self.writer.lock().expect("writer lock").take() {
            let _ = handle.join();
        }
        self.persist_metadata();
        let _ = std::fs::remove_dir_all(&self.command_dir);
    }

    pub fn writer_error(&self) -> Option<String> {
        self.writer_error.lock().expect("writer error lock").clone()
    }

    fn persist_metadata(&self) {
        let metadata = Metadata {
            version: 1,
            updated_at: Utc::now(),
            sessions: self.list(),
        };
        if let Ok(text) = serde_json::to_string_pretty(&metadata) {
            let tmp = self.metadata_path.with_extension("json.tmp");
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(&tmp, &self.metadata_path);
            }
        }
    }
}

fn block_writer(
    path: PathBuf,
    rx: mpsc::Receiver<WriterMessage>,
    error: Arc<Mutex<Option<String>>>,
) {
    let store = match BlockStore::open(&path) {
        Ok(store) => store,
        Err(open_error) => {
            *error.lock().expect("error lock") = Some(open_error.to_string());
            // Drain so senders do not block forever.
            while rx.recv().is_ok() {}
            return;
        }
    };
    while let Ok(message) = rx.recv() {
        match message {
            WriterMessage::Block(block, output) => {
                if let Err(block_error) = store.insert(&block, &output) {
                    *error.lock().expect("error lock") = Some(block_error.to_string());
                }
            }
            WriterMessage::Session(session) => {
                if let Err(session_error) = store.upsert_session(&session) {
                    *error.lock().expect("error lock") = Some(session_error.to_string());
                }
            }
            WriterMessage::Shutdown => break,
        }
    }
}

/// Resolve a shell name to an executable path.
pub fn resolve_shell(shell: &str) -> Result<String> {
    let candidate = Path::new(shell);
    if candidate.components().count() > 1 {
        if candidate.is_file() {
            return Ok(shell.to_string());
        }
        return Err(SessionError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("shell `{shell}` does not exist"),
        )));
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        let mut candidate = dir.join(shell);
        if cfg!(windows) && candidate.extension().is_none() {
            candidate.set_extension("exe");
        }
        if candidate.is_file() {
            return Ok(candidate.display().to_string());
        }
    }
    // Fallbacks that exist on virtually every Unix host.
    for fallback in ["/bin/sh", "/bin/bash", "/usr/bin/sh"] {
        if Path::new(fallback).is_file() {
            return Ok(fallback.to_string());
        }
    }
    Err(SessionError::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("cannot find shell `{shell}` on PATH"),
    )))
}

/// Reference the integration module so downstream callers can generate scripts
/// through one path.
pub fn integration_manifest(dir: &Path) -> std::io::Result<integration::Manifest> {
    integration::ensure_scripts(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-zsession-mgr-{}-{}-{}",
            name,
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn manager(name: &str) -> (SessionManager, PathBuf) {
        let dir = temp_dir(name);
        let options = ManagerOptions::new(&dir, Config::default());
        (SessionManager::new(options).unwrap(), dir)
    }

    #[cfg(unix)]
    #[test]
    fn create_list_snapshot_and_close() {
        let (manager, dir) = manager("lifecycle");
        let info = manager
            .create(CreateParams {
                shell: Some("/bin/sh".into()),
                cwd: Some(dir.clone()),
                rows: Some(24),
                cols: Some(80),
                integration: Some(ShellIntegration::Off),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(info.rows, 24);
        assert_eq!(info.cols, 80);
        assert!(manager.list().iter().any(|s| s.id == info.id));
        let snapshot = manager.snapshot(&info.id).unwrap();
        assert_eq!(snapshot.info.id, info.id);
        let handle = manager.require(&info.id).unwrap();
        handle.input(b"echo zentrion-session-test\n").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let contents = manager.snapshot(&info.id).unwrap().contents;
        assert!(contents.contains("zentrion-session-test"));
        manager.close(&info.id, true).unwrap();
        manager.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn direct_command_session_runs_without_a_shell() {
        let (manager, dir) = manager("direct-command");
        let info = manager
            .create(CreateParams {
                command: Some(vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "echo direct-command; sleep 0.1".into(),
                ]),
                cwd: Some(dir.clone()),
                integration: Some(ShellIntegration::Off),
                ..Default::default()
            })
            .unwrap();
        assert!(!info.integration);
        assert_eq!(info.shell_kind, "program");
        std::thread::sleep(std::time::Duration::from_millis(300));
        let snapshot = manager.snapshot(&info.id).unwrap();
        assert!(
            snapshot.contents.contains("direct-command"),
            "{}",
            snapshot.contents
        );
        manager.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_shell_is_an_error() {
        assert!(resolve_shell("/definitely/not/a/shell").is_err());
    }

    #[test]
    fn metadata_is_persisted() {
        let (manager, dir) = manager("metadata");
        if cfg!(unix) {
            manager
                .create(CreateParams {
                    shell: Some("/bin/sh".into()),
                    cwd: Some(dir.clone()),
                    integration: Some(ShellIntegration::Off),
                    ..Default::default()
                })
                .unwrap();
        }
        let text = std::fs::read_to_string(dir.join("sessions.json")).unwrap();
        assert!(text.contains("\"version\""));
        manager.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

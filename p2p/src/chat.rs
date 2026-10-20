//! Encrypted peer-to-peer LAN chat with UDP discovery.
//!
//! Wire format for messages: `u32` big-endian length followed by an
//! AES-256-GCM sealed JSON payload (nonce included). Discovery uses the same
//! sealed payload inside a UDP datagram prefixed with a magic value.
//!
//! The design is deliberately serverless: peers announce themselves on the
//! broadcast address and connect directly to each other.

use crate::crypto::{decrypt_message, derive_key, encrypt_message, fingerprint};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{broadcast, mpsc, Mutex};

pub const DEFAULT_TCP_PORT: u16 = 7778;
pub const DEFAULT_DISCOVERY_PORT: u16 = 7777;

const MAGIC: &[u8; 4] = b"ZP2P";
const MAX_FRAME: usize = 1024 * 1024;
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(5);
const PEER_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatMessage {
    pub sender: String,
    pub content: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Announce {
    /// Random per-process id so two instances on one host are distinct.
    id: String,
    name: String,
    port: u16,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub id: String,
    pub name: String,
    pub addr: SocketAddr,
    pub last_seen: Instant,
}

#[derive(Debug, Clone)]
pub enum P2pEvent {
    Ready {
        tcp_port: u16,
        discovery_port: Option<u16>,
        fingerprint: String,
    },
    PeerJoined(PeerInfo),
    PeerLeft(String),
    Message(ChatMessage),
    Error(String),
}

#[derive(Debug)]
pub enum P2pCommand {
    /// Send to every currently known peer.
    Broadcast(String),
    /// Send to one peer id.
    Send {
        target_id: String,
        content: String,
    },
    /// Send to an explicit address (used by tests and advanced tooling).
    SendAddr {
        addr: SocketAddr,
        content: String,
    },
    Shutdown,
}

#[derive(Debug, Clone)]
pub struct P2pConfig {
    pub username: String,
    /// Passphrase shared out-of-band with the other peers.
    pub passphrase: String,
    /// TCP port; 0 asks the OS for an ephemeral port.
    pub tcp_port: u16,
    /// `None` disables UDP discovery (useful for tests and direct links).
    pub discovery_port: Option<u16>,
}

impl P2pConfig {
    pub fn new(username: impl Into<String>, passphrase: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            passphrase: passphrase.into(),
            tcp_port: DEFAULT_TCP_PORT,
            discovery_port: Some(DEFAULT_DISCOVERY_PORT),
        }
    }
}

pub struct P2pHandle {
    pub events: broadcast::Receiver<P2pEvent>,
    pub commands: mpsc::UnboundedSender<P2pCommand>,
    pub tcp_port: u16,
    pub fingerprint: String,
    pub instance_id: String,
}

impl P2pHandle {
    pub fn broadcast(&self, content: impl Into<String>) {
        let _ = self.commands.send(P2pCommand::Broadcast(content.into()));
    }

    pub fn send_to(&self, target_id: impl Into<String>, content: impl Into<String>) {
        let _ = self.commands.send(P2pCommand::Send {
            target_id: target_id.into(),
            content: content.into(),
        });
    }

    pub fn shutdown(&self) {
        let _ = self.commands.send(P2pCommand::Shutdown);
    }
}

/// Start the network. Must be called inside a Tokio runtime; spawned tasks
/// live until the runtime shuts down or [`P2pHandle::shutdown`] is called.
pub async fn start(config: P2pConfig) -> Result<P2pHandle> {
    if config.passphrase.trim().is_empty() {
        return Err(anyhow!(
            "a chat passphrase is required; set ZENTRION_P2P_KEY or enter one in the UI"
        ));
    }
    if config.passphrase.chars().count() < 8 {
        return Err(anyhow!(
            "the chat passphrase must be at least 8 characters (use a long shared phrase)"
        ));
    }
    let key = derive_key(&config.passphrase);
    let instance_id = uuid_like();
    let username = if config.username.trim().is_empty() {
        "anonymous".to_string()
    } else {
        config.username.trim().to_string()
    };

    let listener = TcpListener::bind(("0.0.0.0", config.tcp_port))
        .await
        .with_context(|| format!("could not bind TCP port {}", config.tcp_port))?;
    let tcp_port = listener.local_addr()?.port();

    let (event_tx, event_rx) = broadcast::channel(512);
    let (command_tx, command_rx) = mpsc::unbounded_channel();
    let peers: Arc<Mutex<HashMap<String, PeerInfo>>> = Arc::new(Mutex::new(HashMap::new()));

    let _ = event_tx.send(P2pEvent::Ready {
        tcp_port,
        discovery_port: config.discovery_port,
        fingerprint: fingerprint(&key),
    });

    // TCP chat listener.
    {
        let event_tx = event_tx.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let event_tx = event_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_incoming(stream, &key, &event_tx).await {
                                let _ = event_tx.send(P2pEvent::Error(format!(
                                    "connection from {addr} failed: {e}"
                                )));
                            }
                        });
                    }
                    Err(e) => {
                        let _ = event_tx.send(P2pEvent::Error(format!("accept failed: {e}")));
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                }
            }
        });
    }

    // UDP discovery (optional).
    if let Some(discovery_port) = config.discovery_port {
        if discovery_port != 0 {
            match bind_discovery_socket(discovery_port) {
                Ok(udp) => {
                    let announce = Announce {
                        id: instance_id.clone(),
                        name: username.clone(),
                        port: tcp_port,
                    };
                    {
                        let event_tx = event_tx.clone();
                        let peers = peers.clone();
                        let id = instance_id.clone();
                        tokio::spawn(async move {
                            discovery_loop(udp, announce, key, id, discovery_port, peers, event_tx)
                                .await;
                        });
                    }
                }
                Err(e) => {
                    let _ = event_tx.send(P2pEvent::Error(format!(
                        "LAN discovery unavailable on UDP {discovery_port}: {e}"
                    )));
                }
            }
        }
    }

    // Expire peers that stopped announcing.
    {
        let peers = peers.clone();
        let event_tx = event_tx.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let expired: Vec<String> = {
                    let guard = peers.lock().await;
                    guard
                        .iter()
                        .filter(|(_, peer)| peer.last_seen.elapsed() > PEER_TIMEOUT)
                        .map(|(id, _)| id.clone())
                        .collect()
                };
                for id in expired {
                    peers.lock().await.remove(&id);
                    let _ = event_tx.send(P2pEvent::PeerLeft(id));
                }
            }
        });
    }

    // Command processing.
    {
        let peers = peers.clone();
        let event_tx = event_tx.clone();
        let username = username.clone();
        tokio::spawn(async move {
            command_loop(command_rx, peers, key, username, event_tx).await;
        });
    }

    Ok(P2pHandle {
        events: event_rx,
        commands: command_tx,
        tcp_port,
        fingerprint: fingerprint(&key),
        instance_id,
    })
}

/// Bind the UDP discovery socket with address/port reuse so several Zentrion
/// instances can coexist on one machine (and so a second instance can be
/// started without waiting for the first to exit).
fn bind_discovery_socket(port: u16) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("could not create UDP discovery socket")?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_broadcast(true)?;
    socket.bind(&SocketAddr::from(([0, 0, 0, 0], port)).into())?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    Ok(UdpSocket::from_std(std_socket)?)
}

async fn handle_incoming(
    mut stream: TcpStream,
    key: &[u8; 32],
    event_tx: &broadcast::Sender<P2pEvent>,
) -> Result<()> {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(30), read_frame(&mut stream))
            .await
            .map_err(|_| anyhow!("peer idle timeout"))??;
        let Some(frame) = frame else {
            return Ok(());
        };
        let plaintext = decrypt_message(key, &frame)?;
        let message: ChatMessage =
            serde_json::from_slice(&plaintext).map_err(|e| anyhow!("invalid chat payload: {e}"))?;
        let _ = event_tx.send(P2pEvent::Message(message));
    }
}

async fn read_frame(stream: &mut TcpStream) -> Result<Option<Vec<u8>>> {
    let mut length = [0u8; 4];
    match stream.read_exact(&mut length).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 {
        return Ok(None);
    }
    if length > MAX_FRAME {
        return Err(anyhow!("frame exceeds {MAX_FRAME} bytes"));
    }
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

async fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(anyhow!("message is too large"));
    }
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

async fn send_message(addr: SocketAddr, key: &[u8; 32], message: &ChatMessage) -> Result<()> {
    let plaintext = serde_json::to_vec(message)?;
    let sealed = encrypt_message(key, &plaintext)?;
    let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("timed out connecting to {addr}"))?
        .context("connect failed")?;
    write_frame(&mut stream, &sealed).await
}

async fn command_loop(
    mut commands: mpsc::UnboundedReceiver<P2pCommand>,
    peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
    key: [u8; 32],
    username: String,
    event_tx: broadcast::Sender<P2pEvent>,
) {
    while let Some(command) = commands.recv().await {
        match command {
            P2pCommand::Shutdown => break,
            P2pCommand::Broadcast(content) => {
                let targets: Vec<SocketAddr> = {
                    let guard = peers.lock().await;
                    guard.values().map(|peer| peer.addr).collect()
                };
                let message = new_message(&username, content);
                for addr in targets {
                    let message = message.clone();
                    let event_tx = event_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = send_message(addr, &key, &message).await {
                            let _ = event_tx.send(P2pEvent::Error(format!("send: {e}")));
                        }
                    });
                }
            }
            P2pCommand::Send { target_id, content } => {
                let target = {
                    let guard = peers.lock().await;
                    guard.get(&target_id).map(|peer| peer.addr)
                };
                match target {
                    Some(addr) => {
                        let message = new_message(&username, content);
                        if let Err(e) = send_message(addr, &key, &message).await {
                            let _ = event_tx.send(P2pEvent::Error(format!("send: {e}")));
                        }
                    }
                    None => {
                        let _ =
                            event_tx.send(P2pEvent::Error("that peer is no longer online".into()));
                    }
                }
            }
            P2pCommand::SendAddr { addr, content } => {
                let message = new_message(&username, content);
                if let Err(e) = send_message(addr, &key, &message).await {
                    let _ = event_tx.send(P2pEvent::Error(format!("send: {e}")));
                }
            }
        }
    }
}

async fn discovery_loop(
    socket: UdpSocket,
    announce: Announce,
    key: [u8; 32],
    instance_id: String,
    discovery_port: u16,
    peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
    event_tx: broadcast::Sender<P2pEvent>,
) {
    let payload = match serde_json::to_vec(&announce) {
        Ok(payload) => payload,
        Err(_) => return,
    };
    let sealed = match encrypt_message(&key, &payload) {
        Ok(sealed) => sealed,
        Err(_) => return,
    };
    let mut datagram = MAGIC.to_vec();
    datagram.extend_from_slice(&sealed);
    let broadcast_target =
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::BROADCAST), discovery_port);
    // Also announce on loopback so multiple instances on the same machine
    // (and same-host test harnesses) discover each other reliably.
    let loopback_target =
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), discovery_port);

    let mut ticker = tokio::time::interval(ANNOUNCE_INTERVAL);
    let mut buf = [0u8; 2048];

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let _ = socket.send_to(&datagram, broadcast_target).await;
                let _ = socket.send_to(&datagram, loopback_target).await;
            }
            received = socket.recv_from(&mut buf) => {
                let Ok((len, source)) = received else { continue };
                let bytes = &buf[..len];
                if !bytes.starts_with(MAGIC) {
                    continue;
                }
                let Ok(plaintext) = decrypt_message(&key, &bytes[MAGIC.len()..]) else {
                    continue;
                };
                let Ok(remote) = serde_json::from_slice::<Announce>(&plaintext) else {
                    continue;
                };
                if remote.id == instance_id {
                    continue;
                }
                let addr = SocketAddr::new(source.ip(), remote.port);
                let mut guard = peers.lock().await;
                let is_new = !guard.contains_key(&remote.id);
                guard.insert(
                    remote.id.clone(),
                    PeerInfo {
                        id: remote.id.clone(),
                        name: remote.name.clone(),
                        addr,
                        last_seen: Instant::now(),
                    },
                );
                drop(guard);
                if is_new {
                    let _ = event_tx.send(P2pEvent::PeerJoined(PeerInfo {
                        id: remote.id,
                        name: remote.name,
                        addr,
                        last_seen: Instant::now(),
                    }));
                }
            }
        }
    }
}

fn new_message(sender: &str, content: String) -> ChatMessage {
    ChatMessage {
        sender: sender.to_string(),
        content,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    }
}

fn uuid_like() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn start_pair() -> (P2pHandle, P2pHandle) {
        let a = start(P2pConfig {
            username: "alice".into(),
            passphrase: "shared-secret".into(),
            tcp_port: 0,
            discovery_port: None,
        })
        .await
        .unwrap();
        let b = start(P2pConfig {
            username: "bob".into(),
            passphrase: "shared-secret".into(),
            tcp_port: 0,
            discovery_port: None,
        })
        .await
        .unwrap();
        (a, b)
    }

    #[tokio::test]
    async fn delivers_encrypted_message_between_peers() {
        let (a, mut b) = start_pair().await;
        // The Ready event is delivered first.
        let _ = b.events.recv().await;
        let addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), b.tcp_port);
        a.commands
            .send(P2pCommand::SendAddr {
                addr,
                content: "hello bob".into(),
            })
            .unwrap();

        let event = tokio::time::timeout(Duration::from_secs(5), b.events.recv())
            .await
            .expect("timed out waiting for message")
            .unwrap();
        match event {
            P2pEvent::Message(message) => {
                assert_eq!(message.sender, "alice");
                assert_eq!(message.content, "hello bob");
                assert!(message.timestamp > 0);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn messages_fail_with_wrong_passphrase() {
        let a = start(P2pConfig {
            username: "alice".into(),
            passphrase: "passphrase-one".into(),
            tcp_port: 0,
            discovery_port: None,
        })
        .await
        .unwrap();
        let mut b = start(P2pConfig {
            username: "bob".into(),
            passphrase: "passphrase-two".into(),
            tcp_port: 0,
            discovery_port: None,
        })
        .await
        .unwrap();
        let _ = b.events.recv().await;
        let addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), b.tcp_port);
        a.commands
            .send(P2pCommand::SendAddr {
                addr,
                content: "should not decrypt".into(),
            })
            .unwrap();
        // We expect an error event, never a message.
        let event = tokio::time::timeout(Duration::from_secs(5), b.events.recv())
            .await
            .expect("timed out")
            .unwrap();
        assert!(matches!(event, P2pEvent::Error(_)), "got {event:?}");
    }

    #[test]
    fn timestamped_messages_are_serializable() {
        let message = new_message("alice", "hi".into());
        let json = serde_json::to_vec(&message).unwrap();
        let back: ChatMessage = serde_json::from_slice(&json).unwrap();
        assert_eq!(message, back);
    }
}

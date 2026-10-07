use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;
use crate::crypto::{encrypt_message, decrypt_message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub sender: String,
    pub content: String,
    pub timestamp: u64,
}

pub struct P2pNetwork {
    pub username: String,
    pub port: u16,
    pub secret_key: [u8; 32], // Pre-shared key for the network
    pub tx: broadcast::Sender<ChatMessage>,
}

impl P2pNetwork {
    pub fn new(username: String, port: u16, secret_key: [u8; 32]) -> (Arc<Self>, broadcast::Receiver<ChatMessage>) {
        let (tx, rx) = broadcast::channel(100);
        let network = Arc::new(Self {
            username,
            port,
            secret_key,
            tx,
        });
        (network, rx)
    }

    pub async fn start(self: Arc<Self>) -> Result<()> {
        let net_clone1 = self.clone();
        tokio::spawn(async move {
            let _ = net_clone1.listen_tcp().await;
        });

        let net_clone2 = self.clone();
        tokio::spawn(async move {
            let _ = net_clone2.discovery_loop().await;
        });

        Ok(())
    }

    async fn listen_tcp(&self) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port)).await?;
        
        loop {
            let (mut socket, _addr) = listener.accept().await?;
            let tx = self.tx.clone();
            let key = self.secret_key.clone();
            
            tokio::spawn(async move {
                let mut buf = vec![0; 4096];
                if let Ok(n) = socket.read(&mut buf).await {
                    if n > 0 {
                        if let Ok(plaintext) = decrypt_message(&key, &buf[0..n]) {
                            if let Ok(msg) = serde_json::from_slice::<ChatMessage>(&plaintext) {
                                let _ = tx.send(msg);
                            }
                        }
                    }
                }
            });
        }
    }

    async fn discovery_loop(&self) -> Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.set_broadcast(true)?;
        
        // Announce presence every 10 seconds
        loop {
            let announce = format!("ZENTRION_PEER:{}:{}", self.username, self.port);
            let _ = socket.send_to(announce.as_bytes(), format!("255.255.255.255:{}", 7777)).await;
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        }
    }

    pub async fn send_message(&self, target_ip: &str, target_port: u16, content: String) -> Result<()> {
        let msg = ChatMessage {
            sender: self.username.clone(),
            content,
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
        };
        
        let plaintext = serde_json::to_vec(&msg)?;
        let ciphertext = encrypt_message(&self.secret_key, &plaintext)?;
        
        let mut stream = TcpStream::connect(format!("{}:{}", target_ip, target_port)).await?;
        stream.write_all(&ciphertext).await?;
        Ok(())
    }
}

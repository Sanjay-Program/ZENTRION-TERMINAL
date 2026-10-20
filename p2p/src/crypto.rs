//! Authenticated encryption for LAN chat and discovery.
//!
//! A pre-shared passphrase is stretched into an AES-256-GCM key. Every message
//! (including discovery announcements) carries a fresh 96-bit nonce. Peers
//! without the passphrase cannot read traffic, forge a peer, or inject
//! messages.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

/// Derive a stable 256-bit key from a shared passphrase.
///
/// This is deliberately deterministic so two machines that type the same
/// passphrase meet on the LAN. The domain separator prevents reuse of the key
/// material outside Zentrion's chat protocol.
pub fn derive_key(passphrase: &str) -> [u8; 32] {
    // Stretch the passphrase so a captured announcement cannot be brute-forced
    // cheaply. 100k SHA-256 rounds is fast enough at startup and slow enough to
    // make offline guessing meaningfully harder. A memory-hard KDF (Argon2)
    // would be better still and is a candidate for a future version.
    let mut hasher = Sha256::new();
    hasher.update(b"zentrion-p2p-chat-v1\0");
    hasher.update(passphrase.as_bytes());
    let mut digest: [u8; 32] = hasher.finalize().into();
    for _ in 0..100_000 {
        digest = Sha256::digest(digest).into();
    }
    digest
}

pub fn encrypt_message(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| anyhow!("encryption failed"))?;
    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);
    Ok(combined)
}

pub fn decrypt_message(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < 12 {
        return Err(anyhow!("ciphertext is too short"));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&ciphertext[0..12]);
    let payload = &ciphertext[12..];
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| anyhow!("decryption failed: wrong key or tampered message"))
}

/// Short, non-secret identifier for a key, safe to display on screen.
pub fn fingerprint(key: &[u8; 32]) -> String {
    let digest = Sha256::digest(key);
    hex::encode(&digest[..4])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = derive_key("correct horse battery staple");
        let plaintext = b"hello, LAN";
        let sealed = encrypt_message(&key, plaintext).unwrap();
        assert_ne!(&sealed[12..], plaintext);
        assert_eq!(decrypt_message(&key, &sealed).unwrap(), plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = encrypt_message(&derive_key("one"), b"secret").unwrap();
        assert!(decrypt_message(&derive_key("two"), &sealed).is_err());
    }

    #[test]
    fn tampering_fails() {
        let key = derive_key("key");
        let mut sealed = encrypt_message(&key, b"secret").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(decrypt_message(&key, &sealed).is_err());
    }

    #[test]
    fn fingerprint_is_stable_and_short() {
        let key = derive_key("key");
        assert_eq!(fingerprint(&key), fingerprint(&key));
        assert_eq!(fingerprint(&key).len(), 8);
        assert_ne!(fingerprint(&key), fingerprint(&derive_key("other")));
    }
}

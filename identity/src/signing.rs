//! Ed25519 signing keys for checkpoints, evidence bundles and signed exports.
//!
//! The private key is generated with the OS CSPRNG, stored as PKCS#8 in
//! `signing.key` with mode 0600, and never leaves the machine. Verification
//! uses only the public key, so a signed artifact can be checked elsewhere.
//!
//! This is real Ed25519 ([`ring`]), not a hash dressed up as a signature.

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use std::path::{Path, PathBuf};
use z_core::error::{Area, ZenError, ZenResult};

/// A local Ed25519 key pair.
pub struct SigningKey {
    pair: Ed25519KeyPair,
    path: PathBuf,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("public_key", &self.public_key_hex())
            .field("path", &self.path)
            .finish()
    }
}

impl SigningKey {
    /// Load an existing key or create one. The key file is `0600`.
    pub fn load_or_create(dir: &Path) -> ZenResult<Self> {
        std::fs::create_dir_all(dir).map_err(|e| {
            ZenError::new(
                Area::Cor,
                120,
                format!("cannot create key directory {}: {e}", dir.display()),
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let path = dir.join("signing.key");
        if path.exists() {
            return Self::load(&path);
        }
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| {
            ZenError::new(Area::Cor, 121, "CSPRNG failed while generating signing key")
        })?;
        // create_new prevents two processes from racing to different keys.
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                use std::io::Write;
                file.write_all(pkcs8.as_ref()).map_err(|e| {
                    ZenError::new(Area::Cor, 122, format!("cannot write signing key: {e}"))
                })?;
                file.sync_all().ok();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
                }
                Self::load(&path)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Self::load(&path),
            Err(error) => Err(ZenError::new(
                Area::Cor,
                123,
                format!("cannot create signing key {}: {error}", path.display()),
            )),
        }
    }

    /// Load an existing PKCS#8 key file.
    pub fn load(path: &Path) -> ZenResult<Self> {
        let bytes = std::fs::read(path).map_err(|e| {
            ZenError::new(
                Area::Cor,
                124,
                format!("cannot read signing key {}: {e}", path.display()),
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(path) {
                let mode = metadata.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    return Err(ZenError::new(
                        Area::Cor,
                        125,
                        format!(
                            "signing key {} is readable by other users (mode {mode:o})",
                            path.display()
                        ),
                    )
                    .with_remediation("chmod 600 the key file."));
                }
            }
        }
        let pair = Ed25519KeyPair::from_pkcs8(&bytes).map_err(|_| {
            ZenError::new(
                Area::Cor,
                126,
                format!("{} is not a valid Ed25519 PKCS#8 key", path.display()),
            )
        })?;
        Ok(Self {
            pair,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn public_key(&self) -> [u8; 32] {
        let bytes = self.pair.public_key().as_ref();
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[..32]);
        key
    }

    pub fn public_key_hex(&self) -> String {
        hex_encode(&self.public_key())
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.pair.sign(message).as_ref().to_vec()
    }

    pub fn sign_hex(&self, message: &[u8]) -> String {
        hex_encode(&self.sign(message))
    }
}

/// Verify a detached Ed25519 signature.
pub fn verify(public_key_hex: &str, message: &[u8], signature_hex: &str) -> bool {
    let Ok(public_key) = hex_decode(public_key_hex) else {
        return false;
    };
    let Ok(signature) = hex_decode(signature_hex) else {
        return false;
    };
    if public_key.len() != 32 {
        return false;
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(message, &signature)
        .is_ok()
}

/// Write the public key next to the private key for export.
pub fn export_public_key(key: &SigningKey) -> ZenResult<PathBuf> {
    let path = key.path.with_extension("pub");
    let text = format!("zentrion-ed25519 {}\n", key.public_key_hex());
    std::fs::write(&path, text).map_err(|e| {
        ZenError::new(
            Area::Cor,
            127,
            format!("cannot write public key {}: {e}", path.display()),
        )
    })?;
    Ok(path)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn hex_decode(text: &str) -> Result<Vec<u8>, ()> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let mut index = 0;
    while index < text.len() {
        let byte = u8::from_str_radix(&text[index..index + 2], 16).map_err(|_| ())?;
        bytes.push(byte);
        index += 2;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-signing-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn key_round_trips_and_signatures_verify() {
        let dir = temp_dir("keys");
        let key = SigningKey::load_or_create(&dir).unwrap();
        let message = b"checkpoint manifest bytes";
        let signature = key.sign_hex(message);
        assert!(verify(&key.public_key_hex(), message, &signature));
        assert!(!verify(&key.public_key_hex(), b"other", &signature));
        let reloaded = SigningKey::load_or_create(&dir).unwrap();
        assert_eq!(key.public_key_hex(), reloaded.public_key_hex());
        let public = export_public_key(&key).unwrap();
        assert!(std::fs::read_to_string(public)
            .unwrap()
            .contains("zentrion-ed25519"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn insecure_key_permissions_are_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perms");
        let key = SigningKey::load_or_create(&dir).unwrap();
        std::fs::set_permissions(key.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(SigningKey::load(key.path()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_signatures_are_rejected() {
        assert!(!verify("zz", b"x", "00"));
        assert!(!verify("00", b"x", "00"));
    }
}

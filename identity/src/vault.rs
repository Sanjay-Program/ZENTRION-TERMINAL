//! Encrypted vault for storing secrets.
//!
//! Security properties:
//! - AES-256-GCM authenticated encryption (nonce is random per write).
//! - The master key is generated from the OS CSPRNG and stored in a separate
//!   `vault.key` file with `0600` permissions.
//! - Writes are atomic (temp file + rename) so a crash cannot truncate the
//!   vault.
//! - Legacy prototype vaults (which used a public hard-coded key) are migrated
//!   automatically and re-encrypted with the real key.
//!
//! This is a local secrets store, not a hardware-backed keystore: an attacker
//! who can read your user's files can read the key. It protects against
//! accidental disclosure (backups, logs, screen sharing), not a compromised
//! account.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use z_core::error::{Area, ZenError, ZenResult};

const MAGIC: &[u8; 8] = b"ZVAULT1\0";
const LEGACY_KEY: &[u8; 32] = b"zentrion-dummy-master-key-000000";

#[derive(Serialize, Deserialize, Default)]
struct VaultData {
    secrets: HashMap<String, String>,
}

fn base_dir() -> ZenResult<PathBuf> {
    let dir = z_core::config::user_data_dir()
        .or_else(|| dirs::home_dir().map(|home| home.join(".zentrion")))
        .ok_or_else(|| {
            ZenError::new(Area::Cor, 90, "Cannot determine a vault directory")
                .with_remediation("Set HOME or ZENTRION_DATA_DIR.")
        })?;
    let vault_dir = dir.join("vault");
    fs::create_dir_all(&vault_dir).map_err(|e| {
        ZenError::new(
            Area::Cor,
            91,
            format!(
                "Failed to create vault directory {}: {e}",
                vault_dir.display()
            ),
        )
    })?;
    Ok(vault_dir)
}

fn vault_path() -> ZenResult<PathBuf> {
    Ok(base_dir()?.join("secrets.enc"))
}

fn key_path() -> ZenResult<PathBuf> {
    Ok(base_dir()?.join("vault.key"))
}

/// Load the per-install key, creating it with restrictive permissions on first
/// use.
fn load_or_create_key() -> ZenResult<[u8; 32]> {
    let path = key_path()?;
    if path.exists() {
        let bytes = fs::read(&path)
            .map_err(|e| ZenError::new(Area::Cor, 98, format!("Failed to read vault key: {e}")))?;
        if bytes.len() != 32 {
            return Err(ZenError::new(
                Area::Sec,
                99,
                "Vault key file is corrupt (expected 32 bytes)",
            )
            .with_remediation("Restore vault.key from backup or delete the vault to start over."));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }

    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| {
                ZenError::new(Area::Cor, 100, format!("Failed to create vault key: {e}"))
            })?;
        file.write_all(&key)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| {
                ZenError::new(Area::Cor, 100, format!("Failed to create vault key: {e}"))
            })?;
        file.write_all(&key)?;
        file.sync_all()?;
    }
    Ok(key)
}

fn encrypt_with(key: &[u8; 32], data: &[u8]) -> ZenResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| ZenError::new(Area::Sec, 101, format!("Encryption failed: {e}")))?;
    let mut result = Vec::with_capacity(MAGIC.len() + 12 + ciphertext.len());
    result.extend_from_slice(MAGIC);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decrypt_with(key: &[u8; 32], data: &[u8]) -> ZenResult<Vec<u8>> {
    if data.len() < 12 {
        return Err(ZenError::new(
            Area::Sec,
            102,
            "Vault data is too short (missing nonce)",
        ));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&data[0..12]);
    cipher.decrypt(nonce, &data[12..]).map_err(|_| {
        ZenError::new(
            Area::Sec,
            103,
            "Vault decryption failed (wrong key or corrupt data)",
        )
    })
}

fn load_vault() -> ZenResult<VaultData> {
    let path = vault_path()?;
    let mut legacy_candidates = vec![base_dir()?.join("vault.enc")];
    if let Some(home) = dirs::home_dir() {
        let old = home.join(".zentrion").join("vault.enc");
        if !legacy_candidates.contains(&old) {
            legacy_candidates.push(old);
        }
    }
    let legacy = legacy_candidates.into_iter().find(|path| path.exists());

    if !path.exists() {
        if let Some(legacy) = legacy {
            // Migrate the prototype vault: decrypt with the old public key,
            // then immediately re-encrypt with the per-install key.
            let mut bytes = Vec::new();
            fs::File::open(&legacy)
                .and_then(|mut f| f.read_to_end(&mut bytes))
                .map_err(|e| {
                    ZenError::new(Area::Cor, 104, format!("Failed to read legacy vault: {e}"))
                })?;
            let plaintext = decrypt_with(LEGACY_KEY, &bytes).map_err(|_| {
                ZenError::new(
                    Area::Sec,
                    105,
                    "Legacy vault could not be decrypted; leaving it untouched",
                )
            })?;
            let data: VaultData = serde_json::from_slice(&plaintext).map_err(|e| {
                ZenError::new(Area::Cor, 106, format!("Failed to parse legacy vault: {e}"))
            })?;
            save_vault(&data)?;
            let _ = fs::remove_file(&legacy);
            return Ok(data);
        }
        return Ok(VaultData::default());
    }

    let mut raw = Vec::new();
    fs::File::open(&path)
        .and_then(|mut f| f.read_to_end(&mut raw))
        .map_err(|e| ZenError::new(Area::Cor, 107, format!("Failed to read vault: {e}")))?;

    if !raw.starts_with(MAGIC) {
        return Err(ZenError::new(
            Area::Sec,
            108,
            "Vault file has an unrecognized format",
        ));
    }
    let key = load_or_create_key()?;
    let plaintext = decrypt_with(&key, &raw[MAGIC.len()..])?;
    serde_json::from_slice(&plaintext)
        .map_err(|e| ZenError::new(Area::Cor, 109, format!("Failed to parse vault JSON: {e}")))
}

fn save_vault(data: &VaultData) -> ZenResult<()> {
    let path = vault_path()?;
    let key = load_or_create_key()?;
    let json = serde_json::to_vec(data)
        .map_err(|e| ZenError::new(Area::Cor, 110, format!("Failed to serialize vault: {e}")))?;
    let encrypted = encrypt_with(&key, &json)?;

    let tmp = path.with_extension("enc.tmp");
    {
        let mut file = fs::File::create(&tmp).map_err(|e| {
            ZenError::new(Area::Cor, 111, format!("Failed to create temp vault: {e}"))
        })?;
        file.write_all(&encrypted)?;
        file.sync_all()?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }

    fs::rename(&tmp, &path)
        .map_err(|e| ZenError::new(Area::Cor, 112, format!("Failed to commit vault write: {e}")))?;
    Ok(())
}

/// Store a secret. The value is never written to logs or config files.
pub fn set_secret(key: &str, value: &str) -> ZenResult<()> {
    if key.trim().is_empty() {
        return Err(ZenError::new(Area::Cfg, 113, "Secret name cannot be empty"));
    }
    let mut vault = load_vault()?;
    vault.secrets.insert(key.to_string(), value.to_string());
    save_vault(&vault)
}

/// Retrieve a secret.
pub fn get_secret(key: &str) -> ZenResult<Option<String>> {
    let vault = load_vault()?;
    Ok(vault.secrets.get(key).cloned())
}

/// Delete a secret and persist the vault.
pub fn delete_secret(key: &str) -> ZenResult<bool> {
    let mut vault = load_vault()?;
    let removed = vault.secrets.remove(key).is_some();
    if removed {
        save_vault(&vault)?;
    }
    Ok(removed)
}

/// Names only — never values.
pub fn list_secret_names() -> ZenResult<Vec<String>> {
    let vault = load_vault()?;
    let mut names: Vec<String> = vault.secrets.keys().cloned().collect();
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Tests mutate process environment; serialize them.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_temp_home<T>(f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "zentrion_vault_test_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let old_home = std::env::var_os("HOME");
        let old_data = std::env::var_os("ZENTRION_DATA_DIR");
        std::env::set_var("HOME", &dir);
        std::env::set_var("ZENTRION_DATA_DIR", dir.join("data"));
        let result = f();
        match old_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match old_data {
            Some(v) => std::env::set_var("ZENTRION_DATA_DIR", v),
            None => std::env::remove_var("ZENTRION_DATA_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    #[test]
    fn test_set_and_get_secret() {
        with_temp_home(|| {
            assert_eq!(get_secret("test_key").unwrap(), None);
            set_secret("test_key", "super_secret_value").unwrap();
            assert_eq!(
                get_secret("test_key").unwrap(),
                Some("super_secret_value".to_string())
            );
            set_secret("test_key", "new_value").unwrap();
            assert_eq!(
                get_secret("test_key").unwrap(),
                Some("new_value".to_string())
            );
            set_secret("another_key", "another_value").unwrap();
            assert_eq!(
                get_secret("another_key").unwrap(),
                Some("another_value".to_string())
            );
            assert_eq!(
                list_secret_names().unwrap(),
                vec!["another_key".to_string(), "test_key".to_string()]
            );
            assert!(delete_secret("another_key").unwrap());
            assert_eq!(get_secret("another_key").unwrap(), None);
        });
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        with_temp_home(|| {
            set_secret("k", "PLAINTEXT-SENTINEL-1234").unwrap();
            let raw = std::fs::read(vault_path().unwrap()).unwrap();
            assert!(raw.starts_with(MAGIC));
            assert!(!raw
                .windows(b"PLAINTEXT-SENTINEL-1234".len())
                .any(|w| w == b"PLAINTEXT-SENTINEL-1234"));
        });
    }

    #[test]
    fn key_is_private_and_stable() {
        with_temp_home(|| {
            let first = load_or_create_key().unwrap();
            let second = load_or_create_key().unwrap();
            assert_eq!(first, second);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(key_path().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o600, "vault key must not be group/world readable");
            }
        });
    }

    #[test]
    fn wrong_key_is_rejected() {
        use aes_gcm::aead::Aead;
        let key = [7u8; 32];
        let other = [9u8; 32];
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let nonce = Nonce::from_slice(&[1u8; 12]);
        let sealed = cipher.encrypt(nonce, b"data".as_ref()).unwrap();
        assert!(decrypt_with(&other, &sealed).is_err());
    }
}

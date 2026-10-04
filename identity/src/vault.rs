//! Encrypted vault for storing secrets securely.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use z_core::error::{Area, ZenError, ZenResult};

#[derive(Serialize, Deserialize, Default)]
struct VaultData {
    secrets: HashMap<String, String>,
}

const MASTER_KEY: &[u8; 32] = b"zentrion-dummy-master-key-000000"; // Fixed for prototype phase

fn vault_path() -> ZenResult<PathBuf> {
    let mut path = dirs::home_dir().ok_or_else(|| {
        ZenError::new(Area::Cor, 90, "Cannot determine home directory")
    })?;
    path.push(".zentrion");
    fs::create_dir_all(&path).map_err(|e| {
        ZenError::new(Area::Cor, 91, format!("Failed to create .zentrion directory: {}", e))
    })?;
    path.push("vault.enc");
    Ok(path)
}

fn encrypt(data: &[u8]) -> ZenResult<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(MASTER_KEY);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, data).map_err(|e| {
        ZenError::new(Area::Sec, 100, format!("Encryption failed: {}", e))
    })?;
    
    let mut result = Vec::new();
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decrypt(data: &[u8]) -> ZenResult<Vec<u8>> {
    if data.len() < 12 {
        return Err(ZenError::new(Area::Sec, 101, "Data too short, missing nonce"));
    }
    let key = Key::<Aes256Gcm>::from_slice(MASTER_KEY);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&data[0..12]);
    let ciphertext = &data[12..];
    
    cipher.decrypt(nonce, ciphertext).map_err(|e| {
        ZenError::new(Area::Sec, 102, format!("Decryption failed: {}", e))
    })
}

fn load_vault() -> ZenResult<VaultData> {
    let path = vault_path()?;
    if !path.exists() {
        return Ok(VaultData::default());
    }
    
    let mut file = File::open(&path).map_err(|e| {
        ZenError::new(Area::Cor, 92, format!("Failed to open vault file: {}", e))
    })?;
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data).map_err(|e| {
        ZenError::new(Area::Cor, 93, format!("Failed to read vault file: {}", e))
    })?;
    
    let decrypted = decrypt(&encrypted_data)?;
    let vault_data = serde_json::from_slice(&decrypted).map_err(|e| {
        ZenError::new(Area::Cor, 94, format!("Failed to parse vault JSON: {}", e))
    })?;
    Ok(vault_data)
}

fn save_vault(data: &VaultData) -> ZenResult<()> {
    let path = vault_path()?;
    let json_data = serde_json::to_vec(data).map_err(|e| {
        ZenError::new(Area::Cor, 95, format!("Failed to serialize vault JSON: {}", e))
    })?;
    let encrypted = encrypt(&json_data)?;
    
    let mut file = File::create(&path).map_err(|e| {
        ZenError::new(Area::Cor, 96, format!("Failed to create vault file: {}", e))
    })?;
    file.write_all(&encrypted).map_err(|e| {
        ZenError::new(Area::Cor, 97, format!("Failed to write vault file: {}", e))
    })?;
    Ok(())
}

/// Set a secret in the encrypted vault
pub fn set_secret(key: &str, value: &str) -> ZenResult<()> {
    let mut vault = load_vault()?;
    vault.secrets.insert(key.to_string(), value.to_string());
    save_vault(&vault)
}

/// Get a secret from the encrypted vault
pub fn get_secret(key: &str) -> ZenResult<Option<String>> {
    let vault = load_vault()?;
    Ok(vault.secrets.get(key).cloned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get_secret() {
        let temp_dir = std::env::temp_dir().join(format!("zentrion_test_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        std::env::set_var("HOME", temp_dir.clone());
        
        // Initial state
        assert_eq!(get_secret("test_key").unwrap(), None);
        
        // Set secret
        set_secret("test_key", "super_secret_value").unwrap();
        
        // Get secret
        assert_eq!(get_secret("test_key").unwrap(), Some("super_secret_value".to_string()));
        
        // Update secret
        set_secret("test_key", "new_value").unwrap();
        assert_eq!(get_secret("test_key").unwrap(), Some("new_value".to_string()));
        
        // Multiple secrets
        set_secret("another_key", "another_value").unwrap();
        assert_eq!(get_secret("test_key").unwrap(), Some("new_value".to_string()));
        assert_eq!(get_secret("another_key").unwrap(), Some("another_value".to_string()));
        
        std::fs::remove_dir_all(&temp_dir).unwrap_or(());
    }
}

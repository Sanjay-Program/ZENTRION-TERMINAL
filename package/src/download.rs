use anyhow::{Context, Result};
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;

pub async fn download_tool(url: &str, destination: &Path) -> Result<()> {
    let client = Client::new();
    let response = client.get(url).send().await?.error_for_status()?;
    let bytes = response.bytes().await?;

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).await?;
    }

    let mut file = File::create(destination).await?;
    file.write_all(&bytes).await?;

    Ok(())
}

pub async fn verify_checksum(filepath: &Path, expected_sha256: &str) -> Result<bool> {
    let bytes = fs::read(filepath)
        .await
        .context("Failed to read file for checksum verification")?;

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let result = hasher.finalize();

    let actual_hex = hex::encode(result);
    Ok(actual_hex.eq_ignore_ascii_case(expected_sha256))
}

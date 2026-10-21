//! Checksum verification.
//!
//! SHA-256 and SHA-512 are both implemented with a streaming hasher, so
//! artifacts of any size are verified in constant memory.

use sha2::{Digest, Sha256, Sha512};
use std::io::Read;
use z_core::error::{Area, ZenError, ZenResult};

pub use z_audit::sha256_hex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
}

impl HashAlgorithm {
    pub fn prefix(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha512 => "sha512",
        }
    }
}

/// A parsed "algo:hexdigest" checksum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksum {
    pub algorithm: HashAlgorithm,
    pub hex: String,
}

impl Checksum {
    /// Parse `sha256:<64 hex>` (the canonical form). Also accepts a bare
    /// 64-character hex digest, which is interpreted as SHA-256.
    pub fn parse(s: &str) -> ZenResult<Checksum> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("sha256:") {
            let hex = validate_hex(rest, 64, "sha256")?;
            return Ok(Checksum {
                algorithm: HashAlgorithm::Sha256,
                hex,
            });
        }
        if let Some(rest) = s.strip_prefix("sha512:") {
            let hex = validate_hex(rest, 128, "sha512")?;
            return Ok(Checksum {
                algorithm: HashAlgorithm::Sha512,
                hex,
            });
        }
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(Checksum {
                algorithm: HashAlgorithm::Sha256,
                hex: s.to_ascii_lowercase(),
            });
        }
        Err(ZenError::new(
            Area::Sec,
            6000,
            "checksum must be 'sha256:<64 hex>' or a bare 64-character hex digest",
        ))
    }

    pub fn to_string_canonical(&self) -> String {
        format!("{}:{}", self.algorithm.prefix(), self.hex)
    }
}

fn validate_hex(s: &str, len: usize, algo: &str) -> ZenResult<String> {
    if s.len() != len || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ZenError::new(
            Area::Sec,
            6001,
            format!("{algo} digest must be {len} hexadecimal characters"),
        ));
    }
    Ok(s.to_ascii_lowercase())
}

/// Compute the checksum of a byte slice.
pub fn of_bytes(algorithm: HashAlgorithm, data: &[u8]) -> String {
    match algorithm {
        HashAlgorithm::Sha256 => hex::encode(Sha256::digest(data)),
        HashAlgorithm::Sha512 => hex::encode(Sha512::digest(data)),
    }
}

/// Hash a file, streaming so large artifacts do not have to fit in memory.
pub fn of_file(algorithm: HashAlgorithm, path: &std::path::Path) -> ZenResult<String> {
    let mut f = std::fs::File::open(path).map_err(|e| {
        ZenError::new(
            Area::Fs,
            6002,
            format!("cannot open {}: {e}", path.display()),
        )
    })?;
    let mut buf = [0u8; 64 * 1024];
    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            loop {
                let n = f.read(&mut buf).map_err(|e| {
                    ZenError::new(
                        Area::Fs,
                        6002,
                        format!("cannot read {}: {e}", path.display()),
                    )
                })?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            loop {
                let n = f.read(&mut buf).map_err(|e| {
                    ZenError::new(
                        Area::Fs,
                        6002,
                        format!("cannot read {}: {e}", path.display()),
                    )
                })?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
    }
}

/// Verify bytes against an expected checksum.
pub fn verify_bytes(expected: &Checksum, data: &[u8]) -> ZenResult<()> {
    let actual = of_bytes(expected.algorithm, data);
    if actual != expected.hex {
        return Err(ZenError::new(
            Area::Sec,
            6004,
            format!(
                "checksum mismatch: expected {}, got {}",
                expected.hex, actual
            ),
        )
        .with_remediation("The artifact does not match its manifest. It has been quarantined."));
    }
    Ok(())
}

/// Verify a file against an expected checksum.
pub fn verify_file(expected: &Checksum, path: &std::path::Path) -> ZenResult<()> {
    // `of_file` streams, so no artifact-size cap is needed.
    std::fs::metadata(path).map_err(|e| {
        ZenError::new(
            Area::Fs,
            6005,
            format!("cannot stat {}: {e}", path.display()),
        )
    })?;
    let actual = of_file(expected.algorithm, path)?;
    if actual != expected.hex {
        return Err(ZenError::new(
            Area::Sec,
            6007,
            format!(
                "checksum mismatch for {}: expected {}, got {}",
                path.display(),
                expected.hex,
                actual
            ),
        )
        .with_remediation("The artifact does not match its manifest. It has been quarantined."));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_form() {
        let c = Checksum::parse(&format!("sha256:{}", "a".repeat(64))).unwrap();
        assert_eq!(c.algorithm, HashAlgorithm::Sha256);
        assert_eq!(
            c.to_string_canonical(),
            format!("sha256:{}", "a".repeat(64))
        );
    }

    #[test]
    fn parses_bare_hex_as_sha256() {
        let c = Checksum::parse(&"b".repeat(64)).unwrap();
        assert_eq!(c.algorithm, HashAlgorithm::Sha256);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(Checksum::parse("sha256:abc").is_err());
        assert!(Checksum::parse(&"a".repeat(63)).is_err());
    }

    #[test]
    fn rejects_non_hex() {
        assert!(Checksum::parse(&format!("sha256:{}", "z".repeat(64))).is_err());
    }

    #[test]
    fn rejects_unknown_algorithm_prefix() {
        assert!(Checksum::parse(&format!("md5:{}", "a".repeat(32))).is_err());
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn verify_bytes_detects_tamper() {
        let good = Checksum::parse(&format!("sha256:{}", sha256_hex(b"payload"))).unwrap();
        assert!(verify_bytes(&good, b"payload").is_ok());
        assert!(verify_bytes(&good, b"tampered").is_err());
    }

    #[test]
    fn verify_file_detects_tamper() {
        let d = z_native::fs::private_temp_dir("zen-ck").unwrap();
        let f = d.join("blob");
        std::fs::write(&f, b"original").unwrap();
        let good = Checksum::parse(&format!("sha256:{}", sha256_hex(b"original"))).unwrap();
        assert!(verify_file(&good, &f).is_ok());
        std::fs::write(&f, b"modified").unwrap();
        assert!(verify_file(&good, &f).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn sha512_matches_known_vector() {
        assert_eq!(
            of_bytes(HashAlgorithm::Sha512, b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn sha512_verifies_and_rejects_tamper() {
        let d = z_native::fs::private_temp_dir("zen-ck512").unwrap();
        let f = d.join("blob");
        std::fs::write(&f, b"x").unwrap();
        let digest = of_file(HashAlgorithm::Sha512, &f).unwrap();
        let c = Checksum {
            algorithm: HashAlgorithm::Sha512,
            hex: digest,
        };
        assert!(verify_file(&c, &f).is_ok());
        std::fs::write(&f, b"y").unwrap();
        assert!(verify_file(&c, &f).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn streaming_hash_matches_one_shot_for_large_files() {
        let d = z_native::fs::private_temp_dir("zen-ckstream").unwrap();
        let f = d.join("blob");
        let data: Vec<u8> = (0..(1024 * 1024)).map(|i| (i % 251) as u8).collect();
        std::fs::write(&f, &data).unwrap();
        assert_eq!(
            of_file(HashAlgorithm::Sha256, &f).unwrap(),
            of_bytes(HashAlgorithm::Sha256, &data)
        );
        assert_eq!(
            of_file(HashAlgorithm::Sha512, &f).unwrap(),
            of_bytes(HashAlgorithm::Sha512, &data)
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}

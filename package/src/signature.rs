//! Signature verification interface.
//!
//! Phase 2 deliberately ships **no** signature verifier. Adding one means
//! choosing and vendoring a signature scheme; inventing a "verified" result
//! without a real implementation would be the worst possible outcome for a
//! security tool.
//!
//! Every outcome is explicit, and `MISSING`/`UNSUPPORTED` are never treated as
//! success by callers (see `is_trusted`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureOutcome {
    /// A signature was present and verified against a trusted key.
    Supported { key_id: String, algorithm: String },
    /// No verifier is compiled into this build.
    Unsupported { reason: String },
    /// A signature was present but did not verify.
    Invalid { reason: String },
    /// No signature was supplied.
    Missing,
    /// The signing key is explicitly revoked.
    Revoked { key_id: String },
}

impl SignatureOutcome {
    /// Whether this outcome may be treated as a positive trust signal.
    /// Only a genuine `Supported` counts — everything else is not trust.
    pub fn is_trusted(&self) -> bool {
        matches!(self, SignatureOutcome::Supported { .. })
    }

    /// Severity for UI: whether this should block an install.
    pub fn is_blocking(&self) -> bool {
        matches!(
            self,
            SignatureOutcome::Invalid { .. } | SignatureOutcome::Revoked { .. }
        )
    }

    pub fn summary(&self) -> String {
        match self {
            SignatureOutcome::Supported { key_id, algorithm } => {
                format!("signature verified ({algorithm}, key {key_id})")
            }
            SignatureOutcome::Unsupported { reason } => format!("signature not checked: {reason}"),
            SignatureOutcome::Invalid { reason } => format!("signature INVALID: {reason}"),
            SignatureOutcome::Missing => "no signature supplied".to_string(),
            SignatureOutcome::Revoked { key_id } => format!("signing key {key_id} is REVOKED"),
        }
    }
}

pub trait SignatureVerifier {
    /// Verify `signature` over `payload` using `key_id`.
    fn verify(&self, key_id: &str, payload: &[u8], signature: &[u8]) -> SignatureOutcome;
    /// Whether this verifier is implemented at all.
    fn available(&self) -> bool;
}

/// The Phase 2 verifier: honest about not being implemented.
pub struct UnimplementedVerifier;

impl SignatureVerifier for UnimplementedVerifier {
    fn verify(&self, _key_id: &str, _payload: &[u8], _signature: &[u8]) -> SignatureOutcome {
        SignatureOutcome::Unsupported {
            reason: "no signature backend is compiled in Phase 2".to_string(),
        }
    }
    fn available(&self) -> bool {
        false
    }
}

pub fn verifier() -> Box<dyn SignatureVerifier + Send + Sync> {
    Box::new(UnimplementedVerifier)
}

/// Decide whether a signature outcome satisfies a required trust level.
pub fn satisfies(required: bool, outcome: &SignatureOutcome) -> Result<(), String> {
    if outcome.is_blocking() {
        return Err(outcome.summary());
    }
    if required && !outcome.is_trusted() {
        return Err(format!(
            "this artifact requires a verified signature, but {}",
            outcome.summary()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_is_not_trust() {
        let v = UnimplementedVerifier;
        let o = v.verify("key", b"payload", b"sig");
        assert!(
            !o.is_trusted(),
            "an unimplemented verifier must never report trust"
        );
        assert!(matches!(o, SignatureOutcome::Unsupported { .. }));
    }

    #[test]
    fn verifier_reports_unavailable() {
        assert!(!verifier().available());
    }

    #[test]
    fn missing_is_not_trust() {
        assert!(!SignatureOutcome::Missing.is_trusted());
    }

    #[test]
    fn invalid_and_revoked_block() {
        assert!(SignatureOutcome::Invalid { reason: "x".into() }.is_blocking());
        assert!(SignatureOutcome::Revoked { key_id: "k".into() }.is_blocking());
        let r = satisfies(
            false,
            &SignatureOutcome::Invalid {
                reason: "bad".into(),
            },
        );
        assert!(r.is_err());
    }

    #[test]
    fn require_signature_rejects_unsupported_and_missing() {
        let unsup = SignatureOutcome::Unsupported {
            reason: "none".into(),
        };
        assert!(satisfies(true, &unsup).is_err());
        assert!(satisfies(true, &SignatureOutcome::Missing).is_err());
        // But optional signature accepts them.
        assert!(satisfies(false, &unsup).is_ok());
        assert!(satisfies(false, &SignatureOutcome::Missing).is_ok());
    }

    #[test]
    fn supported_satisfies_requirement() {
        let ok = SignatureOutcome::Supported {
            key_id: "k".into(),
            algorithm: "ed25519".into(),
        };
        assert!(satisfies(true, &ok).is_ok());
    }
}

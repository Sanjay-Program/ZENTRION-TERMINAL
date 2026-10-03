//! z-package — artifact handling: download, checksum, signature, extraction.

pub mod checksum;
pub mod extract;
pub mod signature;

pub use checksum::{Checksum, HashAlgorithm};
pub use extract::{extract_archive, ArchiveFormat, ExtractionLimits, ExtractionReport};
pub use signature::{SignatureOutcome, SignatureVerifier};

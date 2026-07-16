#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod error;
mod integrity;
mod integrity_path;
mod recover;

pub use error::EwfForensicError;
pub use integrity::{
    AnalysisProgress, ComputedHashes, EwfHeaderMetadata, EwfIntegrity, EwfIntegrityAnomaly,
    Severity,
};
pub use integrity_path::EwfIntegrityPath;
pub use recover::{EwfRecover, RecoveryReport};

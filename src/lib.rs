mod error;
mod integrity;
mod repair;

pub use error::EwfForensicError;
pub use integrity::{EwfIntegrity, EwfIntegrityAnomaly, Severity};
pub use repair::{
    CannotRepair, CanonicalisationReport, EwfDescriptorCanonicaliser, Repaired,
};
#[allow(deprecated)]
pub use repair::{EwfRepair, RepairReport};

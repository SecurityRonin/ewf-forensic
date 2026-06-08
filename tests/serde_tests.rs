#![allow(clippy::unwrap_used, clippy::expect_used)]

//! RED phase — serde Serialize/Deserialize for public types.
//!
//! Requires the `serde` feature flag.  Run with:
//!   cargo test --test serde_tests --features serde
//!
//! Currently RED: EwfIntegrityAnomaly, Severity, ComputedHashes, and
//! AnalysisProgress do not implement Serialize/Deserialize.

#[cfg(not(feature = "serde"))]
compile_error!("serde_tests must be compiled with --features serde");

use ewf_forensic::{AnalysisProgress, ComputedHashes, EwfIntegrityAnomaly, Severity};
use serde_json;

/// Severity variants must serialize to lowercase strings.
#[test]
fn severity_serializes_to_lowercase_string() {
    assert_eq!(serde_json::to_string(&Severity::Info).unwrap(), "\"Info\"");
    assert_eq!(serde_json::to_string(&Severity::Medium).unwrap(), "\"Medium\"");
    assert_eq!(serde_json::to_string(&Severity::High).unwrap(), "\"High\"");
    assert_eq!(serde_json::to_string(&Severity::Critical).unwrap(), "\"Critical\"");
}

/// EwfIntegrityAnomaly unit variants must round-trip through JSON.
#[test]
fn anomaly_unit_variant_round_trip() {
    let variants = [
        EwfIntegrityAnomaly::InvalidSignature,
        EwfIntegrityAnomaly::HashSectionMissing,
        EwfIntegrityAnomaly::Ewf2HashSectionMissing,
        EwfIntegrityAnomaly::Ewf2MediaInfoMissing,
        EwfIntegrityAnomaly::Ewf2MediaInfoParseFailed,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).expect("serialize");
        let back: EwfIntegrityAnomaly = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, &back, "round-trip failed for {json}");
    }
}

/// EwfIntegrityAnomaly struct variants must round-trip.
#[test]
fn anomaly_struct_variant_round_trip() {
    let v = EwfIntegrityAnomaly::HashMismatch {
        computed: [0xAB; 16],
        stored: [0xCD; 16],
    };
    let json = serde_json::to_string(&v).expect("serialize");
    let back: EwfIntegrityAnomaly = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(v, back);
}

/// ComputedHashes must be serializable.
#[test]
fn computed_hashes_serializable() {
    let h = ComputedHashes {
        md5: [0u8; 16],
        sha1: [0u8; 20],
        sha256: [0u8; 32],
    };
    let json = serde_json::to_string(&h).expect("serialize ComputedHashes");
    assert!(json.contains("md5"), "JSON should contain md5 field: {json}");
}

/// AnalysisProgress must be serializable.
#[test]
fn analysis_progress_serializable() {
    let p = AnalysisProgress {
        chunks_done: 5,
        chunks_total: Some(10),
        bytes_done: 12345,
    };
    let json = serde_json::to_string(&p).expect("serialize AnalysisProgress");
    assert!(json.contains("chunks_done"), "JSON should contain chunks_done: {json}");
    assert!(json.contains("bytes_done"), "JSON should contain bytes_done: {json}");
}

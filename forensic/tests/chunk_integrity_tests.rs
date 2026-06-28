#![allow(clippy::unwrap_used, clippy::expect_used)]

//! RED phase — per-chunk Adler-32 detection (ewfverify parity).
//!
//! ewfverify verifies individual chunk checksums in addition to the overall
//! MD5. EWF v1 appends a 4-byte Adler-32 after each chunk's raw (possibly
//! compressed) bytes. A corrupt checksum must surface as `ChunkChecksumMismatch`.
mod builder;

use builder::E01Builder;
use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly};

// ── Corrupt chunk checksum is detected ────────────────────────────────────────

#[test]
fn corrupt_chunk_checksum_detected() {
    let image = E01Builder::new(512 * 64)
        .with_chunk_checksums()
        .with_corrupt_chunk_checksum(0)
        .build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ChunkChecksumMismatch { .. })),
        "corrupt chunk Adler-32 must produce ChunkChecksumMismatch; got: {findings:#?}"
    );
}

// ── Clean image with checksums produces no false positives ────────────────────

#[test]
fn clean_chunk_checksums_no_anomaly() {
    let image = E01Builder::new(512 * 64).with_chunk_checksums().build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ChunkChecksumMismatch { .. })),
        "correct chunk checksums must not produce ChunkChecksumMismatch; got: {findings:#?}"
    );
}

// ── ChunkChecksumMismatch severity is Error ───────────────────────────────────

#[test]
fn chunk_checksum_mismatch_is_error_severity() {
    use ewf_forensic::Severity;
    let image = E01Builder::new(512 * 64)
        .with_chunk_checksums()
        .with_corrupt_chunk_checksum(0)
        .build();
    let findings = EwfIntegrity::new(&image).analyse();
    let a = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::ChunkChecksumMismatch { .. }))
        .expect("ChunkChecksumMismatch must be present on corrupt image");
    assert_eq!(a.severity(), Severity::High);
}

// ── Images without per-chunk checksums (no-checksum builder) are unaffected ──

#[test]
fn no_checksum_image_no_false_positive() {
    let image = E01Builder::new(512 * 64).build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ChunkChecksumMismatch { .. })),
        "image without per-chunk checksums must not produce ChunkChecksumMismatch; got: {findings:#?}"
    );
}

//! RED phase — tests for new capabilities:
//!   1. Multi-segment EWF v1 (from_segments, SegmentOutOfOrder)
//!   2. EWF v2 analysis (Ewf2SectionDataHashMismatch, Ewf2EncryptedSection, Ewf2HashSectionMissing)
//!   3. SHA-1 from digest section (DigestSha1Mismatch)
//!   4. External reference hash (ExternalMd5Mismatch, ExternalSha1Mismatch)
//!
//! All tests in this file fail until the GREEN implementation lands.
mod builder;

use builder::{make_ewf2_clean_segment, make_ewf2_encrypted_segment, make_ewf2_no_hash_segment, make_ewf2_tampered_segment, E01Builder};
use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly, Severity};
use md5::{Digest as _, Md5};
use sha1::{Digest as _, Sha1};

// ── Multi-segment: clean two-segment image ────────────────────────────────────

#[test]
fn two_segment_e01_clean_no_anomalies() {
    // Segment 1 (non-final): 1 chunk of 32 KB zeros
    // Volume says chunk_count=2, sector_count=128 (total image = 2 chunks)
    let chunk_size: usize = 64 * 512; // 32768

    let seg1 = E01Builder::new(chunk_size as u64)
        .with_nonfinal()
        .with_volume_chunk_count(2)
        .with_volume_sector_count(128)
        .build();

    // Combined MD5: MD5 of 2×32 KB of zeros
    let combined_md5: [u8; 16] = Md5::digest(&vec![0u8; chunk_size * 2]).into();

    let seg2 = E01Builder::new(chunk_size as u64)
        .with_segment_number(2)
        .with_omit_volume()
        .with_md5(combined_md5)
        .build();

    let findings = EwfIntegrity::from_segments(&[&seg1, &seg2]).analyse();

    let errors: Vec<_> = findings
        .iter()
        .filter(|a| matches!(a.severity(), Severity::High | Severity::Critical))
        .collect();
    assert!(
        errors.is_empty(),
        "clean two-segment image must produce no Error/Critical anomalies; got: {errors:#?}"
    );
}

// ── Multi-segment: out-of-order segments ─────────────────────────────────────

#[test]
fn segments_out_of_order_detected() {
    let chunk_size: u64 = 64 * 512;

    // Supply segment 2 first, then segment 1 — SegmentOutOfOrder must fire
    let seg2 = E01Builder::new(chunk_size)
        .with_segment_number(2)
        .with_omit_volume()
        .build();
    let seg1 = E01Builder::new(chunk_size).build();

    let findings = EwfIntegrity::from_segments(&[&seg2, &seg1]).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::SegmentOutOfOrder { .. })),
        "expected SegmentOutOfOrder, got: {findings:#?}"
    );
}

// ── Multi-segment: cross-segment hash mismatch ───────────────────────────────

#[test]
fn two_segment_hash_mismatch_detected() {
    let chunk_size: usize = 64 * 512;

    let seg1 = E01Builder::new(chunk_size as u64)
        .with_nonfinal()
        .with_volume_chunk_count(2)
        .with_volume_sector_count(128)
        .build();

    // Wrong hash (not the combined MD5)
    let seg2 = E01Builder::new(chunk_size as u64)
        .with_segment_number(2)
        .with_omit_volume()
        .with_md5([0xBAu8; 16])
        .build();

    let findings = EwfIntegrity::from_segments(&[&seg1, &seg2]).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::HashMismatch { .. })),
        "expected HashMismatch for combined multi-segment data, got: {findings:#?}"
    );
}

// ── EWF v2: clean segment ─────────────────────────────────────────────────────

#[test]
fn ewf2_clean_segment_no_critical_or_error_anomalies() {
    let data = make_ewf2_clean_segment();
    let findings = EwfIntegrity::new(&data).analyse();
    let fatal: Vec<_> = findings
        .iter()
        .filter(|a| matches!(a.severity(), Severity::High | Severity::Critical))
        .collect();
    assert!(
        fatal.is_empty(),
        "clean EWF v2 segment must produce no Error/Critical anomalies; got: {fatal:#?}"
    );
}

// ── EWF v2: section data hash mismatch ───────────────────────────────────────

#[test]
fn ewf2_section_data_hash_mismatch_detected() {
    let data = make_ewf2_tampered_segment();
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2SectionDataHashMismatch { .. })),
        "expected Ewf2SectionDataHashMismatch, got: {findings:#?}"
    );
}

#[test]
fn ewf2_section_data_hash_mismatch_is_error_severity() {
    let data = make_ewf2_tampered_segment();
    let findings = EwfIntegrity::new(&data).analyse();
    if let Some(a) = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::Ewf2SectionDataHashMismatch { .. }))
    {
        assert_eq!(a.severity(), Severity::High);
    }
}

// ── EWF v2: encrypted section ────────────────────────────────────────────────

#[test]
fn ewf2_encrypted_section_detected() {
    let data = make_ewf2_encrypted_segment();
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2EncryptedSection { .. })),
        "expected Ewf2EncryptedSection, got: {findings:#?}"
    );
}

#[test]
fn ewf2_encrypted_section_is_warning_severity() {
    let data = make_ewf2_encrypted_segment();
    let findings = EwfIntegrity::new(&data).analyse();
    if let Some(a) = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::Ewf2EncryptedSection { .. }))
    {
        assert_eq!(a.severity(), Severity::Medium);
    }
}

// ── EWF v2: hash section missing ─────────────────────────────────────────────

#[test]
fn ewf2_hash_section_missing_detected() {
    let data = make_ewf2_no_hash_segment();
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2HashSectionMissing)),
        "expected Ewf2HashSectionMissing, got: {findings:#?}"
    );
}

// ── SHA-1 from digest section ─────────────────────────────────────────────────

#[test]
fn digest_sha1_mismatch_detected() {
    let bad_sha1 = [0xBAu8; 20];
    let image = E01Builder::new(512 * 64).with_digest_sha1(bad_sha1).build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::DigestSha1Mismatch { .. })),
        "expected DigestSha1Mismatch for wrong SHA-1, got: {findings:#?}"
    );
}

#[test]
fn digest_sha1_correct_no_anomaly() {
    // SHA-1 of all-zero sector data (32 KB)
    let sectors_data = vec![0u8; 64 * 512];
    let correct_sha1: [u8; 20] = Sha1::digest(&sectors_data).into();
    let image = E01Builder::new(512 * 64).with_digest_sha1(correct_sha1).build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::DigestSha1Mismatch { .. })),
        "correct SHA-1 must not produce DigestSha1Mismatch; got: {findings:#?}"
    );
}

#[test]
fn digest_sha1_mismatch_is_error_severity() {
    let bad_sha1 = [0xBAu8; 20];
    let image = E01Builder::new(512 * 64).with_digest_sha1(bad_sha1).build();
    let findings = EwfIntegrity::new(&image).analyse();
    if let Some(a) = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::DigestSha1Mismatch { .. }))
    {
        assert_eq!(a.severity(), Severity::High);
    }
}

// ── External MD5 reference ────────────────────────────────────────────────────

#[test]
fn external_md5_correct_no_anomaly() {
    let sectors_data = vec![0u8; 64 * 512];
    let correct_md5: [u8; 16] = Md5::digest(&sectors_data).into();
    let image = E01Builder::new(512 * 64).build();
    let findings = EwfIntegrity::new(&image)
        .with_expected_md5(correct_md5)
        .analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalMd5Mismatch { .. })),
        "correct external MD5 must not produce ExternalMd5Mismatch; got: {findings:#?}"
    );
}

#[test]
fn external_md5_mismatch_detected() {
    let image = E01Builder::new(512 * 64).build();
    let findings = EwfIntegrity::new(&image)
        .with_expected_md5([0xFFu8; 16])
        .analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalMd5Mismatch { .. })),
        "expected ExternalMd5Mismatch, got: {findings:#?}"
    );
}

#[test]
fn external_md5_mismatch_is_critical() {
    let image = E01Builder::new(512 * 64).build();
    let findings = EwfIntegrity::new(&image)
        .with_expected_md5([0xFFu8; 16])
        .analyse();
    if let Some(a) = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::ExternalMd5Mismatch { .. }))
    {
        assert_eq!(a.severity(), Severity::Critical);
    }
}

// ── External SHA-1 reference ──────────────────────────────────────────────────

#[test]
fn external_sha1_mismatch_detected() {
    let image = E01Builder::new(512 * 64).build();
    let findings = EwfIntegrity::new(&image)
        .with_expected_sha1([0xFFu8; 20])
        .analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalSha1Mismatch { .. })),
        "expected ExternalSha1Mismatch, got: {findings:#?}"
    );
}

#[test]
fn external_sha1_correct_no_anomaly() {
    let sectors_data = vec![0u8; 64 * 512];
    let correct_sha1: [u8; 20] = Sha1::digest(&sectors_data).into();
    let image = E01Builder::new(512 * 64).build();
    let findings = EwfIntegrity::new(&image)
        .with_expected_sha1(correct_sha1)
        .analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalSha1Mismatch { .. })),
        "correct external SHA-1 must not produce ExternalSha1Mismatch; got: {findings:#?}"
    );
}

#[test]
fn external_sha1_mismatch_is_critical() {
    let image = E01Builder::new(512 * 64).build();
    let findings = EwfIntegrity::new(&image)
        .with_expected_sha1([0xFFu8; 20])
        .analyse();
    if let Some(a) = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::ExternalSha1Mismatch { .. }))
    {
        assert_eq!(a.severity(), Severity::Critical);
    }
}

// ── SegmentOutOfOrder severity ────────────────────────────────────────────────

#[test]
fn segment_out_of_order_is_error_severity() {
    let anomaly = EwfIntegrityAnomaly::SegmentOutOfOrder {
        segment_number: 2,
        expected: 1,
    };
    assert_eq!(anomaly.severity(), Severity::High);
}

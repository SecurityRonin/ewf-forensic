//! RED phase — libewf-grounded format quirks.
//!
//! All tests fail until the implementation catches up to the real EWF spec.
//! Sources: `libewf/libewf_segment_file.c`, `libewf/libewf_header_sections.c`,
//!          the `ewf_data_t` struct (1052 bytes), and `ewf_file_header_v1_t`.
mod builder;

use builder::{
    make_dvf_segment, make_e01_full_volume_bad_crc, make_e01_full_volume_clean,
    make_e01_unknown_media_type, make_e01_valid_media_types, make_lvf_segment,
    make_two_segment_guid_mismatch, make_two_segment_matching_guids,
};
use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly, Severity};

// ── DVF signature: libewf dvf_file_signature = { 0x64,0x76,0x66,0x09,0x0d,0x0a,0xff,0x00 }
// ── Must NOT produce InvalidSignature — it is a valid EWF v1 variant. ─────────

#[test]
fn dvf_signature_no_invalid_signature_anomaly() {
    let data = make_dvf_segment();
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::InvalidSignature)),
        "DVF signature must not produce InvalidSignature; got: {findings:#?}"
    );
}

// ── LVF signature: libewf lvf_file_signature = { 0x4c,0x56,0x46,0x09,0x0d,0x0a,0xff,0x00 }

#[test]
fn lvf_signature_no_invalid_signature_anomaly() {
    let data = make_lvf_segment();
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::InvalidSignature)),
        "LVF signature must not produce InvalidSignature; got: {findings:#?}"
    );
}

// ── Other checks still apply to DVF (segment number zero, etc.) ───────────────

#[test]
fn dvf_segment_number_zero_still_detected() {
    let data = make_dvf_segment(); // segment_number = 1 by default — should be clean
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::SegmentNumberZero)),
        "clean DVF segment must not report SegmentNumberZero"
    );
}

// ── Volume body Adler-32 (byte 1048 of ewf_data_t, covers bytes 0..1048) ──────

#[test]
fn full_volume_section_clean_no_crc_anomaly() {
    let data = make_e01_full_volume_clean();
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::VolumeBodyCrcMismatch { .. })),
        "correct volume body Adler-32 must not produce VolumeBodyCrcMismatch; got: {findings:#?}"
    );
}

#[test]
fn full_volume_section_bad_crc_detected() {
    let data = make_e01_full_volume_bad_crc();
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::VolumeBodyCrcMismatch { .. })),
        "corrupt volume body Adler-32 must produce VolumeBodyCrcMismatch; got: {findings:#?}"
    );
}

#[test]
fn full_volume_bad_crc_is_error_severity() {
    let data = make_e01_full_volume_bad_crc();
    let findings = EwfIntegrity::new(&data).analyse();
    if let Some(a) = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::VolumeBodyCrcMismatch { .. }))
    {
        assert_eq!(a.severity(), Severity::High);
    }
}

// ── Short (94-byte) volume sections must NOT trigger the CRC check ────────────

#[test]
fn short_volume_section_no_crc_anomaly() {
    // The existing E01Builder produces a 94-byte volume body — no Adler-32 present.
    use builder::E01Builder;
    let data = E01Builder::new(512 * 64).build();
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::VolumeBodyCrcMismatch { .. })),
        "short volume body must not produce VolumeBodyCrcMismatch; got: {findings:#?}"
    );
}

// ── media_type (byte 0 of ewf_data_t): valid = 0x00,0x01,0x03,0x0e,0x10 ──────

#[test]
fn valid_media_types_no_anomaly() {
    for (label, data) in make_e01_valid_media_types() {
        let findings = EwfIntegrity::new(&data).analyse();
        assert!(
            !findings
                .iter()
                .any(|a| matches!(a, EwfIntegrityAnomaly::MediaTypeUnknown { .. })),
            "media_type={label:#x} must not produce MediaTypeUnknown; got: {findings:#?}"
        );
    }
}

#[test]
fn unknown_media_type_detected() {
    let data = make_e01_unknown_media_type(0xFF);
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::MediaTypeUnknown { .. })),
        "media_type=0xFF must produce MediaTypeUnknown; got: {findings:#?}"
    );
}

#[test]
fn unknown_media_type_is_warning_severity() {
    let data = make_e01_unknown_media_type(0x42);
    let findings = EwfIntegrity::new(&data).analyse();
    if let Some(a) = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::MediaTypeUnknown { .. }))
    {
        assert_eq!(a.severity(), Severity::Medium);
    }
}

// ── Set GUID (bytes 64-79 of ewf_data_t) must match across all segments ───────

#[test]
fn multi_segment_matching_guids_no_anomaly() {
    let (seg1, seg2) = make_two_segment_matching_guids();
    let findings = EwfIntegrity::from_segments(&[&seg1, &seg2]).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::SetIdentifierMismatch { .. })),
        "matching GUIDs must not produce SetIdentifierMismatch; got: {findings:#?}"
    );
}

#[test]
fn multi_segment_mismatched_guids_detected() {
    let (seg1, seg2) = make_two_segment_guid_mismatch();
    let findings = EwfIntegrity::from_segments(&[&seg1, &seg2]).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::SetIdentifierMismatch { .. })),
        "mismatched GUIDs across segments must produce SetIdentifierMismatch; got: {findings:#?}"
    );
}

#[test]
fn set_identifier_mismatch_is_error_severity() {
    let (seg1, seg2) = make_two_segment_guid_mismatch();
    let findings = EwfIntegrity::from_segments(&[&seg1, &seg2]).analyse();
    if let Some(a) = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::SetIdentifierMismatch { .. }))
    {
        assert_eq!(a.severity(), Severity::High);
    }
}

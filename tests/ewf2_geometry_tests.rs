//! RED phase — EWF v2 geometry validation.
//!
//! Tests fail until EWF v2 media-information parsing is added to the analyser.
mod builder;

use builder::make_ewf2_clean_segment_with_media_info;
use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly, Severity};

// ── Clean EWF v2 with valid media info: no geometry anomalies ─────────────────

#[test]
fn ewf2_valid_geometry_no_anomalies() {
    let data = make_ewf2_clean_segment_with_media_info(512, 64, 128);
    let findings = EwfIntegrity::new(&data).analyse();
    let geo_errors: Vec<_> = findings
        .iter()
        .filter(|a| {
            matches!(a, EwfIntegrityAnomaly::Ewf2ChunkTableChecksumMismatch { .. })
        })
        .collect();
    assert!(
        geo_errors.is_empty(),
        "valid geometry must produce no geometry anomalies; got: {geo_errors:#?}"
    );
}

// ── Media info section missing → Ewf2MediaInfoMissing ────────────────────────

#[test]
fn ewf2_media_info_missing_detected() {
    // The existing make_ewf2_clean_segment() has no media info section.
    use builder::make_ewf2_clean_segment;
    let data = make_ewf2_clean_segment();
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2MediaInfoMissing)),
        "expected Ewf2MediaInfoMissing when media info section absent; got: {findings:#?}"
    );
}

#[test]
fn ewf2_media_info_missing_is_warning() {
    use builder::make_ewf2_clean_segment;
    let data = make_ewf2_clean_segment();
    let findings = EwfIntegrity::new(&data).analyse();
    if let Some(a) = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::Ewf2MediaInfoMissing))
    {
        assert_eq!(a.severity(), Severity::Medium);
    }
}

// ── 4096-byte sectors: no geometry anomalies ─────────────────────────────────

#[test]
fn ewf2_4096_bytes_per_sector_no_geometry_error() {
    let data = make_ewf2_clean_segment_with_media_info(4096, 64, 128);
    let findings = EwfIntegrity::new(&data).analyse();
    let geo: Vec<_> = findings
        .iter()
        .filter(|a| {
            matches!(a, EwfIntegrityAnomaly::Ewf2ChunkTableChecksumMismatch { .. })
        })
        .collect();
    assert!(
        geo.is_empty(),
        "4096 bytes/sector must not produce geometry anomalies; got: {geo:#?}"
    );
}

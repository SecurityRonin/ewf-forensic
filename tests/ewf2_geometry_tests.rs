//! RED phase — EWF v2 geometry validation.
//!
//! Tests fail until EWF v2 media-information parsing is added to the analyser.
mod builder;

use builder::{make_ewf2_clean_segment_with_media_info, make_ewf2_segment_bad_geometry};
use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly, Severity};

// ── Clean EWF v2 with valid media info: no geometry anomalies ─────────────────

#[test]
fn ewf2_valid_geometry_no_anomalies() {
    let data = make_ewf2_clean_segment_with_media_info(512, 64, 128);
    let findings = EwfIntegrity::new(&data).analyse();
    let geo_errors: Vec<_> = findings
        .iter()
        .filter(|a| {
            matches!(
                a,
                EwfIntegrityAnomaly::Ewf2BytesPerSectorInvalid { .. }
                    | EwfIntegrityAnomaly::Ewf2ChunkSizeInvalid { .. }
                    | EwfIntegrityAnomaly::Ewf2SectorCountZero
            )
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
        assert_eq!(a.severity(), Severity::Warning);
    }
}

// ── Invalid bytes_per_sector → Ewf2BytesPerSectorInvalid ─────────────────────

#[test]
fn ewf2_bad_bytes_per_sector_detected() {
    let data = make_ewf2_segment_bad_geometry(777, 64, 64);
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2BytesPerSectorInvalid { .. })),
        "expected Ewf2BytesPerSectorInvalid for bps=777; got: {findings:#?}"
    );
}

#[test]
fn ewf2_bad_bytes_per_sector_is_error() {
    let data = make_ewf2_segment_bad_geometry(777, 64, 64);
    let findings = EwfIntegrity::new(&data).analyse();
    if let Some(a) = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::Ewf2BytesPerSectorInvalid { .. }))
    {
        assert_eq!(a.severity(), Severity::Error);
    }
}

// ── sectors_per_chunk not a power-of-two → Ewf2ChunkSizeInvalid ──────────────

#[test]
fn ewf2_bad_chunk_size_detected() {
    let data = make_ewf2_segment_bad_geometry(512, 33, 64); // 33 is not power-of-two
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2ChunkSizeInvalid { .. })),
        "expected Ewf2ChunkSizeInvalid for spc=33; got: {findings:#?}"
    );
}

// ── sector_count = 0 → Ewf2SectorCountZero ───────────────────────────────────

#[test]
fn ewf2_zero_sector_count_detected() {
    let data = make_ewf2_segment_bad_geometry(512, 64, 0);
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2SectorCountZero)),
        "expected Ewf2SectorCountZero for sector_count=0; got: {findings:#?}"
    );
}

#[test]
fn ewf2_zero_sector_count_is_error() {
    let data = make_ewf2_segment_bad_geometry(512, 64, 0);
    let findings = EwfIntegrity::new(&data).analyse();
    if let Some(a) = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::Ewf2SectorCountZero))
    {
        assert_eq!(a.severity(), Severity::Error);
    }
}

// ── 4096-byte sectors are valid ───────────────────────────────────────────────

#[test]
fn ewf2_4096_bytes_per_sector_is_valid() {
    let data = make_ewf2_clean_segment_with_media_info(4096, 64, 128);
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2BytesPerSectorInvalid { .. })),
        "4096 bytes/sector must not produce Ewf2BytesPerSectorInvalid; got: {findings:#?}"
    );
}

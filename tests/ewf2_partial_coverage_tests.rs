use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly};

const EVF2_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];
const EVF1_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];

fn minimal_ewf2() -> Vec<u8> {
    // 32-byte EWF v2 header + 64-byte DONE descriptor (no sector data).
    let mut data = vec![0u8; 32 + 64];
    data[0..8].copy_from_slice(&EVF2_SIGNATURE);
    data[12..16].copy_from_slice(&1u32.to_le_bytes()); // segment_number = 1
    data[32..36].copy_from_slice(&0x0Fu32.to_le_bytes()); // type = DONE
    data
}

/// Minimal EWF v2 without a chunk table must not emit spurious chunk anomalies.
#[test]
fn ewf2_no_chunk_table_no_spurious_chunk_anomalies() {
    let image = minimal_ewf2();
    let findings = EwfIntegrity::new(&image).analyse();
    let chunk_anomalies: Vec<_> = findings
        .iter()
        .filter(|a| {
            matches!(
                a,
                EwfIntegrityAnomaly::ChunkChecksumMismatch { .. }
                    | EwfIntegrityAnomaly::ChunkDecompressionError { .. }
                    | EwfIntegrityAnomaly::HashMismatch { .. }
            )
        })
        .collect();
    assert!(
        chunk_anomalies.is_empty(),
        "EWF v2 without a chunk table must not emit chunk anomalies; got: {chunk_anomalies:#?}"
    );
}

/// EWF v1 analysis must never produce EWF v2 specific anomalies.
#[test]
fn ewf1_analysis_produces_no_ewf2_anomalies() {
    let mut data = vec![0u8; 13];
    data[0..8].copy_from_slice(&EVF1_SIGNATURE);
    let findings = EwfIntegrity::new(&data).analyse();
    let ewf2_anomalies: Vec<_> = findings
        .iter()
        .filter(|a| {
            matches!(
                a,
                EwfIntegrityAnomaly::Ewf2SectionDataHashMismatch { .. }
                    | EwfIntegrityAnomaly::Ewf2EncryptedSection { .. }
                    | EwfIntegrityAnomaly::Ewf2HashSectionMissing
                    | EwfIntegrityAnomaly::Ewf2MediaInfoMissing
            )
        })
        .collect();
    assert!(
        ewf2_anomalies.is_empty(),
        "EWF v1 analysis must not emit EWF v2 anomalies; got: {ewf2_anomalies:#?}"
    );
}

/// A minimal EWF v2 image with no hash section must emit Ewf2HashSectionMissing.
#[test]
fn ewf2_no_hash_section_emits_hash_section_missing() {
    let image = minimal_ewf2();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2HashSectionMissing)),
        "minimal EWF v2 without hash section must emit Ewf2HashSectionMissing; got: {findings:#?}"
    );
}

/// A minimal EWF v2 image with no media info section must emit Ewf2MediaInfoMissing.
#[test]
fn ewf2_no_media_info_emits_media_info_missing() {
    let image = minimal_ewf2();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2MediaInfoMissing)),
        "minimal EWF v2 without media info must emit Ewf2MediaInfoMissing; got: {findings:#?}"
    );
}

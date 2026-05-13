mod builder;

use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly, Severity};

use builder::{E01Builder, EVF_SIGNATURE};

fn clean_image() -> Vec<u8> {
    E01Builder::new(512 * 64).build() // one chunk of 32 KB
}

// ── Phase 1: File Header ──────────────────────────────────────────────────────

// Test 1: baseline — a well-formed image produces no findings
#[test]
fn clean_e01_has_no_anomalies() {
    let image = clean_image();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings.is_empty(),
        "clean image should produce zero findings, got: {findings:#?}"
    );
}

// Test 2: wrong signature byte → InvalidSignature
#[test]
fn invalid_signature_detected() {
    let mut sig = EVF_SIGNATURE;
    sig[0] = 0x00;
    let image = E01Builder::new(512 * 64).with_signature(sig).build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::InvalidSignature)),
        "expected InvalidSignature, got: {findings:#?}"
    );
}

// Test 3: segment number zero is invalid
#[test]
fn segment_number_zero_detected() {
    let image = E01Builder::new(512 * 64).with_segment_number(0).build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::SegmentNumberZero)),
        "expected SegmentNumberZero, got: {findings:#?}"
    );
}

// ── Phase 2: Section Descriptor Integrity ────────────────────────────────────

// Test 4: corrupt section descriptor CRC → SectionDescriptorCrcMismatch
#[test]
fn section_descriptor_crc_mismatch_detected() {
    let image = E01Builder::new(512 * 64).with_corrupt_volume_crc().build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::SectionDescriptorCrcMismatch { .. })),
        "expected SectionDescriptorCrcMismatch, got: {findings:#?}"
    );
}

// Test 5: section chain next pointer beyond EOF → SectionChainBroken
#[test]
fn section_chain_broken_detected() {
    let image = E01Builder::new(512 * 64).with_broken_chain().build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::SectionChainBroken { .. })),
        "expected SectionChainBroken, got: {findings:#?}"
    );
}

// Test 6: inter-section gap (non-section bytes between sections) → SectionGapNonZero
#[test]
fn section_gap_nonzero_detected() {
    let image = E01Builder::new(512 * 64).with_gap().build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::SectionGapNonZero { .. })),
        "expected SectionGapNonZero, got: {findings:#?}"
    );
}

// ── Phase 3: Section Ordering / Completeness ─────────────────────────────────

// Test 7: no volume section → VolumeSectionMissing
#[test]
fn volume_section_missing_detected() {
    let image = E01Builder::new(512 * 64).with_omit_volume().build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::VolumeSectionMissing)),
        "expected VolumeSectionMissing, got: {findings:#?}"
    );
}

// Test 8: unrecognised section type → UnknownSectionType
#[test]
fn unknown_section_type_detected() {
    let image = E01Builder::new(512 * 64).with_volume_type("xyzzy").build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::UnknownSectionType { .. })),
        "expected UnknownSectionType, got: {findings:#?}"
    );
}

// Test 9: done section absent → DoneSectionMissing
#[test]
fn done_section_missing_detected() {
    let image = E01Builder::new(512 * 64).with_omit_done().build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::DoneSectionMissing)),
        "expected DoneSectionMissing, got: {findings:#?}"
    );
}

// ── Phase 4: Volume Geometry Consistency ─────────────────────────────────────

// Test 10: sectors_per_chunk not a power of two → ChunkSizeInvalid
#[test]
fn chunk_size_not_power_of_two_detected() {
    let image = E01Builder::new(512 * 64)
        .with_volume_sectors_per_chunk(63) // 63 is not a power of two
        .build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ChunkSizeInvalid { .. })),
        "expected ChunkSizeInvalid, got: {findings:#?}"
    );
}

// Test 11: sector_count doesn't match chunk_count × sectors_per_chunk → SectorCountMismatch
#[test]
fn sector_count_mismatch_detected() {
    let image = E01Builder::new(512 * 64)
        .with_volume_sector_count(999) // wrong sector count
        .build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::SectorCountMismatch { .. })),
        "expected SectorCountMismatch, got: {findings:#?}"
    );
}

// Test 12: bytes_per_sector not 512 or 4096 → BytesPerSectorInvalid
#[test]
fn bytes_per_sector_invalid_detected() {
    let image = E01Builder::new(512 * 64)
        .with_volume_bytes_per_sector(1024)
        .build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::BytesPerSectorInvalid { .. })),
        "expected BytesPerSectorInvalid, got: {findings:#?}"
    );
}

// ── Phase 5: Table Integrity ──────────────────────────────────────────────────

// Test 13: table entry_count differs from volume chunk_count → TableChunkCountMismatch
#[test]
fn table_chunk_count_mismatch_detected() {
    let image = E01Builder::new(512 * 64).with_table_chunk_count(99).build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::TableChunkCountMismatch { .. })),
        "expected TableChunkCountMismatch, got: {findings:#?}"
    );
}

// Test 14: table entry offset beyond sectors section → TableEntryOutOfBounds
#[test]
fn table_entry_out_of_bounds_detected() {
    // Build image, then patch the first table entry to point beyond the file.
    let mut image = E01Builder::new(512 * 64).build();
    // Table descriptor is after: file_header(13) + ewf_header_section(77) + volume_section(170)
    // = 260. Table header (24) follows, then entries at 260+76+24 = 360.
    let table_entry_off = 13 + 77 + 170 + 76 + 24;
    // Write a huge offset (bit31=0 so not-compressed flag doesn't confuse)
    image[table_entry_off..table_entry_off + 4].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::TableEntryOutOfBounds { .. })),
        "expected TableEntryOutOfBounds, got: {findings:#?}"
    );
}

// ── Phase 6: Hash Integrity ───────────────────────────────────────────────────

// Test 16: stored MD5 differs from computed MD5 of sectors data → HashMismatch
#[test]
fn hash_mismatch_detected() {
    let bad_hash = [0xBAu8; 16];
    let image = E01Builder::new(512 * 64).with_md5(bad_hash).build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::HashMismatch { .. })),
        "expected HashMismatch, got: {findings:#?}"
    );
}

// Test 17: no hash section present → HashSectionMissing (Warning)
#[test]
fn hash_section_missing_detected() {
    let image = E01Builder::new(512 * 64).with_omit_hash().build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::HashSectionMissing)),
        "expected HashSectionMissing, got: {findings:#?}"
    );
    let anomaly = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::HashSectionMissing))
        .unwrap();
    assert_eq!(
        anomaly.severity(),
        Severity::Warning,
        "HashSectionMissing should be Warning severity"
    );
}

// ── Phase 6 continued: Table range and zero-gap detection ────────────────────

// Test 18: table entry inside file but outside sectors body → TableEntryOutsideSectorsRange
#[test]
fn table_entry_outside_sectors_range_detected() {
    // base_offset = 0 → entry 0 resolves to absolute offset 0 (file header),
    // which is inside the file but outside the sectors data body.
    let image = E01Builder::new(512 * 64).with_table_base_offset(0).build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::TableEntryOutsideSectorsRange { .. })),
        "expected TableEntryOutsideSectorsRange, got: {findings:#?}"
    );
    // Entry is inside the file, so OutOfBounds must NOT also fire.
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::TableEntryOutOfBounds { .. })),
        "TableEntryOutOfBounds must not fire when entry is inside file: {findings:#?}"
    );
}

// Test 19: zero-filled inter-section gap → SectionGapZero (Info), not SectionGapNonZero
#[test]
fn zero_byte_gap_detected() {
    let image = E01Builder::new(512 * 64).with_zero_gap().build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::SectionGapZero { .. })),
        "expected SectionGapZero, got: {findings:#?}"
    );
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::SectionGapNonZero { .. })),
        "SectionGapNonZero must not fire for a zero-filled gap: {findings:#?}"
    );
    let anomaly = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::SectionGapZero { .. }))
        .unwrap();
    assert_eq!(
        anomaly.severity(),
        Severity::Info,
        "SectionGapZero must carry Info severity"
    );
}

// ── Phase 7: Severity contract ────────────────────────────────────────────────

// Test 15: severity levels are correct for key anomaly types
#[test]
fn severity_levels_correct() {
    use Severity::*;
    let cases: &[(EwfIntegrityAnomaly, Severity)] = &[
        (EwfIntegrityAnomaly::InvalidSignature, Critical),
        (EwfIntegrityAnomaly::SegmentNumberZero, Error),
        (
            EwfIntegrityAnomaly::SectionDescriptorCrcMismatch {
                offset: 0,
                section_type: String::new(),
                computed: 0,
                stored: 1,
            },
            Error,
        ),
        (
            EwfIntegrityAnomaly::SectionChainBroken {
                at_offset: 0,
                next_offset: 0,
            },
            Critical,
        ),
        (
            EwfIntegrityAnomaly::SectionGapNonZero {
                gap_offset: 0,
                gap_size: 16,
            },
            Warning,
        ),
        (EwfIntegrityAnomaly::VolumeSectionMissing, Critical),
        (
            EwfIntegrityAnomaly::UnknownSectionType {
                offset: 0,
                type_name: String::new(),
            },
            Warning,
        ),
        (EwfIntegrityAnomaly::DoneSectionMissing, Warning),
        (
            EwfIntegrityAnomaly::ChunkSizeInvalid {
                sectors_per_chunk: 63,
                bytes_per_sector: 512,
            },
            Error,
        ),
        (
            EwfIntegrityAnomaly::SectorCountMismatch {
                declared: 0,
                expected: 0,
            },
            Error,
        ),
        (
            EwfIntegrityAnomaly::BytesPerSectorInvalid {
                bytes_per_sector: 1024,
            },
            Error,
        ),
        (
            EwfIntegrityAnomaly::TableChunkCountMismatch {
                in_volume: 1,
                in_table: 99,
            },
            Error,
        ),
        (
            EwfIntegrityAnomaly::TableEntryOutOfBounds {
                chunk_index: 0,
                entry_offset: 0,
                file_size: 0,
            },
            Error,
        ),
        (
            EwfIntegrityAnomaly::TableEntryOutsideSectorsRange {
                chunk_index: 0,
                entry_offset: 0,
                sectors_start: 0,
                sectors_end: 0,
            },
            Error,
        ),
        (
            EwfIntegrityAnomaly::SectionGapZero {
                gap_offset: 0,
                gap_size: 16,
            },
            Info,
        ),
    ];
    for (anomaly, expected) in cases {
        assert_eq!(
            &anomaly.severity(),
            expected,
            "severity mismatch for {anomaly:?}"
        );
    }
}

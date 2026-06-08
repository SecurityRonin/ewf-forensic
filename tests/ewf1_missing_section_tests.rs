//! RED phase — `SectorsSectionMissing` and `TableSectionMissing` anomalies.
//!
//! A valid EWF v1 image must contain at least one `sectors` section and at
//! least one `table` section per segment.  Currently these absences are
//! silently ignored; no anomaly is emitted.
//!
//! Currently RED: neither `SectorsSectionMissing` nor `TableSectionMissing` exist.

mod builder;
use builder::{
    make_section_descriptor, EVF_SIGNATURE, FILE_HEADER_SIZE, SECTION_DESCRIPTOR_SIZE,
    VOLUME_DATA_SIZE,
};
use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly};

/// Build a minimal E01 with only: file header, header, volume, done.
/// Sectors and table sections are intentionally absent.
fn e01_without_sectors_or_table() -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();

    // File header (13 bytes)
    buf.extend_from_slice(&EVF_SIGNATURE);
    buf.push(0x01); // fields-version
    buf.extend_from_slice(&1u16.to_le_bytes()); // segment number = 1
    buf.extend_from_slice(&0u16.to_le_bytes()); // padding

    let header_section_size = (SECTION_DESCRIPTOR_SIZE + 1) as u64;
    let volume_section_size = (SECTION_DESCRIPTOR_SIZE + VOLUME_DATA_SIZE) as u64;
    let done_section_size = SECTION_DESCRIPTOR_SIZE as u64;

    let base = FILE_HEADER_SIZE as u64;
    let volume_off = base + header_section_size;
    let done_off = volume_off + volume_section_size;

    // "header" section — 1-byte body, next → volume
    buf.extend_from_slice(&make_section_descriptor(
        "header",
        volume_off,
        header_section_size,
    ));
    buf.push(0u8); // minimal body

    // "volume" section — zeroed geometry, next → done
    buf.extend_from_slice(&make_section_descriptor(
        "volume",
        done_off,
        volume_section_size,
    ));
    buf.extend(std::iter::repeat_n(0u8, VOLUME_DATA_SIZE));

    // "done" section — no body, points to itself
    buf.extend_from_slice(&make_section_descriptor(
        "done",
        done_off,
        done_section_size,
    ));

    buf
}

/// Build a minimal E01 with: file header, header, volume, sectors, done.
/// The table section is intentionally absent.
fn e01_without_table() -> Vec<u8> {
    let sectors_body: Vec<u8> = vec![0u8; 512 * 64];
    let mut buf: Vec<u8> = Vec::new();

    let header_section_size = (SECTION_DESCRIPTOR_SIZE + 1) as u64;
    let volume_section_size = (SECTION_DESCRIPTOR_SIZE + VOLUME_DATA_SIZE) as u64;
    let sectors_section_size = SECTION_DESCRIPTOR_SIZE as u64 + sectors_body.len() as u64;
    let done_section_size = SECTION_DESCRIPTOR_SIZE as u64;

    let base = FILE_HEADER_SIZE as u64;
    let volume_off = base + header_section_size;
    let sectors_off = volume_off + volume_section_size;
    let done_off = sectors_off + sectors_section_size;

    // File header
    buf.extend_from_slice(&EVF_SIGNATURE);
    buf.push(0x01);
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    buf.extend_from_slice(&make_section_descriptor(
        "header",
        volume_off,
        header_section_size,
    ));
    buf.push(0u8);

    buf.extend_from_slice(&make_section_descriptor(
        "volume",
        sectors_off,
        volume_section_size,
    ));
    buf.extend(std::iter::repeat_n(0u8, VOLUME_DATA_SIZE));

    buf.extend_from_slice(&make_section_descriptor(
        "sectors",
        done_off,
        sectors_section_size,
    ));
    buf.extend_from_slice(&sectors_body);

    buf.extend_from_slice(&make_section_descriptor(
        "done",
        done_off,
        done_section_size,
    ));

    buf
}

/// A clean E01 must not produce `SectorsSectionMissing` or `TableSectionMissing`.
#[test]
fn clean_e01_has_no_missing_section_anomalies() {
    let image = builder::E01Builder::new(512 * 64).build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::SectorsSectionMissing)),
        "clean image must not produce SectorsSectionMissing; got: {findings:#?}"
    );
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::TableSectionMissing)),
        "clean image must not produce TableSectionMissing; got: {findings:#?}"
    );
}

/// An E01 without a sectors section must produce `SectorsSectionMissing`.
///
/// Currently RED: the analyser silently skips if sectors is absent.
#[test]
fn e01_missing_sectors_detected() {
    let image = e01_without_sectors_or_table();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::SectorsSectionMissing)),
        "missing sectors section must produce SectorsSectionMissing; got: {findings:#?}"
    );
}

/// An E01 without a table section must produce `TableSectionMissing`.
///
/// Currently RED: the analyser silently skips if table is absent.
#[test]
fn e01_missing_table_detected() {
    let image = e01_without_table();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::TableSectionMissing)),
        "missing table section must produce TableSectionMissing; got: {findings:#?}"
    );
}

//! RED phase — EWF v1 table2 consistency check.
//!
//! `table2` is a redundant copy of the `table` section written by some
//! acquisition tools.  When present, it must be byte-identical to `table`.
//! A mismatch indicates partial corruption of one of the copies.
//!
//! Currently RED: table2 is in KNOWN_TYPES but never compared to table.

mod builder;
use builder::{
    EVF_SIGNATURE, FILE_HEADER_SIZE, SECTION_DESCRIPTOR_SIZE, VOLUME_DATA_SIZE,
    make_section_descriptor,
};
use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly};

const TABLE_DATA_SIZE: usize = 24 + 4; // header(24) + one entry(4) for a single chunk

/// Build a minimal E01 with: file_header, header, volume, table, sectors,
/// table2 (with `table2_body`), hash, done.
///
/// The table body has one entry pointing to the sectors data start.
fn e01_with_table2(table2_body: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();

    let header_sz = (SECTION_DESCRIPTOR_SIZE + 1) as u64;
    let volume_sz = (SECTION_DESCRIPTOR_SIZE + VOLUME_DATA_SIZE) as u64;
    let table_sz = (SECTION_DESCRIPTOR_SIZE + TABLE_DATA_SIZE) as u64;
    let sectors_data: Vec<u8> = vec![0u8; 512 * 64];
    let sectors_sz = SECTION_DESCRIPTOR_SIZE as u64 + sectors_data.len() as u64;
    let table2_sz = SECTION_DESCRIPTOR_SIZE as u64 + table2_body.len() as u64;
    // Minimal hash section: 16-byte MD5 body
    let hash_body = [0u8; 16];
    let hash_sz = (SECTION_DESCRIPTOR_SIZE + hash_body.len()) as u64;
    let done_sz = SECTION_DESCRIPTOR_SIZE as u64;

    let base = FILE_HEADER_SIZE as u64;
    let volume_off = base + header_sz;
    let table_off = volume_off + volume_sz;
    let sectors_off = table_off + table_sz;
    let table2_off = sectors_off + sectors_sz;
    let hash_off = table2_off + table2_sz;
    let done_off = hash_off + hash_sz;

    // File header
    buf.extend_from_slice(&EVF_SIGNATURE);
    buf.push(0x01);
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    // header section
    buf.extend_from_slice(&make_section_descriptor("header", volume_off, header_sz));
    buf.push(0u8);

    // volume section (zeroed — no chunk count verification in this test)
    buf.extend_from_slice(&make_section_descriptor("volume", table_off, volume_sz));
    buf.extend(std::iter::repeat(0u8).take(VOLUME_DATA_SIZE));

    // table section body: 24-byte header (zeros) + one 4-byte entry
    let table_body: Vec<u8> = {
        let mut v = vec![0u8; 24]; // table header with entry_count=0 (simplest)
        v.extend_from_slice(&(sectors_off as u32).to_le_bytes()); // one entry
        v
    };
    buf.extend_from_slice(&make_section_descriptor("table", sectors_off, table_sz));
    buf.extend_from_slice(&table_body);

    // sectors section
    buf.extend_from_slice(&make_section_descriptor("sectors", table2_off, sectors_sz));
    buf.extend_from_slice(&sectors_data);

    // table2 section
    buf.extend_from_slice(&make_section_descriptor("table2", hash_off, table2_sz));
    buf.extend_from_slice(table2_body);

    // hash section
    buf.extend_from_slice(&make_section_descriptor("hash", done_off, hash_sz));
    buf.extend_from_slice(&hash_body);

    // done section
    buf.extend_from_slice(&make_section_descriptor("done", done_off, done_sz));

    buf
}

fn matching_table_body() -> Vec<u8> {
    let mut v = vec![0u8; 24];
    // Use the same sectors_off as in e01_with_table2 to get a matching table2.
    // The exact offset depends on the layout; we just need matching bytes.
    let sectors_off = (FILE_HEADER_SIZE as u64
        + (SECTION_DESCRIPTOR_SIZE + 1) as u64      // header
        + (SECTION_DESCRIPTOR_SIZE + VOLUME_DATA_SIZE) as u64  // volume
        + (SECTION_DESCRIPTOR_SIZE + TABLE_DATA_SIZE) as u64)  // table
        as u32;
    v.extend_from_slice(&sectors_off.to_le_bytes());
    v
}

/// When table and table2 have identical bodies, no Table2Mismatch is emitted.
#[test]
fn table2_matching_no_anomaly() {
    let body = matching_table_body();
    let image = e01_with_table2(&body);
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::Table2Mismatch { .. })),
        "matching table2 must not produce Table2Mismatch; got: {findings:#?}"
    );
}

/// When table2 body differs from table, Table2Mismatch must be emitted.
///
/// Currently RED: table2 is never compared to table.
#[test]
fn table2_mismatch_detected() {
    let mut corrupted = matching_table_body();
    if !corrupted.is_empty() {
        corrupted[0] ^= 0xFF; // corrupt first byte
    }
    let image = e01_with_table2(&corrupted);
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::Table2Mismatch { .. })),
        "mismatching table2 must produce Table2Mismatch; got: {findings:#?}"
    );
}

/// A clean E01 without table2 must not produce Table2Mismatch.
#[test]
fn clean_e01_no_table2_anomaly() {
    let image = builder::E01Builder::new(512 * 64).build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::Table2Mismatch { .. })),
        "image without table2 must not produce Table2Mismatch; got: {findings:#?}"
    );
}

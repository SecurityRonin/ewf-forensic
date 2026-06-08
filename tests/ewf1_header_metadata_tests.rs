#![allow(clippy::unwrap_used, clippy::expect_used)]

mod builder;

use builder::{
    EVF_SIGNATURE, FILE_HEADER_SIZE, SECTION_DESCRIPTOR_SIZE, VOLUME_DATA_SIZE,
    make_section_descriptor, adler32,
};
use ewf_forensic::EwfIntegrity;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write as _;

fn compress_header(text: &str) -> Vec<u8> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(text.as_bytes()).unwrap();
    enc.finish().unwrap()
}

/// Build a minimal valid E01 with a custom header body (compressed bytes).
fn build_e01_with_header_body(header_body: &[u8]) -> Vec<u8> {
    let header_section_size = (SECTION_DESCRIPTOR_SIZE + header_body.len()) as u64;

    // Compute offsets
    let file_hdr_size = FILE_HEADER_SIZE as u64;
    let volume_desc_off = file_hdr_size + header_section_size;
    let volume_section_size = (SECTION_DESCRIPTOR_SIZE + VOLUME_DATA_SIZE) as u64;
    let table_desc_off = volume_desc_off + volume_section_size;

    // Minimal table: 1 chunk entry
    let table_data_size: u64 = 24 + 4; // table header (24) + 1 entry (4)
    let table_section_size = SECTION_DESCRIPTOR_SIZE as u64 + table_data_size;
    let sectors_desc_off = table_desc_off + table_section_size;

    // 1 chunk: 512 bytes (sectors_per_chunk=1, bytes_per_sector=512)
    let chunk_size: usize = 512;
    let sectors_section_size = SECTION_DESCRIPTOR_SIZE as u64 + chunk_size as u64;
    let hash_desc_off = sectors_desc_off + sectors_section_size;

    let hash_section_size = SECTION_DESCRIPTOR_SIZE as u64 + 16u64;
    let done_desc_off = hash_desc_off + hash_section_size;

    let mut buf = Vec::new();

    // File header
    buf.extend_from_slice(&EVF_SIGNATURE);
    buf.push(0x01); // fields_start
    buf.extend_from_slice(&1u16.to_le_bytes()); // segment_number
    buf.extend_from_slice(&0u16.to_le_bytes()); // fields_end

    // Header section
    buf.extend_from_slice(&make_section_descriptor("header", volume_desc_off, header_section_size));
    buf.extend_from_slice(header_body);

    // Volume section
    let mut vol = vec![0u8; VOLUME_DATA_SIZE];
    vol[0] = 0x01; // media_type = fixed
    vol[4..8].copy_from_slice(&1u32.to_le_bytes()); // chunk_count = 1
    vol[8..12].copy_from_slice(&1u32.to_le_bytes()); // sectors_per_chunk = 1
    vol[12..16].copy_from_slice(&512u32.to_le_bytes()); // bytes_per_sector = 512
    vol[16..24].copy_from_slice(&1u64.to_le_bytes()); // sector_count = 1
    buf.extend_from_slice(&make_section_descriptor("volume", table_desc_off, volume_section_size));
    buf.extend_from_slice(&vol);

    // Table section
    let sectors_data_start = sectors_desc_off + SECTION_DESCRIPTOR_SIZE as u64;
    let mut tbl = vec![0u8; table_data_size as usize];
    tbl[0..4].copy_from_slice(&1u32.to_le_bytes()); // entry_count = 1
    tbl[8..16].copy_from_slice(&sectors_data_start.to_le_bytes()); // base_offset
    let tbl_adler = adler32(&tbl[..16]);
    tbl[16..20].copy_from_slice(&tbl_adler.to_le_bytes());
    // entry: offset 0 relative to base
    tbl[24..28].copy_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&make_section_descriptor("table", sectors_desc_off, table_section_size));
    buf.extend_from_slice(&tbl);

    // Sectors section
    let sectors_data = vec![0u8; chunk_size];
    buf.extend_from_slice(&make_section_descriptor("sectors", hash_desc_off, sectors_section_size));
    buf.extend_from_slice(&sectors_data);

    // Hash section (MD5 of sectors data)
    let mut hash_body = [0u8; 16];
    use md5::{Digest as _, Md5};
    let computed: [u8; 16] = Md5::digest(&sectors_data).into();
    hash_body.copy_from_slice(&computed);
    buf.extend_from_slice(&make_section_descriptor("hash", done_desc_off, hash_section_size));
    buf.extend_from_slice(&hash_body);

    // Done section (next == self)
    buf.extend_from_slice(&make_section_descriptor("done", done_desc_off, SECTION_DESCRIPTOR_SIZE as u64));

    buf
}

#[test]
fn header_metadata_none_for_minimal_builder() {
    // E01Builder puts a single 0u8 as header body — not valid zlib.
    // Must return None without panicking.
    use builder::E01Builder;
    let image = E01Builder::new(512 * 64).build();
    let result = EwfIntegrity::new(&image).header_metadata();
    assert_eq!(result, None);
}

#[test]
fn header_metadata_parsed_from_real_header() {
    let header_text = "1\r\nmain\r\na\tc\te\tt\tm\tu\tp\tr\n\
        TestImage\tCASE-001\tEVIDENCE-042\tJ.Smith\t2024-01-15 10:30:00\t2024-01-15 10:30:00\t\tFTK Imager\n";
    let compressed = compress_header(header_text);
    let image = build_e01_with_header_body(&compressed);

    let result = EwfIntegrity::new(&image).header_metadata();
    assert!(result.is_some(), "expected Some, got None");
    let meta = result.unwrap();

    assert_eq!(meta.description, "TestImage");
    assert_eq!(meta.case_number, "CASE-001");
    assert_eq!(meta.evidence_number, "EVIDENCE-042");
    assert_eq!(meta.examiner_name, "J.Smith");
}

#[test]
fn header_metadata_multi_segment_uses_first() {
    let header_text = "1\r\nmain\r\na\tc\te\tt\tm\tu\tp\tr\n\
        FirstSegImage\tCASE-002\tEVIDENCE-001\tA.Hui\t2024-03-01\t2024-03-01\t\tlibewf\n";
    let compressed = compress_header(header_text);
    let seg1 = build_e01_with_header_body(&compressed);

    // Second segment: invalid (0u8) header body
    let seg2 = build_e01_with_header_body(&[0u8]);

    let result = EwfIntegrity::from_segments(&[seg1.as_slice(), seg2.as_slice()])
        .header_metadata();

    assert!(result.is_some(), "expected Some from first segment");
    let meta = result.unwrap();
    assert_eq!(meta.description, "FirstSegImage");
    assert_eq!(meta.case_number, "CASE-002");
    assert_eq!(meta.evidence_number, "EVIDENCE-001");
    assert_eq!(meta.examiner_name, "A.Hui");
}

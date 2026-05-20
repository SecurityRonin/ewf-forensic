//! RED phase — EWF v2 unsupported compression algorithm detection.
//!
//! The EWF v2 file header bytes [10..12] (u16 LE) specify the compression
//! algorithm.  Currently only deflate/zlib (method_id 0 or 1) is supported.
//! A non-zero/non-deflate method_id (e.g. bzip2=2, lzma=3) should produce
//! `UnsupportedCompressionAlgorithm` instead of a confusing ChunkDecompressionError.
//!
//! Currently RED: the compression_method field is never read.

mod builder;
use builder::{
    adler32, make_ewf2_descriptor, EVF2_SIGNATURE, EVF2_FILE_HEADER_SIZE,
    EVF2_SECTION_TYPE_CHUNK_TABLE, EVF2_SECTION_TYPE_MD5_HASH, EVF2_SECTION_TYPE_DONE,
};
use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly};

const CHUNK_TABLE_HEADER_SIZE: usize = 32;
const CHUNK_TABLE_ENTRY_SIZE: usize = 16;

/// Build an EWF v2 segment with a specified `compression_method` in the file header.
fn make_segment_with_compression_method(method_id: u16, chunk_data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();

    // File header (32 bytes)
    let mut hdr = vec![0u8; EVF2_FILE_HEADER_SIZE];
    hdr[0..8].copy_from_slice(&EVF2_SIGNATURE);
    hdr[8] = 0x01; // major_version
    hdr[9] = 0x00; // minor_version
    hdr[10..12].copy_from_slice(&method_id.to_le_bytes()); // compression_method
    hdr[12..16].copy_from_slice(&1u32.to_le_bytes()); // segment_number = 1
    buf.extend_from_slice(&hdr);

    // Chunk data
    let chunk_off = buf.len() as u32;
    buf.extend_from_slice(chunk_data);
    buf.extend_from_slice(&adler32(chunk_data).to_le_bytes());
    let entry_data_size = chunk_data.len() as u32 + 4;

    // Chunk table body
    let ct_body_start = buf.len();
    let mut ct_hdr = [0u8; CHUNK_TABLE_HEADER_SIZE];
    ct_hdr[8..16].copy_from_slice(&1u64.to_le_bytes());
    buf.extend_from_slice(&ct_hdr);
    let mut entry = [0u8; CHUNK_TABLE_ENTRY_SIZE];
    entry[0..4].copy_from_slice(&chunk_off.to_le_bytes());
    entry[8..12].copy_from_slice(&entry_data_size.to_le_bytes());
    buf.extend_from_slice(&entry);
    buf.extend_from_slice(&adler32(&entry).to_le_bytes());
    let ct_body_len = (buf.len() - ct_body_start) as u64;

    let ct_desc_off = buf.len() as u64;
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_CHUNK_TABLE, 0, 0, ct_body_len, [0u8; 16],
    ));

    buf.extend_from_slice(&[0u8; 16]); // MD5 body
    let md5_desc_off = buf.len() as u64;
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_MD5_HASH, 0, ct_desc_off, 16, [0u8; 16],
    ));

    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_DONE, 0, md5_desc_off, 0, [0u8; 16],
    ));

    buf
}

/// compression_method=0 (deflate/none) must not produce UnsupportedCompressionAlgorithm.
#[test]
fn compression_method_zero_no_anomaly() {
    let seg = make_segment_with_compression_method(0, &[0u8; 512]);
    let findings = EwfIntegrity::new(&seg).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::UnsupportedCompressionAlgorithm { .. })),
        "method=0 (deflate) must not produce UnsupportedCompressionAlgorithm; got: {findings:#?}"
    );
}

/// compression_method=2 (bzip2) must produce UnsupportedCompressionAlgorithm.
///
/// Currently RED: the field is never checked.
#[test]
fn compression_method_bzip2_detected() {
    let seg = make_segment_with_compression_method(2, &[0u8; 512]);
    let findings = EwfIntegrity::new(&seg).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::UnsupportedCompressionAlgorithm { .. })),
        "method=2 (bzip2) must produce UnsupportedCompressionAlgorithm; got: {findings:#?}"
    );
}

/// UnsupportedCompressionAlgorithm must report the correct method_id.
///
/// Currently RED: anomaly never fires.
#[test]
fn compression_method_reports_correct_id() {
    let seg = make_segment_with_compression_method(3, &[0u8; 512]);
    let findings = EwfIntegrity::new(&seg).analyse();
    let anomaly = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::UnsupportedCompressionAlgorithm { .. }));
    if let Some(EwfIntegrityAnomaly::UnsupportedCompressionAlgorithm { method_id }) = anomaly {
        assert_eq!(*method_id, 3, "method_id must equal the file header value");
    } else {
        panic!("expected UnsupportedCompressionAlgorithm not found; got: {findings:#?}");
    }
}

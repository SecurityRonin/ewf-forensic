#![allow(clippy::unwrap_used, clippy::expect_used)]

//! RED phase — EWF v2 stored SHA-256 hash verification.
//!
//! `EVF2_TYPE_SHA256_HASH` (section type 0x0A) body[0..32] must be extracted
//! and compared against the computed SHA-256 of all sector data.
//! On mismatch, `DigestSha256Mismatch` must fire.
//!
//! Currently RED: section type 0x0A is unrecognised, so no check occurs.

mod builder;
use builder::{
    adler32, make_ewf2_descriptor, make_ewf2_file_header,
    EVF2_SECTION_TYPE_CHUNK_TABLE, EVF2_SECTION_TYPE_DONE, EVF2_SECTION_TYPE_SHA256_HASH,
};
use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly};

const CHUNK_TABLE_HEADER_SIZE: usize = 32;
const CHUNK_TABLE_ENTRY_SIZE: usize = 16;

/// Build a minimal EWF v2 segment with one uncompressed chunk and a SHA-256
/// hash section whose stored value is `stored_sha256`.
fn make_segment_with_sha256(chunk_data: &[u8], stored_sha256: [u8; 32]) -> Vec<u8> {
    let mut buf = Vec::new();

    buf.extend_from_slice(&make_ewf2_file_header(1));

    let chunk_file_off = buf.len() as u32;
    buf.extend_from_slice(chunk_data);
    let crc = adler32(chunk_data);
    buf.extend_from_slice(&crc.to_le_bytes());
    let entry_data_size = chunk_data.len() as u32 + 4;

    let ct_body_start = buf.len();
    let mut header = [0u8; CHUNK_TABLE_HEADER_SIZE];
    header[8..16].copy_from_slice(&1u64.to_le_bytes());
    buf.extend_from_slice(&header);

    let mut entry = [0u8; CHUNK_TABLE_ENTRY_SIZE];
    entry[0..4].copy_from_slice(&chunk_file_off.to_le_bytes());
    entry[8..12].copy_from_slice(&entry_data_size.to_le_bytes());
    buf.extend_from_slice(&entry);
    buf.extend_from_slice(&adler32(&entry).to_le_bytes());

    let ct_body_len = (buf.len() - ct_body_start) as u64;

    let ct_desc_off = buf.len() as u64;
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_CHUNK_TABLE,
        0,
        0,
        ct_body_len,
        [0u8; 16],
    ));

    // SHA-256 hash body (32 bytes)
    buf.extend_from_slice(&stored_sha256);
    let sha256_desc_off = buf.len() as u64;
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_SHA256_HASH,
        0,
        ct_desc_off,
        32,
        [0u8; 16],
    ));

    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_DONE,
        0,
        sha256_desc_off,
        0,
        [0u8; 16],
    ));

    buf
}

fn sha256_of(data: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(data).into()
}

/// A stored SHA-256 that does not match computed must produce `DigestSha256Mismatch`.
///
/// Currently RED: section type 0x0A is unrecognised.
#[test]
fn ewf2_stored_sha256_mismatch_detected() {
    let seg = make_segment_with_sha256(&[0u8; 512], [0xFF; 32]);
    let findings = EwfIntegrity::new(&seg).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::DigestSha256Mismatch { .. })),
        "wrong stored SHA-256 must produce DigestSha256Mismatch; got: {findings:#?}"
    );
}

/// A correct stored SHA-256 must not produce `DigestSha256Mismatch`.
#[test]
fn ewf2_stored_sha256_correct_no_mismatch() {
    let chunk = [0u8; 512];
    let correct = sha256_of(&chunk);
    let seg = make_segment_with_sha256(&chunk, correct);
    let findings = EwfIntegrity::new(&seg).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::DigestSha256Mismatch { .. })),
        "correct stored SHA-256 must not produce DigestSha256Mismatch; got: {findings:#?}"
    );
}

/// Real EWF v2 fixture must not produce spurious `DigestSha256Mismatch`.
#[test]
fn ewf2_real_fixture_no_sha256_mismatch() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/zeros_128s.Ex01");
    if !path.exists() {
        eprintln!("skipping: fixture not found");
        return;
    }
    let data = std::fs::read(&path).expect("read fixture");
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::DigestSha256Mismatch { .. })),
        "real fixture must not produce DigestSha256Mismatch; got: {findings:#?}"
    );
}

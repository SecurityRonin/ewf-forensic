//! RED phase — EWF v2 stored SHA-1 hash verification.
//!
//! `EVF2_TYPE_SHA1_HASH` body[0..20] must be extracted and compared against the
//! computed SHA-1 of all sector data.  On mismatch, `DigestSha1Mismatch` must fire.
//!
//! Currently RED: the SHA-1 handler only sets `has_hash = true` and discards
//! the body, so no mismatch anomaly is ever produced.

mod builder;
use builder::{
    adler32, make_ewf2_descriptor, make_ewf2_file_header,
    EVF2_SECTION_TYPE_CHUNK_TABLE, EVF2_SECTION_TYPE_DONE, EVF2_SECTION_TYPE_SHA1_HASH,
};
use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly};

const CHUNK_TABLE_HEADER_SIZE: usize = 32;
const CHUNK_TABLE_ENTRY_SIZE: usize = 16;

/// Build a minimal EWF v2 segment with one uncompressed chunk and a SHA-1
/// hash section whose stored value is `stored_sha1`.  No MD5, no media_info.
fn make_segment_with_sha1(chunk_data: &[u8], stored_sha1: [u8; 20]) -> Vec<u8> {
    let mut buf = Vec::new();

    // [0..32] file header
    buf.extend_from_slice(&make_ewf2_file_header(1));

    // Chunk data body + Adler-32 trailer
    let chunk_file_off = buf.len() as u32;
    buf.extend_from_slice(chunk_data);
    let crc = adler32(chunk_data);
    buf.extend_from_slice(&crc.to_le_bytes());
    let entry_data_size = chunk_data.len() as u32 + 4; // raw + Adler-32

    // Chunk table body (32-byte header + 16-byte entry + 4-byte Adler-32)
    let ct_body_start = buf.len();
    let mut header = [0u8; CHUNK_TABLE_HEADER_SIZE];
    header[8..16].copy_from_slice(&1u64.to_le_bytes()); // chunk_count = 1
    buf.extend_from_slice(&header);

    let mut entry = [0u8; CHUNK_TABLE_ENTRY_SIZE];
    entry[0..4].copy_from_slice(&chunk_file_off.to_le_bytes()); // file_offset
    // entry[4..8] = hi_offset = 0 (padding)
    entry[8..12].copy_from_slice(&entry_data_size.to_le_bytes()); // data_size
    // entry[12..16] = flags = 0 (uncompressed)
    buf.extend_from_slice(&entry);
    buf.extend_from_slice(&adler32(&entry).to_le_bytes()); // table Adler-32

    let ct_body_len = (buf.len() - ct_body_start) as u64;

    // Chunk table descriptor
    let ct_desc_off = buf.len() as u64;
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_CHUNK_TABLE,
        0,
        0,
        ct_body_len,
        [0u8; 16],
    ));

    // SHA-1 hash body (20 bytes)
    buf.extend_from_slice(&stored_sha1);
    // SHA-1 hash descriptor
    let sha1_desc_off = buf.len() as u64;
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_SHA1_HASH,
        0,
        ct_desc_off,
        20,
        [0u8; 16],
    ));

    // DONE descriptor (last 64 bytes, no body)
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_DONE,
        0,
        sha1_desc_off,
        0,
        [0u8; 16],
    ));

    buf
}

fn sha1_of(data: &[u8]) -> [u8; 20] {
    use sha1::Digest as _;
    sha1::Sha1::digest(data).into()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// A stored SHA-1 that does not match the computed SHA-1 must produce
/// `DigestSha1Mismatch`.
///
/// Currently RED: the SHA-1 section body is ignored, so no mismatch fires.
#[test]
fn ewf2_stored_sha1_mismatch_detected() {
    let seg = make_segment_with_sha1(&[0u8; 512], [0xFF; 20]);
    let findings = EwfIntegrity::new(&seg).analyse();
    assert!(
        findings.iter().any(|a| matches!(a, EwfIntegrityAnomaly::DigestSha1Mismatch { .. })),
        "wrong stored SHA-1 must produce DigestSha1Mismatch; got: {findings:#?}"
    );
}

/// A correct stored SHA-1 must not produce `DigestSha1Mismatch`.
#[test]
fn ewf2_stored_sha1_correct_no_mismatch() {
    let chunk = [0u8; 512];
    let correct = sha1_of(&chunk);
    let seg = make_segment_with_sha1(&chunk, correct);
    let findings = EwfIntegrity::new(&seg).analyse();
    assert!(
        !findings.iter().any(|a| matches!(a, EwfIntegrityAnomaly::DigestSha1Mismatch { .. })),
        "correct stored SHA-1 must not produce DigestSha1Mismatch; got: {findings:#?}"
    );
}

/// The real `zeros_128s.Ex01` fixture has no SHA-1 section; verify no spurious
/// `DigestSha1Mismatch` is emitted.
#[test]
fn ewf2_real_fixture_no_sha1_mismatch() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/zeros_128s.Ex01");
    if !path.exists() {
        eprintln!("skipping: fixture not found");
        return;
    }
    let data = std::fs::read(&path).expect("read fixture");
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        !findings.iter().any(|a| matches!(a, EwfIntegrityAnomaly::DigestSha1Mismatch { .. })),
        "real fixture without SHA-1 section must not produce DigestSha1Mismatch; got: {findings:#?}"
    );
}

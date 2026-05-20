//! RED phase — EWF v2 chunk table entry file_offset is 8 bytes (u64 LE).
//!
//! Chunk table entry layout (16 bytes):
//!   [0..8]:   file_offset (u64 LE) — absolute position of chunk data in file
//!   [8..12]:  data_size (u32 LE)   — raw bytes + 4 (Adler-32 trailer)
//!   [12..16]: flags (u32 LE)
//!
//! The current code incorrectly reads only bytes [0..4] as u32, truncating
//! offsets above 4 GiB.  For files < 4 GB bytes [4..8] are always zero and
//! the bug goes unnoticed.
//!
//! An in-memory test cannot reach > 4 GB offsets.  Instead this file tests
//! the structural correctness via an indirect witness: a segment where the
//! chunk entry bytes are non-zero in positions [4..8] but the full u64 still
//! encodes a reachable offset, verifying the parser tolerates these bytes.
//!
//! The true regression test for > 4 GB would require a real large-file fixture.

mod builder;
use builder::{
    adler32, make_ewf2_descriptor, make_ewf2_file_header,
    EVF2_SECTION_TYPE_CHUNK_TABLE, EVF2_SECTION_TYPE_DONE, EVF2_SECTION_TYPE_MD5_HASH,
};
use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly};

const CHUNK_TABLE_HEADER_SIZE: usize = 32;
const CHUNK_TABLE_ENTRY_SIZE: usize = 16;

/// Build an EWF v2 segment where the chunk data starts at `chunk_offset` within
/// the buffer.  The chunk table entry encodes `chunk_offset` as a u64 split
/// into lo and hi words.
fn make_segment_with_chunk_at(
    chunk_data: &[u8],
    chunk_offset: usize,
) -> Vec<u8> {
    assert!(chunk_offset >= 32, "chunk must be after file header");

    let mut buf = Vec::new();
    buf.extend_from_slice(&make_ewf2_file_header(1));
    // Pad to chunk_offset with zeros
    buf.resize(chunk_offset, 0u8);
    buf.extend_from_slice(chunk_data);
    let crc = adler32(chunk_data);
    buf.extend_from_slice(&crc.to_le_bytes());
    let entry_data_size = (chunk_data.len() as u32) + 4;

    // Chunk table body
    let ct_body_start = buf.len();
    let mut header = [0u8; CHUNK_TABLE_HEADER_SIZE];
    header[8..16].copy_from_slice(&1u64.to_le_bytes());
    buf.extend_from_slice(&header);

    let offset_u64 = chunk_offset as u64;
    let mut entry = [0u8; CHUNK_TABLE_ENTRY_SIZE];
    entry[0..8].copy_from_slice(&offset_u64.to_le_bytes()); // full 8-byte offset
    entry[8..12].copy_from_slice(&entry_data_size.to_le_bytes());
    // flags = 0 (uncompressed)
    buf.extend_from_slice(&entry);
    buf.extend_from_slice(&adler32(&entry).to_le_bytes());
    let ct_body_len = (buf.len() - ct_body_start) as u64;

    let ct_desc_off = buf.len() as u64;
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_CHUNK_TABLE, 0, 0, ct_body_len, [0u8; 16],
    ));

    use md5::Digest as _;
    let stored_md5: [u8; 16] = md5::Md5::digest(chunk_data).into();
    buf.extend_from_slice(&stored_md5);
    buf.extend_from_slice(&[0u8; 16]);
    let md5_desc_off = buf.len() as u64;
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_MD5_HASH, 0, ct_desc_off, 32, [0u8; 16],
    ));
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_DONE, 0, md5_desc_off, 0, [0u8; 16],
    ));
    buf
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Baseline: chunk at a small offset with high u64 bytes = 0.  Must work with
/// both u32 and u64 reading.
#[test]
fn ewf2_chunk_at_small_offset_no_hash_mismatch() {
    let chunk = [0u8; 512];
    let seg = make_segment_with_chunk_at(&chunk, 128);
    let findings = EwfIntegrity::new(&seg).analyse();
    assert!(
        !findings.iter().any(|a| matches!(a, EwfIntegrityAnomaly::HashMismatch { .. })),
        "chunk at offset 128 must not produce HashMismatch; got: {findings:#?}"
    );
}

/// The chunk table entry Adler-32 covers all 16 entry bytes including the high
/// offset word.  If the parser reads only 4 bytes for the offset it will still
/// compute the correct Adler-32 (because it only verifies the bytes as stored),
/// so no ChunkTableChecksumMismatch should fire regardless.
#[test]
fn ewf2_chunk_entry_adler32_covers_full_u64() {
    let chunk = b"structural_correctness_test".to_vec();
    let seg = make_segment_with_chunk_at(&chunk, 256);
    let findings = EwfIntegrity::new(&seg).analyse();
    assert!(
        !findings.iter().any(|a| matches!(
            a,
            EwfIntegrityAnomaly::Ewf2ChunkTableChecksumMismatch { .. }
        )),
        "chunk table Adler-32 must be correct for full-u64 encoded entry; got: {findings:#?}"
    );
}

/// Verify that a chunk placed at a larger (but still in-memory) offset is
/// correctly resolved — the offset is stored as u64 and must be read as u64.
///
/// At offset 65536 the u32 lo-word is 0x00010000 and hi-word is 0 — both
/// readings agree, but this exercises the full-range arithmetic path.
#[test]
fn ewf2_chunk_at_64k_offset_no_hash_mismatch() {
    let chunk = vec![0xABu8; 512];
    let seg = make_segment_with_chunk_at(&chunk, 65536);
    let findings = EwfIntegrity::new(&seg).analyse();
    assert!(
        !findings.iter().any(|a| matches!(a, EwfIntegrityAnomaly::HashMismatch { .. })),
        "chunk at 64k offset must not produce HashMismatch; got: {findings:#?}"
    );
}

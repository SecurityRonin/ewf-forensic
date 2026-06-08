//! RED phase — EWF v2 multi-segment cross-segment hash verification.
//!
//! In multi-segment EWF v2 (Ex01 + Ex02 + …), stored hash sections (MD5=0x08,
//! SHA-1=0x09, SHA-256=0x0A) in the FINAL segment cover ALL sector data across
//! ALL segments.  The current code calls `verify_ewf2_sector_data` per segment,
//! so it hashes only that segment's chunks and compares against the full-image
//! stored hash — producing false-positive mismatches on correct multi-segment images.
//!
//! Currently RED: first test fires spurious HashMismatch / DigestSha1Mismatch /
//! DigestSha256Mismatch even though the stored hashes are correct.

mod builder;
use builder::{
    adler32, make_ewf2_descriptor, EVF2_FILE_HEADER_SIZE,
    EVF2_SECTION_TYPE_CHUNK_TABLE, EVF2_SECTION_TYPE_DONE, EVF2_SECTION_TYPE_MD5_HASH,
    EVF2_SECTION_TYPE_SHA1_HASH, EVF2_SECTION_TYPE_SHA256_HASH, EVF2_SIGNATURE,
};
use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly};

const CT_HDR: usize = 32;
const CT_ENTRY: usize = 16;

fn ewf2_file_header(seg_num: u32) -> Vec<u8> {
    let mut h = vec![0u8; EVF2_FILE_HEADER_SIZE];
    h[0..8].copy_from_slice(&EVF2_SIGNATURE);
    h[8] = 0x01;
    h[12..16].copy_from_slice(&seg_num.to_le_bytes());
    h
}

/// Build a non-final EWF v2 segment: one raw (uncompressed) chunk, no hash sections.
fn nonfinal_segment(seg_num: u32, chunk_data: &[u8]) -> Vec<u8> {
    let mut buf = ewf2_file_header(seg_num);

    let chunk_off = buf.len() as u64;
    buf.extend_from_slice(chunk_data);
    buf.extend_from_slice(&adler32(chunk_data).to_le_bytes());
    let entry_data_size = chunk_data.len() as u32 + 4;

    let ct_body_start = buf.len();
    let mut ct_hdr = [0u8; CT_HDR];
    ct_hdr[8..16].copy_from_slice(&1u64.to_le_bytes());
    buf.extend_from_slice(&ct_hdr);
    let mut entry = [0u8; CT_ENTRY];
    entry[0..8].copy_from_slice(&chunk_off.to_le_bytes());
    entry[8..12].copy_from_slice(&entry_data_size.to_le_bytes());
    // flags[12..16] = 0 (uncompressed)
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

    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_DONE,
        0,
        ct_desc_off,
        0,
        [0u8; 16],
    ));
    buf
}

/// Build a final EWF v2 segment: one raw chunk + MD5 + SHA-1 + SHA-256 hash sections.
///
/// The caller provides the FULL-IMAGE hashes (covering all preceding segments too).
fn final_segment(
    seg_num: u32,
    chunk_data: &[u8],
    full_md5: [u8; 16],
    full_sha1: [u8; 20],
    full_sha256: [u8; 32],
) -> Vec<u8> {
    let mut buf = ewf2_file_header(seg_num);

    let chunk_off = buf.len() as u64;
    buf.extend_from_slice(chunk_data);
    buf.extend_from_slice(&adler32(chunk_data).to_le_bytes());
    let entry_data_size = chunk_data.len() as u32 + 4;

    let ct_body_start = buf.len();
    let mut ct_hdr = [0u8; CT_HDR];
    ct_hdr[8..16].copy_from_slice(&1u64.to_le_bytes());
    buf.extend_from_slice(&ct_hdr);
    let mut entry = [0u8; CT_ENTRY];
    entry[0..8].copy_from_slice(&chunk_off.to_le_bytes());
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

    // MD5 hash section
    buf.extend_from_slice(&full_md5);
    let md5_desc_off = buf.len() as u64;
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_MD5_HASH,
        0,
        ct_desc_off,
        16,
        [0u8; 16],
    ));

    // SHA-1 hash section
    buf.extend_from_slice(&full_sha1);
    let sha1_desc_off = buf.len() as u64;
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_SHA1_HASH,
        0,
        md5_desc_off,
        20,
        [0u8; 16],
    ));

    // SHA-256 hash section
    buf.extend_from_slice(&full_sha256);
    let sha256_desc_off = buf.len() as u64;
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_SHA256_HASH,
        0,
        sha1_desc_off,
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

fn full_image_hashes(chunks: &[&[u8]]) -> ([u8; 16], [u8; 20], [u8; 32]) {
    use md5::Digest as _;
    let mut md5_h = md5::Md5::new();
    let mut sha1_h = sha1::Sha1::new();
    let mut sha256_h = sha2::Sha256::new();
    for chunk in chunks {
        md5_h.update(chunk);
        sha1_h.update(chunk);
        sha256_h.update(chunk);
    }
    (
        md5_h.finalize().into(),
        sha1_h.finalize().into(),
        sha256_h.finalize().into(),
    )
}

/// Two-segment EWF v2 with CORRECT cross-segment hashes must produce NO hash mismatch.
///
/// Currently RED: per-segment hash comparison fires a false-positive because
/// the final segment hashes only its own chunks (not all segments' chunks).
#[test]
fn ewf2_multiseg_correct_hashes_no_mismatch() {
    let data1 = vec![0u8; 512];
    let data2 = vec![1u8; 512];
    let (full_md5, full_sha1, full_sha256) =
        full_image_hashes(&[&data1, &data2]);

    let seg1 = nonfinal_segment(1, &data1);
    let seg2 = final_segment(2, &data2, full_md5, full_sha1, full_sha256);

    let findings = EwfIntegrity::from_segments(&[seg1.as_slice(), seg2.as_slice()]).analyse();

    let hash_mismatches: Vec<_> = findings
        .iter()
        .filter(|a| {
            matches!(
                a,
                EwfIntegrityAnomaly::HashMismatch { .. }
                    | EwfIntegrityAnomaly::DigestSha1Mismatch { .. }
                    | EwfIntegrityAnomaly::DigestSha256Mismatch { .. }
            )
        })
        .collect();

    assert!(
        hash_mismatches.is_empty(),
        "correct cross-segment hashes must not produce hash mismatch; got: {hash_mismatches:#?}"
    );
}

/// Two-segment EWF v2 with WRONG hash in final segment must produce a hash mismatch.
#[test]
fn ewf2_multiseg_wrong_hash_detected() {
    let data1 = vec![0u8; 512];
    let data2 = vec![1u8; 512];

    let seg1 = nonfinal_segment(1, &data1);
    // Embed all-zero (wrong) hashes
    let seg2 = final_segment(2, &data2, [0u8; 16], [0u8; 20], [0u8; 32]);

    let findings = EwfIntegrity::from_segments(&[seg1.as_slice(), seg2.as_slice()]).analyse();

    assert!(
        findings.iter().any(|a| matches!(
            a,
            EwfIntegrityAnomaly::HashMismatch { .. }
                | EwfIntegrityAnomaly::DigestSha1Mismatch { .. }
                | EwfIntegrityAnomaly::DigestSha256Mismatch { .. }
        )),
        "wrong cross-segment hash must produce a hash mismatch; got: {findings:#?}"
    );
}

/// Single-segment EWF v2 with CORRECT hashes must still pass — no regression.
#[test]
fn ewf2_singleseg_correct_hash_no_regression() {
    let data = vec![0u8; 512];
    let (md5, sha1, sha256) = full_image_hashes(&[&data]);

    let seg = final_segment(1, &data, md5, sha1, sha256);
    let findings = EwfIntegrity::new(&seg).analyse();

    assert!(
        !findings.iter().any(|a| matches!(
            a,
            EwfIntegrityAnomaly::HashMismatch { .. }
                | EwfIntegrityAnomaly::DigestSha1Mismatch { .. }
                | EwfIntegrityAnomaly::DigestSha256Mismatch { .. }
        )),
        "correct single-segment hash must not produce mismatch; got: {findings:#?}"
    );
}

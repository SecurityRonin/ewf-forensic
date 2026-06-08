#![allow(clippy::unwrap_used, clippy::expect_used)]

//! RED phase — EWF v2 media information section parsing.
//!
//! Real EWF v2 media_info body: zlib-compressed, UTF-16LE with BOM (FF FE),
//! tab-separated header and value rows.  The parser must detect when the body
//! cannot be decompressed or decoded and emit Ewf2MediaInfoParseFailed.
//!
//! Ground truth from zeros_128s.Ex01 (ewfacquirestream + ewfverify):
//!   sb=64  (sectors per chunk)
//!   gr=64  (reported by ewfacquirestream; ewfinfo reads 512 bytes/sector
//!           from the SECTOR_DATA body header, not from media_info)
//!   tb=2   (chunk count)

mod builder;

use builder::{
    make_ewf2_descriptor, make_ewf2_file_header,
    EVF2_SECTION_TYPE_DONE, EVF2_SECTION_TYPE_MD5_HASH, EVF2_SECTION_TYPE_MEDIA_INFO,
};
use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly};
use std::path::PathBuf;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/zeros_128s.Ex01")
}

/// Build a minimal EWF v2 segment whose media_info section body is the raw
/// bytes supplied by the caller (not wrapped in zlib — that's the caller's job).
fn segment_with_raw_media_info_body(body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&make_ewf2_file_header(1));

    buf.extend_from_slice(body);
    let mi_desc_off = buf.len() as u64;
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_MEDIA_INFO,
        0,
        0,
        body.len() as u64,
        [0u8; 16],
    ));

    buf.extend_from_slice(&[0u8; 16]);
    let md5_desc_off = buf.len() as u64;
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_MD5_HASH,
        0,
        mi_desc_off,
        16,
        [0u8; 16],
    ));

    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_DONE,
        0,
        md5_desc_off,
        0,
        [0u8; 16],
    ));

    buf
}

/// Build a correctly-formatted zlib+UTF-16LE media_info body.
fn valid_compressed_media_info_body() -> Vec<u8> {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    let text = "1\nmain\nnm\tcn\ten\tsb\tgr\ttb\n\tcase1\tevidence1\t64\t64\t2\n\n";
    let mut utf16: Vec<u8> = vec![0xFF, 0xFE]; // BOM
    for unit in text.encode_utf16() {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&utf16).unwrap();
    enc.finish().unwrap()
}

// ── Tests against the real fixture ───────────────────────────────────────────

/// The real zeros_128s.Ex01 fixture must not produce Ewf2MediaInfoParseFailed.
#[test]
fn ewf2_real_fixture_media_info_parses_ok() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("skipping: fixture not found");
        return;
    }
    let data = std::fs::read(&path).expect("read fixture");
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        !findings.iter().any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2MediaInfoParseFailed)),
        "real fixture with valid media_info must not produce Ewf2MediaInfoParseFailed; got: {findings:#?}"
    );
}

// ── Tests with synthetic segments ────────────────────────────────────────────

/// A segment with a valid zlib+UTF-16LE media_info body must not produce
/// Ewf2MediaInfoParseFailed.
#[test]
fn ewf2_valid_compressed_media_info_no_parse_failure() {
    let body = valid_compressed_media_info_body();
    let seg = segment_with_raw_media_info_body(&body);
    let findings = EwfIntegrity::new(&seg).analyse();
    assert!(
        !findings.iter().any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2MediaInfoParseFailed)),
        "valid zlib+UTF-16LE body must not produce Ewf2MediaInfoParseFailed; got: {findings:#?}"
    );
}

/// A segment with a non-zlib garbage body must produce Ewf2MediaInfoParseFailed.
///
/// Currently RED: the body is never decompressed, so no parse failure is emitted.
#[test]
fn ewf2_corrupt_media_info_body_detected() {
    // Bytes that are not a valid zlib stream (no valid zlib header/trailer).
    let garbage: Vec<u8> = (0u8..=31).collect();
    let seg = segment_with_raw_media_info_body(&garbage);
    let findings = EwfIntegrity::new(&seg).analyse();
    assert!(
        findings.iter().any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2MediaInfoParseFailed)),
        "non-zlib media_info body must produce Ewf2MediaInfoParseFailed; got: {findings:#?}"
    );
}

/// A segment with raw (uncompressed) UTF-16LE bytes — valid text but not
/// zlib-wrapped — must produce Ewf2MediaInfoParseFailed.
///
/// Currently RED: the body is not examined.
#[test]
fn ewf2_uncompressed_utf16_media_info_detected() {
    // Plain UTF-16LE (no zlib wrapper) — looks like valid text but zlib will reject it.
    let text = "1\nmain\nnm\tsb\n\t64\n";
    let mut raw_utf16: Vec<u8> = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        raw_utf16.extend_from_slice(&unit.to_le_bytes());
    }
    let seg = segment_with_raw_media_info_body(&raw_utf16);
    let findings = EwfIntegrity::new(&seg).analyse();
    assert!(
        findings.iter().any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2MediaInfoParseFailed)),
        "uncompressed (non-zlib) UTF-16LE body must produce Ewf2MediaInfoParseFailed; got: {findings:#?}"
    );
}

/// An empty media_info body must produce Ewf2MediaInfoParseFailed.
///
/// Currently RED: presence of the section clears the missing flag; content is
/// never checked.
#[test]
fn ewf2_empty_media_info_body_detected() {
    let seg = segment_with_raw_media_info_body(&[]);
    let findings = EwfIntegrity::new(&seg).analyse();
    assert!(
        findings.iter().any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2MediaInfoParseFailed)),
        "empty media_info body must produce Ewf2MediaInfoParseFailed; got: {findings:#?}"
    );
}

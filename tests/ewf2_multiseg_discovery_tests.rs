//! RED phase — EWF v2 Ex01/Ex02 multi-segment sibling discovery.
//!
//! Bug: `make_ewf_extension` drops the 'x' from "Ex01" so it generates
//! "E02" instead of "Ex02" when looking for the next segment sibling.
//! After the fix the analyser must discover ev.Ex02 automatically when
//! given ev.Ex01, and the wrong segment_number must produce SegmentOutOfOrder.

mod builder;

use builder::{
    make_ewf2_descriptor, make_ewf2_file_header,
    EVF2_SECTION_TYPE_DONE, EVF2_SECTION_TYPE_MD5_HASH,
};
use ewf_forensic::{EwfIntegrityAnomaly, EwfIntegrityPath};
use std::path::PathBuf;

/// Build a minimal valid EWF v2 segment with the given segment number.
///
/// Layout: [file_header_32][md5_body_16][md5_desc_64][done_desc_64]
fn make_ewf2_segment(segment_number: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&make_ewf2_file_header(segment_number));
    // MD5 hash body (16 zero bytes)
    buf.extend_from_slice(&[0u8; 16]);
    let md5_desc_off = buf.len() as u64;
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_MD5_HASH, 0, 0, 16, [0u8; 16],
    ));
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_DONE, 0, md5_desc_off, 0, [0u8; 16],
    ));
    buf
}

fn write_temp_file(dir: &std::path::Path, name: &str, data: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, data).expect("write temp file");
    path
}

/// EwfIntegrityPath::from_path(ev.Ex01) must automatically discover ev.Ex02
/// and include it in the analysis. ev.Ex02 has segment_number=999 (wrong),
/// which must produce SegmentOutOfOrder { segment_number: 999, expected: 2 }.
#[test]
fn ewf2_ex_prefix_sibling_discovery_detects_wrong_segment_number() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Segment 1: valid
    let seg1 = make_ewf2_segment(1);
    let ex01_path = write_temp_file(dir.path(), "ev.Ex01", &seg1);

    // Segment 2: deliberately wrong segment_number so we can confirm it was found
    let seg2 = make_ewf2_segment(999);
    write_temp_file(dir.path(), "ev.Ex02", &seg2);

    let findings = EwfIntegrityPath::from_path(&ex01_path)
        .analyse()
        .expect("analyse");

    assert!(
        findings.iter().any(|a| matches!(
            a,
            EwfIntegrityAnomaly::SegmentOutOfOrder { segment_number: 999, .. }
        )),
        "ev.Ex02 with segment_number=999 must be discovered and produce \
         SegmentOutOfOrder{{segment_number:999,expected:2}}; got: {findings:#?}"
    );
}

/// EwfIntegrityPath::from_path(ev.Ex01) must NOT discover ev.E02 (different
/// extension family) as a sibling.
#[test]
fn ewf2_ex_prefix_does_not_discover_e02_sibling() {
    let dir = tempfile::tempdir().expect("tempdir");

    let seg1 = make_ewf2_segment(1);
    let ex01_path = write_temp_file(dir.path(), "ev.Ex01", &seg1);

    // Plain .E02 file present — should NOT be auto-discovered
    let seg2 = make_ewf2_segment(999);
    write_temp_file(dir.path(), "ev.E02", &seg2);

    let findings = EwfIntegrityPath::from_path(&ex01_path)
        .analyse()
        .expect("analyse");

    // If E02 were wrongly discovered, we'd see SegmentOutOfOrder for 999
    assert!(
        !findings.iter().any(|a| matches!(
            a,
            EwfIntegrityAnomaly::SegmentOutOfOrder { segment_number: 999, .. }
        )),
        "ev.E02 must NOT be discovered as a sibling of ev.Ex01; got: {findings:#?}"
    );
}

//! RED phase — TableChunkCountMismatch for multi-segment EWF v1 images.
//!
//! For single-segment images the check already works.  For multi-segment images
//! the analyser must sum each segment's table entry_count and compare the total
//! against `volume.chunk_count`.
//!
//! Currently RED: `analyse_all_ewf1_with_progress` only checks the count for
//! `!multi && idx == 0`, so multi-segment mismatches are silently ignored.

mod builder;
use builder::E01Builder;
use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly};
use md5::{Digest as _, Md5};

const CHUNK_SIZE: usize = 64 * 512; // 32 768 bytes

fn two_segment_clean() -> (Vec<u8>, Vec<u8>) {
    let seg1 = E01Builder::new(CHUNK_SIZE as u64)
        .with_nonfinal()
        .with_volume_chunk_count(2)
        .with_volume_sector_count(128)
        .build();
    let combined_md5: [u8; 16] = Md5::digest(&vec![0u8; CHUNK_SIZE * 2]).into();
    let seg2 = E01Builder::new(CHUNK_SIZE as u64)
        .with_segment_number(2)
        .with_omit_volume()
        .with_md5(combined_md5)
        .build();
    (seg1, seg2)
}

/// Baseline: a clean two-segment image must not emit TableChunkCountMismatch.
#[test]
fn multi_segment_clean_no_chunk_count_mismatch() {
    let (seg1, seg2) = two_segment_clean();
    let findings = EwfIntegrity::from_segments(&[&seg1, &seg2]).analyse();
    assert!(
        !findings.iter().any(|a| matches!(a, EwfIntegrityAnomaly::TableChunkCountMismatch { .. })),
        "clean two-segment image must not produce TableChunkCountMismatch; got: {findings:#?}"
    );
}

/// When volume.chunk_count claims 3 but only 2 total table entries exist across
/// two segments, TableChunkCountMismatch must fire.
///
/// Currently RED: multi-segment mode skips the total-count comparison.
#[test]
fn multi_segment_volume_claims_more_chunks_than_tables() {
    // volume says 3 chunks total; tables together have only 2 entries
    let seg1 = E01Builder::new(CHUNK_SIZE as u64)
        .with_nonfinal()
        .with_volume_chunk_count(3) // WRONG — overstates the total
        .with_volume_sector_count(192)
        .build();
    let combined_md5: [u8; 16] = Md5::digest(&vec![0u8; CHUNK_SIZE * 2]).into();
    let seg2 = E01Builder::new(CHUNK_SIZE as u64)
        .with_segment_number(2)
        .with_omit_volume()
        .with_md5(combined_md5)
        .build();
    let findings = EwfIntegrity::from_segments(&[&seg1, &seg2]).analyse();
    assert!(
        findings.iter().any(|a| matches!(
            a,
            EwfIntegrityAnomaly::TableChunkCountMismatch { in_volume: 3, in_table: 2 }
        )),
        "volume claiming 3 chunks with only 2 in tables must fire TableChunkCountMismatch(3,2); got: {findings:#?}"
    );
}

/// When volume.chunk_count is less than the sum of table entries, the same
/// anomaly must fire (tampered table adds extra entries).
///
/// Currently RED: same root cause.
#[test]
fn multi_segment_tables_claim_more_chunks_than_volume() {
    let seg1 = E01Builder::new(CHUNK_SIZE as u64)
        .with_nonfinal()
        .with_volume_chunk_count(2)
        .with_volume_sector_count(128)
        .build();
    let combined_md5: [u8; 16] = Md5::digest(&vec![0u8; CHUNK_SIZE * 3]).into();
    // Segment 2 table says 2 entries (tampered), but volume only expected 1 more
    let seg2 = E01Builder::new(CHUNK_SIZE as u64)
        .with_segment_number(2)
        .with_omit_volume()
        .with_table_chunk_count(2) // tampered: 2 entries instead of 1
        .with_md5(combined_md5)
        .build();
    let findings = EwfIntegrity::from_segments(&[&seg1, &seg2]).analyse();
    assert!(
        findings.iter().any(|a| matches!(
            a,
            EwfIntegrityAnomaly::TableChunkCountMismatch { in_volume: 2, in_table: 3 }
        )),
        "tampered segment 2 table (2 entries) with volume=2 total must fire TableChunkCountMismatch(2,3); got: {findings:#?}"
    );
}

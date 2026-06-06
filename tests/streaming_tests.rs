//! RED phase — streaming/mmap path-based API.
//!
//! Tests fail until EwfIntegrityPath is introduced and memmap2 is wired up.
mod builder;

use builder::E01Builder;
use ewf_forensic::{EwfIntegrityAnomaly, EwfIntegrityPath, Severity};
use md5::{Digest as _, Md5};
use std::io::Write as _;
use tempfile::NamedTempFile;

fn write_temp(data: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

// ── Single-segment, clean image ───────────────────────────────────────────────

#[test]
fn analyse_path_clean_no_anomalies() {
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data);
    let findings = EwfIntegrityPath::from_path(f.path()).analyse().unwrap();
    let errors: Vec<_> = findings
        .iter()
        .filter(|a| matches!(a.severity(), Severity::High | Severity::Critical))
        .collect();
    assert!(
        errors.is_empty(),
        "clean image via path must produce no Error/Critical; got: {errors:#?}"
    );
}

// ── Single-segment, hash mismatch detected from file ─────────────────────────

#[test]
fn analyse_path_hash_mismatch_detected() {
    let data = E01Builder::new(512 * 64).with_md5([0xBAu8; 16]).build();
    let f = write_temp(&data);
    let findings = EwfIntegrityPath::from_path(f.path()).analyse().unwrap();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::HashMismatch { .. })),
        "expected HashMismatch from path-based analysis; got: {findings:#?}"
    );
}

// ── Non-existent path returns Err ─────────────────────────────────────────────

#[test]
fn analyse_path_missing_file_returns_err() {
    let result =
        EwfIntegrityPath::from_path(std::path::Path::new("/nonexistent/evidence.E01")).analyse();
    assert!(result.is_err(), "missing file must return Err");
}

// ── Multi-segment via from_paths ──────────────────────────────────────────────

#[test]
fn analyse_paths_two_segments_clean() {
    let chunk_size: usize = 64 * 512;

    let seg1 = E01Builder::new(chunk_size as u64)
        .with_nonfinal()
        .with_volume_chunk_count(2)
        .with_volume_sector_count(128)
        .build();

    let combined_md5: [u8; 16] = Md5::digest(&vec![0u8; chunk_size * 2]).into();

    let seg2 = E01Builder::new(chunk_size as u64)
        .with_segment_number(2)
        .with_omit_volume()
        .with_md5(combined_md5)
        .build();

    let f1 = write_temp(&seg1);
    let f2 = write_temp(&seg2);

    let findings = EwfIntegrityPath::from_paths(&[f1.path(), f2.path()])
        .analyse()
        .unwrap();
    let errors: Vec<_> = findings
        .iter()
        .filter(|a| matches!(a.severity(), Severity::High | Severity::Critical))
        .collect();
    assert!(
        errors.is_empty(),
        "clean two-segment image via paths must produce no Error/Critical; got: {errors:#?}"
    );
}

// ── Auto-discovery: from_path on E01 finds E02 sibling ───────────────────────

#[test]
fn analyse_path_auto_discovers_e02_sibling() {
    let chunk_size: usize = 64 * 512;

    let seg1_data = E01Builder::new(chunk_size as u64)
        .with_nonfinal()
        .with_volume_chunk_count(2)
        .with_volume_sector_count(128)
        .build();

    let combined_md5: [u8; 16] = Md5::digest(&vec![0u8; chunk_size * 2]).into();
    let seg2_data = E01Builder::new(chunk_size as u64)
        .with_segment_number(2)
        .with_omit_volume()
        .with_md5(combined_md5)
        .build();

    // Write to a named temp dir so extensions are controlled
    let dir = tempfile::tempdir().unwrap();
    let e01 = dir.path().join("evidence.E01");
    let e02 = dir.path().join("evidence.E02");
    std::fs::write(&e01, &seg1_data).unwrap();
    std::fs::write(&e02, &seg2_data).unwrap();

    // Point at E01 only — analyser must auto-discover E02
    let findings = EwfIntegrityPath::from_path(&e01).analyse().unwrap();
    let errors: Vec<_> = findings
        .iter()
        .filter(|a| matches!(a.severity(), Severity::High | Severity::Critical))
        .collect();
    assert!(
        errors.is_empty(),
        "auto-discovered two-segment image must be clean; got: {errors:#?}"
    );
}

// ── External MD5 via path ─────────────────────────────────────────────────────

#[test]
fn analyse_path_with_expected_md5_mismatch() {
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data);
    let findings = EwfIntegrityPath::from_path(f.path())
        .with_expected_md5([0xFFu8; 16])
        .analyse()
        .unwrap();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalMd5Mismatch { .. })),
        "expected ExternalMd5Mismatch from path analysis; got: {findings:#?}"
    );
}

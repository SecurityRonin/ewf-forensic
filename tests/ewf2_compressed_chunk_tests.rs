//! RED phase — EWF v2 compressed chunk decompression.
//!
//! Fixture: tests/fixtures/zeros_128s_compressed.Ex01
//!   Created by Python's zlib.compress(level=1), validated by ewfverify.
//!   2 chunks of 64 sectors × 512 bytes = 65536 bytes total, all zeros.
//!
//! ewfverify-confirmed ground truth (independent oracle):
//!   MD5    : fcd6bcb56c1689fcef28b57c22475bad
//!   SHA-1  : 1adc95bebe9eea8c112d40cd04ab7a8d75c4f961
//!   SHA-256: de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31

use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly, EwfIntegrityPath};
use std::path::PathBuf;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/zeros_128s_compressed.Ex01")
}

fn fixture_bytes() -> Vec<u8> {
    let p = fixture_path();
    if !p.exists() { return vec![]; }
    std::fs::read(&p).expect("read fixture")
}

fn skip_if_missing(data: &[u8]) -> bool {
    if data.is_empty() {
        eprintln!("skipping: fixture not found");
        true
    } else {
        false
    }
}

// ── Clean analysis: zero anomalies ────────────────────────────────────────────

/// A valid compressed EWF v2 image must analyse with zero anomalies.
#[test]
fn ewf2_compressed_clean_no_anomalies() {
    let data = fixture_bytes();
    if skip_if_missing(&data) { return; }
    let findings = EwfIntegrity::new(&data).analyse();
    let errors: Vec<_> = findings
        .iter()
        .filter(|a| {
            !matches!(
                a,
                EwfIntegrityAnomaly::Ewf2MediaInfoMissing
                    | EwfIntegrityAnomaly::HashSectionMissing
            )
        })
        .collect();
    assert!(
        errors.is_empty(),
        "clean compressed EWF v2 must produce no anomalies; got: {findings:#?}"
    );
}

// ── Hash computation via EwfIntegrity::new ────────────────────────────────────

/// compute_hashes() must decompress chunks and return the correct MD5.
#[test]
fn ewf2_compressed_compute_hashes_md5() {
    let data = fixture_bytes();
    if skip_if_missing(&data) { return; }
    let hashes = EwfIntegrity::new(&data).compute_hashes()
        .expect("compute_hashes must return Some for a valid compressed image");
    let expected = hex_to_16("fcd6bcb56c1689fcef28b57c22475bad");
    assert_eq!(
        hashes.md5, expected,
        "MD5 after decompression must match ewfverify ground truth"
    );
}

/// compute_hashes() must return the correct SHA-1 after decompression.
#[test]
fn ewf2_compressed_compute_hashes_sha1() {
    let data = fixture_bytes();
    if skip_if_missing(&data) { return; }
    let hashes = EwfIntegrity::new(&data).compute_hashes()
        .expect("compute_hashes must return Some");
    let expected = hex_to_20("1adc95bebe9eea8c112d40cd04ab7a8d75c4f961");
    assert_eq!(
        hashes.sha1, expected,
        "SHA-1 after decompression must match ewfverify ground truth"
    );
}

/// compute_hashes() must return the correct SHA-256 after decompression.
#[test]
fn ewf2_compressed_compute_hashes_sha256() {
    let data = fixture_bytes();
    if skip_if_missing(&data) { return; }
    let hashes = EwfIntegrity::new(&data).compute_hashes()
        .expect("compute_hashes must return Some");
    let expected = hex_to_32("de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31");
    assert_eq!(
        hashes.sha256, expected,
        "SHA-256 after decompression must match ewfverify ground truth"
    );
}

// ── External hash checks via EwfIntegrityPath ─────────────────────────────────

/// with_expected_md5 on a compressed image must NOT produce mismatch when hash is correct.
#[test]
fn ewf2_compressed_path_correct_md5_no_mismatch() {
    let path = fixture_path();
    if !path.exists() { return; }
    let findings = EwfIntegrityPath::from_path(&path)
        .with_expected_md5(hex_to_16("fcd6bcb56c1689fcef28b57c22475bad"))
        .analyse()
        .expect("analyse");
    assert!(
        !findings.iter().any(|a| matches!(a, EwfIntegrityAnomaly::ExternalMd5Mismatch { .. })),
        "correct MD5 must not trigger ExternalMd5Mismatch; got: {findings:#?}"
    );
}

/// with_expected_md5 wrong value must produce ExternalMd5Mismatch even for compressed images.
#[test]
fn ewf2_compressed_path_wrong_md5_mismatch() {
    let path = fixture_path();
    if !path.exists() { return; }
    let findings = EwfIntegrityPath::from_path(&path)
        .with_expected_md5([0xBAu8; 16])
        .analyse()
        .expect("analyse");
    assert!(
        findings.iter().any(|a| matches!(a, EwfIntegrityAnomaly::ExternalMd5Mismatch { .. })),
        "wrong MD5 must trigger ExternalMd5Mismatch; got: {findings:#?}"
    );
}

// ── Corrupt compressed data → ChunkDecompressionError ─────────────────────────

/// Flipping a byte inside the compressed chunk data must produce ChunkDecompressionError.
#[test]
fn ewf2_corrupt_compressed_chunk_detected() {
    let mut data = fixture_bytes();
    if skip_if_missing(&data) { return; }
    // Chunk 0 starts at file offset 464 (sector data body start).
    // Flip a byte well inside the compressed stream (avoid the zlib header).
    data[464 + 10] ^= 0xFF;
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        findings.iter().any(|a| matches!(a, EwfIntegrityAnomaly::ChunkDecompressionError { .. })),
        "corrupt compressed chunk must produce ChunkDecompressionError; got: {findings:#?}"
    );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn hex_to_16(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn hex_to_20(s: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

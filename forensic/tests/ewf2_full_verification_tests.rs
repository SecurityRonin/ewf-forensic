#![allow(clippy::unwrap_used, clippy::expect_used)]

//! RED phase — EWF v2 full verification: external hashes + chunk table checksum.
//!
//! Fixture: `tests/data/zeros_128s.Ex01`
//!   ewfverify MD5 : fcd6bcb56c1689fcef28b57c22475bad
//!   ewfverify SHA-1: 1adc95bebe9eea8c112d40cd04ab7a8d75c4f961
//!   ewfverify SHA-256: de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31
//!
//! Chunk table body layout (confirmed from fixture hex-dump):
//!   [0..32]   header (`chunk_count` u64 at [8..16])
//!   [32..64]  chunk entries (16 bytes each)
//!   [64..68]  Adler-32 of entries[32..64] (little-endian u32)
//!   [68..80]  zeros (padding)
//!   Chunk table section body starts at file offset 66096.

use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly, EwfIntegrityPath};
use std::path::PathBuf;

fn fixture_bytes() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/zeros_128s.Ex01");
    if !path.exists() {
        return vec![];
    }
    std::fs::read(&path).expect("read fixture")
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/zeros_128s.Ex01")
}

fn skip_if_empty(data: &[u8]) -> bool {
    if data.is_empty() {
        eprintln!("skipping: fixture not found");
        true
    } else {
        false
    }
}

fn hex16(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}
fn hex20(s: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}
fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

const CORRECT_MD5: &str = "fcd6bcb56c1689fcef28b57c22475bad";
const CORRECT_SHA1: &str = "1adc95bebe9eea8c112d40cd04ab7a8d75c4f961";
const CORRECT_SHA256: &str = "de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31";

// ── External MD5 reference hash ───────────────────────────────────────────────

#[test]
fn ewf2_ex01_external_md5_wrong_detected() {
    let data = fixture_bytes();
    if skip_if_empty(&data) {
        return;
    }
    let findings = EwfIntegrity::new(&data)
        .with_expected_md5([0xBAu8; 16])
        .analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalMd5Mismatch { .. })),
        "wrong expected MD5 must produce ExternalMd5Mismatch; got: {findings:#?}"
    );
}

#[test]
fn ewf2_ex01_external_md5_correct_no_mismatch() {
    let data = fixture_bytes();
    if skip_if_empty(&data) {
        return;
    }
    let findings = EwfIntegrity::new(&data)
        .with_expected_md5(hex16(CORRECT_MD5))
        .analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalMd5Mismatch { .. })),
        "correct expected MD5 must not produce ExternalMd5Mismatch; got: {findings:#?}"
    );
}

// ── External SHA-1 reference hash ─────────────────────────────────────────────

#[test]
fn ewf2_ex01_external_sha1_wrong_detected() {
    let data = fixture_bytes();
    if skip_if_empty(&data) {
        return;
    }
    let findings = EwfIntegrity::new(&data)
        .with_expected_sha1([0xBAu8; 20])
        .analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalSha1Mismatch { .. })),
        "wrong expected SHA-1 must produce ExternalSha1Mismatch; got: {findings:#?}"
    );
}

#[test]
fn ewf2_ex01_external_sha1_correct_no_mismatch() {
    let data = fixture_bytes();
    if skip_if_empty(&data) {
        return;
    }
    let findings = EwfIntegrity::new(&data)
        .with_expected_sha1(hex20(CORRECT_SHA1))
        .analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalSha1Mismatch { .. })),
        "correct expected SHA-1 must not produce ExternalSha1Mismatch; got: {findings:#?}"
    );
}

// ── External SHA-256 reference hash ───────────────────────────────────────────

#[test]
fn ewf2_ex01_external_sha256_wrong_detected() {
    let data = fixture_bytes();
    if skip_if_empty(&data) {
        return;
    }
    let findings = EwfIntegrity::new(&data)
        .with_expected_sha256([0xBAu8; 32])
        .analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalSha256Mismatch { .. })),
        "wrong expected SHA-256 must produce ExternalSha256Mismatch; got: {findings:#?}"
    );
}

#[test]
fn ewf2_ex01_external_sha256_correct_no_mismatch() {
    let data = fixture_bytes();
    if skip_if_empty(&data) {
        return;
    }
    let findings = EwfIntegrity::new(&data)
        .with_expected_sha256(hex32(CORRECT_SHA256))
        .analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalSha256Mismatch { .. })),
        "correct expected SHA-256 must not produce ExternalSha256Mismatch; got: {findings:#?}"
    );
}

// ── EwfIntegrityPath external hash (real file) ────────────────────────────────

#[test]
fn ewf2_integrity_path_external_md5_wrong_detected() {
    let path = fixture_path();
    if !path.exists() {
        return;
    }
    let findings = EwfIntegrityPath::from_path(&path)
        .with_expected_md5([0xFFu8; 16])
        .analyse()
        .expect("analyse");
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalMd5Mismatch { .. })),
        "EwfIntegrityPath: wrong expected MD5 must produce ExternalMd5Mismatch; got: {findings:#?}"
    );
}

// ── Chunk table Adler-32 checksum ─────────────────────────────────────────────
//
// Chunk table body in zeros_128s.Ex01:
//   File offset 66096..66176 (80 bytes)
//   Entries at body[32..64]
//   Checksum (Adler-32 of entries) stored at body[64..68] = file[66160..66164]

fn fixture_with_tampered_chunk_table_checksum() -> Vec<u8> {
    let mut data = fixture_bytes();
    if data.is_empty() {
        return data;
    }
    // Corrupt the first byte of the Adler-32 checksum in the chunk table body.
    // Chunk table body at file offset 66096; checksum at body offset 64 → file offset 66160.
    data[66160] ^= 0xFF;
    data
}

#[test]
fn ewf2_chunk_table_checksum_mismatch_detected() {
    let data = fixture_with_tampered_chunk_table_checksum();
    if skip_if_empty(&data) {
        return;
    }
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        findings.iter().any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2ChunkTableChecksumMismatch { .. })),
        "corrupted chunk table checksum must produce Ewf2ChunkTableChecksumMismatch; got: {findings:#?}"
    );
}

#[test]
fn ewf2_chunk_table_checksum_correct_no_anomaly() {
    let data = fixture_bytes();
    if skip_if_empty(&data) {
        return;
    }
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        !findings.iter().any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2ChunkTableChecksumMismatch { .. })),
        "valid chunk table checksum must not produce Ewf2ChunkTableChecksumMismatch; got: {findings:#?}"
    );
}

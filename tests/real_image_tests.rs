#![allow(clippy::unwrap_used, clippy::expect_used)]

// Integration tests against the three small E01 fixtures committed to
// tests/data/. They run in CI on every push.
//
// Ground truth MD5/SHA-1 values come from:
//   ewfverify -q tests/data/<name>.E01
// which is the reference implementation for EWF integrity verification.

use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly, Severity};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).expect("read fixture")
}

fn assert_no_errors(name: &str) {
    let data = fixture(name);
    let findings = EwfIntegrity::new(&data).analyse();
    let errors: Vec<_> = findings
        .iter()
        .filter(|a| matches!(a.severity(), Severity::High | Severity::Critical))
        .collect();
    assert!(
        errors.is_empty(),
        "unexpected Error/Critical findings in {name}:\n{errors:#?}"
    );
}

fn hex_md5(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn hex_sha1(s: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn hex_sha256(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

// ── Structural sanity ─────────────────────────────────────────────────────────

#[test]
fn exfat1_no_error_findings() {
    assert_no_errors("exfat1.E01");
}

#[test]
fn nps_2010_emails_no_error_findings() {
    assert_no_errors("nps-2010-emails.E01");
}

#[test]
fn imageformat_mmls_1_no_error_findings() {
    assert_no_errors("imageformat_mmls_1.E01");
}

// ── Pinned-hash verification against ewfverify ground truth ───────────────────
//
// These tests prove the decompression + hashing path produces byte-exact
// results matching the libewf reference implementation.
//
// ewfverify output (run 2026-05-14):
//   exfat1.E01           MD5: 0777ee90c27ed5ff5868af2015bed635
//   nps-2010-emails.E01  MD5: 7dae50cec8163697415e69fd72387c01
//   imageformat_mmls_1   MD5: 8ec671e301095c258224aad701740503
//                        SHA1: 067bc6ab29685ee19b0cf82c9d15ac510d1e7d95

#[test]
fn exfat1_computed_md5_matches_ewfverify() {
    let data = fixture("exfat1.E01");
    let expected = hex_md5("0777ee90c27ed5ff5868af2015bed635");
    let findings = EwfIntegrity::new(&data)
        .with_expected_md5(expected)
        .analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalMd5Mismatch { .. })),
        "computed MD5 must match ewfverify ground truth for exfat1.E01;\
         got: {findings:#?}"
    );
}

#[test]
fn nps_emails_computed_md5_matches_ewfverify() {
    let data = fixture("nps-2010-emails.E01");
    let expected = hex_md5("7dae50cec8163697415e69fd72387c01");
    let findings = EwfIntegrity::new(&data)
        .with_expected_md5(expected)
        .analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalMd5Mismatch { .. })),
        "computed MD5 must match ewfverify ground truth for nps-2010-emails.E01;\
         got: {findings:#?}"
    );
}

#[test]
fn mmls_computed_md5_matches_ewfverify() {
    let data = fixture("imageformat_mmls_1.E01");
    let expected = hex_md5("8ec671e301095c258224aad701740503");
    let findings = EwfIntegrity::new(&data)
        .with_expected_md5(expected)
        .analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalMd5Mismatch { .. })),
        "computed MD5 must match ewfverify ground truth for imageformat_mmls_1.E01;\
         got: {findings:#?}"
    );
}

#[test]
fn mmls_computed_sha1_matches_ewfverify() {
    let data = fixture("imageformat_mmls_1.E01");
    let expected = hex_sha1("067bc6ab29685ee19b0cf82c9d15ac510d1e7d95");
    let findings = EwfIntegrity::new(&data)
        .with_expected_sha1(expected)
        .analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalSha1Mismatch { .. })),
        "computed SHA-1 must match ewfverify ground truth for imageformat_mmls_1.E01;\
         got: {findings:#?}"
    );
}

// ── Tamper detection: modified sectors body triggers HashMismatch ─────────────
//
// Locates the "sectors" section descriptor by scanning for the magic string,
// then flips one byte in the body. Any modification to compressed chunk data
// causes either a decompression error or a changed MD5, both of which surface
// as HashMismatch.

fn find_sectors_body_start(data: &[u8]) -> Option<usize> {
    const SECTION_DESCRIPTOR_SIZE: usize = 76;
    for i in 0..data.len().saturating_sub(SECTION_DESCRIPTOR_SIZE) {
        if data[i..].starts_with(b"sectors\0") {
            return Some(i + SECTION_DESCRIPTOR_SIZE);
        }
    }
    None
}

#[test]
fn exfat1_sectors_tamper_triggers_hash_mismatch() {
    let mut data = fixture("exfat1.E01");
    let body_start = find_sectors_body_start(&data)
        .expect("sectors section not found in exfat1.E01");
    data[body_start + 16] ^= 0xFF;
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::HashMismatch { .. })),
        "flipped byte in sectors body must produce HashMismatch; got: {findings:#?}"
    );
}

#[test]
fn nps_emails_sectors_tamper_triggers_hash_mismatch() {
    let mut data = fixture("nps-2010-emails.E01");
    let body_start = find_sectors_body_start(&data)
        .expect("sectors section not found in nps-2010-emails.E01");
    data[body_start + 16] ^= 0xFF;
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::HashMismatch { .. })),
        "flipped byte in sectors body must produce HashMismatch; got: {findings:#?}"
    );
}

// ── Per-chunk Adler-32: clean real fixtures produce no false positives ─────────
//
// ewfverify confirms all three fixtures are clean. After implementing
// per-chunk checksum verification, these must not produce ChunkChecksumMismatch.

#[test]
fn exfat1_no_chunk_checksum_mismatch() {
    let data = fixture("exfat1.E01");
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ChunkChecksumMismatch { .. })),
        "clean exfat1.E01 must not produce ChunkChecksumMismatch; got: {findings:#?}"
    );
}

#[test]
fn nps_emails_no_chunk_checksum_mismatch() {
    let data = fixture("nps-2010-emails.E01");
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ChunkChecksumMismatch { .. })),
        "clean nps-2010-emails.E01 must not produce ChunkChecksumMismatch; got: {findings:#?}"
    );
}

#[test]
fn mmls_no_chunk_checksum_mismatch() {
    let data = fixture("imageformat_mmls_1.E01");
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ChunkChecksumMismatch { .. })),
        "clean imageformat_mmls_1.E01 must not produce ChunkChecksumMismatch; got: {findings:#?}"
    );
}

// ── SHA-256 pinned against ewfverify ground truth ─────────────────────────────
//
// ewfverify -d sha256 -q tests/data/<name>.E01 (run 2026-05-14):
//   exfat1.E01          af6f974495187c35050d5c66d271617a1ec00d446adcf8590d7042ad2bf02bb7
//   nps-2010-emails.E01 ed4e1b20fb92d9609778d6f687ef478c2ed88d7da18f98b8b023f3dfecd41a9d
//   imageformat_mmls_1  e7eb6fca46bebeedc4af4cc5bfe9675691bab8ce471315317b561a28899e7902
//
// EWF v1 images do not store SHA-256; ewfverify computes it over sector data.

#[test]
fn exfat1_computed_sha256_matches_ewfverify() {
    let data = fixture("exfat1.E01");
    let expected = hex_sha256(
        "af6f974495187c35050d5c66d271617a1ec00d446adcf8590d7042ad2bf02bb7",
    );
    let findings = EwfIntegrity::new(&data)
        .with_expected_sha256(expected)
        .analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalSha256Mismatch { .. })),
        "computed SHA-256 must match ewfverify ground truth for exfat1.E01;\
         got: {findings:#?}"
    );
}

#[test]
fn nps_emails_computed_sha256_matches_ewfverify() {
    let data = fixture("nps-2010-emails.E01");
    let expected = hex_sha256(
        "ed4e1b20fb92d9609778d6f687ef478c2ed88d7da18f98b8b023f3dfecd41a9d",
    );
    let findings = EwfIntegrity::new(&data)
        .with_expected_sha256(expected)
        .analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalSha256Mismatch { .. })),
        "computed SHA-256 must match ewfverify ground truth for nps-2010-emails.E01;\
         got: {findings:#?}"
    );
}

#[test]
fn mmls_computed_sha256_matches_ewfverify() {
    let data = fixture("imageformat_mmls_1.E01");
    let expected = hex_sha256(
        "e7eb6fca46bebeedc4af4cc5bfe9675691bab8ce471315317b561a28899e7902",
    );
    let findings = EwfIntegrity::new(&data)
        .with_expected_sha256(expected)
        .analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalSha256Mismatch { .. })),
        "computed SHA-256 must match ewfverify ground truth for imageformat_mmls_1.E01;\
         got: {findings:#?}"
    );
}

// ── ChunkDecompressionError: corrupt zlib data is localised ──────────────────
//
// When a compressed chunk's zlib stream is undecodable, silently skipping
// produces HashMismatch with no indication of which chunk is corrupt.
// ChunkDecompressionError must fire with the chunk index.
//
// Chunk 0 of exfat1.E01 starts at sectors body_start (first table entry
// rel=76 = SECTION_DESCRIPTOR_SIZE, so abs = sectors_offset + 76 = body_start).
// Flipping byte 4 of the stream corrupts the DEFLATE data past the zlib header.

#[test]
fn corrupt_zlib_chunk_produces_decompression_error_anomaly() {
    let mut data = fixture("exfat1.E01");
    let body_start = find_sectors_body_start(&data)
        .expect("sectors section not found in exfat1.E01");
    // Offset +4: past the 2-byte zlib CMF/FLG header, into the DEFLATE stream.
    data[body_start + 4] ^= 0xFF;
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ChunkDecompressionError { .. })),
        "corrupt DEFLATE stream must produce ChunkDecompressionError; got: {findings:#?}"
    );
}

#[test]
fn chunk_decompression_error_includes_chunk_index() {
    let mut data = fixture("exfat1.E01");
    let body_start = find_sectors_body_start(&data)
        .expect("sectors section not found");
    data[body_start + 4] ^= 0xFF;
    let findings = EwfIntegrity::new(&data).analyse();
    let anomaly = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::ChunkDecompressionError { .. }))
        .expect("ChunkDecompressionError must be present");
    // Chunk 0 is the first chunk — index must be 0.
    assert!(
        matches!(anomaly, EwfIntegrityAnomaly::ChunkDecompressionError { chunk_index: 0 }),
        "corrupt chunk 0 must report chunk_index=0; got: {anomaly:?}"
    );
}

#[test]
fn chunk_decompression_error_is_error_severity() {
    use ewf_forensic::Severity;
    let mut data = fixture("exfat1.E01");
    let body_start = find_sectors_body_start(&data)
        .expect("sectors section not found");
    data[body_start + 4] ^= 0xFF;
    let findings = EwfIntegrity::new(&data).analyse();
    let anomaly = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::ChunkDecompressionError { .. }))
        .expect("ChunkDecompressionError must be present");
    assert_eq!(anomaly.severity(), Severity::High);
}

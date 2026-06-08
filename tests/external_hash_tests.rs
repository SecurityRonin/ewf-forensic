#![allow(clippy::unwrap_used, clippy::expect_used)]

mod builder;
use builder::E01Builder;

use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly, EwfIntegrityPath};
use std::io::Write as _;
use std::process::Command;
use tempfile::NamedTempFile;

fn write_temp(data: &[u8], suffix: &str) -> NamedTempFile {
    let mut f = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

fn ewf_check() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ewf-check"))
}

// ── EwfIntegrityPath::with_expected_sha256 ────────────────────────────────────

/// `EwfIntegrityPath` must expose `with_expected_sha256`, parity with `EwfIntegrity`.
#[test]
fn ewf_integrity_path_with_expected_sha256_clean_returns_no_mismatch() {
    // Build a single-chunk image and compute the sha256 of its sector data.
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data, ".E01");

    // Get what the library actually computes for this image's sector data
    let findings_without = EwfIntegrity::new(&data).analyse();
    assert!(
        findings_without.is_empty(),
        "builder should produce clean image: {findings_without:#?}"
    );

    // with_expected_sha256 on EwfIntegrityPath should work without panicking
    // (we can't easily know the correct hash without running the verifier,
    //  so we use a wrong hash and assert that it produces ExternalSha256Mismatch)
    let wrong_sha256 = [0xFFu8; 32];
    let checker = EwfIntegrityPath::from_path(f.path()).with_expected_sha256(wrong_sha256);
    let findings = checker.analyse().expect("analyse should not error");
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalSha256Mismatch { .. })),
        "wrong sha256 must produce ExternalSha256Mismatch; got: {findings:#?}"
    );
}

#[test]
fn ewf_integrity_path_with_correct_sha256_produces_no_mismatch() {
    // Use EwfIntegrity to first find what hash the library computes, then
    // feed that hash back via EwfIntegrityPath::with_expected_sha256.
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data, ".E01");

    // The builder creates a known-good image. Run once to collect computed sha256.
    // We extract it from the ExternalSha256Mismatch anomaly computed field using a sentinel.
    let sentinel = [0xEEu8; 32];
    let findings = EwfIntegrity::new(&data)
        .with_expected_sha256(sentinel)
        .analyse();
    let computed = findings
        .iter()
        .find_map(|a| {
            if let EwfIntegrityAnomaly::ExternalSha256Mismatch { computed, .. } = a {
                Some(*computed)
            } else {
                None
            }
        })
        .expect("sentinel mismatch should appear");

    // Now verify with the correct hash via EwfIntegrityPath
    let checker = EwfIntegrityPath::from_path(f.path()).with_expected_sha256(computed);
    let findings = checker.analyse().expect("analyse should not error");
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::ExternalSha256Mismatch { .. })),
        "correct sha256 must not produce mismatch; got: {findings:#?}"
    );
}

// ── CLI --hash-sha256 flag ────────────────────────────────────────────────────

#[test]
fn cli_hash_sha256_wrong_exits_one_with_mismatch() {
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data, ".E01");
    let wrong = "ff".repeat(32); // 64 hex chars = 32 bytes
    let out = ewf_check()
        .arg(format!("--hash-sha256={wrong}"))
        .arg(f.path())
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "--hash-sha256 with wrong hash must exit 1"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.to_lowercase().contains("sha-256") || stdout.contains("ExternalSha256"),
        "must mention SHA-256 mismatch; got: {stdout}"
    );
}

#[test]
fn cli_hash_sha256_invalid_hex_exits_two() {
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data, ".E01");
    let out = ewf_check()
        .arg("--hash-sha256=not-hex")
        .arg(f.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "invalid hex must exit 2");
}

#[test]
fn cli_hash_sha256_wrong_length_exits_two() {
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data, ".E01");
    let too_short = "aabb"; // only 2 bytes
    let out = ewf_check()
        .arg(format!("--hash-sha256={too_short}"))
        .arg(f.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "wrong-length hash must exit 2");
}

// ── CLI --hash-md5 flag ───────────────────────────────────────────────────────

#[test]
fn cli_hash_md5_wrong_exits_one() {
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data, ".E01");
    let wrong = "ff".repeat(16); // 32 hex = 16 bytes
    let out = ewf_check()
        .arg(format!("--hash-md5={wrong}"))
        .arg(f.path())
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "--hash-md5 mismatch must exit 1"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.to_lowercase().contains("md5") || stdout.contains("ExternalMd5"),
        "must mention MD5: {stdout}"
    );
}

// ── CLI --hash-sha1 flag ──────────────────────────────────────────────────────

#[test]
fn cli_hash_sha1_wrong_exits_one() {
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data, ".E01");
    let wrong = "ff".repeat(20); // 40 hex = 20 bytes
    let out = ewf_check()
        .arg(format!("--hash-sha1={wrong}"))
        .arg(f.path())
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "--hash-sha1 mismatch must exit 1"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.to_lowercase().contains("sha") || stdout.contains("ExternalSha1"),
        "must mention SHA-1: {stdout}"
    );
}

// ── --json combines correctly with --hash-sha256 ──────────────────────────────

#[test]
fn cli_json_with_hash_sha256_mismatch_reports_kind() {
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data, ".E01");
    let wrong = "ff".repeat(32);
    let out = ewf_check()
        .arg("--json")
        .arg(format!("--hash-sha256={wrong}"))
        .arg(f.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stdout.contains("ExternalSha256Mismatch"),
        "JSON must name kind: {stdout}"
    );
}

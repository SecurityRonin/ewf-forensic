#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Real EWF v2 fixture tests — zeros_128s.Ex01 created by libewf ewfacquirestream.
//!
//! Fixture: tests/data/zeros_128s.Ex01
//!   Created with: dd if=/dev/zero bs=512 count=128 | ewfacquirestream -f encase7-v2 -d sha1 -d sha256 -t /tmp/test_ex01
//!   ewfverify reports: MD5=fcd6bcb56c1689fcef28b57c22475bad, SHA256=de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31
//!   ewfverify exits: SUCCESS

use ewf_forensic::{ComputedHashes, EwfIntegrityAnomaly, EwfIntegrityPath, Severity};
use std::path::PathBuf;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/zeros_128s.Ex01")
}

// ── Clean real Ex01: no hash-section-missing warning ─────────────────────────

#[test]
fn real_ex01_no_hash_section_missing() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("skipping: fixture not found at {}", path.display());
        return;
    }
    let findings = EwfIntegrityPath::from_path(&path)
        .analyse()
        .expect("analyse must succeed");
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2HashSectionMissing)),
        "valid Ex01 must not produce Ewf2HashSectionMissing; anomalies: {findings:#?}"
    );
}

// ── Clean real Ex01: no media-info-missing warning ────────────────────────────

#[test]
fn real_ex01_no_media_info_missing() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("skipping: fixture not found at {}", path.display());
        return;
    }
    let findings = EwfIntegrityPath::from_path(&path)
        .analyse()
        .expect("analyse must succeed");
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2MediaInfoMissing)),
        "valid Ex01 must not produce Ewf2MediaInfoMissing; anomalies: {findings:#?}"
    );
}

// ── Clean real Ex01: only Info-level anomalies (no warnings/errors) ───────────

#[test]
fn real_ex01_no_warning_or_error_anomalies() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("skipping: fixture not found at {}", path.display());
        return;
    }
    let findings = EwfIntegrityPath::from_path(&path)
        .analyse()
        .expect("analyse must succeed");
    let non_info: Vec<_> = findings
        .iter()
        .filter(|a| a.severity() != Severity::Info)
        .collect();
    assert!(
        non_info.is_empty(),
        "valid Ex01 must produce only Info anomalies; got: {non_info:#?}"
    );
}

// ── Fully-verified real Ex01: zero anomalies ─────────────────────────────────

#[test]
fn real_ex01_zero_anomalies() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("skipping: fixture not found at {}", path.display());
        return;
    }
    let findings = EwfIntegrityPath::from_path(&path)
        .analyse()
        .expect("analyse must succeed");
    assert!(
        findings.is_empty(),
        "fully-verified clean Ex01 must produce zero anomalies; got: {findings:#?}"
    );
}

// ── compute_hashes() works for EWF v2 ────────────────────────────────────────

#[test]
fn real_ex01_compute_hashes_returns_some() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("skipping: fixture not found at {}", path.display());
        return;
    }
    let result: Option<ComputedHashes> = EwfIntegrityPath::from_path(&path)
        .compute_hashes()
        .expect("compute_hashes must not fail");
    assert!(
        result.is_some(),
        "compute_hashes() must return Some for a valid Ex01; got None"
    );
}

#[test]
fn real_ex01_compute_hashes_md5_correct() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("skipping: fixture not found at {}", path.display());
        return;
    }
    let hashes = EwfIntegrityPath::from_path(&path)
        .compute_hashes()
        .expect("must not fail")
        .expect("must return Some");
    let expected_md5: [u8; 16] =
        hex_to_bytes("fcd6bcb56c1689fcef28b57c22475bad");
    assert_eq!(
        hashes.md5, expected_md5,
        "MD5 must match ewfverify-confirmed value"
    );
}

#[test]
fn real_ex01_compute_hashes_sha256_correct() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("skipping: fixture not found at {}", path.display());
        return;
    }
    let hashes = EwfIntegrityPath::from_path(&path)
        .compute_hashes()
        .expect("must not fail")
        .expect("must return Some");
    let expected_sha256: [u8; 32] =
        hex_to_bytes("de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31");
    assert_eq!(
        hashes.sha256, expected_sha256,
        "SHA-256 must match ewfverify-confirmed value"
    );
}

fn hex_to_bytes<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

// ── ewf-check exits 0 for clean real Ex01 (INFO only, no exit 1) ─────────────

#[test]
fn real_ex01_ewf_check_exits_zero() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("skipping: fixture not found at {}", path.display());
        return;
    }
    let bin = env!("CARGO_BIN_EXE_ewf-check");
    let out = std::process::Command::new(bin)
        .arg("--min-severity=warning")
        .arg(&path)
        .output()
        .expect("ewf-check must run");
    assert_eq!(
        out.status.code(),
        Some(0),
        "ewf-check --min-severity=warning must exit 0 for clean Ex01; stdout: {} stderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

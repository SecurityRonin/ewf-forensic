//! RED phase — real EWF v2 fixture created by libewf's ewfacquirestream.
//!
//! Fixture: tests/fixtures/zeros_128s.Ex01
//!   Created with: dd if=/dev/zero bs=512 count=128 | ewfacquirestream -f encase7-v2 -d sha1 -d sha256 -t /tmp/test_ex01
//!   ewfverify reports: MD5=fcd6bcb56c1689fcef28b57c22475bad, SHA256=de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31
//!   ewfverify exits: SUCCESS
//!
//! These tests fail until the EWF v2 section traversal is fixed to walk backward
//! from the DONE descriptor (file_end - 64) via prev_section_offset.

use ewf_forensic::{EwfIntegrityAnomaly, EwfIntegrityPath, Severity};
use std::path::PathBuf;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/zeros_128s.Ex01")
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

// ── Clean real Ex01: exactly Ewf2SectorDataNotVerified (the honest disclosure) ─

#[test]
fn real_ex01_exactly_sector_data_not_verified_info() {
    let path = fixture_path();
    if !path.exists() {
        eprintln!("skipping: fixture not found at {}", path.display());
        return;
    }
    let findings = EwfIntegrityPath::from_path(&path)
        .analyse()
        .expect("analyse must succeed");
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2SectorDataNotVerified)),
        "must disclose that EWF v2 sector data is not verified; anomalies: {findings:#?}"
    );
    // All anomalies must be Info
    for a in &findings {
        assert_eq!(
            a.severity(),
            Severity::Info,
            "unexpected non-Info anomaly: {a}"
        );
    }
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

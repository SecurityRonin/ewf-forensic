#![allow(clippy::unwrap_used, clippy::expect_used)]

//! RED phase — tool-specific format quirks and fixture tests.
//!
//! Two layers:
//!   1. Synthetic builders that mimic per-tool format variations (always run).
//!   2. #[ignore] tests against real binary fixtures (run when present).
//!
//! Synthetic tests fail until the builder helpers are added to builder.rs.
//! Ignored tests will fail until someone drops real E01 files into tests/data/.
mod builder;

use builder::{
    make_e01_ewfacquire_style, make_e01_ftk_imager_style, make_e01_xways_style,
    make_e01_tampered_hash,
};
use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly, Severity};

// ── FTK Imager style: header2 + header, disk section, 64-sector chunks ────────

#[test]
fn ftk_imager_style_clean_no_critical_errors() {
    let data = make_e01_ftk_imager_style(false);
    let findings = EwfIntegrity::new(&data).analyse();
    let errors: Vec<_> = findings
        .iter()
        .filter(|a| matches!(a.severity(), Severity::High | Severity::Critical))
        .collect();
    assert!(
        errors.is_empty(),
        "FTK Imager style E01 must have no Error/Critical anomalies; got: {errors:#?}"
    );
}

#[test]
fn ftk_imager_style_tampered_hash_mismatch_detected() {
    let data = make_e01_ftk_imager_style(true); // tampered = wrong hash
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::HashMismatch { .. })),
        "tampered FTK Imager style must report HashMismatch; got: {findings:#?}"
    );
}

// ── X-Ways / WinHex style: `disk` section type, extended header ───────────────

#[test]
fn xways_style_clean_no_critical_errors() {
    let data = make_e01_xways_style(false);
    let findings = EwfIntegrity::new(&data).analyse();
    let errors: Vec<_> = findings
        .iter()
        .filter(|a| matches!(a.severity(), Severity::High | Severity::Critical))
        .collect();
    assert!(
        errors.is_empty(),
        "X-Ways style E01 must have no Error/Critical anomalies; got: {errors:#?}"
    );
}

#[test]
fn xways_style_tampered_detected() {
    let data = make_e01_xways_style(true);
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::HashMismatch { .. })),
        "tampered X-Ways style must report HashMismatch; got: {findings:#?}"
    );
}

// ── ewfacquire (dc3dd) style: `disk` section, linux-style header, 64-sector ──

#[test]
fn ewfacquire_style_clean_no_critical_errors() {
    let data = make_e01_ewfacquire_style(false);
    let findings = EwfIntegrity::new(&data).analyse();
    let errors: Vec<_> = findings
        .iter()
        .filter(|a| matches!(a.severity(), Severity::High | Severity::Critical))
        .collect();
    assert!(
        errors.is_empty(),
        "ewfacquire style E01 must have no Error/Critical anomalies; got: {errors:#?}"
    );
}

#[test]
fn ewfacquire_style_tampered_detected() {
    let data = make_e01_ewfacquire_style(true);
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::HashMismatch { .. })),
        "tampered ewfacquire style must report HashMismatch; got: {findings:#?}"
    );
}

// ── Generic tamper helper: verify hash mismatch produces Critical/Error ────────

#[test]
fn tampered_hash_severity_is_error() {
    let data = make_e01_tampered_hash();
    let findings = EwfIntegrity::new(&data).analyse();
    if let Some(a) = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::HashMismatch { .. }))
    {
        assert_eq!(a.severity(), Severity::High);
    }
}

// ── Real fixture tests (ignored until files are present) ─────────────────────
//
// To run: cargo test --test tool_fixtures_tests -- --ignored
// Fixture placement: tests/data/ftk_imager_clean.E01 etc.
// See tests/data/README.md for acquisition instructions.

#[test]
#[ignore = "requires tests/data/ftk_imager_clean.E01 — see tests/data/README.md"]
fn real_ftk_imager_clean_fixture_no_anomalies() {
    use ewf_forensic::EwfIntegrityPath;
    let path = std::path::Path::new("tests/data/ftk_imager_clean.E01");
    if !path.exists() {
        panic!("fixture missing: {}", path.display());
    }
    let findings = EwfIntegrityPath::from_path(path).analyse().unwrap();
    let errors: Vec<_> = findings
        .iter()
        .filter(|a| matches!(a.severity(), Severity::High | Severity::Critical))
        .collect();
    assert!(
        errors.is_empty(),
        "real FTK Imager clean fixture must have no Error/Critical; got: {errors:#?}"
    );
}

#[test]
#[ignore = "requires tests/data/ftk_imager_tampered.E01 — see tests/data/README.md"]
fn real_ftk_imager_tampered_fixture_hash_mismatch() {
    use ewf_forensic::EwfIntegrityPath;
    let path = std::path::Path::new("tests/data/ftk_imager_tampered.E01");
    if !path.exists() {
        panic!("fixture missing: {}", path.display());
    }
    let findings = EwfIntegrityPath::from_path(path).analyse().unwrap();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::HashMismatch { .. })),
        "real FTK Imager tampered fixture must report HashMismatch; got: {findings:#?}"
    );
}

#[test]
#[ignore = "requires tests/data/xways_clean.E01 — see tests/data/README.md"]
fn real_xways_clean_fixture_no_anomalies() {
    use ewf_forensic::EwfIntegrityPath;
    let path = std::path::Path::new("tests/data/xways_clean.E01");
    if !path.exists() {
        panic!("fixture missing: {}", path.display());
    }
    let findings = EwfIntegrityPath::from_path(path).analyse().unwrap();
    let errors: Vec<_> = findings
        .iter()
        .filter(|a| matches!(a.severity(), Severity::High | Severity::Critical))
        .collect();
    assert!(
        errors.is_empty(),
        "real X-Ways clean fixture must have no Error/Critical; got: {errors:#?}"
    );
}

#[test]
fn real_ewfacquire_clean_fixture_no_anomalies() {
    use ewf_forensic::EwfIntegrityPath;
    let path = std::path::Path::new("tests/data/ewfacquire_clean.E01");
    if !path.exists() {
        panic!("fixture missing: {}", path.display());
    }
    let findings = EwfIntegrityPath::from_path(path).analyse().unwrap();
    let errors: Vec<_> = findings
        .iter()
        .filter(|a| matches!(a.severity(), Severity::High | Severity::Critical))
        .collect();
    assert!(
        errors.is_empty(),
        "real ewfacquire clean fixture must have no Error/Critical; got: {errors:#?}"
    );
}

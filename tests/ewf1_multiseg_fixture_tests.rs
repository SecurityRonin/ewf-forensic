#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Real multi-segment EWF v1 fixture tests.
//!
//! 8-segment EWF v1 image acquired with ewfacquire (libewf 20231119):
//!   ewfacquire -u -f encase6 -S 1500000 -c none -t `multiseg_v1` -d md5 -d sha1
//!   Source: 10 MiB of /dev/urandom
//!   MD5:  2692f3177a389e58906b5c9080aa1add
//!   SHA-1: 2d51e94e694ab425a73604e94d2020d00c182958
//!   Segments: E01..E08 (7 × 1.4 MiB + 1 × 162 KiB)
//!   Verified clean by ewfverify.
//!
//! These tests are always run (not #[ignore]) because the fixture files are
//! committed to tests/data/.

use ewf_forensic::{EwfIntegrityPath, Severity};
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

const MD5: &str = "2692f3177a389e58906b5c9080aa1add";
const SHA1: &str = "2d51e94e694ab425a73604e94d2020d00c182958";

fn parse_md5(s: &str) -> [u8; 16] {
    let b = hex::decode(s).unwrap();
    b.try_into().unwrap()
}
fn parse_sha1(s: &str) -> [u8; 20] {
    let b = hex::decode(s).unwrap();
    b.try_into().unwrap()
}

/// 8-segment real image must produce zero anomalies.
#[test]
fn multiseg_v1_clean_no_anomalies() {
    let findings = EwfIntegrityPath::from_path(fixture("multiseg_v1.E01"))
        .analyse()
        .expect("multi-segment analysis must not fail");

    let errors: Vec<_> = findings
        .iter()
        .filter(|a| matches!(a.severity(), Severity::High | Severity::Critical))
        .collect();

    assert!(
        errors.is_empty(),
        "real 8-segment EWF v1 must have no error/critical anomalies; got: {errors:#?}"
    );
}

/// MD5 chain-of-custody check must pass with the correct hash.
#[test]
fn multiseg_v1_md5_matches() {
    let findings = EwfIntegrityPath::from_path(fixture("multiseg_v1.E01"))
        .with_expected_md5(parse_md5(MD5))
        .analyse()
        .expect("analysis must not fail");

    assert!(
        !findings.iter().any(|a| matches!(
            a,
            ewf_forensic::EwfIntegrityAnomaly::ExternalMd5Mismatch { .. }
        )),
        "correct MD5 must not produce ExternalMd5Mismatch; got: {findings:#?}"
    );
}

/// SHA-1 chain-of-custody check must pass with the correct hash.
#[test]
fn multiseg_v1_sha1_matches() {
    let findings = EwfIntegrityPath::from_path(fixture("multiseg_v1.E01"))
        .with_expected_sha1(parse_sha1(SHA1))
        .analyse()
        .expect("analysis must not fail");

    assert!(
        !findings.iter().any(|a| matches!(
            a,
            ewf_forensic::EwfIntegrityAnomaly::ExternalSha1Mismatch { .. }
        )),
        "correct SHA-1 must not produce ExternalSha1Mismatch; got: {findings:#?}"
    );
}

/// `compute_hashes()` must return the ewfverify-confirmed hashes.
#[test]
fn multiseg_v1_computed_hashes_match() {
    let hashes = EwfIntegrityPath::from_path(fixture("multiseg_v1.E01"))
        .compute_hashes()
        .expect("compute_hashes must not fail")
        .expect("compute_hashes must return Some for a valid image");

    let md5_hex: String = hashes.md5.iter().map(|b| format!("{b:02x}")).collect();
    let sha1_hex: String = hashes.sha1.iter().map(|b| format!("{b:02x}")).collect();

    assert_eq!(
        md5_hex, MD5,
        "computed MD5 must match ewfverify ground truth"
    );
    assert_eq!(
        sha1_hex, SHA1,
        "computed SHA-1 must match ewfverify ground truth"
    );
}

/// `EwfIntegrityPath` auto-discovers E02..E08 from just the E01 path.
#[test]
fn multiseg_v1_sibling_auto_discovery() {
    // Pass only E01; the path API must discover E02..E08 automatically.
    let findings = EwfIntegrityPath::from_path(fixture("multiseg_v1.E01"))
        .analyse()
        .expect("auto-discovery must succeed");

    // A single-segment analysis would miss hash sections and fire anomalies;
    // zero errors confirms all 8 segments were discovered and processed.
    let errors: Vec<_> = findings
        .iter()
        .filter(|a| matches!(a.severity(), Severity::High | Severity::Critical))
        .collect();

    assert!(
        errors.is_empty(),
        "sibling auto-discovery must find all 8 segments; errors: {errors:#?}"
    );
}

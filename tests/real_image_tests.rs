// Integration tests against the three small E01 fixtures committed to
// tests/fixtures/.  They run in CI on every push.
//
// Run locally with:
//   cargo test --test real_image_tests

use ewf_forensic::{EwfIntegrity, Severity};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn assert_no_errors(name: &str) {
    let path = format!("{FIXTURES}/{name}");
    let data = std::fs::read(&path).expect("read fixture");
    let findings = EwfIntegrity::new(&data).analyse();
    let errors: Vec<_> = findings
        .iter()
        .filter(|a| matches!(a.severity(), Severity::Error | Severity::Critical))
        .collect();
    assert!(
        errors.is_empty(),
        "unexpected Error/Critical findings in {name}:\n{errors:#?}"
    );
}

// A well-formed E01 from a real acquisition must produce no Error/Critical
// findings.  Warnings (e.g. DoneSectionMissing) and Info are acceptable.

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

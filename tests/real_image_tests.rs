// Integration tests against the three small E01 fixtures committed to the ewf
// repository.  These tests are developer-local: if the fixture directory is
// absent the tests return early rather than failing so that CI (which does not
// have the fixtures) is unaffected.
//
// Run locally with:
//   cargo test --test real_image_tests

use ewf_forensic::{EwfIntegrity, Severity};

const FIXTURES: &str = "/Users/4n6h4x0r/src/ewf/ewf/tests/data";

fn run_if_present(name: &str) -> Option<Vec<ewf_forensic::EwfIntegrityAnomaly>> {
    let path = format!("{FIXTURES}/{name}");
    if !std::path::Path::new(&path).exists() {
        return None;
    }
    let data = std::fs::read(&path).expect("read fixture");
    Some(EwfIntegrity::new(&data).analyse())
}

fn assert_no_errors(name: &str) {
    let Some(findings) = run_if_present(name) else {
        return;
    };
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

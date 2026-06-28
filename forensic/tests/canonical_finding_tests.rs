//! ewf-forensic anomalies normalize onto the canonical `forensicnomicon::report`
//! model via the `Observation` producer trait (4-level -> 5-level re-grade).

use ewf_forensic::EwfIntegrityAnomaly;
use forensicnomicon::report::{Observation, Severity, Source};

#[test]
fn anomaly_converts_to_a_canonical_finding() {
    let a = EwfIntegrityAnomaly::InvalidSignature;
    let f = a.to_finding(Source {
        analyzer: "ewf-forensic".to_string(),
        scope: "EWF".to_string(),
        version: None,
    });
    assert_eq!(f.code, "EWF-INVALID-SIGNATURE");
    assert_eq!(f.severity, Some(Severity::Critical));
}

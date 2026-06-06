//! sleuthkit test-data fixture tests — differential testing against ewfverify.
//!
//! Sources:
//!
//!   bogus.E01             — github.com/sleuthkit/sleuthkit test/data (0 bytes; committed)
//!   bogus.E02             — github.com/sleuthkit/sleuthkit test/data (0 bytes; committed)
//!   gpt_130_partitions.E01 — github.com/sleuthkit/sleuthkit test/data (384 KB; committed)
//!
//! bogus.E01 / bogus.E02 are intentionally empty (0 bytes) — the sleuthkit test
//! suite uses them to exercise error paths in tools that open EWF files.  Both
//! tools report failure, but differ in how:
//!
//!   ewfverify   — refuses to open: exits non-zero with "unable to read file header"
//!   ewf-forensic — opens the file, traverses the section chain, and emits two
//!                  CRITICAL anomalies: "section chain broken at 0x0"
//!
//! This is NOT a divergence in verdict — both agree the file is invalid — but a
//! difference in diagnostic depth.  ewf-forensic's structured output names the
//! specific structural invariant that was violated; ewfverify's output is a
//! libewf open error.
//!
//! gpt_130_partitions.E01 is a structurally valid EWF v1 image containing a GPT
//! partition table with 130 partitions.  Both tools report clean.

use ewf_forensic::{EwfIntegrityPath, Severity};
use std::path::{Path, PathBuf};
use std::process::Command;

// ── Harness ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct DiffResult {
    ewfverify_exit: i32,
    ewfverify_output: String,
    ewf_anomalies: Vec<String>,
    ewf_errors: Vec<String>,
    ewf_criticals: Vec<String>,
}

impl DiffResult {
    fn ewfverify_clean(&self) -> bool {
        self.ewfverify_exit == 0
    }
    fn ewf_clean(&self) -> bool {
        self.ewf_errors.is_empty() && self.ewf_criticals.is_empty()
    }
    fn has_anomaly_containing(&self, needle: &str) -> bool {
        self.ewf_anomalies.iter().any(|a| a.contains(needle))
    }
}

/// Returns None if ewfverify is not installed.
fn run_differential(e01_path: &Path) -> Option<DiffResult> {
    let ev = match Command::new("ewfverify").arg("-q").arg(e01_path).output() {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => panic!("ewfverify failed to launch: {e}"),
    };

    let exit = ev.status.code().unwrap_or(-1);
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&ev.stdout),
        String::from_utf8_lossy(&ev.stderr)
    );

    let findings = EwfIntegrityPath::from_path(e01_path)
        .analyse()
        .expect("ewf-forensic I/O must not fail");

    let ewf_errors: Vec<String> = findings
        .iter()
        .filter(|a| a.severity() == Severity::High)
        .map(|a| format!("{a}"))
        .collect();

    let ewf_criticals: Vec<String> = findings
        .iter()
        .filter(|a| a.severity() == Severity::Critical)
        .map(|a| format!("{a}"))
        .collect();

    let ewf_anomalies: Vec<String> = findings.iter().map(|a| format!("{a}")).collect();

    Some(DiffResult {
        ewfverify_exit: exit,
        ewfverify_output: output,
        ewf_anomalies,
        ewf_errors,
        ewf_criticals,
    })
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

// ── bogus.E01 — zero-byte file, both tools report invalid ─────────────────────

/// bogus.E01 from github.com/sleuthkit/sleuthkit (test/data/).
///
/// Both tools agree the file is invalid — the verdict is identical.
/// Diagnostic difference:
///   ewfverify   — rejects at open (non-zero exit, no structured output)
///   ewf-forensic — traverses the section chain and emits CRITICAL anomalies
///
/// The difference matters for automation: ewf-forensic's CRITICAL severity
/// is machine-readable via --json; ewfverify's failure mode is text-only.
#[test]
fn bogus_e01_both_report_invalid() {
    let Some(r) = run_differential(&fixture("bogus.E01")) else { return };

    // ewfverify rejects the file — cannot open a 0-byte EWF.
    assert!(
        !r.ewfverify_clean(),
        "ewfverify must reject bogus.E01 (0-byte file); exit={}; output={}",
        r.ewfverify_exit,
        r.ewfverify_output
    );

    // ewf-forensic must not silently pass an empty file.
    assert!(
        !r.ewf_clean(),
        "ewf-forensic must not report clean for bogus.E01 (0-byte file); \
         anomalies={:?}",
        r.ewf_anomalies
    );

    // The section-chain traversal should reach CRITICAL — the chain is broken
    // at offset 0x0 because there is no data to read.
    let has_chain_error = r.has_anomaly_containing("section chain")
        || r.has_anomaly_containing("chain broken")
        || !r.ewf_criticals.is_empty();
    assert!(
        has_chain_error,
        "ewf-forensic must report a section-chain CRITICAL for bogus.E01; \
         anomalies={:?}",
        r.ewf_anomalies
    );
}

// ── bogus.E02 — zero-byte second-segment file, same behaviour ────────────────

/// bogus.E02 from github.com/sleuthkit/sleuthkit (test/data/).
///
/// The .E02 extension conventionally names the second segment in a multi-segment
/// EWF set.  This file is 0 bytes — it exercises the error path for a completely
/// absent or empty continuation segment.
///
/// Behaviour is identical to bogus.E01: both tools reject it.
#[test]
fn bogus_e02_both_report_invalid() {
    let Some(r) = run_differential(&fixture("bogus.E02")) else { return };

    assert!(
        !r.ewfverify_clean(),
        "ewfverify must reject bogus.E02 (0-byte file); exit={}; output={}",
        r.ewfverify_exit,
        r.ewfverify_output
    );

    assert!(
        !r.ewf_clean(),
        "ewf-forensic must not report clean for bogus.E02 (0-byte file); \
         anomalies={:?}",
        r.ewf_anomalies
    );

    let has_chain_error = r.has_anomaly_containing("section chain")
        || r.has_anomaly_containing("chain broken")
        || !r.ewf_criticals.is_empty();
    assert!(
        has_chain_error,
        "ewf-forensic must report a section-chain CRITICAL for bogus.E02; \
         anomalies={:?}",
        r.ewf_anomalies
    );
}

// ── gpt_130_partitions.E01 — valid EWF, both tools clean ─────────────────────

/// gpt_130_partitions.E01 from github.com/sleuthkit/sleuthkit (test/data/).
///
/// A structurally valid EWF v1 image containing a GPT partition table with
/// 130 partitions.  Used in the sleuthkit suite to exercise partition-table
/// parsing; for ewf-forensic it is a clean container integrity baseline.
///
/// ewfverify: SUCCESS (exit 0).
/// ewf-forensic: CLEAN (0 anomalies at any severity).
#[test]
fn gpt_130_partitions_both_clean() {
    let Some(r) = run_differential(&fixture("gpt_130_partitions.E01")) else { return };

    assert!(
        r.ewfverify_clean(),
        "ewfverify must report SUCCESS for gpt_130_partitions; \
         exit={}; output={}",
        r.ewfverify_exit,
        r.ewfverify_output
    );

    assert!(
        r.ewf_clean(),
        "ewf-forensic must report no errors for gpt_130_partitions; \
         errors={:?}; criticals={:?}",
        r.ewf_errors,
        r.ewf_criticals
    );

    assert!(
        r.ewf_anomalies.is_empty(),
        "ewf-forensic must report zero anomalies (all severities) for \
         gpt_130_partitions; got={:?}",
        r.ewf_anomalies
    );
}

#![allow(clippy::unwrap_used, clippy::expect_used)]

//! CTF and public-corpus EWF fixture tests — differential testing against ewfverify.
//!
//! Sources:
//!
//!   ctf_file6.E01          — github.com/mfput/CTF-Questions (committed; 156 KB)
//!   2011-10-19-Sample.E01  — github.com/oddin-forensic/autopsy-sample-case (not committed; 60 MB)
//!   CNC.E01                — github.com/HaxonicOfficial/CTF-Practice (not committed; 88 MB)
//!
//! To run the ignored tests, download the files to tests/data/ and pass --ignored:
//!
//!   python3 -c "
//!   import urllib.request
//!   urllib.request.urlretrieve(
//!       'https://raw.githubusercontent.com/oddin-forensic/autopsy-sample-case/master/2011-10-19-Sample.E01',
//!       'tests/data/2011-10-19-Sample.E01')
//!   urllib.request.urlretrieve(
//!       'https://raw.githubusercontent.com/HaxonicOfficial/CTF-Practice/master/CNC.E01',
//!       'tests/data/CNC.E01')
//!   "
//!   cargo test --test ctf_fixture_tests -- --ignored

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
}

impl DiffResult {
    fn ewfverify_clean(&self) -> bool {
        self.ewfverify_exit == 0
    }
    fn ewf_clean(&self) -> bool {
        self.ewf_errors.is_empty()
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
        .filter(|a| matches!(a.severity(), Severity::High | Severity::Critical))
        .map(|a| format!("{a}"))
        .collect();

    let ewf_anomalies: Vec<String> = findings.iter().map(|a| format!("{a}")).collect();

    Some(DiffResult {
        ewfverify_exit: exit,
        ewfverify_output: output,
        ewf_anomalies,
        ewf_errors,
    })
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

fn optional_fixture(name: &str) -> Option<PathBuf> {
    let p = fixture(name);
    if p.exists() { Some(p) } else { None }
}

// ── Always-on: both tools agree on small committed CTF fixture ────────────────

/// ctf_file6.E01 from github.com/mfput/CTF-Questions.
///
/// ewfverify: SUCCESS (exit 0).
/// ewf-forensic: CLEAN (0 anomalies at any severity).
/// No divergence.
#[test]
fn ctf_file6_both_clean() {
    let Some(r) = run_differential(&fixture("ctf_file6.E01")) else { return };
    assert!(
        r.ewfverify_clean(),
        "ewfverify must report SUCCESS for ctf_file6; output={}",
        r.ewfverify_output
    );
    assert!(
        r.ewf_clean(),
        "ewf-forensic must report no errors for ctf_file6; anomalies={:?}",
        r.ewf_errors
    );
    assert!(
        r.ewf_anomalies.is_empty(),
        "ewf-forensic must report zero anomalies (all severities) for ctf_file6; got={:?}",
        r.ewf_anomalies
    );
}

// ── Ignored: large files — download to tests/data/ before running ─────────────

/// 2011-10-19-Sample.E01 — Autopsy sample "Victor Bushell Laptop" (60 MB, EnCase 7).
/// Source: github.com/oddin-forensic/autopsy-sample-case
///
/// Documented characterisation difference: ewfverify ignores the error2 section
/// and reports SUCCESS. ewf-forensic correctly surfaces BadSectorsPresent (Warning)
/// because 1 unreadable sector range was recorded at acquisition time.
///
/// This is NOT a false positive in ewf-forensic — the warning is accurate.
/// It documents a gap in ewfverify: acquisitions with bad sectors are reported as
/// SUCCESS without any mention of the unreadable sector record.
///
/// Run: cargo test --test ctf_fixture_tests ctf_autopsy_sample -- --ignored
#[test]
#[ignore = "60 MB — download to tests/data/2011-10-19-Sample.E01 before running"]
fn ctf_autopsy_sample_ewfverify_misses_bad_sectors() {
    let path = match optional_fixture("2011-10-19-Sample.E01") {
        Some(p) => p,
        None => {
            eprintln!(
                "SKIP: tests/data/2011-10-19-Sample.E01 not found. \
                 Download from: https://raw.githubusercontent.com/oddin-forensic/\
                 autopsy-sample-case/master/2011-10-19-Sample.E01"
            );
            return;
        }
    };

    let Some(r) = run_differential(&path) else { return };

    // ewfverify reports SUCCESS despite acquisition-time bad sectors.
    assert!(
        r.ewfverify_clean(),
        "ewfverify characterisation changed: expected SUCCESS; exit={}; output={}",
        r.ewfverify_exit,
        r.ewfverify_output
    );

    // ewf-forensic must report BadSectorsPresent (Warning) — the error2 section is present.
    let has_bad_sectors = r.has_anomaly_containing("error2")
        || r.has_anomaly_containing("bad sector")
        || r.has_anomaly_containing("unreadable sector")
        || r.has_anomaly_containing("BadSectors");
    assert!(
        has_bad_sectors,
        "ewf-forensic must surface BadSectorsPresent for this image; anomalies={:?}",
        r.ewf_anomalies
    );

    // No Error/Critical — ewf-forensic agrees there is no hash mismatch or structural damage;
    // only the Warning-level acquisition-time record differs from ewfverify.
    assert!(
        r.ewf_clean(),
        "ewf-forensic must report no Error/Critical for this image; errors={:?}",
        r.ewf_errors
    );
}

/// CNC.E01 — HaxonicOfficial CTF Practice image (88 MB, FTK Imager).
/// Source: github.com/HaxonicOfficial/CTF-Practice
///
/// Coverage difference (D3): the volume section declares 61 440 chunks (~1.8 GiB)
/// but the table section indexes only 16 375 chunks (~511 MB accessible). The
/// origin of the mismatch is unverified — truncated acquisition, GitHub size
/// limit, tool bug, or intentional CTF design are all plausible.
///
/// ewfverify hashes only table-accessible sectors; the stored MD5 matches those
/// sectors → exits SUCCESS. It does not check whether volume and table agree.
///
/// ewf-forensic detects:
///   TableChunkCountMismatch { in_volume: 61440, in_table: 16375 }   [Error]
///   HashMismatch (computed over full declared range)                 [Error]
///   DigestSha1Mismatch                                               [Error]
///
/// Run: cargo test --test ctf_fixture_tests ctf_cnc -- --ignored
#[test]
#[ignore = "88 MB — download to tests/data/CNC.E01 before running"]
fn ctf_cnc_ewfverify_false_negative_table_mismatch() {
    let path = match optional_fixture("CNC.E01") {
        Some(p) => p,
        None => {
            eprintln!(
                "SKIP: tests/data/CNC.E01 not found. \
                 Download from: https://raw.githubusercontent.com/HaxonicOfficial/\
                 CTF-Practice/master/CNC.E01"
            );
            return;
        }
    };

    let Some(r) = run_differential(&path) else { return };

    // ewfverify does not check table/volume consistency — reports SUCCESS.
    assert!(
        r.ewfverify_clean(),
        "ewfverify behaviour changed: expected SUCCESS; exit={}; output={}",
        r.ewfverify_exit,
        r.ewfverify_output
    );

    // ewf-forensic must detect the table mismatch.
    let has_table_mismatch = r.has_anomaly_containing("chunk count mismatch")
        || r.has_anomaly_containing("TableChunkCount")
        || r.has_anomaly_containing("in_volume")
        || r.has_anomaly_containing("in_table");
    assert!(
        has_table_mismatch,
        "ewf-forensic must report TableChunkCountMismatch (volume=61440, table=16375); \
         anomalies={:?}",
        r.ewf_anomalies
    );

    // ewf-forensic must also detect hash inconsistency (hashing over declared size diverges).
    let has_hash_error = r.has_anomaly_containing("mismatch")
        || r.has_anomaly_containing("HashMismatch");
    assert!(
        has_hash_error,
        "ewf-forensic must report hash mismatch for the partial image; anomalies={:?}",
        r.ewf_anomalies
    );

    // Confirm ewf-forensic is not clean — it correctly reports errors ewfverify missed.
    assert!(
        !r.ewf_clean(),
        "ewf-forensic must report Error/Critical for CNC.E01 (ewfverify false negative); \
         anomalies={:?}",
        r.ewf_anomalies
    );
}

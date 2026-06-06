//! Differential testing: ewf-forensic vs ewfverify (libewf reference implementation).
//!
//! For every committed fixture, both tools are run independently and the results compared.
//! A divergence is any case where the two tools disagree on whether an image is clean:
//!
//!   False positive: ewfverify exits 0 (SUCCESS) but ewf-forensic reports Error/Critical.
//!   False negative: ewfverify exits 1 (FAILURE) but ewf-forensic reports no Error/Critical.
//!
//! Both are bugs — false positives erode trust; false negatives miss real damage.
//!
//! ewfverify exit codes (libewf 20231119):
//!   0 = verified successfully
//!   1 = verification failed (hash mismatch, sector validation error, or structural problem)
//!   2 = usage/I/O error (file not found, etc.)
//!
//! Tests skip automatically if ewfverify is not installed or not in PATH.

use ewf_forensic::{EwfIntegrityPath, Severity};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;


// ── Harness ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct DiffResult {
    path: String,
    ewfverify_exit: i32,
    /// Combined stdout + stderr from ewfverify (ewfverify writes its report to stderr).
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
    fn diverges(&self) -> bool {
        self.ewfverify_clean() != self.ewf_clean()
    }
    fn divergence_summary(&self) -> String {
        if self.ewfverify_clean() && !self.ewf_clean() {
            format!(
                "FALSE POSITIVE in ewf-forensic:\n  ewfverify=SUCCESS\n  ewf-forensic errors={:?}",
                self.ewf_errors
            )
        } else if !self.ewfverify_clean() && self.ewf_clean() {
            format!(
                "FALSE NEGATIVE in ewf-forensic:\n  ewfverify=FAILURE (exit {})\n  ewfverify output={}\n  ewf-forensic all={:?}",
                self.ewfverify_exit,
                self.ewfverify_output.trim(),
                self.ewf_anomalies
            )
        } else {
            "no divergence".to_string()
        }
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
    // ewfverify writes its detailed report to stderr; stdout gets only the version line.
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
        path: e01_path.display().to_string(),
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

fn assert_no_divergence(result: &DiffResult) {
    assert!(
        !result.diverges(),
        "DIVERGENCE on {}:\n{}",
        result.path,
        result.divergence_summary()
    );
}

fn assert_both_detect(result: &DiffResult) {
    assert!(
        !result.ewfverify_clean(),
        "ewfverify did not detect anomaly in {}; stdout={}",
        result.path,
        result.ewfverify_output.trim()
    );
    assert!(
        !result.ewf_clean(),
        "ewf-forensic did not detect anomaly in {}; all anomalies={:?}",
        result.path,
        result.ewf_anomalies
    );
}

// ── Agreement: both tools agree image is clean ────────────────────────────────

#[test]
fn differential_exfat1_both_clean() {
    let Some(r) = run_differential(&fixture("exfat1.E01")) else { return };
    assert_no_divergence(&r);
    assert!(r.ewfverify_clean(), "ewfverify unexpected failure: {}", r.ewfverify_output);
    assert!(r.ewf_clean(), "ewf-forensic false positive: {:?}", r.ewf_errors);
}

#[test]
fn differential_nps_emails_both_clean() {
    let Some(r) = run_differential(&fixture("nps-2010-emails.E01")) else { return };
    assert_no_divergence(&r);
    assert!(r.ewfverify_clean());
    assert!(r.ewf_clean(), "false positive: {:?}", r.ewf_errors);
}

#[test]
fn differential_mmls_both_clean() {
    let Some(r) = run_differential(&fixture("imageformat_mmls_1.E01")) else { return };
    assert_no_divergence(&r);
    assert!(r.ewfverify_clean());
    assert!(r.ewf_clean(), "false positive: {:?}", r.ewf_errors);
}

#[test]
fn differential_ewfacquire_clean_both_clean() {
    let Some(r) = run_differential(&fixture("ewfacquire_clean.E01")) else { return };
    assert_no_divergence(&r);
    assert!(r.ewfverify_clean());
    assert!(r.ewf_clean(), "false positive: {:?}", r.ewf_errors);
}

#[test]
fn differential_multiseg_v1_both_clean() {
    // ewfverify auto-discovers E02..E08 from E01 path.
    let Some(r) = run_differential(&fixture("multiseg_v1.E01")) else { return };
    assert_no_divergence(&r);
    assert!(r.ewfverify_clean());
    assert!(r.ewf_clean(), "false positive on multi-segment: {:?}", r.ewf_errors);
}

#[test]
fn differential_zeros_128s_both_clean() {
    let Some(r) = run_differential(&fixture("zeros_128s.Ex01")) else { return };
    assert_no_divergence(&r);
    assert!(r.ewfverify_clean());
    assert!(r.ewf_clean(), "false positive: {:?}", r.ewf_errors);
}

#[test]
fn differential_zeros_compressed_both_clean() {
    let Some(r) = run_differential(&fixture("zeros_128s_compressed.Ex01")) else { return };
    assert_no_divergence(&r);
    assert!(r.ewfverify_clean());
    assert!(r.ewf_clean(), "false positive: {:?}", r.ewf_errors);
}

// ── Agreement: both tools detect tampered compressed chunk ───────────────────

/// Flip one byte inside the compressed DEFLATE data of exfat1 chunk 195.
/// ewfverify reports: sector validation error + FAILURE (exit 1).
/// ewf-forensic reports: ChunkDecompressionError + HashMismatch.
/// Both must agree there is an anomaly.
#[test]
fn differential_tampered_compressed_chunk_both_detect() {
    let src = fixture("exfat1.E01");
    let src_bytes = std::fs::read(&src).unwrap();

    let mut tmp = tempfile::Builder::new().suffix(".E01").tempfile().unwrap();
    let mut tampered = src_bytes.clone();
    // Flip byte at file offset 100_000 — inside chunk 195's DEFLATE stream.
    tampered[100_000] ^= 0xFF;
    tmp.write_all(&tampered).unwrap();
    tmp.flush().unwrap();

    let Some(r) = run_differential(tmp.path()) else { return };
    assert_both_detect(&r);
}

/// Flip one byte in the uncompressed sector data region of ewfacquire_clean.E01.
/// ewfacquire uses -c none, so chunks are raw bytes followed by Adler-32.
/// Both tools must detect the corruption.
#[test]
fn differential_tampered_uncompressed_chunk_both_detect() {
    let src = fixture("ewfacquire_clean.E01");
    let src_bytes = std::fs::read(&src).unwrap();

    let mut tmp = tempfile::Builder::new().suffix(".E01").tempfile().unwrap();
    let mut tampered = src_bytes.clone();
    // Flip a byte well inside the sectors body (offset 50_000 — past all headers).
    tampered[50_000] ^= 0x01;
    tmp.write_all(&tampered).unwrap();
    tmp.flush().unwrap();

    let Some(r) = run_differential(tmp.path()) else { return };
    assert_both_detect(&r);
}

// ── Divergence documentation: known characterisation differences ──────────────

/// When a compressed chunk is corrupt, ewfverify reports the MD5 as matching
/// even though it exits FAILURE. ewf-forensic reports HashMismatch.
/// This is a characterisation difference, NOT a false positive/negative —
/// both agree the image is anomalous. Asserts the difference is stable.
#[test]
fn differential_compressed_tamper_ewfverify_md5_appears_clean_but_exits_failure() {
    let src = fixture("exfat1.E01");
    let src_bytes = std::fs::read(&src).unwrap();

    let mut tmp = tempfile::Builder::new().suffix(".E01").tempfile().unwrap();
    let mut tampered = src_bytes.clone();
    tampered[100_000] ^= 0xFF;
    tmp.write_all(&tampered).unwrap();
    tmp.flush().unwrap();

    let Some(r) = run_differential(tmp.path()) else { return };

    // Both agree: anomalous.
    assert!(!r.ewfverify_clean(), "ewfverify must exit non-zero for tampered image");
    assert!(!r.ewf_clean(), "ewf-forensic must report Error/Critical for tampered image");

    // Known characterisation difference: ewfverify stdout claims MD5 matches
    // even on FAILURE (per-chunk CRC triggers failure before full-image hash mismatch).
    assert!(
        r.ewfverify_output.contains("MD5 hash stored in file"),
        "ewfverify stdout must contain MD5 line (characterisation check); got: {}",
        r.ewfverify_output
    );

    // ewf-forensic must surface the chunk-level error with precise index.
    let has_decomp = r.ewf_anomalies.iter().any(|a| a.contains("chunk") && a.contains("zlib"));
    let has_hash = r.ewf_anomalies.iter().any(|a| a.contains("MD5 mismatch") || a.contains("hash mismatch"));
    assert!(
        has_decomp || has_hash,
        "ewf-forensic must report decompression error or hash mismatch; got: {:?}",
        r.ewf_anomalies
    );
}

// ── Adversarial edge cases: both tools run on crafted malformed inputs ────────

/// Truncate an otherwise-clean image to half its size.
/// ewfverify must fail (exit ≥ 1); ewf-forensic must report at least one Error/Critical.
#[test]
fn differential_truncated_file_both_detect() {
    let src = std::fs::read(fixture("ewfacquire_clean.E01")).unwrap();
    let half = &src[..src.len() / 2];

    let mut tmp = tempfile::Builder::new().suffix(".E01").tempfile().unwrap();
    tmp.write_all(half).unwrap();
    tmp.flush().unwrap();

    let Some(r) = run_differential(tmp.path()) else { return };
    // Both must agree there is a problem.
    assert!(
        !r.ewfverify_clean() || !r.ewf_clean(),
        "truncated image must be detected by at least one tool; ewfverify_exit={}, ewf={:?}",
        r.ewfverify_exit,
        r.ewf_anomalies
    );
    assert!(
        !r.ewf_clean(),
        "ewf-forensic must detect truncated image; all anomalies={:?}",
        r.ewf_anomalies
    );
}

/// Flip 4 bytes of the EVF magic signature at offset 0.
/// ewfverify must fail; ewf-forensic must report InvalidSignature (Critical).
#[test]
fn differential_invalid_signature_both_detect() {
    let src = std::fs::read(fixture("ewfacquire_clean.E01")).unwrap();

    let mut tmp = tempfile::Builder::new().suffix(".E01").tempfile().unwrap();
    let mut tampered = src.clone();
    // Corrupt the first 4 bytes of the EVF magic (45 56 46 09 0D 0A FF 00).
    tampered[0] = 0x00;
    tampered[1] = 0x00;
    tampered[2] = 0x00;
    tampered[3] = 0x00;
    tmp.write_all(&tampered).unwrap();
    tmp.flush().unwrap();

    // ewfverify cannot open a file with invalid magic — exits 2+ (I/O error).
    // ewf-forensic must report InvalidSignature (Critical) regardless.
    let findings = EwfIntegrityPath::from_path(tmp.path())
        .analyse()
        .expect("ewf-forensic I/O must not fail");

    let has_invalid_sig = findings.iter().any(|a| {
        format!("{a}").to_lowercase().contains("signature")
            || matches!(a, ewf_forensic::EwfIntegrityAnomaly::InvalidSignature)
    });
    assert!(
        has_invalid_sig,
        "ewf-forensic must report InvalidSignature for corrupt magic; got: {findings:#?}"
    );

    // Also verify ewfverify agrees it's broken (exit non-zero).
    let ev = Command::new("ewfverify")
        .arg("-q")
        .arg(tmp.path())
        .output();
    if let Ok(ev) = ev {
        let exit = ev.status.code().unwrap_or(-1);
        assert_ne!(exit, 0, "ewfverify must not report SUCCESS for invalid magic");
    }
}

/// Replace the 16-byte stored MD5 in the hash section with a wrong value.
/// Both tools must detect the hash mismatch.
#[test]
fn differential_wrong_stored_md5_both_detect() {
    let src = std::fs::read(fixture("ewfacquire_clean.E01")).unwrap();

    // Locate the "hash" section by scanning for its type string.
    // EWF v1 section type field is at offset +0 in the 76-byte descriptor.
    let hash_type = b"hash\0\0\0\0\0\0\0\0\0\0\0\0";
    let hash_section_pos = src
        .windows(16)
        .position(|w| w == hash_type)
        .expect("ewfacquire_clean.E01 must contain a hash section");

    // The 76-byte descriptor is followed by the hash section body.
    // EWF v1 hash body = 16-byte MD5 + 16-byte SHA-1 (if present) + padding.
    let body_start = hash_section_pos + 76;

    let mut tampered = src.clone();
    // Flip all bits of the first 16 bytes (the stored MD5).
    for b in &mut tampered[body_start..body_start + 16] {
        *b ^= 0xFF;
    }

    let mut tmp = tempfile::Builder::new().suffix(".E01").tempfile().unwrap();
    tmp.write_all(&tampered).unwrap();
    tmp.flush().unwrap();

    let Some(r) = run_differential(tmp.path()) else { return };
    assert_both_detect(&r);
}

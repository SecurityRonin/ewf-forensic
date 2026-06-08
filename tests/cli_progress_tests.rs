#![allow(clippy::unwrap_used, clippy::expect_used)]

//! RED phase — `--progress` CLI flag for ewf-check.
//!
//! Tests fail until --progress is implemented in the binary.

mod builder;
use builder::E01Builder;
use std::io::Write as _;
use std::process::Command;
use tempfile::NamedTempFile;

fn write_temp(data: &[u8], suffix: &str) -> NamedTempFile {
    let f = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
    let mut f = f;
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

fn ewf_check() -> Command {
    let bin = env!("CARGO_BIN_EXE_ewf-check");
    Command::new(bin)
}

// ── --progress flag is recognised (exit 0 or 1, not 2) ───────────────────────

#[test]
fn progress_flag_accepted() {
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data, ".E01");
    let out = ewf_check()
        .arg("--progress")
        .arg(f.path())
        .output()
        .unwrap();
    let code = out.status.code().unwrap_or(99);
    assert!(
        code == 0 || code == 1,
        "--progress must not cause usage error (exit 2); got exit {code}; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ── --progress stdout must not be corrupted by progress bar ─────────────────
// Progress bar goes to stderr; stdout must still contain the result text.

#[test]
fn progress_stdout_not_corrupted() {
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data, ".E01");
    let out = ewf_check()
        .arg("--progress")
        .arg(f.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // A clean image must print the clean message to stdout (not stderr).
    assert!(
        stdout.contains("clean") || stdout.contains("CLEAN") || stdout.contains("0 anomalies"),
        "--progress must not corrupt stdout; got stdout: {stdout}; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ── --progress combined with --min-severity ───────────────────────────────────

#[test]
fn progress_combined_with_min_severity() {
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data, ".E01");
    let out = ewf_check()
        .arg("--progress")
        .arg("--min-severity=info")
        .arg(f.path())
        .output()
        .unwrap();
    let code = out.status.code().unwrap_or(99);
    assert_eq!(
        code,
        0,
        "--progress + --min-severity=info on clean image must exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

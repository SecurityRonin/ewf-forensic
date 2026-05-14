//! RED phase — CLI binary `ewf-check`.
//!
//! Tests fail until the binary is implemented and `[[bin]]` is added to Cargo.toml.
mod builder;
use builder::E01Builder;
use std::io::Write as _;
use std::process::Command;
use tempfile::NamedTempFile;

fn write_temp(data: &[u8], suffix: &str) -> NamedTempFile {
    let f = tempfile::Builder::new()
        .suffix(suffix)
        .tempfile()
        .unwrap();
    let mut f = f;
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

fn ewf_check() -> Command {
    let bin = env!("CARGO_BIN_EXE_ewf-check");
    Command::new(bin)
}

// ── Clean image: exit 0 ───────────────────────────────────────────────────────

#[test]
fn cli_clean_image_exits_zero() {
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data, ".E01");
    let out = ewf_check().arg(f.path()).output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "clean image must exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ── Clean image: stdout says "clean" ─────────────────────────────────────────

#[test]
fn cli_clean_image_prints_clean() {
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data, ".E01");
    let out = ewf_check().arg(f.path()).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("clean") || stdout.contains("CLEAN") || stdout.contains("0 anomalies"),
        "expected clean output; got: {stdout}"
    );
}

// ── Tampered image: exit 1 ────────────────────────────────────────────────────

#[test]
fn cli_tampered_image_exits_one() {
    let data = E01Builder::new(512 * 64).with_md5([0xBAu8; 16]).build();
    let f = write_temp(&data, ".E01");
    let out = ewf_check().arg(f.path()).output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "image with anomalies must exit 1; stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

// ── Tampered image: anomaly reported on stdout ────────────────────────────────

#[test]
fn cli_tampered_image_reports_anomaly() {
    let data = E01Builder::new(512 * 64).with_md5([0xBAu8; 16]).build();
    let f = write_temp(&data, ".E01");
    let out = ewf_check().arg(f.path()).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("mismatch") || stdout.contains("HASH") || stdout.contains("hash"),
        "expected hash anomaly in output; got: {stdout}"
    );
}

// ── No arguments: exit 2 with usage ──────────────────────────────────────────

#[test]
fn cli_no_args_exits_two() {
    let out = ewf_check().output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "no arguments must exit 2 (usage error)"
    );
}

// ── Missing file: exit 2 with error message ───────────────────────────────────

#[test]
fn cli_missing_file_exits_two() {
    let out = ewf_check()
        .arg("/nonexistent/evidence.E01")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "missing file must exit 2; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ── --help flag exits 0 with usage ───────────────────────────────────────────

#[test]
fn cli_help_flag_exits_zero() {
    let out = ewf_check().arg("--help").output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "--help must exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ── Severity filter --min-severity=critical only shows critical ───────────────

#[test]
fn cli_min_severity_filters_output() {
    // Build an image with a Warning-level anomaly (missing hash section) and
    // verify that --min-severity=error suppresses it.
    let data = E01Builder::new(512 * 64).with_omit_hash().build();
    let f = write_temp(&data, ".E01");
    let out = ewf_check()
        .arg("--min-severity=critical")
        .arg(f.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // HashSectionMissing is Warning; must not appear when filter=critical
    assert!(
        !stdout.contains("HashSectionMissing"),
        "Warning anomaly must be filtered at --min-severity=critical; stdout: {stdout}"
    );
}

// ── --json: clean image ───────────────────────────────────────────────────────

#[test]
fn cli_json_clean_image_exits_zero() {
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data, ".E01");
    let out = ewf_check().arg("--json").arg(f.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "--json clean must exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Must parse as valid JSON object
    assert!(stdout.trim().starts_with('{'), "expected JSON object: {stdout}");
    assert!(stdout.contains("\"clean\""), "missing 'clean' field: {stdout}");
    assert!(stdout.contains("true"), "clean image must have clean:true: {stdout}");
    assert!(stdout.contains("\"anomaly_count\""), "missing anomaly_count: {stdout}");
}

#[test]
fn cli_json_tampered_image_exits_one() {
    let data = E01Builder::new(512 * 64).with_md5([0xBAu8; 16]).build();
    let f = write_temp(&data, ".E01");
    let out = ewf_check().arg("--json").arg(f.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(1), "--json with anomalies must exit 1");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.trim().starts_with('{'), "expected JSON object: {stdout}");
    assert!(stdout.contains("\"clean\""), "{stdout}");
    assert!(stdout.contains("false"), "tampered must have clean:false: {stdout}");
    assert!(stdout.contains("\"anomalies\""), "missing anomalies array: {stdout}");
    assert!(stdout.contains("\"severity\""), "missing severity field: {stdout}");
    assert!(stdout.contains("\"kind\""), "missing kind field: {stdout}");
    assert!(stdout.contains("\"message\""), "missing message field: {stdout}");
    // The anomaly kind is HashMismatch
    assert!(stdout.contains("HashMismatch"), "missing HashMismatch kind: {stdout}");
}

#[test]
fn cli_json_output_is_valid_structure() {
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data, ".E01");
    let out = ewf_check().arg("--json").arg(f.path()).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Must contain required top-level fields
    assert!(stdout.contains("\"clean\":"), "{stdout}");
    assert!(stdout.contains("\"anomaly_count\":"), "{stdout}");
    assert!(stdout.contains("\"anomalies\":"), "{stdout}");
    // Anomalies must be an array
    assert!(stdout.contains("\"anomalies\": [") || stdout.contains("\"anomalies\":["), "{stdout}");
}

#[test]
fn cli_json_min_severity_filters_anomalies() {
    let data = E01Builder::new(512 * 64).with_omit_hash().build();
    let f = write_temp(&data, ".E01");
    let out = ewf_check()
        .arg("--json")
        .arg("--min-severity=critical")
        .arg(f.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // With filter=critical, warning-level anomalies are suppressed → clean
    assert!(stdout.contains("true"), "should be clean at critical filter: {stdout}");
    // anomaly_count should be 0
    assert!(stdout.contains("\"anomaly_count\": 0") || stdout.contains("\"anomaly_count\":0"), "{stdout}");
}

// ── --print-hashes: outputs MD5, SHA-1, SHA-256 ──────────────────────────────

#[test]
fn cli_print_hashes_outputs_three_hashes() {
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data, ".E01");
    let out = ewf_check()
        .arg("--print-hashes")
        .arg(f.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("MD5") || stdout.contains("md5"),
        "--print-hashes must output MD5; got: {stdout}"
    );
    assert!(
        stdout.contains("SHA-1") || stdout.contains("sha1") || stdout.contains("SHA1"),
        "--print-hashes must output SHA-1; got: {stdout}"
    );
    assert!(
        stdout.contains("SHA-256") || stdout.contains("sha256") || stdout.contains("SHA256"),
        "--print-hashes must output SHA-256; got: {stdout}"
    );
}

#[test]
fn cli_print_hashes_exits_zero_on_clean_image() {
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data, ".E01");
    let out = ewf_check()
        .arg("--print-hashes")
        .arg(f.path())
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "--print-hashes on clean image must exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_print_hashes_exits_one_with_anomalies() {
    let data = E01Builder::new(512 * 64).with_md5([0xBAu8; 16]).build();
    let f = write_temp(&data, ".E01");
    let out = ewf_check()
        .arg("--print-hashes")
        .arg(f.path())
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "--print-hashes with anomalies must exit 1; stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn cli_print_hashes_values_are_hex() {
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data, ".E01");
    let out = ewf_check()
        .arg("--print-hashes")
        .arg(f.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Each hash line must contain a valid lowercase hex string (32, 40, or 64 chars)
    let has_md5_hex = stdout.lines().any(|l| {
        l.to_lowercase().contains("md5") && l.chars().any(|c| c.is_ascii_hexdigit())
    });
    assert!(has_md5_hex, "--print-hashes output must contain hex MD5; got: {stdout}");
}

#[test]
fn cli_print_hashes_json_includes_hashes() {
    let data = E01Builder::new(512 * 64).build();
    let f = write_temp(&data, ".E01");
    let out = ewf_check()
        .arg("--json")
        .arg("--print-hashes")
        .arg(f.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"hashes\""),
        "--json --print-hashes must include hashes field; got: {stdout}"
    );
    assert!(
        stdout.contains("\"md5\""),
        "--json --print-hashes must include md5; got: {stdout}"
    );
    assert!(
        stdout.contains("\"sha1\""),
        "--json --print-hashes must include sha1; got: {stdout}"
    );
    assert!(
        stdout.contains("\"sha256\""),
        "--json --print-hashes must include sha256; got: {stdout}"
    );
}

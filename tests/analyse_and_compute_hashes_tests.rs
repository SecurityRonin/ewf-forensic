#![allow(clippy::unwrap_used, clippy::expect_used)]

//! RED phase — EwfIntegrityPath::analyse_and_compute_hashes() single-pass API.
//!
//! Currently RED: the method does not exist.

mod builder;
use builder::E01Builder;
use ewf_forensic::{EwfIntegrityPath};
use std::io::Write as _;
use tempfile::NamedTempFile;

fn write_temp(data: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::with_suffix(".E01").unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

/// analyse_and_compute_hashes must return Ok for a clean image.
#[test]
fn analyse_and_compute_hashes_returns_ok_for_clean_image() {
    let image = E01Builder::new(512 * 64).build();
    let f = write_temp(&image);
    let result = EwfIntegrityPath::from_path(f.path()).analyse_and_compute_hashes();
    assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
}

/// Anomalies must match those from the standalone analyse() call.
#[test]
fn analyse_and_compute_hashes_anomalies_match_analyse() {
    let image = E01Builder::new(512 * 64).build();
    let f = write_temp(&image);
    let (combined_anomalies, _hashes) = EwfIntegrityPath::from_path(f.path())
        .analyse_and_compute_hashes()
        .unwrap();
    let standalone_anomalies = EwfIntegrityPath::from_path(f.path())
        .analyse()
        .unwrap();
    assert_eq!(
        combined_anomalies.len(),
        standalone_anomalies.len(),
        "anomaly count mismatch: combined={}, standalone={}",
        combined_anomalies.len(),
        standalone_anomalies.len()
    );
}

/// Hashes must match those from the standalone compute_hashes() call.
#[test]
fn analyse_and_compute_hashes_hashes_match_compute_hashes() {
    let image = E01Builder::new(512 * 64).build();
    let f = write_temp(&image);
    let (_anomalies, combined_hashes) = EwfIntegrityPath::from_path(f.path())
        .analyse_and_compute_hashes()
        .unwrap();
    let standalone_hashes = EwfIntegrityPath::from_path(f.path())
        .compute_hashes()
        .unwrap()
        .expect("compute_hashes returned None for valid image");
    assert_eq!(combined_hashes.md5, standalone_hashes.md5, "MD5 mismatch");
    assert_eq!(combined_hashes.sha1, standalone_hashes.sha1, "SHA-1 mismatch");
    assert_eq!(combined_hashes.sha256, standalone_hashes.sha256, "SHA-256 mismatch");
}

/// On a tampered image (bad section CRC), anomalies must still be returned
/// alongside hashes — the method does not short-circuit on anomalies.
#[test]
fn analyse_and_compute_hashes_anomalies_and_hashes_on_tampered_image() {
    let mut image = E01Builder::new(512 * 64).build();
    // Corrupt the first section descriptor CRC (bytes 68-72 of the file header + section).
    // Just flip a byte in the middle of the image to trigger some anomaly.
    if image.len() > 100 {
        image[80] ^= 0xFF;
    }
    let f = write_temp(&image);
    let result = EwfIntegrityPath::from_path(f.path()).analyse_and_compute_hashes();
    // Must still return Ok (anomalies are not I/O errors).
    assert!(result.is_ok(), "expected Ok even on tampered image, got: {:?}", result.err());
    let (anomalies, _hashes) = result.unwrap();
    assert!(
        !anomalies.is_empty(),
        "expected at least one anomaly on tampered image"
    );
}

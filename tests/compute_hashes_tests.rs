#![allow(clippy::unwrap_used, clippy::expect_used)]

mod builder;
use builder::E01Builder;
use ewf_forensic::{ComputedHashes, EwfIntegrity, EwfIntegrityPath};
use std::io::Write as _;
use tempfile::NamedTempFile;

// ── Blazehash as independent oracle ──────────────────────────────────────────
//
// E01Builder produces all-zero sector data. We compute expected hashes using
// blazehash::algorithm::hash_bytes — a completely independent code path — then
// assert ewf-forensic's compute_hashes() agrees. This is the doer-checker
// pattern: two implementations must agree or one is wrong.

use blazehash::algorithm::{hash_bytes, Algorithm};

/// Sector bytes for `E01Builder::new(512` * 64): single chunk, all zeros.
fn sector_data_for_single_chunk() -> Vec<u8> {
    vec![0u8; 512 * 64]
}

fn write_temp(data: &[u8], suffix: &str) -> NamedTempFile {
    let mut f = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

fn hex_to_16(s: &str) -> [u8; 16] {
    let b = hex::decode(s).expect("oracle hex");
    b.try_into().unwrap()
}
fn hex_to_20(s: &str) -> [u8; 20] {
    let b = hex::decode(s).expect("oracle hex");
    b.try_into().unwrap()
}
fn hex_to_32(s: &str) -> [u8; 32] {
    let b = hex::decode(s).expect("oracle hex");
    b.try_into().unwrap()
}

// ── EwfIntegrity::compute_hashes API tests ───────────────────────────────────

#[test]
fn compute_hashes_returns_some_for_valid_image() {
    let image = E01Builder::new(512 * 64).build();
    let result = EwfIntegrity::new(&image).compute_hashes();
    assert!(
        result.is_some(),
        "compute_hashes must return Some for a valid image"
    );
}

#[test]
fn compute_hashes_md5_matches_blazehash_oracle() {
    let sector_data = sector_data_for_single_chunk();
    let expected_md5_hex = hash_bytes(Algorithm::Md5, &sector_data);
    let expected: [u8; 16] = hex_to_16(&expected_md5_hex);

    let image = E01Builder::new(512 * 64).build();
    let hashes = EwfIntegrity::new(&image)
        .compute_hashes()
        .expect("must produce hashes");

    assert_eq!(
        hashes.md5,
        expected,
        "MD5 must match blazehash oracle.\n  ewf-forensic: {}\n  blazehash:    {}",
        hex_string(&hashes.md5),
        expected_md5_hex,
    );
}

#[test]
fn compute_hashes_sha1_matches_blazehash_oracle() {
    let sector_data = sector_data_for_single_chunk();
    let expected_sha1_hex = hash_bytes(Algorithm::Sha1, &sector_data);
    let expected: [u8; 20] = hex_to_20(&expected_sha1_hex);

    let image = E01Builder::new(512 * 64).build();
    let hashes = EwfIntegrity::new(&image)
        .compute_hashes()
        .expect("must produce hashes");

    assert_eq!(
        hashes.sha1,
        expected,
        "SHA-1 must match blazehash oracle.\n  ewf-forensic: {}\n  blazehash:    {}",
        hex_string(&hashes.sha1),
        expected_sha1_hex,
    );
}

#[test]
fn compute_hashes_sha256_matches_blazehash_oracle() {
    let sector_data = sector_data_for_single_chunk();
    let expected_sha256_hex = hash_bytes(Algorithm::Sha256, &sector_data);
    let expected: [u8; 32] = hex_to_32(&expected_sha256_hex);

    let image = E01Builder::new(512 * 64).build();
    let hashes = EwfIntegrity::new(&image)
        .compute_hashes()
        .expect("must produce hashes");

    assert_eq!(
        hashes.sha256,
        expected,
        "SHA-256 must match blazehash oracle.\n  ewf-forensic: {}\n  blazehash:    {}",
        hex_string(&hashes.sha256),
        expected_sha256_hex,
    );
}

/// All three hashes must be internally consistent:
/// the MD5 in `compute_hashes` must equal the stored MD5 in the image.
#[test]
fn compute_hashes_md5_consistent_with_stored_hash() {
    let image = E01Builder::new(512 * 64).build();
    let findings = EwfIntegrity::new(&image).analyse();

    // Clean image: no HashMismatch anomaly (stored MD5 is correct)
    assert!(
        findings
            .iter()
            .all(|a| !matches!(a, ewf_forensic::EwfIntegrityAnomaly::HashMismatch { .. })),
        "builder must produce clean image; got: {findings:#?}"
    );

    // compute_hashes must agree with the stored hash that verify() just accepted
    let hashes = EwfIntegrity::new(&image)
        .compute_hashes()
        .expect("must produce hashes");

    // Cross check: feed hashes.md5 back as expected_md5 — should produce no mismatch
    let findings2 = EwfIntegrity::new(&image)
        .with_expected_md5(hashes.md5)
        .analyse();
    assert!(
        findings2.iter().all(|a| !matches!(
            a,
            ewf_forensic::EwfIntegrityAnomaly::ExternalMd5Mismatch { .. }
        )),
        "compute_hashes().md5 must agree with verification path; got: {findings2:#?}"
    );
}

#[test]
fn compute_hashes_returns_none_for_invalid_image() {
    // Too short to parse
    let bad = vec![0u8; 4];
    let result = EwfIntegrity::new(&bad).compute_hashes();
    assert!(
        result.is_none(),
        "compute_hashes on unparseable image should return None"
    );
}

// ── EwfIntegrityPath::compute_hashes ─────────────────────────────────────────

#[test]
fn ewf_integrity_path_compute_hashes_matches_ewf_integrity() {
    let image = E01Builder::new(512 * 64).build();
    let f = write_temp(&image, ".E01");

    let via_path = EwfIntegrityPath::from_path(f.path())
        .compute_hashes()
        .expect("analyse must not error")
        .expect("must produce hashes for valid image");

    let via_slice = EwfIntegrity::new(&image)
        .compute_hashes()
        .expect("must produce hashes");

    assert_eq!(via_path.md5, via_slice.md5, "MD5 must agree");
    assert_eq!(via_path.sha1, via_slice.sha1, "SHA-1 must agree");
    assert_eq!(via_path.sha256, via_slice.sha256, "SHA-256 must agree");
}

// ── ComputedHashes public type ────────────────────────────────────────────────

#[test]
fn computed_hashes_type_is_public() {
    // Verify the type is accessible and its fields are public
    let sector_data = sector_data_for_single_chunk();
    let expected_md5 = hex_to_16(&hash_bytes(Algorithm::Md5, &sector_data));
    let expected_sha1 = hex_to_20(&hash_bytes(Algorithm::Sha1, &sector_data));
    let expected_sha256 = hex_to_32(&hash_bytes(Algorithm::Sha256, &sector_data));

    let image = E01Builder::new(512 * 64).build();
    let hashes: ComputedHashes = EwfIntegrity::new(&image)
        .compute_hashes()
        .expect("must produce hashes");

    // Access fields directly — they must be pub
    let md5: [u8; 16] = hashes.md5;
    let sha1: [u8; 20] = hashes.sha1;
    let sha256: [u8; 32] = hashes.sha256;

    assert_eq!(md5, expected_md5);
    assert_eq!(sha1, expected_sha1);
    assert_eq!(sha256, expected_sha256);
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

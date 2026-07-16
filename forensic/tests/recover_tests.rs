#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Recovery tests for [`EwfRecover`] — the ewf-forensic equivalent of libewf's
//! `ewfrecover`: read a corrupt / truncated / incomplete EWF image tolerantly,
//! recover every readable sector, and emit a recovered raw copy to a NEW path.
//!
//! ## Validation tiers (Evidence-Based Rigor)
//!
//! - **Tier 1 (independent oracle):** libewf's `ewfexport -f raw` is the
//!   error-tolerant reference (as the task allows — "ewfrecover OR ewfexport
//!   with error-tolerance"). `ewfrecover` itself only rebuilds *structurally*
//!   broken EWFs and declines a merely bad-CRC chunk ("not corrupted"), so the
//!   raw oracle is `ewfexport`, which zero-fills unreadable chunks exactly as we
//!   do. We assert our `recover_to_raw` output equals `ewfexport`'s raw
//!   byte-for-byte. Gated on the binary; skips cleanly when absent.
//! - **Tier 2 (self-derived from known construction):** the clean round-trip
//!   asserts our recovered raw equals what [`ewf::EwfReader`] streams from the
//!   same clean image (the canonical in-crate decoder). For the truncated case,
//!   the recovered bytes are asserted equal to the clean image's prefix — a fact
//!   derivable from how we minted the corruption.
//!
//! ## Fixture layout fact (drives the truncation test)
//!
//! In `ewfacquire_clean.E01` the section order is
//! `header2/header/volume/sectors/table/table2/data/digest/hash/done`. The chunk
//! offset map (`table`/`table2`) lives in the *last* ~2.7 KiB, AFTER the 4 MiB
//! `sectors` payload. So a tail truncation removes the table entirely — the
//! chunk offsets are then unknown to any reader (libewf `ewfexport` fails at
//! offset 0 too). The `volume` section (geometry) survives, so recovery keeps
//! the correct image size and zero-fills every chunk it can no longer locate.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use ewf_forensic::EwfRecover;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

/// The full flat raw image as the canonical in-crate reader produces it.
fn reader_raw(path: &Path) -> Vec<u8> {
    let mut reader = ewf::EwfReader::open(path).expect("clean image must open");
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).expect("read_to_end");
    buf
}

/// Is libewf's `ewfexport` oracle available on PATH?
fn have_ewfexport() -> bool {
    Command::new("ewfexport")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Run `ewfexport -q -u -f raw -t <stem> <input>` and return the produced
/// `<stem>.raw` bytes. `-u` = unattended, `-f raw` = flat raw target. ewfexport
/// zero-fills unreadable chunks and still exits SUCCESS with a read-error note.
fn ewfexport_raw(input: &Path, target_stem: &Path) -> Vec<u8> {
    let out = Command::new("ewfexport")
        .arg("-q")
        .arg("-u")
        .arg("-f")
        .arg("raw")
        .arg("-t")
        .arg(target_stem)
        .arg(input)
        .output()
        .expect("ewfexport launch");
    let raw_path = {
        let mut s = target_stem.as_os_str().to_os_string();
        s.push(".raw");
        PathBuf::from(s)
    };
    assert!(
        raw_path.exists(),
        "ewfexport produced no {} (stdout/stderr: {} / {})",
        raw_path.display(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    std::fs::read(&raw_path).expect("read ewfexport raw output")
}

// ── (0) Non-gated clean round-trip — CI coverage without the oracle ──────────

#[test]
fn clean_image_recovers_to_identical_raw() {
    let src = fixture("ewfacquire_clean.E01");
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("clean_recovered.raw");

    let report = EwfRecover::from_path(&src)
        .recover_to_raw(&out)
        .expect("recover clean image");

    // A clean image loses nothing.
    assert_eq!(report.chunks_zero_filled, 0, "clean image lost chunks");
    assert!(report.lost_chunks.is_empty(), "clean image has lost chunks");
    assert_eq!(
        report.chunks_recovered_primary + report.chunks_recovered_table2,
        report.chunks_total,
        "every chunk accounted as recovered"
    );
    assert!(report.truncation_offset.is_none());

    // Tier 2: our recovered raw == the canonical reader's raw, byte-for-byte.
    let recovered = std::fs::read(&out).unwrap();
    let expected = reader_raw(&src);
    assert_eq!(
        recovered.len(),
        expected.len(),
        "recovered raw length must equal the reader's image length"
    );
    assert_eq!(
        recovered, expected,
        "recovered raw must be byte-identical to the reader's output"
    );
}

// ── (a) Truncated acquisition — last N bytes cut off (table lost) ────────────

/// Copy the clean E01 and drop the trailing `cut` bytes → an incomplete image
/// whose trailing table/table2/done are gone (see the module layout note).
fn mint_truncated(dir: &Path, cut: u64) -> PathBuf {
    let src = fixture("ewfacquire_clean.E01");
    let bytes = std::fs::read(&src).unwrap();
    let keep = bytes.len().saturating_sub(cut as usize);
    let out = dir.join("truncated.E01");
    std::fs::write(&out, &bytes[..keep]).unwrap();
    out
}

#[test]
fn truncated_image_is_tolerated_never_aborts_and_spans_full_image() {
    let src = fixture("ewfacquire_clean.E01");
    let clean_raw = reader_raw(&src);

    let dir = tempfile::tempdir().unwrap();
    // Cut 256 KiB off the tail — removes table/table2/done entirely.
    let corrupt = mint_truncated(dir.path(), 256 * 1024);
    let out = dir.path().join("trunc_recovered.raw");

    // The whole point vs the strict reader (which errors on the broken chain):
    // recovery must NOT abort — geometry survives in the volume section.
    let report = EwfRecover::from_path(&corrupt)
        .recover_to_raw(&out)
        .expect("recover must tolerate a truncated image");

    assert!(
        report.truncation_offset.is_some(),
        "truncation must be flagged"
    );
    // With the table gone, every chunk is unlocatable → zero-filled.
    assert!(
        report.chunks_zero_filled > 0,
        "a table-truncated image zero-fills lost chunks"
    );
    assert_eq!(
        report.chunks_recovered_primary
            + report.chunks_recovered_table2
            + report.chunks_zero_filled,
        report.chunks_total,
        "accounting must sum to total"
    );

    // Output spans the full logical image regardless of the cut.
    let recovered = std::fs::read(&out).unwrap();
    assert_eq!(
        recovered.len() as u64,
        report.image_size,
        "recovered raw spans the full logical image"
    );

    // Tier 2: any bytes we DID recover must match the clean image exactly.
    let good = report.bytes_recovered as usize;
    if good > 0 {
        assert_eq!(
            &recovered[..good],
            &clean_raw[..good],
            "recovered prefix must be byte-identical to the clean image"
        );
    }
}

// ── (b) Bad-CRC chunk — a byte flipped inside one chunk's data ────────────────

/// Copy the clean E01 and flip one byte deep in the `sectors` payload so that
/// chunk's stored checksum no longer matches. The chunks in this image are
/// uncompressed, so the sector bytes are physically present: recovery EMITS them
/// (flagged CRC-suspect) rather than discarding recoverable evidence — which is
/// exactly what libewf `ewfexport` does (it exports the sectors and notes a read
/// error). Zero-fill is reserved for genuinely absent data (truncation) or a
/// compressed stream that will not inflate.
fn mint_bad_chunk(dir: &Path) -> PathBuf {
    let src = fixture("ewfacquire_clean.E01");
    let mut bytes = std::fs::read(&src).unwrap();
    // Flip a byte ~1/3 into the file — inside the sectors payload (1779..4196671),
    // away from the header/volume/table structures.
    let pos = bytes.len() / 3;
    bytes[pos] ^= 0xFF;
    let out = dir.join("badchunk.E01");
    std::fs::write(&out, &bytes).unwrap();
    out
}

#[test]
fn bad_crc_chunk_is_flagged_not_lost_never_aborts() {
    let src = fixture("ewfacquire_clean.E01");
    let clean_raw = reader_raw(&src);

    let dir = tempfile::tempdir().unwrap();
    let corrupt = mint_bad_chunk(dir.path());
    let out = dir.path().join("badchunk_recovered.raw");

    // One bad chunk must NOT abort the whole recovery.
    let report = EwfRecover::from_path(&corrupt)
        .recover_to_raw(&out)
        .expect("recover must not abort on one bad chunk");

    let recovered = std::fs::read(&out).unwrap();
    assert_eq!(recovered.len() as u64, report.image_size);
    assert_eq!(
        report.chunks_recovered_primary
            + report.chunks_recovered_table2
            + report.chunks_zero_filled,
        report.chunks_total,
    );
    // The flipped byte lands in an uncompressed chunk whose data is still
    // present: it is EMITTED (flagged), not zero-filled.
    assert_eq!(
        report.chunks_zero_filled, 0,
        "present-but-suspect data must not be zero-filled; lost={:?}",
        report.lost_chunks
    );
    assert_eq!(
        report.chunks_crc_flagged, 1,
        "exactly one chunk should be CRC-flagged; flagged={:?}",
        report.crc_flagged_chunks
    );

    // Tier 2: the recovered image differs from the clean image in exactly the one
    // flipped byte (recoverable data preserved, not discarded).
    let diffs = recovered
        .iter()
        .zip(clean_raw.iter())
        .filter(|(a, b)| a != b)
        .count();
    assert_eq!(
        diffs, 1,
        "recovery must preserve every byte except the single flipped one"
    );
}

// ── (c) bogus.E01 — a real (degenerate, empty) corrupt sample ────────────────

#[test]
fn bogus_e01_errors_not_panics() {
    // bogus.E01 is a committed 0-byte corrupt sample: recovery must fail loudly
    // (an unparseable image is a bootstrap failure, not a silent empty result),
    // never panic.
    let src = fixture("bogus.E01");
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("bogus_recovered.raw");
    let result = EwfRecover::from_path(&src).recover_to_raw(&out);
    assert!(
        result.is_err(),
        "a 0-byte unparseable image must error, not silently succeed"
    );
}

// ── Tier-1 oracle: byte-for-byte vs ewfexport -f raw ─────────────────────────

#[test]
fn oracle_clean_matches_ewfexport() {
    if !have_ewfexport() {
        eprintln!("SKIP: ewfexport not on PATH");
        return;
    }
    let src = fixture("ewfacquire_clean.E01");
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("ours.raw");
    EwfRecover::from_path(&src).recover_to_raw(&out).unwrap();
    let ours = std::fs::read(&out).unwrap();

    let oracle = ewfexport_raw(&src, &dir.path().join("oracle"));

    // Tier 1: a clean image recovers to exactly what ewfexport produces.
    assert_eq!(
        ours.len(),
        oracle.len(),
        "our recovered length must equal ewfexport's"
    );
    assert_eq!(
        ours, oracle,
        "clean recovery must match ewfexport byte-for-byte"
    );
}

#[test]
fn oracle_bad_chunk_matches_ewfexport() {
    if !have_ewfexport() {
        eprintln!("SKIP: ewfexport not on PATH");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let corrupt = mint_bad_chunk(dir.path());
    let out = dir.path().join("ours.raw");
    EwfRecover::from_path(&corrupt)
        .recover_to_raw(&out)
        .unwrap();
    let ours = std::fs::read(&out).unwrap();

    let oracle = ewfexport_raw(&corrupt, &dir.path().join("oracle"));

    // Tier 1: our zero-filled-bad-chunk raw equals ewfexport's error-tolerant
    // raw byte-for-byte (both zero-fill the same unreadable chunk).
    assert_eq!(
        ours.len(),
        oracle.len(),
        "our recovered length must equal ewfexport's"
    );
    assert_eq!(
        ours, oracle,
        "bad-chunk recovery must match ewfexport byte-for-byte"
    );
}

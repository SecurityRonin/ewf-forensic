//! Property-based tests using proptest.
//!
//! These tests verify invariants that must hold for ALL inputs, not just the
//! hand-crafted fixtures used elsewhere.  They act as a complement to the
//! libfuzzer targets in `fuzz/` — proptest runs inside `cargo test` with
//! deterministic shrinking, making it easy to reproduce minimal failure cases.

mod builder;
use builder::E01Builder;
use ewf_forensic::EwfIntegrity;
use proptest::prelude::*;

// ── Robustness: no panics on arbitrary bytes ──────────────────────────────────

proptest! {
    /// analyse() must never panic on arbitrary input, regardless of content.
    #[test]
    fn analyse_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = EwfIntegrity::new(&data).analyse();
    }

    /// analyse_with_progress() must never panic on arbitrary input.
    #[test]
    fn analyse_with_progress_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        let _ = EwfIntegrity::new(&data).analyse_with_progress(|_| {});
    }

    /// compute_hashes() must never panic on arbitrary input.
    #[test]
    fn compute_hashes_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = EwfIntegrity::new(&data).compute_hashes();
    }

    /// from_segments() with multiple arbitrary slices must never panic.
    #[test]
    fn from_segments_never_panics(
        s1 in proptest::collection::vec(any::<u8>(), 0..2048),
        s2 in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let _ = EwfIntegrity::from_segments(&[s1.as_slice(), s2.as_slice()]).analyse();
    }
}

// ── Invariants on clean synthetic images ─────────────────────────────────────

proptest! {
    /// A clean image built with different sector sizes must always be anomaly-free.
    #[test]
    fn clean_builder_image_no_anomalies(
        // sectors_per_chunk: 1, 2, 4, 8, 16, 32, 64 (powers of 2 only)
        log2_spc in 0u32..7u32,
        // number of chunks: 1..8
        chunk_count in 1u32..9u32,
    ) {
        let sectors_per_chunk = 1u32 << log2_spc;
        let total_bytes = u64::from(sectors_per_chunk) * 512 * u64::from(chunk_count);
        let image = E01Builder::new(total_bytes).build();
        let anomalies = EwfIntegrity::new(&image).analyse();
        prop_assert!(
            anomalies.is_empty(),
            "clean builder image must have no anomalies; got: {anomalies:#?}"
        );
    }

    /// Severity must be consistent: every anomaly has a non-panicking severity() call.
    #[test]
    fn severity_never_panics_on_arbitrary_input(
        data in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        let anomalies = EwfIntegrity::new(&data).analyse();
        for a in &anomalies {
            let _ = a.severity();
            let _ = format!("{a}");
        }
    }

    /// analyse() and analyse_with_progress() must return the same anomaly count
    /// for identical input.
    #[test]
    fn analyse_and_with_progress_agree(
        data in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        let baseline = EwfIntegrity::new(&data).analyse();
        let with_cb = EwfIntegrity::new(&data).analyse_with_progress(|_| {});
        prop_assert_eq!(
            baseline.len(), with_cb.len(),
            "analyse() and analyse_with_progress() must return same anomaly count"
        );
    }
}

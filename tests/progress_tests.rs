#![allow(clippy::unwrap_used, clippy::expect_used)]

//! RED phase — streaming / progress callback API.
//!
//! `EwfIntegrity::analyse_with_progress(f)` must call `f` at least once per
//! chunk processed, report monotonically increasing `chunks_done`, and return
//! the same anomaly set as `analyse()`.
//!
//! Tested against both EWF v1 (zeros_128s via builder) and EWF v2 (zeros_128s.Ex01).

mod builder;
use builder::E01Builder;
use ewf_forensic::{AnalysisProgress, EwfIntegrity};
use std::path::PathBuf;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn ewf1_fixture() -> Vec<u8> {
    // 128 sectors × 512 bytes = 65536 bytes; default 64 sectors/chunk → 2 chunks
    E01Builder::new(65536).build()
}

fn ewf2_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/zeros_128s.Ex01")
}

// ── EWF v1 progress tests ─────────────────────────────────────────────────────

/// analyse_with_progress must call the callback at least once for an image
/// with sector data.
#[test]
fn ewf1_progress_called_at_least_once() {
    let data = ewf1_fixture();
    let mut call_count = 0usize;
    EwfIntegrity::new(&data).analyse_with_progress(|_p| {
        call_count += 1;
    });
    assert!(call_count > 0, "progress callback must be called at least once");
}

/// chunks_done in the progress callback must be monotonically non-decreasing.
#[test]
fn ewf1_progress_chunks_done_monotone() {
    let data = ewf1_fixture();
    let mut last = 0usize;
    EwfIntegrity::new(&data).analyse_with_progress(|p: AnalysisProgress| {
        assert!(
            p.chunks_done >= last,
            "chunks_done must not decrease: was {last}, now {}",
            p.chunks_done
        );
        last = p.chunks_done;
    });
}

/// The final progress report must have chunks_done > 0 for an image with data.
#[test]
fn ewf1_progress_final_chunks_done_nonzero() {
    let data = ewf1_fixture();
    let mut final_progress: Option<AnalysisProgress> = None;
    EwfIntegrity::new(&data).analyse_with_progress(|p: AnalysisProgress| {
        final_progress = Some(p);
    });
    let p = final_progress.expect("at least one progress callback must fire");
    assert!(p.chunks_done > 0, "final chunks_done must be > 0; got {}", p.chunks_done);
}

/// analyse_with_progress must return the same anomalies as analyse().
#[test]
fn ewf1_progress_same_anomalies_as_analyse() {
    let data = ewf1_fixture();
    let baseline = EwfIntegrity::new(&data).analyse();
    let with_progress = EwfIntegrity::new(&data).analyse_with_progress(|_| {});
    assert_eq!(
        baseline, with_progress,
        "analyse_with_progress must return same anomalies as analyse()"
    );
}

/// bytes_done in progress must be monotonically non-decreasing.
#[test]
fn ewf1_progress_bytes_done_monotone() {
    let data = ewf1_fixture();
    let mut last_bytes = 0u64;
    EwfIntegrity::new(&data).analyse_with_progress(|p: AnalysisProgress| {
        assert!(
            p.bytes_done >= last_bytes,
            "bytes_done must not decrease: was {last_bytes}, now {}",
            p.bytes_done
        );
        last_bytes = p.bytes_done;
    });
}

// ── EWF v2 progress tests ─────────────────────────────────────────────────────

/// EWF v2 progress: chunks_total must equal the actual chunk count when known.
#[test]
fn ewf2_progress_chunks_total_matches_chunk_table() {
    let path = ewf2_fixture_path();
    if !path.exists() {
        eprintln!("skipping: fixture not found");
        return;
    }
    let data = std::fs::read(&path).expect("read fixture");
    // zeros_128s.Ex01: 2 chunks (64 sectors × 2, chunk_size=64 sectors)
    let mut last: Option<AnalysisProgress> = None;
    EwfIntegrity::new(&data).analyse_with_progress(|p: AnalysisProgress| {
        last = Some(p);
    });
    let p = last.expect("at least one callback");
    assert_eq!(
        p.chunks_total,
        Some(2),
        "zeros_128s.Ex01 has 2 chunks; chunks_total must be Some(2), got {:?}",
        p.chunks_total
    );
    assert_eq!(
        p.chunks_done, 2,
        "final chunks_done must equal chunks_total=2, got {}",
        p.chunks_done
    );
}

/// EWF v2 analyse_with_progress returns same anomalies as analyse().
#[test]
fn ewf2_progress_same_anomalies_as_analyse() {
    let path = ewf2_fixture_path();
    if !path.exists() {
        eprintln!("skipping: fixture not found");
        return;
    }
    let data = std::fs::read(&path).expect("read fixture");
    let baseline = EwfIntegrity::new(&data).analyse();
    let with_progress = EwfIntegrity::new(&data).analyse_with_progress(|_| {});
    assert_eq!(baseline, with_progress);
}

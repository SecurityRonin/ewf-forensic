#![allow(clippy::unwrap_used, clippy::expect_used)]

//! RED phase — `EwfIntegrityPath::analyse_with_progress()`.
//!
//! The path-based API must expose a progress callback so callers can report
//! progress while analysing large (multi-GB) evidence files.
//!
//! Currently RED: `EwfIntegrityPath` has no `analyse_with_progress` method.

mod builder;
use builder::E01Builder;
use ewf_forensic::{AnalysisProgress, EwfIntegrityPath};
use std::io::Write as _;
use tempfile::NamedTempFile;

fn write_temp(data: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::with_suffix(".E01").unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

/// `analyse_with_progress` must return the same anomalies as `analyse()`.
///
/// Currently RED: method does not exist.
#[test]
fn path_analyse_with_progress_matches_analyse() {
    let image = E01Builder::new(512 * 64).build();
    let f = write_temp(&image);
    let checker = EwfIntegrityPath::from_path(f.path());

    let standalone = checker.analyse().unwrap();
    let (with_progress, ()) = checker
        .analyse_with_progress(|_p: AnalysisProgress| {})
        .unwrap();

    assert_eq!(
        standalone.len(),
        with_progress.len(),
        "anomaly count must match between analyse() and analyse_with_progress()"
    );
}

/// The progress callback must be invoked at least once for a non-trivial image.
///
/// Currently RED: method does not exist.
#[test]
fn path_analyse_with_progress_callback_invoked() {
    let image = E01Builder::new(512 * 64 * 4).build(); // 4 chunks
    let f = write_temp(&image);

    let mut call_count = 0usize;
    EwfIntegrityPath::from_path(f.path())
        .analyse_with_progress(|_p: AnalysisProgress| {
            call_count += 1;
        })
        .unwrap();

    assert!(
        call_count > 0,
        "progress callback must be invoked at least once"
    );
}

#![no_main]
use ewf_forensic::EwfIntegrity;
use libfuzzer_sys::fuzz_target;

// Fuzz the multi-segment reassembly path. Splitting the input into two segments
// drives `from_segments` reassembly plus header-metadata (zlib) decoding and
// hash computation over attacker-controlled bytes — a distinct parsed structure
// from the single-buffer `fuzz_integrity` target. All corruption must be
// reported as an anomaly (or `None`), never panicked.
fuzz_target!(|data: &[u8]| {
    let mid = data.len() / 2;
    let (a, b) = data.split_at(mid);
    let integrity = EwfIntegrity::from_segments(&[a, b]);
    let _ = integrity.analyse();
    let _ = integrity.compute_hashes();
    let _ = integrity.header_metadata();
});

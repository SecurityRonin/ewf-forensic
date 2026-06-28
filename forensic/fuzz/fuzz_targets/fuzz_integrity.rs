#![no_main]
use ewf_forensic::EwfIntegrity;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must not panic on any input — all anomalies must be reported, not panicked.
    let _ = EwfIntegrity::new(data).analyse();
});

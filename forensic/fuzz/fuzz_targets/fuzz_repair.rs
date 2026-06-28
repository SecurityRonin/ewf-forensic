#![no_main]
use ewf_forensic::EwfRepair;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must not panic on any input — repair must degrade gracefully on corrupt data.
    let _ = EwfRepair::new(data.to_vec()).repair();
});

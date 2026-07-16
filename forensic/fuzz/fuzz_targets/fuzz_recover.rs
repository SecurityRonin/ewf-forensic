#![no_main]
use ewf_forensic::EwfRecover;
use libfuzzer_sys::fuzz_target;
use std::io::Write;

// Fuzz the tolerant recovery path over attacker-controlled EWF bytes. The input
// is written to a temp segment and driven through `recover_to_raw`, exercising
// the section-chain walk, volume-geometry parse, table/table2 entry decode, and
// per-chunk zlib inflate / Adler-32 checks — all on hostile input. Recovery must
// return an error or a `RecoveryReport`, never panic (no unwrap/expect/OOB in
// production code). The output goes to a scratch temp file that is discarded.
fuzz_target!(|data: &[u8]| {
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let src = dir.path().join("fuzz.E01");
    {
        let mut f = match std::fs::File::create(&src) {
            Ok(f) => f,
            Err(_) => return,
        };
        if f.write_all(data).is_err() {
            return;
        }
    }
    let out = dir.path().join("fuzz.raw");
    // Ignore the Result: an error is a valid tolerant outcome; a panic is not.
    let _ = EwfRecover::from_path(&src).recover_to_raw(&out);
});

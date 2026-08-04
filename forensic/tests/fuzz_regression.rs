//! Inputs that once aborted recovery, kept as ordinary tests.
//!
//! The fixture is the reproducer libFuzzer actually found, downloaded from the
//! failing `fuzz_recover` run's artifact rather than hand-authored.
//!
//! Unlike the `parse_segment` crash this one is not a panic: AddressSanitizer
//! reported `allocation-size-too-big`, i.e. a length taken from the image was
//! handed to an allocation. That fails loudly under ASan and, without it,
//! simply asks the allocator for whatever the image claimed.
//!
//! The assertion is deliberately weak on *what* comes back. A malformed image
//! may legitimately fail to recover, or recover partially with findings; the
//! contract under test is only that it returns rather than aborting.

use std::io::Write;

use ewf_forensic::EwfRecover;

/// `fuzz_recover` reproducer: an image-declared count reached an allocation.
const RECOVER_CRASH: &[u8] = include_bytes!("data/fuzz-crash-recover-alloc-too-big.E01");

#[test]
fn recover_reproducer_does_not_abort() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("fuzz.E01");
    let mut f = std::fs::File::create(&src).expect("create fixture");
    f.write_all(RECOVER_CRASH).expect("write fixture");
    drop(f);

    let out = dir.path().join("fuzz.raw");
    let _ = EwfRecover::from_path(&src).recover_to_raw(&out);
}

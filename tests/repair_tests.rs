mod builder;

use builder::E01Builder;
use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly, EwfRepair};

fn clean_image() -> Vec<u8> {
    E01Builder::new(512 * 64).build()
}

// Test R1: clean image needs no repairs
#[test]
fn repair_clean_image_no_repairs() {
    let image = clean_image();
    let result = EwfRepair::new(image).repair();
    assert!(
        result.repairs.is_empty(),
        "clean image should need no repairs"
    );
    assert!(
        result.cannot_repair.is_empty(),
        "clean image should have no unrepairable issues"
    );
}

// Test R2: section descriptor CRC mismatch is repairable
#[test]
fn repair_crc_mismatch_is_repaired() {
    let image = E01Builder::new(512 * 64).with_corrupt_volume_crc().build();
    let result = EwfRepair::new(image).repair();
    assert!(
        !result.repairs.is_empty(),
        "expected at least one repair action"
    );
    // After repair, running integrity should find no CRC errors
    let post = EwfIntegrity::new(&result.data).analyse();
    assert!(
        !post
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::SectionDescriptorCrcMismatch { .. })),
        "after repair, CRC mismatch should be resolved; got: {post:#?}"
    );
}

// Test R3: hash mismatch cannot be repaired automatically
#[test]
fn repair_hash_mismatch_not_repairable() {
    let bad_hash = [0xBAu8; 16];
    let image = E01Builder::new(512 * 64).with_md5(bad_hash).build();
    let result = EwfRepair::new(image).repair();
    assert!(
        !result.cannot_repair.is_empty(),
        "hash mismatch should be flagged as unrepairable; got: {result:#?}",
        result = result.cannot_repair,
    );
}

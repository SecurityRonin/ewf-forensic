//! Tests for EwfDescriptorCanonicaliser (the renamed EwfRepair).
//!
//! RED phase: these fail until EwfDescriptorCanonicaliser is introduced.
mod builder;
use builder::E01Builder;
use ewf_forensic::{EwfDescriptorCanonicaliser, EwfIntegrity, EwfIntegrityAnomaly};

// ── New name: EwfDescriptorCanonicaliser ──────────────────────────────────────

#[test]
fn canonicaliser_new_repairs_crc() {
    let image = E01Builder::new(512 * 64).with_corrupt_volume_crc().build();
    let report = EwfDescriptorCanonicaliser::new(image).canonicalise();
    assert!(
        !report.repairs.is_empty(),
        "expected CRC repair, got none"
    );
    let post = EwfIntegrity::new(&report.segments[0]).analyse();
    assert!(
        !post
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::SectionDescriptorCrcMismatch { .. })),
        "after canonicalise, CRC mismatch must be resolved; got: {post:#?}"
    );
}

#[test]
fn canonicaliser_from_segments_repairs_crc() {
    let image = E01Builder::new(512 * 64).with_corrupt_volume_crc().build();
    let report = EwfDescriptorCanonicaliser::from_segments(vec![image]).canonicalise();
    assert!(!report.repairs.is_empty());
}

#[test]
fn canonicaliser_clean_image_no_repairs() {
    let image = E01Builder::new(512 * 64).build();
    let report = EwfDescriptorCanonicaliser::new(image).canonicalise();
    assert!(report.repairs.is_empty());
    assert!(report.cannot_repair.is_empty());
}

// ── Old name EwfRepair still compiles via deprecated alias ───────────────────

#[allow(deprecated)]
#[test]
fn ewf_repair_alias_still_works() {
    use ewf_forensic::EwfRepair;
    let image = E01Builder::new(512 * 64).build();
    // Calling the old .repair() method must still work.
    let report = EwfRepair::new(image).repair();
    assert!(report.repairs.is_empty());
}

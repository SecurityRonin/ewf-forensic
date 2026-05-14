use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly};

// ── EWF v2 signature ──────────────────────────────────────────────────────────
const EVF2_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];

fn minimal_ewf2() -> Vec<u8> {
    // Bare-minimum EWF v2 header: 32-byte file header with valid signature,
    // followed by a single done-section descriptor (64 bytes, type=0x0F).
    // Section types: 0x0F = done.
    let mut data = vec![0u8; 32 + 64];
    data[0..8].copy_from_slice(&EVF2_SIGNATURE);
    // Segment number at bytes [12..16] = 1
    data[12..16].copy_from_slice(&1u32.to_le_bytes());
    // Section descriptor at offset 32: type = 0x0F (done)
    data[32..36].copy_from_slice(&0x0Fu32.to_le_bytes()); // section_type
    // data_size = 0, padding_size = 0, stored_hash = all-zero (skip hash check)
    data
}

/// EWF v2 analysis must always include Ewf2SectorDataNotVerified.
/// This makes explicit that chunk-level verification was not performed.
#[test]
fn ewf2_always_emits_sector_data_not_verified() {
    let image = minimal_ewf2();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2SectorDataNotVerified)),
        "expected Ewf2SectorDataNotVerified; got: {findings:#?}"
    );
}

/// Ewf2SectorDataNotVerified must be Info severity — it is not an error,
/// just an honesty signal that coverage was partial.
#[test]
fn ewf2_sector_data_not_verified_is_info_severity() {
    use ewf_forensic::Severity;
    let image = minimal_ewf2();
    let findings = EwfIntegrity::new(&image).analyse();
    let anomaly = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::Ewf2SectorDataNotVerified))
        .expect("Ewf2SectorDataNotVerified missing");
    assert_eq!(
        anomaly.severity(),
        Severity::Info,
        "Ewf2SectorDataNotVerified must be Info, not {:?}",
        anomaly.severity()
    );
}

/// Ewf2SectorDataNotVerified must have a human-readable Display message.
#[test]
fn ewf2_sector_data_not_verified_display_is_readable() {
    let image = minimal_ewf2();
    let findings = EwfIntegrity::new(&image).analyse();
    let anomaly = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::Ewf2SectorDataNotVerified))
        .expect("Ewf2SectorDataNotVerified missing");
    let s = format!("{anomaly}");
    assert!(!s.is_empty(), "Display is empty");
    // Should not be Rust debug format
    assert!(!s.contains("{ "), "Display looks like Debug: {s:?}");
    // Should mention EWF v2 or sector or not verified
    let sl = s.to_lowercase();
    assert!(
        sl.contains("sector") || sl.contains("v2") || sl.contains("verif") || sl.contains("chunk"),
        "message should reference sector/chunk verification: {s:?}"
    );
}

/// Ewf2SectorDataNotVerified must NOT appear for EWF v1 images.
#[test]
fn ewf1_does_not_emit_sector_data_not_verified() {
    // EWF v1 signature
    let evf1_sig = [0x45u8, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
    let mut data = vec![0u8; 13]; // too short to parse — just needs v1 sig
    data[0..8].copy_from_slice(&evf1_sig);
    let findings = EwfIntegrity::new(&data).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::Ewf2SectorDataNotVerified)),
        "Ewf2SectorDataNotVerified must not appear in EWF v1 analysis; got: {findings:#?}"
    );
}

//! RED phase — EWF v1 table header Adler-32 verification.
//!
//! The table header (24 bytes) has the structure:
//!   [0..4]:   `entry_count` (u32 LE)
//!   [4..8]:   reserved (u32, zero)
//!   [8..16]:  `base_offset` (u64 LE)
//!   [16..20]: Adler-32 of bytes [0..16]
//!   [20..24]: padding (zeros)
//!
//! The current `check_table_v1` reads `entry_count` and `base_offset` but never
//! checks the Adler-32 at bytes [16..20].
//!
//! Currently RED: no `TableHeaderAdler32Mismatch` anomaly is ever emitted.

mod builder;
use builder::E01Builder;
use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly};

/// Offset into the built image where the table section's data begins.
/// Layout: `file_header(13)` + `header_section(76+1)` + volume(76+94) + `table_descriptor(76)`
/// = 13 + 77 + 170 + 76 = 336
/// But simpler: use `E01Builder` and search for the adler32 bytes.
fn tamper_table_header_crc(mut image: Vec<u8>) -> Vec<u8> {
    // E01Builder produces a deterministic layout.  The table header starts
    // right after the 76-byte table section descriptor.  We locate the
    // "table" section descriptor by scanning for the ASCII bytes "table"
    // at the start of a descriptor (section-type field).
    let needle = b"table\0\0\0\0\0\0\0\0\0\0\0"; // 16-byte section type field
    if let Some(pos) = image.windows(16).position(|w| w.starts_with(b"table")) {
        // Table header starts at pos + 76 (descriptor size)
        let hdr_off = pos + 76;
        // Adler-32 is at hdr_off + 16..hdr_off + 20.  Corrupt it.
        if hdr_off + 20 <= image.len() {
            image[hdr_off + 16] ^= 0xFF; // flip bits in the stored CRC
        }
    }
    let _ = needle; // suppress unused warning
    image
}

/// A clean image must not produce `TableHeaderAdler32Mismatch`.
#[test]
fn table_header_crc_clean_no_anomaly() {
    let image = E01Builder::new(512 * 64).build();
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::TableHeaderAdler32Mismatch { .. })),
        "clean image must not produce TableHeaderAdler32Mismatch; got: {findings:#?}"
    );
}

/// A tampered table header Adler-32 must produce `TableHeaderAdler32Mismatch`.
///
/// Currently RED: the check is absent.
#[test]
fn table_header_crc_tampered_detected() {
    let image = tamper_table_header_crc(E01Builder::new(512 * 64).build());
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::TableHeaderAdler32Mismatch { .. })),
        "tampered table header Adler-32 must produce TableHeaderAdler32Mismatch; got: {findings:#?}"
    );
}

/// Adler-32 mismatch must report computed ≠ stored.
///
/// Currently RED: anomaly never fires.
#[test]
fn table_header_crc_tampered_values_are_correct() {
    let image = tamper_table_header_crc(E01Builder::new(512 * 64).build());
    let findings = EwfIntegrity::new(&image).analyse();
    let mismatch = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::TableHeaderAdler32Mismatch { .. }));
    if let Some(EwfIntegrityAnomaly::TableHeaderAdler32Mismatch { computed, stored }) = mismatch {
        assert_ne!(
            computed, stored,
            "computed and stored Adler-32 must differ in the anomaly"
        );
    } else {
        panic!("expected TableHeaderAdler32Mismatch not found; got: {findings:#?}");
    }
}

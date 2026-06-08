//! RED phase — EWF v1 `error2` section parsing.
//!
//! The `error2` section records sectors that could not be read during
//! acquisition.  `entry_count` > 0 means the evidence has unreadable sectors;
//! practitioners must be informed.
//!
//! Currently RED: `error2` is listed in `KNOWN_TYPES` but never parsed.

mod builder;
use builder::{
    make_section_descriptor, EVF_SIGNATURE, FILE_HEADER_SIZE, SECTION_DESCRIPTOR_SIZE,
    VOLUME_DATA_SIZE,
};
use ewf_forensic::{EwfIntegrity, EwfIntegrityAnomaly};

/// Build a minimal E01 with: `file_header`, header, volume, error2(count), done.
///
/// The error2 body is 4-byte `entry_count` followed by `count` dummy 16-byte
/// entries (8-byte `first_sector` + 8-byte `num_sectors`, all zeros).
fn e01_with_error2(count: u32) -> Vec<u8> {
    const ENTRY_SIZE: usize = 16; // 8 bytes first_sector + 8 bytes num_sectors

    let error2_body: Vec<u8> = {
        let mut v = count.to_le_bytes().to_vec();
        v.extend(std::iter::repeat_n(0u8, count as usize * ENTRY_SIZE));
        v
    };

    let header_section_size = (SECTION_DESCRIPTOR_SIZE + 1) as u64;
    let volume_section_size = (SECTION_DESCRIPTOR_SIZE + VOLUME_DATA_SIZE) as u64;
    let error2_section_size = SECTION_DESCRIPTOR_SIZE as u64 + error2_body.len() as u64;
    let done_section_size = SECTION_DESCRIPTOR_SIZE as u64;

    let base = FILE_HEADER_SIZE as u64;
    let volume_off = base + header_section_size;
    let error2_off = volume_off + volume_section_size;
    let done_off = error2_off + error2_section_size;

    let mut buf: Vec<u8> = Vec::new();

    // File header
    buf.extend_from_slice(&EVF_SIGNATURE);
    buf.push(0x01);
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    buf.extend_from_slice(&make_section_descriptor(
        "header",
        volume_off,
        header_section_size,
    ));
    buf.push(0u8);

    buf.extend_from_slice(&make_section_descriptor(
        "volume",
        error2_off,
        volume_section_size,
    ));
    buf.extend(std::iter::repeat_n(0u8, VOLUME_DATA_SIZE));

    buf.extend_from_slice(&make_section_descriptor(
        "error2",
        done_off,
        error2_section_size,
    ));
    buf.extend_from_slice(&error2_body);

    buf.extend_from_slice(&make_section_descriptor(
        "done",
        done_off,
        done_section_size,
    ));

    buf
}

/// An error2 section with count=0 must not produce `BadSectorsPresent`.
#[test]
fn error2_count_zero_no_anomaly() {
    let image = e01_with_error2(0);
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        !findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::BadSectorsPresent { .. })),
        "error2 with count=0 must not produce BadSectorsPresent; got: {findings:#?}"
    );
}

/// An error2 section with count=2 must produce `BadSectorsPresent` { count: 2 }.
///
/// Currently RED: error2 body is never parsed.
#[test]
fn error2_count_nonzero_detected() {
    let image = e01_with_error2(2);
    let findings = EwfIntegrity::new(&image).analyse();
    assert!(
        findings
            .iter()
            .any(|a| matches!(a, EwfIntegrityAnomaly::BadSectorsPresent { .. })),
        "error2 with count=2 must produce BadSectorsPresent; got: {findings:#?}"
    );
}

/// `BadSectorsPresent` must report the correct count.
///
/// Currently RED: no anomaly fired at all.
#[test]
fn error2_count_value_is_correct() {
    let image = e01_with_error2(5);
    let findings = EwfIntegrity::new(&image).analyse();
    let anomaly = findings
        .iter()
        .find(|a| matches!(a, EwfIntegrityAnomaly::BadSectorsPresent { .. }));
    if let Some(EwfIntegrityAnomaly::BadSectorsPresent { count }) = anomaly {
        assert_eq!(
            *count, 5,
            "BadSectorsPresent count must equal error2 entry_count"
        );
    } else {
        panic!("expected BadSectorsPresent not found; got: {findings:#?}");
    }
}

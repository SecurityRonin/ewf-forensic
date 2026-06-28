use ewf_forensic::EwfIntegrityAnomaly;

fn is_rust_debug(s: &str) -> bool {
    // Debug output has patterns like `Mismatch { computed:` or `{ section_type:`
    s.contains("computed:") || s.contains("section_type:") || s.contains("{ chunk_index:")
}

#[test]
fn invalid_signature_display() {
    let s = format!("{}", EwfIntegrityAnomaly::InvalidSignature);
    assert!(!is_rust_debug(&s), "looks like Debug: {s:?}");
    assert!(
        s.to_lowercase().contains("signature"),
        "missing 'signature': {s:?}"
    );
}

#[test]
fn segment_number_zero_display() {
    let s = format!("{}", EwfIntegrityAnomaly::SegmentNumberZero);
    assert!(!is_rust_debug(&s));
    assert!(
        s.contains("segment") || s.contains("zero") || s.contains('0'),
        "{s:?}"
    );
}

#[test]
fn section_descriptor_crc_mismatch_display() {
    let s = format!(
        "{}",
        EwfIntegrityAnomaly::SectionDescriptorCrcMismatch {
            offset: 0x100,
            section_type: "table".into(),
            computed: 0xDEAD,
            stored: 0xBEEF,
        }
    );
    assert!(!is_rust_debug(&s));
    assert!(s.contains("table"), "missing section type: {s:?}");
    assert!(
        s.contains("0x100") || s.contains("100"),
        "missing offset: {s:?}"
    );
    assert!(
        s.contains("dead") || s.contains("DEAD") || s.contains("0xdead") || s.contains("0xDEAD"),
        "missing computed: {s:?}"
    );
}

#[test]
fn section_chain_broken_display() {
    let s = format!(
        "{}",
        EwfIntegrityAnomaly::SectionChainBroken {
            at_offset: 0x80,
            next_offset: 0
        }
    );
    assert!(!is_rust_debug(&s));
    assert!(
        s.to_lowercase().contains("chain") || s.to_lowercase().contains("broken"),
        "{s:?}"
    );
}

#[test]
fn hash_mismatch_display() {
    let computed = [0xABu8; 16];
    let stored = [0xCDu8; 16];
    let s = format!("{}", EwfIntegrityAnomaly::HashMismatch { computed, stored });
    assert!(!is_rust_debug(&s));
    // Should contain both hex hashes
    assert!(
        s.to_lowercase().contains("ab") || s.to_lowercase().contains("abab"),
        "missing computed: {s:?}"
    );
    assert!(
        s.to_lowercase().contains("cd") || s.to_lowercase().contains("cdcd"),
        "missing stored: {s:?}"
    );
}

#[test]
fn hash_section_missing_display() {
    let s = format!("{}", EwfIntegrityAnomaly::HashSectionMissing);
    assert!(!is_rust_debug(&s));
    assert!(
        s.to_lowercase().contains("hash") || s.to_lowercase().contains("md5"),
        "{s:?}"
    );
}

#[test]
fn chunk_checksum_mismatch_display() {
    let s = format!(
        "{}",
        EwfIntegrityAnomaly::ChunkChecksumMismatch {
            chunk_index: 7,
            computed: 0x1122_3344,
            stored: 0x5566_7788,
        }
    );
    assert!(!is_rust_debug(&s));
    assert!(s.contains('7'), "missing chunk index: {s:?}");
    assert!(
        s.to_lowercase().contains("11223344") || s.to_lowercase().contains("0x11223344"),
        "missing computed: {s:?}"
    );
}

#[test]
fn chunk_decompression_error_display() {
    let s = format!(
        "{}",
        EwfIntegrityAnomaly::ChunkDecompressionError { chunk_index: 3 }
    );
    assert!(!is_rust_debug(&s));
    assert!(s.contains('3'), "missing chunk index: {s:?}");
    assert!(
        s.to_lowercase().contains("decompress")
            || s.to_lowercase().contains("corrupt")
            || s.to_lowercase().contains("zlib"),
        "{s:?}"
    );
}

#[test]
fn digest_sha1_mismatch_display() {
    let s = format!(
        "{}",
        EwfIntegrityAnomaly::DigestSha1Mismatch {
            computed: [0x11u8; 20],
            stored: [0x22u8; 20],
        }
    );
    assert!(!is_rust_debug(&s));
    assert!(
        s.to_lowercase().contains("sha")
            || s.to_lowercase().contains("sha-1")
            || s.to_lowercase().contains("sha1"),
        "{s:?}"
    );
    assert!(s.to_lowercase().contains("11"), "missing computed: {s:?}");
}

#[test]
fn external_md5_mismatch_display() {
    let s = format!(
        "{}",
        EwfIntegrityAnomaly::ExternalMd5Mismatch {
            computed: [0xAAu8; 16],
            expected: [0xBBu8; 16],
        }
    );
    assert!(!is_rust_debug(&s));
    assert!(
        s.to_lowercase().contains("md5")
            || s.to_lowercase().contains("custody")
            || s.to_lowercase().contains("reference"),
        "{s:?}"
    );
    assert!(s.to_lowercase().contains("aa"), "missing computed: {s:?}");
    assert!(s.to_lowercase().contains("bb"), "missing expected: {s:?}");
}

#[test]
fn external_sha256_mismatch_display() {
    let s = format!(
        "{}",
        EwfIntegrityAnomaly::ExternalSha256Mismatch {
            computed: [0xCCu8; 32],
            expected: [0xDDu8; 32],
        }
    );
    assert!(!is_rust_debug(&s));
    assert!(
        s.to_lowercase().contains("sha-256") || s.to_lowercase().contains("sha256"),
        "{s:?}"
    );
    assert!(s.to_lowercase().contains("cc"), "{s:?}");
    assert!(s.to_lowercase().contains("dd"), "{s:?}");
}

#[test]
fn ewf2_encrypted_section_display() {
    let s = format!(
        "{}",
        EwfIntegrityAnomaly::Ewf2EncryptedSection { offset: 0x200 }
    );
    assert!(!is_rust_debug(&s));
    assert!(s.to_lowercase().contains("encrypt"), "{s:?}");
    assert!(
        s.contains("0x200") || s.contains("200") || s.contains("512"),
        "{s:?}"
    );
}

#[test]
fn ewf2_hash_section_missing_display() {
    let s = format!("{}", EwfIntegrityAnomaly::Ewf2HashSectionMissing);
    assert!(!is_rust_debug(&s));
    assert!(
        s.to_lowercase().contains("hash")
            || s.to_lowercase().contains("ewf v2")
            || s.to_lowercase().contains("v2"),
        "{s:?}"
    );
}

#[test]
fn segment_out_of_order_display() {
    let s = format!(
        "{}",
        EwfIntegrityAnomaly::SegmentOutOfOrder {
            segment_number: 3,
            expected: 2
        }
    );
    assert!(!is_rust_debug(&s));
    assert!(
        s.contains('3') && s.contains('2'),
        "missing segment numbers: {s:?}"
    );
}

#[test]
fn table_entry_out_of_bounds_display() {
    let s = format!(
        "{}",
        EwfIntegrityAnomaly::TableEntryOutOfBounds {
            chunk_index: 5,
            entry_offset: 0xFFFF,
            file_size: 0x1000,
        }
    );
    assert!(!is_rust_debug(&s));
    assert!(s.contains('5'), "missing chunk_index: {s:?}");
}

#[test]
fn display_does_not_contain_struct_braces() {
    let anomalies: Vec<EwfIntegrityAnomaly> = vec![
        EwfIntegrityAnomaly::InvalidSignature,
        EwfIntegrityAnomaly::VolumeSectionMissing,
        EwfIntegrityAnomaly::DoneSectionMissing,
        EwfIntegrityAnomaly::HashSectionMissing,
        EwfIntegrityAnomaly::Ewf2HashSectionMissing,
        EwfIntegrityAnomaly::Ewf2MediaInfoMissing,
        EwfIntegrityAnomaly::Ewf2ChunkTableChecksumMismatch {
            computed: 0x1234,
            stored: 0x5678,
        },
        EwfIntegrityAnomaly::SegmentNumberZero,
    ];
    for a in &anomalies {
        let s = format!("{a}");
        // Debug has " { " patterns; Display should not
        assert!(
            !s.contains(" { "),
            "Display looks like Debug for {a:?}: {s:?}"
        );
        // Should not be empty
        assert!(!s.is_empty(), "Display is empty for {a:?}");
    }
}

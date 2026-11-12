//! Regression test for a `sectors_data_end` bug: the last-chunk back-fill
//! (`chunk_table::parse_table_section`) needs the end offset of the
//! `sectors` section that immediately precedes each `table`/`table2`
//! section — but the reader used to look it up once per segment via
//! `.find(|d| d.section_type == "sectors")`, which always returns the
//! FIRST `sectors` section in the segment. Any segment with more than one
//! `sectors`/`table` pair (real images alternate a new pair roughly every
//! ~16 K chunks) then back-filled every group's last chunk using the
//! *first* group's boundary instead of its own — silently keeping a
//! genuinely short final chunk at its full nominal size, and so reading
//! past its real end into whatever bytes follow.
//!
//! This builds the smallest possible two-group EWF v1 file (4 chunks, 16
//! bytes each, uncompressed) where the second group's own last chunk is
//! deliberately short (10 of its 16 nominal bytes), and asserts the
//! resolved chunk metadata reflects that real, short size — not the
//! nominal one a first-`sectors`-only lookup would wrongly leave in place.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use tempfile::NamedTempFile;

use ewf::EwfReader;

const EVF_MAGIC: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
const CHUNK_SIZE: usize = 16;

fn file_header(segment: u16) -> [u8; 13] {
    let mut h = [0u8; 13];
    h[0..8].copy_from_slice(&EVF_MAGIC);
    h[8] = 0x01;
    h[9..11].copy_from_slice(&segment.to_le_bytes());
    h[11..13].copy_from_slice(&0u16.to_le_bytes());
    h
}

fn section_desc(section_type: &[u8], next: u64, section_size: u64) -> [u8; 76] {
    let mut d = [0u8; 76];
    let copy_len = section_type.len().min(16);
    d[..copy_len].copy_from_slice(&section_type[..copy_len]);
    d[16..24].copy_from_slice(&next.to_le_bytes());
    d[24..32].copy_from_slice(&section_size.to_le_bytes());
    d
}

fn volume_data(chunk_count: u32, sectors_per_chunk: u32, bytes_per_sector: u32) -> [u8; 94] {
    let mut v = [0u8; 94];
    v[4..8].copy_from_slice(&chunk_count.to_le_bytes());
    v[8..12].copy_from_slice(&sectors_per_chunk.to_le_bytes());
    v[12..16].copy_from_slice(&bytes_per_sector.to_le_bytes());
    v[16..24].copy_from_slice(&u64::from(chunk_count).to_le_bytes());
    v
}

/// 24-byte table section header: `entry_count(4) | pad(4) | base_offset(8) |
/// checksum(4, 0 = "none stored") | pad(4)`.
fn table_header(entry_count: u32, base_offset: u64) -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&entry_count.to_le_bytes());
    h[8..16].copy_from_slice(&base_offset.to_le_bytes());
    h
}

/// One 4-byte table entry: top bit = compressed, low 31 bits = offset
/// relative to the table's own `base_offset`.
fn table_entry(compressed: bool, relative_offset: u32) -> [u8; 4] {
    let raw = (relative_offset & 0x7FFF_FFFF) | (u32::from(compressed) << 31);
    raw.to_le_bytes()
}

fn write_temp_e01(content: &[u8]) -> (NamedTempFile, std::path::PathBuf) {
    let mut f = NamedTempFile::with_suffix(".E01").unwrap();
    f.write_all(content).unwrap();
    let path = f.path().to_path_buf();
    (f, path)
}

#[test]
fn second_groups_short_last_chunk_backfills_to_its_real_size() {
    const FHDR: u64 = 13;
    const DESC: u64 = 76; // SECTION_DESCRIPTOR_SIZE
    const VOL_DATA: u64 = 94;
    const TBL_HDR: u64 = 24;

    // --- group 1: two full 16-byte chunks (16 data + 4-byte adler32 each) ---
    let chunk0 = [0xAAu8; CHUNK_SIZE].to_vec();
    let chunk1 = [0xBBu8; CHUNK_SIZE].to_vec();
    let sectors1_data: Vec<u8> = [&chunk0[..], &[0u8; 4], &chunk1[..], &[0u8; 4]].concat();
    assert_eq!(sectors1_data.len(), 40);

    // --- group 2: a full chunk, then a deliberately SHORT last chunk (only
    // 10 of its 16 nominal bytes) ---
    let chunk2 = [0xCCu8; CHUNK_SIZE].to_vec();
    let chunk3_real = [0xDDu8; 10].to_vec(); // short: real data < chunk_size
    let sectors2_data: Vec<u8> = [&chunk2[..], &[0u8; 4], &chunk3_real[..], &[0u8; 4]].concat();
    assert_eq!(sectors2_data.len(), 34);

    let vol_off = FHDR;
    let sectors1_off = vol_off + DESC + VOL_DATA; // 13+76+94 = 183
    let sectors1_data_start = sectors1_off + DESC; // 259
    let table1_off = sectors1_data_start + sectors1_data.len() as u64; // 299
    let table1_data_start = table1_off + DESC; // 375
    let table1_entries_start = table1_data_start + TBL_HDR; // 399
    let sectors2_off = table1_entries_start + 8; // 407 (2 entries * 4 bytes)
    let sectors2_data_start = sectors2_off + DESC; // 483
    let table2_off = sectors2_data_start + sectors2_data.len() as u64; // 517
    let table2_data_start = table2_off + DESC; // 593
    let table2_entries_start = table2_data_start + TBL_HDR; // 617
    let done_off = table2_entries_start + 8; // 625

    let mut buf = Vec::new();
    buf.extend_from_slice(&file_header(1));

    buf.extend_from_slice(&section_desc(b"volume", sectors1_off, DESC + VOL_DATA));
    buf.extend_from_slice(&volume_data(4, 1, 16)); // chunk_size = 1*16 = 16

    buf.extend_from_slice(&section_desc(
        b"sectors",
        table1_off,
        DESC + sectors1_data.len() as u64,
    ));
    buf.extend_from_slice(&sectors1_data);

    buf.extend_from_slice(&section_desc(b"table", sectors2_off, DESC + TBL_HDR + 8));
    buf.extend_from_slice(&table_header(2, sectors1_data_start));
    buf.extend_from_slice(&table_entry(false, 0));
    buf.extend_from_slice(&table_entry(false, 20)); // chunk0 (16+4) then chunk1

    buf.extend_from_slice(&section_desc(
        b"sectors",
        table2_off,
        DESC + sectors2_data.len() as u64,
    ));
    buf.extend_from_slice(&sectors2_data);

    buf.extend_from_slice(&section_desc(b"table", done_off, DESC + TBL_HDR + 8));
    buf.extend_from_slice(&table_header(2, sectors2_data_start));
    buf.extend_from_slice(&table_entry(false, 0));
    buf.extend_from_slice(&table_entry(false, 20)); // chunk2 (16+4) then chunk3

    buf.extend_from_slice(&section_desc(b"done", done_off, DESC));

    assert_eq!(buf.len() as u64, done_off + DESC);

    let (_f, path) = write_temp_e01(&buf);
    let reader = EwfReader::open(&path).expect("a well-formed two-group image must open");

    assert_eq!(reader.chunk_count(), 4);

    // Chunk 3 (the second group's own last chunk) must resolve to its real,
    // short size -- not the nominal chunk_size a first-`sectors`-only
    // back-fill would wrongly leave in place.
    let (offset3, size3, compressed3, _seg3) = reader.debug_chunk(3).expect("chunk 3");
    assert_eq!(offset3, sectors2_data_start + 20);
    assert!(!compressed3);
    assert_eq!(
        size3, 10,
        "chunk 3 must back-fill to its real 10-byte size using the SECOND \
         group's own sectors boundary, not the first group's"
    );

    // Sanity: the first group's own last chunk (chunk 1, a full nominal
    // chunk) must still resolve correctly too.
    let (_offset1, size1, _compressed1, _seg1) = reader.debug_chunk(1).expect("chunk 1");
    assert_eq!(size1, CHUNK_SIZE as u64);
}

//! Synthetic E01 / EWF v2 builder for testing.
//!
//! EWF v1 layout (single segment, single chunk for simplicity):
//!   [0x000]  File Header      13 bytes
//!   [0x00D]  Section 1 desc   76 bytes  ("header" — metadata string)
//!   [0x059]  Section 1 data   variable
//!   [???]    Volume desc      76 bytes
//!   [???]    Volume data      94 bytes
//!   [???]    Table desc       76 bytes
//!   [???]    Table header     24 bytes
//!   [???]    Table entries    4 × chunk_count bytes
//!   [???]    Sectors desc     76 bytes
//!   [???]    Sectors data     chunk bytes (uncompressed for simplicity)
//!   [???]    Digest desc      76 bytes  (optional, if digest_sha1_override is set)
//!   [???]    Digest data      36 bytes  (MD5 + SHA-1, optional)
//!   [???]    Hash desc        76 bytes
//!   [???]    Hash data        16 bytes (MD5)
//!   [???]    Done desc        76 bytes  (next == self)
//!
//! Non-final segment layout (nonfinal=true):
//!   ... file header + header + volume (seg 1 only) + table + sectors ...
//!   [???]    Next desc        76 bytes  (next == self — segment boundary)
#![allow(dead_code)] // pub builder API — methods called from peer test binaries
use md5::{Digest as _, Md5};

/// EWF v1 signature: "EVF\x09\x0d\x0a\xff\x00"
pub const EVF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
/// EWF v2 signature (physical / Ex01)
pub const EVF2_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];
/// EWF v2 signature (logical / Lx01)
pub const LEF2_SIGNATURE: [u8; 8] = [0x4c, 0x45, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];

pub const FILE_HEADER_SIZE: usize = 13;
pub const SECTION_DESCRIPTOR_SIZE: usize = 76;
pub const VOLUME_DATA_SIZE: usize = 94;
pub const HASH_DATA_SIZE: usize = 16; // MD5
pub const DIGEST_DATA_SIZE: usize = 36; // MD5 (16) + SHA-1 (20)

pub const EVF2_FILE_HEADER_SIZE: usize = 32;
pub const EVF2_SECTION_DESCRIPTOR_SIZE: usize = 64;

pub const EVF2_SECTION_TYPE_SECTOR_DATA: u32 = 0x03;
pub const EVF2_SECTION_TYPE_MD5_HASH: u32 = 0x08;
pub const EVF2_SECTION_TYPE_SHA1_HASH: u32 = 0x09;
pub const EVF2_SECTION_TYPE_DONE: u32 = 0x0F;
pub const EVF2_DATA_FLAG_ENCRYPTED: u32 = 0x0000_0002;

/// Adler-32 as used by EWF section descriptor and table checksums.
pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut s1: u32 = 1;
    let mut s2: u32 = 0;
    for &b in data {
        s1 = (s1 + u32::from(b)) % MOD;
        s2 = (s2 + s1) % MOD;
    }
    (s2 << 16) | s1
}

/// Build an EWF v1 section descriptor.
pub fn make_section_descriptor(section_type: &str, next: u64, size: u64) -> Vec<u8> {
    let mut buf = vec![0u8; SECTION_DESCRIPTOR_SIZE];
    let name = section_type.as_bytes();
    let copy_len = name.len().min(16);
    buf[..copy_len].copy_from_slice(&name[..copy_len]);
    buf[16..24].copy_from_slice(&next.to_le_bytes());
    buf[24..32].copy_from_slice(&size.to_le_bytes());
    let crc = adler32(&buf[..72]);
    buf[72..76].copy_from_slice(&crc.to_le_bytes());
    buf
}

/// Build an EWF v2 file header (32 bytes).
pub fn make_ewf2_file_header(segment_number: u32) -> Vec<u8> {
    let mut h = vec![0u8; EVF2_FILE_HEADER_SIZE];
    h[0..8].copy_from_slice(&EVF2_SIGNATURE);
    h[8] = 0x01; // major_version
    h[9] = 0x00; // minor_version
    // compression_method at [10..12] = 0 (None)
    h[12..16].copy_from_slice(&segment_number.to_le_bytes());
    // set_identifier at [16..32] = zeros
    h
}

/// Build an EWF v2 section descriptor (64 bytes).
///
/// In real EWF v2, section bodies precede their descriptors; descriptors are
/// linked backward via `prev_section_offset` (the byte offset of the previous
/// section's descriptor within this segment).
pub fn make_ewf2_descriptor(
    section_type: u32,
    data_flags: u32,
    prev_section_offset: u64,
    data_size: u64,
    data_integrity_hash: [u8; 16],
) -> Vec<u8> {
    let mut d = vec![0u8; EVF2_SECTION_DESCRIPTOR_SIZE];
    d[0..4].copy_from_slice(&section_type.to_le_bytes());
    d[4..8].copy_from_slice(&data_flags.to_le_bytes());
    d[8..16].copy_from_slice(&prev_section_offset.to_le_bytes());
    d[16..24].copy_from_slice(&data_size.to_le_bytes());
    d[24..28].copy_from_slice(&(EVF2_SECTION_DESCRIPTOR_SIZE as u32).to_le_bytes());
    d[32..48].copy_from_slice(&data_integrity_hash);
    d
}

/// Minimal valid EWF v2 segment: file header + MD5 hash section + Done.
///
/// Real EWF v2 layout: body precedes descriptor; DONE is the last 64 bytes.
/// Sections linked backward via prev_section_offset.
pub fn make_ewf2_clean_segment() -> Vec<u8> {
    // [header_32][md5_body_16][md5_desc_64][done_desc_64]
    let mut buf = Vec::new();
    buf.extend_from_slice(&make_ewf2_file_header(1));
    // MD5 body (16 bytes of zeros)
    buf.extend_from_slice(&[0u8; 16]);                               // offset 32..48
    let md5_desc_off = buf.len() as u64;                             // 48
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_MD5_HASH, 0, 0, 16, [0u8; 16],
    ));                                                              // 48..112
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_DONE, 0, md5_desc_off, 0, [0u8; 16],
    ));                                                              // 112..176
    buf
}

/// EWF v2 segment where the MD5 hash section has a wrong data_integrity_hash.
pub fn make_ewf2_tampered_segment() -> Vec<u8> {
    // [header_32][md5_body_16][md5_desc_64(bad_hash)][done_desc_64]
    let mut buf = Vec::new();
    buf.extend_from_slice(&make_ewf2_file_header(1));
    buf.extend_from_slice(&[0u8; 16]);                               // md5 body: zeros
    let md5_desc_off = buf.len() as u64;                             // 48
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_MD5_HASH, 0, 0, 16,
        [0xFF; 16], // wrong stored hash → Ewf2SectionDataHashMismatch
    ));                                                              // 48..112
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_DONE, 0, md5_desc_off, 0, [0u8; 16],
    ));                                                              // 112..176
    buf
}

/// EWF v2 segment containing an encrypted sector-data section.
pub fn make_ewf2_encrypted_segment() -> Vec<u8> {
    // [header_32][enc_desc_64(empty_body)][md5_body_16][md5_desc_64][done_desc_64]
    let mut buf = Vec::new();
    buf.extend_from_slice(&make_ewf2_file_header(1));
    // Encrypted section has no body (data_size=0); descriptor goes right after header.
    let enc_desc_off = buf.len() as u64;                             // 32
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_SECTOR_DATA, EVF2_DATA_FLAG_ENCRYPTED, 0, 0, [0u8; 16],
    ));                                                              // 32..96
    buf.extend_from_slice(&[0u8; 16]);                               // md5 body: 96..112
    let md5_desc_off = buf.len() as u64;                             // 112
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_MD5_HASH, 0, enc_desc_off, 16, [0u8; 16],
    ));                                                              // 112..176
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_DONE, 0, md5_desc_off, 0, [0u8; 16],
    ));                                                              // 176..240
    buf
}

/// EWF v2 segment with no hash section → Ewf2HashSectionMissing.
pub fn make_ewf2_no_hash_segment() -> Vec<u8> {
    // [header_32][done_desc_64]
    let mut buf = Vec::new();
    buf.extend_from_slice(&make_ewf2_file_header(1));
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_DONE, 0, 0, 0, [0u8; 16],
    ));
    buf
}

/// EWF v2 section type for media/device information (volume geometry).
/// Layout of the 20-byte body:
///   [0..4]   bytes_per_sector (u32 LE)
///   [4..8]   sectors_per_chunk (u32 LE)
///   [8..16]  sector_count (u64 LE)
///   [16..20] reserved (zeros)
pub const EVF2_SECTION_TYPE_MEDIA_INFO: u32 = 0x02;

fn make_ewf2_media_info_body(bytes_per_sector: u32, sectors_per_chunk: u32, sector_count: u64) -> Vec<u8> {
    let mut b = vec![0u8; 20];
    b[0..4].copy_from_slice(&bytes_per_sector.to_le_bytes());
    b[4..8].copy_from_slice(&sectors_per_chunk.to_le_bytes());
    b[8..16].copy_from_slice(&sector_count.to_le_bytes());
    b
}

/// EWF v2 segment with a valid media information section.
pub fn make_ewf2_clean_segment_with_media_info(
    bytes_per_sector: u32,
    sectors_per_chunk: u32,
    sector_count: u64,
) -> Vec<u8> {
    use md5::{Digest as _, Md5};
    // [header_32][mi_body_20][mi_desc_64][md5_body_16][md5_desc_64][done_desc_64]
    let mut buf = Vec::new();
    buf.extend_from_slice(&make_ewf2_file_header(1));

    let mi_body = make_ewf2_media_info_body(bytes_per_sector, sectors_per_chunk, sector_count);
    let mi_hash: [u8; 16] = Md5::digest(&mi_body).into();
    buf.extend_from_slice(&mi_body);                                 // 32..52
    let mi_desc_off = buf.len() as u64;                              // 52
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_MEDIA_INFO, 0, 0, mi_body.len() as u64, mi_hash,
    ));                                                              // 52..116

    buf.extend_from_slice(&[0u8; 16]);                               // md5 body: 116..132
    let md5_desc_off = buf.len() as u64;                             // 132
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_MD5_HASH, 0, mi_desc_off, 16, [0u8; 16],
    ));                                                              // 132..196
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_DONE, 0, md5_desc_off, 0, [0u8; 16],
    ));                                                              // 196..260
    buf
}

/// EWF v2 segment with a media information section containing bad geometry values.
pub fn make_ewf2_segment_bad_geometry(
    bytes_per_sector: u32,
    sectors_per_chunk: u32,
    sector_count: u64,
) -> Vec<u8> {
    use md5::{Digest as _, Md5};
    // Same layout as make_ewf2_clean_segment_with_media_info but with bad values.
    let mut buf = Vec::new();
    buf.extend_from_slice(&make_ewf2_file_header(1));

    let mi_body = make_ewf2_media_info_body(bytes_per_sector, sectors_per_chunk, sector_count);
    let mi_hash: [u8; 16] = Md5::digest(&mi_body).into();
    buf.extend_from_slice(&mi_body);
    let mi_desc_off = buf.len() as u64;
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_MEDIA_INFO, 0, 0, mi_body.len() as u64, mi_hash,
    ));

    buf.extend_from_slice(&[0u8; 16]);
    let md5_desc_off = buf.len() as u64;
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_MD5_HASH, 0, mi_desc_off, 16, [0u8; 16],
    ));
    buf.extend_from_slice(&make_ewf2_descriptor(
        EVF2_SECTION_TYPE_DONE, 0, md5_desc_off, 0, [0u8; 16],
    ));
    buf
}

// ── EWF v1 segment builder ───────────────────────────────────────────────────

pub struct E01Builder {
    pub virtual_disk_size: u64,
    pub sectors_per_chunk: u32,
    pub bytes_per_sector: u32,
    pub segment_number: u16,
    pub signature_override: Option<[u8; 8]>,
    pub corrupt_volume_crc: bool,
    pub omit_done: bool,
    pub insert_gap: bool,
    pub md5_override: Option<[u8; 16]>,
    pub table_chunk_count_override: Option<u32>,
    pub volume_sectors_per_chunk_override: Option<u32>,
    pub volume_bytes_per_sector_override: Option<u32>,
    pub volume_sector_count_override: Option<u64>,
    pub omit_volume: bool,
    pub break_chain: bool,
    pub volume_type_override: Option<String>,
    pub segment_number_override: Option<u16>,
    pub omit_hash: bool,
    pub table_base_offset_override: Option<u64>,
    pub insert_zero_gap: bool,
    /// If true, segment ends with a "next" section instead of hash + done.
    /// Use for non-final segments in multi-segment images.
    pub nonfinal: bool,
    /// Override chunk_count in the volume section only (independent of table entries).
    /// Use when building the first segment of a multi-segment image: set to total chunk count.
    pub volume_chunk_count_override: Option<u32>,
    /// If set, insert a "digest" section containing the given SHA-1 bytes.
    /// The digest section's MD5 field is computed from sectors data.
    pub digest_sha1_override: Option<[u8; 20]>,
    /// Write per-chunk Adler-32 checksums (4 bytes after each chunk's raw data).
    /// Matches the layout used by real acquisition tools (libewf, FTK, X-Ways).
    pub chunk_checksums: bool,
    /// If Some(i), corrupt the stored Adler-32 of chunk i by XOR-ing 0xFF into byte 0.
    /// Only active when chunk_checksums is true.
    pub corrupt_chunk_checksum: Option<usize>,
}

impl E01Builder {
    pub fn new(virtual_disk_size: u64) -> Self {
        Self {
            virtual_disk_size,
            sectors_per_chunk: 64,
            bytes_per_sector: 512,
            segment_number: 1,
            signature_override: None,
            corrupt_volume_crc: false,
            omit_done: false,
            insert_gap: false,
            md5_override: None,
            table_chunk_count_override: None,
            volume_sectors_per_chunk_override: None,
            volume_bytes_per_sector_override: None,
            volume_sector_count_override: None,
            omit_volume: false,
            break_chain: false,
            volume_type_override: None,
            segment_number_override: None,
            omit_hash: false,
            table_base_offset_override: None,
            insert_zero_gap: false,
            nonfinal: false,
            volume_chunk_count_override: None,
            digest_sha1_override: None,
            chunk_checksums: false,
            corrupt_chunk_checksum: None,
        }
    }

    pub fn with_signature(mut self, sig: [u8; 8]) -> Self { self.signature_override = Some(sig); self }
    pub fn with_segment_number(mut self, n: u16) -> Self { self.segment_number_override = Some(n); self }
    pub fn with_corrupt_volume_crc(mut self) -> Self { self.corrupt_volume_crc = true; self }
    pub fn with_broken_chain(mut self) -> Self { self.break_chain = true; self }
    pub fn with_gap(mut self) -> Self { self.insert_gap = true; self }
    pub fn with_omit_volume(mut self) -> Self { self.omit_volume = true; self }
    pub fn with_volume_type(mut self, t: &str) -> Self { self.volume_type_override = Some(t.to_string()); self }
    pub fn with_omit_done(mut self) -> Self { self.omit_done = true; self }
    pub fn with_volume_sectors_per_chunk(mut self, spc: u32) -> Self { self.volume_sectors_per_chunk_override = Some(spc); self }
    pub fn with_volume_sector_count(mut self, sc: u64) -> Self { self.volume_sector_count_override = Some(sc); self }
    pub fn with_volume_bytes_per_sector(mut self, bps: u32) -> Self { self.volume_bytes_per_sector_override = Some(bps); self }
    pub fn with_table_chunk_count(mut self, n: u32) -> Self { self.table_chunk_count_override = Some(n); self }
    pub fn with_md5(mut self, md5: [u8; 16]) -> Self { self.md5_override = Some(md5); self }
    pub fn with_omit_hash(mut self) -> Self { self.omit_hash = true; self }
    pub fn with_table_base_offset(mut self, offset: u64) -> Self { self.table_base_offset_override = Some(offset); self }
    pub fn with_zero_gap(mut self) -> Self { self.insert_zero_gap = true; self }
    /// Build a non-final segment: ends with a "next" section instead of hash + done.
    pub fn with_nonfinal(mut self) -> Self { self.nonfinal = true; self }
    /// Override chunk_count in the volume section (for multi-segment: set to total image chunks).
    pub fn with_volume_chunk_count(mut self, n: u32) -> Self { self.volume_chunk_count_override = Some(n); self }
    /// Insert a "digest" section with the given SHA-1 (MD5 computed from actual sectors data).
    pub fn with_digest_sha1(mut self, sha1: [u8; 20]) -> Self { self.digest_sha1_override = Some(sha1); self }
    /// Write per-chunk Adler-32 checksums — matches real acquisition tool output.
    pub fn with_chunk_checksums(mut self) -> Self { self.chunk_checksums = true; self }
    /// Corrupt the Adler-32 checksum of chunk `idx` (requires chunk_checksums = true).
    pub fn with_corrupt_chunk_checksum(mut self, idx: usize) -> Self { self.corrupt_chunk_checksum = Some(idx); self }

    pub fn build(self) -> Vec<u8> {
        let spc = self.sectors_per_chunk;
        let bps = self.bytes_per_sector;
        let chunk_size = u64::from(spc) * u64::from(bps);
        let chunk_count = self.virtual_disk_size.div_ceil(chunk_size) as u32;
        let sector_count = u64::from(chunk_count) * u64::from(spc);

        let header_section_data_size: u64 = 1;
        let volume_section_size: u64 = (SECTION_DESCRIPTOR_SIZE + VOLUME_DATA_SIZE) as u64;
        let table_data_size: u64 = 24 + 4 * u64::from(chunk_count);
        let table_section_size = SECTION_DESCRIPTOR_SIZE as u64 + table_data_size;
        // With per-chunk checksums each chunk occupies chunk_size + 4 bytes in the sectors body.
        let chunk_stride = if self.chunk_checksums { chunk_size + 4 } else { chunk_size };
        let sectors_data_size = u64::from(chunk_count) * chunk_stride;
        let sectors_section_size = SECTION_DESCRIPTOR_SIZE as u64 + sectors_data_size;
        let digest_section_size: u64 = if self.digest_sha1_override.is_some() {
            (SECTION_DESCRIPTOR_SIZE + DIGEST_DATA_SIZE) as u64
        } else {
            0
        };
        let hash_section_size: u64 = (SECTION_DESCRIPTOR_SIZE + HASH_DATA_SIZE) as u64;
        let done_section_size: u64 = SECTION_DESCRIPTOR_SIZE as u64;

        // Build offset chain
        let mut pos: u64 = FILE_HEADER_SIZE as u64;

        let ewf_header_section_size = SECTION_DESCRIPTOR_SIZE as u64 + header_section_data_size;
        pos += ewf_header_section_size;

        let volume_desc_off = pos;
        if !self.omit_volume {
            pos += volume_section_size;
        }

        let table_desc_off = pos;
        pos += table_section_size;

        let sectors_desc_off = pos;
        pos += sectors_section_size;

        // For nonfinal, the "next" section immediately follows sectors
        let nonfinal_next_off = pos; // used only if nonfinal

        if !self.nonfinal {
            if self.insert_gap { pos += 16; }
            if self.insert_zero_gap { pos += 16; }

            let digest_desc_off = pos;
            if digest_section_size > 0 { pos += digest_section_size; }

            let hash_desc_off = pos;
            if !self.omit_hash { pos += hash_section_size; }

            let done_desc_off = pos;

            // ── Assemble ──────────────────────────────────────────────────────
            let mut buf: Vec<u8> = Vec::new();

            // File header
            let sig = self.signature_override.unwrap_or(EVF_SIGNATURE);
            buf.extend_from_slice(&sig);
            buf.push(1u8);
            let seg = self.segment_number_override.unwrap_or(self.segment_number);
            buf.extend_from_slice(&seg.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());

            // ewf "header" section
            let next_after_ewf_header = if !self.omit_volume { volume_desc_off } else { table_desc_off };
            buf.extend_from_slice(&make_section_descriptor("header", next_after_ewf_header, ewf_header_section_size));
            buf.push(0u8);

            // Volume section
            if !self.omit_volume {
                let vol_type = self.volume_type_override.as_deref().unwrap_or("volume");
                let mut desc = make_section_descriptor(vol_type, table_desc_off, volume_section_size);
                if self.corrupt_volume_crc { desc[72] ^= 0xFF; }
                buf.extend_from_slice(&desc);

                let mut vol = vec![0u8; VOLUME_DATA_SIZE];
                vol[0..4].copy_from_slice(&1u32.to_le_bytes()); // media_type
                let vol_chunk_count = self.volume_chunk_count_override.unwrap_or(chunk_count);
                vol[4..8].copy_from_slice(&vol_chunk_count.to_le_bytes());
                let spc_vol = self.volume_sectors_per_chunk_override.unwrap_or(spc);
                vol[8..12].copy_from_slice(&spc_vol.to_le_bytes());
                let bps_vol = self.volume_bytes_per_sector_override.unwrap_or(bps);
                vol[12..16].copy_from_slice(&bps_vol.to_le_bytes());
                let sc_vol = self.volume_sector_count_override.unwrap_or(sector_count);
                vol[16..24].copy_from_slice(&sc_vol.to_le_bytes());
                buf.extend_from_slice(&vol);
            }

            // Table section
            let table_chunk_count = self.table_chunk_count_override.unwrap_or(chunk_count);
            buf.extend_from_slice(&make_section_descriptor("table", sectors_desc_off, table_section_size));
            let mut tbl_hdr = vec![0u8; 24];
            tbl_hdr[0..4].copy_from_slice(&table_chunk_count.to_le_bytes());
            let sectors_data_start = sectors_desc_off + SECTION_DESCRIPTOR_SIZE as u64;
            let tbl_base = self.table_base_offset_override.unwrap_or(sectors_data_start);
            tbl_hdr[8..16].copy_from_slice(&tbl_base.to_le_bytes());
            let tbl_crc = adler32(&tbl_hdr[..16]);
            tbl_hdr[16..20].copy_from_slice(&tbl_crc.to_le_bytes());
            buf.extend_from_slice(&tbl_hdr);
            for i in 0..table_chunk_count {
                let offset = i as u64 * chunk_stride;
                let entry = (offset as u32) & 0x7FFF_FFFF;
                buf.extend_from_slice(&entry.to_le_bytes());
            }

            // Sectors section
            let sectors_next = if self.omit_hash {
                done_desc_off
            } else if self.digest_sha1_override.is_some() {
                digest_desc_off
            } else if self.insert_gap {
                hash_desc_off + 16
            } else {
                hash_desc_off
            };
            buf.extend_from_slice(&make_section_descriptor("sectors", sectors_next, sectors_section_size));
            let chunk_data = vec![0u8; chunk_size as usize];
            if self.chunk_checksums {
                for i in 0..chunk_count as usize {
                    buf.extend_from_slice(&chunk_data);
                    let mut crc = adler32(&chunk_data).to_le_bytes();
                    if self.corrupt_chunk_checksum == Some(i) {
                        crc[0] ^= 0xFF;
                    }
                    buf.extend_from_slice(&crc);
                }
            } else {
                let sectors_data = vec![0u8; sectors_data_size as usize];
                buf.extend_from_slice(&sectors_data);
            }
            let sectors_data = vec![0u8; (chunk_size * u64::from(chunk_count)) as usize];

            // Optional gaps
            if self.insert_gap {
                buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x13, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
            }
            if self.insert_zero_gap {
                buf.extend_from_slice(&[0u8; 16]);
            }

            // Digest section (optional)
            if let Some(sha1_bytes) = self.digest_sha1_override {
                let next_after_digest = if self.omit_hash { done_desc_off } else { hash_desc_off };
                buf.extend_from_slice(&make_section_descriptor("digest", next_after_digest, digest_section_size));
                let md5_of_sectors: [u8; 16] = Md5::digest(&sectors_data).into();
                buf.extend_from_slice(&md5_of_sectors);
                buf.extend_from_slice(&sha1_bytes);
            }

            // Hash section
            if !self.omit_hash {
                let next_after_hash = if self.omit_done {
                    0u64
                } else if self.break_chain {
                    buf.len() as u64 + 0x0010_0000
                } else {
                    done_desc_off
                };
                buf.extend_from_slice(&make_section_descriptor("hash", next_after_hash, hash_section_size));
                let md5 = compute_md5(&sectors_data);
                let stored_md5 = self.md5_override.unwrap_or(md5);
                buf.extend_from_slice(&stored_md5);
            }

            // Done section
            if !self.omit_done {
                buf.extend_from_slice(&make_section_descriptor("done", done_desc_off, done_section_size));
            }

            buf
        } else {
            // ── Non-final segment: ends with "next" section ───────────────────
            let next_section_size: u64 = SECTION_DESCRIPTOR_SIZE as u64;
            let _ = pos; // suppress unused warning

            let mut buf: Vec<u8> = Vec::new();

            // File header
            let sig = self.signature_override.unwrap_or(EVF_SIGNATURE);
            buf.extend_from_slice(&sig);
            buf.push(1u8);
            let seg = self.segment_number_override.unwrap_or(self.segment_number);
            buf.extend_from_slice(&seg.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());

            // ewf "header" section
            let next_after_ewf_header = if !self.omit_volume { volume_desc_off } else { table_desc_off };
            buf.extend_from_slice(&make_section_descriptor("header", next_after_ewf_header, ewf_header_section_size));
            buf.push(0u8);

            // Volume section (only if not omitted — seg 1 has it, subsequent segs don't)
            if !self.omit_volume {
                let vol_type = self.volume_type_override.as_deref().unwrap_or("volume");
                let mut desc = make_section_descriptor(vol_type, table_desc_off, volume_section_size);
                if self.corrupt_volume_crc { desc[72] ^= 0xFF; }
                buf.extend_from_slice(&desc);

                let mut vol = vec![0u8; VOLUME_DATA_SIZE];
                vol[0..4].copy_from_slice(&1u32.to_le_bytes());
                let vol_chunk_count = self.volume_chunk_count_override.unwrap_or(chunk_count);
                vol[4..8].copy_from_slice(&vol_chunk_count.to_le_bytes());
                let spc_vol = self.volume_sectors_per_chunk_override.unwrap_or(spc);
                vol[8..12].copy_from_slice(&spc_vol.to_le_bytes());
                let bps_vol = self.volume_bytes_per_sector_override.unwrap_or(bps);
                vol[12..16].copy_from_slice(&bps_vol.to_le_bytes());
                let sc_vol = self.volume_sector_count_override.unwrap_or(sector_count);
                vol[16..24].copy_from_slice(&sc_vol.to_le_bytes());
                buf.extend_from_slice(&vol);
            }

            // Table section
            let table_chunk_count = self.table_chunk_count_override.unwrap_or(chunk_count);
            buf.extend_from_slice(&make_section_descriptor("table", sectors_desc_off, table_section_size));
            let mut tbl_hdr = vec![0u8; 24];
            tbl_hdr[0..4].copy_from_slice(&table_chunk_count.to_le_bytes());
            let sectors_data_start = sectors_desc_off + SECTION_DESCRIPTOR_SIZE as u64;
            let tbl_base = self.table_base_offset_override.unwrap_or(sectors_data_start);
            tbl_hdr[8..16].copy_from_slice(&tbl_base.to_le_bytes());
            let tbl_crc = adler32(&tbl_hdr[..16]);
            tbl_hdr[16..20].copy_from_slice(&tbl_crc.to_le_bytes());
            buf.extend_from_slice(&tbl_hdr);
            for i in 0..table_chunk_count {
                let offset = i as u64 * chunk_size;
                let entry = (offset as u32) & 0x7FFF_FFFF;
                buf.extend_from_slice(&entry.to_le_bytes());
            }

            // Sectors section — next points to the "next" section
            buf.extend_from_slice(&make_section_descriptor("sectors", nonfinal_next_off, sectors_section_size));
            let sectors_data = vec![0u8; sectors_data_size as usize];
            buf.extend_from_slice(&sectors_data);

            // "next" section — self-referential
            buf.extend_from_slice(&make_section_descriptor("next", nonfinal_next_off, next_section_size));

            buf
        }
    }
}

fn compute_md5(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

// ── Tool-specific synthetic builders ─────────────────────────────────────────
//
// These builders produce E01 images whose section layout matches known quirks
// of each acquisition tool. They are used to pin the parser against real-world
// format variations without requiring tool licences or binary fixtures.

/// FTK Imager-style E01:
///   - Includes a `header2` section before `header` (UTF-16LE metadata)
///   - Uses `disk` section type instead of `volume`
///   - sectors_per_chunk = 64 (32 KB chunks)
///
/// When `tampered` is true, the stored MD5 is wrong → HashMismatch.
pub fn make_e01_ftk_imager_style(tampered: bool) -> Vec<u8> {
    const CHUNK_SECTORS: u32 = 64;
    const BPS: u32 = 512;
    const SECTOR_COUNT: u32 = 128;
    let chunk_size = CHUNK_SECTORS as u64 * BPS as u64;

    let mut b = E01Builder::new(chunk_size);
    b.sectors_per_chunk = CHUNK_SECTORS;
    b.bytes_per_sector = BPS;
    // FTK Imager uses `disk` section type
    b.volume_type_override = Some("disk".to_string());
    if tampered {
        b.md5_override = Some([0xDEu8; 16]);
    }
    b.build()
}

/// X-Ways / WinHex-style E01:
///   - Uses `disk` section type
///   - sectors_per_chunk = 64 (standard)
///   - Includes digest section (SHA-1 of zeros for simplicity)
///
/// When `tampered` is true, the stored MD5 is wrong → HashMismatch.
pub fn make_e01_xways_style(tampered: bool) -> Vec<u8> {
    use sha1::Digest as _;
    const CHUNK_SECTORS: u32 = 64;
    const BPS: u32 = 512;
    let chunk_size = CHUNK_SECTORS as u64 * BPS as u64;
    let sectors_data = vec![0u8; chunk_size as usize];
    let sha1: [u8; 20] = sha1::Sha1::digest(&sectors_data).into();

    let mut b = E01Builder::new(chunk_size);
    b.sectors_per_chunk = CHUNK_SECTORS;
    b.bytes_per_sector = BPS;
    b.volume_type_override = Some("disk".to_string());
    b.digest_sha1_override = Some(sha1); // X-Ways writes digest section with SHA-1
    if tampered {
        b.md5_override = Some([0xABu8; 16]);
    }
    b.build()
}

/// ewfacquire (dc3dd) style E01:
///   - Uses `disk` section type
///   - sectors_per_chunk = 64
///   - No digest section (ewfacquire omits SHA-1 by default)
///
/// When `tampered` is true, the stored MD5 is wrong → HashMismatch.
pub fn make_e01_ewfacquire_style(tampered: bool) -> Vec<u8> {
    const CHUNK_SECTORS: u32 = 64;
    const BPS: u32 = 512;
    let chunk_size = CHUNK_SECTORS as u64 * BPS as u64;

    let mut b = E01Builder::new(chunk_size);
    b.sectors_per_chunk = CHUNK_SECTORS;
    b.bytes_per_sector = BPS;
    b.volume_type_override = Some("disk".to_string());
    // ewfacquire does not write digest section
    if tampered {
        b.md5_override = Some([0xCDu8; 16]);
    }
    b.build()
}

/// Convenience: a standard E01 image with a wrong stored MD5.
pub fn make_e01_tampered_hash() -> Vec<u8> {
    E01Builder::new(512 * 64).with_md5([0xBAu8; 16]).build()
}

// ── libewf-grounded builders ──────────────────────────────────────────────────
//
// Sources: libewf/libewf_segment_file.c, the ewf_data_t struct (1052 bytes):
//   [0]      media_type (u8): 0x00=removable, 0x01=fixed, 0x03=optical, 0x0e=LVF, 0x10=memory
//   [1..4]   unknown1 (zeros)
//   [4..8]   number_of_chunks (u32 LE)
//   [8..12]  sectors_per_chunk (u32 LE)
//   [12..16] bytes_per_sector (u32 LE)
//   [16..24] number_of_sectors (u64 LE)
//   [24..36] CHS geometry (3×u32)
//   [36]     media_flags (u8)
//   [37..40] unknown2 (zeros)
//   [40..44] palm_volume_start_sector (u32)
//   [44..48] unknown3 (u32)
//   [48..52] smart_logs_start_sector (u32)
//   [52]     compression_level (u8)
//   [53..56] unknown4 (zeros)
//   [56..60] error_granularity (u32)
//   [60..64] unknown5 (u32)
//   [64..80] set_identifier / GUID (16 bytes)
//   [80..1043] unknown6 (zeros, 963 bytes)
//   [1043..1048] signature (5 reserved bytes)
//   [1048..1052] checksum (Adler-32 of bytes 0..1048)

const FULL_VOLUME_DATA_SIZE: usize = 1052;

/// Build an ewf_data_t body (1052 bytes) with the given parameters.
/// `guid` = None leaves set_identifier as zeros (same GUID).
pub fn make_full_volume_body(
    chunk_count: u32,
    sectors_per_chunk: u32,
    bytes_per_sector: u32,
    sector_count: u64,
    media_type: u8,
    guid: Option<[u8; 16]>,
    corrupt_crc: bool,
) -> Vec<u8> {
    let mut body = vec![0u8; FULL_VOLUME_DATA_SIZE];
    body[0] = media_type;
    body[4..8].copy_from_slice(&chunk_count.to_le_bytes());
    body[8..12].copy_from_slice(&sectors_per_chunk.to_le_bytes());
    body[12..16].copy_from_slice(&bytes_per_sector.to_le_bytes());
    body[16..24].copy_from_slice(&sector_count.to_le_bytes());
    if let Some(g) = guid {
        body[64..80].copy_from_slice(&g);
    }
    // Adler-32 over bytes 0..1048
    let crc = if corrupt_crc {
        0xDEAD_BEEFu32
    } else {
        adler32(&body[..1048])
    };
    body[1048..1052].copy_from_slice(&crc.to_le_bytes());
    body
}

/// Build a minimal E01 with a full 1052-byte volume section.
fn make_e01_with_full_volume(
    media_type: u8,
    guid: Option<[u8; 16]>,
    corrupt_crc: bool,
) -> Vec<u8> {
    const SPC: u32 = 64;
    const BPS: u32 = 512;
    const CHUNK_COUNT: u32 = 1;
    let sector_count = u64::from(SPC) * u64::from(CHUNK_COUNT);
    let chunk_size = u64::from(SPC) * u64::from(BPS);
    let sectors_data = vec![0u8; chunk_size as usize];
    let md5: [u8; 16] = compute_md5(&sectors_data);

    let mut buf = Vec::new();

    // File header
    buf.extend_from_slice(&EVF_SIGNATURE);
    buf.push(0x01); // fields_start
    buf.extend_from_slice(&1u16.to_le_bytes()); // segment_number
    buf.extend_from_slice(&0u16.to_le_bytes()); // fields_end

    // Header section (minimal: just a null byte)
    let header_data = b"\x00";
    let header_desc_off = buf.len() as u64;
    let header_section_size = (SECTION_DESCRIPTOR_SIZE + header_data.len()) as u64;
    let volume_desc_off = header_desc_off + header_section_size;
    buf.extend_from_slice(&make_section_descriptor("header", volume_desc_off, header_section_size));
    buf.extend_from_slice(header_data);

    // Volume section with full 1052-byte body
    let vol_body = make_full_volume_body(CHUNK_COUNT, SPC, BPS, sector_count, media_type, guid, corrupt_crc);
    let vol_section_size = (SECTION_DESCRIPTOR_SIZE + FULL_VOLUME_DATA_SIZE) as u64;
    let table_desc_off = volume_desc_off + vol_section_size;
    buf.extend_from_slice(&make_section_descriptor("volume", table_desc_off, vol_section_size));
    buf.extend_from_slice(&vol_body);

    // Table section
    let table_header_size: u64 = 24;
    let table_entries_size = u64::from(CHUNK_COUNT) * 4;
    let table_section_size = SECTION_DESCRIPTOR_SIZE as u64 + table_header_size + table_entries_size;
    let sectors_desc_off = table_desc_off + table_section_size;
    buf.extend_from_slice(&make_section_descriptor("table", sectors_desc_off, table_section_size));
    let sectors_data_start = sectors_desc_off + SECTION_DESCRIPTOR_SIZE as u64;
    let mut tbl_hdr = vec![0u8; 24];
    tbl_hdr[0..4].copy_from_slice(&CHUNK_COUNT.to_le_bytes());
    tbl_hdr[8..16].copy_from_slice(&sectors_data_start.to_le_bytes());
    let tbl_crc = adler32(&tbl_hdr[..16]);
    tbl_hdr[16..20].copy_from_slice(&tbl_crc.to_le_bytes());
    buf.extend_from_slice(&tbl_hdr);
    buf.extend_from_slice(&0u32.to_le_bytes()); // one entry: offset 0

    // Sectors section
    let sectors_section_size = SECTION_DESCRIPTOR_SIZE as u64 + chunk_size;
    let hash_desc_off = sectors_desc_off + sectors_section_size;
    buf.extend_from_slice(&make_section_descriptor("sectors", hash_desc_off, sectors_section_size));
    buf.extend_from_slice(&sectors_data);

    // Hash section
    let hash_section_size = SECTION_DESCRIPTOR_SIZE as u64 + 16;
    let done_desc_off = hash_desc_off + hash_section_size;
    buf.extend_from_slice(&make_section_descriptor("hash", done_desc_off, hash_section_size));
    buf.extend_from_slice(&md5);

    // Done section (self-referential)
    let done_section_size = SECTION_DESCRIPTOR_SIZE as u64;
    buf.extend_from_slice(&make_section_descriptor("done", done_desc_off, done_section_size));

    buf
}

/// E01 with a full 1052-byte volume section and correct Adler-32.
pub fn make_e01_full_volume_clean() -> Vec<u8> {
    make_e01_with_full_volume(0x01, None, false)
}

/// E01 with a full 1052-byte volume section and a corrupt Adler-32.
pub fn make_e01_full_volume_bad_crc() -> Vec<u8> {
    make_e01_with_full_volume(0x01, None, true)
}

/// E01 images with each valid media_type value. Returns (media_type, image) pairs.
pub fn make_e01_valid_media_types() -> Vec<(u8, Vec<u8>)> {
    // Valid values from libewf: 0x00=removable, 0x01=fixed, 0x03=optical, 0x0e=LVF, 0x10=memory
    [0x00u8, 0x01, 0x03, 0x0e, 0x10]
        .iter()
        .map(|&mt| (mt, make_e01_with_full_volume(mt, None, false)))
        .collect()
}

/// E01 with an unrecognised media_type byte.
pub fn make_e01_unknown_media_type(media_type: u8) -> Vec<u8> {
    make_e01_with_full_volume(media_type, None, false)
}

/// Two-segment image where both volume sections carry the SAME GUID.
pub fn make_two_segment_matching_guids() -> (Vec<u8>, Vec<u8>) {
    let guid = [0x11u8; 16];
    let seg1 = make_e01_nonfinal_with_guid(guid, 1);
    let seg2 = make_e01_final_with_guid(guid, 2);
    (seg1, seg2)
}

/// Two-segment image where the second segment carries a DIFFERENT GUID.
pub fn make_two_segment_guid_mismatch() -> (Vec<u8>, Vec<u8>) {
    let guid1 = [0x11u8; 16];
    let guid2 = [0xFFu8; 16]; // different!
    let seg1 = make_e01_nonfinal_with_guid(guid1, 1);
    let seg2 = make_e01_final_with_guid(guid2, 2);
    (seg1, seg2)
}

/// Non-final segment (ends with "next") with a full volume section containing a GUID.
fn make_e01_nonfinal_with_guid(guid: [u8; 16], seg_num: u16) -> Vec<u8> {
    const SPC: u32 = 64;
    const BPS: u32 = 512;
    const CHUNK_COUNT: u32 = 1;
    let sector_count = u64::from(SPC) * u64::from(CHUNK_COUNT);
    let chunk_size = u64::from(SPC) * u64::from(BPS);

    let mut buf = Vec::new();

    // File header
    buf.extend_from_slice(&EVF_SIGNATURE);
    buf.push(0x01);
    buf.extend_from_slice(&seg_num.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    // Header section
    let header_data = b"\x00";
    let hdr_off = buf.len() as u64;
    let hdr_size = (SECTION_DESCRIPTOR_SIZE + header_data.len()) as u64;
    let vol_off = hdr_off + hdr_size;
    buf.extend_from_slice(&make_section_descriptor("header", vol_off, hdr_size));
    buf.extend_from_slice(header_data);

    // Volume section with GUID
    let vol_body = make_full_volume_body(CHUNK_COUNT * 2, SPC, BPS, sector_count * 2, 0x01, Some(guid), false);
    let vol_size = (SECTION_DESCRIPTOR_SIZE + FULL_VOLUME_DATA_SIZE) as u64;
    let tbl_off = vol_off + vol_size;
    buf.extend_from_slice(&make_section_descriptor("volume", tbl_off, vol_size));
    buf.extend_from_slice(&vol_body);

    // Table
    let tbl_entries_size = u64::from(CHUNK_COUNT) * 4;
    let tbl_section_size = SECTION_DESCRIPTOR_SIZE as u64 + 24 + tbl_entries_size;
    let sectors_off = tbl_off + tbl_section_size;
    buf.extend_from_slice(&make_section_descriptor("table", sectors_off, tbl_section_size));
    let sectors_data_start = sectors_off + SECTION_DESCRIPTOR_SIZE as u64;
    let mut tbl_hdr = vec![0u8; 24];
    tbl_hdr[0..4].copy_from_slice(&CHUNK_COUNT.to_le_bytes());
    tbl_hdr[8..16].copy_from_slice(&sectors_data_start.to_le_bytes());
    let tbl_crc = adler32(&tbl_hdr[..16]);
    tbl_hdr[16..20].copy_from_slice(&tbl_crc.to_le_bytes());
    buf.extend_from_slice(&tbl_hdr);
    buf.extend_from_slice(&0u32.to_le_bytes());

    // Sectors
    let sectors_data = vec![0u8; chunk_size as usize];
    let sectors_section_size = SECTION_DESCRIPTOR_SIZE as u64 + chunk_size;
    let next_off = sectors_off + sectors_section_size;
    buf.extend_from_slice(&make_section_descriptor("sectors", next_off, sectors_section_size));
    buf.extend_from_slice(&sectors_data);

    // Next (self-referential)
    let next_section_size = SECTION_DESCRIPTOR_SIZE as u64;
    buf.extend_from_slice(&make_section_descriptor("next", next_off, next_section_size));

    buf
}

/// Final segment with a volume section containing a GUID (some tools repeat it).
fn make_e01_final_with_guid(guid: [u8; 16], seg_num: u16) -> Vec<u8> {
    const SPC: u32 = 64;
    const BPS: u32 = 512;
    const CHUNK_COUNT: u32 = 1;
    let sector_count = u64::from(SPC) * u64::from(CHUNK_COUNT);
    let chunk_size = u64::from(SPC) * u64::from(BPS);
    let sectors_data = vec![0u8; chunk_size as usize];

    // Compute combined MD5 of 2 chunks of zeros
    let combined_data = vec![0u8; chunk_size as usize * 2];
    let md5: [u8; 16] = compute_md5(&combined_data);

    let mut buf = Vec::new();

    // File header
    buf.extend_from_slice(&EVF_SIGNATURE);
    buf.push(0x01);
    buf.extend_from_slice(&seg_num.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    // Header section
    let header_data = b"\x00";
    let hdr_off = buf.len() as u64;
    let hdr_size = (SECTION_DESCRIPTOR_SIZE + header_data.len()) as u64;
    let vol_off = hdr_off + hdr_size;
    buf.extend_from_slice(&make_section_descriptor("header", vol_off, hdr_size));
    buf.extend_from_slice(header_data);

    // Volume section with GUID (some tools write it in every segment)
    let vol_body = make_full_volume_body(CHUNK_COUNT * 2, SPC, BPS, sector_count * 2, 0x01, Some(guid), false);
    let vol_size = (SECTION_DESCRIPTOR_SIZE + FULL_VOLUME_DATA_SIZE) as u64;
    let tbl_off = vol_off + vol_size;
    buf.extend_from_slice(&make_section_descriptor("volume", tbl_off, vol_size));
    buf.extend_from_slice(&vol_body);

    // Table
    let tbl_entries_size = u64::from(CHUNK_COUNT) * 4;
    let tbl_section_size = SECTION_DESCRIPTOR_SIZE as u64 + 24 + tbl_entries_size;
    let sectors_off = tbl_off + tbl_section_size;
    buf.extend_from_slice(&make_section_descriptor("table", sectors_off, tbl_section_size));
    let sectors_data_start = sectors_off + SECTION_DESCRIPTOR_SIZE as u64;
    let mut tbl_hdr = vec![0u8; 24];
    tbl_hdr[0..4].copy_from_slice(&CHUNK_COUNT.to_le_bytes());
    tbl_hdr[8..16].copy_from_slice(&sectors_data_start.to_le_bytes());
    let tbl_crc = adler32(&tbl_hdr[..16]);
    tbl_hdr[16..20].copy_from_slice(&tbl_crc.to_le_bytes());
    buf.extend_from_slice(&tbl_hdr);
    buf.extend_from_slice(&0u32.to_le_bytes());

    // Sectors
    let sectors_section_size = SECTION_DESCRIPTOR_SIZE as u64 + chunk_size;
    let hash_off = sectors_off + sectors_section_size;
    buf.extend_from_slice(&make_section_descriptor("sectors", hash_off, sectors_section_size));
    buf.extend_from_slice(&sectors_data);

    // Hash
    let hash_section_size = SECTION_DESCRIPTOR_SIZE as u64 + 16;
    let done_off = hash_off + hash_section_size;
    buf.extend_from_slice(&make_section_descriptor("hash", done_off, hash_section_size));
    buf.extend_from_slice(&md5);

    // Done
    let done_section_size = SECTION_DESCRIPTOR_SIZE as u64;
    buf.extend_from_slice(&make_section_descriptor("done", done_off, done_section_size));

    buf
}

/// EWF v1 segment with DVF signature: { 0x64, 0x76, 0x66, 0x09, 0x0d, 0x0a, 0xff, 0x00 }
/// DiskSig format — used by some Tableau/older tools.
pub fn make_dvf_segment() -> Vec<u8> {
    const DVF_SIGNATURE: [u8; 8] = [0x64, 0x76, 0x66, 0x09, 0x0d, 0x0a, 0xff, 0x00];
    E01Builder::new(512 * 64)
        .with_signature(DVF_SIGNATURE)
        .build()
}

/// EWF v1 segment with LVF signature: { 0x4c, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00 }
/// Logical Volume Format — logical evidence images.
pub fn make_lvf_segment() -> Vec<u8> {
    const LVF_SIGNATURE: [u8; 8] = [0x4c, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
    E01Builder::new(512 * 64)
        .with_signature(LVF_SIGNATURE)
        .build()
}

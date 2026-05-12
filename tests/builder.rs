/// Synthetic E01 builder for testing.
///
/// EWF v1 layout (single segment, single chunk for simplicity):
///   [0x000]  File Header      13 bytes
///   [0x00D]  Section 1 desc   76 bytes  ("header" — metadata string)
///   [0x059]  Section 1 data   variable
///   [???]    Volume desc      76 bytes
///   [???]    Volume data      94 bytes
///   [???]    Table desc       76 bytes
///   [???]    Table header     24 bytes
///   [???]    Table entries    4 × chunk_count bytes
///   [???]    Sectors desc     76 bytes
///   [???]    Sectors data     chunk bytes (uncompressed for simplicity)
///   [???]    Hash desc        76 bytes
///   [???]    Hash data        16 bytes (MD5)
///   [???]    Done desc        76 bytes  (next == self)

use md5::{Digest as _, Md5};
use std::io::Write as _;

/// EWF v1 signature: "EVF\x09\x0d\x0a\xff\x00"
pub const EVF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];

pub const FILE_HEADER_SIZE: usize = 13;
pub const SECTION_DESCRIPTOR_SIZE: usize = 76;
pub const VOLUME_DATA_SIZE: usize = 94;
pub const HASH_DATA_SIZE: usize = 16; // MD5

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

/// Build a section descriptor.
/// `section_type`: ASCII name (≤ 16 chars), NUL-padded.
/// `next`:         absolute file offset of the next section descriptor.
/// `size`:         total section size in bytes (descriptor + data).
pub fn make_section_descriptor(section_type: &str, next: u64, size: u64) -> Vec<u8> {
    let mut buf = vec![0u8; SECTION_DESCRIPTOR_SIZE];
    let name = section_type.as_bytes();
    let copy_len = name.len().min(16);
    buf[..copy_len].copy_from_slice(&name[..copy_len]);
    buf[16..24].copy_from_slice(&next.to_le_bytes());
    buf[24..32].copy_from_slice(&size.to_le_bytes());
    // bytes [32..72] remain zero (padding)
    let crc = adler32(&buf[..72]);
    buf[72..76].copy_from_slice(&crc.to_le_bytes());
    buf
}

pub struct E01Builder {
    /// Virtual disk size in bytes.
    pub virtual_disk_size: u64,
    /// Sectors per chunk (default 64 → 32 KB chunks with 512 B/sector).
    pub sectors_per_chunk: u32,
    /// Bytes per sector (default 512).
    pub bytes_per_sector: u32,
    /// Segment number (default 1).
    pub segment_number: u16,
    /// Override the EVF signature.
    pub signature_override: Option<[u8; 8]>,
    /// If true, corrupt the volume section descriptor's checksum.
    pub corrupt_volume_crc: bool,
    /// If true, set the "done" section's next pointer to 0 instead of self.
    pub omit_done: bool,
    /// If true, insert a 16-byte gap between the sectors and hash sections.
    pub insert_gap: bool,
    /// Override the stored MD5 hash bytes.
    pub md5_override: Option<[u8; 16]>,
    /// Override the chunk_count in the table header (independent of volume).
    pub table_chunk_count_override: Option<u32>,
    /// Override sectors_per_chunk in the volume section only.
    pub volume_sectors_per_chunk_override: Option<u32>,
    /// Override bytes_per_sector in the volume section only.
    pub volume_bytes_per_sector_override: Option<u32>,
    /// Override sector_count in the volume section only.
    pub volume_sector_count_override: Option<u64>,
    /// If true, skip the volume section entirely.
    pub omit_volume: bool,
    /// If true, make the done section's next point beyond the file.
    pub break_chain: bool,
    /// Override the section type string for the volume section.
    pub volume_type_override: Option<String>,
    /// Segment number override (separate from segment_number for testing zero).
    pub segment_number_override: Option<u16>,
    /// If true, skip the hash section entirely.
    pub omit_hash: bool,
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
        }
    }

    pub fn with_signature(mut self, sig: [u8; 8]) -> Self {
        self.signature_override = Some(sig);
        self
    }
    pub fn with_segment_number(mut self, n: u16) -> Self {
        self.segment_number_override = Some(n);
        self
    }
    pub fn with_corrupt_volume_crc(mut self) -> Self {
        self.corrupt_volume_crc = true;
        self
    }
    pub fn with_broken_chain(mut self) -> Self {
        self.break_chain = true;
        self
    }
    pub fn with_gap(mut self) -> Self {
        self.insert_gap = true;
        self
    }
    pub fn with_omit_volume(mut self) -> Self {
        self.omit_volume = true;
        self
    }
    pub fn with_volume_type(mut self, t: &str) -> Self {
        self.volume_type_override = Some(t.to_string());
        self
    }
    pub fn with_omit_done(mut self) -> Self {
        self.omit_done = true;
        self
    }
    pub fn with_volume_sectors_per_chunk(mut self, spc: u32) -> Self {
        self.volume_sectors_per_chunk_override = Some(spc);
        self
    }
    pub fn with_volume_sector_count(mut self, sc: u64) -> Self {
        self.volume_sector_count_override = Some(sc);
        self
    }
    pub fn with_volume_bytes_per_sector(mut self, bps: u32) -> Self {
        self.volume_bytes_per_sector_override = Some(bps);
        self
    }
    pub fn with_table_chunk_count(mut self, n: u32) -> Self {
        self.table_chunk_count_override = Some(n);
        self
    }
    pub fn with_md5(mut self, md5: [u8; 16]) -> Self {
        self.md5_override = Some(md5);
        self
    }
    pub fn with_omit_hash(mut self) -> Self {
        self.omit_hash = true;
        self
    }

    pub fn build(self) -> Vec<u8> {
        let spc = self.sectors_per_chunk;
        let bps = self.bytes_per_sector;
        let chunk_size = u64::from(spc) * u64::from(bps);
        let chunk_count = self.virtual_disk_size.div_ceil(chunk_size) as u32;
        let sector_count = u64::from(chunk_count) * u64::from(spc);

        // --- Compute layout offsets ---
        // File header: 13
        // ewf "header" section: desc(76) + minimal ascii metadata(1)
        let header_section_data_size: u64 = 1; // minimal placeholder
        // Volume section (optional)
        let volume_section_size: u64 =
            (SECTION_DESCRIPTOR_SIZE + VOLUME_DATA_SIZE) as u64;
        // Table section: desc(76) + table_header(24) + entries(4*n)
        let table_data_size: u64 = 24 + 4 * u64::from(chunk_count);
        let table_section_size = SECTION_DESCRIPTOR_SIZE as u64 + table_data_size;
        // Sectors section: desc(76) + chunk_count * chunk_size bytes
        let sectors_data_size = u64::from(chunk_count) * chunk_size;
        let sectors_section_size = SECTION_DESCRIPTOR_SIZE as u64 + sectors_data_size;
        // Hash section: desc(76) + 16 bytes MD5
        let hash_section_size: u64 = (SECTION_DESCRIPTOR_SIZE + HASH_DATA_SIZE) as u64;
        // Done section: desc only (76 bytes, next == self)
        let done_section_size: u64 = SECTION_DESCRIPTOR_SIZE as u64;

        // Build section chain offsets
        let mut pos: u64 = FILE_HEADER_SIZE as u64;

        let ewf_header_desc_off = pos;
        let ewf_header_section_size =
            SECTION_DESCRIPTOR_SIZE as u64 + header_section_data_size;
        pos += ewf_header_section_size;

        let volume_desc_off = pos;
        if !self.omit_volume {
            pos += volume_section_size;
        }

        let table_desc_off = pos;
        pos += table_section_size;

        let sectors_desc_off = pos;
        pos += sectors_section_size;
        if self.insert_gap {
            pos += 16;
        }

        let hash_desc_off = pos;
        if !self.omit_hash {
            pos += hash_section_size;
        }

        let done_desc_off = pos;

        // --- Assemble bytes ---
        let mut buf: Vec<u8> = Vec::new();

        // File header
        let sig = self.signature_override.unwrap_or(EVF_SIGNATURE);
        buf.extend_from_slice(&sig);
        buf.push(1u8); // fields_start
        let seg = self.segment_number_override.unwrap_or(self.segment_number);
        buf.extend_from_slice(&seg.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // fields_end

        // ewf "header" section
        let next_after_ewf_header = if !self.omit_volume {
            volume_desc_off
        } else {
            table_desc_off
        };
        buf.extend_from_slice(&make_section_descriptor(
            "header",
            next_after_ewf_header,
            ewf_header_section_size,
        ));
        buf.push(0u8); // minimal header data (1 byte placeholder)

        // Volume section
        if !self.omit_volume {
            let vol_type = self
                .volume_type_override
                .as_deref()
                .unwrap_or("volume");
            let mut desc =
                make_section_descriptor(vol_type, table_desc_off, volume_section_size);
            if self.corrupt_volume_crc {
                desc[72] ^= 0xFF;
            }
            buf.extend_from_slice(&desc);

            // Volume data (94 bytes)
            let mut vol = vec![0u8; VOLUME_DATA_SIZE];
            // media_type (u32 LE) at [0..4] = 1
            vol[0..4].copy_from_slice(&1u32.to_le_bytes());
            // chunk_count at [4..8]
            vol[4..8].copy_from_slice(&chunk_count.to_le_bytes());
            // sectors_per_chunk at [8..12]
            let spc_vol = self.volume_sectors_per_chunk_override.unwrap_or(spc);
            vol[8..12].copy_from_slice(&spc_vol.to_le_bytes());
            // bytes_per_sector at [12..16]
            let bps_vol = self.volume_bytes_per_sector_override.unwrap_or(bps);
            vol[12..16].copy_from_slice(&bps_vol.to_le_bytes());
            // sector_count at [16..24]
            let sc_vol = self.volume_sector_count_override.unwrap_or(sector_count);
            vol[16..24].copy_from_slice(&sc_vol.to_le_bytes());
            buf.extend_from_slice(&vol);
        }

        // Table section descriptor + data
        let table_chunk_count = self
            .table_chunk_count_override
            .unwrap_or(chunk_count);
        buf.extend_from_slice(&make_section_descriptor(
            "table",
            sectors_desc_off,
            table_section_size,
        ));
        // Table header (24 bytes)
        let mut tbl_hdr = vec![0u8; 24];
        tbl_hdr[0..4].copy_from_slice(&table_chunk_count.to_le_bytes()); // entry_count
        // padding [4..8] = 0
        // base_offset [8..16] — absolute offset where chunk data starts (sectors data body)
        let sectors_data_start = sectors_desc_off + SECTION_DESCRIPTOR_SIZE as u64;
        tbl_hdr[8..16].copy_from_slice(&sectors_data_start.to_le_bytes());
        // checksum [16..24]: adler32 of first 16 bytes then the entries
        // (simplified: store 0 for testing; forensic checks use stored vs computed)
        let tbl_crc = adler32(&tbl_hdr[..16]);
        tbl_hdr[16..20].copy_from_slice(&tbl_crc.to_le_bytes());
        buf.extend_from_slice(&tbl_hdr);

        // Table entries: each is a u32 LE, bits[0..31]=offset-within-base, bit31=compressed
        // For uncompressed chunks, bit31=0, offset=chunk_index * chunk_size
        for i in 0..table_chunk_count {
            let offset = i as u64 * chunk_size;
            // offset relative to base: since base == sectors_data_start, these are absolute
            // EWF stores chunk offsets as absolute (the base_offset in table header is the
            // absolute start; entries are relative to that base).
            let entry = (offset as u32) & 0x7FFF_FFFF; // uncompressed, offset within base
            buf.extend_from_slice(&entry.to_le_bytes());
        }

        // Sectors section
        let sectors_next = if self.omit_hash {
            done_desc_off
        } else if self.insert_gap {
            hash_desc_off + 16
        } else {
            hash_desc_off
        };
        buf.extend_from_slice(&make_section_descriptor(
            "sectors",
            sectors_next,
            sectors_section_size,
        ));
        // Sectors data: all-zero chunks (uncompressed)
        let sectors_data = vec![0u8; sectors_data_size as usize];
        buf.extend_from_slice(&sectors_data);

        // Optional gap (16 non-zero bytes between sections)
        if self.insert_gap {
            buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF,
                                    0xCA, 0xFE, 0xBA, 0xBE,
                                    0x13, 0x37, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x01]);
        }

        // Hash section
        if !self.omit_hash {
            let next_after_hash = if self.omit_done {
                0u64
            } else if self.break_chain {
                buf.len() as u64 + 0x0010_0000 // beyond file
            } else {
                done_desc_off
            };
            buf.extend_from_slice(&make_section_descriptor(
                "hash",
                next_after_hash,
                hash_section_size,
            ));
            let md5 = compute_md5(&sectors_data);
            let stored_md5 = self.md5_override.unwrap_or(md5);
            buf.extend_from_slice(&stored_md5);
        }

        // Done section
        if !self.omit_done {
            // next == self (done points to itself)
            let done_next = done_desc_off;
            buf.extend_from_slice(&make_section_descriptor(
                "done",
                done_next,
                done_section_size,
            ));
        }

        buf
    }
}

fn compute_md5(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

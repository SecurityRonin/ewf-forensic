use flate2::read::ZlibDecoder;
use md5::{Digest as _, Md5};
use sha1::Sha1;
use std::io::Read as _;

// ── EWF v1 constants ─────────────────────────────────────────────────────────

const EVF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
const FILE_HEADER_SIZE: usize = 13;
pub(crate) const SECTION_DESCRIPTOR_SIZE: usize = 76;
const VOLUME_DATA_MIN: usize = 24;

const KNOWN_TYPES: &[&str] = &[
    "header", "header2", "volume", "disk", "table", "table2", "sectors", "hash", "digest",
    "error2", "session", "done", "next", "data", "ltree", "ltreedata",
];

// ── EWF v2 constants ─────────────────────────────────────────────────────────

const EVF2_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];
const LEF2_SIGNATURE: [u8; 8] = [0x4c, 0x45, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];
const EVF2_FILE_HEADER_SIZE: usize = 32;
const EVF2_SECTION_DESCRIPTOR_SIZE: usize = 64;
const EVF2_DATA_FLAG_ENCRYPTED: u32 = 0x0000_0002;
const EVF2_TYPE_MEDIA_INFO: u32 = 0x02;
const EVF2_TYPE_MD5_HASH: u32 = 0x08;
const EVF2_TYPE_SHA1_HASH: u32 = 0x09;
const EVF2_TYPE_DONE: u32 = 0x0F;
const EVF2_TYPE_NEXT: u32 = 0x0D;

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone)]
pub enum EwfIntegrityAnomaly {
    // ── EWF v1 ───────────────────────────────────────────────────────────────
    InvalidSignature,
    SegmentNumberZero,
    SectionDescriptorCrcMismatch {
        offset: u64,
        section_type: String,
        computed: u32,
        stored: u32,
    },
    SectionChainBroken {
        at_offset: u64,
        next_offset: u64,
    },
    SectionGapNonZero {
        gap_offset: u64,
        gap_size: u64,
    },
    VolumeSectionMissing,
    UnknownSectionType {
        offset: u64,
        type_name: String,
    },
    DoneSectionMissing,
    ChunkSizeInvalid {
        sectors_per_chunk: u32,
        bytes_per_sector: u32,
    },
    SectorCountMismatch {
        declared: u64,
        expected: u64,
    },
    BytesPerSectorInvalid {
        bytes_per_sector: u32,
    },
    TableChunkCountMismatch {
        in_volume: u32,
        in_table: u32,
    },
    TableEntryOutOfBounds {
        chunk_index: u32,
        entry_offset: u64,
        file_size: u64,
    },
    TableEntryOutsideSectorsRange {
        chunk_index: u32,
        entry_offset: u64,
        sectors_start: u64,
        sectors_end: u64,
    },
    SectionGapZero {
        gap_offset: u64,
        gap_size: u64,
    },
    HashMismatch {
        computed: [u8; 16],
        stored: [u8; 16],
    },
    HashSectionMissing,
    // ── Multi-segment ─────────────────────────────────────────────────────────
    /// Segment number does not match the expected sequential position.
    SegmentOutOfOrder {
        segment_number: u16,
        expected: u16,
    },
    // ── SHA-1 from EWF v1 digest section ─────────────────────────────────────
    /// Computed SHA-1 of all sector data does not match the stored SHA-1 in the digest section.
    DigestSha1Mismatch {
        computed: [u8; 20],
        stored: [u8; 20],
    },
    // ── External reference hash ───────────────────────────────────────────────
    /// Computed MD5 does not match an externally supplied reference (e.g. chain-of-custody form).
    ExternalMd5Mismatch {
        computed: [u8; 16],
        expected: [u8; 16],
    },
    /// Computed SHA-1 does not match an externally supplied reference.
    ExternalSha1Mismatch {
        computed: [u8; 20],
        expected: [u8; 20],
    },
    // ── EWF v2 ───────────────────────────────────────────────────────────────
    /// A section's stored data_integrity_hash does not match MD5 of the section body.
    Ewf2SectionDataHashMismatch {
        offset: u64,
        section_type_id: u32,
        computed: [u8; 16],
        stored: [u8; 16],
    },
    /// An encrypted section was found; its content cannot be verified.
    Ewf2EncryptedSection {
        offset: u64,
    },
    /// No MD5 or SHA-1 hash section found in the final EWF v2 segment.
    Ewf2HashSectionMissing,
    /// No media information (device information) section found in the EWF v2 image.
    Ewf2MediaInfoMissing,
    /// bytes_per_sector in the EWF v2 media info section is not 512 or 4096.
    Ewf2BytesPerSectorInvalid { bytes_per_sector: u32 },
    /// sectors_per_chunk in the EWF v2 media info section is zero or not a power of two.
    Ewf2ChunkSizeInvalid { sectors_per_chunk: u32 },
    /// sector_count in the EWF v2 media info section is zero.
    Ewf2SectorCountZero,
}

impl EwfIntegrityAnomaly {
    pub fn severity(&self) -> Severity {
        match self {
            Self::InvalidSignature => Severity::Critical,
            Self::SegmentNumberZero => Severity::Error,
            Self::SectionDescriptorCrcMismatch { .. } => Severity::Error,
            Self::SectionChainBroken { .. } => Severity::Critical,
            Self::SectionGapNonZero { .. } => Severity::Warning,
            Self::VolumeSectionMissing => Severity::Critical,
            Self::UnknownSectionType { .. } => Severity::Warning,
            Self::DoneSectionMissing => Severity::Warning,
            Self::ChunkSizeInvalid { .. } => Severity::Error,
            Self::SectorCountMismatch { .. } => Severity::Error,
            Self::BytesPerSectorInvalid { .. } => Severity::Error,
            Self::TableChunkCountMismatch { .. } => Severity::Error,
            Self::TableEntryOutOfBounds { .. } => Severity::Error,
            Self::TableEntryOutsideSectorsRange { .. } => Severity::Error,
            Self::SectionGapZero { .. } => Severity::Info,
            Self::HashMismatch { .. } => Severity::Error,
            Self::HashSectionMissing => Severity::Warning,
            Self::SegmentOutOfOrder { .. } => Severity::Error,
            Self::DigestSha1Mismatch { .. } => Severity::Error,
            Self::ExternalMd5Mismatch { .. } => Severity::Critical,
            Self::ExternalSha1Mismatch { .. } => Severity::Critical,
            Self::Ewf2SectionDataHashMismatch { .. } => Severity::Error,
            Self::Ewf2EncryptedSection { .. } => Severity::Warning,
            Self::Ewf2HashSectionMissing => Severity::Warning,
            Self::Ewf2MediaInfoMissing => Severity::Warning,
            Self::Ewf2BytesPerSectorInvalid { .. } => Severity::Error,
            Self::Ewf2ChunkSizeInvalid { .. } => Severity::Error,
            Self::Ewf2SectorCountZero => Severity::Error,
        }
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

pub struct EwfIntegrity<'a> {
    segments: Vec<&'a [u8]>,
    expected_md5: Option<[u8; 16]>,
    expected_sha1: Option<[u8; 20]>,
}

impl<'a> EwfIntegrity<'a> {
    /// Analyse a single-segment E01 or Ex01 file.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            segments: vec![data],
            expected_md5: None,
            expected_sha1: None,
        }
    }

    /// Analyse a multi-segment image. Pass segments in order: E01, E02, E03 …
    pub fn from_segments(segs: &[&'a [u8]]) -> Self {
        Self {
            segments: segs.to_vec(),
            expected_md5: None,
            expected_sha1: None,
        }
    }

    /// Compare the computed MD5 against an externally-sourced reference
    /// (e.g., a chain-of-custody form). Mismatch → `ExternalMd5Mismatch` (Critical).
    pub fn with_expected_md5(mut self, hash: [u8; 16]) -> Self {
        self.expected_md5 = Some(hash);
        self
    }

    /// Compare the computed SHA-1 against an externally-sourced reference.
    /// Mismatch → `ExternalSha1Mismatch` (Critical).
    pub fn with_expected_sha1(mut self, hash: [u8; 20]) -> Self {
        self.expected_sha1 = Some(hash);
        self
    }

    pub fn analyse(&self) -> Vec<EwfIntegrityAnomaly> {
        let first = self.segments.first().copied().unwrap_or(&[]);
        if first.len() >= 8
            && (first[0..8] == EVF2_SIGNATURE || first[0..8] == LEF2_SIGNATURE)
        {
            return self.analyse_all_ewf2();
        }
        self.analyse_all_ewf1()
    }

    // ── EWF v1 ───────────────────────────────────────────────────────────────

    fn analyse_all_ewf1(&self) -> Vec<EwfIntegrityAnomaly> {
        let mut issues = Vec::new();
        let n = self.segments.len();
        let multi = n > 1;
        let mut geometry: Option<VolumeGeometry> = None;
        let mut all_sections: Vec<Vec<Section>> = Vec::with_capacity(n);

        for (idx, &data) in self.segments.iter().enumerate() {
            let expected_seg_num = (idx + 1) as u16;
            let is_last = idx == n - 1;
            let file_size = data.len() as u64;

            if data.len() < FILE_HEADER_SIZE {
                issues.push(EwfIntegrityAnomaly::SectionChainBroken {
                    at_offset: 0,
                    next_offset: 0,
                });
                all_sections.push(Vec::new());
                continue;
            }

            if data[0..8] != EVF_SIGNATURE {
                issues.push(EwfIntegrityAnomaly::InvalidSignature);
            }

            let seg_num = u16::from_le_bytes(data[9..11].try_into().unwrap());
            if seg_num == 0 {
                issues.push(EwfIntegrityAnomaly::SegmentNumberZero);
            } else if seg_num != expected_seg_num {
                issues.push(EwfIntegrityAnomaly::SegmentOutOfOrder {
                    segment_number: seg_num,
                    expected: expected_seg_num,
                });
            }

            let sections = walk_sections_v1(data, &mut issues);

            // Volume geometry — only from first segment
            if idx == 0 {
                match sections
                    .iter()
                    .find(|s| s.type_name == "volume" || s.type_name == "disk")
                {
                    None => issues.push(EwfIntegrityAnomaly::VolumeSectionMissing),
                    Some(v) => geometry = check_volume_v1(data, v.offset, &mut issues),
                }
            }

            // Table integrity — only check chunk count mismatch in single-segment mode
            let vol_count = if !multi && idx == 0 {
                geometry.as_ref().map(|g| g.chunk_count)
            } else {
                None
            };
            let sectors_range = sections
                .iter()
                .find(|s| s.type_name == "sectors")
                .map(|s| (s.offset + SECTION_DESCRIPTOR_SIZE as u64, s.offset + s.size));
            if let Some(table) = sections.iter().find(|s| s.type_name == "table") {
                check_table_v1(
                    data,
                    table.offset,
                    vol_count,
                    file_size,
                    sectors_range,
                    &mut issues,
                );
            }

            // Done section expected only in the last segment
            if is_last && !sections.iter().any(|s| s.type_name == "done") {
                issues.push(EwfIntegrityAnomaly::DoneSectionMissing);
            }

            all_sections.push(sections);
        }

        // Hash verification spans all segments
        if let Some(geom) = &geometry {
            check_hash_all_segments(
                &self.segments,
                &all_sections,
                geom,
                self.expected_md5,
                self.expected_sha1,
                &mut issues,
            );
        }

        issues
    }

    // ── EWF v2 ───────────────────────────────────────────────────────────────

    fn analyse_all_ewf2(&self) -> Vec<EwfIntegrityAnomaly> {
        let mut issues = Vec::new();
        let n = self.segments.len();

        for (idx, &data) in self.segments.iter().enumerate() {
            let expected_seg_num = (idx + 1) as u32;

            if data.len() < EVF2_FILE_HEADER_SIZE {
                issues.push(EwfIntegrityAnomaly::SectionChainBroken {
                    at_offset: 0,
                    next_offset: 0,
                });
                continue;
            }

            if data[0..8] != EVF2_SIGNATURE && data[0..8] != LEF2_SIGNATURE {
                issues.push(EwfIntegrityAnomaly::InvalidSignature);
            }

            let seg_num = u32::from_le_bytes(data[12..16].try_into().unwrap());
            if seg_num == 0 {
                issues.push(EwfIntegrityAnomaly::SegmentNumberZero);
            } else if seg_num != expected_seg_num {
                issues.push(EwfIntegrityAnomaly::SegmentOutOfOrder {
                    segment_number: seg_num as u16,
                    expected: expected_seg_num as u16,
                });
            }

            let mut pos = EVF2_FILE_HEADER_SIZE;
            let mut has_hash = false;
            let mut has_media_info = false;

            loop {
                if pos + EVF2_SECTION_DESCRIPTOR_SIZE > data.len() {
                    break;
                }
                let desc = &data[pos..pos + EVF2_SECTION_DESCRIPTOR_SIZE];
                let section_type = u32::from_le_bytes(desc[0..4].try_into().unwrap());
                let data_flags = u32::from_le_bytes(desc[4..8].try_into().unwrap());
                let data_size = u64::from_le_bytes(desc[16..24].try_into().unwrap()) as usize;
                let padding_size = u32::from_le_bytes(desc[28..32].try_into().unwrap()) as usize;
                let stored_hash: [u8; 16] = desc[32..48].try_into().unwrap();

                let body_start = pos + EVF2_SECTION_DESCRIPTOR_SIZE;
                let body_end = body_start.saturating_add(data_size);

                if data_flags & EVF2_DATA_FLAG_ENCRYPTED != 0 {
                    issues.push(EwfIntegrityAnomaly::Ewf2EncryptedSection {
                        offset: pos as u64,
                    });
                } else {
                    if stored_hash != [0u8; 16] {
                        if let Some(body) = data.get(body_start..body_end) {
                            let computed: [u8; 16] = Md5::digest(body).into();
                            if computed != stored_hash {
                                issues.push(EwfIntegrityAnomaly::Ewf2SectionDataHashMismatch {
                                    offset: pos as u64,
                                    section_type_id: section_type,
                                    computed,
                                    stored: stored_hash,
                                });
                            }
                        }
                    }

                    if section_type == EVF2_TYPE_MEDIA_INFO {
                        has_media_info = true;
                        check_ewf2_media_info(data, body_start, body_end, &mut issues);
                    }
                }

                if section_type == EVF2_TYPE_MD5_HASH || section_type == EVF2_TYPE_SHA1_HASH {
                    has_hash = true;
                }

                if section_type == EVF2_TYPE_DONE || section_type == EVF2_TYPE_NEXT {
                    break;
                }

                let next_pos = body_end.saturating_add(padding_size);
                if next_pos <= pos {
                    issues.push(EwfIntegrityAnomaly::SectionChainBroken {
                        at_offset: pos as u64,
                        next_offset: next_pos as u64,
                    });
                    break;
                }
                pos = next_pos;
            }

            if idx == n - 1 && !has_hash {
                issues.push(EwfIntegrityAnomaly::Ewf2HashSectionMissing);
            }
            if idx == 0 && !has_media_info {
                issues.push(EwfIntegrityAnomaly::Ewf2MediaInfoMissing);
            }
        }

        issues
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Parse and validate the EWF v2 media information section body.
/// Body layout (20 bytes):
///   [0..4]   bytes_per_sector (u32 LE)
///   [4..8]   sectors_per_chunk (u32 LE)
///   [8..16]  sector_count (u64 LE)
///   [16..20] reserved
fn check_ewf2_media_info(
    data: &[u8],
    body_start: usize,
    body_end: usize,
    issues: &mut Vec<EwfIntegrityAnomaly>,
) {
    let body = match data.get(body_start..body_end) {
        Some(b) if b.len() >= 16 => b,
        _ => return,
    };
    let bps = u32::from_le_bytes(body[0..4].try_into().unwrap());
    let spc = u32::from_le_bytes(body[4..8].try_into().unwrap());
    let sector_count = u64::from_le_bytes(body[8..16].try_into().unwrap());

    if bps != 512 && bps != 4096 {
        issues.push(EwfIntegrityAnomaly::Ewf2BytesPerSectorInvalid { bytes_per_sector: bps });
    }
    if spc == 0 || spc & (spc - 1) != 0 {
        issues.push(EwfIntegrityAnomaly::Ewf2ChunkSizeInvalid { sectors_per_chunk: spc });
    }
    if sector_count == 0 {
        issues.push(EwfIntegrityAnomaly::Ewf2SectorCountZero);
    }
}

struct Section {
    type_name: String,
    offset: u64,
    size: u64,
}

struct VolumeGeometry {
    chunk_count: u32,
    sectors_per_chunk: u32,
    bytes_per_sector: u32,
    sector_count: u64,
}

fn walk_sections_v1(data: &[u8], issues: &mut Vec<EwfIntegrityAnomaly>) -> Vec<Section> {
    let file_size = data.len() as u64;
    let mut sections = Vec::new();
    let mut pos = FILE_HEADER_SIZE as u64;

    loop {
        let off = pos as usize;
        if off + SECTION_DESCRIPTOR_SIZE > data.len() {
            break;
        }
        let desc = &data[off..off + SECTION_DESCRIPTOR_SIZE];

        let type_end = desc[..16].iter().position(|&b| b == 0).unwrap_or(16);
        let type_name = String::from_utf8_lossy(&desc[..type_end]).into_owned();

        let stored_crc = u32::from_le_bytes(desc[72..76].try_into().unwrap());
        let computed_crc = adler32(&desc[..72]);
        if computed_crc != stored_crc {
            issues.push(EwfIntegrityAnomaly::SectionDescriptorCrcMismatch {
                offset: pos,
                section_type: type_name.clone(),
                computed: computed_crc,
                stored: stored_crc,
            });
        }

        if !KNOWN_TYPES.contains(&type_name.as_str()) {
            issues.push(EwfIntegrityAnomaly::UnknownSectionType {
                offset: pos,
                type_name: type_name.clone(),
            });
        }

        let next = u64::from_le_bytes(desc[16..24].try_into().unwrap());
        let section_size = u64::from_le_bytes(desc[24..32].try_into().unwrap());
        let section_end = pos.saturating_add(section_size);

        sections.push(Section {
            type_name: type_name.clone(),
            offset: pos,
            size: section_size,
        });

        // "done" and "next" both terminate a segment's chain
        if type_name == "done" || type_name == "next" {
            break;
        }

        if next == 0 || next > file_size || next <= pos {
            issues.push(EwfIntegrityAnomaly::SectionChainBroken {
                at_offset: pos,
                next_offset: next,
            });
            break;
        }

        if next > section_end {
            let gap_offset = section_end;
            let gap_size = next - section_end;
            let non_zero = data
                .get(section_end as usize..next as usize)
                .map(|s| s.iter().any(|&b| b != 0))
                .unwrap_or(false);
            if non_zero {
                issues.push(EwfIntegrityAnomaly::SectionGapNonZero { gap_offset, gap_size });
            } else {
                issues.push(EwfIntegrityAnomaly::SectionGapZero { gap_offset, gap_size });
            }
        }

        pos = next;
    }

    sections
}

fn check_volume_v1(
    data: &[u8],
    desc_offset: u64,
    issues: &mut Vec<EwfIntegrityAnomaly>,
) -> Option<VolumeGeometry> {
    let data_start = (desc_offset as usize) + SECTION_DESCRIPTOR_SIZE;
    if data.len() < data_start + VOLUME_DATA_MIN {
        return None;
    }
    let vol = &data[data_start..];

    let chunk_count = u32::from_le_bytes(vol[4..8].try_into().unwrap());
    let sectors_per_chunk = u32::from_le_bytes(vol[8..12].try_into().unwrap());
    let bytes_per_sector = u32::from_le_bytes(vol[12..16].try_into().unwrap());
    let sector_count = u64::from_le_bytes(vol[16..24].try_into().unwrap());

    if bytes_per_sector != 512 && bytes_per_sector != 4096 {
        issues.push(EwfIntegrityAnomaly::BytesPerSectorInvalid { bytes_per_sector });
    }
    if sectors_per_chunk == 0 || !sectors_per_chunk.is_power_of_two() {
        issues.push(EwfIntegrityAnomaly::ChunkSizeInvalid {
            sectors_per_chunk,
            bytes_per_sector,
        });
    }

    let max_sectors = u64::from(chunk_count) * u64::from(sectors_per_chunk);
    let min_sectors = max_sectors.saturating_sub(u64::from(sectors_per_chunk));
    if sectors_per_chunk.is_power_of_two() {
        let out_of_range =
            sector_count > max_sectors || (chunk_count > 0 && sector_count <= min_sectors);
        if out_of_range {
            issues.push(EwfIntegrityAnomaly::SectorCountMismatch {
                declared: sector_count,
                expected: max_sectors,
            });
        }
    }

    Some(VolumeGeometry {
        chunk_count,
        sectors_per_chunk,
        bytes_per_sector,
        sector_count,
    })
}

fn check_table_v1(
    data: &[u8],
    desc_offset: u64,
    volume_chunk_count: Option<u32>,
    file_size: u64,
    sectors_range: Option<(u64, u64)>,
    issues: &mut Vec<EwfIntegrityAnomaly>,
) {
    let data_start = (desc_offset as usize) + SECTION_DESCRIPTOR_SIZE;
    if data.len() < data_start + 24 {
        return;
    }
    let tbl = &data[data_start..];
    let entry_count = u32::from_le_bytes(tbl[0..4].try_into().unwrap());
    let base_offset = u64::from_le_bytes(tbl[8..16].try_into().unwrap());

    if let Some(vol_count) = volume_chunk_count {
        if entry_count != vol_count {
            issues.push(EwfIntegrityAnomaly::TableChunkCountMismatch {
                in_volume: vol_count,
                in_table: entry_count,
            });
        }
    }

    let entries_start = data_start + 24;
    for i in 0..entry_count {
        let entry_off = entries_start + (i as usize) * 4;
        if entry_off + 4 > data.len() {
            break;
        }
        let raw = u32::from_le_bytes(data[entry_off..entry_off + 4].try_into().unwrap());
        let chunk_rel = u64::from(raw & 0x7FFF_FFFF);
        let absolute = base_offset.saturating_add(chunk_rel);
        if absolute >= file_size {
            issues.push(EwfIntegrityAnomaly::TableEntryOutOfBounds {
                chunk_index: i,
                entry_offset: absolute,
                file_size,
            });
        } else if let Some((sec_start, sec_end)) = sectors_range {
            if absolute < sec_start || absolute >= sec_end {
                issues.push(EwfIntegrityAnomaly::TableEntryOutsideSectorsRange {
                    chunk_index: i,
                    entry_offset: absolute,
                    sectors_start: sec_start,
                    sectors_end: sec_end,
                });
            }
        }
    }
}

/// Extract `(chunk_start, chunk_end, compressed)` for every chunk in one segment's table.
fn iter_segment_chunks(data: &[u8], sections: &[Section]) -> Vec<(usize, usize, bool)> {
    let table = match sections.iter().find(|s| s.type_name == "table") {
        Some(s) => s,
        None => return Vec::new(),
    };
    let sectors = match sections.iter().find(|s| s.type_name == "sectors") {
        Some(s) => s,
        None => return Vec::new(),
    };

    let tbl_data_start = (table.offset as usize) + SECTION_DESCRIPTOR_SIZE;
    if data.len() < tbl_data_start + 24 {
        return Vec::new();
    }
    let tbl = &data[tbl_data_start..];
    let entry_count = u32::from_le_bytes(tbl[0..4].try_into().unwrap()) as usize;
    let base_offset = u64::from_le_bytes(tbl[8..16].try_into().unwrap()) as usize;
    let entries_start = tbl_data_start + 24;
    let sectors_body_end = (sectors.offset + sectors.size) as usize;

    let mut chunks = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let entry_off = entries_start + i * 4;
        if entry_off + 4 > data.len() {
            break;
        }
        let raw = u32::from_le_bytes(data[entry_off..entry_off + 4].try_into().unwrap());
        let compressed = raw & 0x8000_0000 != 0;
        let rel = (raw & 0x7FFF_FFFF) as usize;
        let start = base_offset + rel;

        let end = if i + 1 < entry_count {
            let next_off = entries_start + (i + 1) * 4;
            if next_off + 4 > data.len() {
                break;
            }
            let next_raw = u32::from_le_bytes(data[next_off..next_off + 4].try_into().unwrap());
            let next_rel = (next_raw & 0x7FFF_FFFF) as usize;
            base_offset + next_rel
        } else {
            sectors_body_end.min(data.len())
        };

        if start >= end || end > data.len() {
            break;
        }
        chunks.push((start, end, compressed));
    }
    chunks
}

/// Hash all chunk data across all segments, verify against stored and external hashes.
fn check_hash_all_segments(
    segments: &[&[u8]],
    all_sections: &[Vec<Section>],
    geom: &VolumeGeometry,
    expected_md5: Option<[u8; 16]>,
    expected_sha1: Option<[u8; 20]>,
    issues: &mut Vec<EwfIntegrityAnomaly>,
) {
    let chunk_size = u64::from(geom.sectors_per_chunk) * u64::from(geom.bytes_per_sector);
    let total_bytes = geom.sector_count * u64::from(geom.bytes_per_sector);
    let mut bytes_remaining = total_bytes;

    let mut md5_h = Md5::new();
    let mut sha1_h = Sha1::new();

    'outer: for (&seg_data, sections) in segments.iter().zip(all_sections.iter()) {
        for (start, end, compressed) in iter_segment_chunks(seg_data, sections) {
            if bytes_remaining == 0 {
                break 'outer;
            }
            let to_hash = bytes_remaining.min(chunk_size) as usize;
            let raw = &seg_data[start..end];

            if compressed {
                let limit = (to_hash as u64).saturating_add(1);
                let mut decompressed = Vec::with_capacity(to_hash);
                if ZlibDecoder::new(raw)
                    .take(limit)
                    .read_to_end(&mut decompressed)
                    .is_err()
                {
                    bytes_remaining = bytes_remaining.saturating_sub(to_hash as u64);
                    continue;
                }
                let slice = &decompressed[..decompressed.len().min(to_hash)];
                md5_h.update(slice);
                sha1_h.update(slice);
            } else {
                let slice = &raw[..raw.len().min(to_hash)];
                md5_h.update(slice);
                sha1_h.update(slice);
            }
            bytes_remaining = bytes_remaining.saturating_sub(to_hash as u64);
        }
    }

    let computed_md5: [u8; 16] = md5_h.finalize().into();
    let computed_sha1: [u8; 20] = sha1_h.finalize().into();

    let last_sections = match all_sections.last() {
        Some(s) => s,
        None => return,
    };
    let last_data = match segments.last() {
        Some(d) => d,
        None => return,
    };

    // Stored MD5 from the EWF hash section
    match last_sections.iter().find(|s| s.type_name == "hash") {
        Some(hash_sec) => {
            let body_start = (hash_sec.offset as usize) + SECTION_DESCRIPTOR_SIZE;
            if let Some(stored_slice) = last_data.get(body_start..body_start + 16) {
                let stored: [u8; 16] = stored_slice.try_into().unwrap();
                if computed_md5 != stored {
                    issues.push(EwfIntegrityAnomaly::HashMismatch {
                        computed: computed_md5,
                        stored,
                    });
                }
            }
        }
        None => issues.push(EwfIntegrityAnomaly::HashSectionMissing),
    }

    // Stored SHA-1 from the EWF digest section (layout: 16-byte MD5, then 20-byte SHA-1)
    if let Some(digest_sec) = last_sections.iter().find(|s| s.type_name == "digest") {
        let body_start = (digest_sec.offset as usize) + SECTION_DESCRIPTOR_SIZE;
        if let Some(sha1_slice) = last_data.get(body_start + 16..body_start + 36) {
            let stored: [u8; 20] = sha1_slice.try_into().unwrap();
            // All-zero stored SHA-1 means "not set" — skip comparison
            if stored != [0u8; 20] && computed_sha1 != stored {
                issues.push(EwfIntegrityAnomaly::DigestSha1Mismatch {
                    computed: computed_sha1,
                    stored,
                });
            }
        }
    }

    // External reference hashes (supplied by caller, e.g. from chain of custody)
    if let Some(expected) = expected_md5 {
        if computed_md5 != expected {
            issues.push(EwfIntegrityAnomaly::ExternalMd5Mismatch {
                computed: computed_md5,
                expected,
            });
        }
    }
    if let Some(expected) = expected_sha1 {
        if computed_sha1 != expected {
            issues.push(EwfIntegrityAnomaly::ExternalSha1Mismatch {
                computed: computed_sha1,
                expected,
            });
        }
    }
}

pub(crate) fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut s1: u32 = 1;
    let mut s2: u32 = 0;
    for &b in data {
        s1 = (s1 + u32::from(b)) % MOD;
        s2 = (s2 + s1) % MOD;
    }
    (s2 << 16) | s1
}

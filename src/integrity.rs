use flate2::read::ZlibDecoder;
use md5::{Digest as _, Md5};
use std::io::Read as _;

const EVF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
const FILE_HEADER_SIZE: usize = 13;
pub(crate) const SECTION_DESCRIPTOR_SIZE: usize = 76;
const VOLUME_DATA_MIN: usize = 24;

/// Known EWF v1 section type strings.
const KNOWN_TYPES: &[&str] = &[
    "header",
    "header2",
    "volume",
    "disk",
    "table",
    "table2",
    "sectors",
    "hash",
    "digest",
    "error2",
    "session",
    "done",
    "next",
    "data",
    "ltree",
    "ltreedata",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone)]
pub enum EwfIntegrityAnomaly {
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
        }
    }
}

pub struct EwfIntegrity<'a> {
    data: &'a [u8],
}

impl<'a> EwfIntegrity<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn analyse(&self) -> Vec<EwfIntegrityAnomaly> {
        let mut issues = Vec::new();
        let data = self.data;
        let file_size = data.len() as u64;

        // ── Layer 1: File Header ──────────────────────────────────────────────
        if data.len() < FILE_HEADER_SIZE {
            issues.push(EwfIntegrityAnomaly::SectionChainBroken {
                at_offset: 0,
                next_offset: 0,
            });
            return issues;
        }
        if data[0..8] != EVF_SIGNATURE {
            issues.push(EwfIntegrityAnomaly::InvalidSignature);
        }
        let segment_number = u16::from_le_bytes(data[9..11].try_into().unwrap());
        if segment_number == 0 {
            issues.push(EwfIntegrityAnomaly::SegmentNumberZero);
        }

        // ── Layer 2 & 3: Walk section chain ──────────────────────────────────
        let sections = self.walk_sections(&mut issues);

        // ── Layer 4: Volume geometry ──────────────────────────────────────────
        let volume = sections
            .iter()
            .find(|s| s.type_name == "volume" || s.type_name == "disk");
        let geometry: Option<VolumeGeometry> = match volume {
            None => {
                issues.push(EwfIntegrityAnomaly::VolumeSectionMissing);
                None
            }
            Some(vol) => self.check_volume(vol.offset, &mut issues),
        };

        // ── Layer 5: Table integrity ──────────────────────────────────────────
        let sectors_range = sections.iter().find(|s| s.type_name == "sectors").map(|s| {
            let data_start = s.offset + SECTION_DESCRIPTOR_SIZE as u64;
            let data_end = s.offset + s.size;
            (data_start, data_end)
        });
        if let Some(table) = sections.iter().find(|s| s.type_name == "table") {
            self.check_table(
                table.offset,
                geometry.as_ref().map(|g| g.chunk_count),
                file_size,
                sectors_range,
                &mut issues,
            );
        }

        // ── Layer 6: Done section present ────────────────────────────────────
        if !sections.iter().any(|s| s.type_name == "done") {
            issues.push(EwfIntegrityAnomaly::DoneSectionMissing);
        }

        // ── Layer 7: Hash verification ────────────────────────────────────────
        self.check_hash(&sections, geometry.as_ref(), &mut issues);

        issues
    }

    fn check_hash(
        &self,
        sections: &[Section],
        geometry: Option<&VolumeGeometry>,
        issues: &mut Vec<EwfIntegrityAnomaly>,
    ) {
        let data = self.data;

        let hash_sec = match sections.iter().find(|s| s.type_name == "hash") {
            Some(s) => s,
            None => {
                issues.push(EwfIntegrityAnomaly::HashSectionMissing);
                return;
            }
        };

        let sectors_sec = match sections.iter().find(|s| s.type_name == "sectors") {
            Some(s) => s,
            None => return,
        };

        let table_sec = match sections.iter().find(|s| s.type_name == "table") {
            Some(s) => s,
            None => return,
        };

        let geom = match geometry {
            Some(g) if g.sectors_per_chunk > 0 && g.bytes_per_sector > 0 => g,
            _ => return,
        };

        // Parse table header for entry_count and base_offset.
        let tbl_data_start = (table_sec.offset as usize) + SECTION_DESCRIPTOR_SIZE;
        if data.len() < tbl_data_start + 24 {
            return;
        }
        let tbl = &data[tbl_data_start..];
        let entry_count = u32::from_le_bytes(tbl[0..4].try_into().unwrap());
        let base_offset = u64::from_le_bytes(tbl[8..16].try_into().unwrap());
        let entries_start = tbl_data_start + 24;

        // Sectors body end boundary used for the last chunk's compressed data.
        let sectors_body_end = (sectors_sec.offset + sectors_sec.size) as usize;

        let chunk_size = u64::from(geom.sectors_per_chunk) * u64::from(geom.bytes_per_sector);
        let total_media_bytes = geom.sector_count * u64::from(geom.bytes_per_sector);
        let mut bytes_remaining = total_media_bytes;

        let mut hasher = Md5::new();

        for i in 0..entry_count {
            if bytes_remaining == 0 {
                break;
            }

            let entry_off = entries_start + (i as usize) * 4;
            if entry_off + 4 > data.len() {
                return;
            }
            let raw = u32::from_le_bytes(data[entry_off..entry_off + 4].try_into().unwrap());
            let is_compressed = raw & 0x8000_0000 != 0;
            let chunk_rel = u64::from(raw & 0x7FFF_FFFF);
            let chunk_abs_start = match base_offset.checked_add(chunk_rel) {
                Some(abs) if (abs as usize) <= data.len() => abs as usize,
                _ => return,
            };

            // End of this chunk's on-disk data = start of next chunk (or sectors body end).
            let chunk_abs_end = if i + 1 < entry_count {
                let next_off = entries_start + (i as usize + 1) * 4;
                if next_off + 4 > data.len() {
                    return;
                }
                let next_raw =
                    u32::from_le_bytes(data[next_off..next_off + 4].try_into().unwrap());
                let next_rel = u64::from(next_raw & 0x7FFF_FFFF);
                match base_offset.checked_add(next_rel) {
                    Some(abs) if (abs as usize) <= data.len() => abs as usize,
                    _ => return,
                }
            } else {
                sectors_body_end.min(data.len())
            };

            if chunk_abs_start >= chunk_abs_end {
                return;
            }

            let chunk_data = &data[chunk_abs_start..chunk_abs_end];
            // Bytes to feed to the hasher from this chunk (last chunk may be partial).
            let to_hash = bytes_remaining.min(chunk_size) as usize;

            if is_compressed {
                // Deflate bomb guard: never decompress more than to_hash + 1 bytes.
                let limit = (to_hash as u64).saturating_add(1);
                let mut decompressed = Vec::with_capacity(to_hash);
                if ZlibDecoder::new(chunk_data)
                    .take(limit)
                    .read_to_end(&mut decompressed)
                    .is_err()
                {
                    return;
                }
                hasher.update(&decompressed[..decompressed.len().min(to_hash)]);
            } else {
                hasher.update(&chunk_data[..chunk_data.len().min(to_hash)]);
            }

            bytes_remaining = bytes_remaining.saturating_sub(to_hash as u64);
        }

        let computed: [u8; 16] = hasher.finalize().into();

        let hash_body_start = (hash_sec.offset as usize) + SECTION_DESCRIPTOR_SIZE;
        let stored_slice = match data.get(hash_body_start..hash_body_start + 16) {
            Some(s) => s,
            None => return,
        };
        let stored: [u8; 16] = stored_slice.try_into().unwrap();

        if computed != stored {
            issues.push(EwfIntegrityAnomaly::HashMismatch { computed, stored });
        }
    }

    fn walk_sections(&self, issues: &mut Vec<EwfIntegrityAnomaly>) -> Vec<Section> {
        let data = self.data;
        let file_size = data.len() as u64;
        let mut sections: Vec<Section> = Vec::new();
        let mut pos = FILE_HEADER_SIZE as u64;

        loop {
            let off = pos as usize;
            if off + SECTION_DESCRIPTOR_SIZE > data.len() {
                break;
            }

            let desc = &data[off..off + SECTION_DESCRIPTOR_SIZE];

            // Section type: NUL-terminated ASCII in first 16 bytes.
            let type_end = desc[..16].iter().position(|&b| b == 0).unwrap_or(16);
            let type_name = String::from_utf8_lossy(&desc[..type_end]).into_owned();

            // Validate Adler-32 CRC over bytes [0..72].
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

            // Validate unknown section type.
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

            // "done" terminates the chain (next == self).
            if type_name == "done" {
                break;
            }

            // Validate next pointer — must advance forward (no cycles or zero).
            if next == 0 || next > file_size || next <= pos {
                issues.push(EwfIntegrityAnomaly::SectionChainBroken {
                    at_offset: pos,
                    next_offset: next,
                });
                break;
            }

            // Gap between end of this section and start of next.
            if next > section_end {
                let gap_offset = section_end;
                let gap_size = next - section_end;
                // Only flag if gap bytes are non-zero.
                let gap_start = gap_offset as usize;
                let gap_end = next as usize;
                let non_zero = data
                    .get(gap_start..gap_end)
                    .map(|s| s.iter().any(|&b| b != 0))
                    .unwrap_or(false);
                if non_zero {
                    issues.push(EwfIntegrityAnomaly::SectionGapNonZero {
                        gap_offset,
                        gap_size,
                    });
                } else {
                    issues.push(EwfIntegrityAnomaly::SectionGapZero {
                        gap_offset,
                        gap_size,
                    });
                }
            }

            pos = next;
        }

        sections
    }

    fn check_volume(
        &self,
        desc_offset: u64,
        issues: &mut Vec<EwfIntegrityAnomaly>,
    ) -> Option<VolumeGeometry> {
        let data_start = (desc_offset as usize) + SECTION_DESCRIPTOR_SIZE;
        let data = self.data;
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

        // Valid range: last chunk may be partially filled.
        // sector_count must satisfy: (chunk_count-1)*spc < sector_count <= chunk_count*spc.
        // Only flag the impossible cases: too many sectors, or so few that a whole chunk
        // is entirely unused (which would imply chunk_count was inflated).
        let max_sectors = u64::from(chunk_count) * u64::from(sectors_per_chunk);
        let min_sectors = max_sectors.saturating_sub(u64::from(sectors_per_chunk));
        let out_of_range =
            sector_count > max_sectors || (chunk_count > 0 && sector_count <= min_sectors);
        if out_of_range && sectors_per_chunk.is_power_of_two() {
            issues.push(EwfIntegrityAnomaly::SectorCountMismatch {
                declared: sector_count,
                expected: max_sectors,
            });
        }

        Some(VolumeGeometry {
            chunk_count,
            sectors_per_chunk,
            bytes_per_sector,
            sector_count,
        })
    }

    fn check_table(
        &self,
        desc_offset: u64,
        volume_chunk_count: Option<u32>,
        file_size: u64,
        sectors_range: Option<(u64, u64)>,
        issues: &mut Vec<EwfIntegrityAnomaly>,
    ) {
        let data_start = (desc_offset as usize) + SECTION_DESCRIPTOR_SIZE;
        let data = self.data;
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

        // Check each entry offset.
        let entries_start = data_start + 24;
        for i in 0..entry_count {
            let entry_off = entries_start + (i as usize) * 4;
            if entry_off + 4 > data.len() {
                break;
            }
            let raw = u32::from_le_bytes(data[entry_off..entry_off + 4].try_into().unwrap());
            let chunk_rel_offset = u64::from(raw & 0x7FFF_FFFF);
            let absolute_offset = base_offset.saturating_add(chunk_rel_offset);
            if absolute_offset >= file_size {
                issues.push(EwfIntegrityAnomaly::TableEntryOutOfBounds {
                    chunk_index: i,
                    entry_offset: absolute_offset,
                    file_size,
                });
            } else if let Some((sec_start, sec_end)) = sectors_range {
                if absolute_offset < sec_start || absolute_offset >= sec_end {
                    issues.push(EwfIntegrityAnomaly::TableEntryOutsideSectorsRange {
                        chunk_index: i,
                        entry_offset: absolute_offset,
                        sectors_start: sec_start,
                        sectors_end: sec_end,
                    });
                }
            }
        }
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

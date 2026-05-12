use md5::{Digest as _, Md5};

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
        let chunk_count_from_volume: Option<u32> = match volume {
            None => {
                issues.push(EwfIntegrityAnomaly::VolumeSectionMissing);
                None
            }
            Some(vol) => self.check_volume(vol.offset, &mut issues),
        };

        // ── Layer 5: Table integrity ──────────────────────────────────────────
        if let Some(table) = sections.iter().find(|s| s.type_name == "table") {
            self.check_table(
                table.offset,
                chunk_count_from_volume,
                file_size,
                &mut issues,
            );
        }

        // ── Layer 6: Done section present ────────────────────────────────────
        if !sections.iter().any(|s| s.type_name == "done") {
            issues.push(EwfIntegrityAnomaly::DoneSectionMissing);
        }

        // ── Layer 7: Hash verification ────────────────────────────────────────
        self.check_hash(&sections, &mut issues);

        issues
    }

    fn check_hash(&self, sections: &[Section], issues: &mut Vec<EwfIntegrityAnomaly>) {
        let data = self.data;

        let hash_sec = sections.iter().find(|s| s.type_name == "hash");
        if hash_sec.is_none() {
            issues.push(EwfIntegrityAnomaly::HashSectionMissing);
            return;
        }
        let hash_sec = hash_sec.unwrap();

        // The sectors section body is everything between the sectors descriptor and
        // the next section.  Use size field: body = size - SECTION_DESCRIPTOR_SIZE.
        let sectors_sec = match sections.iter().find(|s| s.type_name == "sectors") {
            Some(s) => s,
            None => return,
        };
        let body_start = (sectors_sec.offset as usize) + SECTION_DESCRIPTOR_SIZE;
        let body_len = (sectors_sec.size as usize).saturating_sub(SECTION_DESCRIPTOR_SIZE);
        let sectors_body = match data.get(body_start..body_start + body_len) {
            Some(b) => b,
            None => return,
        };

        let computed: [u8; 16] = Md5::digest(sectors_body).into();

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
                }
            }

            pos = next;
        }

        sections
    }

    fn check_volume(&self, desc_offset: u64, issues: &mut Vec<EwfIntegrityAnomaly>) -> Option<u32> {
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

        let expected_sectors = u64::from(chunk_count) * u64::from(sectors_per_chunk);
        if sector_count != expected_sectors && sectors_per_chunk.is_power_of_two() {
            issues.push(EwfIntegrityAnomaly::SectorCountMismatch {
                declared: sector_count,
                expected: expected_sectors,
            });
        }

        Some(chunk_count)
    }

    fn check_table(
        &self,
        desc_offset: u64,
        volume_chunk_count: Option<u32>,
        file_size: u64,
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
            }
        }
    }
}

struct Section {
    type_name: String,
    offset: u64,
    size: u64,
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

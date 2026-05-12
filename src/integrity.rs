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
        todo!("implement analysis")
    }
}

use flate2::read::ZlibDecoder;
use md5::{Digest as _, Md5};
use sha1::Sha1;
use sha2::Sha256;
use std::fmt;
use std::io::Read as _;

// ── EWF v1 constants ─────────────────────────────────────────────────────────

const EVF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
/// DiskSig/Tableau "dvf" signature — a valid EWF v1 variant.
const DVF_SIGNATURE: [u8; 8] = [0x64, 0x76, 0x66, 0x09, 0x0d, 0x0a, 0xff, 0x00];
/// Logical Volume Format "LVF" signature — logical evidence images.
const LVF_SIGNATURE: [u8; 8] = [0x4c, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];

const FILE_HEADER_SIZE: usize = 13;
pub(crate) const SECTION_DESCRIPTOR_SIZE: usize = 76;
const VOLUME_DATA_MIN: usize = 24;
/// The standard `ewf_data_t` body size (per libewf). Adler-32 at byte 1048.
const VOLUME_DATA_FULL: usize = 1052;
/// Valid `media_type` values from the `ewf_data_t` struct.
const VALID_MEDIA_TYPES: &[u8] = &[0x00, 0x01, 0x03, 0x0e, 0x10];

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

// ── EWF v2 constants ─────────────────────────────────────────────────────────

const EVF2_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];
const LEF2_SIGNATURE: [u8; 8] = [0x4c, 0x45, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];
const EVF2_FILE_HEADER_SIZE: usize = 32;
const EVF2_SECTION_DESCRIPTOR_SIZE: usize = 64;
const EVF2_DATA_FLAG_ENCRYPTED: u32 = 0x0000_0002;
const EVF2_CHUNK_FLAG_COMPRESSED: u32 = 0x0000_0001;
const EVF2_TYPE_MEDIA_INFO: u32 = 0x02;
const EVF2_TYPE_CHUNK_TABLE: u32 = 0x04;
const EVF2_TYPE_MD5_HASH: u32 = 0x08;
const EVF2_TYPE_SHA1_HASH: u32 = 0x09;
const EVF2_TYPE_SHA256_HASH: u32 = 0x0A;
const EVF2_CHUNK_TABLE_HEADER_SIZE: usize = 32;
const EVF2_CHUNK_TABLE_ENTRY_SIZE: usize = 16;

// ── Public types ──────────────────────────────────────────────────────────────

/// The canonical 5-level severity scale, shared across every `SecurityRonin`
/// analyzer via [`forensicnomicon::report`].
pub use forensicnomicon::report::Severity;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    /// No `sectors` section was found in this EWF v1 segment.
    SectorsSectionMissing,
    /// No `table` section was found in this EWF v1 segment.
    TableSectionMissing,
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
    TableHeaderAdler32Mismatch {
        computed: u32,
        stored: u32,
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
    /// `table2` body differs from `table` body — one of the redundant copies is corrupt.
    Table2Mismatch {
        /// Byte offset into the table body where the first difference was found.
        offset: usize,
    },
    /// The `error2` section records acquisition errors (unreadable sectors).
    BadSectorsPresent {
        /// Number of error entries in the `error2` section.
        count: u32,
    },
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
    /// Computed SHA-256 of all sector data does not match the stored SHA-256 in the hash section.
    DigestSha256Mismatch {
        computed: [u8; 32],
        stored: [u8; 32],
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
    /// A section's stored `data_integrity_hash` does not match MD5 of the section body.
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
    /// Adler-32 of the 1052-byte `ewf_data_t` body is wrong.
    /// Only checked when the volume body is ≥ 1052 bytes (as in real acquisitions).
    VolumeBodyCrcMismatch {
        computed: u32,
        stored: u32,
    },
    /// `media_type` byte (offset 0 of `ewf_data_t`) is not a known valid value.
    /// Valid: 0x00=removable, 0x01=fixed, 0x03=optical, 0x0e=LVF, 0x10=memory.
    MediaTypeUnknown {
        media_type: u8,
    },
    /// The `set_identifier` GUID (bytes 64-79 of `ewf_data_t`) differs between segments
    /// of the same acquisition — indicates segments from different acquisitions were mixed.
    SetIdentifierMismatch {
        segment: usize,
    },
    /// No media information (device information) section found in the EWF v2 image.
    Ewf2MediaInfoMissing,
    /// The Adler-32 checksum stored at the end of the EWF v2 chunk table body does not
    /// match the Adler-32 computed over the chunk table entries.
    Ewf2ChunkTableChecksumMismatch {
        computed: u32,
        stored: u32,
    },
    /// The Adler-32 stored at the end of a chunk's byte range does not match
    /// the Adler-32 computed over the chunk's raw (possibly compressed) bytes.
    ChunkChecksumMismatch {
        chunk_index: usize,
        computed: u32,
        stored: u32,
    },
    /// A compressed chunk's zlib stream could not be decompressed.
    /// The chunk index identifies exactly which chunk is corrupt.
    ChunkDecompressionError {
        chunk_index: usize,
    },
    /// EWF v2 file header specifies a compression algorithm not supported by this tool.
    UnsupportedCompressionAlgorithm {
        /// Value from file header bytes [10..12].
        method_id: u16,
    },
    /// Computed SHA-256 does not match an externally supplied reference.
    ExternalSha256Mismatch {
        computed: [u8; 32],
        expected: [u8; 32],
    },
    /// The EWF v2 media information section body could not be decompressed (zlib
    /// failure) or decoded as UTF-16LE.  The body is required to be a zlib-
    /// compressed, BOM-prefixed UTF-16LE key=value table.
    Ewf2MediaInfoParseFailed,
}

impl EwfIntegrityAnomaly {
    pub fn severity(&self) -> Severity {
        match self {
            Self::InvalidSignature => Severity::Critical,
            Self::SegmentNumberZero => Severity::High,
            Self::SectionDescriptorCrcMismatch { .. } => Severity::High,
            Self::SectionChainBroken { .. } => Severity::Critical,
            Self::SectionGapNonZero { .. } => Severity::Medium,
            Self::VolumeSectionMissing => Severity::Critical,
            Self::UnknownSectionType { .. } => Severity::Medium,
            Self::DoneSectionMissing => Severity::Medium,
            Self::SectorsSectionMissing => Severity::High,
            Self::TableSectionMissing => Severity::High,
            Self::ChunkSizeInvalid { .. } => Severity::High,
            Self::SectorCountMismatch { .. } => Severity::High,
            Self::BytesPerSectorInvalid { .. } => Severity::High,
            Self::TableChunkCountMismatch { .. } => Severity::High,
            Self::TableHeaderAdler32Mismatch { .. } => Severity::High,
            Self::TableEntryOutOfBounds { .. } => Severity::High,
            Self::TableEntryOutsideSectorsRange { .. } => Severity::High,
            Self::SectionGapZero { .. } => Severity::Info,
            Self::HashMismatch { .. } => Severity::High,
            Self::HashSectionMissing => Severity::Medium,
            Self::Table2Mismatch { .. } => Severity::High,
            Self::BadSectorsPresent { .. } => Severity::Medium,
            Self::SegmentOutOfOrder { .. } => Severity::High,
            Self::DigestSha1Mismatch { .. } => Severity::High,
            Self::DigestSha256Mismatch { .. } => Severity::High,
            Self::ExternalMd5Mismatch { .. } => Severity::Critical,
            Self::ExternalSha1Mismatch { .. } => Severity::Critical,
            Self::VolumeBodyCrcMismatch { .. } => Severity::High,
            Self::MediaTypeUnknown { .. } => Severity::Medium,
            Self::SetIdentifierMismatch { .. } => Severity::High,
            Self::Ewf2SectionDataHashMismatch { .. } => Severity::High,
            Self::Ewf2EncryptedSection { .. } => Severity::Medium,
            Self::Ewf2HashSectionMissing => Severity::Medium,
            Self::Ewf2MediaInfoMissing => Severity::Medium,
            Self::Ewf2ChunkTableChecksumMismatch { .. } => Severity::High,
            Self::ChunkChecksumMismatch { .. } => Severity::High,
            Self::ChunkDecompressionError { .. } => Severity::High,
            Self::UnsupportedCompressionAlgorithm { .. } => Severity::High,
            Self::ExternalSha256Mismatch { .. } => Severity::Critical,
            Self::Ewf2MediaInfoParseFailed => Severity::High,
        }
    }
}

impl fmt::Display for EwfIntegrityAnomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature =>
                write!(f, "invalid EWF signature — not a valid E01/Ex01 file"),
            Self::SegmentNumberZero =>
                write!(f, "segment number is zero (expected ≥ 1)"),
            Self::SectionDescriptorCrcMismatch { offset, section_type, computed, stored } =>
                write!(f, "section '{section_type}' at 0x{offset:x}: descriptor CRC mismatch (computed 0x{computed:08x}, stored 0x{stored:08x})"),
            Self::SectionChainBroken { at_offset, next_offset } =>
                write!(f, "section chain broken at 0x{at_offset:x}: next pointer 0x{next_offset:x} is invalid"),
            Self::SectionGapNonZero { gap_offset, gap_size } =>
                write!(f, "non-zero data in {gap_size}-byte gap at 0x{gap_offset:x} — possible hidden data"),
            Self::VolumeSectionMissing =>
                write!(f, "volume/disk section missing in segment 1"),
            Self::UnknownSectionType { offset, type_name } =>
                write!(f, "unknown section type '{type_name}' at 0x{offset:x}"),
            Self::DoneSectionMissing =>
                write!(f, "done section missing from final segment"),
            Self::SectorsSectionMissing =>
                write!(f, "sectors section missing — chunk data not found in segment"),
            Self::TableSectionMissing =>
                write!(f, "table section missing — chunk offset table not found in segment"),
            Self::ChunkSizeInvalid { sectors_per_chunk, bytes_per_sector } =>
                write!(f, "invalid chunk size: {sectors_per_chunk} sectors × {bytes_per_sector} bytes/sector"),
            Self::SectorCountMismatch { declared, expected } =>
                write!(f, "sector count mismatch: declared {declared}, expected {expected}"),
            Self::BytesPerSectorInvalid { bytes_per_sector } =>
                write!(f, "invalid bytes_per_sector: {bytes_per_sector} (expected 512 or 4096)"),
            Self::TableChunkCountMismatch { in_volume, in_table } =>
                write!(f, "chunk count mismatch: volume declares {in_volume}, table has {in_table}"),
            Self::TableHeaderAdler32Mismatch { computed, stored } =>
                write!(f, "table header Adler-32 mismatch: computed 0x{computed:08x}, stored 0x{stored:08x}"),
            Self::TableEntryOutOfBounds { chunk_index, entry_offset, file_size } =>
                write!(f, "table entry for chunk {chunk_index} points outside file: 0x{entry_offset:x} ≥ 0x{file_size:x}"),
            Self::TableEntryOutsideSectorsRange { chunk_index, entry_offset, sectors_start, sectors_end } =>
                write!(f, "table entry for chunk {chunk_index} at 0x{entry_offset:x} is outside sectors section [0x{sectors_start:x}..0x{sectors_end:x}]"),
            Self::SectionGapZero { gap_offset, gap_size } =>
                write!(f, "zero-padded {gap_size}-byte gap at 0x{gap_offset:x}"),
            Self::HashMismatch { computed, stored } =>
                write!(f, "MD5 mismatch: computed {}, stored {}", hex(computed), hex(stored)),
            Self::HashSectionMissing =>
                write!(f, "hash section missing — cannot verify MD5"),
            Self::Table2Mismatch { offset } =>
                write!(f, "table2 body differs from table at byte offset {offset} — one redundant copy is corrupt"),
            Self::BadSectorsPresent { count } =>
                write!(f, "error2 section reports {count} unreadable sector range(s) from acquisition"),
            Self::SegmentOutOfOrder { segment_number, expected } =>
                write!(f, "segment {segment_number} found where segment {expected} was expected"),
            Self::DigestSha1Mismatch { computed, stored } =>
                write!(f, "SHA-1 mismatch: computed {}, stored {}", hex(computed), hex(stored)),
            Self::DigestSha256Mismatch { computed, stored } =>
                write!(f, "SHA-256 mismatch: computed {}, stored {}", hex(computed), hex(stored)),
            Self::ExternalMd5Mismatch { computed, expected } =>
                write!(f, "MD5 does not match chain-of-custody reference: computed {}, expected {}", hex(computed), hex(expected)),
            Self::ExternalSha1Mismatch { computed, expected } =>
                write!(f, "SHA-1 does not match chain-of-custody reference: computed {}, expected {}", hex(computed), hex(expected)),
            Self::ExternalSha256Mismatch { computed, expected } =>
                write!(f, "SHA-256 does not match chain-of-custody reference: computed {}, expected {}", hex(computed), hex(expected)),
            Self::Ewf2SectionDataHashMismatch { offset, section_type_id, computed, stored } =>
                write!(f, "EWF v2 section (type 0x{section_type_id:02x}) at 0x{offset:x}: data integrity hash mismatch (computed {}, stored {})", hex(computed), hex(stored)),
            Self::Ewf2EncryptedSection { offset } =>
                write!(f, "EWF v2 encrypted section at 0x{offset:x} — content not verifiable"),
            Self::Ewf2HashSectionMissing =>
                write!(f, "EWF v2 hash section missing from final segment"),
            Self::VolumeBodyCrcMismatch { computed, stored } =>
                write!(f, "volume section body CRC mismatch (computed 0x{computed:08x}, stored 0x{stored:08x})"),
            Self::MediaTypeUnknown { media_type } =>
                write!(f, "unknown media_type 0x{media_type:02x}"),
            Self::SetIdentifierMismatch { segment } =>
                write!(f, "set_identifier GUID mismatch in segment {segment} — segments may be from different acquisitions"),
            Self::Ewf2MediaInfoMissing =>
                write!(f, "EWF v2 media information section missing"),
            Self::Ewf2ChunkTableChecksumMismatch { computed, stored } =>
                write!(f, "EWF v2 chunk table checksum mismatch (computed 0x{computed:08x}, stored 0x{stored:08x})"),
            Self::ChunkChecksumMismatch { chunk_index, computed, stored } =>
                write!(f, "chunk {chunk_index}: Adler-32 mismatch (computed 0x{computed:08x}, stored 0x{stored:08x})"),
            Self::ChunkDecompressionError { chunk_index } =>
                write!(f, "chunk {chunk_index}: zlib decompression failed — chunk data is corrupt"),
            Self::UnsupportedCompressionAlgorithm { method_id } =>
                write!(f, "EWF v2 file header specifies unsupported compression algorithm 0x{method_id:04x} — only deflate (0/1) is supported"),
            Self::Ewf2MediaInfoParseFailed =>
                write!(f, "EWF v2 media information section body could not be decompressed or decoded"),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Bounds-checked little-endian integer readers ─────────────────────────────
//
// These never panic on a short or attacker-truncated slice: an out-of-range
// offset yields 0 rather than an out-of-bounds index or `try_into` unwrap. Every
// length/offset/count field parsed from an untrusted EWF image flows through one
// of these.

fn le_u16(data: &[u8], off: usize) -> u16 {
    let mut b = [0u8; 2];
    if let Some(s) = data.get(off..off + 2) {
        b.copy_from_slice(s);
    }
    u16::from_le_bytes(b)
}

fn le_u32(data: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = data.get(off..off + 4) {
        b.copy_from_slice(s);
    }
    u32::from_le_bytes(b)
}

fn le_u64(data: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    if let Some(s) = data.get(off..off + 8) {
        b.copy_from_slice(s);
    }
    u64::from_le_bytes(b)
}

/// Read a fixed-size byte array from `data` at `off`; an out-of-range slice
/// yields all zeroes rather than panicking.
fn array_at<const N: usize>(data: &[u8], off: usize) -> [u8; N] {
    let mut b = [0u8; N];
    if let Some(s) = data.get(off..off + N) {
        b.copy_from_slice(s);
    }
    b
}

/// Snapshot of analysis progress, delivered to the callback passed to
/// [`EwfIntegrity::analyse_with_progress`] after each chunk is processed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AnalysisProgress {
    /// Number of chunks fully processed (hashed + Adler-32 verified) so far.
    pub chunks_done: usize,
    /// Total chunks in the current segment; `None` until the chunk table is parsed.
    pub chunks_total: Option<usize>,
    /// Total sector-data bytes processed so far.
    pub bytes_done: u64,
}

/// The three hashes computed over all sector data in an EWF image.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ComputedHashes {
    pub md5: [u8; 16],
    pub sha1: [u8; 20],
    pub sha256: [u8; 32],
}

/// Acquisition metadata parsed from the zlib-compressed `header` section of an EWF v1 image.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EwfHeaderMetadata {
    pub description: String,
    pub case_number: String,
    pub evidence_number: String,
    pub examiner_name: String,
    pub acquisition_date: String,
    pub system_date: String,
    pub password_hash: String,
    pub acquisition_software: String,
}

// ── Public entry point ────────────────────────────────────────────────────────

pub struct EwfIntegrity<'a> {
    segments: Vec<&'a [u8]>,
    expected_md5: Option<[u8; 16]>,
    expected_sha1: Option<[u8; 20]>,
    expected_sha256: Option<[u8; 32]>,
}

impl<'a> EwfIntegrity<'a> {
    /// Analyse a single-segment E01 or Ex01 file.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            segments: vec![data],
            expected_md5: None,
            expected_sha1: None,
            expected_sha256: None,
        }
    }

    /// Analyse a multi-segment image. Pass segments in order: E01, E02, E03 …
    pub fn from_segments(segs: &[&'a [u8]]) -> Self {
        Self {
            segments: segs.to_vec(),
            expected_md5: None,
            expected_sha1: None,
            expected_sha256: None,
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

    /// Compare the computed SHA-256 against an externally-sourced reference.
    /// Mismatch → `ExternalSha256Mismatch` (Critical).
    pub fn with_expected_sha256(mut self, hash: [u8; 32]) -> Self {
        self.expected_sha256 = Some(hash);
        self
    }

    /// Parse the zlib-compressed acquisition metadata from the `header` section.
    ///
    /// Returns `Some` on the first segment that contains a valid, decompressible
    /// `header` section with a parseable key-value block.  Returns `None` if no
    /// such section exists or any parse step fails.
    pub fn header_metadata(&self) -> Option<EwfHeaderMetadata> {
        for &data in &self.segments {
            if let Some(meta) = parse_header_section(data) {
                return Some(meta);
            }
        }
        None
    }

    /// Compute MD5, SHA-1, and SHA-256 of all sector data without verifying stored hashes.
    ///
    /// Returns `None` if the image is unparseable (too short, invalid signature,
    /// missing geometry, or no chunk table found in an EWF v2 image).
    pub fn compute_hashes(&self) -> Option<ComputedHashes> {
        let first = self.segments.first().copied().unwrap_or(&[]);
        if first.len() >= 8 && (first[0..8] == EVF2_SIGNATURE || first[0..8] == LEF2_SIGNATURE) {
            return compute_hashes_ewf2(&self.segments);
        }
        compute_hashes_ewf1(&self.segments)
    }

    pub fn analyse(&self) -> Vec<EwfIntegrityAnomaly> {
        let first = self.segments.first().copied().unwrap_or(&[]);
        if first.len() >= 8 && (first[0..8] == EVF2_SIGNATURE || first[0..8] == LEF2_SIGNATURE) {
            return self.analyse_all_ewf2();
        }
        self.analyse_all_ewf1()
    }

    /// Analyse with a per-chunk progress callback.
    ///
    /// The callback receives an [`AnalysisProgress`] snapshot after each chunk
    /// is processed.  The final call has `chunks_done == chunks_total` (for
    /// EWF v2) or `chunks_done > 0` (for EWF v1).
    ///
    /// Returns the same anomaly list as [`analyse`][Self::analyse].
    pub fn analyse_with_progress(
        &self,
        progress: impl FnMut(AnalysisProgress),
    ) -> Vec<EwfIntegrityAnomaly> {
        let first = self.segments.first().copied().unwrap_or(&[]);
        if first.len() >= 8 && (first[0..8] == EVF2_SIGNATURE || first[0..8] == LEF2_SIGNATURE) {
            return self.analyse_all_ewf2_with_progress(progress);
        }
        self.analyse_all_ewf1_with_progress(progress)
    }

    // ── EWF v1 ───────────────────────────────────────────────────────────────

    fn analyse_all_ewf1(&self) -> Vec<EwfIntegrityAnomaly> {
        let mut issues = Vec::new();
        let n = self.segments.len();
        let multi = n > 1;
        let mut geometry: Option<VolumeGeometry> = None;
        let mut all_sections: Vec<Vec<Section>> = Vec::with_capacity(n);
        let mut total_table_entries: u32 = 0;

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

            if data[0..8] != EVF_SIGNATURE
                && data[0..8] != DVF_SIGNATURE
                && data[0..8] != LVF_SIGNATURE
            {
                issues.push(EwfIntegrityAnomaly::InvalidSignature);
            }

            let seg_num = le_u16(data, 9);
            if seg_num == 0 {
                issues.push(EwfIntegrityAnomaly::SegmentNumberZero);
            } else if seg_num != expected_seg_num {
                issues.push(EwfIntegrityAnomaly::SegmentOutOfOrder {
                    segment_number: seg_num,
                    expected: expected_seg_num,
                });
            }

            let sections = walk_sections_v1(data, &mut issues);

            // Volume/disk geometry — required in segment 0; compared in later segments.
            if let Some(vol_sec) = sections
                .iter()
                .find(|s| s.type_name == "volume" || s.type_name == "disk")
            {
                if idx == 0 {
                    geometry = check_volume_v1(data, vol_sec.offset, vol_sec.size, &mut issues);
                } else {
                    // Later segments with a volume section: validate its GUID against seg 0.
                    let later = check_volume_v1(data, vol_sec.offset, vol_sec.size, &mut issues);
                    if let (Some(ref base), Some(ref later_geom)) = (&geometry, &later) {
                        let base_guid = base.set_identifier;
                        let later_guid = later_geom.set_identifier;
                        let neither_zero = base_guid != [0u8; 16] && later_guid != [0u8; 16];
                        if neither_zero && base_guid != later_guid {
                            issues.push(EwfIntegrityAnomaly::SetIdentifierMismatch {
                                segment: idx + 1,
                            });
                        }
                    }
                }
            } else if idx == 0 {
                issues.push(EwfIntegrityAnomaly::VolumeSectionMissing);
            }

            // Table integrity — single-segment: check per-entry-count vs volume directly.
            // Multi-segment: accumulate for post-loop total comparison.
            let vol_count = if !multi && idx == 0 {
                geometry.as_ref().map(|g| g.chunk_count)
            } else {
                None
            };
            let sectors_section = sections.iter().find(|s| s.type_name == "sectors");
            let sectors_range = sectors_section
                .map(|s| (s.offset + SECTION_DESCRIPTOR_SIZE as u64, s.offset + s.size));
            if sectors_section.is_none() {
                issues.push(EwfIntegrityAnomaly::SectorsSectionMissing);
            }
            if let Some(table) = sections.iter().find(|s| s.type_name == "table") {
                let data_start = (table.offset as usize) + SECTION_DESCRIPTOR_SIZE;
                if data.len() >= data_start + 4 {
                    let count = le_u32(data, data_start);
                    total_table_entries = total_table_entries.saturating_add(count);
                }
                check_table_v1(
                    data,
                    table.offset,
                    vol_count,
                    file_size,
                    sectors_range,
                    &mut issues,
                );
            } else {
                issues.push(EwfIntegrityAnomaly::TableSectionMissing);
            }

            // table2 consistency: when both table and table2 exist, bodies must match.
            if let (Some(t1), Some(t2)) = (
                sections.iter().find(|s| s.type_name == "table"),
                sections.iter().find(|s| s.type_name == "table2"),
            ) {
                let b1_start = (t1.offset + SECTION_DESCRIPTOR_SIZE as u64) as usize;
                let b1_end = (t1.offset + t1.size) as usize;
                let b2_start = (t2.offset + SECTION_DESCRIPTOR_SIZE as u64) as usize;
                let b2_end = (t2.offset + t2.size) as usize;
                if let (Some(body1), Some(body2)) =
                    (data.get(b1_start..b1_end), data.get(b2_start..b2_end))
                {
                    if body1.len() == body2.len() {
                        if let Some(offset) = body1.iter().zip(body2).position(|(a, b)| a != b) {
                            issues.push(EwfIntegrityAnomaly::Table2Mismatch { offset });
                        }
                    } else {
                        issues.push(EwfIntegrityAnomaly::Table2Mismatch { offset: 0 });
                    }
                }
            }

            // error2 section: parse entry_count, warn if any unreadable sectors.
            if let Some(e2) = sections.iter().find(|s| s.type_name == "error2") {
                let body_start = (e2.offset + SECTION_DESCRIPTOR_SIZE as u64) as usize;
                if body_start + 4 <= data.len() {
                    let count = le_u32(data, body_start);
                    if count > 0 {
                        issues.push(EwfIntegrityAnomaly::BadSectorsPresent { count });
                    }
                }
            }

            // Done section expected only in the last segment
            if is_last && !sections.iter().any(|s| s.type_name == "done") {
                issues.push(EwfIntegrityAnomaly::DoneSectionMissing);
            }

            all_sections.push(sections);
        }

        // Multi-segment total chunk count vs sum of all table entry counts.
        if multi {
            if let Some(geom) = &geometry {
                if total_table_entries != geom.chunk_count {
                    issues.push(EwfIntegrityAnomaly::TableChunkCountMismatch {
                        in_volume: geom.chunk_count,
                        in_table: total_table_entries,
                    });
                }
            }
        }

        // Hash verification spans all segments
        if let Some(geom) = &geometry {
            check_hash_all_segments(
                &self.segments,
                &all_sections,
                geom,
                self.expected_md5,
                self.expected_sha1,
                self.expected_sha256,
                &mut issues,
                &mut |_| {},
            );
        }

        issues
    }

    // ── EWF v2 ───────────────────────────────────────────────────────────────

    fn analyse_all_ewf2(&self) -> Vec<EwfIntegrityAnomaly> {
        self.analyse_all_ewf2_with_progress(|_| {})
    }

    fn analyse_all_ewf2_impl(
        &self,
        progress: &mut dyn FnMut(AnalysisProgress),
    ) -> Vec<EwfIntegrityAnomaly> {
        let mut issues = Vec::new();
        let n = self.segments.len();

        // Stored hashes live in the FINAL segment and cover ALL segments' data.
        let mut final_stored_md5: Option<[u8; 16]> = None;
        let mut final_stored_sha1: Option<[u8; 20]> = None;
        let mut final_stored_sha256: Option<[u8; 32]> = None;

        for (idx, &data) in self.segments.iter().enumerate() {
            let expected_seg_num = (idx + 1) as u32;

            if data.len() < EVF2_FILE_HEADER_SIZE + EVF2_SECTION_DESCRIPTOR_SIZE {
                issues.push(EwfIntegrityAnomaly::SectionChainBroken {
                    at_offset: 0,
                    next_offset: 0,
                });
                continue;
            }

            if data[0..8] != EVF2_SIGNATURE && data[0..8] != LEF2_SIGNATURE {
                issues.push(EwfIntegrityAnomaly::InvalidSignature);
            }

            let seg_num = le_u32(data, 12);
            if seg_num == 0 {
                issues.push(EwfIntegrityAnomaly::SegmentNumberZero);
            } else if seg_num != expected_seg_num {
                issues.push(EwfIntegrityAnomaly::SegmentOutOfOrder {
                    segment_number: seg_num as u16,
                    expected: expected_seg_num as u16,
                });
            }

            // compression_method at file header [10..12]: 0=none/deflate, 1=deflate.
            // Values ≥ 2 indicate bzip2, lzma, or other algorithms not supported here.
            let compression_method = le_u16(data, 10);
            if compression_method > 1 {
                issues.push(EwfIntegrityAnomaly::UnsupportedCompressionAlgorithm {
                    method_id: compression_method,
                });
            }

            // EWF v2: section body precedes its descriptor; the DONE/NEXT descriptor
            // is the last 64 bytes of the segment. Walk backward via prev_section_offset.
            let mut has_hash = false;
            let mut has_media_info = false;
            let mut chunk_table_body: Option<(usize, usize)> = None;
            let mut stored_sector_md5: Option<[u8; 16]> = None;
            let mut stored_sector_sha1: Option<[u8; 20]> = None;
            let mut stored_sector_sha256: Option<[u8; 32]> = None;
            let mut desc_offset = data.len().saturating_sub(EVF2_SECTION_DESCRIPTOR_SIZE);

            loop {
                if desc_offset + EVF2_SECTION_DESCRIPTOR_SIZE > data.len()
                    || desc_offset < EVF2_FILE_HEADER_SIZE
                {
                    break;
                }
                let desc = &data[desc_offset..desc_offset + EVF2_SECTION_DESCRIPTOR_SIZE];
                let section_type = le_u32(desc, 0);
                let data_flags = le_u32(desc, 4);
                let prev_offset = le_u64(desc, 8) as usize;
                let data_size = le_u64(desc, 16) as usize;
                let stored_hash: [u8; 16] = array_at(desc, 32);

                // Body occupies [desc_offset - data_size .. desc_offset].
                let body_end = desc_offset;
                let body_start = desc_offset.saturating_sub(data_size);

                if data_flags & EVF2_DATA_FLAG_ENCRYPTED != 0 {
                    issues.push(EwfIntegrityAnomaly::Ewf2EncryptedSection {
                        offset: desc_offset as u64,
                    });
                } else {
                    if stored_hash != [0u8; 16] {
                        if let Some(body) = data.get(body_start..body_end) {
                            let computed: [u8; 16] = Md5::digest(body).into();
                            if computed != stored_hash {
                                issues.push(EwfIntegrityAnomaly::Ewf2SectionDataHashMismatch {
                                    offset: desc_offset as u64,
                                    section_type_id: section_type,
                                    computed,
                                    stored: stored_hash,
                                });
                            }
                        }
                    }

                    match section_type {
                        EVF2_TYPE_MEDIA_INFO => {
                            has_media_info = true;
                            if let Some(body) = data.get(body_start..body_end) {
                                if !parse_media_info_body(body) {
                                    issues.push(EwfIntegrityAnomaly::Ewf2MediaInfoParseFailed);
                                }
                            } else {
                                issues.push(EwfIntegrityAnomaly::Ewf2MediaInfoParseFailed);
                            }
                        }
                        EVF2_TYPE_CHUNK_TABLE => {
                            chunk_table_body = Some((body_start, body_end));
                        }
                        EVF2_TYPE_MD5_HASH => {
                            has_hash = true;
                            // Body[0..16] = MD5 of all sector data
                            if data_size >= 16 {
                                if let Some(body) = data.get(body_start..body_end) {
                                    let mut h = [0u8; 16];
                                    h.copy_from_slice(&body[..16]);
                                    stored_sector_md5 = Some(h);
                                }
                            }
                        }
                        EVF2_TYPE_SHA1_HASH => {
                            has_hash = true;
                            if data_size >= 20 {
                                if let Some(body) = data.get(body_start..body_end) {
                                    let mut h = [0u8; 20];
                                    h.copy_from_slice(&body[..20]);
                                    stored_sector_sha1 = Some(h);
                                }
                            }
                        }
                        EVF2_TYPE_SHA256_HASH => {
                            has_hash = true;
                            if data_size >= 32 {
                                if let Some(body) = data.get(body_start..body_end) {
                                    let mut h = [0u8; 32];
                                    h.copy_from_slice(&body[..32]);
                                    stored_sector_sha256 = Some(h);
                                }
                            }
                        }
                        _ => {}
                    }
                }

                if prev_offset == 0 {
                    break;
                }
                desc_offset = prev_offset;
            }

            if idx == n - 1 && !has_hash {
                issues.push(EwfIntegrityAnomaly::Ewf2HashSectionMissing);
            }
            if idx == 0 && !has_media_info {
                issues.push(EwfIntegrityAnomaly::Ewf2MediaInfoMissing);
            }

            // Capture stored hashes from the final segment; they cover ALL segments' data.
            if idx == n - 1 {
                final_stored_md5 = stored_sector_md5;
                final_stored_sha1 = stored_sector_sha1;
                final_stored_sha256 = stored_sector_sha256;
            }

            // Per-chunk Adler-32 verification only; stored-hash comparison happens
            // cross-segment after the loop to avoid false positives on multi-segment images.
            if let Some((ct_start, ct_end)) = chunk_table_body {
                verify_ewf2_sector_data(
                    data,
                    ct_start,
                    ct_end,
                    None,
                    None,
                    None,
                    &mut issues,
                    progress,
                );
            }
        }

        // Cross-segment hash comparison: compute hashes over ALL segments and compare
        // with stored values from the final segment, plus any external reference hashes.
        if let Some(computed) = compute_hashes_ewf2(&self.segments) {
            if let Some(stored) = final_stored_md5 {
                if computed.md5 != stored {
                    issues.push(EwfIntegrityAnomaly::HashMismatch {
                        computed: computed.md5,
                        stored,
                    });
                }
            }
            if let Some(stored) = final_stored_sha1 {
                if computed.sha1 != stored {
                    issues.push(EwfIntegrityAnomaly::DigestSha1Mismatch {
                        computed: computed.sha1,
                        stored,
                    });
                }
            }
            if let Some(stored) = final_stored_sha256 {
                if computed.sha256 != stored {
                    issues.push(EwfIntegrityAnomaly::DigestSha256Mismatch {
                        computed: computed.sha256,
                        stored,
                    });
                }
            }
            if let Some(expected) = self.expected_md5 {
                if computed.md5 != expected {
                    issues.push(EwfIntegrityAnomaly::ExternalMd5Mismatch {
                        computed: computed.md5,
                        expected,
                    });
                }
            }
            if let Some(expected) = self.expected_sha1 {
                if computed.sha1 != expected {
                    issues.push(EwfIntegrityAnomaly::ExternalSha1Mismatch {
                        computed: computed.sha1,
                        expected,
                    });
                }
            }
            if let Some(expected) = self.expected_sha256 {
                if computed.sha256 != expected {
                    issues.push(EwfIntegrityAnomaly::ExternalSha256Mismatch {
                        computed: computed.sha256,
                        expected,
                    });
                }
            }
        }

        issues
    }

    fn analyse_all_ewf1_with_progress(
        &self,
        mut progress: impl FnMut(AnalysisProgress),
    ) -> Vec<EwfIntegrityAnomaly> {
        let mut issues = Vec::new();
        let n = self.segments.len();
        let multi = n > 1;
        let mut geometry: Option<VolumeGeometry> = None;
        let mut all_sections: Vec<Vec<Section>> = Vec::with_capacity(n);
        let mut total_table_entries: u32 = 0;

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
            if data[0..8] != EVF_SIGNATURE
                && data[0..8] != DVF_SIGNATURE
                && data[0..8] != LVF_SIGNATURE
            {
                issues.push(EwfIntegrityAnomaly::InvalidSignature);
            }
            let seg_num = le_u16(data, 9);
            if seg_num == 0 {
                issues.push(EwfIntegrityAnomaly::SegmentNumberZero);
            } else if seg_num != expected_seg_num {
                issues.push(EwfIntegrityAnomaly::SegmentOutOfOrder {
                    segment_number: seg_num,
                    expected: expected_seg_num,
                });
            }
            let sections = walk_sections_v1(data, &mut issues);
            if let Some(vol_sec) = sections
                .iter()
                .find(|s| s.type_name == "volume" || s.type_name == "disk")
            {
                if idx == 0 {
                    geometry = check_volume_v1(data, vol_sec.offset, vol_sec.size, &mut issues);
                } else {
                    let later = check_volume_v1(data, vol_sec.offset, vol_sec.size, &mut issues);
                    if let (Some(ref base), Some(ref later_geom)) = (&geometry, &later) {
                        let base_guid = base.set_identifier;
                        let later_guid = later_geom.set_identifier;
                        if base_guid != [0u8; 16]
                            && later_guid != [0u8; 16]
                            && base_guid != later_guid
                        {
                            issues.push(EwfIntegrityAnomaly::SetIdentifierMismatch {
                                segment: idx + 1,
                            });
                        }
                    }
                }
            } else if idx == 0 {
                issues.push(EwfIntegrityAnomaly::VolumeSectionMissing);
            }
            let vol_count = if !multi && idx == 0 {
                geometry.as_ref().map(|g| g.chunk_count)
            } else {
                None
            };
            let sectors_section = sections.iter().find(|s| s.type_name == "sectors");
            let sectors_range = sectors_section
                .map(|s| (s.offset + SECTION_DESCRIPTOR_SIZE as u64, s.offset + s.size));
            if sectors_section.is_none() {
                issues.push(EwfIntegrityAnomaly::SectorsSectionMissing);
            }
            if let Some(table) = sections.iter().find(|s| s.type_name == "table") {
                let data_start = (table.offset as usize) + SECTION_DESCRIPTOR_SIZE;
                if data.len() >= data_start + 4 {
                    let count = le_u32(data, data_start);
                    total_table_entries = total_table_entries.saturating_add(count);
                }
                check_table_v1(
                    data,
                    table.offset,
                    vol_count,
                    file_size,
                    sectors_range,
                    &mut issues,
                );
            } else {
                issues.push(EwfIntegrityAnomaly::TableSectionMissing);
            }
            if let (Some(t1), Some(t2)) = (
                sections.iter().find(|s| s.type_name == "table"),
                sections.iter().find(|s| s.type_name == "table2"),
            ) {
                let b1_start = (t1.offset + SECTION_DESCRIPTOR_SIZE as u64) as usize;
                let b1_end = (t1.offset + t1.size) as usize;
                let b2_start = (t2.offset + SECTION_DESCRIPTOR_SIZE as u64) as usize;
                let b2_end = (t2.offset + t2.size) as usize;
                if let (Some(body1), Some(body2)) =
                    (data.get(b1_start..b1_end), data.get(b2_start..b2_end))
                {
                    if body1.len() == body2.len() {
                        if let Some(offset) = body1.iter().zip(body2).position(|(a, b)| a != b) {
                            issues.push(EwfIntegrityAnomaly::Table2Mismatch { offset });
                        }
                    } else {
                        issues.push(EwfIntegrityAnomaly::Table2Mismatch { offset: 0 });
                    }
                }
            }
            if let Some(e2) = sections.iter().find(|s| s.type_name == "error2") {
                let body_start = (e2.offset + SECTION_DESCRIPTOR_SIZE as u64) as usize;
                if body_start + 4 <= data.len() {
                    let count = le_u32(data, body_start);
                    if count > 0 {
                        issues.push(EwfIntegrityAnomaly::BadSectorsPresent { count });
                    }
                }
            }
            if is_last && !sections.iter().any(|s| s.type_name == "done") {
                issues.push(EwfIntegrityAnomaly::DoneSectionMissing);
            }
            all_sections.push(sections);
        }

        if multi {
            if let Some(geom) = &geometry {
                if total_table_entries != geom.chunk_count {
                    issues.push(EwfIntegrityAnomaly::TableChunkCountMismatch {
                        in_volume: geom.chunk_count,
                        in_table: total_table_entries,
                    });
                }
            }
        }

        if let Some(geom) = &geometry {
            check_hash_all_segments(
                &self.segments,
                &all_sections,
                geom,
                self.expected_md5,
                self.expected_sha1,
                self.expected_sha256,
                &mut issues,
                &mut progress,
            );
        }
        issues
    }

    fn analyse_all_ewf2_with_progress(
        &self,
        mut progress: impl FnMut(AnalysisProgress),
    ) -> Vec<EwfIntegrityAnomaly> {
        self.analyse_all_ewf2_impl(&mut progress)
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn parse_header_section(data: &[u8]) -> Option<EwfHeaderMetadata> {
    if data.len() < FILE_HEADER_SIZE + SECTION_DESCRIPTOR_SIZE {
        return None;
    }
    let desc_off = FILE_HEADER_SIZE;
    let desc = &data[desc_off..desc_off + SECTION_DESCRIPTOR_SIZE];
    let type_end = desc[..16].iter().position(|&b| b == 0).unwrap_or(16);
    if &desc[..type_end] != b"header" {
        return None;
    }
    let section_size = le_u64(desc, 24) as usize;
    let body_start = desc_off + SECTION_DESCRIPTOR_SIZE;
    let body_end = (desc_off + section_size).min(data.len());
    if body_start >= body_end {
        return None;
    }
    let compressed = &data[body_start..body_end];

    let mut decoder = ZlibDecoder::new(compressed);
    let mut text = String::new();
    decoder.read_to_string(&mut text).ok()?;

    parse_header_text(&text)
}

fn parse_header_text(text: &str) -> Option<EwfHeaderMetadata> {
    // Format (CRLF or LF line endings):
    //   line 0: "1"
    //   line 1: "main"
    //   line 2: tab-delimited key names
    //   line 3: tab-delimited values
    let lines: Vec<&str> = text
        .lines()
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.is_empty())
        .collect();
    if lines.len() < 4 {
        return None;
    }
    let keys: Vec<&str> = lines[2].split('\t').collect();
    let vals: Vec<&str> = lines[3].split('\t').collect();

    let mut meta = EwfHeaderMetadata {
        description: String::new(),
        case_number: String::new(),
        evidence_number: String::new(),
        examiner_name: String::new(),
        acquisition_date: String::new(),
        system_date: String::new(),
        password_hash: String::new(),
        acquisition_software: String::new(),
    };

    for (i, &key) in keys.iter().enumerate() {
        let val = vals.get(i).copied().unwrap_or("").to_owned();
        match key {
            "a" => meta.description = val,
            "c" => meta.case_number = val,
            "e" => meta.evidence_number = val,
            "t" => meta.examiner_name = val,
            "m" => meta.acquisition_date = val,
            "u" => meta.system_date = val,
            "p" => meta.password_hash = val,
            "r" => meta.acquisition_software = val,
            _ => {}
        }
    }

    Some(meta)
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
    /// `set_identifier` GUID from `ewf_data_t`[64..80]; all-zero = not present.
    set_identifier: [u8; 16],
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

        let stored_crc = le_u32(desc, 72);
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

        let next = le_u64(desc, 16);
        let section_size = le_u64(desc, 24);
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
                .is_some_and(|s| s.iter().any(|&b| b != 0));
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

fn check_volume_v1(
    data: &[u8],
    desc_offset: u64,
    section_size: u64,
    issues: &mut Vec<EwfIntegrityAnomaly>,
) -> Option<VolumeGeometry> {
    let data_start = (desc_offset as usize) + SECTION_DESCRIPTOR_SIZE;
    if data.len() < data_start + VOLUME_DATA_MIN {
        return None;
    }
    let body_len = (section_size as usize).saturating_sub(SECTION_DESCRIPTOR_SIZE);
    let vol_end = (data_start + body_len).min(data.len());
    let vol = &data[data_start..vol_end];

    // media_type: byte 0 of ewf_data_t (valid: 0x00/0x01/0x03/0x0e/0x10)
    let media_type = vol[0];
    if !VALID_MEDIA_TYPES.contains(&media_type) {
        issues.push(EwfIntegrityAnomaly::MediaTypeUnknown { media_type });
    }

    let chunk_count = le_u32(vol, 4);
    let sectors_per_chunk = le_u32(vol, 8);
    let bytes_per_sector = le_u32(vol, 12);
    let sector_count = le_u64(vol, 16);

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

    // set_identifier GUID at ewf_data_t[64..80]
    let set_identifier: [u8; 16] = array_at(vol, 64);

    // Adler-32 of ewf_data_t bytes 0..1048 stored at bytes 1048..1052.
    // Only present when the section body is ≥ VOLUME_DATA_FULL (1052) bytes.
    if vol.len() >= VOLUME_DATA_FULL {
        let stored_crc = le_u32(vol, 1048);
        let computed_crc = adler32(&vol[..1048]);
        if computed_crc != stored_crc {
            issues.push(EwfIntegrityAnomaly::VolumeBodyCrcMismatch {
                computed: computed_crc,
                stored: stored_crc,
            });
        }
    }

    Some(VolumeGeometry {
        chunk_count,
        sectors_per_chunk,
        bytes_per_sector,
        sector_count,
        set_identifier,
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
    let entry_count = le_u32(tbl, 0);
    let base_offset = le_u64(tbl, 8);

    // Table header Adler-32: covers bytes [0..16], stored at [16..20].
    // When stored = 0 the writer chose not to include the checksum; skip check.
    let stored_crc = le_u32(tbl, 16);
    if stored_crc != 0 {
        let computed_crc = adler32(&tbl[..16]);
        if computed_crc != stored_crc {
            issues.push(EwfIntegrityAnomaly::TableHeaderAdler32Mismatch {
                computed: computed_crc,
                stored: stored_crc,
            });
        }
    }

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
        let raw = le_u32(data, entry_off);
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
    let entry_count = le_u32(tbl, 0) as usize;
    let base_offset = le_u64(tbl, 8) as usize;
    let entries_start = tbl_data_start + 24;
    let sectors_body_end = (sectors.offset + sectors.size) as usize;

    let mut chunks = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let entry_off = entries_start + i * 4;
        if entry_off + 4 > data.len() {
            break;
        }
        let raw = le_u32(data, entry_off);
        let compressed = raw & 0x8000_0000 != 0;
        let rel = (raw & 0x7FFF_FFFF) as usize;
        let start = base_offset + rel;

        let end = if i + 1 < entry_count {
            let next_off = entries_start + (i + 1) * 4;
            if next_off + 4 > data.len() {
                break;
            }
            let next_raw = le_u32(data, next_off);
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
    expected_sha256: Option<[u8; 32]>,
    issues: &mut Vec<EwfIntegrityAnomaly>,
    progress: &mut dyn FnMut(AnalysisProgress),
) {
    let chunk_size = u64::from(geom.sectors_per_chunk) * u64::from(geom.bytes_per_sector);
    let total_bytes = geom.sector_count * u64::from(geom.bytes_per_sector);
    let mut bytes_remaining = total_bytes;

    let mut md5_h = Md5::new();
    let mut sha1_h = Sha1::new();
    let mut sha256_h = Sha256::new();

    let chunk_size_usize = chunk_size as usize;
    let mut global_chunk_idx: usize = 0;

    'outer: for (&seg_data, sections) in segments.iter().zip(all_sections.iter()) {
        for (start, end, compressed) in iter_segment_chunks(seg_data, sections) {
            if bytes_remaining == 0 {
                break 'outer;
            }
            let to_hash = bytes_remaining.min(chunk_size) as usize;
            let raw = &seg_data[start..end];

            // Per-chunk Adler-32 (ewfverify parity).
            //
            // Compressed chunks are self-checksummed by the zlib stream (RFC 1950
            // appends its own big-endian Adler-32 internally); decompression failure
            // already catches corruption via the HashMismatch path.
            //
            // Uncompressed chunks MAY have a separate 4-byte little-endian Adler-32
            // appended by the acquisition tool. Presence is detected by
            // raw.len() > chunk_size (the chunk byte range includes extra bytes).
            let this_chunk_idx = global_chunk_idx;
            global_chunk_idx += 1;

            let has_uncompressed_checksum = !compressed && (raw.len() > chunk_size_usize);
            if has_uncompressed_checksum && raw.len() >= chunk_size_usize + 4 {
                let crc_end = chunk_size_usize;
                let stored = le_u32(raw, crc_end);
                let computed = adler32(&raw[..crc_end]);
                if computed != stored {
                    issues.push(EwfIntegrityAnomaly::ChunkChecksumMismatch {
                        chunk_index: this_chunk_idx,
                        computed,
                        stored,
                    });
                }
            }

            if compressed {
                let limit = (to_hash as u64).saturating_add(1);
                let mut decompressed = Vec::with_capacity(to_hash);
                if ZlibDecoder::new(raw)
                    .take(limit)
                    .read_to_end(&mut decompressed)
                    .is_err()
                {
                    issues.push(EwfIntegrityAnomaly::ChunkDecompressionError {
                        chunk_index: this_chunk_idx,
                    });
                    bytes_remaining = bytes_remaining.saturating_sub(to_hash as u64);
                    continue;
                }
                let slice = &decompressed[..decompressed.len().min(to_hash)];
                md5_h.update(slice);
                sha1_h.update(slice);
                sha256_h.update(slice);
            } else {
                // For uncompressed chunks with trailing checksum, raw.len() = chunk_size + 4;
                // hash only the sector data (to_hash bytes), not the trailing checksum.
                let slice = &raw[..raw.len().min(to_hash)];
                md5_h.update(slice);
                sha1_h.update(slice);
                sha256_h.update(slice);
            }
            bytes_remaining = bytes_remaining.saturating_sub(to_hash as u64);
            progress(AnalysisProgress {
                chunks_done: global_chunk_idx,
                chunks_total: None,
                bytes_done: total_bytes - bytes_remaining,
            });
        }
    }

    let computed_md5: [u8; 16] = md5_h.finalize().into();
    let computed_sha1: [u8; 20] = sha1_h.finalize().into();
    let computed_sha256: [u8; 32] = sha256_h.finalize().into();

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
                let stored: [u8; 16] = stored_slice.try_into().unwrap_or([0u8; 16]);
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
            let stored: [u8; 20] = sha1_slice.try_into().unwrap_or([0u8; 20]);
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
    if let Some(expected) = expected_sha256 {
        if computed_sha256 != expected {
            issues.push(EwfIntegrityAnomaly::ExternalSha256Mismatch {
                computed: computed_sha256,
                expected,
            });
        }
    }
}

/// Verify EWF v2 chunk data integrity and compare overall MD5 against stored value.
///
/// Chunk table entry layout (16 bytes each, starting at body offset 32):
///   [0..8]:   `file_offset` (u64 LE) — absolute position of chunk data in the file
///   [8..12]:  `data_size` (u32 LE) — `raw_sector_bytes` + 4 (Adler-32 trailer)
/// Attempt to zlib-decompress and UTF-16LE-decode a `media_info` section body.
///
/// Returns `true` if the body is a valid zlib stream that decodes as UTF-16LE
/// (with or without BOM), `false` on any failure.  An empty body is rejected.
fn parse_media_info_body(body: &[u8]) -> bool {
    if body.is_empty() {
        return false;
    }
    let mut decompressed = Vec::new();
    if ZlibDecoder::new(body)
        .read_to_end(&mut decompressed)
        .is_err()
    {
        return false;
    }
    // Strip BOM if present
    let text_bytes = if decompressed.starts_with(&[0xFF, 0xFE]) {
        &decompressed[2..]
    } else {
        &decompressed[..]
    };
    // Must be even-length for UTF-16LE
    if text_bytes.len() % 2 != 0 {
        return false;
    }
    let units: Vec<u16> = text_bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    String::from_utf16(&units).is_ok()
}

///   [12..16]: flags (u32 LE) — bit 0: compressed (zlib); other bits: reserved
///
/// On-disk chunk layout: [`sector_data`: `raw_size` bytes][adler32: 4 bytes][alignment pad]
fn verify_ewf2_sector_data(
    data: &[u8],
    ct_start: usize,
    ct_end: usize,
    stored_md5: Option<[u8; 16]>,
    stored_sha1: Option<[u8; 20]>,
    stored_sha256: Option<[u8; 32]>,
    issues: &mut Vec<EwfIntegrityAnomaly>,
    progress: &mut dyn FnMut(AnalysisProgress),
) -> Option<ComputedHashes> {
    let tbl = data.get(ct_start..ct_end)?;
    if tbl.len() < EVF2_CHUNK_TABLE_HEADER_SIZE + EVF2_CHUNK_TABLE_ENTRY_SIZE {
        return None;
    }
    let chunk_count = le_u64(tbl, 8) as usize;

    // Chunk table Adler-32: covers entries[0..chunk_count] immediately after the header.
    let checksum_off = EVF2_CHUNK_TABLE_HEADER_SIZE + chunk_count * EVF2_CHUNK_TABLE_ENTRY_SIZE;
    if checksum_off + 4 <= tbl.len() {
        let computed_cs = adler32(&tbl[EVF2_CHUNK_TABLE_HEADER_SIZE..checksum_off]);
        let stored_cs = le_u32(tbl, checksum_off);
        if computed_cs != stored_cs {
            issues.push(EwfIntegrityAnomaly::Ewf2ChunkTableChecksumMismatch {
                computed: computed_cs,
                stored: stored_cs,
            });
        }
    }

    let mut md5_h = Md5::new();
    let mut sha1_h = Sha1::new();
    let mut sha256_h = Sha256::new();

    for i in 0..chunk_count {
        let entry_off = EVF2_CHUNK_TABLE_HEADER_SIZE + i * EVF2_CHUNK_TABLE_ENTRY_SIZE;
        if entry_off + EVF2_CHUNK_TABLE_ENTRY_SIZE > tbl.len() {
            break;
        }
        let file_offset = le_u64(tbl, entry_off) as usize;
        let chunk_data_size = le_u32(tbl, entry_off + 8) as usize;
        let flags = le_u32(tbl, entry_off + 12);

        // data_size includes a 4-byte Adler-32 trailer; raw sector data precedes it.
        let raw_size = chunk_data_size.saturating_sub(4);
        let chunk_raw = match data.get(file_offset..file_offset + raw_size) {
            Some(r) => r,
            None => break,
        };

        // Per-chunk Adler-32
        if chunk_data_size >= 4 {
            if let Some(crc_bytes) = data.get(file_offset + raw_size..file_offset + raw_size + 4) {
                let stored_crc = u32::from_le_bytes(crc_bytes.try_into().unwrap_or([0u8; 4]));
                let computed_crc = adler32(chunk_raw);
                if computed_crc != stored_crc {
                    issues.push(EwfIntegrityAnomaly::ChunkChecksumMismatch {
                        chunk_index: i,
                        computed: computed_crc,
                        stored: stored_crc,
                    });
                }
            }
        }

        if flags & EVF2_CHUNK_FLAG_COMPRESSED != 0 {
            // Zlib-compressed chunk: decompress before hashing.
            let mut decompressed = Vec::with_capacity(raw_size);
            if ZlibDecoder::new(chunk_raw)
                .read_to_end(&mut decompressed)
                .is_err()
            {
                issues.push(EwfIntegrityAnomaly::ChunkDecompressionError { chunk_index: i });
                continue;
            }
            md5_h.update(&decompressed);
            sha1_h.update(&decompressed);
            sha256_h.update(&decompressed);
        } else {
            md5_h.update(chunk_raw);
            sha1_h.update(chunk_raw);
            sha256_h.update(chunk_raw);
        }
        progress(AnalysisProgress {
            chunks_done: i + 1,
            chunks_total: Some(chunk_count),
            bytes_done: ((i + 1) * raw_size) as u64,
        });
    }

    let computed_md5: [u8; 16] = md5_h.finalize().into();
    let computed_sha1: [u8; 20] = sha1_h.finalize().into();
    let computed_sha256: [u8; 32] = sha256_h.finalize().into();

    if let Some(stored) = stored_md5 {
        if computed_md5 != stored {
            issues.push(EwfIntegrityAnomaly::HashMismatch {
                computed: computed_md5,
                stored,
            });
        }
    }

    if let Some(stored) = stored_sha1 {
        if computed_sha1 != stored {
            issues.push(EwfIntegrityAnomaly::DigestSha1Mismatch {
                computed: computed_sha1,
                stored,
            });
        }
    }

    if let Some(stored) = stored_sha256 {
        if computed_sha256 != stored {
            issues.push(EwfIntegrityAnomaly::DigestSha256Mismatch {
                computed: computed_sha256,
                stored,
            });
        }
    }

    Some(ComputedHashes {
        md5: computed_md5,
        sha1: computed_sha1,
        sha256: computed_sha256,
    })
}

/// Extract sector-data hashes from EWF v2 segments without full anomaly checking.
fn compute_hashes_ewf2(segments: &[&[u8]]) -> Option<ComputedHashes> {
    let mut md5_h = Md5::new();
    let mut sha1_h = Sha1::new();
    let mut sha256_h = Sha256::new();
    let mut found_chunks = false;

    for &data in segments {
        if data.len() < EVF2_FILE_HEADER_SIZE + EVF2_SECTION_DESCRIPTOR_SIZE {
            continue;
        }

        // Walk backward to find the chunk table section.
        let mut desc_offset = data.len().saturating_sub(EVF2_SECTION_DESCRIPTOR_SIZE);
        let mut chunk_table_body: Option<(usize, usize)> = None;

        loop {
            if desc_offset + EVF2_SECTION_DESCRIPTOR_SIZE > data.len()
                || desc_offset < EVF2_FILE_HEADER_SIZE
            {
                break;
            }
            let desc = &data[desc_offset..desc_offset + EVF2_SECTION_DESCRIPTOR_SIZE];
            let section_type = le_u32(desc, 0);
            let data_flags = le_u32(desc, 4);
            let prev_offset = le_u64(desc, 8) as usize;
            let data_size = le_u64(desc, 16) as usize;
            let body_end = desc_offset;
            let body_start = desc_offset.saturating_sub(data_size);

            if data_flags & EVF2_DATA_FLAG_ENCRYPTED == 0 && section_type == EVF2_TYPE_CHUNK_TABLE {
                chunk_table_body = Some((body_start, body_end));
            }

            if prev_offset == 0 {
                break;
            }
            desc_offset = prev_offset;
        }

        let (ct_start, ct_end) = match chunk_table_body {
            Some(b) => b,
            None => continue,
        };
        let tbl = match data.get(ct_start..ct_end) {
            Some(t) => t,
            None => continue,
        };
        if tbl.len() < EVF2_CHUNK_TABLE_HEADER_SIZE + EVF2_CHUNK_TABLE_ENTRY_SIZE {
            continue;
        }
        let chunk_count = le_u64(tbl, 8) as usize;

        for i in 0..chunk_count {
            let entry_off = EVF2_CHUNK_TABLE_HEADER_SIZE + i * EVF2_CHUNK_TABLE_ENTRY_SIZE;
            if entry_off + EVF2_CHUNK_TABLE_ENTRY_SIZE > tbl.len() {
                break;
            }
            let file_offset = le_u64(tbl, entry_off) as usize;
            let chunk_data_size = le_u32(tbl, entry_off + 8) as usize;
            let flags = le_u32(tbl, entry_off + 12);
            let raw_size = chunk_data_size.saturating_sub(4);
            let chunk_raw = match data.get(file_offset..file_offset + raw_size) {
                Some(r) => r,
                None => break,
            };

            if flags & EVF2_CHUNK_FLAG_COMPRESSED != 0 {
                let mut decompressed = Vec::with_capacity(raw_size);
                if ZlibDecoder::new(chunk_raw)
                    .read_to_end(&mut decompressed)
                    .is_err()
                {
                    continue;
                }
                md5_h.update(&decompressed);
                sha1_h.update(&decompressed);
                sha256_h.update(&decompressed);
            } else {
                md5_h.update(chunk_raw);
                sha1_h.update(chunk_raw);
                sha256_h.update(chunk_raw);
            }
            found_chunks = true;
        }
    }

    if !found_chunks {
        return None;
    }
    Some(ComputedHashes {
        md5: md5_h.finalize().into(),
        sha1: sha1_h.finalize().into(),
        sha256: sha256_h.finalize().into(),
    })
}

/// Hash all sector data from EWF v1 segments without running anomaly checks.
/// This is the independent computation path for `compute_hashes()`.
fn compute_hashes_ewf1(segments: &[&[u8]]) -> Option<ComputedHashes> {
    let first = segments.first().copied()?;
    if first.len() < FILE_HEADER_SIZE {
        return None;
    }
    if first[0..8] != EVF_SIGNATURE && first[0..8] != DVF_SIGNATURE && first[0..8] != LVF_SIGNATURE
    {
        return None;
    }

    let mut dummy = Vec::new();
    let sections_first = walk_sections_v1(first, &mut dummy);
    let vol_sec = sections_first
        .iter()
        .find(|s| s.type_name == "volume" || s.type_name == "disk")?;
    let geom = check_volume_v1(first, vol_sec.offset, vol_sec.size, &mut dummy)?;

    let chunk_size = u64::from(geom.sectors_per_chunk) * u64::from(geom.bytes_per_sector);
    let total_bytes = geom.sector_count * u64::from(geom.bytes_per_sector);
    let mut bytes_remaining = total_bytes;

    let mut md5_h = Md5::new();
    let mut sha1_h = Sha1::new();
    let mut sha256_h = Sha256::new();

    let mut all_sections: Vec<Vec<Section>> = Vec::new();
    for &seg in segments {
        let mut d = Vec::new();
        all_sections.push(walk_sections_v1(seg, &mut d));
    }

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
                sha256_h.update(slice);
            } else {
                let slice = &raw[..raw.len().min(to_hash)];
                md5_h.update(slice);
                sha1_h.update(slice);
                sha256_h.update(slice);
            }
            bytes_remaining = bytes_remaining.saturating_sub(to_hash as u64);
        }
    }

    Some(ComputedHashes {
        md5: md5_h.finalize().into(),
        sha1: sha1_h.finalize().into(),
        sha256: sha256_h.finalize().into(),
    })
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

impl EwfIntegrityAnomaly {
    /// Stable, scheme-prefixed machine code for this anomaly.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidSignature => "EWF-INVALID-SIGNATURE",
            Self::SegmentNumberZero => "EWF-SEGMENT-NUMBER-ZERO",
            Self::SectionDescriptorCrcMismatch { .. } => "EWF-SECTION-DESCRIPTOR-CRC-MISMATCH",
            Self::SectionChainBroken { .. } => "EWF-SECTION-CHAIN-BROKEN",
            Self::SectionGapNonZero { .. } => "EWF-SECTION-GAP-NON-ZERO",
            Self::VolumeSectionMissing => "EWF-VOLUME-SECTION-MISSING",
            Self::UnknownSectionType { .. } => "EWF-UNKNOWN-SECTION-TYPE",
            Self::DoneSectionMissing => "EWF-DONE-SECTION-MISSING",
            Self::SectorsSectionMissing => "EWF-SECTORS-SECTION-MISSING",
            Self::TableSectionMissing => "EWF-TABLE-SECTION-MISSING",
            Self::ChunkSizeInvalid { .. } => "EWF-CHUNK-SIZE-INVALID",
            Self::SectorCountMismatch { .. } => "EWF-SECTOR-COUNT-MISMATCH",
            Self::BytesPerSectorInvalid { .. } => "EWF-BYTES-PER-SECTOR-INVALID",
            Self::TableChunkCountMismatch { .. } => "EWF-TABLE-CHUNK-COUNT-MISMATCH",
            Self::TableHeaderAdler32Mismatch { .. } => "EWF-TABLE-HEADER-ADLER32-MISMATCH",
            Self::TableEntryOutOfBounds { .. } => "EWF-TABLE-ENTRY-OUT-OF-BOUNDS",
            Self::TableEntryOutsideSectorsRange { .. } => "EWF-TABLE-ENTRY-OUTSIDE-SECTORS-RANGE",
            Self::SectionGapZero { .. } => "EWF-SECTION-GAP-ZERO",
            Self::HashMismatch { .. } => "EWF-HASH-MISMATCH",
            Self::HashSectionMissing => "EWF-HASH-SECTION-MISSING",
            Self::Table2Mismatch { .. } => "EWF-TABLE2-MISMATCH",
            Self::BadSectorsPresent { .. } => "EWF-BAD-SECTORS-PRESENT",
            Self::SegmentOutOfOrder { .. } => "EWF-SEGMENT-OUT-OF-ORDER",
            Self::DigestSha1Mismatch { .. } => "EWF-DIGEST-SHA1-MISMATCH",
            Self::DigestSha256Mismatch { .. } => "EWF-DIGEST-SHA256-MISMATCH",
            Self::ExternalMd5Mismatch { .. } => "EWF-EXTERNAL-MD5-MISMATCH",
            Self::ExternalSha1Mismatch { .. } => "EWF-EXTERNAL-SHA1-MISMATCH",
            Self::Ewf2SectionDataHashMismatch { .. } => "EWF-EWF2-SECTION-DATA-HASH-MISMATCH",
            Self::Ewf2EncryptedSection { .. } => "EWF-EWF2-ENCRYPTED-SECTION",
            Self::Ewf2HashSectionMissing => "EWF-EWF2-HASH-SECTION-MISSING",
            Self::VolumeBodyCrcMismatch { .. } => "EWF-VOLUME-BODY-CRC-MISMATCH",
            Self::MediaTypeUnknown { .. } => "EWF-MEDIA-TYPE-UNKNOWN",
            Self::SetIdentifierMismatch { .. } => "EWF-SET-IDENTIFIER-MISMATCH",
            Self::Ewf2MediaInfoMissing => "EWF-EWF2-MEDIA-INFO-MISSING",
            Self::Ewf2ChunkTableChecksumMismatch { .. } => "EWF-EWF2-CHUNK-TABLE-CHECKSUM-MISMATCH",
            Self::ChunkChecksumMismatch { .. } => "EWF-CHUNK-CHECKSUM-MISMATCH",
            Self::ChunkDecompressionError { .. } => "EWF-CHUNK-DECOMPRESSION-ERROR",
            Self::UnsupportedCompressionAlgorithm { .. } => "EWF-UNSUPPORTED-COMPRESSION-ALGORITHM",
            Self::ExternalSha256Mismatch { .. } => "EWF-EXTERNAL-SHA256-MISMATCH",
            Self::Ewf2MediaInfoParseFailed => "EWF-EWF2-MEDIA-INFO-PARSE-FAILED",
        }
    }
}

impl forensicnomicon::report::Observation for EwfIntegrityAnomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity())
    }
    fn code(&self) -> &'static str {
        self.code()
    }
    fn note(&self) -> String {
        self.to_string()
    }
}

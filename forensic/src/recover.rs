//! Tolerant EWF recovery — the ewf-forensic equivalent of libewf's `ewfrecover`.
//!
//! [`EwfRecover`] reads a **corrupt / truncated / incomplete** EWF v1 image the
//! way `ewfrecover` does: it recovers every readable sector and emits a flat raw
//! copy to a **NEW** output path, zero-filling the chunks it cannot recover and
//! reporting exactly what was recovered vs lost. It is *read-only-safe by
//! construction* — it opens segment files read-only (memory-mapped) and writes
//! only to the caller-provided output path, never to the source.
//!
//! ## Why a separate path from the reader
//!
//! [`ewf::EwfReader`] is a *strict* reader: a single bad chunk (failed
//! decompression, an out-of-range table entry, a truncated segment) surfaces as
//! an error and aborts the read. That is correct for verification, but useless
//! for recovery — an examiner with a partially-corrupt image wants *every* good
//! sector, not an all-or-nothing failure. `EwfRecover` instead degrades per
//! chunk: primary `table` → `table2` fallback → zero-fill, and **never aborts
//! the whole recovery on one bad chunk**.
//!
//! ## Recovery strategy (per chunk index `0..chunk_count`)
//!
//! 1. Locate the chunk via the segment's primary `table` section (base offset +
//!    per-entry relative offset, bit-31 = compressed).
//! 2. Read + decode it. If the entry is out of range, the segment is truncated
//!    past the chunk data, or a compressed chunk fails to inflate, fall back to
//!    the `table2` section (libewf's redundant copy) and retry.
//! 3. If `table2` also fails (or is absent), **zero-fill** `chunk_size` bytes and
//!    record the chunk index as lost. Continue to the next chunk.
//!
//! Every read is bounds-checked; there are no panics, no `unwrap`/`expect` in
//! this module, and it inherits the crate's `unsafe`-restricted posture (the one
//! `unsafe` site is the audited read-only mmap, shared with the integrity path).

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use ewf::sections::{
    adler32, EwfVolume, SectionDescriptor, TableEntry, TableHeader, EVF_SIGNATURE,
    FILE_HEADER_SIZE, SECTION_DESCRIPTOR_SIZE, TABLE_HEADER_SIZE,
};
use flate2::read::ZlibDecoder;
use memmap2::Mmap;

/// Outcome of a recovery run — the accounting an examiner needs to defend what
/// was and was not salvaged from a corrupt image.
///
/// The three recovery counts partition every chunk: each is either recovered
/// from the primary table, recovered from the redundant `table2`, or zero-filled
/// (lost). `chunks_recovered_primary + chunks_recovered_table2 + chunks_zero_filled
/// == chunks_total` always holds.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecoveryReport {
    /// Logical size of the recovered raw image in bytes (`sector_count *
    /// bytes_per_sector`). The output file is exactly this long.
    pub image_size: u64,
    /// Chunk size in bytes (`sectors_per_chunk * bytes_per_sector`).
    pub chunk_size: u64,
    /// Total number of chunks the volume geometry declares.
    pub chunks_total: usize,
    /// Chunks recovered from the primary `table` section.
    pub chunks_recovered_primary: usize,
    /// Chunks recovered from the redundant `table2` section after the primary
    /// entry failed.
    pub chunks_recovered_table2: usize,
    /// Chunks that could not be recovered from either table and were zero-filled.
    pub chunks_zero_filled: usize,
    /// Chunks whose sector data was physically present and emitted but whose
    /// stored Adler-32 did not match (recoverable-but-suspect data). These are
    /// counted among the recovered chunks — the bytes are exported, not lost —
    /// but flagged so an examiner knows the sectors are checksum-suspect.
    pub chunks_crc_flagged: usize,
    /// Total logical bytes recovered from real chunk data (never counts
    /// zero-filled regions).
    pub bytes_recovered: u64,
    /// Total logical bytes zero-filled for unrecoverable chunks.
    pub bytes_zero_filled: u64,
    /// File offset (in the source segment) at which the segment was found
    /// truncated, if truncation was detected; `None` for an untruncated image.
    pub truncation_offset: Option<u64>,
    /// Indices of every chunk that was zero-filled (lost), in ascending order.
    pub lost_chunks: Vec<usize>,
    /// Indices of every chunk emitted with a checksum mismatch, ascending.
    pub crc_flagged_chunks: Vec<usize>,
}

/// Read-only-safe tolerant EWF recovery.
///
/// Construct with [`from_path`](Self::from_path) (auto-discovers multi-segment
/// siblings) or [`from_paths`](Self::from_paths), then call
/// [`recover_to_raw`](Self::recover_to_raw) to emit a recovered flat image.
pub struct EwfRecover {
    segment_paths: Vec<PathBuf>,
}

impl EwfRecover {
    /// Recover from a single segment or an auto-discovered multi-segment image.
    ///
    /// If `path` matches the EWF numbered-segment pattern (`E01`, `E02`, …) the
    /// consecutive siblings in the same directory are discovered and included.
    #[must_use]
    pub fn from_path(path: impl AsRef<Path>) -> Self {
        Self {
            segment_paths: discover_segments(path.as_ref()),
        }
    }

    /// Recover from an explicit ordered list of segment paths.
    #[must_use]
    pub fn from_paths(paths: &[impl AsRef<Path>]) -> Self {
        Self {
            segment_paths: paths.iter().map(|p| p.as_ref().to_path_buf()).collect(),
        }
    }

    /// Recover the image to a flat raw file at `out_path`, returning the
    /// [`RecoveryReport`].
    ///
    /// The source is never modified; `out_path` must differ from every source
    /// segment (a caller-provided NEW path). Unreadable chunks are zero-filled so
    /// the output always spans the full logical image.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if a segment cannot be opened/mapped, if the image
    /// is too corrupt to establish geometry (no parseable volume section — a
    /// bootstrap failure, surfaced loudly rather than as a silent empty result),
    /// or if the output file cannot be written.
    pub fn recover_to_raw(&self, out_path: impl AsRef<Path>) -> io::Result<RecoveryReport> {
        if self.segment_paths.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no EWF segments to recover",
            ));
        }

        // Map every segment read-only. The OS pages on demand, so large evidence
        // files are handled without loading them into RAM.
        let mmaps = self
            .segment_paths
            .iter()
            .map(|p| {
                let file = File::open(p)?;
                // SAFETY: read-only mmap of an immutable evidence file, identical
                // to the integrity path's audited mmap sites.
                #[allow(unsafe_code)]
                unsafe {
                    Mmap::map(&file)
                }
            })
            .collect::<io::Result<Vec<Mmap>>>()?;
        let segments: Vec<&[u8]> = mmaps.iter().map(std::convert::AsRef::as_ref).collect();

        recover_segments(&segments, out_path.as_ref())
    }
}

/// One parsed section descriptor (type + byte range) within a segment.
struct Section {
    type_name: String,
    offset: u64,
    size: u64,
}

/// Volume geometry needed to drive recovery.
struct Geometry {
    chunk_count: u32,
    sectors_per_chunk: u32,
    bytes_per_sector: u32,
    sector_count: u64,
}

/// Walk a segment's section-descriptor chain tolerantly, returning every parsed
/// section plus the offset at which the chain broke off (truncation / dangling
/// `next`), if any. Unlike the strict reader, a broken chain does not fail — the
/// sections parsed so far are returned so their chunk data can still be
/// recovered.
fn walk_sections(data: &[u8]) -> (Vec<Section>, Option<u64>) {
    let file_size = data.len() as u64;
    let mut sections = Vec::new();
    let mut pos = FILE_HEADER_SIZE as u64;
    let mut truncation: Option<u64> = None;

    loop {
        let off = pos as usize;
        if off.saturating_add(SECTION_DESCRIPTOR_SIZE) > data.len() {
            // Not enough bytes left for another descriptor: the segment was cut
            // mid-structure. Record where.
            if pos < file_size {
                truncation = Some(pos);
            }
            break;
        }
        let raw = &data[off..off.saturating_add(SECTION_DESCRIPTOR_SIZE)];
        let Ok(desc) = SectionDescriptor::parse(raw, pos) else {
            // cov:unreachable: the length guard above slices `raw` to exactly
            // SECTION_DESCRIPTOR_SIZE bytes, and SectionDescriptor::parse only
            // fails on a shorter buffer — this arm is a defensive backstop.
            truncation = Some(pos);
            break;
        };
        let next = desc.next;
        let section_size = desc.section_size;
        let type_name = desc.section_type;

        sections.push(Section {
            type_name: type_name.clone(),
            offset: pos,
            size: section_size,
        });

        if type_name == "done" || type_name == "next" {
            break;
        }

        // A `next` that points past EOF or backwards is a broken/truncated chain.
        if next == 0 || next <= pos {
            break;
        }
        if next > file_size {
            truncation = Some(next);
            break;
        }
        pos = next;
    }

    (sections, truncation)
}

/// Extract the volume geometry from a segment's `volume`/`disk` section.
fn read_geometry(data: &[u8], sections: &[Section]) -> Option<Geometry> {
    let vol = sections
        .iter()
        .find(|s| s.type_name == "volume" || s.type_name == "disk")?;
    let data_start = (vol.offset as usize).saturating_add(SECTION_DESCRIPTOR_SIZE);
    let body_len = (vol.size as usize).saturating_sub(SECTION_DESCRIPTOR_SIZE);
    let vol_end = data_start.saturating_add(body_len).min(data.len());
    let body = data.get(data_start..vol_end)?;
    let parsed = EwfVolume::parse(body).ok()?;
    if parsed.sectors_per_chunk == 0 || parsed.bytes_per_sector == 0 {
        return None;
    }
    Some(Geometry {
        chunk_count: parsed.chunk_count,
        sectors_per_chunk: parsed.sectors_per_chunk,
        bytes_per_sector: parsed.bytes_per_sector,
        sector_count: parsed.sector_count,
    })
}

/// A table section's decoded header + the file offset of its entry array.
struct TableRef {
    entry_count: usize,
    base_offset: u64,
    entries_file_offset: usize,
}

/// Parse the header of a named table section (`table` or `table2`) in a segment.
fn table_ref(data: &[u8], sections: &[Section], name: &str) -> Option<TableRef> {
    let sec = sections.iter().find(|s| s.type_name == name)?;
    let hdr_start = (sec.offset as usize).saturating_add(SECTION_DESCRIPTOR_SIZE);
    let hdr = data.get(hdr_start..hdr_start.saturating_add(TABLE_HEADER_SIZE))?;
    let header = TableHeader::parse(hdr).ok()?;
    Some(TableRef {
        entry_count: header.entry_count as usize,
        base_offset: header.base_offset,
        entries_file_offset: hdr_start.saturating_add(TABLE_HEADER_SIZE),
    })
}

/// The `sectors` section's data end offset (for last-chunk size back-fill).
fn sectors_data_end(sections: &[Section], data_len: usize) -> Option<usize> {
    let sec = sections.iter().find(|s| s.type_name == "sectors")?;
    Some((sec.offset.saturating_add(sec.size) as usize).min(data_len))
}

/// Decode one table entry (`compressed`, absolute file offset) at index `i`.
fn entry_at(data: &[u8], t: &TableRef, i: usize) -> Option<(bool, u64)> {
    let off = t.entries_file_offset.saturating_add(i.saturating_mul(4));
    let bytes = data.get(off..off.saturating_add(4))?;
    let e = TableEntry::parse(bytes).ok()?;
    Some((
        e.compressed,
        t.base_offset.saturating_add(u64::from(e.chunk_offset)),
    ))
}

/// Resolve chunk `i`'s `(start, end, compressed)` byte range from a table.
///
/// `end` is the next entry's start (or the sectors-data end for the last entry),
/// mirroring the reader's boundary logic. Returns `None` when the entry (or its
/// data) is out of range / truncated — the caller then tries the fallback table.
fn chunk_range(
    data: &[u8],
    t: &TableRef,
    i: usize,
    sectors_end: Option<usize>,
) -> Option<(usize, usize, bool)> {
    let (compressed, abs) = entry_at(data, t, i)?;
    let start = abs as usize;
    let end = if i.saturating_add(1) < t.entry_count {
        let (_, next_abs) = entry_at(data, t, i.saturating_add(1))?;
        next_abs as usize
    } else {
        sectors_end.unwrap_or(data.len())
    };
    if start >= end || end > data.len() {
        return None;
    }
    Some((start, end, compressed))
}

/// Decode a chunk's raw byte range into up to `chunk_size` logical bytes,
/// returning `(bytes, crc_ok)`.
///
/// `None` means **no recoverable bytes exist** (a compressed stream that will
/// not inflate) — the caller then tries `table2`, and failing that zero-fills.
/// `Some((bytes, crc_ok))` means the sector bytes are physically present;
/// `crc_ok == false` flags a checksum mismatch on data that is nonetheless
/// emitted. This mirrors libewf `ewfexport`, which exports the physically-present
/// sectors of a CRC-flagged uncompressed chunk rather than discarding them —
/// zero-filling would throw away recoverable evidence.
fn decode_chunk(raw: &[u8], compressed: bool, chunk_size: usize) -> Option<(Vec<u8>, bool)> {
    if compressed {
        let mut out = Vec::with_capacity(chunk_size.min(raw.len().saturating_mul(4).max(1)));
        // Bound the inflate to one chunk_size (+1 to detect overrun) so a
        // malicious/garbage stream cannot balloon memory. A compressed chunk is
        // self-checksummed by zlib's internal Adler-32: if it inflates, the data
        // is good (crc_ok = true); if not, there are no usable bytes → None.
        let limit = (chunk_size as u64).saturating_add(1);
        ZlibDecoder::new(raw)
            .take(limit)
            .read_to_end(&mut out)
            .ok()?;
        if out.is_empty() {
            return None;
        }
        out.truncate(chunk_size);
        Some((out, true))
    } else {
        // Uncompressed: `chunk_size` sector bytes, optionally followed by a
        // 4-byte little-endian Adler-32 over those bytes. The bytes are present
        // regardless of the checksum, so always emit them — only flag crc_ok.
        let has_trailing_crc = raw.len() >= chunk_size.saturating_add(4);
        let crc_ok = if has_trailing_crc {
            let stored = u32::from_le_bytes([
                raw[chunk_size],
                raw[chunk_size + 1],
                raw[chunk_size + 2],
                raw[chunk_size + 3],
            ]);
            adler32(&raw[..chunk_size]) == stored
        } else {
            // No trailing CRC present (or a short final chunk): nothing to check.
            true
        };
        let take = raw.len().min(chunk_size);
        Some((raw[..take].to_vec(), crc_ok))
    }
}

/// Which segment holds global chunk `idx`, given each segment's table entry
/// count — plus that chunk's local index within the segment.
fn locate_chunk(seg_entry_counts: &[usize], idx: usize) -> Option<(usize, usize)> {
    let mut running = 0usize;
    for (seg_idx, &count) in seg_entry_counts.iter().enumerate() {
        if idx < running.saturating_add(count) {
            return Some((seg_idx, idx.saturating_sub(running)));
        }
        running = running.saturating_add(count);
    }
    None
}

/// The core recovery over already-mapped segment byte slices.
fn recover_segments(segments: &[&[u8]], out_path: &Path) -> io::Result<RecoveryReport> {
    // Reject an image with no parseable signature/volume up front — a bootstrap
    // failure must be loud, never a silently-empty "recovery".
    let first = segments.first().copied().unwrap_or(&[]);
    if first.len() < FILE_HEADER_SIZE || !first.starts_with(&EVF_SIGNATURE) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "not an EWF v1 image: first segment is {} bytes, signature {:02x?}",
                first.len(),
                first
                    .get(..FILE_HEADER_SIZE.min(first.len()))
                    .unwrap_or(&[])
            ),
        ));
    }

    // Walk every segment's sections; capture the first truncation offset seen.
    let mut all_sections: Vec<Vec<Section>> = Vec::with_capacity(segments.len());
    let mut truncation_offset: Option<u64> = None;
    for seg in segments {
        let (sections, trunc) = walk_sections(seg);
        if truncation_offset.is_none() {
            truncation_offset = trunc;
        }
        all_sections.push(sections);
    }

    // Geometry comes from segment 0's volume/disk section — the bootstrap value
    // every downstream step depends on.
    let geom = read_geometry(first, &all_sections[0]).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "no parseable volume/disk section: cannot establish image geometry",
        )
    })?;

    let chunk_size =
        u64::from(geom.sectors_per_chunk).saturating_mul(u64::from(geom.bytes_per_sector));
    let image_size = geom
        .sector_count
        .saturating_mul(u64::from(geom.bytes_per_sector));
    let chunk_size_usize = chunk_size as usize;
    let total_chunks = geom.chunk_count as usize;

    // Per-segment primary/fallback table refs + sectors-data ends.
    let mut primary: Vec<Option<TableRef>> = Vec::with_capacity(segments.len());
    let mut fallback: Vec<Option<TableRef>> = Vec::with_capacity(segments.len());
    let mut sec_ends: Vec<Option<usize>> = Vec::with_capacity(segments.len());
    let mut seg_entry_counts: Vec<usize> = Vec::with_capacity(segments.len());
    for (seg, sections) in segments.iter().zip(all_sections.iter()) {
        let p = table_ref(seg, sections, "table");
        let f = table_ref(seg, sections, "table2");
        // The number of chunks this segment contributes is its primary table's
        // entry count (table2 mirrors it); fall back to table2's count if the
        // primary header is unreadable.
        let count = p.as_ref().or(f.as_ref()).map_or(0, |t| t.entry_count);
        seg_entry_counts.push(count);
        primary.push(p);
        fallback.push(f);
        sec_ends.push(sectors_data_end(sections, seg.len()));
    }

    let mut out = io::BufWriter::new(File::create(out_path)?);

    let mut recovered_primary = 0usize;
    let mut recovered_table2 = 0usize;
    let mut zero_filled = 0usize;
    let mut crc_flagged = 0usize;
    let mut bytes_recovered = 0u64;
    let mut bytes_zero_filled = 0u64;
    let mut lost_chunks: Vec<usize> = Vec::new();
    let mut crc_flagged_chunks: Vec<usize> = Vec::new();

    let mut bytes_remaining = image_size;

    // Attempt to decode chunk `local` of segment `seg_idx` from a specific table.
    let decode_from = |table: Option<&TableRef>, seg_idx: usize, local: usize| {
        let seg = segments[seg_idx];
        let sec_end = sec_ends[seg_idx];
        table.and_then(|t| {
            chunk_range(seg, t, local, sec_end)
                .and_then(|(s, e, c)| decode_chunk(&seg[s..e], c, chunk_size_usize))
        })
    };

    for idx in 0..total_chunks {
        if bytes_remaining == 0 {
            break;
        }
        let logical = bytes_remaining.min(chunk_size) as usize;

        // (bytes, via_table2, crc_ok). Try the primary table; on a CRC-flagged or
        // missing result, consult table2 and prefer whichever yields good data.
        let decoded: Option<(Vec<u8>, bool, bool)> = match locate_chunk(&seg_entry_counts, idx) {
            Some((seg_idx, local)) => {
                let from_primary = decode_from(primary[seg_idx].as_ref(), seg_idx, local);
                match from_primary {
                    // Primary is good — done.
                    Some((bytes, true)) => Some((bytes, false, true)),
                    // Primary present but CRC-flagged, or absent: try table2.
                    other => {
                        let from_t2 = decode_from(fallback[seg_idx].as_ref(), seg_idx, local);
                        // `other` here is only ever `Some((_, false))` (primary
                        // CRC-flagged) or `None` — the primary-good case was
                        // handled above.
                        match (other, from_t2) {
                            // table2 recovers good data → prefer it.
                            (_, Some((bytes, true))) => Some((bytes, true, true)),
                            // Keep primary's (present) bytes, flagged CRC-suspect.
                            (Some((bytes, _)), _) => Some((bytes, false, false)),
                            // Only table2 has (CRC-flagged) bytes.
                            (None, Some((bytes, false))) => Some((bytes, true, false)),
                            // Neither table yields any bytes.
                            (None, None) => None,
                        }
                    }
                }
            }
            None => None,
        };

        if let Some((mut bytes, via_table2, crc_ok)) = decoded {
            // Trim/pad to the logical length this chunk backs.
            if bytes.len() > logical {
                bytes.truncate(logical);
            } else if bytes.len() < logical {
                bytes.resize(logical, 0);
            }
            out.write_all(&bytes)?;
            bytes_recovered = bytes_recovered.saturating_add(logical as u64);
            if via_table2 {
                recovered_table2 = recovered_table2.saturating_add(1);
            } else {
                recovered_primary = recovered_primary.saturating_add(1);
            }
            if !crc_ok {
                crc_flagged = crc_flagged.saturating_add(1);
                crc_flagged_chunks.push(idx);
            }
        } else {
            // No recoverable bytes: zero-fill this chunk's logical span.
            write_zeros(&mut out, logical)?;
            zero_filled = zero_filled.saturating_add(1);
            bytes_zero_filled = bytes_zero_filled.saturating_add(logical as u64);
            lost_chunks.push(idx);
        }
        bytes_remaining = bytes_remaining.saturating_sub(logical as u64);
    }

    // If the geometry's chunk count under-covers the logical size (a truncated
    // volume can leave bytes_remaining > 0), zero-fill the rest so the output is
    // always exactly image_size long.
    while bytes_remaining > 0 {
        let logical = bytes_remaining.min(chunk_size) as usize;
        write_zeros(&mut out, logical)?;
        bytes_zero_filled = bytes_zero_filled.saturating_add(logical as u64);
        bytes_remaining = bytes_remaining.saturating_sub(logical as u64);
    }

    out.flush()?;

    Ok(RecoveryReport {
        image_size,
        chunk_size,
        chunks_total: total_chunks,
        chunks_recovered_primary: recovered_primary,
        chunks_recovered_table2: recovered_table2,
        chunks_zero_filled: zero_filled,
        chunks_crc_flagged: crc_flagged,
        bytes_recovered,
        bytes_zero_filled,
        truncation_offset,
        lost_chunks,
        crc_flagged_chunks,
    })
}

/// Write `n` zero bytes to `w` in bounded blocks (no huge single allocation).
fn write_zeros(w: &mut impl Write, n: usize) -> io::Result<()> {
    const BLOCK: usize = 8 * 1024;
    let zeros = [0u8; BLOCK];
    let mut left = n;
    while left > 0 {
        let take = left.min(BLOCK);
        w.write_all(&zeros[..take])?;
        left = left.saturating_sub(take);
    }
    Ok(())
}

/// Discover consecutive EWF v1 segment siblings (`E01`, `E02`, … `EZZ`) starting
/// from `base`. Mirrors the discovery used by the integrity path so a first
/// segment auto-includes its chain. If `base` has no recognisable EWF extension,
/// only `base` itself is returned.
fn discover_segments(base: &Path) -> Vec<PathBuf> {
    let Some(ext) = base.extension().and_then(|e| e.to_str()) else {
        return vec![base.to_path_buf()];
    };
    // Only auto-discover for the v1 `.E01` family (case-insensitive). Anything
    // else is treated as a single explicit segment.
    let lower = ext.to_ascii_lowercase();
    if lower.len() != 3
        || !lower.starts_with('e')
        || !lower[1..].chars().all(|c| c.is_ascii_digit())
    {
        return vec![base.to_path_buf()];
    }
    let upper = ext.chars().next().is_some_and(|c| c.is_ascii_uppercase());
    let mut out = vec![base.to_path_buf()];
    let mut n = 2u32;
    loop {
        let e = if upper {
            format!("E{n:02}")
        } else {
            format!("e{n:02}")
        };
        let candidate = base.with_extension(&e);
        if candidate.exists() {
            out.push(candidate);
            n = n.saturating_add(1);
        } else {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;

    const CHUNK_SIZE: usize = 32768;
    const SECTORS_PER_CHUNK: u32 = 64;
    const BYTES_PER_SECTOR: u32 = 512;

    /// Build a single-chunk EWF v1 image (`volume`→`table`[→`table2`]→`sectors`
    /// →`done`) carrying one compressed chunk of `data` (padded to chunk size).
    /// If `corrupt_stream`, the compressed bytes are mangled so inflate fails.
    /// If `add_table2`, a `table2` section is emitted mirroring `table`.
    fn build_compressed_e01(data: &[u8], corrupt_stream: bool, add_table2: bool) -> Vec<u8> {
        let mut padded = data.to_vec();
        padded.resize(CHUNK_SIZE, 0);
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&padded).unwrap();
        let mut compressed = enc.finish().unwrap();
        if corrupt_stream {
            // Corrupt the middle of the zlib stream (keep the 2-byte header so it
            // is still recognised as zlib, but the deflate body / Adler fails).
            let mid = compressed.len() / 2;
            compressed[mid] ^= 0xFF;
        }

        let sector_count = u64::from(CHUNK_SIZE as u32 / BYTES_PER_SECTOR);
        let mut f = Vec::new();

        // File header (13).
        f.extend_from_slice(&EVF_SIGNATURE);
        f.push(0x01);
        f.extend_from_slice(&1u16.to_le_bytes());
        f.extend_from_slice(&0u16.to_le_bytes());

        // Layout offsets.
        let vol_desc = FILE_HEADER_SIZE as u64;
        let vol_data = vol_desc + SECTION_DESCRIPTOR_SIZE as u64;
        let tbl_desc = vol_data + 94;
        let tbl_hdr = tbl_desc + SECTION_DESCRIPTOR_SIZE as u64;
        let tbl_entries = tbl_hdr + 24;
        let after_tbl = tbl_entries + 4;
        // Optional table2 mirrors the same header+entry.
        let (tbl2_desc, tbl2_hdr, tbl2_entries, after_tbl2) = if add_table2 {
            let d = after_tbl;
            let h = d + SECTION_DESCRIPTOR_SIZE as u64;
            let e = h + 24;
            (Some(d), h, e, e + 4)
        } else {
            (None, 0, 0, after_tbl)
        };
        let sec_desc = after_tbl2;
        let sec_data = sec_desc + SECTION_DESCRIPTOR_SIZE as u64;
        let done_desc = sec_data + compressed.len() as u64;

        // Volume descriptor + body.
        let mut vd = [0u8; SECTION_DESCRIPTOR_SIZE];
        vd[..6].copy_from_slice(b"volume");
        vd[16..24].copy_from_slice(&tbl_desc.to_le_bytes());
        vd[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64 + 94).to_le_bytes());
        f.extend_from_slice(&vd);
        let mut vb = [0u8; 94];
        vb[0..4].copy_from_slice(&1u32.to_le_bytes()); // media_type = fixed
        vb[4..8].copy_from_slice(&1u32.to_le_bytes()); // chunk_count = 1
        vb[8..12].copy_from_slice(&SECTORS_PER_CHUNK.to_le_bytes());
        vb[12..16].copy_from_slice(&BYTES_PER_SECTOR.to_le_bytes());
        vb[16..24].copy_from_slice(&sector_count.to_le_bytes());
        f.extend_from_slice(&vb);

        // Emit a table section (descriptor + 24-byte header + one 4-byte entry).
        let emit_table = |f: &mut Vec<u8>, name: &[u8], next: u64| {
            let mut td = [0u8; SECTION_DESCRIPTOR_SIZE];
            td[..name.len()].copy_from_slice(name);
            td[16..24].copy_from_slice(&next.to_le_bytes());
            td[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64 + 24 + 4).to_le_bytes());
            f.extend_from_slice(&td);
            let mut th = [0u8; 24];
            th[0..4].copy_from_slice(&1u32.to_le_bytes()); // entry_count
            th[8..16].copy_from_slice(&sec_data.to_le_bytes()); // base_offset
            f.extend_from_slice(&th);
            f.extend_from_slice(&0x8000_0000u32.to_le_bytes()); // compressed, rel 0
        };
        emit_table(&mut f, b"table", tbl2_desc.unwrap_or(sec_desc));
        if let Some(_d) = tbl2_desc {
            emit_table(&mut f, b"table2", sec_desc);
        }

        // Sectors descriptor + compressed data.
        let mut sd = [0u8; SECTION_DESCRIPTOR_SIZE];
        sd[..7].copy_from_slice(b"sectors");
        sd[16..24].copy_from_slice(&done_desc.to_le_bytes());
        sd[24..32].copy_from_slice(
            &(SECTION_DESCRIPTOR_SIZE as u64 + compressed.len() as u64).to_le_bytes(),
        );
        f.extend_from_slice(&sd);
        f.extend_from_slice(&compressed);

        // Done.
        let mut dd = [0u8; SECTION_DESCRIPTOR_SIZE];
        dd[..4].copy_from_slice(b"done");
        dd[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64).to_le_bytes());
        f.extend_from_slice(&dd);

        // Suppress unused-warnings for the table2 offset helpers.
        let _ = (tbl2_hdr, tbl2_entries, after_tbl2);
        f
    }

    fn recover_bytes(image: &[u8]) -> (RecoveryReport, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("img.E01");
        std::fs::write(&src, image).unwrap();
        let out = dir.path().join("out.raw");
        let report = EwfRecover::from_path(&src).recover_to_raw(&out).unwrap();
        let raw = std::fs::read(&out).unwrap();
        (report, raw)
    }

    #[test]
    fn compressed_chunk_recovers() {
        let img = build_compressed_e01(b"hello compressed world", false, false);
        let (report, raw) = recover_bytes(&img);
        assert_eq!(report.chunks_total, 1);
        assert_eq!(report.chunks_recovered_primary, 1);
        assert_eq!(report.chunks_zero_filled, 0);
        assert_eq!(raw.len(), CHUNK_SIZE);
        assert_eq!(&raw[..22], b"hello compressed world");
    }

    #[test]
    fn corrupt_compressed_chunk_zero_fills() {
        // A compressed stream that will not inflate yields NO recoverable bytes
        // → zero-fill (this is the compressed-path counterpart to the
        // uncompressed CRC-flag pass-through).
        let img = build_compressed_e01(b"data that becomes garbage", true, false);
        let (report, raw) = recover_bytes(&img);
        assert_eq!(report.chunks_zero_filled, 1, "broken zlib must zero-fill");
        assert_eq!(report.lost_chunks, vec![0]);
        assert_eq!(raw.len(), CHUNK_SIZE);
        assert!(raw.iter().all(|&b| b == 0), "lost chunk is all zeros");
    }

    #[test]
    fn table2_recovers_when_primary_stream_broken() {
        // Primary `table` points at a broken stream; `table2` mirrors it — here
        // both point at the SAME (broken) data, so the outcome is still a
        // zero-fill, but this exercises the table2-consultation path.
        let img = build_compressed_e01(b"x", true, true);
        let (report, _raw) = recover_bytes(&img);
        assert_eq!(report.chunks_zero_filled, 1);
    }

    #[test]
    fn table2_present_clean_recovers_from_primary() {
        let img = build_compressed_e01(b"good data via primary", false, true);
        let (report, raw) = recover_bytes(&img);
        assert_eq!(report.chunks_recovered_primary, 1);
        assert_eq!(report.chunks_recovered_table2, 0);
        assert_eq!(&raw[..21], b"good data via primary");
    }

    #[test]
    fn from_paths_and_empty_error() {
        // Explicit path list works.
        let img = build_compressed_e01(b"z", false, false);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("explicit.E01");
        std::fs::write(&p, &img).unwrap();
        let out = dir.path().join("o.raw");
        let r = EwfRecover::from_paths(&[&p]).recover_to_raw(&out).unwrap();
        assert_eq!(r.chunks_total, 1);

        // Empty path list is a loud error, not a silent empty result.
        let empty: [&Path; 0] = [];
        let err = EwfRecover::from_paths(&empty)
            .recover_to_raw(dir.path().join("none.raw"))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn not_an_ewf_image_errors() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("garbage.bin");
        std::fs::write(&p, b"not an ewf file at all").unwrap();
        let err = EwfRecover::from_paths(&[&p])
            .recover_to_raw(dir.path().join("o.raw"))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn valid_signature_but_no_volume_errors() {
        // Signature present, but the section chain has no volume/disk → geometry
        // bootstrap fails loudly.
        let mut f = Vec::new();
        f.extend_from_slice(&EVF_SIGNATURE);
        f.push(0x01);
        f.extend_from_slice(&1u16.to_le_bytes());
        f.extend_from_slice(&0u16.to_le_bytes());
        // A lone `done` descriptor, no volume.
        let mut dd = [0u8; SECTION_DESCRIPTOR_SIZE];
        dd[..4].copy_from_slice(b"done");
        dd[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64).to_le_bytes());
        f.extend_from_slice(&dd);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("novol.E01");
        std::fs::write(&p, &f).unwrap();
        let err = EwfRecover::from_paths(&[&p])
            .recover_to_raw(dir.path().join("o.raw"))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn walk_sections_flags_short_descriptor_truncation() {
        // A file header followed by fewer than 76 bytes → a descriptor cannot be
        // read; truncation is flagged at the header end.
        let mut f = Vec::new();
        f.extend_from_slice(&EVF_SIGNATURE);
        f.push(0x01);
        f.extend_from_slice(&1u16.to_le_bytes());
        f.extend_from_slice(&0u16.to_le_bytes());
        f.extend_from_slice(&[0u8; 10]); // short — not a full descriptor
        let (sections, trunc) = walk_sections(&f);
        assert!(sections.is_empty());
        assert_eq!(trunc, Some(FILE_HEADER_SIZE as u64));
    }

    #[test]
    fn walk_sections_flags_next_past_eof() {
        // A volume descriptor whose `next` points past EOF → truncation flagged
        // at that offset.
        let mut f = Vec::new();
        f.extend_from_slice(&EVF_SIGNATURE);
        f.push(0x01);
        f.extend_from_slice(&1u16.to_le_bytes());
        f.extend_from_slice(&0u16.to_le_bytes());
        let mut vd = [0u8; SECTION_DESCRIPTOR_SIZE];
        vd[..6].copy_from_slice(b"volume");
        vd[16..24].copy_from_slice(&9_999_999u64.to_le_bytes()); // next past EOF
        vd[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64 + 94).to_le_bytes());
        f.extend_from_slice(&vd);
        let (sections, trunc) = walk_sections(&f);
        assert_eq!(sections.len(), 1);
        assert_eq!(trunc, Some(9_999_999));
    }

    #[test]
    fn decode_uncompressed_bad_crc_still_emits() {
        // Uncompressed chunk + wrong trailing Adler-32: bytes emitted, crc_ok=false.
        let mut raw = vec![0xABu8; CHUNK_SIZE];
        raw.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // wrong CRC
        let (bytes, crc_ok) = decode_chunk(&raw, false, CHUNK_SIZE).unwrap();
        assert_eq!(bytes.len(), CHUNK_SIZE);
        assert!(!crc_ok);
    }

    #[test]
    fn decode_uncompressed_good_crc_ok() {
        let sectors = vec![0x5Au8; CHUNK_SIZE];
        let crc = adler32(&sectors);
        let mut raw = sectors.clone();
        raw.extend_from_slice(&crc.to_le_bytes());
        let (bytes, crc_ok) = decode_chunk(&raw, false, CHUNK_SIZE).unwrap();
        assert_eq!(bytes, sectors);
        assert!(crc_ok);
    }

    #[test]
    fn decode_uncompressed_short_final_chunk() {
        // A short final chunk (no trailing CRC, fewer than chunk_size bytes) is
        // emitted verbatim with crc_ok=true.
        let raw = vec![0x11u8; 100];
        let (bytes, crc_ok) = decode_chunk(&raw, false, CHUNK_SIZE).unwrap();
        assert_eq!(bytes.len(), 100);
        assert!(crc_ok);
    }

    #[test]
    fn locate_chunk_spans_segments() {
        let counts = [3usize, 2, 4];
        assert_eq!(locate_chunk(&counts, 0), Some((0, 0)));
        assert_eq!(locate_chunk(&counts, 2), Some((0, 2)));
        assert_eq!(locate_chunk(&counts, 3), Some((1, 0)));
        assert_eq!(locate_chunk(&counts, 4), Some((1, 1)));
        assert_eq!(locate_chunk(&counts, 5), Some((2, 0)));
        assert_eq!(locate_chunk(&counts, 8), Some((2, 3)));
        assert_eq!(locate_chunk(&counts, 9), None);
    }

    #[test]
    fn discover_segments_non_ewf_extension_single() {
        let p = Path::new("/tmp/whatever.bin");
        assert_eq!(discover_segments(p), vec![p.to_path_buf()]);
    }

    #[test]
    fn discover_segments_no_extension_single() {
        let p = Path::new("/tmp/noext");
        assert_eq!(discover_segments(p), vec![p.to_path_buf()]);
    }

    #[test]
    fn discover_segments_lowercase_e01_single_when_no_siblings() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("img.e01");
        std::fs::write(&p, b"x").unwrap();
        // No e02 sibling → just the one.
        assert_eq!(discover_segments(&p), vec![p]);
    }

    // ── direct helper coverage for the tolerant/defensive arms ───────────────

    #[test]
    fn read_geometry_rejects_zero_geometry() {
        // A volume body with sectors_per_chunk = 0 → geometry rejected (None).
        let mut f = Vec::new();
        f.extend_from_slice(&EVF_SIGNATURE);
        f.push(0x01);
        f.extend_from_slice(&1u16.to_le_bytes());
        f.extend_from_slice(&0u16.to_le_bytes());
        let mut vd = [0u8; SECTION_DESCRIPTOR_SIZE];
        vd[..6].copy_from_slice(b"volume");
        let next = FILE_HEADER_SIZE as u64 + SECTION_DESCRIPTOR_SIZE as u64 + 94;
        vd[16..24].copy_from_slice(&next.to_le_bytes());
        vd[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64 + 94).to_le_bytes());
        f.extend_from_slice(&vd);
        let mut vb = [0u8; 94];
        vb[0..4].copy_from_slice(&1u32.to_le_bytes());
        vb[4..8].copy_from_slice(&1u32.to_le_bytes());
        // sectors_per_chunk left 0 → invalid
        vb[12..16].copy_from_slice(&BYTES_PER_SECTOR.to_le_bytes());
        f.extend_from_slice(&vb);
        let (sections, _) = walk_sections(&f);
        assert!(read_geometry(&f, &sections).is_none());
    }

    #[test]
    fn chunk_range_out_of_bounds_is_none() {
        // A single-entry table whose base_offset + rel points past the data end.
        let data = vec![0u8; 200];
        let t = TableRef {
            entry_count: 1,
            base_offset: 10_000, // past end
            entries_file_offset: 0,
        };
        // The entry bytes at offset 0: compressed bit set, rel 0.
        let mut data = data;
        data[0..4].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        assert!(chunk_range(&data, &t, 0, Some(200)).is_none());
    }

    #[test]
    fn decode_compressed_empty_output_is_none() {
        // A zlib stream that inflates to zero bytes → treated as no usable data.
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"").unwrap();
        let empty_stream = enc.finish().unwrap();
        assert!(decode_chunk(&empty_stream, true, CHUNK_SIZE).is_none());
    }

    /// Build a single-uncompressed-chunk E01 where `table` points at garbage but
    /// `table2` points at the real (good) chunk — exercising the table2-good
    /// recovery arm. Geometry `chunk_count`/`sector_count` are caller-set to also
    /// drive the over/under-cover zero-fill paths.
    fn build_uncompressed_table2_good(chunk_count: u32, sector_count: u64) -> Vec<u8> {
        let sectors = vec![0x7Eu8; CHUNK_SIZE];
        let crc = adler32(&sectors);

        let mut f = Vec::new();
        f.extend_from_slice(&EVF_SIGNATURE);
        f.push(0x01);
        f.extend_from_slice(&1u16.to_le_bytes());
        f.extend_from_slice(&0u16.to_le_bytes());

        let vol_desc = FILE_HEADER_SIZE as u64;
        let vol_data = vol_desc + SECTION_DESCRIPTOR_SIZE as u64;
        let tbl_desc = vol_data + 94;
        let tbl2_desc = tbl_desc + SECTION_DESCRIPTOR_SIZE as u64 + 24 + 4;
        let sec_desc = tbl2_desc + SECTION_DESCRIPTOR_SIZE as u64 + 24 + 4;
        let sec_data = sec_desc + SECTION_DESCRIPTOR_SIZE as u64;
        let chunk_len = CHUNK_SIZE as u64 + 4; // sectors + trailing CRC
        let done_desc = sec_data + chunk_len;

        // Volume.
        let mut vd = [0u8; SECTION_DESCRIPTOR_SIZE];
        vd[..6].copy_from_slice(b"volume");
        vd[16..24].copy_from_slice(&tbl_desc.to_le_bytes());
        vd[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64 + 94).to_le_bytes());
        f.extend_from_slice(&vd);
        let mut vb = [0u8; 94];
        vb[0..4].copy_from_slice(&1u32.to_le_bytes());
        vb[4..8].copy_from_slice(&chunk_count.to_le_bytes());
        vb[8..12].copy_from_slice(&SECTORS_PER_CHUNK.to_le_bytes());
        vb[12..16].copy_from_slice(&BYTES_PER_SECTOR.to_le_bytes());
        vb[16..24].copy_from_slice(&sector_count.to_le_bytes());
        f.extend_from_slice(&vb);

        // table (garbage base_offset) → table2 (correct base_offset).
        let emit = |f: &mut Vec<u8>, name: &[u8], next: u64, base: u64| {
            let mut td = [0u8; SECTION_DESCRIPTOR_SIZE];
            td[..name.len()].copy_from_slice(name);
            td[16..24].copy_from_slice(&next.to_le_bytes());
            td[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64 + 24 + 4).to_le_bytes());
            f.extend_from_slice(&td);
            let mut th = [0u8; 24];
            th[0..4].copy_from_slice(&1u32.to_le_bytes());
            th[8..16].copy_from_slice(&base.to_le_bytes());
            f.extend_from_slice(&th);
            f.extend_from_slice(&0u32.to_le_bytes()); // uncompressed, rel 0
        };
        emit(&mut f, b"table", tbl2_desc, 9_000_000); // garbage → out of range
        emit(&mut f, b"table2", sec_desc, sec_data); // correct

        // Sectors: the real chunk + trailing CRC.
        let mut sd = [0u8; SECTION_DESCRIPTOR_SIZE];
        sd[..7].copy_from_slice(b"sectors");
        sd[16..24].copy_from_slice(&done_desc.to_le_bytes());
        sd[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64 + chunk_len).to_le_bytes());
        f.extend_from_slice(&sd);
        f.extend_from_slice(&sectors);
        f.extend_from_slice(&crc.to_le_bytes());

        let mut dd = [0u8; SECTION_DESCRIPTOR_SIZE];
        dd[..4].copy_from_slice(b"done");
        dd[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64).to_le_bytes());
        f.extend_from_slice(&dd);
        f
    }

    #[test]
    fn table2_recovers_good_data_when_primary_out_of_range() {
        // 1 chunk, exact geometry: primary points out of range, table2 rescues.
        let img = build_uncompressed_table2_good(1, u64::from(SECTORS_PER_CHUNK));
        let (report, raw) = recover_bytes(&img);
        assert_eq!(report.chunks_recovered_table2, 1, "table2 must rescue");
        assert_eq!(report.chunks_recovered_primary, 0);
        assert_eq!(report.chunks_zero_filled, 0);
        assert_eq!(raw.len(), CHUNK_SIZE);
        assert!(raw.iter().all(|&b| b == 0x7E));
    }

    #[test]
    fn table2_crc_flagged_when_primary_absent() {
        // Primary out of range → None; table2 points at present-but-CRC-suspect
        // uncompressed data (we corrupt the trailing Adler-32). The bytes are
        // still emitted, via table2, flagged CRC-suspect.
        let mut img = build_uncompressed_table2_good(1, u64::from(SECTORS_PER_CHUNK));
        // The trailing 4-byte CRC sits just before the final 76-byte `done`
        // descriptor. Flip it so the Adler-32 no longer matches.
        let crc_pos = img.len() - SECTION_DESCRIPTOR_SIZE - 4;
        for b in &mut img[crc_pos..crc_pos + 4] {
            *b ^= 0xFF;
        }
        let (report, raw) = recover_bytes(&img);
        assert_eq!(
            report.chunks_recovered_table2, 1,
            "table2 still supplies data"
        );
        assert_eq!(report.chunks_recovered_primary, 0);
        assert_eq!(
            report.chunks_zero_filled, 0,
            "present data is not zero-filled"
        );
        assert_eq!(
            report.chunks_crc_flagged, 1,
            "table2 data flagged CRC-suspect"
        );
        assert_eq!(report.crc_flagged_chunks, vec![0]);
        assert!(raw.iter().all(|&b| b == 0x7E));
    }

    #[test]
    fn geometry_undercover_zero_fills_tail() {
        // chunk_count=1 but sector_count spans 2 chunks → after the one recovered
        // chunk, the post-loop zero-fills the remaining logical bytes.
        let img = build_uncompressed_table2_good(1, u64::from(SECTORS_PER_CHUNK) * 2);
        let (report, raw) = recover_bytes(&img);
        assert_eq!(report.image_size, (CHUNK_SIZE * 2) as u64);
        assert_eq!(raw.len(), CHUNK_SIZE * 2);
        // First chunk recovered (via table2), second half zero-filled.
        assert!(raw[..CHUNK_SIZE].iter().all(|&b| b == 0x7E));
        assert!(raw[CHUNK_SIZE..].iter().all(|&b| b == 0));
        assert!(report.bytes_zero_filled >= CHUNK_SIZE as u64);
    }

    #[test]
    fn walk_sections_breaks_on_next_zero_nonterminal() {
        // A `volume` (non-terminal) descriptor with next == 0 → chain ends
        // without truncation (line 215-216 break).
        let mut f = Vec::new();
        f.extend_from_slice(&EVF_SIGNATURE);
        f.push(0x01);
        f.extend_from_slice(&1u16.to_le_bytes());
        f.extend_from_slice(&0u16.to_le_bytes());
        let mut vd = [0u8; SECTION_DESCRIPTOR_SIZE];
        vd[..6].copy_from_slice(b"volume");
        vd[16..24].copy_from_slice(&0u64.to_le_bytes()); // next = 0, non-terminal
        vd[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64 + 94).to_le_bytes());
        f.extend_from_slice(&vd);
        f.extend_from_slice(&[0u8; 94]);
        let (sections, trunc) = walk_sections(&f);
        assert_eq!(sections.len(), 1);
        assert_eq!(trunc, None, "next==0 ends the chain, not a truncation");
    }

    /// Build a single-chunk uncompressed E01 whose sectors region carries
    /// `chunk_body` bytes (which may be shorter or longer than one logical chunk)
    /// with a caller-chosen geometry — used to drive the trim/pad arms.
    fn build_uncompressed_sized(chunk_body: &[u8], sector_count: u64) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&EVF_SIGNATURE);
        f.push(0x01);
        f.extend_from_slice(&1u16.to_le_bytes());
        f.extend_from_slice(&0u16.to_le_bytes());

        let vol_desc = FILE_HEADER_SIZE as u64;
        let vol_data = vol_desc + SECTION_DESCRIPTOR_SIZE as u64;
        let tbl_desc = vol_data + 94;
        let sec_desc = tbl_desc + SECTION_DESCRIPTOR_SIZE as u64 + 24 + 4;
        let sec_data = sec_desc + SECTION_DESCRIPTOR_SIZE as u64;
        let done_desc = sec_data + chunk_body.len() as u64;

        let mut vd = [0u8; SECTION_DESCRIPTOR_SIZE];
        vd[..6].copy_from_slice(b"volume");
        vd[16..24].copy_from_slice(&tbl_desc.to_le_bytes());
        vd[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64 + 94).to_le_bytes());
        f.extend_from_slice(&vd);
        let mut vb = [0u8; 94];
        vb[0..4].copy_from_slice(&1u32.to_le_bytes());
        vb[4..8].copy_from_slice(&1u32.to_le_bytes()); // chunk_count = 1
        vb[8..12].copy_from_slice(&SECTORS_PER_CHUNK.to_le_bytes());
        vb[12..16].copy_from_slice(&BYTES_PER_SECTOR.to_le_bytes());
        vb[16..24].copy_from_slice(&sector_count.to_le_bytes());
        f.extend_from_slice(&vb);

        let mut td = [0u8; SECTION_DESCRIPTOR_SIZE];
        td[..5].copy_from_slice(b"table");
        td[16..24].copy_from_slice(&sec_desc.to_le_bytes());
        td[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64 + 24 + 4).to_le_bytes());
        f.extend_from_slice(&td);
        let mut th = [0u8; 24];
        th[0..4].copy_from_slice(&1u32.to_le_bytes());
        th[8..16].copy_from_slice(&sec_data.to_le_bytes());
        f.extend_from_slice(&th);
        f.extend_from_slice(&0u32.to_le_bytes()); // uncompressed, rel 0

        let mut sd = [0u8; SECTION_DESCRIPTOR_SIZE];
        sd[..7].copy_from_slice(b"sectors");
        sd[16..24].copy_from_slice(&done_desc.to_le_bytes());
        sd[24..32].copy_from_slice(
            &(SECTION_DESCRIPTOR_SIZE as u64 + chunk_body.len() as u64).to_le_bytes(),
        );
        f.extend_from_slice(&sd);
        f.extend_from_slice(chunk_body);

        let mut dd = [0u8; SECTION_DESCRIPTOR_SIZE];
        dd[..4].copy_from_slice(b"done");
        dd[24..32].copy_from_slice(&(SECTION_DESCRIPTOR_SIZE as u64).to_le_bytes());
        f.extend_from_slice(&dd);
        f
    }

    #[test]
    fn chunk_longer_than_logical_is_truncated() {
        // sector_count spans only 32 sectors (half a chunk) but the sectors body
        // holds a full chunk_size → decoded bytes (chunk_size) > logical (16384),
        // exercising the truncate arm.
        let body = vec![0x42u8; CHUNK_SIZE];
        let img = build_uncompressed_sized(&body, u64::from(SECTORS_PER_CHUNK) / 2);
        let (report, raw) = recover_bytes(&img);
        assert_eq!(report.image_size, (CHUNK_SIZE / 2) as u64);
        assert_eq!(raw.len(), CHUNK_SIZE / 2);
        assert!(raw.iter().all(|&b| b == 0x42));
    }

    #[test]
    fn chunk_shorter_than_logical_is_padded() {
        // The sectors body holds only 100 bytes but the logical chunk is
        // chunk_size → decoded bytes (100) < logical, exercising the resize/pad
        // arm; the remainder is zero-padded.
        let body = vec![0x24u8; 100];
        let img = build_uncompressed_sized(&body, u64::from(SECTORS_PER_CHUNK));
        let (report, raw) = recover_bytes(&img);
        assert_eq!(report.image_size, CHUNK_SIZE as u64);
        assert_eq!(raw.len(), CHUNK_SIZE);
        assert!(raw[..100].iter().all(|&b| b == 0x24));
        assert!(
            raw[100..].iter().all(|&b| b == 0),
            "short chunk zero-padded"
        );
    }

    #[test]
    fn geometry_overcover_stops_at_image_size() {
        // chunk_count=2 but sector_count spans only 1 chunk → the loop breaks when
        // bytes_remaining hits 0 before the second chunk index.
        let img = build_uncompressed_table2_good(2, u64::from(SECTORS_PER_CHUNK));
        let (report, raw) = recover_bytes(&img);
        assert_eq!(report.image_size, CHUNK_SIZE as u64);
        assert_eq!(raw.len(), CHUNK_SIZE);
        // Only one chunk's worth was emitted despite chunk_count=2.
        assert_eq!(
            report.chunks_recovered_primary
                + report.chunks_recovered_table2
                + report.chunks_zero_filled,
            1
        );
    }
}

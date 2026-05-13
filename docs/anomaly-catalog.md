# Detection Capability and Threat Model

ewf-forensic runs seven analysis layers against the raw bytes of an EWF v1 (E01) segment file and returns every structural, geometric, and cryptographic anomaly it finds. This document maps those anomalies to the real-world scenarios that produce them — distinguishing accidental corruption, anti-forensic manipulation, and crafted-input attacks against the parser itself.

The library cannot determine intent. Accidental corruption and deliberate tampering can produce identical anomalies. That determination is the analyst's job. The library's job is to ensure nothing is missed.

---

## Threat Actors and Goals

| Actor | Goal | Primary signals |
|-------|------|-----------------|
| Evidence tamperer | Modify sector content after acquisition | `HashMismatch` |
| Evidence suppressor | Prevent the image from being read | `InvalidSignature`, `VolumeSectionMissing`, `SectionChainBroken` |
| Data concealer | Hide information outside the standard chain | `SectionGapNonZero`, `SectionGapZero`, `UnknownSectionType` |
| Evidence redirector | Make forensic tools reconstruct the wrong filesystem | `BytesPerSectorInvalid`, `ChunkSizeInvalid`, `TableEntryOutOfBounds`, `TableEntryOutsideSectorsRange` |
| Parser attacker | Crash or OOM the forensic workstation | `SectionChainBroken` (cycle), `TableEntryOutOfBounds` |
| Anti-forensic evader | Make tampering look clean to naive tools | recomputed Adler-32, MD5 collision |
| Storage / acquisition failure | No malicious intent | any anomaly, especially `DoneSectionMissing` |

---

## Scenario 1 — Evidence Suppression

The goal is to make the image unreadable or unanalysable — either preventing examination entirely, or forcing the analyst to declare the evidence unusable.

### `InvalidSignature` — header bytes overwritten

**What it means:** The first 8 bytes of a well-formed E01 are always `45 56 46 09 0D 0A FF 00` (the EVF magic). Any deviation is flagged as Critical.

**How it's done:**
- Zero the magic bytes to make the file look empty.
- Replace with the magic of another format (e.g., a ZIP header) to redirect forensic tools to the wrong parser.
- Flip a single bit — enough to defeat signature-based detection while keeping the rest of the structure intact.

**Accidental cause:** Physical damage to the start of the file, filesystem corruption, or overwrite by another process.

**Analyst action:** Even with an invalid signature, the rest of the structure may still be intact. Continue reading the findings — a single `InvalidSignature` alongside an otherwise clean report suggests media corruption rather than intentional forgery.

---

### `VolumeSectionMissing` — geometry metadata deleted

**What it means:** Neither a `volume` nor a `disk` section was found in the chain. The volume section defines `chunk_count`, `sectors_per_chunk`, `bytes_per_sector`, and `sector_count` — without it, the image cannot be reconstructed into addressable sectors.

**How it's done:**
- Overwrite the volume section descriptor's type field with garbage, causing it to be skipped as an unknown section type (also produces `UnknownSectionType`).
- Set the `next` pointer in the section preceding the volume to skip over it, unlinking it from the chain without modifying its bytes.
- Physically delete the bytes and rewrite the preceding section's `next` pointer.

**Accidental cause:** Severe corruption of the volume section descriptor.

**Analyst action:** If the sectors data is still physically present in the file, the sector body can often be recovered by locating it directly (the sectors section is typically the largest contiguous block). The absence of geometry metadata does not mean the sector data is gone.

---

### `SectionChainBroken` — chain terminated early

**What it means:** A section's `next` pointer is `0`, past EOF, or points backward — any of which causes the chain walk to stop. Sections after the break point are invisible to the parser.

**How it's done:**
- Set `next = 0` or `next = 0xFFFFFFFFFFFFFFFF` to immediately terminate traversal.
- Set `next` to a value just past the actual file size.
- Truncate the file after a specific section to remove everything that follows.

The break point can be carefully chosen: an attacker who wants to hide a specific file that was deleted from the imaged drive could corrupt the chain after the sectors section, making that sector range unreachable from the table.

**Accidental cause:** Write interruption during acquisition, storage media failure, filesystem corruption after the E01 was written.

**Analyst action:** Note `at_offset` — the last successfully parsed section — and `next_offset`. If `next_offset` is within the file, the section data may still be physically present at that location even though the chain is broken. Manual inspection at that offset is warranted.

---

### `DoneSectionMissing` — acquisition never completed cleanly

**What it means:** A well-formed E01 ends with a `done` section whose `next` field points to itself. Absence means either the acquisition was interrupted, the file was truncated after the fact, or the `done` section was deliberately removed.

**Accidental cause:** Power failure, process termination, or storage full during acquisition. This is the most common non-malicious cause.

**Analyst action:** Check whether a `SectionChainBroken` accompanies this — if the chain also breaks, the interruption happened mid-write. If the chain is otherwise intact and only `done` is missing, the removal may have been deliberate.

---

## Scenario 2 — Evidence Modification

The goal is to alter the content of the imaged drive — adding, changing, or removing files — while keeping the E01 structurally plausible.

### `HashMismatch` — sector data was changed

**What it means:** The MD5 computed by decompressing each chunk (zlib where bit 31 is set, raw otherwise) and hashing exactly `sector_count × bytes_per_sector` bytes does not match the 16-byte digest stored in the `hash` section. This is the primary tamper indicator.

**How it's done:**

**Case A — Sectors modified, hash not updated:**
The attacker modifies sector data directly (e.g., to overwrite a file they want to hide) and does not update the stored hash. Detected immediately: computed ≠ stored.

**Case B — Sectors modified, hash updated to match:**
The attacker modifies sector data and recomputes a valid MD5 over the new sectors body, storing the new hash. The hash now verifies correctly — `HashMismatch` is NOT reported. This case requires a supplementary hash over the full image using a stronger algorithm (SHA-256, BLAKE3) to detect. See [Limitations](#limitations).

**Case C — Hash modified, sectors unchanged:**
The attacker modifies only the 16 bytes of the stored hash — perhaps to invalidate the image's admissibility. Detected: computed (correct MD5 over untouched sectors) ≠ stored (the forged value).

**Case D — Both modified inconsistently:**
Attacker modifies both sectors and hash but makes an error (wrong offset, byte order, alignment). Detected.

**Accidental cause:** Bit-rot on the storage device holding the E01; transmission error that corrupted the sectors section but not the hash section or vice versa.

**Analyst action:** This is the highest-priority finding after structural checks. Document the `computed` and `stored` values verbatim. Do not repair. Preserve both the original and any working copies as separate exhibits.

ewf-forensic deliberately classifies `HashMismatch` as `CannotRepair` — the library cannot determine which value is authoritative. That is a human decision.

---

### `SectorCountMismatch` — geometry edited to hide sector count

**What it means:** The volume section declares a `sector_count` that does not equal `chunk_count × sectors_per_chunk`. This arithmetic invariant must hold in a valid image.

**How it's done:** An attacker who adds or removes chunks from the sectors section must update the geometry fields. If they update `chunk_count` (in the volume section and the table) but forget to recalculate `sector_count`, or if they set `sector_count` to a value that implies more or fewer sectors than the chunk structure actually contains, this is detected.

**Accidental cause:** Bug in the acquisition tool's geometry calculation, particularly for drives with non-standard sector sizes.

---

## Scenario 3 — Evidence Insertion and Concealment

The goal is to embed data in the E01 that was not part of the original acquisition — either to plant evidence or to use the forensic image as a covert channel.

### `SectionGapNonZero` — hidden data between sections

**What it means:** In a clean E01, consecutive sections are contiguous — the `next` pointer of section *n* equals `section_n_offset + section_n_size`. If `next > section_end` and the bytes in that gap are non-zero, data exists outside the section chain.

**How it's done:** An attacker extends a section's `next` pointer beyond its actual data, then writes arbitrary bytes into the gap region. Naive parsers that only follow the chain never inspect those bytes. The gap can contain anything: a deleted file, encryption keys, exfiltrated data, or a secondary E01 embedded in the gap.

Note: A gap filled with zero bytes is **not** flagged. If the gap was deliberately zeroed, the payload has been removed (or the gap was never used). Only non-zero gaps are reported.

**Accidental cause:** Alignment padding by some acquisition tools. However, no standard EWF v1 implementation pads with non-zero bytes.

**Analyst action:** Extract the bytes from `gap_offset` to `gap_offset + gap_size` and examine them as a separate exhibit. Apply file carving and entropy analysis.

---

### `UnknownSectionType` — non-standard section injected

**What it means:** A section's type field contains a string not in the EWF v1 specification. The 16 known types are: `header`, `header2`, `volume`, `disk`, `table`, `table2`, `sectors`, `hash`, `digest`, `error2`, `session`, `done`, `next`, `data`, `ltree`, `ltreedata`.

**How it's done:** An attacker adds a custom section to the chain (giving it a valid CRC so the descriptor verifies) and uses it to carry a payload — metadata about the tampering operation, an exfiltrated key, or additional data. Some non-standard acquisition tools produce legitimate unknown sections; context matters.

**Accidental cause:** Acquisition tool using a vendor extension not defined in the public specification.

**Analyst action:** Inspect the section body at `offset + 76` bytes. If the section type looks like a vendor name or tool identifier, check whether it corresponds to the acquisition software listed in the case log. If it does not match, treat it as suspect.

---

## Scenario 4 — Evidence Redirection

The goal is to make forensic tools reconstruct the wrong filesystem, causing them to present artefacts that do not reflect the original media.

### `BytesPerSectorInvalid` — LBA mapping corrupted

**What it means:** `bytes_per_sector` in the volume section is not 512 or 4096 (the only values valid for standard EWF v1).

**How it's done:** Set `bytes_per_sector` to an arbitrary value (e.g., 1024, 2048, 8192). Tools that use this value to convert LBAs to byte offsets will read sector data at wrong positions, reconstructing a filesystem that looks internally consistent but does not reflect the original drive. A forensic examiner may conclude the filesystem is corrupt when in fact the geometry field was tampered with.

**Accidental cause:** Non-standard source media (e.g., optical drives, some SSDs) with unusual sector sizes, or acquisition tool bugs.

---

### `ChunkSizeInvalid` — chunk boundary misalignment

**What it means:** `sectors_per_chunk` is zero or not a power of two.

**How it's done:** Set `sectors_per_chunk` to a value like 3, 7, or 63. Any parser that uses this for chunk boundary calculations produces misaligned reads. Because chunk boundaries determine where the decompressor expects compressed chunk data to begin, even a single-sector misalignment propagates to corrupted output across the entire image.

**Accidental cause:** Acquisition tool bug or deliberate use of a non-standard chunk geometry that the reading tool does not support.

---

### `TableChunkCountMismatch` — conflicting chunk counts

**What it means:** The table section's `entry_count` field differs from the `chunk_count` in the volume section. These must agree in a valid image.

**How it's done:**
- Increase `entry_count` in the table: the extra entries point to attacker-controlled offsets, redirecting specific chunk reads.
- Decrease `entry_count`: some chunks become inaccessible from the table, effectively hiding those sectors from tools that rely on the table for navigation.
- Modify `chunk_count` in the volume: alters the declared total drive size without touching the actual sector data.

**Analyst action:** Treat the table and the volume counts as separately sourced values. Document both. If `in_table > in_volume`, the extra entries warrant inspection — they may point outside the sectors section.

---

### `TableEntryOutOfBounds` — chunk pointer beyond file end

**What it means:** A table entry's absolute chunk offset (base_offset + relative_offset) is ≥ file_size. The chunk it references does not exist within the file.

**How it's done:**
- Set a specific entry's relative offset to a large value to make that chunk unreadable — effectively hiding whatever was at that LBA range on the original drive.
- Set `base_offset` itself to a value near u64::MAX so all entries resolve beyond EOF.
- Target parsers that do not validate entry offsets: the out-of-bounds dereference may trigger a buffer over-read or crash.

**Analyst action:** Note which `chunk_index` values are out-of-bounds. Cross-reference with the volume geometry to determine which LBA ranges are affected. Those LBAs may contain evidence the attacker wants suppressed.

---

### `SegmentNumberZero` — header field zeroed

**What it means:** The 2-byte segment number at file offset 9 is 0. Valid E01 files start at segment 1.

**How it's done:** Zeroing this field alone has limited effect on most parsers but may confuse tools that use it to order multi-segment acquisitions. More commonly seen in isolation when only the header was partially overwritten.

---

### `SectionDescriptorCrcMismatch` — descriptor checksum wrong

**What it means:** The Adler-32 checksum over the first 72 bytes of a section descriptor does not match the stored 4-byte checksum at bytes [72..76].

**How it's done:**
- **After modifying a descriptor field:** Any post-acquisition edit to a descriptor (type, next, size, or padding bytes) invalidates the Adler-32. If the attacker does not recompute the checksum, this is detected immediately.
- **Recomputed checksum after modification:** If the attacker recomputes the Adler-32 over their modified descriptor, it verifies correctly and this anomaly is NOT reported. The modification would only be detectable through an external hash over the full image.
- **Accidental:** Storage bit-rot affecting the descriptor bytes.

**Repair caveat:** ewf-forensic can repair a `SectionDescriptorCrcMismatch` by recomputing the correct Adler-32. This is appropriate for benign corruption. However, if the CRC was deliberately left wrong (e.g., an attacker modified the descriptor but chose not to update the checksum, intending to create a false signal of corruption), repairing it destroys the only evidence that the descriptor was tampered with. Always document the `computed` and `stored` values before repairing, and do not repair on an original exhibit — only on a working copy.

---

## Scenario 5 — Parser Exploitation

An E01 presented to a forensic workstation is an untrusted input. An attacker who controls the evidence medium (or the transfer chain) can craft an E01 specifically to compromise the analyst's machine through the forensic parser.

ewf-forensic is safe against all of the following — verified by libfuzzer across 4.5 M iterations with zero panics. They are documented here because other EWF parsers, including older versions of [ewf](https://github.com/SecurityRonin/ewf), may be vulnerable.

### Cyclic chain — OOM / infinite loop

**Mechanism:** Set any non-`done` section's `next` field to point to an earlier offset, forming a cycle. A parser without cycle detection follows `A → B → C → B → C → …` indefinitely, appending to its section list until OOM.

**ewf-forensic defence:** `walk_sections` requires `next > pos` at every step. Any backward or same-offset pointer immediately produces `SectionChainBroken` and exits the loop. Fuzz-confirmed: the OOM corpus entry was reproduced and the cycle was caught in the first iteration.

---

### Deflate bomb — header decompression OOM

**Mechanism:** Craft the zlib-compressed `header` section with extreme compression ratio (e.g., 1 MB compressed → 1 GB output using repeated patterns). Parsers that decompress with `collect::<Vec<u8>>()` — no output size limit — OOM on the decompressed buffer.

**ewf-forensic:** Decompresses sector chunks during hash verification, but each chunk is read through `ZlibDecoder::take(chunk_size + 1)` — capping output to one chunk's worth of data. A deflate bomb in a chunk body produces at most `sectors_per_chunk × bytes_per_sector + 1` bytes before the decompressor is dropped. Not vulnerable to OOM.

**ewf (fixed):** `flate2::read::ZlibDecoder::take(10 MB)` limits output. Fixed in the security backport from this project.

---

### entry_count capacity attack — Vec::with_capacity OOM

**Mechanism:** Set the `error2` section's entry_count field to `u32::MAX`. Parsers that call `Vec::with_capacity(entry_count)` before any per-entry bounds check attempt a ~32 GB allocation.

**ewf-forensic:** Does not parse `error2` section data during analysis. Not vulnerable.

**ewf (fixed):** Capacity capped by `data.len() / entry_size`. Fixed in the security backport from this project.

---

### Out-of-bounds table entry — buffer over-read / crash

**Mechanism:** Craft a table entry whose resolved absolute offset is within the file but points into a section descriptor rather than sector data. Parsers that use table entries to drive decompressor seeks may read structured EWF metadata as compressed chunk data, producing an invalid zlib stream — typically a crash or error cascade.

**ewf-forensic detection:** `TableEntryOutOfBounds` fires for any entry resolving ≥ file_size. `TableEntryOutsideSectorsRange` fires for entries that are within the file but outside `[sectors_data_start, sectors_section_end)` — catching redirects into section descriptors, the table itself, or the hash section.

---

## Limitations

### MD5 is cryptographically broken

EWF v1 stores an MD5 digest in the `hash` section. MD5 chosen-prefix collision construction is feasible on consumer hardware in minutes. A sufficiently resourced adversary can:

1. Modify sector data to alter the forensic evidence.
2. Construct a new sectors body with the same MD5 as the original using a chosen-prefix collision.
3. Store the original MD5 in the `hash` section.

The hash now verifies correctly — `HashMismatch` is not reported. ewf-forensic cannot detect a valid MD5 collision.

**Mitigation:** Compute and archive an independent SHA-256 or BLAKE3 manifest over the full E01 at acquisition time (e.g., with [blazehash](https://github.com/SecurityRonin/blazehash)). Store the manifest separately from the image. Verify both at analysis time.

---

### Single-segment scope

ewf-forensic analyses one segment file at a time. Multi-segment acquisitions (`.E01`, `.E02`, `.E03` …) require each segment to be validated independently. The library does not check cross-segment consistency: a table in `.E01` pointing into `.E02` cannot be validated here.

---

### Sector content is not inspected beyond hash verification

The library decompresses each chunk and hashes the resulting sector data to verify the stored MD5. It does not parse filesystem structures within those sectors. It cannot identify which specific LBA ranges were modified, detect filesystem-level tampering (e.g., journal manipulation, MFT entry modification), or identify what data was changed. That analysis requires a full EWF reader such as [ewf](https://github.com/SecurityRonin/ewf).

---

### Recomputed Adler-32 does not prove the descriptor is unmodified

If an attacker modifies a section descriptor field and then recomputes the Adler-32 over the modified bytes, the descriptor verifies correctly. Only an external hash over the full image — taken at acquisition time and verified now — can detect this. `SectionDescriptorCrcMismatch` catches the lazy attacker; it does not catch the careful one.

---

### Recomputed Adler-32 does not prove the descriptor is structurally intact

If an attacker rewrites a table entry's absolute offset to point somewhere inside the file — but outside the sectors data body — the Adler-32 CRC on the section descriptor is unaffected and will not catch the redirect. Layer 6 now detects this case as `TableEntryOutsideSectorsRange` (Error), which fires when a chunk offset resolves inside the file but outside `[sectors_data_start, sectors_data_start + sectors_data_size)`. This catches entries pointing into header descriptors, the table itself, or the hash section.

---

### Zero-byte inter-section gaps

Zero-filled bytes between consecutive sections are now flagged as `SectionGapZero` (Info). While zero-gap padding is sometimes produced legitimately by alignment-conscious acquisition tools, the gap's existence is worth noting — an attacker who zeroed a payload region before removing it leaves a structurally visible trace. Analysts should investigate any gap, zero or not, against the expected section layout for the acquisition tool that produced the image.

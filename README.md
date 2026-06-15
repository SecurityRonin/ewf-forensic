<p align="center">
  <h1 align="center">ewf-forensic</h1>
  <p align="center">Forensic integrity analysis for EWF / E01 images</p>
</p>

[![Crates.io](https://img.shields.io/crates/v/ewf-forensic.svg)](https://crates.io/crates/ewf-forensic)
[![docs.rs](https://img.shields.io/docsrs/ewf-forensic)](https://docs.rs/ewf-forensic)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/ewf-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/ewf-forensic/actions/workflows/ci.yml)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Verify the image. Trust the evidence.**

`ewf-forensic` is a pure-Rust integrity analyser for EWF images — no `libewf`, no C toolchain, no build complexity. It supports EWF v1 (E01 multi-segment with sibling auto-discovery), EWF v2 (Ex01/Lx01), SHA-1 and SHA-256 from digest sections, chain-of-custody external hash comparison (MD5, SHA-1, SHA-256), and optional header metadata extraction.

The analyser reports exactly what is structurally wrong across eight layers: signature forgery, broken section chains, cyclic chain attacks, Adler-32 descriptor corruption, volume geometry inconsistencies, table mismatches, out-of-bounds chunk pointers, MD5/SHA-1/SHA-256 hash mismatches, per-chunk checksum errors, and EWF v2 per-section data integrity. 40 distinct anomaly types across four severity levels.

---

## Install

```toml
[dependencies]
ewf-forensic = "0.4"
```

Optional Serde support for serialising anomalies and progress events to JSON:

```toml
ewf-forensic = { version = "0.4", features = ["serde"] }
```

---

## What It Checks

### Layer 1 — File Header

| Anomaly | Severity |
|---------|----------|
| `InvalidSignature` — EVF magic bytes corrupted or absent | **Critical** |
| `SegmentNumberZero` — segment number field is 0 (invalid) | Error |

### Layer 2 — Section Descriptor Integrity

| Anomaly | Severity |
|---------|----------|
| `SectionDescriptorCrcMismatch { offset, section_type, computed, stored }` — Adler-32 over descriptor bytes [0..72] does not match stored checksum | Error |

### Layer 3 — Section Chain

| Anomaly | Severity |
|---------|----------|
| `SectionChainBroken { at_offset, next_offset }` — `next` pointer is zero, past EOF, or points backward (cycle) | **Critical** |
| `SectionGapNonZero { gap_offset, gap_size }` — non-zero bytes exist between consecutive sections | Warning |
| `SectionGapZero { gap_offset, gap_size }` — zero-filled bytes between sections (alignment padding; noted as structural anomaly) | Info |

### Layer 4 — Section Completeness

| Anomaly | Severity |
|---------|----------|
| `VolumeSectionMissing` — neither `volume` nor `disk` section found | **Critical** |
| `SectorsSectionMissing` — no `sectors` section found; sector data absent | Error |
| `TableSectionMissing` — no `table` section found; chunk index unusable | Error |
| `UnknownSectionType { offset, type_name }` — section type string not in the EWF v1 spec | Warning |
| `DoneSectionMissing` — chain ends without a `done` section | Warning |

### Layer 5 — Volume Geometry

| Anomaly | Severity |
|---------|----------|
| `BytesPerSectorInvalid { bytes_per_sector }` — not 512 or 4 096 | Error |
| `VolumeBodyCrcMismatch { computed, stored }` — Adler-32 over volume section body does not match (EWF v2) | Error |
| `ChunkSizeInvalid { sectors_per_chunk, bytes_per_sector }` — zero or not a power of two | Error |
| `SectorCountMismatch { declared, expected }` — `sector_count` is outside the valid range; last-chunk padding is normal and not flagged | Error |
| `MediaTypeUnknown { media_type }` — `media_type` byte is not a recognised EWF v2 value | Warning |
| `SetIdentifierMismatch { segment, expected }` — set GUID in segment header does not match the first segment (EWF v2 multi-segment) | Error |

### Layer 6 — Table Integrity

| Anomaly | Severity |
|---------|----------|
| `TableChunkCountMismatch { in_volume, in_table }` — entry count in table header differs from volume | Error |
| `TableHeaderAdler32Mismatch { computed, stored }` — Adler-32 over table header bytes does not match stored checksum | Error |
| `Table2Mismatch { chunk_index, offset_in_table, offset_in_table2 }` — `table` and `table2` entries disagree for the same chunk index | Error |
| `TableEntryOutOfBounds { chunk_index, entry_offset, file_size }` — chunk offset resolves past EOF | Error |
| `TableEntryOutsideSectorsRange { chunk_index, entry_offset, sectors_start, sectors_end }` — entry resolves inside the file but outside the sectors data body | Error |
| `Ewf2ChunkTableChecksumMismatch { segment, computed, stored }` — EWF v2 chunk table Adler-32 does not match | Error |
| `ChunkChecksumMismatch { chunk_index, computed, stored }` — per-chunk Adler-32 (appended after uncompressed chunk data) does not match | Error |
| `ChunkDecompressionError { chunk_index }` — compressed chunk cannot be decompressed (corrupt DEFLATE stream) | Error |
| `UnsupportedCompressionAlgorithm { chunk_index, algorithm }` — compression method is not deflate | Error |

### Layer 7 — Hash Verification

| Anomaly | Severity |
|---------|----------|
| `HashMismatch { computed, stored }` — MD5 of all sector data does not match stored hash | Error |
| `HashSectionMissing` — no `hash` section found | Warning |
| `DigestSha1Mismatch { computed, stored }` — SHA-1 of all sector data does not match `digest` section | Error |
| `DigestSha256Mismatch { computed, stored }` — SHA-256 of all sector data does not match `digest` section | Error |
| `BadSectorsPresent { count }` — `error2` section reports unreadable sectors at acquisition time | Warning |

### Layer 8 — Multi-segment and External Reference

| Anomaly | Severity |
|---------|----------|
| `SegmentOutOfOrder { segment_number, expected }` — supplied segments are not in sequential order | Error |
| `ExternalMd5Mismatch { computed, expected }` — computed MD5 does not match externally-supplied chain-of-custody hash | **Critical** |
| `ExternalSha1Mismatch { computed, expected }` — computed SHA-1 does not match externally-supplied reference | **Critical** |
| `ExternalSha256Mismatch { computed, expected }` — computed SHA-256 does not match externally-supplied reference | **Critical** |

### EWF v2 — Per-section and Media Integrity

| Anomaly | Severity |
|---------|----------|
| `Ewf2SectionDataHashMismatch { offset, section_type_id, computed, stored }` — MD5 of section body does not match `data_integrity_hash` in the descriptor | Error |
| `Ewf2EncryptedSection { offset }` — encrypted section found; content cannot be verified | Warning |
| `Ewf2HashSectionMissing` — no hash section (type 0x08 or 0x09) in the final segment | Warning |
| `Ewf2MediaInfoMissing` — no media_info section found in the image | Warning |
| `Ewf2MediaInfoParseFailed` — media_info section body is not a valid zlib stream | Error |

---

## Usage

### Analyse an E01 file (recommended path-based API)

```rust
use ewf_forensic::{EwfIntegrityPath, Severity};

fn main() -> std::io::Result<()> {
    // Pass only the .E01 — siblings E02, E03 … are auto-discovered.
    let findings = EwfIntegrityPath::from_path("evidence.E01").analyse()?;

    if findings.is_empty() {
        println!("clean — no anomalies detected");
        return Ok(());
    }

    for anomaly in &findings {
        let tag = match anomaly.severity() {
            Severity::Critical => "[CRITICAL]",
            Severity::Error    => "[ERROR]   ",
            Severity::Warning  => "[WARNING] ",
            Severity::Info     => "[INFO]    ",
        };
        println!("{tag} {anomaly}");
    }
    Ok(())
}
```

### In-memory API (e.g., when you already have the bytes)

```rust
use ewf_forensic::{EwfIntegrity, Severity};

let data = std::fs::read("evidence.E01").unwrap();
let findings = EwfIntegrity::new(&data).analyse();
```

### Multi-segment image — explicit paths

```rust
use ewf_forensic::EwfIntegrityPath;

let findings = EwfIntegrityPath::from_paths(&[
    "evidence.E01",
    "evidence.E02",
    "evidence.E03",
]).analyse()?;
```

### Verify against a chain-of-custody hash

```rust
use ewf_forensic::EwfIntegrityPath;

let coc_md5:    [u8; 16] = /* bytes from acquisition report */;
let coc_sha256: [u8; 32] = /* bytes from acquisition report */;

// ExternalMd5Mismatch / ExternalSha256Mismatch (Critical) fire if image was altered.
let findings = EwfIntegrityPath::from_path("evidence.E01")
    .with_expected_md5(coc_md5)
    .with_expected_sha256(coc_sha256)
    .analyse()?;
```

### Compute hashes independently

```rust
use ewf_forensic::EwfIntegrityPath;

// Returns None if the image is not a valid EWF.
if let Some(hashes) = EwfIntegrityPath::from_path("evidence.E01").compute_hashes()? {
    println!("MD5:    {:x?}", hashes.md5);
    println!("SHA-1:  {:x?}", hashes.sha1);
    println!("SHA-256:{:x?}", hashes.sha256);
}
```

### Single-pass: analyse and compute hashes together

```rust
use ewf_forensic::EwfIntegrityPath;

let (anomalies, hashes) = EwfIntegrityPath::from_path("evidence.E01")
    .analyse_and_compute_hashes()?;
// Both results from a single read pass — useful for large images.
```

### Progress callback (long images, pipelines)

```rust
use ewf_forensic::{EwfIntegrityPath, AnalysisProgress};

let (anomalies, ()) = EwfIntegrityPath::from_path("evidence.E01")
    .analyse_with_progress(|p: AnalysisProgress| {
        if let Some(total) = p.chunks_total {
            eprint!("\r{}/{} chunks", p.chunks_done, total);
        }
    })?;
```

### Read acquisition metadata from the header

```rust
use ewf_forensic::{EwfIntegrity, EwfHeaderMetadata};

let data = std::fs::read("evidence.E01").unwrap();
if let Some(meta) = EwfIntegrity::new(&data).header_metadata() {
    println!("Examiner:  {}", meta.examiner_name);
    println!("Acquired:  {}", meta.acquisition_date);
    println!("Case:      {}", meta.case_number);
}
```

### Triage by severity

```rust
use ewf_forensic::{EwfIntegrityPath, Severity};

let findings = EwfIntegrityPath::from_path("evidence.E01").analyse()?;

let critical: Vec<_> = findings.iter()
    .filter(|a| a.severity() == Severity::Critical)
    .collect();

if !critical.is_empty() {
    eprintln!("{} critical finding(s) — image may be unreadable or tampered", critical.len());
}
```

### Serde — serialise findings to JSON

```toml
ewf-forensic = { version = "0.4", features = ["serde"] }
```

```rust
use ewf_forensic::EwfIntegrityPath;

let findings = EwfIntegrityPath::from_path("evidence.E01").analyse()?;
let json = serde_json::to_string_pretty(&findings).unwrap();
println!("{json}");
```

---

## CLI — `ewf-check`

```
ewf-check [OPTIONS] <segment>...

ARGUMENTS
    <segment>...    One or more segment paths. When a single .E01 is given,
                    consecutive siblings are discovered automatically.

OPTIONS
    --min-severity=<level>    Only report anomalies at or above this level.
                              Levels: info, warning, error, critical [default: info]
    --json                    Emit machine-readable JSON.
    --hash-md5=<hex>          Compare computed MD5 against this hex string.
    --hash-sha1=<hex>         Compare computed SHA-1 against this hex string.
    --hash-sha256=<hex>       Compare computed SHA-256 against this hex string.
    --print-hashes            Compute and print MD5, SHA-1, and SHA-256.
    --progress                Show a progress bar on stderr during analysis.
    --help / --version

EXIT CODES
    0   Clean — no anomalies at or above --min-severity
    1   Anomalies found
    2   Usage error or I/O failure
```

Example: verify an 8-segment acquisition against an external hash manifest:

```bash
ewf-check --hash-md5=2692f3177a389e58906b5c9080aa1add evidence.E01
# auto-discovers evidence.E02 … evidence.E08
```

---

## Design

- **File-based API uses memory-mapped I/O** — `EwfIntegrityPath` mmaps each segment rather than reading it into a `Vec<u8>`. Large images (100 GB+) do not require 100 GB of RAM.
- **No unsafe code in ewf-forensic** — the crate itself contains no `unsafe` blocks. `memmap2` wraps the OS mmap syscall but its unsafety is isolated to that dependency.
- **No panics on adversarial input** — every parser path is bounded; cycle attacks and integer overflows are explicitly handled. Verified by libfuzzer (4.5 M iterations, zero crashes) and proptest (property-based, runs in `cargo test`).
- **Validated against 11 committed real-world fixtures** — seven acquisition-tool images (EWF v1 and EWF v2, all confirmed clean by `ewfverify`), plus CTF and sleuthkit test-corpus images including structurally invalid zero-byte inputs. See [docs/validation.md](docs/validation.md) for image sources and reproduction steps.
- **MSRV 1.85** — no nightly, no unstable features.

---

## Fuzzing

```bash
cargo +nightly fuzz run fuzz_integrity
cargo +nightly fuzz run fuzz_repair
```

Both targets run in CI for 30 seconds on every push. To run longer locally, remove `-max_total_time`.

---

## Anomaly Catalog

[`docs/anomaly-catalog.md`](docs/anomaly-catalog.md) maps every detectable anomaly to its threat scenario — evidence suppression, modification, insertion, redirection, and parser exploitation — and documents known detection limits.

---

## Limitations

### MD5 is cryptographically broken

EWF v1 stores an MD5 digest in the `hash` section. MD5 chosen-prefix collisions are feasible on consumer hardware. A sufficiently resourced adversary can modify sector data, construct a new sectors body with the same MD5, and store the original hash — `HashMismatch` is not reported. ewf-forensic cannot detect a valid MD5 collision.

**Mitigation:** Supply `--hash-sha256` (or `.with_expected_sha256()`) with a SHA-256 computed at acquisition time and stored separately from the image.

### Sector content not inspected beyond hash verification

The analyser decompresses and hashes every chunk but does not parse filesystem structures within those sectors. It cannot identify which specific LBA ranges were modified, detect filesystem-level tampering (MFT manipulation, journal editing), or report what changed. That requires a full EWF reader such as [ewf](https://github.com/SecurityRonin/ewf).

### Recomputed Adler-32 does not prove a descriptor is unmodified

If an attacker modifies a section descriptor field and recomputes the Adler-32 over the modified bytes, the descriptor verifies correctly. Only an external hash over the full image taken at acquisition time can detect this. `SectionDescriptorCrcMismatch` catches the lazy attacker; it does not catch the careful one.

### EWF v2 encrypted sections are not verified

When `Ewf2EncryptedSection` is reported, the section body is skipped. Content inside an encrypted section cannot be integrity-checked. If every data section is encrypted, the analyser provides structural checks only.

### Progress callbacks report `chunks_total = None` for EWF v1

EWF v1 does not declare the total chunk count in a header field — it is discovered by walking the section chain. `AnalysisProgress.chunks_total` is `None` during EWF v1 analysis and `Some(n)` during EWF v2 analysis where the chunk table declares its entry count up front.

### FTK Imager and X-Ways real-fixture tests are deferred

`tool_fixtures_tests` includes tests against real `ftk_imager_clean.E01` and `xways_clean.E01` fixtures. These are marked `#[ignore]` because the acquisition tools are Windows-only and not available in CI. The format variations they exercise are covered by always-on synthetic builder tests.

---

[Privacy Policy](https://securityronin.github.io/ewf-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/ewf-forensic/terms/) · © 2026 Security Ronin Ltd

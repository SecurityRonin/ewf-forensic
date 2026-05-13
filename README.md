<p align="center">
  <h1 align="center">ewf-forensic</h1>
  <p align="center">Forensic integrity analysis and repair for EWF / E01 images</p>
</p>

[![Crates.io](https://img.shields.io/crates/v/ewf-forensic.svg)](https://crates.io/crates/ewf-forensic)
[![docs.rs](https://img.shields.io/docsrs/ewf-forensic)](https://docs.rs/ewf-forensic)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/ewf-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/ewf-forensic/actions/workflows/ci.yml)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Verify the image. Trust the evidence.**

`ewf-forensic` is a pure-Rust integrity analyser and in-memory repair engine for EWF images — no `libewf`, no C toolchain, no build complexity. It supports EWF v1 (E01/E02/E03 multi-segment), EWF v2 (Ex01/Lx01), SHA-1 from digest sections, and chain-of-custody external hash comparison.

The analyser reports exactly what is structurally wrong across eight layers: signature forgery, broken section chains, cyclic chain attacks, Adler-32 descriptor corruption, volume geometry inconsistencies, table mismatches, out-of-bounds chunk pointers, MD5/SHA-1 hash mismatches, and EWF v2 per-section data integrity checks. Section descriptor CRC errors are repairable in-memory — patched bytes written to a fresh buffer, original untouched. Hash mismatches are surfaced as `CannotRepair` so you decide what to do next.

---

## Install

```toml
[dependencies]
ewf-forensic = "0.1"
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
| `SectionGapZero { gap_offset, gap_size }` — zero-filled bytes exist between consecutive sections (legitimate in alignment-padded images; noted as structural anomaly) | Info |

### Layer 4 — Section Completeness

| Anomaly | Severity |
|---------|----------|
| `VolumeSectionMissing` — neither `volume` nor `disk` section found | **Critical** |
| `UnknownSectionType { offset, type_name }` — section type string not in the EWF v1 spec | Warning |
| `DoneSectionMissing` — chain ends without a `done` section | Warning |

### Layer 5 — Volume Geometry

| Anomaly | Severity |
|---------|----------|
| `BytesPerSectorInvalid { bytes_per_sector }` — not 512 or 4 096 | Error |
| `ChunkSizeInvalid { sectors_per_chunk, bytes_per_sector }` — zero or not a power of two | Error |
| `SectorCountMismatch { declared, expected }` — `sector_count` is outside the valid range `((chunk_count−1)×spc, chunk_count×spc]`; last-chunk padding is normal and not flagged | Error |

### Layer 6 — Table Integrity

| Anomaly | Severity |
|---------|----------|
| `TableChunkCountMismatch { in_volume, in_table }` — entry count in table header differs from volume | Error |
| `TableEntryOutOfBounds { chunk_index, entry_offset, file_size }` — chunk offset resolves past EOF | Error |
| `TableEntryOutsideSectorsRange { chunk_index, entry_offset, sectors_start, sectors_end }` — entry resolves inside the file but outside the sectors data body (e.g., into a descriptor or the table itself) | Error |

### Layer 7 — Hash Verification

| Anomaly | Severity |
|---------|----------|
| `HashMismatch { computed, stored }` — MD5 of decompressed sector data does not match stored hash | Error |
| `HashSectionMissing` — no `hash` section found | Warning |
| `DigestSha1Mismatch { computed, stored }` — computed SHA-1 of all sector data does not match the SHA-1 stored in the `digest` section | Error |

### Layer 8 — Multi-segment and External Reference

| Anomaly | Severity |
|---------|----------|
| `SegmentOutOfOrder { segment_number, expected }` — supplied segments are not in sequential order | Error |
| `ExternalMd5Mismatch { computed, expected }` — computed MD5 does not match an externally-supplied chain-of-custody hash | **Critical** |
| `ExternalSha1Mismatch { computed, expected }` — computed SHA-1 does not match an externally-supplied reference | **Critical** |

### EWF v2 — Per-section Integrity

| Anomaly | Severity |
|---------|----------|
| `Ewf2SectionDataHashMismatch { offset, section_type_id, computed, stored }` — MD5 of section body does not match `data_integrity_hash` in the descriptor | Error |
| `Ewf2EncryptedSection { offset }` — encrypted section found; content cannot be verified | Warning |
| `Ewf2HashSectionMissing` — no hash section (type 0x08 or 0x09) found in the final segment | Warning |

---

## Usage

### Analyse an E01 image

```rust
use ewf_forensic::{EwfIntegrity, Severity};

fn main() -> std::io::Result<()> {
    let data = std::fs::read("evidence.E01")?;
    let findings = EwfIntegrity::new(&data).analyse();

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
        println!("{tag} {anomaly:?}");
    }
    Ok(())
}
```

### Triage by severity

```rust
use ewf_forensic::{EwfIntegrity, Severity};

let data = std::fs::read("evidence.E01").unwrap();
let findings = EwfIntegrity::new(&data).analyse();

let critical: Vec<_> = findings.iter()
    .filter(|a| a.severity() == Severity::Critical)
    .collect();

if !critical.is_empty() {
    eprintln!("{} critical finding(s) — image may be unreadable", critical.len());
}
```

### Analyse a multi-segment image (E01, E02, E03 …)

```rust
use ewf_forensic::EwfIntegrity;

let seg1 = std::fs::read("evidence.E01").unwrap();
let seg2 = std::fs::read("evidence.E02").unwrap();
let seg3 = std::fs::read("evidence.E03").unwrap();

let findings = EwfIntegrity::from_segments(&[&seg1, &seg2, &seg3]).analyse();
```

### Verify against a chain-of-custody hash

```rust
use ewf_forensic::EwfIntegrity;

let data = std::fs::read("evidence.E01").unwrap();
let coc_md5: [u8; 16] = [/* hash from acquisition report */];

let findings = EwfIntegrity::new(&data)
    .with_expected_md5(coc_md5)
    .analyse();
// ExternalMd5Mismatch (Critical) fires if the image has been altered.
```

### Repair in-memory (non-destructive)

`EwfRepair` never touches your original file. It applies only safe mechanical fixes (Adler-32 recomputation) and returns a patched buffer per segment alongside a full audit trail of what was repaired and what could not be.

```rust
use ewf_forensic::{EwfIntegrity, EwfRepair};

let original = std::fs::read("evidence.E01").unwrap();
let report = EwfRepair::new(original.clone()).repair();

// What was fixed automatically
for r in &report.repairs {
    println!("repaired: {r:?}");
}

// What still needs human review
for c in &report.cannot_repair {
    println!("cannot repair: {c:?}");
}

// Verify the patched image is now clean
let post = EwfIntegrity::new(&report.segments[0]).analyse();
assert!(post.iter().all(|a| !matches!(
    a,
    ewf_forensic::EwfIntegrityAnomaly::SectionDescriptorCrcMismatch { .. }
)));

// Write the repaired copy — original is untouched
std::fs::write("evidence_repaired.E01", &report.segments[0]).unwrap();
```

### What is and is not repairable

| Anomaly | Repairable? | Reason |
|---------|:-----------:|--------|
| `SectionDescriptorCrcMismatch` | Yes | Adler-32 is deterministically recomputed from the bytes already present |
| `HashMismatch` | No | Cannot determine whether the sector data or the stored hash is authoritative |
| All others | No | Structural damage requires analyst judgement |

---

## Design

- **Zero allocation on clean images** — the analyser returns an empty `Vec` and touches no heap beyond the slice you hand it.
- **No unsafe code** — `ewf_forensic` itself contains no `unsafe` blocks.
- **No panics on adversarial input** — every parser path is bounded; cycle attacks and integer overflows are explicitly handled. Verified by libfuzzer (4.5 M iterations, zero crashes).
- **Validated against real acquisitions** — zero false positives across three public E01 fixtures (exFAT, email corpus, MMLS) with full MD5 hash verification including per-chunk zlib decompression. Three small images are committed as test fixtures and run in CI. See [docs/VALIDATION.md](docs/VALIDATION.md) for image sources, download URLs, and reproduction steps.
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

[Privacy Policy](https://securityronin.github.io/ewf-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/ewf-forensic/terms/) · © 2026 Security Ronin Ltd

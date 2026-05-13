<p align="center">
  <h1 align="center">ewf-forensic</h1>
  <p align="center">Forensic integrity analysis and repair for EWF / E01 images</p>
</p>

[![Crates.io](https://img.shields.io/crates/v/ewf-forensic.svg)](https://crates.io/crates/ewf-forensic)
[![docs.rs](https://img.shields.io/docsrs/ewf-forensic)](https://docs.rs/ewf-forensic)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/ewf-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/ewf-forensic/actions/workflows/ci.yml)
[![Rust 1.82+](https://img.shields.io/badge/rust-1.82%2B-orange.svg)](https://www.rust-lang.org)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Verify the image. Trust the evidence.**

`ewf-forensic` is a zero-dependency\* Rust library that reads raw EWF v1 (E01) bytes and reports exactly what is wrong — and what can be fixed automatically — without modifying your original evidence.

It detects signature forgery, broken section chains, cyclic chain attacks, Adler-32 descriptor corruption, volume geometry inconsistencies, table mismatches, out-of-bounds chunk pointers, and MD5 hash mismatches across seven distinct analysis layers. Section descriptor CRC errors are repairable in-memory; hash mismatches are surfaced as `CannotRepair` so you decide what to do next.

\* `md-5` is the only runtime dependency.

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

### Repair in-memory (non-destructive)

`EwfRepair` never touches your original file. It clones the bytes, applies only safe mechanical fixes (Adler-32 recomputation), and returns the patched buffer alongside a full audit trail of what was repaired and what could not be.

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
let post = EwfIntegrity::new(&report.data).analyse();
assert!(post.iter().all(|a| !matches!(
    a,
    ewf_forensic::EwfIntegrityAnomaly::SectionDescriptorCrcMismatch { .. }
)));

// Write the repaired copy — original is untouched
std::fs::write("evidence_repaired.E01", &report.data).unwrap();
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
- **Validated against real acquisitions** — zero false positives across three public E01 fixtures with full MD5 hash verification (including per-chunk zlib decompression):
  - [`exfat1.E01`](https://digitalcorpora.s3.amazonaws.com/corpora/drives/dftt-2004/exfat1.E01) — Digital Corpora DFTT exFAT image (EnCase/ADI)
  - [`nps-2010-emails.E01`](https://digitalcorpora.s3.amazonaws.com/corpora/drives/nps-2010-emails/nps-2010-emails.E01) — NPS 2010 email corpus (EnCase 6, best compression)
  - [`imageformat_mmls_1.E01`](https://digitalcorpora.s3.amazonaws.com/corpora/drives/dftt-2004/imageformat_mmls_1.E01) — Digital Corpora DFTT MMLS test image (FTK Imager)
- **MSRV 1.82** — no nightly, no unstable features.

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

## License

MIT — see [LICENSE](LICENSE).

---

[Sponsor this project](https://github.com/sponsors/h4x0r) · © 2026 Security Ronin Ltd

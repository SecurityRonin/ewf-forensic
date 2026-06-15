# ewf-forensic

**Verify the image. Trust the evidence.**

`ewf-forensic` is a pure-Rust integrity analyser for EWF / E01 images — no `libewf`, no C toolchain, no build complexity. It supports EWF v1 (E01 multi-segment with sibling auto-discovery), EWF v2 (Ex01/Lx01), SHA-1 and SHA-256 from digest sections, chain-of-custody external hash comparison (MD5, SHA-1, SHA-256), and optional header metadata extraction.

The analyser reports exactly what is structurally wrong across eight layers: signature forgery, broken section chains, cyclic chain attacks, Adler-32 descriptor corruption, volume geometry inconsistencies, table mismatches, out-of-bounds chunk pointers, MD5/SHA-1/SHA-256 hash mismatches, per-chunk checksum errors, and EWF v2 per-section data integrity. 40 distinct anomaly types across four severity levels.

## Install

```toml
[dependencies]
ewf-forensic = "0.4"
```

## Analyse an E01 file

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

The `ewf-check` CLI wraps the same analysis for command-line triage, and the `serde` feature serialises findings to JSON.

## What it checks

ewf-forensic layers its integrity checks from the file header inward:

- **Layer 1 — File header**: signature and version validation.
- **Layer 2 — Section descriptor integrity**: Adler-32 descriptor checksums.
- **Layer 3 — Section chain**: chain continuity and cyclic-chain attack detection.
- **Layer 4 — Section completeness**: required sections present.
- **Layer 5 — Volume geometry**: chunk/sector/size consistency.
- **Layer 6 — Table integrity**: table/table2 agreement, out-of-bounds chunk pointers, per-chunk checksums.
- **Layer 7 — Hash verification**: stored MD5/SHA-1/SHA-256 against recomputed values, plus chain-of-custody external hash comparison.
- **Layer 8 — Multi-segment and external reference**: sibling segment discovery and cross-segment consistency.
- **EWF v2** adds per-section and media-integrity checks.

See the [Anomaly Catalog](anomaly-catalog.md) for the full list of anomaly types and the [Validation](validation.md) report for the real-artifact evidence.

## Design

- **Pure Rust** — no `libewf`, no C dependency, no build complexity.
- **Panic-free** — EWF images are untrusted input; lengths, offsets, and pointers are bounds-checked before use.
- **Fuzzed** (`cargo fuzz`) and validated against real EWF images, not only synthetic builder output.

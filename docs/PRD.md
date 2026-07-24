# ewf-forensic — Purpose & Scope

This repository is a **library**, not an examiner application. It ships two published crates and a debug CLI; the examiner-facing disk tool in the fleet is `disk4n6`/Issen, which *links* these crates. The design rationale behind the decisions summarised here lives in [`docs/decisions/`](docs/decisions/) (ADRs).

**What it is.** A pure-Rust EWF (E01 / Ex01 / Lx01) stack in two roles (ADR 0001):

- **`ewf`** — the CONTAINER-layer *reader*: decodes an EWF image to a `Read + Seek` raw sector stream, with multi-segment auto-discovery, chunk decompression, and — behind the `vfs` feature — the `forensic-vfs` `ImageSource` contract so any VFS stack can mount an E01 with no format-specific branch (ADR 0007).
- **`ewf-forensic`** — the *analyzer*: audits the raw on-disk structure across seven layers (signature, section chain + descriptor CRC, completeness, volume geometry, table integrity, hash verification, multi-segment/external reference) plus EWF v2 per-section integrity, emitting graded anomalies; and `EwfRecover`, which salvages a damaged image to a new output path (ADR 0009).

**Who links it.** Filesystem/VFS composition layers and orchestration (`disk4n6`/Issen) that need EWF decode; triage pipelines that need a defensible integrity verdict and chain-of-custody hash comparison.

**Design pillars** (see ADRs): pure-Rust with no `libewf`/C FFI (0002); the analyzer builds on the reader's `ewf::sections` structural single-source-of-truth rather than its happy-path data API (0003); `forbid(unsafe)` in the reader, `deny` + bounded read-only mmap allows in the analyzer (0004); panic-free, fuzzed parsing validated against independent oracles — `ewfverify`, `ewfexport`, `blazehash-core` — on real corpora (0005); Adler-32 via the audited `adler2` crate (0006); a low 1.85 MSRV floor on the published libraries (0008).

**Non-goals.** It does not parse filesystem structures inside recovered sectors (no MFT/journal-level tampering detection — that is the filesystem readers' job); it is not the examiner front-end (that is `disk4n6`/Issen); it does not detect an MD5 collision or a descriptor whose Adler-32 was recomputed after tampering (only an external acquisition-time hash can). See the **Limitations** section of [`docs/anomaly-catalog.md`](anomaly-catalog.md) for the full list.

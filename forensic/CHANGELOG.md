# Changelog

All notable changes to `ewf-forensic` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.1](https://github.com/SecurityRonin/ewf-forensic/compare/ewf-forensic-v0.7.0...ewf-forensic-v0.7.1) - 2026-07-19

### Documentation

- *(readme)* two-row badge standard

## [0.7.0]

### Added

- **EWF recovery (`EwfRecover`) — libewf `ewfrecover`-equivalent, oracle-validated.**
  Tolerantly reads a corrupt / truncated / incomplete EWF v1 image and emits a
  recovered flat raw copy to a **new** output path, recovering every readable
  sector and zero-filling only genuinely unrecoverable chunks. Read-only-safe by
  construction (read-only mmap of the source, writes only to the caller-provided
  path). Per-chunk strategy: primary `table` → `table2` fallback → zero-fill,
  never aborting the whole recovery on one bad chunk. Present-but-suspect
  uncompressed sectors are exported (flagged) rather than discarded, matching
  libewf `ewfexport`; only absent data (truncation, out-of-range entries) or a
  compressed chunk that will not inflate is zero-filled.
- `RecoveryReport` — the recovery accounting: total / primary-recovered /
  table2-recovered / CRC-flagged / zero-filled chunk counts, bytes recovered vs
  zero-filled, the truncation offset (if any), and the lists of lost and
  CRC-flagged chunk indices.
- Validated byte-for-byte against libewf `ewfexport -f raw` (Tier-1 independent
  oracle) on clean and bad-CRC-chunk images, plus a non-gated clean round-trip
  against the in-crate `ewf::EwfReader`.

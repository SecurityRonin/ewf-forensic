# Changelog

All notable changes to `ewf` (the reader) are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0](https://github.com/SecurityRonin/ewf-forensic/compare/ewf-v0.4.10...ewf-v0.5.0) - 2026-09-20

### Added

- *(l01)* extract file contents; verified against EnCase's own MD5
- *(l01)* GREEN - logical media size and binary extents
- *(l01)* locate the ltree across segments; validate on real evidence
- *(l01)* GREEN - name-indexed entry tree with lenient UTF-16
- *(l01)* GREEN - ltree header integrity values

### Fixed

- *(verify)* never present a hash over a PARTIAL image as a verdict
- *(logical)* stop losing segments past 99, and stop blaming the signature
- *(l01)* retract a documented capability that does not exist

### Other

- Merge main, re-expressing the ewfexport install as a fleet-ci input

## [0.4.10](https://github.com/SecurityRonin/ewf-forensic/compare/ewf-v0.4.9...ewf-v0.4.10) - 2026-08-08

### Documentation

- unlink the crate-private parse_table_section from open_lazy's docs

## [0.4.9](https://github.com/SecurityRonin/ewf-forensic/compare/ewf-v0.4.8...ewf-v0.4.9) - 2026-08-06

### Fixed

- *(core)* GREEN — treat an empty extension as absent; adopt safe-read

## [0.4.8](https://github.com/SecurityRonin/ewf-forensic/compare/ewf-v0.4.7...ewf-v0.4.8) - 2026-08-04

### Fixed

- *(chunks)* GREEN - bound the values the image declares

## [0.4.7](https://github.com/SecurityRonin/ewf-forensic/compare/ewf-v0.4.6...ewf-v0.4.7) - 2026-07-24

### Fixed

- *(ci)* remove panic-y debug_assert in Chunk::new; mask malformed offset (panic-free on untrusted input)
- *(ci)* saturate EwfVolume::total_size to stop fuzz overflow panic

## [0.4.5](https://github.com/SecurityRonin/ewf-forensic/compare/ewf-v0.4.4...ewf-v0.4.5) - 2026-07-19

### Fixed

- *(deps)* bump forensic-vfs 0.4 -> 0.5

## [0.4.3]

- Current published reader: EWF v1 (E01 multi-segment with sibling
  auto-discovery) and EWF v2 (Ex01/Lx01) parsing over any `Read + Seek` source,
  chunk-table navigation, DEFLATE chunk decompression, and (behind the default
  `verify` feature) MD5/SHA-1/SHA-256 hashing. `forbid(unsafe)`, panic-free by
  lint, input-fuzzed.

<!-- release-plz appends new versions above this line, newest first. -->

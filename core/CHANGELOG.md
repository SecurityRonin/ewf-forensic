# Changelog

All notable changes to `ewf` (the reader) are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

# Validation Report

Integrity analysis of ewf-forensic against three publicly available E01 forensic images committed to `tests/fixtures/`. Every claim here is reproducible from the test suite.

Test images run automatically on every CI push via `cargo test --test real_image_tests`.

## Test Environment

| Component | Version | Source |
|-----------|---------|--------|
| ewf-forensic | 0.4.0 | [crates.io](https://crates.io/crates/ewf-forensic) |
| Rust (rustc) | 1.87.0 | [rustup.rs](https://rustup.rs/) |
| ewfverify | 20231119 (libewf-tools) | `brew install libewf` |
| Platform | macOS Darwin 24.6.0, arm64 (Apple Silicon) | — |

## Methodology

Each fixture is verified in two independent ways:

1. **ewf-forensic**: `EwfIntegrity::new(&data).with_expected_md5(known_hash).analyse()` — decompresses all zlib chunks, streams bytes through MD5/SHA-1/SHA-256, compares against the stored hash section and the ewfverify ground truth.
2. **ewfverify** (libewf reference implementation): `ewfverify -q <image>` and `ewfverify -d sha256 <image>` — used to establish the ground-truth hash values pinned in the test suite.

Both must agree for each hash algorithm. If they disagree, `ExternalMd5Mismatch` / `ExternalSha1Mismatch` / `ExternalSha256Mismatch` (all Critical) fires.

**Tamper detection** is verified for two fixtures by flipping a byte inside the sectors section body and asserting `HashMismatch` is produced. This proves the decompression path is exercised end-to-end — a silently skipped decompression would still report the wrong hash, but the tamper test makes it explicit.

**Decompression error localisation** is verified by corrupting the DEFLATE stream of a known chunk and asserting `ChunkDecompressionError { chunk_index: 0 }` is produced with the correct index and `Error` severity.

**Per-chunk Adler-32** is verified synthetically (no real uncompressed-chunk fixture is available): a builder-constructed image with a deliberately corrupted chunk checksum produces `ChunkChecksumMismatch`; a clean image does not.

## Test Images

### 1. exfat1 (DFTT)

| Property | Value |
|----------|-------|
| Project | [Digital Forensics Tool Testing (DFTT)](http://dftt.sourceforge.net/) (Brian Carrier) |
| Source | [Digital Corpora](https://digitalcorpora.org/) — AWS Open Data |
| URL | `https://digitalcorpora.s3.amazonaws.com/corpora/drives/dftt-2004/exfat1.E01` |
| Filename | `exfat1.E01` |
| E01 file MD5 | `74aca823a3959867a9de72a6b4c79b50` |
| Format | EnCase 6, deflate best-compression |
| Media size | 100,020,736 bytes (95 MiB) |
| Sectors/chunk | 64 |
| Chunk count | 3,053 (all compressed) |
| Partial last chunk | Yes — 25 of 64 sectors used |
| Filesystem | exFAT |
| Stored MD5 | `0777ee90c27ed5ff5868af2015bed635` |
| Stored SHA-1 | not present in image |

**ewfverify output (2026-05-14):**
```
MD5 hash stored in file:      0777ee90c27ed5ff5868af2015bed635
MD5 hash calculated over data: 0777ee90c27ed5ff5868af2015bed635
ewfverify: SUCCESS
```

**ewfverify SHA-256 (2026-05-14):**
```
SHA256 hash calculated over data: af6f974495187c35050d5c66d271617a1ec00d446adcf8590d7042ad2bf02bb7
ewfverify: SUCCESS
```

**ewf-forensic result:** CLEAN — no anomalies.
- MD5 pinned against ewfverify ground truth in `exfat1_computed_md5_matches_ewfverify`.
- SHA-256 pinned against ewfverify ground truth in `exfat1_computed_sha256_matches_ewfverify`.
- Tamper detection verified in `exfat1_sectors_tamper_triggers_hash_mismatch`.
- Decompression error localisation verified in `corrupt_zlib_chunk_produces_decompression_error_anomaly`, `chunk_decompression_error_includes_chunk_index`, `chunk_decompression_error_is_error_severity`.

---

### 2. nps-2010-emails (NPS)

| Property | Value |
|----------|-------|
| Project | Naval Postgraduate School (NPS) forensic test corpora |
| Source | [Digital Corpora](https://digitalcorpora.org/) — AWS Open Data |
| URL | `https://digitalcorpora.s3.amazonaws.com/corpora/drives/nps-2010-emails/nps-2010-emails.E01` |
| Filename | `nps-2010-emails.E01` |
| E01 file MD5 | `98e52ff847a440df3ba08261a3eea0f8` |
| Format | EnCase 6, deflate best-compression |
| Media size | 10,485,760 bytes (10 MiB) |
| Sectors/chunk | 64 |
| Chunk count | 320 (all compressed) |
| Partial last chunk | No — sector count is an exact multiple of 64 |
| Content | 30 email addresses in various document formats |
| Stored MD5 | `7dae50cec8163697415e69fd72387c01` |
| Stored SHA-1 | not present in image |

**ewfverify output (2026-05-14):**
```
MD5 hash stored in file:      7dae50cec8163697415e69fd72387c01
MD5 hash calculated over data: 7dae50cec8163697415e69fd72387c01
ewfverify: SUCCESS
```

**ewfverify SHA-256 (2026-05-14):**
```
SHA256 hash calculated over data: ed4e1b20fb92d9609778d6f687ef478c2ed88d7da18f98b8b023f3dfecd41a9d
ewfverify: SUCCESS
```

**ewf-forensic result:** CLEAN — no anomalies.
- MD5 pinned against ewfverify ground truth in `nps_emails_computed_md5_matches_ewfverify`.
- SHA-256 pinned against ewfverify ground truth in `nps_emails_computed_sha256_matches_ewfverify`.
- Tamper detection verified in `nps_emails_sectors_tamper_triggers_hash_mismatch`.

---

### 3. imageformat_mmls_1 (DFTT)

| Property | Value |
|----------|-------|
| Project | [Digital Forensics Tool Testing (DFTT)](http://dftt.sourceforge.net/) (Brian Carrier) |
| Source | [Digital Corpora](https://digitalcorpora.org/) — AWS Open Data |
| URL | `https://digitalcorpora.s3.amazonaws.com/corpora/drives/dftt-2004/imageformat_mmls_1.E01` |
| Filename | `imageformat_mmls_1.E01` |
| E01 file MD5 | `bb6c6bec25d589e87a11af9129275cc9` |
| Format | FTK Imager, deflate-compressed (labelled "no compression" in acquisition metadata — the 405 KB E01 for a 60 MiB image proves otherwise) |
| Media size | 62,915,072 bytes (60 MiB) |
| Sectors/chunk | 64 |
| Chunk count | 1,921 (all compressed) |
| Partial last chunk | Yes — 1 of 64 sectors used |
| Filesystem | NTFS (partition at offset 65,536) |
| Description | Created to test Sleuth Kit MMLS library |
| Stored MD5 | `8ec671e301095c258224aad701740503` |
| Stored SHA-1 | `067bc6ab29685ee19b0cf82c9d15ac510d1e7d95` (in `digest` section) |

**ewfverify output (2026-05-14):**
```
MD5 hash stored in file:       8ec671e301095c258224aad701740503
MD5 hash calculated over data: 8ec671e301095c258224aad701740503
SHA1 hash stored in file:      067bc6ab29685ee19b0cf82c9d15ac510d1e7d95
SHA1 hash calculated over data: 067bc6ab29685ee19b0cf82c9d15ac510d1e7d95
ewfverify: SUCCESS
```

**ewfverify SHA-256 (2026-05-14):**
```
SHA256 hash calculated over data: e7eb6fca46bebeedc4af4cc5bfe9675691bab8ce471315317b561a28899e7902
ewfverify: SUCCESS
```

**ewf-forensic result:** CLEAN — no anomalies.
- MD5 and SHA-1 both pinned against ewfverify ground truth in `mmls_computed_md5_matches_ewfverify` and `mmls_computed_sha1_matches_ewfverify`.
- SHA-256 pinned against ewfverify ground truth in `mmls_computed_sha256_matches_ewfverify`.

---

## Decompression Error Localisation

`ChunkDecompressionError { chunk_index }` fires when a compressed chunk's zlib stream cannot be decoded. Without this anomaly, a corrupt chunk produces only `HashMismatch` with no indication of which chunk caused it. ewfverify reports the failing chunk; ewf-forensic now does too.

**Test method (exfat1.E01):**
Chunk 0 begins at the sectors section body start. Byte 4 of the stream (past the 2-byte zlib CMF/FLG header, inside the DEFLATE bitstream) is flipped with `^= 0xFF`. This corrupts the DEFLATE data without invalidating the zlib header check, triggering a decompression error rather than a header-parse error.

| Test | What it asserts |
|------|----------------|
| `corrupt_zlib_chunk_produces_decompression_error_anomaly` | `ChunkDecompressionError` fires when DEFLATE data is corrupt |
| `chunk_decompression_error_includes_chunk_index` | `chunk_index` is 0 (the first chunk — index is zero-based and accurate) |
| `chunk_decompression_error_is_error_severity` | Severity is `Error` |

---

## Per-Chunk Adler-32 (Uncompressed Chunks)

EWF v1 acquisition tools append a 4-byte little-endian Adler-32 after the raw bytes of each **uncompressed** chunk. Compressed chunks are self-checksummed by their zlib stream (RFC 1950 appends a big-endian Adler-32 internally) and do not carry a separate EWF-layer checksum.

`ChunkChecksumMismatch { chunk_index, computed, stored }` fires when the stored and computed Adler-32 disagree for an uncompressed chunk.

No real uncompressed-chunk fixture is available in the public Digital Corpora corpus; these tests use a synthetic builder (`tests/builder.rs`) that constructs a minimal EWF v1 image with uncompressed chunks and optional per-chunk checksums.

| Test | What it asserts |
|------|----------------|
| `corrupt_chunk_checksum_detected` | `ChunkChecksumMismatch` fires for a deliberate bad checksum |
| `clean_chunk_checksums_no_anomaly` | No false positive on a clean image with correct checksums |
| `chunk_checksum_mismatch_is_error_severity` | Severity is `Error` |
| `no_checksum_image_no_false_positive` | No false positive when no per-chunk checksums are present |
| `exfat1_no_chunk_checksum_mismatch` | Real compressed fixture produces no false positive |
| `nps_emails_no_chunk_checksum_mismatch` | Real compressed fixture produces no false positive |
| `mmls_no_chunk_checksum_mismatch` | Real compressed fixture produces no false positive |

---

## How to Reproduce

### Run fixture tests

```bash
cargo test --test real_image_tests
```

### Run per-chunk checksum tests

```bash
cargo test --test chunk_integrity_tests
```

### Run full suite

```bash
cargo test
```

### Run ewfverify independently

```bash
ewfverify -q tests/fixtures/exfat1.E01
ewfverify -q tests/fixtures/nps-2010-emails.E01
ewfverify -q tests/fixtures/imageformat_mmls_1.E01

# SHA-256 (computed over data; not stored in these images):
ewfverify -d sha256 tests/fixtures/exfat1.E01
ewfverify -d sha256 tests/fixtures/nps-2010-emails.E01
ewfverify -d sha256 tests/fixtures/imageformat_mmls_1.E01
```

### Download and verify fixtures from source

```bash
curl -L -o exfat1.E01 \
  https://digitalcorpora.s3.amazonaws.com/corpora/drives/dftt-2004/exfat1.E01
md5 exfat1.E01  # expect 74aca823a3959867a9de72a6b4c79b50

curl -L -o nps-2010-emails.E01 \
  https://digitalcorpora.s3.amazonaws.com/corpora/drives/nps-2010-emails/nps-2010-emails.E01
md5 nps-2010-emails.E01  # expect 98e52ff847a440df3ba08261a3eea0f8

curl -L -o imageformat_mmls_1.E01 \
  https://digitalcorpora.s3.amazonaws.com/corpora/drives/dftt-2004/imageformat_mmls_1.E01
md5 imageformat_mmls_1.E01  # expect bb6c6bec25d589e87a11af9129275cc9
```

## Summary

| Image | Format | Media size | Chunks | MD5 | SHA-1 | SHA-256 | Tamper | Decomp error |
|-------|--------|-----------|--------|-----|-------|---------|--------|--------------|
| exfat1 | EnCase 6, compressed | 95 MiB | 3,053 | ewfverify match | N/A (not stored) | ewfverify match | Detected | Localised (chunk 0) |
| nps-2010-emails | EnCase 6, compressed | 10 MiB | 320 | ewfverify match | N/A (not stored) | ewfverify match | Detected | — |
| imageformat_mmls_1 | FTK Imager, compressed | 60 MiB | 1,921 | ewfverify match | ewfverify match | ewfverify match | — | — |

All three images pass with zero Error/Critical findings. MD5, SHA-1 (where stored), and SHA-256 match ewfverify byte-for-byte. Tamper detection and decompression error localisation are verified by targeted byte-flip mutation tests.

## Known Limitations

- All three fixtures use compressed chunks exclusively. The uncompressed-chunk Adler-32 path (`ChunkChecksumMismatch`) is covered only by synthetic tests; no real uncompressed-chunk fixture is available in the public corpus.
- Multi-segment images (E01+E02+…) are covered by synthetic builder tests; no real multi-segment fixture is committed.
- EWF v2 (Ex01) format coverage is structural only (section descriptor hashes, media info, encryption flags); no sector-data hash verification is implemented for EWF v2.

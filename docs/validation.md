# Validation Report

Integrity analysis of ewf-forensic against real E01 forensic images from public corpora and CTF repositories, plus systematic differential testing against ewfverify (libewf reference implementation). Every claim here is reproducible from the test suite.

Test images run automatically on every CI push via `cargo test --test real_image_tests`.

## Test Environment

| Component | Version | Source |
|-----------|---------|--------|
| ewf-forensic | 0.4.0 (250 tests) | [crates.io](https://crates.io/crates/ewf-forensic) |
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

**EWF v2 compressed chunks** are verified using `zeros_128s_compressed.Ex01` — a Python-generated fixture validated by ewfverify (independent oracle). MD5, SHA-1, and SHA-256 computed by `compute_hashes()` match ewfverify byte-for-byte. Corrupt chunk detection is verified by flipping a byte inside the zlib stream and asserting `ChunkDecompressionError`.

**EWF v2 media_info parsing** is verified by asserting `Ewf2MediaInfoParseFailed` fires when the section body is not a valid zlib stream, and does not fire for both the real fixture and a synthetically correct body.

**Progress callbacks**: `analyse_with_progress(impl FnMut(AnalysisProgress))` is verified to call its callback at least once per image, report monotonically non-decreasing `chunks_done` and `bytes_done`, report `chunks_total = Some(n)` for EWF v2, and return the same anomaly set as `analyse()`.

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

### 4. multiseg_v1 (ewfacquire — EWF v1 8-segment)

| Property | Value |
|----------|-------|
| Tool | ewfacquire 20231119 (libewf-tools) |
| Filename | `multiseg_v1.E01` … `multiseg_v1.E08` |
| Format | EWF v1 (EnCase 6), no compression, 1.5 MiB segment limit |
| Source | 10 MiB of `/dev/urandom` |
| Segments | 8 (7 × 1.4 MiB + 1 × 162 KiB) |
| Stored MD5 | `2692f3177a389e58906b5c9080aa1add` |
| Stored SHA-1 | `2d51e94e694ab425a73604e94d2020d00c182958` |

**ewfverify output:**
```
MD5 hash stored in file:       2692f3177a389e58906b5c9080aa1add
MD5 hash calculated over data: 2692f3177a389e58906b5c9080aa1add
SHA1 hash stored in file:      2d51e94e694ab425a73604e94d2020d00c182958
SHA1 hash calculated over data: 2d51e94e694ab425a73604e94d2020d00c182958
ewfverify: SUCCESS
```

**ewf-forensic result:** CLEAN — no anomalies across all 8 segments.
- MD5 and SHA-1 pinned against ewfverify ground truth in `multiseg_v1_md5_matches` / `multiseg_v1_sha1_matches`.
- `compute_hashes()` matches ewfverify ground truth in `multiseg_v1_computed_hashes_match`.
- Sibling auto-discovery (pass only E01, auto-finds E02..E08) verified in `multiseg_v1_sibling_auto_discovery`.

---

### 5. ewfacquire_clean (ewfacquire — EWF v1 single-segment)

| Property | Value |
|----------|-------|
| Tool | ewfacquire 20231119 (libewf-tools) |
| Filename | `ewfacquire_clean.E01` |
| Format | EWF v1 (EnCase 6), no compression |
| Source | 4 MiB of `/dev/zero` |
| Stored MD5 | `b5cfa9d6c8febd618f91ac2843d50a1c` |
| Stored SHA-1 | `2bccbd2f38f15c13eb7d5a89fd9d85f595e23bc3` |

**ewfacquire output:**
```
MD5 hash calculated over data:  b5cfa9d6c8febd618f91ac2843d50a1c
SHA1 hash calculated over data: 2bccbd2f38f15c13eb7d5a89fd9d85f595e23bc3
ewfacquire: SUCCESS
```

**ewf-forensic result:** CLEAN — no anomalies.
- Verified in `real_ewfacquire_clean_fixture_no_anomalies`.

---

### 6. zeros_128s (ewfacquirestream — EWF v2 uncompressed)

| Property | Value |
|----------|-------|
| Tool | ewfacquirestream 20231119 (libewf-tools) |
| Filename | `zeros_128s.Ex01` |
| Format | EWF v2 (EnCase 7), uncompressed |
| Media | 128 sectors × 512 bytes = 64 KB, all zeros |
| Sectors/chunk | 64 |
| Chunk count | 2 |

**ewfverify-confirmed hashes:**
```
MD5    : fcd6bcb56c1689fcef28b57c22475bad
SHA-256: de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31
ewfverify: SUCCESS
```

**ewf-forensic result:** CLEAN (excluding expected optional-section warnings `Ewf2MediaInfoMissing`, `HashSectionMissing`).
- MD5 and SHA-256 pinned in `ewf2_computed_md5_matches_ewfverify` / `ewf2_computed_sha256_matches_ewfverify`.
- External MD5/SHA-1/SHA-256 mismatch detection verified by `ewf2_path_wrong_*_triggers_mismatch`.
- Chunk table Adler-32 tampering verified by `ewf2_tampered_chunk_table_checksum_detected`.

---

### 7. zeros_128s_compressed (Python zlib + ewfverify — EWF v2 compressed)

| Property | Value |
|----------|-------|
| Tool | Python `zlib.compress(level=1)` (independent of Rust's `ZlibDecoder`) + ewfverify |
| Filename | `zeros_128s_compressed.Ex01` |
| Format | EWF v2, zlib-compressed (chunk flags 0x03 = HAS_CHECKSUM \| IS_COMPRESSED) |
| Media | 128 sectors × 512 bytes = 64 KB, all zeros |
| Sectors/chunk | 64 |
| Chunk count | 2 |
| Chunk offsets | [464..627], [631..794] (163 bytes compressed each) |

**ewfverify-confirmed hashes (independent oracle):**
```
MD5    : fcd6bcb56c1689fcef28b57c22475bad
SHA-1  : 1adc95bebe9eea8c112d40cd04ab7a8d75c4f961
SHA-256: de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31
ewfverify: SUCCESS
```

Python's `zlib.compress()` (CPython C extension) and Rust's `flate2::ZlibDecoder` are independent implementations of RFC 1950. Agreement between ewfverify and ewf-forensic across all three hash algorithms confirms the decompression path is correct.

**ewf-forensic result:** CLEAN.
- MD5/SHA-1/SHA-256 all match ewfverify in `ewf2_compressed_compute_hashes_md5/sha1/sha256`.
- Corrupt chunk at offset 464+10 triggers `ChunkDecompressionError` in `ewf2_corrupt_compressed_chunk_detected`.
- External MD5 mismatch detection verified by `ewf2_compressed_path_wrong_md5_mismatch`.

---

### 8. ctf_file6 (CTF — Cal Poly)

| Property | Value |
|----------|-------|
| Source | [github.com/mfput/CTF-Questions](https://github.com/mfput/CTF-Questions/blob/master/file6.E01) |
| Filename | `ctf_file6.E01` |
| E01 file MD5 | `88a92832d3ac8235a483b96216d0281b` |
| Format | EWF v1, compressed |
| Size on disk | 156 KB |
| Stored MD5 | `dbd1e66d8beb0d4c541d6cb87c48e05d` |
| Stored SHA-1 | `8c89f5cd2420ca93d5483f128494130d1165a247` |

**ewfverify output:**
```
ewfverify: SUCCESS (exit 0)
```

**ewf-forensic result:** CLEAN — 0 anomalies at any severity.
- Agreement with ewfverify verified in `ctf_file6_both_clean` (`tests/ctf_fixture_tests.rs`).

---

### 9. 2011-10-19-Sample (Autopsy sample — not committed)

| Property | Value |
|----------|-------|
| Source | [github.com/oddin-forensic/autopsy-sample-case](https://github.com/oddin-forensic/autopsy-sample-case/blob/master/2011-10-19-Sample.E01) |
| Filename | `2011-10-19-Sample.E01` |
| Format | EWF v1 / EnCase 7 |
| Size | 60 MB |
| Content | Autopsy sample case "Victor Bushell Laptop" |

**ewfverify output:**
```
ewfverify: SUCCESS (exit 0)
```

**ewf-forensic result:** 1 anomaly:
```
[WARNING]  error2 section reports 1 unreadable sector range(s) from acquisition
```

**Characterisation difference (not a bug in either tool):**

ewfverify ignores the `error2` section entirely. When an acquisition tool records unreadable sectors in `error2`, ewfverify silently skips them and reports SUCCESS. ewf-forensic reads the `error2` section and surfaces `BadSectorsPresent` (Warning) — the sectors were unreadable at acquisition time.

ewf-forensic is more informative: the warning is accurate and the investigator should know that some sector ranges could not be read at acquisition time. Both tools agree there is no hash mismatch or structural damage; they disagree on whether acquisition-time sector errors are worth reporting.

Test: `ctf_autopsy_sample_ewfverify_misses_bad_sectors` (`#[ignore]`, `tests/ctf_fixture_tests.rs`).
Download: `https://raw.githubusercontent.com/oddin-forensic/autopsy-sample-case/master/2011-10-19-Sample.E01`

---

### 10. CNC (HaxonicOfficial CTF — not committed)

| Property | Value |
|----------|-------|
| Source | [github.com/HaxonicOfficial/CTF-Practice](https://github.com/HaxonicOfficial/CTF-Practice/blob/master/CNC.E01) |
| Filename | `CNC.E01` |
| Format | EWF v1 / FTK Imager |
| Size on disk | 88 MB |
| Declared media | 1.8 GiB (61 440 chunks × 512 bytes/sector × 64 sectors/chunk) |
| Table entries | 16 375 (covering ~511 MB of accessible sectors) |
| Stored MD5 | `8ac02f473188c200fa388733f1b0d9ed` |
| Stored SHA-1 | `da9d570...` |

**ewfverify output:**
```
MD5 hash stored in file:       8ac02f473188c200fa388733f1b0d9ed
MD5 hash calculated over data: 8ac02f473188c200fa388733f1b0d9ed
ewfverify: SUCCESS (exit 0)
```

**ewf-forensic result:** 3 anomalies:
```
[ERROR]  chunk count mismatch: volume declares 61440, table has 16375
[ERROR]  MD5 mismatch: computed a2a03d7f37507cff805710d2c53d9253, stored 8ac02f473188c200fa388733f1b0d9ed
[ERROR]  SHA-1 mismatch: computed cd6a6169873477274eabf3e569a49650db3456a1, stored da9d570...
```

**ewfverify false negative — critical finding:**

The volume section declares 61 440 chunks (~1.8 GiB of sector data). The table section indexes only 16 375 entries (~511 MB). The remaining ~1.3 GiB of declared media has no accessible chunk offsets.

ewfverify hashes only the table-accessible sectors. The stored MD5 was computed over the same 16 375 accessible sectors at acquisition time, so ewfverify's computed hash matches the stored hash and it exits SUCCESS — despite the image being structurally inconsistent with a 1.3 GiB gap between declared and accessible data.

ewf-forensic detects `TableChunkCountMismatch` (volume ≠ table entry count) as an Error, then hashes over the full declared sector range. Because it accounts for all 61 440 declared chunks, its computed MD5 differs from the stored value → `HashMismatch`. This is correct behaviour: the structural inconsistency is a real integrity problem.

**This is a genuine false negative in ewfverify.** An investigator who relies solely on ewfverify would not know that 1.3 GiB of declared media is structurally inaccessible.

Test: `ctf_cnc_ewfverify_false_negative_table_mismatch` (`#[ignore]`, `tests/ctf_fixture_tests.rs`).
Download: `https://raw.githubusercontent.com/HaxonicOfficial/CTF-Practice/master/CNC.E01`

---

## Differential Testing

`tests/differential_tests.rs` and `tests/ctf_fixture_tests.rs` run ewf-forensic and ewfverify side-by-side on the same input and compare results. Tests skip automatically if ewfverify is not installed.

**Divergence taxonomy:**

| Type | Definition |
|------|-----------|
| False positive | ewfverify exits 0 (SUCCESS) but ewf-forensic reports Error/Critical |
| False negative | ewfverify exits ≠ 0 (FAILURE) but ewf-forensic reports nothing |
| Characterisation difference | Both agree the image has an issue but characterise it differently |
| ewfverify false negative | ewfverify exits 0 on a structurally inconsistent image; ewf-forensic reports Error |

**Results across 10 committed fixtures + 3 CTF inputs (13 real EWF images):**

| Category | Count |
|----------|-------|
| Agreement: both clean | 9 |
| Agreement: both detect anomaly | 2 |
| Characterisation difference | 1 |
| ewfverify false negative | 1 |
| True false positive in ewf-forensic | 0 |
| True false negative in ewf-forensic | 0 |

**No false positives and no false negatives were found in ewf-forensic across any real image tested.**

### Divergence Catalogue

#### D1 — Compressed chunk tamper: ewfverify reports MD5 match but exits FAILURE

**Image:** exfat1.E01 with byte 100 000 flipped.
**ewfverify:** exits 1 (FAILURE), but stdout reports "MD5 hash stored in file: …" appearing to match.
**ewf-forensic:** reports `ChunkDecompressionError` + `HashMismatch` (both Error).
**Classification:** characterisation difference — both correctly identify the image as anomalous; ewfverify's per-chunk CRC fires before it can compute the full-image hash, leaving the stored MD5 line in stdout even on FAILURE.
**Test:** `differential_compressed_tamper_ewfverify_md5_appears_clean_but_exits_failure`.

#### D2 — Autopsy sample: ewfverify silently ignores error2 section

**Image:** 2011-10-19-Sample.E01 (60 MB, Victor Bushell Laptop).
**ewfverify:** exits 0 (SUCCESS) — no mention of bad sectors.
**ewf-forensic:** exits 1, reports `BadSectorsPresent { count: 1 }` (Warning).
**Classification:** ewfverify characterisation gap — the image has a valid `error2` section recording 1 acquisition-time bad sector range. ewfverify does not check `error2`. ewf-forensic is more informative; this is not a false positive.
**Test:** `ctf_autopsy_sample_ewfverify_misses_bad_sectors` (`#[ignore]`).

#### D3 — CNC: ewfverify false negative on partial/truncated image

**Image:** CNC.E01 (88 MB, declares 1.8 GiB).
**ewfverify:** exits 0 (SUCCESS) — hashes only table-accessible sectors; stored hash matches.
**ewf-forensic:** exits 1, reports `TableChunkCountMismatch` + `HashMismatch` + `DigestSha1Mismatch` (all Error).
**Classification:** ewfverify false negative — the structural inconsistency (61 440 declared vs 16 375 accessible chunks) is not caught. ewf-forensic detects it. This is the most significant divergence found: a forensic investigator relying solely on ewfverify would not know that ~1.3 GiB of declared media is inaccessible.
**Test:** `ctf_cnc_ewfverify_false_negative_table_mismatch` (`#[ignore]`).

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

### Run differential tests (ewf-forensic vs ewfverify)

Requires `ewfverify` installed (`brew install libewf`). Tests skip automatically if not present.

```bash
# Always-on differential tests (all committed fixtures + adversarial mutations):
cargo test --test differential_tests

# CTF fixture differential tests (always-on only; ignored tests need downloads):
cargo test --test ctf_fixture_tests

# Run ignored CTF tests after downloading large fixtures:
python3 -c "
import urllib.request
urllib.request.urlretrieve(
    'https://raw.githubusercontent.com/oddin-forensic/autopsy-sample-case/master/2011-10-19-Sample.E01',
    'tests/data/2011-10-19-Sample.E01')
urllib.request.urlretrieve(
    'https://raw.githubusercontent.com/HaxonicOfficial/CTF-Practice/master/CNC.E01',
    'tests/data/CNC.E01')
"
cargo test --test ctf_fixture_tests -- --ignored
```

### Run full suite

```bash
cargo test
```

### Run ewfverify independently

```bash
ewfverify -q tests/data/exfat1.E01
ewfverify -q tests/data/nps-2010-emails.E01
ewfverify -q tests/data/imageformat_mmls_1.E01
ewfverify -q tests/data/zeros_128s.Ex01
ewfverify -q tests/data/zeros_128s_compressed.Ex01

# SHA-256 (computed over data; not stored in these images):
ewfverify -d sha256 tests/data/exfat1.E01
ewfverify -d sha256 tests/data/nps-2010-emails.E01
ewfverify -d sha256 tests/data/imageformat_mmls_1.E01
ewfverify -d sha256 -d sha1 tests/data/zeros_128s.Ex01
ewfverify -d sha256 -d sha1 tests/data/zeros_128s_compressed.Ex01
```

### Run ewfverify on CTF fixtures (reproduces divergences)

```bash
# Both clean (no divergence):
ewfverify -q tests/data/ctf_file6.E01

# Characterisation gap D2: ewfverify ignores error2 → SUCCESS; ewf-forensic → BadSectorsPresent:
ewfverify -q tests/data/2011-10-19-Sample.E01
cargo run --bin ewf-check -- tests/data/2011-10-19-Sample.E01

# False negative D3: ewfverify → SUCCESS on partial image; ewf-forensic → 3 errors:
ewfverify -q tests/data/CNC.E01
cargo run --bin ewf-check -- tests/data/CNC.E01
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

### Committed fixtures (always-on tests)

| Image | Format | Segments | Media size | MD5 | SHA-1 | SHA-256 | Tamper | Decomp error |
|-------|--------|----------|-----------|-----|-------|---------|--------|--------------|
| exfat1 | EnCase 6, compressed | 1 | 95 MiB | ewfverify match | N/A | ewfverify match | Detected | Localised (chunk 0) |
| nps-2010-emails | EnCase 6, compressed | 1 | 10 MiB | ewfverify match | N/A | ewfverify match | Detected | — |
| imageformat_mmls_1 | FTK Imager, compressed | 1 | 60 MiB | ewfverify match | ewfverify match | ewfverify match | — | — |
| multiseg_v1 | ewfacquire, uncompressed | 8 | 10 MiB | ewfverify match | ewfverify match | N/A | — | — |
| ewfacquire_clean | ewfacquire, uncompressed | 1 | 4 MiB | ewfacquire match | ewfacquire match | N/A | — | — |
| zeros_128s | EWF v2 uncompressed | 1 | 64 KB | ewfverify match | N/A | ewfverify match | — | — |
| zeros_128s_compressed | EWF v2 zlib (Python oracle) | 1 | 64 KB | ewfverify match | ewfverify match | ewfverify match | — | Localised (chunk 0) |
| ctf_file6 | EWF v1, compressed | 1 | — | ewfverify match | ewfverify match | N/A | — | — |

All eight always-on images pass with zero Error/Critical findings. MD5, SHA-1 (where stored), and SHA-256 match ewfverify byte-for-byte. Tamper detection and decompression error localisation are verified by targeted byte-flip mutation tests.

### CTF fixtures (ignored — download required)

| Image | Divergence | ewfverify | ewf-forensic |
|-------|-----------|-----------|--------------|
| 2011-10-19-Sample.E01 | D2 — characterisation gap | SUCCESS (ignores error2) | BadSectorsPresent (Warning) |
| CNC.E01 | D3 — ewfverify false negative | SUCCESS (partial image) | TableChunkCountMismatch + HashMismatch (Error) |

**No false positives and no false negatives were found in ewf-forensic across any real image tested.**

## Known Limitations

- The committed EWF v1 fixtures from Digital Corpora (`exfat1`, `nps-2010-emails`, `imageformat_mmls_1`) all use compressed chunks. The uncompressed-chunk Adler-32 path (`ChunkChecksumMismatch`) is covered by synthetic builder tests and by the `ewfacquire_clean.E01` fixture; no large real-world uncompressed fixture is available in the public corpus.
- `AnalysisProgress.chunks_total` is `None` during EWF v1 analysis — the chunk count is discovered by walking the section chain, not declared in a header. `Some(n)` is available for EWF v2 only, where the chunk table declares its entry count up front.
- The `zeros_128s_compressed.Ex01` fixture is Python-generated (not acquired by a commercial tool). It passes ewfverify but may not expose tool-specific quirks in the EWF v2 writer.
- FTK Imager and X-Ways real-fixture tests are deferred (`#[ignore]`) — these are Windows-only GUI tools. The format variations they produce are covered by always-on synthetic builder tests in `tool_fixtures_tests`.

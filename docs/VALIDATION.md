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

1. **ewf-forensic**: `EwfIntegrity::new(&data).with_expected_md5(known_hash).analyse()` — decompresses all zlib chunks, streams bytes through MD5/SHA-1, compares against the stored hash section and the ewfverify ground truth.
2. **ewfverify** (libewf reference implementation): `ewfverify -q <image>` — used to establish the ground-truth hash values pinned in the test suite.

Both must agree. If they disagree, the test `ExternalMd5Mismatch` (Critical) fires.

**Tamper detection** is also verified for two fixtures by flipping a byte inside the sectors section body and asserting `HashMismatch` is produced. This proves the decompression path is exercised — a silently skipped decompression would still report the wrong hash, but the tamper test makes it explicit.

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

**ewf-forensic result:** CLEAN — no anomalies. MD5 pinned against ewfverify ground truth in `exfat1_computed_md5_matches_ewfverify`. Tamper detection verified in `exfat1_sectors_tamper_triggers_hash_mismatch`.

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

**ewf-forensic result:** CLEAN — no anomalies. MD5 pinned against ewfverify ground truth in `nps_emails_computed_md5_matches_ewfverify`. Tamper detection verified in `nps_emails_sectors_tamper_triggers_hash_mismatch`.

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

**ewf-forensic result:** CLEAN — no anomalies. MD5 and SHA-1 both pinned against ewfverify ground truth in `mmls_computed_md5_matches_ewfverify` and `mmls_computed_sha1_matches_ewfverify`.

---

## How to Reproduce

### Run fixture tests

```bash
cargo test --test real_image_tests
```

### Run ewfverify independently

```bash
ewfverify -q tests/fixtures/exfat1.E01
ewfverify -q tests/fixtures/nps-2010-emails.E01
ewfverify -q tests/fixtures/imageformat_mmls_1.E01

# SHA-256 (computed over data; not stored in these images):
ewfverify -d sha256 tests/fixtures/exfat1.E01
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

| Image | Format | Media size | Chunks | MD5 matches ewfverify | SHA-1 matches ewfverify | Tamper detected |
|-------|--------|-----------|--------|-----------------------|-------------------------|-----------------|
| exfat1 | EnCase 6, compressed | 95 MiB | 3,053 | Yes | N/A (not stored) | Yes |
| nps-2010-emails | EnCase 6, compressed | 10 MiB | 320 | Yes | N/A (not stored) | Yes |
| imageformat_mmls_1 | FTK Imager, compressed | 60 MiB | 1,921 | Yes | Yes | — |

All three images pass with zero Error/Critical findings. MD5 (and SHA-1 where stored) match ewfverify byte-for-byte. Tamper detection is verified by flipping a byte in the sectors body and asserting `HashMismatch` fires.

## Known limitations

- All three fixtures use compressed chunks exclusively. The uncompressed-chunk Adler-32 path (`ChunkChecksumMismatch`) is covered only by synthetic tests; no real uncompressed-chunk fixture is available.
- SHA-256 is not yet supported (`ewfverify -d sha256` computes it; we do not).
- Multi-segment images (E01+E02+…) are covered by synthetic builder tests; no real multi-segment fixture is committed.

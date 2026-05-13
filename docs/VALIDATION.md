# Validation Report

Integrity analysis of ewf-forensic against three publicly available E01 forensic images.  Each image is run through all seven analysis layers.  Zero Error/Critical findings are expected; stored MD5 hash sections are verified via per-chunk zlib decompression.

Test images are committed in `tests/fixtures/` and executed automatically on every CI push via `cargo test --test real_image_tests`.

## Test Environment

| Component | Version | Source |
|-----------|---------|--------|
| ewf-forensic | 0.1.0 | [crates.io](https://crates.io/crates/ewf-forensic) |
| Rust (rustc) | 1.88.0 (6b00bc388) | [rustup.rs](https://rustup.rs/) |
| Platform | macOS Darwin 24.6.0, arm64 (Apple Silicon) | — |

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
| Chunk count | 3,053 |
| Partial last chunk | Yes — 25 of 64 sectors used |
| Filesystem | exFAT |
| Stored MD5 | `0777ee90c27ed5ff5868af2015bed635` |

**ewf-forensic result:** CLEAN — no anomalies. Stored MD5 verified via decompression of 3,053 zlib chunks.

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
| Chunk count | 320 |
| Partial last chunk | No — sector count is an exact multiple of 64 |
| Content | 30 email addresses in various document formats |
| Stored MD5 | `7dae50cec8163697415e69fd72387c01` |

**ewf-forensic result:** CLEAN — no anomalies. Stored MD5 verified via decompression of 320 zlib chunks.

---

### 3. imageformat_mmls_1 (DFTT)

| Property | Value |
|----------|-------|
| Project | [Digital Forensics Tool Testing (DFTT)](http://dftt.sourceforge.net/) (Brian Carrier) |
| Source | [Digital Corpora](https://digitalcorpora.org/) — AWS Open Data |
| URL | `https://digitalcorpora.s3.amazonaws.com/corpora/drives/dftt-2004/imageformat_mmls_1.E01` |
| Filename | `imageformat_mmls_1.E01` |
| E01 file MD5 | `bb6c6bec25d589e87a11af9129275cc9` |
| Format | FTK Imager, deflate-compressed (labelled "no compression" in acquisition metadata — the 405 KB E01 size for a 60 MiB image proves otherwise) |
| Media size | 62,915,072 bytes (60 MiB) |
| Sectors/chunk | 64 |
| Chunk count | 1,921 |
| Partial last chunk | Yes — 1 of 64 sectors used |
| Filesystem | NTFS (partition at offset 65,536) |
| Description | Created to test Sleuth Kit MMLS library |
| Stored MD5 | `8ec671e301095c258224aad701740503` |

**ewf-forensic result:** CLEAN — no anomalies. Stored MD5 verified via decompression of 1,921 zlib chunks.

---

## How to Reproduce

### Run fixture tests

```bash
cargo test --test real_image_tests
```

### Verify fixture downloads

```bash
# Download and verify E01 file integrity
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

### Run the validate example against any E01

```bash
cargo run --example validate path/to/image.E01
```

## Summary

| Image | Format | Media Size | Chunks | Stored MD5 Verified | Anomalies |
|-------|--------|------------|--------|---------------------|-----------|
| exfat1 | EnCase 6, compressed | 95 MiB | 3,053 | Yes | None |
| nps-2010-emails | EnCase 6, compressed | 10 MiB | 320 | Yes | None |
| imageformat_mmls_1 | FTK Imager, compressed | 60 MiB | 1,921 | Yes | None |

All three images pass with zero Error/Critical findings and successful MD5 hash verification.  Images are committed as test fixtures and run in CI.

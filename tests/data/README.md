# Test Fixtures

Binary EWF fixtures from real acquisition tools.

Large or tool-licensed E01s are NOT committed — place them here and run ignored
tests with:

```bash
cargo test --test tool_fixtures_tests -- --ignored
```

## Committed fixtures

| File | Format | Size | Tool |
|------|--------|------|------|
| `zeros_128s.Ex01` | EWF v2 (EnCase 7) | 66 400 B | ewfacquirestream 20231119 |
| `zeros_128s_compressed.Ex01` | EWF v2 compressed | 1 166 B | Python zlib, verified by ewfverify |
| `multiseg_v1.E01` … `multiseg_v1.E08` | EWF v1 (EnCase 6), no compression | 8 × ~1.4 MiB | ewfacquire 20231119 |
| `ewfacquire_clean.E01` | EWF v1 (EnCase 6), no compression | 4.0 MiB | ewfacquire 20231119 |
| `exfat1.E01` | EWF v1 (EnCase 6), compressed | 268 KiB | FTK Imager (DFTT corpus) |
| `imageformat_mmls_1.E01` | EWF v1, compressed | 405 KiB | FTK Imager (DFTT corpus) |
| `nps-2010-emails.E01` | EWF v1 (EnCase 6), compressed | 507 KiB | EnCase (NPS corpus) |

### zeros_128s.Ex01

128 sectors × 512 bytes = 64 KB of zero-filled sector data.

**Creation:**
```bash
dd if=/dev/zero bs=512 count=128 | \
  ewfacquirestream -f encase7-v2 -d sha1 -d sha256 -t /tmp/test_ex01
mv /tmp/test_ex01.Ex01 tests/fixtures/zeros_128s.Ex01
```

**ewfverify-confirmed hashes (libewf ground truth):**
```
MD5    : fcd6bcb56c1689fcef28b57c22475bad
SHA-256: de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31
Result : SUCCESS (ewfverify exits 0)
```

**ewfinfo geometry:** 128 sectors, 512 bytes/sector, 64 KB

**ewf-forensic expected behavior:**
- 0 anomalies at any severity
- `ewf-check --min-severity=info` exits 0

### zeros_128s_compressed.Ex01

128 sectors × 512 bytes = 64 KB of zero-filled sector data, stored as 2 zlib-compressed
chunks (chunk flag 0x03 = HAS\_CHECKSUM | IS\_COMPRESSED). Created with Python's `zlib.compress(level=1)`,
validated by ewfverify.

**ewfverify-confirmed hashes (independent oracle):**
```
MD5    : fcd6bcb56c1689fcef28b57c22475bad
SHA-1  : 1adc95bebe9eea8c112d40cd04ab7a8d75c4f961
SHA-256: de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31
Result : SUCCESS (ewfverify exits 0)
```

**ewfinfo geometry:** 128 sectors, 512 bytes/sector, 64 KB, 2 chunks, deflate/fast compression

**ewf-forensic expected behavior:**
- 0 anomalies at any severity
- `compute_hashes()` returns the same MD5/SHA-1/SHA-256 as above

### multiseg_v1.E01 … multiseg_v1.E08

10 MiB of `/dev/urandom`, acquired as 8 EWF v1 segments (no compression, 1.5 MiB segment limit).

**Creation:**
```bash
dd if=/dev/urandom bs=1M count=10 of=urandom_10m.img
ewfacquire -u -f encase6 -S 1500000 -c none -t multiseg_v1 -d md5 -d sha1 urandom_10m.img
mv multiseg_v1.E0* tests/data/
```

**ewfverify-confirmed hashes (libewf ground truth):**
```
MD5 hash stored in file:       2692f3177a389e58906b5c9080aa1add
SHA1 hash stored in file:      2d51e94e694ab425a73604e94d2020d00c182958
ewfverify: SUCCESS
```

**ewf-forensic expected behavior:**
- 0 anomalies at any severity across all 8 segments
- `compute_hashes()` returns the same MD5/SHA-1 as above
- Sibling auto-discovery: `EwfIntegrityPath::from_path("multiseg_v1.E01")` finds E02..E08 automatically

---

### ewfacquire_clean.E01

4 MiB of `/dev/zero`, acquired as a single EWF v1 segment (no compression).

**Creation:**
```bash
dd if=/dev/zero bs=512 count=8192 of=blank_4mb.img
ewfacquire -u -f encase6 -c none -t ewfacquire_clean -d md5 -d sha1 blank_4mb.img
mv ewfacquire_clean.E01 tests/data/
```

**ewfacquire-confirmed hashes:**
```
MD5 hash calculated over data:  b5cfa9d6c8febd618f91ac2843d50a1c
SHA1 hash calculated over data: 2bccbd2f38f15c13eb7d5a89fd9d85f595e23bc3
ewfacquire: SUCCESS
```

**ewf-forensic expected behavior:**
- 0 anomalies at any severity

---

## Required files (not committed — Windows tools only)

| File | Tool | How to generate |
|------|------|-----------------|
| `ftk_imager_clean.E01` | FTK Imager ≥ 4.x | Acquire a blank 4 MB image via the GUI with a small image file as source. Acquire with MD5. |
| `ftk_imager_tampered.E01` | — | Copy `ftk_imager_clean.E01`, open in hex editor, flip one byte inside the sectors region, save. |
| `xways_clean.E01` | X-Ways Forensics / WinHex | Acquire a 4 MB zero image using `File → Create Disk Image`. Keep original hash report. |
| `xways_tampered.E01` | — | As above; flip a byte in the sectors data. |

## Known tool quirks encoded in synthetic builders

The ignored tests exercise real binary behaviour. The always-on synthetic tests
in `tool_fixtures_tests.rs` encode the format variations we know about:

| Tool | `disk` vs `volume` | `header2` | `digest` section |
|------|:---:|:---:|:---:|
| FTK Imager | `disk` | yes | no |
| X-Ways | `disk` | no | yes (SHA-1) |
| ewfacquire | `disk` | no | no |

If a real fixture reveals a new quirk, add a synthetic builder variant and
an always-on test before adding the ignored fixture test.

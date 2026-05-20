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

## Required files (not committed)

| File | Tool | How to generate |
|------|------|-----------------|
| `ftk_imager_clean.E01` | FTK Imager ≥ 4.x | Acquire a blank 4 MB RAM disk: `dd if=/dev/zero bs=4M count=1 \| ...` or use the GUI with a small image file as source. Acquire with MD5. |
| `ftk_imager_tampered.E01` | — | Copy `ftk_imager_clean.E01`, open in hex editor, flip one byte inside the sectors region, save. |
| `xways_clean.E01` | X-Ways Forensics / WinHex | Acquire a 4 MB zero image using `File → Create Disk Image`. Keep original hash report. |
| `xways_tampered.E01` | — | As above; flip a byte in the sectors data. |
| `ewfacquire_clean.E01` | ewfacquire (libewf-tools) | `dd if=/dev/zero bs=512 count=8192 > blank.img && ewfacquire -t evidence blank.img` |
| `ewfacquire_tampered.E01` | — | Flip a byte in the sectors region of `ewfacquire_clean.E01`. |

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

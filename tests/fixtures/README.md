# Test Fixtures

Binary E01 fixtures from real acquisition tools. Not committed to git (too large;
tool licences vary). Place files here and run ignored tests with:

```bash
cargo test --test tool_fixtures_tests -- --ignored
```

## Required files

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

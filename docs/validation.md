# Validation

`ewf-forensic` analyses untrusted EWF/E01 forensic acquisition images and reports
integrity anomalies. Correctness is therefore established the way forensic tooling
must be: against **independent oracles** (a different tool, or a different code
path, that already decodes the same bytes correctly) on **real third-party
corpora** with known ground truth — never against fixtures we hand-encoded and
then graded ourselves.

This page records exactly which oracle and which corpus back each capability, so
the claim is independently re-checkable. Per-file provenance (source, download
URL, hashes, tool) lives in [`tests/data/README.md`](https://github.com/SecurityRonin/ewf-forensic/blob/main/tests/data/README.md);
the fleet-wide machine index is `issen/docs/corpus-catalog.md`. This page
cross-references both rather than duplicating them.

## How to read the evidence tiers

Each validation below is tagged with the trustworthiness of its check, not
whether the data is "synthetic":

- **Tier 1** — an independent third party authored the artifact *and* the answer
  key, or it is real-world data decoded by an independent tool. The strongest claim.
- **Tier 2** — real engine output whose ground truth is derivable from the
  documented construction, or confirmed by an *independent code path* on real
  data. Genuinely checked, but we chose the scenario.
- **Tier 3** — fixture and expected answer both authored here, nothing
  independent vouching. Used only for per-branch coverage, never as a
  correctness claim: a self-consistent round trip proves internal consistency,
  not correctness against real-world bytes.

## Independent oracles

| Oracle | Independent of us? | Validates | Tier |
|---|---|---|---|
| **`ewfverify`** (libewf-tools 20231119) | Yes — separate C codebase (Joachim Metz) | Stored vs computed MD5/SHA-1/SHA-256 over decompressed media data; SUCCESS/FAILURE verdict on every committed real fixture | 1 |
| **`ewfacquire`** (libewf-tools 20231119) | Yes — same C codebase, the *writer* | Ground-truth hashes for the images it acquired (`multiseg_v1`, `ewfacquire_clean`) | 1 |
| **`blazehash`** (`blazehash::algorithm::hash_bytes`) | Yes — independent hashing code path from the in-tree `md-5`/`sha1`/`sha2` readers | `compute_hashes()` MD5/SHA-1/SHA-256 match an independent hasher over the same recovered media bytes | 2 |
| **Python `zlib.compress`** (CPython C extension) | Yes — independent RFC-1950 implementation from Rust's `flate2::ZlibDecoder` | The EWF v2 zlib decompression path (compressed-chunk fixture authored with Python's encoder, decoded by ours) | 1 |
| **The Sleuth Kit test corpus** (`bogus.E01/.E02`, `gpt_130_partitions.E01`) | Yes — third-party DFIR project | Error-path rejection of invalid input and a clean-container baseline, cross-checked against `ewfverify` | 1 |

`ewfverify` and `ewf-forensic` are also run **side-by-side on the same input** in
`tests/differential_tests.rs` and `tests/ctf_fixture_tests.rs`, so neither tool's
verdict is load-bearing alone; the differential harness classifies any divergence
(false positive / false negative / characterisation / coverage). All `ewfverify`
tests skip cleanly when the binary is absent (`run_differential` returns `None`,
`tests/differential_tests.rs:66`).

## Independent test corpora

All committed real fixtures are third-party or tool-acquired with
independently established ground truth. Large CTF images are gitignored and
fetched manually; the small fixtures are committed. Hashes and full provenance
are in [`tests/data/README.md`](https://github.com/SecurityRonin/ewf-forensic/blob/main/tests/data/README.md).

| Corpus | Source | Used for | License / redistribution |
|---|---|---|---|
| **DFTT `exfat1` / `imageformat_mmls_1`** | Brian Carrier's Digital Forensics Tool Testing, via [Digital Corpora](https://digitalcorpora.org/) (AWS Open Data) | EnCase/FTK compressed-chunk MD5/SHA-1/SHA-256 vs `ewfverify` | Public research corpus; gitignored, fetched per `tests/data/README.md` |
| **NPS `nps-2010-emails`** | Naval Postgraduate School corpus, via Digital Corpora | EnCase compressed-chunk hashes vs `ewfverify` | Public research corpus; gitignored |
| **`ctf_file6.E01`** | [github.com/mfput/CTF-Questions](https://github.com/mfput/CTF-Questions) (Cal Poly CTF) | Clean EWF v1 baseline, agreement with `ewfverify` | CTF public distribution; committed |
| **`gpt_130_partitions.E01`, `bogus.E01/.E02`** | [github.com/sleuthkit/sleuthkit](https://github.com/sleuthkit/sleuthkit/tree/develop/test/data) | Clean-container baseline + zero-byte error-path rejection | sleuthkit test/data; committed |
| **`2011-10-19-Sample.E01`** (not committed) | [oddin-forensic/autopsy-sample-case](https://github.com/oddin-forensic/autopsy-sample-case) | `error2` bad-sector coverage difference vs `ewfverify` | Sample case; gitignored, download in `tests/data/README.md` |
| **`CNC.E01`** (not committed) | [HaxonicOfficial/CTF-Practice](https://github.com/HaxonicOfficial/CTF-Practice) | Volume/table mismatch coverage difference vs `ewfverify` | CTF practice image; gitignored |
| **`multiseg_v1.E01..E08`, `ewfacquire_clean.E01`, `zeros_128s*.Ex01`** | Acquired here with `ewfacquire` / `ewfacquirestream` / Python zlib | Multi-segment discovery, EWF v2 (un)compressed paths; ground truth from `ewfverify`/`ewfacquire` | Tool-acquired; committed (generator commands in `tests/data/README.md`) |

## Per-capability validation

### Stored-hash verification (MD5 / SHA-1 / SHA-256) — Tier 1

`tests/real_image_tests.rs` decompresses the full media stream of each committed
real image and compares ewf-forensic's computed digest against the **ground-truth
value `ewfverify` derived independently**, pinned per algorithm: e.g.
`exfat1_computed_md5_matches_ewfverify` / `exfat1_computed_sha256_matches_ewfverify`,
`nps_emails_computed_*`, `mmls_computed_md5/sha1/sha256_matches_ewfverify`. The
`multiseg_v1` set is pinned in `multiseg_v1_md5_matches` / `multiseg_v1_sha1_matches`
against `ewfacquire`/`ewfverify` ground truth.

### Verdict agreement with ewfverify (differential) — Tier 1

`tests/differential_tests.rs` runs `ewfverify` and `ewf-forensic` on the same
input and asserts the verdicts agree (`differential_exfat1_both_clean`,
`_nps_emails_`, `_mmls_`, `_ewfacquire_clean_`, `_multiseg_v1_`, `_zeros_128s_`,
`_zeros_compressed_`, `:136`–`:209`). Adversarial mutations are asserted to be
caught by **both** tools (`differential_tampered_compressed_chunk_both_detect`,
`_tampered_uncompressed_chunk_`, `_truncated_file_`, `_invalid_signature_`,
`_wrong_stored_md5_both_detect`). The harness flags any true false positive /
false negative; across the committed corpus none is found.

### `compute_hashes()` independent-code-path check — Tier 2

`tests/compute_hashes_tests.rs` recomputes the recovered media bytes through
**`blazehash::algorithm::hash_bytes`** — a hashing implementation independent of
the in-tree `md-5`/`sha1`/`sha2` readers — and asserts byte-equality:
`compute_hashes_md5_matches_blazehash_oracle` (`:56`),
`compute_hashes_sha1_matches_blazehash_oracle` (`:76`),
`compute_hashes_sha256_matches_blazehash_oracle` (`:96`). A second code path
(`EwfIntegrityPath` mmap vs in-memory `EwfIntegrity`) is cross-checked in
`ewf_integrity_path_compute_hashes_matches_ewf_integrity` (`:162`).

### EWF v2 zlib decompression — Tier 1

`zeros_128s_compressed.Ex01` is authored with **Python's `zlib.compress(level=1)`**
(an RFC-1950 encoder independent of Rust's `flate2` decoder) and confirmed by
`ewfverify`. `tests/ewf2_compressed_chunk_tests.rs` asserts ewf-forensic's
`compute_hashes()` reproduces the `ewfverify`-confirmed MD5/SHA-1/SHA-256 and that
flipping a byte inside the zlib stream produces `ChunkDecompressionError`. The
uncompressed EWF v2 path is covered by `zeros_128s.Ex01` (`tests/ewf2_*_tests.rs`).

### Invalid-input rejection + diagnostic depth — Tier 1

`tests/sleuthkit_fixture_tests.rs` drives the sleuthkit zero-byte fixtures:
`bogus_e01_both_report_invalid` (`:114`) and `bogus_e02_both_report_invalid`
(`:158`) assert both tools reject the input (ewf-forensic emits a structured
`CRITICAL` section-chain anomaly; `ewfverify` an open error).
`gpt_130_partitions_both_clean` (`:199`) confirms a clean-container baseline
agrees with `ewfverify`.

### Coverage differences ewfverify misses (CTF, env/download-gated) — Tier 1

`tests/ctf_fixture_tests.rs` records two real images where ewf-forensic surfaces
structure `ewfverify` does not check: the `error2` acquisition-bad-sector section
(`2011-10-19-Sample.E01` → `BadSectorsPresent`) and a volume-vs-table chunk-count
mismatch (`CNC.E01` → `TableChunkCountMismatch`). These tests are `#[ignore]` and
require the large images to be downloaded (instructions in `tests/data/README.md`).

### Per-chunk Adler-32 (uncompressed chunks) — Tier 3

No real uncompressed-chunk fixture with a known-bad checksum exists in the public
corpus, so `ChunkChecksumMismatch` detection is exercised with a builder-authored
image (`tests/builder.rs`, `tests/chunk_integrity_tests.rs`:
`corrupt_chunk_checksum_detected`, `clean_chunk_checksums_no_anomaly`). This is a
self-authored round trip — internal consistency, not a correctness claim against
real-world bytes. **Gap:** a real uncompressed-chunk acquisition with a corrupt
Adler-32 would lift this to Tier 1/2; the clean side is partially covered by the
real `ewfacquire_clean.E01` / `multiseg_v1` uncompressed fixtures.

### Canonical reporting model — Tier 2

`tests/canonical_finding_tests.rs` (`anomaly_converts_to_a_canonical_finding`,
`:8`) verifies `EwfIntegrityAnomaly` normalises onto `forensicnomicon::report`
via the `Observation` producer trait (`src/integrity.rs:2041`), applying the
4-level→5-level severity re-grade.

### Robustness — never panic, never over-read

`analyse`, `analyse_with_progress`, `compute_hashes`, and `from_segments` are
property-tested to never panic on arbitrary input (`tests/proptest_tests.rs`:
`analyse_never_panics` `:18`, `analyse_with_progress_never_panics` `:24`,
`compute_hashes_never_panics` `:32`, `from_segments_never_panics` `:38`) and
fuzzed by two `cargo-fuzz` targets (`fuzz/fuzz_targets/fuzz_integrity.rs`,
`fuzz_repair.rs`; a `fuzz.yml` CI workflow builds and smoke-runs them). The crate
contains no `unsafe` of its own except the read-only `memmap2::Mmap::map` of
immutable evidence files: lints are set to `unsafe_code = "deny"` with a justified
`#[allow(unsafe_code)]` on each mmap site (`src/integrity_path.rs:84`, `:105`,
`:144`), and `clippy::unwrap_used` / `clippy::expect_used` are denied
(`Cargo.toml`).

## Reproducing the validation

The committed always-on tests run with `cargo test`. The CTF differentials need
the large images (fetch per `tests/data/README.md`) and `ewfverify` (skips if
absent).

```bash
# Real-image hash pinning + clean-verdict (committed fixtures, always run)
cargo test --test real_image_tests

# compute_hashes() vs the blazehash independent code path
cargo test --test compute_hashes_tests

# Per-chunk Adler-32 (synthetic builder)
cargo test --test chunk_integrity_tests

# sleuthkit baseline + zero-byte rejection
cargo test --test sleuthkit_fixture_tests

# Differential: ewf-forensic vs ewfverify (needs `brew install libewf`; skips if absent)
cargo test --test differential_tests
cargo test --test ctf_fixture_tests

# CTF coverage-difference tests (download the large images first, then):
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

# Run ewfverify independently to reproduce the ground-truth values
ewfverify -q tests/data/ctf_file6.E01
ewfverify -q tests/data/gpt_130_partitions.E01
ewfverify -d sha256 -d sha1 tests/data/zeros_128s_compressed.Ex01

# Full suite (includes property tests)
cargo test
```

## Coverage & fuzzing as backstops

Line coverage is enforced in CI (`cargo llvm-cov`, failing on any zero-hit line
not annotated `// cov:unreachable`). Coverage is a regression backstop that proves
behavior is exercised — it is not the correctness claim. The oracles above are.

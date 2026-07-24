# 5. Panic-free, fuzzed parsing of adversarial EWF input, validated against independent oracles

Date: 2026-07-24
Status: Accepted

## Context

Every byte this suite parses is attacker-controllable. A lying length field, a
truncated section, a cyclic `next`-offset chain, or an integer that overflows
during offset arithmetic must never crash the tool or, worse, produce silently
wrong output — a forensic tool that panics on a crafted image is a
denial-of-service on the investigation. Real, lived failures in this repo prove
the threat: commit `ab7a6af` fixed an EWF v2 section-walk OOM/hang on crafted
`prev_offset` chains, and a run of commits (`05a9d85`, `a453eb2`, `77efb13`,
`0975a10`, `e120a17`) replaced panicking arithmetic with saturating arithmetic
across the v1/v2 walkers and hash paths.

Because the reader is pure-Rust with no `libewf` at runtime (ADR 0002),
correctness must be earned against an *independent* oracle, not self-authored
fixtures (fleet Evidence-Based Rigor, tier 1).

## Decision

Enforce the posture both statically and dynamically:

- **Static**: `ewf-forensic` denies `clippy::unwrap_used` and `expect_used` in
  production (forensic `Cargo.toml` `[lints.clippy]`); the reader is
  `forbid(unsafe)` (ADR 0004). Length/offset/count fields are bounds-checked and
  arithmetic saturates. Commit `78ca097` introduced this ("enforce paranoid
  security lints, make parsing panic-free, add fuzz CI").
- **Dynamic**: a `cargo-fuzz` target per parsed structure —
  `core/fuzz` (`parse_header`, `parse_segment`) and `forensic/fuzz`
  (`fuzz_integrity`, `fuzz_multisegment`, `fuzz_recover`) — built and smoke-run in
  CI, invariant: no input may panic.
- **Oracle validation**: `ewfverify` (libewf, separate C codebase) and
  `blazehash-core` (independent hashing code path, dev-dep aliased `blazehash`)
  cross-check hashes and verdicts on real acquisition-tool and DFIR corpora; the
  differential harness reconciles every finding (`docs/validation.md`).

## Consequences

- Malformed evidence degrades to an error or partial result, never a crash.
- The fuzz targets and the differential oracle harness are maintained CI surface.
- The two fuzz crates carry their own `[workspace]` and are `exclude`d from the
  stable workspace (root `Cargo.toml`) because libfuzzer is nightly-only.

# 4. Unsafe posture: `forbid(unsafe)` in the reader, `deny` + bounded mmap allows in the analyzer

Date: 2026-07-24
Status: Accepted

## Context

Both crates parse untrusted, attacker-controllable evidence images, so the
memory-safety bar is `forbid(unsafe)` by default (fleet Paranoid Gatekeeper
standard). But the path-based analyzer needs one genuine, benefit-carrying
exception: to audit a 100 GB+ image without loading it into a 100 GB `Vec<u8>`,
it memory-maps each immutable segment. `memmap2::Mmap::map` is `unsafe` (the file
could in principle be mutated under the mapping). `unsafe_code = "forbid"` cannot
be locally overridden, so a single mmap site would otherwise force the whole crate
off the strongest posture.

## Decision

Apply the bar per crate, per the fleet unsafe cost-benefit exception:

- **Reader (`ewf`) and `ewf-cli`**: `unsafe_code = "forbid"` via the shared
  `[workspace.lints.rust]` table (root `Cargo.toml`). The reader has no `unsafe`.
- **Analyzer (`ewf-forensic`)**: downgrade to `unsafe_code = "deny"` in its own
  inline `[lints.rust]` (forensic `Cargo.toml`), with exactly the read-only
  `memmap2::Mmap::map` sites opting in via a justified `#[allow(unsafe_code)]`
  (4 in `forensic/src/integrity_path.rs`, 1 in `forensic/src/recover.rs` — 5
  sites total). Every other `unsafe` stays a hard error, so
  `rg 'allow(unsafe_code)'` is the complete audit surface.

The root `Cargo.toml` comment records why the two cannot share one lint table.

## Consequences

- The reader — the crate most consumers link — is provably `unsafe`-free and can
  wear the "unsafe forbidden (core)" badge; the analyzer honestly reads as
  "`deny` + 5 bounded mmap allows," never "unsafe-forbidden" (README design
  section states this precisely).
- Large-image analysis is O(1) in RAM.
- The one accepted `unsafe` is pure-Rust and bounded (read-only mmap of immutable
  evidence), the lowest-liability form — no C-FFI (ADR 0002).

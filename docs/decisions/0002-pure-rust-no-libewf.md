# 2. Pure-Rust EWF implementation — no `libewf`, no C FFI

Date: 2026-07-24
Status: Accepted

## Context

The de-facto reference EWF implementation is `libewf` (Joachim Metz), a C library.
Binding it would pull a C toolchain into every downstream build, introduce a
`-sys` FFI surface the Rust compiler cannot see into, and — most importantly for a
tool that parses *untrusted, attacker-controllable* evidence images — reintroduce
the C memory-corruption class that safe Rust deletes by construction.

The fleet posture (`~/src/ronin-issen/CLAUDE.md`, "`unsafe` Is an Avoidable
Cost-Benefit Exception"; Paranoid Gatekeeper) weights a C-FFI dependency as a
categorically larger liability than pure-Rust bounded `unsafe`, and prefers our
own pure-Rust crates over third-party C bindings.

## Decision

Implement the EWF v1 (E01) and EWF v2 (Ex01/Lx01) formats natively in Rust. The
reader decodes signatures, section descriptors, volume/table geometry, and
zlib-compressed chunks itself (`core/src/reader.rs`, `core/src/sections.rs`,
`core/src/ewf2.rs`); the analyzer parses the same structures for audit
(`forensic/src/integrity.rs`). No `libewf` linkage, no C toolchain — the README's
headline promise is "no `libewf`, no C toolchain, no build complexity."

`libewf`'s tools are retained only as *external validation oracles*, never as a
runtime dependency: `ewfverify` for the integrity verdict/hashes (ADR 0005,
`docs/validation.md`) and `ewfexport` for tolerant-recovery raw output (ADR 0009,
`forensic/tests/recover_tests.rs` `oracle_*` tests, documented in
`forensic/tests/data/README.md`).

## Consequences

- The crate builds as a single pure-Rust artifact with `cargo build`; no
  `cc`/pkg-config/system-`libewf`.
- Correctness cannot lean on `libewf` at runtime, so it must be *proven* against
  an independent oracle on real corpora (ADR 0005, `docs/validation.md`).
- Rationale reconstructed from the README design section, the module layout, and
  the fleet C-FFI-avoidance policy; the original build-vs-bind deliberation is
  consistent with the code but not separately minuted in commit history.

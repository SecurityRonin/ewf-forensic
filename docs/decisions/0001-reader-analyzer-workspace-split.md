# 1. Two-crate workspace: bare `ewf` reader + `ewf-forensic` analyzer, independently versioned

Date: 2026-07-24
Status: Accepted

## Context

EWF (E01) evidence images need two distinct capabilities that serve different
callers. A *reader* decodes the container to an addressable byte stream — what a
filesystem/VFS layer or an examiner tool links to get at sector data. An
*analyzer* audits the on-disk structure for tampering, corruption, and
chain-of-custody mismatches — what a triage pipeline links to grade evidence.
Shipping these as one crate would force every consumer of a plain reader to
compile the audit machinery (hashing, mmap, progress UI) and would blur the
low-MSRV compatibility promise a pure reader wants to keep.

This mirrors the fleet Crate-structure standard in `~/src/ronin-issen/CLAUDE.md`
("reader/analyzer split — `core/` + `forensic/`"; reference impl `ntfs-forensic`).
Commit `d681ac5` consolidated the previously-separate reader into this workspace
as `core/` + `cli/` + `forensic/`.

## Decision

One workspace repo (`ewf-forensic`) with three members:

- `core/` → crate **`ewf`**, the pure reader: `Read + Seek` over E01/Ex01/L01,
  multi-segment auto-discovery, chunk decompression, `ewf::sections` structural
  primitives (`core/src/lib.rs`).
- `forensic/` → crate **`ewf-forensic`**, the analyzer: `EwfIntegrity` /
  `EwfIntegrityPath` / `EwfRecover` emitting graded anomalies (`forensic/src/lib.rs`).
- `cli/` → crate **`ewf-cli`** (binary `ewf`), a debug/inspection front-end
  (`info`/`verify`/`read`/`sections`/`search`/`extract`/`mcp`).

`version` is deliberately **not** hoisted into `[workspace.package]` (root
`Cargo.toml` comment): the reader (`ewf` 0.4.x, `ewf-cli` 0.3.x) and the analyzer
(`ewf-forensic` 0.7.x) are versioned and released independently, because a reader
API change and an analyzer detection change are unrelated events. `edition`,
`rust-version`, `license`, `repository`, and `authors` **are** hoisted (DRY).

## Consequences

- A VFS/filesystem consumer links only `ewf` and never compiles the audit stack.
- The two crates release on independent SemVer clocks via release-plz (per-crate
  tags), so an analyzer patch does not force a reader bump.
- The repo keeps the analyzer as its headline name (`ewf-forensic`) even though it
  also holds the reader crate, per the fleet standard.
- The `cli/` `ewf` binary is a debug surface, not the examiner-facing tool — the
  fleet's end-user disk CLI is `disk4n6`/Issen, which links `ewf` as a library.

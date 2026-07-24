# 8. Low MSRV floor (1.85) on the published libraries; dev toolchain pinned to 1.96.0

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy separates the *dev toolchain* (what the repo builds/lints
with) from the *declared MSRV* (`rust-version`, a downstream compatibility
promise). `ewf` and `ewf-forensic` are published libraries other crates link, so a
low, CI-verified MSRV is a deliberate compatibility feature — raising it narrows
the crates.io audience and is a near-breaking change. At the same time, all
contributors and CI should build on one current stable to end fmt/clippy drift.

## Decision

- Declared MSRV `rust-version = "1.85"` in `[workspace.package]` (root
  `Cargo.toml`), inherited by every member — the downstream promise, verified by a
  separate MSRV CI job.
- Dev toolchain pinned to `channel = "1.96.0"` in `rust-toolchain.toml`, with
  `components = ["clippy", "rustfmt"]` declared there as the single source of truth
  (so CI jobs that float `@stable` still get fmt/clippy on the pinned version).
  Commit `0e95b46` set the pin ("pin dev toolchain to 1.96.0, fleet standard,
  matches ntfs-forensic").

The `rust-toolchain.toml` header comment records the dev-vs-MSRV distinction
explicitly.

## Consequences

- Third-party consumers can link `ewf`/`ewf-forensic` on Rust as old as 1.85.
- Contributors share one lint/format toolchain; no "which Rust am I on" churn.
- An MSRV bump is a deliberate, separately-justified event, not a side effect of
  updating the dev pin.

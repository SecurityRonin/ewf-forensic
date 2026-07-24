# 7. Implement the `forensic-vfs` `ImageSource` contract behind a `vfs` feature

Date: 2026-07-24
Status: Accepted

## Context

The fleet's VFS/universal-container policy (`~/src/ronin-issen/CLAUDE.md`, "VFS &
Universal Container Abstraction") requires that a consumer reading an evidence
image never special-case one container format. Filesystems and higher layers
compose over a uniform positioned-byte edge — `forensic-vfs::ImageSource` — so an
`E01 → GPT → NTFS` stack reads as one `Arc<dyn ImageSource>`. For that to include
E01, the `ewf` reader must *implement* the contract rather than expose a bespoke
API each consumer adapts.

Commits `93aa1ac`/`f3cc52a` added the impl ("EwfReader as ImageSource, Phase 2"),
`00c340b` proved it end-to-end (`E01 → NTFS` through the contracts), and
`ce91823`/`7fe1aa4`/`fedb4b9`/`bbe0200` tracked the `forensic-vfs` dep from 0.2 to
0.7.

## Decision

`EwfReader` implements `forensic_vfs::ImageSource` (`core/src/vfs.rs:12`), mapping
its existing positioned `read_at` onto the trait's short-read contract (a read
past EOF yields 0). The dependency is gated behind an **optional `vfs` feature**
(`core/Cargo.toml`: `vfs = ["dep:forensic-vfs"]`, `forensic-vfs = { version =
"0.7", optional = true }`) so a consumer that only wants the raw reader does not
compile the contract crate.

## Consequences

- Any `forensic-vfs`-based stack can mount an E01 with no format-specific branch;
  adding EWF benefits every VFS consumer at once.
- Keeping it feature-gated preserves a minimal default dependency graph for
  reader-only consumers.
- The reader depends *up* onto the KNOWLEDGE-leaf contract crate only when the
  feature is on; the default reader stays contract-free.

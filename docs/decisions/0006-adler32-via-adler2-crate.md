# 6. Adler-32 over EWF sections via the `adler2` crate, not a hand-rolled CRC

Date: 2026-07-24
Status: Accepted

## Context

EWF stores an Adler-32 checksum over each section descriptor, the volume body, and
the table header. The analyzer recomputes these to detect descriptor/geometry
corruption (`SectionDescriptorCrcMismatch`, `TableHeaderAdler32Mismatch`, …). An
early version hand-rolled the Adler-32. A hand-rolled checksum is unaudited, can
drift from the reader's copy, and is the exact "roll-your-own where a vetted crate
exists" smell the fleet forbids; the maintained `adler` crate was itself flagged
unmaintained (RUSTSEC-2025-0056), with `adler2` as the maintained drop-in — the
canonical Root-Cause-Over-Suppression ("adler2 law") case.

## Decision

Compute Adler-32 through the published **`adler2`** crate. Commit `e852d16`
replaced the hand-rolled implementation ("adler32 via the adler2 crate — drop
hand-rolled"); commit `4860b3a` pinned the result to the published Adler-32 test
vectors. `adler2` is declared once in `[workspace.dependencies]` (root
`Cargo.toml`) — it is already in the tree via `flate2`, but is declared directly
so `ewf::sections` can compute it as the single CRC entry point that both reader
and analyzer share (ADR 0003).

## Consequences

- One audited, spec-vector-pinned Adler-32; no bespoke checksum math to get wrong.
- `deny.toml` documents the `adler` (RUSTSEC-2025-0056) advisory as reaching the
  tree only as a transitive *dev-dep* of `blazehash-core`, superseded by `adler2`
  in production — the fix, not a blanket ignore.
- Reader and analyzer cannot disagree on a section CRC because both funnel through
  `ewf::sections::adler32`.

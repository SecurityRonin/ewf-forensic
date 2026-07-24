# 9. `EwfRecover` reconstructs a recovered raw image to a NEW output path, never mutating the source

Date: 2026-07-24
Status: Accepted

## Context

A partially-corrupt E01 (truncated segment, bad-CRC chunks, a broken chain) can
still hold recoverable evidence. Examiners need a way to salvage the readable
sectors into a usable raw image without a full reader choking on the damage. Two
hard constraints apply: the operation must be **read-only-safe** on the evidence
(a forensic tool must never write to the source), and its recovery behavior must
match an accepted reference so results are defensible.

Commits `ab2d31a` (RED) and `14ac605` (GREEN) added `EwfRecover` as
"tolerant EWF recovery, ewfexport-oracle-validated"; `c30b222` added the
`fuzz_recover` target.

## Decision

Provide `EwfRecover` / `RecoveryReport` (`forensic/src/recover.rs`) that walk a
possibly-damaged image and emit a recovered flat raw copy to a **caller-provided
output path**. It is read-only by construction: segment files are opened
read-only (memory-mapped) and writes go only to the output path, never the source
(module doc `recover.rs:5-8`). Unrecoverable chunks are zero-filled so the output
always spans the full logical image length. Recovery semantics mirror libewf
`ewfexport` — a CRC-flagged but physically-present uncompressed chunk is exported
(with the mismatch reported), not discarded, because zero-filling recoverable
bytes would destroy evidence (`decode_chunk` doc, `recover.rs:321`). `ewfexport`
(`ewfexport -q -u -f raw`) is the independent validation oracle: the `oracle_*`
tests in `forensic/tests/recover_tests.rs` assert the recovered raw equals
`ewfexport`'s byte-for-byte and skip cleanly when it is off PATH — documented
under "Tier-1 oracle" in `forensic/tests/data/README.md`.

## Consequences

- Salvage runs on original evidence with no risk of mutating it — consistent with
  the fleet "read-only reconstructor emits to new paths" naming/safety rule.
- Recovery decisions are checkable against an established reference tool rather
  than only against damage we injected ourselves.
- The tolerant walker is fuzzed (`fuzz_recover`) under the same no-panic invariant
  as the rest of the parser surface (ADR 0005).

# 3. `ewf-forensic` builds on `ewf::sections` (structural SSOT), not the reader's `Read + Seek` data API

Date: 2026-07-24
Status: Accepted

## Context

An anomaly auditor must *see* exactly what a robust reader hides. The `ewf`
reader's `Read + Seek` interface is built to serve *valid* sector data: it
transparently verifies-and-discards CRCs, normalizes geometry, and skips or
rejects malformed structures. That is the opposite of what an integrity check
needs — the auditor must inspect the raw section descriptors, the stored (and
possibly wrong) Adler-32 CRCs, table entries that resolve out of bounds, and
section chains that point backward.

The fleet Crate-structure standard is explicit that `-forensic` need not depend on
the reader's data API and "often needs to go much lower level than the `-core`
API" — citing `ewf-forensic` itself as the model that consumes only the
low-level structural parser. Two commits established this: `7a6d088` made
`ewf::sections` "the single source of truth for EWF v1 layout + CRCs," and
`3c17701` refactored `ewf-forensic` to consume it "instead of re-implementing EWF
v1 layout."

## Decision

`ewf::sections` is the single source of truth for EWF v1 on-disk primitives —
signatures, descriptor/volume/table-header/table-entry layout, and the shared
`sections::adler32` entry point (`core/src/lib.rs` doc, `pub mod sections`).
`ewf-forensic` depends on the `ewf` crate but imports **only** `ewf::sections`
(`forensic/src/integrity.rs:22`, `forensic/src/recover.rs:38`), parsing the raw
structure in-situ — it does **not** route its audit through the reader's
`Read + Seek` / data interface. The Adler-32 the analyzer recomputes is the
byte-exact `ewf::sections::adler32`, so reader and auditor can never disagree on
a checksum by using divergent CRC code (`forensic/src/integrity.rs:2057`).

## Consequences

- Offset/CRC layout is defined once; the auditor cannot drift from the reader.
- The analyzer sees malformed/overwritten/slack structures the reader would
  normalize away — the whole point of the audit.
- The dependency arrow points down (analyzer → reader's structural module → nothing
  below), honoring the fleet layer rule that a PARSER-role crate never imports a
  higher layer.

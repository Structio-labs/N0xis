# Archive — N0x v0 (superseded)

This folder holds the **first-generation N0x implementation**, archived on
2026-07-08 when the project was reset for a full rewrite under a new modular /
adapter architecture (see [`../CONCEPT.md`](../CONCEPT.md) and
[`../ROADMAP.md`](../ROADMAP.md)).

## Contents

- `n0x-cli-rs-v0/` — the original Rust CLI backend (single `n0x-cli-rs` crate).
  Working, but architected as a god-module (`main.rs`, ~4.1k lines) with the ISA,
  I/O, analysis and presentation layers tangled together. Kept as a **reference
  implementation** — the disassembler, CFG builder, switch-table detection/
  resolution, frame analysis and static-PE adapter are all sound and should be
  ported (not rewritten from a blank page) into the new `n0x-core` / `n0x-arch`
  crates.
- `docs-v0/` — the v0 design docs (`BACKEND_SPEC.md`, `CLI_FEATURES_SPEC.md`) and
  `Decompile.txt` (a hand-annotated pseudo-C example that motivated the rewrite).

## Why it was reset

The v0 module boundaries were drawn along technical artifacts, not contracts:
- `main.rs` did arg-parsing + process/memory I/O + PE glue + symbol/IAT maps +
  switch resolution + output formatting all at once.
- The x64 / Win64-ABI assumptions were hardcoded and scattered across `ir.rs`
  and `pseudo.rs` — no seam to plug in another ISA.
- The pseudo-C renderer performed analysis work itself (lifting, condition
  recovery, dominators), leaving nowhere clean to insert an optimizing IR
  (SSA / propagation / DCE).
- Schemas and helpers were duplicated across modules instead of living in one
  source of truth.

The one thing v0 got right — `IrSource { Live(pid), Static(pe) }`, a single
analysis path over both a live process and a file on disk — is the seed the new
architecture generalizes into an explicit adapter layer.

## Current CLI surface (preserved)

The complete v0 command surface is documented at
[`../docs/CLI_COMMANDS_v0.md`](../docs/CLI_COMMANDS_v0.md). The new CLI must
preserve this surface (same verbs, same JSON `ok/data/meta` envelope) so existing
agent workflows and the global `n0x` shim keep working across the rewrite.

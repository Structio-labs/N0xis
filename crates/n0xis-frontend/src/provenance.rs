// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The static half of `provenance trace`: one hit, explained back to its function and
//! statement. One definition for the CLI and MCP doors, which each built their own
//! context, and built it empty.
//!
//! An empty `Ctx` has no functions the image states. On an unstripped PIE, `late_writer`
//! sits at an unaligned address right after a function that ends in a `jmp`, and only
//! `pthread_create`'s argument names it: no prologue rule, no `call` and no boundary finds
//! it, and the answer was "no recovered function covers" an address the image's own
//! `.eh_frame` and symbol table cover (audit 2026-11-06, row 9). Its `instruction_va` was
//! then the trap's address, the instruction after the write, since the write is found in
//! the function's instruction stream. The context here has what `function discover` has.

use n0xis_arch::Arch;
use n0xis_contracts::Va;
use n0xis_core::{Ctx, CoreError, Pass, ProvenanceGraph, ProvenanceHit, ProvenanceInput, ProvenancePass};
use n0xis_sources::LiveTarget;

use crate::source::Src;

/// Explain one access to `value_addr` by the instruction the trap reported at `rip`.
pub fn explain_hit(live: Box<dyn LiveTarget>, arch: &dyn Arch, value_addr: Va, rip: Va, access_kind: &str) -> Result<ProvenanceGraph, CoreError> {
    let insn_module = live.modules().iter().find(|m| m.contains(rip)).cloned();
    // The code window searched for the containing function. `.text` from section
    // headers is the precise answer, but not always reachable (a stripped ELF, a module
    // whose headers are not mapped); `code_ranges_of` falls back to the module's
    // executable mappings, and the range holding the instruction is the one to search.
    let code_ranges = insn_module.as_ref().map(|m| live.code_ranges_of(m.base)).unwrap_or_default();
    let (code_scan_start, code_scan_size) = code_ranges
        .iter()
        .find(|(start, size)| rip.get() >= start.get() && rip.get() < start.get().saturating_add(*size))
        .or_else(|| code_ranges.first())
        .map(|(start, size)| (Some(*start), *size as usize))
        .unwrap_or((None, 0));
    let src = Src::Live(live);
    let stated = crate::registry::stated_functions(&src);
    let Src::Live(live) = &src else { unreachable!("built as live above") };
    let ctx = Ctx::new(live.as_ref(), arch)
        .with_symbols(live.as_ref())
        .with_modules(live.as_ref())
        .with_stated_functions(&stated, crate::registry::stated_coverage(&src));
    ProvenancePass.run(
        &ctx,
        ProvenanceInput {
            value_addr,
            hits: vec![ProvenanceHit { instruction_va: rip, access_kind: access_kind.to_string() }],
            module: insn_module,
            code_scan_start,
            code_scan_size,
        },
    )
}

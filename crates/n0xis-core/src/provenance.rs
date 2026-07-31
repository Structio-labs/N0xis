//! [`ProvenancePass`] — ROADMAP Phase 4c, the principal killer feature
//! (CONCEPT §11, KF-1): fuses the dynamic side (a hardware-watchpoint hit —
//! "something at this address just read/wrote/executed this instruction",
//! already built in Phase 4b's `debug watch`) with the static side (the SSA
//! decompiler, Phase 3) into one typed, agent-readable explanation of what a
//! runtime value *means*.
//!
//! No other does this in one step: a memory scanner's "find what accesses
//! this address" stops at a raw disassembly line; any other reverse-engineering tool's
//! decompilers don't know about a live watchpoint hit at all. This pass is
//! the seam that turns "value at 0x7ff6...1862 changed" into "written by
//! `sub_140001063`, in the statement `*rax.1 = 0x0;`" — pure analysis: the
//! *live* half (arming the watchpoint) stays in `n0xis-cli`/`n0xis-sources`,
//! this pass only explains an address it's handed.

use n0xis_contracts::{Module, Va};
use serde::Serialize;

use crate::decomp::{DecompInput, DecompPass, DecompStyle};
use crate::discover::{DiscoverInput, DiscoverPass};
use crate::ir::{CfgArtifact, CfgInput, CfgPass};
use crate::{Ctx, CoreError, Pass};

/// One instruction that touched the value being explained.
#[derive(Clone, Debug, Serialize)]
pub struct ProvenanceHit {
    pub instruction_va: Va,
    /// `"read"` / `"write"` / `"execute"` — mirrors `debug watch`'s `WatchKind`.
    pub access_kind: String,
}

/// The static-side explanation of one [`ProvenanceHit`] — `None` fields mean
/// that part of the chain didn't resolve (no module, no discovered function
/// covering the address, …), never a guess (CONCEPT §3 rule 6).
#[derive(Clone, Debug, Serialize)]
pub struct ProvenanceEntry {
    pub instruction_va: Va,
    pub access_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rva: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_va: Option<Va>,
    /// The rendered pseudo-C for exactly the block containing
    /// `instruction_va`, from the `--style ssa` decompile of the containing
    /// function — the causal explanation in source-level terms, not just an
    /// address.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub decompiled_context: Vec<String>,
}

/// The provenance graph for one value (`n0xis.provenance.v1`): every traced
/// access to `value_addr`, each explained back to its recovered function and
/// decompiled statement.
#[derive(Clone, Debug, Serialize)]
pub struct ProvenanceGraph {
    pub value_addr: Va,
    pub entries: Vec<ProvenanceEntry>,
}

pub struct ProvenanceInput {
    pub value_addr: Va,
    pub hits: Vec<ProvenanceHit>,
    /// The module each hit's `instruction_va` is expected to fall in —
    /// resolves `module`/`rva` and bounds the function search to its code.
    pub module: Option<Module>,
    /// Code range to search for the containing function (typically the
    /// module's `.text`); required for function resolution to succeed.
    pub code_scan_start: Option<Va>,
    pub code_scan_size: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProvenancePass;

impl Pass for ProvenancePass {
    type In = ProvenanceInput;
    type Out = ProvenanceGraph;

    fn name(&self) -> &'static str {
        "provenance"
    }

    fn run(&self, ctx: &Ctx, input: ProvenanceInput) -> Result<ProvenanceGraph, CoreError> {
        let entries = input
            .hits
            .into_iter()
            .map(|hit| explain_hit(ctx, hit, input.module.as_ref(), input.code_scan_start, input.code_scan_size))
            .collect();
        Ok(ProvenanceGraph { value_addr: input.value_addr, entries })
    }
}

fn explain_hit(ctx: &Ctx, hit: ProvenanceHit, module: Option<&Module>, scan_start: Option<Va>, scan_size: usize) -> ProvenanceEntry {
    let (module_name, rva) = match module {
        Some(m) => (Some(m.name.clone()), m.rva(hit.instruction_va)),
        None => (None, None),
    };

    let mut function_va = None;
    let mut decompiled_context = Vec::new();
    if let Some(start) = scan_start
        && let Some((func_start, cfg)) = find_function_containing(ctx, start, scan_size, hit.instruction_va)
    {
        function_va = Some(func_start);
        // Extract the block id (Copy) before `cfg` moves into `DecompInput`.
        let block_id = cfg
            .blocks
            .iter()
            .find(|b| b.start.get() <= hit.instruction_va.get() && hit.instruction_va.get() < b.end.get())
            .map(|b| b.id);
        if let Some(block_id) = block_id
            && let Ok(pseudo) = DecompPass.run(ctx, DecompInput { cfg, style: DecompStyle::Ssa, explain: false })
        {
            decompiled_context = extract_block_context(&pseudo.pseudo, block_id);
        }
    }

    ProvenanceEntry { instruction_va: hit.instruction_va, access_kind: hit.access_kind, module: module_name, rva, function_va, decompiled_context }
}

/// Walk discovered function candidates in `[scan_start, scan_start+scan_size)`
/// backward from `target`, building each one's CFG until one's extent
/// actually covers `target`. Bounded (`MAX_CANDIDATES_TRIED`) so a target far
/// from any recognized prologue fails fast rather than rebuilding CFGs
/// forever.
const MAX_CANDIDATES_TRIED: usize = 8;
const FUNCTION_MAX_BYTES: usize = 8192;

/// How far back from `target` to look for the containing function's prologue.
/// A single function is at most `FUNCTION_MAX_BYTES`; 64 KiB gives generous
/// slack for discovery heuristics without scanning the whole module.
const DISCOVER_WINDOW_BACK: u64 = 64 * 1024;

fn find_function_containing(ctx: &Ctx, scan_start: Va, scan_size: usize, target: Va) -> Option<(Va, CfgArtifact)> {
    if target.get() < scan_start.get() {
        return None;
    }
    // We only need the *one* function that contains `target`. Discovering the
    // entire `.text` here is pathologically slow over live memory (a hit's
    // scan range is the whole module — thousands of ReadProcessMemory calls
    // that made `provenance trace` appear to hang). The containing function's
    // prologue sits at most a function's length before `target`, so window the
    // discovery to a bounded region ending just past it.
    let scan_end = scan_start.get().saturating_add(scan_size as u64);
    let win_start = target.get().saturating_sub(DISCOVER_WINDOW_BACK).max(scan_start.get());
    let win_end = target.get().saturating_add(16).min(scan_end);
    let win_size = win_end.saturating_sub(win_start) as usize;
    let discovered = DiscoverPass.run(ctx, DiscoverInput { start: Va(win_start), size: win_size, limit: 100_000, offset: 0 }).ok()?;
    let mut candidates: Vec<Va> = discovered.functions.iter().map(|f| f.va).filter(|&va| va.get() <= target.get()).collect();
    candidates.sort_by_key(|va| std::cmp::Reverse(va.get()));

    for &start in candidates.iter().take(MAX_CANDIDATES_TRIED) {
        let Ok(cfg) = CfgPass.run(ctx, CfgInput::new(start, FUNCTION_MAX_BYTES)) else { continue };
        if target.get() < cfg.end.get() {
            return Some((start, cfg));
        }
    }
    None
}

/// Every rendered line belonging to block `block_id` — from its
/// `"// block_<id>: 0x..."` header (structure.rs always emits one) up to the
/// next block header or the end of the function.
fn extract_block_context(pseudo: &[String], block_id: usize) -> Vec<String> {
    let marker = format!("// block_{block_id}:");
    let Some(start_idx) = pseudo.iter().position(|l| l.trim_start().starts_with(&marker)) else {
        return Vec::new();
    };
    let end_idx = pseudo[start_idx + 1..]
        .iter()
        .position(|l| l.trim_start().starts_with("// block_"))
        .map(|off| start_idx + 1 + off)
        .unwrap_or(pseudo.len());
    pseudo[start_idx..end_idx].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    #[test]
    fn explains_a_write_inside_its_containing_function() {
        // sub_1000: sub rsp,0x20 (a recognized prologue, so DiscoverPass
        // finds this function's start) ; mov [rax+8], rcx ; add rsp,0x20 ; ret
        let code = vec![
            0x48, 0x83, 0xEC, 0x20, // 0x1000 sub rsp, 0x20
            0x48, 0x89, 0x48, 0x08, // 0x1004 mov [rax+8], rcx
            0x48, 0x83, 0xC4, 0x20, // 0x1008 add rsp, 0x20
            0xC3, // 0x100c ret
        ];
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);

        let hit = ProvenanceHit { instruction_va: Va(0x1004), access_kind: "write".to_string() };
        let graph = ProvenancePass
            .run(
                &ctx,
                ProvenanceInput {
                    value_addr: Va(0x2008),
                    hits: vec![hit],
                    module: None,
                    code_scan_start: Some(Va(0x1000)),
                    code_scan_size: 64,
                },
            )
            .unwrap();

        assert_eq!(graph.entries.len(), 1);
        let entry = &graph.entries[0];
        assert_eq!(entry.function_va, Some(Va(0x1000)), "should resolve the containing function");
        assert!(!entry.decompiled_context.is_empty(), "should have extracted the block's pseudo-C");
        let text = entry.decompiled_context.join("\n");
        assert!(text.contains("rcx"), "expected the write's source register in the decompiled context: {text}");
    }

    #[test]
    fn a_hit_with_no_module_or_scan_range_still_reports_the_raw_address() {
        let snap = Snapshot::builder().region(Va(0x1000), vec![0xC3]).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let hit = ProvenanceHit { instruction_va: Va(0x1000), access_kind: "execute".to_string() };
        let graph = ProvenancePass
            .run(&ctx, ProvenanceInput { value_addr: Va(0x1000), hits: vec![hit], module: None, code_scan_start: None, code_scan_size: 0 })
            .unwrap();
        assert_eq!(graph.entries.len(), 1);
        assert_eq!(graph.entries[0].function_va, None);
        assert!(graph.entries[0].decompiled_context.is_empty());
    }
}

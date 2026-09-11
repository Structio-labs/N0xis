// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`ProvenancePass`] — ROADMAP Phase 4c, the static⇄dynamic fusion
//! (CONCEPT §11, KF-1): fuses the dynamic side (a hardware-watchpoint hit —
//! "something at this address just read/wrote/executed this instruction",
//! already built in Phase 4b's `debug watch`) with the static side (the SSA
//! decompiler, Phase 3) into one typed, agent-readable explanation of what a
//! runtime value *means*.
//!
//! Nothing joins the two sides in one step: a "find what accesses this address"
//! scan stops at a raw disassembly line, and a decompiler has no knowledge of a
//! live watchpoint hit at all. This pass is
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
    /// The instruction that performed the access — **not** always the address
    /// the trap reported. See [`responsible_instruction`].
    pub instruction_va: Va,
    /// The raw address the hardware trap reported, when it differs from
    /// `instruction_va`. Present only on a data access that had to be stepped
    /// back, so nothing is hidden: the corrected answer and the number it was
    /// corrected from are both in the envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trap_va: Option<Va>,
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
    /// Why there is no `function_va`/`decompiled_context`, when there is none.
    ///
    /// The two fields above are the whole reason this command exists — the
    /// difference between "something wrote your value" and "*this statement*
    /// wrote your value". When the containing function cannot be recovered they
    /// simply vanished from the envelope, and a caller could not tell a tool
    /// that does not do this from a target where it did not work. Say which.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_unavailable: Option<String>,
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
    let mut context_unavailable = None;
    let found = scan_start.and_then(|start| find_function_containing(ctx, start, scan_size, hit.instruction_va));
    if scan_start.is_none() {
        context_unavailable =
            Some(format!("no executable range was resolved for the module holding {}", hit.instruction_va));
    } else if found.is_none() {
        context_unavailable = Some(format!(
            "no recovered function contains {} — on a live target without symbols the containing \
             function is found by prologue scanning, and a leaf function that starts with plain \
             arithmetic has no prologue to find",
            hit.instruction_va
        ));
    }
    let mut site = hit.instruction_va;
    if let Some((func_start, cfg)) = found {
        function_va = Some(func_start);
        // The address the hardware reported is not always the address that did
        // the work — see `responsible_instruction`.
        site = responsible_instruction(&cfg, hit.instruction_va, &hit.access_kind).unwrap_or(hit.instruction_va);
        // Extract the block id (Copy) before `cfg` moves into `DecompInput`.
        let block_id = cfg
            .blocks
            .iter()
            .find(|b| b.start.get() <= site.get() && site.get() < b.end.get())
            .map(|b| b.id);
        if let Some(block_id) = block_id
            && let Ok(pseudo) = DecompPass.run(ctx, DecompInput { cfg, style: DecompStyle::Ssa, explain: false, strip_block_labels: false, var_names: Default::default(), var_types: Default::default(), struct_defs: Default::default() })
        {
            decompiled_context = extract_block_context(&pseudo.pseudo, block_id);
        }
    }

    if function_va.is_some() && decompiled_context.is_empty() && context_unavailable.is_none() {
        context_unavailable =
            Some(format!("the containing function {} was recovered but its block did not render", site));
    }
    let (module_name, rva) = if site == hit.instruction_va {
        (module_name, rva)
    } else {
        match module {
            Some(m) => (Some(m.name.clone()), m.rva(site)),
            None => (module_name, rva),
        }
    };
    ProvenanceEntry {
        instruction_va: site,
        trap_va: (site != hit.instruction_va).then_some(hit.instruction_va),
        access_kind: hit.access_kind,
        module: module_name,
        rva,
        function_va,
        decompiled_context,
        context_unavailable,
    }
}

/// The instruction that actually performed a data access, given the address the
/// hardware trap reported.
///
/// An x86 data breakpoint is **trap**-class: the CPU raises it *after* the
/// instruction that touched the address has retired, so the reported `rip` is
/// the instruction that comes next. An execute breakpoint is fault-class and
/// reports before executing, so its address is already the right one and is
/// returned untouched.
///
/// Measured on a target whose writing instruction was known from its own
/// source: the trap reported `0x401381`, and the write was `mov [rdx], eax` at
/// `0x40137f`. Naming the trap address made this command answer a different
/// question from the one it exists to answer — the statement it printed as
/// responsible was the *following* one.
///
/// Backwards decoding is not possible on a variable-length ISA, so the answer
/// comes from the containing function's own instruction stream: the responsible
/// instruction is the one that **ends** where the trap was reported. `None`
/// when no instruction does — an access from a function this CFG does not
/// cover, say — and the caller then keeps the reported address rather than
/// guessing one.
fn responsible_instruction(cfg: &CfgArtifact, trap: Va, access_kind: &str) -> Option<Va> {
    if access_kind == "execute" {
        return None;
    }
    cfg.blocks
        .iter()
        .flat_map(|b| b.insns.iter())
        .find(|i| i.va.get().checked_add(u64::from(i.len)) == Some(trap.get()))
        .map(|i| i.va)
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

    // Nothing with a recognised prologue covers the target. A leaf function
    // often has none — `n0x_tick` on the verification target begins
    // `mov rax,rdi`, which no prologue pattern matches — so the whole
    // explanation collapsed to a bare address for exactly the small functions
    // a watchpoint most often lands in.
    //
    // The other boundary a function has is the end of the one before it. Walk
    // back from the target to the nearest return and try the byte after it:
    // that is where the next function starts, whatever its prologue looks like.
    boundary_before(ctx, win_start, target)
        .and_then(|start| CfgPass.run(ctx, CfgInput::new(start, FUNCTION_MAX_BYTES)).ok().map(|cfg| (start, cfg)))
        .filter(|(_, cfg)| target.get() < cfg.end.get())
}

/// The most recent function boundary below `target`.
///
/// Decoding backward is not possible on x86, so this decodes *forward* from
/// `from` and keeps the last boundary it passes. Two things mark one, and both
/// are needed: a `ret`, and the end of a padding run. The first version looked
/// only for `ret` and still found nothing on the verification target, because
/// the function before the one being explained ends in an infinite `loop {}` —
/// a backward `jmp` — and is followed by `int3` padding. Padding is the more
/// general marker: a compiler puts it *between* functions and nowhere else.
fn boundary_before(ctx: &Ctx, from: u64, target: Va) -> Option<Va> {
    let len = target.get().checked_sub(from)? as usize;
    if len == 0 || len > DISCOVER_WINDOW_BACK as usize {
        return None;
    }
    let bytes = ctx.source.read(Va(from), len).ok()?;
    let insns = ctx.arch.decode_range(&bytes, Va(from), usize::MAX);

    let is_padding = |i: &n0xis_arch::DecodedInsn| i.mnemonic == "int3" || i.mnemonic == "nop";
    let mut boundary: Option<u64> = None;
    let mut in_padding = false;
    for i in &insns {
        if i.va.get() >= target.get() {
            break;
        }
        if is_padding(i) {
            in_padding = true;
            continue;
        }
        // The first non-padding instruction after a padding run starts a
        // function; so does the one after a return.
        if in_padding {
            boundary = Some(i.va.get());
            in_padding = false;
        }
        if i.kind == n0xis_arch::InsnKind::Ret {
            boundary = Some(i.va.get() + i.len as u64);
        }
    }
    boundary.filter(|&b| b <= target.get()).map(Va)
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

    /// A leaf function has no prologue to find, and this is the command's whole
    /// point.
    ///
    /// The README's front-page example is a watchpoint resolved to the
    /// *statement* that moved the value. On a live target there are no symbols
    /// and no `.pdata`, so the containing function is found by scanning for a
    /// prologue — and a leaf function that begins `mov rax,rdi` has none. The
    /// explanation then collapsed to a bare address with no field saying why:
    /// exactly the answer the command exists to improve on. Measured on the
    /// verification target, where `n0x_tick` is such a function.
    ///
    /// The recovery is the other boundary a function has — the padding a
    /// compiler puts *between* functions. (A `ret` alone is not enough: the
    /// function before this one on the real target ends in an infinite loop.)
    #[test]
    fn a_leaf_function_with_no_prologue_is_still_explained() {
        // 0x1000  a function ending in a backward jmp — an infinite loop, so
        //         there is no `ret` to find before the next function.
        // 0x1004  int3 padding
        // 0x1008  the leaf: mov rax,rdi ; mov [rip+..],rdi ; ret
        let code = vec![
            0x48, 0x83, 0xEC, 0x20, // 0x1000 sub rsp,0x20 (a recognised prologue)
            0xEB, 0xFE, // 0x1004 jmp $  (infinite loop, no ret)
            0xCC, 0xCC, // 0x1006 padding
            0x48, 0x89, 0xF8, // 0x1008 mov rax,rdi   <- leaf starts here, no prologue
            0x48, 0x89, 0x3D, 0x10, 0x00, 0x00, 0x00, // 0x100b mov [rip+0x10],rdi
            0xC3, // 0x1012 ret
        ];
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = ProvenancePass
            .run(
                &ctx,
                ProvenanceInput {
                    value_addr: Va(0x1022),
                    hits: vec![ProvenanceHit {
                        instruction_va: Va(0x100b),
                        access_kind: "write".into(),
                    }],
                    module: None,
                    code_scan_start: Some(Va(0x1000)),
                    code_scan_size: 0x13,
                },
            )
            .expect("provenance runs");
        let e = &art.entries[0];
        assert_eq!(e.function_va, Some(Va(0x1008)), "the leaf begins after the padding run");
        assert!(!e.decompiled_context.is_empty(), "the statement, not just the address: {e:?}");
        assert!(e.context_unavailable.is_none());
    }

    /// When the function genuinely cannot be recovered, say so.
    ///
    /// The two fields that carry the explanation simply vanished from the
    /// envelope, and a caller could not tell a tool that does not do this from
    /// a target where it did not work.
    #[test]
    fn an_unexplainable_hit_says_why_instead_of_omitting_the_fields() {
        let snap = Snapshot::builder().region(Va(0x1000), vec![0x90; 8]).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = ProvenancePass
            .run(
                &ctx,
                ProvenanceInput {
                    value_addr: Va(0x2000),
                    hits: vec![ProvenanceHit { instruction_va: Va(0x1004), access_kind: "write".into() }],
                    module: None,
                    code_scan_start: None,
                    code_scan_size: 0,
                },
            )
            .expect("provenance runs");
        let e = &art.entries[0];
        assert!(e.function_va.is_none());
        assert!(e.context_unavailable.is_some(), "a missing explanation must state its reason");
    }

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

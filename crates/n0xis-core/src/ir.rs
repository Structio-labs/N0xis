// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`CfgPass`] — control-flow graph + block/def-use IR.
//!
//! The first real analysis pass. Over the [`Arch`](n0xis_arch::Arch) and source
//! seams it: decodes a function's linear extent (optionally auto-detecting the
//! end), computes basic-block leaders, splits blocks, wires successor edges
//! (fall / jmp / cjmp-true / cjmp-false / tail), and records per-instruction
//! register **def-use** (each read linked to its defining instruction in the
//! block). Call targets resolve to names when a [`SymbolProvider`] is present.
//!
//! Ported from the proven v0 `ir.rs` CFG core, refit to `DecodedInsn` +
//! [`Arch::reg_access`](n0xis_arch::Arch::reg_access) so no ISA decoder leaks
//! into the pass. Switch resolution and frame analysis are recognized entirely
//! by the arch seam (`Arch::detect_switch` / `Arch::analyze_frame`); arg-hint
//! recovery is a follow-on slice.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use n0xis_arch::{DecodedInsn, FrameInfo, InsnKind};
use n0xis_contracts::{SymKind, Va};
use serde::{Deserialize, Serialize};

use crate::switch::{ResolvedSwitch, SWITCH_CASE_CONFIDENCE, resolve_switch};
use crate::{Ctx, CoreError, Pass};

/// Generous linear cap; `auto_end` normally stops well before this.
const DEFAULT_MAX_INSNS: usize = 8192;

/// What to analyze.
#[derive(Clone, Copy, Debug)]
pub struct CfgInput {
    pub start: Va,
    /// Byte window to pull from the source (the function's max extent).
    pub max_bytes: usize,
    /// Stop at the detected function end (a terminator past all forward edges).
    pub auto_end: bool,
}

impl CfgInput {
    pub fn new(start: Va, max_bytes: usize) -> Self {
        CfgInput {
            start,
            max_bytes,
            auto_end: true,
        }
    }
}

/// The CFG + def-use artifact (`n0xis.ir.cfg.v1`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CfgArtifact {
    pub start: Va,
    pub end: Va,
    pub block_count: usize,
    pub insn_count: usize,
    pub blocks: Vec<CfgBlock>,
    pub callsites: Vec<Callsite>,
    /// Jump-table dispatches whose cases were resolved from memory (the
    /// live-source edge). Empty when the function has no recognized switch.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub switches: Vec<ResolvedSwitch>,
    /// What the prolog reveals about the stack frame (arch-recognized).
    pub frame: FrameInfo,
    pub stats: CfgStats,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CfgStats {
    pub returns: usize,
    pub calls: usize,
    pub indirect_branches: usize,
    pub tail_calls: usize,
    /// Calls to a well-known noreturn import (`ExitProcess`, `abort`, …) —
    /// each one ends its block like a `ret` (terminator `"call-noreturn"`),
    /// since nothing after it is reachable (ROADMAP Phase 10, CFG fidelity).
    /// `#[serde(default)]` so a pre-existing `.n0x/ir-cache/*.json` entry
    /// (Phase 6) from before this field existed still deserializes (as `0`,
    /// same observable behavior as the old code) instead of erroring.
    #[serde(default)]
    pub noreturn_calls: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CfgBlock {
    pub id: usize,
    pub start: Va,
    pub end: Va,
    /// How the block leaves: `fall` / `jmp` / `cjmp` / `ijmp` / `ret` / `int` /
    /// `tail-call` / `call-noreturn` (a call to a well-known noreturn import —
    /// zero successors, nothing after it is reachable).
    pub terminator: String,
    pub successors: Vec<Successor>,
    pub insns: Vec<IrInsn>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Successor {
    pub to: Va,
    pub kind: String,
    pub confidence: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IrInsn {
    pub va: Va,
    pub len: u8,
    pub mnemonic: String,
    pub text: String,
    /// Flow classification (`seq` / `call` / `jump` / `cond_jump` / `ret` / …).
    pub flow: InsnKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<Va>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reads: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub writes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub def_use: Vec<DefUse>,
    /// The instruction's condition when it executes conditionally (AArch32), e.g.
    /// `Some("eq")` — carried from the arch's stateful decode (a Thumb `IT`-block
    /// condition can't be re-derived from a standalone re-decode) so the lift
    /// reads it here. `None` for unconditional / other arches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cond: Option<String>,
    /// On a return, the argument bytes the callee pops (`ret 8` → `Some(8)`).
    /// Carried through from the decode because it is the only statement a
    /// stack-argument ABI makes about a function's arity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_adjust: Option<u16>,
}

/// A read of `reg` linked back to the instruction that last defined it in this
/// block (the local def-use chain).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DefUse {
    pub reg: String,
    pub def_index: usize,
    pub def_addr: Va,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Callsite {
    pub from: Va,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<Va>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_name: Option<String>,
    /// For a call/tail-jump made *through* a memory slot (`call qword ptr
    /// [rip+disp]` — an import), the slot's address. The callee VA itself is
    /// unknowable statically (the loader fills the slot at run time), so
    /// `target` stays `None` while this pins down *which* pointer is called —
    /// which is what lets the renderer print the import's name instead of a
    /// raw dereference, and what an agent needs to correlate a callsite with
    /// a live IAT read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_slot: Option<Va>,
}

/// CFG construction pass.
#[derive(Clone, Copy, Debug, Default)]
pub struct CfgPass;

impl Pass for CfgPass {
    type In = CfgInput;
    type Out = CfgArtifact;

    fn name(&self) -> &'static str {
        "ir.cfg"
    }

    fn run(&self, ctx: &Ctx, input: CfgInput) -> Result<CfgArtifact, CoreError> {
        // The declared extent is a **fact** about the function; `max_bytes` is a
        // budget for guessing when there is none. Reading only the budget and
        // then discarding a declared end that fell outside it is the worst of
        // both: `QPageSize::name` is 5 102 bytes by both `st_size` and its FDE,
        // and came back as 99 — the heuristic cut at the first indirect jump —
        // taking its 119 switch cases out of the function with it. 334 of one
        // Qt build's 15 467 declared functions are longer than the default
        // window, and every one of them was reshaped this way.
        let stated_len = declared_extent(ctx, input.start).map(|e| e.saturating_sub(input.start.0));
        let want = match stated_len {
            // A length read out of an image is never trusted to size a read —
            // the ceiling is what a function could plausibly be, not what the
            // bytes claim.
            Some(n) => input.max_bytes.max((n as usize).min(MAX_DECLARED_EXTENT)),
            None => input.max_bytes,
        };
        let bytes = ctx.source.read(input.start, want)?;
        let end_cap = input.start.0 + bytes.len() as u64;
        let all = ctx
            .arch
            .decode_stream(&bytes, input.start, DEFAULT_MAX_INSNS);
        // An authoritative extent beats the heuristic outright. Two sources
        // state one, and both are read here: the linker's `st_size` on a
        // symbolized ELF (and a PE's `.pdata`, which `symbol_size` reports),
        // and the unwind tables via `Ctx::functions` — `.eh_frame` FDEs or the
        // same `.pdata`. The second matters because a stripped or
        // partially-symbolized image still carries unwind information: on one
        // Qt build `.eh_frame` states an extent for 15 467 functions where the
        // symbol table speaks for 7 105, and the two agree on every function
        // where both do. Without it the heuristic ran on the difference and
        // stretched an 82-byte function to the whole 32 KB decode window.
        //
        // This fixes BOTH failure directions the heuristic has — over-extending
        // past a `call __stack_chk_fail` into the next function, and stopping
        // short of an exception landing pad that no control-flow edge reaches.
        // With neither source the heuristic is unchanged.
        let stated_end = declared_extent(ctx, input.start).filter(|e| *e <= end_cap);
        let instrs = match (input.auto_end, stated_end) {
            (true, Some(end)) => all.into_iter().take_while(|i| i.va.0 < end).collect(),
            (true, None) => {
                // The heuristic raises the function's end for every **direct**
                // forward branch it sees. A jump-table case target is not a
                // direct branch, so a case body emitted after the default's
                // `ret` — which is where gcc routinely puts one — fell outside
                // the function, and the resolver then dropped that case for not
                // landing on an instruction of this function. A switch silently
                // short one case is *missing control flow*, which is the CFG's
                // worst failure and the one thing downstream cannot detect.
                //
                // So: truncate, resolve whatever switches are now in view, and
                // if any of their cases lie beyond the cut, truncate again with
                // that as a floor. It only ever **extends**, only on a switch
                // whose case count a guard bounds — the same evidence the CFG
                // already trusts to create the edges — and only within the
                // analysis window. Bounded to three rounds; one is enough on
                // every corpus here, and an unbounded loop over a heuristic is
                // how a function grows to fill a 32 KB window.
                let mut floor = input.start.0;
                let mut instrs = truncate_to_function(&all, input.start.0, end_cap, floor, |ins| {
                    is_noreturn_call(ctx, ins)
                });
                for _ in 0..3 {
                    let reach = switch_case_reach(ctx, &instrs, input.start.0, end_cap);
                    if reach <= floor {
                        break;
                    }
                    floor = reach;
                    instrs = truncate_to_function(&all, input.start.0, end_cap, floor, |ins| {
                        is_noreturn_call(ctx, ins)
                    });
                }
                instrs
            }
            (false, _) => all,
        };

        build(ctx, &instrs, input.start)
    }
}

/// Resolve the symbolic name of a branch/call target: a direct near-branch
/// operand first, falling back to the RIP-relative memory operand (an IAT
/// slot — the shape of `call qword ptr [rip+disp]` to an import, and of an
/// import thunk's `jmp`). Without the fallback the overwhelming majority of
/// real import calls resolve no name at all, silently defeating both noreturn
/// detection and thunk tail-call recognition. Single source of truth: used by
/// both the function-end heuristic and CFG construction.
/// The import a **thunk** forwards to.
///
/// A linker does not always let a call reach an IAT slot directly: it emits a
/// six-byte stub, `jmp qword ptr [rip+disp]`, and every caller calls the stub.
/// Both existing sources miss it — the stub has no symbol of its own, and the
/// *caller's* instruction is a plain direct call with no RIP operand — so the
/// callee came back as `sub_XXXX` and everything keyed on the name went blind.
///
/// Measured on a real C++ DLL: the whole-program noreturn fixpoint proved
/// **2** functions of 1 398, against 12 an independent function table finds.
/// The ten it missed are `_Xbad_alloc`, `_Xlength_error`, `terminate` and
/// their siblings — every one of which ends in a call to the
/// `_CxxThrowException` *stub*, whose name it could not see.
///
/// One decode of the target, and only for a call whose callee is otherwise
/// nameless.
pub(crate) fn thunk_import(ctx: &Ctx, target: Va) -> Option<n0xis_contracts::Symbol> {
    let bytes = ctx.source.read(target, 16).ok()?;
    let ins = ctx.arch.decode(&bytes, target).ok()?;
    if ins.kind != InsnKind::Jump || ins.target.is_some() {
        return None;
    }
    ctx.symbols.and_then(|s| s.iat_slot(ins.rip_target?))
}

/// The symbol on a function **entry**, including the import an entry that is
/// only an import stub stands for.
///
/// One answer, so two commands cannot give an address two names. `function
/// discover`, `function summary` and `xref` each resolved this themselves, and
/// none of them knew about stubs — so a call to `_CxxThrowException` printed
/// the import's name while the function at that very address listed as
/// `sub_180049BFC`.
pub(crate) fn symbol_on_entry(ctx: &Ctx, va: Va) -> Option<n0xis_contracts::Symbol> {
    ctx.symbols.and_then(|s| s.symbol_at(va)).filter(|sym| sym.va == va).or_else(|| thunk_import(ctx, va))
}

fn resolved_target_name(ctx: &Ctx, ins: &DecodedInsn) -> Option<String> {
    ins.target
        .and_then(|t| ctx.symbols.and_then(|s| s.symbol_at(t)))
        .or_else(|| ins.rip_target.and_then(|t| ctx.symbols.and_then(|s| s.iat_slot(t))))
        .or_else(|| ins.target.and_then(|t| thunk_import(ctx, t)))
        // A function *defined in this image* — however we learned its name (an
        // export table, an ELF `.symtab`, a signature match) — is called by its
        // bare name: `crc32_z`, not `libz.so!crc32_z`. The `module!` prefix exists
        // only to route a cross-module **import** (`kernel32!CreateFileW`,
        // `MSVCP140.dll!?sputc@…`) through the demangler and keep it
        // identifier-safe, so it belongs to imports alone.
        .map(|sym| match sym.kind {
            SymKind::Import => format!("{}!{}", sym.module, sym.name),
            _ => sym.name,
        })
}

/// The memory slot a call/branch goes *through*, for the indirect-through-
/// memory shape (`call`/`jmp qword ptr [rip+disp]`). `None` for a direct
/// branch — there the callee address is the operand itself, in `target`.
fn memory_slot(ins: &DecodedInsn) -> Option<Va> {
    ins.target.is_none().then_some(ins.rip_target).flatten()
}

/// Is this instruction a call to a function that never comes back? Two sources,
/// both ending the block (and, for [`truncate_to_function`], the function):
/// a well-known noreturn **import** (`ExitProcess`, `abort`, …), resolved by
/// name; or a direct call to one of N0xis's *own* discovered functions that the
/// whole-program fixpoint ([`crate::NoReturnPropagatePass`]) proved noreturn,
/// resolved by address through `ctx.noreturn`. The second is what lets a custom
/// `FatalError`/`Assert` wrapper — a `sub_XXXX`, not a named import — prune a
/// caller's dead fall-through (ROADMAP Phase 10, priority 0).
fn is_noreturn_call(ctx: &Ctx, ins: &DecodedInsn) -> bool {
    if ins.kind != InsnKind::Call {
        return false;
    }
    let by_name = resolved_target_name(ctx, ins)
        .as_deref()
        .and_then(|n| n.rsplit('!').next())
        .map(crate::noreturn::is_known_noreturn)
        .unwrap_or(false);
    let by_addr = matches!((ctx.noreturn, ins.target), (Some(set), Some(t)) if set.contains(&t));
    by_name || by_addr
}

/// Cut the linear stream at the detected function end. Ported from v0
/// `decode_linear`'s auto-end heuristic: track the furthest forward in-range
/// edge; a terminator whose fallthrough passes it ends the function.
///
/// `is_noreturn_call` reports a call that never comes back (`ExitProcess`,
/// `abort`, …). Such a call ends the function exactly like a `ret` when no
/// forward edge reaches past it — without it the heuristic walks straight
/// into the padding/next function after a `call ExitProcess` (ROADMAP Phase
/// 10, priority 0: the follow-on the per-block CFG fix deliberately left).
/// How far any **resolved, guard-bounded** jump table in `instrs` reaches.
///
/// Only a switch whose case count a guard bounds counts: an unbounded probe
/// walks off the end of its own table into the neighbouring one, whose entries
/// are code addresses too and so pass every check — 229 cases where the guard
/// says 29, on one real function. The bound is what makes this evidence rather
/// than a guess, and it is the same evidence the CFG uses for the edges.
fn switch_case_reach(ctx: &Ctx, instrs: &[DecodedInsn], start: u64, end_cap: u64) -> u64 {
    let mut furthest = start;
    for (idx, ins) in instrs.iter().enumerate() {
        if ins.kind != InsnKind::Jump || ins.target.is_some() {
            continue;
        }
        // Where the dispatching block begins, approximately: after the last
        // instruction that ends a block. The detector reads the guard from
        // *before* that point, so offering the wrong boundary costs a bound and
        // therefore costs the extension — it cannot invent one.
        let block_start = instrs[..idx]
            .iter()
            .rposition(|i| {
                matches!(
                    i.kind,
                    InsnKind::CondJump | InsnKind::Jump | InsnKind::Ret | InsnKind::Int | InsnKind::Call
                )
            })
            .map(|p| p + 1)
            .unwrap_or(0);
        let Some(disp) = ctx.arch.detect_switch_with_context(&instrs[..=idx], block_start) else {
            continue;
        };
        let r = resolve_switch(ctx, &disp);
        if !r.resolved || r.bound.is_none() {
            continue;
        }
        for c in &r.cases {
            if c.0 >= start && c.0 < end_cap && c.0 > furthest {
                furthest = c.0;
            }
        }
    }
    furthest
}

fn truncate_to_function(
    all: &[DecodedInsn],
    start: u64,
    end_cap: u64,
    floor: u64,
    is_noreturn_call: impl Fn(&DecodedInsn) -> bool,
) -> Vec<DecodedInsn> {
    let mut max_forward_leader = start.max(floor);
    let mut cut = all.len();
    for (idx, ins) in all.iter().enumerate() {
        let next = ins.va.0 + ins.len as u64;
        let tgt = ins.target.map(|v| v.0).unwrap_or(0);
        let in_range = tgt != 0 && tgt >= start && tgt < end_cap;
        match ins.kind {
            InsnKind::CondJump if in_range && tgt > max_forward_leader => {
                max_forward_leader = tgt;
            }
            InsnKind::Jump => {
                let tail = !in_range;
                if !tail && tgt > max_forward_leader {
                    max_forward_leader = tgt;
                }
                if tail && next > max_forward_leader {
                    cut = idx + 1;
                    break;
                }
                if !tail && tgt < next && next > max_forward_leader {
                    cut = idx + 1;
                    break;
                }
            }
            InsnKind::Ret | InsnKind::Int if next > max_forward_leader => {
                cut = idx + 1;
                break;
            }
            InsnKind::Call if next > max_forward_leader && is_noreturn_call(ins) => {
                cut = idx + 1;
                break;
            }
            _ => {}
        }
    }
    all[..cut].to_vec()
}

/// Largest declared extent this will read for one function. A length that comes
/// out of an image never sizes a read unbounded (the OOM rule); no real
/// function approaches this, and one that claims to is not believed.
const MAX_DECLARED_EXTENT: usize = 1 << 20;

/// The exclusive end the image itself declares for the function at `start`, from
/// either source that states one: the linker's `st_size` (and a PE's `.pdata`,
/// which `symbol_size` reports), or the unwind tables via [`Ctx::functions`].
///
/// The second matters because a stripped or partially-symbolized image still
/// carries unwind information: on one Qt build `.eh_frame` states an extent for
/// 15 467 functions where the symbol table speaks for 7 105, and the two agree
/// on every function where both do.
fn declared_extent(ctx: &Ctx, start: Va) -> Option<u64> {
    if let Some(end) = ctx.symbols.and_then(|s| s.symbol_size(start)).and_then(|n| start.0.checked_add(n))
        && end > start.0
    {
        return Some(end);
    }
    // Sorted by start (see `Ctx::functions`), so this is a lookup, not a walk:
    // a linear scan would be 15 467 comparisons per function on a Qt-sized image.
    let f = ctx.functions?;
    let i = f.binary_search_by(|(s, _)| s.0.cmp(&start.0)).ok()?;
    Some(f[i].1.0).filter(|e| *e > start.0)
}

fn compute_leaders(instrs: &[DecodedInsn], valid: &BTreeSet<u64>) -> BTreeSet<u64> {
    let mut leaders = BTreeSet::new();
    if let Some(first) = instrs.first() {
        leaders.insert(first.va.0);
    }
    for ins in instrs {
        if matches!(
            ins.kind,
            InsnKind::CondJump | InsnKind::Jump | InsnKind::Ret | InsnKind::Int
        ) {
            let next = ins.va.0 + ins.len as u64;
            if valid.contains(&next) {
                leaders.insert(next);
            }
            if let Some(t) = ins.target
                && valid.contains(&t.0)
            {
                leaders.insert(t.0);
            }
        }
    }
    leaders
}

fn edge_confidence(kind: &str) -> f32 {
    match kind {
        "fall" | "jmp" | "cjmp-true" | "cjmp-false" => 1.0,
        _ => 0.8,
    }
}

fn build(ctx: &Ctx, instrs: &[DecodedInsn], start: Va) -> Result<CfgArtifact, CoreError> {
    let frame = ctx.arch.analyze_frame(instrs);
    let end_ip = instrs
        .last()
        .map(|i| i.va.0 + i.len as u64)
        .unwrap_or(start.0);
    let valid: BTreeSet<u64> = instrs.iter().map(|i| i.va.0).collect();
    let mut leaders = compute_leaders(instrs, &valid);
    // A landing pad is entered by the unwinder, never by a branch, so nothing in
    // `compute_leaders` would ever start a block there — it would be swallowed
    // into whatever block precedes it (ROADMAP Phase 10, priority 0).
    let eh_regions: &[crate::EhRegion] = ctx.eh.unwrap_or(&[]);
    for r in eh_regions {
        if valid.contains(&r.landing_pad.0) {
            leaders.insert(r.landing_pad.0);
        }
    }

    // Resolve the jump tables **before** the blocks are cut, because a case
    // target starts a block exactly the way a branch target does. Resolving
    // them inside the block loop, as this used to, left every case pointing
    // into the *middle* of whatever block happened to contain it — an edge no
    // consumer can follow, and a malformed graph.
    let mut resolved_switches: BTreeMap<u64, ResolvedSwitch> = BTreeMap::new();
    {
        let mut block_start = 0usize;
        for (idx, ins) in instrs.iter().enumerate() {
            if ins.kind == InsnKind::Jump
                && ins.target.is_none()
                && let Some(disp) = ctx.arch.detect_switch_with_context(&instrs[..=idx], block_start)
            {
                let r = resolve_switch(ctx, &disp);
                for c in &r.cases {
                    if valid.contains(&c.0) {
                        leaders.insert(c.0);
                    }
                }
                resolved_switches.insert(ins.va.0, r);
            }
            // A terminator ends the block, so the next instruction starts one —
            // the same rule `compute_leaders` follows.
            if matches!(ins.kind, InsnKind::CondJump | InsnKind::Jump | InsnKind::Ret | InsnKind::Int) {
                block_start = idx + 1;
            }
        }
    }
    let mut block_id_by_ip: BTreeMap<u64, usize> = BTreeMap::new();
    for (id, ip) in leaders.iter().enumerate() {
        block_id_by_ip.insert(*ip, id);
    }

    let mut blocks: Vec<CfgBlock> = Vec::new();
    let mut callsites: Vec<Callsite> = Vec::new();
    let mut switches: Vec<ResolvedSwitch> = Vec::new();
    let mut stats = CfgStats::default();

    let mut i = 0usize;
    while i < instrs.len() {
        let block_start_ip = instrs[i].va.0;
        let block_id = *block_id_by_ip.get(&block_start_ip).unwrap_or(&blocks.len());
        let mut ir_insns: Vec<IrInsn> = Vec::new();
        let mut successors: Vec<Successor> = Vec::new();
        let mut terminator = "fall".to_string();
        // reg -> (index-in-block, defining address)
        let mut last_def: HashMap<String, (usize, u64)> = HashMap::new();

        loop {
            let ins = &instrs[i];
            let mut access = ctx.arch.reg_access(ins);
            // A `call` architecturally writes only `rsp`, and that is what
            // `reg_access` answers, because whether `rax` changes is an ABI
            // fact about the callee rather than a property of the instruction.
            // Def-use analysis needs the ABI fact: without it the definition of
            // the value a call produced does not exist, and a backward slice of
            // that value stops at the `mov` that copied it out of the return
            // register without ever naming the call. Measured on a function
            // whose source is `middle(v) + leaf_a(v)`: the slice reported the
            // three register moves and neither call.
            if ins.kind == InsnKind::Call
                && let Some(ret) = abi_return_register(ctx)
                && !access.writes.contains(&ret)
            {
                access.writes.push(ret);
            }

            let mut def_use = Vec::new();
            for r in &access.reads {
                if let Some((idx, addr)) = last_def.get(r) {
                    def_use.push(DefUse {
                        reg: r.clone(),
                        def_index: *idx,
                        def_addr: Va(*addr),
                    });
                }
            }

            // Resolve the target's name via the symbol seam (direct operand
            // first, IAT slot second) — see `resolved_target_name`.
            let target_name = resolved_target_name(ctx, ins);

            // A direct `jmp` outside this function's own range is a tail call.
            let is_direct_tail = ins.kind == InsnKind::Jump
                && ins
                    .target
                    .map(|t| t.0 < start.0 || t.0 >= end_ip)
                    .unwrap_or(false);
            // So is an **import thunk** — `jmp qword ptr [rip+disp]` through an
            // IAT slot, the single most common tail-call shape in a real PE
            // (every `__imp_` forwarder is one). The branch is indirect, but
            // the callee is known *by name*, so classifying it as an
            // unrecoverable `ijmp` throws away information we hold: a resolved
            // IAT name here is treated as a tail call, not a dead end
            // (ROADMAP Phase 10, priority 0). `target_name` can only have come
            // from the `iat_slot` arm when there is no direct target.
            let is_thunk_tail =
                ins.kind == InsnKind::Jump && ins.target.is_none() && target_name.is_some();
            let is_tail = is_direct_tail || is_thunk_tail;

            let cur_index = ir_insns.len();
            ir_insns.push(IrInsn {
                va: ins.va,
                len: ins.len,
                mnemonic: ins.mnemonic.clone(),
                text: ins.text.clone(),
                flow: ins.kind,
                target: ins.target,
                target_name: target_name.clone(),
                reads: access.reads.clone(),
                writes: access.writes.clone(),
                def_use,
                cond: ins.cond.clone(),
                stack_adjust: ins.stack_adjust,
            });
            for w in &access.writes {
                last_def.insert(w.clone(), (cur_index, ins.va.0));
            }

            match ins.kind {
                InsnKind::Ret => {
                    stats.returns += 1;
                    terminator = "ret".into();
                    i += 1;
                    break;
                }
                InsnKind::Int => {
                    terminator = "int".into();
                    i += 1;
                    break;
                }
                InsnKind::Jump => {
                    if is_tail {
                        stats.tail_calls += 1;
                        terminator = "tail-call".into();
                        callsites.push(Callsite {
                            from: ins.va,
                            kind: "tail".into(),
                            target: ins.target,
                            target_name,
                            via_slot: memory_slot(ins),
                        });
                    } else if let Some(t) = ins.target {
                        terminator = "jmp".into();
                        successors.push(Successor {
                            to: t,
                            kind: "jmp".into(),
                            confidence: edge_confidence("jmp"),
                        });
                    } else {
                        stats.indirect_branches += 1;
                        terminator = "ijmp".into();
                        // Try to recognize a jump-table dispatch and resolve its
                        // cases from memory, closing the CFG for the switch.
                        // The bound check that says how many cases a table has
                        // (`cmp $0x1c,%edx` / `ja default`) ends its own basic
                        // block, so it is in the *predecessor*, not here.
                        // Passing only this block hid it, the walk fell back to
                        // an unbounded probe, and it ran on through whatever
                        // followed — in a densely packed jump-table region that
                        // is the neighbouring tables, whose entries are code
                        // addresses too and so pass every check. One Qt
                        // function came out with 229 cases where the guard says
                        // 29. Every instruction decoded for this function so
                        // far is offered instead, so the guard is in view.
                        if let Some(resolved) = resolved_switches.remove(&ins.va.0) {
                            for case in &resolved.cases {
                                // A case must land on an instruction boundary of
                                // *this* function. A table entry that does not
                                // is not a case of this switch, and an edge to
                                // it is invented control flow — the CFG's worst
                                // failure, because it is indistinguishable from
                                // the real thing downstream.
                                if !valid.contains(&case.0) {
                                    continue;
                                }
                                successors.push(Successor {
                                    to: *case,
                                    kind: "switch-case".into(),
                                    confidence: SWITCH_CASE_CONFIDENCE,
                                });
                            }
                            switches.push(resolved);
                        }
                    }
                    i += 1;
                    break;
                }
                InsnKind::CondJump => {
                    terminator = "cjmp".into();
                    if let Some(t) = ins.target {
                        if valid.contains(&t.0) {
                            successors.push(Successor {
                                to: t,
                                kind: "cjmp-true".into(),
                                confidence: edge_confidence("cjmp-true"),
                            });
                        } else {
                            // A conditional branch out of the function is a
                            // *conditional tail call* — `je some_stub`. There is
                            // no block on the other side, so an edge to it is
                            // one no consumer can follow; 320 of them on one Qt
                            // build. The call is the fact worth keeping, and
                            // the taken side is recorded as one.
                            stats.tail_calls += 1;
                            callsites.push(Callsite {
                                from: ins.va,
                                kind: "tail".into(),
                                target: Some(t),
                                target_name: target_name.clone(),
                                via_slot: memory_slot(ins),
                            });
                        }
                    }
                    // The fall-through needs the same gate as the taken side.
                    // A conditional branch as the function's *last* instruction
                    // has both sides outside it: the taken one was already
                    // recorded as a conditional tail call, and the fall-through
                    // lands on the next function's first byte. Emitting it
                    // anyway produces an edge to a block that does not exist —
                    // measured twice on one PE, against 19 437 edges, which is
                    // exactly the size at which an invented edge hides.
                    let next = ins.va.0 + ins.len as u64;
                    if valid.contains(&next) {
                        successors.push(Successor {
                            to: Va(next),
                            kind: "cjmp-false".into(),
                            confidence: edge_confidence("cjmp-false"),
                        });
                    } else {
                        stats.tail_calls += 1;
                        callsites.push(Callsite {
                            from: ins.va,
                            kind: "tail".into(),
                            target: Some(Va(next)),
                            target_name: None,
                            via_slot: None,
                        });
                    }
                    i += 1;
                    break;
                }
                InsnKind::Call => {
                    stats.calls += 1;
                    // A call to a well-known noreturn import (ExitProcess,
                    // abort, …) ends the block like a `ret`: nothing after it
                    // is reachable, so — unlike an ordinary call — it must
                    // not be treated as falling through (ROADMAP Phase 10).
                    let is_noreturn = is_noreturn_call(ctx, ins);
                    callsites.push(Callsite {
                        from: ins.va,
                        kind: if target_name.is_some() { "named" } else { "direct" }.into(),
                        target: ins.target,
                        target_name,
                        via_slot: memory_slot(ins),
                    });
                    if is_noreturn {
                        stats.noreturn_calls += 1;
                        terminator = "call-noreturn".into();
                        i += 1;
                        break;
                    }
                    // Otherwise: calls do not end a basic block.
                }
                _ => {}
            }

            i += 1;
            if i >= instrs.len() {
                break;
            }
            let next_ip = instrs[i].va.0;
            if leaders.contains(&next_ip) {
                terminator = "fall".into();
                successors.push(Successor {
                    to: Va(next_ip),
                    kind: "fall".into(),
                    confidence: edge_confidence("fall"),
                });
                break;
            }
        }

        let block_end_ip = ir_insns
            .last()
            .map(|x| x.va.0 + x.len as u64)
            .unwrap_or(block_start_ip);
        // Exception edges. An exception raised anywhere inside a protected range
        // transfers to that range's landing pad, so every block overlapping the
        // range gains the edge — not just the one holding `try_start`. Confidence
        // is below a decoded branch's on purpose: the transfer is real but
        // conditional on a throw, which no instruction here expresses.
        for r in eh_regions {
            let overlaps = block_start_ip < r.try_end.0 && block_end_ip > r.try_start.0;
            let pad = r.landing_pad.0;
            if overlaps && pad != block_start_ip && !successors.iter().any(|s| s.to.0 == pad) {
                successors.push(Successor { to: Va(pad), kind: "eh".into(), confidence: edge_confidence("eh") });
            }
        }
        blocks.push(CfgBlock {
            id: block_id,
            start: Va(block_start_ip),
            end: Va(block_end_ip),
            terminator,
            successors,
            insns: ir_insns,
        });
    }

    Ok(CfgArtifact {
        start,
        end: Va(end_ip),
        block_count: blocks.len(),
        insn_count: instrs.len(),
        blocks,
        callsites,
        switches,
        frame,
        stats,
    })
}

/// The ABI's **integer return register** — where a callee leaves its result,
/// and where a `ret` is modelled as reading one from.
///
/// The convention is chosen by name (`"win64"` for a PE, `"sysv"` for an ELF)
/// and falls back to the architecture's native one, exactly as the lift picks
/// it — so the two never disagree about where a return value lands.
pub(crate) fn abi_return_register(ctx: &Ctx) -> Option<String> {
    let cc = abi_conv(ctx)?;
    ctx.arch.regs().name(cc.ret).map(str::to_string)
}

/// **The** calling convention of the target, and the only place that choice is
/// made: the one whose name the *source* declares (`MemorySource::abi_name` —
/// `"win64"` for a PE, `"sysv"` for an ELF), falling back to the architecture's
/// first when the name is unknown.
///
/// One function because the rule was written out four times, and a rule copied
/// four times is a rule that will eventually be four different rules. Every
/// defect this pass found had that shape: one fact derived in more than one
/// place, drifting into a confident wrong answer rather than an error.
pub(crate) fn abi_conv<'a>(ctx: &'a Ctx<'a>) -> Option<&'a n0xis_arch::CallConv> {
    ctx.arch.calling_convention(ctx.source.abi_name())
}

/// The registers a floating-point argument **arrives in**, under the source's
/// ABI — empty where the ABI passes them on the stack (i386) or the lift does
/// not model them.
///
/// The mirror of [`float_return_registers`], through the same single
/// convention lookup. It was the missing half: parameter recovery scanned the
/// integer argument registers only, so `double f(double)` read its zero
/// integer arguments and the signature stated `(void)` — a claim of no
/// parameters for a function with one.
pub(crate) fn float_arg_registers(ctx: &Ctx) -> &'static [&'static str] {
    abi_conv(ctx).map(|cc| cc.float_args).unwrap_or(&[])
}

/// Does a floating-point argument take the same positional slot as an integer
/// one under this target's ABI (Win64) or a slot of its own (System V)? See
/// [`n0xis_arch::CallConv::float_args_share_position`].
pub(crate) fn float_args_share_position(ctx: &Ctx) -> bool {
    abi_conv(ctx).is_some_and(|cc| cc.float_args_share_position)
}

/// The registers a *floating-point* result comes back in, under the source's
/// ABI — `(None, None)` where the model has none (see
/// [`n0xis_arch::CallConv::ret_float`]).
///
/// Same convention lookup as [`abi_return_register`], for the same reason: the
/// lift, the CFG and the SSA pass must not disagree about where a value lands.
/// Both registers a floating-point result can arrive in: the scalar one, and
/// the second half of a two-member floating-point struct.
pub(crate) fn float_return_registers(ctx: &Ctx) -> (Option<&'static str>, Option<&'static str>) {
    match abi_conv(ctx) {
        Some(cc) => (cc.ret_float, cc.ret_float_second),
        None => (None, None),
    }
}

/// Human-readable summary lines (`ir explain`).
pub fn explain(art: &CfgArtifact) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "Function {} .. {} — {} instructions in {} blocks",
        art.start, art.end, art.insn_count, art.block_count
    ));
    lines.push(format!(
        "stats: {} returns, {} calls, {} indirect branches, {} tail calls, {} noreturn calls",
        art.stats.returns,
        art.stats.calls,
        art.stats.indirect_branches,
        art.stats.tail_calls,
        art.stats.noreturn_calls
    ));
    if art.frame.frame_size > 0 || art.frame.uses_rbp || !art.frame.spilled_regs.is_empty() {
        lines.push(format!(
            "frame: size=0x{:x} uses_rbp={} spilled=[{}]",
            art.frame.frame_size,
            art.frame.uses_rbp,
            art.frame.spilled_regs.join(",")
        ));
    }
    for b in &art.blocks {
        let succ: Vec<String> = b
            .successors
            .iter()
            .map(|s| format!("{}→{}", s.kind, s.to))
            .collect();
        lines.push(format!(
            "  block {} [{}..{}] {} ({} insns) {}",
            b.id,
            b.start,
            b.end,
            b.terminator,
            b.insns.len(),
            succ.join(" ")
        ));
    }
    if !art.callsites.is_empty() {
        lines.push(format!("callsites: {}", art.callsites.len()));
        for c in &art.callsites {
            let name = c.target_name.clone().unwrap_or_else(|| {
                c.target.map(|t| t.to_string()).unwrap_or_else(|| "?".into())
            });
            lines.push(format!("  {} {} -> {}", c.from, c.kind, name));
        }
    }
    if !art.switches.is_empty() {
        lines.push(format!("switches: {}", art.switches.len()));
        for sw in &art.switches {
            let table = sw.table.map(|t| t.to_string()).unwrap_or_else(|| "?".into());
            let bound = sw.bound.map(|b| b.to_string()).unwrap_or_else(|| "?".into());
            lines.push(format!(
                "  {} {} table={} idx={} scale={} bound={} -> {} cases",
                sw.at,
                sw.kind,
                table,
                sw.index_reg.clone().unwrap_or_else(|| "?".into()),
                sw.scale,
                bound,
                sw.cases.len(),
            ));
            for (n, case) in sw.cases.iter().enumerate() {
                lines.push(format!("    case[{n}] -> {case}"));
            }
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    #[test]
    fn builds_cfg_with_branch_and_defuse() {
        // 0x1000 cmp rcx,0   48 83 f9 00
        // 0x1004 je 0x1009   74 03
        // 0x1006 inc rcx     48 ff c1
        // 0x1009 ret         c3
        let code = vec![
            0x48, 0x83, 0xf9, 0x00, // cmp rcx, 0
            0x74, 0x03, // je +3 -> 0x1009
            0x48, 0xff, 0xc1, // inc rcx
            0xc3, // ret
        ];
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);

        let art = CfgPass
            .run(&ctx, CfgInput::new(Va(0x1000), 64))
            .expect("cfg builds");

        assert_eq!(art.block_count, 3, "entry / fallthrough / target blocks");
        // Entry block ends in a conditional branch with true+false edges.
        let entry = &art.blocks[0];
        assert_eq!(entry.terminator, "cjmp");
        assert_eq!(entry.successors.len(), 2);
        assert!(entry.successors.iter().any(|s| s.kind == "cjmp-true"));
        assert!(entry.successors.iter().any(|s| s.kind == "cjmp-false"));
        // Last block returns.
        assert_eq!(art.blocks.last().unwrap().terminator, "ret");
        assert_eq!(art.stats.returns, 1);
        // `inc rcx` writes rcx (def-use plumbing is populated by the arch seam).
        let wrote_rcx = art
            .blocks
            .iter()
            .flat_map(|b| &b.insns)
            .any(|i| i.writes.iter().any(|w| w == "rcx"));
        assert!(wrote_rcx, "reg_access should surface the rcx write");
    }

    #[test]
    fn resolves_mem_indexed_switch_from_memory() {
        // 0x1000 cmp rax, 2                 48 83 f8 02
        // 0x1004 jmp [rax*8 + 0x2000]       ff 24 c5 00 20 00 00
        // Absolute-pointer table at 0x2000 → cases 0x1500 / 0x1600 / 0x1700.
        // The case targets are inside the function, which is where a compiler
        // puts them — and a CFG edge to an address this function has no block
        // for is not an edge at all. The `ja` past the switch body is what
        // keeps the decode going far enough to cover them, exactly as the
        // guard/default pair does in real code.
        let mut code = vec![
            0x48, 0x83, 0xf8, 0x02, // 0x1000 cmp rax, 2  (bound = 2 → 3 cases)
            0x77, 0x28, //             0x1004 ja  +0x28 → 0x102e (the default)
            0xff, 0x24, 0xc5, 0x00, 0x20, 0x00, 0x00, // 0x1006 jmp qword [rax*8 + 0x2000]
        ];
        code.resize(0x2f, 0x90); // bodies at 0x1010/0x1018/0x1020, default 0x102e
        code[0x2e] = 0xc3; // ret
        let mut table = Vec::new();
        for case in [0x1010u64, 0x1018, 0x1020] {
            table.extend_from_slice(&case.to_le_bytes());
        }
        let snap = Snapshot::builder().region(Va(0x1000), code).region(Va(0x2000), table).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);

        let art = CfgPass
            .run(&ctx, CfgInput::new(Va(0x1000), 64))
            .expect("cfg builds");

        assert_eq!(art.stats.indirect_branches, 1, "the jmp is indirect");
        assert_eq!(art.switches.len(), 1, "one switch dispatch recognized");
        let sw = &art.switches[0];
        assert_eq!(sw.kind, "mem-indexed");
        assert_eq!(sw.table, Some(Va(0x2000)));
        assert_eq!(sw.bound, Some(2));
        assert_eq!(sw.entry_size, 8);
        assert!(sw.resolved, "cases came from memory");
        assert_eq!(sw.cases, vec![Va(0x1010), Va(0x1018), Va(0x1020)]);

        // The resolved cases become CFG edges — the switch is no longer a dead end.
        let edges: Vec<Va> = art
            .blocks
            .iter()
            .flat_map(|b| &b.successors)
            .filter(|s| s.kind == "switch-case")
            .map(|s| s.to)
            .collect();
        assert_eq!(edges, vec![Va(0x1010), Va(0x1018), Va(0x1020)]);
    }

    #[test]
    fn recognizes_a_standard_msvc_prolog() {
        // 0x1000 push rbx          53
        // 0x1001 sub rsp, 0x20     48 83 ec 20
        // 0x1005 mov rbp, rsp      48 8b ec
        // 0x1008 mov [rsp+8], rcx  48 89 4c 24 08  (home-space store)
        // 0x100d nop                90  (ends the prolog)
        // 0x100e ret                c3
        let code = vec![
            0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0xec, 0x48, 0x89, 0x4c, 0x24, 0x08, 0x90,
            0xc3,
        ];
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);

        let art = CfgPass
            .run(&ctx, CfgInput::new(Va(0x1000), 64))
            .expect("cfg builds");

        assert_eq!(art.frame.frame_size, 0x20);
        assert!(art.frame.uses_rbp);
        assert_eq!(art.frame.spilled_regs, vec!["rbx".to_string()]);
        assert_eq!(
            art.frame.prolog,
            vec![Va(0x1000), Va(0x1001), Va(0x1005), Va(0x1008)],
            "the nop ends the prolog scan"
        );
    }

    #[test]
    fn call_to_known_noreturn_ends_the_block_with_no_successors() {
        // 0x1000 call 0x2000        e8 fb 0f 00 00   (direct near call)
        // 0x1005 mov rax, 1         48 c7 c0 01 00 00 00   -- dead, unreachable
        // 0x100c ret                c3                     -- dead, unreachable
        let code = vec![
            0xe8, 0xfb, 0x0f, 0x00, 0x00, // call 0x2000
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1 (dead)
            0xc3, // ret (dead)
        ];
        let snap = Snapshot::builder()
            .region(Va(0x1000), code)
            .symbol(n0xis_contracts::Symbol {
                va: Va(0x2000),
                module: "kernel32".into(),
                name: "ExitProcess".into(),
                kind: n0xis_contracts::SymKind::Export,
            })
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch).with_symbols(&snap);

        let art = CfgPass
            .run(&ctx, CfgInput::new(Va(0x1000), 64))
            .expect("cfg builds");

        let entry = &art.blocks[0];
        assert_eq!(entry.terminator, "call-noreturn");
        assert!(
            entry.successors.is_empty(),
            "a noreturn call must not get a fall-through successor"
        );
        assert_eq!(art.stats.noreturn_calls, 1);
    }

    #[test]
    fn iat_call_to_known_noreturn_ends_the_block() {
        // call qword ptr [rip+disp] -> an IAT slot at 0x3000, holding ExitProcess.
        let insn_va = 0x1000i64;
        let insn_len = 6i64; // ff 15 + disp32
        let slot_va = 0x3000i64;
        let disp = (slot_va - (insn_va + insn_len)) as i32;
        let mut code = vec![0xff, 0x15];
        code.extend_from_slice(&disp.to_le_bytes());

        let snap = Snapshot::builder()
            .region(Va(0x1000), code)
            .iat_symbol(
                Va(0x3000),
                n0xis_contracts::Symbol {
                    va: Va(0x3000),
                    module: "kernel32".into(),
                    name: "ExitProcess".into(),
                    kind: n0xis_contracts::SymKind::Import,
                },
            )
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch).with_symbols(&snap);

        let art = CfgPass
            .run(&ctx, CfgInput::new(Va(0x1000), 64))
            .expect("cfg builds");

        assert_eq!(
            art.blocks[0].terminator, "call-noreturn",
            "the rip_target/iat_slot fallback must resolve the IAT call's name"
        );
        assert_eq!(art.stats.noreturn_calls, 1);
    }

    #[test]
    fn import_thunk_jmp_is_a_tail_call_not_an_unrecovered_indirect_branch() {
        // jmp qword ptr [rip+disp] -> an IAT slot at 0x3000 holding CloseHandle:
        // the classic `__imp_` forwarder thunk. The branch is indirect, but the
        // callee is known by name, so it must not degrade to `ijmp`.
        let insn_va = 0x1000i64;
        let insn_len = 6i64; // ff 25 + disp32
        let slot_va = 0x3000i64;
        let disp = (slot_va - (insn_va + insn_len)) as i32;
        let mut code = vec![0xff, 0x25];
        code.extend_from_slice(&disp.to_le_bytes());

        let snap = Snapshot::builder()
            .region(Va(0x1000), code)
            .iat_symbol(
                Va(0x3000),
                n0xis_contracts::Symbol {
                    va: Va(0x3000),
                    module: "kernel32".into(),
                    name: "CloseHandle".into(),
                    kind: n0xis_contracts::SymKind::Import,
                },
            )
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch).with_symbols(&snap);

        let art = CfgPass
            .run(&ctx, CfgInput::new(Va(0x1000), 64))
            .expect("cfg builds");

        assert_eq!(art.blocks[0].terminator, "tail-call");
        assert_eq!(art.stats.tail_calls, 1);
        assert_eq!(
            art.stats.indirect_branches, 0,
            "a resolved thunk is a call, not an unrecovered indirect branch"
        );
        let site = art
            .callsites
            .iter()
            .find(|c| c.kind == "tail")
            .expect("the thunk should be recorded as a tail callsite");
        assert_eq!(site.target_name.as_deref(), Some("kernel32!CloseHandle"));
    }

    #[test]
    fn an_unresolvable_indirect_jmp_stays_an_indirect_branch() {
        // jmp rax — no symbol, no table: the honest answer is still `ijmp`.
        let snap = Snapshot::builder().region(Va(0x1000), vec![0xff, 0xe0]).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);

        let art = CfgPass
            .run(&ctx, CfgInput::new(Va(0x1000), 64))
            .expect("cfg builds");

        assert_eq!(art.blocks[0].terminator, "ijmp");
        assert_eq!(art.stats.tail_calls, 0);
        assert_eq!(art.stats.indirect_branches, 1);
    }

    #[test]
    fn function_end_stops_after_a_noreturn_call() {
        // call ExitProcess, then bytes that belong to whatever follows. With
        // the callee known not to return, the function ends at the call — the
        // trailing bytes must not be decoded as part of it.
        let mut code = vec![0xe8, 0xfb, 0x0f, 0x00, 0x00]; // call 0x2000
        code.extend_from_slice(&[0x48, 0xff, 0xc1, 0x48, 0xff, 0xc1, 0xc3]); // inc rcx; inc rcx; ret

        let snap = Snapshot::builder()
            .region(Va(0x1000), code)
            .symbol(n0xis_contracts::Symbol {
                va: Va(0x2000),
                module: "kernel32".into(),
                name: "ExitProcess".into(),
                kind: n0xis_contracts::SymKind::Export,
            })
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch).with_symbols(&snap);

        let art = CfgPass
            .run(&ctx, CfgInput::new(Va(0x1000), 64))
            .expect("cfg builds");

        assert_eq!(art.insn_count, 1, "only the call itself belongs to the function");
        assert_eq!(art.end, Va(0x1005));
        assert_eq!(art.blocks.len(), 1);
        assert_eq!(art.blocks[0].terminator, "call-noreturn");
    }

    #[test]
    fn call_to_a_non_noreturn_named_function_does_not_end_the_block() {
        // call to CloseHandle (named, but not noreturn), then ret — must stay reachable.
        let code = vec![
            0xe8, 0xfb, 0x0f, 0x00, 0x00, // call 0x2000 (CloseHandle)
            0xc3, // ret
        ];
        let snap = Snapshot::builder()
            .region(Va(0x1000), code)
            .symbol(n0xis_contracts::Symbol {
                va: Va(0x2000),
                module: "kernel32".into(),
                name: "CloseHandle".into(),
                kind: n0xis_contracts::SymKind::Export,
            })
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch).with_symbols(&snap);

        let art = CfgPass
            .run(&ctx, CfgInput::new(Va(0x1000), 64))
            .expect("cfg builds");

        assert_eq!(art.block_count, 1, "call+ret should be a single fallthrough block");
        assert_eq!(art.blocks[0].terminator, "ret");
        assert_eq!(art.stats.noreturn_calls, 0);
    }

    #[test]
    fn an_unwind_declared_extent_cuts_the_function_when_no_symbol_does() {
        // A stripped or partially-symbolized image still carries unwind
        // information. Without reading it the heuristic ran on every function
        // the symbol table is silent about and stretched an 82-byte function to
        // the whole decode window.
        let mut code = vec![0x90u8; 0x20];
        code[0x10] = 0xC3; // a `ret` well past the declared end
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let stated = [(Va(0x1000), Va(0x1008))];
        let ctx = Ctx::new(&snap, &arch).with_stated_functions(&stated);
        let art = CfgPass
            .run(&ctx, CfgInput { start: Va(0x1000), max_bytes: 0x20, auto_end: true })
            .unwrap();
        assert_eq!(art.end, Va(0x1008), "the declared extent wins over the heuristic");
    }
    /// A conditional branch as the function's *last* instruction has both sides
    /// outside it, and neither may be an edge.
    ///
    /// The taken side was already recorded as a conditional tail call. The
    /// fall-through was not: it was emitted as a `cjmp-false` edge to the next
    /// function's first byte — a block that does not exist in this graph. Two
    /// of them on one PE against 19 437 edges, four on a 4 000-function slice
    /// of a very large ELF: the size at which an invented edge is invisible.
    #[test]
    fn a_conditional_branch_at_the_end_of_a_function_invents_no_edge() {
        let arch = X64::new();
        // 0x1000: 48 85 c9        test rcx,rcx
        // 0x1003: 0f 82 f7 00 00 00  jb 0x1100   (out of the function)
        // 0x1009 is the end: the fall-through leaves the function too.
        let code = vec![0x48, 0x85, 0xc9, 0x0f, 0x82, 0xf7, 0x00, 0x00, 0x00];
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let ctx = Ctx::new(&snap, &arch);
        // A stated extent that stops right after the branch.
        let stated = [(Va(0x1000), Va(0x1009))];
        let ctx = ctx.with_stated_functions(&stated);
        let art = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), 9)).expect("cfg builds");

        let blocks: std::collections::BTreeSet<u64> = art.blocks.iter().map(|b| b.start.0).collect();
        for b in &art.blocks {
            for s in &b.successors {
                assert!(
                    blocks.contains(&s.to.0),
                    "edge {} -> {} lands on no block in this graph",
                    b.start,
                    s.to
                );
            }
        }
        // Both sides are recorded as leaving, not dropped in silence.
        assert_eq!(art.stats.tail_calls, 2, "the taken branch and the fall-through both leave");
    }

}

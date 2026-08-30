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
use n0xis_contracts::Va;
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
        let bytes = ctx.source.read(input.start, input.max_bytes)?;
        let end_cap = input.start.0 + bytes.len() as u64;
        let all = ctx
            .arch
            .decode_stream(&bytes, input.start, DEFAULT_MAX_INSNS);
        let instrs = if input.auto_end {
            truncate_to_function(&all, input.start.0, end_cap, |ins| is_noreturn_call(ctx, ins))
        } else {
            all
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
fn resolved_target_name(ctx: &Ctx, ins: &DecodedInsn) -> Option<String> {
    ins.target
        .and_then(|t| ctx.symbols.and_then(|s| s.symbol_at(t)))
        .or_else(|| ins.rip_target.and_then(|t| ctx.symbols.and_then(|s| s.iat_slot(t))))
        .map(|sym| format!("{}!{}", sym.module, sym.name))
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
fn truncate_to_function(
    all: &[DecodedInsn],
    start: u64,
    end_cap: u64,
    is_noreturn_call: impl Fn(&DecodedInsn) -> bool,
) -> Vec<DecodedInsn> {
    let mut max_forward_leader = start;
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
    let leaders = compute_leaders(instrs, &valid);
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
        let block_start_index = i;
        let block_start_ip = instrs[i].va.0;
        let block_id = *block_id_by_ip.get(&block_start_ip).unwrap_or(&blocks.len());
        let mut ir_insns: Vec<IrInsn> = Vec::new();
        let mut successors: Vec<Successor> = Vec::new();
        let mut terminator = "fall".to_string();
        // reg -> (index-in-block, defining address)
        let mut last_def: HashMap<String, (usize, u64)> = HashMap::new();

        loop {
            let ins = &instrs[i];
            let access = ctx.arch.reg_access(ins);

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
                        if let Some(disp) = ctx.arch.detect_switch(&instrs[block_start_index..=i]) {
                            let resolved = resolve_switch(ctx, &disp);
                            for case in &resolved.cases {
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
                        successors.push(Successor {
                            to: t,
                            kind: "cjmp-true".into(),
                            confidence: edge_confidence("cjmp-true"),
                        });
                    }
                    let next = ins.va.0 + ins.len as u64;
                    successors.push(Successor {
                        to: Va(next),
                        kind: "cjmp-false".into(),
                        confidence: edge_confidence("cjmp-false"),
                    });
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
        let code = vec![
            0x48, 0x83, 0xf8, 0x02, // cmp rax, 2  (bound = 2 → 3 cases)
            0xff, 0x24, 0xc5, 0x00, 0x20, 0x00, 0x00, // jmp qword [rax*8 + 0x2000]
        ];
        let mut table = Vec::new();
        for case in [0x1500u64, 0x1600, 0x1700] {
            table.extend_from_slice(&case.to_le_bytes());
        }
        let snap = Snapshot::builder()
            .region(Va(0x1000), code)
            .region(Va(0x2000), table)
            // Backing for the case targets so the plausibility gate accepts them.
            .region(Va(0x1500), vec![0x90; 0x300])
            .build();
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
        assert_eq!(sw.cases, vec![Va(0x1500), Va(0x1600), Va(0x1700)]);

        // The resolved cases become CFG edges — the switch is no longer a dead end.
        let edges: Vec<Va> = art
            .blocks
            .iter()
            .flat_map(|b| &b.successors)
            .filter(|s| s.kind == "switch-case")
            .map(|s| s.to)
            .collect();
        assert_eq!(edges, vec![Va(0x1500), Va(0x1600), Va(0x1700)]);
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
}

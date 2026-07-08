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
//! into the pass. Switch resolution, frame analysis, and arg-hint recovery are
//! follow-on slices; the artifact is shaped to grow them additively.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use n0xis_arch::{DecodedInsn, InsnKind};
use n0xis_contracts::Va;
use serde::Serialize;

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
#[derive(Clone, Debug, Serialize)]
pub struct CfgArtifact {
    pub start: Va,
    pub end: Va,
    pub block_count: usize,
    pub insn_count: usize,
    pub blocks: Vec<CfgBlock>,
    pub callsites: Vec<Callsite>,
    pub stats: CfgStats,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct CfgStats {
    pub returns: usize,
    pub calls: usize,
    pub indirect_branches: usize,
    pub tail_calls: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct CfgBlock {
    pub id: usize,
    pub start: Va,
    pub end: Va,
    /// How the block leaves: `fall` / `jmp` / `cjmp` / `ijmp` / `ret` / `int` /
    /// `tail-call`.
    pub terminator: String,
    pub successors: Vec<Successor>,
    pub insns: Vec<IrInsn>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Successor {
    pub to: Va,
    pub kind: String,
    pub confidence: f32,
}

#[derive(Clone, Debug, Serialize)]
pub struct IrInsn {
    pub va: Va,
    pub len: u8,
    pub mnemonic: String,
    pub text: String,
    /// Flow classification (`seq` / `call` / `jump` / `cond_jump` / `ret` / …).
    pub flow: InsnKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<Va>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reads: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub writes: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub def_use: Vec<DefUse>,
}

/// A read of `reg` linked back to the instruction that last defined it in this
/// block (the local def-use chain).
#[derive(Clone, Debug, Serialize)]
pub struct DefUse {
    pub reg: String,
    pub def_index: usize,
    pub def_addr: Va,
}

#[derive(Clone, Debug, Serialize)]
pub struct Callsite {
    pub from: Va,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<Va>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_name: Option<String>,
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
            truncate_to_function(&all, input.start.0, end_cap)
        } else {
            all
        };

        build(ctx, &instrs, input.start)
    }
}

/// Cut the linear stream at the detected function end. Ported from v0
/// `decode_linear`'s auto-end heuristic: track the furthest forward in-range
/// edge; a terminator whose fallthrough passes it ends the function.
fn truncate_to_function(all: &[DecodedInsn], start: u64, end_cap: u64) -> Vec<DecodedInsn> {
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

            // Resolve a direct target's name via the symbol seam, if any.
            let target_name = ins.target.and_then(|t| {
                ctx.symbols
                    .and_then(|s| s.symbol_at(t))
                    .map(|sym| format!("{}!{}", sym.module, sym.name))
            });

            let is_tail = ins.kind == InsnKind::Jump
                && ins
                    .target
                    .map(|t| t.0 < start.0 || t.0 >= end_ip)
                    .unwrap_or(false);

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
                    callsites.push(Callsite {
                        from: ins.va,
                        kind: if target_name.is_some() { "named" } else { "direct" }.into(),
                        target: ins.target,
                        target_name,
                    });
                    // Calls do not end a basic block.
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
        "stats: {} returns, {} calls, {} indirect branches, {} tail calls",
        art.stats.returns, art.stats.calls, art.stats.indirect_branches, art.stats.tail_calls
    ));
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
}

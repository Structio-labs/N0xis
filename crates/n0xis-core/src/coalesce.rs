// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! SSA-version coalescing (ROADMAP Rung 3b) — turn a register's phi-web of
//! versions (`rcx.1`/`rcx.2`/`rcx.3`, the loop-carried counter) back into one
//! named variable, the source-level readable-locals win:
//!
//! ```text
//!   rcx.1 = 0x3;                        v1 = 3;
//!   while (rcx.3 != 0x0) {       ->     while (v1 != 0) {
//!       rcx.3 = (rcx.2 - 0x1);              v1 = v1 - 1;
//!   }                                   }
//! ```
//!
//! This is SSA destruction, which is unsound if done naively (the classic
//! lost-copy / swap problems): two versions that are *simultaneously live with
//! different values* must never share a name. So this pass is **guarded by a
//! real liveness analysis** and refuses to coalesce a class the moment any two
//! of its members interfere — a refused class simply keeps its subscripts
//! (sound, just less pretty). Sound-over-complete, rule #1.
//!
//! One structural fact keeps naming collision-free: a phi merges only versions
//! of the *same* register (`Phi::var` is a single root), so every congruence
//! class is single-root. A class that contains a recovered parameter's entry
//! version is named after that parameter; every other coalesced class gets a
//! fresh `vN`, which can collide with neither a register name nor a
//! `root.version` (both carry a `.`), nor another `vN`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use n0xis_arch::{CallTarget, MicroExpr, MicroStmt};
use n0xis_contracts::Va;

use crate::ir::{CfgArtifact, CfgBlock, Successor};
use crate::ssa::{SsaBlock, SsaStmt};
use crate::typeinfer::RecoveredSignature;

/// The `flags` pseudo-register is never rendered (it's filtered as noise), so
/// its phi-webs must not consume a `vN` or be coalesced.
fn is_flags(name: &str) -> bool {
    name.split('.').next() == Some("flags")
}

/// Every `Var` name referenced in an expression tree.
fn expr_vars(e: &MicroExpr, out: &mut HashSet<String>) {
    match e {
        MicroExpr::Var(n) => {
            out.insert(n.clone());
        }
        MicroExpr::Load { addr, .. } => expr_vars(addr, out),
        MicroExpr::Unary(_, v) => expr_vars(v, out),
        MicroExpr::Binary(_, l, r) => {
            expr_vars(l, out);
            expr_vars(r, out);
        }
        MicroExpr::Cast { expr, .. } => expr_vars(expr, out),
        MicroExpr::AddrOf(inner) => expr_vars(inner, out),
        MicroExpr::Select { cond, a, b } => {
            expr_vars(cond, out);
            expr_vars(a, out);
            expr_vars(b, out);
        }
        MicroExpr::Compare { lhs, rhs, .. } => {
            expr_vars(lhs, out);
            expr_vars(rhs, out);
        }
        MicroExpr::Call { target, args } => {
            if let CallTarget::Indirect(t) = target {
                expr_vars(t, out);
            }
            for a in args {
                expr_vars(a, out);
            }
        }
        MicroExpr::Const { .. } | MicroExpr::OpaqueFlags { .. } | MicroExpr::Unknown(_) => {}
    }
}

/// The variable a statement defines (its single SSA dst), if any.
fn stmt_def(stmt: &MicroStmt) -> Option<&str> {
    match stmt {
        MicroStmt::Assign { dst, .. } => Some(dst.as_str()),
        MicroStmt::Call { ret: Some(r), .. } => Some(r.as_str()),
        _ => None,
    }
}

/// The variables a statement *reads* (uses), not counting its own dst.
fn stmt_uses(stmt: &MicroStmt, out: &mut HashSet<String>) {
    match stmt {
        MicroStmt::Assign { value, .. } => expr_vars(value, out),
        MicroStmt::Store { addr, value, .. } => {
            expr_vars(addr, out);
            expr_vars(value, out);
        }
        MicroStmt::Call { target, args, .. } => {
            if let CallTarget::Indirect(t) = target {
                expr_vars(t, out);
            }
            for a in args {
                expr_vars(a, out);
            }
        }
        MicroStmt::Return(Some(e)) => expr_vars(e, out),
        MicroStmt::Return(None) | MicroStmt::Nop | MicroStmt::Unlifted { .. } => {}
    }
}

/// Minimal union-find over SSA variable names.
#[derive(Default)]
struct Uf {
    parent: HashMap<String, String>,
}

impl Uf {
    fn find(&mut self, x: &str) -> String {
        let mut cur = x.to_string();
        loop {
            let p = self.parent.get(&cur).cloned().unwrap_or_else(|| cur.clone());
            if p == cur {
                return cur;
            }
            // Path halving keeps this near-flat without recursion.
            let gp = self.parent.get(&p).cloned().unwrap_or_else(|| p.clone());
            self.parent.insert(cur.clone(), gp.clone());
            cur = p;
        }
    }
    fn union(&mut self, a: &str, b: &str) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra != rb {
            self.parent.insert(ra, rb);
        }
    }
}

/// Per-block upward-exposed uses and definitions, for the liveness pass.
struct BlockUseDef {
    /// Vars read before any local definition (upward-exposed) — the ones whose
    /// liveness flows *in* to this block.
    use_set: HashSet<String>,
    /// Vars defined in this block (phi dsts and statement dsts).
    def_set: HashSet<String>,
}

/// Standard backward SSA liveness. Returns `(live_in, live_out)` indexed the
/// same as `blocks`. Phi semantics are modelled precisely: a phi dst is a
/// definition at the head of its block, and each phi input value is a use on
/// the edge from its predecessor (so it is live-*out* of that predecessor, not
/// live-in of the phi's block).
fn liveness(blocks: &[SsaBlock]) -> (Vec<HashSet<String>>, Vec<HashSet<String>>) {
    let n = blocks.len();
    let idx_of_id: HashMap<usize, usize> = blocks.iter().enumerate().map(|(i, b)| (b.id, i)).collect();
    let idx_of_va: HashMap<u64, usize> = blocks.iter().enumerate().map(|(i, b)| (b.start.get(), i)).collect();

    // Successors (block indices) and the phi-input values each block must keep
    // live *out* because a successor's phi consumes them along this edge.
    let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut phi_out: Vec<HashSet<String>> = vec![HashSet::new(); n];
    for (i, b) in blocks.iter().enumerate() {
        for s in &b.successors {
            if let Some(&j) = idx_of_va.get(&s.to.get()) {
                succ[i].push(j);
            }
        }
        // For every phi in this block, the input value from predecessor P is a
        // use live-out of P.
        for phi in &b.phis {
            if phi.dst.is_empty() {
                continue;
            }
            for input in &phi.inputs {
                if let Some(&p) = idx_of_id.get(&input.from_block) {
                    phi_out[p].insert(input.value.clone());
                }
            }
        }
    }

    // use/def per block. Phi input values are NOT uses of their own block.
    let ud: Vec<BlockUseDef> = blocks
        .iter()
        .map(|b| {
            let mut use_set = HashSet::new();
            let mut def_set = HashSet::new();
            for phi in &b.phis {
                if !phi.dst.is_empty() {
                    def_set.insert(phi.dst.clone());
                }
            }
            for s in &b.stmts {
                let mut uses = HashSet::new();
                stmt_uses(&s.stmt, &mut uses);
                for u in uses {
                    if !def_set.contains(&u) {
                        use_set.insert(u);
                    }
                }
                if let Some(d) = stmt_def(&s.stmt) {
                    def_set.insert(d.to_string());
                }
            }
            if let Some(c) = &b.condition {
                let mut uses = HashSet::new();
                expr_vars(c, &mut uses);
                for u in uses {
                    if !def_set.contains(&u) {
                        use_set.insert(u);
                    }
                }
            }
            BlockUseDef { use_set, def_set }
        })
        .collect();

    let mut live_in: Vec<HashSet<String>> = vec![HashSet::new(); n];
    let mut live_out: Vec<HashSet<String>> = vec![HashSet::new(); n];

    let mut changed = true;
    while changed {
        changed = false;
        // Reverse order converges faster on mostly-forward CFGs.
        for i in (0..n).rev() {
            // live_out[i] = ∪ live_in[succ] ∪ phi_out[i]
            let mut new_out = phi_out[i].clone();
            for &j in &succ[i] {
                new_out.extend(live_in[j].iter().cloned());
            }
            // live_in[i] = use[i] ∪ (live_out[i] \ def[i])
            let mut new_in = ud[i].use_set.clone();
            for v in &new_out {
                if !ud[i].def_set.contains(v) {
                    new_in.insert(v.clone());
                }
            }
            if new_out != live_out[i] {
                live_out[i] = new_out;
                changed = true;
            }
            if new_in != live_in[i] {
                live_in[i] = new_in;
                changed = true;
            }
        }
    }
    (live_in, live_out)
}

/// The coalescing result: a map from an SSA variable name to the display name
/// it should render under. A variable absent from the map renders unchanged.
pub fn coalesce_vars(blocks: &[SsaBlock], sig: &RecoveredSignature) -> HashMap<String, String> {
    // A recovered parameter's entry version renders under its parameter name
    // (Rung 3b baseline — holds whether or not the parameter is in a phi web).
    let param_name: HashMap<String, String> = sig.params.iter().map(|p| (format!("{}.0", p.reg), p.name.clone())).collect();

    // Build phi-congruence classes: union each phi dst with its input values.
    let mut uf = Uf::default();
    let mut members: BTreeSet<String> = BTreeSet::new();
    for b in blocks {
        for phi in &b.phis {
            if phi.dst.is_empty() || is_flags(&phi.dst) {
                continue;
            }
            members.insert(phi.dst.clone());
            for input in &phi.inputs {
                if is_flags(&input.value) {
                    continue;
                }
                members.insert(input.value.clone());
                uf.union(&phi.dst, &input.value);
            }
        }
    }

    let mut out = param_name.clone();
    if members.is_empty() {
        return out; // nothing to coalesce; parameter naming still applies.
    }

    // Group members by congruence-class root.
    let mut classes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for m in &members {
        classes.entry(uf.find(m)).or_default().push(m.clone());
    }

    // Liveness → **statement-granularity** interference. Block-boundary
    // liveness alone would miss two class members that are both born and killed
    // inside one block with overlapping ranges, so this walks each block
    // backward from its live-out set and records an interference between a
    // variable being defined and every variable simultaneously live at that
    // point. Only pairs among phi-web members are stored (the only ones this
    // pass could coalesce). A variable used in the *same* statement that
    // defines another does not interfere with it — it is added to the live set
    // only after the def is processed — so a loop-counter self-update
    // (`v = v - 1`) still coalesces, while a counter whose pre-update value is
    // also read at the block's end (`v-1; if (v != 0)`) correctly does not.
    let (_live_in, live_out) = liveness(blocks);
    let mut interference: HashSet<(String, String)> = HashSet::new();
    let mark = |a: &str, b: &str, set: &mut HashSet<(String, String)>| {
        if a != b && members.contains(a) && members.contains(b) {
            let (x, y) = if a < b { (a.to_string(), b.to_string()) } else { (b.to_string(), a.to_string()) };
            set.insert((x, y));
        }
    };
    for (i, b) in blocks.iter().enumerate() {
        let mut live = live_out[i].clone();
        // The terminator's condition is evaluated at the block's end.
        if let Some(c) = &b.condition {
            expr_vars(c, &mut live);
        }
        for s in b.stmts.iter().rev() {
            if let Some(d) = stmt_def(&s.stmt) {
                for v in &live {
                    mark(d, v, &mut interference);
                }
                live.remove(d);
            }
            let mut uses = HashSet::new();
            stmt_uses(&s.stmt, &mut uses);
            live.extend(uses);
        }
        // Phi destinations are defined at the block head, after all statements.
        for phi in &b.phis {
            if phi.dst.is_empty() {
                continue;
            }
            for v in &live {
                mark(&phi.dst, v, &mut interference);
            }
            live.remove(&phi.dst);
        }
    }
    let interfere = |a: &str, b: &str| -> bool {
        let (x, y) = if a < b { (a, b) } else { (b, a) };
        interference.contains(&(x.to_string(), y.to_string()))
    };

    let mut next_v = 1usize;
    for (_root, mut group) in classes {
        group.sort();
        if group.len() < 2 {
            continue; // a lone version is not a coalescing (parameter map still applies).
        }
        // Refuse the whole class if any two members interfere.
        let mut safe = true;
        'pairs: for i in 0..group.len() {
            for j in (i + 1)..group.len() {
                if interfere(&group[i], &group[j]) {
                    safe = false;
                    break 'pairs;
                }
            }
        }
        if !safe {
            continue;
        }
        // Name the class: a parameter's name if it contains a parameter entry
        // version, else a fresh `vN`.
        let name = group
            .iter()
            .find_map(|m| param_name.get(m).cloned())
            .unwrap_or_else(|| {
                let v = format!("v{next_v}");
                next_v += 1;
                v
            });
        for m in group {
            out.insert(m, name.clone());
        }
    }
    out
}

/// Base for synthetic block addresses minted when splitting a critical edge.
/// Non-canonical (in the address-space hole, bit 63 set) so it can never
/// collide with a real image or live address, and stays obviously synthetic in
/// a rendered `// block_…:` comment.
pub(crate) const SYNTHETIC_VA_BASE: u64 = 0xF000_0000_0000_0000;

/// Whether an address is a synthetic edge-split block minted by
/// [`destruct_ssa`] (it has no real instruction address to show).
pub(crate) fn is_synthetic_va(va: Va) -> bool {
    va.get() >= SYNTHETIC_VA_BASE
}

/// Complete SSA destruction: eliminate every phi that [`coalesce_vars`] did
/// **not** merge, so no phi destination is ever read without a visible
/// definition (the `rax.6` "undefined variable" artifact). A coalesced phi
/// needs nothing — its members already share one name and one defining
/// assignment. A phi that survived coalescing (an interference refused it) is
/// materialized with edge copies:
///
/// ```text
///   dst = φ(v_i from pred_i)   ->   append  dst = v_i  at the end of pred_i
/// ```
///
/// When the edge `pred_i -> phi-block` is **critical** (`pred_i` has more than
/// one successor) the copy cannot live in `pred_i` — it would also run on
/// `pred_i`'s other out-edges — so the edge is split by a fresh fall-through
/// block that carries the copy. In structured output that split block becomes
/// the matching `if`/`else` arm. Returns modified copies of the CFG and SSA
/// blocks (the caller keeps the originals for the other render styles).
pub fn destruct_ssa(cfg: &CfgArtifact, blocks: &[SsaBlock], names: &HashMap<String, String>) -> (CfgArtifact, Vec<SsaBlock>) {
    let mut cfg = cfg.clone();
    let mut blocks = blocks.to_vec();
    let disp = |n: &str| names.get(n).cloned().unwrap_or_else(|| n.to_string());
    let id_to_idx: HashMap<usize, usize> = blocks.iter().enumerate().map(|(i, b)| (b.id, i)).collect();

    // The copies each edge must carry: (from_idx, phi_block_idx) -> [(dst, val)].
    let mut edge_copies: BTreeMap<(usize, usize), Vec<(String, String)>> = BTreeMap::new();
    for (bi, b) in blocks.iter().enumerate() {
        for phi in &b.phis {
            if phi.dst.is_empty() {
                continue;
            }
            let dn = disp(&phi.dst);
            // Coalesced: dst and every input already render as one name.
            if phi.inputs.iter().all(|i| disp(&i.value) == dn) {
                continue;
            }
            for inp in &phi.inputs {
                let Some(&fi) = id_to_idx.get(&inp.from_block) else { continue };
                if disp(&inp.value) == dn {
                    continue; // this arm already agrees — no copy needed.
                }
                edge_copies.entry((fi, bi)).or_default().push((phi.dst.clone(), inp.value.clone()));
            }
        }
    }
    if edge_copies.is_empty() {
        return (cfg, blocks);
    }

    let mut next_id = blocks.iter().map(|b| b.id).max().unwrap_or(0) + 1;
    let mut synth = 0u64;
    for ((from_idx, to_idx), copies) in edge_copies {
        let to_start = blocks[to_idx].start;
        let copy_stmts: Vec<SsaStmt> = copies
            .into_iter()
            .map(|(dst, val)| SsaStmt { va: to_start, stmt: MicroStmt::Assign { dst, value: MicroExpr::var(val) } })
            .collect();
        let distinct_succ: HashSet<u64> = cfg.blocks[from_idx].successors.iter().map(|s| s.to.get()).collect();

        if distinct_succ.len() <= 1 {
            // Non-critical: the copies run exactly when from -> to is taken.
            blocks[from_idx].stmts.extend(copy_stmts);
        } else {
            // Critical: split the edge with a fresh fall-through block. The
            // copies (phi dsts) are defined at the merge and their sources
            // before it, so they never conflict and sequentialize in any order.
            let new_start = Va(SYNTHETIC_VA_BASE + synth);
            synth += 1;
            let new_id = next_id;
            next_id += 1;
            let succ = vec![Successor { to: to_start, kind: "jmp".into(), confidence: 1.0 }];
            cfg.blocks.push(CfgBlock { id: new_id, start: new_start, end: new_start, terminator: "jmp".into(), successors: succ.clone(), insns: vec![] });
            blocks.push(SsaBlock { id: new_id, start: new_start, end: new_start, terminator: "jmp".into(), successors: succ, phis: vec![], stmts: copy_stmts, condition: None });
            for e in cfg.blocks[from_idx].successors.iter_mut().filter(|e| e.to == to_start) {
                e.to = new_start;
            }
            for e in blocks[from_idx].successors.iter_mut().filter(|e| e.to == to_start) {
                e.to = new_start;
            }
        }
    }
    (cfg, blocks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssa::{Phi, PhiInput, SsaBlock, SsaStmt};
    use crate::typeinfer::RecoveredSignature;
    use n0xis_arch::{BinOp, MicroExpr, MicroStmt};
    use n0xis_contracts::Va;
    use n0xis_core_successor::mk;

    // A tiny block builder lives in a helper module below to keep these tests
    // readable.

    fn assign(dst: &str, value: MicroExpr) -> SsaStmt {
        SsaStmt { va: Va(0), stmt: MicroStmt::Assign { dst: dst.into(), value } }
    }

    fn empty_sig() -> RecoveredSignature {
        RecoveredSignature { params: vec![], ret: None }
    }

    /// A minimal `CfgArtifact` mirroring the SSA blocks' ids/starts/successors
    /// — enough for `destruct_ssa`, which only reads `cfg.blocks`.
    fn mk_cfg(blocks: &[SsaBlock]) -> crate::ir::CfgArtifact {
        let cfg_blocks = blocks
            .iter()
            .map(|b| crate::ir::CfgBlock {
                id: b.id,
                start: b.start,
                end: b.end,
                terminator: b.terminator.clone(),
                successors: b.successors.clone(),
                insns: vec![],
            })
            .collect();
        crate::ir::CfgArtifact {
            start: blocks[0].start,
            end: blocks.last().unwrap().end,
            block_count: blocks.len(),
            insn_count: 0,
            blocks: cfg_blocks,
            callsites: vec![],
            switches: vec![],
            frame: n0xis_arch::FrameInfo::default(),
            stats: crate::ir::CfgStats::default(),
        }
    }

    fn succ_to(va: u64, kind: &str) -> crate::ir::Successor {
        crate::ir::Successor { to: Va(va), kind: kind.into(), confidence: 1.0 }
    }

    #[test]
    fn a_critical_edge_phi_is_materialized_by_splitting_the_edge() {
        // Diamond with an *empty* then-arm, so the then-edge goes straight from
        // the cjmp block (0x1000, two successors) to the merge (0x1030) — a
        // critical edge. rax.6 = φ(rax.3 @0x1000, rax.5 @0x1010) is not
        // coalesced (empty name map), so destruction must define rax.6 on both
        // paths: the non-critical else-edge (0x1010, one successor) gets the
        // copy appended, and the critical then-edge is split by a new block.
        let b0 = SsaBlock {
            id: 0,
            start: Va(0x1000),
            end: Va(0x1008),
            terminator: "cjmp".into(),
            successors: vec![succ_to(0x1030, "cjmp-true"), succ_to(0x1010, "cjmp-false")],
            phis: vec![],
            stmts: vec![assign("rax.3", MicroExpr::constant(7, 64))],
            condition: Some(MicroExpr::binary(BinOp::Ne, MicroExpr::var("rcx.0"), MicroExpr::constant(0, 64))),
        };
        let b2 = SsaBlock {
            id: 2,
            start: Va(0x1010),
            end: Va(0x1018),
            terminator: "jmp".into(),
            successors: vec![succ_to(0x1030, "jmp")],
            phis: vec![],
            stmts: vec![assign("rax.5", MicroExpr::load(MicroExpr::var("rcx.0"), 64, false))],
            condition: None,
        };
        let b3 = SsaBlock {
            id: 3,
            start: Va(0x1030),
            end: Va(0x1038),
            terminator: "ret".into(),
            successors: vec![],
            phis: vec![Phi {
                var: "rax".into(),
                dst: "rax.6".into(),
                inputs: vec![PhiInput { from_block: 0, value: "rax.3".into() }, PhiInput { from_block: 2, value: "rax.5".into() }],
            }],
            stmts: vec![SsaStmt { va: Va(0), stmt: MicroStmt::Return(Some(MicroExpr::var("rax.6"))) }],
            condition: None,
        };
        let cfg = mk_cfg(&[b0.clone(), b2.clone(), b3.clone()]);
        let names: HashMap<String, String> = HashMap::new();
        let (dcfg, dblocks) = destruct_ssa(&cfg, &[b0, b2, b3], &names);

        // A split block was appended (both views stay index-aligned).
        assert_eq!(dblocks.len(), 4);
        assert_eq!(dcfg.blocks.len(), 4);

        let is_copy = |s: &SsaStmt, d: &str, v: &str| matches!(&s.stmt, MicroStmt::Assign { dst, value } if dst == d && *value == MicroExpr::var(v));
        // The non-critical else-edge appended `rax.6 = rax.5` to block 0x1010 (index 1).
        assert!(dblocks[1].stmts.iter().any(|s| is_copy(s, "rax.6", "rax.5")), "{:?}", dblocks[1].stmts);
        // The split block (index 3) carries the then-edge copy `rax.6 = rax.3`.
        assert!(dblocks[3].stmts.iter().any(|s| is_copy(s, "rax.6", "rax.3")), "{:?}", dblocks[3].stmts);
        // The cjmp's true-edge was redirected off the merge, and the split block
        // falls through to it — in both the SSA and CFG views.
        assert!(!dblocks[0].successors.iter().any(|e| e.to == Va(0x1030)), "true edge must be redirected: {:?}", dblocks[0].successors);
        assert!(!dcfg.blocks[0].successors.iter().any(|e| e.to == Va(0x1030)), "cfg true edge must be redirected too");
        assert!(dblocks[3].successors.iter().any(|e| e.to == Va(0x1030)), "split block must fall through to the merge");
    }

    #[test]
    fn a_coalesced_phi_needs_no_edge_copies() {
        // When the phi's members all coalesce to one name, destruction inserts
        // nothing (the shared name is already defined by the real assignments).
        let b0 = SsaBlock {
            id: 0,
            start: Va(0x1000),
            end: Va(0x1004),
            terminator: "jmp".into(),
            successors: vec![succ_to(0x1004, "jmp")],
            phis: vec![],
            stmts: vec![assign("rcx.1", MicroExpr::constant(3, 64))],
            condition: None,
        };
        let b1 = SsaBlock {
            id: 1,
            start: Va(0x1004),
            end: Va(0x1008),
            terminator: "cjmp".into(),
            successors: vec![succ_to(0x1004, "cjmp-true"), succ_to(0x1008, "cjmp-false")],
            phis: vec![Phi {
                var: "rcx".into(),
                dst: "rcx.2".into(),
                inputs: vec![PhiInput { from_block: 0, value: "rcx.1".into() }, PhiInput { from_block: 1, value: "rcx.3".into() }],
            }],
            stmts: vec![assign("rcx.3", MicroExpr::binary(BinOp::Sub, MicroExpr::var("rcx.2"), MicroExpr::constant(1, 64)))],
            condition: Some(MicroExpr::binary(BinOp::Ne, MicroExpr::var("rcx.3"), MicroExpr::constant(0, 64))),
        };
        let b2 = SsaBlock {
            id: 2,
            start: Va(0x1008),
            end: Va(0x1009),
            terminator: "ret".into(),
            successors: vec![],
            phis: vec![],
            stmts: vec![SsaStmt { va: Va(0), stmt: MicroStmt::Return(None) }],
            condition: None,
        };
        let cfg = mk_cfg(&[b0.clone(), b1.clone(), b2.clone()]);
        // The loop counter coalesces to one name -> the phi is satisfied.
        let names = coalesce_vars(&[b0.clone(), b1.clone(), b2.clone()], &empty_sig());
        let (_dcfg, dblocks) = destruct_ssa(&cfg, &[b0, b1, b2], &names);
        assert_eq!(dblocks.len(), 3, "no split blocks should be added for a coalesced phi");
    }

    #[test]
    fn a_loop_counter_phi_web_coalesces_to_one_name() {
        // block0: rcx.1 = 3 ; -> block1
        // block1 (loop head): phi rcx.2 = (rcx.1 from b0, rcx.3 from b1)
        //                      rcx.3 = rcx.2 - 1 ; cond rcx.3 != 0 ; -> b1 / b2
        // block2: ret
        let b0 = SsaBlock {
            id: 0,
            start: Va(0x1000),
            end: Va(0x1004),
            terminator: "jmp".into(),
            successors: vec![mk(0x1004)],
            phis: vec![],
            stmts: vec![assign("rcx.1", MicroExpr::constant(3, 64))],
            condition: None,
        };
        let b1 = SsaBlock {
            id: 1,
            start: Va(0x1004),
            end: Va(0x1008),
            terminator: "cjmp".into(),
            successors: vec![mk(0x1004), mk(0x1008)],
            phis: vec![Phi {
                var: "rcx".into(),
                dst: "rcx.2".into(),
                inputs: vec![PhiInput { from_block: 0, value: "rcx.1".into() }, PhiInput { from_block: 1, value: "rcx.3".into() }],
            }],
            stmts: vec![assign("rcx.3", MicroExpr::binary(BinOp::Sub, MicroExpr::var("rcx.2"), MicroExpr::constant(1, 64)))],
            condition: Some(MicroExpr::binary(BinOp::Ne, MicroExpr::var("rcx.3"), MicroExpr::constant(0, 64))),
        };
        let b2 = SsaBlock {
            id: 2,
            start: Va(0x1008),
            end: Va(0x1009),
            terminator: "ret".into(),
            successors: vec![],
            phis: vec![],
            stmts: vec![SsaStmt { va: Va(0), stmt: MicroStmt::Return(None) }],
            condition: None,
        };
        let map = coalesce_vars(&[b0, b1, b2], &empty_sig());
        // All three versions collapse to a single fresh name.
        let n1 = map.get("rcx.1").expect("rcx.1 coalesced");
        assert_eq!(map.get("rcx.2"), Some(n1));
        assert_eq!(map.get("rcx.3"), Some(n1));
        assert!(n1.starts_with('v'), "non-parameter loop var should be a fresh vN: {n1}");
    }

    #[test]
    fn a_value_that_escapes_the_loop_is_not_coalesced() {
        // The lost-copy shape: rcx.2 (the phi dst) is *also* used after the
        // loop, so its live range overlaps rcx.3 — coalescing would be unsound,
        // and the pass must refuse (leave the versions un-renamed).
        // block0: rcx.1 = 3 ; -> b1
        // block1: phi rcx.2=(rcx.1@b0, rcx.3@b1); rcx.3 = rcx.2 - 1;
        //         cond rcx.3 != 0 ; -> b1 / b2
        // block2: return rcx.2    <-- rcx.2 escapes the loop
        let b0 = SsaBlock {
            id: 0,
            start: Va(0x1000),
            end: Va(0x1004),
            terminator: "jmp".into(),
            successors: vec![mk(0x1004)],
            phis: vec![],
            stmts: vec![assign("rcx.1", MicroExpr::constant(3, 64))],
            condition: None,
        };
        let b1 = SsaBlock {
            id: 1,
            start: Va(0x1004),
            end: Va(0x1008),
            terminator: "cjmp".into(),
            successors: vec![mk(0x1004), mk(0x1008)],
            phis: vec![Phi {
                var: "rcx".into(),
                dst: "rcx.2".into(),
                inputs: vec![PhiInput { from_block: 0, value: "rcx.1".into() }, PhiInput { from_block: 1, value: "rcx.3".into() }],
            }],
            stmts: vec![assign("rcx.3", MicroExpr::binary(BinOp::Sub, MicroExpr::var("rcx.2"), MicroExpr::constant(1, 64)))],
            condition: Some(MicroExpr::binary(BinOp::Ne, MicroExpr::var("rcx.3"), MicroExpr::constant(0, 64))),
        };
        let b2 = SsaBlock {
            id: 2,
            start: Va(0x1008),
            end: Va(0x1009),
            terminator: "ret".into(),
            successors: vec![],
            phis: vec![],
            stmts: vec![SsaStmt { va: Va(0), stmt: MicroStmt::Return(Some(MicroExpr::var("rcx.2"))) }],
            condition: None,
        };
        let map = coalesce_vars(&[b0, b1, b2], &empty_sig());
        // rcx.2 is live after the loop while rcx.3 is live across the back edge,
        // so they interfere → the class is refused, nothing coalesced.
        assert!(
            !map.contains_key("rcx.1") && !map.contains_key("rcx.2") && !map.contains_key("rcx.3"),
            "escaping value must not coalesce: {map:?}"
        );
    }

    #[test]
    fn a_counter_whose_pre_update_value_is_tested_is_not_coalesced() {
        // The subtle within-block hazard: the loop tests the *pre*-decrement
        // value (`if (rcx.2 != 0)`) but the decrement `rcx.3 = rcx.2 - 1`
        // executes first in the block. Coalescing rcx.2 and rcx.3 into one name
        // would make the test read the *decremented* value — a semantic change.
        // rcx.2 is still live at rcx.3's definition (it feeds the condition at
        // the block's end), so the statement-granularity interference check
        // must catch it and refuse. Block-boundary liveness alone would miss it.
        let b0 = SsaBlock {
            id: 0,
            start: Va(0x1000),
            end: Va(0x1004),
            terminator: "jmp".into(),
            successors: vec![mk(0x1004)],
            phis: vec![],
            stmts: vec![assign("rcx.1", MicroExpr::constant(3, 64))],
            condition: None,
        };
        let b1 = SsaBlock {
            id: 1,
            start: Va(0x1004),
            end: Va(0x1008),
            terminator: "cjmp".into(),
            successors: vec![mk(0x1004), mk(0x1008)],
            phis: vec![Phi {
                var: "rcx".into(),
                dst: "rcx.2".into(),
                inputs: vec![PhiInput { from_block: 0, value: "rcx.1".into() }, PhiInput { from_block: 1, value: "rcx.3".into() }],
            }],
            stmts: vec![assign("rcx.3", MicroExpr::binary(BinOp::Sub, MicroExpr::var("rcx.2"), MicroExpr::constant(1, 64)))],
            // The condition tests the PRE-decrement value rcx.2, not rcx.3.
            condition: Some(MicroExpr::binary(BinOp::Ne, MicroExpr::var("rcx.2"), MicroExpr::constant(0, 64))),
        };
        let b2 = SsaBlock {
            id: 2,
            start: Va(0x1008),
            end: Va(0x1009),
            terminator: "ret".into(),
            successors: vec![],
            phis: vec![],
            stmts: vec![SsaStmt { va: Va(0), stmt: MicroStmt::Return(None) }],
            condition: None,
        };
        let map = coalesce_vars(&[b0, b1, b2], &empty_sig());
        assert!(
            !map.contains_key("rcx.1") && !map.contains_key("rcx.2") && !map.contains_key("rcx.3"),
            "pre-update-tested counter must not coalesce (would change the tested value): {map:?}"
        );
    }

    #[test]
    fn a_parameter_in_a_phi_web_keeps_its_parameter_name() {
        // rcx is a parameter (rcx.0). It is updated in a loop, so rcx.0/rcx.2/
        // rcx.3 form a phi web — the coalesced name must be the parameter name
        // `rcx`, not a fresh vN.
        let b0 = SsaBlock {
            id: 0,
            start: Va(0x1000),
            end: Va(0x1004),
            terminator: "jmp".into(),
            successors: vec![mk(0x1004)],
            phis: vec![],
            stmts: vec![],
            condition: None,
        };
        let b1 = SsaBlock {
            id: 1,
            start: Va(0x1004),
            end: Va(0x1008),
            terminator: "cjmp".into(),
            successors: vec![mk(0x1004), mk(0x1008)],
            phis: vec![Phi {
                var: "rcx".into(),
                dst: "rcx.2".into(),
                inputs: vec![PhiInput { from_block: 0, value: "rcx.0".into() }, PhiInput { from_block: 1, value: "rcx.3".into() }],
            }],
            stmts: vec![assign("rcx.3", MicroExpr::binary(BinOp::Sub, MicroExpr::var("rcx.2"), MicroExpr::constant(1, 64)))],
            condition: Some(MicroExpr::binary(BinOp::Ne, MicroExpr::var("rcx.3"), MicroExpr::constant(0, 64))),
        };
        let b2 = SsaBlock {
            id: 2,
            start: Va(0x1008),
            end: Va(0x1009),
            terminator: "ret".into(),
            successors: vec![],
            phis: vec![],
            stmts: vec![SsaStmt { va: Va(0), stmt: MicroStmt::Return(None) }],
            condition: None,
        };
        let sig = RecoveredSignature {
            params: vec![crate::typeinfer::ParamInfo { reg: "rcx", name: "rcx".into(), ty: crate::typeinfer::CType { bits: 64, signed: false, name: None } }],
            ret: None,
        };
        let map = coalesce_vars(&[b0, b1, b2], &sig);
        assert_eq!(map.get("rcx.0").map(String::as_str), Some("rcx"));
        assert_eq!(map.get("rcx.2").map(String::as_str), Some("rcx"));
        assert_eq!(map.get("rcx.3").map(String::as_str), Some("rcx"));
    }
}

/// A minuscule `Successor` builder, only for tests (kept in its own module so
/// the `#[cfg(test)]` import above is a single clean path).
#[cfg(test)]
mod n0xis_core_successor {
    use crate::ir::Successor;
    use n0xis_contracts::Va;
    pub fn mk(to: u64) -> Successor {
        Successor { to: Va(to), kind: "edge".into(), confidence: 1.0 }
    }
}

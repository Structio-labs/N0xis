//! Backward register slice over a built CFG (`ir slice`).
//!
//! Given a query point and a register, walk the intra-block def-use chains
//! already recorded in [`CfgArtifact`] backward to the instructions that
//! compute that register's value. A pure view over the artifact; the only ISA
//! knowledge it needs is register aliasing, taken through
//! [`Arch::normalize_reg`](n0xis_arch::Arch::normalize_reg) so a query for
//! `eax` matches a def recorded as `rax`.
//!
//! Scope note: def-use in the current IR is **intra-block** (a read links to
//! the last writer in the same block). The slice therefore stays within a
//! block from the seed; cross-block value flow arrives with SSA (Phase 3),
//! after which this walk widens for free over the richer chains.

use std::collections::{BTreeSet, HashMap};

use n0xis_arch::Arch;
use n0xis_contracts::Va;
use serde::Serialize;

use crate::ir::{CfgArtifact, IrInsn};

/// Backward-slice artifact (`n0xis.ir.slice.v1`).
#[derive(Clone, Debug, Serialize)]
pub struct SliceArtifact {
    /// The query point the slice was taken at.
    pub at: Va,
    /// The normalized register that was sliced.
    pub reg: String,
    /// The seed instruction (the writer of `reg` at/before `at`), if found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<Va>,
    pub node_count: usize,
    pub edge_count: usize,
    /// Nodes with no in-slice dependency — the slice's inputs.
    pub roots: Vec<Va>,
    /// Instructions in the slice, in address order.
    pub nodes: Vec<SliceNode>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SliceNode {
    pub va: Va,
    pub text: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reads: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub writes: Vec<String>,
    /// Addresses of the in-slice instructions this one depends on.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deps: Vec<Va>,
}

/// Compute the backward slice of `reg` at `at` over `art`.
pub fn slice(arch: &dyn Arch, art: &CfgArtifact, at: Va, reg: &str) -> SliceArtifact {
    let reg = arch.normalize_reg(reg);

    // Flatten to a single addressable stream (def_use addresses are absolute).
    let flat: Vec<&IrInsn> = art.blocks.iter().flat_map(|b| &b.insns).collect();
    let idx_by_addr: HashMap<u64, usize> =
        flat.iter().enumerate().map(|(i, ins)| (ins.va.0, i)).collect();

    let seed = find_seed(&flat, &idx_by_addr, at, &reg);

    // Reachable set via the def-use edges, starting from the seed.
    let mut used: BTreeSet<usize> = BTreeSet::new();
    let mut stack: Vec<usize> = seed.into_iter().collect();
    while let Some(cur) = stack.pop() {
        if !used.insert(cur) {
            continue;
        }
        for d in &flat[cur].def_use {
            if let Some(&dep) = idx_by_addr.get(&d.def_addr.0) {
                stack.push(dep);
            }
        }
    }

    let mut nodes: Vec<SliceNode> = Vec::new();
    let mut roots: Vec<Va> = Vec::new();
    let mut edge_count = 0usize;
    for &i in &used {
        let ins = flat[i];
        let mut deps: Vec<Va> = ins
            .def_use
            .iter()
            .filter(|d| idx_by_addr.get(&d.def_addr.0).is_some_and(|d| used.contains(d)))
            .map(|d| d.def_addr)
            .collect();
        deps.sort_by_key(|v| v.0);
        deps.dedup();
        edge_count += deps.len();
        if deps.is_empty() {
            roots.push(ins.va);
        }
        nodes.push(SliceNode {
            va: ins.va,
            text: ins.text.clone(),
            reads: ins.reads.clone(),
            writes: ins.writes.clone(),
            deps,
        });
    }
    nodes.sort_by_key(|n| n.va.0);
    roots.sort_by_key(|v| v.0);

    SliceArtifact {
        at,
        reg,
        seed: seed.map(|i| flat[i].va),
        node_count: nodes.len(),
        edge_count,
        roots,
        nodes,
    }
}

/// Seed selection: the instruction at `at` if it writes `reg`, else the nearest
/// writer of `reg` at an address `<= at`.
fn find_seed(
    flat: &[&IrInsn],
    idx_by_addr: &HashMap<u64, usize>,
    at: Va,
    reg: &str,
) -> Option<usize> {
    if let Some(&i) = idx_by_addr.get(&at.0)
        && flat[i].writes.iter().any(|w| w == reg)
    {
        return Some(i);
    }
    flat.iter()
        .enumerate()
        .filter(|(_, ins)| ins.va.0 <= at.0 && ins.writes.iter().any(|w| w == reg))
        .max_by_key(|(_, ins)| ins.va.0)
        .map(|(i, _)| i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CfgInput, CfgPass};
    use crate::{Ctx, Pass};
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    fn build(code: Vec<u8>) -> CfgArtifact {
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        CfgPass.run(&ctx, CfgInput::new(Va(0x1000), 64)).unwrap()
    }

    #[test]
    fn slices_a_def_use_chain_backward() {
        // 0x1000 mov eax, 5     b8 05 00 00 00
        // 0x1005 add eax, 3     83 c0 03
        // 0x1008 mov ecx, eax   89 c1
        // 0x100a ret            c3
        let code = vec![
            0xb8, 0x05, 0x00, 0x00, 0x00, 0x83, 0xc0, 0x03, 0x89, 0xc1, 0xc3,
        ];
        let art = build(code);
        let arch = X64::new();

        // Query `ecx` (sub-register form) — must normalize to rcx and hit the
        // `mov ecx, eax` writer, then chase eax back through the chain.
        let sl = slice(&arch, &art, Va(0x1008), "ecx");
        assert_eq!(sl.reg, "rcx", "sub-register query normalized to full width");
        assert_eq!(sl.seed, Some(Va(0x1008)));
        assert_eq!(sl.node_count, 3, "mov ecx / add eax / mov eax");
        assert_eq!(sl.edge_count, 2);
        assert_eq!(sl.roots, vec![Va(0x1000)], "the constant load is the input");
        let addrs: Vec<u64> = sl.nodes.iter().map(|n| n.va.0).collect();
        assert_eq!(addrs, vec![0x1000, 0x1005, 0x1008]);
    }

    #[test]
    fn seed_falls_back_to_nearest_prior_writer() {
        // Same code; query at the `ret` (0x100a) which doesn't write rcx — the
        // seed should walk back to the `mov ecx, eax` at 0x1008.
        let code = vec![
            0xb8, 0x05, 0x00, 0x00, 0x00, 0x83, 0xc0, 0x03, 0x89, 0xc1, 0xc3,
        ];
        let art = build(code);
        let arch = X64::new();
        let sl = slice(&arch, &art, Va(0x100a), "rcx");
        assert_eq!(sl.seed, Some(Va(0x1008)));
        assert_eq!(sl.node_count, 3);
    }
}

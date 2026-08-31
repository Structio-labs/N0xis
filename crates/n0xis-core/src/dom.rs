//! Dominator-tree math shared by [`crate::SsaPass`] (dominance frontier → phi
//! placement) and the control-structuring pass (natural loops, `if`/`else`
//! merge points). One implementation so the two passes can never disagree on
//! what dominates what (CONCEPT §3 rule 3: a duplicated contract is a bug).
//!
//! The dominator computation itself is the same O(blocks²) iterative
//! fixed-point v0 used (its `pseudo.rs`) — correct and
//! simple; a real function rarely has enough blocks for this to matter, and
//! the roadmap's perf pass (Phase 6) is the place to revisit it, not here.

use std::collections::BTreeSet;

use n0xis_contracts::Va;

use crate::ir::CfgArtifact;

/// Block-index successor/predecessor adjacency, resolved from a `CfgArtifact`'s
/// address-keyed edges. Successor addresses that fall outside the function
/// (tail calls, unresolved indirect branches) simply have no edge — sound,
/// since those are not intra-function control flow.
pub fn block_graph(cfg: &CfgArtifact) -> (Vec<Vec<usize>>, Vec<Vec<usize>>) {
    let n = cfg.blocks.len();
    let addr_to_idx: std::collections::HashMap<Va, usize> =
        cfg.blocks.iter().enumerate().map(|(i, b)| (b.start, i)).collect();
    let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut pred: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, b) in cfg.blocks.iter().enumerate() {
        for s in &b.successors {
            if let Some(&j) = addr_to_idx.get(&s.to) {
                succ[i].push(j);
                pred[j].push(i);
            }
        }
    }
    (succ, pred)
}

/// Forward dominator sets: `dom[i]` = every block that dominates block `i`
/// (always includes `i` itself). Block `0` is assumed to be the function
/// entry.
///
/// **Unreachable blocks are excluded from the lattice**, and that is not a
/// detail. Dominance is only defined over paths from the entry, so a block
/// no path reaches has no meaningful dominator set — but the naive iteration
/// leaves it at its `all` initializer, and [`immediate_doms`] then happily
/// picks an "idom" for it out of that garbage. Two mutually unreachable
/// blocks pick each other, and the resulting `idom` graph contains a *cycle*
/// instead of being a tree — which spins [`dominance_frontier`] forever.
///
/// That is not hypothetical: a plain `decomp pseudo` over a real function
/// (56 blocks, 7 of them unreachable — blocks 1 and 15 pointed their idom at
/// each other) hung with the CPU pinned, taking `cargo test --workspace` with
/// it. Unreachable blocks get `dom[i] = {i}`, so their `idom` is `None` and
/// every chain terminates.
pub fn dominators_fwd(n: usize, pred: &[Vec<usize>]) -> Vec<BTreeSet<usize>> {
    if n == 0 {
        return Vec::new();
    }
    let reachable = reachable_from_entry(n, pred);

    let all: BTreeSet<usize> = (0..n).collect();
    let mut dom = vec![all; n];
    dom[0] = BTreeSet::from([0]);
    for (i, d) in dom.iter_mut().enumerate() {
        if !reachable[i] {
            *d = BTreeSet::from([i]);
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        for i in 1..n {
            if !reachable[i] {
                continue;
            }
            // Intersect over reachable predecessors only: an unreachable one
            // now carries `{itself}`, which would wrongly empty the meet.
            let mut acc: Option<BTreeSet<usize>> = None;
            for &p in pred[i].iter().filter(|&&p| reachable[p]) {
                acc = Some(match acc {
                    None => dom[p].clone(),
                    Some(s) => s.intersection(&dom[p]).copied().collect(),
                });
            }
            let Some(mut new) = acc else { continue };
            new.insert(i);
            if new != dom[i] {
                dom[i] = new;
                changed = true;
            }
        }
    }
    dom
}

/// Which blocks are reachable from block `0`, derived from `pred` (the
/// successor direction is just `pred` inverted — callers already have `pred`,
/// so this keeps the signature unchanged).
fn reachable_from_entry(n: usize, pred: &[Vec<usize>]) -> Vec<bool> {
    let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, ps) in pred.iter().enumerate().take(n) {
        for &p in ps {
            if p < n {
                succ[p].push(i);
            }
        }
    }
    let mut reachable = vec![false; n];
    reachable[0] = true;
    let mut stack = vec![0usize];
    while let Some(b) = stack.pop() {
        for &s in &succ[b] {
            if !reachable[s] {
                reachable[s] = true;
                stack.push(s);
            }
        }
    }
    reachable
}

/// Reverse dominator (post-dominator) sets over a synthetic exit node that
/// collects every block with no intra-function successor. Index `n` in the
/// input/output space is that synthetic exit; the returned vec is truncated
/// back to `0..n` (real blocks only) with the exit removed from each set.
pub fn dominators_rev(n: usize, succ: &[Vec<usize>], is_exit: &[bool], is_abort: &[bool]) -> Vec<BTreeSet<usize>> {
    if n == 0 {
        return Vec::new();
    }
    let exit = n;
    let total = n + 1;
    let mut rpred: Vec<Vec<usize>> = vec![Vec::new(); total];
    for i in 0..n {
        // Connect to the virtual exit a real exit, or a dead-end (no successors)
        // that is *not* an abort. A no-return / trap block ends the path without
        // ever reaching normal completion, so it must not be an exit — otherwise
        // a shared tail that all *returning* paths converge on would falsely stop
        // post-dominating (the abort path bypasses it), forcing a `goto`.
        if is_exit[i] || (succ[i].is_empty() && !is_abort[i]) {
            rpred[i].push(exit);
        }
        for &s in &succ[i] {
            rpred[i].push(s);
        }
    }
    let all: BTreeSet<usize> = (0..total).collect();
    let mut dom = vec![all; total];
    dom[exit] = BTreeSet::from([exit]);
    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..n {
            if rpred[i].is_empty() {
                continue;
            }
            let mut acc: Option<BTreeSet<usize>> = None;
            for &p in &rpred[i] {
                acc = Some(match acc {
                    None => dom[p].clone(),
                    Some(s) => s.intersection(&dom[p]).copied().collect(),
                });
            }
            let mut new = acc.unwrap_or_default();
            new.insert(i);
            if new != dom[i] {
                dom[i] = new;
                changed = true;
            }
        }
    }
    dom.into_iter()
        .take(n)
        .map(|mut s| {
            s.remove(&exit);
            s
        })
        .collect()
}

/// The unique immediate dominator of each block (`None` for the entry).
pub fn immediate_doms(dom: &[BTreeSet<usize>]) -> Vec<Option<usize>> {
    let n = dom.len();
    let mut out = vec![None; n];
    for i in 0..n {
        let candidates: Vec<usize> = dom[i].iter().copied().filter(|&j| j != i).collect();
        for &c in &candidates {
            let is_idom = candidates.iter().all(|&d| d == c || dom[c].contains(&d));
            if is_idom {
                out[i] = Some(c);
                break;
            }
        }
    }
    out
}

/// The dominance frontier of every block (Cytron et al.): `df[b]` is the set
/// of blocks where `b`'s dominance "runs out" — exactly where SSA phi
/// placement needs to look.
pub fn dominance_frontier(n: usize, pred: &[Vec<usize>], idom: &[Option<usize>]) -> Vec<BTreeSet<usize>> {
    let mut df = vec![BTreeSet::new(); n];
    for b in 0..n {
        if pred[b].len() < 2 {
            continue;
        }
        for &p in &pred[b] {
            let mut runner = p;
            // `seen` is a belt-and-braces guard, not the fix: `dominators_fwd`
            // now guarantees `idom` is a forest, so this walk terminates on
            // its own. It stays because the failure mode of a malformed idom
            // is an unkillable spin at 100% CPU — the worst way for an
            // analysis pass to be wrong. Bailing early degrades one function's
            // phi placement; spinning takes down the whole run.
            let mut seen = vec![false; idom.len()];
            loop {
                if Some(runner) == idom[b] || seen[runner] {
                    break;
                }
                seen[runner] = true;
                df[runner].insert(b);
                match idom[runner] {
                    Some(next) => runner = next,
                    None => break,
                }
            }
        }
    }
    df
}

/// Dominator-tree children of each block, derived from `idom`.
pub fn dom_children(idom: &[Option<usize>]) -> Vec<Vec<usize>> {
    let n = idom.len();
    let mut children = vec![Vec::new(); n];
    for (i, p) in idom.iter().enumerate() {
        if let Some(p) = p {
            children[*p].push(i);
        }
    }
    children
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A diamond: 0 -> {1,2} -> 3. Block 3's idom is 0 (neither 1 nor 2 alone
    /// dominates it), and its dominance frontier membership is empty (it's
    /// dominated straight from the root); 1 and 2 are each in the other's
    /// non-frontier but 3 is in the frontier of both 1 and 2 conceptually —
    /// concretely: df[1] and df[2] both contain 3 (3 has 2 preds and neither
    /// pred strictly dominates it beyond the shared root).
    #[test]
    fn diamond_cfg_frontier_and_idom() {
        let pred = vec![vec![], vec![0], vec![0], vec![1, 2]];
        let dom = dominators_fwd(4, &pred);
        let idom = immediate_doms(&dom);
        assert_eq!(idom, vec![None, Some(0), Some(0), Some(0)]);
        let df = dominance_frontier(4, &pred, &idom);
        assert_eq!(df[1], BTreeSet::from([3]));
        assert_eq!(df[2], BTreeSet::from([3]));
        assert!(df[3].is_empty());
        assert!(df[0].is_empty());
    }

    #[test]
    fn dom_children_builds_the_tree() {
        let idom = vec![None, Some(0), Some(0), Some(0)];
        let children = dom_children(&idom);
        assert_eq!(children[0], vec![1, 2, 3]);
        assert!(children[1].is_empty());
    }

    /// Regression: a CFG with an unreachable region (real code has plenty —
    /// padding after a `noreturn` call, unresolved jump-table targets) used to
    /// produce a *cyclic* `idom` and spin `dominance_frontier` forever, which
    /// hung every `decomp`/`ir value-set` call on the affected function.
    ///
    /// Shape: 0 -> {2,3} -> 4 is the reachable part; 1 and 5 are mutually
    /// reachable but unreachable from the entry — exactly the pair that used
    /// to pick each other as immediate dominator.
    #[test]
    fn unreachable_blocks_get_no_idom_and_do_not_hang() {
        //          0        1 <-> 5  (island, no edge from the entry)
        //         / \
        //        2   3
        //         \ /
        //          4
        let pred = vec![
            vec![],        // 0: entry
            vec![5],       // 1: only from 5
            vec![0],       // 2
            vec![0],       // 3
            vec![2, 3],    // 4
            vec![1],       // 5: only from 1
        ];
        let dom = dominators_fwd(6, &pred);
        let idom = immediate_doms(&dom);

        // The reachable part is unchanged...
        assert_eq!(idom[0], None);
        assert_eq!(idom[2], Some(0));
        assert_eq!(idom[3], Some(0));
        assert_eq!(idom[4], Some(0));
        // ...and the unreachable island has no dominator at all, so no cycle.
        assert_eq!(idom[1], None, "unreachable block must not get an idom");
        assert_eq!(idom[5], None, "unreachable block must not get an idom");

        // The call that used to never return.
        let df = dominance_frontier(6, &pred, &idom);
        assert_eq!(df[2], BTreeSet::from([4]));
        assert_eq!(df[3], BTreeSet::from([4]));
    }

    /// Even if some future change hands `dominance_frontier` a malformed
    /// (cyclic) idom directly, it must terminate rather than spin.
    #[test]
    fn cyclic_idom_input_still_terminates() {
        let pred = vec![vec![], vec![2], vec![1], vec![1, 2]];
        let idom = vec![None, Some(2), Some(1), Some(0)]; // 1 <-> 2 cycle
        let df = dominance_frontier(4, &pred, &idom);
        assert!(df.len() == 4);
    }
}

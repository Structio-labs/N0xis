//! Dominator-tree math shared by [`crate::SsaPass`] (dominance frontier → phi
//! placement) and the control-structuring pass (natural loops, `if`/`else`
//! merge points). One implementation so the two passes can never disagree on
//! what dominates what (CONCEPT §3 rule 3: a duplicated contract is a bug).
//!
//! The dominator computation itself is the same O(blocks²) iterative
//! fixed-point v0 used (`archive/n0x-cli-rs-v0/src/pseudo.rs`) — correct and
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
pub fn dominators_fwd(n: usize, pred: &[Vec<usize>]) -> Vec<BTreeSet<usize>> {
    if n == 0 {
        return Vec::new();
    }
    let all: BTreeSet<usize> = (0..n).collect();
    let mut dom = vec![all; n];
    dom[0] = BTreeSet::from([0]);
    let mut changed = true;
    while changed {
        changed = false;
        for i in 1..n {
            if pred[i].is_empty() {
                continue;
            }
            let mut acc: Option<BTreeSet<usize>> = None;
            for &p in &pred[i] {
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
    dom
}

/// Reverse dominator (post-dominator) sets over a synthetic exit node that
/// collects every block with no intra-function successor. Index `n` in the
/// input/output space is that synthetic exit; the returned vec is truncated
/// back to `0..n` (real blocks only) with the exit removed from each set.
pub fn dominators_rev(n: usize, succ: &[Vec<usize>], is_exit: &[bool]) -> Vec<BTreeSet<usize>> {
    if n == 0 {
        return Vec::new();
    }
    let exit = n;
    let total = n + 1;
    let mut rpred: Vec<Vec<usize>> = vec![Vec::new(); total];
    for i in 0..n {
        if is_exit[i] || succ[i].is_empty() {
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
            loop {
                if Some(runner) == idom[b] {
                    break;
                }
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
}

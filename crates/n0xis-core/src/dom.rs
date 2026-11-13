// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Dominator-tree math shared by [`crate::SsaPass`] (dominance frontier → phi
//! placement) and the control-structuring pass (natural loops, `if`/`else`
//! merge points). One implementation so the two passes can never disagree on
//! what dominates what (CONCEPT §3 rule 3: a duplicated contract is a bug).
//!
//! The tree is computed directly, in reverse post-order (Cooper, Harvey and
//! Kennedy, "A Simple, Fast Dominance Algorithm"), and whether one block
//! dominates another is read from it. It replaced a fixed point over a set of
//! dominators per block: a function of n blocks in a line took n passes over n
//! sets of n, so `decomp` on 1 000 blocks took 147 s, nearly all of it here.

use std::collections::BTreeSet;

use n0xis_contracts::Va;

use crate::ir::{CfgArtifact, Successor};

/// The immediate dominator of each block of `cfg`, from the edges [`crate::SsaPass`]
/// placed its phis by: what a block with no phi for a register inherits.
pub fn idom_of(cfg: &CfgArtifact) -> Vec<Option<usize>> {
    let (_, pred) = block_graph(cfg);
    DomTree::forward(cfg.blocks.len(), &pred).idom().to_vec()
}

/// Block-index successor/predecessor adjacency, resolved from a `CfgArtifact`'s
/// address-keyed edges. Successor addresses that fall outside the function
/// (tail calls, unresolved indirect branches) simply have no edge — sound,
/// since those are not intra-function control flow.
pub fn block_graph(cfg: &CfgArtifact) -> (Vec<Vec<usize>>, Vec<Vec<usize>>) {
    let blocks: Vec<(Va, &[Successor])> = cfg.blocks.iter().map(|b| (b.start, b.successors.as_slice())).collect();
    block_graph_of(&blocks)
}

/// [`block_graph`] over any blocks given as `(start, successors)`, in block
/// order — the SSA blocks carry the CFG's, so a pass on SSA reads the same
/// edges the dominators of [`crate::SsaPass`] were computed from.
pub fn block_graph_of(blocks: &[(Va, &[Successor])]) -> (Vec<Vec<usize>>, Vec<Vec<usize>>) {
    let n = blocks.len();
    let addr_to_idx: std::collections::HashMap<Va, usize> = blocks.iter().enumerate().map(|(i, (start, _))| (*start, i)).collect();
    let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut pred: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, (_, successors)) in blocks.iter().enumerate() {
        for s in *successors {
            if let Some(&j) = addr_to_idx.get(&s.to) {
                succ[i].push(j);
                pred[j].push(i);
            }
        }
    }
    (succ, pred)
}

/// What a block no path reaches has for dominators.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Unreached {
    /// Forward: dominance is only defined over paths from the entry, so a block
    /// no path reaches has only itself and no immediate dominator. Anything else
    /// let two mutually unreachable blocks pick each other, and the "tree" had a
    /// cycle: a plain `decomp pseudo` on a real function (56 blocks, 7 of them
    /// unreachable) spun forever in [`dominance_frontier`].
    OnlyItself,
    /// Reverse: a block with no path to an exit is post-dominated vacuously, by
    /// every block. Such a block on one side of a branch does not count against
    /// a merge the other side reaches, which is what lets every returning path
    /// converge past an abort.
    Everything,
}

/// Who dominates whom in one function's blocks: [`Self::forward`] from the
/// entry, [`Self::reverse`] from the exits.
pub struct DomTree {
    idom: Vec<Option<usize>>,
    /// Each reached block's interval in a walk of the tree: `a` dominates `b`
    /// when `a`'s holds `b`'s.
    spans: Vec<Option<(u32, u32)>>,
    unreached: Unreached,
}

impl DomTree {
    /// Dominators from block `0`, the function's entry.
    pub fn forward(n: usize, pred: &[Vec<usize>]) -> Self {
        if n == 0 {
            return Self { idom: Vec::new(), spans: Vec::new(), unreached: Unreached::OnlyItself };
        }
        let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (i, ps) in pred.iter().enumerate().take(n) {
            for &p in ps.iter().filter(|&&p| p < n) {
                succ[p].push(i);
            }
        }
        let idom = immediate_tree(0, &succ, pred);
        let spans = tree_spans(0, &idom);
        Self { idom, spans, unreached: Unreached::OnlyItself }
    }

    /// Post-dominators, over a virtual exit every real exit leads to, and every
    /// dead end but an abort: a no-return or trap block ends the path without
    /// reaching normal completion, so were it an exit, a shared tail all
    /// *returning* paths converge on would stop post-dominating them, and the
    /// merge would become a `goto`.
    pub fn reverse(n: usize, succ: &[Vec<usize>], is_exit: &[bool], is_abort: &[bool]) -> Self {
        if n == 0 {
            return Self { idom: Vec::new(), spans: Vec::new(), unreached: Unreached::Everything };
        }
        let exit = n;
        let mut rpred: Vec<Vec<usize>> = vec![Vec::new(); n + 1];
        let mut rsucc: Vec<Vec<usize>> = vec![Vec::new(); n + 1];
        for i in 0..n {
            if is_exit[i] || (succ[i].is_empty() && !is_abort[i]) {
                rpred[i].push(exit);
                rsucc[exit].push(i);
            }
            for &s in &succ[i] {
                rpred[i].push(s);
                rsucc[s].push(i);
            }
        }
        let mut idom = immediate_tree(exit, &rsucc, &rpred);
        let spans = tree_spans(exit, &idom);
        idom.truncate(n);
        for d in idom.iter_mut().filter(|d| **d == Some(exit)) {
            *d = None;
        }
        let mut tree = Self { idom, spans, unreached: Unreached::Everything };
        // A block with no path to an exit: every other block is a candidate, and
        // the answer is the lowest one all the others dominate. It names no merge
        // anyone chose; it is kept to the block because `structure` reads it and
        // changing it changes answers.
        for i in (0..n).filter(|&i| tree.spans[i].is_none()).collect::<Vec<_>>() {
            let found = (0..n).filter(|&c| c != i).find(|&c| (0..n).filter(|&d| d != i && d != c).all(|d| tree.dominates(d, c)));
            tree.idom[i] = found;
        }
        tree
    }

    /// The immediate dominator of each block: `None` for the root, and for a
    /// block with only itself.
    pub fn idom(&self) -> &[Option<usize>] {
        &self.idom
    }

    /// Does every path to `b` pass through `a`? A block dominates itself.
    pub fn dominates(&self, a: usize, b: usize) -> bool {
        if a == b {
            return true;
        }
        match (self.spans[a], self.spans[b]) {
            (_, None) => self.unreached == Unreached::Everything,
            (None, Some(_)) => false,
            (Some((a_in, a_out)), Some((b_in, b_out))) => a_in <= b_in && b_out <= a_out,
        }
    }
}

/// A block with no immediate dominator yet.
const NO_BLOCK: usize = usize::MAX;

/// The immediate dominators of what `root` reaches. Reverse post-order sees a
/// block after its dominators on any graph without back edges, so one pass and
/// a check suffice there, and a few more with loops. The walk keeps its own
/// stack: a function's blocks are input, and nothing bounds a recursion on them.
fn immediate_tree(root: usize, succ: &[Vec<usize>], pred: &[Vec<usize>]) -> Vec<Option<usize>> {
    let total = succ.len();
    let mut seen = vec![false; total];
    let mut post_number = vec![0usize; total];
    let mut post_order = Vec::with_capacity(total);
    seen[root] = true;
    let mut stack = vec![(root, 0usize)];
    while let Some((b, next)) = stack.last_mut() {
        if let Some(&s) = succ[*b].get(*next) {
            *next += 1;
            if !std::mem::replace(&mut seen[s], true) {
                stack.push((s, 0));
            }
        } else {
            post_number[*b] = post_order.len();
            post_order.push(*b);
            stack.pop();
        }
    }

    let mut idom = vec![NO_BLOCK; total];
    idom[root] = root;
    let meet = |mut a: usize, mut b: usize, idom: &[usize]| {
        while a != b {
            while post_number[a] < post_number[b] {
                a = idom[a];
            }
            while post_number[b] < post_number[a] {
                b = idom[b];
            }
        }
        a
    };
    let mut changed = true;
    while changed {
        changed = false;
        for &b in post_order.iter().rev().skip(1) {
            let mut new = NO_BLOCK;
            for &p in pred[b].iter().filter(|&&p| idom[p] != NO_BLOCK) {
                new = if new == NO_BLOCK { p } else { meet(p, new, &idom) };
            }
            if idom[b] != new {
                idom[b] = new;
                changed = true;
            }
        }
    }
    idom[root] = NO_BLOCK;
    idom.into_iter().map(|d| (d != NO_BLOCK).then_some(d)).collect()
}

/// Enter and leave times of a walk of the tree under `root`; `None` for a block
/// the tree does not hold.
fn tree_spans(root: usize, idom: &[Option<usize>]) -> Vec<Option<(u32, u32)>> {
    let children = dom_children(idom);
    let mut spans = vec![None; idom.len()];
    let mut clock = 0u32;
    let mut stack = vec![(root, 0usize, 0u32)];
    while let Some((b, next, entered)) = stack.last_mut() {
        if let Some(&child) = children[*b].get(*next) {
            *next += 1;
            clock += 1;
            stack.push((child, 0, clock));
        } else {
            clock += 1;
            spans[*b] = Some((*entered, clock));
            stack.pop();
        }
    }
    spans
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

    /// The set-based fixed point this module used to compute, kept as the
    /// reference: dominance by definition, slow, and with the answers on
    /// unreachable blocks every caller was written against.
    mod by_sets {
        use std::collections::BTreeSet;

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
    }

    /// A small deterministic generator, so a failing graph can be run again by its seed.
    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    /// Successors and predecessors of a random graph of `n` blocks, sparse or
    /// dense, loops, islands and dead ends included.
    fn random_graph(n: usize, density: u64, state: &mut u64) -> (Vec<Vec<usize>>, Vec<Vec<usize>>) {
        let mut succ = vec![Vec::new(); n];
        let mut pred = vec![Vec::new(); n];
        for (i, s) in succ.iter_mut().enumerate() {
            for (j, p) in pred.iter_mut().enumerate() {
                if next(state) % 100 < density {
                    s.push(j);
                    p.push(i);
                }
            }
        }
        (succ, pred)
    }

    /// Every answer on 6 000 random graphs against dominance by definition,
    /// forward and reverse, with exits and aborts where the graph puts them.
    #[test]
    fn the_tree_answers_what_the_sets_answer() {
        let mut state = 0x004e_3058_4953u64;
        for round in 0..6000 {
            let n = 1 + (next(&mut state) % 24) as usize;
            let density = [3, 6, 10, 20, 40][round % 5];
            let (succ, pred) = random_graph(n, density, &mut state);

            let sets = by_sets::dominators_fwd(n, &pred);
            let tree = DomTree::forward(n, &pred);
            assert_eq!(tree.idom(), by_sets::immediate_doms(&sets), "forward idom, round {round}, {succ:?}");
            for a in 0..n {
                for (b, set) in sets.iter().enumerate() {
                    assert_eq!(tree.dominates(a, b), set.contains(&a), "forward {a} over {b}, round {round}, {succ:?}");
                }
            }

            let is_exit: Vec<bool> = (0..n).map(|_| next(&mut state).is_multiple_of(5)).collect();
            let is_abort: Vec<bool> = (0..n).map(|_| next(&mut state).is_multiple_of(5)).collect();
            let sets = by_sets::dominators_rev(n, &succ, &is_exit, &is_abort);
            let tree = DomTree::reverse(n, &succ, &is_exit, &is_abort);
            assert_eq!(tree.idom(), by_sets::immediate_doms(&sets), "reverse idom, round {round}, {succ:?}, {is_exit:?}, {is_abort:?}");
            for a in 0..n {
                for (b, set) in sets.iter().enumerate() {
                    assert_eq!(tree.dominates(a, b), set.contains(&a), "reverse {a} over {b}, round {round}, {succ:?}, {is_exit:?}, {is_abort:?}");
                }
            }
        }
    }

    /// Blocks in a line are the worst case the set code had: n passes over n
    /// sets of n in reverse. 200 000 is out of its reach in time and in memory.
    #[test]
    fn a_long_line_of_blocks_takes_no_time() {
        let n = 200_000;
        let succ: Vec<Vec<usize>> = (0..n).map(|i| if i + 1 < n { vec![i + 1] } else { Vec::new() }).collect();
        let pred: Vec<Vec<usize>> = (0..n).map(|i| if i > 0 { vec![i - 1] } else { Vec::new() }).collect();
        let is_exit: Vec<bool> = (0..n).map(|i| i + 1 == n).collect();
        let is_abort = vec![false; n];
        let forward = DomTree::forward(n, &pred);
        let reverse = DomTree::reverse(n, &succ, &is_exit, &is_abort);
        assert_eq!(forward.idom()[n - 1], Some(n - 2));
        assert_eq!(reverse.idom()[0], Some(1));
        assert!(forward.dominates(0, n - 1) && !forward.dominates(n - 1, 0));
        assert!(reverse.dominates(n - 1, 0) && !reverse.dominates(0, n - 1));
    }

    /// A diamond: 0 -> {1,2} -> 3. Block 3's idom is 0 (neither 1 nor 2 alone
    /// dominates it), and its dominance frontier membership is empty (it's
    /// dominated straight from the root); 1 and 2 are each in the other's
    /// non-frontier but 3 is in the frontier of both 1 and 2 conceptually —
    /// concretely: df[1] and df[2] both contain 3 (3 has 2 preds and neither
    /// pred strictly dominates it beyond the shared root).
    #[test]
    fn diamond_cfg_frontier_and_idom() {
        let pred = vec![vec![], vec![0], vec![0], vec![1, 2]];
        let tree = DomTree::forward(4, &pred);
        let idom = tree.idom();
        assert_eq!(idom, [None, Some(0), Some(0), Some(0)]);
        let df = dominance_frontier(4, &pred, idom);
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
        let tree = DomTree::forward(6, &pred);
        let idom = tree.idom();

        // The reachable part is unchanged...
        assert_eq!(idom[0], None);
        assert_eq!(idom[2], Some(0));
        assert_eq!(idom[3], Some(0));
        assert_eq!(idom[4], Some(0));
        // ...and the unreachable island has no dominator at all, so no cycle.
        assert_eq!(idom[1], None, "unreachable block must not get an idom");
        assert_eq!(idom[5], None, "unreachable block must not get an idom");

        // The call that used to never return.
        let df = dominance_frontier(6, &pred, idom);
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

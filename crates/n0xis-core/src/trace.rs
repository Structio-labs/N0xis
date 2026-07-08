//! [`TracePass`] — breadth-first call-graph walk from a root (`function trace`).
//!
//! Starting at `root`, builds the CFG for each visited function (via
//! [`CfgPass`]) and follows its callsites to the next depth, up to `depth`
//! levels and `max_nodes` visited functions. Each visited function's
//! function-end detection reuses `CfgPass`'s existing `auto_end` heuristic —
//! a meaningful improvement over v0, which bounded a function's body crudely
//! at "the next known function start" from a separate discovery pass.

use std::collections::{HashSet, VecDeque};

use n0xis_contracts::Va;
use serde::Serialize;

use crate::ir::{CfgInput, CfgPass, Callsite};
use crate::{Ctx, CoreError, Pass};

/// What to walk and how far.
#[derive(Clone, Copy, Debug)]
pub struct TraceInput {
    pub root: Va,
    /// Maximum call-graph depth from `root` (0 = only the root itself).
    pub depth: usize,
    /// Cap on visited functions; 0 = unlimited.
    pub max_nodes: usize,
    /// Byte window handed to `CfgPass` for each visited function.
    pub max_bytes: usize,
}

/// One visited function and the calls it makes.
#[derive(Clone, Debug, Serialize)]
pub struct TraceNode {
    pub addr: Va,
    pub depth: usize,
    pub end: Va,
    pub calls: Vec<Callsite>,
    /// `true` when the function's bytes couldn't be read/decoded (e.g. a call
    /// landed on an IAT thunk or other non-code address) — `end`/`calls` are
    /// empty in that case, but the node is still reported so the caller can
    /// see the call graph reached there.
    pub unreadable: bool,
}

/// The trace artifact (`n0xis.function.trace.v1`).
#[derive(Clone, Debug, Serialize)]
pub struct TraceArtifact {
    pub root: Va,
    pub depth: usize,
    pub node_count: usize,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncate_reason: Option<&'static str>,
    pub nodes: Vec<TraceNode>,
}

/// Call-graph trace pass.
#[derive(Clone, Copy, Debug, Default)]
pub struct TracePass;

impl Pass for TracePass {
    type In = TraceInput;
    type Out = TraceArtifact;

    fn name(&self) -> &'static str {
        "function.trace"
    }

    fn run(&self, ctx: &Ctx, input: TraceInput) -> Result<TraceArtifact, CoreError> {
        let mut nodes = Vec::new();
        let mut seen: HashSet<u64> = HashSet::new();
        let mut queue: VecDeque<(Va, usize)> = VecDeque::new();
        queue.push_back((input.root, 0));

        let mut truncated = false;
        let mut truncate_reason: Option<&'static str> = None;

        while let Some((addr, depth)) = queue.pop_front() {
            if !seen.insert(addr.0) {
                continue;
            }
            if input.max_nodes > 0 && nodes.len() >= input.max_nodes {
                truncated = true;
                truncate_reason = Some("max_nodes");
                break;
            }

            let cfg_input = CfgInput::new(addr, input.max_bytes);
            let art = match CfgPass.run(ctx, cfg_input) {
                Ok(a) => a,
                Err(_) => {
                    nodes.push(TraceNode { addr, depth, end: addr, calls: Vec::new(), unreadable: true });
                    continue;
                }
            };

            if depth < input.depth {
                for c in &art.callsites {
                    if let Some(t) = c.target {
                        queue.push_back((t, depth + 1));
                    }
                }
            }

            nodes.push(TraceNode { addr, depth, end: art.end, calls: art.callsites, unreadable: false });
        }

        Ok(TraceArtifact {
            root: input.root,
            depth: input.depth,
            node_count: nodes.len(),
            truncated,
            truncate_reason,
            nodes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    #[test]
    fn walks_a_two_level_call_chain() {
        // root (0x1000): call mid (0x1100); ret
        // mid  (0x1100): call leaf (0x1200); ret
        // leaf (0x1200): ret
        let root = vec![0xE8, 0xFB, 0x00, 0x00, 0x00, 0xC3]; // call +0xfb -> 0x1100
        let mid = vec![0xE8, 0xFB, 0x00, 0x00, 0x00, 0xC3]; // call +0xfb -> 0x1200
        let leaf = vec![0xC3];
        let snap = Snapshot::builder()
            .region(Va(0x1000), root)
            .region(Va(0x1100), mid)
            .region(Va(0x1200), leaf)
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);

        let art = TracePass
            .run(&ctx, TraceInput { root: Va(0x1000), depth: 5, max_nodes: 0, max_bytes: 64 })
            .expect("trace runs");

        assert_eq!(art.node_count, 3, "root, mid, leaf all visited");
        assert!(!art.truncated);
        let addrs: HashSet<u64> = art.nodes.iter().map(|n| n.addr.0).collect();
        assert_eq!(addrs, HashSet::from([0x1000, 0x1100, 0x1200]));
        let root_node = art.nodes.iter().find(|n| n.addr == Va(0x1000)).unwrap();
        assert_eq!(root_node.depth, 0);
        assert_eq!(root_node.calls.len(), 1);
        assert_eq!(root_node.calls[0].target, Some(Va(0x1100)));
        let leaf_node = art.nodes.iter().find(|n| n.addr == Va(0x1200)).unwrap();
        assert_eq!(leaf_node.depth, 2);
        assert!(leaf_node.calls.is_empty());
    }

    #[test]
    fn depth_limit_stops_the_walk() {
        let root = vec![0xE8, 0xFB, 0x00, 0x00, 0x00, 0xC3]; // call -> 0x1100
        let mid = vec![0xE8, 0xFB, 0x00, 0x00, 0x00, 0xC3]; // call -> 0x1200
        let leaf = vec![0xC3];
        let snap = Snapshot::builder()
            .region(Va(0x1000), root)
            .region(Va(0x1100), mid)
            .region(Va(0x1200), leaf)
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);

        // depth=1: root (0) and mid (1) are visited; leaf (2) is beyond depth.
        let art = TracePass
            .run(&ctx, TraceInput { root: Va(0x1000), depth: 1, max_nodes: 0, max_bytes: 64 })
            .expect("trace runs");
        assert_eq!(art.node_count, 2);
        assert!(art.nodes.iter().all(|n| n.addr != Va(0x1200)));
    }

    #[test]
    fn max_nodes_truncates_and_reports_why() {
        let root = vec![0xE8, 0xFB, 0x00, 0x00, 0x00, 0xC3];
        let mid = vec![0xE8, 0xFB, 0x00, 0x00, 0x00, 0xC3];
        let leaf = vec![0xC3];
        let snap = Snapshot::builder()
            .region(Va(0x1000), root)
            .region(Va(0x1100), mid)
            .region(Va(0x1200), leaf)
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);

        let art = TracePass
            .run(&ctx, TraceInput { root: Va(0x1000), depth: 5, max_nodes: 1, max_bytes: 64 })
            .expect("trace runs");
        assert_eq!(art.node_count, 1);
        assert!(art.truncated);
        assert_eq!(art.truncate_reason, Some("max_nodes"));
    }

    #[test]
    fn a_shared_callee_is_visited_once() {
        // Both root and mid call leaf — leaf must appear exactly once, at its
        // shallowest reachable depth (BFS visits root's own edges first).
        // root (0x1000): call mid (0x1100); call leaf (0x1200); ret
        let root = vec![
            0xE8, 0xFB, 0x00, 0x00, 0x00, // 0x1000: call +0xfb -> 0x1100
            0xE8, 0xF6, 0x01, 0x00, 0x00, // 0x1005: call +0x1f6 -> 0x1200
            0xC3,
        ];
        let mid = vec![0xE8, 0xFB, 0x00, 0x00, 0x00, 0xC3]; // 0x1100: call +0xfb -> 0x1200
        let leaf = vec![0xC3];
        let snap = Snapshot::builder()
            .region(Va(0x1000), root)
            .region(Va(0x1100), mid)
            .region(Va(0x1200), leaf)
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);

        let art = TracePass
            .run(&ctx, TraceInput { root: Va(0x1000), depth: 5, max_nodes: 0, max_bytes: 64 })
            .expect("trace runs");
        assert_eq!(art.node_count, 3, "leaf deduplicated despite two callers");
        let leaf_node = art.nodes.iter().find(|n| n.addr == Va(0x1200)).unwrap();
        assert_eq!(leaf_node.depth, 1, "reached directly from root before mid's edge");
    }
}

// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Graphviz DOT rendering of a built CFG (`ir dot`).
//!
//! A pure presentation over [`CfgArtifact`] — no source or arch needed, it just
//! walks the blocks and their successor edges. Edges whose target is a decoded
//! block point block→block; edges to anything else (tail calls, switch cases
//! outside the decoded extent) point to a distinct external node so the flow
//! stays visible — including the memory-resolved `switch-case` edges.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use n0xis_contracts::Va;
use serde::Serialize;

use crate::ir::CfgArtifact;

/// DOT artifact (`n0xis.ir.dot.v1`): the graph source plus a small summary.
#[derive(Clone, Debug, Serialize)]
pub struct DotArtifact {
    pub start: Va,
    pub end: Va,
    pub block_count: usize,
    pub edge_count: usize,
    /// Number of edges that leave the decoded blocks (tail/switch/etc.).
    pub external_count: usize,
    /// The Graphviz `digraph` source.
    pub dot: String,
}

/// Render `art` to Graphviz DOT.
pub fn dot(art: &CfgArtifact) -> DotArtifact {
    let id_by_start: BTreeMap<u64, usize> =
        art.blocks.iter().map(|b| (b.start.0, b.id)).collect();

    let mut out = String::new();
    out.push_str("digraph n0xis_cfg {\n");
    out.push_str("  rankdir=TB;\n");
    out.push_str("  node [shape=box, fontname=\"Consolas\", fontsize=10];\n");
    out.push_str("  edge [fontname=\"Consolas\", fontsize=9];\n");

    for b in &art.blocks {
        let label = format!(
            "B{}\\n{}..{}\\n{} · {} insns",
            b.id,
            b.start,
            b.end,
            b.terminator,
            b.insns.len()
        );
        let _ = writeln!(out, "  b{} [label=\"{}\"];", b.id, escape_dot(&label));
    }

    // External targets get one node each, keyed by address, drawn distinctly.
    let mut externals: BTreeMap<u64, usize> = BTreeMap::new();
    let mut edge_count = 0usize;
    for b in &art.blocks {
        for s in &b.successors {
            let edge_label = format!("{} (q={:.2})", s.kind, s.confidence);
            match id_by_start.get(&s.to.0) {
                Some(to_id) => {
                    let _ = writeln!(
                        out,
                        "  b{} -> b{} [label=\"{}\"];",
                        b.id,
                        to_id,
                        escape_dot(&edge_label)
                    );
                }
                None => {
                    let next = externals.len();
                    let ext = *externals.entry(s.to.0).or_insert(next);
                    let _ = writeln!(
                        out,
                        "  b{} -> ext{} [style=dashed, label=\"{}\"];",
                        b.id,
                        ext,
                        escape_dot(&edge_label)
                    );
                }
            }
            edge_count += 1;
        }
    }

    for (addr, id) in &externals {
        let _ = writeln!(
            out,
            "  ext{} [shape=oval, style=dashed, label=\"{}\"];",
            id,
            escape_dot(&Va(*addr).to_string())
        );
    }

    out.push_str("}\n");

    DotArtifact {
        start: art.start,
        end: art.end,
        block_count: art.block_count,
        edge_count,
        external_count: externals.len(),
        dot: out,
    }
}

/// Escape a DOT label (backslashes and quotes; `\n` sequences are already
/// literal two-char escapes in the labels we build).
fn escape_dot(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                // Preserve intentional `\n` label breaks; escape a lone backslash.
                if chars.peek() == Some(&'n') {
                    out.push('\\');
                    out.push('n');
                    chars.next();
                } else {
                    out.push_str("\\\\");
                }
            }
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CfgInput, CfgPass};
    use crate::{Ctx, Pass};
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    #[test]
    fn renders_branch_cfg_to_dot() {
        // cmp rcx,0 / je / inc rcx / ret — three blocks, one cjmp.
        let code = vec![
            0x48, 0x83, 0xf9, 0x00, 0x74, 0x03, 0x48, 0xff, 0xc1, 0xc3,
        ];
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), 64)).unwrap();

        let d = dot(&art);
        assert_eq!(d.block_count, 3);
        assert!(d.dot.starts_with("digraph n0xis_cfg {"));
        assert!(d.dot.trim_end().ends_with('}'));
        // One node per block and at least the two cjmp edges present.
        assert!(d.dot.contains("b0 [label="));
        assert_eq!(d.edge_count, art.blocks.iter().map(|b| b.successors.len()).sum::<usize>());
    }

    #[test]
    fn switch_cases_appear_as_edges() {
        // Same mem-indexed switch as the ir test: cases land outside the tiny
        // decoded function, so they render as dashed external edges — the whole
        // point of putting resolved switch targets on the graph.
        let code = vec![
            0x48, 0x83, 0xf8, 0x02, 0xff, 0x24, 0xc5, 0x00, 0x20, 0x00, 0x00,
        ];
        let mut table = Vec::new();
        for case in [0x1500u64, 0x1600, 0x1700] {
            table.extend_from_slice(&case.to_le_bytes());
        }
        let snap = Snapshot::builder()
            .region(Va(0x1000), code)
            .region(Va(0x2000), table)
            .region(Va(0x1500), vec![0x90; 0x300])
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), 64)).unwrap();

        let d = dot(&art);
        assert_eq!(d.external_count, 3, "three switch cases as external targets");
        assert!(d.dot.contains("style=dashed"));
        assert!(d.dot.contains("switch-case"));
        for case in ["0x1500", "0x1600", "0x1700"] {
            assert!(d.dot.contains(case), "case {case} should appear as a node");
        }
    }
}

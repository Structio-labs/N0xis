//! [`ManifestPass`] — lightweight per-function index with quality scoring
//! (`ir manifest`).
//!
//! Runs [`CfgPass`] over a batch of candidate addresses (typically from
//! [`DiscoverPass`](crate::DiscoverPass), or a symbol table) and reduces each
//! to a compact triage entry: shape counts, the frame summary, and a
//! heuristic 0.0..=1.0 "does this look like a real function" quality score.
//! Built for scale — an agent staring at thousands of discovered candidates
//! needs this cheap summary before spending a full `ir build`/`ir explain` on
//! any one of them. Ported from v0's manifest scoring, now computed from the
//! typed [`CfgArtifact`] instead of re-parsing disassembly text.

use serde::Serialize;

use n0xis_contracts::Va;

use crate::ir::{CfgArtifact, CfgInput, CfgPass};
use crate::{Ctx, Pass};

/// One address to summarize, and the name to report it under.
#[derive(Clone, Debug)]
pub struct ManifestCandidate {
    pub name: String,
    pub va: Va,
}

/// What to summarize, and the per-function analysis budget.
#[derive(Clone, Debug)]
pub struct ManifestInput {
    pub candidates: Vec<ManifestCandidate>,
    /// Byte window handed to `CfgPass` for each candidate.
    pub max_bytes: usize,
}

/// The manifest artifact (`n0xis.ir.manifest.v1`).
#[derive(Clone, Debug, Serialize)]
pub struct ManifestArtifact {
    pub count: usize,
    pub entries: Vec<ManifestEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ManifestEntry {
    pub va: Va,
    pub name: String,
    pub end: Va,
    pub insn_count: usize,
    pub block_count: usize,
    pub returns: usize,
    pub indirect_branches: usize,
    pub tail_calls: usize,
    pub callsites: usize,
    pub switches: usize,
    pub frame_size: u64,
    /// 0.0..=1.0 confidence this candidate is a real, well-formed function.
    pub quality: f32,
    /// Short categorical flags, e.g. `leaf`, `has-switch`, `stub`, `no-frame`.
    pub flags: Vec<&'static str>,
}

/// Batch summarization pass. Never fails outright — a candidate that can't be
/// decoded (bad address, unmapped) becomes a zeroed, `unreadable`-flagged
/// entry rather than aborting the whole manifest.
#[derive(Clone, Copy, Debug, Default)]
pub struct ManifestPass;

impl Pass for ManifestPass {
    type In = ManifestInput;
    type Out = ManifestArtifact;

    fn name(&self) -> &'static str {
        "ir.manifest"
    }

    fn run(&self, ctx: &Ctx, input: ManifestInput) -> Result<ManifestArtifact, crate::CoreError> {
        let entries: Vec<ManifestEntry> = input
            .candidates
            .into_iter()
            .map(|c| summarize(ctx, c, input.max_bytes))
            .collect();
        Ok(ManifestArtifact {
            count: entries.len(),
            entries,
        })
    }
}

fn summarize(ctx: &Ctx, candidate: ManifestCandidate, max_bytes: usize) -> ManifestEntry {
    let input = CfgInput::new(candidate.va, max_bytes);
    match CfgPass.run(ctx, input) {
        Ok(art) => ManifestEntry {
            va: candidate.va,
            name: candidate.name,
            end: art.end,
            insn_count: art.insn_count,
            block_count: art.block_count,
            returns: art.stats.returns,
            indirect_branches: art.stats.indirect_branches,
            tail_calls: art.stats.tail_calls,
            callsites: art.callsites.len(),
            switches: art.switches.len(),
            frame_size: art.frame.frame_size,
            quality: quality_score(&art),
            flags: flags(&art),
        },
        Err(_) => ManifestEntry {
            va: candidate.va,
            name: candidate.name,
            end: candidate.va,
            insn_count: 0,
            block_count: 0,
            returns: 0,
            indirect_branches: 0,
            tail_calls: 0,
            callsites: 0,
            switches: 0,
            frame_size: 0,
            quality: 0.0,
            flags: vec!["unreadable"],
        },
    }
}

/// Score how "real" this recovered function looks. Combines structural
/// signals (prolog, return, multi-block CFG, plausible size) into a rough
/// 0.0..=1.0 confidence. Weights ported as-is from v0's proven heuristic.
fn quality_score(art: &CfgArtifact) -> f32 {
    let mut s = 0.0_f32;
    let frame_ok =
        art.frame.frame_size > 0 || art.frame.uses_rbp || !art.frame.spilled_regs.is_empty();
    if frame_ok {
        s += 0.25;
    }
    if art.stats.returns >= 1 {
        s += 0.25;
    }
    if art.block_count >= 2 {
        s += 0.10;
    }
    if (5..=2000).contains(&art.insn_count) {
        s += 0.15;
    }
    if !art.callsites.is_empty() {
        s += 0.05;
    }
    let max_indirect = art.block_count.max(1);
    if art.stats.indirect_branches <= max_indirect {
        s += 0.10;
    }
    if art.insn_count > 0 {
        s += 0.05;
    }
    if art.stats.tail_calls > 0 || art.stats.returns > 0 {
        s += 0.05;
    }
    s.min(1.0)
}

/// Categorical flags for fast filtering / display in a manifest.
fn flags(art: &CfgArtifact) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    if art.callsites.is_empty() {
        out.push("leaf");
    }
    if !art.switches.is_empty() {
        out.push("has-switch");
    }
    if art.stats.tail_calls > 0 {
        out.push("tail");
    }
    if art.insn_count < 5 {
        out.push("stub");
    }
    if art.insn_count > 2000 {
        out.push("runaway");
    }
    let no_frame =
        art.frame.frame_size == 0 && !art.frame.uses_rbp && art.frame.spilled_regs.is_empty();
    if no_frame {
        out.push("no-frame");
    }
    if art.stats.returns == 0 && art.stats.tail_calls == 0 {
        out.push("no-return");
    }
    if art.stats.noreturn_calls > 0 {
        out.push("calls-noreturn");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    #[test]
    fn scores_a_well_formed_function_higher_than_a_stub() {
        // A real-looking function: prolog, a branch, a return.
        let real = vec![
            0x53, // push rbx
            0x48, 0x83, 0xec, 0x20, // sub rsp, 0x20
            0x48, 0x83, 0xf9, 0x00, // cmp rcx, 0
            0x74, 0x03, // je +3
            0x48, 0xff, 0xc1, // inc rcx
            0x48, 0x83, 0xc4, 0x20, // add rsp, 0x20
            0x5b, // pop rbx
            0xc3, // ret
        ];
        // A stub: just `ret`.
        let stub = vec![0xc3];

        let snap = Snapshot::builder()
            .region(Va(0x1000), real)
            .region(Va(0x2000), stub)
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);

        let input = ManifestInput {
            candidates: vec![
                ManifestCandidate { name: "real_fn".into(), va: Va(0x1000) },
                ManifestCandidate { name: "stub_fn".into(), va: Va(0x2000) },
            ],
            max_bytes: 64,
        };
        let art = ManifestPass.run(&ctx, input).expect("manifest builds");

        assert_eq!(art.count, 2);
        let real_entry = &art.entries[0];
        let stub_entry = &art.entries[1];
        assert!(
            real_entry.quality > stub_entry.quality,
            "well-formed function ({}) should outscore a bare-ret stub ({})",
            real_entry.quality,
            stub_entry.quality
        );
        assert!(stub_entry.flags.contains(&"stub"));
        assert!(real_entry.flags.contains(&"leaf"));
    }

    #[test]
    fn a_function_whose_only_exit_is_a_noreturn_call_is_flagged_both_ways() {
        // A function whose entire body is a call to ExitProcess: never
        // returns and never tail-calls, so the pre-existing "no-return"
        // heuristic becomes accurate for this case for free, alongside the
        // new "calls-noreturn" flag naming why.
        let code = vec![0xe8, 0xfb, 0x0f, 0x00, 0x00]; // call 0x2000
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

        let input = ManifestInput {
            candidates: vec![ManifestCandidate { name: "dies".into(), va: Va(0x1000) }],
            max_bytes: 64,
        };
        let art = ManifestPass.run(&ctx, input).expect("manifest builds");

        let entry = &art.entries[0];
        assert!(entry.flags.contains(&"no-return"));
        assert!(entry.flags.contains(&"calls-noreturn"));
    }

    #[test]
    fn unreadable_candidate_gets_a_zeroed_flagged_entry() {
        let snap = Snapshot::builder().region(Va(0x1000), vec![0xc3]).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let input = ManifestInput {
            candidates: vec![ManifestCandidate { name: "ghost".into(), va: Va(0xdead0000) }],
            max_bytes: 64,
        };
        let art = ManifestPass.run(&ctx, input).expect("manifest builds");
        assert_eq!(art.entries[0].flags, vec!["unreadable"]);
        assert_eq!(art.entries[0].quality, 0.0);
    }
}

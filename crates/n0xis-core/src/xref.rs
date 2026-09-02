//! [`XrefPass`] — cross-references to or from an address.
//!
//! Decodes a code range and finds references via the arch-provided fields on
//! [`DecodedInsn`](n0xis_arch::DecodedInsn): `target` (direct branch/call) and
//! `rip_target` (RIP-relative data access, e.g. `lea`). Because both come from
//! the arch, this pass carries **no** ISA byte patterns — unlike v0, which
//! hand-scanned `48 8D … mod/rm` for `lea`. Works over any source.

use std::collections::BTreeMap;

use n0xis_arch::InsnKind;
use n0xis_contracts::Va;
use serde::{Deserialize, Serialize};

use crate::{Ctx, CoreError, Pass};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum XrefDir {
    /// Who references `addr`.
    To,
    /// What `addr` references.
    From,
}

/// What to cross-reference.
#[derive(Clone, Copy, Debug)]
pub struct XrefInput {
    /// Start of the code window to scan.
    pub scan_start: Va,
    /// Size of the window.
    pub size: usize,
    /// The address of interest.
    pub addr: Va,
    pub dir: XrefDir,
}

#[derive(Clone, Debug, Serialize)]
pub struct XrefEntry {
    pub from: Va,
    pub to: Va,
    /// `call` / `jmp` / `cond_jmp` / `data`.
    pub kind: String,
    pub text: String,
    /// The `to` target's symbol name, when the symbol layer has one at exactly
    /// that address (a recovered RTTI method, a user rename, an export). Lets the
    /// caller render `→ verify_signature` beside a row instead of a bare address —
    /// the instruction `text` itself stays the raw decoded form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sym: Option<String>,
}

/// The xref artifact (`n0xis.xref.v1`).
#[derive(Clone, Debug, Serialize)]
pub struct XrefArtifact {
    pub addr: Va,
    pub dir: XrefDir,
    pub count: usize,
    pub refs: Vec<XrefEntry>,
}

/// Cross-reference pass.
#[derive(Clone, Copy, Debug, Default)]
pub struct XrefPass;

fn branch_kind(k: InsnKind) -> Option<&'static str> {
    match k {
        InsnKind::Call => Some("call"),
        InsnKind::Jump => Some("jmp"),
        InsnKind::CondJump => Some("cond_jmp"),
        _ => None,
    }
}

impl Pass for XrefPass {
    type In = XrefInput;
    type Out = XrefArtifact;

    fn name(&self) -> &'static str {
        "xref"
    }

    fn run(&self, ctx: &Ctx, input: XrefInput) -> Result<XrefArtifact, CoreError> {
        let bytes = ctx.source.read(input.scan_start, input.size)?;
        // Generous instruction cap: a full window can be large.
        let insns = ctx
            .arch
            .decode_range(&bytes, input.scan_start, bytes.len());
        let mut refs = Vec::new();

        // The `to` target's name, when the symbol layer has one at exactly that
        // address (recovered RTTI method, user rename, export).
        let name_of = |va: Va| ctx.symbols.and_then(|s| s.symbol_at(va)).filter(|sy| sy.va == va).map(|sy| sy.name);

        for ins in &insns {
            match input.dir {
                XrefDir::To => {
                    if ins.target == Some(input.addr) {
                        let kind = branch_kind(ins.kind).unwrap_or("branch");
                        refs.push(XrefEntry {
                            from: ins.va,
                            to: input.addr,
                            kind: kind.to_string(),
                            text: ins.text.clone(),
                            sym: name_of(input.addr),
                        });
                    } else if ins.rip_target == Some(input.addr) {
                        refs.push(XrefEntry {
                            from: ins.va,
                            to: input.addr,
                            kind: "data".to_string(),
                            text: ins.text.clone(),
                            sym: name_of(input.addr),
                        });
                    }
                }
                XrefDir::From => {
                    if ins.va != input.addr {
                        continue;
                    }
                    if let Some(t) = ins.target {
                        let kind = branch_kind(ins.kind).unwrap_or("branch");
                        refs.push(XrefEntry {
                            from: input.addr,
                            to: t,
                            kind: kind.to_string(),
                            text: ins.text.clone(),
                            sym: name_of(t),
                        });
                    }
                    if let Some(t) = ins.rip_target {
                        refs.push(XrefEntry {
                            from: input.addr,
                            to: t,
                            kind: "data".to_string(),
                            text: ins.text.clone(),
                            sym: name_of(t),
                        });
                    }
                }
            }
        }

        Ok(XrefArtifact {
            addr: input.addr,
            dir: input.dir,
            count: refs.len(),
            refs,
        })
    }
}

/// A reverse-edge map (`referenced VA → the VAs that reference it`), built with
/// ONE `decode_range` pass over all code ranges. Turns `xref to` from a full
/// re-scan of the code section (seconds on a large image) into a map lookup.
///
/// Only the *source addresses* are stored — not the reference kind or the
/// instruction text. On a large image storing those per edge multiplies the
/// on-disk size for nothing, since a query needs them only for the handful of
/// hits it returns: both are re-derived by decoding the single `from`
/// instruction at query time (see [`xref_kind`]). It is a *cache of a
/// deterministic pass*, keyed on the actual bytes by the caller
/// (`n0xis-pipeline`), never a mutable source of truth (CONCEPT §3 rule 6).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct XrefIndex {
    /// Referenced address (raw VA) → the VAs of instructions that reference it.
    pub edges: BTreeMap<u64, Vec<u64>>,
    /// How many instructions were decoded to build this index (for `meta`).
    pub insns: usize,
}

impl XrefIndex {
    /// The addresses of every instruction that references `addr`.
    pub fn to(&self, addr: Va) -> Vec<Va> {
        self.edges.get(&addr.0).map(|v| v.iter().map(|&f| Va(f)).collect()).unwrap_or_default()
    }
}

/// The reference-kind string for a branch instruction, or `"branch"` for an
/// indirect/other control-flow instruction. Public so a caller re-deriving a hit
/// from the index (which stores no kind) classifies it exactly as the pass would.
pub fn xref_kind(kind: InsnKind) -> &'static str {
    branch_kind(kind).unwrap_or("branch")
}

/// Bytes decoded per chunk when building the index (8 MiB). A whole code section
/// can be 100 MB+; decoding it in one `decode_range` call materialized ~30M
/// `DecodedInsn`s at once (multi-GB — it swapped the box). Chunking caps the live
/// instruction buffer to one chunk while producing the **identical** edge set,
/// because each chunk resumes exactly at the previous chunk's last instruction
/// boundary (a real boundary from the same linear sweep), never mid-instruction.
const XREF_CHUNK: u64 = 8 * 1024 * 1024;
/// Overhang past a chunk so the boundary-spanning instruction is decoded whole
/// (x86 instructions are ≤15 bytes); the next chunk still resumes after it.
const XREF_OVERLAP: u64 = 16;

/// Build the reverse-xref index over `ranges` (`[(start, size)]`) — a linear
/// decode per range recording every `target` (branch/call) and `rip_target`
/// (data) edge, done once for the whole program so queries need no scan at all.
/// Streamed in [`XREF_CHUNK`]-sized windows so peak memory stays bounded on a
/// huge image (CLAUDE.md: a parser must be OOM-proof by design).
pub fn build_xref_index(ctx: &Ctx, ranges: &[(Va, u64)]) -> XrefIndex {
    let mut idx = XrefIndex::default();
    for &(start, size) in ranges {
        if size == 0 {
            continue;
        }
        let end = start.0.saturating_add(size);
        let mut pos = start.0;
        while pos < end {
            let keep_to = pos.saturating_add(XREF_CHUNK).min(end); // keep insns starting before here
            let read_len = (keep_to.saturating_add(XREF_OVERLAP).min(end) - pos) as usize;
            let Ok(bytes) = ctx.source.read(Va(pos), read_len) else {
                break;
            };
            let insns = ctx.arch.decode_range(&bytes, Va(pos), bytes.len());
            let mut advanced = pos;
            for ins in &insns {
                if ins.va.0 >= keep_to {
                    break; // belongs to the next chunk (decoded there, aligned)
                }
                idx.insns += 1;
                if let Some(t) = ins.target {
                    idx.edges.entry(t.0).or_default().push(ins.va.0);
                }
                if let Some(t) = ins.rip_target {
                    idx.edges.entry(t.0).or_default().push(ins.va.0);
                }
                advanced = ins.va.0.saturating_add(ins.len.max(1) as u64);
            }
            // Resume after the last kept instruction; guarantee forward progress
            // if a chunk decoded nothing (bad bytes) so the loop can't hang.
            pos = if advanced > pos { advanced } else { keep_to.max(pos + 1) };
        }
    }
    idx
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    #[test]
    fn finds_call_xref_to_target() {
        // 0x1000: e8 03 00 00 00  call 0x1008
        // 0x1005: 90 90 90        nops
        // 0x1008: c3              ret  (the target)
        let code = vec![
            0xE8, 0x03, 0x00, 0x00, 0x00, // call 0x1008
            0x90, 0x90, 0x90, // padding
            0xC3, // 0x1008 ret
        ];
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = XrefPass
            .run(
                &ctx,
                XrefInput {
                    scan_start: Va(0x1000),
                    size: 64,
                    addr: Va(0x1008),
                    dir: XrefDir::To,
                },
            )
            .unwrap();
        assert_eq!(art.count, 1);
        assert_eq!(art.refs[0].from, Va(0x1000));
        assert_eq!(art.refs[0].kind, "call");
    }

    #[test]
    fn reverse_index_matches_a_direct_to_scan() {
        // 0x1000: e8 03 00 00 00  call 0x1008
        // 0x1005: 90 90 90
        // 0x1008: c3              ret (the target)
        let code = vec![0xE8, 0x03, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0xC3];
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let idx = build_xref_index(&ctx, &[(Va(0x1000), 64)]);
        let hits = idx.to(Va(0x1008));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0], Va(0x1000));
        // an address nothing references yields nothing
        assert!(idx.to(Va(0x1005)).is_empty());
    }

    #[test]
    fn reverse_index_round_trips_through_json() {
        let code = vec![0xE8, 0x03, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0xC3];
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let idx = build_xref_index(&ctx, &[(Va(0x1000), 64)]);
        let json = serde_json::to_string(&idx).unwrap();
        let back: XrefIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(back.to(Va(0x1008)).len(), 1);
        assert_eq!(back.insns, idx.insns);
    }
}

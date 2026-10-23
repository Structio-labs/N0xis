// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`XrefPass`] — cross-references to or from an address.
//!
//! Decodes a code range and finds references via the arch-provided fields on
//! [`DecodedInsn`](n0xis_arch::DecodedInsn): `target` (direct branch/call) and
//! `rip_target` (RIP-relative data access, e.g. `lea`). Because both come from
//! the arch, this pass carries **no** ISA byte patterns — unlike v0, which
//! hand-scanned `48 8D … mod/rm` for `lea`. Works over any source.

use std::collections::BTreeMap;
use std::ops::ControlFlow;

use n0xis_arch::InsnKind;
use n0xis_contracts::Va;
use serde::{Deserialize, Serialize};

use crate::sweep::{SWEEP_CHUNK, sweep_code};
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
    /// The index of the function `from` is in, beside the position, on an
    /// image whose functions are identified by index (a WebAssembly module:
    /// docs/design/WASM.md §5 decision 1). Absent on a native image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_function: Option<u32>,
    /// What is referenced. Absent only for a reference to an imported
    /// WebAssembly function, which has an index (`to_function`) and no
    /// position: a `call 0` to an import is a call, and is listed as one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Va>,
    /// The index of the function referenced, on an image whose functions are
    /// identified by index; absent on a native image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_function: Option<u32>,
    /// `call` / `jmp` / `cond_jmp` / `data` (a `ref.func`, which takes a
    /// function as a value, is `data`, as taking an address is natively).
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

/// Enough bytes to hold any single instruction on the supported ISAs — x86-64
/// tops out at 15, AArch64 is a fixed 4. Used to bound the `From` read to the one
/// instruction that direction can ever report.
const MAX_INSN_BYTES: usize = 16;

/// Cross-reference pass.
#[derive(Clone, Copy, Debug, Default)]
pub struct XrefPass;

/// One reference, with what every reference states beside its positions: the
/// function indices where the image identifies functions by index, and the
/// referenced function's symbol name. The one constructor, so the pass and
/// the index lookup in the frontend cannot state an entry two ways.
///
/// `to` is `None` only with `to_function` naming an imported function.
pub fn xref_entry(ctx: &Ctx, from: Va, to: Option<Va>, to_function: Option<u32>, kind: &str, text: String) -> XrefEntry {
    let to_function = to_function.or_else(|| to.and_then(|t| ctx.arch.indexed_function(t)).filter(|f| Some(f.body) == to).map(|f| f.index));
    XrefEntry {
        from,
        from_function: ctx.arch.indexed_function(from).map(|f| f.index),
        to,
        to_function,
        kind: kind.to_string(),
        text,
        sym: to.and_then(|t| crate::ir::symbol_on_entry(ctx, t)).map(|sy| sy.name),
    }
}

/// Whether `ins` references the function `index` by index without a branch
/// target to it: a `ref.func`, or a call to an import (which has no body to
/// be a target).
fn names_function(ins: &n0xis_arch::DecodedInsn, index: Option<u32>) -> bool {
    index.is_some() && ins.target_function.map(|f| f.index) == index
}

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
        self.run_in(ctx, input, SWEEP_CHUNK)
    }
}

impl XrefPass {
    /// [`Pass::run`] with the sweep's window size given, so a test can show the
    /// answer does not depend on it.
    pub(crate) fn run_in(&self, ctx: &Ctx, input: XrefInput, chunk: u64) -> Result<XrefArtifact, CoreError> {
        let target = Some(input.addr);
        let mut refs = Vec::new();
        match input.dir {
            XrefDir::To => {
                // The function that starts at `addr`, where functions are
                // identified by index: a `ref.func` names it by that index alone.
                let addr_index = ctx.arch.indexed_function(input.addr).filter(|f| f.body == input.addr).map(|f| f.index);
                // Swept, not decoded whole: only the hits are kept, and their
                // text is the only text cloned (`crate::sweep`).
                sweep_code(ctx, input.scan_start, input.size as u64, chunk, |ins| {
                    let named = ins.target_function.map(|f| f.index);
                    if ins.target == target {
                        let kind = branch_kind(ins.kind).unwrap_or("branch");
                        refs.push(xref_entry(ctx, ins.va, target, named, kind, ins.text.clone()));
                    } else if ins.rip_target == target || names_function(ins, addr_index) {
                        refs.push(xref_entry(ctx, ins.va, target, named, "data", ins.text.clone()));
                    }
                    ControlFlow::Continue(())
                })?;
            }
            XrefDir::From => {
                // `From` reports ONLY the single instruction at `addr`. Decoding
                // the caller's whole window to then discard all of it is pure
                // waste, and for a whole-program query (the shape `xref from`
                // gets from the frontend, which has no reverse-index fast path
                // for this direction) that window is the entire `.text`:
                // measured at **16 s and +2.8 GB per call** on the Qt desktop
                // PE, for a 0.2 KB answer. Reading one instruction's worth
                // instead is identical by construction — `XrefArtifact` exposes
                // no scan range, so the narrowing is invisible. Bounded, so not
                // a sweep.
                //
                // The window bound is still honoured: a caller that sweeps
                // several code ranges must not get the same refs back once per
                // range.
                let end = input.scan_start.get().saturating_add(input.size as u64);
                if input.addr.get() < input.scan_start.get() || input.addr.get() >= end {
                    return Ok(XrefArtifact { addr: input.addr, dir: input.dir, count: 0, refs: Vec::new() });
                }
                let bytes = ctx.source.read(input.addr, MAX_INSN_BYTES)?;
                for ins in ctx.arch.decode_range(&bytes, input.addr, bytes.len()) {
                    if ins.va != input.addr {
                        continue;
                    }
                    let named = ins.target_function.map(|f| f.index);
                    match (ins.target, ins.target_function) {
                        (Some(t), _) => {
                            let kind = branch_kind(ins.kind).unwrap_or("branch");
                            refs.push(xref_entry(ctx, input.addr, Some(t), named, kind, ins.text.clone()));
                        }
                        // Named by index with no branch target: a call to an
                        // import, which has no position, or a `ref.func`.
                        (None, Some(f)) => {
                            let kind = branch_kind(ins.kind).unwrap_or("data");
                            refs.push(xref_entry(ctx, input.addr, f.body, Some(f.index), kind, ins.text.clone()));
                        }
                        (None, None) => {}
                    }
                    if let Some(t) = ins.rip_target {
                        refs.push(xref_entry(ctx, input.addr, Some(t), None, "data", ins.text.clone()));
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
/// ONE sweep ([`crate::sweep`]) over all code ranges. Turns `xref to` from a full
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

/// Build the reverse-xref index over `ranges` (`[(start, size)]`) — a linear
/// decode per range recording every `target` (branch/call) and `rip_target`
/// (data) edge, done once for the whole program so queries need no scan at all.
/// Swept ([`crate::sweep`]), so peak memory is one window of instructions
/// whatever the image's size (CLAUDE.md: a parser must be OOM-proof by design).
///
/// It was the first chunked sweep, in 8 MiB windows that cost 650-750 MB each
/// on a real library, resuming *after* the last kept instruction, which is not
/// where the whole-range decode resumes when an undecodable byte follows it
/// (`crate::sweep` says why).
pub fn build_xref_index(ctx: &Ctx, ranges: &[(Va, u64)]) -> XrefIndex {
    build_xref_index_in(ctx, ranges, SWEEP_CHUNK)
}

/// [`build_xref_index`] with the sweep's window size given.
pub(crate) fn build_xref_index_in(ctx: &Ctx, ranges: &[(Va, u64)], chunk: u64) -> XrefIndex {
    let mut idx = XrefIndex::default();
    for &(start, size) in ranges {
        if size == 0 {
            continue;
        }
        // A range whose start cannot be read adds nothing, as it did when the
        // index broke out of its chunk loop on a failed read.
        let _ = sweep_code(ctx, start, size, chunk, |ins| {
            idx.insns += 1;
            if let Some(t) = ins.target {
                idx.edges.entry(t.0).or_default().push(ins.va.0);
            }
            if let Some(t) = ins.rip_target {
                idx.edges.entry(t.0).or_default().push(ins.va.0);
            }
            // A function named by index with no branch to it (`ref.func`)
            // references its body all the same.
            if ins.target.is_none()
                && let Some(body) = ins.target_function.and_then(|f| f.body)
            {
                idx.edges.entry(body.0).or_default().push(ins.va.0);
            }
            ControlFlow::Continue(())
        });
    }
    idx
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    #[test]
    fn from_is_window_bounded_and_window_size_independent() {
        // `From` reports only the instruction AT `addr`, so its result must not
        // depend on how large a window the caller sweeps — the frontend passes the
        // WHOLE program for this direction, which used to decode all of `.text`
        // (16 s, +2.8 GB on a real target) to keep one instruction.
        let code = vec![
            0xE8, 0x03, 0x00, 0x00, 0x00, // 0x1000: call 0x1008
            0x90, 0x90, 0x90, // padding
            0xC3, // 0x1008: ret
        ];
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let run = |scan_start, size| {
            XrefPass.run(&ctx, XrefInput { scan_start, size, addr: Va(0x1000), dir: XrefDir::From }).unwrap()
        };
        let tight = run(Va(0x1000), 16);
        let wide = run(Va(0x1000), 4096);
        assert_eq!(tight.count, 1, "the call at 0x1000 references 0x1008");
        assert_eq!(tight.refs[0].to, Some(Va(0x1008)));
        // Same answer no matter how much the caller asked us to sweep.
        assert_eq!(format!("{:?}", tight.refs), format!("{:?}", wide.refs));

        // Still window-bounded: a caller sweeping several ranges must not get the
        // same refs back once per range.
        let outside = XrefPass
            .run(&ctx, XrefInput { scan_start: Va(0x1008), size: 8, addr: Va(0x1000), dir: XrefDir::From })
            .unwrap();
        assert_eq!(outside.count, 0, "addr outside the window yields nothing");
    }

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

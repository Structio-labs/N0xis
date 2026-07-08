//! [`XrefPass`] — cross-references to or from an address.
//!
//! Decodes a code range and finds references via the arch-provided fields on
//! [`DecodedInsn`](n0xis_arch::DecodedInsn): `target` (direct branch/call) and
//! `rip_target` (RIP-relative data access, e.g. `lea`). Because both come from
//! the arch, this pass carries **no** ISA byte patterns — unlike v0, which
//! hand-scanned `48 8D … mod/rm` for `lea`. Works over any source.

use n0xis_arch::InsnKind;
use n0xis_contracts::Va;
use serde::Serialize;

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
            .decode_stream(&bytes, input.scan_start, bytes.len());
        let mut refs = Vec::new();

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
                        });
                    } else if ins.rip_target == Some(input.addr) {
                        refs.push(XrefEntry {
                            from: ins.va,
                            to: input.addr,
                            kind: "data".to_string(),
                            text: ins.text.clone(),
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
                        });
                    }
                    if let Some(t) = ins.rip_target {
                        refs.push(XrefEntry {
                            from: input.addr,
                            to: t,
                            kind: "data".to_string(),
                            text: ins.text.clone(),
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
}

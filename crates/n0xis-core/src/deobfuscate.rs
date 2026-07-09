//! [`DeobfuscatePass`] — pattern-based deobfuscation (ROADMAP Phase 7:
//! "Deobfuscation passes, pattern-based, as optional pipeline stages").
//!
//! Two independent, narrow, high-confidence techniques — deliberately not an
//! attempt at general deobfuscation (control-flow flattening, VM-based
//! protectors, and the like are a different, much larger problem this pass
//! does not attempt; the same "documented, not silently claimed" scope limit
//! `Arch::detect_switch` already sets for exotic idioms):
//!
//! - **Junk instructions**: structural, no-dataflow-needed identities a
//!   packer/obfuscator inserts as filler — `mov reg, reg`, `xchg reg, reg`,
//!   `push reg` immediately undone by `pop reg`, and `add/sub/or reg, 0`.
//!   Each is a semantic no-op regardless of any other context, so these are
//!   flagged with full confidence.
//! - **Opaque predicates**: a conditional branch whose condition
//!   [`ValueSetPass`] can *prove* constant (both sides of the comparison
//!   resolve to known values) is dead code disguised as a branch — one
//!   successor edge can never execute. Reported, not silently rewritten:
//!   CONCEPT §3 rule 6 says never drop information the caller didn't ask to
//!   drop, so removing the dead block is left to the caller/a follow-on
//!   pass, not done here.

use n0xis_contracts::Va;
use serde::Serialize;

use crate::ir::CfgArtifact;
use crate::ssa::SsaPass;
use crate::valueset::{eval, ValueSet, ValueSetPass};
use crate::{CoreError, Ctx, Pass};

#[derive(Clone, Debug, Serialize)]
pub struct JunkInsn {
    pub va: Va,
    pub len: u8,
    /// Human-readable reason, e.g. `"self-move (mov eax, eax)"`.
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct OpaqueBranch {
    /// Address of the conditional branch instruction.
    pub at: Va,
    /// `true` when the branch is provably always taken, `false` when
    /// provably never taken.
    pub always_taken: bool,
    /// The successor address that can never actually execute.
    pub dead_target: Va,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeobfuscateArtifact {
    pub start: Va,
    pub end: Va,
    pub junk: Vec<JunkInsn>,
    pub opaque_branches: Vec<OpaqueBranch>,
    /// Total bytes covered by `junk` — a quick "how much filler" metric.
    pub junk_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DeobfuscatePass;

/// The two operands of a formatted instruction text (`"mov eax, eax"` ->
/// `("eax", "eax")`), or `None` if it isn't exactly a mnemonic + two
/// comma-separated operands.
fn two_operands(text: &str) -> Option<(&str, &str)> {
    let rest = text.split_once(char::is_whitespace)?.1.trim();
    let (a, b) = rest.split_once(',')?;
    Some((a.trim(), b.trim()))
}

fn one_operand(text: &str) -> Option<&str> {
    let rest = text.split_once(char::is_whitespace)?.1.trim();
    if rest.contains(',') { None } else { Some(rest) }
}

fn is_zero_literal(s: &str) -> bool {
    matches!(s, "0" | "0x0")
}

impl Pass for DeobfuscatePass {
    type In = CfgArtifact;
    type Out = DeobfuscateArtifact;

    fn name(&self) -> &'static str {
        "deobfuscate"
    }

    fn run(&self, ctx: &Ctx, cfg: Self::In) -> Result<Self::Out, CoreError> {
        let start = cfg.start;
        let end = cfg.end;

        let mut junk = Vec::new();
        for block in &cfg.blocks {
            let insns = &block.insns;
            for (i, insn) in insns.iter().enumerate() {
                match insn.mnemonic.as_str() {
                    "mov" | "xchg" => {
                        if let Some((a, b)) = two_operands(&insn.text) {
                            if a == b {
                                junk.push(JunkInsn {
                                    va: insn.va,
                                    len: insn.len,
                                    reason: format!("self-{} ({})", insn.mnemonic, insn.text),
                                });
                                continue;
                            }
                        }
                    }
                    "add" | "sub" | "or" => {
                        if let Some((_, b)) = two_operands(&insn.text) {
                            if is_zero_literal(b) {
                                junk.push(JunkInsn {
                                    va: insn.va,
                                    len: insn.len,
                                    reason: format!("identity arithmetic ({})", insn.text),
                                });
                                continue;
                            }
                        }
                    }
                    "push" => {
                        if let (Some(reg), Some(next)) = (one_operand(&insn.text), insns.get(i + 1)) {
                            if next.mnemonic == "pop" {
                                if let Some(popped) = one_operand(&next.text) {
                                    if popped == reg {
                                        junk.push(JunkInsn {
                                            va: insn.va,
                                            len: insn.len,
                                            reason: format!("push/pop pair cancels out ({} / {})", insn.text, next.text),
                                        });
                                        junk.push(JunkInsn {
                                            va: next.va,
                                            len: next.len,
                                            reason: format!("push/pop pair cancels out ({} / {})", insn.text, next.text),
                                        });
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        let junk_bytes = junk.iter().map(|j| j.len as usize).sum();

        // Opaque predicates: needs SSA + value-set analysis of the same CFG.
        let ssa = SsaPass.run(ctx, cfg.clone())?;
        let values = ValueSetPass.run(ctx, ssa.clone())?;
        let mut opaque_branches = Vec::new();
        for (idx, block) in ssa.blocks.iter().enumerate() {
            let Some(condition) = &block.condition else { continue };
            let Some(taken) = as_known_bool(&eval(condition, &values.sets)) else { continue };
            // A `cjmp` block always has exactly two successors: the taken
            // edge (kind `"cjmp-true"`) and the fall-through (`"cjmp-false"`
            // or `"fall"`) — find whichever one this constant result kills.
            let dead = block.successors.iter().find(|s| (s.kind == "cjmp-true") != taken);
            if let Some(dead) = dead {
                // `ssa.blocks` and `cfg.blocks` share the same order/ids —
                // recover the branch instruction's real address from the CFG
                // side, since an `SsaBlock`'s statements don't necessarily
                // include one entry per decoded instruction.
                let at = cfg.blocks.get(idx).and_then(|b| b.insns.last()).map(|i| i.va).unwrap_or(block.start);
                opaque_branches.push(OpaqueBranch {
                    at,
                    always_taken: taken,
                    dead_target: dead.to,
                    reason: format!("condition {condition:?} resolves to the constant {taken}"),
                });
            }
        }

        Ok(DeobfuscateArtifact { start, end, junk, opaque_branches, junk_bytes })
    }
}

/// Interpret a fully-resolved boolean value set (`{0}` or `{1}`) as a known
/// `bool`; anything else (unresolved, or a value set that isn't exactly one
/// of the two boolean encodings) is genuinely unknown.
fn as_known_bool(v: &ValueSet) -> Option<bool> {
    match v.as_single() {
        Some(0) => Some(false),
        Some(1) => Some(true),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;
    use crate::ir::CfgPass;
    use crate::CfgInput;

    fn deobfuscate(code: Vec<u8>) -> DeobfuscateArtifact {
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let cfg = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), 64)).unwrap();
        DeobfuscatePass.run(&ctx, cfg).unwrap()
    }

    #[test]
    fn flags_a_self_move_as_junk() {
        // mov eax, eax ; ret
        let art = deobfuscate(vec![0x89, 0xc0, 0xc3]);
        assert_eq!(art.junk.len(), 1);
        assert!(art.junk[0].reason.contains("self-mov"));
    }

    #[test]
    fn flags_identity_add_as_junk() {
        // add eax, 0 ; ret
        let art = deobfuscate(vec![0x83, 0xc0, 0x00, 0xc3]);
        assert_eq!(art.junk.len(), 1);
        assert!(art.junk[0].reason.contains("identity arithmetic"));
    }

    #[test]
    fn flags_a_push_pop_pair_as_junk() {
        // push rax ; pop rax ; ret
        let art = deobfuscate(vec![0x50, 0x58, 0xc3]);
        assert_eq!(art.junk.len(), 2, "both the push and the pop are flagged");
    }

    #[test]
    fn a_real_move_is_never_flagged() {
        // mov eax, ecx ; ret — a real move, must not be flagged.
        let art = deobfuscate(vec![0x89, 0xc8, 0xc3]);
        assert!(art.junk.is_empty(), "a genuine cross-register move must never be reported as junk: {:#?}", art.junk);
    }

    #[test]
    fn a_real_add_by_a_nonzero_constant_is_never_flagged() {
        // add eax, 5 ; ret
        let art = deobfuscate(vec![0x83, 0xc0, 0x05, 0xc3]);
        assert!(art.junk.is_empty());
    }

    #[test]
    fn detects_an_always_true_opaque_predicate() {
        // mov eax, 5 ; cmp eax, 5 ; je +N ; <dead path> ; ret
        // Both cmp operands resolve to the constant 5, so the branch is
        // provably always taken — the fall-through path is dead.
        let code = vec![
            0xb8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5
            0x83, 0xf8, 0x05, // cmp eax, 5
            0x74, 0x02, // je +2 (skip the next 2-byte insn)
            0xeb, 0xfe, // jmp $ (dead: never reached — 2 bytes so the je target lands past it)
            0xc3, // ret
        ];
        let art = deobfuscate(code);
        assert_eq!(art.opaque_branches.len(), 1, "expected exactly one opaque branch: {:#?}", art.opaque_branches);
        assert!(art.opaque_branches[0].always_taken);
    }

    #[test]
    fn a_real_conditional_branch_on_unknown_input_is_never_flagged() {
        // cmp eax, 5 ; je +2 ; jmp $ ; ret — eax is an unmodeled input
        // (never assigned in this function), so the branch outcome is
        // genuinely unknown and must not be reported as opaque.
        let code = vec![
            0x83, 0xf8, 0x05, // cmp eax, 5
            0x74, 0x02, // je +2
            0xeb, 0xfe, // jmp $ (only reached if eax != 5)
            0xc3, // ret
        ];
        let art = deobfuscate(code);
        assert!(art.opaque_branches.is_empty(), "an unknown input's branch must never be called opaque: {:#?}", art.opaque_branches);
    }
}

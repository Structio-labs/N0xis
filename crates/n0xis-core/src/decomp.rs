//! [`DecompPass`] — the top of the pipeline: wires lift → SSA → (optimize) →
//! (structure) → render into the three `decomp pseudo` styles
//! (`docs/CLI_COMMANDS_v0.md`): `goto` (flat, labeled), `structured`
//! (`if`/`while`/…, unoptimized), `ssa` (structured *and* optimized — the
//! ROADMAP Phase 3 target style). All three already get **exact** branch
//! conditions from [`crate::SsaPass`] — that correctness fix isn't gated
//! behind `--style ssa`, only the expression-collapsing prettification is.
//!
//! Reuses the v0 wire schema (`n0x.decomp.pseudo.v1`, `docs/CLI_COMMANDS_v0.md`)
//! rather than minting a new one: `--style ssa` is documented as an additive
//! style on the *same* command, not a new capability.

use n0xis_contracts::Va;
use serde::Serialize;

use crate::ir::CfgArtifact;
use crate::optimize::{OptDeltaEntry, OptimizePass};
use crate::render::{c_type, render_condition, render_stmt, RenderNames};
use crate::ssa::{SsaBlock, SsaPass};
use crate::structure::structure;
use crate::typeinfer::{RecoveredSignature, TypeInferInput, TypeInferPass};
use crate::{Ctx, CoreError, Pass};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecompStyle {
    /// Flat, labeled blocks + `goto` — no control-flow reconstruction.
    Goto,
    /// `if`/`else`/`while`/… reconstruction over un-optimized SSA.
    Structured,
    /// Structured **and** optimized (copy/const/expr-prop + DCE) — the
    /// default style.
    Ssa,
}

impl DecompStyle {
    fn as_str(self) -> &'static str {
        match self {
            DecompStyle::Goto => "goto",
            DecompStyle::Structured => "structured",
            DecompStyle::Ssa => "ssa",
        }
    }
}

pub struct DecompInput {
    pub cfg: CfgArtifact,
    pub style: DecompStyle,
}

#[derive(Clone, Debug, Serialize)]
pub struct PseudoFunction {
    pub address: Va,
    pub end_address: Va,
    pub signature: String,
    pub style: &'static str,
    pub pseudo: Vec<String>,
    /// Fraction of the original instructions this pipeline understood well
    /// enough to lift (not left as a verbatim `// asm:` line).
    pub quality: f32,
    pub flags: Vec<&'static str>,
    pub instruction_count: usize,
    /// What each optimization round changed — only populated for
    /// `--style ssa` (`n0xis.opt.delta.v1`'s content, inlined here for
    /// convenience; also independently requestable via `ir ssa`/`opt`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub delta: Vec<OptDeltaEntry>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DecompPass;

impl Pass for DecompPass {
    type In = DecompInput;
    type Out = PseudoFunction;

    fn name(&self) -> &'static str {
        "decomp.pseudo"
    }

    fn run(&self, ctx: &Ctx, input: DecompInput) -> Result<PseudoFunction, CoreError> {
        let cfg = input.cfg;

        let ssa = SsaPass.run(ctx, cfg.clone())?;
        let unlifted = count_unlifted(&ssa.blocks);
        // Recovered locals/struct-fields/signature (ROADMAP Phase 4) are
        // always computed from the *optimized* form for analysis quality —
        // propagation/DCE resolve pointer origins that raw SSA leaves as
        // opaque — then applied to whichever style's own IR is rendered.
        let opt = OptimizePass.run(ctx, ssa.clone())?;
        let types = TypeInferPass.run(ctx, TypeInferInput { cfg: cfg.clone(), blocks: opt.blocks.clone() })?;
        let names = RenderNames::new(&cfg.callsites).with_types(&types);
        let signature = format_signature(cfg.start, &types.signature);

        let (pseudo, has_loop, fallback_count, delta) = match input.style {
            DecompStyle::Goto => (render_goto(&cfg, &ssa.blocks, &names), false, 0, Vec::new()),
            DecompStyle::Structured => {
                let out = structure(&cfg, &ssa.blocks, &names);
                (out.lines, out.has_loop, out.fallback_count, Vec::new())
            }
            DecompStyle::Ssa => {
                let out = structure(&cfg, &opt.blocks, &names);
                (out.lines, out.has_loop, out.fallback_count, opt.delta)
            }
        };

        let quality = if cfg.insn_count == 0 { 0.0 } else { 1.0 - (unlifted as f32 / cfg.insn_count as f32) };
        let mut flags: Vec<&'static str> = vec![input.style.as_str()];
        if !cfg.switches.is_empty() {
            flags.push("has-switch");
        }
        if cfg.stats.indirect_branches > 0 {
            flags.push("has-indirect");
        }
        if cfg.stats.tail_calls > 0 {
            flags.push("has-tail");
        }
        if has_loop {
            flags.push("has-loop");
        }
        if fallback_count > 0 {
            flags.push("structured-partial");
        }
        if quality < 0.8 {
            flags.push("low-coverage");
        }

        let body_lines: Vec<String> = std::iter::once(format!("{signature} {{"))
            .chain(pseudo)
            .chain(std::iter::once("}".to_string()))
            .collect();

        Ok(PseudoFunction {
            address: cfg.start,
            end_address: cfg.end,
            signature,
            style: input.style.as_str(),
            pseudo: body_lines,
            quality,
            flags,
            instruction_count: cfg.insn_count,
            delta,
        })
    }
}

/// The real (recovered) signature line, replacing the old fixed
/// `void sub_X(uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9)`
/// placeholder — real arity (only the register args actually read) and a
/// real return type (`void` unless something other than the untouched entry
/// `rax` gets returned).
fn format_signature(va: Va, sig: &RecoveredSignature) -> String {
    let ret = match &sig.ret {
        Some(ty) => ty.name.clone().unwrap_or_else(|| c_type(ty.bits, ty.signed).to_string()),
        None => "void".to_string(),
    };
    let params = if sig.params.is_empty() {
        "void".to_string()
    } else {
        sig.params.iter().map(|p| format!("uint64_t {}", p.name)).collect::<Vec<_>>().join(", ")
    };
    format!("{ret} sub_{:x}({params})", va.get())
}

fn count_unlifted(blocks: &[SsaBlock]) -> usize {
    blocks
        .iter()
        .flat_map(|b| &b.stmts)
        .filter(|s| matches!(s.stmt, n0xis_arch::MicroStmt::Unlifted { .. }))
        .count()
}

fn addr_to_id(cfg: &CfgArtifact, addr: Va) -> Option<usize> {
    cfg.blocks.iter().find(|b| b.start == addr).map(|b| b.id)
}

/// Flat, labeled rendering — no dominators, no loop/if reconstruction, just
/// blocks and `goto`s. Still uses the exact SSA condition for `cjmp` (that
/// correctness gain isn't specific to structuring).
fn render_goto(cfg: &CfgArtifact, blocks: &[SsaBlock], names: &RenderNames) -> Vec<String> {
    let mut lines = Vec::new();
    for (i, b) in blocks.iter().enumerate() {
        if i > 0 {
            lines.push(String::new());
        }
        lines.push(format!("block_{}:    // {}", b.id, b.start));
        for s in &b.stmts {
            if let Some(text) = render_stmt(&s.stmt, names) {
                lines.push(format!("    {text}"));
            }
        }
        match b.terminator.as_str() {
            "ret" | "tail-call" | "int" => {}
            "ijmp" => {
                if b.successors.iter().any(|s| s.kind == "switch-case") {
                    lines.push("    // switch dispatch:".to_string());
                    for s in &b.successors {
                        if let Some(j) = addr_to_id(cfg, s.to) {
                            lines.push(format!("    //   case -> goto block_{j};"));
                        }
                    }
                } else {
                    lines.push("    // indirect jump (unrecovered)".to_string());
                }
            }
            "jmp" | "fall" => {
                if let Some(j) = b.successors.first().and_then(|s| addr_to_id(cfg, s.to)) {
                    lines.push(format!("    goto block_{j};"));
                }
            }
            "cjmp" => {
                let cond = b.condition.as_ref().map(|e| render_condition(e, names)).unwrap_or_else(|| "/*?*/".to_string());
                let t = b.successors.iter().find(|s| s.kind == "cjmp-true").and_then(|s| addr_to_id(cfg, s.to));
                let f = b.successors.iter().find(|s| s.kind == "cjmp-false").and_then(|s| addr_to_id(cfg, s.to));
                if let Some(t) = t {
                    lines.push(format!("    if ({cond}) goto block_{t};"));
                }
                if let Some(f) = f {
                    lines.push(format!("    goto block_{f};"));
                }
            }
            _ => {}
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CfgInput, CfgPass};
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    fn decomp(code: Vec<u8>, style: DecompStyle) -> PseudoFunction {
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let cfg = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), 128)).unwrap();
        DecompPass.run(&ctx, DecompInput { cfg, style }).unwrap()
    }

    /// The Phase 3 exit-test property (ROADMAP Phase 3 / CONCEPT §6.3):
    /// `rax = f(); count = *(rax+0x68);` must read like C — the pointer
    /// value's origin inlined, no bare register names in the common path.
    #[test]
    fn ssa_style_has_no_bare_registers_and_resolves_the_field_load() {
        let code = vec![
            0xE8, 0x00, 0x00, 0x00, 0x00, // call +0            -> rax = f()
            0x48, 0x8B, 0x50, 0x68, // mov rdx, [rax+0x68]      -> rdx = *(rax+0x68)
            0x48, 0x89, 0xD0, // mov rax, rdx                   -> rax = rdx
            0xC3, // ret
        ];
        let out = decomp(code, DecompStyle::Ssa);
        // Skip the signature line (still a fixed Win64-ABI placeholder —
        // real arity/type recovery is Phase 4) and the closing brace; check
        // only the reconstructed body.
        let body = out.pseudo[1..out.pseudo.len() - 1].join("\n");
        assert!(body.contains("0x68"), "{body}");
        // `rdx.0`/`rcx.0` (the fixed Win64 call-arg forwarding, `.0` meaning
        // "the incoming parameter") are expected and fine; what must *not*
        // survive is a bare, un-collapsed intermediate — the call's own
        // result register (`rax`) or a loaded-then-reused `rdx.1`.
        assert!(!body.contains("rax"), "the call result should have collapsed into its use: {body}");
        assert!(!body.contains("rdx.1"), "the loaded value should have collapsed into the return: {body}");
        assert!(body.contains("sub_1005("), "expected the call inlined as an expression: {body}");
    }

    #[test]
    fn goto_and_structured_styles_still_produce_sound_output() {
        let code = vec![0x48, 0x89, 0xC8, 0xC3]; // mov rax, rcx ; ret
        for style in [DecompStyle::Goto, DecompStyle::Structured] {
            let out = decomp(code.clone(), style);
            assert!(!out.pseudo.is_empty());
            assert!(out.pseudo.iter().any(|l| l.contains("return")), "{:?}: {:#?}", style, out.pseudo);
        }
    }
}

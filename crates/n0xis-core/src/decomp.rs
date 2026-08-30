//! [`DecompPass`] — the top of the pipeline: wires lift → SSA → (optimize) →
//! (structure) → render into the three `decomp pseudo` styles
//! (`docs/CLI_COMMANDS.md`): `goto` (flat, labeled), `structured`
//! (`if`/`while`/…, unoptimized), `ssa` (structured *and* optimized — the
//! ROADMAP Phase 3 target style). All three already get **exact** branch
//! conditions from [`crate::SsaPass`] — that correctness fix isn't gated
//! behind `--style ssa`, only the expression-collapsing prettification is.
//!
//! Reuses the v0 wire schema (`n0x.decomp.pseudo.v1`, `docs/CLI_COMMANDS.md`)
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
    /// Carry the per-round optimization delta in the result
    /// ([`PseudoFunction::delta`]).
    ///
    /// Off by default because it is **larger than the pseudocode it explains**
    /// — measured on a real function: 59 518 bytes of delta against 42 306
    /// bytes of pseudo-C, 59% of the whole payload. A caller asking "what does
    /// this function do" should not pay for the answer to "why did the
    /// optimizer render it that way"; that question has its own command
    /// (`ir explain`).
    pub explain: bool,
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
    /// What each optimization round changed (`n0xis.opt.delta.v1`'s content).
    /// Populated only for `--style ssa` **and** only when the caller asked via
    /// [`DecompInput::explain`] — see that field for why it is not free.
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
        // The function's own name, when a symbol source has one. **Only an
        // exact hit counts**: a provider that attributes a whole function span
        // answers for any address inside it, so accepting a near miss would
        // name this function after whichever one precedes it — the same
        // sound-over-complete rule the callee naming already follows.
        let own_name = ctx
            .symbols
            .and_then(|s| s.symbol_at(cfg.start))
            .filter(|sym| sym.va == cfg.start)
            .map(|sym| crate::render::render_callee_name(&sym.name));
        let signature = format_signature(cfg.start, &types.signature, own_name.as_deref());

        let (pseudo, has_loop, fallback_count, delta) = match input.style {
            DecompStyle::Goto => (render_goto(&cfg, &ssa.blocks, &names), false, 0, Vec::new()),
            DecompStyle::Structured => {
                let out = structure(&cfg, &ssa.blocks, &names);
                (out.lines, out.has_loop, out.fallback_count, Vec::new())
            }
            DecompStyle::Ssa => {
                let out = structure(&cfg, &opt.blocks, &names);
                let delta = if input.explain { opt.delta } else { Vec::new() };
                (out.lines, out.has_loop, out.fallback_count, delta)
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
/// `name` is the function's own recovered name when a symbol source knows it —
/// an export table, or an imported IL2CPP index (Phase 12). Absent, the address
/// stands in as it always did, so a target with no symbols renders unchanged.
fn format_signature(va: Va, sig: &RecoveredSignature, name: Option<&str>) -> String {
    // A *demangled* name is already a complete C++ prototype — return type,
    // qualified name, and its own (real, source-level) parameter list, e.g.
    // `unsigned short __cdecl CompressToolsLib::ReadHeightValue(struct … *,
    // unsigned int, unsigned int)`. It is authoritative: prepending our
    // recovered `ret` and appending our register-name `(params)` produced the
    // garbled `uint32_t <full-prototype>(uint64_t rcx, …)` seen on real MSVC
    // exports. When the name carries its own arg list, use it verbatim.
    if let Some(n) = name
        && n.contains('(')
    {
        return n.to_string();
    }
    let ret = match &sig.ret {
        Some(ty) => ty.name.clone().unwrap_or_else(|| c_type(ty.bits, ty.signed).to_string()),
        None => "void".to_string(),
    };
    let params = if sig.params.is_empty() {
        "void".to_string()
    } else {
        sig.params
            .iter()
            .map(|p| {
                let tyname = p.ty.name.clone().unwrap_or_else(|| c_type(p.ty.bits, p.ty.signed).to_string());
                // `void *rcx`, not `void * rcx` — a pointer type already ends
                // with `*`, so it butts against the name the way C is written.
                let sep = if tyname.ends_with('*') { "" } else { " " };
                format!("{tyname}{sep}{}", p.name)
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    match name {
        Some(n) => format!("{ret} {n}({params})"),
        None => format!("{ret} sub_{:x}({params})", va.get()),
    }
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
            "ret" | "tail-call" | "int" | "call-noreturn" => {}
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
        DecompPass.run(&ctx, DecompInput { cfg, style, explain: true }).unwrap()
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

    /// ROADMAP Phase 10, priority 0 — tail-call promotion. `jmp func` at the
    /// end of a function is `return func(...)`, not a dangling branch: before
    /// promotion this block rendered no terminator statement at all (the `jmp`
    /// lifts to nothing and the CFG edge left the function), silently dropping
    /// both the call and the returned value.
    #[test]
    fn a_tail_jmp_renders_as_a_returned_call_in_every_style() {
        // 0x1000 mov rcx, rdx   48 89 D1
        // 0x1003 jmp 0x1500     E9 F8 04 00 00   (outside the function)
        let code = vec![0x48, 0x89, 0xD1, 0xE9, 0xF8, 0x04, 0x00, 0x00];
        for style in [DecompStyle::Goto, DecompStyle::Structured, DecompStyle::Ssa] {
            let out = decomp(code.clone(), style);
            let body = out.pseudo.join("\n");
            assert!(
                body.contains("sub_1500(") && body.contains("return"),
                "{style:?} should render the tail call as a call whose value is returned: {body}"
            );
        }
        // The optimizing styles additionally collapse the two into one
        // expression — the shape a human would write.
        let body = decomp(code, DecompStyle::Ssa).pseudo.join("\n");
        assert!(body.contains("return sub_1500("), "{body}");
    }

    #[test]
    fn a_demangled_prototype_name_is_used_verbatim_not_wrapped() {
        // A demangled C++ name already carries return type + real parameters;
        // wrapping it produced the garbled
        // `uint32_t <full-prototype>(uint64_t rcx, …)` seen on MSVC exports.
        let sig = RecoveredSignature { params: vec![], ret: None };
        let name = "unsigned short __cdecl CompressToolsLib::ReadHeightValue(struct CompressToolsLib::CompressedImageFile *, unsigned int, unsigned int)";
        assert_eq!(format_signature(Va(0x1940), &sig, Some(name)), name);
    }

    #[test]
    fn a_plain_symbol_name_without_args_still_gets_the_recovered_signature() {
        // A plain C export (no parenthesized arg list) keeps the recovered
        // `ret name(params)` rendering — only a full prototype is verbatim.
        let sig = RecoveredSignature { params: vec![], ret: None };
        assert_eq!(format_signature(Va(0x1000), &sig, Some("Compress")), "void Compress(void)");
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

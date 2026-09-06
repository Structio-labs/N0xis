// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`DecompPass`] — the top of the pipeline: wires lift → SSA → (optimize) →
//! (structure) → render into the three `decomp pseudo` styles
//! (`docs/CLI_COMMANDS.md`): `goto` (flat, labeled), `structured`
//! (`if`/`while`/…, unoptimized), `ssa` (structured *and* optimized — the
//! ROADMAP Phase 3's target style). All three already get **exact** branch
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

/// Process memo for "which class names did RTTI recover a vtable for" — the set
/// consulted to synthesize a `vftable` field at offset 0.
///
/// Building it per decompile hashed **every** class name (57k on a Qt/MSVC
/// target) to answer the 0–2 membership questions one function actually asks.
/// Keyed by the source label plus the symbol fingerprint, so a re-`analyze` that
/// changes the recovered classes invalidates it — the same discipline as the
/// vtable map and callee-type memos.
type VtableClassMemo = Option<(String, std::sync::Arc<std::collections::HashSet<String>>)>;
static VTABLE_CLASSES: std::sync::Mutex<VtableClassMemo> = std::sync::Mutex::new(None);

fn vtable_class_set(ctx: &Ctx) -> std::sync::Arc<std::collections::HashSet<String>> {
    let id = format!(
        "{}|{}|{}",
        ctx.source.label(),
        ctx.symbols.map(|s| s.symbol_fingerprint()).unwrap_or_default(),
        ctx.vtables.map_or(0, |v| v.len()),
    );
    if let Ok(memo) = VTABLE_CLASSES.lock()
        && let Some((cached, set)) = memo.as_ref()
        && *cached == id
    {
        return std::sync::Arc::clone(set);
    }
    let set: std::collections::HashSet<String> = ctx.vtables.map(|m| m.values().cloned().collect()).unwrap_or_default();
    let arc = std::sync::Arc::new(set);
    if let Ok(mut memo) = VTABLE_CLASSES.lock() {
        *memo = Some((id, std::sync::Arc::clone(&arc)));
    }
    arc
}
use crate::ssa::{SsaBlock, SsaPass};
use crate::structure::structure;
use crate::typeinfer::{RecoveredSignature, TypeArtifact, TypeInferInput, TypeInferPass};
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
    /// Drop the `// block_N: <addr>` anchor comment from every block that no
    /// `goto` targets — a label is only meaningful at a jump target, and these
    /// anchors are otherwise ~a third of the lines and pure noise to a reader (or
    /// an LLM). Left **off** for a consumer that needs the anchor to map a line
    /// back to an address — [`crate::ProvenancePass`] extracts a block's pseudo-C
    /// by that very comment — and **on** for display / agent-facing output.
    pub strip_block_labels: bool,
    /// User renames of this function's variables, keyed by the variable's current
    /// **displayed** name (`local_78`, `rcx`, `v3`) → the chosen name. Empty for
    /// every internal caller; the frontend fills it from `.n0x/annotations.json`
    /// so a rename reaches the signature, the local declarations, and the body
    /// alike. Pure-core stays pure: the map is passed in, never read from disk here.
    pub var_names: std::collections::HashMap<String, String>,
    /// User C-type overrides for this function, keyed by the variable's
    /// **synthesized** name (`local_78`, `rcx`, `v3`) → a C-type string, plus the
    /// reserved key `"@return"` for the return type (`"void"`/empty → `void`).
    /// Applied before the rename pass and rendered verbatim in the signature and
    /// the local declarations. Same pure-core discipline as `var_names`.
    pub var_types: std::collections::HashMap<String, String>,
    /// The project's struct catalog: `struct name → (field offset → field name)`.
    /// When a parameter is typed (by the user via `var_types`, or by RTTI
    /// inference) as a pointer to one of these, its field accesses render the real
    /// field name (`this->count`) instead of `this->field_0x68`. Empty for callers
    /// with no defined types.
    pub struct_defs: std::collections::HashMap<String, std::collections::BTreeMap<i64, String>>,
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
    /// Virtual calls resolved to a concrete method by
    /// [`crate::devirtualize`] — reported rather than only rendered, because
    /// "this `call [rax+0x40]` is `Widget::paint`" is a *finding* an agent may
    /// want to act on, not just prettier text.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub devirtualized: Vec<crate::Devirtualized>,
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

        let mut ssa = SsaPass.run(ctx, cfg.clone())?;
        let unlifted = count_unlifted(&ssa.blocks);
        // Recovered locals/struct-fields/signature (ROADMAP Phase 4) are
        // always computed from the *optimized* form for analysis quality —
        // propagation/DCE resolve pointer origins that raw SSA leaves as
        // opaque — then applied to whichever style's own IR is rendered.
        let mut opt = OptimizePass.run(ctx, ssa.clone())?;
        let mut types = TypeInferPass.run(ctx, TypeInferInput { cfg: cfg.clone(), blocks: opt.blocks.clone() })?;
        // Apply user C-type overrides FIRST (while names are still the synthesized
        // keys the overrides are stored under): a local gets a `type_override`, a
        // parameter's `ty` is replaced, and `"@return"` sets the signature return.
        // Rendered verbatim in the decl block and the signature.
        if !input.var_types.is_empty() {
            for l in types.locals.iter_mut() {
                if let Some(t) = input.var_types.get(&l.name).filter(|t| !t.trim().is_empty()) {
                    l.type_override = Some(t.clone());
                }
            }
            for p in types.signature.params.iter_mut() {
                if let Some(t) = input.var_types.get(&p.name).filter(|t| !t.trim().is_empty()) {
                    p.ty = crate::typeinfer::CType::named(t.clone());
                }
            }
            if let Some(rt) = input.var_types.get("@return") {
                types.signature.ret = match rt.trim() {
                    "" | "void" => None,
                    other => Some(crate::typeinfer::CType::named(other.to_string())),
                };
            }
        }
        // Apply user variable renames onto the recovered types up front, so the
        // signature line and the typed-local declarations pick them up too (not
        // just the body). Keyed by the default displayed name (`local_78`, the
        // register for a parameter); the render-site overlay below then covers the
        // coalesced `vN` / raw SSA names that never pass through `types`.
        if !input.var_names.is_empty() {
            for l in types.locals.iter_mut() {
                if let Some(u) = input.var_names.get(&l.name) {
                    l.name = u.clone();
                }
            }
            for p in types.signature.params.iter_mut() {
                if let Some(u) = input.var_names.get(&p.name) {
                    p.name = u.clone();
                }
            }
        }
        // Devirtualization (ROADMAP Phase 10 — the ❌ "indirect / virtual call
        // resolution"). Runs *after* type inference because it needs the `this`
        // type, and *before* the renderer because it rewrites the call target.
        // Both the raw and the optimized IR are rewritten so every style shows
        // the same resolved callee.
        // It runs on the **raw** SSA, not the optimized form, and that ordering
        // is the difference between working and not: expression propagation
        // rewrites the vptr's defining assignment, so in `opt.blocks` the
        // dispatch is no longer the recognizable `*( *this + off )` — measured,
        // the `goto` style resolved three calls in this very function while the
        // `ssa` style still rendered `(*rax.1->field_0x8)(…)`. Re-optimizing
        // afterwards carries the now-`Direct` targets through every style, and
        // only costs a second optimizer run when something was actually
        // resolved.
        let mut devirtualized = crate::devirt::devirtualize(ctx, &mut ssa.blocks, &types);
        if !devirtualized.is_empty() {
            // The same dispatch appears at several sites; report each once.
            devirtualized.sort_by(|a, b| (a.method.0, a.slot).cmp(&(b.method.0, b.slot)).then_with(|| a.class.cmp(&b.class)));
            devirtualized.dedup_by(|a, b| a.method == b.method && a.slot == b.slot && a.class == b.class);
            opt = OptimizePass.run(ctx, ssa.clone())?;
        }

        let mut names = RenderNames::new(&cfg.callsites).with_types(&types);
        // A devirtualized callee is not in `cfg.callsites` (the CFG saw an
        // indirect branch), so its name has to be injected here or the call
        // would render `sub_XXXX` despite having just been resolved.
        if !devirtualized.is_empty() {
            names = names.with_extra_callees(devirtualized.iter().map(|d| (d.method.get(), d.name.clone())).collect());
        }
        // Bind struct field names: for each recovered struct base var, if its ROOT
        // register matches a parameter typed (by user or RTTI) as a pointer to a
        // struct, attach that struct's field-name map — so `this->field_0x68`
        // renders `this->count`. Field names come from the user's type catalog
        // (`struct_defs`); additionally, a class that RTTI recovered a vtable for
        // gets `vftable` synthesized at offset 0 (the vtable pointer a C++ object
        // always carries there). Keyed by `p.reg`, stable across renames.
        if !types.structs.is_empty() {
            let param_ty: std::collections::HashMap<&str, &str> = types
                .signature
                .params
                .iter()
                .filter_map(|p| p.ty.name.as_deref().map(|n| (p.reg, n)))
                .collect();
            // Class names RTTI recovered a vtable for (for `vftable@0` synthesis).
            let vtable_classes = vtable_class_set(ctx);
            let mut binds: std::collections::HashMap<String, std::collections::BTreeMap<i64, String>> = std::collections::HashMap::new();
            for rt in &types.structs {
                let root = rt.base_var.split('.').next().unwrap_or(&rt.base_var);
                // The base's type: a recovered parameter's type (inferred or user),
                // OR a direct user `var_types` on the register/name — so a struct
                // pointer that never became a formal parameter still binds.
                let tystr = param_ty.get(root).map(|s| s.to_string()).or_else(|| input.var_types.get(root).cloned());
                if let Some(tystr) = tystr {
                    let sname = struct_name_of(&tystr);
                    let mut fields = input.struct_defs.get(&sname).cloned().unwrap_or_default();
                    if vtable_classes.contains(sname.as_str()) {
                        fields.entry(0).or_insert_with(|| "vftable".to_string());
                    }
                    if !fields.is_empty() {
                        binds.insert(rt.base_var.clone(), fields);
                    }
                }
            }
            if !binds.is_empty() {
                names = names.with_struct_fields(binds);
            }
        }
        if !input.var_names.is_empty() {
            names = names.with_user_names(input.var_names.clone());
        }
        // RTTI (ROADMAP Phase 10 item 7): if the frontend attached the recovered
        // vtable map, a vtable constant renders as `&Class::vtable`. Shared by
        // `Arc` — a deep clone here cost 57k string allocations *per decompile*
        // on a Qt/MSVC target (the map is one entry per class, not "a handful"),
        // and freeing them showed up as the top destructor in a profile.
        if let Some(vtables) = ctx.vtables {
            names = names.with_vtables(std::sync::Arc::clone(vtables));
        }
        // String-literal recovery: a constant that is the address of a printable
        // NUL-terminated string in the source renders as that C literal
        // (`"hello %s"`) instead of a bare `0x…`. Read straight from the image
        // bytes and validated to be a real string before it is trusted — sound
        // over pretty, the same rule the vtable naming follows. Scans both the raw
        // and optimized IR so a string used only in dead code still resolves.
        let strings = recover_strings(&[&ssa.blocks, &opt.blocks], ctx.source);
        if !strings.is_empty() {
            names = names.with_strings(strings);
        }
        // Data-symbol naming: a constant that is the address of a named global /
        // static (`crc_table`, a vtable, an exported object) renders as `&name`
        // instead of `0x…`. Only an *exact* symbol hit at that address counts, so
        // an interior address is never mis-attributed to the symbol before it.
        if let Some(syms) = ctx.symbols {
            let data_refs = recover_data_refs(&[&ssa.blocks, &opt.blocks], syms);
            if !data_refs.is_empty() {
                names = names.with_data_refs(data_refs);
            }
        }
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
        // A constructor or destructor has no source-level return value, however
        // the ABI uses the return register. Read off the function's own name,
        // the same evidence the class-layout pass uses.
        // `ctor_class_of` wants the *qualified name*, not a whole prototype:
        // the demangled form carries its argument list, and `Class::Class(…)`
        // never matches `Class` until the list is cut off.
        names = names.as_ctor_or_dtor(
            own_name
                .as_deref()
                .map(|n| n.split('(').next().unwrap_or(n).trim())
                .and_then(crate::classlayout::ctor_class_of)
                .is_some(),
        );
        let signature = format_signature(cfg.start, &types.signature, own_name.as_deref());

        let (pseudo, has_loop, fallback_count, delta) = match input.style {
            // (the arms below produce `pseudo`; block-label stripping is applied
            // to it after the match, gated on `input.strip_block_labels`)
            DecompStyle::Goto => (render_goto(&cfg, &ssa.blocks, &names), false, 0, Vec::new()),
            DecompStyle::Structured => {
                let out = structure(&cfg, &ssa.blocks, &names);
                (out.lines, out.has_loop, out.fallback_count, Vec::new())
            }
            DecompStyle::Ssa => {
                // Coalesce SSA-version phi-webs into named variables (Rung 3b/3c),
                // then destruct the phis coalescing didn't merge by inserting
                // edge copies (Rung 3d) so no phi destination renders undefined.
                // Both run against the exact blocks this style renders — the
                // raw/structured styles show the un-coalesced SSA on purpose.
                let var_names = crate::coalesce::coalesce_vars(&opt.blocks, &types.signature);
                let (dcfg, dblocks) = crate::coalesce::destruct_ssa(&cfg, &opt.blocks, &var_names);
                let names = names.with_coalescing(var_names);
                let out = structure(&dcfg, &dblocks, &names);
                let delta = if input.explain { opt.delta } else { Vec::new() };
                (out.lines, out.has_loop, out.fallback_count, delta)
            }
        };

        let pseudo = if input.strip_block_labels { strip_unreferenced_block_labels(pseudo) } else { pseudo };

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

        // Typed-locals declaration block (Rung 3): the recovered
        // stack locals, declared with their inferred C type at the top of the
        // function before the body — only for the C-like styles, and only those
        // that actually appear in the rendered body (so a local dead-eliminated
        // by the optimizer is not declared as if it were used). `goto` stays a
        // flat instruction listing with no preamble.
        let decls = match input.style {
            DecompStyle::Structured | DecompStyle::Ssa => local_decls(&types, &pseudo),
            DecompStyle::Goto => Vec::new(),
        };
        let preamble = if decls.is_empty() {
            Vec::new()
        } else {
            decls.into_iter().chain(std::iter::once(String::new())).collect::<Vec<_>>()
        };

        let body_lines: Vec<String> = std::iter::once(format!("{signature} {{"))
            .chain(preamble)
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
            devirtualized,
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
    // `unsigned short __cdecl SomeLib::SomeMethod(struct … *, unsigned int,
    // unsigned int)`. It is authoritative: prepending our
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

/// The typed-locals declaration lines for a function's body — one
/// `type local_XX;` per recovered stack local that actually appears in the
/// rendered `body`, in stack-offset order. Filtering on appearance keeps the
/// block honest: a local the optimizer removed (dead store, fully forwarded)
/// leaves no reference to declare. The `local_XX` name matches the renderer's
/// (both derive it from the offset — single source of truth).
/// The struct name inside a pointer type string: `"Foo *"` → `"Foo"`,
/// `"std::exception *"` → `"std::exception"`. Trailing `*` and whitespace only —
/// a non-pointer type maps to itself (harmless; it just won't match a struct).
fn struct_name_of(ty: &str) -> String {
    ty.trim().trim_end_matches('*').trim().to_string()
}

fn local_decls(types: &TypeArtifact, body: &[String]) -> Vec<String> {
    let joined = body.join("\n");
    let mut locals: Vec<&crate::typeinfer::LocalVar> = types.locals.iter().filter(|l| joined.contains(&l.name)).collect();
    locals.sort_by_key(|l| l.offset);
    locals
        .iter()
        .map(|l| {
            let ty = l.type_override.clone().unwrap_or_else(|| c_type(l.size_bits, l.signed).to_string());
            format!("    {ty} {};", l.name)
        })
        .collect()
}

/// Drop the `// block_N: …` anchor comment from every block no `goto` jumps to
/// — a label is only meaningful at a jump target, so on straight-line code
/// these anchors are pure noise (and ~a third of the lines). A goto-targeted
/// block keeps its comment as the label the `goto block_N` reads. Pure display
/// transform; the un-stripped form stays available to
/// [`crate::ProvenancePass`], which maps a line to an address by this comment.
fn strip_unreferenced_block_labels(lines: Vec<String>) -> Vec<String> {
    let mut targets: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for l in &lines {
        if let Some(rest) = l.split("goto block_").nth(1)
            && let Ok(n) = rest.trim_end().trim_end_matches(';').trim().parse::<usize>()
        {
            targets.insert(n);
        }
    }
    lines
        .into_iter()
        .filter(|l| {
            let Some(rest) = l.trim_start().strip_prefix("// block_") else { return true };
            match rest.split(':').next().and_then(|s| s.trim().parse::<usize>().ok()) {
                Some(n) => targets.contains(&n),
                None => true,
            }
        })
        .collect()
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

/// The widest byte window read at a candidate string address. A real C string a
/// decompiler wants to inline is short; a "string" longer than this is treated as
/// not-a-string (data), so the read — and the cost — stay bounded.
const MAX_STRING_LEN: usize = 200;
/// Below this many characters a match is too likely to be a coincidence (a small
/// integer that happens to address printable bytes), so short runs are ignored.
const MIN_STRING_LEN: usize = 4;

/// Recover the `address → C-string-literal` map for every constant that appears
/// in `block_sets` and turns out to address a printable NUL-terminated string in
/// the image. Reading the bytes and validating them *is* the soundness check: a
/// constant that is not a mapped address, or whose bytes are not a clean string,
/// simply gets no entry and renders as a number exactly as before.
fn recover_strings(block_sets: &[&[SsaBlock]], source: &dyn n0xis_sources::MemorySource) -> std::collections::HashMap<u64, String> {
    let mut addrs: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for blocks in block_sets {
        for b in *blocks {
            for s in &b.stmts {
                collect_const_addrs(&s.stmt, &mut addrs);
            }
        }
    }
    let mut out = std::collections::HashMap::new();
    for va in addrs {
        if let Some(lit) = read_c_string(source, va) {
            out.insert(va, lit);
        }
    }
    out
}

/// The `address → &name` map for every constant in `block_sets` that is the
/// exact address of a named symbol (a data object or a function). Used to render
/// a global's address as `&crc_table` rather than a bare number. Sound: only an
/// exact-address hit is taken, so an interior offset never borrows the symbol
/// that precedes it — the same rule the function's own-name recovery uses.
fn recover_data_refs(block_sets: &[&[SsaBlock]], syms: &dyn n0xis_sources::SymbolProvider) -> std::collections::HashMap<u64, String> {
    let mut addrs: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for blocks in block_sets {
        for b in *blocks {
            for s in &b.stmts {
                collect_const_addrs(&s.stmt, &mut addrs);
            }
        }
    }
    let mut out = std::collections::HashMap::new();
    for va in addrs {
        if let Some(sym) = syms.symbol_at(Va(va)).filter(|s| s.va.0 == va) {
            out.insert(va, format!("&{}", crate::render::render_callee_name(&sym.name)));
        }
    }
    out
}

/// Read the bytes at `va` and, if they are a printable NUL-terminated string of
/// at least [`MIN_STRING_LEN`] characters, return its escaped, quoted C literal.
fn read_c_string(source: &dyn n0xis_sources::MemorySource, va: u64) -> Option<String> {
    let bytes = source.read(Va(va), MAX_STRING_LEN).ok()?;
    let nul = bytes.iter().position(|&b| b == 0)?; // must terminate within the window
    if nul < MIN_STRING_LEN {
        return None;
    }
    let text = &bytes[..nul];
    // Every byte must be printable ASCII or ordinary whitespace; one stray
    // control/high byte means this is data that merely contains a run of text.
    if !text.iter().all(|&b| (0x20..=0x7e).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r')) {
        return None;
    }
    let mut lit = String::with_capacity(nul + 2);
    lit.push('"');
    for &b in text {
        match b {
            b'"' => lit.push_str("\\\""),
            b'\\' => lit.push_str("\\\\"),
            b'\t' => lit.push_str("\\t"),
            b'\n' => lit.push_str("\\n"),
            b'\r' => lit.push_str("\\r"),
            _ => lit.push(b as char),
        }
    }
    lit.push('"');
    Some(lit)
}

/// Add every constant used as (or foldable into) an address in `stmt` to `out`.
fn collect_const_addrs(stmt: &n0xis_arch::MicroStmt, out: &mut std::collections::HashSet<u64>) {
    use n0xis_arch::MicroStmt;
    match stmt {
        MicroStmt::Assign { value, .. } => collect_const_exprs(value, out),
        MicroStmt::Store { addr, value, .. } => {
            collect_const_exprs(addr, out);
            collect_const_exprs(value, out);
        }
        MicroStmt::Call { target, args, .. } => {
            if let n0xis_arch::CallTarget::Indirect(e) = target {
                collect_const_exprs(e, out);
            }
            for a in args {
                collect_const_exprs(a, out);
            }
        }
        MicroStmt::Return(Some(e)) => collect_const_exprs(e, out),
        MicroStmt::Return(None) | MicroStmt::Nop | MicroStmt::Unlifted { .. } => {}
    }
}

fn collect_const_exprs(e: &n0xis_arch::MicroExpr, out: &mut std::collections::HashSet<u64>) {
    use n0xis_arch::MicroExpr;
    match e {
        MicroExpr::Const { value, .. } => {
            if let Ok(v) = u64::try_from(*value) {
                out.insert(v);
            }
        }
        MicroExpr::AddrOf(inner) | MicroExpr::Unary(_, inner) | MicroExpr::Cast { expr: inner, .. } | MicroExpr::Load { addr: inner, .. } => {
            collect_const_exprs(inner, out)
        }
        MicroExpr::Binary(_, l, r) => {
            collect_const_exprs(l, out);
            collect_const_exprs(r, out);
        }
        MicroExpr::Compare { lhs, rhs, .. } => {
            collect_const_exprs(lhs, out);
            collect_const_exprs(rhs, out);
        }
        MicroExpr::Select { cond, a, b } => {
            collect_const_exprs(cond, out);
            collect_const_exprs(a, out);
            collect_const_exprs(b, out);
        }
        MicroExpr::Call { target, args } => {
            if let n0xis_arch::CallTarget::Indirect(inner) = target {
                collect_const_exprs(inner, out);
            }
            for a in args {
                collect_const_exprs(a, out);
            }
        }
        MicroExpr::Var(_) | MicroExpr::OpaqueFlags { .. } | MicroExpr::Unknown(_) => {}
    }
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
        DecompPass.run(&ctx, DecompInput { cfg, style, explain: true, strip_block_labels: false, var_names: Default::default(), var_types: Default::default(), struct_defs: Default::default() }).unwrap()
    }

    #[test]
    fn recover_data_refs_names_an_exact_symbol_address_only() {
        use n0xis_contracts::{SymKind, Symbol};
        use n0xis_sources::SymbolProvider;

        struct OneGlobal;
        impl SymbolProvider for OneGlobal {
            fn symbol_at(&self, va: Va) -> Option<Symbol> {
                // A global spanning [0x4000, 0x4100): answers for any interior
                // address, exactly like a real span-attributing provider.
                (0x4000..0x4100).contains(&va.0).then(|| Symbol {
                    va: Va(0x4000),
                    module: String::new(),
                    name: "crc_table".into(),
                    kind: SymKind::Data,
                })
            }
        }

        // Two constants: the global's exact start, and an interior offset.
        let stmt = |dst: &str, v: i128| crate::ssa::SsaStmt {
            va: Va(0x1000),
            stmt: n0xis_arch::MicroStmt::Assign { dst: dst.into(), value: n0xis_arch::MicroExpr::constant(v, 64) },
        };
        let blocks = vec![SsaBlock {
            id: 0,
            start: Va(0x1000),
            end: Va(0x1010),
            terminator: "ret".into(),
            successors: Vec::new(),
            phis: Vec::new(),
            stmts: vec![stmt("a", 0x4000), stmt("b", 0x4040)],
            condition: None,
        }];
        let refs = recover_data_refs(&[&blocks], &OneGlobal);
        // The exact address is named; the interior offset is not (sound — it must
        // not borrow the symbol that starts before it).
        assert_eq!(refs.get(&0x4000).map(String::as_str), Some("&crc_table"));
        assert_eq!(refs.get(&0x4040), None);
    }

    #[test]
    fn read_c_string_recovers_a_real_string_and_rejects_non_strings() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"hi %s\n\0"); // 0x3000: a genuine string (len 6)
        bytes.extend_from_slice(b"abc\x01d\0"); // 0x3007: long enough, but a control byte inside
        bytes.extend_from_slice(b"ab\0"); // 0x300d: too short (< MIN_STRING_LEN)
        bytes.extend_from_slice(b"no terminator within this window"); // 0x3010: never NUL
        let snap = Snapshot::builder().region(Va(0x3000), bytes).build();

        // A clean string is recovered, escaped and quoted.
        assert_eq!(read_c_string(&snap, 0x3000), Some("\"hi %s\\n\"".to_string()));
        // A control byte inside a long-enough run → not a string.
        assert_eq!(read_c_string(&snap, 0x3007), None);
        // Below the minimum length → ignored as a likely coincidence.
        assert_eq!(read_c_string(&snap, 0x300d), None);
        // No terminator before the buffer ends → treated as data, not a string.
        assert_eq!(read_c_string(&snap, 0x3010), None);
        // An unmapped address simply yields nothing.
        assert_eq!(read_c_string(&snap, 0x9999), None);
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
        let name = "unsigned short __cdecl SomeLib::ReadValue(struct SomeLib::SomeFile *, unsigned int, unsigned int)";
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
    fn the_ssa_style_emits_a_typed_locals_declaration_block() {
        // A width-mismatched spill/reload keeps a real stack local at [rsp+8]:
        // mov [rsp+8], rcx ; mov eax, [rsp+8] ; ret. The C-like styles now
        // declare it at the top (`uint... local_8;`); `goto` does not.
        let code = vec![0x48, 0x89, 0x4c, 0x24, 0x08, 0x8b, 0x44, 0x24, 0x08, 0xc3];
        let ssa = decomp(code.clone(), DecompStyle::Ssa);
        // A declaration line: `local_8` on its own, ending in `;`, no `=`.
        let decl = ssa.pseudo.iter().find(|l| l.contains("local_8;") && !l.contains('='));
        assert!(decl.is_some(), "expected a typed-locals decl for local_8: {:#?}", ssa.pseudo);
        assert!(decl.unwrap().contains("local_8"), "{decl:?}");
        // The declaration precedes the first use of the local in the body.
        let joined = ssa.pseudo.join("\n");
        let decl_pos = ssa.pseudo.iter().position(|l| l.contains("local_8;") && !l.contains('=')).unwrap();
        let use_pos = ssa.pseudo.iter().position(|l| l.contains("local_8") && l.contains('=')).unwrap();
        assert!(decl_pos < use_pos, "decl must precede use: {joined}");
        // `goto` style stays a flat listing — no declaration preamble.
        let goto = decomp(code, DecompStyle::Goto);
        assert!(!goto.pseudo.iter().any(|l| l.contains("local_8;") && !l.contains('=')), "goto should not declare locals: {:#?}", goto.pseudo);
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

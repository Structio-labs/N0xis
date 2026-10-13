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

use std::collections::HashMap;

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
/// Keyed by the source's identity plus the symbol fingerprint, so a re-`analyze`
/// that changes the recovered classes invalidates it — the same discipline as
/// the vtable map and callee-type memos. A source with no identity is not kept.
type VtableClassMemo = Option<(String, std::sync::Arc<std::collections::HashSet<String>>)>;
static VTABLE_CLASSES: std::sync::Mutex<VtableClassMemo> = std::sync::Mutex::new(None);

fn vtable_class_set(ctx: &Ctx) -> std::sync::Arc<std::collections::HashSet<String>> {
    let id = ctx.source.identity().map(|source| {
        format!(
            "{source}|{}|{}",
            ctx.symbols.map(|s| s.symbol_fingerprint()).unwrap_or_default(),
            ctx.vtables.map_or(0, |v| v.len()),
        )
    });
    if let Some(id) = &id
        && let Ok(memo) = VTABLE_CLASSES.lock()
        && let Some((cached, set)) = memo.as_ref()
        && cached == id
    {
        return std::sync::Arc::clone(set);
    }
    let set: std::collections::HashSet<String> = ctx.vtables.map(|m| m.values().cloned().collect()).unwrap_or_default();
    let arc = std::sync::Arc::new(set);
    if let Some(id) = id
        && let Ok(mut memo) = VTABLE_CLASSES.lock()
    {
        *memo = Some((id, std::sync::Arc::clone(&arc)));
    }
    arc
}
use crate::ssa::{SsaBlock, SsaPass};
use crate::structure::structure;
use crate::typeinfer::{RecoveredSignature, TypeArtifact, TypeInferInput, TypeInferPass, ReturnType};
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
    /// Every variable `pseudo` shows, with the key a rename or a type is stored
    /// under. A front end renames what the user points at by looking it up here,
    /// instead of guessing from the text which words are variables.
    pub variables: Vec<DecompVar>,
}

/// One variable of a decompiled function.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DecompVar {
    /// The name as `pseudo` prints it, after any rename.
    pub name: String,
    /// What `annotate var --var` and `annotate vartype --var` take for this
    /// variable: its name before the user renamed it.
    pub key: String,
    pub kind: VarKind,
}

/// What a variable is, which decides what can be said about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VarKind {
    /// A parameter of the recovered signature. Takes a name and a type.
    Param,
    /// A recovered stack local. Takes a name and a type.
    Local,
    /// Any other variable: a register value or a merged SSA value. Takes a name
    /// only. A type stored for it changes nothing, because types apply to
    /// parameters and locals.
    Value,
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
        let mut types = TypeInferPass.run(ctx, TypeInferInput { cfg: cfg.clone(), blocks: opt.blocks.clone(), float_return: opt.float_return, float_return_pair: opt.float_return_pair })?;
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
                    // The user asserting `void` is a *measurement* — theirs.
                    "" | "void" => crate::typeinfer::ReturnType::Void,
                    other => crate::typeinfer::ReturnType::Known(crate::typeinfer::CType::named(other.to_string())),
                };
            }
        }
        // Apply user variable renames onto the recovered types up front, so the
        // signature line and the typed-local declarations pick them up too (not
        // just the body). Keyed by the default displayed name (`local_78`, the
        // register for a parameter); the render-site overlay below then covers the
        // coalesced `vN` / raw SSA names that never pass through `types`.
        // The names before this rename are the keys renames are stored under;
        // `renamed_*` maps a shown name back to its key for the variable list.
        let param_keys: Vec<String> = types.signature.params.iter().map(|p| p.name.clone()).collect();
        let local_keys: Vec<String> = types.locals.iter().map(|l| l.name.clone()).collect();
        let mut renamed_params: HashMap<String, String> = HashMap::new();
        let mut renamed_locals: HashMap<String, String> = HashMap::new();
        if !input.var_names.is_empty() {
            for l in types.locals.iter_mut() {
                if let Some(u) = input.var_names.get(&l.name) {
                    renamed_locals.insert(u.clone(), l.name.clone());
                    l.name = u.clone();
                }
            }
            for p in types.signature.params.iter_mut() {
                if let Some(u) = input.var_names.get(&p.name) {
                    renamed_params.insert(u.clone(), p.name.clone());
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

        let mut names = RenderNames::new(&cfg.callsites)
            .with_stack_pointer(ctx.arch.stack_pointer())
            .with_return_register(crate::ir::abi_return_register(ctx).as_deref())
            .with_register_spelling(ctx.arch.display_reg_map())
            .with_types(&types);
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
        // One answer to "what is the function at this entry called" — see
        // `ir::symbol_on_entry`, which also knows an import stub is the import.
        let own_name =
            crate::ir::symbol_on_entry(ctx, cfg.start).map(|sym| crate::render::render_callee_name(&sym.name));
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

        let (pseudo, has_loop, fallback_count, delta, printed) = match input.style {
            // (the arms below produce `pseudo`; block-label stripping is applied
            // to it after the match, gated on `input.strip_block_labels`)
            DecompStyle::Goto => {
                let lines = render_goto(&cfg, &ssa.blocks, &names);
                (lines, false, 0, Vec::new(), names.printed_vars())
            }
            DecompStyle::Structured => {
                let out = structure(&cfg, &ssa.blocks, &names);
                (out.lines, out.has_loop, out.fallback_count, Vec::new(), names.printed_vars())
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
                (out.lines, out.has_loop, out.fallback_count, delta, names.printed_vars())
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

        let variables = printed_variables(
            &printed,
            &types.signature.params.iter().map(|p| p.name.clone()).collect::<Vec<_>>(),
            &VarKeys { params: &param_keys, locals: &local_keys, renamed_params: &renamed_params, renamed_locals: &renamed_locals },
            &body_lines,
        );

        Ok(PseudoFunction {
            address: cfg.start,
            end_address: cfg.end,
            signature,
            style: input.style.as_str(),
            pseudo: body_lines,
            variables,
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
        ReturnType::Known(ty) => ty.name.clone().unwrap_or_else(|| c_type(ty.bits, ty.signed).to_string()),
        ReturnType::Void => "void".to_string(),
        // C has no notation for "I did not find out", and `void` is the wrong
        // one — it claims the function produces nothing. The house placeholder
        // says the true thing instead.
        ReturnType::Unknown => "/*unknown*/".to_string(),
    };
    let params = if sig.params.is_empty() {
        // `(void)` is C for "takes nothing"; `()` is C for "unspecified". The
        // tool printed the first when it meant the second — on a stack-argument
        // ABI nothing is measured, and seven of ten functions on a purpose-built
        // 32-bit target were told they take no arguments while taking one to
        // three. The notation for "I did not find out" already exists; use it.
        if sig.params_known { "void".to_string() } else { String::new() }
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

/// The keys a function's renames are stored under, and the user's upfront
/// renames of parameters and locals mapped back to them.
struct VarKeys<'a> {
    params: &'a [String],
    locals: &'a [String],
    renamed_params: &'a HashMap<String, String>,
    renamed_locals: &'a HashMap<String, String>,
}

/// The variables a decompiled function shows. `printed` is what the renderer
/// printed; `shown_params` are the signature's parameter names as printed,
/// which appear on the signature line even when the body never reads them.
/// Only names that are on the page are kept: a render that was discarded must
/// not leave a variable nobody can see.
fn printed_variables(printed: &[crate::render::PrintedVar], shown_params: &[String], keys: &VarKeys<'_>, body: &[String]) -> Vec<DecompVar> {
    let text = body.join("\n");
    let kind_of = |key: &str, stack_local: bool| {
        if keys.params.iter().any(|k| k == key) {
            VarKind::Param
        } else if stack_local || keys.locals.iter().any(|k| k == key) {
            VarKind::Local
        } else {
            VarKind::Value
        }
    };
    let mut out = std::collections::BTreeSet::new();
    for v in printed {
        let renamed = if v.stack_local { keys.renamed_locals } else { keys.renamed_params };
        let key = renamed.get(&v.key).cloned().unwrap_or_else(|| v.key.clone());
        let kind = kind_of(&key, v.stack_local);
        out.insert(DecompVar { name: v.shown.clone(), key, kind });
    }
    for (shown, key) in shown_params.iter().zip(keys.params) {
        out.insert(DecompVar { name: shown.clone(), key: key.clone(), kind: VarKind::Param });
    }
    out.into_iter().filter(|v| shows_as_name(&text, &v.name)).collect()
}

/// `name` appears in `text` as a whole name: not inside a longer identifier
/// (`v1` in `v10`) and not as the stem of a versioned SSA name (`rsi` in
/// `rsi.2`).
fn shows_as_name(text: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut from = 0;
    while let Some(i) = text[from..].find(name) {
        let start = from + i;
        let end = start + name.len();
        let before = text[..start].chars().next_back().is_none_or(|c| !ident(c) && c != '.');
        let mut rest = text[end..].chars();
        let after = match rest.next() {
            None => true,
            Some('.') => !rest.next().is_some_and(|d| d.is_ascii_digit()),
            Some(c) => !ident(c),
        };
        if before && after {
            return true;
        }
        from = start + text[start..].chars().next().map_or(1, char::len_utf8);
    }
    false
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

/// Turn each `// block_N: …` anchor into what the reader needs: a **real
/// label** where a `goto` targets it, and nothing where none does.
///
/// A label is only meaningful at a jump target, so on straight-line code these
/// anchors are pure noise (and ~a third of the lines). At a target, a comment
/// is not enough: the output carried `goto block_2;` — a statement — against
/// `// block_2: 0x10a8ce` — a comment — so 6 350 gotos over 1 812 Qt functions
/// jumped to nothing that exists in the text. Anything reading the output,
/// a person included, had to follow a `goto` into a comment.
///
/// Pure display transform; the un-stripped form stays available to
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
        .filter_map(|l| {
            let indent = l.len() - l.trim_start().len();
            let Some(rest) = l.trim_start().strip_prefix("// block_") else { return Some(l) };
            let Some(n) = rest.split(':').next().and_then(|s| s.trim().parse::<usize>().ok()) else {
                return Some(l);
            };
            if !targets.contains(&n) {
                return None;
            }
            // The address the anchor carried stays, as the comment it always
            // was — the label is what becomes real.
            let addr = rest.split_once(':').map(|(_, a)| a.trim()).unwrap_or_default();
            Some(format!("{}block_{n}:    // {addr}", " ".repeat(indent)))
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
    // A different question from `ir::symbol_on_entry`: these are **data**
    // addresses whose name is taken (`&g_thing`), not function entries, so the
    // import-stub fallback has nothing to contribute and would cost a read and
    // a decode per address.
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

/// Add every constant *used as an address* in `stmt` to `out` — the base of a
/// Load/Store address operand, an indirect call target, or anything under an
/// `AddrOf` (a `lea`/RIP-relative address). A constant that flows only as an
/// integer VALUE — a return value, an arithmetic operand, a compared value — is
/// NOT an address and is excluded: string/data-ref resolution off this set must
/// never mistake the integer `1000` (or a value that happens to land on
/// printable bytes) for a pointer to a string. The `in_addr` flag carried
/// through [`collect_const_exprs`] is what distinguishes the two positions; a
/// bare `Const` is collected only when it is reached in address position.
fn collect_const_addrs(stmt: &n0xis_arch::MicroStmt, out: &mut std::collections::HashSet<u64>) {
    use n0xis_arch::MicroStmt;
    match stmt {
        // The assigned value is a value; addresses inside it announce themselves
        // via `Load`/`AddrOf` (e.g. `rax = &g_thing` is `AddrOf(Const)`).
        MicroStmt::Assign { value, .. } => collect_const_exprs(value, false, out),
        MicroStmt::Store { addr, value, .. } => {
            collect_const_exprs(addr, true, out);
            collect_const_exprs(value, false, out);
        }
        MicroStmt::Call { target, args, .. } => {
            // The indirect target is the address jumped to.
            if let n0xis_arch::CallTarget::Indirect(e) = target {
                collect_const_exprs(e, true, out);
            }
            // Arguments are values (a string arg is an `AddrOf(Const)` and still
            // self-announces as an address).
            for a in args {
                collect_const_exprs(a, false, out);
            }
        }
        MicroStmt::Return(Some(e)) => collect_const_exprs(e, false, out),
        MicroStmt::Return(None) | MicroStmt::Nop | MicroStmt::Unlifted { .. } => {}
    }
}

/// Collect constants that reach an *address position*. `in_addr` is true when
/// the current sub-expression is being used to compute an address; a bare
/// `Const` is recorded only then. `Load`/`AddrOf` turn their operand into an
/// address position regardless of the incoming flag; a `Compare` yields a
/// boolean, so its operands are values; every other node propagates the flag
/// (address arithmetic `base + i*stride` keeps its base an address).
fn collect_const_exprs(e: &n0xis_arch::MicroExpr, in_addr: bool, out: &mut std::collections::HashSet<u64>) {
    use n0xis_arch::MicroExpr;
    match e {
        MicroExpr::Const { value, .. } => {
            if in_addr && let Ok(v) = u64::try_from(*value) {
                out.insert(v);
            }
        }
        // The dereferenced/taken address is an address position; the value a
        // `Load` yields is not, but a `Load` has no other constant children.
        MicroExpr::AddrOf(inner) | MicroExpr::Load { addr: inner, .. } => collect_const_exprs(inner, true, out),
        MicroExpr::Unary(_, inner) | MicroExpr::Cast { expr: inner, .. } => collect_const_exprs(inner, in_addr, out),
        MicroExpr::Binary(_, l, r) => {
            collect_const_exprs(l, in_addr, out);
            collect_const_exprs(r, in_addr, out);
        }
        // A comparison produces a boolean; its operands are compared as values.
        MicroExpr::Compare { lhs, rhs, .. } => {
            collect_const_exprs(lhs, false, out);
            collect_const_exprs(rhs, false, out);
        }
        // The selected value inherits the context (`*(cond ? p : q)` makes both
        // arms addresses); the condition is a boolean.
        MicroExpr::Select { cond, a, b } => {
            collect_const_exprs(cond, false, out);
            collect_const_exprs(a, in_addr, out);
            collect_const_exprs(b, in_addr, out);
        }
        MicroExpr::Call { target, args } => {
            if let n0xis_arch::CallTarget::Indirect(inner) = target {
                collect_const_exprs(inner, true, out);
            }
            for a in args {
                collect_const_exprs(a, false, out);
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

    /// A32 bytes through the whole pipeline — lift, SSA, render — in the
    /// structured style, which keeps every statement.
    fn decomp_a32(code: Vec<u8>) -> PseudoFunction {
        decomp_a32_as(code, DecompStyle::Structured)
    }

    fn decomp_a32_as(code: Vec<u8>, style: DecompStyle) -> PseudoFunction {
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = n0xis_arch::Arm32::a32();
        let ctx = Ctx::new(&snap, &arch);
        let cfg = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), 128)).unwrap();
        DecompPass.run(&ctx, DecompInput { cfg, style, explain: false, strip_block_labels: false, var_names: Default::default(), var_types: Default::default(), struct_defs: Default::default() }).unwrap()
    }

    /// Compiled from C (`clang --target=armv6-none-eabi -marm -O2`), so the
    /// meaning is the source's: `int f(int a) { return a >> 8; }` and
    /// `int f(int a, int b) { return a < b ? 7 : 9; }`. Both are signed, and
    /// both printed as operations on `uint32_t` — `(r0 >> 0x8)`, a logical
    /// shift in C, and `(r0 < r1)`, an unsigned compare.
    #[test]
    fn an_a32_signed_shift_and_compare_render_signed() {
        // e1a00440 asr r0, r0, #8; e12fff1e bx lr
        let f = decomp_a32_as(words(&[0xe1a00440, 0xe12fff1e]), DecompStyle::Ssa);
        assert!(f.pseudo.iter().any(|l| l.contains("return ((int32_t)r0 >> 0x8);")), "{:#?}", f.pseudo);
        // e3a02009 mov r2, #9; e1500001 cmp r0, r1; b3a02007 movlt r2, #7;
        // e1a00002 mov r0, r2; e12fff1e bx lr
        let f = decomp_a32_as(words(&[0xe3a02009, 0xe1500001, 0xb3a02007, 0xe1a00002, 0xe12fff1e]), DecompStyle::Ssa);
        assert!(f.pseudo.iter().any(|l| l.contains("((int32_t)r0 < (int32_t)r1)")), "{:#?}", f.pseudo);
    }

    fn words(ws: &[u32]) -> Vec<u8> {
        ws.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    /// The `if` line of a structured A32 function.
    fn condition_line(f: &PseudoFunction) -> &str {
        f.pseudo.iter().find(|l| l.trim_start().starts_with("if ")).unwrap_or_else(|| panic!("no `if` in {:#?}", f.pseudo))
    }

    // The sequences below are ones the 0.4 decoder's phantom operands lifted
    // wrong; every word was checked with `llvm-mc --disassemble
    // -triple=armv6-none-eabi`. Each ends `mov r0, #1; bx lr; mov r0, #2; bx lr`
    // (e3a00001 e12fff1e e3a00002 e12fff1e) behind a `beq` (0a000001).

    /// `cmp r4, #0; beq` decompiled to `if ((r0 == 0x0))`: the 0.4 decoder put
    /// the compare's should-be-zero `Rd` field where its first operand belongs.
    #[test]
    fn an_a32_compare_branches_on_the_register_it_compares() {
        let f = decomp_a32(words(&[0xe3540000, 0x0a000001, 0xe3a00001, 0xe12fff1e, 0xe3a00002, 0xe12fff1e]));
        assert!(condition_line(&f).contains("(r4.0 == 0x0)"), "cmp r4, #0 → r4 == 0: {:#?}", f.pseudo);
    }

    /// `tst r1, #255; beq` branches on `(r1 & 0xff) == 0`; it used to stay
    /// `asm` with the branch reading `/*cond(beq)*/`.
    #[test]
    fn an_a32_tst_branches_on_the_masked_register() {
        let f = decomp_a32(words(&[0xe31100ff, 0x0a000001, 0xe3a00001, 0xe12fff1e, 0xe3a00002, 0xe12fff1e]));
        assert!(condition_line(&f).contains("((r1 & 0xff) == 0x0)"), "tst r1, #255 → (r1 & 0xff) == 0: {:#?}", f.pseudo);
    }

    /// `cmp r2, #1; teq r1, #1; beq` — the `teq` stays `asm`, and the branch
    /// must not read the `cmp` it overwrote: a missing condition, not a wrong
    /// one.
    #[test]
    fn an_a32_flag_setter_kept_as_asm_hides_the_earlier_compare() {
        let f = decomp_a32(words(&[0xe3520001, 0xe3310001, 0x0a000001, 0xe3a00001, 0xe12fff1e, 0xe3a00002, 0xe12fff1e]));
        let cond = condition_line(&f);
        assert!(!cond.contains("=="), "the branch must not test the stale `cmp r2, #1`: {cond}");
        assert!(cond.contains("cond(beq)"), "it states that its condition is unknown: {cond}");
    }

    /// `mvn r0, #0` returns 0xffffffff; it decompiled to `return ~r0;`.
    #[test]
    fn an_a32_move_not_of_an_immediate_returns_the_inverted_immediate() {
        let f = decomp_a32(words(&[0xe3e00000, 0xe12fff1e]));
        assert!(f.pseudo.iter().any(|l| l.contains("= 0xffffffff;")), "mvn r0, #0 → 0xffffffff: {:#?}", f.pseudo);
    }

    /// `ldr r3, [r0, #0x24]; asr r3, r3, #8; str r3, [r1, #0xc]` stored the
    /// pointer `r0` itself, because the shifted move read the `Rn` field: the
    /// shift has to be there, applied to the loaded field.
    #[test]
    fn an_a32_shifted_move_keeps_the_value_it_shifts() {
        let f = decomp_a32(words(&[0xe5903024, 0xe1a03443, 0xe581300c, 0xe12fff1e]));
        assert!(f.pseudo.iter().any(|l| l.contains("((int32_t)r3.1 >> 0x8)")), "asr r3, r3, #8 shifts the loaded value, signed: {:#?}", f.pseudo);
    }

    fn decomp_arm64(code: Vec<u8>) -> PseudoFunction {
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = n0xis_arch::Arm64::new();
        let ctx = Ctx::new(&snap, &arch);
        let cfg = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), 128)).unwrap();
        DecompPass.run(&ctx, DecompInput { cfg, style: DecompStyle::Ssa, explain: false, strip_block_labels: false, var_names: Default::default(), var_types: Default::default(), struct_defs: Default::default() }).unwrap()
    }

    /// The `return` line of a decompiled function.
    fn return_line(f: &PseudoFunction) -> &str {
        f.pseudo.iter().map(|l| l.trim()).find(|l| l.starts_with("return")).unwrap_or_else(|| panic!("no return in {:#?}", f.pseudo))
    }

    // An instruction the lift leaves as `asm` still reads registers and may
    // touch memory. These are the shapes measured wrong before the `Unlifted`
    // statement said so; every word is llvm-mc's, and each test checks the
    // optimized style, because dead-code elimination and memory forwarding are
    // where the two omissions turned into wrong answers.

    /// `mov r8, r3; strb r8, [r1]; bx lr` — the `strb` is `asm`, and it is the
    /// only reader of `r8`. With no reads on the statement `r8 = r3` was dead,
    /// and `r1` and `r3` vanished from the signature (`sub_1000(uint32_t r0)`).
    /// The same with `uxtb r8, r3` in place of the move.
    #[test]
    fn a_definition_only_an_unlifted_instruction_reads_is_kept() {
        // e1a08003 mov r8, r3; e5c18000 strb r8, [r1]; e12fff1e bx lr
        let f = decomp_a32_as(words(&[0xe1a08003, 0xe5c18000, 0xe12fff1e]), DecompStyle::Ssa);
        assert!(f.pseudo.iter().any(|l| l.contains("r8.1 = r3;")), "{:#?}", f.pseudo);
        assert!(f.signature.contains("r1") && f.signature.contains("r3"), "r1 and r3 are read: {}", f.signature);
        // e6ef8073 uxtb r8, r3
        let f = decomp_a32_as(words(&[0xe6ef8073, 0xe5c18000, 0xe12fff1e]), DecompStyle::Ssa);
        assert!(f.pseudo.iter().any(|l| l.contains("r8.1 = (uint8_t)r3;")), "{:#?}", f.pseudo);
        assert!(f.signature.contains("r1") && f.signature.contains("r3"), "r1 and r3 are read: {}", f.signature);
    }

    /// x86-64: `mov r8, r9; crc32 eax, r8b; ret`. `r9` is read through the
    /// copy, so it is a parameter, and the copy stays.
    #[test]
    fn a_copy_only_an_unlifted_x64_instruction_reads_is_kept() {
        // 4d 89 c8 mov r8, r9; f2 41 0f 38 f0 c0 crc32 eax, r8b; c3 ret
        let f = decomp(vec![0x4d, 0x89, 0xc8, 0xf2, 0x41, 0x0f, 0x38, 0xf0, 0xc0, 0xc3], DecompStyle::Ssa);
        assert!(f.pseudo.iter().any(|l| l.contains("r8.1 = r9;")), "{:#?}", f.pseudo);
        assert!(f.signature.contains("r9"), "r9 is read: {}", f.signature);
    }

    /// `str r3, [r1]; strb r2, [r1]; ldr r0, [r1]; bx lr` — the `strb` is `asm`
    /// and overwrites the low byte. It was not a store to anything, so the load
    /// was forwarded the first store's `r3`; the processor returns `r3` with its
    /// low byte replaced by `r2`'s. Nothing here can compute that, so the load
    /// has to stay a load.
    #[test]
    fn an_unlifted_store_is_not_forwarded_across() {
        // e5813000 str r3, [r1]; e5c12000 strb r2, [r1]; e5910000 ldr r0, [r1]
        let f = decomp_a32_as(words(&[0xe5813000, 0xe5c12000, 0xe5910000, 0xe12fff1e]), DecompStyle::Ssa);
        let ret = return_line(&f);
        assert!(!ret.contains("r3") && ret.contains("*r1"), "the load reads memory: {ret}");
        // 89 11 mov [rcx], edx; 44 0f c3 01 movnti [rcx], r8d; 8b 01 mov eax, [rcx]; c3 ret
        let f = decomp(vec![0x89, 0x11, 0x44, 0x0f, 0xc3, 0x01, 0x8b, 0x01, 0xc3], DecompStyle::Ssa);
        let ret = return_line(&f);
        assert!(!ret.contains("rdx") && ret.contains("*rcx"), "the load reads memory: {ret}");
    }

    /// …and an unlifted instruction that touches no memory does **not** stop
    /// forwarding: the fix above must not cost every function with one `asm`
    /// line its forwarded loads.
    #[test]
    fn an_unlifted_instruction_without_a_memory_operand_is_forwarded_across() {
        // e5813000 str r3, [r1]; e1a02162 ror r2, r2, #2; e5910000 ldr r0, [r1]
        let f = decomp_a32_as(words(&[0xe5813000, 0xe1a02162, 0xe5910000, 0xe12fff1e]), DecompStyle::Ssa);
        assert_eq!(return_line(&f), "return r3;", "{:#?}", f.pseudo);
        // 89 11 mov [rcx], edx; f2 45 0f 38 f0 c8 crc32 r9d, r8b; 8b 01 mov eax, [rcx]
        let f = decomp(vec![0x89, 0x11, 0xf2, 0x45, 0x0f, 0x38, 0xf0, 0xc8, 0x8b, 0x01, 0xc3], DecompStyle::Ssa);
        let ret = return_line(&f);
        assert!(ret.contains("rdx") && !ret.contains("*rcx"), "forwarded: {ret}");
    }

    /// `mov [rsp+8], rcx; crc32 eax, dword ptr [rsp+8]; ret` — the `crc32` is
    /// `asm` and reads the slot. It was no load to dead-store elimination, so
    /// the store went, and `rcx` with it: the function read a stack slot
    /// nothing had written.
    #[test]
    fn a_store_an_unlifted_instruction_may_read_is_kept() {
        // 48 89 4c 24 08 mov [rsp+8], rcx; f2 0f 38 f1 44 24 08 crc32 eax, [rsp+8]; c3 ret
        let f = decomp(vec![0x48, 0x89, 0x4c, 0x24, 0x08, 0xf2, 0x0f, 0x38, 0xf1, 0x44, 0x24, 0x08, 0xc3], DecompStyle::Ssa);
        assert!(f.pseudo.iter().any(|l| l.trim().ends_with("= rcx;")), "the store stays: {:#?}", f.pseudo);
        assert!(f.signature.contains("rcx"), "{}", f.signature);
    }

    /// `mov edi, 1; mov eax, 60; syscall; ret` — the system call consumes
    /// `rdi`, which nothing on this side of it records: iced lists no such
    /// read. Its reads are unknown, so every definition reaching it stays; the
    /// argument used to be deleted as dead.
    #[test]
    fn an_instruction_that_may_read_any_register_keeps_every_definition() {
        // bf 01 00 00 00 mov edi, 1; b8 3c 00 00 00 mov eax, 60; 0f 05 syscall; c3 ret
        let f = decomp(vec![0xbf, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3], DecompStyle::Ssa);
        assert!(f.pseudo.iter().any(|l| l.contains("rdi.1 = 0x1;")), "the argument stays: {:#?}", f.pseudo);
        assert!(!f.signature.contains("rcx"), "an unknown read is not a parameter: {}", f.signature);
    }

    /// The shape of every system-call wrapper in a C library (`renameat`,
    /// `kill`, …): `mov eax, NR; syscall; cmp rax, -0x1000; ja error; ret`.
    /// The kernel returns in `rax`, and nothing said so — the test compared the
    /// call number `0x108` with the error range, and the success path returned
    /// it.
    #[test]
    fn a_system_call_wrapper_tests_the_result_not_the_call_number() {
        // b8 08 01 00 00 mov eax, 0x108; 0f 05 syscall; 48 3d 00 f0 ff ff
        // cmp rax, -0x1000; 77 01 ja +1; c3 ret; f7 d8 neg eax; c3 ret (llvm-mc)
        let f = decomp(
            vec![0xb8, 0x08, 0x01, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x3d, 0x00, 0xf0, 0xff, 0xff, 0x77, 0x01, 0xc3, 0xf7, 0xd8, 0xc3],
            DecompStyle::Ssa,
        );
        let cond = f.pseudo.iter().map(|l| l.trim()).find(|l| l.starts_with("if ")).unwrap_or_else(|| panic!("no `if` in {:#?}", f.pseudo));
        let called = f.pseudo.iter().position(|l| l.trim() == "rax.1 = 0x108;").unwrap_or_else(|| panic!("{:#?}", f.pseudo));
        assert!(!cond.contains("rax.1 "), "the test reads what the kernel returned, not the number: {cond}\n{:#?}", f.pseudo);
        assert!(
            !f.pseudo[called + 1..].iter().any(|l| l.contains("rax.1;") || l.contains("rax.1)")),
            "the call number is not read after the system call: {:#?}",
            f.pseudo
        );
    }

    /// The shape of `clock_getres` in a C library, on Win64's registers: an
    /// indirect call that passes the first two arguments through, a third
    /// argument register the code never touches, and a `syscall` reachable
    /// both before and after the call. The syscall may read any register, so
    /// it keeps every register's phi alive, and the coalescing map then named
    /// `r8.0` — which the padding test read as "is a parameter". The call
    /// printed a third argument, `v3`, that does not exist.
    #[test]
    fn a_register_only_a_bound_read_keeps_alive_is_not_a_call_argument() {
        // 48 83 ec 28 sub rsp,0x28; 48 8b 04 25 00 20 00 00 mov rax,[0x2000];
        // 48 85 c0 test rax,rax; 74 22 je sys; 48 89 54 24 08 mov [rsp+8],rdx;
        // 89 4c 24 04 mov [rsp+4],ecx; ff d0 call rax; 48 63 d0 movsxd rdx,eax;
        // 48 83 fa da cmp rdx,-0x26; 8b 4c 24 04 mov ecx,[rsp+4];
        // 48 8b 54 24 08 mov rdx,[rsp+8]; 74 05 je sys; 48 83 c4 28 add rsp,0x28;
        // c3 ret; sys: b8 e5 00 00 00 mov eax,0xe5; 0f 05 syscall;
        // 48 83 c4 28 add rsp,0x28; c3 ret
        let f = decomp(
            vec![
                0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x22,
                0x48, 0x89, 0x54, 0x24, 0x08, 0x89, 0x4c, 0x24, 0x04, 0xff, 0xd0, 0x48, 0x63, 0xd0, 0x48, 0x83, 0xfa,
                0xda, 0x8b, 0x4c, 0x24, 0x04, 0x48, 0x8b, 0x54, 0x24, 0x08, 0x74, 0x05, 0x48, 0x83, 0xc4, 0x28, 0xc3,
                0xb8, 0xe5, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x83, 0xc4, 0x28, 0xc3,
            ],
            DecompStyle::Ssa,
        );
        let call = f.pseudo.iter().find(|l| l.contains("(*rax")).unwrap_or_else(|| panic!("no call in {:#?}", f.pseudo));
        assert!(call.trim().ends_with("(*rax.1)(rcx, rdx);"), "exactly the two arguments the code passes: {call}");
    }

    /// `movsd xmm0,[rsi]; aesenc xmm0,xmm1; movsd [rdi],xmm0` stores what
    /// `aesenc` computed. The fallback invalidated `zmm0`, a name nothing in
    /// the IR reads, and the store took the value loaded before it.
    #[test]
    fn an_unlifted_vector_instruction_replaces_the_register_it_writes() {
        let f = decomp(
            vec![0xf2, 0x0f, 0x10, 0x06, 0x66, 0x0f, 0x38, 0xdc, 0xc1, 0xf2, 0x0f, 0x11, 0x07, 0xc3],
            DecompStyle::Ssa,
        );
        let store = f.pseudo.iter().find(|l| l.contains("*rdi")).unwrap_or_else(|| panic!("no store in {:#?}", f.pseudo));
        assert!(!store.contains("rsi") && !store.contains("xmm0.1"), "the store is of the aesenc result: {store}");
    }

    /// `ldr r0, [r1], #4; mov r0, r1; bx lr` returns `r1 + 4` — post-indexing
    /// writes the base back. It returned the old `r1`.
    #[test]
    fn a_post_indexed_load_kept_as_asm_writes_its_base_back() {
        // e4910004 ldr r0, [r1], #4; e1a00001 mov r0, r1
        let f = decomp_a32_as(words(&[0xe4910004, 0xe1a00001, 0xe12fff1e]), DecompStyle::Ssa);
        assert_ne!(return_line(&f), "return r1;", "{:#?}", f.pseudo);
    }

    /// `str r3, [sp, #-8]; push {r4, lr}; ldr r0, [sp]; pop {r4, pc}` returns
    /// `r4`: the `push` overwrote the slot the `str` wrote. With no stores on
    /// the `push`, the load was forwarded the `str`'s `r3`.
    #[test]
    fn a_slot_a_push_overwrites_is_not_forwarded_from_before_it() {
        // e50d3008 str r3, [sp, #-8]; e92d4010 push {r4, lr};
        // e59d0000 ldr r0, [sp]; e8bd8010 pop {r4, pc} (llvm-mc)
        let f = decomp_a32_as(words(&[0xe50d3008, 0xe92d4010, 0xe59d0000, 0xe8bd8010]), DecompStyle::Ssa);
        assert_eq!(return_line(&f), "return r4.0;", "{:#?}", f.pseudo);
    }

    /// `push {r4, lr}; mov r4, #9; pop {r4, lr}; mov r0, r4; bx lr` returns
    /// the `r4` it was called with: a callee-saved register comes back off the
    /// stack as itself. The `pop` used to restore an unknown.
    #[test]
    fn a_register_pushed_and_popped_comes_back_as_itself() {
        // e92d4010 push {r4, lr}; e3a04009 mov r4, #9; e8bd4010 pop {r4, lr};
        // e1a00004 mov r0, r4; e12fff1e bx lr (llvm-mc)
        let f = decomp_a32_as(words(&[0xe92d4010, 0xe3a04009, 0xe8bd4010, 0xe1a00004, 0xe12fff1e]), DecompStyle::Ssa);
        assert_eq!(return_line(&f), "return r4.0;", "{:#?}", f.pseudo);
    }

    /// `mov r0, #5; cmp r1, #0; blne f; bx lr` — when the call is taken `r0`
    /// is its result, so the function does not return 5. And the call's
    /// argument registers keep their definitions alive without becoming
    /// parameters: only `r1` is read by this function.
    #[test]
    fn a_conditional_call_kept_as_asm_clobbers_and_claims_no_parameters() {
        // e3a00005 mov r0, #5; e3510000 cmp r1, #0; 1b000000 blne; e12fff1e bx lr
        let f = decomp_a32_as(words(&[0xe3a00005, 0xe3510000, 0x1b000000, 0xe12fff1e]), DecompStyle::Ssa);
        let ret = return_line(&f);
        assert!(!ret.contains("r0.1") && !ret.contains("0x5"), "r0 is the call's on one path: {ret}");
        assert!(!f.signature.contains("r2") && !f.signature.contains("r3"), "a call's argument reads are not parameters: {}", f.signature);
    }

    /// AArch64: `mov x0, #5; ldr d0, [x1]; ret` returns 5. The load's
    /// transfer register is `d0`; reading its field as a general register
    /// invalidated `x0`.
    #[test]
    fn an_arm64_floating_point_load_leaves_x0_alone() {
        // d28000a0 mov x0, #5; fd400020 ldr d0, [x1]; d65f03c0 ret
        let f = decomp_arm64(words(&[0xd28000a0, 0xfd400020, 0xd65f03c0]));
        assert!(f.pseudo.iter().any(|l| l.contains("= 0x5;")) && return_line(&f) == "return x0.1;", "{:#?}", f.pseudo);
    }

    /// The register a `mov _, #5` defined, if the function still states it.
    fn defined_as_five(f: &PseudoFunction) -> Option<String> {
        f.pseudo.iter().find_map(|l| l.trim().strip_suffix(" = 0x5;").map(str::to_string))
    }

    /// Whether `line` names the SSA variable `var` (`x2.1`) as a whole token —
    /// not `x2.10`, not `x12.1`.
    fn names_var(line: &str, var: &str) -> bool {
        line.match_indices(var).any(|(i, _)| {
            let before = line[..i].chars().next_back();
            let after = line[i + var.len()..].chars().next();
            !before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') && !after.is_some_and(|c| c.is_ascii_digit())
        })
    }

    /// AArch64 instructions the access table had no row for wrote no register
    /// as far as the IR knew, so the value from before them stayed readable:
    /// each of these returned 5. Every word is llvm-mc's (`-triple=aarch64`).
    #[test]
    fn an_arm64_instruction_outside_the_table_replaces_what_it_writes() {
        let cases: &[(&str, &[u32])] = &[
            // d28000a0 mov x0, #5; d53bd040 mrs x0, tpidr_el0
            ("mrs", &[0xd28000a0, 0xd53bd040]),
            // 9e660000 fmov x0, d0
            ("fmov x0, d0", &[0xd28000a0, 0x9e660000]),
            // 0e0c3c20 mov w0, v1.s[1] (umov)
            ("umov", &[0xd28000a0, 0x0e0c3c20]),
            // d28000a2 mov x2, #5; c8027c83 stxr w2, x3, [x4]; aa0203e0 mov x0, x2
            ("stxr status", &[0xd28000a2, 0xc8027c83, 0xaa0203e0]),
            // d28000a5 mov x5, #5; c805fce6 stlxr w5, x6, [x7]; aa0503e0 mov x0, x5
            ("stlxr status", &[0xd28000a5, 0xc805fce6, 0xaa0503e0]),
            // d28000a1 mov x1, #5; c87f0440 ldxp x0, x1, [x2]; aa0103e0 mov x0, x1
            ("ldxp second register", &[0xd28000a1, 0xc87f0440, 0xaa0103e0]),
        ];
        let mut stale = Vec::new();
        for (what, body) in cases {
            let mut code = body.to_vec();
            code.push(0xd65f03c0); // ret
            let f = decomp_arm64(words(&code));
            let ret = return_line(&f);
            if defined_as_five(&f).is_some_and(|v| names_var(ret, &v)) || ret.contains("0x5") {
                stale.push(format!("{what}: {ret}"));
            }
        }
        assert!(stale.is_empty(), "the value from before the instruction is returned:\n  {}", stale.join("\n  "));
    }

    /// A SIMD structure load post-indexed writes its base back: by the bytes it
    /// transferred for the immediate form, by `Xm` for the register form. The
    /// lift returned the old base for both.
    #[test]
    fn an_arm64_simd_post_indexed_load_writes_its_base_back() {
        // 4cdf7020 ld1 {v0.16b}, [x1], #16; aa0103e0 mov x0, x1; d65f03c0 ret
        let f = decomp_arm64(words(&[0x4cdf7020, 0xaa0103e0, 0xd65f03c0]));
        assert!(return_line(&f).contains("(x1 + 0x10)"), "{:#?}", f.pseudo);
        // 4cc3a840 ld1 {v0.4s, v1.4s}, [x2], x3; aa0203e0 mov x0, x2; d65f03c0 ret
        let f = decomp_arm64(words(&[0x4cc3a840, 0xaa0203e0, 0xd65f03c0]));
        assert!(return_line(&f).contains("(x2 + x3)"), "{:#?}", f.pseudo);
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

        // Two constants: the global's exact start, and an interior offset. Each is
        // taken as an ADDRESS (`lea`-shaped `AddrOf(Const)`, `x = &g`) — the only
        // position `collect_const_addrs` now treats as an address, so that a plain
        // integer value is never mistaken for a pointer (see the string-recovery
        // test below). A bare `Assign { value: Const }` would be an integer here.
        let stmt = |dst: &str, v: i128| crate::ssa::SsaStmt {
            va: Va(0x1000),
            stmt: n0xis_arch::MicroStmt::Assign {
                dst: dst.into(),
                value: n0xis_arch::MicroExpr::AddrOf(Box::new(n0xis_arch::MicroExpr::constant(v, 64))),
            },
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
    fn string_recovery_resolves_a_pointer_but_never_an_integer_that_collides_with_it() {
        // Defect B: `recover_strings` drives off `collect_const_addrs`, which must
        // collect a constant ONLY where it is used as an ADDRESS. A plain integer
        // whose numeric value happens to equal a real string's address (here the
        // return value `mov $0x3000,%eax; ret`) must render as the integer, not
        // the string; a genuine pointer to that same string (`lea 0x3000(%rip)` →
        // `AddrOf(Const)`) must still resolve to the literal. Assert BOTH — a
        // restriction that made real strings vanish would trade one wrong answer
        // for another (the refusal trap).
        let snap = Snapshot::builder().region(Va(0x3000), b"hello, world\0".to_vec()).build();

        let block = |value: n0xis_arch::MicroExpr| {
            vec![SsaBlock {
                id: 0,
                start: Va(0x1000),
                end: Va(0x1010),
                terminator: "ret".into(),
                successors: Vec::new(),
                phis: Vec::new(),
                stmts: vec![crate::ssa::SsaStmt { va: Va(0x1000), stmt: n0xis_arch::MicroStmt::Return(Some(value)) }],
                condition: None,
            }]
        };

        // (a) The integer 0x3000 returned as a value — NOT an address. It must not
        // be mistaken for the string at 0x3000.
        let int_blocks = block(n0xis_arch::MicroExpr::constant(0x3000, 64));
        let int_strings = recover_strings(&[&int_blocks], &snap);
        assert_eq!(int_strings.get(&0x3000), None, "an integer return value must not resolve to a string");

        // (b) A genuine pointer to the string (`AddrOf(Const)`) still resolves.
        let ptr_blocks = block(n0xis_arch::MicroExpr::AddrOf(Box::new(n0xis_arch::MicroExpr::constant(0x3000, 64))));
        let ptr_strings = recover_strings(&[&ptr_blocks], &snap);
        assert_eq!(ptr_strings.get(&0x3000).map(String::as_str), Some("\"hello, world\""), "a real string reference must still resolve");
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
        let sig = RecoveredSignature { params: vec![], ret: ReturnType::Void, ret_registers: vec![], params_known: true };
        let name = "unsigned short __cdecl SomeLib::ReadValue(struct SomeLib::SomeFile *, unsigned int, unsigned int)";
        assert_eq!(format_signature(Va(0x1940), &sig, Some(name)), name);
    }

    #[test]
    fn a_plain_symbol_name_without_args_still_gets_the_recovered_signature() {
        // A plain C export (no parenthesized arg list) keeps the recovered
        // `ret name(params)` rendering — only a full prototype is verbatim.
        let sig = RecoveredSignature { params: vec![], ret: ReturnType::Void, ret_registers: vec![], params_known: true };
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

    fn decomp_with(code: Vec<u8>, style: DecompStyle, renames: &[(&str, &str)], types: &[(&str, &str)]) -> PseudoFunction {
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let cfg = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), 128)).unwrap();
        let map = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        DecompPass.run(&ctx, DecompInput { cfg, style, explain: false, strip_block_labels: true, var_names: map(renames), var_types: map(types), struct_defs: Default::default() }).unwrap()
    }

    fn decomp_renamed(code: Vec<u8>, style: DecompStyle, renames: &[(&str, &str)]) -> PseudoFunction {
        decomp_with(code, style, renames, &[])
    }

    /// `mov [rsp+8], rcx ; mov eax, [rsp+8] ; ret`: one parameter, one stack local.
    const PARAM_AND_LOCAL: [u8; 10] = [0x48, 0x89, 0x4c, 0x24, 0x08, 0x8b, 0x44, 0x24, 0x08, 0xc3];

    #[test]
    fn the_variable_list_is_what_the_page_shows() {
        for style in [DecompStyle::Goto, DecompStyle::Structured, DecompStyle::Ssa] {
            let f = decomp_renamed(PARAM_AND_LOCAL.to_vec(), style, &[]);
            let text = f.pseudo.join("\n");
            assert!(!f.variables.is_empty(), "{style:?}: no variables listed for {text}");
            for v in &f.variables {
                assert!(shows_as_name(&text, &v.name), "{style:?}: {v:?} is not on the page: {text}");
            }
            let param = f.variables.iter().find(|v| v.kind == VarKind::Param);
            assert_eq!(param.map(|v| v.key.as_str()), Some("rcx"), "{style:?}: {:?}\n{text}", f.variables);
        }
        let ssa = decomp_renamed(PARAM_AND_LOCAL.to_vec(), DecompStyle::Ssa, &[]);
        assert!(
            ssa.variables.iter().any(|v| v.kind == VarKind::Local && v.key == "local_8" && v.name == "local_8"),
            "{:?}\n{}",
            ssa.variables,
            ssa.pseudo.join("\n")
        );
    }

    #[test]
    fn a_renamed_variable_keeps_the_key_its_rename_is_stored_under() {
        let f = decomp_renamed(PARAM_AND_LOCAL.to_vec(), DecompStyle::Ssa, &[("rcx", "input"), ("local_8", "saved")]);
        let text = f.pseudo.join("\n");
        assert!(text.contains("input") && text.contains("saved"), "{text}");
        assert!(f.variables.contains(&DecompVar { name: "input".into(), key: "rcx".into(), kind: VarKind::Param }), "{:?}\n{text}", f.variables);
        assert!(f.variables.contains(&DecompVar { name: "saved".into(), key: "local_8".into(), kind: VarKind::Local }), "{:?}\n{text}", f.variables);
        assert!(!f.variables.iter().any(|v| v.name == "rcx" || v.name == "local_8"), "an old name is listed: {:?}", f.variables);
        assert!(!f.variables.iter().any(|v| v.key == "input" || v.key == "saved"), "a user's name used as a key: {:?}", f.variables);
    }

    /// `mov [rsp+8], rcx ; mov eax, [rsp+8] ; test rdx, rdx ; je +4 ; add rax, 1 ;
    /// ret`: two parameters, a stack local, and a value the two paths merge into.
    const EVERY_KIND: [u8; 19] = [
        0x48, 0x89, 0x4c, 0x24, 0x08, 0x8b, 0x44, 0x24, 0x08, 0x48, 0x85, 0xd2, 0x74, 0x04, 0x48, 0x83, 0xc0, 0x01, 0xc3,
    ];

    #[test]
    fn only_a_param_or_a_local_takes_a_type() {
        let plain = decomp_with(EVERY_KIND.to_vec(), DecompStyle::Ssa, &[], &[]);
        let text = plain.pseudo.join("\n");
        for kind in [VarKind::Param, VarKind::Local, VarKind::Value] {
            assert!(plain.variables.iter().any(|v| v.kind == kind), "no {kind:?} to test with: {:?}\n{text}", plain.variables);
        }
        for v in &plain.variables {
            let typed = decomp_with(EVERY_KIND.to_vec(), DecompStyle::Ssa, &[], &[(v.key.as_str(), "struct Probe *")]);
            let changed = typed.pseudo != plain.pseudo;
            assert_eq!(changed, v.kind != VarKind::Value, "{v:?}: a type {} the text\n{text}", if changed { "changed" } else { "did not change" });
        }
    }

    #[test]
    fn a_name_counts_only_as_a_whole_name() {
        assert!(shows_as_name("v1 = 0;", "v1"));
        assert!(!shows_as_name("v10 = 0;", "v1"));
        assert!(!shows_as_name("rsi.2 = 0;", "rsi"));
        assert!(shows_as_name("return rsi;", "rsi"));
        assert!(shows_as_name("x = (rsi.2 + 1.5);", "rsi.2"));
        assert!(shows_as_name("лічильник = 1;", "лічильник"));
        assert!(!shows_as_name("мій_лічильник = 1;", "лічильник"));
        assert!(!shows_as_name("anything", ""));
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
    /// `(void)` is a claim; `()` is C's own notation for "unspecified". The
    /// renderer printed the first when it meant the second — on a 32-bit
    /// caller-cleanup ABI nothing measures the arity, and seven of ten
    /// functions on a purpose-built target were told they take no arguments
    /// while taking one to three.
    #[test]
    fn an_unmeasured_parameter_list_renders_as_unspecified_not_as_none() {
        let unknown = RecoveredSignature { params: vec![], ret: ReturnType::Void, ret_registers: vec![], params_known: false };
        assert_eq!(format_signature(Va(0x1000), &unknown, Some("f")), "void f()");
        let none = RecoveredSignature { params: vec![], ret: ReturnType::Void, ret_registers: vec![], params_known: true };
        assert_eq!(format_signature(Va(0x1000), &none, Some("f")), "void f(void)");
    }

}

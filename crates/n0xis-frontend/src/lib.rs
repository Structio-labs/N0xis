// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! # n0xis-frontend — the shared frontend seam
//!
//! Everything a frontend must do *before* it can call a pass: turn
//! `--pid`/`--file`/`--snapshot`/`--remote-cmd`/`--bytes` into a source, pick
//! an ISA, and parse the address/size/byte-string arguments that every command
//! takes. None of it is analysis, all of it is identical for every frontend —
//! which is exactly why it belongs in one crate.
//!
//! Before this crate existed, `n0xis-cli` and `n0xis-mcp` each carried their
//! own copy of the source seam (`build_source` vs `source::resolve`), and the
//! copies had already drifted: the CLI never consulted the `.n0x/` session
//! default that `attach` writes, so `attach` then a bare `decomp pseudo`
//! worked through MCP and failed through the CLI, despite the docs promising
//! both. CONCEPT §3 rule 3 calls a contract duplicated across two sides a bug;
//! this is that bug's fix.
//!
//! ```text
//!   n0xis-cli ─┐
//!   n0xis-mcp ─┼─▶ n0xis-frontend ─▶ n0xis-pipeline ─▶ n0xis-core
//!   n0xis-hud ─┘   (source + arch + argument parsing)
//! ```
//!
//! Frontends stay free to differ where they genuinely differ (clap flags vs
//! JSON tool arguments, text vs structured output) — but never on what `--pid`
//! *means*.

pub mod annotation_syms;
pub mod arch;
pub mod flirt_syms;
pub mod il2cpp_caps;
pub mod method_caps;
pub mod parse;
pub mod project_caps;
pub mod registry;
pub mod source;

pub use arch::{pick_arch, resolve_arch};
pub use registry::{Capability, Origin, Plugin, Registry, build_registry};
pub use parse::{opt_hex, parse_hex_bytes, parse_hex_or_decimal_f64, parse_hex_or_decimal_u64, parse_hex_or_decimal_usize, strip_hex_marker};
pub use source::{FrontendError, ResolvedSource, SourceSpec, Src, base_for_module, load_snapshot, module_base_of, scan_range};

/// Every function of the target, `.pdata`-exact when the format offers it and a
/// prologue scan otherwise — the discovery both whole-program passes
/// (`function summary`, `function typeflow`) start from. `limit == 0` means
/// every function.
///
/// Shared rather than duplicated because the two passes must reason over the
/// *same* program: a type propagated into a function the other pass never saw
/// is a fact nobody can check.
pub fn discovered_functions(
    ctx: &n0xis_core::Ctx,
    src: &source::Src,
    module: Option<&str>,
    limit: usize,
) -> Vec<n0xis_contracts::Va> {
    let mut all: Vec<n0xis_contracts::Va> = src
        .module_base()
        .and_then(|b| n0xis_core::discover_pdata(ctx.source, b).ok())
        .map(|f| f.into_iter().map(|c| c.va).collect())
        .unwrap_or_default();
    if all.is_empty() {
        for (start, size) in src.code_ranges_of(module) {
            if let Ok(art) = n0xis_core::Pass::run(
                &n0xis_core::DiscoverPass,
                ctx,
                n0xis_core::DiscoverInput { start, size: size as usize, limit: 0, offset: 0 },
            ) {
                all.extend(art.functions.into_iter().map(|c| c.va));
            }
        }
        all.sort_by_key(|v| v.get());
        all.dedup();
    }
    if limit != 0 {
        all.truncate(limit);
    }
    all
}

/// The persisted whole-program type store, adapted to the core's
/// [`TypeFlowLookup`](n0xis_core::TypeFlowLookup) seam and memoized per process
/// (it is rewritten only by `analyze --typeflow`, and re-parsing it on every
/// decompile would undo the point of persisting it).
pub struct PersistedTypeFlow(std::sync::Arc<n0xis_project::type_flow::TypeFlow>);

static TYPE_FLOW_MEMO: std::sync::Mutex<Option<(u64, std::sync::Arc<n0xis_project::type_flow::TypeFlow>)>> =
    std::sync::Mutex::new(None);

impl PersistedTypeFlow {
    /// Load (or reuse) the project's store. Empty when `analyze --typeflow` has
    /// not run, in which case typing is per-function exactly as before.
    pub fn load() -> Self {
        let sig = annotation_syms::project_file_signature("type-flow.json");
        if let Ok(memo) = TYPE_FLOW_MEMO.lock()
            && let Some((cached, data)) = memo.as_ref()
            && *cached == sig
        {
            return PersistedTypeFlow(std::sync::Arc::clone(data));
        }
        let data = std::sync::Arc::new(n0xis_project::type_flow::load().unwrap_or_default());
        if let Ok(mut memo) = TYPE_FLOW_MEMO.lock() {
            *memo = Some((sig, std::sync::Arc::clone(&data)));
        }
        PersistedTypeFlow(data)
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The persisted class-layout store, adapted to the core's
/// [`ClassLayoutLookup`](n0xis_core::ClassLayoutLookup) seam and memoized per
/// process — same reasoning as [`PersistedTypeFlow`]: it is rewritten only by
/// `analyze --layout`, and re-parsing it on every decompile would undo the point
/// of persisting it.
pub struct PersistedLayout(std::sync::Arc<n0xis_project::class_layout::ClassLayouts>);

static LAYOUT_MEMO: std::sync::Mutex<Option<(u64, std::sync::Arc<n0xis_project::class_layout::ClassLayouts>)>> =
    std::sync::Mutex::new(None);

impl PersistedLayout {
    /// Load (or reuse) the project's store. Empty when `analyze --layout` has
    /// not run, in which case a field dispatch stays indirect exactly as before.
    pub fn load() -> Self {
        let sig = annotation_syms::project_file_signature("class-layout.json");
        if let Ok(memo) = LAYOUT_MEMO.lock()
            && let Some((cached, data)) = memo.as_ref()
            && *cached == sig
        {
            return PersistedLayout(std::sync::Arc::clone(data));
        }
        let data = std::sync::Arc::new(n0xis_project::class_layout::load().unwrap_or_default());
        if let Ok(mut memo) = LAYOUT_MEMO.lock() {
            *memo = Some((sig, std::sync::Arc::clone(&data)));
        }
        PersistedLayout(data)
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl n0xis_core::ClassLayoutLookup for PersistedLayout {
    fn field_type(&self, class: &str, offset: i64) -> Option<&str> {
        self.0.field_type(class, offset)
    }
    /// Varies with the run that produced the store and with how much of it
    /// actually carries a type — so the decompile cache is perturbed exactly
    /// when a rendered dispatch could differ.
    fn layout_fingerprint(&self) -> String {
        if self.0.is_empty() {
            String::new()
        } else {
            format!("layout:{}:{}:{}", self.0.generation, self.0.classes.len(), self.0.typed_fields())
        }
    }
}

/// Convert the core pass's store into the persisted shape, keeping only what is
/// worth writing: a class with no fields describes nothing.
pub fn layout_to_persisted(
    generation: impl Into<String>,
    store: &n0xis_core::LayoutStore,
) -> n0xis_project::class_layout::ClassLayouts {
    n0xis_project::class_layout::ClassLayouts {
        generation: generation.into(),
        classes: store
            .classes
            .iter()
            .filter(|(_, c)| !c.fields.is_empty())
            .map(|(name, c)| {
                let fields = c
                    .fields
                    .iter()
                    .map(|f| {
                        (
                            f.offset.to_string(),
                            n0xis_project::class_layout::Field {
                                size_bits: f.size_bits,
                                signed: f.signed,
                                access_count: f.access_count,
                                methods: f.methods,
                                // An ambiguous field is persisted *without* a
                                // type: the disagreement is the answer.
                                ty: if f.ty_ambiguous { None } else { f.ty.clone() },
                            },
                        )
                    })
                    .collect();
                (name.clone(), n0xis_project::class_layout::Class { methods: c.methods, extent: c.extent, fields })
            })
            .collect(),
    }
}

impl n0xis_core::TypeFlowLookup for PersistedTypeFlow {
    fn param(&self, va: u64, index: usize) -> Option<&str> {
        self.0.param(va, index)
    }
    fn ret(&self, va: u64) -> Option<&str> {
        self.0.ret(va)
    }
    /// Varies with the run that produced the store and with how much it holds,
    /// and is empty when there is nothing — so the decompile cache is perturbed
    /// exactly when a rendered type could differ.
    fn type_flow_fingerprint(&self) -> String {
        if self.0.is_empty() {
            String::new()
        } else {
            format!("flow:{}:{}:{}", self.0.generation, self.0.params.len(), self.0.rets.len())
        }
    }
}

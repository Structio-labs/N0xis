// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! # n0xis-core — pure analysis
//!
//! The analysis brain: a set of [`Pass`]es over the [`Arch`](n0xis_arch::Arch)
//! seam and the source seams ([`MemorySource`](n0xis_sources::MemorySource) &
//! friends). **No I/O, no OS** — this crate names only abstractions, so it can
//! be tested end-to-end against the [`Snapshot`](n0xis_sources::Snapshot) mock
//! with zero Windows APIs linked. That property is the Phase 1 exit test and
//! the proof the boundaries hold (CONCEPT §4).
//!
//! Phase 1 ships the pass framework and one trivial pass, [`DecodePass`]. The
//! optimizing decompiler passes (SSA, propagate/fold, DCE, structuring) are
//! added in Phase 3 as more `impl Pass` — same shape, same context.

mod aob;
mod aot;
mod aslr;
mod bindings;
mod constident;
mod decode;
mod decomp;
mod deobfuscate;
mod demangle;
mod diff;
mod devirt;
mod discover;
mod dissect;
mod dom;
mod dot;
mod eh;
mod gamegrep;
mod icalls;
mod coalesce;
mod klass;
mod ir;
mod lift;
mod manifest;
mod noreturn;
mod noreturn_ipa;
mod optimize;
mod pointer;
mod profile;
mod provenance;
mod render;
mod scan;
mod signatures;
mod summary;
mod typeprop;
mod slice;
mod ssa;
mod structural;
mod structure;
mod sigvalidate;
mod rtti;
mod switch;
mod trace;
mod trampoline;
mod typeinfer;
mod ui_locate;
mod valueset;
mod xref;
mod xref_string;

pub use aob::{parse_aob, AobArtifact, AobByte, AobInput, AobScanPass};
pub use aot::{parse_aot, AotArtifact, AotSymbol, RvaSize};
pub use aslr::{rebase, rva_of, va_at};
pub use bindings::{Binding, BindingsArtifact, BindingsInput, BindingsPass};
pub use constident::{identify_f64, identify_u64, ConstMatch};
pub use gamegrep::{rank as game_grep_rank, Document, GameGrepArtifact, RankOptions, RankedHit, TermHit};
pub use sigvalidate::{
    parse_mask, parse_sample, validate as sig_validate, MaskByte, MaskFinding, SigValidateArtifact,
    SigValidateInput, MIN_INDEPENDENT_SAMPLES,
};
pub use structural::{FieldSpec, StructuralHit, StructuralScanArtifact, StructuralScanInput, StructuralScanPass};
pub use ui_locate::{
    aabb_plausible, rect_overlap, Aabb, AabbLayout, CoordSpace, Rect, SpaceBound, UiElementHit,
    UiLocateArtifact, UiLocateInput, UiLocatePass,
};
pub use decode::{DecodeInput, DecodeOutput, DecodePass};
pub use decomp::{DecompInput, DecompPass, DecompStyle, PseudoFunction};
pub use deobfuscate::{DeobfuscateArtifact, DeobfuscatePass, JunkInsn, OpaqueBranch};
pub use demangle::demangle;
pub use diff::{DiffArtifact, DiffHunk, DiffInput, DiffOp, DiffPass};
pub use klass::{ClassScanArtifact, ClassScanInput, ClassScanPass, ClassSummary, KlassArtifact, KlassField, KlassInput, KlassPass, LayoutEvidence};
pub use icalls::{Icall, IcallArtifact, IcallInput, IcallPass, ResolverCount};
pub use discover::{discover_pdata, DiscoverArtifact, DiscoverInput, DiscoverPass, FunctionCandidate};
pub use summary::{summarize, FunctionSummary, SummaryInput, SummaryPass};
pub use devirt::{devirtualize, Devirtualized};
pub use typeprop::{TypePropInput, TypePropagatePass, TypeStore};
pub use eh::{landing_pads, scan_eh_frame, EhFunction, EhRegion};
pub use profile::{advisories, assemble_profile, profile_image, Advisory, EngineHint, ExportInfo, FoldedExports, ImageProfile, SectionInfo};
pub use dissect::{DissectArtifact, DissectField, DissectInput, DissectPass, GuessedKind};
pub use dot::{DotArtifact, dot};
pub use ir::{
    CfgArtifact, CfgBlock, CfgInput, CfgPass, CfgStats, Callsite, DefUse, IrInsn, Successor, explain,
};
pub use lift::{LiftPass, LiftedBlock, LiftedFunction, LiftedStmt};
pub use manifest::{ManifestArtifact, ManifestCandidate, ManifestEntry, ManifestInput, ManifestPass};
pub use noreturn::is_known_noreturn;
pub use noreturn_ipa::{propagate_noreturn, NoReturnArtifact, NoReturnInput, NoReturnPropagatePass};
pub use optimize::{OptArtifact, OptDeltaEntry, OptimizePass};
pub use pointer::{resolve_pointer_path, PointerPath, PointerPathArtifact, PointerPathInput, PointerPathPass, PointerRoot};
pub use provenance::{ProvenanceEntry, ProvenanceGraph, ProvenanceHit, ProvenanceInput, ProvenancePass};
pub use render::{render_condition, render_expr, render_stmt, negate_condition, RenderNames};
pub use scan::{
    FilterCriterion, FilterInput, FilterPass, GroupArtifact, GroupField, GroupFieldHit, GroupHit, GroupScanInput, GroupScanPass, RegionData,
    RegionState, ScanCriterion, ScanInput, ScanMatch, ScanPass, ScanReport, ScanState, ScanValue, Slot, ValueType, PREVIEW_LIMIT,
};
pub use signatures::{known_signature, KnownParam, KnownSignature};
pub use slice::{SliceArtifact, SliceNode, slice};
pub use ssa::{Phi, PhiInput, SsaArtifact, SsaBlock, SsaPass, SsaStmt};
pub use structure::{StructuredOutput, structure};
pub use rtti::{demangle_rtti_name, rtti_symbol_map, scan_itanium_rtti, scan_msvc_rtti, RttiVtable};
pub use switch::{ResolvedSwitch, SWITCH_CASE_CONFIDENCE, resolve_switch};
pub use typeinfer::{
    CType, FieldAccess, LocalVar, ParamInfo, RecoveredSignature, RecoveredType, TypeArtifact,
    TypeInferInput, TypeInferPass,
};
pub use trace::{TraceArtifact, TraceInput, TraceNode, TracePass};
pub use trampoline::{build_trampoline, near_jmp};
pub use valueset::{alias, AliasResult, ValueSet, ValueSetArtifact, ValueSetPass};
pub use xref::{XrefArtifact, XrefDir, XrefEntry, XrefIndex, XrefInput, XrefPass, build_xref_index, xref_kind};
pub use xref_string::{StringHit, StringXrefArtifact, StringXrefInput, StringXrefPass};

use n0xis_arch::Arch;
use n0xis_sources::{MemorySource, ModuleProvider, SymbolProvider};

/// Anything a pass can fail with.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error(transparent)]
    Source(#[from] n0xis_sources::SourceError),
    #[error(transparent)]
    Decode(#[from] n0xis_arch::DecodeError),
    #[error("{0}")]
    Other(String),
}

/// The analysis context handed to every [`Pass`]: the seams it may use, and
/// nothing else. A pass reads bytes through [`source`](Ctx::source), decodes
/// through [`arch`](Ctx::arch), and optionally resolves names/modules — it can
/// never reach past these to an OS call.
pub struct Ctx<'a> {
    pub source: &'a dyn MemorySource,
    pub arch: &'a dyn Arch,
    pub symbols: Option<&'a dyn SymbolProvider>,
    pub modules: Option<&'a dyn ModuleProvider>,
    /// Entry addresses of functions proven never to return — the output of the
    /// whole-program noreturn fixpoint ([`NoReturnPropagatePass`]). When set, a
    /// direct `call` to one of these ends its block like a call to a known
    /// noreturn import, so a caller's dead fall-through is pruned even when the
    /// callee is one of N0xis's *own* discovered functions, not a named import
    /// (ROADMAP Phase 10, priority 0 — the CFG-fidelity follow-on). `None` =
    /// intraprocedural analysis with imports as the only noreturn oracle.
    pub noreturn: Option<&'a std::collections::HashSet<n0xis_contracts::Va>>,
    /// Recovered C++ vtable address → class name, from [`scan_msvc_rtti`]
    /// (ROADMAP Phase 10 item 7). The frontend scans `.rdata` once and attaches
    /// the map so a pass can name a vtable constant: the constructor idiom
    /// `*this = 0x180021548` reads `*this = &std::exception::vtable`, and the
    /// `this` pointer types to that class. `None` on a non-PE/non-MSVC target
    /// (ELF, live, stripped) — every such site renders exactly as before.
    pub vtables: Option<&'a std::sync::Arc<std::collections::HashMap<u64, String>>>,
    /// Exception edges for the function under analysis: protected ranges and the
    /// landing pads they unwind to ([`scan_eh_frame`]). A landing pad has **no
    /// incoming branch** — the personality routine enters it during unwinding —
    /// so without this it is an unreachable island in the CFG, or (before the
    /// extent was known) not decoded at all. With it, the pad becomes a block
    /// leader and every block overlapping a protected range gains an `eh`
    /// successor. `None` = exactly the previous behaviour, so a PE, a stripped
    /// image or a target with no `.eh_frame` is unaffected.
    pub eh: Option<&'a [crate::EhRegion]>,
    /// Whole-program propagated types ([`TypePropagatePass`]), as
    /// `(function VA, parameter index) → type name` and `VA → return type`.
    /// Consulted **only where local inference found nothing better** — a type a
    /// function proved about itself always wins over one inferred from its
    /// callers. `None` = per-function typing exactly as before.
    pub type_flow: Option<&'a dyn crate::TypeFlowLookup>,
}

/// The whole-program type store, as the decompiler consumes it. A trait so the
/// core never depends on where the store came from (a live pass, or the JSON
/// `analyze` persisted) — the same Code-seam discipline as `SymbolProvider`.
pub trait TypeFlowLookup {
    /// Propagated type of parameter `index` of the function at `va`.
    fn param(&self, va: u64, index: usize) -> Option<&str>;
    /// Propagated return type of the function at `va`.
    fn ret(&self, va: u64) -> Option<&str>;

    /// A token identifying **which types this store will give**, folded into the
    /// decompile-cache key. Load-bearing for the same reason
    /// [`SymbolProvider::symbol_fingerprint`](n0xis_sources::SymbolProvider::symbol_fingerprint)
    /// is: a decompile cached before `analyze --typeflow` ran embeds the old,
    /// untyped rendering, and without this it would keep being served.
    fn type_flow_fingerprint(&self) -> String {
        String::new()
    }
}

impl<'a> Ctx<'a> {
    pub fn new(source: &'a dyn MemorySource, arch: &'a dyn Arch) -> Self {
        Ctx {
            source,
            arch,
            symbols: None,
            modules: None,
            noreturn: None,
            vtables: None,
            eh: None,
            type_flow: None,
        }
    }
    pub fn with_symbols(mut self, symbols: &'a dyn SymbolProvider) -> Self {
        self.symbols = Some(symbols);
        self
    }
    pub fn with_modules(mut self, modules: &'a dyn ModuleProvider) -> Self {
        self.modules = Some(modules);
        self
    }
    /// Attach a set of proven-noreturn function addresses (see the field docs).
    pub fn with_noreturn(mut self, noreturn: &'a std::collections::HashSet<n0xis_contracts::Va>) -> Self {
        self.noreturn = Some(noreturn);
        self
    }
    /// Attach the recovered vtable-address → class-name map (see the field docs).
    pub fn with_vtables(mut self, vtables: &'a std::sync::Arc<std::collections::HashMap<u64, String>>) -> Self {
        self.vtables = Some(vtables);
        self
    }
    /// Attach this function's exception regions (see the field docs).
    pub fn with_eh(mut self, eh: &'a [crate::EhRegion]) -> Self {
        self.eh = Some(eh);
        self
    }
    /// Attach the whole-program type store (see the field docs).
    pub fn with_type_flow(mut self, flow: &'a dyn crate::TypeFlowLookup) -> Self {
        self.type_flow = Some(flow);
        self
    }
}

/// One analysis step with a typed input/output contract, à la LLVM passes /
/// Bevy systems. Every capability in N0xis is (or becomes) a `Pass`, and each
/// emits a schema'd artifact the frontends can request individually.
pub trait Pass {
    type In;
    type Out;

    /// Stable id, linked to the emitted schema (see `n0xis-contracts::schema`).
    fn name(&self) -> &'static str;

    /// Run the pass against `ctx`.
    fn run(&self, ctx: &Ctx, input: Self::In) -> Result<Self::Out, CoreError>;
}

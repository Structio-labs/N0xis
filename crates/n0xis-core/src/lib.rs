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
mod aslr;
mod bindings;
mod constident;
mod decode;
mod decomp;
mod deobfuscate;
mod demangle;
mod diff;
mod discover;
mod dissect;
mod dom;
mod dot;
mod gamegrep;
mod ir;
mod lift;
mod manifest;
mod noreturn;
mod optimize;
mod pointer;
mod profile;
mod provenance;
mod render;
mod scan;
mod signatures;
mod slice;
mod ssa;
mod structural;
mod structure;
mod sigvalidate;
mod switch;
mod trace;
mod trampoline;
mod typeinfer;
mod ui_locate;
mod valueset;
mod xref;
mod xref_string;

pub use aob::{parse_aob, AobArtifact, AobByte, AobInput, AobScanPass};
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
pub use discover::{discover_pdata, DiscoverArtifact, DiscoverInput, DiscoverPass, FunctionCandidate};
pub use profile::{advisories, profile_image, Advisory, EngineHint, ExportInfo, FoldedExports, ImageProfile, SectionInfo};
pub use dissect::{DissectArtifact, DissectField, DissectInput, DissectPass, GuessedKind};
pub use dot::{DotArtifact, dot};
pub use ir::{
    CfgArtifact, CfgBlock, CfgInput, CfgPass, CfgStats, Callsite, DefUse, IrInsn, Successor, explain,
};
pub use lift::{LiftPass, LiftedBlock, LiftedFunction, LiftedStmt};
pub use manifest::{ManifestArtifact, ManifestCandidate, ManifestEntry, ManifestInput, ManifestPass};
pub use noreturn::{
    is_known_noreturn, proven_set, NoreturnArtifact, NoreturnFn, NoreturnInput, NoreturnPass,
};
pub use optimize::{OptArtifact, OptDeltaEntry, OptimizePass};
pub use pointer::{resolve_pointer_path, PointerPath, PointerPathArtifact, PointerPathInput, PointerPathPass, PointerRoot};
pub use provenance::{ProvenanceEntry, ProvenanceGraph, ProvenanceHit, ProvenanceInput, ProvenancePass};
pub use render::{render_condition, render_expr, render_stmt, negate_condition, RenderNames};
pub use scan::{
    FilterCriterion, FilterInput, FilterPass, RegionData, RegionState, ScanCriterion, ScanInput,
    ScanMatch, ScanPass, ScanReport, ScanState, ScanValue, Slot, ValueType, PREVIEW_LIMIT,
};
pub use signatures::{known_signature, KnownParam, KnownSignature};
pub use slice::{SliceArtifact, SliceNode, slice};
pub use ssa::{Phi, PhiInput, SsaArtifact, SsaBlock, SsaPass, SsaStmt};
pub use structure::{StructuredOutput, structure};
pub use switch::{ResolvedSwitch, SWITCH_CASE_CONFIDENCE, resolve_switch};
pub use typeinfer::{
    CType, FieldAccess, LocalVar, ParamInfo, RecoveredSignature, RecoveredType, TypeArtifact,
    TypeInferInput, TypeInferPass,
};
pub use trace::{TraceArtifact, TraceInput, TraceNode, TracePass};
pub use trampoline::{build_trampoline, near_jmp};
pub use valueset::{alias, AliasResult, ValueSet, ValueSetArtifact, ValueSetPass};
pub use xref::{XrefArtifact, XrefDir, XrefEntry, XrefInput, XrefPass};
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
    /// Entry addresses of functions proven never to return — the result of
    /// [`NoreturnPass`]'s whole-program fixpoint, fed back in so a *single*
    /// function's CFG closes at a call to one of them, exactly as it already
    /// does at a known noreturn import. Absent by default: without this, only
    /// the import table is known, which is what every `ir build` saw before
    /// (correct, just less complete — never wrong).
    ///
    /// Set by an embedder that ran the fixpoint in the same process
    /// (`Ctx::with_noreturn_fns`). The frontends do **not** set it yet: doing
    /// so across separate CLI invocations means persisting the set under
    /// `.n0x/`, which needs its own staleness discipline (the same trap the
    /// IR cache's analysis fingerprint fixed) — a tracked follow-on, scoped
    /// deliberately rather than smuggled in with the analysis itself.
    pub noreturn_fns: Option<&'a std::collections::BTreeSet<u64>>,
}

impl<'a> Ctx<'a> {
    pub fn new(source: &'a dyn MemorySource, arch: &'a dyn Arch) -> Self {
        Ctx {
            source,
            arch,
            symbols: None,
            modules: None,
            noreturn_fns: None,
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
    /// Feed back a proven-noreturn function set (see [`Ctx::noreturn_fns`]).
    pub fn with_noreturn_fns(mut self, fns: &'a std::collections::BTreeSet<u64>) -> Self {
        self.noreturn_fns = Some(fns);
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

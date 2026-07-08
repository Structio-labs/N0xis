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

mod decode;
mod discover;
mod ir;
mod switch;
mod xref;

pub use decode::{DecodeInput, DecodeOutput, DecodePass};
pub use discover::{DiscoverArtifact, DiscoverInput, DiscoverPass, FunctionCandidate};
pub use ir::{
    CfgArtifact, CfgBlock, CfgInput, CfgPass, CfgStats, Callsite, DefUse, IrInsn, Successor, explain,
};
pub use switch::{ResolvedSwitch, SWITCH_CASE_CONFIDENCE, resolve_switch};
pub use xref::{XrefArtifact, XrefDir, XrefEntry, XrefInput, XrefPass};

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
}

impl<'a> Ctx<'a> {
    pub fn new(source: &'a dyn MemorySource, arch: &'a dyn Arch) -> Self {
        Ctx {
            source,
            arch,
            symbols: None,
            modules: None,
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

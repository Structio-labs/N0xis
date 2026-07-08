//! # n0xis-pipeline — wiring the core to concrete inputs
//!
//! Binds a [`MemorySource`](n0xis_sources::MemorySource) and an
//! [`Arch`](n0xis_arch::Arch) into a [`Ctx`](n0xis_core::Ctx) and runs
//! [`Pass`](n0xis_core::Pass)es over it. This is the single place the frontends
//! (`n0xis-cli`, `n0xis-mcp`) call into — they never touch analysis internals,
//! only this façade and the contracts.
//!
//! Phase 1 is deliberately thin: run a pass, get its artifact. The
//! `PassManager` grows artifact caching and incremental recompute in Phase 6
//! (so IR isn't rebuilt on every call); the API here is shaped to absorb that
//! without changing callers.

pub use n0xis_arch as arch;
pub use n0xis_contracts as contracts;
pub use n0xis_core as core;
pub use n0xis_project as project;
pub use n0xis_sources as sources;

use n0xis_arch::Arch;
use n0xis_contracts::Va;
use n0xis_core::{Ctx, CoreError, DecodeInput, DecodeOutput, DecodePass, Pass};
use n0xis_sources::MemorySource;

/// A ready-to-run analysis context over one source + arch.
pub struct Pipeline<'a> {
    ctx: Ctx<'a>,
}

impl<'a> Pipeline<'a> {
    pub fn new(source: &'a dyn MemorySource, arch: &'a dyn Arch) -> Self {
        Pipeline {
            ctx: Ctx::new(source, arch),
        }
    }

    /// Build from a pre-configured context (e.g. one carrying symbols/modules).
    pub fn from_ctx(ctx: Ctx<'a>) -> Self {
        Pipeline { ctx }
    }

    /// The source's provenance label, for `meta.source`.
    pub fn source_label(&self) -> String {
        self.ctx.source.label()
    }

    /// Run any pass against this pipeline's context.
    pub fn run<P: Pass>(&self, pass: &P, input: P::In) -> Result<P::Out, CoreError> {
        pass.run(&self.ctx, input)
    }

    /// Convenience: linear disassembly of ~`count` instructions from `start`.
    pub fn disassemble(&self, start: Va, count: usize) -> Result<DecodeOutput, CoreError> {
        self.run(&DecodePass, DecodeInput::count(start, count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    #[test]
    fn pipeline_disassembles_through_the_facade() {
        let snap = Snapshot::builder()
            .region(Va(0x1000), vec![0x90u8, 0x90, 0xC3]) // nop; nop; ret
            .label("snapshot:pipe")
            .build();
        let arch = X64::new();
        let pipe = Pipeline::new(&snap, &arch);
        let out = pipe.disassemble(Va(0x1000), 8).unwrap();
        assert_eq!(out.count, 3);
        assert_eq!(pipe.source_label(), "snapshot:pipe");
    }
}

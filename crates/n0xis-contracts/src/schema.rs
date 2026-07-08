//! Schema identifiers — the versioned names that tag every `data` payload.
//!
//! Naming policy (CONCEPT §12): new v1 schemas are `n0xis.*.vN`; the archived
//! v0 schemas stay `n0x.*` and are reserved here so the compatibility surface
//! is explicit and nothing silently reuses an id. Breaking a payload's shape
//! bumps its `vN`.

/// New v1 (`n0xis.*`) schema ids, minted as capabilities land.
pub mod v1 {
    /// Linear decode / disassembly output (`decode` pass, `disasm`).
    pub const DECODE: &str = "n0xis.decode.v1";
    /// Environment / readiness report (`doctor`).
    pub const DOCTOR: &str = "n0xis.doctor.v1";
    /// Built-in quick reference (`guide`).
    pub const GUIDE: &str = "n0xis.guide.v1";
    /// Project init report (`init`).
    pub const PROJECT_INIT: &str = "n0xis.project.init.v1";
    /// Resolved project paths/config (`project info`).
    pub const PROJECT_INFO: &str = "n0xis.project.info.v1";

    // --- reserved for the phases ahead (declared so the id is owned) ---
    /// SSA form (ROADMAP Phase 3).
    pub const IR_SSA: &str = "n0xis.ir.ssa.v1";
    /// Per-pass optimization delta — the "explainable" artifact (Phase 3, KF-5).
    pub const OPT_DELTA: &str = "n0xis.opt.delta.v1";
    /// Provenance graph — the principal (Phase 4c, KF-1).
    pub const PROVENANCE: &str = "n0xis.provenance.v1";
}

/// Reserved v0 (`n0x.*`) schema ids — the compatibility contract from
/// [`docs/CLI_COMMANDS_v0.md`](../../../docs/CLI_COMMANDS_v0.md). Kept so the
/// port preserves the exact wire names agents already depend on.
pub mod v0 {
    pub const IR: &str = "n0x.ir.v1";
    pub const IR_CFG: &str = "n0x.ir.cfg.v1";
    pub const IR_DOT: &str = "n0x.ir.dot.v1";
    pub const IR_SLICE: &str = "n0x.ir.slice.v1";
    pub const IR_MANIFEST: &str = "n0x.ir.manifest.v1";
    pub const IR_EXPLAIN: &str = "n0x.ir.explain.v1";
    pub const DECOMP_PSEUDO: &str = "n0x.decomp.pseudo.v1";
    pub const DEBUG_AWAIT_HIT: &str = "n0x.debug.await_hit.v1";
}

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
    /// Process listing (`process ps`).
    pub const PROCESS_PS: &str = "n0xis.process.ps.v1";
    /// Module listing (`module list`).
    pub const MODULE_LIST: &str = "n0xis.module.list.v1";
    /// CFG + block/def-use IR (`ir build` / `ir cfg`).
    pub const IR_CFG: &str = "n0xis.ir.cfg.v1";
    /// Human-readable IR summary (`ir explain`).
    pub const IR_EXPLAIN: &str = "n0xis.ir.explain.v1";
    /// Graphviz DOT rendering of the CFG (`ir dot`).
    pub const IR_DOT: &str = "n0xis.ir.dot.v1";
    /// Backward register slice over a function (`ir slice`).
    pub const IR_SLICE: &str = "n0xis.ir.slice.v1";
    /// Per-function index with quality scoring (`ir manifest`).
    pub const IR_MANIFEST: &str = "n0xis.ir.manifest.v1";
    /// Heuristic function discovery (`function discover`).
    pub const FUNCTION_DISCOVER: &str = "n0xis.function.discover.v1";
    /// Cross-references to/from an address (`xref to` / `xref from`).
    pub const XREF: &str = "n0xis.xref.v1";
    /// Memory read (`mem read`).
    pub const MEM_READ: &str = "n0xis.mem.read.v1";
    /// Memory write (`mem write`).
    pub const MEM_WRITE: &str = "n0xis.mem.write.v1";
    /// Address-space region map (`mem map`).
    pub const MEM_MAP: &str = "n0xis.mem.map.v1";
    /// Patch operation result (`patch *`).
    pub const PATCH: &str = "n0xis.patch.v1";
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

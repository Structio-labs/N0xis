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
    /// Call-graph walk from a root (`function trace`).
    pub const FUNCTION_TRACE: &str = "n0xis.function.trace.v1";
    /// Cross-references to/from an address (`xref to` / `xref from`).
    pub const XREF: &str = "n0xis.xref.v1";
    /// String-literal search + referencing instructions (`xref string`).
    pub const XREF_STRING: &str = "n0xis.xref.string.v1";
    /// Memory read (`mem read`).
    pub const MEM_READ: &str = "n0xis.mem.read.v1";
    /// Memory write (`mem write`).
    pub const MEM_WRITE: &str = "n0xis.mem.write.v1";
    /// Address-space region map (`mem map`).
    pub const MEM_MAP: &str = "n0xis.mem.map.v1";
    /// Patch operation result (`patch *`).
    pub const PATCH: &str = "n0xis.patch.v1";
    /// Named memory-range selection (`selection *`).
    pub const SELECTION: &str = "n0xis.selection.v1";
    /// Persistent artifact store (`dump *`).
    pub const DUMP: &str = "n0xis.dump.v1";
    /// Environment / readiness report (`doctor`).
    pub const DOCTOR: &str = "n0xis.doctor.v1";
    /// Built-in quick reference (`guide`).
    pub const GUIDE: &str = "n0xis.guide.v1";
    /// Project init report (`init`).
    pub const PROJECT_INIT: &str = "n0xis.project.init.v1";
    /// Resolved project paths/config (`project info`).
    pub const PROJECT_INFO: &str = "n0xis.project.info.v1";
    /// Software-breakpoint hit report (`debug await-hit`).
    pub const DEBUG_AWAIT_HIT: &str = "n0xis.debug.await_hit.v1";
    /// SSA form (`ir ssa`, ROADMAP Phase 3).
    pub const IR_SSA: &str = "n0xis.ir.ssa.v1";
    /// Per-pass optimization delta — the "explainable" artifact (`ir opt`,
    /// Phase 3, KF-5); also inlined into `decomp pseudo --style ssa`.
    pub const OPT_DELTA: &str = "n0xis.opt.delta.v1";
    /// Typed value scan / rescan result (`scan value` / `scan filter`, Phase 4b).
    pub const SCAN: &str = "n0xis.scan.v1";
    /// AOB signature scan result (`scan aob`, Phase 4b).
    pub const AOB_SCAN: &str = "n0xis.scan.aob.v1";
    /// Pointer-path scan result (`scan pointer-path`, Phase 4b).
    pub const POINTER_PATH: &str = "n0xis.scan.pointer_path.v1";
    /// Struct dissection result (`scan dissect`, Phase 4b).
    pub const DISSECT: &str = "n0xis.scan.dissect.v1";
    /// A `.n0xt` table or entry (`table *`, CONCEPT §10, Phase 4b).
    pub const TABLE: &str = "n0xis.table.v1";
    /// Freeze-loop report (`table freeze`, Phase 4b).
    pub const FREEZE: &str = "n0xis.freeze.v1";
    /// Hardware-breakpoint watchpoint hit report (`debug watch`, Phase 4b).
    pub const WATCHPOINT: &str = "n0xis.debug.watchpoint.v1";

    /// Provenance graph — the principal (Phase 4c, KF-1).
    pub const PROVENANCE: &str = "n0xis.provenance.v1";
    /// One address's asserted name/type/comment + history (`annotate *`, Phase 6).
    pub const ANNOTATION: &str = "n0xis.annotation.v1";
    /// A captured, reloadable memory snapshot (`snapshot dump`, Phase 6).
    pub const SNAPSHOT: &str = "n0xis.snapshot.v1";
    /// Per-SSA-variable value-set analysis (`ir value-set`, Phase 7).
    pub const VALUE_SET: &str = "n0xis.value_set.v1";
    /// Deobfuscated pseudo-C, with the removed junk logged (`decomp pseudo
    /// --deobfuscate`, Phase 7).
    pub const DEOBFUSCATE: &str = "n0xis.deobfuscate.v1";
    /// A structural diff between two functions/binaries (`diff functions`,
    /// Phase 7).
    pub const DIFF: &str = "n0xis.diff.v1";

    /// Bitsquid/Stingray bundle entry listing (`bundle list`).
    pub const BUNDLE_LIST: &str = "n0xis.bundle.list.v1";
    /// Bitsquid/Stingray bundle extraction result (`bundle extract`).
    pub const BUNDLE_EXTRACT: &str = "n0xis.bundle.extract.v1";
    /// Lua/LuaJIT bytecode disassembly (`lua disasm`).
    pub const LUA_DISASM: &str = "n0xis.lua.disasm.v1";
    /// Live LuaJIT GCstr discovery in a running process (`lua strings`).
    pub const LUA_STRINGS: &str = "n0xis.lua.strings.v1";

    // --- reserved for the phases ahead (declared so the id is owned) ---
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

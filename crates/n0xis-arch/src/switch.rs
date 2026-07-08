//! Switch / jump-table *dispatch* description — the ISA-specific recognition of
//! an indirect branch that implements a `switch`. Detection lives in the arch
//! ([`Arch::detect_switch`](crate::Arch::detect_switch)); it yields this
//! neutral shape. The memory-side *resolution* of the actual case targets is a
//! `n0xis-core` concern (it reads the table through the `MemorySource` seam),
//! because the arch is forbidden from touching memory. That split is the whole
//! trick behind resolving jump tables from a *live* process — the edge static
//! tools lack (CONCEPT §5.1).

use n0xis_contracts::Va;

/// Which jump-table idiom an indirect branch matches. The two forms differ in
/// what the table *holds*, which is what the resolver needs to know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwitchKind {
    /// `jmp [rip+disp + idx*scale]` — the table holds **absolute pointers**
    /// (one native pointer per case). Common in gnu/clang output.
    MemIndexed,
    /// MSVC idiom: `lea base,[rip+disp]; movsxd r,[base + idx*4]; add r,base;
    /// jmp r` — the table holds **signed 32-bit offsets** relative to the table
    /// base; each case target is `base + rel32`.
    RegRel32,
}

impl SwitchKind {
    /// Stable wire tag.
    pub fn as_str(self) -> &'static str {
        match self {
            SwitchKind::MemIndexed => "mem-indexed",
            SwitchKind::RegRel32 => "reg-rel32",
        }
    }

    /// Size in bytes of one table entry for this idiom. `MemIndexed` entries are
    /// native pointers (hence `pointer_size`); `RegRel32` entries are always
    /// 4-byte signed offsets regardless of pointer width.
    pub fn entry_size(self, pointer_size: u8) -> u32 {
        match self {
            SwitchKind::MemIndexed => pointer_size as u32,
            SwitchKind::RegRel32 => REL32_ENTRY_SIZE,
        }
    }
}

/// A recognized jump-table dispatch, *before* its cases are resolved from
/// memory. Produced by the arch; consumed by the core's memory-side resolver.
#[derive(Clone, Debug)]
pub struct SwitchDispatch {
    /// Address of the dispatching indirect `jmp`.
    pub at: Va,
    pub kind: SwitchKind,
    /// Resolved table base (absolute VA). `None` when the base could not be
    /// recovered from the surrounding instructions.
    pub table: Option<Va>,
    /// Full-width name of the index register, when recovered.
    pub index_reg: Option<String>,
    /// Index scale (1 / 4 / 8).
    pub scale: u32,
    /// Upper bound on the index from a preceding `cmp`/`sub idx, imm`, when
    /// found. `Some(n)` means the case count is bounded (`n + 1` targets).
    pub bound: Option<u64>,
}

/// Table-entry size for the MSVC rel32 idiom.
const REL32_ENTRY_SIZE: u32 = 4;

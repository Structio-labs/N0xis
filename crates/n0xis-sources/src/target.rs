//! The **live-target seam** — what "a running process" means, with no OS in
//! the signature.
//!
//! Until this module existed the live half of the toolkit had good file
//! boundaries but no *polymorphic* one: `LiveProcess` was a concrete Win32
//! struct, `Src::Live` was an enum variant that only existed on Windows, and
//! six call sites down in `n0xis-project`/`n0xis-frontend` took `&LiveProcess`
//! by value-type even though their bodies only ever called `read`/`write`.
//! Adding a second OS therefore meant editing every one of those, which is
//! exactly the "a second OS is an adapter, not a rewrite" property CONCEPT §4
//! claims. This trait is that claim, made structural.
//!
//! Note what is *not* here: nothing about handles, `/proc`, ptrace, or section
//! header formats. An implementation may be Win32 (`live::LiveProcess`), Linux
//! `/proc` + `process_vm_readv` (`live_linux::LinuxProcess`), or — in
//! principle — a remote agent, an emulator, or a core dump. The analysis
//! pipeline above it never learns which.

use n0xis_contracts::Va;

use crate::{MemorySource, ModuleProvider, SourceError, SymbolProvider};

/// One process in a listing (`process ps`).
#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
}

/// One region from the process address-space map (`mem map`).
///
/// The string vocabulary is deliberately Win32-flavoured (`state` is
/// `commit`/`reserve`/`free`, `protect` is `rwx`-style) because it is already
/// baked into the `n0xis.mem.map.v1` wire schema and agents parse it. A
/// non-Windows adapter maps its own model onto these words rather than
/// inventing a second vocabulary — see `live_linux`'s `/proc/<pid>/maps`
/// translation, where every mapping present in `maps` is by definition
/// committed.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MemRegion {
    pub base: Va,
    pub end: Va,
    pub size: u64,
    pub state: String,
    pub protect: String,
    pub kind: String,
}

/// Readable+writable data, not the (usually huge, rarely value-bearing)
/// read-only/executable code — what [`LiveTarget::default_writable_regions`]
/// filters to.
///
/// `rc-`/`rcx` are Windows copy-on-write; Linux private-writable maps report as
/// `rw-`/`rwx` and land in the same set.
pub fn is_default_scan_region(protect: &str) -> bool {
    matches!(protect, "rw-" | "rwx" | "rc-" | "rcx")
}

/// An attached, live process address space.
///
/// Supertraits carry the byte/symbol/module access; this trait adds only what
/// is specific to a *live* target — the things a file-backed source cannot do
/// (enumerate regions, allocate in the target) or answers differently (section
/// ranges read out of mapped memory rather than a file's section table).
///
/// Object-safe on purpose: `Src::Live` stores a `Box<dyn LiveTarget>`, so the
/// frontends hold one type regardless of OS. Trait upcasting (stable since
/// 1.86) lets a `&dyn LiveTarget` be handed to anything wanting
/// `&dyn MemorySource`.
pub trait LiveTarget: MemorySource + ModuleProvider + SymbolProvider {
    /// The attached process id.
    fn pid(&self) -> u32;

    /// The process's main module (its executable image), if enumerated.
    fn main_module(&self) -> Option<&n0xis_contracts::Module>;

    /// Locate the main module's executable extent — `.text` on PE, the
    /// `r-xp` load segment on ELF.
    fn text_range(&self) -> Option<(Va, u64)>;

    /// Locate a named section's `(start, size)` in the main module. `name` is
    /// any section, not just `.text` — e.g. `.rdata`/`.rodata` for
    /// string-literal scanning.
    fn section_range(&self, name: &str) -> Option<(Va, u64)>;

    /// Same, but for *any* loaded module by its base — not just the main one.
    /// Needed once an address (e.g. a watchpoint hit's `rip`) can fall in a
    /// shared library rather than the main image: function resolution must
    /// scan the *code* section, never the module base, which is the header
    /// page and would silently clamp `read`'s read-up-to-region-end semantics.
    fn section_range_of(&self, module_base: Va, name: &str) -> Option<(Va, u64)>;

    /// Walk the process address space, up to `limit` regions (`mem map`).
    fn regions(&self, limit: usize) -> Vec<MemRegion>;

    /// All committed, writable regions — the default region set a scan/AOB
    /// search covers when no explicit `--start`/`--size` is given, since a
    /// value could be anywhere in dynamically-allocated memory. One definition
    /// of "the default region set", not a copy per caller.
    fn default_writable_regions(&self) -> Vec<(Va, usize)> {
        self.regions(1_000_000)
            .into_iter()
            .filter(|r| r.state == "commit" && is_default_scan_region(&r.protect))
            .map(|r| (r.base, r.size as usize))
            .collect()
    }

    /// Allocate `size` bytes of RWX memory in the target — a "code cave" for a
    /// detour/trampoline hook.
    ///
    /// Default: unsupported. Allocating *inside another process* needs an OS
    /// primitive with no portable equivalent (`VirtualAllocEx` has one;
    /// Linux requires hijacking a thread via ptrace to run `mmap` in-target),
    /// so an adapter opts in rather than being forced to fake it.
    fn alloc_code_cave(&self, _size: usize) -> Result<Va, SourceError> {
        Err(SourceError::Os("code-cave allocation is not supported by this live adapter".into()))
    }

    /// Release a previously allocated code cave.
    fn free_code_cave(&self, _addr: Va) -> Result<(), SourceError> {
        Err(SourceError::Os("code-cave allocation is not supported by this live adapter".into()))
    }

    /// Recover the call stack from a captured register set, up to `max_frames`
    /// deep. Frame 0 is `regs.rip` (the capture site); each caller is recovered
    /// through that module's unwind data — PE `.pdata`/`.xdata` or ELF
    /// `.eh_frame` DWARF CFI, chosen per module. Everything (unwind tables *and*
    /// stack slots) is read through this target's own
    /// [`MemorySource`](crate::MemorySource), so the default body serves every
    /// adapter unchanged — Win32 and Linux `/proc` alike, including a Wine PE
    /// target read through `/proc`. An adapter never needs to override it.
    ///
    /// The one genuinely OS-specific piece is *capturing* the initial
    /// [`UnwindRegs`](crate::UnwindRegs) — a thread's live register file
    /// (`GetThreadContext` on Win32, `ptrace(GETREGS)` on Linux). That belongs
    /// to a debug adapter, not here; this method starts from registers already
    /// in hand.
    #[cfg(feature = "live")]
    fn stack_unwind(&self, regs: crate::UnwindRegs, max_frames: usize) -> Vec<crate::Frame> {
        let reader = crate::unwind::SourceReader(self);
        let modules: Vec<crate::ModuleRange> = self
            .modules()
            .iter()
            .map(|m| crate::ModuleRange { base: m.base.0, size: m.size, name: m.name.clone() })
            .collect();
        crate::unwind(&reader, &modules, regs, max_frames)
    }
}

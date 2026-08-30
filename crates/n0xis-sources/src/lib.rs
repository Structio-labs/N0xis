//! # n0xis-sources — the source seam
//!
//! Replaces v0's `enum IrSource { Live, Static }` with traits. Whether bytes
//! come from a **live process**, a **static PE**, a cached **snapshot**, or a
//! **remote agent** stops being an `if` in the analysis — it becomes a choice
//! of adapter behind these traits. That is what lets the same SSA→opt→types
//! pipeline run byte-for-byte identically on a running game and a file on disk
//! (CONCEPT §5.1).
//!
//! Phase 1 ships only [`Snapshot`], a pure in-memory implementation with **no
//! OS dependency** — the test double the whole core is validated against. The
//! `LiveProcess` (Win32) and `StaticPe` (goblin) adapters arrive in Phase 2,
//! gated behind features so this crate stays OS-free by default.

mod snapshot;

pub use snapshot::{Snapshot, SnapshotBuilder};

mod linewire;

mod remote;

pub use remote::{RemoteAgent, serve_stdio as remote_serve_stdio, split_command_line};

mod plugin;

pub use plugin::{call_once as plugin_call_once, PluginSession};

#[cfg(feature = "static-pe")]
mod static_pe;
#[cfg(feature = "static-pe")]
pub use static_pe::StaticPe;
#[cfg(feature = "static-pe")]
mod static_elf;
#[cfg(feature = "static-pe")]
pub use static_elf::StaticElf;
#[cfg(feature = "static-pe")]
mod static_image;
#[cfg(feature = "static-pe")]
pub use static_image::StaticImage;

// The live-target seam itself is OS-free and always compiled: `trait
// LiveTarget` plus the vocabulary its answers are phrased in. Frontends can
// therefore *name* the seam on any platform, and only the implementations come
// and go with the target.
mod target;
pub use target::{LiveTarget, MemRegion, ProcInfo, is_default_scan_region};

/// Does this build have a live-process adapter behind [`LiveTarget`]?
///
/// The `live` feature says "the capability was asked for"; this says "a backing
/// implementation exists for this target". They differ on, e.g., macOS, where
/// the feature can be on and nothing implements it (mach_vm_read has no adapter
/// yet) — a frontend must degrade there, not fail to compile.
pub const HAS_LIVE_ADAPTER: bool = cfg!(all(feature = "live", any(windows, target_os = "linux", target_os = "android")));

#[cfg(all(feature = "live", windows))]
mod live;
#[cfg(all(feature = "live", windows))]
pub use live::{LiveProcess, list_processes};

// Linux and Android share the adapter: Android is a Linux kernel, so
// /proc/<pid>/maps and process_vm_readv are the same primitives there.
#[cfg(all(feature = "live", any(target_os = "linux", target_os = "android")))]
mod live_linux;
#[cfg(all(feature = "live", any(target_os = "linux", target_os = "android")))]
pub use live_linux::{LinuxProcess, list_processes};

// Linux register capture (ptrace) — the seed of the Linux debug adapter, and
// the register source that seeds the portable unwinder on Linux.
#[cfg(all(feature = "live", any(target_os = "linux", target_os = "android")))]
mod dbg_linux;
#[cfg(all(feature = "live", any(target_os = "linux", target_os = "android")))]
pub use dbg_linux::{list_thread_ids, StoppedThread};
// The Linux debug adapter's free functions — byte-identical signatures to the
// Win32 ones, so the CLI/MCP call one name on either OS (see the `debug` export).
#[cfg(all(feature = "live", any(target_os = "linux", target_os = "android")))]
pub use dbg_linux::{attach_and_wait, await_breakpoint_hit, await_watchpoint_hit, await_watchpoint_hit_where};

// The remaining live modules are still Win32-only. They were gated on the
// `live` feature alone, which was equivalent while `live` *meant* Windows;
// now that the feature means the capability, each needs to say `windows` for
// itself. A Linux debugger (ptrace), window system (X11/Wayland) and input
// injector (uinput) are separate adapters, not variations of these.
// The OS-free hit vocabulary (report + register + condition types, and the x86
// debug-register bit encodings) — shared by the Win32 and Linux debug adapters
// so both emit the identical wire shape. Only the arming/event-loop is per-OS.
#[cfg(feature = "live")]
mod hit;
#[cfg(feature = "live")]
pub use hit::{AwaitHitOutcome, BreakpointHit, RegCond, Registers, WatchKind};

#[cfg(all(feature = "live", windows))]
mod debug;
#[cfg(all(feature = "live", windows))]
pub use debug::{attach_and_wait, await_breakpoint_hit, await_watchpoint_hit, await_watchpoint_hit_where};

// The stack unwinder is pure logic over the `MemReader` seam — it names no OS
// API — so it compiles on every platform under `live`. It carries both format
// backends (PE `.pdata`/`.xdata` and ELF `.eh_frame` DWARF CFI) and dispatches
// per module by header, which also lets it unwind a Wine PE target read through
// `/proc`. Only the *register capture* that seeds it stays per-OS.
#[cfg(feature = "live")]
mod unwind;
#[cfg(feature = "live")]
pub use unwind::{unwind, Frame, MemReader, ModuleRange, UnwindRegs};

#[cfg(all(feature = "live", windows))]
mod input;
#[cfg(all(feature = "live", windows))]
pub use input::{probe_actuation, MethodResult, ProbeReport, DEFAULT_PROBE_VK};

#[cfg(all(feature = "live", windows))]
mod window;
#[cfg(all(feature = "live", windows))]
pub use window::{
    b64_encode, best_window, classify_frame, encode_png, focus, list_windows, screenshot,
    window_pid, CaptureAttempt, CaptureError, CaptureMethod, FocusResult, FrameStats, FrameVerdict,
    Screenshot, WindowInfo,
};

use n0xis_contracts::{Module, Symbol, Va};

/// Something went wrong reading/writing a source.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("address {0} is not mapped in this source")]
    Unmapped(Va),
    #[error("this source is read-only (write not supported)")]
    ReadOnly,
    #[error("failed to load source: {0}")]
    Load(String),
    #[error("os error: {0}")]
    Os(String),
}

/// Byte-level access to an address space.
///
/// **Read semantics:** [`read`](MemorySource::read) returns *up to* `len` bytes
/// starting at `va`, truncated where the mapped region ends. It errors only
/// when `va` itself is unmapped. This matches how a live `ReadProcessMemory`
/// and a static section both behave at a boundary, and lets a disassembler ask
/// for a generous window without knowing the region size in advance. Callers
/// needing an exact count check the returned length.
pub trait MemorySource {
    fn read(&self, va: Va, len: usize) -> Result<Vec<u8>, SourceError>;

    /// Is `va` backed by this source?
    fn contains(&self, va: Va) -> bool;

    /// Executable code extent `(start, size)`, when the source knows it (a
    /// PE's `.text`, a live module's code section). Lets passes tell code from
    /// data through the seam — e.g. the switch resolver rejects jump-table
    /// entries that don't land in code. Default `None`: unknown, so callers
    /// fall back to [`contains`](MemorySource::contains).
    ///
    /// ⚠️ **One range cannot describe every image.** Prefer
    /// [`code_ranges`](MemorySource::code_ranges) for anything that must cover
    /// *all* the code; this stays for callers that genuinely want the primary
    /// extent.
    fn code_range(&self) -> Option<(Va, u64)> {
        None
    }

    /// **Every** executable range this source knows about, in address order.
    ///
    /// `.text` is not always where the code is. A Unity IL2CPP build puts the
    /// transpiled C# in a section named `il2cpp` with the same
    /// `CODE|EXECUTE|READ` characteristics as `.text` — measured on a real
    /// target: `.text` 7 247 840 bytes, `il2cpp` 61 303 411. Anything that
    /// treats `.text` as "the code" then covers a tenth of the image and
    /// reports the rest as containing nothing, which is a silent false
    /// negative rather than a visible refusal.
    ///
    /// Default: [`code_range`](MemorySource::code_range) as a one-element list,
    /// so a source that knows only one extent behaves exactly as it did.
    fn code_ranges(&self) -> Vec<(Va, u64)> {
        self.code_range().into_iter().collect()
    }

    /// Write bytes at `va`. Default: [`SourceError::ReadOnly`] — only live
    /// sources override this. `StaticPe`/`Snapshot` stay read-only.
    fn write(&self, _va: Va, _bytes: &[u8]) -> Result<(), SourceError> {
        Err(SourceError::ReadOnly)
    }

    /// Provenance label for `meta.source`, e.g. `"snapshot:test"`.
    fn label(&self) -> String;
}

/// Resolve symbols by address (exports, imports, IAT slots, recovered names).
pub trait SymbolProvider {
    fn symbol_at(&self, va: Va) -> Option<Symbol>;

    /// If `va` is an IAT slot, the imported symbol it resolves to.
    fn iat_slot(&self, _va: Va) -> Option<Symbol> {
        None
    }

    /// A stable token identifying **which names this provider will give**.
    ///
    /// Cached analysis artifacts embed *resolved* names, so a cache key built
    /// only from the bytes serves stale, unnamed artifacts forever after a new
    /// symbol source appears — measured: importing an IL2CPP index changed
    /// nothing on any function already analyzed, until `.n0x/ir-cache/` was
    /// deleted by hand. Providers whose names are derived from the same bytes
    /// the key already covers (a PE's own exports) can leave this empty;
    /// anything loaded from beside the binary must not.
    fn symbol_fingerprint(&self) -> String {
        String::new()
    }
}

/// Two [`SymbolProvider`]s consulted as one — the composition the seam needed
/// once a target could have names from more than one place (a PE's exports
/// *and* an imported IL2CPP index, say).
///
/// **The tighter fit wins, not the first answer.** Both providers report the
/// address of the symbol they matched, so the one whose symbol starts closest
/// at-or-below the query is the more specific answer and is preferred. Taking
/// the primary's answer unconditionally would let a provider that attributes a
/// whole function span swallow an exact hit from the other — e.g. an imported
/// method at `0x1000` claiming a runtime export at `0x1100` simply because it
/// was asked first. Ties go to `primary`.
pub struct ChainedSymbols<'a> {
    primary: &'a dyn SymbolProvider,
    fallback: &'a dyn SymbolProvider,
}

impl<'a> ChainedSymbols<'a> {
    pub fn new(primary: &'a dyn SymbolProvider, fallback: &'a dyn SymbolProvider) -> Self {
        ChainedSymbols { primary, fallback }
    }
}

impl SymbolProvider for ChainedSymbols<'_> {
    fn symbol_at(&self, va: Va) -> Option<Symbol> {
        match (self.primary.symbol_at(va), self.fallback.symbol_at(va)) {
            (Some(a), Some(b)) => Some(if b.va.0 > a.va.0 { b } else { a }),
            (a, b) => a.or(b),
        }
    }

    fn iat_slot(&self, va: Va) -> Option<Symbol> {
        self.primary.iat_slot(va).or_else(|| self.fallback.iat_slot(va))
    }

    fn symbol_fingerprint(&self) -> String {
        let (a, b) = (self.primary.symbol_fingerprint(), self.fallback.symbol_fingerprint());
        if a.is_empty() && b.is_empty() { String::new() } else { format!("{a}+{b}") }
    }
}

/// Enumerate the modules mapped in an address space and locate an owner.
pub trait ModuleProvider {
    fn modules(&self) -> &[Module];

    fn owner_of(&self, va: Va) -> Option<&Module> {
        self.modules().iter().find(|m| m.contains(va))
    }
}

#[cfg(test)]
mod chain_tests {
    use super::*;
    use n0xis_contracts::SymKind;

    /// A provider that owns everything from `at` upwards, like an index that
    /// attributes a whole function span to its start.
    struct Spanning {
        at: u64,
        name: &'static str,
    }
    impl SymbolProvider for Spanning {
        fn symbol_at(&self, va: Va) -> Option<Symbol> {
            (va.0 >= self.at).then(|| Symbol { va: Va(self.at), module: "m".into(), name: self.name.into(), kind: SymKind::Function })
        }
    }

    /// A provider that answers only on an exact address, like an export table.
    struct Exact {
        at: u64,
        name: &'static str,
    }
    impl SymbolProvider for Exact {
        fn symbol_at(&self, va: Va) -> Option<Symbol> {
            (va.0 == self.at).then(|| Symbol { va: Va(self.at), module: "m".into(), name: self.name.into(), kind: SymKind::Export })
        }
    }

    #[test]
    fn the_tighter_fit_wins_even_when_it_is_the_fallback() {
        let index = Spanning { at: 0x1000, name: "Managed$$Method" };
        let exports = Exact { at: 0x1100, name: "il2cpp_runtime_thing" };
        let chain = ChainedSymbols::new(&index, &exports);

        // Inside the span and nothing more specific: the index answers.
        assert_eq!(chain.symbol_at(Va(0x1050)).unwrap().name, "Managed$$Method");
        // Exactly on the export: the closer symbol wins despite being second,
        // which is the whole reason this is not a plain `or_else`.
        assert_eq!(chain.symbol_at(Va(0x1100)).unwrap().name, "il2cpp_runtime_thing");
    }

    #[test]
    fn either_side_alone_still_answers_and_neither_means_none() {
        let index = Spanning { at: 0x1000, name: "A" };
        let empty = Exact { at: 0x9999, name: "unused" };
        let chain = ChainedSymbols::new(&index, &empty);
        assert_eq!(chain.symbol_at(Va(0x1000)).unwrap().name, "A");
        assert!(chain.symbol_at(Va(0x0fff)).is_none());

        let chain = ChainedSymbols::new(&empty, &index);
        assert_eq!(chain.symbol_at(Va(0x1000)).unwrap().name, "A", "order must not decide whether an answer exists");
    }

    #[test]
    fn a_tie_goes_to_the_primary() {
        let a = Exact { at: 0x2000, name: "primary" };
        let b = Exact { at: 0x2000, name: "fallback" };
        assert_eq!(ChainedSymbols::new(&a, &b).symbol_at(Va(0x2000)).unwrap().name, "primary");
    }
}

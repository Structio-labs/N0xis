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
    fn code_range(&self) -> Option<(Va, u64)> {
        None
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
}

/// Enumerate the modules mapped in an address space and locate an owner.
pub trait ModuleProvider {
    fn modules(&self) -> &[Module];

    fn owner_of(&self, va: Va) -> Option<&Module> {
        self.modules().iter().find(|m| m.contains(va))
    }
}

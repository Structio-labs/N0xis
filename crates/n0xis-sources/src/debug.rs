//! Win32 debug API: arm a software breakpoint (`int3`) and block until it
//! fires — `debug await-hit`. The agent sets the breakpoint, something in the
//! target triggers it (a human pressing a key in a game, another automated
//! actor), and this reports back exactly which thread hit it with a full
//! register + stack snapshot.
//!
//! Gated behind the same `live` feature as [`LiveProcess`](crate::LiveProcess)
//! — the only other OS-linked adapter — but deliberately a standalone flow
//! rather than a `LiveProcess` method: `DebugActiveProcess` needs a fresh
//! handle and makes the caller the target's debugger for the process's
//! lifetime of the call, which doesn't fit the already-open read/write handle
//! `LiveProcess` holds for unrelated `mem`/`ir` work.
//!
//! Every step that mutates target/debugger state (the patched byte, the debug
//! attach) is wrapped in an RAII guard, so a breakpoint left over from an
//! error or a timeout is *always* restored and the debugger detached — no
//! manual cleanup bookkeeping on each early-return path, unlike v0.
//!
//! Ported from the proven v0 `debug.rs`, refit to windows-sys 0.61 + `SourceError`.

use std::ffi::c_void;
use std::mem;
use std::time::{Duration, Instant};

use n0xis_contracts::{Module, Va};
use serde::Serialize;

use windows_sys::Win32::Foundation::{
    CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, EXCEPTION_BREAKPOINT,
    EXCEPTION_SINGLE_STEP, GetLastError, HANDLE, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64, CONTEXT_FULL_AMD64, CREATE_PROCESS_DEBUG_EVENT,
    CREATE_THREAD_DEBUG_EVENT, ContinueDebugEvent, DEBUG_EVENT, DebugActiveProcess,
    DebugActiveProcessStop, DebugSetProcessKillOnExit, EXCEPTION_DEBUG_EVENT,
    EXIT_THREAD_DEBUG_EVENT, FlushInstructionCache, GetThreadContext, ReadProcessMemory,
    SetThreadContext, WaitForDebugEvent, WriteProcessMemory,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
};
use windows_sys::Win32::System::Threading::{
    GetProcessId, OpenProcess, OpenThread, PROCESS_ALL_ACCESS, ResumeThread, SuspendThread,
    THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
};

use crate::SourceError;
use crate::unwind::{self, ModuleRange, UnwindRegs};

/// `CONTEXT`'s floating-point/XMM save area needs 16-byte alignment — the
/// kernel performs an aligned SIMD save/restore into it during
/// `Get`/`SetThreadContext`. windows-sys declares `CONTEXT` as plain
/// `#[repr(C)]` with no explicit alignment, so a bare stack local can land
/// under-aligned depending on the surrounding code, and the kernel's
/// internal save then faults with `ERROR_NOACCESS` (998) — intermittent and
/// call-site-dependent, which is exactly the shape of bug this caused before
/// the fix. This wrapper forces the alignment the API actually needs; `Deref`/
/// `DerefMut` keep every existing `ctx.Field` access unchanged — only the
/// `&mut ctx` passed *by pointer* to `Get`/`SetThreadContext` needs `&mut
/// ctx.0` instead.
#[repr(C, align(16))]
struct AlignedContext(CONTEXT);

impl AlignedContext {
    fn zeroed() -> Self {
        AlignedContext(unsafe { mem::zeroed() })
    }
}

impl std::ops::Deref for AlignedContext {
    type Target = CONTEXT;
    fn deref(&self) -> &CONTEXT {
        &self.0
    }
}

impl std::ops::DerefMut for AlignedContext {
    fn deref_mut(&mut self) -> &mut CONTEXT {
        &mut self.0
    }
}

/// How often `WaitForDebugEvent` re-checks the deadline.
const POLL_MS: u32 = 250;
/// Some kernels report `ERROR_SEM_TIMEOUT` instead of `WAIT_TIMEOUT` from a
/// timed-out `WaitForDebugEvent`.
const ERROR_SEM_TIMEOUT: u32 = 121;

/// Full integer GPR snapshot at the moment of the hit.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Registers {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

impl Registers {
    /// Read a register by lowercase name, for condition matching.
    pub fn by_name(&self, name: &str) -> Option<u64> {
        Some(match name {
            "rax" => self.rax,
            "rbx" => self.rbx,
            "rcx" => self.rcx,
            "rdx" => self.rdx,
            "rsi" => self.rsi,
            "rdi" => self.rdi,
            "rbp" => self.rbp,
            "r8" => self.r8,
            "r9" => self.r9,
            "r10" => self.r10,
            "r11" => self.r11,
            "r12" => self.r12,
            "r13" => self.r13,
            "r14" => self.r14,
            "r15" => self.r15,
            _ => return None,
        })
    }
}

/// A condition a hit must satisfy to be reported, e.g. `r9=4`.
///
/// Without this a breakpoint on a hot function is close to useless: the first
/// hit is whatever ran first, and re-arming just returns the same caller every
/// time (live: a UI draw routine kept reporting `r9=6` across six consecutive
/// arms, never the 4-arrow call we were after). Filtering in the debug loop lets
/// the interesting call be singled out instead of hoping to land on it.
#[derive(Clone, Debug)]
pub struct RegCond {
    pub reg: String,
    pub value: u64,
}

impl RegCond {
    /// Parse `"<reg>=<value>"`; value may be decimal or `0x`-prefixed.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (reg, val) = s.split_once('=').ok_or_else(|| format!("expected <reg>=<value>, got `{s}`"))?;
        let reg = reg.trim().to_ascii_lowercase();
        let val = val.trim();
        let value = if let Some(hex) = val.strip_prefix("0x").or_else(|| val.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).map_err(|e| format!("bad hex value `{val}`: {e}"))?
        } else {
            val.parse::<u64>().map_err(|e| format!("bad value `{val}`: {e}"))?
        };
        if Registers::default().by_name(&reg).is_none() {
            return Err(format!("unknown register `{reg}`"));
        }
        Ok(RegCond { reg, value })
    }

    fn matches(&self, r: &Registers) -> bool {
        r.by_name(&self.reg) == Some(self.value)
    }
}

/// One breakpoint hit.
#[derive(Clone, Debug, Serialize)]
pub struct BreakpointHit {
    pub thread_id: u32,
    pub rip: Va,
    pub rsp: Va,
    /// `"<module>+0x<rva>"`, when `rip` falls inside the module passed to
    /// [`await_breakpoint_hit`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relative_rip: Option<String>,
    pub registers: Registers,
    /// Qwords read from the stack starting at `rsp`, in order.
    pub stack: Vec<u64>,
    /// The recovered call-stack: frame 0 is `rip` (the hit site), each further
    /// entry a real caller resolved through x64 unwind data (`.pdata`/`.xdata`),
    /// not a raw `[rsp]` guess. Empty if unwinding couldn't start (e.g. no
    /// module map). See [`crate::unwind`].
    pub frames: Vec<unwind::Frame>,
}

/// Result of one [`await_breakpoint_hit`] call.
#[derive(Clone, Debug, Serialize)]
pub struct AwaitHitOutcome {
    pub breakpoint_va: Va,
    pub timed_out: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hit: Option<BreakpointHit>,
}

/// Become `pid`'s debugger and hold the attach for `timeout_ms` without
/// arming anything (no `int3` patch, no debug-register write) — a diagnostic
/// primitive to isolate whether a target's instability comes from
/// `DebugActiveProcess` itself (anti-debug checks reacting to being under a
/// debugger) versus something a specific breakpoint/watchpoint does. All
/// debug events are just continued unmodified; on return the debugger is
/// detached (`DebugGuard`'s `Drop`), same as every other function here.
pub fn attach_and_wait(pid: u32, timeout_ms: u64) -> Result<(), SourceError> {
    let _debug_guard = DebugGuard::attach(pid)?;
    let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(1));
    let mut first_bp_seen = false;
    loop {
        if Instant::now() >= deadline {
            break;
        }
        let mut ev: DEBUG_EVENT = unsafe { mem::zeroed() };
        let remaining = deadline.saturating_duration_since(Instant::now()).as_millis();
        let wait_ms = POLL_MS.min(remaining.min(u128::from(u32::MAX)) as u32).max(1);
        if unsafe { WaitForDebugEvent(&mut ev, wait_ms) } == 0 {
            let err = unsafe { GetLastError() };
            if err == WAIT_TIMEOUT || err == ERROR_SEM_TIMEOUT {
                continue;
            }
            return Err(SourceError::Os(format!("WaitForDebugEvent failed (GLE {err})")));
        }
        // Windows delivers exactly one system-injected `EXCEPTION_BREAKPOINT`
        // right after `DebugActiveProcess` (the "a debugger attached" notice).
        // The debugger MUST swallow it with `DBG_CONTINUE`; passing it back as
        // `DBG_EXCEPTION_NOT_HANDLED` delivers an unexpected breakpoint
        // exception to a target that has no handler for it, which crashes the
        // target. This one line was the real cause of the "attaching kills the
        // game" behaviour we misattributed to anti-debug.
        let status = if ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
            let code = unsafe { ev.u.Exception.ExceptionRecord.ExceptionCode };
            if code == EXCEPTION_BREAKPOINT && !first_bp_seen {
                first_bp_seen = true;
                DBG_CONTINUE
            } else {
                // Any other exception is the target's own — hand it back
                // unchanged so its normal handlers (LuaJIT, the CRT, …) run.
                DBG_EXCEPTION_NOT_HANDLED
            }
        } else {
            DBG_CONTINUE
        };
        unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status) };
    }
    Ok(())
}

/// Patch an `int3` at `addr` in `pid`, become its debugger, and block until
/// either that exact breakpoint fires or `timeout_ms` elapses. On a hit,
/// captures the thread's registers and up to `stack_qwords` stack qwords,
/// rewinds `Rip` back to `addr` so the target resumes as if nothing had
/// happened, and continues it. The patched byte is restored and the debugger
/// detached on every path — hit, timeout, or error — via RAII guards; the
/// process is never killed by detaching (`DebugSetProcessKillOnExit(false)`).
pub fn await_breakpoint_hit(
    pid: u32,
    addr: Va,
    timeout_ms: u64,
    stack_qwords: usize,
    module: Option<&Module>,
) -> Result<AwaitHitOutcome, SourceError> {
    let h_process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if h_process.is_null() {
        return Err(SourceError::Os(format!(
            "OpenProcess(PROCESS_ALL_ACCESS, {pid}) failed (GLE {}) — process may be elevated/protected or gone",
            unsafe { GetLastError() }
        )));
    }
    let _process_guard = HandleGuard(h_process);

    let mut bp = BreakpointGuard::arm(h_process, addr)?;
    let _debug_guard = DebugGuard::attach(pid)?;

    let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(1));
    let mut hit: Option<BreakpointHit> = None;
    // The first `EXCEPTION_BREAKPOINT` after attach is Windows' own attach
    // notification and must be `DBG_CONTINUE`d, never handed back to the target.
    let mut first_bp_seen = false;

    loop {
        if Instant::now() >= deadline {
            break;
        }
        let mut ev: DEBUG_EVENT = unsafe { mem::zeroed() };
        let remaining = deadline.saturating_duration_since(Instant::now()).as_millis();
        let wait_ms = POLL_MS.min(remaining.min(u128::from(u32::MAX)) as u32).max(1);

        if unsafe { WaitForDebugEvent(&mut ev, wait_ms) } == 0 {
            let err = unsafe { GetLastError() };
            if err == WAIT_TIMEOUT || err == ERROR_SEM_TIMEOUT {
                continue;
            }
            return Err(SourceError::Os(format!("WaitForDebugEvent failed (GLE {err})")));
        }

        if ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
            let info = unsafe { ev.u.Exception };
            let code = info.ExceptionRecord.ExceptionCode;
            let exc_addr = Va(info.ExceptionRecord.ExceptionAddress as u64);

            if code == EXCEPTION_BREAKPOINT && exc_addr == addr && info.dwFirstChance != 0 {
                let captured = capture_hit(h_process, ev.dwThreadId, module, stack_qwords)?;
                bp.disarm();
                rewind_rip(ev.dwThreadId, addr)?;
                unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE) };
                drain_pending_events();
                hit = Some(captured);
                break;
            }

            // Swallow the system's initial attach breakpoint; only *other*
            // breakpoints (the target's own int3s) go back unhandled.
            let status = if code == EXCEPTION_BREAKPOINT && !first_bp_seen {
                first_bp_seen = true;
                DBG_CONTINUE
            } else if code == EXCEPTION_BREAKPOINT {
                DBG_EXCEPTION_NOT_HANDLED
            } else {
                DBG_CONTINUE
            };
            unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status) };
            continue;
        }

        unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE) };
    }

    // `bp`/`_debug_guard`/`_process_guard` restore/detach/close on drop below,
    // whether we broke out on a hit or fell through on timeout.
    Ok(AwaitHitOutcome { breakpoint_va: addr, timed_out: hit.is_none(), hit })
}

/// Closes a `HANDLE` on drop.
struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Owns the patched `int3` byte; restores the original on drop unless already
/// [`disarm`](Self::disarm)ed.
struct BreakpointGuard {
    handle: HANDLE,
    addr: Va,
    orig: u8,
    armed: bool,
}

impl BreakpointGuard {
    fn arm(handle: HANDLE, addr: Va) -> Result<Self, SourceError> {
        let orig = read_byte(handle, addr)?;
        write_byte(handle, addr, 0xCC)?;
        unsafe { FlushInstructionCache(handle, addr.0 as *const c_void, 1) };
        Ok(BreakpointGuard { handle, addr, orig, armed: true })
    }

    /// Restore the original byte now (idempotent). Called explicitly right
    /// after a hit is captured, so the target doesn't keep re-trapping while
    /// the report is assembled; also runs automatically on drop for the
    /// timeout/error paths.
    fn disarm(&mut self) {
        if self.armed {
            let _ = write_byte(self.handle, self.addr, self.orig);
            unsafe { FlushInstructionCache(self.handle, self.addr.0 as *const c_void, 1) };
            self.armed = false;
        }
    }
}

impl Drop for BreakpointGuard {
    fn drop(&mut self) {
        self.disarm();
    }
}

/// Owns the `DebugActiveProcess` attach; detaches on drop.
struct DebugGuard(u32);

impl DebugGuard {
    fn attach(pid: u32) -> Result<Self, SourceError> {
        if unsafe { DebugActiveProcess(pid) } == 0 {
            return Err(SourceError::Os(format!(
                "DebugActiveProcess({pid}) failed (GLE {}) — already under another debugger?",
                unsafe { GetLastError() }
            )));
        }
        // Must be called *after* a successful DebugActiveProcess.
        if unsafe { DebugSetProcessKillOnExit(0) } == 0 {
            unsafe { DebugActiveProcessStop(pid) };
            return Err(SourceError::Os("DebugSetProcessKillOnExit(false) failed".into()));
        }
        Ok(DebugGuard(pid))
    }
}

impl Drop for DebugGuard {
    fn drop(&mut self) {
        unsafe { DebugActiveProcessStop(self.0) };
    }
}

fn read_byte(handle: HANDLE, va: Va) -> Result<u8, SourceError> {
    let mut b = 0u8;
    let mut sz = 0usize;
    let ok = unsafe {
        ReadProcessMemory(handle, va.0 as *const c_void, (&mut b) as *mut u8 as *mut c_void, 1, &mut sz)
    };
    if ok == 0 || sz != 1 {
        return Err(SourceError::Os(format!("ReadProcessMemory failed at {va}")));
    }
    Ok(b)
}

fn write_byte(handle: HANDLE, va: Va, byte: u8) -> Result<(), SourceError> {
    let mut sz = 0usize;
    let ok = unsafe {
        WriteProcessMemory(handle, va.0 as *mut c_void, (&byte) as *const u8 as *const c_void, 1, &mut sz)
    };
    if ok == 0 || sz != 1 {
        return Err(SourceError::Os(format!("WriteProcessMemory failed at {va}")));
    }
    Ok(())
}

fn capture_hit(
    h_process: HANDLE,
    tid: u32,
    module: Option<&Module>,
    stack_qwords: usize,
) -> Result<BreakpointHit, SourceError> {
    let h_thread = unsafe { OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, 0, tid) };
    if h_thread.is_null() {
        return Err(SourceError::Os(format!("OpenThread({tid}) failed (GLE {})", unsafe { GetLastError() })));
    }
    let _guard = HandleGuard(h_thread);

    let mut ctx = AlignedContext::zeroed();
    ctx.ContextFlags = CONTEXT_FULL_AMD64;
    if unsafe { GetThreadContext(h_thread, &mut ctx.0) } == 0 {
        return Err(SourceError::Os(format!("GetThreadContext({tid}) failed (GLE {})", unsafe { GetLastError() })));
    }

    let rip = Va(ctx.Rip);
    let rsp = Va(ctx.Rsp);
    let relative_rip = module
        .and_then(|m| m.rva(rip).map(|rva| (m, rva)))
        .map(|(m, rva)| format!("{}+0x{rva:x}", m.name));

    let mut stack = Vec::new();
    let n = stack_qwords.min(512);
    if n > 0 && rsp.0 != 0 {
        let want = n * 8;
        let mut buf = vec![0u8; want];
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(h_process, rsp.0 as *const c_void, buf.as_mut_ptr() as *mut c_void, want, &mut read)
        };
        if ok != 0 {
            for chunk in buf[..read - (read % 8)].chunks_exact(8) {
                stack.push(u64::from_le_bytes(chunk.try_into().unwrap()));
            }
        }
    }

    // Recover the true caller chain by unwinding the target's stack through its
    // own `.pdata`/`.xdata` — a hardware watchpoint lands mid-function, where
    // `[rsp]` is *not* the return address, so a raw stack read gives the wrong
    // caller. Best-effort: an empty `frames` (no module map, unreadable unwind
    // data) degrades to "just registers + raw stack", never an error.
    let pid = unsafe { GetProcessId(h_process) };
    let modules = enumerate_modules(pid);
    let reader = ProcMemReader(h_process);
    let regs = UnwindRegs {
        rip: ctx.Rip,
        gpr: [
            ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rbx, ctx.Rsp, ctx.Rbp, ctx.Rsi, ctx.Rdi, ctx.R8, ctx.R9,
            ctx.R10, ctx.R11, ctx.R12, ctx.R13, ctx.R14, ctx.R15,
        ],
    };
    let frames = unwind::unwind(&reader, &modules, regs, MAX_UNWIND_FRAMES);

    Ok(BreakpointHit {
        thread_id: tid,
        rip,
        rsp,
        relative_rip,
        registers: Registers {
            rax: ctx.Rax,
            rbx: ctx.Rbx,
            rcx: ctx.Rcx,
            rdx: ctx.Rdx,
            rsi: ctx.Rsi,
            rdi: ctx.Rdi,
            rbp: ctx.Rbp,
            r8: ctx.R8,
            r9: ctx.R9,
            r10: ctx.R10,
            r11: ctx.R11,
            r12: ctx.R12,
            r13: ctx.R13,
            r14: ctx.R14,
            r15: ctx.R15,
        },
        stack,
        frames,
    })
}

/// Depth cap for stack unwinding — a bound against a corrupt frame chain
/// looping forever, generous enough for any real call stack.
const MAX_UNWIND_FRAMES: usize = 128;

/// A [`crate::unwind::MemReader`] backed by `ReadProcessMemory` on the target.
struct ProcMemReader(HANDLE);

impl unwind::MemReader for ProcMemReader {
    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut got = 0usize;
        let ok = unsafe {
            ReadProcessMemory(self.0, addr as *const c_void, buf.as_mut_ptr() as *mut c_void, len, &mut got)
        };
        if ok == 0 || got != len {
            return None;
        }
        Some(buf)
    }
}

/// Enumerate the target's loaded modules `(base, size, name)` via a ToolHelp
/// snapshot — the module map the unwinder needs to find each frame's `.pdata`
/// and to label frames. Returns empty on failure (unwinding then no-ops).
fn enumerate_modules(pid: u32) -> Vec<ModuleRange> {
    let mut out = Vec::new();
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) };
    if snap.is_null() || snap == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return out;
    }
    let _guard = HandleGuard(snap);
    let mut me: MODULEENTRY32W = unsafe { mem::zeroed() };
    me.dwSize = mem::size_of::<MODULEENTRY32W>() as u32;
    if unsafe { Module32FirstW(snap, &mut me) } == 0 {
        return out;
    }
    loop {
        out.push(ModuleRange {
            base: me.modBaseAddr as u64,
            size: me.modBaseSize as u64,
            name: wide_to_string(&me.szModule),
        });
        if unsafe { Module32NextW(snap, &mut me) } == 0 {
            break;
        }
    }
    out
}

/// UTF-16 (NUL-terminated) to `String`, for ToolHelp's `szModule`.
fn wide_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

/// After `int3`, `Rip` is past the patch byte; we restored only that one byte
/// of a possibly multi-byte instruction, so execution must re-run from
/// `bp_va` or the target mis-decodes whatever follows.
fn rewind_rip(tid: u32, bp_va: Va) -> Result<(), SourceError> {
    let h_thread = unsafe { OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, 0, tid) };
    if h_thread.is_null() {
        return Err(SourceError::Os(format!("OpenThread(SET_CONTEXT, {tid}) failed")));
    }
    let _guard = HandleGuard(h_thread);

    let mut ctx = AlignedContext::zeroed();
    ctx.ContextFlags = CONTEXT_FULL_AMD64;
    if unsafe { GetThreadContext(h_thread, &mut ctx.0) } == 0 {
        return Err(SourceError::Os(format!("GetThreadContext(rewind, {tid}) failed")));
    }
    ctx.Rip = bp_va.0;
    if unsafe { SetThreadContext(h_thread, &ctx.0) } == 0 {
        return Err(SourceError::Os(format!("SetThreadContext(Rip={bp_va}, {tid}) failed")));
    }
    Ok(())
}

/// Best-effort: swallow any debug events still in flight right after resuming
/// from the hit, so they don't linger and confuse the next `WaitForDebugEvent`
/// caller. Short, bounded window — not a full event loop.
fn drain_pending_events() {
    let deadline = Instant::now() + Duration::from_millis(250);
    while Instant::now() < deadline {
        let mut ev: DEBUG_EVENT = unsafe { mem::zeroed() };
        if unsafe { WaitForDebugEvent(&mut ev, 50) } == 0 {
            break;
        }
        unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE) };
    }
}

// ============================================================================
// Hardware-breakpoint watchpoints (ROADMAP Phase 4b) — value-change
// watchpoints via the CPU's debug registers (DR0-DR7), not a patched byte:
// unlike `int3`, this can watch a *data* address for read/write, not just an
// instruction for execution, and never touches the target's code bytes.
// ============================================================================

/// What a hardware watchpoint traps on. There is no hardware "read-only"
/// mode on x86 — only `Write` or `ReadOrWrite` — so this doesn't invent one
/// (CONCEPT §3 rule 6: the API reflects what the CPU can actually do).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchKind {
    Execute,
    Write,
    ReadOrWrite,
}

impl WatchKind {
    fn rw_bits(self) -> u64 {
        match self {
            WatchKind::Execute => 0b00,
            WatchKind::Write => 0b01,
            WatchKind::ReadOrWrite => 0b11,
        }
    }
}

/// Intel SDM Vol 3B §17.2.5: LEN field encodes 1/2/8/4 bytes for `00/01/10/11`
/// — note the non-monotonic order. The address must be naturally aligned to
/// `len` or the CPU silently ignores the high bits; we reject that instead
/// of installing a watchpoint that won't fire as described.
fn len_bits(addr: Va, len: u8) -> Result<u64, SourceError> {
    if len > 1 && !addr.0.is_multiple_of(len as u64) {
        return Err(SourceError::Os(format!("watchpoint address {addr} is not {len}-byte aligned")));
    }
    match len {
        1 => Ok(0b00),
        2 => Ok(0b01),
        8 => Ok(0b10),
        4 => Ok(0b11),
        _ => Err(SourceError::Os(format!("unsupported watchpoint length {len} (must be 1, 2, 4, or 8)"))),
    }
}

/// DR7 bits for slot 0 only: `L0` (local enable, bit 0), bit 10 (reserved,
/// conventionally set), `RW0` (bits 16-17), `LEN0` (bits 18-19).
fn dr7_slot0(kind: WatchKind, addr: Va, len: u8) -> Result<u64, SourceError> {
    if kind == WatchKind::Execute && len != 1 {
        return Err(SourceError::Os("an execute watchpoint must have length 1 (Intel SDM Vol 3B §17.2.5)".into()));
    }
    let rw = kind.rw_bits();
    let lb = len_bits(addr, len)?;
    Ok(1u64 | (1u64 << 10) | (rw << 16) | (lb << 18))
}

/// Owns the DR0/DR7 write on every thread it succeeded on; restores each
/// thread's original values on drop unless already disarmed. Best-effort per
/// thread — a thread we can't open (already exited, access denied) is just
/// skipped.
///
/// Threads are armed one at a time from the debugger event loop, in response
/// to `CREATE_PROCESS`/`CREATE_THREAD` debug events — at which point the
/// thread is stopped, so `SetThreadContext` on its debug registers reliably
/// sticks (writing DR on a *freely running* thread is unreliable, and misses
/// exactly the busy worker threads we most want to trap). Because
/// `DebugActiveProcess` synthesises a `CREATE_THREAD` event for every
/// pre-existing thread on attach, and delivers a real one for every thread
/// created afterwards, this covers the whole thread set — including workers
/// spawned after arming, which an arm-once-at-attach implementation missed.
struct WatchGuard {
    addr: Va,
    dr7_bits: u64,
    entries: Vec<(u32, u64, u64)>,
}

impl WatchGuard {
    fn new(addr: Va, kind: WatchKind, len: u8) -> Result<Self, SourceError> {
        let dr7_bits = dr7_slot0(kind, addr, len)?;
        Ok(WatchGuard { addr, dr7_bits, entries: Vec::new() })
    }

    /// Arm DR0/DR7 slot 0 on a single thread by id. Intended to be called
    /// while the thread is stopped at a debug event, where the context write
    /// is reliable. Idempotent-ish: skips a tid already tracked so a stray
    /// duplicate `CREATE_THREAD` can't stack a second (already-armed) orig.
    fn arm_tid(&mut self, tid: u32) {
        if self.entries.iter().any(|(t, _, _)| *t == tid) {
            return;
        }
        let h = unsafe {
            OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, 0, tid)
        };
        if h.is_null() {
            return;
        }
        let _g = HandleGuard(h);
        let mut ctx = AlignedContext::zeroed();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
        if unsafe { GetThreadContext(h, &mut ctx.0) } == 0 {
            return;
        }
        let (orig_dr0, orig_dr7) = (ctx.Dr0, ctx.Dr7);
        ctx.Dr0 = self.addr.0;
        ctx.Dr7 = orig_dr7 | self.dr7_bits;
        if unsafe { SetThreadContext(h, &ctx.0) } != 0 {
            self.entries.push((tid, orig_dr0, orig_dr7));
        }
    }

    /// Drop tracking for a thread that has exited — its context is gone, and
    /// its tid could be recycled, so we must not try to "restore" DR on it.
    fn forget_tid(&mut self, tid: u32) {
        self.entries.retain(|(t, _, _)| *t != tid);
    }

    fn disarm(&mut self) {
        for (tid, orig_dr0, orig_dr7) in self.entries.drain(..) {
            // CRITICAL: a `SetThreadContext` write to the debug registers only
            // reliably sticks on a *stopped* thread — the same reason arming is
            // done from inside the event loop. At disarm time every thread
            // except the one that hit is running freely, so we must suspend it
            // first, or the DR clear silently fails and the thread keeps a live
            // hardware breakpoint. After we detach, that thread traps again with
            // no debugger attached → an unhandled single-step exception →
            // the target crashes. (This was the observed "watchpoint crashes the
            // game" bug: the busy worker threads we most want to trap are exactly
            // the ones whose DR clear was being dropped.)
            let h = unsafe {
                OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, 0, tid)
            };
            if h.is_null() {
                continue;
            }
            let _g = HandleGuard(h);
            // -1 (0xFFFF_FFFF) means the call failed; the thread is likely gone,
            // so skip it rather than clearing DR on a wrong/recycled context.
            let suspended = unsafe { SuspendThread(h) };
            if suspended == u32::MAX {
                continue;
            }
            let mut ctx = AlignedContext::zeroed();
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
            if unsafe { GetThreadContext(h, &mut ctx.0) } != 0 {
                ctx.Dr0 = orig_dr0;
                ctx.Dr7 = orig_dr7;
                unsafe { SetThreadContext(h, &ctx.0) };
            }
            unsafe { ResumeThread(h) };
        }
    }
}

impl Drop for WatchGuard {
    fn drop(&mut self) {
        self.disarm();
    }
}

fn dr6_slot0_set(tid: u32) -> bool {
    let h = unsafe { OpenThread(THREAD_GET_CONTEXT, 0, tid) };
    if h.is_null() {
        return false;
    }
    let _g = HandleGuard(h);
    let mut ctx = AlignedContext::zeroed();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
    if unsafe { GetThreadContext(h, &mut ctx.0) } == 0 {
        return false;
    }
    ctx.Dr6 & 0x1 != 0
}

fn clear_dr6(tid: u32) {
    let h = unsafe { OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, tid) };
    if h.is_null() {
        return;
    }
    let _g = HandleGuard(h);
    let mut ctx = AlignedContext::zeroed();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
    if unsafe { GetThreadContext(h, &mut ctx.0) } != 0 {
        ctx.Dr6 = 0;
        unsafe { SetThreadContext(h, &ctx.0) };
    }
}

/// Arm a hardware watchpoint (DR0) on `addr` across every thread of `pid`,
/// and block until it fires or `timeout_ms` elapses — the value-change
/// counterpart to [`await_breakpoint_hit`]'s code breakpoint. One-shot: the
/// watchpoint is disarmed from every thread on return (hit, timeout, or
/// error), same RAII guarantee as the software breakpoint path. Threads
/// created *after* arming aren't covered — a documented scope limit, not a
/// silent gap (real debuggers additionally arm on `CREATE_THREAD_DEBUG_EVENT`,
/// a reasonable follow-on).
pub fn await_watchpoint_hit(
    pid: u32,
    addr: Va,
    kind: WatchKind,
    len: u8,
    timeout_ms: u64,
    stack_qwords: usize,
    module: Option<&Module>,
) -> Result<AwaitHitOutcome, SourceError> {
    await_watchpoint_hit_where(pid, addr, kind, len, timeout_ms, stack_qwords, module, None)
}

/// [`await_watchpoint_hit`], but only reports a hit whose registers satisfy
/// `cond` — hits that don't match are resumed with the watchpoint still armed.
/// This is what makes a breakpoint on a hot function usable: it singles out the
/// one call of interest instead of returning whichever call happened to run first.
#[allow(clippy::too_many_arguments)]
pub fn await_watchpoint_hit_where(
    pid: u32,
    addr: Va,
    kind: WatchKind,
    len: u8,
    timeout_ms: u64,
    stack_qwords: usize,
    module: Option<&Module>,
    cond: Option<&RegCond>,
) -> Result<AwaitHitOutcome, SourceError> {
    let h_process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if h_process.is_null() {
        return Err(SourceError::Os(format!(
            "OpenProcess(PROCESS_ALL_ACCESS, {pid}) failed (GLE {}) — process may be elevated/protected or gone",
            unsafe { GetLastError() }
        )));
    }
    let _process_guard = HandleGuard(h_process);

    // Attach BEFORE arming. We arm each thread from inside the event loop
    // while it is stopped at its `CREATE_THREAD` event — the only place a
    // `SetThreadContext` write to the debug registers reliably sticks (on a
    // freely-running thread it can silently fail). `DebugActiveProcess`
    // synthesises a `CREATE_THREAD` for every pre-existing thread and a real
    // one for every thread spawned later, so the loop covers the full set.
    let _debug_guard = DebugGuard::attach(pid)?;
    let mut watch = WatchGuard::new(addr, kind, len)?;

    let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(1));
    let mut hit: Option<BreakpointHit> = None;
    // The first `EXCEPTION_BREAKPOINT` after attach is Windows' attach
    // notification — must be `DBG_CONTINUE`d, not handed back to the target
    // (doing so crashes it: the cause of the "watchpoint kills the game" bug).
    let mut first_bp_seen = false;
    // Budget for non-matching conditional hits — see the bail-out below.
    const MAX_CONDITION_MISSES: u32 = 300;
    let mut misses: u32 = 0;

    loop {
        if Instant::now() >= deadline {
            break;
        }
        let mut ev: DEBUG_EVENT = unsafe { mem::zeroed() };
        let remaining = deadline.saturating_duration_since(Instant::now()).as_millis();
        let wait_ms = POLL_MS.min(remaining.min(u128::from(u32::MAX)) as u32).max(1);

        if unsafe { WaitForDebugEvent(&mut ev, wait_ms) } == 0 {
            let err = unsafe { GetLastError() };
            if err == WAIT_TIMEOUT || err == ERROR_SEM_TIMEOUT {
                continue;
            }
            return Err(SourceError::Os(format!("WaitForDebugEvent failed (GLE {err})")));
        }

        if ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
            let info = unsafe { ev.u.Exception };
            let code = info.ExceptionRecord.ExceptionCode;

            if code == EXCEPTION_SINGLE_STEP && dr6_slot0_set(ev.dwThreadId) {
                // Capture first, but disarm + resume the target REGARDLESS of
                // whether capture succeeded — a `?` early-return here would
                // leave the hitting thread stopped at an un-continued debug
                // event, so detaching (guard drop) would hang or crash it.
                let captured = capture_hit(h_process, ev.dwThreadId, module, stack_qwords);
                // Not the call we asked for: resume it with the watchpoint still
                // armed and keep waiting. Disarming here (as the unconditional
                // path does) would end the wait on the wrong hit.
                if let (Some(c), Ok(h)) = (cond, captured.as_ref()) {
                    if !c.matches(&h.registers) {
                        clear_dr6(ev.dwThreadId);
                        unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE) };
                        misses += 1;
                        // Every miss is a full stop/inspect/resume round-trip for
                        // the target thread. On a per-frame function that is
                        // thousands of them, and the target effectively runs
                        // single-stepped — enough to kill a game (it did). Bail
                        // with an explanation instead of grinding it to death:
                        // a condition this rare needs a colder trap site.
                        if misses >= MAX_CONDITION_MISSES {
                            watch.disarm();
                            drain_pending_events();
                            return Err(SourceError::Os(format!(
                                "condition `{}={}` did not match in {MAX_CONDITION_MISSES} hits — this trap site is too hot to \
                                 filter on (every non-matching hit stops the target). Pick a colder address, or watch a data \
                                 address instead of an executed one.",
                                c.reg, c.value
                            )));
                        }
                        continue;
                    }
                }
                watch.disarm();
                clear_dr6(ev.dwThreadId);
                unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE) };
                drain_pending_events();
                hit = Some(captured?);
                break;
            }

            // Swallow the system's initial attach breakpoint. A stray
            // single-step (e.g. another tool's trap flag) is also ours to
            // continue; any other exception is the target's own and goes back
            // unchanged so its normal handlers run.
            let status = if code == EXCEPTION_BREAKPOINT && !first_bp_seen {
                first_bp_seen = true;
                DBG_CONTINUE
            } else if code == EXCEPTION_SINGLE_STEP {
                DBG_CONTINUE
            } else {
                DBG_EXCEPTION_NOT_HANDLED
            };
            unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status) };
            continue;
        }

        // Non-exception events. `DebugActiveProcess` delivers one
        // `CREATE_THREAD` per pre-existing thread on attach and a real one
        // for every thread spawned afterwards — arm each as it stops here so
        // the watchpoint covers the whole (evolving) thread set. Drop the
        // tracking for a thread that exits so we never touch a recycled tid.
        match ev.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT | CREATE_THREAD_DEBUG_EVENT => watch.arm_tid(ev.dwThreadId),
            EXIT_THREAD_DEBUG_EVENT => watch.forget_tid(ev.dwThreadId),
            _ => {}
        }
        unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE) };
    }

    Ok(AwaitHitOutcome { breakpoint_va: addr, timed_out: hit.is_none(), hit })
}

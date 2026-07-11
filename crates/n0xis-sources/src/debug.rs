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
    EXCEPTION_SINGLE_STEP, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64, CONTEXT_FULL_AMD64, ContinueDebugEvent, DEBUG_EVENT,
    DebugActiveProcess, DebugActiveProcessStop, DebugSetProcessKillOnExit, EXCEPTION_DEBUG_EVENT,
    FlushInstructionCache, GetThreadContext, ReadProcessMemory, SetThreadContext,
    WaitForDebugEvent, WriteProcessMemory,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenThread, PROCESS_ALL_ACCESS, ResumeThread, SuspendThread, THREAD_GET_CONTEXT,
    THREAD_QUERY_INFORMATION, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
};

use crate::SourceError;

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
}

/// Result of one [`await_breakpoint_hit`] call.
#[derive(Clone, Debug, Serialize)]
pub struct AwaitHitOutcome {
    pub breakpoint_va: Va,
    pub timed_out: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hit: Option<BreakpointHit>,
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

            let status = if code == EXCEPTION_BREAKPOINT { DBG_EXCEPTION_NOT_HANDLED } else { DBG_CONTINUE };
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
    })
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

fn list_thread_ids(pid: u32) -> Result<Vec<u32>, SourceError> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return Err(SourceError::Os(format!("CreateToolhelp32Snapshot(THREAD) failed (GLE {})", unsafe { GetLastError() })));
    }
    let _guard = HandleGuard(snap);
    let mut te: THREADENTRY32 = unsafe { mem::zeroed() };
    te.dwSize = mem::size_of::<THREADENTRY32>() as u32;
    let mut ids = Vec::new();
    if unsafe { Thread32First(snap, &mut te) } != 0 {
        loop {
            if te.th32OwnerProcessID == pid {
                ids.push(te.th32ThreadID);
            }
            if unsafe { Thread32Next(snap, &mut te) } == 0 {
                break;
            }
        }
    }
    Ok(ids)
}

/// Owns the DR0/DR7 write on every thread it succeeded on; restores each
/// thread's original values on drop unless already disarmed. Best-effort per
/// thread — a thread we can't open (already exited, access denied) is just
/// skipped, not a hard error, as long as at least one thread got armed.
struct WatchGuard {
    entries: Vec<(u32, u64, u64)>,
}

impl WatchGuard {
    fn arm(pid: u32, addr: Va, kind: WatchKind, len: u8) -> Result<Self, SourceError> {
        let dr7_bits = dr7_slot0(kind, addr, len)?;
        let tids = list_thread_ids(pid)?;
        let mut entries = Vec::new();
        for tid in tids {
            let h = unsafe {
                OpenThread(
                    THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
                    0,
                    tid,
                )
            };
            if h.is_null() {
                continue;
            }
            let _g = HandleGuard(h);
            // `SetThreadContext` on a *running* thread is unreliable — the
            // debug registers may silently fail to stick on a busy thread
            // (exactly the hot worker threads whose writes we most want to
            // trap). Suspend around the Get/Set so the DR0/DR7 write lands,
            // then resume. Best-effort: if the suspend fails we still try.
            let suspended = unsafe { SuspendThread(h) } != u32::MAX;
            let mut ctx = AlignedContext::zeroed();
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
            if unsafe { GetThreadContext(h, &mut ctx.0) } == 0 {
                if suspended {
                    unsafe { ResumeThread(h) };
                }
                continue;
            }
            let (orig_dr0, orig_dr7) = (ctx.Dr0, ctx.Dr7);
            ctx.Dr0 = addr.0;
            ctx.Dr7 = orig_dr7 | dr7_bits;
            if unsafe { SetThreadContext(h, &ctx.0) } != 0 {
                entries.push((tid, orig_dr0, orig_dr7));
            }
            if suspended {
                unsafe { ResumeThread(h) };
            }
        }
        if entries.is_empty() {
            return Err(SourceError::Os("failed to arm the hardware watchpoint on any thread".into()));
        }
        Ok(WatchGuard { entries })
    }

    fn disarm(&mut self) {
        for (tid, orig_dr0, orig_dr7) in self.entries.drain(..) {
            let h = unsafe { OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, 0, tid) };
            if h.is_null() {
                continue;
            }
            let _g = HandleGuard(h);
            let suspended = unsafe { SuspendThread(h) } != u32::MAX;
            let mut ctx = AlignedContext::zeroed();
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
            if unsafe { GetThreadContext(h, &mut ctx.0) } != 0 {
                ctx.Dr0 = orig_dr0;
                ctx.Dr7 = orig_dr7;
                unsafe { SetThreadContext(h, &ctx.0) };
            }
            if suspended {
                unsafe { ResumeThread(h) };
            }
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
    let h_process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if h_process.is_null() {
        return Err(SourceError::Os(format!(
            "OpenProcess(PROCESS_ALL_ACCESS, {pid}) failed (GLE {}) — process may be elevated/protected or gone",
            unsafe { GetLastError() }
        )));
    }
    let _process_guard = HandleGuard(h_process);

    let mut watch = WatchGuard::arm(pid, addr, kind, len)?;
    let _debug_guard = DebugGuard::attach(pid)?;

    let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(1));
    let mut hit: Option<BreakpointHit> = None;

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
                let captured = capture_hit(h_process, ev.dwThreadId, module, stack_qwords)?;
                watch.disarm();
                clear_dr6(ev.dwThreadId);
                unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE) };
                drain_pending_events();
                hit = Some(captured);
                break;
            }

            // A stray single-step (e.g. another tool's trap flag) or any
            // other exception: hand it back to the target/OS unchanged.
            let status = if code == EXCEPTION_SINGLE_STEP { DBG_CONTINUE } else { DBG_EXCEPTION_NOT_HANDLED };
            unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status) };
            continue;
        }

        unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE) };
    }

    Ok(AwaitHitOutcome { breakpoint_va: addr, timed_out: hit.is_none(), hit })
}

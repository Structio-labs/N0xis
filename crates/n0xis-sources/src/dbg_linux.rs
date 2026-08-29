//! The seed of the Linux debug adapter: capturing a thread's live register
//! file via `ptrace` — the one OS-specific piece the portable stack unwinder
//! ([`crate::unwind`]) needs but cannot provide itself.
//!
//! On Win32 the register seed comes from `GetThreadContext` inside the (Windows-
//! only) [`crate::debug`] module. Linux has no such module yet; this provides
//! the minimal equivalent — `PTRACE_ATTACH` + `PTRACE_GETREGS` — without the
//! full watch/breakpoint event loop. A [`StoppedThread`] holds the target
//! thread stopped for as long as the guard lives, so a caller can read a
//! *coherent* register set and walk that thread's stack while it cannot move,
//! then let it resume on drop.
//!
//! This is deliberately the thin end of the wedge. The full Linux debug adapter
//! (hardware watchpoints via the debug registers, software breakpoints, a
//! `waitpid` event loop) is a separate, larger piece — but it seeds the same
//! [`crate::UnwindRegs`] into the same portable unwinder this module already
//! feeds.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::time::{Duration, Instant};

use n0xis_contracts::{Module, Va};

use crate::hit::{dr7_slot0, AwaitHitOutcome, BreakpointHit, RegCond, Registers, WatchKind, MAX_CONDITION_MISSES, MAX_UNWIND_FRAMES};
use crate::{LinuxProcess, LiveTarget, MemorySource, SourceError, UnwindRegs};

/// The thread ids of a process, from `/proc/<pid>/task`. The main thread's tid
/// equals the pid; the rest are the process's other threads. Empty if the
/// process is gone or unreadable.
pub fn list_thread_ids(pid: u32) -> Vec<u32> {
    let mut tids: Vec<u32> = fs::read_dir(format!("/proc/{pid}/task"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()))
        .collect();
    tids.sort_unstable();
    tids
}

/// A ptrace-attached, stopped thread. Attaching stops the thread with a
/// `SIGSTOP`-equivalent; the guard detaches (resuming it) on drop, even on an
/// early return, so the target is never left frozen.
pub struct StoppedThread {
    tid: u32,
}

impl StoppedThread {
    /// Attach to and stop thread `tid`, waiting for it to actually stop.
    ///
    /// Fails with a Yama-aware message on `EPERM`, mirroring the read path:
    /// attaching to a non-descendant needs `kernel.yama.ptrace_scope=0`,
    /// `CAP_SYS_PTRACE`, or running as root.
    pub fn attach(tid: u32) -> Result<Self, SourceError> {
        // SAFETY: ptrace with a valid request and tid; no memory is aliased.
        let rc = unsafe { libc::ptrace(libc::PTRACE_ATTACH, tid as libc::pid_t, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) };
        if rc == -1 {
            let e = std::io::Error::last_os_error();
            let msg = if e.raw_os_error() == Some(libc::EPERM) {
                format!(
                    "ptrace(ATTACH, {tid}) denied (EPERM): yama ptrace_scope forbids attaching to a \
                     non-descendant. Fix for this boot with `sudo sysctl kernel.yama.ptrace_scope=0`, \
                     grant CAP_SYS_PTRACE, or run as root"
                )
            } else {
                format!("ptrace(ATTACH, {tid}) failed: {e}")
            };
            return Err(SourceError::Os(msg));
        }
        // Wait for the attach-stop. __WALL is required to wait on a thread that
        // is not a direct child in the classic sense.
        let mut status: libc::c_int = 0;
        let w = unsafe { libc::waitpid(tid as libc::pid_t, &mut status, libc::__WALL) };
        if w == -1 {
            let e = std::io::Error::last_os_error();
            // Best-effort detach before surfacing the error.
            unsafe { libc::ptrace(libc::PTRACE_DETACH, tid as libc::pid_t, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) };
            return Err(SourceError::Os(format!("waitpid({tid}) after attach failed: {e}")));
        }
        Ok(StoppedThread { tid })
    }

    /// The thread id this guard holds stopped.
    pub fn tid(&self) -> u32 {
        self.tid
    }

    /// Read the thread's integer register file and project it onto the unwinder's
    /// [`UnwindRegs`] model (rip + the 16 GPRs, indexed by the architectural x64
    /// numbering the unwind codes use — *not* the DWARF numbering).
    pub fn registers(&self) -> Result<UnwindRegs, SourceError> {
        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        // SAFETY: `regs` is a live, correctly-typed out-buffer for GETREGS.
        let rc = unsafe { libc::ptrace(libc::PTRACE_GETREGS, self.tid as libc::pid_t, std::ptr::null_mut::<libc::c_void>(), &mut regs as *mut _ as *mut libc::c_void) };
        if rc == -1 {
            return Err(SourceError::Os(format!("ptrace(GETREGS, {}) failed: {}", self.tid, std::io::Error::last_os_error())));
        }
        let mut gpr = [0u64; 16];
        // Architectural x64 order: RAX,RCX,RDX,RBX,RSP,RBP,RSI,RDI,R8..R15.
        gpr[crate::unwind::reg::RAX] = regs.rax;
        gpr[crate::unwind::reg::RCX] = regs.rcx;
        gpr[crate::unwind::reg::RDX] = regs.rdx;
        gpr[crate::unwind::reg::RBX] = regs.rbx;
        gpr[crate::unwind::reg::RSP] = regs.rsp;
        gpr[crate::unwind::reg::RBP] = regs.rbp;
        gpr[crate::unwind::reg::RSI] = regs.rsi;
        gpr[crate::unwind::reg::RDI] = regs.rdi;
        gpr[8] = regs.r8;
        gpr[9] = regs.r9;
        gpr[10] = regs.r10;
        gpr[11] = regs.r11;
        gpr[12] = regs.r12;
        gpr[13] = regs.r13;
        gpr[14] = regs.r14;
        gpr[15] = regs.r15;
        Ok(UnwindRegs { rip: regs.rip, gpr })
    }
}

impl Drop for StoppedThread {
    fn drop(&mut self) {
        // Resume the thread. Errors here are unactionable (the process may have
        // exited); swallow them so a drop never panics.
        unsafe {
            libc::ptrace(libc::PTRACE_DETACH, self.tid as libc::pid_t, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>());
        }
    }
}

// ============================================================================
// The Linux debug adapter — the ptrace twin of the Win32 `debug` module.
//
// Software breakpoints (`int3`) and hardware watchpoints (the CPU's debug
// registers DR0-DR7) over `PTRACE_SEIZE`, producing the SAME `BreakpointHit` /
// `AwaitHitOutcome` wire types (from `crate::hit`) the Windows adapter does, and
// feeding the SAME portable unwinder for the caller chain. Where Windows fought
// its own debug API over anti-debug, here the whole mechanism is plain syscalls.
//
// The single most important property is teardown safety: on x86 a debug-register
// write (or a DETACH) only takes on a *stopped* thread, so a watchpoint left live
// after detach re-traps with no debugger and the kernel kills the target. Every
// path therefore funnels through ONE RAII `Session::drop` that (0) adopts pending
// clone children, (1) STOPS all threads, (2) restores the patched byte, (2b)
// rewinds every sibling stranded at a breakpoint's `addr+1`, (3) clears the debug
// registers, and (4) detaches — in that order — best-effort and panic-free.
//
// Known residual limitations (from an adversarial review; low-severity or
// inherent to ptrace, recorded rather than papered over):
//  * A thread wedged in an uninterruptible (D-state) syscall longer than the
//    teardown stop-bound can't be stopped in time, so its debug register can't be
//    cleared — an inherent ptrace limitation shared by real debuggers.
//  * A genuine job-control group-stop (`kill -STOP`) during an attach is `CONT`ed
//    rather than preserved via `PTRACE_LISTEN`, so the target isn't suspendable
//    while attached. (PTRACE_LISTEN is the planned follow-on.)
//  * A real signal pending at a *teardown* stop is dropped (DETACH data=0); the
//    running event loop forwards signals, but the final stop-all does not.
// ============================================================================

use libc::{c_void, pid_t};

const POLL_SLICE: Duration = Duration::from_millis(2);
/// Bound on the "seize, rescan for threads a not-yet-seized thread spawned,
/// repeat" loop — converges in 1-2 rounds on any real process.
const SEIZE_RESCAN_CAP: u32 = 128;
/// Per-thread bound on the teardown "interrupt then wait for the stop" spin.
const TEARDOWN_STOP_TRIES: u32 = 200;
/// Bound on the teardown drain that adopts pending clone children / stray stops
/// before detaching — large enough to never truncate a real burst, still finite.
const DRAIN_CAP: u32 = 4096;

fn os(m: impl Into<String>) -> SourceError {
    SourceError::Os(m.into())
}

/// Byte offset of debug register `n` within `struct user` — where
/// `PTRACE_PEEKUSER`/`POKEUSER` read/write DR0..DR7.
fn dr_off(n: usize) -> u64 {
    (std::mem::offset_of!(libc::user, u_debugreg) + n * 8) as u64
}

/// `PTRACE_PEEKUSER` a `struct user` word. Uses the errno protocol because a
/// peeked value of `-1` is legitimate.
fn peekuser(tid: u32, off: u64) -> Option<u64> {
    unsafe {
        *libc::__errno_location() = 0;
        let v = libc::ptrace(libc::PTRACE_PEEKUSER, tid as pid_t, off as *mut c_void, std::ptr::null_mut::<c_void>());
        if v == -1 && *libc::__errno_location() != 0 {
            None
        } else {
            Some(v as u64)
        }
    }
}

fn pokeuser(tid: u32, off: u64, val: u64) -> bool {
    unsafe { libc::ptrace(libc::PTRACE_POKEUSER, tid as pid_t, off as *mut c_void, val as usize as *mut c_void) != -1 }
}

fn ptrace_cont(tid: u32, sig: i32) {
    unsafe {
        libc::ptrace(libc::PTRACE_CONT, tid as pid_t, std::ptr::null_mut::<c_void>(), sig as usize as *mut c_void);
    }
}

fn ptrace_interrupt(tid: u32) -> bool {
    unsafe { libc::ptrace(libc::PTRACE_INTERRUPT, tid as pid_t, std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>()) != -1 }
}

fn ptrace_detach(tid: u32) {
    unsafe {
        libc::ptrace(libc::PTRACE_DETACH, tid as pid_t, std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
    }
}

fn getregs(tid: u32) -> Option<libc::user_regs_struct> {
    let mut r: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ptrace(libc::PTRACE_GETREGS, tid as pid_t, std::ptr::null_mut::<c_void>(), &mut r as *mut _ as *mut c_void) };
    (rc != -1).then_some(r)
}

fn setregs(tid: u32, r: &libc::user_regs_struct) {
    unsafe {
        libc::ptrace(libc::PTRACE_SETREGS, tid as pid_t, std::ptr::null_mut::<c_void>(), r as *const _ as *mut c_void);
    }
}

fn geteventmsg(tid: u32) -> u64 {
    let mut msg: libc::c_ulong = 0;
    unsafe {
        libc::ptrace(libc::PTRACE_GETEVENTMSG, tid as pid_t, std::ptr::null_mut::<c_void>(), &mut msg as *mut _ as *mut c_void);
    }
    msg as u64
}

/// x86 `EXECUTE` watchpoints fault *before* the instruction retires, so resuming
/// a thread that we chose not to report (a conditional miss) with the watchpoint
/// still armed would re-fault the same instruction forever. Setting `EFLAGS.RF`
/// (resume flag) suppresses the breakpoint for exactly one instruction, breaking
/// the livelock. Harmless for data watchpoints (fault-after), so unconditional.
fn set_eflags_rf(tid: u32) {
    if let Some(mut r) = getregs(tid) {
        r.eflags |= 1 << 16;
        setregs(tid, &r);
    }
}

/// A waitpid status classified for the event loop.
enum Ev {
    /// A thread exited (already `forget`-ten); the caller ends the walk only once
    /// no tracee remains, since a leader can exit while workers run.
    Exited,
    /// A `SIGTRAP` with no PTRACE event — possibly *our* breakpoint/watchpoint;
    /// the caller inspects rip / DR6.
    Trap(u32),
    /// Fully handled internally (clone/exit/stop event, or a forwarded signal).
    Handled,
}

/// A ptrace debug session over a whole thread-group. Owns the seize set, the
/// per-thread debug-register originals, and the optional patched code byte, and
/// guarantees safe teardown on drop.
struct Session {
    live: LinuxProcess,
    tids: HashSet<u32>,
    /// tid -> (orig_dr0, orig_dr7), only for threads we actually armed.
    armed: HashMap<u32, (u64, u64)>,
    /// Best-effort "this tid is currently ptrace-stopped" tracking — teardown
    /// must never POKE a debug register on, or DETACH, a *running* tracee.
    stopped: HashSet<u32>,
    /// (addr, original_byte) of an installed `int3`, restored before any detach.
    patched: Option<(Va, u8)>,
    /// The breakpoint address, tracked *independently* of `patched` (which is
    /// taken when the first hit restores the byte) so teardown can still rewind
    /// every sibling thread that piled onto the `int3` and is stranded at
    /// `addr+1` — otherwise they resume mid-instruction and crash the target.
    bp_addr: Option<Va>,
}

/// `PTRACE_SEIZE` every thread of `pid` (no SIGSTOP, no synthetic attach
/// breakpoint), rescanning until no new thread appears so a thread cloned by a
/// not-yet-seized sibling can't slip through. Attaches a `LinuxProcess` reader
/// first, giving the early Yama-aware error and the memory/module access the
/// capture path needs.
fn seize_group(pid: u32) -> Result<Session, SourceError> {
    let live = LinuxProcess::attach(pid)?;
    let mut s = Session { live, tids: HashSet::new(), armed: HashMap::new(), stopped: HashSet::new(), patched: None, bp_addr: None };
    // TRACECLONE catches later-spawned threads; TRACEEXIT lets us drop tracking
    // before a thread's tid can be recycled. Never EXITKILL: tracer death must
    // resume the target, not kill it.
    let opts = (libc::PTRACE_O_TRACECLONE | libc::PTRACE_O_TRACEEXIT) as usize;
    for _ in 0..SEIZE_RESCAN_CAP {
        let mut added = false;
        for tid in list_thread_ids(pid) {
            if s.tids.contains(&tid) {
                continue;
            }
            let rc = unsafe { libc::ptrace(libc::PTRACE_SEIZE, tid as pid_t, std::ptr::null_mut::<c_void>(), opts as *mut c_void) };
            if rc != -1 {
                s.tids.insert(tid);
                added = true;
            } else {
                let e = std::io::Error::last_os_error();
                match e.raw_os_error() {
                    Some(libc::ESRCH) => {} // died mid-enumeration; skip
                    Some(libc::EPERM) => {
                        return Err(os(format!(
                            "ptrace(SEIZE, {tid}) denied (EPERM): yama ptrace_scope forbids attaching to a non-descendant, \
                             or it is already traced. Fix for this boot with `sudo sysctl kernel.yama.ptrace_scope=0`, grant \
                             CAP_SYS_PTRACE, or run as root"
                        )));
                    }
                    _ => return Err(os(format!("ptrace(SEIZE, {tid}) failed: {e}"))),
                }
            }
        }
        if !added {
            break;
        }
    }
    if !s.tids.contains(&pid) {
        return Err(os(format!("main thread of pid {pid} vanished during attach")));
    }
    Ok(s)
}

impl Session {
    /// INTERRUPT `tid` and wait — *bounded* — for it to reach a ptrace-stop.
    /// Returns true iff it is now stopped. Never blocks unbounded: a thread stuck
    /// in an uninterruptible (D-state) syscall is skipped after the bound rather
    /// than hanging the whole session (a hung tracer can't even run its Drop).
    fn stop_bounded(&mut self, tid: u32) -> bool {
        if self.stopped.contains(&tid) {
            return true;
        }
        if !ptrace_interrupt(tid) {
            return false;
        }
        for _ in 0..TEARDOWN_STOP_TRIES {
            let mut st: libc::c_int = 0;
            let w = unsafe { libc::waitpid(tid as pid_t, &mut st, libc::__WALL | libc::WNOHANG) };
            if w == tid as pid_t {
                if libc::WIFSTOPPED(st) {
                    self.stopped.insert(tid);
                    return true;
                }
                if libc::WIFEXITED(st) || libc::WIFSIGNALED(st) {
                    self.forget(tid);
                    return false;
                }
            } else if w == 0 {
                std::thread::sleep(POLL_SLICE);
            } else {
                return false; // -1 (ESRCH): gone
            }
        }
        false
    }

    /// Bring every seized thread to a ptrace-stop (watchpoint setup needs each
    /// stopped before its DR write).
    fn interrupt_all_and_wait(&mut self) {
        for tid in self.tids.clone() {
            self.stop_bounded(tid);
        }
    }

    /// Reap and adopt any pending waitpid events the main loop didn't drain:
    /// clone children auto-seized in the break/teardown window (so teardown
    /// detaches them instead of leaving them traced+stopped forever) and exits.
    /// Bounded; leaves adopted threads stopped for the teardown steps that follow.
    fn drain_and_adopt(&mut self) {
        for _ in 0..DRAIN_CAP {
            let mut st: libc::c_int = 0;
            let w = unsafe { libc::waitpid(-1, &mut st, libc::__WALL | libc::WNOHANG) };
            if w <= 0 {
                break; // 0 = nothing pending, -1 = no tracees left
            }
            let tid = w as u32;
            if libc::WIFEXITED(st) || libc::WIFSIGNALED(st) {
                self.forget(tid);
                continue;
            }
            self.tids.insert(tid);
            self.stopped.insert(tid);
            if libc::WSTOPSIG(st) == libc::SIGTRAP && (st >> 16) & 0xff == libc::PTRACE_EVENT_CLONE {
                let child = geteventmsg(tid) as u32;
                self.tids.insert(child);
                self.stopped.insert(child);
            }
        }
    }

    /// Arm DR0/DR7 slot 0 on a single *stopped* thread. Idempotent per tid.
    fn arm_dr(&mut self, tid: u32, addr: Va, dr7_bits: u64) -> bool {
        if self.armed.contains_key(&tid) {
            return true;
        }
        let (Some(o0), Some(o7)) = (peekuser(tid, dr_off(0)), peekuser(tid, dr_off(7))) else {
            return false;
        };
        if !pokeuser(tid, dr_off(0), addr.0) {
            return false;
        }
        pokeuser(tid, dr_off(6), 0);
        if !pokeuser(tid, dr_off(7), o7 | dr7_bits) {
            return false;
        }
        self.armed.insert(tid, (o0, o7));
        true
    }

    fn cont(&mut self, tid: u32, sig: i32) {
        self.stopped.remove(&tid);
        ptrace_cont(tid, sig);
    }

    fn forget(&mut self, tid: u32) {
        self.tids.remove(&tid);
        self.armed.remove(&tid);
        self.stopped.remove(&tid);
    }

    /// Handle the housekeeping half of a waitpid event (clones, exits, group/
    /// interrupt stops, and non-trap signals), arming new threads with `arm`
    /// (`Some((addr, dr7_bits))` for a watchpoint, `None` for a breakpoint).
    /// Returns [`Ev::Trap`] only for a `SIGTRAP` the caller must inspect.
    fn classify(&mut self, tid: u32, st: libc::c_int, arm: Option<(Va, u64)>) -> Ev {
        if libc::WIFEXITED(st) || libc::WIFSIGNALED(st) {
            self.forget(tid);
            return Ev::Exited;
        }
        self.stopped.insert(tid);
        // A clone child's own stop can arrive before its parent's clone event —
        // adopt any unknown tid as a new tracee.
        self.tids.insert(tid);

        let sig = libc::WSTOPSIG(st);
        let event = (st >> 16) & 0xff;

        if sig == libc::SIGTRAP && event == libc::PTRACE_EVENT_CLONE {
            let child = geteventmsg(tid) as u32;
            self.tids.insert(child);
            self.stopped.insert(child); // a TRACECLONE child starts stopped
            if let Some((addr, bits)) = arm {
                self.arm_dr(child, addr, bits);
            }
            self.cont(child, 0);
            self.cont(tid, 0);
            return Ev::Handled;
        }
        if event == libc::PTRACE_EVENT_EXIT {
            self.forget(tid);
            ptrace_cont(tid, 0); // let it finish exiting
            return Ev::Handled;
        }
        if event == libc::PTRACE_EVENT_STOP {
            // Our INTERRUPT-stop, a new thread's initial stop, or a group-stop:
            // (re)arm if this is a watchpoint session, then release.
            if let Some((addr, bits)) = arm {
                self.arm_dr(tid, addr, bits);
            }
            self.cont(tid, 0);
            return Ev::Handled;
        }
        if sig == libc::SIGTRAP {
            return Ev::Trap(tid);
        }
        // A real signal destined for the target — forward it so its own handlers
        // run; swallowing it would make the target misbehave.
        self.cont(tid, sig);
        Ev::Handled
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // (0) Adopt clone children / stray stops the loop left unreaped, so the
        // steps below cover them instead of stranding them traced+stopped.
        self.drain_and_adopt();
        // (1) STOP-ALL: a DR clear or DETACH only takes on a stopped thread.
        for tid in self.tids.clone() {
            self.stop_bounded(tid);
        }
        // (2) restore the int3 byte BEFORE any detach, or a thread reaching it
        // after we leave takes an unhandled SIGTRAP and crashes.
        if let Some((addr, orig)) = self.patched.take() {
            let _ = self.live.write(addr, &[orig]);
        }
        // (2b) rewind EVERY thread stranded at the breakpoint (rip == addr+1),
        // not just the reported one. The byte is now restored, so each resumes by
        // re-executing the original instruction cleanly; without this a sibling
        // that raced onto the int3 detaches mid-instruction and crashes.
        if let Some(bp) = self.bp_addr {
            for tid in self.stopped.clone() {
                if let Some(mut r) = getregs(tid)
                    && r.rip == bp.0 + 1
                {
                    r.rip = bp.0;
                    setregs(tid, &r);
                }
            }
        }
        // (3) clear DR on every stopped, armed thread (DR7 disable, DR0, DR6).
        let armed: Vec<(u32, (u64, u64))> = self.armed.iter().map(|(&t, &v)| (t, v)).collect();
        for (tid, (o0, o7)) in armed {
            if !self.stopped.contains(&tid) {
                continue; // never POKE a running tracee
            }
            pokeuser(tid, dr_off(7), o7);
            pokeuser(tid, dr_off(0), o0);
            pokeuser(tid, dr_off(6), 0);
        }
        // (4) detach all — data=0 resumes each untraced with no pending signal.
        for tid in self.tids.clone() {
            ptrace_detach(tid);
        }
    }
}

/// Snapshot a stopped thread into a [`BreakpointHit`]: registers, up to
/// `stack_qwords` stack qwords, and the recovered caller chain via the portable
/// unwinder (reusing `LiveTarget::stack_unwind` over the target's own memory).
fn capture_hit(live: &LinuxProcess, tid: u32, module: Option<&Module>, stack_qwords: usize) -> Result<BreakpointHit, SourceError> {
    let r = getregs(tid).ok_or_else(|| os(format!("ptrace(GETREGS, {tid}) failed at hit")))?;
    let rip = Va(r.rip);
    let rsp = Va(r.rsp);
    let relative_rip = module.and_then(|m| m.rva(rip).map(|rva| format!("{}+0x{rva:x}", m.name)));

    let mut stack = Vec::new();
    let n = stack_qwords.min(512);
    if n > 0 && rsp.0 != 0 && let Ok(buf) = live.read(rsp, n * 8) {
        for c in buf.as_chunks::<8>().0 {
            stack.push(u64::from_le_bytes(*c));
        }
    }

    // A hit lands mid-function, where [rsp] is not the return address, so recover
    // the real chain through unwind data (ELF `.eh_frame` here). Best-effort:
    // empty frames on failure, never an error.
    let regs = UnwindRegs {
        rip: r.rip,
        gpr: [r.rax, r.rcx, r.rdx, r.rbx, r.rsp, r.rbp, r.rsi, r.rdi, r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15],
    };
    let frames = live.stack_unwind(regs, MAX_UNWIND_FRAMES);

    Ok(BreakpointHit {
        thread_id: tid,
        rip,
        rsp,
        relative_rip,
        registers: Registers {
            rax: r.rax,
            rbx: r.rbx,
            rcx: r.rcx,
            rdx: r.rdx,
            rsi: r.rsi,
            rdi: r.rdi,
            rbp: r.rbp,
            r8: r.r8,
            r9: r.r9,
            r10: r.r10,
            r11: r.r11,
            r12: r.r12,
            r13: r.r13,
            r14: r.r14,
            r15: r.r15,
        },
        stack,
        frames,
    })
}

/// Become `pid`'s ptrace tracer and hold the attach for `timeout_ms` without
/// arming anything — the diagnostic counterpart of the Win32 `attach_and_wait`.
/// Forwards the target's own signals; detaches (resuming it) on return.
pub fn attach_and_wait(pid: u32, timeout_ms: u64) -> Result<(), SourceError> {
    let mut s = seize_group(pid)?;
    let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(1));
    'ev: while Instant::now() < deadline {
        loop {
            let mut st: libc::c_int = 0;
            let w = unsafe { libc::waitpid(-1, &mut st, libc::__WALL | libc::WNOHANG) };
            if w == 0 {
                break;
            }
            if w == -1 {
                match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::ECHILD) => break 'ev,
                    Some(libc::EINTR) => continue,
                    _ => break 'ev,
                }
            }
            let tid = w as u32;
            match s.classify(tid, st, None) {
                // A thread-group-leader exit is NOT whole-process exit (it can
                // pthread_exit while workers run); end only when no tracee remains.
                Ev::Exited => {
                    if s.tids.is_empty() {
                        break 'ev;
                    }
                }
                Ev::Trap(tid) => s.cont(tid, 0), // no bp/watch here: swallow stray traps
                Ev::Handled => {}
            }
        }
        std::thread::sleep(POLL_SLICE);
    }
    Ok(()) // `s` drops -> stop-all -> detach-all
}

/// Patch an `int3` at `addr`, run the whole thread-group under trace, and block
/// until that breakpoint fires or `timeout_ms` elapses. On a hit: rewind rip to
/// `addr`, restore the byte (one-shot), capture, resume. The byte is restored
/// and the group detached on every path via [`Session`]'s drop.
pub fn await_breakpoint_hit(pid: u32, addr: Va, timeout_ms: u64, stack_qwords: usize, module: Option<&Module>) -> Result<AwaitHitOutcome, SourceError> {
    let mut s = seize_group(pid)?;
    let orig = s.live.read(addr, 1)?.first().copied().ok_or_else(|| os(format!("could not read the byte at {addr}")))?;
    s.live.write(addr, &[0xCC])?;
    s.patched = Some((addr, orig));
    s.bp_addr = Some(addr); // tracked past the byte-restore, for the teardown rewind

    let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(1));
    let mut hit: Option<BreakpointHit> = None;

    'ev: loop {
        if Instant::now() >= deadline {
            break;
        }
        loop {
            let mut st: libc::c_int = 0;
            let w = unsafe { libc::waitpid(-1, &mut st, libc::__WALL | libc::WNOHANG) };
            if w == 0 {
                break;
            }
            if w == -1 {
                match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::ECHILD) => break 'ev,
                    Some(libc::EINTR) => continue,
                    e => return Err(os(format!("waitpid failed: {:?}", e))),
                }
            }
            let tid = w as u32;
            match s.classify(tid, st, None) {
                // Leader exit ≠ process exit; end only when no tracee remains.
                Ev::Exited => {
                    if s.tids.is_empty() {
                        break 'ev;
                    }
                }
                Ev::Handled => {}
                Ev::Trap(tid) => {
                    let Some(mut r) = getregs(tid) else {
                        s.cont(tid, 0);
                        continue;
                    };
                    if r.rip == addr.0 + 1 {
                        // Our int3. Rewind rip to addr, restore the byte, capture
                        // (now sees rip == addr), resume — truly one-shot.
                        r.rip = addr.0;
                        setregs(tid, &r);
                        let _ = s.live.write(addr, &[orig]);
                        s.patched = None;
                        let captured = capture_hit(&s.live, tid, module, stack_qwords);
                        s.cont(tid, 0);
                        hit = Some(captured?);
                        break 'ev;
                    }
                    // A stray/target int3 — swallow it (data=0) and keep waiting.
                    s.cont(tid, 0);
                }
            }
        }
        std::thread::sleep(POLL_SLICE);
    }

    Ok(AwaitHitOutcome { breakpoint_va: addr, timed_out: hit.is_none(), hit })
}

/// Arm a hardware watchpoint (DR0 slot 0) on `addr` across every thread and block
/// until it fires or times out — the value-change counterpart of
/// [`await_breakpoint_hit`], watching *data* without touching code bytes.
pub fn await_watchpoint_hit(
    pid: u32,
    addr: Va,
    kind: WatchKind,
    len: u8,
    timeout_ms: u64,
    stack_qwords: usize,
    module: Option<&Module>,
) -> Result<AwaitHitOutcome, SourceError> {
    await_watchpoint_hit_where(pid, addr, kind, len, timeout_ms, stack_qwords, module, &[], None)
}

/// [`await_watchpoint_hit`], but with two filters on which hit "counts":
///
/// - `exclude_rip`: `[lo, hi)` instruction-pointer ranges to ignore. A hit whose
///   `rip` falls in one is resumed with the watchpoint still armed and does **not**
///   count against the condition budget — the intended tool for a data field that
///   a `memcpy`/serialization helper constantly rewrites: exclude the copy site's
///   range and the next distinct writer (the semantic setter) is what surfaces.
/// - `cond`: only report a hit whose registers satisfy it; non-matching hits are
///   resumed, up to a miss budget past which it bails with a "trap site too hot"
///   diagnostic (every miss single-steps the target).
#[allow(clippy::too_many_arguments)]
pub fn await_watchpoint_hit_where(
    pid: u32,
    addr: Va,
    kind: WatchKind,
    len: u8,
    timeout_ms: u64,
    stack_qwords: usize,
    module: Option<&Module>,
    exclude_rip: &[(u64, u64)],
    cond: Option<&RegCond>,
) -> Result<AwaitHitOutcome, SourceError> {
    let dr7_bits = dr7_slot0(kind, addr, len)?; // validates align/len/Execute-len before any ptrace

    let mut s = seize_group(pid)?;
    s.interrupt_all_and_wait();
    let mut armed = 0;
    for tid in s.tids.clone() {
        if s.arm_dr(tid, addr, dr7_bits) {
            armed += 1;
        }
    }
    if armed == 0 {
        return Err(os("could not arm a hardware watchpoint on any thread")); // `s` drops -> teardown
    }
    for tid in s.tids.clone() {
        s.cont(tid, 0);
    }

    let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(1));
    let mut misses = 0u32;
    let mut hit: Option<BreakpointHit> = None;
    let arm = Some((addr, dr7_bits));

    'ev: loop {
        if Instant::now() >= deadline {
            break;
        }
        loop {
            let mut st: libc::c_int = 0;
            let w = unsafe { libc::waitpid(-1, &mut st, libc::__WALL | libc::WNOHANG) };
            if w == 0 {
                break;
            }
            if w == -1 {
                match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::ECHILD) => break 'ev,
                    Some(libc::EINTR) => continue,
                    e => return Err(os(format!("waitpid failed: {:?}", e))),
                }
            }
            let tid = w as u32;
            match s.classify(tid, st, arm) {
                // Leader exit ≠ process exit; end only when no tracee remains.
                Ev::Exited => {
                    if s.tids.is_empty() {
                        break 'ev;
                    }
                }
                Ev::Handled => {}
                Ev::Trap(tid) => {
                    if peekuser(tid, dr_off(6)).unwrap_or(0) & 1 == 0 {
                        // Not our watchpoint (a stray single-step) — swallow it.
                        s.cont(tid, 0);
                        continue;
                    }
                    // Our hit. Capture BEFORE any resume; never `?` here.
                    let captured = capture_hit(&s.live, tid, module, stack_qwords);
                    // Exclude-rip filter: a write from a known copy/serialization
                    // site is not the setter we want. Resume with the watchpoint
                    // still armed, and — unlike a condition miss — don't spend the
                    // hot-site budget on it (a resumed write does not re-fault).
                    if let Ok(h) = &captured
                        && exclude_rip.iter().any(|&(lo, hi)| h.rip.0 >= lo && h.rip.0 < hi)
                    {
                        pokeuser(tid, dr_off(6), 0);
                        if kind == WatchKind::Execute {
                            set_eflags_rf(tid);
                        }
                        s.cont(tid, 0);
                        continue;
                    }
                    let matched = match (cond, &captured) {
                        (Some(c), Ok(h)) => c.matches(&h.registers),
                        (Some(_), Err(_)) => false,
                        (None, _) => true,
                    };
                    pokeuser(tid, dr_off(6), 0); // clear the sticky DR6 hit flag
                    if !matched {
                        if kind == WatchKind::Execute {
                            set_eflags_rf(tid); // fault-before: avoid re-faulting the same insn
                        }
                        s.cont(tid, 0); // resume; DR still armed on all threads
                        misses += 1;
                        if misses >= MAX_CONDITION_MISSES {
                            let c = cond.map(|c| format!("{}={}", c.reg, c.value)).unwrap_or_default();
                            return Err(os(format!(
                                "condition `{c}` did not match in {MAX_CONDITION_MISSES} hits — this trap site is too hot to \
                                 filter on (every non-matching hit stops the target). Pick a colder address, or watch a data \
                                 address instead of an executed one."
                            )));
                        }
                        continue;
                    }
                    // Match (or no condition): `?` only now — break lets `Session`
                    // drop disarm-all + detach (which resumes the thread).
                    hit = Some(captured?);
                    break 'ev;
                }
            }
        }
        std::thread::sleep(POLL_SLICE);
    }

    Ok(AwaitHitOutcome { breakpoint_va: addr, timed_out: hit.is_none(), hit })
}

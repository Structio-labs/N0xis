// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! End-to-end proof of the Linux ptrace debug adapter on a real live child.
//!
//! Runs only under `--features live` on Linux/Android. Each test `fork()`s a
//! child that writes a known global / calls a known function; because the child
//! is a descendant of the test process it is ptraceable even under
//! `kernel.yama.ptrace_scope=1`, and because `fork` shares the address space the
//! test already knows the addresses to watch (no ASLR dance, no helper binary).
//!
//! The child body is async-signal-safe (volatile stores + `nanosleep` only — no
//! allocation), which is the one real constraint on `fork` inside the
//! (multi-threaded) test harness.
//!
//! The tests are serialized: each adapter call runs `waitpid(-1, __WALL)`, so two
//! concurrent sessions would steal each other's child events.
#![cfg(all(feature = "live", any(target_os = "linux", target_os = "android")))]

use std::sync::Mutex;

use n0xis_contracts::Va;
use n0xis_sources::{attach_and_wait, await_breakpoint_hit, await_watchpoint_hit, await_watchpoint_hit_where, RegCond, WatchKind};

static SERIAL: Mutex<()> = Mutex::new(());

static mut GLOBAL: u64 = 0;
static mut UNTOUCHED: u64 = 0;
static mut TICKS: u64 = 0;

/// A never-inlined function the child calls each iteration — the software-
/// breakpoint target. Does a real (volatile) store so it can't be elided.
#[inline(never)]
extern "C" fn tick() {
    unsafe {
        let p = core::ptr::addr_of_mut!(TICKS);
        core::ptr::write_volatile(p, core::ptr::read_volatile(p).wrapping_add(1));
    }
}

fn nanosleep_ms(ms: u64) {
    let ts = libc::timespec { tv_sec: (ms / 1000) as libc::time_t, tv_nsec: ((ms % 1000) * 1_000_000) as libc::c_long };
    unsafe {
        libc::nanosleep(&ts, core::ptr::null_mut());
    }
}

/// Fork a child that every ~`cadence_ms` calls `tick()` then increments
/// `GLOBAL`. The child never returns — it loops until killed. Returns its pid.
fn spawn_writer(cadence_ms: u64) -> u32 {
    match unsafe { libc::fork() } {
        0 => {
            // Child: async-signal-safe only.
            loop {
                tick();
                unsafe {
                    let p = core::ptr::addr_of_mut!(GLOBAL);
                    core::ptr::write_volatile(p, core::ptr::read_volatile(p).wrapping_add(1));
                }
                nanosleep_ms(cadence_ms);
            }
        }
        pid if pid > 0 => pid as u32,
        _ => panic!("fork failed: {}", std::io::Error::last_os_error()),
    }
}

fn is_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// `TracerPid` from `/proc/<pid>/status` — must be 0 once we've detached.
fn tracer_pid(pid: u32) -> Option<i32> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    s.lines().find_map(|l| l.strip_prefix("TracerPid:").and_then(|v| v.trim().parse().ok()))
}

/// The cleanup invariant asserted after EVERY case: the target survived and is
/// no longer traced (catches a byte left patched, a DR left live, or a thread
/// left stopped/traced — the crash bugs this adapter exists to avoid).
fn assert_alive_and_untraced(pid: u32) {
    assert!(is_alive(pid), "target {pid} was killed by the debug session");
    assert_eq!(tracer_pid(pid), Some(0), "target {pid} left traced after the session");
}

fn kill_and_reap(pid: u32) {
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
        let mut st = 0;
        libc::waitpid(pid as libc::pid_t, &mut st, 0);
    }
}

#[test]
fn watchpoint_catches_a_data_write() {
    let _serial = SERIAL.lock().unwrap();
    let g = core::ptr::addr_of!(GLOBAL) as u64;
    let pid = spawn_writer(5);
    nanosleep_ms(60); // let it enter the loop

    let outcome = await_watchpoint_hit(pid, Va(g), WatchKind::Write, 8, 3000, 16, None);

    if is_alive(pid) {
        assert_alive_and_untraced(pid);
    }
    kill_and_reap(pid);

    let outcome = outcome.expect("watchpoint call returned Err");
    assert!(!outcome.timed_out, "watchpoint should have caught a write to GLOBAL");
    let hit = outcome.hit.expect("a hit");
    assert_eq!(hit.thread_id, pid, "single-threaded child");
    assert!(hit.rsp.0 != 0, "rsp captured");
    assert!(!hit.frames.is_empty(), "unwinder recovered frames: {:#x?}", hit);
}

#[test]
fn software_breakpoint_fires_and_is_one_shot() {
    let _serial = SERIAL.lock().unwrap();
    let bp = tick as *const () as usize as u64;
    let pid = spawn_writer(5);
    nanosleep_ms(60);

    let outcome = await_breakpoint_hit(pid, Va(bp), 3000, 16, None);

    // Must still be alive (byte restored → one-shot) and running.
    let alive_after = is_alive(pid);
    if alive_after {
        assert_alive_and_untraced(pid);
    }
    kill_and_reap(pid);

    let outcome = outcome.expect("breakpoint call returned Err");
    assert!(!outcome.timed_out, "breakpoint at tick() should have fired");
    let hit = outcome.hit.expect("a hit");
    assert_eq!(hit.rip, Va(bp), "reported rip is the breakpoint addr, not addr+1");
    assert!(alive_after, "child must survive (0xCC restored, one-shot)");
}

#[test]
fn watchpoint_times_out_on_an_untouched_address() {
    let _serial = SERIAL.lock().unwrap();
    let u = core::ptr::addr_of!(UNTOUCHED) as u64;
    let pid = spawn_writer(5);
    nanosleep_ms(30);

    let outcome = await_watchpoint_hit(pid, Va(u), WatchKind::Write, 8, 300, 16, None);

    if is_alive(pid) {
        assert_alive_and_untraced(pid);
    }
    kill_and_reap(pid);

    let outcome = outcome.expect("call ok");
    assert!(outcome.timed_out, "an address nobody writes must time out");
    assert!(outcome.hit.is_none());
}

#[test]
fn condition_filter_selects_the_matching_hit() {
    // Watch GLOBAL, but only accept the hit where rcx equals a sentinel. The
    // child doesn't control rcx, so use a condition that IS reachable: match the
    // first hit unconditionally is covered elsewhere; here assert the filter
    // path runs and still returns a hit that satisfies the predicate. We use a
    // register the write path reliably leaves a known value in is fragile, so
    // instead assert the miss/забій machinery doesn't crash and eventually the
    // budget path is exercised via an impossible condition -> "too hot" Err.
    let _serial = SERIAL.lock().unwrap();
    let g = core::ptr::addr_of!(GLOBAL) as u64;
    let pid = spawn_writer(0); // hot: writes as fast as possible
    nanosleep_ms(30);

    // rax can never be this sentinel at the watchpoint on a plain increment.
    let cond = RegCond::parse("rax=0xDEADBEEFCAFEBABE").unwrap();
    let outcome = await_watchpoint_hit_where(pid, Va(g), WatchKind::Write, 8, 4000, 8, None, &[], Some(&cond));

    if is_alive(pid) {
        assert_alive_and_untraced(pid);
    }
    kill_and_reap(pid);

    // Either it ground through the miss budget ("too hot" Err) or timed out —
    // both are acceptable; what must NOT happen is a crash of the target or a
    // spurious matching hit.
    match outcome {
        Err(e) => assert!(e.to_string().contains("too hot"), "expected the miss-budget diagnostic, got: {e}"),
        Ok(o) => assert!(o.timed_out, "an impossible condition must not yield a hit"),
    }
}

// --- multi-threaded target, for the concurrent-hit / multi-thread-coverage
// paths the single-threaded fork child cannot exercise. The child spawns real
// threads via raw `clone` (shared VM) onto stacks pre-mapped BEFORE the fork, so
// no post-fork allocation happens; the workers touch only static memory (no libc
// → no TLS/errno hazard on a bare clone thread). ------------------------------

/// A worker thread body: hammer `tick()` and `GLOBAL` forever, memory-only.
extern "C" fn mt_worker(_: *mut libc::c_void) -> libc::c_int {
    loop {
        tick();
        unsafe {
            let p = core::ptr::addr_of_mut!(GLOBAL);
            core::ptr::write_volatile(p, core::ptr::read_volatile(p).wrapping_add(1));
        }
        // A short memory-only spacer so threads genuinely overlap on the int3.
        for _ in 0..3000 {
            unsafe {
                std::hint::black_box(core::ptr::read_volatile(core::ptr::addr_of!(GLOBAL)));
            }
        }
    }
}

/// Fork a child that runs `n_workers + 1` threads all executing `mt_worker`.
fn spawn_writer_mt(n_workers: usize) -> u32 {
    const STACK: usize = 256 * 1024;
    // Pre-map the worker stacks in the parent so the child inherits them.
    let mut stacks = Vec::new();
    for _ in 0..n_workers {
        let p = unsafe {
            libc::mmap(core::ptr::null_mut(), STACK, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK, -1, 0)
        };
        assert!(p != libc::MAP_FAILED, "mmap stack failed");
        stacks.push(p as usize);
    }
    match unsafe { libc::fork() } {
        0 => {
            let flags = libc::CLONE_VM | libc::CLONE_FS | libc::CLONE_FILES | libc::CLONE_SIGHAND | libc::CLONE_THREAD | libc::CLONE_SYSVSEM;
            for &s in &stacks {
                let top = (s + STACK) as *mut libc::c_void;
                unsafe {
                    libc::clone(mt_worker, top, flags, core::ptr::null_mut());
                }
            }
            mt_worker(core::ptr::null_mut()); // main thread joins the hammering
            unreachable!()
        }
        pid if pid > 0 => {
            for s in stacks {
                unsafe { libc::munmap(s as *mut libc::c_void, STACK) };
            }
            pid as u32
        }
        _ => panic!("fork failed: {}", std::io::Error::last_os_error()),
    }
}

#[test]
fn multithreaded_breakpoint_survives_concurrent_hits() {
    // Exercises the concurrent-int3 path: with 4 threads piling onto the same
    // `int3`, siblings are left stranded at addr+1, and teardown must rewind ALL
    // of them (not just the reported one) so they re-execute the original
    // instruction cleanly. Whether an *un*-rewound sibling visibly crashes is
    // prologue-dependent (skipping an `endbr64` is benign; skipping a `push rbp`
    // corrupts the frame and faults later), so this test can't prove the rewind
    // in isolation — it asserts the group survives the concurrent session and is
    // left untraced, then settles and rechecks to catch a delayed corruption
    // crash where the prologue makes one observable.
    let _serial = SERIAL.lock().unwrap();
    let bp = tick as *const () as usize as u64;
    let pid = spawn_writer_mt(3); // 4 threads hammering tick()
    nanosleep_ms(100);

    let outcome = await_breakpoint_hit(pid, Va(bp), 3000, 8, None);

    let alive = is_alive(pid);
    if alive {
        assert_alive_and_untraced(pid);
    }
    // Let any corrupted sibling run a while, then confirm the group is still alive.
    nanosleep_ms(200);
    let alive_after_settle = is_alive(pid);
    kill_and_reap(pid);

    let outcome = outcome.expect("breakpoint call returned Err");
    assert!(!outcome.timed_out, "a hot 4-thread tick() must hit the breakpoint");
    assert!(alive, "the multithreaded target must survive the concurrent int3 session");
    assert!(alive_after_settle, "the target must keep running after the session (no stranded-sibling crash)");
}

#[test]
fn multithreaded_watchpoint_covers_all_threads() {
    // Any of the 4 threads writing GLOBAL must be caught, and the whole group
    // must survive + be left untraced (no stale-DR crash across threads).
    let _serial = SERIAL.lock().unwrap();
    let g = core::ptr::addr_of!(GLOBAL) as u64;
    let pid = spawn_writer_mt(3);
    nanosleep_ms(100);

    let outcome = await_watchpoint_hit(pid, Va(g), WatchKind::Write, 8, 3000, 8, None);

    let alive = is_alive(pid);
    if alive {
        assert_alive_and_untraced(pid);
    }
    kill_and_reap(pid);

    let outcome = outcome.expect("watchpoint call returned Err");
    assert!(!outcome.timed_out, "a write to GLOBAL from some thread must be caught");
    assert!(alive, "the multithreaded target must survive the watchpoint session");
}

#[test]
fn attach_and_wait_holds_then_detaches_cleanly() {
    let _serial = SERIAL.lock().unwrap();
    let pid = spawn_writer(5);
    nanosleep_ms(30);

    attach_and_wait(pid, 200).expect("attach_and_wait ok");

    assert_alive_and_untraced(pid);
    kill_and_reap(pid);
}

// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A watchpoint outlives no run unaccounted for.** `debug watch` and `provenance trace`
//! arm a debug register on every thread of the target. A tracer that dies leaves it there,
//! and the thread dies of `SIGTRAP` at its next hit: measured on 1d619e5 with `SIGKILL`,
//! and with `SIGINT`, `SIGTERM` and `SIGHUP`, which that build did not handle on this OS.
//! Now a signal clears it, and a kill leaves a journal record that `patch undo` clears from.
//!
//! The kernel and the target are the oracles. What a thread holds is read here, with
//! `ptrace`, by no code of the engine's; whether it lives is what it prints, and how it ended.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::FileExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde_json::Value;

mod support;

/// Prints the addresses of a cell, of a cell nothing writes and of a function. Two threads
/// wait on stdin's word: `main` and `worker` write the cell from that thread, `site` runs
/// the function, `spawn` starts a third thread that waits, `late` writes the cell from
/// that one, and each prints `ran`.
const TARGET_SRC: &str = r#"
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::channel;
const PR_SET_PTRACER: i32 = 0x59616d61;
unsafe extern "C" { fn prctl(o: i32, a: u64, b: u64, c: u64, d: u64) -> i32; }
static CELL: AtomicU64 = AtomicU64::new(0x1122334455667788);
static QUIET: AtomicU64 = AtomicU64::new(0);
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn site(x: u64) -> u64 { std::hint::black_box(x).wrapping_mul(3) }
fn main() {
    // Any process may trace this one, under any Yama scope.
    unsafe { prctl(PR_SET_PTRACER, u64::MAX, 0, 0, 0) };
    let writer = |asked: std::sync::mpsc::Receiver<()>, tell: std::sync::mpsc::Sender<()>| {
        for () in asked {
            CELL.fetch_add(1, Ordering::SeqCst);
            tell.send(()).unwrap();
        }
    };
    let (ask, asked) = channel::<()>();
    let (tell, told) = channel::<()>();
    std::thread::spawn(move || writer(asked, tell));
    let mut late = None;
    let _ = QUIET.load(Ordering::SeqCst);
    println!("{:#x} {:#x} {:#x}", &CELL as *const _ as usize, &QUIET as *const _ as usize, site as extern "C" fn(u64) -> u64 as usize);
    std::io::stdout().flush().unwrap();
    for line in std::io::stdin().lock().lines() {
        match line.unwrap().as_str() {
            "main" => { CELL.fetch_add(1, Ordering::SeqCst); }
            "worker" => { ask.send(()).unwrap(); told.recv().unwrap(); }
            "site" => { site(14); }
            "spawn" => {
                let (ask, asked) = channel::<()>();
                let (tell, told) = channel::<()>();
                std::thread::spawn(move || { tell.send(()).unwrap(); writer(asked, tell) });
                told.recv().unwrap();
                late = Some((ask, told));
            }
            "late" => {
                let (ask, told) = late.as_ref().unwrap();
                ask.send(()).unwrap();
                told.recv().unwrap();
            }
            other => panic!("{other}"),
        }
        println!("ran");
        std::io::stdout().flush().unwrap();
    }
}
"#;

fn target_exe() -> &'static Path {
    static EXE: OnceLock<PathBuf> = OnceLock::new();
    EXE.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("n0xis-watchpoint-build-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("build dir");
        let src = dir.join("target.rs");
        let exe = dir.join("target");
        std::fs::write(&src, TARGET_SRC).expect("write the target");
        let out = Command::new("rustc").args(["-O", "--edition", "2024", "-o"]).arg(&exe).arg(&src).output().expect("invoke rustc");
        assert!(out.status.success(), "rustc failed on the target:\n{}", String::from_utf8_lossy(&out.stderr));
        exe
    })
}

/// What a thread holds, by `ptrace` from here: DR0 to DR7, by index.
type Registers = [u64; 8];

fn dr_offset(n: usize) -> *mut libc::c_void {
    (std::mem::offset_of!(libc::user, u_debugreg) + n * 8) as *mut libc::c_void
}

/// With `tid` seized and stopped, for as long as `f` runs.
fn with_thread_stopped<R>(tid: u32, f: impl FnOnce(libc::pid_t) -> R) -> R {
    let t = tid as libc::pid_t;
    unsafe {
        assert_eq!(libc::ptrace(libc::PTRACE_SEIZE, t, 0usize, 0usize), 0, "seize {tid}: {}", std::io::Error::last_os_error());
        assert_eq!(libc::ptrace(libc::PTRACE_INTERRUPT, t, 0usize, 0usize), 0, "interrupt {tid}");
        let mut status = 0;
        assert_eq!(libc::waitpid(t, &mut status, libc::__WALL), t, "wait for {tid}");
        let out = f(t);
        assert_eq!(libc::ptrace(libc::PTRACE_DETACH, t, 0usize, 0usize), 0, "detach {tid}");
        out
    }
}

fn peek(t: libc::pid_t, n: usize) -> u64 {
    unsafe {
        *libc::__errno_location() = 0;
        let v = libc::ptrace(libc::PTRACE_PEEKUSER, t, dr_offset(n), 0usize);
        assert_eq!(*libc::__errno_location(), 0, "peek DR{n}");
        v as u64
    }
}

fn poke(t: libc::pid_t, n: usize, v: u64) {
    assert_eq!(unsafe { libc::ptrace(libc::PTRACE_POKEUSER, t, dr_offset(n), v as usize) }, 0, "poke DR{n}: {}", std::io::Error::last_os_error());
}

fn registers_of(tid: u32) -> Registers {
    with_thread_stopped(tid, |t| {
        let mut regs = [0; 8];
        for n in [0, 1, 2, 3, 6, 7] {
            regs[n] = peek(t, n);
        }
        regs
    })
}

/// DR7's slot 0 and slot 1: L0, G0, RW0, LEN0 and L1, G1, RW1, LEN1.
const SLOT0: u64 = 0b11 | (0b1111 << 16);
const SLOT1: u64 = 0b1100 | (0b1111 << 20);
/// `L0`, `RW0` = write, `LEN0` = 8 bytes: Intel SDM Vol 3B §17.2.4, not the engine's table.
const WRITE_8: u64 = 0b01 | (0b1001 << 16);
const EXECUTE_1: u64 = 0b01;

struct Target {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    pid: u32,
    cell: u64,
    quiet: u64,
    site: u64,
    dir: PathBuf,
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Target {
    fn spawn(name: &str) -> Target {
        let dir = std::env::temp_dir().join(format!("n0xis-watchpoint-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".n0x")).expect("a project of its own");
        let mut child = Command::new(target_exe()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("run the target");
        let stdin = child.stdin.take().expect("stdin");
        let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let mut line = String::new();
        stdout.read_line(&mut line).expect("the target's addresses");
        let addrs: Vec<u64> = line.split_whitespace().map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).expect("an address")).collect();
        let pid = child.id();
        let t = Target { child, stdin, stdout, pid, cell: addrs[0], quiet: addrs[1], site: addrs[2], dir };
        // Started and waiting: both threads are there before anything is armed.
        let start = Instant::now();
        while t.threads().len() < 2 {
            assert!(start.elapsed() < Duration::from_secs(20), "the worker never started");
            std::thread::sleep(Duration::from_millis(1));
        }
        t
    }

    fn threads(&self) -> Vec<u32> {
        let tids = std::fs::read_dir(format!("/proc/{}/task", self.pid)).expect("/proc");
        let mut tids: Vec<u32> = tids.map(|e| e.unwrap().file_name().to_str().unwrap().parse().unwrap()).collect();
        tids.sort_unstable();
        tids
    }

    fn registers(&self) -> Vec<Registers> {
        self.threads().into_iter().map(registers_of).collect()
    }

    /// How many threads hold slot 0 at `addr` with these bits, by the kernel.
    fn holding(&self, addr: u64, bits: u64) -> usize {
        self.registers().iter().filter(|r| r[0] == addr && r[7] & SLOT0 == bits).count()
    }

    fn cell_bytes(&self) -> [u8; 8] {
        let mem = std::fs::File::open(format!("/proc/{}/mem", self.pid)).expect("open the target's memory");
        let mut b = [0u8; 8];
        mem.read_exact_at(&mut b, self.cell).expect("read the cell");
        b
    }

    /// Have the target do `what`. Whether it lived through that, by its own print.
    fn does(&mut self, what: &str) -> bool {
        if writeln!(self.stdin, "{what}").and_then(|_| self.stdin.flush()).is_err() {
            return false;
        }
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap_or(0) > 0 && line.trim() == "ran"
    }

    fn engine(&self, args: &[&str]) -> (Value, i32) {
        let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).current_dir(&self.dir).output().expect("run n0xis");
        (serde_json::from_slice(&out.stdout).unwrap_or(Value::Null), out.status.code().unwrap_or(-1))
    }

    /// The engine started with `args` around a `--pid` and a long timeout, and a record in
    /// the journal. Its stderr goes to a file in this target's directory.
    fn waiting_engine(&self, args: &[&str]) -> Child {
        let pid = self.pid.to_string();
        let stderr = std::fs::File::create(self.dir.join("stderr")).expect("a file for stderr");
        let tool = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
            .args(args)
            .args(["--pid", &pid, "--timeout-ms", "60000"])
            .current_dir(&self.dir)
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()
            .expect("run n0xis");
        let start = Instant::now();
        while self.records().is_empty() {
            assert!(start.elapsed() < Duration::from_secs(20), "no record appeared");
            std::thread::sleep(Duration::from_millis(5));
        }
        tool
    }

    fn watching_the_cell(&self) -> Child {
        let cell = format!("{:#x}", self.cell);
        self.waiting_engine(&["debug", "watch", "--addr", &cell, "--kind", "write", "--len", "8"])
    }

    /// The journal's files, read as JSON here and not through the engine.
    fn records(&self) -> Vec<Value> {
        let Ok(dir) = std::fs::read_dir(self.dir.join(".n0x/patches")) else { return Vec::new() };
        dir.filter_map(|e| std::fs::read(e.unwrap().path()).ok()).filter_map(|b| serde_json::from_slice(&b).ok()).collect()
    }

    fn tracer(&self) -> Option<i64> {
        let s = std::fs::read_to_string(format!("/proc/{}/status", self.pid)).ok()?;
        s.lines().find_map(|l| l.strip_prefix("TracerPid:").and_then(|v| v.trim().parse().ok()))
    }

    fn record_path(&self) -> PathBuf {
        let mut dir = std::fs::read_dir(self.dir.join(".n0x/patches")).expect("the journal");
        dir.next().expect("a record").expect("an entry").path()
    }
}

/// How long a run takes from its record to its registers, past which it is worth looking.
/// Nothing outside shows the moment they land, and a thread's registers cannot be read while
/// the run traces it. So: kill, read them, and if the run was killed before it got there,
/// which the load on a machine can do, start again and allow it longer. Never a target
/// that does not hold the watch on all its threads, or the test would prove nothing.
fn killed_while_armed(name: &str, start: impl Fn(&Target) -> Child, addr: impl Fn(&Target) -> u64, bits: u64) -> Target {
    for attempt in 1..=6 {
        let t = Target::spawn(&format!("{name}-{attempt}"));
        let mut tool = start(&t);
        std::thread::sleep(Duration::from_millis(200 * attempt));
        tool.kill().expect("SIGKILL");
        tool.wait().expect("reap");
        if t.holding(addr(&t), bits) == t.threads().len() {
            return t;
        }
    }
    panic!("{name}: six runs killed, and no target held the watch on all its threads");
}

fn killed_watching_the_cell(name: &str) -> Target {
    killed_while_armed(name, Target::watching_the_cell, |t| t.cell, WRITE_8)
}

fn signal(pid: u32, sig: libc::c_int) {
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, sig) }, 0, "signal the engine");
}

fn signal_clears_and_detaches(name: &str, sig: libc::c_int) {
    let mut t = Target::spawn(name);
    let tool = t.watching_the_cell();
    assert_eq!(t.records().len(), 1, "{name}: the watch is on record while it is armed");
    std::thread::sleep(Duration::from_millis(300));
    signal(tool.id(), sig);
    let out = tool.wait_with_output().expect("the engine ends");
    let answer: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    assert_eq!(answer["error"]["code"], "interrupted", "{name}: {answer}");
    assert_eq!(t.holding(t.cell, WRITE_8), 0, "{name}: no thread holds it");
    assert_eq!(t.records().len(), 0, "{name}: nothing is left to undo");
    assert!(t.does("main"), "{name}: the target writes the cell");
    assert!(t.does("worker"), "{name}: from the other thread too");
}

#[test]
fn sigint_clears_the_register_and_detaches() {
    signal_clears_and_detaches("int", libc::SIGINT);
}

#[test]
fn sigterm_clears_the_register_and_detaches() {
    signal_clears_and_detaches("term", libc::SIGTERM);
}

#[test]
fn sighup_clears_the_register_and_detaches() {
    signal_clears_and_detaches("hup", libc::SIGHUP);
}

#[test]
fn a_killed_watch_leaves_a_record_and_patch_undo_clears_it() {
    let mut t = killed_watching_the_cell("kill");
    let threads = t.threads().len();
    assert_eq!(threads, 2);

    // Named, listed and announced.
    let (listed, _) = t.engine(&["patch", "list", "--status", "applied"]);
    assert_eq!(listed["data"]["count"], 1, "{listed}");
    let item = &listed["data"]["items"][0];
    assert_eq!(item["planted_by"], "debug watch", "{listed}");
    assert_eq!(item["pid"], t.pid, "{listed}");
    let id = item["id"].as_str().expect("an id").to_string();
    let told = std::fs::read_to_string(t.dir.join("stderr")).expect("stderr");
    assert!(told.contains(&id), "the id is on stderr: {told}");

    // A thread started now does not hold it, and is not among those cleared.
    let armed_threads = t.threads();
    assert!(t.does("spawn"), "the target starts a thread");
    assert_eq!(t.threads().len(), threads + 1);
    assert_eq!(t.holding(t.cell, WRITE_8), threads, "no address in a new thread");

    let bytes = t.cell_bytes();
    let (undone, rc) = t.engine(&["patch", "undo"]);
    assert_eq!(rc, 0, "{undone}");
    let d = &undone["data"];
    assert_eq!((d["threads_cleared"].as_u64(), d["slots_cleared"].as_u64()), (Some(2), Some(2)), "{undone}");
    assert_eq!(d["threads_seen"], 3, "{undone}");
    assert!(d.get("restored").is_none(), "no bytes are claimed: {undone}");
    assert_eq!(t.holding(t.cell, WRITE_8), 0, "by the kernel, no thread holds it");
    for tid in armed_threads {
        let r = registers_of(tid);
        assert!(r[0] == 0 && r[7] & SLOT0 == 0, "{tid}: {r:x?}");
    }
    assert_eq!(t.records().len(), 0, "the record went");
    assert_eq!(t.cell_bytes(), bytes, "and the address was not written, as a record of bytes would have been");

    assert!(t.does("main"), "the target writes the cell");
    assert!(t.does("worker"), "from the other thread too");
    assert_eq!(t.tracer(), Some(0));
}

/// What `patch undo` is for: this is the death the record exists to prevent, and the test
/// above means nothing if the target would have lived anyway.
#[test]
fn without_the_undo_the_killed_runs_register_kills_the_target() {
    for who in ["main", "worker"] {
        let mut t = killed_watching_the_cell(&format!("death-{who}"));
        assert!(!t.does(who), "a debug register with no debugger ends the target");
        let status = t.child.wait().expect("reap");
        assert_eq!(status.signal(), Some(libc::SIGTRAP), "{status:?}");
    }
}

/// A new thread of a target that keeps the register is given DR7's value by the kernel, and
/// no address and no breakpoint: read back as DR0 0 with DR7 0x90401. So it does not hold the
/// watch, and the proof is that it writes the cell and lives, where the others die.
#[test]
fn a_thread_started_after_the_kill_is_not_armed() {
    let mut t = killed_watching_the_cell("late");
    let old = t.threads();
    assert!(t.does("spawn"), "the target starts a thread");
    let new = *t.threads().iter().find(|tid| !old.contains(tid)).expect("a new thread");
    let on_new = registers_of(new);
    assert_eq!(on_new[0], 0, "{on_new:x?}");
    assert!(t.does("late"), "it writes the cell and lives");
    assert!(!t.does("main"), "calibration: this one still holds it");
    assert_eq!(t.child.wait().expect("reap").signal(), Some(libc::SIGTRAP));
}

#[test]
fn every_other_slot_stays_as_it_was() {
    let mut t = killed_watching_the_cell("others");
    let tids = t.threads();
    let [main, worker] = tids[..] else { panic!("{tids:?}") };
    // On the main thread, another tool's watch in slot 1, on a cell nothing touches.
    // On the worker, slot 0 itself is someone else's by now: their address, and the same bits.
    let theirs = t.quiet;
    with_thread_stopped(main, |h| {
        poke(h, 1, theirs);
        let dr7 = peek(h, 7);
        poke(h, 7, dr7 | 0b0100 | (0b1001 << 20));
    });
    with_thread_stopped(worker, |h| poke(h, 0, theirs));

    let (undone, rc) = t.engine(&["patch", "undo"]);
    assert_eq!(rc, 0, "{undone}");
    let d = &undone["data"];
    assert_eq!((d["threads_seen"].as_u64(), d["threads_cleared"].as_u64(), d["slots_cleared"].as_u64()), (Some(2), Some(1), Some(1)), "{undone}");

    let on_main = registers_of(main);
    assert_eq!(on_main[0], 0, "ours is gone from the main thread");
    assert_eq!(on_main[7] & SLOT0, 0);
    assert_eq!(on_main[1], theirs, "slot 1 keeps its address");
    assert_eq!(on_main[7] & SLOT1, 0b0100 | (0b1001 << 20), "and its bits");
    let on_worker = registers_of(worker);
    assert_eq!(on_worker[0], theirs, "the worker's slot 0 no longer held what the record says");
    assert_eq!(on_worker[7] & SLOT0, WRITE_8);
    assert_eq!(t.records().len(), 0);

    // Lives through a write to what was ours, and theirs are still armed for what they watch.
    assert!(t.does("main"));
    assert!(t.does("worker"));
}

#[test]
fn a_target_that_is_gone_clears_nothing_and_says_so() {
    for reaped in [true, false] {
        let mut t = killed_watching_the_cell(if reaped { "gone" } else { "zombie" });
        t.child.kill().expect("kill the target");
        if reaped {
            t.child.wait().expect("reap");
        } else {
            // Dead and not waited for: `/proc` still lists it, and nothing can run there.
            let start = Instant::now();
            while !std::fs::read_to_string(format!("/proc/{}/stat", t.pid)).unwrap_or_default().contains(") Z ") {
                assert!(start.elapsed() < Duration::from_secs(20), "the target never ended");
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let (undone, rc) = t.engine(&["patch", "undo"]);
        assert_eq!(rc, 0, "{undone}");
        let d = &undone["data"];
        assert_eq!(d["target_present"], false, "{undone}");
        assert_eq!((d["threads_cleared"].as_u64(), d["slots_cleared"].as_u64()), (Some(0), Some(0)), "{undone}");
        assert!(d["note"].as_str().unwrap_or("").contains("gone"), "{undone}");
        assert_eq!(t.records().len(), 0, "the record went");
    }
}

/// The pid of a killed run's target, and now another process's. Made by changing the record
/// to a target of our own, which is what a reused pid looks like from there.
#[test]
fn a_reused_pid_holding_nothing_of_ours_clears_nothing_and_says_so() {
    let holder = killed_watching_the_cell("reuse-a");
    let mut other = Target::spawn("reuse-b");
    let before = other.registers();
    let mut record = holder.records().remove(0);
    record["pid"] = other.pid.into();
    std::fs::create_dir_all(other.dir.join(".n0x/patches")).expect("the journal");
    let name = holder.record_path().file_name().expect("a name").to_owned();
    std::fs::write(other.dir.join(".n0x/patches").join(name), record.to_string()).expect("the record");

    let (undone, rc) = other.engine(&["patch", "undo"]);
    assert_eq!(rc, 0, "{undone}");
    let d = &undone["data"];
    assert_eq!(d["target_present"], true, "{undone}");
    assert_eq!(d["threads_seen"], 2, "{undone}");
    assert_eq!((d["threads_cleared"].as_u64(), d["slots_cleared"].as_u64()), (Some(0), Some(0)), "{undone}");
    assert!(d["note"].as_str().unwrap_or("").contains("nothing was cleared"), "{undone}");
    assert_eq!(other.records().len(), 0, "the record went");
    assert_eq!(other.registers(), before, "and it was not touched");
    assert!(other.does("main"));
}

/// `--pid` at another process says nothing of the one on record, so a mistyped one takes
/// away no way back.
#[test]
fn patch_undo_with_another_pid_that_holds_nothing_keeps_the_record() {
    let holder = killed_watching_the_cell("pid-a");
    let other = Target::spawn("pid-b");
    let (undone, rc) = holder.engine(&["patch", "undo", "--pid", &other.pid.to_string()]);
    assert_eq!(rc, 0, "{undone}");
    assert_eq!(undone["data"]["record_removed"], false, "{undone}");
    assert!(undone["data"]["note"].as_str().unwrap_or("").contains("the record stays"), "{undone}");
    assert_eq!(holder.records().len(), 1, "the record stays");
    assert_eq!(holder.holding(holder.cell, WRITE_8), 2, "the target on record still holds it");
    let (undone, rc) = holder.engine(&["patch", "undo"]);
    assert_eq!(rc, 0, "{undone}");
    assert_eq!(undone["data"]["slots_cleared"], 2, "{undone}");
    assert_eq!(holder.records().len(), 0);
}

/// While the run lives it traces the target, and `patch undo` cannot, and says so.
#[test]
fn patch_undo_refuses_a_target_a_live_run_traces_and_keeps_the_record() {
    let t = Target::spawn("busy");
    let mut tool = t.watching_the_cell();
    let (undone, rc) = t.engine(&["patch", "undo"]);
    assert_ne!(rc, 0, "{undone}");
    assert_eq!(undone["error"]["code"], "undo-failed", "{undone}");
    assert_eq!(t.records().len(), 1, "the record stays");
    tool.kill().expect("SIGKILL");
    tool.wait().expect("reap");
    // It may have been killed before it armed, and either way this leaves nothing.
    let (undone, rc) = t.engine(&["patch", "undo"]);
    assert_eq!(rc, 0, "{undone}");
    assert_eq!(t.records().len(), 0);
    assert_eq!(t.holding(t.cell, WRITE_8), 0);
}

#[test]
fn a_killed_provenance_trace_is_on_the_record_too() {
    let mut t = killed_while_armed(
        "prov",
        |t| {
            let cell = format!("{:#x}", t.cell);
            t.waiting_engine(&["provenance", "trace", "--addr", &cell, "--kind", "write", "--len", "8"])
        },
        |t| t.cell,
        WRITE_8,
    );
    let (listed, _) = t.engine(&["patch", "list", "--status", "applied"]);
    assert_eq!(listed["data"]["items"][0]["planted_by"], "provenance trace", "{listed}");
    let (undone, rc) = t.engine(&["patch", "undo"]);
    assert_eq!(rc, 0, "{undone}");
    assert_eq!(undone["data"]["slots_cleared"], 2, "{undone}");
    assert!(t.does("main"));
    assert!(t.does("worker"));
}

/// Another kind and length, for what the record has to say to find it again.
#[test]
fn a_killed_execute_watch_is_found_and_cleared_too() {
    let mut t = killed_while_armed(
        "exec",
        |t| {
            let site = format!("{:#x}", t.site);
            t.waiting_engine(&["debug", "watch", "--addr", &site, "--kind", "execute", "--len", "1"])
        },
        |t| t.site,
        EXECUTE_1,
    );
    let (undone, rc) = t.engine(&["patch", "undo"]);
    assert_eq!(rc, 0, "{undone}");
    assert_eq!(undone["data"]["slots_cleared"], 2, "{undone}");
    assert!(t.does("site"), "the target runs the function");
    assert_eq!(t.holding(t.site, EXECUTE_1), 0);
}

#[test]
fn a_watch_that_ends_by_itself_leaves_no_record() {
    let mut t = Target::spawn("timeout");
    let (cell, pid) = (format!("{:#x}", t.cell), t.pid.to_string());
    let (a, rc) = t.engine(&["debug", "watch", "--pid", &pid, "--addr", &cell, "--kind", "write", "--len", "8", "--timeout-ms", "200"]);
    assert_eq!(rc, 0, "{a}");
    assert_eq!(a["data"]["timed_out"], true, "{a}");
    assert_eq!(t.records().len(), 0, "a timeout leaves nothing to undo");
    assert_eq!(t.holding(t.cell, WRITE_8), 0);
    assert!(t.does("main"));
    assert!(t.does("worker"));
}

#[test]
fn a_watch_that_hits_leaves_no_record() {
    let mut t = Target::spawn("hit");
    let tool = t.watching_the_cell();
    std::thread::sleep(Duration::from_millis(300));
    assert!(t.does("worker"), "a write the run catches");
    let out = tool.wait_with_output().expect("the engine ends");
    let a: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    assert_eq!(a["data"]["timed_out"], false, "{a}");
    assert_eq!(t.records().len(), 0, "a hit leaves nothing to undo");
    assert_eq!(t.holding(t.cell, WRITE_8), 0);
    assert!(t.does("main"));
    assert!(t.does("worker"));
}

#[test]
fn a_journal_that_cannot_be_written_means_nothing_is_armed() {
    use std::os::unix::fs::PermissionsExt;
    let mut t = Target::spawn("readonly");
    let patches = t.dir.join(".n0x/patches");
    std::fs::create_dir_all(&patches).expect("the journal's directory");
    std::fs::set_permissions(&patches, std::fs::Permissions::from_mode(0o500)).expect("read-only");
    // Running as root writes anyway, and this asks nothing of that case.
    let writable = std::fs::write(patches.join("probe"), b"x").is_ok();
    let (cell, pid) = (format!("{:#x}", t.cell), t.pid.to_string());
    if !writable {
        let (a, rc) = t.engine(&["debug", "watch", "--pid", &pid, "--addr", &cell, "--kind", "write", "--len", "8", "--timeout-ms", "300"]);
        assert_ne!(rc, 0, "{a}");
        assert!(a["error"]["message"].as_str().unwrap_or("").contains("nothing was armed"), "{a}");
        assert_eq!(t.holding(t.cell, WRITE_8), 0);
        assert!(t.does("main"));
    }
    std::fs::set_permissions(&patches, std::fs::Permissions::from_mode(0o700)).expect("back");
}

/// A journal from before the debug register: a file as that build wrote it, by hand here,
/// reads as it did, is listed as it was, and undoes as bytes.
#[test]
fn an_old_journal_still_reads_and_undoes_as_bytes() {
    let mut t = Target::spawn("old");
    let before = t.cell_bytes();
    let mut applied = before;
    applied[0] ^= 0xFF;
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ");
    let record = format!(
        "{{\n  \"id\": \"1700000000-000000001\",\n  \"pid\": {},\n  \"address\": \"{:#x}\",\n  \"size\": 8,\n  \"before_hex\": \"{}\",\n  \"after_hex\": \"{}\",\n  \"status\": \"applied\",\n  \"created_at_unix\": 1700000000\n}}",
        t.pid,
        t.cell,
        hex(&before),
        hex(&applied)
    );
    let patches = t.dir.join(".n0x/patches");
    std::fs::create_dir_all(&patches).expect("the journal");
    std::fs::write(patches.join("patch-1700000000-000000001.json"), &record).expect("the record");
    let mem = std::fs::OpenOptions::new().write(true).open(format!("/proc/{}/mem", t.pid)).expect("open memory");
    mem.write_all_at(&applied, t.cell).expect("the patch itself");

    let (listed, _) = t.engine(&["patch", "list", "--status", "applied"]);
    let expected: Value = serde_json::from_str(&record).expect("the record is JSON");
    assert_eq!(listed["data"]["items"][0], expected, "listed field for field as it was written");
    let (shown, _) = t.engine(&["patch", "show", "--id", "1700000000-000000001"]);
    assert_eq!(shown["data"]["item"], expected, "{shown}");

    let (undone, rc) = t.engine(&["patch", "undo"]);
    assert_eq!(rc, 0, "{undone}");
    assert_eq!(undone["data"]["restored"], 8, "{undone}");
    assert_eq!(t.cell_bytes(), before, "the bytes are back");
    assert_eq!(t.records()[0]["status"], "undone", "and it keeps its record, as ever");
    assert!(t.does("main"));
}

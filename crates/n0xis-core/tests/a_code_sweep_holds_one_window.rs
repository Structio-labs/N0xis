// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Every pass that sweeps a code range answers 64 MiB of code within a fixed
//! heap budget above the image: the memory half of `n0xis_core`'s sweep
//! (`src/sweep.rs`), calibrated against the code it replaced.
//!
//! Until 2026-10-23 those passes decoded the whole range in one
//! `Arch::decode_range` call and kept every instruction alive at once, about
//! 104 MiB of RSS per MiB of code (getrusage `maxrss` on real libraries: 1.73 GB
//! for `bindings list` on 16.7 MiB of code), and the reverse-xref index held one
//! 8 MiB window of them, 650-750 MB. The sweep holds one 1 MiB window.
//!
//! How it is measured: this binary's allocator counts the bytes live on the
//! heap and, in a child process, ends the child at once (exit status
//! [`REFUSED`], saying how much was asked) when an allocation would take them
//! past the planted image plus [`BUDGET`]. Ending it rather than refusing the
//! allocation: a refused allocation aborts, and an abort leaves a core dump
//! of a 100 MB process behind for every pass. The parent fails on its own
//! assertion, naming the pass; nothing runs the machine out of memory,
//! whatever the code under test does. Each child checks the planted answer
//! too, so a pass that fits by answering less is caught as well.
//!
//! Calibrated 2026-10-23: with `src/{xref,xref_string,bindings,icalls}.rs`
//! restored to `2313b89`, all five passes are refused (the index's first
//! 8 MiB window asks for 88 MiB in one allocation; each whole-range pass
//! passes the budget at 22 MiB of instructions). With the sweep the largest
//! peak above the image is 37 MiB.

use std::alloc::{GlobalAlloc, Layout, System};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use n0xis_arch::{Arch, X64};
use n0xis_contracts::Va;
use n0xis_core::{
    BindingsInput, BindingsPass, Ctx, IcallInput, IcallPass, Pass, StringXrefInput, StringXrefPass, XrefDir, XrefInput, XrefPass, build_xref_index,
};
use n0xis_sources::Snapshot;

/// Bytes of planted code: the size the step was specified at.
const CODE_BYTES: usize = 64 << 20;

/// Heap a pass may hold above the planted image. Measured with the sweep: the
/// largest of the five peaks is printed by each child (`peak above the image`).
/// The code it replaced needs over a GiB here for any whole-range pass, and
/// one 8 MiB window of the old index is several hundred MiB.
const BUDGET: usize = 96 << 20;

const CHILD: &str = "N0XIS_SWEEP_MEMORY_CHILD";
/// A child's exit status when a pass needed more than the budget.
const REFUSED: i32 = 86;
const THIS_TEST: &str = "every_sweeping_pass_answers_64_mib_of_code_within_one_window";

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// Zero: no limit (the parent, and the child while it plants the image).
static CAP: AtomicUsize = AtomicUsize::new(0);

struct Counting;

impl Counting {
    /// Count `size` more live bytes; past the cap, end the process.
    fn take(size: usize) {
        let now = LIVE.fetch_add(size, Ordering::SeqCst) + size;
        let cap = CAP.load(Ordering::SeqCst);
        if cap != 0 && now > cap {
            // Said without allocating: the message goes through a stack buffer.
            use std::io::Write;
            let mut line = [0u8; 160];
            let mut at = std::io::Cursor::new(&mut line[..]);
            let _ = writeln!(at, "refused: an allocation of {size} bytes would hold {} KiB above the image", (now - (cap - BUDGET)) / 1024);
            let len = at.position() as usize;
            let _ = std::io::stderr().write_all(&line[..len]);
            std::process::exit(REFUSED);
        }
        PEAK.fetch_max(now, Ordering::SeqCst);
    }
}

// SAFETY: every call is forwarded to the system allocator unchanged; the
// count beside it only decides whether the process goes on.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        Self::take(layout.size());
        let p = unsafe { System.alloc(layout) };
        if p.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        Self::take(layout.size());
        let p = unsafe { System.alloc_zeroed(layout) };
        if p.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        }
        p
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // A growing reallocation may copy, holding both blocks at once; count
        // the new one in full before the old one is let go.
        Self::take(new_size);
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        LIVE.fetch_sub(if p.is_null() { new_size } else { layout.size() }, Ordering::SeqCst);
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const CODE: u64 = 0x1000_0000;
const DATA: u64 = 0x2000_0000;
const SLOTS: u64 = 0x3000_0000;

/// A 15-byte instruction, the longest x86 allows: a `nop` with six redundant
/// operand-size prefixes and a segment override. Long, so 64 MiB is as few
/// instructions as it can be and the test is quick.
const FILLER: [u8; 15] = [0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00];

/// What was planted where: 64 MiB of filler, then at its very end every shape
/// the five passes look for, so a sweep that stopped early answers wrong.
struct Planted {
    snap: Snapshot,
    code_len: usize,
    data_len: usize,
    filler: usize,
    calls: [u64; 2],
    string_load: u64,
    binding_load: u64,
    icall_load: u64,
}

fn planted() -> Planted {
    let mut data = Vec::new();
    let mut put = |s: &[u8]| {
        let at = DATA + data.len() as u64;
        data.extend_from_slice(s);
        data.push(0);
        at
    };
    let binding = put(b"planted_binding");
    let icall = put(b"Planted.Type::Method(System.Int32)");
    let string = put(b"a planted string");

    let filler = CODE_BYTES.div_ceil(FILLER.len());
    let mut code = Vec::with_capacity(filler * FILLER.len() + 64);
    for _ in 0..filler {
        code.extend_from_slice(&FILLER);
    }
    let here = |code: &Vec<u8>| CODE + code.len() as u64;
    let rip = |code: &Vec<u8>, len: u64, to: u64| ((to as i64) - (here(code) + len) as i64) as i32;
    let lea = |code: &mut Vec<u8>, modrm: u8, to: u64| {
        let at = here(code);
        let d = rip(code, 7, to);
        code.extend_from_slice(&[0x48, 0x8D, modrm]);
        code.extend_from_slice(&d.to_le_bytes());
        at
    };
    let call = |code: &mut Vec<u8>, to: u64| {
        let at = here(code);
        let d = rip(code, 5, to);
        code.push(0xE8);
        code.extend_from_slice(&d.to_le_bytes());
        at
    };
    // lea rdx,[cfunc] ; lea rcx,[binding] ; call registrar
    lea(&mut code, 0x15, CODE + 0x10);
    let binding_load = lea(&mut code, 0x0D, binding);
    let first = call(&mut code, CODE);
    // lea rcx,[icall] ; call resolver ; test rax,rax ; mov [slot],rax
    let icall_load = lea(&mut code, 0x0D, icall);
    let second = call(&mut code, CODE);
    code.extend_from_slice(&[0x48, 0x85, 0xC0]);
    let d = rip(&code, 7, SLOTS);
    code.extend_from_slice(&[0x48, 0x89, 0x05]);
    code.extend_from_slice(&d.to_le_bytes());
    // lea rcx,[string] ; ret
    let string_load = lea(&mut code, 0x0D, string);
    code.push(0xC3);

    let (code_len, data_len) = (code.len(), data.len());
    let snap = Snapshot::builder().region(Va(CODE), code).region(Va(DATA), data).region(Va(SLOTS), vec![0u8; 8]).build();
    Planted { snap, code_len, data_len, filler, calls: [first, second], string_load, binding_load, icall_load }
}

/// Run one pass on the planted image under the cap and check its answer.
fn child(pass: &str) {
    let p = planted();
    let arch = X64::new();
    let filler = arch.decode(&FILLER, Va(CODE)).expect("the filler decodes");
    assert_eq!(filler.len as usize, FILLER.len(), "the filler is one instruction");
    let ctx = Ctx::new(&p.snap, &arch);
    let (code, size) = (Va(CODE), p.code_len);

    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    CAP.store(base + BUDGET, Ordering::SeqCst);
    match pass {
        "index" => {
            let idx = build_xref_index(&ctx, &[(code, size as u64)]);
            assert_eq!(idx.to(Va(CODE)), p.calls.map(Va).to_vec(), "the two planted calls");
            assert_eq!(idx.insns, p.filler + 9, "every instruction indexed");
        }
        "xref_to" => {
            let art = XrefPass.run(&ctx, XrefInput { scan_start: code, size, addr: Va(CODE), dir: XrefDir::To }).unwrap();
            assert_eq!(art.refs.iter().map(|r| r.from.0).collect::<Vec<_>>(), p.calls, "the two planted calls");
        }
        "xref_string" => {
            let input = StringXrefInput {
                data_start: Va(DATA),
                data_size: p.data_len,
                code_start: code,
                code_size: size,
                query: "a planted string".into(),
                limit: 50,
            };
            let art = StringXrefPass.run(&ctx, input).unwrap();
            assert_eq!(art.count, 1);
            assert_eq!(art.hits[0].xrefs.iter().map(|x| x.from.0).collect::<Vec<_>>(), [p.string_load]);
        }
        "bindings" => {
            let input =
                BindingsInput { data_start: Va(DATA), data_size: p.data_len, code_start: code, code_size: size, names: Vec::new(), window: 8, limit: 200 };
            let art = BindingsPass.run(&ctx, input).unwrap();
            assert_eq!(art.count, 1, "{art:?}");
            let b = &art.bindings[0];
            assert_eq!((b.name.as_str(), b.name_ref_site.0, b.cfunc.0, b.call_nearby), ("planted_binding", p.binding_load, CODE + 0x10, true));
        }
        "icalls" => {
            let input = IcallInput {
                data_start: Va(DATA),
                data_size: p.data_len,
                code_start: code,
                code_size: size,
                slot_start: Va(SLOTS),
                slot_size: 8,
                window: 0,
                limit: 0,
            };
            let art = IcallPass.run(&ctx, input).unwrap();
            assert_eq!(art.count, 1, "{art:?}");
            let c = &art.icalls[0];
            assert_eq!((c.site.0, c.resolver, c.slot), (p.icall_load, Some(Va(CODE)), Some(Va(SLOTS))));
        }
        other => panic!("no pass {other}"),
    }
    CAP.store(0, Ordering::SeqCst);
    println!("{pass}: peak above the image {} KiB (budget {} KiB)", (PEAK.load(Ordering::SeqCst) - base) / 1024, BUDGET / 1024);
}

#[test]
fn every_sweeping_pass_answers_64_mib_of_code_within_one_window() {
    if let Ok(pass) = std::env::var(CHILD) {
        child(&pass);
        return;
    }
    let exe = std::env::current_exe().expect("this test binary");
    // One child per pass, side by side: each holds the image and at most the
    // budget, so five of them stay near 1 GiB even when every pass is refused.
    let runs: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = ["index", "xref_to", "xref_string", "bindings", "icalls"]
            .map(|pass| {
                let exe = &exe;
                s.spawn(move || {
                    let out = Command::new(exe)
                        .args(["--exact", THIS_TEST, "--nocapture", "--test-threads=1"])
                        .env(CHILD, pass)
                        .output()
                        .expect("the child runs");
                    (pass, out)
                })
            })
            .into_iter()
            .collect();
        handles.into_iter().map(|h| h.join().expect("the spawning thread")).collect()
    });
    let said = |b: &[u8]| {
        String::from_utf8_lossy(b)
            .lines()
            .filter(|l| l.contains("peak above") || l.contains("refused:") || l.contains("panicked") || l.contains("assertion"))
            .collect::<Vec<_>>()
            .join(" | ")
    };
    let mut refused = Vec::new();
    for (pass, out) in &runs {
        println!("{pass}: {}{}", said(&out.stdout), said(&out.stderr));
        if !out.status.success() {
            refused.push(format!("{pass} ({}): {}", out.status, said(&out.stderr)));
        }
    }
    assert!(refused.is_empty(), "a pass needed more than {} MiB above 64 MiB of code, or answered wrong: {refused:#?}", BUDGET >> 20);
}

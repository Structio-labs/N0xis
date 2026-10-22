// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The hostile-input contract (docs/design/IMAGE_FORMATS.md §4) through the
//! layers stage 2 puts over the WebAssembly reader: the image (`Image`'s
//! answers, the constant offset expressions it evaluates), the module's
//! architecture (decoding every body and every range), and function discovery
//! over the two. The stage-1 reader keeps the contract on its own
//! (`crates/n0xis-wasm/tests/mutated.rs`); this is that the layers over it do
//! not break it.
//!
//! Each fixture is corrupted 2 000 ways, chosen by the case number so a
//! failure names a case that can be run again: bits flipped, bytes changed,
//! the file cut short, a byte inserted or removed, a LEB128 set to an extreme
//! value. Every case is opened; when it opens, every answer of the image is
//! asked, every body decoded through the architecture, the whole code
//! section decoded as one range, and the function list made. Each runs on its
//! own thread under a deadline, and the largest single allocation is bounded
//! by the input's length: a decoded instruction is at least one byte of it.
//!
//! What a case must give beside no crash: every instruction the range decode
//! yields lies inside one body, with the file's bytes; and discovery lists the
//! declared starts and nothing else.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use n0xis_arch::Arch;
use n0xis_contracts::Va;
use n0xis_sources::{FormatTables, MemorySource, OpenOptions, Opened};

const HARD_CAP: usize = 1 << 30;
const DEADLINE: Duration = Duration::from_secs(10);
const CASES: u64 = 2000;

static LARGEST: AtomicUsize = AtomicUsize::new(0);

struct Capped;

// SAFETY: every call is forwarded to the system allocator unchanged, except
// that a request past `HARD_CAP` answers null, which the allocator contract
// allows (it is an allocation failure).
unsafe impl GlobalAlloc for Capped {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        if layout.size() > HARD_CAP {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        if layout.size() > HARD_CAP {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LARGEST.fetch_max(new_size, Ordering::Relaxed);
        if new_size > HARD_CAP {
            return std::ptr::null_mut();
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Capped = Capped;

/// xorshift64*, seeded by the case number.
struct Rng(u64);

impl Rng {
    fn new(case: u64) -> Self {
        Rng(case.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

const EXTREME_LEBS: [&[u8]; 5] =
    [&[0xff, 0xff, 0xff, 0xff, 0x0f], &[0x80, 0x80, 0x80, 0x80, 0x08], &[0x80, 0x80, 0x80, 0x80, 0x00], &[0xff, 0xff, 0xff, 0xff, 0xff, 0x7f], &[0x7f]];

fn corrupt(original: &[u8], case: u64) -> Vec<u8> {
    let mut rng = Rng::new(case);
    let mut bytes = original.to_vec();
    let len = bytes.len();
    match case % 5 {
        0 => {
            for _ in 0..1 + rng.below(8) {
                let at = rng.below(len);
                bytes[at] ^= 1 << rng.below(8);
            }
        }
        1 => {
            for _ in 0..1 + rng.below(4) {
                let at = rng.below(len);
                bytes[at] = rng.next() as u8;
            }
        }
        2 => bytes.truncate(8 + rng.below(len.saturating_sub(8))),
        3 => {
            let at = 8 + rng.below(len.saturating_sub(8));
            if rng.below(2) == 0 {
                bytes.insert(at, rng.next() as u8);
            } else if at < bytes.len() {
                bytes.remove(at);
            }
        }
        _ => {
            let at = 8 + rng.below(len.saturating_sub(8));
            let with = EXTREME_LEBS[rng.below(EXTREME_LEBS.len())];
            let end = (at + 1).min(bytes.len());
            bytes.splice(at..end, with.iter().copied());
        }
    }
    bytes
}

/// Open `bytes` and ask every layer everything; `Err` with what was wrong,
/// `Ok(true)` when it opened, `Ok(false)` when the reader refused it.
fn run(bytes: Vec<u8>) -> Result<bool, String> {
    let Some(format) = n0xis_sources::recognize(&bytes) else { return Ok(false) };
    let Ok(Opened::Thin { image, tables }) = (format.open)(bytes.clone(), &OpenOptions::default()) else { return Ok(false) };
    let FormatTables::Wasm(module) = tables else { return Err("a module opened as a native image".into()) };
    // Every answer of the image.
    let _ = (image.machine(), image.linkage(), image.segments(), image.sections(), image.symbols(), image.imports(), image.exports());
    let _ = (image.findings(), image.binding_at(Va(0)), image.codeview(), image.start_coverage());
    let starts: Vec<(u64, u64)> = image
        .declared_starts()
        .read
        .iter()
        .map(|s| match s.extent {
            n0xis_sources::Extent::Stated(n) => (s.va.0, s.va.0 + n),
            n0xis_sources::Extent::Unknown => (s.va.0, s.va.0),
        })
        .collect();
    let arch = n0xis_arch::Wasm::new(module.shared(), module.identity());
    let loaded = image.loaded_bytes();
    // Every body, from its start; then the code section as one range.
    for &(start, end) in starts.iter().filter(|(s, e)| e > s) {
        let window = loaded.read(Va(start), (end - start) as usize).map_err(|e| format!("body at {start:#x}: {e}"))?;
        let insns = arch.decode_stream(&window, Va(start), usize::MAX);
        if insns.iter().any(|i| i.va.0 < start || i.va.0 + u64::from(i.len) > end) {
            return Err(format!("the body at {start:#x} decoded past its end {end:#x}"));
        }
    }
    for s in image.sections().iter().filter(|s| s.executable) {
        let window = loaded.read(s.va, s.size as usize).map_err(|e| e.to_string())?;
        for i in arch.decode_range(&window, s.va, usize::MAX) {
            let inside = starts.iter().any(|&(b, e)| i.va.0 >= b && i.va.0 + u64::from(i.len) <= e);
            if !inside {
                return Err(format!("an instruction at {} lies in no body", i.va));
            }
            if bytes.get(i.va.0 as usize..i.va.0 as usize + i.len as usize) != Some(i.bytes.as_slice()) {
                return Err(format!("the instruction at {} is not the file's bytes", i.va));
            }
        }
    }
    // The function list: the declared starts, and nothing else.
    let extents: Vec<(Va, Va)> = starts.iter().map(|&(s, e)| (Va(s), Va(e))).collect();
    let ctx = n0xis_core::Ctx::new(&loaded, &arch).with_stated_functions(&extents, image.start_coverage());
    for s in image.sections().iter().filter(|s| s.executable) {
        let found = n0xis_core::discover_entries(&ctx, s.va, s.size as usize).map_err(|e| e.to_string())?;
        let listed: Vec<u64> = found.entries.iter().map(|(va, _)| va.0).collect();
        let declared: Vec<u64> = starts.iter().map(|&(s, _)| s).filter(|&v| v >= found.start.0 && v < found.start.0 + found.scanned_bytes as u64).collect();
        if listed != declared {
            return Err(format!("discovery listed {listed:x?}, the module declares {declared:x?}"));
        }
    }
    Ok(true)
}

#[test]
fn a_corrupted_module_is_answered_by_every_layer_never_crashed() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../n0xis-wasm/tests/fixtures");
    let mut fixtures: Vec<std::path::PathBuf> =
        std::fs::read_dir(&dir).expect("fixtures").flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "wasm")).collect();
    fixtures.sort();
    assert_eq!(fixtures.len(), 14, "{fixtures:?}");
    let per_byte = 2 * std::mem::size_of::<n0xis_arch::DecodedInsn>().max(std::mem::size_of::<n0xis_wasm::Located>());
    let mut failures = Vec::new();
    let mut worst = 0.0f64;
    for path in &fixtures {
        let original = std::fs::read(path).expect("a fixture");
        let (mut opened, mut refused) = (0, 0);
        for case in 0..CASES {
            let bytes = corrupt(&original, case);
            let len = bytes.len();
            let label = format!("{} case {case}", path.file_name().unwrap().to_string_lossy());
            let (send, receive) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                LARGEST.store(0, Ordering::Relaxed);
                let outcome = std::panic::catch_unwind(move || run(bytes));
                let _ = send.send((outcome, LARGEST.load(Ordering::Relaxed)));
            });
            match receive.recv_timeout(DEADLINE) {
                Ok((Ok(Ok(true)), largest)) => {
                    opened += 1;
                    worst = worst.max(largest as f64 / len.max(1) as f64);
                    if largest > per_byte * len.max(64) {
                        failures.push(format!("{label}: asked for {largest} bytes at once, {len} of input"));
                    }
                }
                Ok((Ok(Ok(false)), _)) => refused += 1,
                Ok((Ok(Err(what)), _)) => failures.push(format!("{label}: {what}")),
                Ok((Err(_), _)) => failures.push(format!("{label}: a panic escaped")),
                Err(_) => failures.push(format!("{label}: no answer within {DEADLINE:?}")),
            }
        }
        eprintln!("{}: {CASES} corrupted copies: {opened} opened and answered, {refused} refused", path.display());
        assert!(opened > 0 && refused > 0, "{}: the cases reached the layers one way only: {opened} opened, {refused} refused", path.display());
    }
    eprintln!("largest single allocation {worst:.1} times the input's length (bound {per_byte})");
    assert!(failures.is_empty(), "{} cases failed:\n{}", failures.len(), failures.join("\n"));
}

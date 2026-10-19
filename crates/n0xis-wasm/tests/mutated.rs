// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A corrupted module is an error, a finding or a partial answer, never a
//! crash, a hang, an internal error or an allocation the input cannot justify.
//!
//! Each case corrupts a copy of a fixture in a way chosen by its number, so a
//! failure names a case that can be run again: bits flipped, bytes changed, the
//! file cut short, a byte inserted or removed, a section's size or a vector's
//! count set to an extreme LEB128, a section repeated (out of order), a body's
//! bytes overwritten. Every case is read, and when it reads, every body is
//! decoded. Each runs on its own thread under a deadline, and this binary's
//! allocator records the largest single request.
//!
//! The allocation bound is stated in input bytes, never in a count read from
//! the file: a decoded instruction takes `size_of::<Located>()` bytes for as
//! little as one byte of input, and a growing vector may hold twice what it
//! uses, so one allocation may be up to `2 * size_of::<Located>()` times the
//! file's length. A request sized by a claimed count (a billion entries, say)
//! is far past that on files of a few kilobytes.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Refused outright: the test process stops, which is a failure no one misses.
const HARD_CAP: usize = 1 << 30;
const DEADLINE: Duration = Duration::from_secs(5);
const CASES: u64 = 2400;

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

/// xorshift64*, seeded by the case number: the same case corrupts the same way.
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

/// LEB128 encodings that drive a reader's counts and sizes to their edges:
/// u32::MAX, 2^31, 2^28, a padded zero, a value one past u32, an over-long one.
const EXTREME_LEBS: [&[u8]; 7] = [
    &[0xff, 0xff, 0xff, 0xff, 0x0f],
    &[0x80, 0x80, 0x80, 0x80, 0x08],
    &[0x80, 0x80, 0x80, 0x80, 0x01],
    &[0x80, 0x80, 0x80, 0x80, 0x00],
    &[0x80, 0x80, 0x80, 0x80, 0x10],
    &[0x80, 0x80, 0x80, 0x80, 0x80, 0x00],
    &[0xff, 0xff, 0xff, 0x7f],
];

/// Where each section's header (its id byte) and contents begin.
fn section_starts(m: &n0xis_wasm::Module) -> Vec<(usize, usize)> {
    let mut header = 8;
    m.sections()
        .iter()
        .map(|s| {
            let at = (header, s.contents.start);
            header = s.contents.end;
            at
        })
        .collect()
}

/// Replace `bytes[at..at + old_len]` with `with`.
fn splice(bytes: &mut Vec<u8>, at: usize, old_len: usize, with: &[u8]) {
    let end = (at + old_len).min(bytes.len());
    bytes.splice(at..end, with.iter().copied());
}

fn corrupt(original: &[u8], m: &n0xis_wasm::Module, case: u64) -> Vec<u8> {
    let mut rng = Rng::new(case);
    let mut bytes = original.to_vec();
    let len = bytes.len();
    let sections = section_starts(m);
    let extreme = |rng: &mut Rng| EXTREME_LEBS[rng.below(EXTREME_LEBS.len())];
    match case % 8 {
        // Bits flipped anywhere.
        0 => {
            for _ in 0..1 + rng.below(8) {
                let at = rng.below(len);
                bytes[at] ^= 1 << rng.below(8);
            }
        }
        // A few bytes set to any value.
        1 => {
            for _ in 0..1 + rng.below(4) {
                let at = rng.below(len);
                bytes[at] = rng.next() as u8;
            }
        }
        // The file cut short.
        2 => bytes.truncate(rng.below(len)),
        // A byte inserted, or one removed: everything after it shifts.
        3 => {
            let at = rng.below(len);
            if rng.below(2) == 0 {
                bytes.insert(at, rng.next() as u8);
            } else {
                bytes.remove(at);
            }
        }
        // A section's size set to an extreme value.
        4 => {
            let (header, contents) = sections[rng.below(sections.len())];
            splice(&mut bytes, header + 1, contents - header - 1, extreme(&mut rng));
        }
        // The first LEB128 of a section's contents (a vector's count, in
        // every standard section that has one) set to an extreme value.
        5 => {
            let (_, contents) = sections[rng.below(sections.len())];
            let old = original[contents..].iter().position(|b| b & 0x80 == 0).map_or(1, |p| p + 1);
            splice(&mut bytes, contents, old, extreme(&mut rng));
        }
        // A section repeated after itself, which the format forbids.
        6 => {
            let i = rng.below(sections.len());
            let (header, _) = sections[i];
            let end = m.sections()[i].contents.end;
            let copy = original[header..end].to_vec();
            splice(&mut bytes, end, 0, &copy);
        }
        // Inside a body: an extreme LEB128 or random bytes over a few of its
        // own, which lands on locals counts, immediates and opcodes.
        _ => {
            let bodies = m.bodies();
            if bodies.is_empty() {
                bytes.truncate(rng.below(len));
            } else {
                let body = &bodies[rng.below(bodies.len())];
                let at = body.start + rng.below(body.len());
                if rng.below(2) == 0 {
                    splice(&mut bytes, at, 1, extreme(&mut rng));
                } else {
                    for i in 0..1 + rng.below(4) {
                        if at + i < bytes.len() {
                            bytes[at + i] = rng.next() as u8;
                        }
                    }
                }
            }
        }
    }
    bytes
}

#[derive(Debug)]
enum Outcome {
    Clean,
    WithFindings,
    Refused,
    /// A body that `read` found fine and `body` did not, or the reverse.
    Inconsistent(String),
    Internal(String),
}

fn run(bytes: &[u8]) -> Outcome {
    let m = match n0xis_wasm::read(bytes) {
        Ok(m) => m,
        Err(n0xis_wasm::Error::Internal(why)) => return Outcome::Internal(why),
        Err(_) => return Outcome::Refused,
    };
    let broken: Vec<u32> = m
        .findings()
        .iter()
        .filter_map(|f| match f {
            n0xis_wasm::Finding::Body { func, .. } => Some(func.0),
            _ => None,
        })
        .collect();
    let first = m.imported_functions();
    for i in 0..m.bodies().len() as u32 {
        let func = n0xis_wasm::FuncIdx(first + i);
        match m.body(func) {
            Some(Ok(_)) if broken.contains(&func.0) => {
                return Outcome::Inconsistent(format!("func {} decodes and `read` found it broken", func.0));
            }
            Some(Ok(_)) => {}
            Some(Err(n0xis_wasm::Error::Internal(why))) => return Outcome::Internal(why),
            Some(Err(_)) if !broken.contains(&func.0) => {
                return Outcome::Inconsistent(format!("func {} fails and `read` found it fine", func.0));
            }
            Some(Err(_)) => {}
            None => return Outcome::Inconsistent(format!("func {} has no body", func.0)),
        }
    }
    if m.findings().is_empty() { Outcome::Clean } else { Outcome::WithFindings }
}

#[test]
fn a_corrupted_module_is_an_error_or_a_finding_never_a_crash() {
    let per_byte = 2 * std::mem::size_of::<n0xis_wasm::Located>();
    let mut failures = Vec::new();
    let mut worst_ratio = 0.0f64;
    for stem in common::FIXTURES {
        let original = common::bytes(stem);
        let m = common::module(stem);
        let (mut clean, mut found, mut refused) = (0, 0, 0);
        for case in 0..CASES {
            let bytes = corrupt(&original, &m, case);
            let cap = per_byte * bytes.len();
            let (send, receive) = std::sync::mpsc::channel();
            let input = bytes.clone();
            std::thread::spawn(move || {
                // Measured around the reader alone, on its own thread: the
                // thread and the channel allocate too, and are not the reader.
                LARGEST.store(0, Ordering::Relaxed);
                let outcome = std::panic::catch_unwind(|| run(&input));
                let largest = LARGEST.load(Ordering::Relaxed);
                let _ = send.send((outcome, largest));
            });
            let largest = match receive.recv_timeout(DEADLINE) {
                Ok((outcome, largest)) => {
                    match outcome {
                        Ok(Outcome::Clean) => clean += 1,
                        Ok(Outcome::WithFindings) => found += 1,
                        Ok(Outcome::Refused) => refused += 1,
                        Ok(Outcome::Inconsistent(what)) => failures.push(format!("{stem} case {case}: {what}")),
                        Ok(Outcome::Internal(why)) => {
                            failures.push(format!("{stem} case {case}: the reader stopped: {why}"))
                        }
                        Err(_) => failures.push(format!("{stem} case {case}: a panic escaped the reader")),
                    }
                    largest
                }
                Err(_) => {
                    failures.push(format!("{stem} case {case}: no answer within {DEADLINE:?}"));
                    LARGEST.load(Ordering::Relaxed)
                }
            };
            worst_ratio = worst_ratio.max(largest as f64 / bytes.len().max(1) as f64);
            if largest > cap {
                failures.push(format!("{stem} case {case}: asked for {largest} bytes at once, {} of input", bytes.len()));
            }
        }
        eprintln!("{stem}: {CASES} corrupted copies: {clean} read clean, {found} read with findings, {refused} refused");
        // The corruptions reached the reader every way: some still read, some
        // read with a finding, some were refused. All of one kind would mean
        // the cases test nothing. (`simd` has one body and no name section, so
        // a finding there is a body that broke.)
        assert!(clean > 0 && found > 0 && refused > 0, "{stem}: clean {clean}, findings {found}, refused {refused}");
    }
    eprintln!("largest single allocation: {worst_ratio:.1} times the input's length (bound {per_byte})");
    assert!(failures.is_empty(), "{} cases failed:\n{}", failures.len(), failures.join("\n"));
}

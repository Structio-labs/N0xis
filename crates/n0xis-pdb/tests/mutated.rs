// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A corrupted PDB is an error or a partial answer, never a crash, a hang or a
//! huge allocation.
//!
//! Each case corrupts a copy of a real PDB (`fixtures/pdbtarget.pdb`) in a way
//! chosen by its number, so a failure names a case that can be run again:
//! bytes changed at random, a field set to an extreme value, the file cut
//! short, a field of the MSF header the reader sizes its work from, a whole
//! page cleared. Each read runs on its own thread under a deadline, and this
//! test binary's allocator records the largest single request and refuses one
//! past a gigabyte. That is how the candidate reader rejected on 2026-10-04 was
//! caught: asked for 3.6 GB while merely opening a mutated file.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Refused outright: the test process stops, which is a failure no one misses.
const HARD_CAP: usize = 1 << 30;
/// The most a read of this 120 KB file may ask for at once.
const SOFT_CAP: usize = 64 << 20;
const DEADLINE: Duration = Duration::from_secs(5);
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

/// Values that drive a reader's arithmetic and allocations to their edges.
const EXTREMES: [u32; 7] = [0, 1, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFF, 0x1000_0000, 0xFFFF_FFF0];

fn corrupt(original: &[u8], case: u64) -> Vec<u8> {
    let mut rng = Rng::new(case);
    let mut bytes = original.to_vec();
    let len = bytes.len();
    match case % 5 {
        // A few bytes changed anywhere.
        0 => {
            for _ in 0..1 + rng.below(8) {
                let at = rng.below(len);
                bytes[at] = rng.next() as u8;
            }
        }
        // A 32-bit field anywhere set to an extreme value.
        1 => {
            let at = rng.below(len / 4) * 4;
            bytes[at..at + 4].copy_from_slice(&EXTREMES[rng.below(EXTREMES.len())].to_le_bytes());
        }
        // The file cut short.
        2 => bytes.truncate(rng.below(len)),
        // A field of the MSF header: block size, free-map block, block count,
        // directory size, the reserved word, the directory map's block.
        3 => {
            let at = 32 + rng.below(6) * 4;
            let value = if rng.below(2) == 0 { EXTREMES[rng.below(EXTREMES.len())] } else { rng.next() as u32 };
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        // A whole 4 KiB page cleared, or filled with one value.
        _ => {
            let page = rng.below(len / 4096) * 4096;
            let fill = if rng.below(2) == 0 { 0 } else { 0xFF };
            bytes[page..(page + 4096).min(len)].fill(fill);
        }
    }
    bytes
}

#[test]
fn a_corrupted_pdb_is_an_error_or_a_partial_answer_never_a_crash() {
    let original = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pdbtarget.pdb")).expect("the fixture");
    let mut failures = Vec::new();
    let (mut read, mut refused) = (0, 0);
    for case in 0..CASES {
        let bytes = corrupt(&original, case);
        LARGEST.store(0, Ordering::Relaxed);
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let outcome = std::panic::catch_unwind(|| n0xis_pdb::read(&bytes).map(|contents| contents.functions.len()));
            let _ = send.send(outcome);
        });
        match receive.recv_timeout(DEADLINE) {
            Ok(Ok(Ok(_))) => read += 1,
            Ok(Ok(Err(_))) => refused += 1,
            Ok(Err(_)) => failures.push(format!("case {case}: the reader panicked")),
            Err(_) => failures.push(format!("case {case}: no answer within {DEADLINE:?}")),
        }
        let largest = LARGEST.load(Ordering::Relaxed);
        if largest > SOFT_CAP {
            failures.push(format!("case {case}: asked for {largest} bytes at once"));
        }
    }
    assert!(failures.is_empty(), "{} of {CASES} cases failed:\n{}", failures.len(), failures.join("\n"));
    // The corruptions reached the reader both ways: some files still read,
    // some were refused. All of one kind would mean the cases test nothing.
    assert!(read > 0 && refused > 0, "read {read}, refused {refused}");
    eprintln!("{CASES} corrupted copies: {read} read, {refused} refused");
}

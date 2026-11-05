// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The memory one engine run may hold, kept by the engine.
//!
//! A run that wants more than the machine or its cgroup gives is killed by the
//! kernel: the caller gets no answer, and the desktop raises a memory alarm. A
//! length read from a corrupted file can ask for that much in one allocation, and
//! an answer of millions of rows gets there in small ones. So a door installs
//! [`CeilingAlloc`] and states a ceiling, and past it the run stops itself through
//! the door's own refusal, in the door's own format. Every allocation is counted,
//! so no path has to remember to ask, and nothing is ever given back as a null a
//! caller would have to handle.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

/// What a heap keeps beside each block, and the size it rounds up to. Counting only
/// what was asked for would undercount millions of small strings by half, and the
/// kernel counts what the heap took.
const BLOCK_OVERHEAD: usize = 16;
const BLOCK_ROUNDING: usize = 16;

static HELD: AtomicUsize = AtomicUsize::new(0);
static CEILING: AtomicUsize = AtomicUsize::new(usize::MAX);
static REFUSAL: OnceLock<fn(u64)> = OnceLock::new();

fn cost(size: usize) -> usize {
    size.max(BLOCK_ROUNDING).saturating_add(BLOCK_OVERHEAD + BLOCK_ROUNDING - 1) & !(BLOCK_ROUNDING - 1)
}

fn charge(bytes: usize) {
    let held = HELD.fetch_add(bytes, Ordering::Relaxed).saturating_add(bytes);
    if held > CEILING.load(Ordering::Relaxed) {
        // The refusal itself needs memory, so the ceiling goes first. Another
        // thread past it now simply carries on until the process exits.
        let ceiling = CEILING.swap(usize::MAX, Ordering::Relaxed);
        if ceiling != usize::MAX
            && let Some(refuse) = REFUSAL.get()
        {
            refuse(ceiling as u64);
            std::process::exit(1);
        }
    }
}

fn credit(bytes: usize) {
    HELD.fetch_sub(bytes, Ordering::Relaxed);
}

/// The system's allocator, counted against [`set_memory_ceiling`].
pub struct CeilingAlloc;

// SAFETY: every call goes to `System` with the arguments it was given; the rest only
// counts, in atomics, and allocates nothing while the ceiling holds.
unsafe impl GlobalAlloc for CeilingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        charge(cost(layout.size()));
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        charge(cost(layout.size()));
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        credit(cost(layout.size()));
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let (old, new) = (cost(layout.size()), cost(new_size));
        if new > old {
            charge(new - old);
        } else {
            credit(old - new);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// States the ceiling and what a run past it does: `refuse` gets the ceiling in
/// bytes, says so in the door's format and exits; if it returns, the run exits with
/// status 1. `None` states no ceiling: the host told us nothing and the caller set
/// nothing.
pub fn set_memory_ceiling(ceiling: Option<u64>, refuse: fn(u64)) {
    let _ = REFUSAL.set(refuse);
    if let Some(bytes) = ceiling {
        CEILING.store(usize::try_from(bytes).unwrap_or(usize::MAX), Ordering::Relaxed);
    }
}

/// A size as the configuration states it: bytes, or with a `K`, `M` or `G` suffix.
pub fn parse_memory_size(text: &str) -> Option<u64> {
    let text = text.trim();
    let (digits, unit) = match text.char_indices().last()? {
        (at, c) if c.is_ascii_alphabetic() => (&text[..at], c.to_ascii_uppercase()),
        _ => (text, 'B'),
    };
    let scale: u64 = match unit {
        'B' => 1,
        'K' => 1 << 10,
        'M' => 1 << 20,
        'G' => 1 << 30,
        _ => return None,
    };
    digits.trim().parse::<u64>().ok()?.checked_mul(scale)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_costs_what_a_heap_takes_for_it() {
        assert_eq!(cost(0), 32);
        assert_eq!(cost(16), 32);
        assert_eq!(cost(17), 48);
        assert_eq!(cost(1 << 20), (1 << 20) + 16);
        assert_eq!(cost(usize::MAX), usize::MAX & !15, "a length from a file cannot wrap it to small");
    }

    #[test]
    fn a_stated_size_reads_as_the_cage_writes_it() {
        assert_eq!(parse_memory_size("4096"), Some(4096));
        assert_eq!(parse_memory_size("512K"), Some(512 << 10));
        assert_eq!(parse_memory_size("12288M"), Some(12288 << 20));
        assert_eq!(parse_memory_size("12g"), Some(12 << 30));
        for wrong in ["", "G", "12X", "-1G", "1.5G", "99999999999999G"] {
            assert_eq!(parse_memory_size(wrong), None, "{wrong}");
        }
    }
}

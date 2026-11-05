// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The stack an analysis runs on, stated instead of inherited.
//!
//! A main thread's stack is whatever the system gives: 8 MiB on Linux, 1 MiB on
//! Windows. So one input could get an answer on one and kill the process on the
//! other, because Rust has no way to report an overflow: the process dies with no
//! answer, and no `ok: false`. Every door runs its work on a thread with this much
//! instead, so depth limits mean the same everywhere.
//!
//! It is address space, not memory: the system commits a stack's pages when they
//! are touched, on Linux and on Windows alike.

use std::sync::Mutex;

/// Enough for [`crate`]'s recursions at their stated bounds, in a debug build.
pub const ANALYSIS_STACK_BYTES: usize = 256 << 20;

/// Runs `work` on a thread with [`ANALYSIS_STACK_BYTES`] of stack and returns
/// what it returns. A panic in it goes on as a panic here. Where the system gives
/// no such thread (a limit on address space), the work still runs, on the stack
/// the caller has.
pub fn on_analysis_stack<T: Send>(work: impl FnOnce() -> T + Send) -> T {
    let slot = Mutex::new(Some(work));
    let take = || slot.lock().ok().and_then(|mut work| work.take());
    let on_thread = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("analysis".to_string())
            .stack_size(ANALYSIS_STACK_BYTES)
            .spawn_scoped(scope, || take().map(|work| work()))
            .map(|thread| thread.join())
    });
    match on_thread {
        Ok(Ok(Some(value))) => value,
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Ok(Ok(None)) | Err(_) => match take() {
            Some(work) => work(),
            None => unreachable!("the work is taken once, and only a thread that ran it took it"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deeper than any default stack (2 MiB in a test thread, 8 MiB at most in a
    /// main one) with room to spare in this one, in a debug build too.
    #[test]
    fn the_stated_stack_is_the_stack_the_work_gets() {
        #[inline(never)]
        fn down(levels: usize) -> usize {
            let frame = [levels as u8; 1024];
            if levels == 0 { std::hint::black_box(frame)[0] as usize } else { down(levels - 1) + std::hint::black_box(frame)[0] as usize % 2 }
        }
        let levels = 16 * 1024;
        assert!(on_analysis_stack(|| down(levels)) > 0);
    }

    #[test]
    fn what_the_work_returns_comes_back() {
        assert_eq!(on_analysis_stack(|| 41 + 1), 42);
    }

    #[test]
    #[should_panic(expected = "stays a panic")]
    fn a_panic_in_the_work_stays_a_panic() {
        on_analysis_stack(|| panic!("stays a panic"))
    }
}

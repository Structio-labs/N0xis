// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Well-known imports that never return control to their caller — used by
//! [`crate::CfgPass`] to correctly end a basic block (instead of assuming
//! normal fall-through) at a call to one of these, closing the gap ROADMAP
//! Phase 10 names: bytes after a call to `ExitProcess`/`abort`/etc. are dead
//! code, but were previously included in the CFG as if reachable — a
//! sound-over-complete violation (CONCEPT §3 rule 6).
//!
//! Sibling to [`crate::signatures`]'s known-API table: same shape (a flat
//! static array, bare-name, case-insensitive lookup — the caller strips any
//! `module!` prefix first), narrower purpose (control flow, not argument
//! typing). Deliberately scoped to Win32/CRT/MSVC-C++ — N0xis's actual corpus
//! is Windows game binaries (mostly C/C++, not Rust); Rust panic/unwind
//! symbol names are mangling/version-fragile and are an explicit non-goal
//! here, not a silent gap.

/// Bare function names that provably never return to their caller.
static KNOWN_NORETURN: &[&str] = &[
    // --- Win32 process/thread termination ---
    "ExitProcess",
    "TerminateProcess",
    "FatalExit",
    "FatalAppExitA",
    "FatalAppExitW",
    "RtlExitUserProcess",
    "RtlExitUserThread",
    "ExitThread",
    // --- CRT ---
    "abort",
    "_exit",
    "_Exit",
    "quick_exit",
    "_cexit",
    "_amsg_exit",
    "_invalid_parameter_noinfo_noreturn",
    // --- MSVC C++ exceptions: control never falls through to the next
    // instruction — it either unwinds past the call site or terminates ---
    "_CxxThrowException",
    // --- x86/x64 fail-fast ---
    "__fastfail",
];

/// Is `bare_name` a well-known function that never returns to its caller?
/// Case-insensitive; the caller is expected to have already stripped a
/// `module!` prefix (same contract as [`crate::signatures::known_signature`]).
pub fn is_known_noreturn(bare_name: &str) -> bool {
    KNOWN_NORETURN.iter().any(|n| n.eq_ignore_ascii_case(bare_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_case_insensitively() {
        assert!(is_known_noreturn("ExitProcess"));
        assert!(is_known_noreturn("exitprocess"));
        assert!(is_known_noreturn("EXITPROCESS"));
        assert!(is_known_noreturn("abort"));
        assert!(is_known_noreturn("_CxxThrowException"));
    }

    #[test]
    fn unknown_name_returns_false() {
        assert!(!is_known_noreturn("sub_140001063"));
        assert!(!is_known_noreturn("CloseHandle"));
        assert!(!is_known_noreturn("SomeUnknownGameFunction"));
    }
}

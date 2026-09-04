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
//! typing). Covers Win32/CRT/MSVC-C++ **and** the glibc/Itanium-ABI names an
//! ELF target calls — the latter only became reachable once
//! [`StaticElf`](../../n0xis_sources/struct.StaticElf.html) learned to resolve
//! GOT slots to import names (2026-09-05); before that no ELF callee had a
//! name to look up, so this table was dead on Linux binaries. Rust
//! panic/unwind symbol names are mangling/version-fragile and are an explicit
//! non-goal here, not a silent gap.
//!
//! **Membership rule (sound over complete): a name belongs here only if it can
//! *never* hand control back to its caller on any path.** `error(3)` returns
//! when its `status` argument is 0 and `std::terminate` handlers are
//! replaceable-but-still-noreturn — the first is excluded, the second kept.

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
    // --- C standard: `exit` runs atexit handlers, then terminates ---
    "exit",
    // --- glibc: stack-protector / _FORTIFY_SOURCE failure paths. The single
    // most common noreturn callee in a hardened ELF: gcc emits
    // `call __stack_chk_fail` as the last instruction of a guarded function,
    // so without this every such function's CFG ran on into the next one ---
    "__stack_chk_fail",
    "__stack_chk_fail_local",
    "__fortify_fail",
    "__chk_fail",
    "__libc_fatal",
    // --- glibc: assertion failure ---
    "__assert_fail",
    "__assert_perror_fail",
    // --- glibc/POSIX: control transfers elsewhere and never comes back ---
    "pthread_exit",
    "longjmp",
    "_longjmp",
    "siglongjmp",
    "err",
    "errx",
    "verr",
    "verrx",
    // --- Itanium C++ ABI (libstdc++/libsupc++): throw and unwind ---
    "__cxa_throw",
    "__cxa_rethrow",
    "__cxa_bad_cast",
    "__cxa_bad_typeid",
    "__cxa_pure_virtual",
    "__cxa_deleted_virtual",
    "_Unwind_Resume",
    "_Unwind_Resume_or_Rethrow",
    // `std::terminate()` / `std::unexpected()` / `std::rethrow_exception`,
    // as the *mangled* symbols an import resolves to — the lookup sees the raw
    // symbol name, not a demangled one.
    "_ZSt9terminatev",
    "_ZSt10unexpectedv",
    "_ZSt17rethrow_exceptionSt13exception_ptr",
];

/// `libstdc++`'s `std::__throw_*` family (`_ZSt17__throw_bad_allocv`,
/// `_ZSt20__throw_length_errorPKc`, `_ZSt24__throw_out_of_range_fmtPKcz`, …):
/// every member constructs an exception and throws it, so none returns. They
/// are enumerated by *shape* rather than listed because the set is large and
/// grows with each libstdc++ release, and the mangling encodes the argument
/// types — an exact-name table would silently miss new ones.
///
/// The prefix is `_ZSt` (namespace `std`) + a length digit run + `__throw_`,
/// which no other Itanium symbol produces: `_ZSt` fixes the namespace, and a
/// member function of a *class* in `std` would mangle as `_ZNSt…`.
fn is_std_throw_helper(bare: &str) -> bool {
    let Some(rest) = bare.strip_prefix("_ZSt") else { return false };
    let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    digits > 0 && rest[digits..].starts_with("__throw_")
}

/// Is `bare_name` a well-known function that never returns to its caller?
/// Case-insensitive; the caller is expected to have already stripped a
/// `module!` prefix (same contract as [`crate::signatures::known_signature`]).
pub fn is_known_noreturn(bare_name: &str) -> bool {
    KNOWN_NORETURN.iter().any(|n| n.eq_ignore_ascii_case(bare_name)) || is_std_throw_helper(bare_name)
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
    fn matches_the_glibc_and_itanium_names_an_elf_target_calls() {
        // The stack-protector failure path — by far the most frequent noreturn
        // callee in a hardened ELF, and the reason this set exists.
        assert!(is_known_noreturn("__stack_chk_fail"));
        assert!(is_known_noreturn("__assert_fail"));
        assert!(is_known_noreturn("_Unwind_Resume"));
        assert!(is_known_noreturn("__cxa_throw"));
        assert!(is_known_noreturn("_ZSt9terminatev"));
        assert!(is_known_noreturn("pthread_exit"));
        assert!(is_known_noreturn("exit"));
    }

    #[test]
    fn matches_the_std_throw_helper_family_by_shape() {
        assert!(is_known_noreturn("_ZSt17__throw_bad_allocv"));
        assert!(is_known_noreturn("_ZSt20__throw_length_errorPKc"));
        assert!(is_known_noreturn("_ZSt24__throw_out_of_range_fmtPKcz"));
        // Not a `std::__throw_*` free function: `_ZNSt…` is a *member* of a
        // class in `std`, and a plain `std::` function that doesn't throw.
        assert!(!is_known_noreturn("_ZNSt8__detail15_List_node_base7_M_hookEPS0_"));
        assert!(!is_known_noreturn("_ZSt4cout"));
        assert!(!is_known_noreturn("_ZSt__throw_x")); // no length digits
    }

    #[test]
    fn a_conditionally_returning_name_is_excluded() {
        // `error(status, …)` returns to its caller when `status == 0`, so it is
        // NOT noreturn — flagging it would prune a live path (the exact
        // sound-over-complete violation this table must not commit). Its
        // always-terminating siblings `err`/`errx` are in the set.
        assert!(!is_known_noreturn("error"));
        assert!(!is_known_noreturn("error_at_line"));
        assert!(is_known_noreturn("errx"));
    }

    #[test]
    fn unknown_name_returns_false() {
        assert!(!is_known_noreturn("sub_140001063"));
        assert!(!is_known_noreturn("CloseHandle"));
        assert!(!is_known_noreturn("SomeUnknownGameFunction"));
    }
}

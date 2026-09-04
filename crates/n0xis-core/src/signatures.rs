// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A known-API signature library (ROADMAP Phase 4) — real argument names and
//! types for the Win32/CRT functions a game binary calls constantly, so a
//! call site renders as `CreateFileW(/*lpFileName*/ rcx.0, /*dwDesiredAccess*/
//! rdx.0)` instead of four generic, unnamed register reads.
//!
//! **Single source of truth** (CONCEPT §3 rule 3 / anti-hardcode): one static
//! table, keyed by bare function name (case-insensitive, no `module!`
//! prefix) — extend it here, nowhere else. Deliberately small: this is a
//! floor of the most common calls a Windows game binary makes, not an
//! attempt to embed the whole Win32 SDK. Anything not listed falls back to
//! the existing generic 4-register rendering — sound, just less pretty
//! (CONCEPT §3 rule 6).

/// One parameter's recovered name + type-name (a display string like
/// `"HANDLE"` or `"DWORD"`, not a structural [`n0xis_arch::Bits`] — this
/// library only needs to be *readable*, not drive further type inference).
#[derive(Clone, Copy, Debug)]
pub struct KnownParam {
    pub name: &'static str,
    pub type_name: &'static str,
}

#[derive(Clone, Copy, Debug)]
pub struct KnownSignature {
    pub params: &'static [KnownParam],
    /// `None` means `void`.
    pub ret: Option<&'static str>,
    pub variadic: bool,
}

macro_rules! p {
    ($name:literal, $ty:literal) => {
        KnownParam { name: $name, type_name: $ty }
    };
}

macro_rules! sig {
    ([$($param:expr),* $(,)?], $ret:expr) => {
        KnownSignature { params: &[$($param),*], ret: $ret, variadic: false }
    };
    ([$($param:expr),* $(,)?], $ret:expr, variadic) => {
        KnownSignature { params: &[$($param),*], ret: $ret, variadic: true }
    };
}

/// `(bare function name, signature)`. Matched case-insensitively against a
/// callsite's resolved name with any `module!` prefix stripped.
static KNOWN_SIGNATURES: &[(&str, KnownSignature)] = &[
    // --- kernel32 / file & handle I/O ---
    ("CreateFileW", sig!([p!("lpFileName", "LPCWSTR"), p!("dwDesiredAccess", "DWORD"), p!("dwShareMode", "DWORD"), p!("lpSecurityAttributes", "LPSECURITY_ATTRIBUTES")], Some("HANDLE"))),
    ("CreateFileA", sig!([p!("lpFileName", "LPCSTR"), p!("dwDesiredAccess", "DWORD"), p!("dwShareMode", "DWORD"), p!("lpSecurityAttributes", "LPSECURITY_ATTRIBUTES")], Some("HANDLE"))),
    ("ReadFile", sig!([p!("hFile", "HANDLE"), p!("lpBuffer", "LPVOID"), p!("nNumberOfBytesToRead", "DWORD"), p!("lpNumberOfBytesRead", "LPDWORD")], Some("BOOL"))),
    ("WriteFile", sig!([p!("hFile", "HANDLE"), p!("lpBuffer", "LPCVOID"), p!("nNumberOfBytesToWrite", "DWORD"), p!("lpNumberOfBytesWritten", "LPDWORD")], Some("BOOL"))),
    ("CloseHandle", sig!([p!("hObject", "HANDLE")], Some("BOOL"))),
    ("GetLastError", sig!([], Some("DWORD"))),
    ("SetLastError", sig!([p!("dwErrCode", "DWORD")], None)),
    // --- kernel32 / memory ---
    ("VirtualAlloc", sig!([p!("lpAddress", "LPVOID"), p!("dwSize", "SIZE_T"), p!("flAllocationType", "DWORD"), p!("flProtect", "DWORD")], Some("LPVOID"))),
    ("VirtualFree", sig!([p!("lpAddress", "LPVOID"), p!("dwSize", "SIZE_T"), p!("dwFreeType", "DWORD")], Some("BOOL"))),
    ("VirtualProtect", sig!([p!("lpAddress", "LPVOID"), p!("dwSize", "SIZE_T"), p!("flNewProtect", "DWORD"), p!("lpflOldProtect", "PDWORD")], Some("BOOL"))),
    ("HeapAlloc", sig!([p!("hHeap", "HANDLE"), p!("dwFlags", "DWORD"), p!("dwBytes", "SIZE_T")], Some("LPVOID"))),
    ("HeapFree", sig!([p!("hHeap", "HANDLE"), p!("dwFlags", "DWORD"), p!("lpMem", "LPVOID")], Some("BOOL"))),
    ("GetProcessHeap", sig!([], Some("HANDLE"))),
    // --- kernel32 / modules & process ---
    ("GetProcAddress", sig!([p!("hModule", "HMODULE"), p!("lpProcName", "LPCSTR")], Some("FARPROC"))),
    ("LoadLibraryA", sig!([p!("lpLibFileName", "LPCSTR")], Some("HMODULE"))),
    ("LoadLibraryW", sig!([p!("lpLibFileName", "LPCWSTR")], Some("HMODULE"))),
    ("GetModuleHandleA", sig!([p!("lpModuleName", "LPCSTR")], Some("HMODULE"))),
    ("GetModuleHandleW", sig!([p!("lpModuleName", "LPCWSTR")], Some("HMODULE"))),
    ("ExitProcess", sig!([p!("uExitCode", "UINT")], None)),
    ("TerminateProcess", sig!([p!("hProcess", "HANDLE"), p!("uExitCode", "UINT")], Some("BOOL"))),
    ("Sleep", sig!([p!("dwMilliseconds", "DWORD")], None)),
    ("GetTickCount", sig!([], Some("DWORD"))),
    ("QueryPerformanceCounter", sig!([p!("lpPerformanceCount", "LARGE_INTEGER*")], Some("BOOL"))),
    // --- msvcrt / ucrtbase (CRT) ---
    ("malloc", sig!([p!("size", "size_t")], Some("void*"))),
    ("calloc", sig!([p!("num", "size_t"), p!("size", "size_t")], Some("void*"))),
    ("realloc", sig!([p!("ptr", "void*"), p!("new_size", "size_t")], Some("void*"))),
    ("free", sig!([p!("ptr", "void*")], None)),
    ("memcpy", sig!([p!("dest", "void*"), p!("src", "const void*"), p!("count", "size_t")], Some("void*"))),
    ("memmove", sig!([p!("dest", "void*"), p!("src", "const void*"), p!("count", "size_t")], Some("void*"))),
    ("memset", sig!([p!("dest", "void*"), p!("ch", "int"), p!("count", "size_t")], Some("void*"))),
    ("strlen", sig!([p!("str", "const char*")], Some("size_t"))),
    ("strcmp", sig!([p!("lhs", "const char*"), p!("rhs", "const char*")], Some("int"))),
    ("strcpy", sig!([p!("dest", "char*"), p!("src", "const char*")], Some("char*"))),
    ("fopen", sig!([p!("filename", "const char*"), p!("mode", "const char*")], Some("FILE*"))),
    ("fclose", sig!([p!("stream", "FILE*")], Some("int"))),
    ("fread", sig!([p!("buffer", "void*"), p!("size", "size_t"), p!("count", "size_t")], Some("size_t"))),
    ("fwrite", sig!([p!("buffer", "const void*"), p!("size", "size_t"), p!("count", "size_t")], Some("size_t"))),
    ("printf", sig!([p!("format", "const char*")], Some("int"), variadic)),
    ("sprintf", sig!([p!("buffer", "char*"), p!("format", "const char*")], Some("int"), variadic)),
];

/// Look up a known signature by bare function name (case-insensitive). The
/// caller is expected to have already stripped a `module!` prefix.
pub fn known_signature(bare_name: &str) -> Option<&'static KnownSignature> {
    KNOWN_SIGNATURES.iter().find(|(name, _)| name.eq_ignore_ascii_case(bare_name)).map(|(_, sig)| sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_up_case_insensitively() {
        assert!(known_signature("createfilew").is_some());
        assert!(known_signature("CreateFileW").is_some());
        assert_eq!(known_signature("CreateFileW").unwrap().params.len(), 4);
        assert_eq!(known_signature("CreateFileW").unwrap().ret, Some("HANDLE"));
    }

    #[test]
    fn unknown_name_returns_none() {
        assert!(known_signature("sub_140001063").is_none());
        assert!(known_signature("SomeUnknownGameFunction").is_none());
    }

    #[test]
    fn void_return_is_none() {
        assert_eq!(known_signature("free").unwrap().ret, None);
        assert_eq!(known_signature("ExitProcess").unwrap().ret, None);
    }
}

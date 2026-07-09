//! Symbol demangling — Rust ([`rustc_demangle`]), MSVC ([`msvc_demangler`]),
//! and Itanium C++ ([`cpp_demangle`]). A pure string transform (no OS/ISA
//! knowledge), tried in that order; falls through to the original name
//! unchanged if nothing recognizes it — never invents a name, never panics
//! outward (CONCEPT §3 rule 6: sound over silently wrong).
//!
//! Wired into [`crate::RenderNames`] so every displayed call target goes
//! through this uniformly, whether the binary is MSVC-built (the primary
//! target per CONCEPT §1), MinGW/clang-built (Itanium), or Rust.

/// Demangle `name` if it matches a recognized scheme; otherwise return it
/// unchanged.
pub fn demangle(name: &str) -> String {
    demangle_rust(name)
        .or_else(|| demangle_msvc(name))
        .or_else(|| demangle_itanium(name))
        .unwrap_or_else(|| name.to_string())
}

fn demangle_rust(name: &str) -> Option<String> {
    let sym = rustc_demangle::try_demangle(name).ok()?;
    // The alternate (`{:#}`) form omits the trailing `::h<hash>` disambiguator
    // — that hash is a linker artifact, not something a reverse engineer
    // reads for meaning.
    Some(format!("{sym:#}"))
}

fn demangle_msvc(name: &str) -> Option<String> {
    // Real MSVC-mangled names always start with `?`; gate on it so we don't
    // waste a parse (or risk a misleading partial result) on unrelated input.
    if !name.starts_with('?') {
        return None;
    }
    msvc_demangler::demangle(name, msvc_demangler::DemangleFlags::llvm()).ok()
}

fn demangle_itanium(name: &str) -> Option<String> {
    if !(name.starts_with("_Z") || name.starts_with("__Z")) {
        return None;
    }
    let sym = cpp_demangle::Symbol::new(name).ok()?;
    sym.demangle().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demangles_a_legacy_rust_symbol() {
        assert_eq!(demangle("_ZN3foo3barE"), "foo::bar");
    }

    #[test]
    fn demangles_an_itanium_cpp_symbol() {
        assert_eq!(demangle("_Z3fooi"), "foo(int)");
    }

    #[test]
    fn demangles_an_msvc_symbol() {
        // `int __cdecl foo(int)`
        assert_eq!(demangle("?foo@@YAHH@Z"), "int __cdecl foo(int)");
    }

    #[test]
    fn leaves_an_unrecognized_name_untouched() {
        assert_eq!(demangle("kernel32!CreateFileW"), "kernel32!CreateFileW");
        assert_eq!(demangle("sub_140001063"), "sub_140001063");
    }
}

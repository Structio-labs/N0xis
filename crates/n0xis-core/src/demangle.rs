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

/// Fully demangle an MSVC RTTI **TypeDescriptor** decorated name (`.?AVFoo@@`,
/// `.?AV?$vector@H@std@@`) to its readable class name (`Foo`,
/// `std::vector<int>`) — including the templated names `demangle_rtti_name`'s
/// hand-rolled `@`-splitter deliberately refuses.
///
/// The stored TD name is the type-encoding half of the RTTI type-descriptor
/// symbol `??_R0<type>@8`; wrapping it back into that symbol lets the real MSVC
/// demangler parse the full template, and its output
/// `class std::vector<int>::`RTTI Type Descriptor'` is trimmed of the leading
/// aggregate keyword and the trailing `` ::`RTTI Type Descriptor' `` tag.
/// Returns `None` if the name is not a TD name or the demangler declines it —
/// the caller then keeps the verbatim decorated form (sound over pretty).
pub fn demangle_rtti_type_descriptor(td_name: &str) -> Option<String> {
    let rest = td_name.strip_prefix(".")?;
    if !rest.starts_with("?A") {
        return None;
    }
    let symbol = format!("??_R0{rest}@8");
    let full = msvc_demangler::demangle(&symbol, msvc_demangler::DemangleFlags::llvm()).ok()?;
    let core = full.strip_suffix("::`RTTI Type Descriptor'")?;
    let core = ["class ", "struct ", "union ", "enum "].iter().find_map(|kw| core.strip_prefix(kw)).unwrap_or(core);
    (!core.is_empty()).then(|| core.to_string())
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


// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

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

/// Demangle an MSVC C++ symbol to its **qualified name only** — no return type,
/// parameter list, or access/calling-convention keywords — the form a *call
/// site* wants (`std::basic_streambuf<…>::sputc`, as other tools show), rather
/// than [`demangle`]'s full prototype. `None` if `name` is not an MSVC symbol.
pub fn demangle_msvc_name_only(name: &str) -> Option<String> {
    if !name.starts_with('?') {
        return None;
    }
    let flags = msvc_demangler::DemangleFlags::NAME_ONLY | msvc_demangler::DemangleFlags::NO_MS_KEYWORDS;
    msvc_demangler::demangle(name, flags).ok()
}

/// If `name` is a **non-static C++ member function**, the class it belongs to —
/// the type of its implicit `this` (the first argument under the x64 ABI). This
/// is the seam for whole-program `this`-type propagation (matching other tools):
/// a value passed as arg 0 to `Class::method` is a `Class *`. `None` for a free
/// function, a static member, or a non-C++ symbol — those have no `this`, so
/// their arg 0 must not be mistyped. Membership is read from the demangler's
/// access specifier (`public:`/`private:`/`protected:`), which only a member
/// carries, gated against `static`.
pub fn member_function_class(name: &str) -> Option<String> {
    if let Some(class) = itanium_cv_member_class(name) {
        return Some(class);
    }
    if !name.starts_with('?') {
        return None;
    }
    let full = msvc_demangler::demangle(name, msvc_demangler::DemangleFlags::llvm()).ok()?;
    let is_member = full.starts_with("public:") || full.starts_with("private:") || full.starts_with("protected:");
    if !is_member || full.contains("static ") {
        return None;
    }
    // Drop the trailing `::method` from the qualified name; the last `::` is the
    // method separator (a template argument's `::` sits inside `<…>`, after
    // which `method` has none).
    let qualified = demangle_msvc_name_only(name)?;
    let class = qualified.rsplit_once("::")?.0;
    (!class.is_empty()).then(|| class.to_string())
}

/// The class of an Itanium **cv-qualified** member function — `_ZNK…`,
/// `_ZNV…` — read off the mangling alone.
///
/// This is the Itanium half of [`member_function_class`], and it rests on one
/// rule of the language rather than on a naming convention: **a static member
/// function can never be const- or volatile-qualified**, because it has no
/// `this` to qualify. So a `K` or `V` in the nested-name's CV slot is a *proof*
/// that argument 0 is a real `this` pointer to the enclosing class — the first
/// positive evidence of non-staticness that exists on ELF, where nothing else
/// in a symbol distinguishes `QPixmap::isNull() const` from a free function.
///
/// The converse is not true and is not claimed: an unqualified `_ZN…` may be
/// either a static or an ordinary mutating method, and this returns `None` for
/// both.
pub fn itanium_cv_member_class(name: &str) -> Option<String> {
    if !itanium_cv_qualified(name) {
        return None;
    }
    let full = demangle_itanium(name)?;
    let qualified = full.split('(').next()?.trim();
    let (class, _) = last_scope(qualified)?;
    (!class.is_empty()).then(|| class.to_string())
}

/// Does an Itanium symbol's nested-name carry a **cv-qualifier**?
///
/// `<nested-name> ::= N [<CV-qualifiers>] [<ref-qualifier>] <prefix> …` and
/// `<CV-qualifiers> ::= [r] [V] [K]`, so the qualifiers are exactly the leading
/// run of `r`/`V`/`K` after the `N`. Nothing else can appear there: a `<prefix>`
/// starts with a digit, `S`, `T`, `D` or `L`, never one of those three letters.
fn itanium_cv_qualified(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("_ZN").or_else(|| name.strip_prefix("__ZN")) else {
        return false;
    };
    rest.bytes()
        .take_while(|c| matches!(c, b'r' | b'V' | b'K'))
        .any(|c| matches!(c, b'V' | b'K'))
}

/// Split a demangled qualified name at its **last top-level `::`**:
/// `QPixmap::isNull` → `("QPixmap", "isNull")`.
///
/// Bracket-aware, which a plain `rsplit_once("::")` is not. A member function
/// template names a type in its own template arguments — `Foo::bar<ns::Baz>` —
/// and splitting on the textually last `::` there yields the nonsense class
/// `Foo::bar<ns`. Depth is clamped at zero so an unbalanced `>` from an
/// `operator<`/`operator>` tail cannot drag the scan negative.
pub fn last_scope(qualified: &str) -> Option<(&str, &str)> {
    let b = qualified.as_bytes();
    let (mut depth, mut cut) = (0usize, None);
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'<' | b'(' | b'[' => depth += 1,
            b'>' | b')' | b']' => depth = depth.saturating_sub(1),
            b':' if depth == 0 && b.get(i + 1) == Some(&b':') => {
                cut = Some(i);
                i += 2;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    let cut = cut?;
    Some((&qualified[..cut], &qualified[cut + 2..]))
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
    fn member_function_class_identifies_only_non_static_members() {
        // A non-static member (`QEAA` = public) → its class is the `this` type.
        assert_eq!(
            member_function_class("?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@XZ").as_deref(),
            Some("std::basic_ostream<char,struct std::char_traits<char> >")
        );
        // A free function (`YA`) has no `this` — must return None.
        assert_eq!(member_function_class("?uncaught_exception@std@@YA_NXZ"), None);
        assert_eq!(member_function_class("?foo@@YAHH@Z"), None);
        // A static member (`SA`) has no `this` either.
        assert_eq!(member_function_class("?max@?$numeric_limits@H@std@@SAHXZ"), None);
        // Not an MSVC symbol at all.
        assert_eq!(member_function_class("CreateFileW"), None);
    }

    #[test]
    fn an_itanium_const_member_proves_its_own_class() {
        // `QPixmap::isNull() const` — const-qualified, so never a static.
        assert_eq!(member_function_class("_ZNK7QPixmap6isNullEv").as_deref(), Some("QPixmap"));
        // Volatile counts for the same reason.
        assert!(itanium_cv_qualified("_ZNV3Foo3barEv"));
        // A plain `_ZN…` says nothing: it may be a static member.
        assert_eq!(member_function_class("_ZN15QGuiApplication7paletteEv"), None);
        assert!(!itanium_cv_qualified("_ZN7QPixmapC1Ev"));
        // A free function is not a member however it is spelled.
        assert_eq!(member_function_class("_Z8helper_fv"), None);
        // Nested classes keep their full scope.
        assert_eq!(
            member_function_class("_ZNK2ns3Out2In3getEv").as_deref(),
            Some("ns::Out::In")
        );
    }

    #[test]
    fn last_scope_splits_on_the_last_top_level_separator() {
        assert_eq!(last_scope("QPixmap::isNull"), Some(("QPixmap", "isNull")));
        assert_eq!(last_scope("Foo<ns::Bar>::get"), Some(("Foo<ns::Bar>", "get")));
        // The trap a plain rsplit_once falls into: a member function template
        // whose own template argument is scope-qualified.
        assert_eq!(last_scope("Foo::bar<ns::Baz>"), Some(("Foo", "bar<ns::Baz>")));
        assert_eq!(last_scope("QTextStream::operator<<"), Some(("QTextStream", "operator<<")));
        assert_eq!(last_scope("free_function"), None);
    }

    #[test]
    fn leaves_an_unrecognized_name_untouched() {
        assert_eq!(demangle("kernel32!CreateFileW"), "kernel32!CreateFileW");
        assert_eq!(demangle("sub_140001063"), "sub_140001063");
    }
}


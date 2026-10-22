// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The name of a function nothing names: one home for it
//! (docs/design/WASM.md §5 decision 1).
//!
//! It was formatted in five places with two spellings — `sub_{:X}` in the
//! function list, the `.pdata` list and the summaries, `sub_{:x}` for a callee
//! and in the decompiler's signature line — so one function at an address
//! with a letter in it was `sub_1400010A0` in `function discover` and
//! `sub_1400010a0` in the `decomp pseudo` of its caller. The spelling is now
//! the function list's, everywhere (an announced change of answers, in
//! CHANGELOG).
//!
//! A WebAssembly function is identified by its index, not by where its body
//! is (decision 1), so its fallback is `func_<index>`: wasm-objdump's
//! `func[N]` and V8's `wasm-function[N]` name it by index too, and the name is
//! an identifier, so it renders in pseudo-C.

use n0xis_contracts::Va;

use crate::Ctx;

/// How the image identifies the function the name stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnnamedFunction {
    /// A native function, identified by its address.
    Address(Va),
    /// A WebAssembly function, identified by its index in the module's
    /// function index space.
    WasmIndex(u32),
}

/// The name of a function no symbol source names.
pub fn unnamed_function_name(f: UnnamedFunction) -> String {
    match f {
        UnnamedFunction::Address(va) => format!("sub_{:X}", va.0),
        UnnamedFunction::WasmIndex(index) => format!("func_{index}"),
    }
}

/// The identity of the function that starts at `va`, as `ctx`'s architecture
/// states it: an index where its code space identifies functions by index
/// (a WebAssembly module, whose architecture is built from the module and so
/// is present in every `Ctx` built for one), the address everywhere else.
///
/// Asked of the architecture, not of the symbol seam, because a `Ctx` may be
/// built without symbols and always has an architecture: a WebAssembly
/// function list built from a `Ctx::new` with no symbols attached must still
/// name its functions by index.
pub fn unnamed_at(ctx: &Ctx, va: Va) -> UnnamedFunction {
    match ctx.arch.indexed_function(va).filter(|f| f.body == va) {
        Some(f) => UnnamedFunction::WasmIndex(f.index),
        None => UnnamedFunction::Address(va),
    }
}

/// What the function that starts at `va` is called in a list of functions
/// (`function discover`, a summary): its symbol's name, or the fallback of
/// [`unnamed_at`]. The one answer to the question for every list, so two
/// lists cannot spell one function two ways.
///
/// **A native symbol** is a linker's name, and the list renders it as the
/// callee in pseudo-C would be ([`crate::render::render_callee_name`]):
/// demangled where it is mangled, else an identifier.
///
/// **A WebAssembly function's name is the module's own text**, from its
/// `name` section or an export, and is listed as the module states it.
/// Neither is a linker symbol: a producer writes the name section already
/// demangled (`Vec::push(int)`), any UTF-8 is a valid one (`a-b`,
/// `legalstub$x`), and `wasm-objdump`, `wasm-tools print` and V8's stack
/// traces all print it verbatim. Rendering it as an identifier turned
/// `Vec::push(int)` into `Vec__push_int_` — a name no source states, which
/// `xref` (reading the symbol itself) did not share — and made `a-b` and
/// `a_b` one name.
pub fn function_name(ctx: &Ctx, va: Va) -> String {
    match crate::ir::symbol_on_entry(ctx, va) {
        Some(sym) if ctx.arch.indexed_function(va).is_some() => sym.name,
        Some(sym) => crate::render::render_callee_name(&sym.name),
        None => unnamed_function_name(unnamed_at(ctx, va)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The spelling every site gives an unnamed function, hex letters included:
    /// the address `0x1400010a0` has letters, which is where the two spellings
    /// the five sites used to have differed.
    #[test]
    fn an_address_is_named_in_upper_case_hex_and_an_index_in_decimal() {
        assert_eq!(unnamed_function_name(UnnamedFunction::Address(Va(0x1400010a0))), "sub_1400010A0");
        assert_eq!(unnamed_function_name(UnnamedFunction::WasmIndex(12)), "func_12");
    }
}

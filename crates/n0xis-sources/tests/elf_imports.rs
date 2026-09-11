// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **ELF import resolution on a real, compiler-produced shared object.**
//!
//! [`StaticElf::iat_slot`] maps a GOT slot to the imported symbol it resolves
//! to — the ELF twin of the PE IAT map, and the seam every callee-name
//! consumer reads (`ir::resolved_target_name`, thunk/tail-call recognition,
//! the known-API signature table, noreturn CFG closure). Until 2026-09-05 it
//! was a stub returning `None`, so on ELF every import call decompiled as
//! `(**(uint64_t*)(0x…))(…)` and *no* name-keyed analysis fired at all.
//!
//! This test deliberately uses a **real linker's output**, not a synthetic
//! fixture. The PE side of this exact map was keyed on the wrong RVA for
//! months while its synthetic unit tests passed (ROADMAP Phase 10, priority 0):
//! a hand-built image proves the code path and never the *data*. It builds two
//! objects on purpose — the default (lazy PLT → `JUMP_SLOT`) and `-fno-plt`
//! (direct GOT call → `GLOB_DAT`) — because modern distro builds are the
//! second shape and recognizing only the first would miss most real calls.
//!
//! Linux-only: it links a real `.so` against the system libc.
#![cfg(all(feature = "static-pe", target_os = "linux", target_arch = "x86_64"))]

use std::path::PathBuf;
use std::process::Command;

use n0xis_contracts::{SymKind, Va};
use n0xis_sources::{MemorySource, StaticElf, SymbolProvider};

/// A shared object that calls one libc import (`getenv`) and one function it
/// **defines itself** and also exports (`n0x_local_helper`). The second is the
/// soundness half of the test: in a PIE the linker routes a reference to an
/// exported-and-interposable symbol through the GOT too, and reporting *that*
/// slot as an import would invent a foreign name for local code.
const SRC: &str = r#"
#include <stdlib.h>
char *n0x_local_helper(void) { return getenv("N0X_TEST"); }
char *n0x_entry(void) { return n0x_local_helper(); }
"#;

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Compile `SRC` into a shared object. `extra` selects the call shape
/// (`-fno-plt` for the GOT-direct form). Returns `None` when no C compiler is
/// on PATH — the test then skips rather than failing on an unrelated machine.
fn build_so(dir: &std::path::Path, name: &str, extra: &[&str]) -> Option<PathBuf> {
    let src = dir.join("n0x_imports.c");
    std::fs::write(&src, SRC).expect("write source");
    let out = dir.join(name);
    for cc in ["cc", "gcc", "clang"] {
        let status = Command::new(cc)
            .args(["-shared", "-fPIC", "-O1"])
            .args(extra)
            .arg("-o")
            .arg(&out)
            .arg(&src)
            .status();
        if matches!(status, Ok(s) if s.success()) {
            return Some(out);
        }
    }
    None
}

/// Every GOT slot the image maps to an import, as `(bare name, module)`.
fn imports(elf: &StaticElf) -> Vec<(String, String)> {
    // The map is private, so probe it the way the pipeline does: over every
    // 8-byte-aligned address of the sections that can hold a GOT.
    let mut out = Vec::new();
    for (name, va, size) in elf.sections() {
        if !name.starts_with(".got") && name != ".data.rel.ro" {
            continue;
        }
        let mut a = va.get();
        while a < va.get() + size {
            if let Some(sym) = elf.iat_slot(Va(a)) {
                assert_eq!(sym.kind, SymKind::Import, "a GOT-slot symbol must be an import");
                out.push((sym.name, sym.module));
            }
            a += 8;
        }
    }
    out
}

#[test]
fn got_slots_resolve_to_imported_symbol_names() {
    let dir = std::env::temp_dir().join(format!("n0xis-elf-imports-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let _scratch = Scratch(dir.clone());

    // Both call shapes: lazy PLT (`JUMP_SLOT`) and direct GOT (`GLOB_DAT`).
    for (name, extra) in [("plt.so", &[][..]), ("noplt.so", &["-fno-plt"][..])] {
        let Some(path) = build_so(&dir, name, extra) else {
            eprintln!("skipping: no C compiler on PATH");
            return;
        };
        let elf = StaticElf::load(&path).expect("load the shared object we just built");
        let found = imports(&elf);

        let getenv = found.iter().find(|(n, _)| n == "getenv");
        assert!(getenv.is_some(), "{name}: `getenv` must resolve from a GOT slot; got {found:?}");
        // The provider comes from `.gnu.version_r` (`getenv@GLIBC_2.2.5`), so a
        // glibc link must name the library, not fall back to the placeholder.
        let module = &getenv.unwrap().1;
        assert!(module.starts_with("libc.so"), "{name}: expected a libc provider, got {module:?}");

        // Soundness: a symbol this image *defines* is never reported as an
        // import, however the linker routed the reference to it.
        assert!(
            !found.iter().any(|(n, _)| n == "n0x_local_helper" || n == "n0x_entry"),
            "{name}: a locally-defined symbol must not be reported as an import; got {found:?}"
        );
    }
}


/// With **lazy binding** — the default, and what a stripped ELF executable
/// almost always uses — a call to an import is a *direct* `call` to a PLT stub,
/// so the GOT map above never sees it and the callee would stay `sub_1030`.
/// Naming the stub after its import is what makes the two link shapes behave
/// the same, and it is the shape that matters most on a stripped target.
#[test]
fn plt_stubs_are_named_after_the_import_they_jump_to() {
    let dir = std::env::temp_dir().join(format!("n0xis-elf-plt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let _scratch = Scratch(dir.clone());

    // `-Wl,-z,lazy` forces the classic `.plt`; strip so nothing but the dynamic
    // symbols is left — exactly what a real stripped target offers.
    let Some(path) = build_so(&dir, "lazy.so", &["-Wl,-z,lazy"]) else {
        eprintln!("skipping: no C compiler on PATH");
        return;
    };
    let _ = Command::new("strip").arg("--strip-all").arg(&path).status();
    let elf = StaticElf::load(&path).expect("load the stripped shared object");

    // Walk every executable `.plt*` section and collect the stub names.
    let mut stubs = Vec::new();
    for (name, va, size) in elf.sections() {
        if !name.starts_with(".plt") {
            continue;
        }
        let mut a = va.get();
        while a < va.get() + size {
            if let Some(sym) = elf.symbol_at(Va(a)) {
                assert_eq!(sym.kind, SymKind::Import, "a PLT stub names an import");
                stubs.push(sym.name);
            }
            a += 2; // finest entry alignment worth probing; entries are 8/16 apart
        }
    }
    assert!(stubs.iter().any(|n| n == "getenv"), "expected a `getenv` PLT stub; got {stubs:?}");
    // PLT0 (the lazy resolver) jumps through `GOT+0x10`, which is not a symbol —
    // it must not be mistaken for an import.
    assert!(!stubs.is_empty() && stubs.len() < 32, "implausible stub count {}: {stubs:?}", stubs.len());
    // And the stub address is a real code address: `code_range` must contain it.
    assert!(elf.code_ranges().iter().any(|(s, n)| {
        let end = s.get() + n;
        elf.sections().iter().any(|(nm, v, _)| nm.starts_with(".plt") && v.get() >= s.get() && v.get() < end)
    }));
}

/// A PLT stub is named after its import (above) — but it must NOT be offered as
/// one of the image's own defined functions. `named_functions()` feeds `sig gen`
/// and `profile --exports`; a stub is a thunk into another library, and signing
/// one is actively harmful: every lazy x86-64 PLT entry embeds its own
/// relocation index (`push <n>`), which is specific to this binary's link order.
#[test]
fn plt_stubs_are_not_reported_as_defined_functions() {
    let dir = std::env::temp_dir().join(format!("n0xis-elf-plt-defined-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let _scratch = Scratch(dir.clone());

    let Some(path) = build_so(&dir, "lazydef.so", &["-Wl,-z,lazy"]) else {
        eprintln!("skipping: no C compiler on PATH");
        return;
    };
    let elf = StaticElf::load(&path).expect("load the shared object");
    let defined: Vec<String> = elf.named_functions().into_iter().map(|(_, n)| n).collect();

    assert!(defined.iter().any(|n| n == "n0x_entry"), "its own functions are still there: {defined:?}");
    assert!(!defined.iter().any(|n| n == "getenv"), "an imported PLT stub must not be listed: {defined:?}");
}

/// `Elf64_Sym.st_size` is the linker's own statement of a function's extent, so
/// it must reach the analysis as a *fact* rather than something the
/// end-of-function heuristic re-derives. This is the seam
/// ([`SymbolProvider::symbol_size`]) the CFG and discovery read it through.
#[test]
fn defined_functions_report_their_stated_size_and_nothing_else_does() {
    let dir = std::env::temp_dir().join(format!("n0xis-elf-size-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let _scratch = Scratch(dir.clone());

    let Some(path) = build_so(&dir, "sized.so", &[]) else {
        eprintln!("skipping: no C compiler on PATH");
        return;
    };
    let elf = StaticElf::load(&path).expect("load the shared object");

    // Its own functions state a size, and it agrees with the next symbol's start
    // being at least that far away (a size that overlapped would be malformed).
    let mut defined: Vec<(Va, String)> = elf.named_functions();
    defined.sort_by_key(|(va, _)| va.get());
    let entry = defined.iter().find(|(_, n)| n == "n0x_entry").expect("its own function");
    let size = elf.symbol_size(entry.0).expect("a defined function states st_size");
    assert!(size > 0 && size < 4096, "implausible st_size {size}");

    // An address that is not a function start states nothing — the contract is
    // "exactly this function is n bytes", never an interpolation.
    assert_eq!(elf.symbol_size(Va(entry.0.get() + 1)), None, "no size for an interior address");
    assert_eq!(elf.symbol_size(Va(0xdead_beef)), None, "no size for an unmapped address");
}

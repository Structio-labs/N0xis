// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The seed of whole-program type propagation, measured against the compiler.**
//!
//! `TypePropagatePass` refused 474 of 528 typed arguments on a shipped library
//! as *not portable*, and it was right to: a type named `struct_rdi_0 *`,
//! recovered inside one function from how that function uses a register, means
//! nothing in any other function. The pass is not the bottleneck — the *supply
//! of program-wide names* is.
//!
//! A `this` pointer is such a name. `Widget *` means the same thing everywhere
//! in the program, so every `this` recovered is a seed that can travel along
//! the call graph, and every one **invented** is a wrong type propagated
//! confidently to a fixpoint. So the two numbers this test takes are not
//! interchangeable:
//!
//! * **claims that are wrong** must be zero. The Itanium ABI mangles a static
//!   member function exactly like an instance method — `_ZN5Plain7combineEii`
//!   and `_ZN5Plain5scaleEi` have the same shape — and a static member has no
//!   `this` at all. A rule written from the name would put a `Plain *` in the
//!   first argument of a function whose first argument is an `int`.
//! * **claims that are missing** are a recall number, and a work list.
//!
//! The truth comes from the compiler: `DW_AT_object_pointer` on a
//! `DW_TAG_subprogram` is gcc saying, of the function it has just emitted,
//! which formal parameter is `this`. It is rung 1 — an answer written down
//! before the question was asked — and it is not a demangler's opinion. The
//! *class* is cross-checked with `c++filt`, a third-party demangler, so
//! n0xis's own demangling is never both the question and the answer.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use n0xis_arch::X64;
use n0xis_contracts::Va;
use n0xis_core::{Ctx, this_class_of};
use n0xis_sources::{StaticElf, SymbolProvider};

fn oracle_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("oracle")
}

fn have(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

/// `linkage name → does the compiler say this function has a `this``.
///
/// `objdump --dwarf=info` is the independent parser. A DIE's attributes are the
/// lines between its `Abbrev Number:` line and the next one, which is the only
/// boundary in this format that does not need the nesting depth parsed.
fn object_pointers(so: &Path) -> BTreeMap<String, bool> {
    let out = Command::new("objdump")
        .arg("--dwarf=info")
        .arg(so)
        .env("LC_ALL", "C")
        .output()
        .expect("objdump runs");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut map = BTreeMap::new();
    let mut in_subprogram = false;
    let mut name: Option<String> = None;
    let mut has_this = false;
    let mut flush = |name: &mut Option<String>, has_this: &mut bool| {
        if let Some(n) = name.take() {
            // A declaration and its concrete definition both carry the linkage
            // name; either stating an object pointer settles it.
            let e = map.entry(n).or_insert(false);
            *e |= *has_this;
        }
        *has_this = false;
    };
    for line in text.lines() {
        if line.contains("Abbrev Number:") {
            flush(&mut name, &mut has_this);
            in_subprogram = line.contains("(DW_TAG_subprogram)");
            continue;
        }
        if !in_subprogram {
            continue;
        }
        if let Some(v) = line.split("DW_AT_linkage_name").nth(1) {
            name = v.rsplit(ororacle_sep()).next().map(|s| s.trim().to_string());
        }
        if line.contains("DW_AT_object_pointer") {
            has_this = true;
        }
    }
    flush(&mut name, &mut has_this);
    map
}

/// `objdump` writes a string attribute as
/// `: (indirect string, offset: 0x2a): _ZN5PlainC4Ei` — the value is after the
/// last `): `.
fn ororacle_sep() -> &'static str {
    "): "
}

/// Defined function symbols and their addresses, from `nm`.
fn symbols(so: &Path) -> BTreeMap<String, u64> {
    let out = Command::new("nm")
        .args(["--defined-only"])
        .arg(so)
        .env("LC_ALL", "C")
        .output()
        .expect("nm runs");
    let mut map = BTreeMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut it = line.split_whitespace();
        let (Some(addr), Some(kind), Some(name)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if (kind == "T" || kind == "t" || kind == "W")
            && name.starts_with("_Z")
            && let Ok(a) = u64::from_str_radix(addr, 16)
        {
            map.insert(name.to_string(), a);
        }
    }
    map
}

/// The class a **third-party** demangler reads out of the mangled name — the
/// qualified prefix of the function. Not n0xis's demangler, on purpose: this
/// test is checking a claim n0xis makes about a name, so the name's meaning has
/// to come from somewhere else.
fn class_from_cxxfilt(mangled: &str) -> Option<String> {
    let out = Command::new("c++filt").arg("-n").arg(mangled).env("LC_ALL", "C").output().ok()?;
    let full = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if full == mangled {
        return None;
    }
    // Cut the parameter list, then take everything before the last `::`.
    let head = match full.find('(') {
        Some(i) => &full[..i],
        None => &full[..],
    };
    let (class, _) = head.rsplit_once("::")?;
    Some(class.trim().to_string())
}

#[test]
fn a_this_pointer_is_claimed_only_where_the_compiler_recorded_one() {
    if !have("g++") || !have("objdump") || !have("nm") || !have("c++filt") {
        eprintln!("skip: needs g++, objdump, nm and c++filt — nothing was checked");
        return;
    }
    let dir = oracle_dir();
    let tmp = std::env::temp_dir().join("n0xis-cxx-this");
    std::fs::create_dir_all(&tmp).expect("tmp dir");

    let mut totals = (0usize, 0usize, 0usize);
    for level in ["-O0", "-O1", "-O2"] {
        let so = tmp.join(format!("cxx_this{level}.so"));
        let built = Command::new("g++")
            .args(["-g", level, "-fPIC", "-shared", "-fno-inline", "-o"])
            .arg(&so)
            .arg(dir.join("cxx_this.cpp"))
            .status()
            .expect("g++ runs");
        assert!(built.success(), "g++ could not build oracle/cxx_this.cpp at {level}");
        let (found, missed, wrong) = check(&so, level);
        totals = (totals.0 + found, totals.1 + missed, totals.2 + wrong);
    }
    eprintln!(
        "\nall levels: {} `this` recovered, {} missed, {} claimed wrongly",
        totals.0, totals.1, totals.2
    );
    assert!(totals.0 > 0, "nothing was actually checked");
}

fn check(so: &Path, level: &str) -> (usize, usize, usize) {
    let dwarf = object_pointers(so);
    assert!(!dwarf.is_empty(), "{level}: objdump reported no subprograms — built without -g?");
    let syms = symbols(so);
    let elf = StaticElf::load(so).expect("n0xis loads it");
    let arch = X64::new();
    // Both of these are what the real pipeline attaches, and without them the
    // question cannot be asked at all: every ground `this_class_of` stands on
    // is a fact about a *symbol* or about a *vtable*. The first run of this
    // test reported 0 of 22 recovered and 0 wrong, which reads exactly like a
    // rule that never fires and was the harness handing it neither. Measuring
    // a rule while starving it is the third time in this project that the
    // instrument, not the subject, was the broken part.
    let vtables: std::sync::Arc<std::collections::HashMap<u64, String>> = std::sync::Arc::new(
        n0xis_core::scan_itanium_rtti(
            &elf as &dyn n0xis_sources::MemorySource,
            &elf.data_symbols(),
            n0xis_sources::MemorySource::code_range(&elf),
        )
        .into_iter()
        .map(|v| (v.vtable.get(), v.name))
        .collect(),
    );
    let ctx = Ctx::new(&elf, &arch)
        .with_symbols(&elf as &dyn SymbolProvider)
        .with_vtables(&vtables);

    let mut found = Vec::new();
    let mut missed = Vec::new();
    let mut wrong = Vec::new();

    for (mangled, addr) in &syms {
        let Some(&compiler_says_this) = dwarf.get(mangled) else { continue };
        let claim = this_class_of(&ctx, Va(*addr));
        match (compiler_says_this, claim) {
            (true, Some(c)) => {
                // The right answer, and the right *class*: a nested class or a
                // template instantiation must not collapse to its outer name.
                match class_from_cxxfilt(mangled) {
                    Some(expected) if expected != c => {
                        wrong.push(format!("{mangled}: n0xis says `{c}`, the name says `{expected}`"))
                    }
                    _ => found.push(mangled.clone()),
                }
            }
            (true, None) => missed.push(mangled.clone()),
            (false, Some(c)) => wrong.push(format!(
                "{mangled}: n0xis claims a `{c} *` first argument; the compiler recorded no \
                 object pointer"
            )),
            (false, None) => {}
        }
    }

    eprintln!(
        "\n{level}: {} of {} functions with a `this` recovered; {} claimed wrongly",
        found.len(),
        found.len() + missed.len(),
        wrong.len()
    );
    for m in &missed {
        eprintln!("  missed  {m}");
    }
    for w in &wrong {
        eprintln!("  WRONG   {w}");
    }
    assert!(
        wrong.is_empty(),
        "{level}: {} functions were given a `this` the compiler did not record, or the wrong \
         class. Every one of these is a program-wide type propagated to a fixpoint from a false \
         seed:\n  {}",
        wrong.len(),
        wrong.join("\n  ")
    );
    (found.len(), missed.len(), wrong.len())
}

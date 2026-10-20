// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Itanium vtables, at both pointer widths, where the image puts them.**
//!
//! The Itanium RTTI scan read a 16-byte vtable header and 8-byte slots whatever
//! the image was, and the static ELF reported every image as 64-bit. On a
//! 32-bit shared object built from a two-method class, `rtti scan` answered
//! `ok: true` with no vtables, where the same source for x86-64 answered one.
//! On this corpus it found 2 of 7 classes on i686 and ARMv7 shared objects,
//! each 8 bytes past its real vptr, and none in their executables.
//!
//! The fixtures (`n0xis-sources/tests/fixtures/itanium_vtables/`) are seven
//! classes from `vtables.cpp`, built by `build.sh` for i686, ARMv7 (A32 and
//! Thumb), x86-64 and AArch64, each as a shared object and a static
//! executable, and for big-endian AArch64 as a shared object. Nothing expected
//! below comes from this tool:
//!
//! - **the classes, their bases and each table's first method** are read off
//!   the source and written here;
//! - **where each `_ZTV`/`_ZTI` object is and how wide a pointer is** come from
//!   `llvm-nm` and `llvm-readobj`'s `Class` line, recorded beside the fixtures;
//! - **that the reported address really is the first slot** comes from the
//!   relocation `llvm-readobj -r` lists there (shared object), or the word its
//!   hex dump of `.rodata` shows there (executable) — which names the method
//!   the source puts first, independently of the "symbol + two pointers" rule.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

mod support;

const TARGETS: [&str; 4] = ["i686-linux-gnu", "armv7-linux-gnueabihf", "x86_64-linux-gnu", "aarch64-linux-gnu"];

/// The same source as Thumb-2 (`-mthumb`): every method is a Thumb function,
/// so a slot holding one holds its address with bit 0 set (the ARM ELF ABI's
/// interworking rule; `llvm-nm` prints the address with the bit cleared).
const THUMB: &str = "armv7-thumb-linux-gnueabihf";

/// Big-endian AArch64 (`EI_DATA` = 2), a shared object only.
const BIG_ENDIAN: &str = "vt-aarch64_be-linux-gnu.so";

/// `(class, its _ZTV/_ZTI suffix, the first method its table holds, its bases)`,
/// from `vtables.cpp`. `Derived` does not override `f`, so its first slot is
/// `Base::f`; `Shape::area` is pure, so its slot is the runtime's
/// `__cxa_pure_virtual`.
const CLASSES: [(&str, &str, &str, &[&str]); 7] = [
    ("Base", "4Base", "_ZNK4Base1fEv", &[]),
    ("Derived", "7Derived", "_ZNK4Base1fEv", &["Base"]),
    ("Shape", "5Shape", "__cxa_pure_virtual", &[]),
    ("Square", "6Square", "_ZNK6Square4areaEv", &["Shape"]),
    ("Left", "4Left", "_ZN4Left1lEv", &[]),
    ("Right", "5Right", "_ZN5Right1rEv", &[]),
    ("Both", "4Both", "_ZN4Both1lEv", &["Left", "Right"]),
];

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../n0xis-sources/tests/fixtures/itanium_vtables")
}

/// What the recordings say about one fixture.
struct Recorded {
    /// `llvm-readobj`'s `Class` line: 4 for `32-bit (0x1)`, 8 for `64-bit (0x2)`.
    ptr: u64,
    /// Every symbol `llvm-nm` gives an address.
    symbols: BTreeMap<String, u64>,
    /// `llvm-readobj -r`: relocation offset → the symbol it names (`-` for none).
    relocs: BTreeMap<u64, String>,
    /// `llvm-readobj --hex-dump=.rodata`: address → byte, executables only.
    rodata: BTreeMap<u64, u8>,
}

fn recorded(name: &str) -> Recorded {
    let read = |ext: &str| {
        std::fs::read_to_string(fixtures().join(format!("{name}.{ext}.txt"))).unwrap_or_else(|e| panic!("{name}.{ext}.txt: {e}"))
    };
    let symbols = read("nm")
        .lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            let (addr, _kind, sym) = (w.next()?, w.next()?, w.next()?);
            Some((sym.to_string(), u64::from_str_radix(addr, 16).ok()?))
        })
        .collect();
    let readobj = read("readobj");
    let ptr = match readobj.lines().find_map(|l| l.trim().strip_prefix("Class: ")) {
        Some("32-bit (0x1)") => 4,
        Some("64-bit (0x2)") => 8,
        other => panic!("{name}: llvm-readobj's Class line is {other:?}"),
    };
    let mut relocs = BTreeMap::new();
    let mut rodata = BTreeMap::new();
    for l in readobj.lines() {
        let t = l.trim();
        let mut w = t.split_whitespace();
        let Some(first) = w.next() else { continue };
        let Some(addr) = first.strip_prefix("0x").and_then(|h| u64::from_str_radix(h, 16).ok()) else { continue };
        let rest: Vec<&str> = w.collect();
        if rest.first().is_some_and(|k| k.starts_with("R_")) {
            relocs.insert(addr, rest.get(1).copied().unwrap_or("-").to_string());
        } else {
            // A hex-dump row: up to four groups of at most four bytes, in file
            // order, then the ASCII column (a short last row has short groups).
            let mut at = addr;
            let is_group = |g: &&&str| g.len() <= 8 && g.len().is_multiple_of(2) && g.chars().all(|c| c.is_ascii_hexdigit());
            for group in rest.iter().take(4).take_while(is_group) {
                for i in 0..group.len() / 2 {
                    rodata.insert(at, u8::from_str_radix(&group[2 * i..2 * i + 2], 16).unwrap());
                    at += 1;
                }
            }
        }
    }
    Recorded { ptr, symbols, relocs, rodata }
}

impl Recorded {
    fn sym(&self, name: &str) -> u64 {
        *self.symbols.get(name).unwrap_or_else(|| panic!("llvm-nm lists no {name}"))
    }
    /// The little-endian word of the image's width at `va`, from the hex dump.
    fn word(&self, va: u64) -> Option<u64> {
        (0..self.ptr).rev().try_fold(0u64, |acc, i| self.rodata.get(&(va + i)).map(|b| acc << 8 | u64::from(*b)))
    }
}

fn project() -> PathBuf {
    // A `.n0x/` of its own keeps the engine's caches out of the user's global project.
    let dir = std::env::temp_dir().join(format!("n0xis-itanium-vtables-{}", std::process::id()));
    std::fs::create_dir_all(dir.join(".n0x")).expect("temp project");
    dir
}

fn n0xis(args: &[&str], file: &Path) -> Value {
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
        .current_dir(project())
        .args(args)
        .arg("--file")
        .arg(file)
        .arg("--quiet")
        .output()
        .expect("run n0xis");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("one envelope from {args:?}: {e}"))
}

fn hex(v: &Value) -> u64 {
    let s = v.as_str().unwrap_or_else(|| panic!("an address, got {v}"));
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or_else(|e| panic!("{s}: {e}"))
}

#[test]
fn every_class_is_listed_at_its_symbol_plus_two_pointers_on_both_widths() {
    let mut checked = 0;
    for t in TARGETS.iter().copied().chain([THUMB]) {
        for name in [format!("vt-{t}.so"), format!("vt-{t}")] {
            let shared = name.ends_with(".so");
            // A Thumb method's address, as a slot holds it.
            let code = |va: u64| if t == THUMB { va | 1 } else { va };
            let rec = recorded(&name);
            let scan = n0xis(&["rtti", "scan"], &fixtures().join(&name));
            assert_eq!(scan["ok"], true, "{name}: {scan}");
            let listed = scan["data"]["vtables"].as_array().expect("a vtable list");
            let names: Vec<&str> = listed.iter().filter_map(|v| v["name"].as_str()).collect();
            assert_eq!(scan["data"]["count"], CLASSES.len(), "{name}: the source has seven polymorphic classes, the scan listed {names:?}");
            // No class of the source has a virtual base, so none has a VTT,
            // and every first slot is a method in `.text` (or zero). Shape's
            // is `__cxa_pure_virtual`, which no image here defines: zero and no
            // relocation in an executable, and still listed there, because its
            // second word names its own `_ZTI`.
            assert_eq!(scan["data"]["refused_virtual_bases"], 0, "{name}");
            assert_eq!(scan["data"]["refused_first_slot_not_code"], 0, "{name}");
            assert_eq!(scan["data"]["refused_first_slot_empty"], 0, "{name}");
            for (class, suffix, first, bases) in CLASSES {
                let v = listed.iter().find(|v| v["name"] == class).unwrap_or_else(|| panic!("{name}: no {class} in {names:?}"));
                let ztv = rec.sym(&format!("_ZTV{suffix}"));
                let zti = rec.sym(&format!("_ZTI{suffix}"));
                let vptr = hex(&v["vtable"]);
                // The ABI's layout: offset_to_top, the type_info pointer, then the slots.
                assert_eq!(vptr, ztv + 2 * rec.ptr, "{name}: {class}'s vptr is _ZTV{suffix} ({ztv:#x}) plus two {}-byte pointers", rec.ptr);
                assert_eq!(hex(&v["type_descriptor"]), ztv + rec.ptr, "{name}: {class}'s type-info slot is one pointer into _ZTV{suffix}");
                // The same two addresses, from what fills them rather than from the rule.
                if shared {
                    assert_eq!(rec.relocs.get(&vptr).map(String::as_str), Some(first), "{name}: llvm-readobj -r names what fills {class}'s first slot at {vptr:#x}");
                    assert_eq!(rec.relocs.get(&(ztv + rec.ptr)), Some(&format!("_ZTI{suffix}")), "{name}: {class}'s type-info slot");
                } else {
                    let want = if first == "__cxa_pure_virtual" { 0 } else { code(rec.sym(first)) };
                    assert_eq!(rec.word(vptr), Some(want), "{name}: the word .rodata holds at {class}'s first slot {vptr:#x} is {first}");
                    assert_eq!(rec.word(ztv + rec.ptr), Some(zti), "{name}: {class}'s type-info slot holds _ZTI{suffix}");
                }
                // Bases are read from the class's own `_ZTI`, which every class
                // here has (llvm-nm lists it above). In a shared object the
                // vtable's type_info pointer is a symbolic relocation, zero in
                // the file (checked above), and it once left every class's
                // bases unknown. A class with no base is now `[]`. A class
                // with one is `base-not-named`: the pointer to its base's
                // `_ZTI` — one pointer past the name, or each `__base_info`'s
                // first word from 8 bytes further — is a symbolic relocation
                // too, which `llvm-readobj -r` lists there.
                if shared && bases.is_empty() {
                    assert_eq!(v["bases"], serde_json::json!([]), "{name}: {class} has no base: {v}");
                    assert_eq!(v.get("bases_unknown"), None, "{name}: {class}: {v}");
                } else if shared {
                    let base_pointer = |i: u64| if bases.len() == 1 { zti + 2 * rec.ptr } else { zti + 2 * rec.ptr + 8 + i * 2 * rec.ptr };
                    for (i, base) in bases.iter().enumerate() {
                        let (_, base_suffix, ..) = CLASSES.iter().find(|c| c.0 == *base).expect("a class of the source");
                        let at = base_pointer(i as u64);
                        assert_eq!(rec.relocs.get(&at), Some(&format!("_ZTI{base_suffix}")), "{name}: {class}'s base {base} is a symbolic relocation at {at:#x}");
                    }
                    assert_eq!(v.get("bases"), None, "{name}: {class}'s base is not named in the file: {v}");
                    assert_eq!(v["bases_unknown"], "base-not-named", "{name}: {class}: {v}");
                } else {
                    let got: Option<Vec<&str>> = v["bases"].as_array().map(|a| a.iter().filter_map(|b| b.as_str()).collect());
                    assert_eq!(got.as_deref(), Some(bases), "{name}: {class}'s bases, from the source — an array, `[]` for none: {v}");
                    assert_eq!(v.get("bases_unknown"), None, "{name}: {class}: {v}");
                }
                checked += 1;
            }
        }
    }
    assert_eq!(checked, (TARGETS.len() + 1) * 2 * CLASSES.len());
}

/// What a virtual call in the source resolves to, and why the ones that do not
/// resolve do not.
///
/// - `fresh` stores `Base`'s vtable into the object itself, so the object's
///   dynamic type is `Base` and the call is `Base::g` — on x86-64, read at the
///   image's slot width.
/// - `Base::h` calls `g` through `this`, whose class is only its **declared**
///   type. `Derived` derives from `Base` here, and on a `Derived` the processor
///   runs `Derived::g` (`processor_run.cpp` beside the fixtures, its recorded
///   output `processor_run.txt`: 42, where `Base::g` would give 6). So the call
///   is refused, on every target. It once resolved to `Base::g`.
/// - On i686 `fresh` does not resolve either, and the reason is not the slot
///   width: the object arrives **on the stack**. The dispatch matcher follows
///   the object back to the load from its argument slot, a field of the stack
///   pointer that no class reaches; and **no stack parameter is typed as
///   `this`** at all, so `Base::h` has no class to refuse even before the
///   subclass guard. The 32-bit lift also wraps every operand in a cast the
///   matcher does not look through (looking through the casts alone, tried,
///   still resolves nothing). Recorded so that the day it changes, this fails
///   and says so; the slot width itself is checked on planted 32-bit IR in
///   `n0xis-core`'s devirtualization tests.
#[test]
fn a_virtual_call_resolves_to_the_method_the_slot_holds() {
    /// What one call must come to.
    enum Want {
        /// `Base::g`, through slot 1.
        BaseG,
        /// Unresolved, because resolving it would be wrong; the reason.
        Refused(&'static str),
        /// Unresolved, a recorded gap; the reason.
        Gap(&'static str),
    }
    use Want::*;
    const DECLARED: &str = "`this` has Base only as its declared type and Derived derives from Base: on a Derived the processor runs Derived::g";
    const ON_THE_STACK: &str = "the object is a stack argument, which the dispatch matcher follows into a field of the stack pointer";
    let rows = [
        ("x86_64-linux-gnu", "_ZNK4Base1hEv", Refused(DECLARED)),
        ("x86_64-linux-gnu", "_Z5freshPv", BaseG),
        // Were `this` typed here, it would be refused as on x86-64; it is not
        // typed at all, which is the gap.
        ("i686-linux-gnu", "_ZNK4Base1hEv", Refused("`this` is a stack argument and no stack parameter is typed `this`; were it, Derived derives from Base")),
        ("i686-linux-gnu", "_Z5freshPv", Gap(ON_THE_STACK)),
    ];
    for (t, caller, want) in rows {
        let name = format!("vt-{t}");
        let rec = recorded(&name);
        let g = rec.sym("_ZNK4Base1gEv");
        let out = n0xis(&["decomp", "pseudo", "--addr", &format!("{:#x}", rec.sym(caller))], &fixtures().join(&name));
        assert_eq!(out["ok"], true, "{name} {caller}: {out}");
        let found: Vec<(String, u64, u64, String)> = out["data"]["devirtualized"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|d| {
                        let s = |k: &str| d[k].as_str().unwrap_or("").to_string();
                        (s("class"), d["slot"].as_u64().unwrap_or(0), hex(&d["method"]), s("name"))
                    })
                    .collect()
            })
            .unwrap_or_default();
        match want {
            BaseG => {
                // `g` is Base's second virtual method: slot 1, one pointer in.
                let base_g = ("Base".to_string(), rec.ptr, g, "Base::vf1".to_string());
                assert_eq!(found, vec![base_g], "{name} {caller}: the call is Base::g at {g:#x}");
            }
            Refused(why) => assert!(found.is_empty(), "{name} {caller}: must stay unresolved — {why}; resolved to {found:?}"),
            Gap(why) => assert!(
                found.is_empty(),
                "{name} {caller}: a recorded gap closed ({why}) — {found:?}; if it is Base::g at slot {} ({g:#x}), update this test",
                rec.ptr
            ),
        }
    }
}

/// The calls of `flow.cpp`'s functions, decompiled: `(class, slot, method)`
/// for each the decompiler resolved.
fn devirtualized_in(name: &str, rec: &Recorded, function: &str) -> Vec<(String, u64, u64)> {
    let out = n0xis(&["decomp", "pseudo", "--addr", &format!("{:#x}", rec.sym(function))], &fixtures().join(name));
    assert_eq!(out["ok"], true, "{name} {function}: {out}");
    out["data"]["devirtualized"]
        .as_array()
        .map(|a| a.iter().map(|d| (d["class"].as_str().unwrap_or("").to_string(), d["slot"].as_u64().unwrap_or(u64::MAX), hex(&d["method"]))).collect())
        .unwrap_or_default()
}

/// A construction — a vtable stored into the object, here by a placement
/// new — is the object's dynamic type only where it **dominates** the call,
/// and only where no other construction of the object can reach the call.
///
/// From the source (`flow.cpp`) and the processor (`flow_run.cpp`, recorded
/// in `processor_run.txt`; each call prints f + 1, D::f 43, B::f 7):
///
/// - `g` builds a `B` in its argument only on the branch that returns, and
///   calls `f` on the other: on a `D` the processor runs `D::f` (43). Taking
///   the stored vtable as the variable's class resolved the call to `B::f`.
/// - `built` builds a `D` and calls `f`: `D::f` (43), and it resolves so.
/// - `rebuilt` builds a `D`, and a `B` over it on one path: the processor runs
///   `D::f` (43) or `B::f` (7) by its argument, so the call has no one
///   method. It resolved to `B::f`, the last vtable stored in program order.
#[test]
fn a_construction_names_the_object_only_where_it_dominates_the_call() {
    let name = "vf-x86_64-linux-gnu";
    let rec = recorded(name);
    let d_f = rec.sym("_ZNK1D1fEv");
    // The recorded `.rodata`: slot 0 of D's table is D::f, of B's B::f.
    assert_eq!(rec.word(rec.sym("_ZTV1D") + 2 * rec.ptr), Some(d_f), "{name}: D's first slot");
    assert_eq!(rec.word(rec.sym("_ZTV1B") + 2 * rec.ptr), Some(rec.sym("_ZNK1B1fEv")), "{name}: B's first slot");
    let g = devirtualized_in(name, &rec, "_Z1gPvi");
    assert_eq!(g, vec![], "{name} g: the B built on the other branch is not the object at the call; on a D the processor runs D::f");
    let built = devirtualized_in(name, &rec, "_Z5builtPv");
    assert_eq!(built, vec![("D".to_string(), 0, d_f)], "{name} built: the D built before the call, D::f at {d_f:#x}");
    let rebuilt = devirtualized_in(name, &rec, "_Z7rebuiltPvi");
    assert_eq!(rebuilt, vec![], "{name} rebuilt: built as D, and as B on one path to the call; the processor runs either");
}

/// A project directory of its own for one engine run that **persists** what it
/// finds: `analyze` writes `.n0x/rtti-symbols.json`, and every later run in the
/// same directory renders those names, so sharing [`project`] would let one
/// fixture's names leak into another's decompilation.
fn own_project(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis-itanium-vtables-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("temp project");
    dir
}

/// The file bytes the loader maps: up to the end of the last `PT_LOAD`'s file
/// contents. Read here, little-endian, from the program headers — what an
/// image is made of, not what any parser of this project says it is.
fn mapped_end(elf: &[u8]) -> usize {
    let u16_at = |o: usize| usize::from(u16::from_le_bytes([elf[o], elf[o + 1]]));
    let word = |o: usize, n: usize| (0..n).rev().fold(0usize, |acc, i| acc << 8 | usize::from(elf[o + i]));
    let wide = elf[4] == 2;
    let (phoff, phentsize, phnum) =
        if wide { (word(0x20, 8), u16_at(0x36), u16_at(0x38)) } else { (word(0x1c, 4), u16_at(0x2a), u16_at(0x2c)) };
    (0..phnum)
        .map(|i| phoff + i * phentsize)
        .filter(|&ph| word(ph, 4) == 1) // PT_LOAD
        .map(|ph| if wide { word(ph + 8, 8) + word(ph + 0x20, 8) } else { word(ph + 4, 4) + word(ph + 0x10, 4) })
        .max()
        .expect("an executable has a PT_LOAD")
}

/// `analyze` names each method a vtable slot holds `Class::vfN`, counting the
/// slots at the image's width. A symbol the image already has wins over that
/// name, so on the unstripped executables there is nothing left to see: these
/// are the same executables with every symbol but `_ZT*` removed.
///
/// Read with 8-byte slots — which is what `analyze` passed for every ELF — a
/// 32-bit table's first two slots join into one value that is no code address,
/// and no method is named. The expected names are the source's, at the
/// addresses `llvm-nm` gave the unstripped file, and every reported `N` is
/// checked against the word the recorded `.rodata` holds in that slot.
#[test]
fn analyze_names_the_slots_of_a_symbol_free_image_at_its_width() {
    // The methods the walk reaches, from the source. Each is named once, by
    // the first table that holds it, so `Derived`'s inherited `Base::f` is not
    // named twice. `Shape`'s first slot is the pure virtual, which this
    // executable links to 0; the walk stops at a slot that is not code, so
    // `Shape::sides` behind it is not named — a recorded gap.
    const NAMED: [&str; 10] = [
        "_ZNK4Base1fEv", "_ZNK4Base1gEv", "_ZNK7Derived1gEv", "_ZNK7Derived1kEv", "_ZNK6Square4areaEv",
        "_ZNK6Square5sidesEv", "_ZN4Left1lEv", "_ZN5Right1rEv", "_ZN4Both1lEv", "_ZN4Both1rEv",
    ];
    for t in TARGETS {
        let name = format!("vt-{t}");
        let rec = recorded(&name);
        let (full, cut) = (fixtures().join(&name), fixtures().join("stripped").join(&name));
        let (full_bytes, cut_bytes) = (std::fs::read(&full).expect("the executable"), std::fs::read(&cut).expect("the stripped one"));
        // The recordings are the unstripped file's. They hold for the stripped
        // one because the loader maps the same bytes from both. Left out of the
        // comparison: the ELF header from `e_shoff` on, where stripping moved
        // and shrank the section header table (measured: `e_shoff`, `e_shnum`
        // and `e_shstrndx` are the only bytes there that differ).
        let (sh_fields, ehsize) = if rec.ptr == 8 { (0x28..0x40, 0x40) } else { (0x20..0x34, 0x34) };
        let end = mapped_end(&full_bytes);
        assert_eq!(mapped_end(&cut_bytes), end, "{name}: the same program headers");
        assert_eq!(full_bytes[..sh_fields.start], cut_bytes[..sh_fields.start], "{name}: the ELF header up to e_shoff");
        assert!(full_bytes[ehsize..end] == cut_bytes[ehsize..end], "{name}: every mapped byte is the unstripped file's");

        let dir = own_project(t);
        let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
            .current_dir(&dir)
            .args(["analyze", "--no-cfg", "--quiet", "--file"])
            .arg(&cut)
            .output()
            .expect("run n0xis analyze");
        let envelope: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{name}: one envelope from analyze: {e}"));
        assert_eq!(envelope["ok"], true, "{name}: {envelope}");
        let persisted: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join(".n0x/rtti-symbols.json")).expect("analyze persisted rtti-symbols.json"))
                .expect("JSON");
        let _ = std::fs::remove_dir_all(&dir);
        let syms = persisted["syms"].as_array().expect("a symbol list");
        let entries = |kind: &str| -> BTreeMap<u64, String> {
            syms.iter()
                .filter(|s| s["kind"] == kind)
                .map(|s| (s["va"].as_u64().expect("an address"), s["name"].as_str().expect("a name").to_string()))
                .collect()
        };

        let vptr = |class: &str| {
            let (_, suffix, _, _) = CLASSES.iter().find(|c| c.0 == class).unwrap_or_else(|| panic!("{name}: {class} is no class of the source"));
            rec.sym(&format!("_ZTV{suffix}")) + 2 * rec.ptr
        };
        let tables: BTreeMap<u64, String> = CLASSES.iter().map(|(c, ..)| (vptr(c), format!("{c}::vftable"))).collect();
        assert_eq!(entries("data"), tables, "{name}: each class's vftable at _ZTV + two {}-byte pointers", rec.ptr);

        let functions = entries("function");
        for (va, method) in &functions {
            let (class, n) = method.rsplit_once("::vf").unwrap_or_else(|| panic!("{name}: {method} at {va:#x} is no slot name"));
            let n: u64 = n.parse().unwrap_or_else(|e| panic!("{name}: {method}: {e}"));
            let slot = vptr(class) + n * rec.ptr;
            assert_eq!(rec.word(slot), Some(*va), "{name}: {method} at {va:#x}, but slot {n} of {class} ({slot:#x}) holds another word");
        }
        let want: std::collections::BTreeSet<u64> = NAMED.iter().map(|m| rec.sym(m)).collect();
        let got: std::collections::BTreeSet<u64> = functions.keys().copied().collect();
        assert_eq!(got, want, "{name}: the methods the source puts in the walked slots, each named once: {functions:?}");
    }
}

/// The vtable `fresh` stores into its object is named in the decompilation,
/// which needs the vtable map the decompiler is handed to be at the image's
/// width: read at 8 bytes, a 32-bit executable's map is empty and the store is
/// a bare number. On ARM the address is built by two instructions the lift
/// leaves as asm (`movw`/`movt`, `adrp`/`add`), so nothing names it there yet —
/// recorded, so that the day it changes this fails and says so.
#[test]
fn the_vtable_a_constructor_stores_is_named_at_both_widths() {
    for (t, named) in [("i686-linux-gnu", true), ("x86_64-linux-gnu", true), ("armv7-linux-gnueabihf", false), ("aarch64-linux-gnu", false)] {
        let name = format!("vt-{t}");
        let rec = recorded(&name);
        let dir = own_project(&format!("fresh-{t}"));
        let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
            .current_dir(&dir)
            .args(["decomp", "pseudo", "--quiet", "--addr", &format!("{:#x}", rec.sym("_Z5freshPv")), "--file"])
            .arg(fixtures().join(&name))
            .output()
            .expect("run n0xis decomp");
        let _ = std::fs::remove_dir_all(&dir);
        let out: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{name}: one envelope from decomp: {e}"));
        assert_eq!(out["ok"], true, "{name}: {out}");
        let lines: Vec<&str> = out["data"]["pseudo"].as_array().expect("pseudo lines").iter().filter_map(Value::as_str).collect();
        // `fresh` builds a `Base` in place: the one vtable it can store is Base's.
        let stores_base = lines.iter().any(|l| l.trim_end().ends_with("= &Base::vtable;"));
        assert_eq!(stores_base, named, "{name}: {}", if named { "fresh stores Base's vtable" } else { "a recorded gap closed" });
        assert!(!lines.iter().any(|l| l.contains("::vtable") && !l.contains("&Base::vtable")), "{name}: only Base's table is stored: {lines:#?}");
    }
}

/// Runs `analyze` on `file` in a project of its own and returns its envelope
/// and the `rtti-symbols.json` it persisted, if any.
fn analyze(file: &Path, tag: &str) -> (Value, Option<Value>) {
    let dir = own_project(tag);
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
        .current_dir(&dir)
        .args(["analyze", "--no-cfg", "--quiet", "--file"])
        .arg(file)
        .output()
        .expect("run n0xis analyze");
    let envelope: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{tag}: one envelope from analyze: {e}"));
    let persisted = std::fs::read_to_string(dir.join(".n0x/rtti-symbols.json")).ok().map(|s| serde_json::from_str(&s).expect("JSON"));
    let _ = std::fs::remove_dir_all(&dir);
    (envelope, persisted)
}

/// On 32-bit ARM a Thumb method's slot holds its address with bit 0 set. Read
/// as an address, that named an odd address, mid-instruction, `Class::vfN`:
/// on the stripped `-mthumb` executable `analyze` persisted ten such names,
/// every one odd. Until bit 0 is cleared by one rule for symbols and slots
/// alike (the format seam's step 2), such a slot is not named, and the count
/// of slots refused is in `analyze`'s answer.
#[test]
fn a_thumb_slot_is_not_named_at_its_odd_address() {
    let name = format!("vt-{THUMB}");
    let rec = recorded(&name);
    let vptr = |suffix: &str| rec.sym(&format!("_ZTV{suffix}")) + 2 * rec.ptr;
    // The fixture is what it says: the first slot of Base holds Base::f's
    // address plus one, in the recorded `.rodata`.
    assert_eq!(rec.word(vptr("4Base")), Some(rec.sym("_ZNK4Base1fEv") | 1), "{name}: a Thumb method's slot holds its address with bit 0 set");

    let (envelope, persisted) = analyze(&fixtures().join("stripped").join(&name), "thumb");
    assert_eq!(envelope["ok"], true, "{name}: {envelope}");
    let data = &envelope["data"];
    assert_eq!(data["rtti_classes"], CLASSES.len(), "{name}: {data}");
    // The slots the walk reaches, from the source: Base f, g; Derived f, g, k;
    // Shape none (its first slot, the pure virtual, links to 0 here and ends
    // the walk); Square area, sides; Left l; Right r; Both l, r — Both::r gets
    // a slot in Both's primary table, since Left has no r.
    assert_eq!(data["rtti_thumb_slots_refused"], 11, "{name}: every walked slot is a Thumb method: {data}");
    let persisted = persisted.expect("analyze persisted rtti-symbols.json");
    let syms = persisted["syms"].as_array().expect("a symbol list");
    let named: Vec<(u64, &str)> = syms
        .iter()
        .filter(|s| s["kind"] == "function")
        .map(|s| (s["va"].as_u64().expect("an address"), s["name"].as_str().expect("a name")))
        .collect();
    assert!(named.iter().all(|(va, _)| va & 1 == 0), "{name}: a name at an odd address: {named:?}");
    assert_eq!(named, Vec::<(u64, &str)>::new(), "{name}: no method is named from a Thumb slot");
    let tables: BTreeMap<u64, String> = CLASSES.iter().map(|(c, suffix, ..)| (vptr(suffix), format!("{c}::vftable"))).collect();
    let got: BTreeMap<u64, String> = syms
        .iter()
        .filter(|s| s["kind"] == "data")
        .map(|s| (s["va"].as_u64().expect("an address"), s["name"].as_str().expect("a name").to_string()))
        .collect();
    assert_eq!(got, tables, "{name}: the vtables themselves are still named, at _ZTV + two 4-byte pointers");
}

/// A big-endian ELF's pointers read byte-swapped by every RTTI reader here, so
/// each RTTI path refuses one with an error naming the byte order. Before,
/// `rtti scan` on this shared object answered `ok: true` with seven classes
/// whose type_info and slots had been read little-endian.
#[test]
fn a_big_endian_image_is_refused_by_every_rtti_path() {
    let rec = recorded(BIG_ENDIAN);
    let readobj = std::fs::read_to_string(fixtures().join(format!("{BIG_ENDIAN}.readobj.txt"))).expect("the recording");
    assert!(readobj.lines().any(|l| l.trim() == "DataEncoding: BigEndian (0x2)"), "{BIG_ENDIAN}: llvm-readobj says it is big-endian");
    let file = fixtures().join(BIG_ENDIAN);
    let refused = |what: &str, out: &Value| {
        assert_eq!(out["ok"], false, "{what}: {out}");
        assert_eq!(out["error"]["code"], "big-endian-image", "{what}: {out}");
        let message = out["error"]["message"].as_str().unwrap_or("");
        assert!(message.contains("big-endian") && message.contains("EI_DATA"), "{what}: the message names the byte order: {message}");
    };
    refused("rtti scan", &n0xis(&["rtti", "scan"], &file));
    let h = format!("{:#x}", rec.sym("_ZNK4Base1hEv"));
    refused("decomp pseudo", &n0xis(&["decomp", "pseudo", "--addr", &h], &file));
    let (envelope, persisted) = analyze(&file, "big-endian");
    refused("analyze", &envelope);
    assert!(persisted.is_none(), "{BIG_ENDIAN}: nothing persisted from RTTI read in the wrong byte order");
    // Not an RTTI path, and not changed here: `ir build` still answers, reading
    // the code little-endian like every reader but these — an open item.
    assert_eq!(n0xis(&["ir", "build", "--addr", &h], &file)["ok"], true, "ir build is not an RTTI path");
}

/// A class with virtual bases has a VTT (`_ZTT`), and its vtable begins with
/// its virtual-base offsets: `_ZTV` + two pointers is its `type_info` slot, not
/// its vptr. Such a class was reported there — on `libstdc++.so.6`, 27 of 179
/// classes at either width. It is now refused and counted, at both widths.
///
/// From the source (`vbases.cpp`): `Mid` has a virtual base and `Leaf` an
/// indirect one, so both have a VTT; `VBase` has none. From the recordings:
/// `llvm-nm` lists the two `_ZTT`s, and `llvm-readobj -r` names `_ZTI3Mid` and
/// `_ZTI4Leaf` as what fills `_ZTV` + two pointers — where the old answer put
/// each vptr.
#[test]
fn a_class_with_virtual_bases_is_refused_at_both_widths() {
    for t in ["i686-linux-gnu", "x86_64-linux-gnu"] {
        let name = format!("vb-{t}.so");
        let rec = recorded(&name);
        for (class, suffix) in [("Mid", "3Mid"), ("Leaf", "4Leaf")] {
            rec.sym(&format!("_ZTT{suffix}"));
            let old_vptr = rec.sym(&format!("_ZTV{suffix}")) + 2 * rec.ptr;
            assert_eq!(
                rec.relocs.get(&old_vptr),
                Some(&format!("_ZTI{suffix}")),
                "{name}: {class}'s _ZTV + two pointers is its type_info slot, not a method"
            );
        }
        let scan = n0xis(&["rtti", "scan"], &fixtures().join(&name));
        assert_eq!(scan["ok"], true, "{name}: {scan}");
        let listed: Vec<&str> = scan["data"]["vtables"].as_array().expect("a vtable list").iter().filter_map(|v| v["name"].as_str()).collect();
        assert_eq!(listed, vec!["VBase"], "{name}: only the class without a virtual base has a vptr to report");
        assert_eq!(scan["data"]["count"], 1, "{name}");
        assert_eq!(scan["data"]["refused_virtual_bases"], 2, "{name}: Mid and Leaf, counted rather than placed");
        assert_eq!(scan["data"]["refused_first_slot_not_code"], 0, "{name}");
        let vbase = &scan["data"]["vtables"][0];
        let vptr = hex(&vbase["vtable"]);
        assert_eq!(rec.relocs.get(&vptr).map(String::as_str), Some("_ZNK5VBase1aEv"), "{name}: VBase's first slot");
    }
}

/// The word of `rec`'s image that names `_ZTI<suffix>`, first in the `_ZTV`
/// object: the relocation `llvm-readobj -r` lists there (shared object), or the
/// word `.rodata` holds there (executable). One pointer past it is the
/// address point — where an object's vptr points.
fn type_info_word(rec: &Recorded, suffix: &str, shared: bool) -> u64 {
    let ztv = rec.sym(&format!("_ZTV{suffix}"));
    let zti = format!("_ZTI{suffix}");
    (0..64)
        .map(|i| ztv + i * rec.ptr)
        .find(|&at| if shared { rec.relocs.get(&at) == Some(&zti) } else { rec.word(at) == Some(rec.sym(&zti)) })
        .unwrap_or_else(|| panic!("no word of _ZTV{suffix} names {zti}"))
}

/// A class with virtual bases and **no VTT**: clang at `-O2` emits none for a
/// class without a key function, so refusing only where a `_ZTT` exists left
/// every such class reported at `_ZTV` + two pointers. On the shared object
/// that is two pointers before the address point; `analyze` persisted
/// `M::vftable` and `N::vftable` there, and a virtual call on an `M` built by
/// its constructor resolved to the method one slot off (`f1` for `f3`).
///
/// From the source (`vbinline.cpp`): `M` and `N` have virtual bases, `Plain`
/// and `Tail` none. From the recordings: `llvm-nm` lists no `_ZTT` at all, and
/// the word that names `M`'s and `N`'s own `_ZTI` — a relocation, or the word
/// `.rodata` holds — is past `_ZTV` + one pointer, so `_ZTV` + two pointers is
/// not their vptr; one pointer past it is, and it holds the method the source
/// puts first.
#[test]
fn a_class_with_virtual_bases_and_no_vtt_is_refused() {
    for t in ["i686-linux-gnu", "x86_64-linux-gnu"] {
        for name in [format!("vbi-{t}.so"), format!("vbi-{t}")] {
            let shared = name.ends_with(".so");
            let rec = recorded(&name);
            assert!(!rec.symbols.keys().any(|s| s.starts_with("_ZTT")), "{name}: llvm-nm lists no VTT");
            for (suffix, first) in [("1M", "_ZNK1M2f1Ev"), ("1N", "_ZNK1N2fpEv")] {
                let ztv = rec.sym(&format!("_ZTV{suffix}"));
                let address_point = type_info_word(&rec, suffix, shared) + rec.ptr;
                assert!(address_point > ztv + 2 * rec.ptr, "{name}: _ZTV{suffix}'s address point {address_point:#x} is past _ZTV + two pointers");
                let holds = if shared { rec.relocs.get(&address_point).cloned() } else { None };
                if shared {
                    assert_eq!(holds.as_deref(), Some(first), "{name}: _ZTV{suffix}'s first method, at its address point");
                } else {
                    assert_eq!(rec.word(address_point), Some(rec.sym(first)), "{name}: _ZTV{suffix}'s first method, at its address point");
                }
            }
            let scan = n0xis(&["rtti", "scan"], &fixtures().join(&name));
            assert_eq!(scan["ok"], true, "{name}: {scan}");
            let listed: Vec<(&str, u64)> = scan["data"]["vtables"]
                .as_array()
                .expect("a vtable list")
                .iter()
                .map(|v| (v["name"].as_str().unwrap_or(""), hex(&v["vtable"])))
                .collect();
            let plain = |suffix: &str| rec.sym(&format!("_ZTV{suffix}")) + 2 * rec.ptr;
            assert_eq!(listed, vec![("Plain", plain("5Plain")), ("Tail", plain("4Tail"))], "{name}: the classes without a virtual base, at _ZTV + two pointers");
            assert_eq!(scan["data"]["refused_virtual_bases"], 2, "{name}: M and N, counted rather than placed");
            assert_eq!(scan["data"]["refused_first_slot_not_code"], 0, "{name}");
            if !shared {
                // Neither has a base. Tail's type_info is the last object of
                // its segment, and reading past it once made it unreadable.
                for v in scan["data"]["vtables"].as_array().expect("a vtable list") {
                    assert_eq!(v["bases"], serde_json::json!([]), "{name}: {v}");
                }
            }
            if !shared {
                let (envelope, persisted) = analyze(&fixtures().join(&name), &format!("vbi-{t}"));
                assert_eq!(envelope["ok"], true, "{name}: {envelope}");
                assert_eq!(envelope["data"]["rtti_refused_virtual_bases"], 2, "{name}: {envelope}");
                let persisted = persisted.expect("analyze persisted rtti-symbols.json");
                let tables: BTreeMap<u64, &str> = persisted["syms"]
                    .as_array()
                    .expect("a symbol list")
                    .iter()
                    .filter(|s| s["kind"] == "data")
                    .map(|s| (s["va"].as_u64().expect("an address"), s["name"].as_str().expect("a name")))
                    .collect();
                let want: BTreeMap<u64, &str> = [(plain("5Plain"), "Plain::vftable"), (plain("4Tail"), "Tail::vftable")].into_iter().collect();
                assert_eq!(tables, want, "{name}: no vftable is named for a class whose vptr is not where the scan reads it");
            }
        }
    }
    // A virtual call on an object its constructor built: `M`'s is not resolved,
    // as `M`'s table is not placed; `Plain`'s, the control, is `Plain::g`.
    let name = "vbi-x86_64-linux-gnu";
    let rec = recorded(name);
    let devirtualized = |caller: &str| -> Vec<(String, u64)> {
        let out = n0xis(&["decomp", "pseudo", "--addr", &format!("{:#x}", rec.sym(caller))], &fixtures().join(name));
        assert_eq!(out["ok"], true, "{name} {caller}: {out}");
        out["data"]["devirtualized"]
            .as_array()
            .map(|a| a.iter().map(|d| (d["class"].as_str().unwrap_or("").to_string(), hex(&d["method"]))).collect())
            .unwrap_or_default()
    };
    assert_eq!(devirtualized("_Z7build_mPv"), vec![], "{name}: M's vptr is not known, so M's slots are not read");
    assert_eq!(devirtualized("_Z11build_plainPv"), vec![("Plain".to_string(), rec.sym("_ZNK5Plain1gEv"))], "{name}: Plain::g, the control");
}

/// A class the scan does not list is still a class of the image. `Sub`'s
/// first method is outside every executable section (`notcode.cpp` writes it
/// in assembly into a writable `.data`; `llvm-nm` gives it kind `D`, data), so
/// the word at `_ZTV3Sub` + two pointers is no code address to the scan. `Sub`
/// was once dropped without a word — from the hierarchy too, so the subclass
/// guard read `Base` as derived from nowhere and resolved `Base::h`'s call
/// through `this` to `Base::g`, where on a `Sub` the processor runs `Sub::g`
/// (`outside.cpp`, the same classes: 123, where `Base::g` gives 6). `Sub` is
/// counted, and an image with a class the scan did not read has an unknown
/// hierarchy.
#[test]
fn a_class_the_scan_does_not_list_is_counted_and_keeps_the_hierarchy_open() {
    let name = "vd-x86_64-linux-gnu";
    let rec = recorded(name);
    let sub_first = rec.sym("_ZTV3Sub") + 2 * rec.ptr;
    assert_eq!(rec.word(sub_first), Some(rec.sym("_ZNK3Sub1fEv")), "{name}: Sub's first slot holds Sub::f");
    assert_eq!(nm_kind(name, "_ZNK3Sub1fEv"), "D", "{name}: llvm-nm puts Sub::f in a data section");
    let scan = n0xis(&["rtti", "scan"], &fixtures().join(name));
    assert_eq!(scan["ok"], true, "{name}: {scan}");
    let listed: Vec<&str> = scan["data"]["vtables"].as_array().expect("a vtable list").iter().filter_map(|v| v["name"].as_str()).collect();
    assert_eq!(listed, vec!["Base", "Last"], "{name}");
    assert_eq!(scan["data"]["refused_first_slot_not_code"], 1, "{name}: Sub, counted");
    assert_eq!(scan["data"]["refused_virtual_bases"], 0, "{name}");
    // Every class the scan lists has its bases read, so only Sub can keep
    // the hierarchy open. (Last's type_info ends its segment; reading past
    // it once made Last unreadable, which refused the call below for a
    // reason that had nothing to do with Sub.)
    for v in scan["data"]["vtables"].as_array().expect("a vtable list") {
        assert_eq!(v["bases"], serde_json::json!([]), "{name}: {v}");
    }
    let out = n0xis(&["decomp", "pseudo", "--addr", &format!("{:#x}", rec.sym("_ZNK4Base1hEv"))], &fixtures().join(name));
    assert_eq!(out["ok"], true, "{name}: {out}");
    let resolved = out["data"]["devirtualized"].as_array().cloned().unwrap_or_default();
    assert_eq!(resolved, Vec::<Value>::new(), "{name}: Base::h's call through `this` must stay unresolved — Sub derives from Base");
}

/// The kind letter `llvm-nm` recorded for `symbol` in `name`'s recording.
fn nm_kind(name: &str, symbol: &str) -> String {
    let nm = std::fs::read_to_string(fixtures().join(format!("{name}.nm.txt"))).expect("the recording");
    nm.lines()
        .find_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            (w.len() == 3 && w[2] == symbol).then(|| w[1].to_string())
        })
        .unwrap_or_else(|| panic!("{name}: llvm-nm lists no {symbol}"))
}

/// A method in an executable section other than `.text` is code. `outside.cpp`
/// puts `Sub::f` in `hot_code` (`llvm-nm` kind `T`, a code section), and the
/// scan, gated on `.text` alone, refused `Sub` as having no code at its first
/// slot. It lists `Sub` now, at `_ZTV3Sub` + two pointers, with its base read
/// — so `Base` is known to be derived from, and `Base::h`'s call through
/// `this` stays unresolved for that reason (on a `Sub` the processor runs
/// `Sub::g`: 123, where `Base::g` gives 6).
#[test]
fn a_first_method_in_another_code_section_is_code() {
    let name = "vo-x86_64-linux-gnu";
    let rec = recorded(name);
    let sub_first = rec.sym("_ZTV3Sub") + 2 * rec.ptr;
    assert_eq!(rec.word(sub_first), Some(rec.sym("_ZNK3Sub1fEv")), "{name}: Sub's first slot holds Sub::f, which the source puts in hot_code");
    assert_eq!(nm_kind(name, "_ZNK3Sub1fEv"), "T", "{name}: llvm-nm puts Sub::f in a code section");
    let scan = n0xis(&["rtti", "scan"], &fixtures().join(name));
    assert_eq!(scan["ok"], true, "{name}: {scan}");
    let by: BTreeMap<&str, &Value> =
        scan["data"]["vtables"].as_array().expect("a vtable list").iter().map(|v| (v["name"].as_str().unwrap_or(""), v)).collect();
    assert_eq!(by.keys().copied().collect::<Vec<_>>(), vec!["Base", "Last", "Sub"], "{name}");
    assert_eq!(hex(&by["Sub"]["vtable"]), sub_first, "{name}: Sub at _ZTV3Sub + two pointers");
    assert_eq!(by["Sub"]["bases"], serde_json::json!(["Base"]), "{name}: Sub : Base, from the source");
    assert_eq!(scan["data"]["refused_first_slot_not_code"], 0, "{name}");
    let out = n0xis(&["decomp", "pseudo", "--addr", &format!("{:#x}", rec.sym("_ZNK4Base1hEv"))], &fixtures().join(name));
    assert_eq!(out["ok"], true, "{name}: {out}");
    let resolved = out["data"]["devirtualized"].as_array().cloned().unwrap_or_default();
    assert_eq!(resolved, Vec::<Value>::new(), "{name}: Base::h's call through `this` stays unresolved — Sub derives from Base");
}

/// A class whose base this image cannot name has a base all the same. Its
/// `type_info` is three pointers — the one-base layout, as `Local : Ext` in
/// the source — and the third, the base's, reads zero, because `_ZTI3Ext` is
/// in another image. Read by the bytes after the name, that was "no bases";
/// it is `base-not-named` now. `Alone`, with no base, is `[]` — its
/// `type_info` is two pointers and nothing past it is read.
#[test]
fn a_base_in_another_image_is_unknown_not_absent() {
    for t in ["i686-linux-gnu", "x86_64-linux-gnu"] {
        let name = format!("vx-{t}");
        let rec = recorded(&name);
        assert!(!rec.symbols.contains_key("_ZTI3Ext"), "{name}: llvm-nm gives _ZTI3Ext no address here");
        assert_eq!(rec.word(rec.sym("_ZTI5Local") + 2 * rec.ptr), Some(0), "{name}: Local's base pointer reads zero");
        let scan = n0xis(&["rtti", "scan"], &fixtures().join(&name));
        assert_eq!(scan["ok"], true, "{name}: {scan}");
        let by: BTreeMap<&str, &Value> =
            scan["data"]["vtables"].as_array().expect("a vtable list").iter().map(|v| (v["name"].as_str().unwrap_or(""), v)).collect();
        assert_eq!(by.keys().copied().collect::<Vec<_>>(), vec!["Alone", "Local"], "{name}");
        assert_eq!(by["Local"].get("bases"), None, "{name}: {}", by["Local"]);
        assert_eq!(by["Local"]["bases_unknown"], "base-not-named", "{name}: {}", by["Local"]);
        assert_eq!(by["Alone"]["bases"], serde_json::json!([]), "{name}: {}", by["Alone"]);
    }
}

/// Where `rec`'s image has the first method of the `_ZTV<suffix>` table,
/// `first`: the first word of the table a relocation `llvm-readobj -r` lists
/// names it (shared object), or that `.rodata` holds its `llvm-nm` address
/// (executable). Nothing from this tool.
fn first_method_word(rec: &Recorded, suffix: &str, first: &str, shared: bool) -> u64 {
    let ztv = rec.sym(&format!("_ZTV{suffix}"));
    (0..64)
        .map(|i| ztv + i * rec.ptr)
        .find(|&at| if shared { rec.relocs.get(&at).map(String::as_str) == Some(first) } else { rec.word(at) == Some(rec.sym(first)) })
        .unwrap_or_else(|| panic!("no word of _ZTV{suffix} holds {first}"))
}

/// `(class, _ZTV suffix, first method)` of `vbnortti.cpp`, and whether the
/// class has a virtual base.
const NO_RTTI: [(&str, &str, &str, bool); 4] = [
    ("P", "1P", "_ZNK1P1pEv", false),
    ("HM", "2HM", "_ZNK2HM1pEv", true),
    ("HL", "2HL", "_ZNK2HL1pEv", true),
    ("Q", "1Q", "_ZNK1Q1qEv", false),
];

/// A class built **without RTTI** whose virtual base has no data and shares
/// its vptr, with no VTT: `HM : virtual P` and `HL : HM`. Every word of their
/// tables before the first method is zero — vcall and virtual-base offsets,
/// `offset_to_top`, a `type_info` slot with no `type_info` to name — so none
/// of the virtual-base facts sees them, and the zero at `_ZTV` + two pointers
/// was taken for a method the loader fills. `rtti scan` listed both there, and
/// `analyze` persisted `HM::vftable` and `HL::vftable` there: on i686 and
/// ARMv7 eight bytes into a table whose vptr the processor puts at + 20
/// (`vbnortti_run.cpp`, recorded in `processor_run.txt`), on x86-64 at + 16 for
/// + 40.
///
/// No relocation writes that word, so it is zero at run time, and the class is
/// refused (`refused_first_slot_empty`). From the source: `HM` and `HL` have a
/// virtual base, `P` and `Q` none. From the recordings: `llvm-nm` lists no
/// `_ZTI` and no `_ZTT`; the word that holds each class's first method — a
/// relocation `llvm-readobj -r` lists, or a word of `.rodata` — is
/// `_ZTV` + two pointers for `P` and `Q` and further in for `HM` and `HL`,
/// where nothing is relocated.
#[test]
fn a_class_without_rtti_whose_virtual_base_shares_its_vptr_is_refused() {
    let mut checked = 0;
    for name in [
        "vn-i686-linux-gnu",
        "vn-i686-linux-gnu.so",
        "vn-x86_64-linux-gnu",
        "vn-x86_64-linux-gnu.so",
        "vn-armv7-linux-gnueabihf",
    ] {
        let shared = name.ends_with(".so");
        let rec = recorded(name);
        assert!(!rec.symbols.keys().any(|s| s.starts_with("_ZTI") || s.starts_with("_ZTT")), "{name}: no type_info and no VTT");
        let mut want = Vec::new();
        for (class, suffix, first, virtual_base) in NO_RTTI {
            let ztv = rec.sym(&format!("_ZTV{suffix}"));
            let at = first_method_word(&rec, suffix, first, shared);
            if virtual_base {
                assert_eq!(at, ztv + 5 * rec.ptr, "{name}: {class}'s first method is five pointers in, where the processor's vptr is");
                assert!(!rec.relocs.contains_key(&(ztv + 2 * rec.ptr)), "{name}: nothing relocates {class}'s _ZTV + two pointers");
            } else {
                assert_eq!(at, ztv + 2 * rec.ptr, "{name}: {class}'s first method at _ZTV + two pointers");
                want.push((class.to_string(), at));
            }
        }
        let scan = n0xis(&["rtti", "scan"], &fixtures().join(name));
        assert_eq!(scan["ok"], true, "{name}: {scan}");
        let listed: Vec<(String, u64)> = scan["data"]["vtables"]
            .as_array()
            .expect("a vtable list")
            .iter()
            .map(|v| (v["name"].as_str().unwrap_or("").to_string(), hex(&v["vtable"])))
            .collect();
        assert_eq!(listed, want, "{name}: the classes without a virtual base, at their first method");
        assert_eq!(scan["data"]["refused_first_slot_empty"], 2, "{name}: HM and HL, counted rather than placed");
        assert_eq!(scan["data"]["refused_virtual_bases"], 0, "{name}");
        assert_eq!(scan["data"]["refused_first_slot_not_code"], 0, "{name}");
        let (envelope, persisted) = analyze(&fixtures().join(name), &format!("vn-{checked}"));
        assert_eq!(envelope["ok"], true, "{name}: {envelope}");
        assert_eq!(envelope["data"]["rtti_refused_first_slot_empty"], 2, "{name}: {envelope}");
        let persisted = persisted.expect("analyze persisted rtti-symbols.json");
        let mut tables: Vec<(String, u64)> = persisted["syms"]
            .as_array()
            .expect("a symbol list")
            .iter()
            .filter(|s| s["kind"] == "data")
            .map(|s| (s["name"].as_str().expect("a name").trim_end_matches("::vftable").to_string(), s["va"].as_u64().expect("an address")))
            .collect();
        tables.sort_by_key(|(_, va)| *va);
        assert_eq!(tables, want, "{name}: no vftable is named for HM or HL");
        checked += 1;
    }
    assert_eq!(checked, 5);
}

/// A class whose virtual base is **indirect** and shares its vptr, in a shared
/// object whose `type_info` pointers are symbolic relocations, with no VTT:
/// none of the facts read from bytes sees it — its offsets are zero, its own
/// `_ZTI`'s address is not in the file, and its `type_info` names a
/// non-virtual base. `Leaf : Mid : virtual P` was listed at `_ZTV` + two
/// pointers, an offset, and `Leaf2 : Mid2 : virtual E` (`E` empty, one offset)
/// at the relocation that names `_ZTI5Leaf2`, one pointer before its vptr.
///
/// Each class has its own `_ZTI`, so the second word of a table without
/// virtual bases is its `type_info` pointer, which a relocation writes; theirs
/// is zero and nothing writes it, so both are refused as having virtual bases.
/// From the recordings: the word `llvm-readobj -r` names their own `_ZTI` at,
/// and the method one pointer past it, which is the source's first.
#[test]
fn a_class_whose_virtual_base_is_indirect_is_refused_in_a_shared_object() {
    for t in ["i686-linux-gnu", "x86_64-linux-gnu"] {
        let name = format!("vy-{t}.so");
        let rec = recorded(&name);
        assert!(!rec.symbols.keys().any(|s| s.starts_with("_ZTT")), "{name}: llvm-nm lists no VTT");
        for (suffix, first) in [("4Leaf", "_ZNK3Mid2fpEv"), ("5Leaf2", "_ZNK5Leaf22m2Ev")] {
            let ztv = rec.sym(&format!("_ZTV{suffix}"));
            let address_point = type_info_word(&rec, suffix, true) + rec.ptr;
            assert!(address_point > ztv + 2 * rec.ptr, "{name}: _ZTV{suffix}'s address point {address_point:#x} is past _ZTV + two pointers");
            assert_eq!(rec.relocs.get(&address_point).map(String::as_str), Some(first), "{name}: _ZTV{suffix}'s first method");
            assert!(!rec.relocs.contains_key(&(ztv + rec.ptr)), "{name}: nothing relocates _ZTV{suffix} + one pointer");
        }
        let plain = rec.sym("_ZTV5Plain") + 2 * rec.ptr;
        assert_eq!(rec.relocs.get(&plain).map(String::as_str), Some("_ZNK5Plain1gEv"), "{name}: Plain, the control");
        let scan = n0xis(&["rtti", "scan"], &fixtures().join(&name));
        assert_eq!(scan["ok"], true, "{name}: {scan}");
        let listed: Vec<(&str, u64)> =
            scan["data"]["vtables"].as_array().expect("a vtable list").iter().map(|v| (v["name"].as_str().unwrap_or(""), hex(&v["vtable"]))).collect();
        assert_eq!(listed, vec![("Plain", plain)], "{name}");
        assert_eq!(scan["data"]["refused_virtual_bases"], 2, "{name}: Leaf and Leaf2");
        assert_eq!(scan["data"]["refused_first_slot_empty"], 0, "{name}");
    }
}

/// The same seven classes as `vt-<target>.so`, linked with packed relative
/// relocations (`RELR`): every class is listed at `_ZTV` + two pointers, as
/// the source lays it out, and none is refused. The control for the two rules
/// above, which read which words the loader writes: a reader of `RELR` that
/// missed its words would refuse classes here.
#[test]
fn packed_relative_relocations_keep_every_class_listed() {
    for t in ["i686-linux-gnu", "x86_64-linux-gnu"] {
        let name = format!("vr-{t}.so");
        let rec = recorded(&name);
        let scan = n0xis(&["rtti", "scan"], &fixtures().join(&name));
        assert_eq!(scan["ok"], true, "{name}: {scan}");
        let mut listed: Vec<(&str, u64)> =
            scan["data"]["vtables"].as_array().expect("a vtable list").iter().map(|v| (v["name"].as_str().unwrap_or(""), hex(&v["vtable"]))).collect();
        listed.sort();
        let mut want: Vec<(&str, u64)> = CLASSES.iter().map(|(class, suffix, ..)| (*class, rec.sym(&format!("_ZTV{suffix}")) + 2 * rec.ptr)).collect();
        want.sort();
        assert_eq!(listed, want, "{name}");
        for key in ["refused_virtual_bases", "refused_first_slot_not_code", "refused_first_slot_empty"] {
            assert_eq!(scan["data"][key], 0, "{name}: {key}");
        }
    }
}

/// A library's classes may be derived from in the program that loads it, so a
/// call through `this` in a library is not resolved by the declared class.
/// Nothing in `plugin.cpp` derives from `Plugin` or `Codec`, and every base is
/// read (`[]`), so the image alone says the hierarchy is closed; `Plugin::drive`'s
/// `run()` was resolved to `Plugin::run` in the shared object. The processor,
/// running a program linked against that very file, ran the program's own
/// `My::run` there: `My.drive()` printed 1007, where `Plugin::run` gives 1001
/// (`plugin_run.cpp`, `processor_run.txt`). In a program nothing else can
/// derive from `Plugin`, and the call is `Plugin::run`, whether its type is
/// `ET_EXEC` or `ET_DYN` (a position-independent executable).
#[test]
fn a_class_a_library_holds_may_be_derived_from_by_the_program_that_loads_it() {
    let calls = |name: &str| {
        let rec = recorded(name);
        let scan = n0xis(&["rtti", "scan"], &fixtures().join(name));
        assert_eq!(scan["ok"], true, "{name}: {scan}");
        let mut listed: Vec<(&str, &Value)> =
            scan["data"]["vtables"].as_array().expect("a vtable list").iter().map(|v| (v["name"].as_str().unwrap_or(""), &v["bases"])).collect();
        listed.sort_by_key(|(name, _)| *name);
        let none = serde_json::json!([]);
        assert_eq!(listed, vec![("Codec", &none), ("Plugin", &none)], "{name}: both classes, their bases read");
        (devirtualized_in(name, &rec, "_ZNK6Plugin5driveEv"), rec)
    };
    let (found, _) = calls("vp-x86_64-linux-gnu.so");
    assert_eq!(found, vec![], "vp-x86_64-linux-gnu.so: a program that loads it may derive from Plugin; on a My the processor runs My::run");
    for name in ["vp-x86_64-linux-gnu", "vp-pie-x86_64-linux-gnu"] {
        let (found, rec) = calls(name);
        assert_eq!(found, vec![("Plugin".to_string(), 0, rec.sym("_ZNK6Plugin3runEv"))], "{name}: a program, where nothing derives from Plugin");
    }
}

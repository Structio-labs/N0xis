// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Classes of a stripped C++ image, by the structure of its `type_info` and vtables.**
//!
//! The Itanium scan was driven by `_ZTV` symbols, so `strip` took every class with
//! it, and `rtti scan` said `ok: true` with no vtables on a program whose typeinfo
//! is all there: `oracle/xref/classes.cpp` keeps each `_ZTS` string in `.rodata` and
//! each `type_info` and vtable in `.data.rel.ro`, stripped or not.
//!
//! Nothing expected comes from this tool. The source says which class has which
//! bases and slots, and is written here. `nm` on the same file before `strip` says
//! where each `_ZTV` is and where each method is. The engine is asked of the copy
//! `strip` made, which has neither.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

mod support;

fn n0xis_exe() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("n0xis")
}

fn source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../oracle/xref/classes.cpp")
}

fn hex(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().expect("an address").trim_start_matches("0x"), 16).expect("hex")
}

/// `name → (address, size)` of each symbol, by `nm -S`.
fn nm(file: &Path) -> BTreeMap<String, (u64, u64)> {
    let out = Command::new("nm").env("LC_ALL", "C").arg("-S").arg(file).output().expect("nm");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            match f.as_slice() {
                [addr, size, _, name] => Some((name.to_string(), (u64::from_str_radix(addr, 16).ok()?, u64::from_str_radix(size, 16).ok()?))),
                [addr, _, name] => Some((name.to_string(), (u64::from_str_radix(addr, 16).ok()?, 0))),
                _ => None,
            }
        })
        .collect()
}

fn scan(file: &Path) -> Value {
    let mut cmd = support::isolated(Command::new(n0xis_exe()));
    let out = cmd.args(["rtti", "scan", "--file"]).arg(file).output().expect("n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("no envelope ({e})"));
    assert_eq!(v["ok"], true, "{v}");
    v["data"].clone()
}

/// `(class as read, its _ZTV, its direct bases, its slots from the first, by mangled
/// method)`, from `classes.cpp`. Empty for a slot whose method may not be in the image.
const CLASSES: [(&str, &str, &[&str], &[&str]); 9] = [
    ("Base", "_ZTV4Base", &[], &["_ZN4BaseD1Ev", "_ZN4BaseD0Ev", "_ZN4Base1fEv"]),
    ("Derived", "_ZTV7Derived", &["Base"], &["_ZN7DerivedD1Ev", "_ZN7DerivedD0Ev", "_ZN7Derived1fEv", "_ZN7Derived1gEv"]),
    ("Left", "_ZTV4Left", &[], &["_ZN4Left1lEv"]),
    ("Right", "_ZTV5Right", &[], &["_ZN5Right1rEv"]),
    ("Both", "_ZTV4Both", &["Left", "Right"], &["_ZN4Both1lEv", "_ZN4Both1rEv"]),
    // gcc writes a zero for an abstract class's destructors, so nothing past `pure` can
    // be asked of it, and the walk stops at the zero.
    ("Abstract", "_ZTV8Abstract", &[], &[]),
    ("Concrete", "_ZTV8Concrete", &["Abstract"], &["_ZN8Concrete4pureEv", "", ""]),
    ("deep::Box<int>", "_ZTVN4deep3BoxIiEE", &["Base"], &["", "", "_ZN4deep3BoxIiE1fEv"]),
    ("(anonymous namespace)::Hidden", "_ZTVN12_GLOBAL__N_16HiddenE", &["Base"], &["", "", "_ZN12_GLOBAL__N_16Hidden1fEv"]),
];

fn build(tag: &str, compiler: &str, flags: &[&str], src: &Path) -> Option<(PathBuf, PathBuf)> {
    let dir = std::env::temp_dir().join(format!("n0xis_rtti_stripped_{}_{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let whole = dir.join("whole");
    match Command::new(compiler).args(flags).arg("-o").arg(&whole).arg(src).output() {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            eprintln!("{tag}: skipped, {compiler}: {}", String::from_utf8_lossy(&o.stderr).lines().next().unwrap_or(""));
            return None;
        }
        Err(e) => {
            eprintln!("{tag}: skipped, {compiler}: {e}");
            return None;
        }
    }
    let stripped = dir.join("stripped");
    std::fs::copy(&whole, &stripped).expect("copy");
    assert!(Command::new("strip").arg(&stripped).status().expect("strip").success());
    assert!(!nm(&stripped).keys().any(|k| k.starts_with("_ZTV4")), "strip left the vtable symbols");
    Some((whole, stripped))
}

fn every_class_of_the_source(tag: &str, compiler: &str, flags: &[&str]) {
    let Some((whole, stripped)) = build(tag, compiler, flags, &source()) else { return };
    let truth = nm(&whole);
    let answer = scan(&stripped);
    let rows = answer["vtables"].as_array().expect("vtables");
    for (class, ztv, bases, slots) in CLASSES {
        let &(ztv_at, _) = truth.get(ztv).unwrap_or_else(|| panic!("{tag}: nm has no {ztv}"));
        let row = rows.iter().find(|r| r["name"] == class).unwrap_or_else(|| {
            let names: Vec<&str> = rows.iter().filter_map(|r| r["name"].as_str()).collect();
            panic!("{tag}: {class} is in the image and not in the answer: {names:?}")
        });
        assert_eq!(hex(&row["vtable"]), ztv_at + 16, "{tag}: {class}: {row}");
        assert_eq!(hex(&row["type_descriptor"]), ztv_at + 8, "{tag}: {class}: {row}");
        let listed: Vec<&str> = row["bases"].as_array().unwrap_or_else(|| panic!("{tag}: {class}: {row}")).iter().filter_map(Value::as_str).collect();
        assert_eq!(listed, bases, "{tag}: {class}: {row}");
        let listed_slots = row["slots"].as_array().cloned().unwrap_or_default();
        assert!(listed_slots.len() >= slots.len(), "{tag}: {class} has {} slots in the source: {row}", slots.len());
        for (i, method) in slots.iter().enumerate() {
            if method.is_empty() {
                continue;
            }
            let &(at, _) = truth.get(*method).unwrap_or_else(|| panic!("{tag}: nm has no {method}"));
            assert_eq!(hex(&listed_slots[i]), at, "{tag}: {class} slot {i}, {method}: {row}");
        }
    }
    // The first slot of the second table of `Both` is `Right`'s method's thunk, and
    // it is not a vptr of any class in the answer.
    let both = truth["_ZTV4Both"];
    let second_starts = both.0 + 16 + 2 * 8;
    for r in rows {
        let at = hex(&r["vtable"]);
        assert!(!(at > second_starts && at < both.0 + both.1), "{tag}: a class in Both's second table: {r}");
    }
    // A class with a virtual base is refused, as for one with its symbol; none listed
    // is outside its own table.
    assert!(answer["refused_virtual_bases"].as_u64().unwrap_or(0) >= 1, "{tag}: VMid: {answer}");
    assert!(!rows.iter().any(|r| r["name"] == "VMid"), "{tag}: {answer}");
    for r in rows.iter().filter(|r| r["name"] == "VLeaf" || r["name"] == "VBase") {
        let ztv = if r["name"] == "VLeaf" { "_ZTV5VLeaf" } else { "_ZTV5VBase" };
        let (start, size) = truth[ztv];
        let at = hex(&r["vtable"]);
        assert!(at > start && at < start + size, "{tag}: {r}");
    }
    // A class that is thrown has a type_info and no table.
    assert!(!rows.iter().any(|r| r["name"] == "Thrown"), "{tag}: {answer}");

    the_layouts_are_the_compilers(tag, &stripped);
}

/// `function layout` on the stripped copy, against the offsets the program prints
/// about its own classes.
fn the_layouts_are_the_compilers(tag: &str, stripped: &Path) {
    let said = Command::new(stripped).arg("offsets").output().expect("the program runs");
    let mut truth: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for line in String::from_utf8_lossy(&said.stdout).lines() {
        let (class, offset) = line.split_once(' ').expect("class offset");
        truth.entry(class.to_string()).or_default().push(offset.parse().expect("a number"));
    }
    assert_eq!(truth.len(), 5, "{tag}: the program said {truth:?}");

    let mut cmd = support::isolated(Command::new(n0xis_exe()));
    let out = cmd.args(["function", "layout", "--file"]).arg(stripped).output().expect("n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("no envelope ({e})"));
    assert_eq!(v["ok"], true, "{v}");
    let classes = &v["data"]["store"]["classes"];
    for (class, offsets) in &truth {
        let fields = classes[class]["fields"].as_array().unwrap_or_else(|| panic!("{tag}: no layout of {class}: {classes}"));
        let listed: Vec<u64> = fields.iter().filter_map(|f| f["offset"].as_u64()).collect();
        // The vptr is a field too: the one word at 0 that is no member.
        for at in &listed {
            assert!(*at == 0 || offsets.contains(at), "{tag}: {class} has no field at {at}: the program says {offsets:?}: {classes}");
        }
    }
    // Each method that reads a field is in the source, so each of these is reached.
    let has = |class: &str, at: u64| classes[class]["fields"].as_array().is_some_and(|f| f.iter().any(|x| x["offset"].as_u64() == Some(at)));
    for (class, at) in [("Derived", truth["Derived"][1]), ("Left", truth["Left"][0]), ("Right", truth["Right"][0]), ("Both", truth["Both"][1])] {
        assert!(has(class, at), "{tag}: {class} reads a field at {at} in the source: {classes}");
    }
}

#[test]
fn gcc_position_independent() {
    every_class_of_the_source("gcc_pie", "g++", &["-O1", "-fPIE", "-pie"]);
}

#[test]
fn gcc_position_independent_with_relr() {
    every_class_of_the_source("gcc_relr", "g++", &["-O1", "-fPIE", "-pie", "-Wl,-z,pack-relative-relocs"]);
}

#[test]
fn gcc_fixed() {
    every_class_of_the_source("gcc_fixed", "g++", &["-O1", "-fno-pie", "-no-pie"]);
}

/// The C++ runtime linked in: more classes than the source's, and no symbol to fill a
/// pure virtual slot, so it stays zero. Every class of the source is still found.
#[test]
fn gcc_static() {
    every_class_of_the_source("gcc_static", "g++", &["-O1", "-static", "-no-pie", "-fno-pie"]);
}

#[test]
fn gcc_static_position_independent() {
    every_class_of_the_source("gcc_static_pie", "g++", &["-O1", "-static-pie"]);
}

#[test]
fn clang_position_independent() {
    every_class_of_the_source("clang_pie", "clang++", &["-O1", "-fPIE", "-pie"]);
}

#[test]
fn clang_fixed() {
    every_class_of_the_source("clang_fixed", "clang++", &["-O1", "-fno-pie", "-no-pie"]);
}

/// No type_info in the image: the program has vtables, and no RTTI to read.
#[test]
fn a_program_with_no_rtti_stays_empty() {
    let Some((_, stripped)) = build("no_rtti", "g++", &["-O1", "-fPIE", "-pie", "-fno-rtti", "-DNO_RTTI"], &source_without_rtti()) else { return };
    let answer = scan(&stripped);
    let own: Vec<&Value> = answer["vtables"].as_array().expect("vtables").iter().collect();
    assert!(own.is_empty(), "{answer}");
}

/// A C program has nothing to scan either, and says nothing that is not so.
#[test]
fn a_c_program_stays_empty() {
    let dir = std::env::temp_dir().join(format!("n0xis_rtti_stripped_{}_c", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let src = dir.join("c.c");
    std::fs::write(&src, "#include <stdio.h>\nconst char* const looks[] = {\"3foo\", \"N3bar3bazE\"};\nint main(int c, char** v) { puts(looks[c & 1]); return v == 0; }\n").expect("write");
    let Some((_, stripped)) = build("c", "gcc", &["-O1", "-fPIE", "-pie"], &src) else { return };
    let answer = scan(&stripped);
    assert_eq!(answer["count"], 0, "strings that read as mangled type names are not classes: {answer}");
}

/// Where the relocations are not read, the scan cannot tell, and has to say so.
#[test]
fn an_object_file_cannot_tell_and_says_so() {
    let dir = std::env::temp_dir().join(format!("n0xis_rtti_stripped_{}_o", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let object = dir.join("classes.o");
    match Command::new("g++").args(["-O1", "-c", "-o"]).arg(&object).arg(source()).output() {
        Ok(o) if o.status.success() => {}
        _ => {
            eprintln!("skipped: g++ could not build");
            return;
        }
    }
    let answer = scan(&object);
    assert!(answer["structure_not_read"].as_str().is_some_and(|w| !w.is_empty()), "{answer}");
}

/// The same source with nothing a `-fno-rtti` build refuses.
fn source_without_rtti() -> PathBuf {
    let text = std::fs::read_to_string(source()).expect("read");
    let text = text.replace("dynamic_cast<Derived*>(b)->g()", "static_cast<Derived*>(b)->g()");
    let dir = std::env::temp_dir().join(format!("n0xis_rtti_stripped_{}_src", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("classes.cpp");
    std::fs::write(&path, text).expect("write");
    path
}

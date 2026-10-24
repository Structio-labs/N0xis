// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Every contradiction `contradictions` reports is in the tables, and every
//! one the tables hold is reported** (docs/design/WHY.md §6 item 1, rung 3).
//!
//! For each image, the tables are read with tools that are not this one, the
//! disagreements among them are worked out here, and the answer must be
//! exactly that set — a reported value its table does not hold is a wrong
//! answer, and a disagreement the tables show that the answer leaves out is a
//! missed one:
//!
//! - `end` and `overlap`: FDE ranges from GNU `objdump --dwarf=frames`,
//!   `RUNTIME_FUNCTION`s from `llvm-readobj --unwind`, `STT_FUNC` sizes from
//!   `readelf -sW` (both tables), a module's bodies from `wasm-objdump -d`
//!   and `-x`, and a PDB's procedure lengths from `llvm-pdbutil dump
//!   --symbols` (with the section addresses of `llvm-readobj --sections`)
//!   where a PDB of the image's name sits beside it. Which tables state
//!   extents is the engine's rule, restated: `.pdata` on a PE that has one
//!   (its `.eh_frame` then only adds regions), else `.eh_frame`; and the
//!   answer's own list of sources must be the tables that are not empty.
//! - `name`: on an ELF, the defined `STT_FUNC`/`STT_OBJECT` names of
//!   `.symtab` and `.dynsym` (`readelf -sW`), a version suffix cut off, at
//!   every address where either table has a function; two tables disagree
//!   when they share no name. On a module, the name section's name of each
//!   body against its export names (`wasm-objdump -x`).
//! - `image`: a module's data segments placed past their memory, from
//!   `wasm-objdump -x`; an ELF slot two `GLOB_DAT`/`JUMP_SLOT` relocations
//!   name, from `llvm-readobj -r`. Any other image finding is counted as not
//!   checked here.
//!
//! The targets: the planted fixtures (`tests/fixtures/contradictions/`),
//! `oracle/sysv.c` built by `gcc` and both mingw compilers, `/usr/lib/libz.so.1`
//! when present, and every path in `N0XIS_CONTRADICTION_IMAGES` (`:`
//! separated), which is how the corpus measurement in docs/VERIFICATION.md was
//! run with this same checker. A missing tool skips the test and says so.

#![cfg(feature = "oracle")]

use std::collections::{BTreeMap, BTreeSet};
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
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

fn hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim().trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
}

/// A tool's stdout, in the C locale (a translated listing parses as nothing).
fn tool(program: &str, args: &[&str], file: &Path) -> Option<String> {
    let out = Command::new(program).args(args).arg(file).env("LC_ALL", "C").output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Pe,
    Elf,
    Module,
}

fn kind_of(file: &Path) -> Option<Kind> {
    let head = std::fs::read(file).ok()?;
    Some(if head.starts_with(b"MZ") {
        Kind::Pe
    } else if head.starts_with(b"\0asm") {
        Kind::Module
    } else {
        Kind::Elf
    })
}

/// A table that states extents, as the answer names it (`why`'s sources, with
/// the two routes a PDB length takes folded into one: one table).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ExtentTable {
    EhFrame,
    Pdata,
    StSize,
    Body,
    Pdb,
}

fn extent_table(by: &Value) -> Option<ExtentTable> {
    Some(match (by["source"].as_str()?, by["table"].as_str(), by["of"].as_str()) {
        ("unwind", Some("eh_frame"), _) => ExtentTable::EhFrame,
        ("unwind", Some("pdata"), _) => ExtentTable::Pdata,
        ("symbol_size", _, Some("st_size")) => ExtentTable::StSize,
        ("body", ..) => ExtentTable::Body,
        ("pdb", ..) | ("symbol_size", _, Some("pdb")) => ExtentTable::Pdb,
        _ => return None,
    })
}

/// A defined symbol, as `readelf -sW` lists it.
struct Sym {
    name: String,
    func: bool,
}

/// What the independent readers say the image holds.
#[derive(Default)]
struct Tables {
    /// `(start, end)` → the tables stating exactly that extent.
    extents: BTreeMap<(u64, u64), BTreeSet<ExtentTable>>,
    /// `.symtab` and `.dynsym` symbols by address.
    symtab: BTreeMap<u64, Vec<Sym>>,
    dynsym: BTreeMap<u64, Vec<Sym>>,
    /// A module's bodies: offset → the name section's name, and the export
    /// names.
    name_section: BTreeMap<u64, String>,
    exports: BTreeMap<u64, BTreeSet<String>>,
    /// The image findings this checker can work out, as the start of the
    /// sentence the reader writes.
    findings: BTreeSet<String>,
}

impl Tables {
    fn extent(&mut self, start: u64, end: u64, table: ExtentTable) {
        if end > start {
            self.extents.entry((start, end)).or_default().insert(table);
        }
    }
}

fn read_symbols(file: &Path, t: &mut Tables) {
    let Some(text) = tool("readelf", &["-sW"], file) else { return };
    let mut into_dynamic = false;
    for line in text.lines() {
        if line.starts_with("Symbol table '.dynsym'") {
            into_dynamic = true;
            continue;
        }
        if line.starts_with("Symbol table '.symtab'") {
            into_dynamic = false;
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 || !f[0].ends_with(':') {
            continue;
        }
        let (Some(value), size) = (hex(f[1]), if let Some(h) = f[2].strip_prefix("0x") { hex(h) } else { f[2].parse().ok() }) else { continue };
        let Some(size) = size else { continue };
        if value == 0 || f[6] == "UND" || !(f[3] == "FUNC" || f[3] == "OBJECT") {
            continue;
        }
        let sym = Sym { name: f[7].to_string(), func: f[3] == "FUNC" };
        if sym.func {
            t.extent(value, value + size, ExtentTable::StSize);
        }
        if into_dynamic { &mut t.dynsym } else { &mut t.symtab }.entry(value).or_default().push(sym);
    }
}

fn read_relocations(file: &Path, t: &mut Tables) {
    let Some(text) = tool("llvm-readobj", &["-r"], file) else { return };
    let mut per_slot: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 3 && (f[1].ends_with("_JUMP_SLOT") || f[1].ends_with("_GLOB_DAT")) && let Some(slot) = hex(f[0]) {
            per_slot.entry(slot).or_default().insert(format!("{} {}", f[1], f[2]));
        }
    }
    for (slot, named) in per_slot.into_iter().filter(|(_, n)| n.len() > 1) {
        t.findings.insert(format!("{} GLOB_DAT or JUMP_SLOT relocations name the slot at {slot:#x}", named.len()));
    }
}

fn read_unwind(file: &Path, kind: Kind, t: &mut Tables) {
    let mut pdata = Vec::new();
    if kind == Kind::Pe
        && let Some(text) = tool("llvm-readobj", &["--unwind"], file)
    {
        let mut start = None;
        for line in text.lines().map(str::trim) {
            let paren = || line.rsplit_once('(').and_then(|(_, v)| hex(v.trim_end_matches(')')));
            if line.starts_with("StartAddress:") {
                start = paren();
            } else if line.starts_with("EndAddress:")
                && let (Some(s), Some(e)) = (start.take(), paren())
            {
                pdata.push((s, e));
            }
        }
    }
    if !pdata.is_empty() {
        for (s, e) in pdata {
            t.extent(s, e, ExtentTable::Pdata);
        }
        return;
    }
    // `FDE cie=00000000 pc=62dc14a0..62dc14ba`
    if let Some(text) = tool("objdump", &["--dwarf=frames"], file) {
        for line in text.lines().filter(|l| l.contains(" FDE ")) {
            if let Some(pc) = line.split_whitespace().find_map(|w| w.strip_prefix("pc="))
                && let Some((a, b)) = pc.split_once("..")
                && let (Some(a), Some(b)) = (hex(a), hex(b))
            {
                t.extent(a, b, ExtentTable::EhFrame);
            }
        }
    }
}

/// A PDB of the image's name beside it: each procedure's start and length.
fn read_pdb(file: &Path, t: &mut Tables) {
    let pdb = file.with_extension("pdb");
    if !pdb.exists() {
        return;
    }
    let base = tool("llvm-readobj", &["--file-headers"], file).and_then(|h| h.lines().find_map(|l| l.trim().strip_prefix("ImageBase:").and_then(hex))).unwrap_or(0);
    // `Number: 1` … `VirtualAddress: 0x1000`, per section.
    let mut sections: BTreeMap<u64, u64> = BTreeMap::new();
    if let Some(text) = tool("llvm-readobj", &["--sections"], file) {
        let mut number = None;
        for line in text.lines().map(str::trim) {
            if let Some(n) = line.strip_prefix("Number:") {
                number = n.trim().parse().ok();
            } else if let (Some(n), Some(va)) = (number, line.strip_prefix("VirtualAddress:").and_then(hex)) {
                sections.insert(n, va);
            }
        }
    }
    let Some(text) = tool("llvm-pdbutil", &["dump", "--symbols"], &pdb) else { return };
    let mut in_proc = false;
    for line in text.lines().map(str::trim) {
        if line.contains("S_GPROC32") || line.contains("S_LPROC32") {
            in_proc = true;
            continue;
        }
        // `parent = 0, end = 660, addr = 0001:1488, code size = 139`
        if in_proc && let Some((_, rest)) = line.split_once("addr = ") {
            in_proc = false;
            let Some((place, size)) = rest.split_once(", code size = ") else { continue };
            let Some((sec, off)) = place.split_once(':') else { continue };
            let (Ok(sec), Ok(off), Ok(size)) = (sec.parse::<u64>(), off.parse::<u64>(), size.trim().parse::<u64>()) else { continue };
            if let Some(va) = sections.get(&sec) {
                let start = base + va + off;
                t.extent(start, start + size, ExtentTable::Pdb);
            }
        }
    }
}

/// A module's bodies, names, exports and misplaced data segments
/// (`wasm-objdump -d` and `-x`). `false` when `wasm-objdump` cannot read the
/// module (one using a proposal it does not decode): nothing is known then.
fn read_module(file: &Path, t: &mut Tables) -> bool {
    let mut at: BTreeMap<u64, u64> = BTreeMap::new();
    if let Some(text) = tool("wasm-objdump", &["-d"], file) {
        for line in text.lines() {
            let Some((offset, rest)) = line.split_once(" func[") else { continue };
            let (Some(offset), Some((index, tail))) = (hex(offset), rest.split_once(']')) else { continue };
            if let (Ok(index), true) = (index.parse::<u64>(), tail.ends_with(':')) {
                at.insert(index, offset);
            }
        }
    }
    let Some(text) = tool("wasm-objdump", &["-x"], file) else { return false };
    let mut section = "";
    let mut custom_name = false;
    // Memory index → (initial bytes, imported max bytes).
    let mut memories: Vec<(u128, Option<u128>, bool)> = Vec::new();
    for line in text.lines() {
        if !line.starts_with(' ') {
            section = line.split('[').next().unwrap_or("").trim_end_matches(':');
            custom_name = false;
            continue;
        }
        let item = line.trim().trim_start_matches("- ");
        if section == "Custom" && item.starts_with("name: ") {
            custom_name = item == "name: \"name\"";
            continue;
        }
        if section == "Import" || section == "Memory" {
            // ` - memory[1] pages: initial=1 max=65536 i64`, ` - memory[0] pages: initial=1 <- env.memory`
            if let Some(rest) = item.strip_prefix("memory[") {
                let field = |k: &str| rest.split_whitespace().find_map(|w| w.strip_prefix(k)).and_then(|v| v.parse::<u128>().ok());
                memories.push((field("initial=").unwrap_or(0) * 65536, field("max=").map(|m| m * 65536), section == "Import"));
            }
            continue;
        }
        if section == "Data" {
            // ` - segment[0] memory=0 size=10 - init i32=65530`
            if let Some(rest) = item.strip_prefix("segment[") {
                let index = rest.split(']').next().unwrap_or("");
                let field = |k: &str| rest.split_whitespace().find_map(|w| w.strip_prefix(k)).and_then(|v| v.parse::<u128>().ok());
                let at_ = field("i32=").or_else(|| field("i64="));
                if let (Some(m), Some(size), Some(placed)) = (field("memory="), field("size="), at_)
                    && let Some(&(initial, max, imported)) = memories.get(m as usize)
                {
                    let bound = if imported { max } else { Some(initial) };
                    if bound.is_some_and(|b| placed + size > b) {
                        t.findings.insert(format!("data segment {index} is placed at {placed:#x} in memory {m}"));
                    }
                }
            }
            continue;
        }
        let Some(rest) = item.strip_prefix("func[") else { continue };
        let Some((index, tail)) = rest.split_once(']') else { continue };
        let Ok(index) = index.parse::<u64>() else { continue };
        let Some(&offset) = at.get(&index) else { continue };
        match section {
            "Code" => {
                if let Some(size) = tail.trim().strip_prefix("size=").and_then(|s| s.split_whitespace().next()).and_then(|s| s.parse::<u64>().ok()) {
                    t.extent(offset, offset + size, ExtentTable::Body);
                }
            }
            "Export" => {
                if let Some((_, n)) = tail.rsplit_once("-> ") {
                    let n = n.trim().trim_matches('"');
                    if !n.is_empty() {
                        t.exports.entry(offset).or_default().insert(n.to_string());
                    }
                }
            }
            "Custom" if custom_name => {
                if let Some(n) = tail.trim().strip_prefix('<').and_then(|n| n.strip_suffix('>'))
                    && !n.is_empty()
                {
                    t.name_section.insert(offset, n.to_string());
                }
            }
            _ => {}
        }
    }
    true
}

/// What the tools read, or `None` where one could not read the image.
fn read_tables(file: &Path, kind: Kind) -> Option<Tables> {
    let mut t = Tables::default();
    match kind {
        Kind::Module => {
            if !read_module(file, &mut t) {
                return None;
            }
        }
        Kind::Elf => {
            read_unwind(file, kind, &mut t);
            read_symbols(file, &mut t);
            read_relocations(file, &mut t);
        }
        Kind::Pe => {
            read_unwind(file, kind, &mut t);
            read_pdb(file, &mut t);
        }
    }
    Some(t)
}

/// An extent and the tables stating exactly it.
type Stated = (u64, u64, Vec<ExtentTable>);

/// The disagreements the tables hold, in the answer's terms.
#[derive(Default, PartialEq, Debug)]
struct Found {
    /// start → every `(end, table)` stated for it, where the ends differ.
    ends: BTreeMap<u64, BTreeSet<(u64, ExtentTable)>>,
    /// `((first start, end), (second start, end))`, each extent with its tables.
    overlaps: BTreeSet<(Stated, Stated)>,
    /// address → `(table, name)` for every name compared there.
    names: BTreeMap<u64, BTreeSet<(String, String)>>,
    /// The start of each image finding's sentence that this checker can
    /// work out.
    findings: BTreeSet<String>,
}

fn expected(t: &Tables, kind: Kind) -> Found {
    let mut f = Found::default();
    let mut per_start: BTreeMap<u64, BTreeSet<(u64, ExtentTable)>> = BTreeMap::new();
    for (&(s, e), tables) in &t.extents {
        for &table in tables {
            per_start.entry(s).or_default().insert((e, table));
        }
    }
    for (s, ends) in per_start {
        if ends.iter().map(|(e, _)| e).collect::<BTreeSet<_>>().len() > 1 {
            f.ends.insert(s, ends);
        }
    }
    let all: Vec<Stated> = t.extents.iter().map(|(&(s, e), tables)| (s, e, tables.iter().copied().collect())).collect();
    for a in &all {
        for b in &all {
            if a.0 < b.0 && b.0 < a.1 {
                f.overlaps.insert((a.clone(), b.clone()));
            }
        }
    }
    match kind {
        Kind::Elf => {
            let functions: BTreeSet<u64> = t.symtab.iter().chain(&t.dynsym).filter(|(_, s)| s.iter().any(|s| s.func)).map(|(a, _)| *a).collect();
            let unversioned = |s: &Sym| s.name.split('@').next().unwrap_or(&s.name).to_string();
            for va in functions {
                let (Some(st), Some(dy)) = (t.symtab.get(&va), t.dynsym.get(&va)) else { continue };
                let a: BTreeSet<String> = st.iter().map(unversioned).collect();
                let b: BTreeSet<String> = dy.iter().map(unversioned).collect();
                if a.is_disjoint(&b) {
                    let mut names: BTreeSet<(String, String)> = a.into_iter().map(|n| ("static".to_string(), n)).collect();
                    names.extend(b.into_iter().map(|n| ("dynamic".to_string(), n)));
                    f.names.insert(va, names);
                }
            }
        }
        Kind::Module => {
            for (va, name) in &t.name_section {
                if let Some(exports) = t.exports.get(va)
                    && !exports.contains(name)
                {
                    let mut names: BTreeSet<(String, String)> = exports.iter().map(|n| ("exports".to_string(), n.clone())).collect();
                    names.insert(("name_section".to_string(), name.clone()));
                    f.names.insert(*va, names);
                }
            }
        }
        Kind::Pe => {}
    }
    f.findings = t.findings.clone();
    f
}

/// What the answer says, in the same terms, and what it reported that this
/// checker cannot work out.
fn reported(answer: &Value) -> (Found, Vec<String>, Vec<String>) {
    let mut f = Found::default();
    let (mut malformed, mut not_checked) = (Vec::new(), Vec::new());
    let tables_of = |by: &Value| -> Option<Vec<ExtentTable>> {
        let mut out: Vec<ExtentTable> = by.as_array()?.iter().map(extent_table).collect::<Option<Vec<_>>>()?;
        out.sort();
        out.dedup();
        Some(out)
    };
    for c in answer["data"]["contradictions"].as_array().into_iter().flatten() {
        match c["kind"].as_str() {
            Some("end") => {
                let Some(start) = c["start"].as_str().and_then(hex) else { malformed.push(c.to_string()); continue };
                let slot = f.ends.entry(start).or_default();
                for e in c["ends"].as_array().into_iter().flatten() {
                    match (e["end"].as_str().and_then(hex), tables_of(&e["by"])) {
                        (Some(end), Some(tables)) => slot.extend(tables.into_iter().map(|t| (end, t))),
                        _ => malformed.push(c.to_string()),
                    }
                }
            }
            Some("overlap") => {
                let side = |x: &Value| Some((x["start"].as_str().and_then(hex)?, x["end"].as_str().and_then(hex)?, tables_of(&x["by"])?));
                match (side(&c["first"]), side(&c["second"])) {
                    (Some(a), Some(b)) => {
                        f.overlaps.insert((a, b));
                    }
                    _ => malformed.push(c.to_string()),
                }
            }
            Some("name") => {
                let Some(va) = c["addr"].as_str().and_then(hex) else { malformed.push(c.to_string()); continue };
                for n in c["names"].as_array().into_iter().flatten() {
                    match (n["source"].as_str(), n["table"].as_str(), n["name"].as_str()) {
                        (Some("image"), Some(table), Some(name)) => {
                            let name = if matches!(table, "static" | "dynamic") { name.split('@').next().unwrap_or(name) } else { name };
                            f.names.entry(va).or_default().insert((table.to_string(), name.to_string()));
                        }
                        _ => not_checked.push(format!("name from {n}")),
                    }
                }
            }
            Some("image") => {
                let what = c["what"].as_str().unwrap_or_default();
                // The start of the sentence, as far as this checker writes it.
                let head = what.split(" and ends at ").next().unwrap_or(what);
                let head = head.split(": ").next().unwrap_or(head);
                if head.starts_with("data segment ") || head.contains("GLOB_DAT or JUMP_SLOT") {
                    f.findings.insert(head.to_string());
                } else {
                    not_checked.push(format!("image: {what}"));
                }
            }
            _ => malformed.push(c.to_string()),
        }
    }
    (f, malformed, not_checked)
}

/// The answer's sources of extents must be the tables that are not empty.
fn stated_sources(answer: &Value) -> BTreeSet<ExtentTable> {
    answer["data"]["kinds"]["end"]["sources"].as_array().into_iter().flatten().filter_map(extent_table).collect()
}

struct Tally {
    counts: BTreeMap<&'static str, usize>,
    wrong: Vec<String>,
    not_checked: Vec<String>,
}

fn check_image(file: &Path, work: &Path) -> Tally {
    let mut tally = Tally { counts: BTreeMap::new(), wrong: Vec::new(), not_checked: Vec::new() };
    let dir = work.join(format!("run-{}", file.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()));
    let _ = std::fs::create_dir_all(dir.join(".n0x"));
    let out = support::isolated(Command::new(n0xis_exe())).args(["contradictions", "--limit", "0", "--quiet", "--file"]).arg(file).current_dir(&dir).output();
    let answer: Value = out.ok().and_then(|o| serde_json::from_slice(&o.stdout).ok()).unwrap_or(Value::Null);
    if answer["ok"] != true {
        tally.wrong.push(format!("no answer: {answer}"));
        return tally;
    }
    let Some(kind) = kind_of(file) else {
        tally.wrong.push("unreadable".into());
        return tally;
    };
    let Some(tables) = read_tables(file, kind) else {
        tally.not_checked.push("image: the independent reader could not read it".into());
        return tally;
    };
    let want = expected(&tables, kind);
    let (got, malformed, not_checked) = reported(&answer);
    tally.wrong.extend(malformed.into_iter().map(|m| format!("not in the answer's vocabulary: {m}")));
    tally.not_checked = not_checked;
    let sources: BTreeSet<ExtentTable> = tables.extents.values().flatten().copied().collect();
    if stated_sources(&answer) != sources {
        tally.wrong.push(format!("the answer read extents from {:?}, the tables hold {:?}", stated_sources(&answer), sources));
    }
    for (what, n) in [("end", got.ends.len()), ("overlap", got.overlaps.len()), ("name", got.names.len()), ("image", got.findings.len())] {
        tally.counts.insert(what, n);
    }
    // How much the tables held, so a sweep that compared nothing shows.
    let named = match kind {
        Kind::Elf => tables.symtab.keys().chain(tables.dynsym.keys()).collect::<BTreeSet<_>>().len(),
        Kind::Module => tables.name_section.keys().chain(tables.exports.keys()).collect::<BTreeSet<_>>().len(),
        Kind::Pe => 0,
    };
    tally.counts.insert("table extents", tables.extents.len());
    tally.counts.insert("named addresses", named);
    let diff = |what: &str, w: String, g: String, tally: &mut Tally| tally.wrong.push(format!("{what}: the tables say {w}, the answer {g}"));
    for (s, ends) in want.ends.iter() {
        if got.ends.get(s) != Some(ends) {
            diff("end", format!("{s:#x} {ends:x?}"), format!("{:x?}", got.ends.get(s)), &mut tally);
        }
    }
    for (s, ends) in got.ends.iter().filter(|(s, _)| !want.ends.contains_key(s)) {
        diff("end", format!("no disagreement at {s:#x}"), format!("{ends:x?}"), &mut tally);
    }
    for o in want.overlaps.symmetric_difference(&got.overlaps) {
        let side = if want.overlaps.contains(o) { "missing" } else { "not in the tables" };
        tally.wrong.push(format!("overlap {side}: {o:x?}"));
    }
    for va in want.names.keys().chain(got.names.keys()).collect::<BTreeSet<_>>() {
        if want.names.get(va) != got.names.get(va) {
            diff("name", format!("{va:#x} {:?}", want.names.get(va)), format!("{:?}", got.names.get(va)), &mut tally);
        }
    }
    for f in want.findings.symmetric_difference(&got.findings) {
        let side = if want.findings.contains(f) { "missing" } else { "not in the tables" };
        tally.wrong.push(format!("image finding {side}: {f}"));
    }
    if kind == Kind::Pe {
        tally.not_checked.push("names: a PE's names are its exports and its PDB's, and no PDB beside an image here names what an export does".into());
    }
    let _ = std::fs::remove_dir_all(&dir);
    tally
}

fn build_targets(dir: &Path) -> Vec<PathBuf> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../oracle/sysv.c");
    let mut out = Vec::new();
    for (cc, flags, name) in [
        ("gcc", &["-shared", "-O1", "-fPIC"][..], "sysv.so"),
        ("x86_64-w64-mingw32-gcc", &["-shared", "-O2"][..], "sysv64.dll"),
        ("i686-w64-mingw32-gcc", &["-shared", "-O2"][..], "sysv32.dll"),
    ] {
        let path = dir.join(name);
        match Command::new(cc).args(flags).arg("-o").arg(&path).arg(&src).output() {
            Ok(o) if o.status.success() => out.push(path),
            _ => eprintln!("contradictions tables: skipping {name} — {cc} could not build it"),
        }
    }
    out
}

/// `n0xis-pdb`'s image with its PDB beside it, as built, and with `main`'s
/// `.pdata` end moved 4 bytes in (as `contradictions_on_planted_images.rs`
/// plants it): the PDB's lengths read through `llvm-pdbutil`.
fn pdb_targets(dir: &Path) -> Vec<PathBuf> {
    let from = Path::new(env!("CARGO_MANIFEST_DIR")).join("../n0xis-pdb/tests/fixtures");
    let mut out = Vec::new();
    for (name, plant) in [("as-built", false), ("planted", true)] {
        let d = dir.join(name);
        let _ = std::fs::create_dir_all(&d);
        let (image, pdb) = (d.join("pdbtarget.exe"), d.join("pdbtarget.pdb"));
        if std::fs::copy(from.join("pdbtarget.pdb"), &pdb).is_err() {
            continue;
        }
        let Ok(mut bytes) = std::fs::read(from.join("pdbtarget.exe")) else { continue };
        if plant {
            let entry: Vec<u8> = [0x15d0u32, 0x165b].iter().flat_map(|v| v.to_le_bytes()).collect();
            let at: Vec<usize> = bytes.windows(8).enumerate().filter(|(_, w)| *w == entry.as_slice()).map(|(i, _)| i).collect();
            assert_eq!(at.len(), 1, "main's RUNTIME_FUNCTION is in the image once");
            bytes[at[0] + 4..at[0] + 8].copy_from_slice(&0x1657u32.to_le_bytes());
        }
        if std::fs::write(&image, bytes).is_ok() {
            out.push(image);
        }
    }
    out
}

#[test]
fn every_contradiction_is_in_the_tables_and_every_one_there_is_reported() {
    if !n0xis_exe().exists() {
        eprintln!("contradictions tables: skipping — {} is not built", n0xis_exe().display());
        return;
    }
    for t in ["objdump", "readelf", "llvm-readobj", "llvm-pdbutil", "wasm-objdump"] {
        if Command::new(t).arg("--version").output().is_err() {
            eprintln!("contradictions tables: skipping — {t} is not installed");
            return;
        }
    }
    let work = std::env::temp_dir().join(format!("n0xis_contradictions_tables_{}", std::process::id()));
    std::fs::create_dir_all(&work).expect("temp dir");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/contradictions");
    let mut images = vec![
        fixtures.join("planted.so"),
        fixtures.join("same_table.so"),
        fixtures.join("planted.wasm"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../n0xis-sources/tests/fixtures/contested_slot/contested-x86_64.so"),
    ];
    images.extend(build_targets(&work));
    images.extend(pdb_targets(&work));
    let libz = Path::new("/usr/lib/libz.so.1");
    if libz.exists() {
        images.push(libz.to_path_buf());
    }
    if let Ok(extra) = std::env::var("N0XIS_CONTRADICTION_IMAGES") {
        images.extend(extra.split(':').filter(|p| !p.is_empty()).map(PathBuf::from));
    }
    let mut total: BTreeMap<&str, usize> = BTreeMap::new();
    let mut not_checked: BTreeMap<String, usize> = BTreeMap::new();
    let mut wrong = Vec::new();
    for image in &images {
        let tally = check_image(image, &work);
        eprintln!("contradictions tables: {}: {:?}, {} wrong", image.display(), tally.counts, tally.wrong.len());
        for (k, v) in tally.counts {
            *total.entry(k).or_default() += v;
        }
        for n in tally.not_checked {
            *not_checked.entry(n.split(':').next().unwrap_or_default().to_string()).or_default() += 1;
        }
        wrong.extend(tally.wrong.into_iter().map(|w| format!("{}: {w}", image.display())));
    }
    eprintln!("contradictions tables: {} images; reported and checked {total:?}; not checked here {not_checked:?}; {} wrong", images.len(), wrong.len());
    // The planted images hold one of each kind this checker reads: a sweep
    // that saw none was not looking.
    assert!(total.values().all(|&n| n > 0), "a kind was never seen, so its check never ran: {total:?}");
    assert!(total.get("image").is_some_and(|&n| n >= 2), "the planted module's and the contested slot's findings: {total:?}");
    let _ = std::fs::remove_dir_all(&work);
    assert!(wrong.is_empty(), "contradictions the tables do not bear out, or bear out and the answer left out:\n  {}", wrong.join("\n  "));
}

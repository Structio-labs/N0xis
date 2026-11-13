// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`xref` through a jump table.**
//!
//! A case block is reached by an indexed jump whose target is in a table, so no
//! instruction names it. `xref to` showed the one `ja` that goes to a default block
//! where 41 table entries land, and `xref from` at the jump showed nothing at all.
//!
//! `oracle/xref/switches.c` writes each table's size and holes. `objdump -d` says
//! where the jump and the guard's branch are, and `objdump -h` where the file holds
//! each entry, which is read here and not taken from the answer.

// It builds its target with a compiler at run time, so its answer depends on that
// compiler's version: a local instrument, not a CI gate.
#![cfg(feature = "oracle")]
#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
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

fn run(tool: &str, args: &[&str], file: &Path) -> String {
    let out = Command::new(tool).env("LC_ALL", "C").args(args).arg(file).output().unwrap_or_else(|e| panic!("{tool}: {e}"));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

struct Built {
    file: PathBuf,
    objdump: &'static str,
}

fn build(tag: &str, compiler: &str, objdump: &'static str, flags: &[&str]) -> Option<Built> {
    let dir = std::env::temp_dir().join(format!("n0xis_xref_tables_{}_{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let file = dir.join(if compiler.contains("mingw") { "sw.exe" } else { "sw" });
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../oracle/xref/switches.c");
    // Built only with the `oracle` feature, which is asking for this compiler: one
    // that is missing is a failure, not a pass with nothing checked.
    match Command::new(compiler).args(["-O2"]).args(flags).arg("-o").arg(&file).arg(source).output() {
        Ok(o) if o.status.success() => Some(Built { file, objdump }),
        Ok(o) => panic!("{tag}: {compiler} could not build: {}", String::from_utf8_lossy(&o.stderr)),
        Err(e) => panic!("{tag}: {compiler} is not here: {e}"),
    }
}

impl Built {
    /// `(address, text)` of each instruction `function` has, from `objdump -d`.
    fn instructions(&self, function: &str) -> Vec<(u64, String)> {
        let wanted = format!("--disassemble={function}");
        run(self.objdump, &["-d", "-M", "intel", "--no-show-raw-insn", &wanted], &self.file)
            .lines()
            .filter_map(|l| {
                let (head, text) = l.split_once(":\t")?;
                Some((u64::from_str_radix(head.trim(), 16).ok()?, text.trim().to_string()))
            })
            .collect()
    }

    /// The function's one indirect jump. objdump prints `jmp rax`, `notrack jmp rax`
    /// and `jmp QWORD PTR [...]`.
    fn indirect_jump(&self, function: &str) -> u64 {
        let all = self.instructions(function);
        let jumps: Vec<u64> = all
            .iter()
            .filter(|(_, t)| {
                let t = t.strip_prefix("notrack ").unwrap_or(t);
                t.starts_with("jmp") && !t.contains('<') && !t.split_whitespace().nth(1).is_some_and(|o| o.starts_with("0x"))
            })
            .map(|(a, _)| *a)
            .collect();
        assert!(!jumps.is_empty(), "objdump shows no indirect jump in {function}: {all:?}");
        jumps[0]
    }

    /// Each indirect jump of `function`, with the bound its bytes put on the index: the
    /// `cmp` against a constant that a `ja` or `jae` follows, in the straight run of
    /// instructions before the jump (no jump or return between). `ja` lets the
    /// constant through, `jae` one less. Without one there is no guard. Read from the
    /// bytes and not the source: gcc 14 guards a `switch` whose default is
    /// `__builtin_unreachable()`, which gcc 16 and clang do not.
    fn guards(&self, function: &str) -> Vec<(u64, Option<u64>)> {
        let all = self.instructions(function);
        let text = |i: usize| all[i].1.strip_prefix("notrack ").unwrap_or(&all[i].1).to_string();
        let mut out = Vec::new();
        for (i, (at, _)) in all.iter().enumerate() {
            let t = text(i);
            if !(t.starts_with("jmp") && !t.contains('<') && !t.split_whitespace().nth(1).is_some_and(|o| o.starts_with("0x"))) {
                continue;
            }
            let mut bound = None;
            for j in (0..i).rev() {
                let u = text(j);
                if u.starts_with("jmp") || u.starts_with("ret") {
                    break;
                }
                let (ja, jae) = (u.starts_with("ja "), u.starts_with("jae "));
                if (ja || jae) && j > 0 {
                    let cmp = text(j - 1);
                    let imm = cmp.strip_prefix("cmp").and_then(|c| c.rsplit(',').next()).and_then(|v| u64::from_str_radix(v.trim().strip_prefix("0x")?, 16).ok());
                    if let Some(imm) = imm {
                        bound = if ja { Some(imm) } else { imm.checked_sub(1) };
                        break;
                    }
                }
            }
            out.push((*at, bound));
        }
        assert!(!out.is_empty(), "objdump shows no indirect jump in {function}: {all:?}");
        out
    }

    /// Where the function's first `ja` goes: its table's default.
    fn guarded_default(&self, function: &str) -> u64 {
        let all = self.instructions(function);
        let ja = all.iter().find(|(_, t)| t.starts_with("ja")).unwrap_or_else(|| panic!("no ja in {function}: {all:?}"));
        u64::from_str_radix(ja.1.split_whitespace().nth(1).expect("a target"), 16).expect("hex")
    }

    /// The `bytes` bytes the file holds at `va`, by `objdump -h`.
    fn read(&self, va: u64, bytes: usize) -> Vec<u8> {
        let text = run(self.objdump, &["-h"], &self.file);
        for line in text.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() == 7
                && let (Ok(size), Ok(vma), Ok(off)) = (u64::from_str_radix(f[2], 16), u64::from_str_radix(f[3], 16), u64::from_str_radix(f[5], 16))
                && va >= vma
                && va - vma < size
            {
                let file = std::fs::read(&self.file).expect("read");
                let at = (off + va - vma) as usize;
                return file[at..at + bytes].to_vec();
            }
        }
        panic!("objdump -h has no section at {va:#x}");
    }

    fn xref(&self, dir: &str, addr: u64) -> Value {
        let mut cmd = support::isolated(Command::new(n0xis_exe()));
        let out = cmd.arg("xref").arg(dir).arg("--file").arg(&self.file).arg("--addr").arg(format!("{addr:#x}")).output().expect("n0xis");
        let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("no envelope ({e}): {}", String::from_utf8_lossy(&out.stdout)));
        assert_eq!(v["ok"], true, "{v}");
        v["data"].clone()
    }

    /// `nm`-style address of a symbol, from the header of `objdump -d`'s function.
    fn symbol(&self, function: &str) -> u64 {
        self.instructions(function).first().map(|(a, _)| *a).unwrap_or_else(|| panic!("no {function}"))
    }
}

fn hex(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().expect("an address").trim_start_matches("0x"), 16).expect("hex")
}

fn table_rows(answer: &Value) -> Vec<&Value> {
    answer["refs"].as_array().expect("refs").iter().filter(|r| r["kind"] == "jump_table").collect()
}

/// Every row's target, against the word the file holds at its slot.
fn each_entry_is_what_the_file_holds(tag: &str, b: &Built, rows: &[&Value]) {
    for row in rows {
        let (slot, to) = (hex(&row["slot"]), hex(&row["to"]));
        let held = match row.get("relative_to") {
            Some(base) => {
                let word = i32::from_le_bytes(b.read(slot, 4).try_into().expect("4 bytes"));
                hex(base).wrapping_add(i64::from(word) as u64)
            }
            None => u64::from_le_bytes(b.read(slot, 8).try_into().expect("8 bytes")),
        };
        assert_eq!(held, to, "{tag}: the word at {slot:#x}");
    }
}

fn a_table_of_forty_one(tag: &str, b: &Built) {
    let jump = b.indirect_jump("big_switch");
    let default = b.guarded_default("big_switch");

    let from = b.xref("from", jump);
    let rows = table_rows(&from);
    assert_eq!(rows.len(), 41, "{tag}: the source writes 41 entries: {from}");
    assert_eq!(from["jump_table"]["state"], "resolved", "{tag}: {from}");
    assert_eq!(from["jump_table"]["guarded"], true, "{tag}: {from}");
    assert_eq!(from["jump_table"]["entries"], 41, "{tag}: {from}");
    assert_eq!(from["count"], 41, "{tag}: {from}");
    let slots: BTreeSet<u64> = rows.iter().map(|r| hex(&r["slot"])).collect();
    assert_eq!(slots.len(), 41, "{tag}: each entry has its own word");
    assert!(rows.iter().all(|r| r["evidence"] == "jump_table_guarded" && !r["section"].as_str().unwrap_or("").is_empty()), "{tag}: {from}");
    each_entry_is_what_the_file_holds(tag, b, &rows);
    let distinct: BTreeSet<u64> = rows.iter().map(|r| hex(&r["to"])).collect();
    assert_eq!(distinct.len(), 29, "{tag}: 28 cases and the default: {distinct:?}");

    // 13 holes land on the default, and the `ja` goes there too.
    let to = b.xref("to", default);
    let rows = table_rows(&to);
    assert_eq!(rows.len(), 13, "{tag}: 13 holes in the source: {to}");
    assert!(rows.iter().all(|r| hex(&r["from"]) == jump), "{tag}: each from the indexed jump: {to}");
    assert_eq!(to["refs"].as_array().expect("refs").iter().filter(|r| r["kind"] == "cond_jmp").count(), 1, "{tag}: and the guard's branch: {to}");
    each_entry_is_what_the_file_holds(tag, b, &rows);
    // A word of a table the jump reads is the jump's reference, and is not listed
    // again as a word of data or as a table relative to a base.
    let others: Vec<&Value> = to["refs"].as_array().expect("refs").iter().filter(|r| r["kind"] == "data_word" || r["kind"] == "relative_entry").collect();
    assert!(others.is_empty(), "{tag}: {others:?}");
    let resolved = to["searched"]["jump_tables"]["resolved"].as_u64().expect("a count");
    assert!(resolved >= 2, "{tag}: big_switch and interpret: {to}");

    // A case block is reached by its one entry.
    let case_block = hex(&from_row_at_index(&from, 0));
    let to_case = b.xref("to", case_block);
    assert_eq!(table_rows(&to_case).len(), 1, "{tag}: {to_case}");
}

/// The target of the entry for case `i`, by the order of its slot.
fn from_row_at_index(from: &Value, i: usize) -> Value {
    let rows = table_rows(from);
    let mut by_slot: Vec<&&Value> = rows.iter().collect();
    by_slot.sort_by_key(|r| hex(&r["slot"]));
    by_slot[i]["to"].clone()
}

/// A loop keeps the table's base in a register set before it, and compares memory
/// for the guard, with a step limit in a register above it.
fn a_table_guarded_by_memory(tag: &str, b: &Built) {
    let jump = b.indirect_jump("interpret");
    let from = b.xref("from", jump);
    let rows = table_rows(&from);
    assert_eq!(rows.len(), 13, "{tag}: the source writes 13 cases, 0 to 12: {from}");
    assert_eq!(from["jump_table"]["guarded"], true, "{tag}: {from}");
    each_entry_is_what_the_file_holds(tag, b, &rows);
}

/// With no guard, a table ends where the next one's base is, which the code takes.
fn two_tables_side_by_side(tag: &str, b: &Built) {
    let guards = b.guards("two_tables");
    let all = b.instructions("two_tables");
    let jumps: Vec<u64> = all
        .iter()
        .filter(|(_, t)| {
            let t = t.strip_prefix("notrack ").unwrap_or(t);
            t.starts_with("jmp") && !t.contains('<')
        })
        .map(|(a, _)| *a)
        .collect();
    // A compiler may copy the second dispatch into each case of the first, so it is
    // tables that are counted and not jumps.
    assert!(jumps.len() >= 2, "{tag}: the source has two switches: {all:?}");
    let mut sizes = std::collections::BTreeMap::new();
    for jump in jumps {
        let from = b.xref("from", jump);
        assert_eq!(from["jump_table"]["state"], "resolved", "{tag}: {from}");
        let guarded = guards.iter().find(|(at, _)| *at == jump).is_some_and(|(_, g)| g.is_some());
        assert_eq!(from["jump_table"]["guarded"], guarded, "{tag}: as the bytes guard it: {from}");
        let rows = table_rows(&from);
        let evidence = if guarded { "jump_table_guarded" } else { "jump_table_walked" };
        assert!(rows.iter().all(|r| r["evidence"] == evidence), "{tag}: {from}");
        each_entry_is_what_the_file_holds(tag, b, &rows);
        sizes.insert(hex(&from["jump_table"]["table"]), rows.len());
    }
    let mut sizes: Vec<usize> = sizes.into_values().collect();
    sizes.sort_unstable();
    assert_eq!(sizes, vec![8, 10], "{tag}: the source writes 10 entries and 8");
}

/// One bound for a table, the guard's, in every answer: `ir build`'s graph and
/// its cases, `ir explain`, and the `case` labels `decomp pseudo` prints. A step limit
/// of 99999 stands above the guard in `interpret`, compared in a register, and the
/// guard itself compares memory: the graph took the step limit, and read on past the
/// table by it. Where the bytes guard nothing, no bound is said.
fn one_bound_for_every_consumer(tag: &str, b: &Built) {
    let ask = |what: &[&str], function: &str| -> Value {
        let mut cmd = support::isolated(Command::new(n0xis_exe()));
        let out = cmd.args(what).arg("--file").arg(&b.file).args(["--addr", &format!("{:#x}", b.symbol(function))]).output().expect("n0xis");
        let v: Value = serde_json::from_slice(&out.stdout).expect("an envelope");
        assert_eq!(v["ok"], true, "{tag}: {v}");
        v["data"].clone()
    };
    for function in ["interpret", "big_switch", "two_tables"] {
        let guards = b.guards(function);
        let graph = ask(&["ir", "build"], function);
        let switches = graph["switches"].as_array().cloned().unwrap_or_default();
        let explain: Vec<String> = ask(&["ir", "explain"], function)["lines"].as_array().expect("lines").iter().filter_map(|l| l.as_str().map(str::to_string)).collect();
        let mut seen = 0;
        for (jump, guard) in &guards {
            let Some(sw) = switches.iter().find(|s| hex(&s["at"]) == *jump) else { continue };
            seen += 1;
            assert_eq!(sw["bound"].as_u64(), *guard, "{tag} {function}: the graph's bound is the guard's: {sw}");
            let line = explain.iter().find(|l| l.trim_start().starts_with(&format!("{jump:#x} "))).unwrap_or_else(|| panic!("{tag} {function}: {explain:?}"));
            let said = guard.map_or("bound=? ".to_string(), |g| format!("bound={g} "));
            assert!(line.contains(&said), "{tag} {function}: {said}in {line}");
            if let Some(g) = guard {
                let cases = sw["cases"].as_array().expect("cases").len() as u64;
                assert_eq!(cases, g + 1, "{tag} {function}: as many case edges as the guard lets through: {sw}");
                assert!(line.contains(&format!("-> {} cases", g + 1)), "{tag} {function}: {line}");
            }
        }
        assert!(seen > 0, "{tag} {function}: the graph has a switch at a jump the bytes show: {guards:?} {switches:?}");
        // The body's `case` labels: none past what a guard lets through, where all are guarded.
        if guards.iter().all(|(_, g)| g.is_some()) {
            let most = guards.iter().filter_map(|(_, g)| *g).max().expect("guarded");
            let body = ask(&["decomp", "pseudo"], function)["pseudo"].as_array().expect("pseudo").iter().filter_map(|l| l.as_str().map(str::to_string)).collect::<Vec<_>>();
            let labels: Vec<u64> = body.iter().filter_map(|l| u64::from_str_radix(l.trim().strip_prefix("case 0x")?.strip_suffix(':')?, 16).ok()).collect();
            assert!(!labels.is_empty() && labels.iter().all(|&k| k <= most), "{tag} {function}: case labels past the guard's {most}: {labels:?}");
        }
    }
}

/// A jump with no table says it does not know.
fn a_jump_with_no_table(tag: &str, b: &Built) {
    let jump = b.indirect_jump("through_a_label");
    let from = b.xref("from", jump);
    assert_eq!(from["jump_table"]["state"], "not_resolved", "{tag}: {from}");
    assert!(!from["jump_table"]["why"].as_str().unwrap_or("").is_empty(), "{tag}: {from}");
    assert!(table_rows(&from).is_empty(), "{tag}: {from}");
    let to = b.xref("to", b.symbol("through_a_label"));
    let j = &to["searched"]["jump_tables"];
    let no_table = j["no_table"].as_u64().expect("a count");
    let not_resolved = j["not_resolved"].as_u64().expect("a count");
    assert!(no_table + not_resolved >= 1, "{tag}: its jump is counted among those not read: {j}");
}

#[test]
fn gcc_position_independent() {
    let Some(b) = build("gcc_pie", "gcc", "objdump", &["-fPIE", "-pie"]) else { return };
    a_table_of_forty_one("gcc_pie", &b);
    a_table_guarded_by_memory("gcc_pie", &b);
    two_tables_side_by_side("gcc_pie", &b);
    a_jump_with_no_table("gcc_pie", &b);
    one_bound_for_every_consumer("gcc_pie", &b);
}

/// gcc 14 guards the second table of `two_tables`, whose default is unreachable,
/// where gcc 16 and clang do not: the bytes say which, not the source.
#[test]
fn gcc14_position_independent() {
    let Some(b) = build("gcc14_pie", "gcc-14", "objdump", &["-fPIE", "-pie"]) else { return };
    a_table_of_forty_one("gcc14_pie", &b);
    a_table_guarded_by_memory("gcc14_pie", &b);
    two_tables_side_by_side("gcc14_pie", &b);
    a_jump_with_no_table("gcc14_pie", &b);
    one_bound_for_every_consumer("gcc14_pie", &b);
}

#[test]
fn gcc_fixed_with_absolute_entries() {
    let Some(b) = build("gcc_fixed", "gcc", "objdump", &["-fno-pie", "-no-pie"]) else { return };
    a_table_of_forty_one("gcc_fixed", &b);
    a_table_guarded_by_memory("gcc_fixed", &b);
    a_jump_with_no_table("gcc_fixed", &b);
    one_bound_for_every_consumer("gcc_fixed", &b);
}

#[test]
fn clang_position_independent() {
    let Some(b) = build("clang_pie", "clang", "objdump", &["-fPIE", "-pie"]) else { return };
    a_table_of_forty_one("clang_pie", &b);
    a_table_guarded_by_memory("clang_pie", &b);
    two_tables_side_by_side("clang_pie", &b);
    a_jump_with_no_table("clang_pie", &b);
    one_bound_for_every_consumer("clang_pie", &b);
}

#[test]
fn clang_fixed_with_absolute_entries() {
    let Some(b) = build("clang_fixed", "clang", "objdump", &["-fno-pie", "-no-pie"]) else { return };
    a_table_of_forty_one("clang_fixed", &b);
    a_table_guarded_by_memory("clang_fixed", &b);
    a_jump_with_no_table("clang_fixed", &b);
    one_bound_for_every_consumer("clang_fixed", &b);
}

#[test]
fn mingw_pe() {
    let Some(b) = build("mingw", "x86_64-w64-mingw32-gcc", "x86_64-w64-mingw32-objdump", &["-static"]) else { return };
    a_table_of_forty_one("mingw", &b);
    a_table_guarded_by_memory("mingw", &b);
    a_jump_with_no_table("mingw", &b);
    one_bound_for_every_consumer("mingw", &b);
}

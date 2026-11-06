// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`found_unreferenced` is true when it is said.**
//!
//! `xref string` matched a reference only on the text's first byte, of an instruction's
//! RIP-relative operand. So a format reached through a longer string, a suffix a linker
//! merged into another, a string held by a word of data, and on a fixed image every
//! string (`mov edi, 0x402010` has no such operand) were all `count: 0,
//! found_unreferenced`.
//!
//! What is expected is read here from the built file: `objdump -d` lists what `main`
//! names, the file's own bytes say what string each lands in, and `nm` where the table
//! is. Both directions are held: every reference of `main` that reaches the text is in
//! the answer, and the answer has none from `main` that is not one.

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

struct Built {
    file: PathBuf,
    objdump: &'static str,
    nm: &'static str,
}

fn run(tool: &str, args: &[&str], file: &Path) -> String {
    let out = Command::new(tool).env("LC_ALL", "C").args(args).arg(file).output().unwrap_or_else(|e| panic!("{tool}: {e}"));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn build(tag: &str, compiler: &str, objdump: &'static str, nm: &'static str, flags: &[&str]) -> Option<Built> {
    let dir = std::env::temp_dir().join(format!("n0xis_xref_strings_{}_{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let file = dir.join(if compiler.contains("mingw") { "s.exe" } else { "s" });
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../oracle/xref/strings.c");
    match Command::new(compiler).arg("-O2").args(flags).arg("-o").arg(&file).arg(source).output() {
        Ok(o) if o.status.success() => Some(Built { file, objdump, nm }),
        Ok(o) => {
            eprintln!("{tag}: skipped: {}", String::from_utf8_lossy(&o.stderr).lines().next().unwrap_or(""));
            None
        }
        Err(e) => {
            eprintln!("{tag}: skipped: {e}");
            None
        }
    }
}

impl Built {
    /// `(va, file offset, size)` of each section the file holds, by `objdump -h`.
    fn sections(&self) -> Vec<(u64, u64, u64)> {
        run(self.objdump, &["-h"], &self.file)
            .lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                if f.len() != 7 {
                    return None;
                }
                Some((u64::from_str_radix(f[3], 16).ok()?, u64::from_str_radix(f[5], 16).ok()?, u64::from_str_radix(f[2], 16).ok()?))
            })
            .collect()
    }

    /// Every address an instruction of `main` names, by `objdump -d`: `(instruction,
    /// address)`. The comment on a RIP-relative operand, and a bare hex immediate.
    fn named_by_main(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        for line in run(self.objdump, &["-d", "-M", "intel", "--no-show-raw-insn", "--disassemble=main"], &self.file).lines() {
            let Some((head, text)) = line.split_once(":\t") else { continue };
            let Ok(at) = u64::from_str_radix(head.trim(), 16) else { continue };
            if let Some(comment) = text.split("# ").nth(1) {
                if let Ok(v) = u64::from_str_radix(comment.split_whitespace().next().unwrap_or(""), 16) {
                    out.push((at, v));
                }
            } else if let Some(imm) = text.rsplit(',').next().and_then(|o| o.trim().strip_prefix("0x"))
                && let Ok(v) = u64::from_str_radix(imm, 16)
            {
                out.push((at, v));
            }
        }
        out
    }

    /// The C string the file holds at `va`, from its first byte; `None` outside the file.
    fn string_at(&self, bytes: &[u8], va: u64) -> Option<Vec<u8>> {
        let (start, off, _) = *self.sections().iter().find(|&&(s, _, n)| va >= s && va - s < n)?;
        let at = (off + va - start) as usize;
        let rest = bytes.get(at..)?;
        Some(rest[..rest.iter().position(|&b| b == 0)?].to_vec())
    }

    /// The bytes before `va` back to the NUL, from the same section.
    fn before_in_string(&self, bytes: &[u8], va: u64) -> Vec<u8> {
        let Some(&(start, off, _)) = self.sections().iter().find(|&&(s, _, n)| va >= s && va - s < n) else { return Vec::new() };
        let at = (off + va - start) as usize;
        let from = bytes[off as usize..at].iter().rposition(|&b| b == 0).map_or(off as usize, |p| off as usize + p + 1);
        bytes[from..at].to_vec()
    }

    fn query(&self, q: &str) -> Value {
        let mut cmd = support::isolated(Command::new(n0xis_exe()));
        let out = cmd.args(["xref", "string", "--file"]).arg(&self.file).args(["--query", q]).output().expect("n0xis");
        let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("no envelope ({e})"));
        assert_eq!(v["ok"], true, "{v}");
        v["data"].clone()
    }

    fn symbol(&self, name: &str) -> u64 {
        run(self.nm, &[], &self.file)
            .lines()
            .find_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                (f.len() == 3 && f[2] == name).then(|| u64::from_str_radix(f[0], 16).expect("hex"))
            })
            .unwrap_or_else(|| panic!("nm has no {name}"))
    }
}

fn hex(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().expect("an address").trim_start_matches("0x"), 16).expect("hex")
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// `(instruction, address)` of each reference from `main` that reaches `q`, read from
/// the file: the string from the address on holds `q`, or the address is inside `q`,
/// which is what the bytes before it and after it then say.
fn truth(b: &Built, q: &str) -> BTreeSet<(u64, u64)> {
    let bytes = std::fs::read(&b.file).expect("read");
    let q = q.as_bytes();
    let mut out = BTreeSet::new();
    for (at, va) in b.named_by_main() {
        let Some(from_here) = b.string_at(&bytes, va) else { continue };
        let before = b.before_in_string(&bytes, va);
        let whole: Vec<u8> = before.iter().chain(&from_here).copied().collect();
        let inside = (0..q.len()).any(|k| k <= before.len() && whole[before.len() - k..].starts_with(q));
        if contains(&from_here, q) || inside {
            out.insert((at, va));
        }
    }
    out
}

fn rows_from_main(b: &Built, answer: &Value) -> BTreeSet<(u64, u64)> {
    let in_main: BTreeSet<u64> = b.named_by_main().into_iter().map(|(a, _)| a).collect();
    answer["hits"]
        .as_array()
        .expect("hits")
        .iter()
        .flat_map(|h| h["xrefs"].as_array().expect("xrefs").iter())
        .filter(|x| x["kind"] != "data_word")
        .map(|x| (hex(&x["from"]), hex(&x["to"])))
        .filter(|(from, _)| in_main.contains(from))
        .collect()
}

fn all_rows(answer: &Value) -> Vec<&Value> {
    answer["hits"].as_array().expect("hits").iter().flat_map(|h| h["xrefs"].as_array().expect("xrefs").iter()).collect()
}

/// The offset of each row from `main`: a runtime linked in has its own strings, which
/// may hold the same text.
fn offsets_from_main(b: &Built, answer: &Value) -> Vec<i64> {
    let in_main: BTreeSet<u64> = b.named_by_main().into_iter().map(|(a, _)| a).collect();
    all_rows(answer).iter().filter(|x| in_main.contains(&hex(&x["from"]))).filter_map(|x| x["string_offset"].as_i64()).collect()
}

fn the_answers(tag: &str, b: &Built, data_evidence: &str) {
    // Reached through a tail: the first byte's reference, and the longer string's.
    for q in ["merged end", "the value", "the suffix", "prefix the suffix"] {
        let want = truth(b, q);
        assert!(!want.is_empty(), "{tag}: the source references {q:?}, and the reference found none: the fixture is broken");
        let answer = b.query(q);
        assert_eq!(rows_from_main(b, &answer), want, "{tag}: {q:?}: {answer}");
        assert_eq!(answer["found_unreferenced"], 0, "{tag}: {q:?} is referenced: {answer}");
    }
    let answer = b.query("merged end");
    assert_eq!(all_rows(&answer).len(), 2, "{tag}: two references in the source: {answer}");
    assert!(all_rows(&answer).iter().any(|x| x["string_offset"].as_i64().is_some_and(|o| o < 0)), "{tag}: the longer string starts before the text: {answer}");

    // The middle of a format, starting 7 bytes before.
    let answer = b.query("the value");
    assert_eq!(offsets_from_main(b, &answer), vec![-7], "{tag}: {answer}");

    // Reached from inside the text: `s + 7` of "prefix the suffix".
    let answer = b.query("prefix the suffix");
    assert_eq!(offsets_from_main(b, &answer), vec![7], "{tag}: {answer}");

    // Held by a word of data, and by no instruction.
    let answer = b.query("pointed at");
    assert_eq!(answer["found_unreferenced"], 0, "{tag}: {answer}");
    let table = b.symbol("pointer_table");
    let row = all_rows(&answer).into_iter().find(|x| x["kind"] == "data_word").unwrap_or_else(|| panic!("{tag}: {answer}"));
    assert_eq!(hex(&row["slot"]), table, "{tag}: {row}");
    assert_eq!(row["evidence"], data_evidence, "{tag}: {row}");

    // The zero that stays: in the image, and reached by nothing.
    let answer = b.query("nobody reads");
    assert_eq!(answer["count"], 0, "{tag}: {answer}");
    assert_eq!(answer["found_unreferenced"], 1, "{tag}: {answer}");
    assert_eq!(answer["searched"]["data"]["state"], "searched", "{tag}: {answer}");
    assert!(!answer["searched"]["code"].as_array().expect("code").is_empty(), "{tag}: {answer}");

    // Absent is another answer.
    let answer = b.query("this text is in no image");
    assert_eq!(answer["found_unreferenced"], 0, "{tag}: {answer}");
    assert_eq!(answer["count"], 0, "{tag}: {answer}");
}

#[test]
fn gcc_position_independent_with_merged_tails() {
    let flags = ["-fmerge-constants", "-Wl,-O2", "-fPIE", "-pie", "-Wl,-z,nopack-relative-relocs"];
    let Some(b) = build("gcc_pie", "gcc", "objdump", "nm", &flags) else { return };
    the_answers("gcc_pie", &b, "relative_relocation");
}

#[test]
fn gcc_fixed_whose_strings_are_immediates() {
    let flags = ["-fmerge-constants", "-Wl,-O2", "-fno-pie", "-no-pie"];
    let Some(b) = build("gcc_fixed", "gcc", "objdump", "nm", &flags) else { return };
    the_answers("gcc_fixed", &b, "matching_value");
    let answer = b.query("the value");
    assert_eq!(all_rows(&answer).first().map(|x| x["kind"].clone()), Some(Value::from("immediate")), "{answer}");
}

#[test]
fn clang_position_independent_with_a_tail_lld_merges() {
    let flags = ["-fmerge-constants", "-fuse-ld=lld", "-Wl,-O2", "-fPIE", "-pie", "-Wl,-z,nopack-relative-relocs"];
    let Some(b) = build("clang_pie", "clang", "objdump", "nm", &flags) else { return };
    the_answers("clang_pie", &b, "relative_relocation");
    // lld at this level leaves one string, so both references reach one occurrence.
    let answer = b.query("merged end");
    assert_eq!(answer["count"], 1, "{answer}");
    assert_eq!(all_rows(&answer).len(), 2, "{answer}");
}

#[test]
fn clang_fixed() {
    let flags = ["-fuse-ld=lld", "-Wl,-O2", "-fno-pie", "-no-pie"];
    let Some(b) = build("clang_fixed", "clang", "objdump", "nm", &flags) else { return };
    the_answers("clang_fixed", &b, "matching_value");
}

#[test]
fn mingw_pe() {
    let flags = ["-fmerge-constants", "-static"];
    let Some(b) = build("mingw", "x86_64-w64-mingw32-gcc", "x86_64-w64-mingw32-objdump", "x86_64-w64-mingw32-nm", &flags) else { return };
    the_answers("mingw", &b, "base_relocation");
}

/// Strings cut by a length have no NUL between them, so the bytes before a text are
/// another string. What says so is the image: rustc names itself in `.comment`.
#[test]
fn strings_with_no_nul_between_them() {
    const SOURCE: &str = r#"
__asm__(".section .rodata\n.globl blob\nblob:\n.ascii \"first literal, \"\n.ascii \"second literal\"\n.byte 0\n.text\n");
extern const char blob[];
void use(const char*);
__attribute__((noinline)) void use(const char* p) { __asm__ volatile("" : : "r"(p)); }
int main(void) { use(blob); return 0; }
"#;
    const COMMENT: &str = r#"__asm__(".section .comment\n.string \"rustc version 1.99.0 (000000000 2099-01-01)\"\n.text\n");"#;
    let dir = std::env::temp_dir().join(format!("n0xis_xref_strings_{}_cut", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    for (tag, text, reached) in [("rust", format!("{COMMENT}{SOURCE}"), false), ("c", SOURCE.to_string(), true)] {
        let src = dir.join(format!("{tag}.c"));
        std::fs::write(&src, text).expect("write");
        let file = dir.join(tag);
        match Command::new("gcc").args(["-O1", "-fPIE", "-pie", "-o"]).arg(&file).arg(&src).output() {
            Ok(o) if o.status.success() => {}
            _ => {
                eprintln!("skipped: gcc could not build");
                return;
            }
        }
        let b = Built { file, objdump: "objdump", nm: "nm" };
        let answer = b.query("first literal");
        assert_eq!(all_rows(&answer).len(), 1, "{tag}: the reference is on the text's first byte: {answer}");
        let answer = b.query("second literal");
        if reached {
            assert_eq!(answer["found_unreferenced"], 0, "{tag}: one C string, referenced at its start: {answer}");
        } else {
            assert_eq!(answer["found_unreferenced"], 1, "{tag}: another literal, referenced by nothing: {answer}");
            let not_searched = answer["searched"]["not_searched"].to_string();
            assert!(not_searched.contains("cuts its strings by a length"), "{tag}: {answer}");
        }
    }
}

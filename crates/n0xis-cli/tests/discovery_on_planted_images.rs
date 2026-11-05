// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Function discovery on images planted so that one rule, or none, can find
//! each start** — the list whole, and `why`'s sources for the starts each
//! wrong-answer class of the rule-accuracy round was about (docs/VERIFICATION.md,
//! "How often each rule is right"), so a rule that fires where it must not, or
//! stops firing where it must, fails here on its own line.
//!
//! The truth is the bytes, planted on purpose (`tests/fixtures/discovery/*.s`,
//! rebuilt by `plant.sh`); where they landed is what `readelf` and `objdump`
//! recorded beside each file:
//!
//! - `x86_64.so` (`x86_64.so.sections.txt`): `.plt` `0x1000..0x1020`, `.text`
//!   from `0x1020`. `.eh_frame` holds two FDEs (`x86_64.so.frames.txt`): the
//!   linker's over the whole `.plt`, `0x1000..0x1020`, and `caller`'s,
//!   `0x1030..0x1043`. `readelf -sW` (`x86_64.so.symbols.txt`): `sym_only` at
//!   `0x1020` size 6 and `caller` at `0x1030` size 19 in both tables;
//!   `zero_size` at `0x1028` size 0; `in_data` at `0x5008` size 4 in `.data`
//!   (section 12). `objdump -d` (`x86_64.so.disassembly.txt`): the stub
//!   `ext@plt` at `0x1010`; `caller` calls it at `0x1034` and `big` at
//!   `0x1039`; `big` runs from `0x1045` to its `ret` at `0x2431`, 1 700
//!   three-byte `add`s, so 4 096 bytes from its start fall one byte into an
//!   instruction (`0x1045 + 1 365 * 3 = 0x2044`).
//! - `i386.so` (`i386.so.disassembly.txt`, `i386.so.frames.txt`): two FDEs,
//!   `0x1000..0x100f` and `0x1060..0x1063`; `lea` padding at `0x100f`,
//!   `0x1025`, `0x103b`, `0x1044`; `call 1036` at `0x1031` followed by `pop
//!   %ebx` at `0x1036`; `call 105a` at `0x1055` followed by `push %ebp` at
//!   `0x105a`. The functions, by the source: `0x1000`, `0x1020`, `0x1030`,
//!   `0x1040`, `0x1050`, `0x105a`, `0x1060`.
//! - `aarch64.so` (`aarch64.so.disassembly.txt`): two functions with no symbol
//!   and no FDE: `paciasp` at `0x1b0`, `stp x29, x30, [sp, #-16]!` at `0x1b4`;
//!   `stp` at `0x1d0`, `cbz` at `0x1d8` and a second `stp` at `0x1dc`.
//! - `rules.so` (`rules.so.disassembly.txt`, `rules.so.frames.txt`): `rules.s`
//!   says what is at each address.
//! - `lying.so` (`lying.so.disassembly.txt`, `.frames.txt`, `.symbols.txt`):
//!   its own test says what is planted.
//! - `arm32.so` (`arm32.so.symbols.txt`): `in_arm` at `0x10198` size 8 and
//!   `in_thumb` at `0x101a1` size 4, both tables; `.text` is `0x10198..0x101a4`
//!   (`arm32.so.sections.txt`), so `in_thumb`'s code starts at `0x101a0`.

use std::path::{Path, PathBuf};
use std::process::Command;

use n0xis_contracts::Va;
use n0xis_sources::{ImageSource, StartReason, SymbolTable};
use serde_json::{Value, json};

mod support;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/discovery").join(name)
}

/// A project of its own for each test: the function list `why` reads is kept
/// there.
fn project(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis_discovery_planted_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("project");
    dir
}

fn run(dir: &Path, args: &[&str]) -> Value {
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).arg("--quiet").current_dir(dir).output().expect("run n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("one JSON object from {args:?}: {e}"));
    assert_eq!(v["ok"], true, "{args:?}: {v}");
    v["data"].clone()
}

/// Every start `function discover` lists.
fn listed(dir: &Path, image: &Path) -> Vec<String> {
    let image = image.to_str().expect("a UTF-8 path");
    let data = run(dir, &["function", "discover", "--file", image]);
    data["functions"].as_array().expect("a list").iter().map(|f| f["va"].as_str().expect("an address").to_string()).collect()
}

/// `why`'s answer for the function at `addr`.
fn why(dir: &Path, image: &Path, addr: &str) -> Value {
    run(dir, &["why", "--file", image.to_str().expect("a UTF-8 path"), "--addr", addr])["function"].clone()
}

fn symbol(table: &str) -> Value {
    json!({"source": "symbol", "table": table})
}

/// A function only its symbol declares is listed, from the symbol, with the
/// table it is in: `sym_only` has no FDE, no caller, no prologue pattern, and
/// nothing ends before it in `.text`. A symbol of size 0 declares no start
/// (`zero_size` is found by the rules that follow a declared end, not by its
/// symbol), and one in `.data` is no function of the list.
#[test]
fn a_function_only_its_symbol_declares_is_listed_from_the_symbol() {
    let dir = project("symbol");
    let image = fixture("x86_64.so");
    let sym_only = why(&dir, &image, "0x1020");
    assert_eq!(sym_only["found"]["start"], "0x1020", "{sym_only}");
    assert_eq!(sym_only["found"]["start_sources"], json!([symbol("static"), symbol("dynamic")]), "{sym_only}");
    assert_eq!(sym_only["found"]["end"], json!({"va": "0x1026", "source": "symbol_size", "of": "st_size"}), "{sym_only}");
    let zero_size = why(&dir, &image, "0x1028");
    assert_eq!(zero_size["found"]["start_sources"], json!([{"source": "after_declared_end"}, {"source": "gap_sweep"}]), "{zero_size}");
    assert!(!listed(&dir, &image).contains(&"0x5008".to_string()), "`in_data` is in `.data`");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Where a symbol's size and an FDE state two ends for one start, both stay
/// sources of the start, the symbol's size still gives the end the list
/// shows (as it did before a symbol declared starts), and the two ends are a
/// contradiction (`contradictions_on_planted_images.rs` holds that answer
/// whole). `planted.so`'s `ends_twice`: `.size` 8, FDE 16.
#[test]
fn a_symbol_and_an_fde_that_disagree_both_stay_sources() {
    let dir = project("both");
    let image = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/contradictions/planted.so");
    let got = why(&dir, &image, "0x1000");
    assert_eq!(
        got["found"]["start_sources"],
        json!([symbol("static"), symbol("dynamic"), {"source": "unwind", "table": "eh_frame"}]),
        "{got}"
    );
    assert_eq!(got["found"]["end"], json!({"va": "0x1008", "source": "symbol_size", "of": "st_size"}), "{got}");
    let c = run(&dir, &["contradictions", "--file", image.to_str().expect("a UTF-8 path")]);
    assert_eq!(c["contradictions"][0]["kind"], "end", "{c}");
    assert_eq!(c["contradictions"][0]["start"], "0x1000", "{c}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The linker's FDE over `.plt` is the PLT's, not a function's: nothing in
/// `.plt` is listed (the FDE made `0x1000` a function ending at `0x1020`,
/// over the stub), and the stub keeps its import's name where it is called.
#[test]
fn an_fde_over_the_plt_is_not_a_function() {
    let dir = project("plt");
    let image = fixture("x86_64.so");
    let starts = listed(&dir, &image);
    assert_eq!(starts, ["0x1020", "0x1028", "0x1030", "0x1045"], "nothing below `.text`: {starts:?}");
    let plt0 = why(&dir, &image, "0x1000");
    assert!(plt0.get("none").is_some(), "the PLT's header is in no function: {plt0}");
    let pseudo = run(&dir, &["decomp", "pseudo", "--file", image.to_str().expect("a UTF-8 path"), "--addr", "0x1030"]);
    let text = pseudo["pseudo"].as_array().expect("lines").iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n");
    assert!(text.contains("ext("), "the stub is still named after `ext`: {text}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// i386 `lea` padding after a declared end is padding: the next function is
/// the first instruction after it, found by the rule that follows a declared
/// end and by the gap sweep, and the `lea` is listed by neither.
#[test]
fn i386_lea_padding_after_a_declared_end_is_not_a_function() {
    let dir = project("padding");
    let image = fixture("i386.so");
    let starts = listed(&dir, &image);
    assert!(!starts.contains(&"0x100f".to_string()), "the `lea` after f1's FDE is padding: {starts:?}");
    let f2 = why(&dir, &image, "0x1020");
    assert_eq!(f2["found"]["start"], "0x1020", "{f2}");
    assert_eq!(f2["found"]["start_sources"], json!([{"source": "after_declared_end"}, {"source": "gap_sweep"}]), "{f2}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The image's answer behind the first test, read without the CLI: the
/// functions a symbol declares, with their tables, and the PLT's range.
/// On 32-bit ARM a Thumb function's `st_value` is one past its code, and such
/// a symbol declares no start (an odd address no instruction begins at).
#[test]
fn the_symbols_that_declare_functions_are_the_sized_ones_in_code() {
    let x64 = ImageSource::load(&fixture("x86_64.so")).expect("load x86_64.so");
    let got: Vec<(u64, u64, StartReason)> = x64.symbol_functions().iter().map(|f| (f.start.0, f.end.0, f.why)).collect();
    let sym = |table| StartReason::Symbol { table };
    assert_eq!(
        got,
        // In each table's own order (`x86_64.so.symbols.txt`), `.symtab` first.
        [
            (0x1030, 0x1043, sym(SymbolTable::Static)),
            (0x1020, 0x1026, sym(SymbolTable::Static)),
            (0x1020, 0x1026, sym(SymbolTable::Dynamic)),
            (0x1030, 0x1043, sym(SymbolTable::Dynamic)),
        ]
    );
    assert_eq!(x64.plt_ranges(), [(Va(0x1000), Va(0x1020))]);
    let arm = ImageSource::load(&fixture("arm32.so")).expect("load arm32.so");
    let got: Vec<(u64, u64)> = arm.symbol_functions().iter().map(|f| (f.start.0, f.end.0)).collect();
    assert_eq!(got, [(0x10198, 0x101a0), (0x10198, 0x101a0)], "`in_arm` from both tables, `in_thumb` from neither");
    assert!(arm.plt_ranges().is_empty());
}

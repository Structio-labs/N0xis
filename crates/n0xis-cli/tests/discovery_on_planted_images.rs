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

/// The linker's FDE over `.plt` is the PLT's, not a function's: nothing in
/// `.plt` is listed (the FDE made `0x1000` a function ending at `0x1020`,
/// over the stub), and the stub keeps its import's name where it is called.
#[test]
fn an_fde_over_the_plt_is_not_a_function() {
    let dir = project("plt");
    let image = fixture("x86_64.so");
    let starts = listed(&dir, &image);
    assert!(!starts.contains(&"0x1000".to_string()), "nothing below `.text`: {starts:?}");
    let plt0 = why(&dir, &image, "0x1000");
    assert!(plt0.get("none").is_some(), "the PLT's header is in no function: {plt0}");
    let pseudo = run(&dir, &["decomp", "pseudo", "--file", image.to_str().expect("a UTF-8 path"), "--addr", "0x1030"]);
    let text = pseudo["pseudo"].as_array().expect("lines").iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n");
    assert!(text.contains("ext("), "the stub is still named after `ext`: {text}");
    let _ = std::fs::remove_dir_all(&dir);
}
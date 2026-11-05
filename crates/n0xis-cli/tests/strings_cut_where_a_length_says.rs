// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`strings` cuts a run of text where a reference states a length, and only
//! there** (`n0xis_core::cut_run`), on images planted so each answer is known
//! before the question is asked: `tests/fixtures/literals/*.s`, built with `as`
//! and `ld` by `plant.sh`. Where each label landed is what `readelf` recorded
//! beside each file (`*.symbols.txt`), so no address here comes from the tool.
//!
//! - `rela.so`, `rela_zero.so`, `relr.so`: one source, position-independent, in
//!   the three shapes a relocated word takes. `rela_zero.so` is lld's, which
//!   leaves the word zero and the address in the table alone.
//! - `exec`: the same source at fixed addresses, where a word states an address
//!   as it is stored and nothing relocates it.
//! - `i386.so`, `i386_exec`, `aarch64_be.so`, `aarch64_be_exec`: 32-bit words and
//!   big-endian words.
//! - `win64.exe`: a register pair under the ABI whose argument order differs.
//!
//! A real compiler, under `--features oracle`: `a_compiler_s_literals_come_back_apart`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

mod support;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/literals").join(name)
}

fn project(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis_literals_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("project");
    dir
}

/// A row as the answer gives it: address, text, and its evidence as kind and address.
type Row = (String, String, Option<(String, String)>);

/// Every row of `strings` on `image` that holds planted text.
fn rows(tag: &str, image: &Path, extra: &[&str]) -> Vec<Row> {
    let dir = project(tag);
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
        .args(["strings", "--file", image.to_str().expect("a UTF-8 path"), "--limit", "0", "--quiet"])
        .args(extra)
        .current_dir(&dir)
        .output()
        .expect("runs");
    let v: Value = serde_json::from_slice(&out.stdout).expect("one JSON object");
    assert_eq!(v["ok"], true, "{v}");
    let _ = std::fs::remove_dir_all(&dir);
    v["data"]["strings"]
        .as_array()
        .expect("a list")
        .iter()
        .filter(|r| {
            let t = r["text"].as_str().expect("text");
            ["DATA_", "CODE_", "BOTH_", "NUMBER_", "IMMED_", "IMSLOT_", "REG_", "partial_", "false_", "PQRS"].iter().any(|p| t.starts_with(p))
        })
        .map(|r| {
            let by = r.get("cut_by").map(|c| (c["kind"].as_str().expect("kind").to_string(), c["at"].as_str().expect("at").to_string()));
            (r["address"].as_str().expect("address").to_string(), r["text"].as_str().expect("text").to_string(), by)
        })
        .collect()
}

/// What `readelf -sW` recorded: a name's address.
fn symbols(image: &str) -> HashMap<String, u64> {
    let text = std::fs::read_to_string(fixture(&format!("{image}.symbols.txt"))).expect("the recording");
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (value, name) = (f.get(1)?, f.get(7)?);
            Some(((*name).to_string(), u64::from_str_radix(value, 16).ok()?))
        })
        .collect()
}

/// The row the labels say: a label's address, its text, and the evidence's kind
/// and label.
struct Want<'a>(&'a HashMap<String, u64>);

impl Want<'_> {
    fn at(&self, label: &str) -> String {
        format!("{:#x}", self.0.get(label).unwrap_or_else(|| panic!("no symbol {label}")))
    }

    fn row(&self, label: &str, text: &str, by: Option<(&str, &str)>) -> Row {
        (self.at(label), text.to_string(), by.map(|(kind, at)| (kind.to_string(), self.at(at))))
    }
}

/// The rows every image built from `x86_64.s` gives, but for `.fixed`.
fn x86_64_rows(w: &Want) -> Vec<Row> {
    let data = |at| Some(("data_pair", at));
    let code = |at| Some(("code_pair", at));
    vec![
        // A data pair alone: its end cuts a run no NUL ends...
        w.row("data_one_a", "DATA_ONE_A", data("pair_data_one")),
        w.row("data_one_b", "DATA_ONE_B", None),
        // A start alone, in a run a NUL ends, is a merged string tail: no cut...
        w.row("data_two_a", "DATA_TWO_ADATA_TWO_B", None),
        // ...in a run no NUL ends, it is a cut...
        w.row("data_three_a", "DATA_THREE", None),
        w.row("data_three_b", "DATA_THR_B", data("pair_data_three")),
        // ...and a start with an end at the same point cuts either.
        w.row("data_four_a", "DATA_FOURA", data("pair_data_four_a")),
        w.row("data_four_b", "DATA_FOURB", data("pair_data_four_b")),
        // A code pair alone, length in a register, the same two ways.
        w.row("code_one_a", "CODE_ONE_A", code("code_pair_one")),
        w.row("code_one_b", "CODE_ONE_B", None),
        // A code pair with its length in the slot beside the pointer's.
        w.row("code_two_a", "CODE_TWO_A", None),
        w.row("code_two_b", "CODE_TWO_B", code("code_pair_two")),
        // Together in one run; one literal with both says the first, here code.
        w.row("both_a", "BOTH_AAAAA", None),
        w.row("both_b", "BOTH_BBBBB", data("pair_both_b")),
        w.row("both_c", "BOTH_CCCCC", code("code_pair_both_c")),
        w.row("both_d", "BOTH_DDDDD", code("code_pair_both_d")),
        // The register form: the length in the ABI's next register, and not in
        // another, on either side of the load, nor in the other ABI's next.
        w.row("reg_true_a", "REG_TRUE", code("code_pair_reg_true")),
        w.row("reg_true_b", "REG_REST", None),
        w.row("reg_false", "REG_FALSE_LENGTH", None),
        w.row("reg_before", "REG_FALSE_BEFORE", None),
        w.row("reg_other_abi", "REG_OTHER_ABI", None),
        // A partial length on a string a NUL ends, from data and from code.
        w.row("partial", "partial_c_string", None),
        // Lengths past the run, and a zero one.
        w.row("false_one", "false_length_one", None),
        w.row("false_two", "false_length_two", None),
        w.row("false_three", "false_length_six", None),
    ]
}

#[test]
fn every_shape_of_relocated_word_says_the_same() {
    for image in ["rela.so", "rela_zero.so", "relr.so"] {
        let table = symbols(image);
        let w = Want(&table);
        let mut want = x86_64_rows(&w);
        // Two words no relocation writes, in an image that may load anywhere,
        // are numbers, and so are immediates: these runs stay whole.
        let fixed = [
            w.row("number_a", "NUMBER_AAANUMBER_BBB", None),
            w.row("immed_a", "IMMED_AAAAIMMED_BBBB", None),
            w.row("imslot_a", "IMSLOT_AAAIMSLOT_BBB", None),
        ];
        // `.fixed` sits below `.rodata` in lld's layout and above it in GNU ld's.
        want.extend(fixed);
        want.sort();
        let mut found = rows("reloc", &fixture(image), &[]);
        found.sort();
        assert_eq!(found, want, "{image}");
    }
}

#[test]
fn a_fixed_image_states_addresses_as_stored() {
    let table = symbols("exec");
    let w = Want(&table);
    let mut want = x86_64_rows(&w);
    want.extend([
        w.row("number_a", "NUMBER_AAA", None),
        w.row("number_b", "NUMBER_BBB", Some(("data_pair", "pair_number"))),
        w.row("immed_a", "IMMED_AAAA", None),
        w.row("immed_b", "IMMED_BBBB", Some(("code_pair", "code_immediate"))),
        w.row("imslot_a", "IMSLOT_AAA", None),
        w.row("imslot_b", "IMSLOT_BBB", Some(("code_pair", "code_immediate_slot"))),
    ]);
    want.sort();
    let mut found = rows("exec", &fixture("exec"), &[]);
    found.sort();
    assert_eq!(found, want);
}

/// The planted pair points into the middle of printable instructions. With code
/// sections left out there is no row to cut, so this asks for them.
#[test]
fn a_pointer_into_instructions_cuts_nothing() {
    for image in ["rela.so", "rela_zero.so", "relr.so", "exec"] {
        let table = symbols(image);
        let w = Want(&table);
        let found = rows("blob", &fixture(image), &["--all-sections"]);
        let blob: Vec<&Row> = found.iter().filter(|r| r.1.starts_with("PQRS")).collect();
        assert_eq!(blob, [&w.row("blob", "PQRSVWXYZ[^_PQRS", None)], "{image}");
    }
}

/// `lea rcx; mov edx,8` is a pair here and `lea rdi; mov esi,4` is not, the reverse
/// of the same instructions on System V in `x86_64.s`. Which order applies is the
/// image's: nothing on this command line says it.
#[test]
fn the_next_register_is_the_image_s_abi_s() {
    let table = symbols("win64.exe");
    let w = Want(&table);
    let want = vec![
        w.row("reg_true_a", "REG_TRUE", Some(("code_pair", "code_pair_reg_true"))),
        w.row("reg_true_b", "REG_REST", None),
        w.row("reg_false", "REG_FALSE_LENGTH", None),
        w.row("reg_other_abi", "REG_OTHER_ABI", None),
    ];
    assert_eq!(rows("win64", &fixture("win64.exe"), &[]), want);
}

#[test]
fn the_word_size_and_order_are_the_image_s() {
    for image in ["i386.so", "i386_exec", "aarch64_be.so", "aarch64_be_exec"] {
        let table = symbols(image);
        let w = Want(&table);
        let data = |at| Some(("data_pair", at));
        let want = vec![
            w.row("data_one_a", "DATA_ONE_A", data("pair_data_one")),
            w.row("data_one_b", "DATA_ONE_B", None),
            w.row("data_two_a", "DATA_TWO_A", None),
            w.row("data_two_b", "DATA_TWO_B", data("pair_data_two")),
            w.row("partial", "partial_c_string", None),
            w.row("false_one", "false_length_one", None),
        ];
        assert_eq!(rows("width", &fixture(image), &[]), want, "{image}");
    }
}

/// The evidence is the image's: the same bytes with no image around them state no
/// pointer, and stay one run.
#[test]
fn loose_bytes_are_not_cut() {
    let dir = project("bytes");
    let hex: String = b"PLANTED_ALPHAPLANTED_BETA\0".iter().map(|b| format!("{b:02x}")).collect();
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
        .args(["strings", "--bytes", &hex, "--start", "0x1000", "--size", "26", "--quiet"])
        .current_dir(&dir)
        .output()
        .expect("runs");
    let v: Value = serde_json::from_slice(&out.stdout).expect("one JSON object");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(v["data"]["strings"][0]["text"], "PLANTED_ALPHAPLANTED_BETA", "{v}");
    assert_eq!(v["data"]["strings"][0].get("cut_by"), None, "{v}");
}

/// Rung 1 with a real compiler: `planted.rs`, both manglings, position-independent
/// and not. A local instrument: the shape depends on the compiler's version.
#[cfg(feature = "oracle")]
#[test]
fn a_compiler_s_literals_come_back_apart() {
    let out_dir = project("rustc");
    let legacy: &[&str] = &["-Z", "unstable-options", "-C", "symbol-mangling-version=legacy"];
    let v0: &[&str] = &["-C", "symbol-mangling-version=v0"];
    // Fixed addresses two ways: the code loads a literal's address with `lea`, or
    // as an immediate.
    let no_pic: &[&str] = &["-C", "relocation-model=dynamic-no-pic", "-C", "link-args=-no-pie"];
    let fixed: &[&str] = &["-C", "relocation-model=static"];
    for (name, mangling, model) in [
        ("legacy_pie", legacy, &[][..]),
        ("v0_pie", v0, &[][..]),
        ("legacy_no_pic", legacy, no_pic),
        ("v0_no_pic", v0, no_pic),
        ("legacy_fixed", legacy, fixed),
        ("v0_fixed", v0, fixed),
    ] {
        let image = out_dir.join(name);
        let built = Command::new("rustc")
            .env("RUSTC_BOOTSTRAP", "1")
            .args(["-O", "-o"])
            .arg(&image)
            .args(mangling)
            .args(model)
            .arg(fixture("planted.rs"))
            .status()
            .expect("rustc runs");
        assert!(built.success(), "{name}");
        let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
            .args(["strings", "--file", image.to_str().expect("a UTF-8 path"), "--limit", "0", "--contains", "PLANTED", "--quiet"])
            .current_dir(&out_dir)
            .output()
            .expect("runs");
        let v: Value = serde_json::from_slice(&out.stdout).expect("one JSON object");
        let texts: Vec<&str> = v["data"]["strings"].as_array().expect("a list").iter().map(|r| r["text"].as_str().expect("text")).collect();
        for planted in ["PLANTED_ALPHA", "PLANTED_BETA", "PLANTED_SQUARE", "PLANTED_RECT", "PLANTED_PANIC"] {
            assert!(texts.contains(&planted), "{name}: {planted} is not a row of {texts:?}");
        }
    }
    let _ = std::fs::remove_dir_all(&out_dir);
}

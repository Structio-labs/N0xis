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
//! - `gaps.so`, `gaps_aarch64.so` (`.disassembly.txt`, `.frames.txt`,
//!   `.sections.txt`): frames of `0x100` bytes, each a gap between declared
//!   functions; the `.s` says what is at each offset. `.text` is at `0x1000` and
//!   `0x1b0`.

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

/// A function with no stated end whose graph runs out of its 4 KiB window:
/// the answer says the graph was cut there, never that the function ends
/// there.
#[test]
fn a_graph_cut_by_its_window_says_it_was_cut() {
    let dir = project("window");
    let got = why(&dir, &fixture("x86_64.so"), "0x1045");
    assert_eq!(got["found"]["end"], json!({"source": "not_stated", "cfg": {"cut": {"at": "0x2045", "read": 4096}}}), "{got}");
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

/// `call 1f; 1: pop` reads the code's own address and calls no function; a
/// call to the next instruction that does not pop is a call, and its target a
/// function (f5, at the instruction after f4's last call).
#[test]
fn i386_get_pc_is_not_a_call_and_a_call_to_the_next_function_is() {
    let dir = project("get_pc");
    let image = fixture("i386.so");
    let starts = listed(&dir, &image);
    assert!(!starts.contains(&"0x1036".to_string()), "the `pop` of `call 1f; 1: pop %ebx` is no function: {starts:?}");
    let f5 = why(&dir, &image, "0x105a");
    assert_eq!(f5["found"]["start"], "0x105a", "{f5}");
    assert_eq!(f5["found"]["start_sources"], json!([{"source": "call_target", "from": "0x1055"}]), "{f5}");
    assert_eq!(starts, ["0x1000", "0x1020", "0x1030", "0x1040", "0x1050", "0x105a", "0x1060"], "every planted function and nothing else");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A function that signs its return address begins with `paciasp`; its `stp`
/// is one word in, and the start is the `paciasp`.
#[test]
fn an_aarch64_function_that_signs_its_return_address_starts_at_paciasp() {
    let dir = project("paciasp");
    let image = fixture("aarch64.so");
    // At `paciasp`, not at the `stp` after it; and the second function at its
    // first `stp`, not at the one its `cbz` runs on into (`0x1dc`).
    assert_eq!(listed(&dir, &image), ["0x1b0", "0x1d0"]);
    let got = why(&dir, &image, "0x1b0");
    assert_eq!(got["found"]["start_sources"], json!([{"source": "prologue"}]), "{got}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// **A declared source is a claim, what the table says, never the truth** (the
/// code may be obfuscated, or the table simply wrong). `lying.so` plants FDEs
/// and `STT_FUNC` symbols that state wrong starts and sizes
/// (`fixtures/discovery/lying.s`; every function there is 16 bytes on a 16-byte
/// boundary, `objdump -d` in `lying.so.disassembly.txt`).
///
/// This pins what the engine answers, **not what it should**. Where nothing
/// else speaks about the lie, the answer repeats it and `contradictions` has
/// nothing to report; where a second source speaks, it reports the two. A
/// change here is a change of what a lying table can make the engine say.
#[test]
fn a_lying_table_is_repeated_and_contradicted_only_where_a_second_source_speaks() {
    let dir = project("lying");
    let image = fixture("lying.so");
    let file = image.to_str().expect("a UTF-8 path");
    let fde = json!({"source": "unwind", "table": "eh_frame"});
    let st_size = json!({"source": "symbol_size", "of": "st_size"});

    // The list: real starts 0x1000, 0x1010, ... 0x1080, at 16-byte intervals.
    // Of those 0x1010, 0x1030, 0x1060 and 0x1080 are not listed; 0x1004, 0x1024
    // and 0x1044 are starts no function has (and 0x1015, 0x1035 the rules' own,
    // after a lying end).
    assert_eq!(
        listed(&dir, &image),
        ["0x1000", "0x1004", "0x1015", "0x1020", "0x1024", "0x1035", "0x1040", "0x1044", "0x1050", "0x1070"],
        "as measured"
    );

    // An FDE alone, with a start inside the function: the lie is stated as the
    // table's, with no doubt, beside the real start the section's first bytes
    // gave the gap sweep.
    let alone = why(&dir, &image, "0x1004");
    assert_eq!(alone["found"]["start_sources"], json!([fde]), "{alone}");
    assert_eq!(alone["found"]["end"], json!({"va": "0x1014", "source": "unwind", "table": "eh_frame"}), "{alone}");

    // A symbol alone, with a start in the middle of an instruction.
    let wrong_start = why(&dir, &image, "0x1044");
    assert_eq!(wrong_start["found"]["start_sources"], json!([symbol("static"), symbol("dynamic")]), "{wrong_start}");
    assert_eq!(wrong_start["found"]["name"]["name"], "wrong_start", "{wrong_start}");
    assert_eq!(wrong_start["found"]["end"], json!({"va": "0x1050", "source": "symbol_size", "of": "st_size"}), "{wrong_start}");

    // A symbol alone, too long: the function it swallows is listed as part of
    // it, and nothing says so. (Before a symbol declared starts, `0x1060` was
    // listed: a lying size now hides a real function.)
    let swallowed = why(&dir, &image, "0x1060");
    assert_eq!(swallowed["found"]["start"], "0x1050", "{swallowed}");
    assert_eq!(swallowed["found"]["addr_is_start"], false, "{swallowed}");

    // Only where a second source speaks does `contradictions` say anything:
    // the FDE and the size of `contested` as an end, `witnessed`'s true size
    // and its lying FDE as an overlap. Nothing about `alone`, `wrong_start` or
    // `wrong_size`.
    let c = run(&dir, &["contradictions", "--file", file]);
    assert_eq!(
        c["contradictions"],
        json!([
            {"kind": "end", "start": "0x1070", "ends": [{"end": "0x1080", "by": [fde]}, {"end": "0x1090", "by": [st_size]}]},
            {"kind": "overlap",
             "first": {"start": "0x1020", "end": "0x1030", "by": [st_size]},
             "second": {"start": "0x1024", "end": "0x1034", "by": [fde]}},
        ]),
        "{c}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The rules' edges: the section's start brackets the code before the first
/// declared function; a branch into the filler means what follows the filler
/// is the same function; an entry pattern the code before runs on into is the
/// middle of a function, and the same pattern after filler is an entry.
#[test]
fn the_gap_sweep_and_the_scan_stop_where_the_code_goes_on() {
    let dir = project("rules");
    let image = fixture("rules.so");
    let starts = listed(&dir, &image);
    assert!(!starts.contains(&"0x1036".to_string()), "`leave` after a branch into the filler goes on: {starts:?}");
    assert!(!starts.contains(&"0x1060".to_string()), "`push` runs on into `sub`: {starts:?}");
    for (head, sources) in [("0x1000", json!([{"source": "gap_sweep"}])), ("0x1010", json!([{"source": "gap_sweep"}])), ("0x1070", json!([{"source": "prologue"}]))] {
        let got = why(&dir, &image, head);
        assert_eq!(got["found"]["start"], head, "{got}");
        assert_eq!(got["found"]["start_sources"], sources, "{head}: {got}");
    }
    assert_eq!(starts, ["0x1000", "0x1010", "0x1020", "0x1030", "0x1040", "0x1050", "0x1070"], "every planted function and nothing else");
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

/// The offsets from `.text` of the starts listed in one frame of `gaps.s`, after
/// the declared function it begins with: what the gap holds and nothing else.
fn frame(starts: &[String], text: u64, n: u64) -> Vec<u64> {
    let (lo, hi) = (text + n * 0x100 + 0x10, text + (n + 1) * 0x100);
    starts.iter().map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex")).filter(|va| (lo..hi).contains(va)).map(|va| va - text).collect()
}

/// `.text` of `gaps.so` (`gaps.so.sections.txt`).
const GAPS_TEXT: u64 = 0x1000;
/// `.text` of `gaps_aarch64.so` (`gaps_aarch64.so.sections.txt`).
const GAPS_AARCH64_TEXT: u64 = 0x1b0;

fn gaps(tag: &str, image: &str) -> Vec<String> {
    let dir = project(tag);
    let starts = listed(&dir, &fixture(image));
    let _ = std::fs::remove_dir_all(&dir);
    starts
}

/// Rule A: a jump past the gap's end, direct or conditional, has left the
/// function and silences nothing after it. The class this rule closes: 2088 of
/// one release PE's 2160 missed functions lay after such a jump.
#[test]
fn a_jump_past_the_end_of_the_gap_silences_nothing() {
    let starts = gaps("gap_a", "gaps.so");
    assert_eq!(frame(&starts, GAPS_TEXT, 1), [0x110, 0x120, 0x130, 0x140], "{starts:?}");
    let dir = project("gap_a_why");
    let got = why(&dir, &fixture("gaps.so"), "0x1120");
    assert_eq!(got["found"]["start_sources"], json!([{"source": "gap_sweep"}]), "{got}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A jump inside the gap covers what it jumps over, as it did: A must not read
/// every jump as leaving.
#[test]
fn a_forward_jump_inside_one_function_lists_nothing_it_jumps_over() {
    let starts = gaps("gap_a_not", "gaps.so");
    assert_eq!(frame(&starts, GAPS_TEXT, 2), [0x210, 0x240], "{starts:?}");
}

/// Rule C: straight after a far jump, code off the entry alignment is the same
/// function going on.
#[test]
fn unaligned_code_after_a_far_jump_is_not_a_start() {
    let starts = gaps("gap_c", "gaps.so");
    assert_eq!(frame(&starts, GAPS_TEXT, 3), [0x310, 0x330], "{starts:?}");
}

/// Only a far jump asks for alignment: not a return and filler, not a jump back.
#[test]
fn nothing_but_a_far_jump_asks_for_alignment() {
    let starts = gaps("gap_c_not", "gaps.so");
    assert_eq!(frame(&starts, GAPS_TEXT, 4), [0x410, 0x417, 0x420, 0x430, 0x437], "{starts:?}");
}

/// Rule E: a whole table's cases are not functions, each after filler where
/// nothing else would stop it, and they cover nothing: the function between two
/// of them and the one after the last are listed.
#[test]
fn the_cases_of_a_whole_jump_table_are_not_functions_and_cover_nothing() {
    let starts = gaps("gap_e", "gaps.so");
    assert_eq!(frame(&starts, GAPS_TEXT, 5), [0x510, 0x540, 0x570], "{starts:?}");
}

/// E, for a case the walk had already passed when it reached the dispatch.
#[test]
fn a_jump_table_case_before_its_dispatch_is_taken_back() {
    let starts = gaps("gap_e_back", "gaps.so");
    assert_eq!(frame(&starts, GAPS_TEXT, 6), [0x610, 0x630, 0x660], "{starts:?}");
}

/// A table one of whose cases is called is a table of functions: all listed.
#[test]
fn a_table_with_a_case_something_calls_is_no_function_s_table() {
    let starts = gaps("gap_e_called", "gaps.so");
    assert_eq!(frame(&starts, GAPS_TEXT, 7), [0x710, 0x730, 0x740, 0x750], "{starts:?}");
}

/// With no bound, how far the table goes is a probe, and its cases are not
/// taken as exact.
#[test]
fn a_table_with_no_bound_is_not_taken_as_a_whole() {
    let starts = gaps("gap_e_probe", "gaps.so");
    assert_eq!(frame(&starts, GAPS_TEXT, 8), [0x810, 0x830, 0x840, 0x850], "{starts:?}");
}

/// Rule F: a conditional branch back joins what it spans, and its target too
/// when that is a start.
#[test]
fn a_conditional_branch_back_joins_what_it_spans() {
    let starts = gaps("gap_f", "gaps.so");
    assert_eq!(frame(&starts, GAPS_TEXT, 9), [0x910, 0x940], "{starts:?}");
    assert_eq!(frame(&starts, GAPS_TEXT, 10), [0xa10, 0xa40], "{starts:?}");
}

/// An unconditional jump back may be a tail call: it joins nothing.
#[test]
fn an_unconditional_jump_back_joins_nothing() {
    let starts = gaps("gap_f_jmp", "gaps.so");
    assert_eq!(frame(&starts, GAPS_TEXT, 11), [0xb10, 0xb20, 0xb30, 0xb40], "{starts:?}");
}

/// A branch back to a call target goes to a function of its own: it joins
/// nothing, and 0xc30 and 0xc40 between them stay.
#[test]
fn a_branch_back_to_a_call_target_joins_nothing() {
    let starts = gaps("gap_f_call", "gaps.so");
    assert_eq!(frame(&starts, GAPS_TEXT, 12), [0xc10, 0xc20, 0xc30, 0xc40, 0xc50], "{starts:?}");
}

/// A branch to itself spans nothing. The first measurement of F panicked on
/// one: the range it took began past its end.
#[test]
fn a_branch_to_itself_spans_nothing() {
    let starts = gaps("gap_f_self", "gaps.so");
    assert_eq!(frame(&starts, GAPS_TEXT, 13), [0xd10, 0xd20, 0xd30, 0xd40], "{starts:?}");
}

/// Rule H: code that reads a callee-saved register it never wrote, or gives
/// back stack it never took, is no entry; a register saved and then set, one
/// cleared, a volatile one, one read only to be changed in place, are.
#[test]
fn code_that_uses_what_no_entry_has_is_not_a_start() {
    let starts = gaps("gap_h", "gaps.so");
    assert_eq!(frame(&starts, GAPS_TEXT, 14), [0xe10, 0xe60, 0xe70, 0xe80, 0xe90], "{starts:?}");
}

/// Rule I: what follows an unexplained jump through a register at once is that
/// dispatch going on, through its own direct jumps; filler ends it.
#[test]
fn what_follows_an_open_dispatch_at_once_is_not_a_start() {
    let starts = gaps("gap_i", "gaps.so");
    assert_eq!(frame(&starts, GAPS_TEXT, 15), [0xf10, 0xf30, 0xf40, 0xf50], "{starts:?}");
}

/// A call target ends an open dispatch, and a jump after it arms the sweep.
#[test]
fn a_call_target_ends_an_open_dispatch() {
    let starts = gaps("gap_i_call", "gaps.so");
    assert_eq!(frame(&starts, GAPS_TEXT, 16), [0x1010, 0x1017, 0x101e, 0x1030], "{starts:?}");
}

/// A jump through a memory slot reads no register that opens a dispatch, and
/// one through the stack pointer is no dispatch: a row of thunks is a row of
/// functions.
#[test]
fn a_row_of_thunks_opens_no_dispatch() {
    let starts = gaps("gap_i_thunk", "gaps.so");
    assert_eq!(frame(&starts, GAPS_TEXT, 17), [0x1110, 0x1116, 0x111c, 0x1122, 0x1126, 0x1130], "{starts:?}");
}

/// Where the architecture recognizes no jump table, none of the jump rules
/// holds, since a table's cases would read as functions: a far jump covers the
/// gap, nothing joins, nothing is refused as an entry, and an indirect jump arms
/// as it did.
#[test]
fn an_architecture_with_no_jump_tables_keeps_the_older_answer() {
    let starts = gaps("gap_aarch64", "gaps_aarch64.so");
    assert_eq!(frame(&starts, GAPS_AARCH64_TEXT, 1), [0x110], "{starts:?}");
    assert_eq!(frame(&starts, GAPS_AARCH64_TEXT, 2), [0x210, 0x220, 0x230, 0x240], "{starts:?}");
    assert_eq!(frame(&starts, GAPS_AARCH64_TEXT, 3), [0x310, 0x320, 0x330], "{starts:?}");
    assert_eq!(frame(&starts, GAPS_AARCH64_TEXT, 4), [0x410, 0x418, 0x420, 0x430], "{starts:?}");
}

/// Rule B holds everywhere: past a zero word and past a word that does not
/// decode, the sweep steps by the word and lands on the next instruction. A
/// byte-wise step read words from inside words and listed what it read.
#[test]
fn the_sweep_stays_on_the_word_boundary() {
    let starts = gaps("gap_aarch64_b", "gaps_aarch64.so");
    assert_eq!(frame(&starts, GAPS_AARCH64_TEXT, 5), [0x510, 0x520, 0x530], "{starts:?}");
    assert_eq!(frame(&starts, GAPS_AARCH64_TEXT, 6), [0x610, 0x620, 0x630], "{starts:?}");
}

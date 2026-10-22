// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A module that breaks the format is answered with what it holds, and the
//! answer says what is wrong** — never a list that silently drops a function,
//! a finding that says something other than what the reader did, or an index
//! that names nothing presented like one that does.
//!
//! Every module here is planted byte by byte, so what it holds is known before
//! asking. What a validator says about each was checked by hand with
//! `wasm-validate` (wabt 1.0.42) and `wasmtime` 49.0.3, and is quoted beside
//! it; this test does not run them (a tool's answer gates nothing in CI).
//!
//! - an out-of-order `name` map (`wasm-validate`: "function index out of
//!   order: 1", and for a repeated index "duplicate function name: 1"): the
//!   stage-1 reader keeps such a name, and leaves out only a second name for
//!   an index it has named. Its finding said "what it names is left out" for
//!   both, in Rust's debug spelling, while the function list named the
//!   function;
//! - a body of size 0 (`wasm-validate`: "expected valid local type" with one,
//!   "function body must end with END opcode" with all four): dropped from
//!   the function list without a word (`count: 0` for a module whose every
//!   body was empty);
//! - a start function or an export naming a function past the index space
//!   (`wasm-validate`: "function variable out of range: 99 (max 2)", and
//!   "…: 77 (max 2)"), answered in the same shape as a valid one, with no
//!   finding;
//! - a data segment placed past its memory's initial size, which
//!   instantiation traps on (`wasmtime run`: "failed to instantiate …: wasm
//!   trap: out of bounds memory access"), reported at that placement with no
//!   word;
//! - a module whose `name` section names 160 000 functions: opening it took
//!   12.9 s (a linear search per name), against 0.05 s without the section.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

static IN_PROJECT: Mutex<()> = Mutex::new(());

/// Run `work` in a scratch project holding `modules`, by file name.
fn in_project<T>(modules: &[(&str, Vec<u8>)], work: impl FnOnce(&Path) -> T) -> T {
    let _one = IN_PROJECT.lock().unwrap_or_else(|e| e.into_inner());
    let root = std::env::temp_dir().join(format!("n0xis-malformed-module-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(".n0x")).expect("scratch project");
    for (name, bytes) in modules {
        std::fs::write(root.join(name), bytes).expect("a module");
    }
    std::env::set_current_dir(&root).expect("into the scratch project");
    let out = work(&root);
    let _ = std::env::set_current_dir(std::env::temp_dir());
    let _ = std::fs::remove_dir_all(&root);
    out
}

fn ask(cap: &str, args: Value) -> Value {
    serde_json::to_value(n0xis_frontend::build_registry().dispatch(cap, &args)).expect("an envelope")
}

fn ok(v: Value, what: &str) -> Value {
    assert_eq!(v["ok"], true, "{what}: {v}");
    v["data"].clone()
}

// ---- a module, byte by byte ------------------------------------------------

fn leb(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn name(s: &str, out: &mut Vec<u8>) {
    leb(s.len() as u64, out);
    out.extend_from_slice(s.as_bytes());
}

fn section(id: u8, contents: &[u8], out: &mut Vec<u8>) {
    out.push(id);
    leb(contents.len() as u64, out);
    out.extend_from_slice(contents);
}

/// A module of `functions` functions of type `() -> ()`, each body empty but
/// for its `end` unless `bodies` gives its bytes (after the size; an empty
/// one is a body of size 0), plus the sections `extra` places by id.
struct Planted {
    functions: usize,
    bodies: Vec<(usize, Vec<u8>)>,
    memory_pages: Option<u64>,
    exports: Vec<(String, u32)>,
    start: Option<u32>,
    data: Vec<(u32, Vec<u8>)>,
    names: Vec<(u32, String)>,
}

impl Planted {
    fn new(functions: usize) -> Self {
        Planted { functions, bodies: Vec::new(), memory_pages: None, exports: Vec::new(), start: None, data: Vec::new(), names: Vec::new() }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut m = b"\0asm\x01\0\0\0".to_vec();
        section(1, &[0x01, 0x60, 0x00, 0x00], &mut m);
        let mut funcs = Vec::new();
        leb(self.functions as u64, &mut funcs);
        funcs.extend(std::iter::repeat_n(0x00, self.functions));
        section(3, &funcs, &mut m);
        if let Some(pages) = self.memory_pages {
            let mut mem = vec![0x01, 0x00];
            leb(pages, &mut mem);
            section(5, &mem, &mut m);
        }
        if !self.exports.is_empty() {
            let mut e = Vec::new();
            leb(self.exports.len() as u64, &mut e);
            for (n, f) in &self.exports {
                name(n, &mut e);
                e.push(0x00);
                leb(u64::from(*f), &mut e);
            }
            section(7, &e, &mut m);
        }
        if let Some(start) = self.start {
            let mut s = Vec::new();
            leb(u64::from(start), &mut s);
            section(8, &s, &mut m);
        }
        let mut code = Vec::new();
        leb(self.functions as u64, &mut code);
        for i in 0..self.functions {
            let body = self.bodies.iter().find(|(f, _)| *f == i).map(|(_, b)| b.clone()).unwrap_or_else(|| vec![0x00, 0x0b]);
            leb(body.len() as u64, &mut code);
            code.extend_from_slice(&body);
        }
        section(10, &code, &mut m);
        if !self.data.is_empty() {
            let mut d = Vec::new();
            leb(self.data.len() as u64, &mut d);
            for (at, bytes) in &self.data {
                d.push(0x00);
                d.push(0x41);
                // i32.const, signed LEB: the planted offsets are below 2^31.
                let mut v = *at as i64;
                loop {
                    let byte = (v & 0x7f) as u8;
                    v >>= 7;
                    let done = (v == 0 && byte & 0x40 == 0) || (v == -1 && byte & 0x40 != 0);
                    d.push(if done { byte } else { byte | 0x80 });
                    if done {
                        break;
                    }
                }
                d.push(0x0b);
                leb(bytes.len() as u64, &mut d);
                d.extend_from_slice(bytes);
            }
            section(11, &d, &mut m);
        }
        if !self.names.is_empty() {
            let mut map = Vec::new();
            leb(self.names.len() as u64, &mut map);
            for (index, n) in &self.names {
                leb(u64::from(*index), &mut map);
                name(n, &mut map);
            }
            let mut custom = Vec::new();
            name("name", &mut custom);
            custom.push(0x01);
            leb(map.len() as u64, &mut custom);
            custom.extend_from_slice(&map);
            section(0, &custom, &mut m);
        }
        m
    }
}

/// What `profile` answers for the module (the CLI's command, which builds it
/// with this function).
fn profile(file: &str) -> Value {
    let img = n0xis_sources::ImageSource::load(Path::new(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
    n0xis_frontend::image_caps::wasm_profile(&img, false).expect("a module")
}

/// `profile`'s findings about the module, as text.
fn findings(file: &str) -> Vec<String> {
    let p = profile(file);
    p["module"]["findings"].as_array().unwrap_or_else(|| panic!("{p}")).iter().map(|f| f.to_string()).collect()
}

fn listed(file: &str) -> Vec<Value> {
    ok(ask("function.discover", json!({ "file": file, "limit": 0 })), file)["functions"].as_array().cloned().unwrap_or_default()
}

// ---- the cases ---------------------------------------------------------------

/// `[(4, "four"), (1, "one")]`: index 1 is out of order and is kept, so the
/// function list names function 1 `one`; and the finding says it is kept,
/// in words. wasm-objdump leaves function 1 unnamed here — a policy of its own
/// on a malformed name section, which the format lets a reader ignore whole.
#[test]
fn an_out_of_order_name_is_said_to_be_kept() {
    let mut m = Planted::new(5);
    m.names = vec![(4, "four".into()), (1, "one".into())];
    let mut repeated = Planted::new(5);
    repeated.names = vec![(1, "one".into()), (1, "uno".into())];
    in_project(&[("unsorted.wasm", m.bytes()), ("repeated.wasm", repeated.bytes())], |_| {
        for (file, kept) in [("unsorted.wasm", "one"), ("repeated.wasm", "one")] {
            let names: Vec<(Value, Value)> = listed(file).iter().map(|f| (f["index"].clone(), f["name"].clone())).collect();
            assert!(names.contains(&(json!(1), json!(kept))), "{file}: function 1 is `{kept}`: {names:?}");
            let found = findings(file);
            let about = found.iter().find(|f| f.contains("name section")).unwrap_or_else(|| panic!("{file}: no finding: {found:?}"));
            assert!(!about.contains("IndexOrder"), "{file}: said in words, not the reader's debug spelling: {about}");
            assert!(!about.contains("what it names is left out"), "{file}: a name that is kept is not said to be left out: {about}");
            assert!(about.contains("index 1") && about.contains("is kept"), "{file}: {about}");
        }
    });
}

/// Function 1's body has size 0 — no locals count, no `end` — and it is still
/// a function the module declares: listed at its offset with its index, as the
/// other three are, while the findings name the body. All four empty: four
/// listed, not `count: 0`, the last of them at the end of the code section,
/// where a body of no bytes after the last size starts.
#[test]
fn a_function_with_a_body_of_size_0_is_listed() {
    let mut one = Planted::new(4);
    one.bodies = vec![(1, Vec::new())];
    let mut all = Planted::new(4);
    all.bodies = (0..4).map(|i| (i, Vec::new())).collect();
    in_project(&[("z1.wasm", one.bytes()), ("zall.wasm", all.bytes())], |_| {
        for file in ["z1.wasm", "zall.wasm"] {
            let functions = listed(file);
            let indices: Vec<Value> = functions.iter().map(|f| f["index"].clone()).collect();
            assert_eq!(indices, [json!(0), json!(1), json!(2), json!(3)], "{file}: every declared function, by index: {functions:?}");
            let f1 = &functions[1];
            assert_eq!(f1["name"], "func_1", "{file}: named by its index: {f1}");
            assert!(findings(file).iter().any(|f| f.contains("the body of function 1")), "{file}: the findings name the body");
        }
    });
}

/// A start function and an export past the function index space are carried
/// as stated, and the findings say they name nothing; a valid module's start
/// and export carry no such finding.
#[test]
fn an_index_past_the_index_space_is_said_to_name_nothing() {
    let mut start = Planted::new(2);
    start.start = Some(99);
    let mut export = Planted::new(2);
    export.exports = vec![("ghost".into(), 77), ("real".into(), 1)];
    let mut valid = Planted::new(2);
    valid.start = Some(1);
    valid.exports = vec![("real".into(), 1)];
    in_project(&[("start.wasm", start.bytes()), ("export.wasm", export.bytes()), ("valid.wasm", valid.bytes())], |_| {
        let p = profile("start.wasm");
        assert_eq!(p["module"]["start"]["index"], 99, "{p}");
        assert!(findings("start.wasm").iter().any(|f| f.contains("start section names function 99") && f.contains("2 functions")), "{:?}", findings("start.wasm"));
        let f = findings("export.wasm");
        assert!(f.iter().any(|f| f.contains("\\\"ghost\\\" names function 77")), "{f:?}");
        assert!(!f.iter().any(|f| f.contains("real")), "a valid export is no contradiction: {f:?}");
        assert!(findings("valid.wasm").iter().all(|f| !f.contains("contradiction")), "{:?}", findings("valid.wasm"));
    });
}

/// A segment of 32 bytes placed 16 bytes before the end of a 1-page memory is
/// reported where the module places it, and the findings say instantiation
/// traps on it; one that ends exactly at the end does not (wasmtime
/// instantiates it; `wasm-validate` accepts both, the trap being
/// instantiation's).
#[test]
fn a_segment_past_its_memory_is_said_to_trap() {
    let mut past = Planted::new(1);
    past.memory_pages = Some(1);
    past.data = vec![(65536 - 16, vec![0xaa; 32])];
    let mut fits = Planted::new(1);
    fits.memory_pages = Some(1);
    fits.data = vec![(65536 - 32, vec![0xaa; 32])];
    in_project(&[("past.wasm", past.bytes()), ("fits.wasm", fits.bytes())], |_| {
        let p = profile("past.wasm");
        assert_eq!(p["module"]["data_segments"][0]["placement"], json!({ "placed": { "memory": 0, "address": "0xfff0" } }), "{p}");
        let f = findings("past.wasm");
        assert!(f.iter().any(|f| f.contains("data segment 0") && f.contains("traps")), "{f:?}");
        assert!(findings("fits.wasm").iter().all(|f| !f.contains("traps")), "{:?}", findings("fits.wasm"));
    });
}

/// A module whose `name` section names each of 160 000 functions (2.2 MB) is
/// opened in time linear in its size. Each name looked its function's body up
/// by a linear search, which made opening quadratic: 12.9 s in a release
/// build, against 0.05 s for the same functions with no name section. The
/// bound is generous for a debug build on a loaded machine; the quadratic
/// search, in a debug build, takes minutes.
#[test]
fn a_module_naming_every_function_opens_in_linear_time() {
    const N: usize = 160_000;
    let mut m = Planted::new(N);
    m.names = (0..N as u32).map(|i| (i, format!("f{i}"))).collect();
    let path: PathBuf = std::env::temp_dir().join(format!("n0xis-many-names-{}.wasm", std::process::id()));
    std::fs::write(&path, m.bytes()).expect("the module");
    let began = Instant::now();
    let img = n0xis_sources::ImageSource::load(&path).expect("the module opens");
    let took = began.elapsed();
    let _ = std::fs::remove_file(&path);
    assert_eq!(n0xis_sources::SymbolProvider::symbol_at(&img, img.every_function().expect("a module")[N - 1].0).map(|s| s.name), Some(format!("f{}", N - 1)));
    assert!(took < Duration::from_secs(20), "opening took {took:?}");
}

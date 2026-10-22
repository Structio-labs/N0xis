// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Every command that needs the lift refuses a WebAssembly module, by name,
//! and none decodes its bytes as another instruction set** (the lead's
//! DECISIONS item 5 for docs/design/WASM.md stage 2).
//!
//! A module's architecture decodes and lifts nothing yet (the stack-machine
//! lift is stage 3). The lift's default, one `Unlifted` statement per
//! instruction, would let `decomp pseudo` answer `ok: true` over a body it
//! never understood, and a control-flow graph built from branches whose
//! targets are label depths would be a graph of nothing. So each such command
//! refuses with `not-lifted`, the reason naming stage 3: through the
//! registry (what the CLI, the MCP server and `serve` reach) and through the
//! CLI's own handlers (`analyze`, `const identify`, `bindings list`, `sig
//! gen`). And `--arch x64` on a module is refused, not obeyed: the module
//! declares its machine.
//!
//! The commands that only decode answer: `disasm`, `function discover` and
//! `xref` — checked against wasm-objdump in `wasm_facts_are_what_wasm_objdump_lists.rs`.

mod support;

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

fn module() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../n0xis-wasm/tests/fixtures/ctarget-O2.wasm")
}

/// A function of the module: `mix32`'s body (wasm-objdump -d: `0003d1 func[7] <mix32>:`).
const BODY: &str = "0x3d1";

/// The registry reads and writes the project of the working directory, which
/// is the process's: the tests that set it here take turns.
static IN_PROJECT: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn refused(v: &Value, what: &str) {
    refused_as(v, what, "not-lifted");
}

fn refused_as(v: &Value, what: &str, code: &str) {
    assert_eq!(v["ok"], false, "{what} answered: {v}");
    assert_eq!(v["error"]["code"], code, "{what}: {v}");
    let message = v["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("stage 3"), "{what}: the refusal names stage 3: {message}");
}

#[test]
fn every_capability_that_needs_the_lift_refuses_a_module() {
    let _one = IN_PROJECT.lock().unwrap_or_else(|e| e.into_inner());
    let file = module();
    let file = file.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("n0xis-lift-refusal-{}", std::process::id()));
    std::fs::create_dir_all(root.join(".n0x")).expect("scratch project");
    std::env::set_current_dir(&root).expect("into the scratch project");
    let registry = n0xis_frontend::build_registry();
    let ask = |cap: &str, args: Value| serde_json::to_value(registry.dispatch(cap, &args)).expect("an envelope");
    let at = json!({ "file": file, "addr": BODY });
    for cap in ["decomp.pseudo", "ir.cfg", "ir.explain", "ir.dot", "ir.value-set", "ir.deobfuscate"] {
        refused(&ask(cap, at.clone()), cap);
    }
    refused(&ask("ir.slice", json!({ "file": file, "addr": BODY, "reg": "x" })), "ir.slice");
    for cap in ["function.summary", "function.typeflow", "function.layout", "ir.manifest", "function.noreturn"] {
        refused(&ask(cap, json!({ "file": file })), cap);
    }
    refused(&ask("function.trace", at.clone()), "function.trace");
    refused(&ask("xref.string", json!({ "file": file, "query": "abc" })), "xref.string");
    // A diff names the side that failed, as it does every side's error.
    refused_as(&ask("diff.functions", json!({ "a_file": file, "a_addr": BODY, "b_file": file, "b_addr": BODY })), "diff.functions", "a-not-lifted");

    // The commands that only decode answer.
    for (cap, args) in [("decode", at.clone()), ("function.discover", json!({ "file": file })), ("xref", at.clone())] {
        let v = ask(cap, args);
        assert_eq!(v["ok"], true, "{cap}: {v}");
    }

    // An instruction set named against the module's own is refused, never
    // obeyed: x86 over a module's bytes is a confident wrong answer.
    let v = ask("decode", json!({ "file": file, "addr": BODY, "arch": "x64" }));
    assert_eq!(v["ok"], false, "{v}");
    assert_eq!(v["error"]["code"], "bad-arch", "{v}");
    assert!(v["error"]["message"].as_str().is_some_and(|m| m.contains("WebAssembly")), "{v}");
    let v = ask("decode", json!({ "file": file, "addr": BODY, "arch": "wasm" }));
    assert_eq!(v["data"]["insns"][0]["mnemonic"], "locals", "`--arch wasm` is the module's own: {v}");
    let _ = std::env::set_current_dir(std::env::temp_dir());
}

#[test]
fn every_cli_handler_that_needs_the_lift_refuses_a_module() {
    let file = module();
    let file = file.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("n0xis-lift-refusal-cli-{}", std::process::id()));
    std::fs::create_dir_all(root.join(".n0x")).expect("scratch project");
    let run = |args: &[&str]| -> Value {
        let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).arg("--quiet").current_dir(&root).output().expect("n0xis runs");
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{args:?}: not JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)))
    };
    refused(&run(&["analyze", "--file", file]), "analyze");
    refused(&run(&["const", "identify", "--file", file, "--addr", BODY]), "const identify");
    refused(&run(&["bindings", "list", "--file", file]), "bindings list");
    refused(&run(&["sig", "gen", "--file", file]), "sig gen");
    refused(&run(&["decomp", "pseudo", "--file", file, "--addr", BODY]), "decomp pseudo");

    // A snapshot records bytes at addresses and no format, and `--snapshot`
    // decodes them as x86-64: a module's code captured that way was
    // decompiled as x86 pseudo-C, `ok: true`, past every refusal above. The
    // capture is refused, and nothing is written.
    let v = run(&["snapshot", "dump", "--file", file, "--name", "module"]);
    assert_eq!(v["ok"], false, "a module is captured: {v}");
    assert_eq!(v["error"]["code"], "unsupported", "{v}");
    assert!(v["error"]["message"].as_str().is_some_and(|m| m.contains("WebAssembly")), "{v}");
    assert!(!root.join(".n0x/dumps/snapshot/module.json").exists(), "the refused capture was written");
    let _ = std::fs::remove_dir_all(&root);
}

/// The module's own coordinates, asked where they hold no instruction or no
/// native value. An offset where no instruction starts — inside one, inside
/// the locals declaration, the size before a body, the magic — is
/// `decode-failed`, never an `invalid` instruction the module does not hold;
/// and the bytes of a data segment hold linear-memory values, so `scan
/// dissect` guesses none of them a pointer into the module, and says why.
#[test]
fn a_modules_offsets_are_answered_as_the_module_lays_them_out() {
    let _one = IN_PROJECT.lock().unwrap_or_else(|e| e.into_inner());
    let file = module();
    let file = file.to_str().expect("utf-8 path");
    let root = std::env::temp_dir().join(format!("n0xis-module-offsets-{}", std::process::id()));
    std::fs::create_dir_all(root.join(".n0x")).expect("scratch project");
    std::env::set_current_dir(&root).expect("into the scratch project");
    let registry = n0xis_frontend::build_registry();
    let ask = |cap: &str, args: Value| serde_json::to_value(registry.dispatch(cap, &args)).expect("an envelope");

    // wasm-objdump -d: `0003d1 func[7] <mix32>:`, its locals run at 0x3d2
    // (`03 7f`), then `0003d4: 20 02 | local.get 2`. 0x3d0 is the body's size.
    for (addr, at) in [("0x3d5", "inside `local.get 2`"), ("0x3d2", "inside the locals declaration"), ("0x3d0", "the body's size"), ("0x0", "the magic")] {
        let v = ask("decode", json!({ "file": file, "addr": addr, "count": 1 }));
        assert_eq!(v["ok"], false, "{at} ({addr}) decoded: {v}");
        assert_eq!(v["error"]["code"], "decode-failed", "{at}: {v}");
    }
    let v = ask("decode", json!({ "file": file, "addr": "0x3d4", "count": 1 }));
    assert_eq!((v["data"]["insns"][0]["text"].clone(), v["data"]["function"].clone()), (json!("local.get 2"), json!(7)), "{v}");

    // The data segment: wasm-objdump -x, `segment[0] <.data> memory=0
    // size=36`, whose small values (7, 1, 2, 3) fell below the module's length
    // and were guessed pointers into its code.
    let img = n0xis_sources::ImageSource::load(Path::new(file)).expect("the module");
    let profile = n0xis_frontend::image_caps::wasm_profile(&img, false).expect("a module");
    let at = profile["module"]["data_segments"][0]["bytes_at"].as_str().expect("the segment's bytes").to_string();
    let v = ask("scan.dissect", json!({ "file": file, "start": at, "size": 36 }));
    assert_eq!(v["ok"], true, "{v}");
    let fields = v["data"]["fields"].as_array().unwrap_or_else(|| panic!("{v}"));
    assert!(!fields.is_empty(), "{v}");
    assert!(fields.iter().all(|f| f["kind"] != "pointer"), "a linear-memory value read as a module offset: {v}");
    assert!(v["meta"]["note"].as_str().is_some_and(|n| n.contains("no field is guessed a pointer")), "{v}");
    let _ = std::env::set_current_dir(std::env::temp_dir());
}

// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Phase 12 exit test (item 0 — import an external managed index)**.
//!
//! The target is the test binary's own `n0xis.exe`: a real PE with a real
//! `.text` range and a real image base, so the binding measurement is made
//! against a genuine image rather than a mock. Synthetic dumps are then written
//! in each of the two conventions dumper versions disagree about, and the point
//! of the test is that the tool **measures** which one fits instead of encoding
//! a guess that silently breaks on the next dumper release.
//!
//! The two refusals matter as much as the success: an IL2CPP WebGL index must
//! never bind to a native image, and a dump from a different build must be
//! rejected rather than applied. On this corpus a confident wrong name is the
//! worst possible output — it poisons every downstream command at once.
//!
//! Windows-only: the binding tests below use the test binary itself as a real
//! PE and hard-code `RVAS` — the real function starts of n0xis's OWN
//! `n0xis.exe`. On a non-PE host (an ELF `n0xis`) there is no equivalent
//! self-image and those RVAs bind 0.0%, so these end-to-end assertions stay
//! gated to Windows; the cross-platform `n0xis-il2cpp` unit tests cover the
//! parser.
//!
//! The name-binding tests that used to live here (the ones discovering a real
//! caller/callee pair via `find_call_pair`) were the only ones whose ground
//! truth was n0xis's own compiled machine code — which moved between build
//! configurations and failed on the MSVC runner while passing on GNU/ELF. They
//! moved to `phase12_il2cpp_fixture.rs`, which analyses a committed,
//! deterministic PE fixture instead and therefore runs on any host and gates CI
//! on both OSes.
#![cfg(windows)]

use std::process::Command;

use serde_json::Value;

/// The image base of `n0xis.exe`, and the RVAs of four real functions inside
/// its `.text` (taken from `function discover` on the MSVC build). These are
/// n0xis's OWN build artifact, which is why this file is `#![cfg(windows)]`.
const IMAGE_BASE: u64 = 0x1_4000_0000;
const RVAS: [u64; 4] = [0x1000, 0x102c, 0x1420, 0x3b50];

struct Scratch(std::path::PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Scratch {
    /// A temp directory with its own `.n0x/`, so nothing touches the developer's
    /// real project store.
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("n0xis-phase12-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        let s = Scratch(dir);
        let (v, ok) = s.run(&["init"]);
        assert!(ok, "n0x init should succeed in a fresh directory: {v}");
        s
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }

    /// Run the real binary **with the scratch directory as its cwd**, so `.n0x/`
    /// resolves there.
    fn run(&self, args: &[&str]) -> (Value, bool) {
        let out = Command::new(env!("CARGO_BIN_EXE_n0xis")).args(args).current_dir(&self.0).output().expect("run n0xis");
        let text = String::from_utf8_lossy(&out.stdout);
        let value: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("stdout was not one JSON envelope ({e}):\n{text}"));
        (value, out.status.success())
    }

    fn write_dump(&self, name: &str, entries: &[(u64, &str)]) -> std::path::PathBuf {
        let methods: Vec<String> = entries
            .iter()
            .map(|(a, n)| format!(r#"{{"Address":{a},"Name":"{n}","Signature":"void f(void *, const MethodInfo *)"}}"#))
            .collect();
        let json = format!(r#"{{"ScriptMethod":[{}],"ScriptString":[{{"Address":65536,"Value":"You died"}}]}}"#, methods.join(","));
        let path = self.path(name);
        std::fs::write(&path, json).unwrap();
        path
    }

    /// A structurally valid `global-metadata.dat` carrying `literals`.
    ///
    /// The real blobs are tens of megabytes and cannot live in a repo, so the
    /// fixture is built to the format instead: the `0xFAB11BAF` sanity word, the
    /// version, the twenty version-independent offset/size pairs (only the two
    /// literal tables populated), then the index and the data blob. The parser's
    /// own unit tests cover the malformed shapes; this exists to prove the
    /// *command* reads a file end to end.
    fn write_metadata(&self, name: &str, version: u32, literals: &[&str]) -> std::path::PathBuf {
        const FIXED_PREFIX: usize = 8 + 20 * 8;
        let mut blob: Vec<u8> = Vec::new();
        let mut index: Vec<u8> = Vec::new();
        for s in literals {
            index.extend_from_slice(&(s.len() as u32).to_le_bytes());
            index.extend_from_slice(&(blob.len() as u32).to_le_bytes());
            blob.extend_from_slice(s.as_bytes());
        }
        let mut out = Vec::new();
        out.extend_from_slice(&0xFAB1_1BAFu32.to_le_bytes());
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&(FIXED_PREFIX as u32).to_le_bytes());
        out.extend_from_slice(&(index.len() as u32).to_le_bytes());
        out.extend_from_slice(&((FIXED_PREFIX + index.len()) as u32).to_le_bytes());
        out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        for _ in 2..20 {
            out.extend_from_slice(&0u64.to_le_bytes());
        }
        assert_eq!(out.len(), FIXED_PREFIX);
        out.extend_from_slice(&index);
        out.extend_from_slice(&blob);
        let path = self.path(name);
        std::fs::write(&path, out).unwrap();
        path
    }
}

fn exe() -> String {
    env!("CARGO_BIN_EXE_n0xis").to_string()
}

fn names() -> [&'static str; 4] {
    ["PlayerHealth$$ApplyDamage", "CombatResolver$$Resolve", "EnemyAI$$Update", "Inventory$$CommitSlot"]
}

#[test]
fn an_rva_dump_is_detected_as_rva_and_bound_to_the_real_image() {
    let s = Scratch::new("rva");
    let entries: Vec<(u64, &str)> = RVAS.iter().copied().zip(names()).collect();
    let dump = s.write_dump("rva.json", &entries);

    let (v, ok) = s.run(&["il2cpp", "import", "--script-json", dump.to_str().unwrap(), "--name", "rva", "--file", &exe(), "--module", "n0xis.exe"]);
    assert!(ok, "{v}");
    assert_eq!(v["meta"]["schema"], "n0xis.il2cpp.import.v1");
    let d = &v["data"];
    assert_eq!(d["symbols"], 4);
    assert_eq!(d["space"], "native");
    assert_eq!(d["bindable"], true);
    // The convention is measured, and the losing one is reported alongside so
    // the decision is auditable rather than asserted.
    assert_eq!(d["binding"]["kind"], "rva+base");
    assert_eq!(d["binding"]["hits_rva"], 4);
    assert_eq!(d["binding"]["hits_va"], 0);
    assert_eq!(d["binding"]["accepted"], true);
}

#[test]
fn an_absolute_va_dump_of_the_same_functions_is_detected_as_such() {
    let s = Scratch::new("va");
    let entries: Vec<(u64, &str)> = RVAS.iter().map(|r| IMAGE_BASE + r).zip(names()).collect();
    let dump = s.write_dump("va.json", &entries);

    let (v, ok) = s.run(&["il2cpp", "import", "--script-json", dump.to_str().unwrap(), "--name", "va", "--file", &exe()]);
    assert!(ok, "{v}");
    assert_eq!(v["data"]["binding"]["kind"], "absolute-va");
    assert_eq!(v["data"]["binding"]["hits_va"], 4);
    assert_eq!(v["data"]["binding"]["hits_rva"], 0, "the same addresses cannot fit both conventions — that is what makes the measurement decisive");
}

#[test]
fn an_address_inside_a_function_resolves_to_its_csharp_name() {
    let s = Scratch::new("lookup");
    let entries: Vec<(u64, &str)> = RVAS.iter().copied().zip(names()).collect();
    let dump = s.write_dump("rva.json", &entries);
    let (v, ok) = s.run(&["il2cpp", "import", "--script-json", dump.to_str().unwrap(), "--name", "idx", "--file", &exe()]);
    assert!(ok, "{v}");

    // 0x10 past a function start: the address a call site or a watchpoint hit
    // would actually give you.
    let addr = format!("0x{:x}", IMAGE_BASE + RVAS[0] + 0x10);
    let (v, ok) = s.run(&["il2cpp", "symbols", "--name", "idx", "--addr", &addr, "--file", &exe()]);
    assert!(ok, "{v}");
    assert_eq!(v["data"]["count"], 1);
    assert_eq!(v["data"]["symbols"][0]["name"], "PlayerHealth$$ApplyDamage");
    assert_eq!(v["data"]["symbols"][0]["va"], format!("0x{:x}", IMAGE_BASE + RVAS[0]), "the reported VA is the function start, not the queried address");
    assert_eq!(v["data"]["symbols"][0]["kind"], "function");
}

#[test]
fn a_webgl_index_imports_as_a_name_table_and_never_binds_to_a_native_image() {
    let s = Scratch::new("webgl");
    // IL2CPP WebGL goes through the same IL2CPP pipeline, so the *names* are the
    // same shape — and the addresses are meaningless against a PE.
    let entries: Vec<(u64, &str)> = RVAS.iter().copied().zip(names()).collect();
    let dump = s.write_dump("webgl.json", &entries);

    let (v, ok) = s.run(&["il2cpp", "import", "--script-json", dump.to_str().unwrap(), "--name", "webgl", "--space", "wasm", "--module", "game.wasm"]);
    assert!(ok, "a WebGL dump is importable: {v}");
    assert_eq!(v["data"]["space"], "wasm");
    assert_eq!(v["data"]["bindable"], false);
    assert!(v["data"]["binding"].is_null(), "a categorically unbindable index must not be given a confidence score, which would imply a better dump could fix it");

    // Searchable as a name table.
    let (v, ok) = s.run(&["il2cpp", "symbols", "--name", "webgl", "--query", "applydamage"]);
    assert!(ok, "{v}");
    assert_eq!(v["data"]["matched"], 1);
    assert_eq!(v["data"]["addresses_are"], "wasm", "the answer must say which space its addresses are in");

    // But an address lookup against a native target is refused by name.
    let addr = format!("0x{:x}", IMAGE_BASE + RVAS[0]);
    let (v, ok) = s.run(&["il2cpp", "symbols", "--name", "webgl", "--addr", &addr, "--file", &exe()]);
    assert!(!ok, "binding a wasm index to a PE must fail: {v}");
    assert_eq!(v["error"]["code"], "unbindable");
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(msg.contains("WebAssembly"), "{msg}");
    assert!(msg.contains("il2cpp symbols"), "the refusal should name what you can do instead: {msg}");
}

#[test]
fn a_dump_from_a_different_build_is_refused_unless_forced() {
    let s = Scratch::new("mismatch");
    let entries: Vec<(u64, &str)> = [0x9000_0000u64, 0x9000_1000].iter().copied().zip(["X$$x", "Y$$y"]).collect();
    let dump = s.write_dump("wrong.json", &entries);

    let (v, ok) = s.run(&["il2cpp", "import", "--script-json", dump.to_str().unwrap(), "--name", "wrong", "--file", &exe()]);
    assert!(!ok, "a mismatched dump must exit non-zero: {v}");
    assert_eq!(v["error"]["code"], "binding-rejected");
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(msg.contains("0.0%"), "the refusal should carry the measurement: {msg}");
    assert!(msg.contains("different builds"), "{msg}");

    // The escape hatch exists, and taking it is explicit.
    let (v, ok) = s.run(&["il2cpp", "import", "--script-json", dump.to_str().unwrap(), "--name", "wrong", "--file", &exe(), "--force"]);
    assert!(ok, "--force should store it anyway: {v}");
    assert_eq!(v["data"]["binding"]["accepted"], false, "forcing stores the index without pretending the binding is sound");
}

#[test]
fn importing_without_a_target_is_allowed_and_says_it_was_not_validated() {
    let s = Scratch::new("notarget");
    let entries: Vec<(u64, &str)> = RVAS.iter().copied().zip(names()).collect();
    let dump = s.write_dump("d.json", &entries);

    let (v, ok) = s.run(&["il2cpp", "import", "--script-json", dump.to_str().unwrap(), "--name", "later"]);
    assert!(ok, "{v}");
    assert!(v["data"]["binding"].is_null());
    assert!(v["data"]["note"].as_str().unwrap().contains("not measured"), "silence about an unvalidated mapping would read as validation: {v}");
}

#[test]
fn a_name_query_returns_a_set_and_reports_what_it_paged_over() {
    let s = Scratch::new("set");
    // Generic sharing: two C# methods on one native body.
    let entries = [(RVAS[0], "List_1$$Add_System_Object"), (RVAS[0], "List_1$$Add_UnityEngine_Object"), (RVAS[1], "Other$$Add")];
    let dump = s.write_dump("gen.json", &entries);
    let (v, ok) = s.run(&["il2cpp", "import", "--script-json", dump.to_str().unwrap(), "--name", "gen", "--file", &exe()]);
    assert!(ok, "{v}");

    let (v, _) = s.run(&["il2cpp", "symbols", "--name", "gen", "--query", "List_1"]);
    assert_eq!(v["data"]["matched"], 2, "one address, two C# methods — the API must be able to say so");

    let (v, _) = s.run(&["il2cpp", "symbols", "--name", "gen", "--query", "$$add", "--limit", "1"]);
    assert_eq!(v["data"]["matched"], 3);
    assert_eq!(v["data"]["count"], 1);
    assert_eq!(v["data"]["more"], true, "a page must say more exists rather than leaving it to be inferred");
}

#[test]
fn a_mismatched_index_says_it_was_not_applied_instead_of_going_quiet() {
    let s = Scratch::new("skipnote");
    let dump = s.write_dump("wrong.json", &[(0x9000_0000, "X$$x"), (0x9000_1000, "Y$$y")]);
    let (v, ok) = s.run(&["il2cpp", "import", "--script-json", dump.to_str().unwrap(), "--file", &exe(), "--force"]);
    assert!(ok, "{v}");

    let addr = format!("0x{:x}", IMAGE_BASE + RVAS[0]);
    let (v, ok) = s.run(&["decomp", "pseudo", "--file", &exe(), "--addr", &addr]);
    assert!(ok, "an unusable index must not break the command: {v}");
    let note = v["meta"]["note"].as_str().unwrap_or_default();
    assert!(note.contains("NOT applied"), "a present-but-unusable index must say so, or the user stares at unnamed output wondering why: {note}");
}

#[test]
fn the_managed_capabilities_are_in_the_registry_both_frontends_read() {
    let s = Scratch::new("registry");
    let (v, ok) = s.run(&["capability", "list"]);
    assert!(ok, "{v}");
    let names: Vec<&str> = v["data"]["capabilities"].as_array().expect("a capability list").iter().filter_map(|c| c["name"].as_str()).collect();
    for want in ["il2cpp.import", "il2cpp.symbols", "il2cpp.metadata"] {
        assert!(names.contains(&want), "{want} should be registered — that is what makes it reachable from MCP without a new tool method; got {names:?}");
    }
}

// ---------------------------------------------------------------------------
// Item 1 — the native metadata parser, reachable
// ---------------------------------------------------------------------------

#[test]
fn a_metadata_blob_is_read_natively_with_no_dumper_in_sight() {
    let s = Scratch::new("metadata");
    let dat = s.write_metadata("global-metadata.dat", 31, &["You died", "Press any key", "Inventory full"]);
    let (v, ok) = s.run(&["il2cpp", "metadata", "--metadata", dat.to_str().unwrap()]);
    assert!(ok, "{v}");
    assert_eq!(v["data"]["version"], 31);
    assert_eq!(v["data"]["literals_total"], 3);
    assert_eq!(v["data"]["literals_not_utf8"], 0);
    let tables = v["data"]["tables"].as_array().expect("the fixed tables");
    assert_eq!(tables.len(), 20, "only the version-independent prefix is read, and it is exactly twenty pairs");
    assert_eq!(tables[0]["name"], "string_literal");
}

#[test]
fn a_literal_query_answers_is_this_text_in_the_game() {
    // The most common entry point in practice, and the one `xref string`
    // structurally cannot serve on this format: the literals are not in the
    // image at all.
    let s = Scratch::new("litquery");
    let dat = s.write_metadata("global-metadata.dat", 29, &["You died", "Press any key", "Inventory full"]);
    let (v, ok) = s.run(&["il2cpp", "metadata", "--metadata", dat.to_str().unwrap(), "--query", "inventory"]);
    assert!(ok, "{v}");
    assert_eq!(v["data"]["matched"], 1, "the search is case-insensitive over the literal text");
    assert_eq!(v["data"]["literals"][0]["value"], "Inventory full");

    // And the honest limit is stated rather than left to be discovered: a
    // literal index is not an address, so this is not yet xref-able.
    let note = v["meta"]["note"].as_str().unwrap_or_default();
    assert!(note.contains("not yet xref-able"), "the answer must say what it cannot do next: {note}");
}

#[test]
fn a_literal_page_reports_what_it_paged_over() {
    let s = Scratch::new("litpage");
    let dat = s.write_metadata("global-metadata.dat", 31, &["a1", "a2", "a3", "a4"]);
    let (v, ok) = s.run(&["il2cpp", "metadata", "--metadata", dat.to_str().unwrap(), "--limit", "2"]);
    assert!(ok, "{v}");
    assert_eq!(v["meta"]["returned"], 2);
    assert_eq!(v["meta"]["total"], 4);
    assert_eq!(v["meta"]["truncated"], true, "a capped list must not look like a complete one");
    assert_eq!(v["data"]["more"], true);

    let (v, ok) = s.run(&["il2cpp", "metadata", "--metadata", dat.to_str().unwrap(), "--limit", "2", "--offset", "2"]);
    assert!(ok, "{v}");
    assert_eq!(v["data"]["literals"][0]["value"], "a3");
    assert_eq!(v["data"]["more"], false, "the last page is not 'more'");
}

#[test]
fn a_file_that_is_not_metadata_is_refused_by_name() {
    let s = Scratch::new("notmeta");
    let path = s.path("random.bin");
    // Long enough to clear the length check, so the *magic* is what refuses it —
    // a short file would be rejected for a different, less interesting reason.
    std::fs::write(&path, vec![0x41u8; 4096]).unwrap();
    let (v, ok) = s.run(&["il2cpp", "metadata", "--metadata", path.to_str().unwrap()]);
    assert!(!ok, "a non-metadata file must fail, not return an empty success: {v}");
    assert_eq!(v["error"]["code"], "bad-metadata");
    assert!(
        v["error"]["message"].as_str().unwrap_or_default().contains("global-metadata.dat"),
        "the refusal should say what the file is not: {v}"
    );
}

#[test]
fn the_blob_is_found_beside_the_target_without_being_told_where() {
    // The IL2CPP layout is `<Game>_Data/il2cpp_data/Metadata/`, and an agent
    // holding `--file GameAssembly.dll` should not have to know that.
    let s = Scratch::new("discover");
    let data_dir = s.path("Game_Data").join("il2cpp_data").join("Metadata");
    std::fs::create_dir_all(&data_dir).unwrap();
    let blob = s.write_metadata("tmp.dat", 31, &["You died"]);
    std::fs::rename(&blob, data_dir.join("global-metadata.dat")).unwrap();
    let image = s.path("GameAssembly.dll");
    std::fs::write(&image, b"not a real PE, but the search only looks at the directory").unwrap();

    let (v, ok) = s.run(&["il2cpp", "metadata", "--file", image.to_str().unwrap()]);
    assert!(ok, "{v}");
    assert_eq!(v["data"]["literals_total"], 1);

    // And a target with no blob beside it says so. It needs a directory of its
    // own: the search looks at *siblings*, so leaving it next to `Game_Data`
    // would have found the blob above and quietly proved nothing.
    let elsewhere = s.path("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let lonely = elsewhere.join("Elsewhere.dll");
    std::fs::write(&lonely, b"x").unwrap();
    let (v, ok) = s.run(&["il2cpp", "metadata", "--file", lonely.to_str().unwrap()]);
    assert!(!ok, "{v}");
    assert_eq!(v["error"]["code"], "no-metadata");
}

// ---------------------------------------------------------------------------
// The code-window finding (not IL2CPP-specific, but IL2CPP is where it bites)
// ---------------------------------------------------------------------------

#[test]
fn an_unmatched_module_refuses_instead_of_scanning_a_different_one() {
    // Range-scoped commands take `--module` because a live IL2CPP target keeps
    // its code in `GameAssembly.dll` while the main module is a thin player.
    // The failure mode to prevent is the quiet substitution: asking for a
    // module that is not there and being handed another one's code back, which
    // is how a wrong answer comes to look right.
    let s = Scratch::new("nomodule");
    for cmd in [
        vec!["xref", "string", "--file", &exe(), "--module", "NotLoaded.dll", "--query", "anything"],
        vec!["xref", "to", "--file", &exe(), "--module", "NotLoaded.dll", "--addr", "0x140001000"],
        vec!["ir", "manifest", "--file", &exe(), "--module", "NotLoaded.dll"],
    ] {
        let (v, ok) = s.run(&cmd);
        assert!(!ok, "{cmd:?} should refuse an unloaded module: {v}");
        assert_eq!(v["error"]["code"], "no-module", "{cmd:?}: {v}");
    }
}

#[test]
fn naming_the_real_module_scans_it_exactly_as_before() {
    // The control for the test above: the same commands against the module
    // that *is* there behave as they always did.
    let s = Scratch::new("realmodule");
    let (v, ok) = s.run(&["ir", "manifest", "--file", &exe(), "--module", "n0xis", "--limit", "3"]);
    assert!(ok, "naming the loaded module must work: {v}");
    assert!(v["data"]["entries"].as_array().map(|f| !f.is_empty()).unwrap_or(false), "it should still find functions: {v}");
}

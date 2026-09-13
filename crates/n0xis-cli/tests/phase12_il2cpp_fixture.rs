// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Phase 12 — IL2CPP name binding against a committed PE fixture.**
//!
//! These six tests prove that an imported IL2CPP index attaches managed names
//! to a native image through every path that renders a function name: a call
//! target in a decompiled body, a function's own signature, the cache-key
//! invalidation, the range-scoped `ir manifest` seam, and the two soundness
//! refusals (a covering-but-inexact symbol must NOT name a function).
//!
//! The ground truth is `tests/fixtures/native_pe.dll` — a tiny, deterministic
//! PE built once with mingw (see `native_pe.c`) at image base 0x140000000, with
//! an unnamed internal function `mid` (`sub_14000102a`) that calls an unnamed
//! internal `leaf` (`sub_140001000`). It is committed FROZEN and never rebuilt
//! in CI; the tests only READ it.
//!
//! This replaces the earlier design where these assertions ran against n0xis's
//! OWN compiled binary. That made their ground truth a build artifact of
//! whichever compiler the CI runner shipped — the same function moved between
//! build configurations, and one of these tests failed on the Windows MSVC
//! runner while passing on the GNU/ELF build (an own-binary-layout dependency,
//! not a real defect). With a committed fixture the tests are deterministic on
//! any host and gate CI on both OSes — the Linux n0xis analyses the PE
//! statically, so no toolchain is spawned at test time and no `#[cfg(windows)]`
//! or oracle feature is needed.
//!
//! The sibling file `phase12_il2cpp.rs` keeps the tests that bind synthetic
//! dumps against `n0xis.exe` at its real RVAs; those remain `#![cfg(windows)]`
//! because their addresses are that PE's own function starts.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

/// The fixture's image base, matching `native_pe.dll` (verified with
/// `objdump -p`: `ImageBase 0000000140000000`). `rva_of` converts a reported VA
/// back to an RVA against it.
const IMAGE_BASE: u64 = 0x1_4000_0000;

/// Absolute path to the committed fixture PE, resolved from the crate manifest
/// so it is found regardless of the test's working directory.
fn fixture() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join("native_pe.dll").to_str().expect("fixture path is utf-8").to_string()
}

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
        let dir = std::env::temp_dir().join(format!("n0xis-phase12fx-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        let s = Scratch(dir);
        let (v, ok) = s.run(&["init"]);
        assert!(ok, "n0x init should succeed in a fresh directory: {v}");
        s
    }

    /// Run the real binary **with the scratch directory as its cwd**, so `.n0x/`
    /// resolves there.
    fn run(&self, args: &[&str]) -> (Value, bool) {
        let out = Command::new(env!("CARGO_BIN_EXE_n0xis")).args(args).current_dir(&self.0).output().expect("run n0xis");
        let text = String::from_utf8_lossy(&out.stdout);
        let value: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("stdout was not one JSON envelope ({e}):\n{text}"));
        (value, out.status.success())
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
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
}

/// Find the fixture's real caller/callee pair by asking the binary itself.
///
/// Deliberately discovered rather than hardcoded: it re-derives the pair from
/// the committed fixture, so a future rebuild of the fixture cannot silently
/// desync a pinned address. Returns the caller's VA as a hex string and the
/// callee's RVA. On the committed `native_pe.dll` this is `mid`
/// (`sub_14000102a`) calling `leaf` (`sub_140001000`, RVA 0x1000).
///
/// Side effect by design: the `decomp pseudo` calls here populate the artifact
/// cache *before* any index exists, which is exactly the state the cache-key
/// regression test needs.
fn find_call_pair(s: &Scratch) -> (String, u64) {
    let (v, ok) = s.run(&["function", "discover", "--file", &fixture()]);
    assert!(ok, "function discover should work on the fixture: {v}");
    let text = v.to_string();

    let candidates: Vec<String> = text
        .match_indices("0x1")
        .filter_map(|(i, _)| {
            let tail = &text[i..];
            let end = tail.find(|c: char| !c.is_ascii_hexdigit() && c != 'x')?;
            (end > 6).then(|| tail[..end].to_string())
        })
        .take(40)
        .collect();

    for addr in candidates {
        let (v, ok) = s.run(&["decomp", "pseudo", "--file", &fixture(), "--addr", &addr]);
        if !ok {
            continue;
        }
        let body = v["data"]["pseudo"].to_string();
        let self_name = format!("sub_{}", addr.trim_start_matches("0x"));
        // A call to some *other* function is what we need — the function's own
        // header names itself and proves nothing about symbol resolution.
        if let Some(i) = body.match_indices("sub_1").map(|(i, _)| i).find(|&i| !body[i..].starts_with(&self_name)) {
            let tail = &body[i + 4..];
            let end = tail.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(tail.len());
            if let Ok(callee) = u64::from_str_radix(&tail[..end], 16)
                && callee > IMAGE_BASE
            {
                return (addr, callee - IMAGE_BASE);
            }
        }
    }
    panic!("no function in the fixture showed a call to another function — the fixture assumption is broken");
}

fn rva_of(addr: &str) -> u64 {
    u64::from_str_radix(addr.trim_start_matches("0x"), 16).expect("hex address") - IMAGE_BASE
}

#[test]
fn an_imported_index_names_call_targets_in_decompiled_output() {
    let s = Scratch::new("naming");
    let (caller, callee_rva) = find_call_pair(&s);
    let dump = s.write_dump("m.json", &[(callee_rva, "PlayerHealth$$ApplyDamage")]);
    let (v, ok) = s.run(&["il2cpp", "import", "--script-json", dump.to_str().unwrap(), "--file", &fixture()]);
    assert!(ok, "{v}");

    let (v, ok) = s.run(&["decomp", "pseudo", "--file", &fixture(), "--addr", &caller]);
    assert!(ok, "{v}");
    let body = v["data"]["pseudo"].to_string();
    assert!(body.contains("PlayerHealth"), "the call target should carry its managed name, got: {body}");
    assert!(!body.contains(&format!("sub_{:x}", IMAGE_BASE + callee_rva)), "the raw address name should be gone: {body}");

    // And the answer must say where the names came from — `meta.note` exists
    // for results that are easy to misread, and "these names are from a file
    // beside the binary" is exactly that.
    let note = v["meta"]["note"].as_str().unwrap_or_default();
    assert!(note.contains("il2cpp index"), "the response should name the layer its names came from: {note}");
}

#[test]
fn importing_an_index_takes_effect_on_already_analyzed_functions() {
    // Regression: the artifact cache keyed on the binary's bytes alone, so a
    // CFG built before an index existed was reused afterwards — with its
    // pre-import, unnamed call targets baked in. Importing appeared to do
    // nothing until `.n0x/ir-cache/` was deleted by hand.
    let s = Scratch::new("cachekey");

    // Discovery decompiles as it searches, so by the time it returns the
    // artifact cache already holds this function — analyzed with no index in
    // sight. That is precisely the poisoned state the fix has to survive.
    let (caller, callee_rva) = find_call_pair(&s);
    let (v, ok) = s.run(&["decomp", "pseudo", "--file", &fixture(), "--addr", &caller]);
    assert!(ok, "{v}");
    assert!(
        v["data"]["pseudo"].to_string().contains(&format!("sub_{:x}", IMAGE_BASE + callee_rva)),
        "precondition: the callee is unnamed before any index exists"
    );

    let dump = s.write_dump("m.json", &[(callee_rva, "PlayerHealth$$ApplyDamage")]);
    let (v, ok) = s.run(&["il2cpp", "import", "--script-json", dump.to_str().unwrap(), "--file", &fixture()]);
    assert!(ok, "{v}");

    // No cache clearing between these two runs — that is the whole point.
    let (v, ok) = s.run(&["decomp", "pseudo", "--file", &fixture(), "--addr", &caller]);
    assert!(ok, "{v}");
    assert!(
        v["data"]["pseudo"].to_string().contains("PlayerHealth"),
        "a newly imported index must invalidate cached artifacts, not be shadowed by them: {}",
        v["data"]["pseudo"]
    );
}

#[test]
fn an_indexed_function_names_itself_not_only_its_callees() {
    let s = Scratch::new("selfname");
    let (caller, _) = find_call_pair(&s);
    let dump = s.write_dump("self.json", &[(rva_of(&caller), "Inventory$$CommitSlot")]);
    let (v, ok) = s.run(&["il2cpp", "import", "--script-json", dump.to_str().unwrap(), "--file", &fixture()]);
    assert!(ok, "{v}");

    let (v, ok) = s.run(&["decomp", "pseudo", "--file", &fixture(), "--addr", &caller]);
    assert!(ok, "{v}");
    let sig = v["data"]["signature"].as_str().unwrap();
    assert!(sig.contains("Inventory"), "the signature line should carry the managed name: {sig}");
    assert!(!sig.contains("sub_"), "the address placeholder should be gone: {sig}");
    // The body's opening line is built from the same string — one fix, both places.
    let first = v["data"]["pseudo"][0].as_str().unwrap();
    assert!(first.contains("Inventory"), "the rendered body should open with the same name: {first}");
}

#[test]
fn a_symbol_that_merely_covers_the_address_does_not_name_the_function() {
    // Soundness: the index attributes a whole span to its symbol, so a query
    // anywhere inside answers. Naming a function from a *near* hit would label
    // it after whichever one precedes it — the exact confident-wrong-name
    // failure this corpus makes easy.
    let s = Scratch::new("nearmiss");
    let (caller, _) = find_call_pair(&s);
    let just_below = rva_of(&caller) - 0x10;
    let dump = s.write_dump("near.json", &[(just_below, "NotThisOne$$Method")]);
    let (v, ok) = s.run(&["il2cpp", "import", "--script-json", dump.to_str().unwrap(), "--file", &fixture()]);
    assert!(ok, "{v}");

    let (v, ok) = s.run(&["decomp", "pseudo", "--file", &fixture(), "--addr", &caller]);
    assert!(ok, "{v}");
    let sig = v["data"]["signature"].as_str().unwrap();
    assert!(!sig.contains("NotThisOne"), "only an exact hit on the function start may name it: {sig}");
    assert!(sig.contains("sub_"), "with no exact hit the address stands in, as it always did: {sig}");
}

#[test]
fn range_scoped_analysis_gets_managed_names_too() {
    // `ir manifest` discovers functions over a range and ranks them; it went
    // through the range-scoped helper, which did not chain the index — so a
    // triage listing stayed a wall of `sub_` on a target whose names were
    // sitting in the project. Triage is where names matter most: it is read as
    // a list, not one address at a time.
    let s = Scratch::new("manifest");
    let (caller, _) = find_call_pair(&s);
    let rva = rva_of(&caller);
    let dump = s.write_dump("m.json", &[(rva, "CombatResolver$$Resolve")]);
    let (v, ok) = s.run(&["il2cpp", "import", "--script-json", dump.to_str().unwrap(), "--file", &fixture()]);
    assert!(ok, "{v}");

    let start = format!("0x{:x}", IMAGE_BASE + rva);
    let (v, ok) = s.run(&["ir", "manifest", "--file", &fixture(), "--start", &start, "--size", "0x40", "--limit", "8"]);
    assert!(ok, "{v}");
    let body = v.to_string();
    assert!(body.contains("CombatResolver"), "a discovered function with an indexed start must carry its managed name: {body}");
    let note = v["meta"]["note"].as_str().unwrap_or_default();
    assert!(note.contains("il2cpp index"), "and the response must say which layer named it: {note}");
}

#[test]
fn a_covering_symbol_does_not_name_a_discovered_function() {
    // The span-attribution half of the exact-hit rule, asserted where a real
    // span-attributing provider exists: an imported index answers for any
    // address inside a function, so a candidate discovered *after* a symbol's
    // start must not inherit its name.
    let s = Scratch::new("mfnearmiss");
    let (caller, _) = find_call_pair(&s);
    let rva = rva_of(&caller);
    let dump = s.write_dump("near.json", &[(rva - 0x20, "NotThisOne$$Method")]);
    let (v, ok) = s.run(&["il2cpp", "import", "--script-json", dump.to_str().unwrap(), "--file", &fixture()]);
    assert!(ok, "{v}");

    let start = format!("0x{:x}", IMAGE_BASE + rva);
    let (v, ok) = s.run(&["ir", "manifest", "--file", &fixture(), "--start", &start, "--size", "0x40", "--limit", "8"]);
    assert!(ok, "{v}");
    assert!(!v.to_string().contains("NotThisOne"), "a symbol that merely covers the address must not name the function: {v}");
}

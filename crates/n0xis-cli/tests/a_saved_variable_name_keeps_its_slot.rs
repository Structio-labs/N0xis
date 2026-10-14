// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A variable name or type the user saved stays on the variable it was saved
//! for, across a change of the names the decompiler synthesizes.**
//!
//! A stack local's annotation is stored under the local's synthesized name. That
//! name was `local_<hex>` of the offset's magnitude, so `rsp + 8` and `rsp - 8`
//! were both `local_8`; it is now signed (`local_8` / `local_neg_8`). Read by the
//! current naming, a `local_8` saved for the `-8` slot attached to the `+8` slot
//! of any function that has one — a different variable, silently — and to
//! nothing in one that has only `-8`.
//!
//! The image is `fixtures/stack_slots.so`, built from `fixtures/stack_slots.s`:
//! four functions whose whole bodies are the stack loads that define their
//! slots, at addresses read with `nm`. The saved annotations are
//! `fixtures/stack_slots_v1_annotations.json`, **written by the build before the
//! version field existed** (`annotate var/vartype` with no image, so nothing
//! checked the key): it pins the format an existing project has on disk.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

mod support;

/// `both_slots`: `rsp + 8` and `rsp - 8`.
const BOTH: &str = "0x1000";
/// `below_only`: `rsp - 8`.
const BELOW: &str = "0x100b";
/// `above_only`: `rsp + 8`.
const ABOVE: &str = "0x1011";
/// `other_slot`: `rsp + 0x10`, neither slot the earlier `local_8` named.
const OTHER: &str = "0x1017";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

fn image() -> String {
    fixture("stack_slots.so").to_str().expect("utf-8 path").to_string()
}

/// One envelope, or — when the binary printed none, as an older build does for
/// a flag it does not know — an object saying so, so the failure lands on the
/// caller's assertion and not inside this helper.
fn envelope(out: &std::process::Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
        serde_json::json!({
            "unparsed": String::from_utf8_lossy(&out.stdout),
            "stderr": String::from_utf8_lossy(&out.stderr),
        })
    })
}

/// A temp folder with its own `.n0x/` — without one the engine writes to the
/// user's global project — holding the given annotations file, if any.
struct Project {
    dir: PathBuf,
}

impl Project {
    fn new(tag: &str, annotations: Option<&Path>) -> Self {
        let dir = std::env::temp_dir().join(format!("n0xis-var-slot-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".n0x")).expect("temp project");
        if let Some(src) = annotations {
            std::fs::copy(src, dir.join(".n0x/annotations.json")).expect("plant annotations");
        }
        Project { dir }
    }

    fn with_v1_annotations(tag: &str) -> Self {
        Project::new(tag, Some(&fixture("stack_slots_v1_annotations.json")))
    }

    fn run(&self, args: &[&str]) -> Value {
        let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
            .current_dir(&self.dir)
            .args(args)
            .arg("--quiet")
            .output()
            .expect("run n0xis");
        envelope(&out)
    }

    fn decomp(&self, addr: &str) -> Value {
        self.run(&["decomp", "pseudo", "--file", &image(), "--addr", addr])
    }

    /// The annotations file as it is on disk.
    fn stored(&self) -> Value {
        let raw = std::fs::read_to_string(self.dir.join(".n0x/annotations.json")).expect("annotations.json");
        serde_json::from_str(&raw).expect("annotations.json is JSON")
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn pseudo(decomp: &Value) -> String {
    decomp["data"]["pseudo"].as_array().map(|l| l.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n")).unwrap_or_default()
}

fn note(answer: &Value) -> &str {
    answer["meta"]["note"].as_str().unwrap_or("")
}

/// The `-8` slot is the only one `local_8` can have meant here: it takes the
/// saved name and the saved type, and the answer says where they came from.
/// The current naming read `local_8` as `+8`, which this function does not
/// have, and applied neither.
#[test]
fn an_earlier_key_lands_on_the_one_slot_below() {
    let p = Project::with_v1_annotations("below");
    let d = p.decomp(BELOW);
    assert_eq!(d["ok"], true, "{d}");
    let text = pseudo(&d);
    assert!(text.contains("int64_t planted_below;"), "the -8 slot takes the name and the type saved as `local_8`:\n{text}");
    assert!(!text.contains("local_neg_8"), "{text}");
    assert!(note(&d).contains("planted_below") && note(&d).contains("applied there"), "{d}");
}

/// The `+8` slot is the only one here: it takes the saved name.
#[test]
fn an_earlier_key_lands_on_the_one_slot_above() {
    let p = Project::with_v1_annotations("above");
    let d = p.decomp(ABOVE);
    assert_eq!(d["ok"], true, "{d}");
    let text = pseudo(&d);
    assert!(text.contains("planted_above"), "the +8 slot takes the name saved as `local_8`:\n{text}");
}

/// Both slots exist: `local_8` may have meant either, so it is applied to
/// neither, and every answer that shows the function's annotations says so,
/// naming the key and both slots. The current naming put it on `+8`.
#[test]
fn an_earlier_key_with_both_slots_present_lands_on_neither_and_says_so() {
    let p = Project::with_v1_annotations("both");
    let d = p.decomp(BOTH);
    assert_eq!(d["ok"], true, "{d}");
    let text = pseudo(&d);
    assert!(!text.contains("planted_both"), "applied to a slot it may not have meant:\n{text}");
    assert!(text.contains("local_8") && text.contains("local_neg_8"), "{text}");
    let says_so = |n: &str| n.contains("planted_both") && n.contains("`local_8`") && n.contains("`local_neg_8`");
    assert!(says_so(note(&d)), "the decompile names the key and both slots: {d}");

    let shown = p.run(&["annotate", "show", "--addr", BOTH, "--file", &image()]);
    assert!(says_so(note(&shown)), "`annotate show` with the image names the key and both slots: {shown}");

    // A `serve` session supplies its own image to `annotate show`.
    let mut session = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
        .current_dir(&p.dir)
        .args(["serve", "--quiet", "--file", &image()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn serve");
    {
        use std::io::Write;
        let mut stdin = session.stdin.take().expect("stdin");
        writeln!(stdin, "annotate show --addr {BOTH}").expect("write line");
        writeln!(stdin).expect("a blank line ends the session");
    }
    let out = session.wait_with_output().expect("serve");
    let answer: Value = String::from_utf8_lossy(&out.stdout).lines().nth(1).and_then(|l| serde_json::from_str(l).ok()).unwrap_or(Value::Null);
    assert!(says_so(note(&answer)), "a session's `annotate show` places against the session's image: {answer}");

    // With no image there is no function to place it against; the answer
    // says the key depends on one.
    let unchecked = p.run(&["annotate", "show", "--addr", BOTH]);
    assert!(unchecked["meta"]["note"].as_str().is_some_and(|n| n.contains("planted_both") && n.contains("--file")), "{unchecked}");
}

/// Neither slot exists: applied nowhere, as before, and the answer says so.
#[test]
fn an_earlier_key_with_neither_slot_present_lands_nowhere() {
    let p = Project::with_v1_annotations("neither");
    let d = p.decomp(OTHER);
    assert_eq!(d["ok"], true, "{d}");
    let text = pseudo(&d);
    assert!(text.contains("local_10") && !text.contains("planted_none"), "{text}");
    assert!(note(&d).contains("planted_none") && note(&d).contains("none of them"), "{d}");
}

/// A write to a version-1 record moves every key that lands on one slot to
/// that slot's current name, keeps the value, records the move, and makes the
/// record version 2. The rest of the file is rewritten as version 2 too, each
/// earlier key set aside with its value.
#[test]
fn a_write_moves_a_version_1_record_onto_the_current_naming() {
    let p = Project::with_v1_annotations("migrate");
    let w = p.run(&["annotate", "vartype", "--file", &image(), "--addr", BELOW, "--var", "local_neg_8", "--value", "char *"]);
    assert_eq!(w["ok"], true, "{w}");

    let rec = &p.stored()[BELOW];
    assert_eq!(rec["var_names"], serde_json::json!({ "local_neg_8": "planted_below" }), "the name moved to the slot it meant: {rec}");
    assert_eq!(rec["var_types"], serde_json::json!({ "local_neg_8": "char *" }), "{rec}");
    assert_eq!(rec["var_key_version"], 2, "{rec}");
    let moved = rec["history"].as_array().into_iter().flatten().any(|h| h["field"] == "var-key" && h["old"] == "local_8" && h["new"] == "local_neg_8");
    assert!(moved, "the move is in the record's history: {rec}");
    let stored = p.stored();
    for (untouched, value) in [(BOTH, "planted_both"), (ABOVE, "planted_above"), (OTHER, "planted_none")] {
        let rec = &stored[untouched];
        assert_eq!(rec["var_key_version"], 2, "{rec}");
        assert_eq!(rec["earlier_var_names"]["local_8"], value, "kept aside, never read as a current key: {rec}");
        assert!(rec.get("var_names").is_none(), "{rec}");
    }

    let text = pseudo(&p.decomp(BELOW));
    assert!(text.contains("char * planted_below;"), "{text}");
}

/// A write elsewhere in a function whose earlier key is ambiguous never drops
/// that key's value and never lets it land on a slot: it stays, with the note.
#[test]
fn a_write_keeps_an_ambiguous_earlier_key_and_its_note() {
    let p = Project::with_v1_annotations("keep");
    let w = p.run(&["annotate", "var", "--file", &image(), "--addr", BOTH, "--var", "local_neg_8", "--value", "fresh_below"]);
    assert_eq!(w["ok"], true, "{w}");
    assert_eq!(p.stored()[BOTH]["earlier_var_names"]["local_8"], "planted_both", "the user's value is kept");
    assert!(note(&w).contains("planted_both"), "the write's answer names what is still not applied: {w}");

    let d = p.decomp(BOTH);
    let text = pseudo(&d);
    assert!(text.contains("fresh_below") && !text.contains("planted_both"), "{text}");
    assert!(note(&d).contains("planted_both"), "{d}");
}

/// A write to the very name an ambiguous earlier key has lands on the current
/// variable of that name and never overwrites the earlier value: both stay.
#[test]
fn an_ambiguous_earlier_key_survives_a_write_to_the_same_name() {
    let p = Project::with_v1_annotations("same");
    let w = p.run(&["annotate", "var", "--file", &image(), "--addr", BOTH, "--var", "local_8", "--value", "fresh_above"]);
    assert_eq!(w["ok"], true, "{w}");
    let rec = &p.stored()[BOTH];
    assert_eq!(rec["var_names"]["local_8"], "fresh_above", "{rec}");
    assert_eq!(rec["earlier_var_names"]["local_8"], "planted_both", "{rec}");

    let d = p.decomp(BOTH);
    let text = pseudo(&d);
    assert!(text.contains("fresh_above") && text.contains("local_neg_8") && !text.contains("planted_both"), "{text}");
    assert!(note(&d).contains("planted_both"), "{d}");
}

/// With no image a write settles nothing, and the earlier key stays aside; the
/// next write that names the image — whose function has one of the two slots —
/// settles it there.
#[test]
fn a_later_write_settles_an_earlier_key_once_the_image_disambiguates() {
    let p = Project::with_v1_annotations("settle");
    let blind = p.run(&["annotate", "vartype", "--addr", BELOW, "--var", "@return", "--value", "int"]);
    assert_eq!(blind["ok"], true, "{blind}");
    assert_eq!(p.stored()[BELOW]["earlier_var_names"]["local_8"], "planted_below", "nothing to settle it against");

    let seen = p.run(&["annotate", "vartype", "--file", &image(), "--addr", BELOW, "--var", "@return", "--value", "long"]);
    assert_eq!(seen["ok"], true, "{seen}");
    let rec = &p.stored()[BELOW];
    assert_eq!(rec["var_names"], serde_json::json!({ "local_neg_8": "planted_below" }), "{rec}");
    assert!(rec.get("earlier_var_names").is_none(), "{rec}");
}

/// A key written now is exact: `local_8` is the `+8` slot, though the function
/// has `-8` as well.
#[test]
fn a_version_2_key_is_exact() {
    let p = Project::new("v2", None);
    let w = p.run(&["annotate", "var", "--file", &image(), "--addr", BOTH, "--var", "local_8", "--value", "written_now"]);
    assert_eq!(w["ok"], true, "{w}");
    assert_eq!(p.stored()[BOTH]["var_key_version"], 2, "a record written now is version 2");

    let d = p.decomp(BOTH);
    let text = pseudo(&d);
    assert!(text.contains("written_now") && text.contains("local_neg_8"), "`local_8` is +8 exactly:\n{text}");
    assert!(!note(&d).contains("written_now"), "{d}");
}

/// The file an existing project has — no version field anywhere — loads, every
/// saved value reads back, and reading it never rewrites it.
#[test]
fn a_file_without_the_version_field_still_loads() {
    let raw = std::fs::read_to_string(fixture("stack_slots_v1_annotations.json")).expect("fixture");
    assert!(!raw.contains("var_key_version"), "the fixture is the format from before the field");

    let p = Project::with_v1_annotations("load");
    let list = p.run(&["annotate", "list"]);
    assert_eq!(list["ok"], true, "{list}");
    assert_eq!(list["data"]["count"], 4, "{list}");
    let shown = p.run(&["annotate", "show", "--addr", BELOW]);
    assert_eq!(shown["ok"], true, "{shown}");
    assert_eq!(shown["data"]["earlier_var_names"]["local_8"], "planted_below", "{shown}");
    assert_eq!(shown["data"]["earlier_var_types"]["local_8"], "int64_t", "{shown}");
    for addr in [BOTH, BELOW, ABOVE, OTHER] {
        assert_eq!(p.decomp(addr)["ok"], true);
    }
    let after = std::fs::read_to_string(p.dir.join(".n0x/annotations.json")).expect("annotations.json");
    assert_eq!(after, raw, "nobody wrote, so the file keeps its bytes");
}

/// A store this build cannot read — here, a record of a version it does not
/// know — is said, never swallowed: a decompile still renders and names the
/// error, `annotate show` and `list` answer with it, and every write refuses,
/// so the record it cannot read is never written over.
#[test]
fn an_unreadable_store_is_said_and_never_overwritten() {
    let p = Project::new("unreadable", None);
    let store = format!(
        r#"{{ "{BOTH}": {{ "va": "{BOTH}", "var_names": {{ "local_8": "from_a_newer_build" }}, "var_key_version": 99 }} }}"#
    );
    let path = p.dir.join(".n0x/annotations.json");
    std::fs::write(&path, &store).expect("plant");

    let d = p.decomp(ABOVE);
    assert_eq!(d["ok"], true, "the decompile still renders: {d}");
    assert!(note(&d).contains("annotations could not be read") && note(&d).contains("99"), "{d}");

    let shown = p.run(&["annotate", "show", "--addr", BOTH]);
    assert_eq!(shown["ok"], false, "{shown}");
    assert!(shown["error"]["message"].as_str().is_some_and(|m| m.contains("99")), "{shown}");
    assert_eq!(p.run(&["annotate", "list"])["ok"], false);

    for write in [
        vec!["annotate", "comment", "--addr", ABOVE, "--value", "x"],
        vec!["annotate", "var", "--addr", ABOVE, "--var", "local_8", "--value", "x"],
        vec!["annotate", "bookmark", "--addr", ABOVE],
    ] {
        assert_eq!(p.run(&write)["ok"], false, "{write:?}");
    }
    assert_eq!(std::fs::read_to_string(&path).expect("store"), store, "the record it cannot read is untouched");
}

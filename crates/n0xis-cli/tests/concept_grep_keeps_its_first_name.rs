// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`concept grep` was renamed from `game grep`; the catalog shows one name and
//! the old one still runs.**
//!
//! Two promises, each of which can break without anything else noticing:
//!
//! - `n0x guide` is what an agent reads instead of guessing. It must list the
//!   command under its current name, in its category, and must not list the
//!   old name beside it — a second entry would also move the command count the
//!   documents state.
//! - Every script written against `game grep` must keep getting the same
//!   answer. The parse-level check lives beside the CLI definition
//!   (`concept_alias_tests` in `main.rs`); this one runs the binary on a
//!   directory planted here, whose answer is known before either spelling is
//!   asked, and requires both spellings to return it.
//! - A consumer dispatching on `meta.schema` must keep working too. The first
//!   release answered `n0xis.game.grep.v1`; the old spelling still does, and
//!   only the new spelling answers `n0xis.concept.grep.v1` — one-shot and
//!   inside a `serve` session, where the spelling is the request line's own.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

fn run(args: &[&str]) -> Value {
    let out = Command::new(env!("CARGO_BIN_EXE_n0xis")).args(args).output().expect("run n0xis");
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("`n0xis {}` printed no envelope ({e}); stderr: {}", args.join(" "), String::from_utf8_lossy(&out.stderr)))
}

/// Every leaf command in the catalog, as `(path, category)`.
fn catalog() -> Vec<(String, String)> {
    let v = run(&["guide", "--brief", "--quiet"]);
    assert_eq!(v["ok"], Value::Bool(true), "guide failed: {v}");
    v["data"]["commands"]
        .as_array()
        .expect("guide carries a command array")
        .iter()
        .map(|c| {
            (
                c["path"].as_str().expect("every command has a path").to_string(),
                c["category"].as_str().expect("every command has a category").to_string(),
            )
        })
        .collect()
}

#[test]
fn the_guide_does_not_list_the_first_name() {
    let old: Vec<String> = catalog().into_iter().map(|(p, _)| p).filter(|p| p.split(' ').next() == Some("game")).collect();
    assert!(old.is_empty(), "the guide lists the retired name `game`: {old:?}");
}

#[test]
fn the_guide_lists_concept_grep_in_the_method_tooling_category() {
    let cat = catalog();
    let found = cat.iter().find(|(p, _)| p == "concept grep");
    assert!(found.is_some(), "the guide does not list `concept grep`");
    // The category map is keyed by the top-level name, so a rename that misses
    // it drops the command into "Other" without any other test noticing.
    assert_eq!(found.map(|(_, c)| c.as_str()), Some("Spec-first method tooling (Phase 8)"));
}

/// A directory whose ranking is known by construction: one file carries two of
/// the three terms, one carries one, one carries none.
fn plant(dir: &Path) {
    std::fs::create_dir_all(dir).expect("temp dir");
    std::fs::write(dir.join("both.txt"), "call retry() then backoff(250)\n").expect("write");
    std::fs::write(dir.join("one.txt"), "timeout = 30\n").expect("write");
    std::fs::write(dir.join("none.txt"), "nothing to see here\n").expect("write");
}

/// The schema id each spelling must answer with — written out, not read from
/// the contracts crate, because these strings are the wire contract itself.
const NEW_ID: &str = "n0xis.concept.grep.v1";
const OLD_ID: &str = "n0xis.game.grep.v1";

/// The envelope with `meta.schema` taken out, after checking it is `id`. The
/// two spellings differ there on purpose and must agree on everything else.
fn without_schema(mut v: Value, id: &str, who: &str) -> Value {
    assert_eq!(v["meta"]["schema"], id, "{who} answered under the wrong schema id: {v}");
    v["meta"].as_object_mut().expect("a success carries meta").remove("schema");
    v
}

#[test]
fn both_names_return_the_same_answer_on_a_planted_directory() {
    let dir: PathBuf = std::env::temp_dir().join(format!("n0xis_concept_grep_{}", std::process::id()));
    plant(&dir);
    let d = dir.to_string_lossy().to_string();
    let new = run(&["concept", "grep", "retry,backoff,timeout", "--dir", &d, "--quiet"]);
    let old = run(&["game", "grep", "retry,backoff,timeout", "--dir", &d, "--quiet"]);
    let _ = std::fs::remove_dir_all(&dir);

    // The planted answer first, so the comparison below cannot pass by both
    // spellings failing, or both answering nothing, in the same way.
    assert_eq!(new["ok"], Value::Bool(true), "concept grep failed: {new}");
    assert_eq!(new["data"]["documents_scanned"], 3);
    assert_eq!(new["data"]["documents_matched"], 2);
    let top = new["data"]["hits"][0]["id"].as_str().unwrap_or_default();
    assert!(top.ends_with("both.txt"), "the two-term file must rank first, got {top:?}");

    // Each spelling answers under its own id, and nothing else may differ.
    let new = without_schema(new, NEW_ID, "`concept grep`");
    let old = without_schema(old, OLD_ID, "`game grep`");
    assert_eq!(old, new, "`game grep` and `concept grep` answered differently");
}

/// Global flags may stand anywhere, including between the two words; the
/// spelling must still be read off the words themselves.
#[test]
fn the_spelling_survives_global_flags_between_the_words() {
    let dir: PathBuf = std::env::temp_dir().join(format!("n0xis_concept_grep_flags_{}", std::process::id()));
    plant(&dir);
    let d = dir.to_string_lossy().to_string();
    let old = run(&["--quiet", "game", "--pretty", "grep", "retry", "--dir", &d]);
    let new = run(&["--quiet", "concept", "--pretty", "grep", "retry", "--dir", &d]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(old["meta"]["schema"], OLD_ID, "{old}");
    assert_eq!(new["meta"]["schema"], NEW_ID, "{new}");
}

/// Inside a `serve` session each request line is parsed on its own, so the
/// spelling has to come from that line, not from the `serve` command line.
/// Both forms of request the session accepts are sent: a plain line and a JSON
/// array of argument strings.
#[test]
fn inside_a_session_each_line_answers_under_its_own_spelling() {
    let dir: PathBuf = std::env::temp_dir().join(format!("n0xis_concept_grep_serve_{}", std::process::id()));
    plant(&dir);
    let d = dir.to_string_lossy().to_string();
    // The session needs an image to load; this test's own executable is one.
    let image = std::env::current_exe().expect("test exe");
    let mut child = Command::new(env!("CARGO_BIN_EXE_n0xis"))
        .args(["serve", "--quiet", "--file"])
        .arg(&image)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn serve");
    let dir_json = serde_json::to_string(&d).expect("json string");
    let lines = [
        format!("game grep retry,backoff,timeout --dir {d}"),
        format!("concept grep retry,backoff,timeout --dir {d}"),
        format!(r#"["game","grep","retry,backoff,timeout","--dir",{dir_json}]"#),
        format!(r#"["concept","grep","retry,backoff,timeout","--dir",{dir_json}]"#),
    ];
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for l in &lines {
            writeln!(stdin, "{l}").expect("write request");
        }
        writeln!(stdin).expect("a blank line ends the session");
    }
    let out = child.wait_with_output().expect("serve exits");
    let _ = std::fs::remove_dir_all(&dir);
    let answers: Vec<Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not an envelope ({e}): {l}")))
        .collect();
    // The banner, then one answer per request line.
    assert_eq!(answers.len(), 1 + lines.len(), "answers: {answers:?}");
    assert_eq!(answers[0]["meta"]["schema"], "n0xis.serve.ready.v1", "banner: {}", answers[0]);
    let want = [OLD_ID, NEW_ID, OLD_ID, NEW_ID];
    let mut bodies = Vec::new();
    for ((line, answer), id) in lines.iter().zip(&answers[1..]).zip(want) {
        assert_eq!(answer["ok"], Value::Bool(true), "`{line}` failed: {answer}");
        assert_eq!(answer["data"]["documents_matched"], 2, "`{line}` lost the planted answer: {answer}");
        bodies.push(without_schema(answer.clone(), id, line));
    }
    assert!(bodies.windows(2).all(|w| w[0] == w[1]), "the four requests answered differently: {bodies:?}");
}

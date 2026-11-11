// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **What a decompile asked of the image's functions is kept, for that image only.**
//!
//! `decomp pseudo` asks every callee what it takes, what it gives back and whether
//! it comes back, a few calls down. The command line runs one process a function,
//! and each asked them all again: a body took twice as long. The answers are kept
//! in `.n0x/answers-cache/`, one entry an image, keyed by the image's bytes, its
//! names, the decoder and the engine's build.
//!
//! Here a planted answer stands for a kept one: `two` is said to take nothing. A
//! second function's call to it, decompiled in another process, has to show that
//! answer, which proves the entry is read; the same image with one byte added at
//! its end has to show what `two` really takes, which proves the key is the image.
//!
//! It spawns a C compiler, so it is a local instrument (`--features oracle`), and
//! there a compiler that is not there fails it: a skip would read as a pass.

#![cfg(all(target_os = "linux", feature = "oracle"))]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

mod support;

const SOURCE: &str = r#"
__attribute__((noipa)) int two(int a, int b) { return a * b + 3; }
__attribute__((noipa)) int first(int x) { return two(x, x + 1) + 1; }
__attribute__((noipa)) int second(int y) { return two(y, 7) - 2; }
int main(int c, char **v) { (void)v; return first(c) + second(c); }
"#;

fn build(dir: &Path) -> PathBuf {
    let src = dir.join("kept.c");
    std::fs::write(&src, SOURCE).expect("write the source");
    let file = dir.join("kept");
    let out = Command::new("cc").args(["-O2", "-o"]).arg(&file).arg(&src).output().expect("cc, which this instrument needs");
    assert!(out.status.success(), "cc could not build: {}", String::from_utf8_lossy(&out.stderr));
    file
}

/// `nm`'s address for `name`.
fn symbol(file: &Path, name: &str) -> u64 {
    let out = Command::new("nm").env("LC_ALL", "C").arg(file).output().expect("nm");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| {
            let mut w = l.split_whitespace();
            let (addr, _kind, n) = (w.next()?, w.next()?, w.next()?);
            (n == name).then(|| u64::from_str_radix(addr, 16).expect("hex"))
        })
        .unwrap_or_else(|| panic!("nm lists no {name}"))
}

/// The line of `function`'s body that calls `two`, decompiled in `project`.
fn call_to_two(project: &Path, file: &Path, function: u64) -> String {
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
        .current_dir(project)
        .args(["decomp", "pseudo", "--quiet", "--addr", &format!("{function:#x}"), "--file"])
        .arg(file)
        .output()
        .expect("run n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).expect("one envelope");
    assert_eq!(v["ok"], true, "{v}");
    let lines: Vec<&str> = v["data"]["pseudo"].as_array().expect("lines").iter().filter_map(Value::as_str).collect();
    lines.iter().find(|l| l.contains("two(")).unwrap_or_else(|| panic!("no call to two in {lines:#?}")).to_string()
}

fn entries(project: &Path) -> Vec<PathBuf> {
    match std::fs::read_dir(project.join(".n0x/answers-cache")) {
        Ok(d) => d.map(|e| e.expect("entry").path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect(),
        Err(_) => Vec::new(),
    }
}

#[test]
fn a_kept_answer_is_read_and_only_for_its_image() {
    let dir = std::env::temp_dir().join(format!("n0xis_kept_answers_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("project");
    let file = build(&dir);
    let (two, first, second) = (symbol(&file, "two"), symbol(&file, "first"), symbol(&file, "second"));

    let asked = call_to_two(&dir, &file, first);
    assert_eq!(asked.matches(',').count(), 1, "two takes two arguments, as its source says: {asked}");
    let kept = entries(&dir);
    assert_eq!(kept.len(), 1, "one entry for the one image asked about: {kept:?}");

    // Plant: `two` takes nothing, at every depth it was asked.
    let mut answers: Value = serde_json::from_str(&std::fs::read_to_string(&kept[0]).expect("read")).expect("json");
    let mut planted = 0;
    for t in answers["takes"].as_array_mut().expect("takes") {
        if t[0].as_u64() == Some(two) {
            t[2] = serde_json::json!({ "Exactly": 0 });
            planted += 1;
        }
    }
    assert!(planted > 0, "the entry holds what two takes: {answers}");
    std::fs::write(&kept[0], answers.to_string()).expect("plant");

    let read = call_to_two(&dir, &file, second);
    assert!(read.contains("two()"), "the kept answer is what another process reads: {read}");

    // The same program with one byte more is another image.
    let other = dir.join("kept-other");
    let mut bytes = std::fs::read(&file).expect("read the image");
    bytes.push(0);
    std::fs::write(&other, bytes).expect("write the other image");
    let fresh = call_to_two(&dir, &other, second);
    assert_eq!(fresh.matches(',').count(), 1, "another image is not answered from this one's entry: {fresh}");
    assert_eq!(entries(&dir).len(), 2, "and keeps its own");
    let _ = std::fs::remove_dir_all(&dir);
}

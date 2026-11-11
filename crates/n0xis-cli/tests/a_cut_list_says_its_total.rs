// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A list cut at a limit says how long it was.** The claims audit of 2026-11-06
//! found four answers that looked whole and were not: `ir manifest` said `count:
//! 200` of 1126 functions, `mem map` `count: 256` of a map of 440, and `function
//! layout` and `function typeflow` `considered: 400` of 1126, none with a word that
//! the rest had not been looked at. Each now carries `total` and `truncated`.
//!
//! `mem map` is held against the kernel's own map of a child, `/proc/<pid>/maps`.
//! The function lists are held against the same command with no limit: what is
//! checked is that the cut answer states the whole list's length, and the whole
//! list is longer than the cut on this image (nm: seven functions in `.text`).

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

mod support;

const IMAGE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/strings_planted.so");

fn project(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis-cut-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("scratch dir");
    dir
}

fn ok(dir: &Path, args: &[&str]) -> Value {
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).current_dir(dir).output().expect("run n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{args:?}: {e}\n{}", String::from_utf8_lossy(&out.stdout)));
    assert_eq!(v["ok"], true, "{args:?}: {v}");
    v["data"].clone()
}

/// `(listed, total, truncated)` of a cut answer, by the name the command gives its count.
fn cut(d: &Value, count: &str) -> (u64, u64, bool) {
    (d[count].as_u64().unwrap_or_else(|| panic!("no {count}: {d}")), d["total"].as_u64().unwrap_or_else(|| panic!("no total: {d}")), d["truncated"].as_bool().unwrap_or_else(|| panic!("no truncated: {d}")))
}

#[test]
fn a_function_list_cut_at_a_limit_says_its_total() {
    let dir = project("functions");
    for (cmd, count) in [(&["ir", "manifest"][..], "count"), (&["function", "typeflow"][..], "considered"), (&["function", "layout"][..], "considered")] {
        let with = |limit: &str| {
            let mut a: Vec<&str> = cmd.to_vec();
            a.extend(["--file", IMAGE, "--limit", limit]);
            ok(&dir, &a)
        };
        let all = with("0");
        let (n, total, truncated) = cut(&all, count);
        assert_eq!((n, truncated), (total, false), "{cmd:?} with no limit lists all: {all}");
        assert!(total > 2, "{cmd:?}: the image has more than two functions (nm lists seven in .text): {all}");
        let two = with("2");
        assert_eq!(cut(&two, count), (2, total, true), "{cmd:?} cut at two says how many there were: {two}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(target_os = "linux")]
#[test]
fn a_memory_map_cut_at_a_limit_says_its_total() {
    // A target that lets this test's other child, n0xis, read it.
    let src = r#"
        unsafe extern "C" { fn prctl(o: i32, a: u64, b: u64, c: u64, d: u64) -> i32; }
        fn main() {
            unsafe { prctl(0x59616d61, u64::MAX, 0, 0, 0) };
            println!("ready");
            let mut s = String::new();
            let _ = std::io::stdin().read_line(&mut s);
        }
    "#;
    let build = project("map-build");
    let exe = build.join("target");
    std::fs::write(build.join("target.rs"), src).expect("write the target");
    let out = Command::new("rustc").args(["-O", "-o"]).arg(&exe).arg(build.join("target.rs")).output().expect("rustc");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let mut child = Command::new(&exe).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().expect("spawn the target");
    {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut line).expect("ready");
        assert_eq!(line.trim(), "ready");
    }
    let pid = child.id().to_string();
    let dir = project("map");
    let lines = std::fs::read_to_string(format!("/proc/{pid}/maps")).expect("the kernel's map").lines().count() as u64;
    assert!(lines > 3, "a process has more than three mappings: {lines}");
    let d = ok(&dir, &["mem", "map", "--pid", &pid, "--limit", "3"]);
    let whole = ok(&dir, &["mem", "map", "--pid", &pid, "--limit", "0"]);
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(cut(&d, "count"), (3, lines, true), "{d}");
    assert_eq!(cut(&whole, "count"), (lines, lines, false), "{whole}");
    let _ = std::fs::remove_dir_all(&dir);
}

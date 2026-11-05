// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **On a real LuaJIT, the header chosen is the one that gives the bases the VM states
//! about itself.** The script prints each string's and table's address through its own
//! `%p`, and the size of its header through the FFI, so the answer does not come from
//! n0xis. Needs a `luajit` on the machine, so it is an `oracle` test: it depends on what
//! is installed, and does not gate CI.
#![cfg(all(target_os = "linux", feature = "oracle"))]

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::Value;

mod support;

/// Yama lets only an ancestor read a process, and n0xis runs as a sibling: the script
/// grants the read itself.
const SCRIPT: &str = r#"
local ffi = require("ffi")
ffi.cdef[[int prctl(int, unsigned long, unsigned long, unsigned long, unsigned long);]]
ffi.C.prctl(0x59616d61, -1ULL, 0, 0, 0)
local t = {"zorkmid", "quuxian", "quuxian", "zorkmid", "blargle"}
print("gc64", ffi.abi("gc64"))
print("zorkmid", string.format("%p", "zorkmid"))
print("quuxian", string.format("%p", "quuxian"))
print("blargle", string.format("%p", "blargle"))
print("table", string.format("%p", t))
print("ready")
io.stdout:flush()
io.read("*l")
print(#t)
"#;

#[test]
fn the_chosen_header_gives_the_bases_the_vm_prints() {
    let dir = std::env::temp_dir().join(format!("n0xis-real-luajit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("scratch dir");
    let script = dir.join("t.lua");
    std::fs::write(&script, SCRIPT).expect("write the script");
    let mut child = Command::new("luajit").arg(&script).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("spawn luajit");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut said = std::collections::HashMap::new();
    loop {
        let mut line = String::new();
        assert!(stdout.read_line(&mut line).expect("read the script") > 0, "the script ended early");
        let mut f = line.split_whitespace();
        let key = f.next().expect("a key").to_string();
        if key == "ready" {
            break;
        }
        said.insert(key, f.next().expect("a value").to_string());
    }
    // `len` by LuaJIT's own `GCstr`: 0x14 where a `GCRef` is 8 bytes, else 0x10 in 2.1.
    let want = if said["gc64"] == "true" { "0x14" } else { "0x10" };

    let run = |args: &[&str]| -> Value {
        let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).current_dir(&dir).output().expect("run n0xis");
        let v: Value = serde_json::from_slice(&out.stdout).expect("one JSON object");
        assert_eq!(v["ok"], true, "{args:?}: {v}");
        v["data"].clone()
    };
    let pid = child.id().to_string();
    let d = run(&["lua", "combo", "--pid", &pid, "--strings", "zorkmid,quuxian,blargle"]);
    eprintln!("{}", d["layout"]);
    assert_eq!(d["layout"]["len_offset"], want, "{d}");
    assert_eq!(d["layout"]["chosen_by"], "references", "{d}");
    for name in ["zorkmid", "quuxian", "blargle"] {
        let t = d["targets"].as_array().expect("targets").iter().find(|t| t["text"] == name && t["addr"] == said[name].as_str());
        let t = t.unwrap_or_else(|| panic!("the base `%p` printed for {name}, {}: {d}", said[name]));
        assert!(t["references"].as_u64().expect("a count") > 0, "{d}");
        assert!(t["in_values"].as_u64().expect("a count") > 0, "the table holds it: {d}");
    }
    let run_of_five = d["runs"].as_array().expect("runs").iter().find(|r| r["kind"] == "tvalue8" && r["len"] == 5);
    let run_of_five = run_of_five.unwrap_or_else(|| panic!("the table's array: {d}"));
    assert_eq!(run_of_five["values"], serde_json::json!(["zorkmid", "quuxian", "quuxian", "zorkmid", "blargle"]), "{d}");

    let d = run(&["lua", "strings", "--pid", &pid, "--contains", "zorkmid"]);
    assert_eq!(d["layout"]["len_offset"], want, "{d}");
    assert!(d["matches"].as_array().expect("matches").iter().any(|h| h["object_base"] == said["zorkmid"].as_str()), "{d}");

    let _ = writeln!(stdin);
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A function read in part says so, and counts nothing of it as whole.**
//!
//! A claims audit (2026-11-14) found, on a function `nm` sizes at 0x418a bytes
//! with no symbols to read it by: `ir build` ending at the 4 KiB window with no
//! `cut` (its `end_by` named the window, which the audit read as the function's
//! end), and `ir manifest` answering `returns: 0` beside the flag `cut`, of a
//! function whose `ret` lies past the cut.
//!
//! The truth is the bytes, planted: `push rbp; mov rbp,rsp`, 30 `mov eax,1`,
//! `pop rbp; ret`, so the one `ret` is at 0x109b, past a window of 64 bytes and
//! inside the default one.

use std::process::Command;

use serde_json::{Value, json};

mod support;

fn n0xis_exe() -> std::path::PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

fn planted() -> String {
    let mut b = vec![0x55, 0x48, 0x89, 0xe5];
    for _ in 0..30 {
        b.extend_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00]);
    }
    b.extend_from_slice(&[0x5d, 0xc3]);
    assert_eq!(b.len(), 0x9c, "the ret is the last byte, at 0x109b");
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}

fn tool(args: &[&str]) -> Option<Value> {
    let exe = n0xis_exe();
    if !exe.exists() {
        eprintln!("skipping: {} not built", exe.display());
        return None;
    }
    let out = support::isolated(Command::new(&exe)).args(args).output().expect("run n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("not one JSON object ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    assert_eq!(v["ok"], Value::Bool(true), "{v}");
    Some(v)
}

#[test]
fn ir_build_says_a_graph_cut_at_its_window_is_cut() {
    let Some(v) = tool(&["ir", "build", "--bytes", &planted(), "--addr", "0x1000", "--size", "64"]) else { return };
    let cut = &v["data"]["cut"];
    assert_eq!(cut["at"], "0x1040", "cut where the 64 bytes end, before the ret at 0x109b: {v}");
    assert!(cut["words"].as_str().is_some_and(|w| w.contains("the function goes on")), "{v}");

    // And a graph read to its `ret` says nothing of a cut.
    let Some(v) = tool(&["ir", "build", "--bytes", &planted(), "--addr", "0x1000"]) else { return };
    assert!(v["data"].get("cut").is_none(), "{v}");
    assert_eq!(v["data"]["end"], "0x109c", "{v}");
}

#[test]
fn ir_manifest_counts_the_returns_of_a_cut_function_as_a_lower_bound() {
    let Some(v) = tool(&["ir", "manifest", "--bytes", &planted(), "--start", "0x1000", "--max-bytes", "64"]) else { return };
    let e = &v["data"]["entries"][0];
    assert_eq!(e["va"], "0x1000", "{v}");
    assert_eq!(e["returns"], json!({"at_least": 0}), "the ret at 0x109b is past the cut: {v}");

    // Read whole, the one `ret` is a count.
    let Some(v) = tool(&["ir", "manifest", "--bytes", &planted(), "--start", "0x1000"]) else { return };
    assert_eq!(v["data"]["entries"][0]["returns"], json!(1), "{v}");
}

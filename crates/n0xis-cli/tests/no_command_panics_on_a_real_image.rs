// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A debug build has overflow checks; a release build wraps.**
//!
//! Arithmetic that silently wraps in release is not a crash and not a wrong
//! answer you can see — it is a slow, quiet detour. `sweep_declared_gaps`
//! computed `va - lo` on unsigned addresses before checking that `va` was
//! inside the scanned window, and a declared function *can* end before the
//! window starts, because the exception table describes the whole image while
//! the buffer is one section. Release wrapped the subtraction and crawled one
//! byte at a time from a nonsense offset up to the window — the right answer,
//! arrived at slowly, which is why nothing ever noticed. **Debug panicked
//! outright**, so anyone building from source hit it on a real C library.
//!
//! This test runs in the debug build by construction (it invokes the binary
//! `cargo test` just built), so those checks are on. It drives every command
//! the guide lists, with arguments built from the guide's own schema.
//!
//! **A real image is required, and the purpose-built shape is not enough.**
//! Reverting the fix leaves the oracle shape passing and makes a system C
//! library panic: a fixture proves the rule, a real binary has the awkward
//! shape. Both are used, and with no system library present the test says what
//! it could not check.
//!
//! Commands that mutate anything are skipped by name, not by hope.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn n0xis_exe() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

/// Verbs that change something — a file, the project, the machine. Skipped by
/// name so the list is reviewable, rather than by guessing from the output.
const MUTATING: &[&str] = &[
    "write", "patch", "set", "rm", "save", "dump", "kill", "alloc", "free", "inject", "detour", "trampoline", "undo",
    "redo", "apply", "init", "serve", "remote-serve", "await-hit", "watch", "step", "attach", "resume", "spawn",
    "import", "bookmark", "annotate",
];

/// Command families that need a live process or an OS surface a static image
/// cannot provide; they refuse cleanly and there is nothing to exercise here.
const NEEDS_A_LIVE_TARGET: &[&str] = &["process", "debug", "ui", "mem map", "stack backtrace", "scan", "filter", "group"];

/// A plausible value for a required argument, by flag name. Anything not in
/// here means the command is skipped rather than invoked with a guess — an
/// invented argument tests the argument parser, not the analysis.
fn value_for(flag: &str, target: &str, addr: &str) -> Option<String> {
    let v = match flag.trim_start_matches('-') {
        "file" | "path" | "other" | "a-file" | "b-file" => target,
        "addr" | "at" | "a-addr" | "b-addr" => addr,
        "query" | "string" | "name" => "malloc",
        "pattern" => "48 89",
        "reg" | "var" => "rax",
        "value" | "index" | "offset" | "id" | "slot" => "0",
        "size" => "4096",
        "limit" | "count" => "16",
        "len" => "16",
        "type" => "int",
        "style" => "ssa",
        "arch" => "x64",
        "topic" => "scan",
        "dir" => "/tmp",
        _ => return None,
    };
    Some(v.to_string())
}

fn commands() -> Vec<Value> {
    let out = Command::new(n0xis_exe()).args(["guide", "--quiet"]).output().expect("run guide");
    let v: Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("guide envelope");
    v["data"]["commands"].as_array().cloned().unwrap_or_default()
}

fn first_function(target: &str) -> Option<String> {
    let out = Command::new(n0xis_exe()).args(["function", "discover", "--quiet", "--file", target]).output().ok()?;
    let v: Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).ok()?;
    v["data"]["functions"].as_array()?.get(2)?["va"].as_str().map(str::to_string)
}

/// Drive every runnable command against one image. Returns `(ran, panics)`.
fn sweep(target: &str) -> (usize, Vec<String>) {
    let Some(addr) = first_function(target) else {
        return (0, vec![format!("{target}: no function to aim at")]);
    };
    let (mut ran, mut panics) = (0usize, Vec::new());
    for c in commands() {
        let Some(path) = c["path"].as_str() else { continue };
        if MUTATING.iter().any(|v| path.split_whitespace().any(|w| w == *v))
            || NEEDS_A_LIVE_TARGET.iter().any(|p| path.starts_with(p))
        {
            continue;
        }
        let empty = Vec::new();
        let args_spec = c["args"].as_array().unwrap_or(&empty);
        let mut args: Vec<String> = path.split_whitespace().map(str::to_string).collect();
        let mut usable = true;
        for a in args_spec {
            if a["required"].as_bool() != Some(true) {
                continue;
            }
            let Some(name) = a["name"].as_str() else { continue };
            let Some(v) = value_for(name, target, &addr) else {
                usable = false;
                break;
            };
            if a["positional"].as_bool() == Some(true) {
                args.push(v);
            } else {
                args.push(name.to_string());
                args.push(v);
            }
        }
        if !usable {
            continue;
        }
        let names: Vec<&str> = args_spec.iter().filter_map(|a| a["name"].as_str()).collect();
        for (flag, val) in [("--file", target), ("--addr", addr.as_str()), ("--limit", "16")] {
            if names.contains(&flag) && !args.iter().any(|a| a == flag) {
                args.push(flag.to_string());
                args.push(val.to_string());
            }
        }
        args.push("--quiet".into());
        let Ok(out) = Command::new(n0xis_exe()).args(&args).output() else { continue };
        ran += 1;
        let err = String::from_utf8_lossy(&out.stderr);
        if let Some(line) = err.lines().find(|l| l.contains("panicked at")) {
            panics.push(format!("{path} on {target}: {}", line.trim()));
        }
    }
    (ran, panics)
}

/// The same system library the extent check uses — present on essentially every
/// Linux, and the shape a purpose-built fixture does not have.
fn a_system_library() -> Option<String> {
    ["/usr/lib/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib64/libc.so.6", "/usr/lib/libm.so.6"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .map(str::to_string)
}

#[test]
fn no_command_panics_with_overflow_checks_on() {
    if !n0xis_exe().exists() {
        eprintln!("panic sweep: skipping — {} is not built", n0xis_exe().display());
        return;
    }
    let tmp = std::env::temp_dir().join(format!("n0xis_panics_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("temp dir");
    let shape = tmp.join("sysv.so");
    let built = Command::new("gcc")
        .args(["-shared", "-O1", "-fPIC", "-o"])
        .arg(&shape)
        .arg(repo_root().join("oracle").join("sysv.c"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let mut targets: Vec<String> = Vec::new();
    if built {
        targets.push(shape.display().to_string());
    } else {
        eprintln!("panic sweep: gcc unavailable — the purpose-built shape was not checked");
    }
    match a_system_library() {
        Some(lib) => targets.push(lib),
        // Worth saying plainly: reverting the fix that motivated this test
        // leaves the oracle shape passing. Without a real image this checks
        // much less than it looks like it does.
        None => eprintln!("panic sweep: no system library — only the purpose-built shape was checked"),
    }

    let (mut total, mut panics) = (0usize, Vec::new());
    for t in &targets {
        let (ran, found) = sweep(t);
        total += ran;
        panics.extend(found);
    }
    let _ = std::fs::remove_dir_all(&tmp);

    if targets.is_empty() {
        eprintln!("panic sweep: no target at all — nothing was checked");
        return;
    }
    assert!(total > 40, "only {total} command runs across {} target(s) — too few to mean anything", targets.len());
    eprintln!("panic sweep: {total} command runs across {} target(s), no panic", targets.len());
    assert!(panics.is_empty(), "a command panicked with overflow checks on:\n  {}", panics.join("\n  "));
}

// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`serve` exit test**: the session must keep the promise its own help text
//! makes — "load `--file` once, then read one command line per line".
//!
//! It did not. Each line was parsed and dispatched on its own, so a line naming
//! no source got `missing-source` and the caller had to repeat `--file` on
//! every one; and the ready banner carried no `meta` at all, though the
//! documented envelope says every response does. A front-end that dispatches on
//! `meta.schema` broke on the first line it read.
//!
//! The fixture is this test binary's own executable — a real image of the host
//! format, needing no compiler and no network.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::Value;

fn n0xis_exe() -> std::path::PathBuf {
    // `target/<profile>/deps/<test>` → `target/<profile>/n0xis`
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

/// Drive one `serve` session and collect one parsed envelope per input line,
/// plus the banner.
fn serve(lines: &[&str]) -> Vec<Value> {
    let exe = n0xis_exe();
    if !exe.exists() {
        eprintln!("skipping: {} not built", exe.display());
        return Vec::new();
    }
    let fixture = std::env::current_exe().expect("test exe");
    let mut child = Command::new(&exe)
        .args(["serve", "--quiet", "--file"])
        .arg(&fixture)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn serve");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for l in lines {
            writeln!(stdin, "{l}").expect("write line");
        }
        writeln!(stdin).expect("blank line ends the session");
    }
    let out = BufReader::new(child.stdout.take().expect("stdout"));
    let vals: Vec<Value> = out
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(&l).unwrap_or_else(|e| panic!("every session line is one JSON envelope: {e} in {l}")))
        .collect();
    let _ = child.wait();
    vals
}

#[test]
fn the_banner_is_an_envelope_like_every_other_response() {
    let out = serve(&["doctor"]);
    if out.is_empty() {
        return; // binary not built in this profile
    }
    let banner = &out[0];
    assert_eq!(banner["ok"], true, "the session opened: {banner}");
    assert_eq!(
        banner["meta"]["schema"], "n0xis.serve.ready.v1",
        "the banner must carry a schema — a front-end dispatching on it reads this line first: {banner}"
    );
    assert_eq!(banner["data"]["ready"], true);
}

#[test]
fn a_session_command_inherits_the_file_it_was_started_with() {
    // THE POINT: no `--file` on the line. The session was started with one.
    let out = serve(&["module list"]);
    if out.is_empty() {
        return;
    }
    assert!(out.len() >= 2, "banner plus one response, got {}", out.len());
    let resp = &out[1];
    assert_eq!(resp["ok"], true, "a line naming no source must use the session's image: {resp}");
    assert_eq!(resp["meta"]["schema"], "n0xis.module.list.v1");
}

#[test]
fn a_command_that_takes_no_file_still_runs() {
    // The injection is *tried*, not forced: `doctor` accepts no `--file`, and
    // must not start failing because the session has one.
    let out = serve(&["doctor"]);
    if out.is_empty() {
        return;
    }
    assert_eq!(out[1]["ok"], true, "{}", out[1]);
}

/// Two front doors onto the same operation must answer the same request the
/// same way. `n0x disasm` and the `decode` capability (the door an MCP client
/// reaches) had defaulted to 20 and 16 instructions, so the answer depended on
/// which one was used.
#[test]
fn both_front_doors_onto_a_linear_disassembly_agree() {
    let exe = n0xis_exe();
    if !exe.exists() {
        return;
    }
    let fixture = std::env::current_exe().expect("test exe");
    let f = fixture.to_string_lossy().to_string();
    let run = |args: Vec<String>| -> Value {
        let out = Command::new(&exe).args(&args).output().expect("run n0xis");
        serde_json::from_slice(&out.stdout).unwrap_or(Value::Null)
    };

    // Ask the image where its code starts rather than assuming an entry point:
    // the fixture is whatever this host builds test binaries as.
    let disc = run(vec!["function".into(), "discover".into(), "--file".into(), f.clone(), "--limit".into(), "1".into(), "--quiet".into()]);
    let Some(addr) = disc["data"]["functions"][0]["va"].as_str().map(str::to_string) else {
        return; // no code recognised on this host's format; nothing to compare
    };

    let disasm = run(vec!["disasm".into(), "--file".into(), f.clone(), "--addr".into(), addr.clone(), "--quiet".into()]);
    let args_json = serde_json::json!({ "file": f, "addr": addr }).to_string();
    let decode = run(vec!["capability".into(), "run".into(), "decode".into(), "--args".into(), args_json, "--quiet".into()]);

    assert_eq!(disasm["ok"], true, "disasm: {disasm}");
    assert_eq!(decode["ok"], true, "decode: {decode}");
    let inner = if decode["data"].get("data").is_some() { &decode["data"]["data"] } else { &decode["data"] };
    assert_eq!(
        disasm["data"]["count"], inner["count"],
        "the same request through two doors must decode the same amount: {disasm} vs {decode}"
    );
}

#[test]
fn a_bad_line_reports_its_own_error_and_the_session_continues() {
    let out = serve(&["this is not a command", "doctor"]);
    if out.is_empty() {
        return;
    }
    assert_eq!(out[1]["ok"], false);
    assert_eq!(out[1]["error"]["code"], "parse-error");
    let msg = out[1]["error"]["message"].as_str().unwrap_or_default();
    assert!(!msg.contains("--file"), "the error must be about what the caller typed, not an injected flag: {msg}");
    assert_eq!(out[2]["ok"], true, "one bad line does not end the session");
}

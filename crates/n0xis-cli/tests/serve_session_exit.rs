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
    serve_in(None, lines)
}

/// [`serve`], with the session's working directory set — which is what decides
/// the `.n0x/` project, and so the project default a request with no source
/// falls back to.
fn serve_in(cwd: Option<&std::path::Path>, lines: &[&str]) -> Vec<Value> {
    let exe = n0xis_exe();
    if !exe.exists() {
        eprintln!("skipping: {} not built", exe.display());
        return Vec::new();
    }
    let fixture = std::env::current_exe().expect("test exe");
    let mut cmd = Command::new(&exe);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let mut child = cmd
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

/// A client learns the request forms from the server. The GUI writes JSON argv
/// only when the banner lists it, and an older engine that does not is driven
/// with text lines instead of being sent a form it would misread.
#[test]
fn the_banner_lists_the_request_forms_the_session_reads() {
    let out = serve(&["doctor"]);
    if out.is_empty() {
        return;
    }
    let formats = out[0]["data"]["request_formats"].as_array().cloned().unwrap_or_default();
    assert!(formats.iter().any(|f| f == "json-argv"), "{}", out[0]);
    assert!(formats.iter().any(|f| f == "text"), "{}", out[0]);
}

#[test]
fn a_json_argv_request_runs_like_its_text_form() {
    let out = serve(&[r#"["module","list"]"#]);
    if out.is_empty() {
        return;
    }
    assert_eq!(out[1]["ok"], true, "a JSON request inherits the session's file too: {}", out[1]);
    assert_eq!(out[1]["meta"]["schema"], "n0xis.module.list.v1");
}

/// THE POINT of the JSON form. The text form has no escape: `"` only toggles
/// quoting and is dropped, so this argument cannot be sent as text at all. As
/// JSON it must reach the argument parser byte for byte; the parser's error
/// quotes the unexpected argument back, which is what this reads.
#[test]
fn a_json_argv_argument_arrives_exactly_as_sent() {
    let arg = r#"say "hi" \ back"#;
    let line = serde_json::to_string(&["doctor", arg]).expect("encode");
    let out = serve(&[&line]);
    if out.is_empty() {
        return;
    }
    assert_eq!(out[1]["ok"], false, "{}", out[1]);
    assert_eq!(out[1]["error"]["code"], "parse-error");
    let msg = out[1]["error"]["message"].as_str().unwrap_or_default();
    assert!(msg.contains(arg), "the argument must reach the parser exactly as sent: {msg}");
}

#[test]
fn a_malformed_json_request_is_reported_and_the_session_continues() {
    let out = serve(&[r#"["doctor","#, "doctor"]);
    if out.is_empty() {
        return;
    }
    assert_eq!(out[1]["ok"], false);
    assert_eq!(out[1]["error"]["code"], "bad-command");
    assert_eq!(out[2]["ok"], true, "one bad line does not end the session");
}

/// Bytes planted in this test binary — the session's image — so the answer to
/// "where are they?" is known before the question is asked. Random-looking on
/// purpose: a run of them occurring by accident elsewhere in the image is not
/// a realistic worry, and the expectation is counted from the file anyway.
#[used]
static PLANTED: [u8; 20] = [
    0x9d, 0x3b, 0xe1, 0x52, 0x0f, 0xa7, 0x6c, 0xd4, 0x18, 0x83, 0x5e, 0xb9, 0x27, 0xf0, 0x4a, 0xc6, 0x71, 0x0e, 0x95, 0x3d,
];

/// A working directory whose `.n0x/` project names a *different* image as the
/// default source — the state the defect needed to answer from the wrong file.
/// The decoy is a real image that does not hold [`PLANTED`], so searching it
/// is a successful, silent zero rather than an error.
fn decoy_project(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis-serve-source-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(dir.join(".n0x")).expect("create .n0x");
    let decoy = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native_pe.dll");
    let session = serde_json::json!({ "file": decoy.to_string_lossy(), "attached_at_unix": 0 });
    std::fs::write(dir.join(".n0x/session.json"), session.to_string()).expect("write session.json");
    dir
}

/// How many times `needle` occurs in `hay` — counted from the raw file, not by
/// the tool under test.
fn occurrences(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

/// THE DEFECT. `find --bytes` takes a *pattern*; a session took it for an
/// inline-bytes source because it is spelled like one, withheld its own image,
/// and `find` searched the project default instead — here a decoy that answers
/// "0 matches" with `ok: true`.
#[test]
fn a_find_pattern_in_a_session_searches_the_session_image() {
    let fixture = std::fs::read(std::env::current_exe().expect("test exe")).expect("read fixture");
    let expected = occurrences(&fixture, &PLANTED);
    assert!(expected >= 1, "the planted bytes are in the fixture file");

    let pattern: Vec<String> = PLANTED.iter().map(|b| format!("{b:02x}")).collect();
    let line = serde_json::to_string(&["find", "--bytes", &pattern.join(" "), "--limit", "0"]).expect("encode");
    let dir = decoy_project("find");
    let out = serve_in(Some(&dir), &[&line]);
    let _ = std::fs::remove_dir_all(&dir);
    if out.is_empty() {
        return;
    }
    let resp = &out[1];
    assert_eq!(resp["ok"], true, "{resp}");
    assert_eq!(
        resp["data"]["count"].as_u64(),
        Some(expected as u64),
        "the pattern must be searched for in the session's image, which holds it {expected} time(s): {resp}"
    );
    let name = std::env::current_exe().expect("test exe").file_name().expect("name").to_string_lossy().to_string();
    assert_eq!(resp["meta"]["source"], format!("static:{name}"), "and the image searched is the session's: {resp}");
}

/// The other direction: where `--bytes` *is* the source, it still wins over
/// the session's image.
#[test]
fn inline_bytes_in_a_session_are_still_the_source() {
    let dir = decoy_project("disasm");
    let out = serve_in(Some(&dir), &[r#"["disasm","--bytes","48 89 c8 c3","--addr","0x1000","--count","2"]"#]);
    let _ = std::fs::remove_dir_all(&dir);
    if out.is_empty() {
        return;
    }
    let resp = &out[1];
    assert_eq!(resp["ok"], true, "inline bytes must be read, not merged with the session file: {resp}");
    assert_eq!(resp["meta"]["source"], "bytes@0x1000", "the source is the inline bytes: {resp}");
    let insns = resp["data"]["insns"].as_array().cloned().unwrap_or_default();
    let text: Vec<String> = insns.iter().map(|i| i["text"].as_str().unwrap_or_default().to_string()).collect();
    assert_eq!(text, ["mov rax,rcx", "ret"], "the four inline bytes, decoded: {resp}");
}

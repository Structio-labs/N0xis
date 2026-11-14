// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `n0x feedback`, run by the real binary inside a project that has just analysed a planted image,
//! holds nothing of that image: not its path, its name, a string planted in it, an address in it or
//! a name given there, and nothing of this machine's (docs/FEEDBACK.md).
//!
//! People analyse files they may not be allowed to share, so this is the test that matters most. What
//! is searched is the report as the binary shows it, as it saves it, and as the body `--send` posts:
//! [`n0xis_feedback::frame`] of those bytes with the attachment's, which is what the client of
//! `n0xis-update` posts, byte for byte (`n0xis-feedback-receiver/tests/the_path_of_a_report.rs` holds
//! that against the real receiver). This binary cannot itself be made to post: it accepts only a
//! manifest signed by the release key, and a test holds no private key for it.
//!
//! The answer is known before the binary is asked: the fixture's string is in its source, its address
//! is `nm`'s, the paths and names are the ones planted here.

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_n0xis");
/// In `strings_planted.c`, and so in the image.
const PLANTED_STRING: &str = "n0xis-planted-ascii-7f3a";
/// `nm -D strings_planted.so`: `00000000000010e9 T n0x_pick`.
const PLANTED_FUNCTION: (&str, u64) = ("n0x_pick", 0x10e9);

fn scratch() -> PathBuf {
    // A directory and file names no report has a reason to hold, so a hit is a leak and not chance.
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("feedback-leak-{}", std::process::id())).join("secret-workdir-k2v9");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

fn run(dir: &Path, config: &Path, args: &[&str]) -> Output {
    support::isolated(Command::new(BIN))
        .args(args)
        .current_dir(dir)
        .env("N0X_CONFIG_DIR", config)
        .env("N0X_NO_UPDATE_CHECK", "1")
        .output()
        .expect("run n0xis")
}

fn envelope(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("not one JSON envelope ({e}): {}", String::from_utf8_lossy(&out.stdout)))
}

/// What a report must not hold, each with what it is, all from this test's own planting.
fn needles(dir: &Path, target: &Path, image: &[u8]) -> Vec<(String, String)> {
    let mut n = vec![
        ("the working directory".to_string(), dir.display().to_string()),
        ("the working directory's name".to_string(), "secret-workdir-k2v9".to_string()),
        ("the target's path".to_string(), target.display().to_string()),
        ("the target's name".to_string(), "zz-planted-target-5521".to_string()),
        ("the project's name".to_string(), "secretproj-k2v9".to_string()),
        ("a string planted in the target".to_string(), PLANTED_STRING.to_string()),
        ("a function's name in the target".to_string(), PLANTED_FUNCTION.0.to_string()),
        ("an address in the target".to_string(), format!("{:#x}", PLANTED_FUNCTION.1)),
        ("an address in the target, in decimal".to_string(), PLANTED_FUNCTION.1.to_string()),
        ("a name given in the project".to_string(), "planted_name_q8".to_string()),
        ("the attachment's file name".to_string(), "crash-shot-x4".to_string()),
        ("the target's sha256".to_string(), n0xis_feedback::sha256_hex(image)),
    ];
    // Nothing of the machine or the person: home, user, host.
    for var in ["HOME", "USER", "USERNAME", "USERPROFILE", "COMPUTERNAME"] {
        if let Ok(v) = std::env::var(var)
            && v.len() >= 3
        {
            n.push((format!("${var}"), v));
        }
    }
    if let Ok(host) = std::fs::read_to_string("/proc/sys/kernel/hostname")
        && host.trim().len() >= 3
    {
        n.push(("the host's name".to_string(), host.trim().to_string()));
    }
    // A host or user named as the OS family or the architecture is told apart by nothing: the report
    // states those by design. Measured here: a machine named `Linux` read as a leak of its name.
    n.retain(|(_, v)| !v.eq_ignore_ascii_case(std::env::consts::OS) && !v.eq_ignore_ascii_case(std::env::consts::ARCH));
    n
}

fn holds(haystack: &[u8], needle: &str) -> bool {
    let hay = String::from_utf8_lossy(haystack).to_ascii_lowercase();
    // JSON writes a `/` as is and a `\` doubled: a Windows path is searched in both spellings.
    let needle = needle.to_ascii_lowercase();
    hay.contains(&needle) || hay.contains(&needle.replace('\\', "\\\\"))
}

#[test]
fn a_report_holds_nothing_of_the_target_or_the_machine() {
    let dir = scratch();
    let config = dir.parent().expect("parent").join("config");
    std::fs::create_dir_all(&config).expect("config dir");
    let image = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/strings_planted.so")).expect("fixture");
    let target = dir.join("zz-planted-target-5521.so");
    std::fs::write(&target, &image).expect("plant");
    let t = target.to_str().expect("utf-8 path");
    let addr = format!("{:#x}", PLANTED_FUNCTION.1);

    // A project that has analysed the target, so `.n0x/` holds what a report must not.
    for args in [
        vec!["init", "--name", "secretproj-k2v9"],
        vec!["profile", "--file", t],
        vec!["strings", "--file", t, "--limit", "50"],
        vec!["decomp", "pseudo", "--addr", &addr, "--file", t],
        vec!["annotate", "name", "--addr", &addr, "--value", "planted_name_q8", "--file", t],
    ] {
        let out = run(&dir, &config, &args);
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stdout));
    }
    // Calibration of the haystack: the project does hold the planted facts, so their absence below
    // is the report's and not an analysis that never happened.
    let project: Vec<u8> = walk(&dir.join(".n0x")).into_iter().flat_map(|p| std::fs::read(p).unwrap_or_default()).collect();
    assert!(holds(&project, "planted_name_q8"), "the project never recorded the planted name");

    let shot_path = dir.join("zz-planted-target-5521-crash-shot-x4.png");
    let mut shot = b"\x89PNG\r\n\x1a\n".to_vec();
    shot.extend_from_slice(&[0u8; 64]);
    std::fs::write(&shot_path, &shot).expect("shot");
    let text = "the decompiler printed a loop where there is none";
    let out = run(&dir, &config, &["feedback", text, "--attach", shot_path.to_str().expect("utf-8")]);
    let answer = envelope(&out);
    assert_eq!(answer["ok"], true, "{answer}");
    assert_eq!(answer["data"]["sent"], Value::Null, "nothing is sent without --send");

    // Saved in this project, and the bytes saved are the bytes shown.
    let saved = PathBuf::from(answer["data"]["saved"].as_str().expect("saved"));
    // By what the project's folder holds, not by the path's spelling: under Wine the binary names it
    // `Z:\run\…` and this test, built on the host, `/run/…`, the same place.
    let in_project: Vec<_> = std::fs::read_dir(dir.join(".n0x").join("feedback")).expect("the project's feedback folder").flatten().map(|e| e.file_name()).collect();
    assert_eq!(in_project, vec![saved.file_name().expect("a file").to_os_string()], "saved at {}", saved.display());
    let report = std::fs::read(&saved).expect("saved report");
    let shown = format!("\"report\":{}", String::from_utf8_lossy(&report));
    assert!(String::from_utf8_lossy(&out.stdout).contains(&shown), "the report shown is not, byte for byte, the report saved");
    // The body `--send` posts.
    let body = n0xis_feedback::frame(&report, &[&shot]);
    let mut leaks = Vec::new();
    for (what, needle) in needles(&dir, &target, &image) {
        for (place, hay) in [("the report", &report), ("the body", &body)] {
            if holds(hay, &needle) {
                leaks.push(format!("{place} holds {what} ({needle})"));
            }
        }
    }
    assert!(leaks.is_empty(), "a report holds what it must not:\n  {}", leaks.join("\n  "));
    // And it is the report asked for: checked after the leak, so a leak is reported as that.
    let parsed: Value = serde_json::from_slice(&report).expect("json");
    assert_eq!(parsed["text"], text);
    assert_eq!(parsed["attachments"][0]["size"], shot.len());

    // `--send` with nowhere to send it: refused as that, the report saved again, nothing reached past the
    // loopback (the override is the only address asked, and nothing listens there).
    let set = run(&dir, &config, &["config", "set", "update.manifest_url", "https://127.0.0.1:9/manifest.json"]);
    assert!(set.status.success(), "{}", String::from_utf8_lossy(&set.stdout));
    let out = run(&dir, &config, &["feedback", text, "--send"]);
    let answer = envelope(&out);
    assert_eq!(answer["ok"], false, "{answer}");
    assert_eq!(answer["error"]["code"], "manifest-unavailable", "{answer}");
    let fallback = &answer["error"]["fallback"];
    assert_eq!(fallback["contact"], n0xis_feedback::CONTACT);
    assert!(fallback["issue"].as_str().is_some_and(|u| u.starts_with(n0xis_feedback::NEW_ISSUE)), "{fallback}");
    let again = std::fs::read(fallback["saved"].as_str().expect("saved")).expect("saved again");
    for (what, needle) in needles(&dir, &target, &image) {
        assert!(!holds(&again, &needle), "the report saved on a failed send holds {what} ({needle})");
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

#[test]
fn the_limits_and_the_types_hold_at_the_door() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("feedback-limits-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let config = dir.join("config");
    let code = |args: &[&str]| -> String {
        let answer = envelope(&run(&dir, &config, args));
        answer["error"]["code"].as_str().map(str::to_string).unwrap_or_else(|| format!("ok: {}", answer["ok"]))
    };
    let gif = dir.join("a.png");
    std::fs::write(&gif, b"GIF89a, named .png").expect("gif");
    assert_eq!(code(&["feedback", "x", "--attach", gif.to_str().expect("utf-8")]), "not-an-image", "a type is its bytes, not its name");
    let big = dir.join("big.png");
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    bytes.resize(n0xis_feedback::CLIENT_LIMITS.max_attachment_bytes as usize + 1, 0);
    std::fs::write(&big, &bytes).expect("big");
    assert_eq!(code(&["feedback", "x", "--attach", big.to_str().expect("utf-8")]), "attachment-too-large");
    bytes.truncate(n0xis_feedback::CLIENT_LIMITS.max_attachment_bytes as usize);
    std::fs::write(&big, &bytes).expect("at the bound");
    assert_eq!(code(&["feedback", "x", "--attach", big.to_str().expect("utf-8")]), "ok: true", "the bound itself is taken");
    // The text's bound at its edge is `n0xis-feedback`'s own test: 64 KiB is past what a Windows
    // command line holds, so the door is shown to pass the refusal on with a short one instead.
    assert_eq!(code(&["feedback", "   "]), "empty-text");
    assert_eq!(code(&["feedback", "x", "--attach", dir.join("no-such.png").to_str().expect("utf-8")]), "attachment-unreadable");
}

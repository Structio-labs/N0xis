// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A record is about the image it was made on.** Every native target shared
//! one map of records keyed by address, so a rename made on one image was
//! printed as the name of whatever another image held at that address, with
//! nothing to say it was a user's name for something else (audit 2026-11-06).
//! Each image keeps its own now, under the digest of its file.
//!
//! The two images here differ by one byte and nothing else, so every address
//! is the same in both: only the file tells them apart.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

mod support;

const ELF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/strings_planted.so");

fn run(dir: &PathBuf, args: &[&str]) -> Value {
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).current_dir(dir).output().expect("run n0xis");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{args:?}: {e}: {}", String::from_utf8_lossy(&out.stdout)))
}

#[test]
fn a_rename_on_one_image_is_not_another_images_name() {
    let dir = std::env::temp_dir().join(format!("n0xis-one-image-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).unwrap();
    let (a, b) = (dir.join("a.so"), dir.join("b.so"));
    std::fs::copy(ELF, &a).unwrap();
    let mut bytes = std::fs::read(ELF).unwrap();
    // The last byte of the planted ASCII string: data, not a header.
    let at = bytes.windows(4).position(|w| w == b"7f3a").expect("the planted string") + 3;
    bytes[at] = b'b';
    std::fs::write(&b, &bytes).unwrap();
    let (a, b) = (a.to_str().unwrap(), b.to_str().unwrap());

    let f = run(&dir, &["function", "discover", "--file", a]);
    let addr = f["data"]["functions"].as_array().unwrap().iter().find(|x| x["name"] == "n0x_pick").expect("n0x_pick")["va"].as_str().unwrap().to_string();
    assert_eq!(run(&dir, &["annotate", "name", "--addr", &addr, "--value", "USER_NAME_FOR_A", "--file", a])["ok"], true);

    let on_a = run(&dir, &["decomp", "pseudo", "--file", a, "--addr", &addr]);
    assert!(on_a["data"]["pseudo"].to_string().contains("USER_NAME_FOR_A"), "{on_a}");
    let on_b = run(&dir, &["decomp", "pseudo", "--file", b, "--addr", &addr]);
    assert!(!on_b.to_string().contains("USER_NAME_FOR_A"), "a's rename printed on b: {on_b}");
    assert_eq!(run(&dir, &["annotate", "list", "--file", b])["data"]["count"], 0);

    // With no image named, a write is refused, and names both ways to name one.
    let refused = run(&dir, &["annotate", "name", "--addr", &addr, "--value", "X"]);
    assert_eq!(refused["error"]["code"], "no-image", "{refused}");
    let message = refused["error"]["message"].as_str().unwrap();
    assert!(message.contains("--file") && message.contains("--pid"), "{refused}");
    let _ = std::fs::remove_dir_all(&dir);
}

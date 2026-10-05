// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`project cache`**: it reports what the derived caches take on disk, and
//! `--clear` removes exactly those. The user's own work in the same `.n0x/`
//! (names, comments, types) must survive a clear byte for byte: that is the line
//! between a cache and a project.

use std::process::Command;

use serde_json::Value;

fn n0xis_exe() -> std::path::PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

fn run(cwd: &std::path::Path, args: &[&str]) -> Value {
    let out = Command::new(n0xis_exe()).current_dir(cwd).args(args).output().expect("run n0xis");
    serde_json::from_slice(&out.stdout).expect("one envelope")
}

#[test]
fn a_clear_frees_what_it_reported_and_keeps_the_users_work() {
    if !n0xis_exe().exists() {
        return; // binary not built in this profile
    }
    let project = std::env::temp_dir().join(format!("n0xis-project-cache-{}", std::process::id()));
    let n0x = project.join(".n0x");
    std::fs::create_dir_all(&n0x).expect("temp project");
    // Planted: two cache kinds with known sizes, and the user's work beside them.
    for (dir, name, len) in [("ir-cache", "a.json", 1000usize), ("ir-cache", "b.json", 24), ("xref-index", "c.json", 300)] {
        std::fs::create_dir_all(n0x.join(dir)).unwrap();
        std::fs::write(n0x.join(dir).join(name), vec![b'x'; len]).unwrap();
    }
    let work = br#"{"0x1000":{"va":"0x1000","name":"kept","history":[]}}"#;
    std::fs::write(n0x.join("annotations.json"), work).unwrap();
    std::fs::write(n0x.join("types.json"), b"{\"structs\":[],\"enums\":[]}").unwrap();

    let report = run(&project, &["project", "cache"]);
    assert_eq!(report["ok"], true, "{report}");
    assert_eq!(report["data"]["is_local"], true, "the project in the folder, not the global one");
    assert_eq!(report["data"]["bytes"], 1324, "the planted cache bytes: {report}");
    let ir = report["data"]["caches"].as_array().unwrap().iter().find(|c| c["name"] == "ir-cache").cloned().unwrap();
    assert_eq!((ir["files"].as_u64(), ir["bytes"].as_u64()), (Some(2), Some(1024)));

    let cleared = run(&project, &["project", "cache", "--clear"]);
    assert_eq!(cleared["data"]["freed"], 1324, "{cleared}");
    assert_eq!(run(&project, &["project", "cache"])["data"]["bytes"], 0, "nothing left");
    assert_eq!(std::fs::read(n0x.join("annotations.json")).unwrap(), work.to_vec(), "the user's names survive");
    assert!(n0x.join("types.json").exists(), "and their types");
    let _ = std::fs::remove_dir_all(&project);
}

// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The recordings beside the Itanium vtable fixtures say what the tools say.**
//!
//! `fixtures/itanium_vtables/*.txt` are `llvm-nm` and `llvm-readobj` output,
//! committed so the tests that compare the engine with them need neither tool.
//! A recording edited by hand, or left behind when a fixture was rebuilt, would
//! make those tests compare the engine with something no tool said. So this
//! runs the commands `record.sh` runs and compares, byte for byte.
//!
//! A local instrument (`--features oracle`): it needs the LLVM tools installed,
//! and their output format belongs to their version.
#![cfg(feature = "oracle")]

use std::path::PathBuf;
use std::process::Command;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/itanium_vtables")
}

fn run(tool: &str, args: &[&str]) -> String {
    let out = Command::new(tool)
        .args(args)
        .current_dir(fixtures())
        .env("LC_ALL", "C")
        .output()
        .unwrap_or_else(|e| panic!("{tool} is needed here: {e}"));
    assert!(out.status.success(), "{tool} {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).expect("UTF-8")
}

#[test]
fn every_recording_is_what_the_tool_prints_now() {
    let mut checked = 0;
    for entry in std::fs::read_dir(fixtures()).expect("the fixture directory") {
        let name = entry.expect("an entry").file_name().to_string_lossy().into_owned();
        if !["vt-", "vb-", "vbi-", "vo-", "vd-", "vx-", "vf-", "vn-", "vy-", "vr-", "vp-"].iter().any(|p| name.starts_with(p)) || name.ends_with(".txt") {
            continue;
        }
        let read = |ext: &str| std::fs::read_to_string(fixtures().join(format!("{name}.{ext}.txt"))).expect("a recording");
        assert_eq!(run("llvm-nm", &[&name]), read("nm"), "{name}: llvm-nm");
        let mut args = vec!["--file-headers"];
        if name.starts_with("vp-") {
            args.extend(["--program-headers", "--dynamic-table"]);
        }
        args.push("--relocations");
        if !name.ends_with(".so") {
            args.push("--hex-dump=.rodata");
        }
        args.push(&name);
        assert_eq!(run("llvm-readobj", &args), read("readobj"), "{name}: llvm-readobj");
        checked += 1;
    }
    assert_eq!(
        checked, 34,
        "five targets, a shared object and an executable each; a big-endian shared object; two with virtual bases; \
         four with virtual bases and no VTT; one with a method in another code section and one with a method outside \
         the code; two with a base in another image; one with constructions on different paths; five built without \
         RTTI with a virtual base; two with an indirect virtual base; two with packed relative relocations; a class \
         nothing derives from as a shared object, an executable and a position-independent executable"
    );
}

/// `stripped/vt-<target>` is what `build.sh`'s `llvm-objcopy` line makes of the
/// committed executable, byte for byte. The tests that read a stripped fixture
/// take every address from the unstripped one's recordings, which holds only
/// if the stripped file is that executable with symbols cut and nothing else.
#[test]
fn every_stripped_fixture_is_llvm_objcopy_of_its_executable() {
    let out = std::env::temp_dir().join(format!("n0xis-stripped-vtables-{}", std::process::id()));
    std::fs::create_dir_all(&out).expect("a scratch directory");
    let mut checked = 0;
    for entry in std::fs::read_dir(fixtures().join("stripped")).expect("the stripped fixtures") {
        let name = entry.expect("an entry").file_name().to_string_lossy().into_owned();
        let made = out.join(&name);
        let made_arg = made.to_string_lossy().into_owned();
        run("llvm-objcopy", &["--strip-all", "--keep-symbol=_ZT*", "--wildcard", &name, &made_arg]);
        let committed = std::fs::read(fixtures().join("stripped").join(&name)).expect("the committed fixture");
        assert!(std::fs::read(&made).expect("llvm-objcopy's output") == committed, "stripped/{name}: not what llvm-objcopy makes of {name}");
        checked += 1;
    }
    let _ = std::fs::remove_dir_all(&out);
    assert_eq!(checked, 5, "one stripped executable per target");
}

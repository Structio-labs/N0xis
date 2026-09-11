// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Phase 10 item 8 exit test — signature naming reaches the whole product.**
//!
//! The matcher and the generator have been verified since 2026-08-31, but
//! `--flirt` lived only on `decomp pseudo`, one function at a time: the names
//! never reached the function list, `xref`, or the GUI. This test pins the thing
//! that changed — `analyze --flirt` **persists** its matches into `.n0x/`, and
//! afterwards every consumer renders them **with no flag of its own**.
//!
//! It is deliberately end-to-end over real compiler output, and the fixture is
//! the realistic FLIRT scenario rather than a self-referential one: signatures
//! are learned from **binary A** (statically linked, symbolized) and applied to
//! a *different* program, **binary B**, stripped. Nothing in B carries a symbol,
//! so every name it gets is genuinely re-derived from bytes.
//!
//! The soundness assertion is the important half: B's unstripped twin gives the
//! true name at every address, and **not one** matched name may disagree with
//! it. On this corpus a confidently wrong name is worse than no name at all
//! (CONCEPT §3 rule 6).
//!
//! Linux/x86-64 only — it needs a C compiler that can link statically.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// Binary A — the *reference*: it is compiled with symbols and never stripped,
/// and its statically-linked libc is what the signatures are learned from.
const SRC_REFERENCE: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
int main(void) {
  FILE *f = fopen("/etc/hostname", "r"); char b[256];
  if (f) { while (fgets(b, sizeof b, f)) fputs(b, stdout); fclose(f); }
  char *s = malloc(64); snprintf(s, 64, "%ld", (long)time(NULL)); puts(s);
  qsort(b, 4, 1, (int (*)(const void *, const void *))strcmp); free(s);
  return strlen(b) > 0;
}
"#;

/// Binary B — the *target*: a different program, so the shared code is the
/// library, not the author's. Stripped before analysis.
const SRC_TARGET: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
  char buf[64]; char *e = getenv("PATH"); if (!e) abort();
  strncpy(buf, e, sizeof buf - 1); buf[63] = 0; printf("%s\n", buf); return 0;
}
"#;

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Statically link `src` into `dir/name`. `None` when no C compiler on PATH can
/// produce a static binary — the test then skips instead of failing on a
/// machine that simply cannot build the fixture.
fn build_static(dir: &Path, name: &str, src: &str) -> Option<PathBuf> {
    let src_path = dir.join(format!("{name}.c"));
    std::fs::write(&src_path, src).expect("write source");
    let out = dir.join(name);
    for cc in ["cc", "gcc", "clang"] {
        let ok = Command::new(cc)
            .args(["-O2", "-static", "-o"])
            .arg(&out)
            .arg(&src_path)
            .status()
            .is_ok_and(|s| s.success());
        if ok {
            return Some(out);
        }
    }
    None
}

/// Run `n0xis` with cwd = `dir`, and parse its JSON envelope.
fn n0xis(dir: &Path, args: &[&str]) -> Value {
    let out = Command::new(env!("CARGO_BIN_EXE_n0xis")).args(args).current_dir(dir).output().expect("run n0xis");
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("n0xis {args:?} did not emit JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)))
}

/// Every defined function symbol of an unstripped ELF, as `va -> {names}` —
/// the ground truth a matched name is checked against. Several symbols can
/// share an address (aliases like `free`/`__libc_free`), so a set, not a name.
fn true_names(path: &Path) -> HashMap<u64, HashSet<String>> {
    let bytes = std::fs::read(path).expect("read target");
    let elf = goblin::elf::Elf::parse(&bytes).expect("parse target");
    let mut out: HashMap<u64, HashSet<String>> = HashMap::new();
    let mut collect = |syms: &goblin::elf::Symtab, strtab: &goblin::strtab::Strtab| {
        for sym in syms.iter() {
            if sym.st_type() != 2 || sym.st_value == 0 || sym.st_shndx == 0 {
                continue; // not a *defined* function
            }
            if let Some(name) = strtab.get_at(sym.st_name).filter(|n| !n.is_empty()) {
                // `free@GLIBC_2.2.5` and `free` name the same code.
                out.entry(sym.st_value).or_default().insert(name.split('@').next().unwrap_or(name).to_string());
            }
        }
    };
    collect(&elf.syms, &elf.strtab);
    collect(&elf.dynsyms, &elf.dynstrtab);
    out
}

/// The function list renders a name as a valid **C identifier** (`render.rs`'s
/// `mangle_call_name`), so a linker symbol like `fde_single_encoding_compare.cold`
/// comes back as `..._cold`. Normalize the ground truth the same way: the point
/// of the check is whether the right *function* was identified, not how the
/// renderer spells it.
fn as_c_identifier(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect()
}

fn named_count(functions: &[Value]) -> usize {
    functions.iter().filter(|f| !f["name"].as_str().unwrap_or("").starts_with("sub_")).count()
}

#[test]
fn analyze_flirt_persists_names_that_every_consumer_then_renders() {
    let dir = std::env::temp_dir().join(format!("n0xis-flirt-exit-{}", std::process::id()));
    std::fs::create_dir_all(dir.join(".n0x")).expect("create project dir");
    let _scratch = Scratch(dir.clone());

    let (Some(reference), Some(target)) =
        (build_static(&dir, "reference", SRC_REFERENCE), build_static(&dir, "target", SRC_TARGET))
    else {
        eprintln!("skipping: no C compiler that can link statically");
        return;
    };
    // Keep an unstripped twin of the target as ground truth, then strip the one
    // under analysis so nothing but bytes is left to name it by.
    let truth = true_names(&target);
    let stripped = dir.join("target-stripped");
    std::fs::copy(&target, &stripped).expect("copy target");
    if !Command::new("strip").arg("--strip-all").arg(&stripped).status().is_ok_and(|s| s.success()) {
        eprintln!("skipping: `strip` not available");
        return;
    }

    // Baseline: with nothing persisted, the list is entirely anonymous. This is
    // what triage looks like without signatures — and why it needs them.
    let before = n0xis(&dir, &["function", "discover", "--file", stripped.to_str().unwrap(), "--quiet"]);
    assert_eq!(before["ok"], true, "{before}");
    let before_fns = before["data"]["functions"].as_array().expect("functions").clone();
    assert!(before_fns.len() > 500, "a static binary should discover many functions, got {}", before_fns.len());
    assert_eq!(named_count(&before_fns), 0, "a stripped binary carries no names of its own");

    // Learn signatures from the *reference* binary and persist matches on the target.
    let generated = n0xis(&dir, &["sig", "gen", "--file", reference.to_str().unwrap(), "--quiet"]);
    assert_eq!(generated["ok"], true, "{generated}");
    let npat = dir.join("reference.npat");
    std::fs::write(&npat, generated["data"]["npat"].as_str().expect("npat text")).expect("write npat");

    let analyzed = n0xis(
        &dir,
        &["analyze", "--file", stripped.to_str().unwrap(), "--flirt", npat.to_str().unwrap(), "--no-cfg", "--quiet"],
    );
    assert_eq!(analyzed["ok"], true, "{analyzed}");
    let matched = analyzed["data"]["flirt_named"].as_u64().expect("flirt_named");
    assert!(matched > 100, "the shared static libc should yield many matches, got {matched}");
    assert!(dir.join(".n0x/flirt-symbols.json").exists(), "matches must be persisted, not just counted");

    // THE POINT: the same command, with no flag, now renders those names.
    let after = n0xis(&dir, &["function", "discover", "--file", stripped.to_str().unwrap(), "--quiet"]);
    let after_fns = after["data"]["functions"].as_array().expect("functions").clone();
    assert_eq!(
        named_count(&after_fns) as u64,
        matched,
        "every persisted name must reach the function list without `--flirt`"
    );

    // Soundness: not one matched name may disagree with the ground truth.
    let mut checked = 0usize;
    for f in &after_fns {
        let name = f["name"].as_str().unwrap_or_default();
        if name.starts_with("sub_") {
            continue;
        }
        let va = u64::from_str_radix(f["va"].as_str().unwrap_or("0x0").trim_start_matches("0x"), 16).expect("va");
        let expected = truth.get(&va).unwrap_or_else(|| panic!("{name} named an address with no function symbol"));
        assert!(
            expected.iter().any(|t| as_c_identifier(t) == name),
            "at {va:#x}: matched {name:?}, truth is {expected:?}"
        );
        checked += 1;
    }
    assert_eq!(checked as u64, matched);

    // And the decompiler renders the same names, also with no flag — the seam
    // is one persisted map, not a per-command option.
    let named = after_fns
        .iter()
        .find(|f| !f["name"].as_str().unwrap_or("").starts_with("sub_"))
        .expect("at least one named function");
    let (va, name) = (named["va"].as_str().unwrap(), named["name"].as_str().unwrap());
    let pseudo = n0xis(&dir, &["decomp", "pseudo", "--file", stripped.to_str().unwrap(), "--addr", va, "--quiet"]);
    assert_eq!(pseudo["ok"], true, "{pseudo}");
    let head = pseudo["data"]["pseudo"][0].as_str().unwrap_or_default();
    assert!(head.contains(name), "decomp must render the persisted name; got {head:?} for {name}");
}

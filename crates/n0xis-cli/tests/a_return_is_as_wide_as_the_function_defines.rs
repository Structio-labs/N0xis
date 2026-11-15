// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A return type is no wider than what the function defines.** The lift returns the
//! whole register at every `ret`, and a body printed `uint64_t` over a result its
//! function wrote a byte of (`setl %al; ret`), or passed on from a callee that did: on a
//! generated set that was the largest class of wrong bodies, 231 over three builds.
//!
//! `oracle/summary/return_width.c` names each function by the type it returns, so the
//! source is the truth. Built by gcc and clang at `-O1` and `-O2`; `nm` says where each
//! one is. The printed width is held against the source's:
//!
//! - a type of 32 or 64 bits is printed at exactly its width;
//! - a narrower type is printed at exactly its width where the bytes say it, and at 32
//!   where they do not. A compiler loads an `int8_t` with `movzbl (%rdi),%eax` and
//!   computes one in `%eax`, which defines 32 bits and says nothing of 8, so "equal to
//!   the source" cannot be asked of those. `objdump` says which a function is: one
//!   whose `ret` follows a write of `%al` (or `%ax`, `cbtw`) states its width, and has
//!   to be printed at it. Never 64, and never "not known", in either case.
//!
//! One form is printed wider than its source, and is listed ([`MERGED`]) so that it is
//! counted and not forgotten: a byte written over a value the function itself put in
//! the register. `mov %rdi,%rax; mov %sil,%al; ret` is a `uint64_t` with a byte merged
//! in, and clang builds a `uint8_t` comparison as `mov %rdi,%rax; ...; setl %al; ret`
//! after using `%rax` to hold a parameter: the same bytes for two types, read as the
//! first. An entry that is printed at its source's width again fails here as stale.

// It builds its target with a compiler at run time, so its answer depends on that
// compiler's version: a local instrument, not a CI gate.
#![cfg(feature = "oracle")]
#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

mod support;

fn n0xis_exe() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("n0xis")
}

fn build(tag: &str, compiler: &str, opt: &str) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("n0xis_return_width_{}_{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let file = dir.join("return_width.so");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../oracle/summary/return_width.c");
    // One image whose calls go straight to its own functions: a call through the PLT of
    // a shared object may be to another image's function of that name.
    let flags = [opt, "-shared", "-fPIC", "-fvisibility=hidden", "-Wl,-Bsymbolic"];
    match Command::new(compiler).args(flags).arg("-o").arg(&file).arg(source).output() {
        Ok(o) if o.status.success() => Some(file),
        _ => {
            eprintln!("{tag}: skipped, {compiler} could not build");
            None
        }
    }
}

/// The width the source gives a function's return, from its name: `c_u16` is 16.
fn source_width(name: &str) -> Option<u32> {
    let (how, ty) = name.split_once('_')?;
    let bits = ty.strip_prefix('i').or_else(|| ty.strip_prefix('u'))?.parse().ok()?;
    (how.len() == 1 && "dcftp".contains(how) && [8, 16, 32, 64].contains(&bits)).then_some(bits)
}

/// `(name, address)` of every fixture function, from `nm`.
fn functions(file: &Path) -> Vec<(String, u64)> {
    let out = Command::new("nm").env("LC_ALL", "C").arg(file).output().expect("nm");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() == 3 && matches!(f[1], "T" | "t") && source_width(f[2]).is_some()).then(|| (f[2].to_string(), u64::from_str_radix(f[0], 16).expect("hex")))
        })
        .collect()
}

/// The instructions of each function, by `objdump`, without padding.
fn disassembly(file: &Path) -> BTreeMap<String, Vec<String>> {
    let out = Command::new("objdump").env("LC_ALL", "C").args(["-d", "--no-show-raw-insn"]).arg(file).output().expect("objdump");
    let mut by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut cur = None;
    for l in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(name) = l.strip_suffix(">:").and_then(|h| h.split_once(" <")).map(|(_, n)| n) {
            cur = Some(name.to_string());
        } else if let (Some(name), Some((_, insn))) = (&cur, l.split_once(":\t")) {
            let insn = insn.split('#').next().unwrap_or(insn).split_whitespace().collect::<Vec<_>>().join(" ");
            if !insn.is_empty() && !insn.contains("nop") && !insn.starts_with("xchg %ax,%ax") && !insn.starts_with("data16") {
                by_name.entry(name.clone()).or_default().push(insn);
            }
        }
    }
    by_name
}

/// Do the bytes state a result of `bits` (8 or 16): is some `ret` reached straight from
/// a write of that part of the register and no more? AT&T puts the destination last.
fn states_its_width(insns: &[String], bits: u32) -> bool {
    let part = if bits == 8 { "%al" } else { "%ax" };
    insns.windows(2).any(|w| w[1].starts_with("ret") && (w[0].ends_with(&format!(",{part}")) || w[0].ends_with(&format!(" {part}")) || (bits == 16 && w[0] == "cbtw")))
}

/// The width of the return type `decomp pseudo` prints, or `None` where it prints no
/// integer type of a width.
fn printed_width(file: &Path, name: &str, va: u64) -> (Option<u32>, String) {
    let mut cmd = support::isolated(Command::new(n0xis_exe()));
    let out = cmd.args(["decomp", "pseudo", "--quiet", "--file"]).arg(file).args(["--addr", &format!("{va:#x}")]).output().expect("n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("no envelope ({e})"));
    assert_eq!(v["ok"], true, "{v}");
    let sig = v["data"]["signature"].as_str().unwrap_or_else(|| panic!("no signature: {v}")).to_string();
    let ty = sig.split(&format!(" {name}(")).next().unwrap_or("");
    let bits = ty.strip_suffix("_t").and_then(|t| t.strip_prefix("uint").or_else(|| t.strip_prefix("int"))).and_then(|b| b.parse().ok());
    (bits, sig)
}

/// `(compiler, function)` printed at 64 bits over an 8-bit source: see the module's
/// last paragraph. `c_i8` is `mov %esi,%eax; mul %dil; add $0x3,%al; ret`, a byte added
/// over the product.
const MERGED: &[(&str, &str)] = &[("clang", "p_u8"), ("clang", "p_i8"), ("clang", "c_i8")];

#[test]
fn a_return_type_is_as_wide_as_the_source_where_the_bytes_say_it() {
    let builds = [("gcc-O1", "gcc", "-O1"), ("gcc-O2", "gcc", "-O2"), ("clang-O1", "clang", "-O1"), ("clang-O2", "clang", "-O2")];
    let mut asked = 0;
    let mut wrong = Vec::new();
    for (tag, compiler, opt) in builds {
        let Some(file) = build(tag, compiler, opt) else { continue };
        let found = functions(&file);
        assert_eq!(found.len(), 26, "{tag}: nm lists the fixture's 26 functions: {found:?}");
        let insns = disassembly(&file);
        let (mut exact, mut stated_narrow, mut written_wider, mut merged) = (0, 0, 0, 0);
        for (name, va) in found {
            asked += 1;
            let source = source_width(&name).expect("listed by it");
            let body = insns.get(&name).unwrap_or_else(|| panic!("{tag}: objdump has no {name}"));
            let stated = source >= 32 || states_its_width(body, source);
            // What a write of `%eax` defines, where the bytes say nothing narrower.
            let listed = MERGED.contains(&(compiler, name.as_str()));
            let want = if listed { 64 } else if stated { source } else { 32 };
            let (got, sig) = printed_width(&file, &name, va);
            if listed && got == Some(want) {
                merged += 1;
            } else if got == Some(want) {
                exact += usize::from(stated);
                stated_narrow += usize::from(stated && source < 32);
                written_wider += usize::from(!stated);
            } else {
                wrong.push(format!("{tag} {name}: `{sig}`, the source returns {source} bits and the bytes define {want}: {}", body.join("; ")));
            }
        }
        eprintln!("{tag}: {exact} printed at the source's width ({stated_narrow} of them narrower than 32), {written_wider} at the 32 bits the compiler wrote for a narrower type, {merged} at 64 over a narrower type (a part written over a value the function put there)");
        // Without one of these the narrow half of the check asked nothing of this build.
        assert!(stated_narrow > 0 || !wrong.is_empty(), "{tag}: no function states a width under 32 in its bytes");
    }
    assert!(asked > 0, "no build ran: nothing was asked");
    assert!(wrong.is_empty(), "{} of {asked} wrong:\n{}", wrong.len(), wrong.join("\n"));
}

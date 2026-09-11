// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The tool has no way to be wrong, so one is built here.**
//!
//! In most programs, wrong means a crash, an exception, a red test. Here it
//! means a *plausible string*: the compiler cannot tell `rax` from `esp`, and
//! no test tells `(void)` from `()` unless someone wrote that exact
//! expectation. Every verification pass on this project found the same shape —
//! confident wrong answers, never errors — and 674 passing tests found none of
//! them. One new *shape of input* found four classes in an hour.
//!
//! So this runs n0xis against targets whose answer is known **before the
//! question is asked**: `oracle/*.c`, compiled here, checked against
//! `oracle/expect.json`, which was written from the C and not from any tool's
//! output. See `oracle/README.md` for the contract and for how to add a case.
//!
//! Three shapes, because one shape of input buys one shape of blindness:
//! ELF/SysV/x86-64, PE/Win64/x86-64, PE32/i386 (`cdecl` + `stdcall`). Each
//! exists because it exposed something the others could not.
//!
//! A missing compiler **skips that shape and says so on stderr**; a check that
//! quietly does nothing is worse than no check. The corpus's own integrity —
//! every function in the C has an entry in `expect.json` and the reverse — is
//! verified with no toolchain at all.

use std::path::{Path, PathBuf};
// `Command` and every item below carrying `#[cfg(feature = "oracle")]` spawn a
// compiler or the built n0xis binary. The feature keeps them out of CI (they
// depend on the runner's unpinned toolchain — see CONTRIBUTING.md), while the
// fixture-only coherence test compiles unconditionally and stays a CI gate.
#[cfg(feature = "oracle")]
use std::process::Command;

use serde_json::Value;

fn oracle_dir() -> PathBuf {
    // crates/n0xis-cli -> repo root
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("oracle")
}

#[cfg(feature = "oracle")]
fn n0xis_exe() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

fn expect_json() -> Value {
    let path = oracle_dir().join("expect.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()))
}

/// The class of one recovered parameter, named after the *register file* the
/// tool put it in — which is exactly the fact that was wrong when a
/// floating-point argument was reported as absent.
#[cfg(feature = "oracle")]
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
enum Class {
    /// An integer/pointer argument register (`rdi`, `rcx`, …).
    Int,
    /// A vector argument register (`xmm0`, …).
    Float,
    /// A stack slot — the ABI gives no register to key it on (i386).
    Stack,
}

#[cfg(feature = "oracle")]
impl Class {
    fn parse(s: &str) -> Class {
        match s {
            "int" => Class::Int,
            "float" => Class::Float,
            "stack" => Class::Stack,
            other => panic!("expect.json: unknown parameter class {other:?}"),
        }
    }

    /// From a rendered parameter (`double xmm0`, `uint64_t rdi`, `uint32_t arg0`).
    /// The *name* carries the answer: the renderer names a register parameter
    /// after its register and a stack one `argN`.
    fn of_rendered(param: &str) -> Class {
        let name = param.rsplit(' ').next().unwrap_or(param).trim_start_matches('*');
        if name.starts_with("xmm") || name.starts_with("ymm") || name.starts_with("zmm") {
            Class::Float
        } else if name.starts_with("arg") {
            Class::Stack
        } else {
            Class::Int
        }
    }
}

/// The return's class as the signature states it.
#[cfg(feature = "oracle")]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Ret {
    Void,
    Int,
    Float,
    /// The tool says so out loud. Never equal to a truth — a gap is not an
    /// answer — but distinct from `Void`, which is a *claim* that the function
    /// produces nothing.
    Unknown,
}

#[cfg(feature = "oracle")]
impl Ret {
    fn parse(s: &str) -> Ret {
        match s {
            "void" => Ret::Void,
            "int" => Ret::Int,
            "float" => Ret::Float,
            // Not spellable as a truth: the C source always knows.
            other => panic!("expect.json: unknown return class {other:?}"),
        }
    }
}

/// What the tool claims, parsed out of the one string a user actually reads.
///
/// `params: None` is `()` — C for *unspecified*, which is what an unmeasured
/// arity must render as. `Some(vec![])` is `(void)`, C for *none*. Collapsing
/// those two is the defect this distinction exists to catch.
#[cfg(feature = "oracle")]
#[derive(Debug)]
struct Claim {
    params: Option<Vec<Class>>,
    ret: Ret,
}

#[cfg(feature = "oracle")]
fn parse_signature(sig: &str) -> Claim {
    let open = sig.find('(').unwrap_or_else(|| panic!("no parameter list in {sig:?}"));
    let close = sig.rfind(')').unwrap_or_else(|| panic!("unterminated parameter list in {sig:?}"));
    let head = &sig[..open];
    let ret_text = head.rsplit_once(' ').map(|(r, _)| r).unwrap_or("").trim();
    let ret = if ret_text.contains("unknown") {
        Ret::Unknown
    } else if ret_text.is_empty() || ret_text == "void" {
        Ret::Void
    } else if ret_text.contains("double") || ret_text.contains("float") {
        Ret::Float
    } else {
        Ret::Int
    };
    let inner = sig[open + 1..close].trim();
    let params = match inner {
        "" => None,
        "void" => Some(Vec::new()),
        list => Some(list.split(',').map(|p| Class::of_rendered(p.trim())).collect()),
    };
    Claim { params, ret }
}

/// `oracle/<shape>.c`'s exported function names, from the source — so the
/// corpus can be checked against itself with no compiler present.
fn declared_in_source(src: &str, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in src.lines() {
        let Some(at) = line.find(prefix) else { continue };
        let rest = &line[at..];
        let end = rest.find('(').unwrap_or(rest.len());
        let name = rest[..end].trim();
        // A mention inside a comment is not a definition.
        if !line.trim_start().starts_with('*') && !line.trim_start().starts_with("//") && rest.contains('(') {
            out.push(name.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// **The corpus must describe itself.** A function added to the `.c` and not to
/// `expect.json` is a case that silently checks nothing — which is how a
/// harness rots into decoration.
#[test]
fn every_oracle_function_has_a_stated_truth_and_the_reverse() {
    let doc = expect_json();
    for shape in doc["shapes"].as_array().expect("shapes") {
        let id = shape["id"].as_str().unwrap();
        let src_path = oracle_dir().join(shape["source"].as_str().unwrap());
        let src = std::fs::read_to_string(&src_path).unwrap_or_else(|e| panic!("{}: {e}", src_path.display()));
        let in_source = declared_in_source(&src, &format!("{id}_"));
        let mut stated: Vec<String> = shape["functions"].as_object().unwrap().keys().cloned().collect();
        stated.sort();
        assert_eq!(
            in_source, stated,
            "{id}: `{}` and expect.json disagree about which functions exist",
            shape["source"].as_str().unwrap()
        );
        assert!(!stated.is_empty(), "{id}: an empty shape checks nothing");
    }
}

/// Build one shape, or `None` with a printed reason.
#[cfg(feature = "oracle")]
fn build(shape: &Value, out_dir: &Path) -> Option<PathBuf> {
    let id = shape["id"].as_str().unwrap();
    let cc = shape["compiler"].as_str().unwrap();
    if Command::new(cc).arg("--version").output().is_err() {
        eprintln!("oracle: skipping shape `{id}` — `{cc}` is not installed");
        return None;
    }
    let out = out_dir.join(shape["binary"].as_str().unwrap());
    let mut cmd = Command::new(cc);
    for a in shape["cc_args"].as_array().unwrap() {
        cmd.arg(a.as_str().unwrap());
    }
    cmd.arg("-o").arg(&out).arg(oracle_dir().join(shape["source"].as_str().unwrap()));
    match cmd.output() {
        Ok(o) if o.status.success() => Some(out),
        Ok(o) => {
            eprintln!("oracle: shape `{id}` failed to build:\n{}", String::from_utf8_lossy(&o.stderr));
            None
        }
        Err(e) => {
            eprintln!("oracle: shape `{id}` failed to run {cc}: {e}");
            None
        }
    }
}

/// Every discovered function's entry address, by name. Names come from the
/// image's own export/symbol table; a wrong one shows up as "not found", which
/// is a failure and never a false pass.
#[cfg(feature = "oracle")]
fn entry_addresses(binary: &Path) -> Vec<(String, String)> {
    let out = Command::new(n0xis_exe())
        .args(["function", "discover", "--quiet", "--file"])
        .arg(binary)
        .output()
        .expect("run n0xis");
    let v: Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout))
        .unwrap_or_else(|e| panic!("function discover on {}: {e}", binary.display()));
    v["data"]["functions"]
        .as_array()
        .map(|fs| {
            fs.iter()
                .filter_map(|f| Some((f["name"].as_str()?.to_string(), f["va"].as_str()?.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

/// `i386_stdcall_i_i2` is exported as `i386_stdcall_i_i2@8`, and the renderer
/// makes that a C identifier (`…_8`). Match the stem, not the decoration.
#[cfg(feature = "oracle")]
fn same_function(discovered: &str, wanted: &str) -> bool {
    let Some(rest) = discovered.strip_prefix(wanted) else { return false };
    rest.is_empty() || rest.starts_with('@') || rest.trim_start_matches('_').chars().all(|c| c.is_ascii_digit())
}

#[cfg(feature = "oracle")]
fn signature_at(binary: &Path, va: &str) -> Option<String> {
    let out = Command::new(n0xis_exe())
        .args(["decomp", "pseudo", "--quiet", "--addr", va, "--file"])
        .arg(binary)
        .output()
        .ok()?;
    let v: Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).ok()?;
    v["data"]["signature"].as_str().map(str::to_string)
}

/// The measurement. Each claim is compared with the truth; a claim listed under
/// `known_open` is *expected* to disagree, and **agreeing fails** — a gap that
/// quietly closed leaves `expect.json` lying about the tool, which is how a
/// recorded limitation rots into folklore.
#[cfg(feature = "oracle")]
#[test]
fn the_oracle_corpus_answers_what_it_was_built_to_answer() {
    if !n0xis_exe().exists() {
        eprintln!("oracle: skipping — {} is not built", n0xis_exe().display());
        return;
    }
    let doc = expect_json();
    let tmp = std::env::temp_dir().join(format!("n0xis_oracle_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("temp dir");

    let mut checked = 0usize;
    let mut shapes_run = 0usize;
    let mut failures: Vec<String> = Vec::new();
    let mut open_gaps: Vec<String> = Vec::new();

    for shape in doc["shapes"].as_array().unwrap() {
        let id = shape["id"].as_str().unwrap();
        let Some(binary) = build(shape, &tmp) else { continue };
        shapes_run += 1;
        let ordered = shape["params_ordered"].as_bool().unwrap_or(true);
        let found = entry_addresses(&binary);

        for (name, truth) in shape["functions"].as_object().unwrap() {
            let Some((_, va)) = found.iter().find(|(n, _)| same_function(n, name)) else {
                failures.push(format!("{id}/{name}: not discovered at all"));
                continue;
            };
            let Some(sig) = signature_at(&binary, va) else {
                failures.push(format!("{id}/{name}: no signature at {va}"));
                continue;
            };
            let claim = parse_signature(&sig);
            checked += 1;

            let want_params: Vec<Class> =
                truth["params"].as_array().unwrap().iter().map(|c| Class::parse(c.as_str().unwrap())).collect();
            let params_match = match &claim.params {
                None => false, // `()` — unspecified is never equal to a known list
                Some(got) => {
                    if ordered {
                        *got == want_params
                    } else {
                        let (mut a, mut b) = (got.clone(), want_params.clone());
                        a.sort();
                        b.sort();
                        a == b
                    }
                }
            };
            let ret_match = claim.ret == Ret::parse(truth["ret"].as_str().unwrap());

            for (field, matched, detail) in [
                ("params", params_match, format!("{:?} vs truth {want_params:?}", claim.params)),
                ("ret", ret_match, format!("{:?} vs truth {}", claim.ret, truth["ret"])),
            ] {
                let open = truth.get("known_open").and_then(|k| k.get(field)).and_then(Value::as_str);
                match (open, matched) {
                    (Some(reason), false) => open_gaps.push(format!("{id}/{name}.{field}: {detail} — {reason}")),
                    (Some(_), true) => failures.push(format!(
                        "{id}/{name}.{field}: GAP CLOSED — the tool now agrees ({detail}). Remove the `known_open` entry from oracle/expect.json."
                    )),
                    (None, false) => failures.push(format!("{id}/{name}.{field}: {detail}   [{sig}]")),
                    (None, true) => {}
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);

    if shapes_run == 0 {
        eprintln!("oracle: NO shape could be built — this test verified nothing about behaviour");
        return;
    }
    for gap in &open_gaps {
        eprintln!("oracle: known-open  {gap}");
    }
    eprintln!("oracle: {shapes_run} shape(s), {checked} function(s), {} known-open", open_gaps.len());
    assert!(failures.is_empty(), "oracle corpus disagreed:\n  {}", failures.join("\n  "));
}

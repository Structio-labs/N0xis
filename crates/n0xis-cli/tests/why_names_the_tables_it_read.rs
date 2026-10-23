// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`why` says a fact came from a table; the table must say so too**
//! (docs/design/WHY.md §4, rung 3).
//!
//! For every function `function discover` lists, `why --addr <start>` names
//! where its start, its end and its name came from. A claim that a table
//! states something is checkable by a reader that is not this tool, and is
//! checked here, every one of them:
//!
//! - a start or an end from `.eh_frame` — an FDE with that `pc_begin` (and that
//!   end), as GNU `objdump --dwarf=frames` lists them, on an ELF and a PE alike;
//! - from `.pdata` — a `RuntimeFunction` with that start (and end), as
//!   `llvm-readobj --unwind` lists them;
//! - an `export` — an export at that address in `llvm-readobj --coff-exports`,
//!   plus the `ImageBase` of `--file-headers`;
//! - an end from `st_size`, a name from `.symtab` or `.dynsym` — a defined
//!   symbol at that address (of that size) in `llvm-nm` (`-D` for `.dynsym`);
//! - on a WebAssembly module, a `body` start or end — a body of that function
//!   at that offset (`wasm-objdump -d`) of that size (`-x`), and a name from
//!   its exports or its name section — an export of that function (`-x`), a
//!   name `-d` prints for it.
//!
//! **A claim with no entry there is a wrong answer.** Every listed function
//! must also have a non-empty set of start sources (the empty-success sweep),
//! be the function `why` answers for its own start, and have the end the list
//! gives it. And one rung-1 check of the name layers: a rename planted in the
//! project is reported as the user's, with the image's name for the same
//! address beside it.
//!
//! The targets: `oracle/sysv.c` built by `gcc` (ELF), by
//! `x86_64-w64-mingw32-gcc` (a PE32+, with `.pdata`) and by
//! `i686-w64-mingw32-gcc` (a PE32, whose unwind information is `.eh_frame`),
//! each with its C runtime; `/usr/lib/libz.so.1` when present; and every path
//! in `N0XIS_WHY_IMAGES` (separated by `:`), which is how the broader
//! measurement recorded in docs/VERIFICATION.md was run with this same checker.
//! A missing compiler or tool skips its target and says so.

#![cfg(feature = "oracle")]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

mod support;

fn n0xis_exe() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

fn hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim().trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
}

/// A tool's stdout, in the C locale (a translated listing parses as nothing).
fn tool(program: &str, args: &[&str], file: &Path) -> Option<String> {
    let out = Command::new(program).args(args).arg(file).env("LC_ALL", "C").output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// What the independent readers say the image's tables hold.
#[derive(Default)]
struct Tables {
    /// `.eh_frame` FDEs, `pc_begin → pc ends` (`objdump --dwarf=frames`).
    fdes: BTreeMap<u64, BTreeSet<u64>>,
    /// `.pdata` `RuntimeFunction`s, `start → ends` (`llvm-readobj --unwind`).
    pdata: BTreeMap<u64, BTreeSet<u64>>,
    /// PE exports by address (`llvm-readobj --coff-exports` + `ImageBase`).
    exports: BTreeMap<u64, Vec<String>>,
    /// `.symtab` symbols, `address → (name, size)` (`llvm-nm`).
    symtab: BTreeMap<u64, Vec<(String, Option<u64>)>>,
    /// `.dynsym` symbols (`llvm-nm -D`).
    dynsym: BTreeMap<u64, Vec<(String, Option<u64>)>>,
    /// A module's bodies, `offset → (function index, exclusive end)`
    /// (`wasm-objdump -d` and `-x`).
    bodies: BTreeMap<u64, (u64, u64)>,
    /// A module's bodies `wasm-objdump -d` prints a name for.
    named_bodies: BTreeSet<u64>,
}

/// What kind of image a file is, by its first bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Pe,
    Elf,
    Module,
}

fn kind_of(file: &Path) -> Option<Kind> {
    let head = std::fs::read(file).ok()?;
    Some(if head.starts_with(b"MZ") {
        Kind::Pe
    } else if head.starts_with(b"\0asm") {
        Kind::Module
    } else {
        Kind::Elf
    })
}

/// A module's bodies, exports and names, as `wasm-objdump` lists them.
fn read_module(file: &Path, t: &mut Tables) {
    // `-d`: `0001c1 func[10] <__wasm_call_ctors>:` — where each body is.
    let mut at: HashMap<u64, u64> = HashMap::new();
    if let Some(text) = tool("wasm-objdump", &["-d"], file) {
        for line in text.lines() {
            let Some((offset, rest)) = line.split_once(" func[") else { continue };
            let (Some(offset), Some((index, tail))) = (hex(offset), rest.split_once(']')) else { continue };
            let Ok(index) = index.parse::<u64>() else { continue };
            if !tail.ends_with(':') {
                continue;
            }
            at.insert(index, offset);
            if tail.trim_start().starts_with('<') {
                t.named_bodies.insert(offset);
            }
        }
    }
    // `-x`: ` - func[10] size=3` in `Code`, ` - func[19] <x> -> "x"` in `Export`.
    if let Some(text) = tool("wasm-objdump", &["-x"], file) {
        let mut section = "";
        for line in text.lines() {
            if !line.starts_with(' ') {
                section = if line.starts_with("Code[") { "code" } else if line.starts_with("Export[") { "export" } else { "" };
                continue;
            }
            let Some(rest) = line.trim().strip_prefix("- func[") else { continue };
            let Some((index, tail)) = rest.split_once(']') else { continue };
            let Ok(index) = index.parse::<u64>() else { continue };
            let Some(&offset) = at.get(&index) else { continue };
            match section {
                "code" => {
                    // `size=332`, then the body's name where it has one: `size=332 <J>`.
                    if let Some(size) = tail.trim().strip_prefix("size=").and_then(|s| s.split_whitespace().next()).and_then(|s| s.parse::<u64>().ok()) {
                        t.bodies.insert(offset, (index, offset + size));
                    }
                }
                "export" => {
                    let name = tail.rsplit_once("-> ").map_or("", |(_, n)| n.trim_matches('"'));
                    t.exports.entry(offset).or_default().push(name.to_string());
                }
                _ => {}
            }
        }
    }
}

fn read_tables(file: &Path, kind: Kind) -> Tables {
    let mut t = Tables::default();
    if kind == Kind::Module {
        read_module(file, &mut t);
        return t;
    }
    let pe = kind == Kind::Pe;
    // `FDE cie=00000000 pc=62dc14a0..62dc14ba`
    if let Some(text) = tool("objdump", &["--dwarf=frames"], file) {
        for line in text.lines().filter(|l| l.contains(" FDE ")) {
            if let Some(pc) = line.split_whitespace().find_map(|w| w.strip_prefix("pc="))
                && let Some((a, b)) = pc.split_once("..")
                && let (Some(a), Some(b)) = (hex(a), hex(b))
            {
                t.fdes.entry(a).or_default().insert(b);
            }
        }
    }
    if pe {
        if let Some(text) = tool("llvm-readobj", &["--unwind"], file) {
            let mut start = None;
            for line in text.lines().map(str::trim) {
                let paren = || line.rsplit_once('(').and_then(|(_, v)| hex(v.trim_end_matches(')')));
                if line.starts_with("StartAddress:") {
                    start = paren();
                } else if line.starts_with("EndAddress:")
                    && let (Some(s), Some(e)) = (start.take(), paren())
                {
                    t.pdata.entry(s).or_default().insert(e);
                }
            }
        }
        let base = tool("llvm-readobj", &["--file-headers"], file)
            .and_then(|h| h.lines().find_map(|l| l.trim().strip_prefix("ImageBase:").and_then(hex)))
            .unwrap_or(0);
        if let Some(text) = tool("llvm-readobj", &["--coff-exports"], file) {
            let mut name = String::new();
            for line in text.lines().map(str::trim) {
                if let Some(n) = line.strip_prefix("Name:") {
                    name = n.trim().to_string();
                } else if let Some(rva) = line.strip_prefix("RVA:").and_then(hex) {
                    t.exports.entry(base + rva).or_default().push(std::mem::take(&mut name));
                }
            }
        }
    } else {
        for (args, into) in [(&["--defined-only", "-S", "--no-sort"][..], &mut t.symtab), (&["-D", "--defined-only", "-S", "--no-sort"][..], &mut t.dynsym)] {
            let Some(text) = tool("llvm-nm", args, file) else { continue };
            for line in text.lines() {
                let f: Vec<&str> = line.split_whitespace().collect();
                // `addr size type name` or `addr type name`.
                let (addr, size, name) = match f.as_slice() {
                    [a, s, _, n] => (hex(a), hex(s), *n),
                    [a, _, n] => (hex(a), None, *n),
                    _ => continue,
                };
                if let Some(addr) = addr {
                    into.entry(addr).or_default().push((name.to_string(), size));
                }
            }
        }
    }
    t
}

/// Counts of claims checked and claims the tables contradict, by kind.
#[derive(Default)]
struct Tally {
    checked: BTreeMap<String, usize>,
    wrong: Vec<String>,
    not_checked: BTreeMap<String, usize>,
    functions: usize,
    /// `function discover` refused the image (a resource-only DLL has no code
    /// to list): the error code, which `why` must give too.
    refused: Option<String>,
}

impl Tally {
    fn claim(&mut self, kind: &str, holds: bool, what: impl FnOnce() -> String) {
        *self.checked.entry(kind.to_string()).or_default() += 1;
        if !holds {
            self.wrong.push(format!("{kind}: {}", what()));
        }
    }
}

/// One `serve` session over `file`, asked `why` for every address in `addrs`.
fn why_all(file: &Path, cwd: &Path, addrs: &[String]) -> Vec<Value> {
    let mut child = support::isolated(Command::new(n0xis_exe()))
        .args(["serve", "--file"])
        .arg(file)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("serve");
    let mut stdin = child.stdin.take().expect("stdin");
    let requests: Vec<String> = addrs.iter().map(|a| serde_json::json!(["why", "--addr", a]).to_string()).collect();
    // Written from another thread: a session answers as it reads, and a pipe
    // that fills while nobody reads it stops both sides.
    let writer = std::thread::spawn(move || {
        for r in requests {
            if writeln!(stdin, "{r}").is_err() {
                break;
            }
        }
    });
    let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines();
    let _banner = lines.next();
    let mut out = Vec::new();
    for _ in addrs {
        let Some(Ok(line)) = lines.next() else { break };
        out.push(serde_json::from_str(&line).unwrap_or(Value::Null));
    }
    let _ = writer.join();
    let _ = child.kill();
    let _ = child.wait();
    out
}

fn check_image(file: &Path, work: &Path) -> Option<Tally> {
    let dir = work.join(format!("run-{}", file.file_name()?.to_string_lossy()));
    std::fs::create_dir_all(dir.join(".n0x")).ok()?;
    let listed = support::isolated(Command::new(n0xis_exe())).args(["function", "discover", "--quiet", "--file"]).arg(file).current_dir(&dir).output().ok()?;
    let listed: Value = serde_json::from_slice(&listed.stdout).ok()?;
    if listed["ok"] == false {
        // No list, so no function to ask about; `why` must refuse the same way.
        let code = listed["error"]["code"].as_str().unwrap_or("").to_string();
        let asked = why_all(file, &dir, &["0x0".to_string()]);
        let mut tally = Tally { refused: Some(code.clone()), ..Default::default() };
        tally.claim("a refused list is a refused answer", asked.first().is_some_and(|a| a["error"]["code"] == code.as_str()), || format!("discover refused with `{code}`, why answered {asked:?}"));
        return Some(tally);
    }
    let functions = listed["data"]["functions"].as_array()?.clone();
    let tables = read_tables(file, kind_of(file)?);
    let addrs: Vec<String> = functions.iter().filter_map(|f| f["va"].as_str().map(str::to_string)).collect();
    let answers = why_all(file, &dir, &addrs);
    let mut tally = Tally { functions: functions.len(), ..Default::default() };
    if answers.len() != functions.len() {
        tally.wrong.push(format!("{} answers for {} listed functions", answers.len(), functions.len()));
        return Some(tally);
    }
    for (f, a) in functions.iter().zip(&answers) {
        let va = f["va"].as_str().and_then(hex).unwrap_or(0);
        let found = &a["data"]["function"]["found"];
        // The empty-success sweep, and the list and `why` as one answer.
        tally.claim("listed start answered", a["ok"] == true && found["start"].as_str().and_then(hex) == Some(va), || format!("{va:#x}: {a}"));
        tally.claim("start sources non-empty", found["start_sources"].as_array().is_some_and(|s| !s.is_empty()), || format!("{va:#x}: {a}"));
        let listed_end = f["end"].as_str().and_then(hex);
        let end = &found["end"];
        let end_va = end["va"].as_str().and_then(hex);
        tally.claim(
            "end as listed",
            match listed_end {
                Some(e) => end_va == Some(e),
                None => end["source"] == "not_stated",
            },
            || format!("{va:#x}: listed {listed_end:x?}, why {end}"),
        );
        for s in found["start_sources"].as_array().into_iter().flatten() {
            match (s["source"].as_str(), s["table"].as_str()) {
                (Some("unwind"), Some("eh_frame")) => tally.claim("start: unwind eh_frame", tables.fdes.contains_key(&va), || format!("{va:#x} has no FDE")),
                (Some("unwind"), Some("pdata")) => tally.claim("start: unwind pdata", tables.pdata.contains_key(&va), || format!("{va:#x} has no RuntimeFunction")),
                (Some("export"), _) => tally.claim("start: export", tables.exports.contains_key(&va), || format!("{va:#x} is no export")),
                (Some("body"), _) => tally.claim(
                    "start: body",
                    tables.bodies.get(&va).is_some_and(|(index, _)| s["function"].as_u64() == Some(*index)),
                    || format!("{va:#x} is no body of function {}", s["function"]),
                ),
                (Some(other), _) => *tally.not_checked.entry(format!("start: {other}")).or_default() += 1,
                (None, _) => tally.wrong.push(format!("{va:#x}: a start source with no category: {s}")),
            }
        }
        if let Some(e) = end_va {
            match (end["source"].as_str(), end["table"].as_str(), end["of"].as_str()) {
                (Some("unwind"), Some("eh_frame"), _) => {
                    tally.claim("end: unwind eh_frame", tables.fdes.get(&va).is_some_and(|ends| ends.contains(&e)), || format!("{va:#x}..{e:#x} is no FDE"))
                }
                (Some("unwind"), Some("pdata"), _) => {
                    tally.claim("end: unwind pdata", tables.pdata.get(&va).is_some_and(|ends| ends.contains(&e)), || format!("{va:#x}..{e:#x} is no RuntimeFunction"))
                }
                (Some("body"), ..) => tally.claim("end: body", tables.bodies.get(&va).is_some_and(|(_, end)| *end == e), || format!("{va:#x}..{e:#x} is no body")),
                (Some("symbol_size"), _, Some("st_size")) => tally.claim(
                    "end: symbol_size st_size",
                    tables.symtab.get(&va).into_iter().chain(tables.dynsym.get(&va)).flatten().any(|(_, size)| *size == Some(e - va)),
                    || format!("{va:#x}: no symbol there of size {:#x}", e - va),
                ),
                (Some(other), _, of) => *tally.not_checked.entry(format!("end: {other} {}", of.unwrap_or(""))).or_default() += 1,
                (None, ..) => tally.wrong.push(format!("{va:#x}: an end with no category: {end}")),
            }
        }
        let name = &found["name"];
        let mut layers = vec![name.clone()];
        layers.extend(name["also"].as_array().cloned().unwrap_or_default());
        for n in layers {
            match (n["source"].as_str(), n["table"].as_str()) {
                (Some("image"), Some("static")) => tally.claim("name: image .symtab", tables.symtab.contains_key(&va), || format!("{va:#x} `{}`: no .symtab symbol there", n["name"])),
                (Some("image"), Some("dynamic")) => tally.claim("name: image .dynsym", tables.dynsym.contains_key(&va), || format!("{va:#x} `{}`: no .dynsym symbol there", n["name"])),
                (Some("image"), Some("exports")) => tally.claim("name: image exports", tables.exports.contains_key(&va), || format!("{va:#x} `{}`: no export there", n["name"])),
                (Some("image"), Some("name_section")) => {
                    tally.claim("name: image name section", tables.named_bodies.contains(&va), || format!("{va:#x} `{}`: wasm-objdump names no body there", n["name"]))
                }
                (Some(other), table) => *tally.not_checked.entry(format!("name: {other} {}", table.unwrap_or(""))).or_default() += 1,
                (None, _) => tally.wrong.push(format!("{va:#x}: a name with no category: {n}")),
            }
        }
    }
    Some(tally)
}

/// The targets built from `oracle/sysv.c`, each with what built it.
fn build_targets(dir: &Path) -> Vec<PathBuf> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../oracle/sysv.c");
    let mut out = Vec::new();
    for (cc, flags, name) in [
        ("gcc", &["-shared", "-O1", "-fPIC"][..], "sysv.so"),
        ("x86_64-w64-mingw32-gcc", &["-shared", "-O2"][..], "sysv64.dll"),
        ("i686-w64-mingw32-gcc", &["-shared", "-O2"][..], "sysv32.dll"),
    ] {
        let path = dir.join(name);
        match Command::new(cc).args(flags).arg("-o").arg(&path).arg(&src).output() {
            Ok(o) if o.status.success() => out.push(path),
            _ => eprintln!("why tables: skipping {name} — {cc} could not build it"),
        }
    }
    out
}

#[test]
fn every_table_why_names_states_what_it_is_cited_for() {
    if !n0xis_exe().exists() {
        eprintln!("why tables: skipping — {} is not built", n0xis_exe().display());
        return;
    }
    for t in ["objdump", "llvm-readobj", "llvm-nm", "wasm-objdump"] {
        if Command::new(t).arg("--version").output().is_err() {
            eprintln!("why tables: skipping — {t} is not installed");
            return;
        }
    }
    let work = std::env::temp_dir().join(format!("n0xis_why_tables_{}", std::process::id()));
    std::fs::create_dir_all(&work).expect("temp dir");
    let mut images = build_targets(&work);
    let libz = Path::new("/usr/lib/libz.so.1");
    if libz.exists() {
        images.push(libz.to_path_buf());
    }
    images.push(Path::new(env!("CARGO_MANIFEST_DIR")).join("../n0xis-wasm/tests/fixtures/core.wasm"));
    if let Ok(extra) = std::env::var("N0XIS_WHY_IMAGES") {
        images.extend(extra.split(':').filter(|p| !p.is_empty()).map(PathBuf::from));
    }
    assert!(!images.is_empty(), "no image to check: no compiler built one and none was named");

    let mut total: HashMap<String, usize> = HashMap::new();
    let mut not_checked: HashMap<String, usize> = HashMap::new();
    let (mut wrong, mut functions) = (Vec::new(), 0usize);
    for image in &images {
        let Some(tally) = check_image(image, &work) else {
            wrong.push(format!("{}: no function list or no answers", image.display()));
            continue;
        };
        let claims: usize = tally.checked.values().sum();
        if let Some(code) = &tally.refused {
            eprintln!("why tables: {}: `function discover` refused it ({code}), and so did `why`: {} wrong", image.display(), tally.wrong.len());
        }
        eprintln!(
            "why tables: {}: {} functions, {claims} claims checked, {} wrong; {:?}; not checked here {:?}",
            image.display(),
            tally.functions,
            tally.wrong.len(),
            tally.checked,
            tally.not_checked
        );
        functions += tally.functions;
        for (k, v) in tally.checked {
            *total.entry(k).or_default() += v;
        }
        for (k, v) in tally.not_checked {
            *not_checked.entry(k).or_default() += v;
        }
        wrong.extend(tally.wrong.into_iter().map(|w| format!("{}: {w}", image.display())));
    }
    let mut total: Vec<_> = total.into_iter().collect();
    total.sort();
    eprintln!("why tables: {} images, {functions} functions; checked {total:?}; not checked here {not_checked:?}; {} wrong", images.len(), wrong.len());
    assert!(functions > 0, "the images listed no function — the harness asked nothing");

    // The name layers, planted (rung 1): a rename the project holds is the
    // user's, and the image's own name for the address is listed beside it.
    let elf = images.iter().find(|p| p.extension().is_some_and(|e| e == "so")).cloned();
    if let Some(elf) = elf {
        let dir = work.join("rename");
        std::fs::create_dir_all(dir.join(".n0x")).expect("project");
        let run = |args: &[&str]| -> Value {
            let out = support::isolated(Command::new(n0xis_exe())).args(args).arg("--file").arg(&elf).arg("--quiet").current_dir(&dir).output().expect("run");
            serde_json::from_slice(&out.stdout).unwrap_or(Value::Null)
        };
        let named = read_tables(&elf, Kind::Elf);
        let (&va, syms) = named.dynsym.iter().find(|(_, s)| s.iter().any(|(_, size)| size.is_some_and(|n| n > 0))).expect("a defined dynamic function");
        let addr = format!("{va:#x}");
        assert_eq!(run(&["annotate", "name", "--addr", &addr, "--value", "planted_by_the_test"])["ok"], true);
        let name = run(&["why", "--addr", &addr])["data"]["function"]["found"]["name"].clone();
        assert_eq!(name["name"], "planted_by_the_test", "{name}");
        assert_eq!(name["source"], "user", "{name}");
        // The image keeps the first table's name at an address (`.symtab`
        // before `.dynsym`), and that table must list one there.
        let also = name["also"].as_array().cloned().unwrap_or_default();
        let listed_by_its_table = |n: &Value| match n["table"].as_str() {
            Some("static") => named.symtab.contains_key(&va),
            Some("dynamic") => named.dynsym.contains_key(&va),
            _ => false,
        };
        assert!(
            also.iter().any(|n| n["source"] == "image" && listed_by_its_table(n)),
            "the image's own name for {addr} ({syms:?}) must be listed beside the rename: {name}"
        );
    }
    let _ = std::fs::remove_dir_all(&work);
    assert!(wrong.is_empty(), "claims the tables contradict:\n  {}", wrong.join("\n  "));
}

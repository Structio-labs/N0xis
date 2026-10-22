// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **What the engine says about a WebAssembly module is what wabt's
//! `wasm-objdump` says** (docs/design/WASM.md §4, stage 2: every fact against
//! `wasm-objdump -x` on modules built here).
//!
//! For every module of `crates/n0xis-wasm/tests/fixtures/` that wabt reads —
//! built here from known source by that directory's `build.sh`, which also
//! recorded `wasm-objdump -h`, `-x` and `-d` beside each — the answers a user
//! gets are compared with those recordings, fact by fact:
//!
//! - `profile`'s sections (title, start, end) with `-h`;
//! - its module block's imports (kind, index in the kind's space, module and
//!   name), exports (kind, index, name, and a function's body), memories
//!   (index type, limits, shared, import), tables (element type, limits,
//!   import), start function, element segments (table, count, placement) and
//!   data segments (memory, size, placement, and the bytes at the module
//!   offset given for them) with `-x`;
//! - `function discover`'s list (every defined function at its body, with
//!   its index, its exact extent, and its name) with `-x`'s code section
//!   (sizes) and function section (names) and `-d`'s function headers (body
//!   offsets);
//! - `disasm` from each body to its end with `-d`: the locals declaration
//!   (each run's count and type), then every instruction's offset, bytes and
//!   mnemonic. The rest of an instruction's text is the stage-1 decoder's
//!   rendering, which `crates/n0xis-wasm/tests/references.rs` compares with
//!   this same recording and with `wasm-tools print`;
//! - `strings`: each data segment's strings at the module offset of their
//!   bytes, with their place in memory the segment's own plus the string's
//!   offset into it.
//!
//! Plus a module planted on purpose (`placed-by-import.wat`, assembled by
//! `wasm-tools parse`), whose data and element segments are placed by an
//! imported global: the answer must say they are not placed, and why.
//!
//! The comparison counts what it compared, per module, and those counts are
//! asserted to be non-zero where the module has the thing, so a comparison
//! that silently stops comparing fails. Not compared: `gc.wasm`, which wabt
//! 1.0.42 refuses (`gc.wabt-refuses.txt`), and a global's or a tag's details,
//! which no command shows beyond their count.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{Value, json};

/// The fixtures `crates/n0xis-wasm` built and recorded.
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../n0xis-wasm/tests/fixtures")
}

/// The planted modules of this crate.
fn planted() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wasm")
}

/// The fixtures wabt does not read; each has a `<stem>.wabt-refuses.txt`.
const WABT_REFUSES: &[&str] = &["gc"];

/// The registry reads and writes the project of the working directory, which
/// is the process's: every test here works in one scratch project, one at a
/// time.
static IN_PROJECT: Mutex<()> = Mutex::new(());

fn in_project<T>(work: impl FnOnce() -> T) -> T {
    let _one = IN_PROJECT.lock().unwrap_or_else(|e| e.into_inner());
    let root = std::env::temp_dir().join(format!("n0xis-wasm-facts-{}", std::process::id()));
    std::fs::create_dir_all(root.join(".n0x")).expect("scratch project");
    std::env::set_current_dir(&root).expect("into the scratch project");
    let out = work();
    let _ = std::env::set_current_dir(std::env::temp_dir());
    out
}

fn ask(cap: &str, args: Value) -> Value {
    serde_json::to_value(n0xis_frontend::build_registry().dispatch(cap, &args)).expect("an envelope")
}

fn ok<'a>(v: &'a Value, what: &str) -> &'a Value {
    assert_eq!(v["ok"], true, "{what}: {v}");
    &v["data"]
}

fn hex(v: &Value) -> u64 {
    let s = v.as_str().unwrap_or_else(|| panic!("not an address: {v}"));
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or_else(|_| panic!("not hex: {s}"))
}

/// A word `key=value` of a line, the value up to the next space.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let at = line.find(&format!(" {key}="))? + key.len() + 2;
    Some(line[at..].split_whitespace().next().unwrap_or(""))
}

/// `kind[index]` at the start of an entry line (` - func[3] ...`).
fn kind_index(line: &str) -> Option<(String, u32)> {
    let rest = line.trim_start().strip_prefix("- ")?;
    let open = rest.find('[')?;
    let close = rest.find(']')?;
    Some((rest[..open].to_string(), rest[open + 1..close].parse().ok()?))
}

/// The `<name>` right after `kind[index]`, if the line gives one. It runs to
/// the line's last `>`: a C++ name holds its own (`int ns::twice<int>(int)`),
/// and reading to the first one cut it at `int ns::twice<int`.
fn angle_name(line: &str) -> Option<String> {
    let after = &line[line.find(']')? + 1..];
    let after = after.trim_start();
    let after = after.strip_prefix("sig=").map(|r| r.split_once(' ').map_or("", |(_, rest)| rest)).unwrap_or(after);
    let inner = after.trim_start().strip_prefix('<')?;
    Some(inner[..inner.rfind('>')?].to_string())
}

/// `wasm-objdump -x`, by section title: the entry lines of each.
fn details(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if !line.starts_with(' ') && line.ends_with(':') && !line.contains(' ') {
            let title = line.trim_end_matches(':');
            let title = title.split('[').next().unwrap_or(title).to_string();
            out.entry(title.clone()).or_default();
            current = Some(title);
            continue;
        }
        if let Some(t) = &current
            && line.starts_with(" -") | line.starts_with("  -")
        {
            out.get_mut(t).expect("opened").push(line.to_string());
        }
    }
    out
}

/// `wasm-objdump -h`: (title, custom name, start, end) per section.
fn headers(text: &str) -> Vec<(String, Option<String>, u64, u64)> {
    text.lines()
        .filter(|l| l.contains(" start=0x"))
        .map(|l| {
            let title = l.split_whitespace().next().expect("a title").to_string();
            let num = |k: &str| u64::from_str_radix(field(l, k).expect(k).trim_start_matches("0x"), 16).expect("hex");
            let custom = l.rfind('"').and_then(|end| l[..end].rfind('"').map(|start| l[start + 1..end].to_string()));
            (title, custom, num("start"), num("end"))
        })
        .collect()
}

/// One instruction line of `wasm-objdump -d`, its continuation lines' bytes
/// joined to it.
#[derive(Debug, Clone, PartialEq)]
struct Line {
    offset: u64,
    bytes: Vec<u8>,
    text: String,
}

/// One function of `wasm-objdump -d`: its header's offset and name, its
/// local-run lines and its instruction lines.
type Disassembled = (u64, Option<String>, Vec<Line>, Vec<Line>);

/// `wasm-objdump -d`, per function index.
fn disassembly(text: &str) -> BTreeMap<u32, Disassembled> {
    let mut out: BTreeMap<u32, Disassembled> = BTreeMap::new();
    let mut current: Option<u32> = None;
    for line in text.lines() {
        if let Some(head) = line.strip_suffix(':')
            && let Some((offset, rest)) = head.split_once(" func[")
            && offset.len() == 6
            && offset.chars().all(|c| c.is_ascii_hexdigit())
        {
            let index: u32 = rest[..rest.find(']').expect("]")].parse().expect("an index");
            let name = rest.find('<').map(|s| rest[s + 1..rest.rfind('>').expect(">")].to_string());
            out.insert(index, (u64::from_str_radix(offset, 16).expect("hex"), name, Vec::new(), Vec::new()));
            current = Some(index);
            continue;
        }
        let (Some(f), Some((left, text))) = (current, line.split_once('|')) else { continue };
        let Some((offset, bytes)) = left.trim().split_once(':') else { continue };
        let Ok(offset) = u64::from_str_radix(offset, 16) else { continue };
        let bytes: Vec<u8> = bytes.split_whitespace().map(|b| u8::from_str_radix(b, 16).expect("a byte")).collect();
        let text = text.trim().to_string();
        let entry = out.get_mut(&f).expect("a function");
        if text.is_empty() {
            // A continuation line: the rest of the previous instruction's bytes.
            entry.3.last_mut().expect("a continuation follows an instruction").bytes.extend(bytes);
        } else if text.starts_with("local[") {
            entry.2.push(Line { offset, bytes, text });
        } else {
            entry.3.push(Line { offset, bytes, text });
        }
    }
    out
}

/// What was compared on one module.
#[derive(Debug, Default)]
struct Counts {
    sections: usize,
    imports: usize,
    exports: usize,
    functions: usize,
    memories: usize,
    tables: usize,
    elements: usize,
    data: usize,
    instructions: usize,
    calls: usize,
    /// Direct calls and tail calls to an imported function: an index, no body.
    import_calls: usize,
    /// `ref.func`s, which take a function as a value.
    function_refs: usize,
    strings: usize,
    /// Functions exported under several names, none in a `name` section.
    several_export_names: usize,
}

/// `kind` as `wasm-objdump` spells it, from an `ItemKind`'s JSON.
fn objdump_kind(kind: &Value) -> &'static str {
    match kind.as_str().expect("a kind") {
        "function" => "func",
        "table" => "table",
        "memory" => "memory",
        "global" => "global",
        "tag" => "tag",
        other => panic!("a module has no {other} import or export"),
    }
}

/// The value `- init i32=8` / `i64=…` states, as the address it places at;
/// `None` for an initializer that is not a constant (`global=…`).
fn init_value(line: &str) -> Option<u64> {
    let init = &line[line.find(" - init ")? + 8..];
    let (ty, value) = init.split_once('=')?;
    let value = value.split_whitespace().next()?;
    match ty {
        "i32" => value.parse::<i64>().ok().map(|v| u64::from(v as u32)),
        "i64" => value.parse::<i64>().ok().map(|v| v as u64),
        _ => None,
    }
}

/// The largest module whose code section is swept whole per question here.
const SMALL_MODULE: usize = 64 << 10;

/// The code section's contents, `(start, size)`, as `wasm-objdump -h` gives it.
fn theirs_code_section(headers_text: &str) -> Option<(u64, u64)> {
    headers(headers_text).into_iter().find(|(title, ..)| title == "Code").map(|(_, _, start, end)| (start, end - start))
}

fn check_module(path: &Path, headers_text: &str, details_text: &str, disassembly_text: &str) -> Counts {
    let file = path.to_str().expect("utf-8 path");
    let bytes = std::fs::read(path).expect("the module");
    let mut c = Counts::default();
    let x = details(details_text);
    let d = disassembly(disassembly_text);
    let entries = |title: &str| x.get(title).cloned().unwrap_or_default();

    let img = n0xis_sources::ImageSource::load(path).expect("the module loads");
    let profile = n0xis_frontend::image_caps::wasm_profile(&img, true).expect("a module has a module profile");
    let module = &profile["module"];

    // Sections, with -h.
    let ours: Vec<(String, u64, u64)> = profile["image"]["sections"]
        .as_array()
        .expect("sections")
        .iter()
        .map(|s| (s["name"].as_str().unwrap().to_string(), hex(&s["va"]), s["virtual_size"].as_u64().unwrap()))
        .collect();
    let theirs = headers(headers_text);
    assert_eq!(ours.len(), theirs.len(), "{file}: section count");
    for ((name, va, size), (title, custom, start, end)) in ours.iter().zip(&theirs) {
        let want = match custom {
            Some(n) if title == "Custom" => format!("custom:{n}"),
            _ => title.clone(),
        };
        assert_eq!((name, *va, va + size), (&want, *start, *end), "{file}: a section");
        c.sections += 1;
    }

    // Imports, by module, each reached by its index in its kind's space.
    let imports = &module["imports"]["read"];
    let libraries: Vec<&str> = imports["libraries"].as_array().unwrap().iter().map(|l| l["name"].as_str().unwrap()).collect();
    let refs = imports["references"].as_array().unwrap();
    let theirs = entries("Import");
    assert_eq!(refs.len(), theirs.len(), "{file}: import count");
    for (r, line) in refs.iter().zip(&theirs) {
        let (kind, index) = kind_index(line).expect("an import line");
        let library = libraries[r["library"]["binds"].as_u64().expect("bound") as usize];
        let path = format!("{library}.{}", r["name"].as_str().unwrap());
        assert_eq!(objdump_kind(&r["kind"]), kind, "{file}: {line}");
        assert_eq!(r["reach"]["read"], json!([{ "index": index }]), "{file}: {line}");
        assert!(line.ends_with(&format!(" <- {path}")), "{file}: {line} is not {path}");
        c.imports += 1;
    }

    // Exports: kind, index, name; a defined function's body is its -d header.
    let exports = module["exports"].as_array().unwrap();
    let theirs = entries("Export");
    assert_eq!(exports.len(), theirs.len(), "{file}: export count");
    for (e, line) in exports.iter().zip(&theirs) {
        let (kind, index) = kind_index(line).expect("an export line");
        assert_eq!(objdump_kind(&e["kind"]), kind, "{file}: {line}");
        assert!(line.ends_with(&format!("-> \"{}\"", e["name"].as_str().unwrap())), "{file}: {line}");
        let target = if kind == "func" { &e["target"]["function"] } else { &e["target"]["entry"] };
        assert_eq!(target["index"], index, "{file}: {line}");
        if kind == "func" {
            let body = d.get(&index).map(|(offset, ..)| json!(format!("{offset:#x}"))).unwrap_or(Value::Null);
            assert_eq!(target["body"], body, "{file}: {line}: a defined function's body, an import's none");
        }
        c.exports += 1;
    }
    // The image profile's exports — a defined function's, at its body — carry
    // the index beside the position as the module block's do, and those that
    // share one function are folded, by index.
    let mut by_index: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    // Absent when the module exports no function (an empty list is not written).
    for e in profile["image"]["exports"].as_array().into_iter().flatten() {
        let name = e["name"].as_str().unwrap();
        let line = theirs.iter().find(|l| l.ends_with(&format!("-> \"{name}\"")) && l.contains("- func[")).unwrap_or_else(|| panic!("{file}: {e} is no function export"));
        let (_, index) = kind_index(line).expect("an export line");
        assert_eq!(e["index"], index, "{file}: {e}");
        assert_eq!(e["va"], d.get(&index).map(|(offset, ..)| json!(format!("{offset:#x}"))).unwrap_or(Value::Null), "{file}: {e}");
        by_index.entry(u64::from(index)).or_default().push(name.to_string());
    }
    let mut folded: Vec<(u64, Vec<String>)> = profile["image"]["folded"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (f["index"].as_u64().expect("a folded export's index"), f["names"].as_array().unwrap().iter().map(|n| n.as_str().unwrap().to_string()).collect()))
        .collect();
    folded.sort();
    let mut want: Vec<(u64, Vec<String>)> = by_index.into_iter().filter(|(_, n)| n.len() > 1).map(|(i, mut n)| (i, { n.sort(); n })).collect();
    want.sort();
    assert_eq!(folded, want, "{file}: functions exported under several names");

    // Memories, imported and defined, in index order.
    let memories = module["memories"].as_array().unwrap();
    let theirs: Vec<String> = entries("Import").into_iter().filter(|l| l.contains("- memory[")).chain(entries("Memory")).collect();
    assert_eq!(memories.len(), theirs.len(), "{file}: memory count");
    for (m, line) in memories.iter().zip(&theirs) {
        assert_eq!(kind_index(line).map(|(_, i)| i), m["index"].as_u64().map(|i| i as u32), "{file}: {line}");
        assert_eq!(field(line, "initial").map(|v| v.parse::<u64>().unwrap()), m["min_pages"].as_u64(), "{file}: {line}");
        assert_eq!(field(line, "max").map(|v| v.parse::<u64>().unwrap()), m["max_pages"].as_u64(), "{file}: {line}");
        assert_eq!(line.split_whitespace().any(|w| w == "i64"), m["address"] == "i64", "{file}: {line}");
        assert_eq!(line.split_whitespace().any(|w| w == "shared"), m["shared"] == true, "{file}: {line}");
        assert_eq!(line.contains(" <- "), !m["import"].is_null(), "{file}: {line}");
        c.memories += 1;
    }

    // Tables, the same way.
    let tables = module["tables"].as_array().unwrap();
    let theirs: Vec<String> = entries("Import").into_iter().filter(|l| l.contains("- table[")).chain(entries("Table")).collect();
    assert_eq!(tables.len(), theirs.len(), "{file}: table count");
    for (t, line) in tables.iter().zip(&theirs) {
        // A reference type may have spaces (`(ref null 1)`): it runs to the
        // limits that follow it.
        let ty = line.split(" type=").nth(1).and_then(|r| r.split(" initial=").next());
        assert_eq!(ty, t["element"].as_str(), "{file}: {line}");
        assert_eq!(field(line, "initial").map(|v| v.parse::<u64>().unwrap()), t["min"].as_u64(), "{file}: {line}");
        assert_eq!(field(line, "max").map(|v| v.parse::<u64>().unwrap()), t["max"].as_u64(), "{file}: {line}");
        assert_eq!(line.split_whitespace().any(|w| w == "i64"), t["address"] == "i64", "{file}: {line}");
        assert_eq!(line.contains(" <- "), !t["import"].is_null(), "{file}: {line}");
        c.tables += 1;
    }

    // The start function.
    let start = entries("Start").first().and_then(|l| l.split("start function: ").nth(1)?.split_whitespace().next()?.parse::<u64>().ok());
    assert_eq!(module["start"]["index"].as_u64(), start, "{file}: the start function");

    // Element segments: table, count, and where a constant offset places them.
    let elements = module["element_segments"].as_array().unwrap();
    let theirs: Vec<String> = entries("Elem").into_iter().filter(|l| l.starts_with(" - segment[")).collect();
    assert_eq!(elements.len(), theirs.len(), "{file}: element segment count");
    for (e, line) in elements.iter().zip(&theirs) {
        assert_eq!(field(line, "count").map(|v| v.parse::<u64>().unwrap()), e["items"].as_u64(), "{file}: {line}");
        let flags: u32 = field(line, "flags").expect("flags").parse().unwrap();
        match (flags & 1 == 0, init_value(line)) {
            (true, Some(at)) => {
                let placed = &e["placement"]["placed"];
                assert_eq!((placed["table"].as_u64(), placed["at"].as_u64()), (field(line, "table").map(|v| v.parse().unwrap()), Some(at)), "{file}: {line}");
            }
            (true, None) => assert!(e["placement"]["not_placed"].is_object(), "{file}: {line}: a non-constant offset places nothing"),
            (false, _) => assert!(e["placement"]["not_placed"].is_object(), "{file}: {line}: passive or declarative"),
        }
        c.elements += 1;
    }

    // Data segments: memory, size, placement, and the bytes the module holds
    // where the answer says they are.
    let segments = module["data_segments"].as_array().unwrap();
    let theirs = entries("Data");
    let heads: Vec<&String> = theirs.iter().filter(|l| l.starts_with(" - segment[")).collect();
    assert_eq!(segments.len(), heads.len(), "{file}: data segment count");
    for (i, (s, line)) in segments.iter().zip(&heads).enumerate() {
        assert_eq!(field(line, "size").map(|v| v.parse::<u64>().unwrap()), s["len"].as_u64(), "{file}: {line}");
        let at = hex(&s["bytes_at"]) as usize;
        let len = s["len"].as_u64().unwrap() as usize;
        // The dump lines under this segment's head, to the next head.
        let start = theirs.iter().position(|l| l == *line).unwrap() + 1;
        let dump: Vec<u8> = theirs[start..]
            .iter()
            .take_while(|l| l.starts_with("  - "))
            .flat_map(|l| {
                let hexpart = &l[l.find(':').unwrap() + 1..];
                let hexpart = &hexpart[..hexpart.len().min(41)];
                hexpart.split_whitespace().flat_map(|w| (0..w.len() / 2).map(move |k| u8::from_str_radix(&w[2 * k..2 * k + 2], 16).unwrap())).collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(&bytes[at..at + len], &dump[..], "{file}: segment {i}'s bytes at {at:#x}");
        match (line.contains(" passive "), init_value(line)) {
            (false, Some(address)) => {
                let placed = &s["placement"]["placed"];
                assert_eq!(placed["memory"].as_u64(), field(line, "memory").map(|v| v.parse().unwrap()), "{file}: {line}");
                assert_eq!(hex(&placed["address"]), address, "{file}: {line}");
            }
            _ => assert!(s["placement"]["not_placed"]["why"].is_string(), "{file}: {line}: placed nowhere statically"),
        }
        c.data += 1;
    }

    // The function list: every defined function at its body, with its index,
    // its extent and its name.
    let found = ok(&ask("function.discover", json!({ "file": file, "limit": 0 })), file).clone();
    let listed = found["functions"].as_array().unwrap();
    let sizes: BTreeMap<u32, u64> = entries("Code")
        .iter()
        .filter_map(|l| Some((kind_index(l)?.1, field(l, "size")?.parse().ok()?)))
        .collect();
    let names: BTreeMap<u32, Option<String>> = entries("Function").iter().filter_map(|l| Some((kind_index(l)?.1, angle_name(l)))).collect();
    // A function's export names: the name it has where the `name` section
    // gives none, as it does to wasm-objdump.
    let mut exported: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for l in entries("Export") {
        if let (Some(("func", index)), Some(name)) = (kind_index(&l).as_ref().map(|(k, i)| (k.as_str(), *i)), l.rsplit("-> \"").next()) {
            exported.entry(index).or_default().push(name.trim_end_matches('"').to_string());
        }
    }
    assert_eq!(listed.len(), d.len(), "{file}: one function per body");
    for f in listed {
        let index = f["index"].as_u64().expect("an index beside the position") as u32;
        let (body, ..) = &d[&index];
        assert_eq!(hex(&f["va"]), *body, "{file}: func[{index}] is at its body");
        assert_eq!(hex(&f["end"]) - body, sizes[&index], "{file}: func[{index}]'s extent");
        // The name the image gives the function, as stored, and the name the
        // list gives it: both are the module's own text, which wasm-objdump
        // prints verbatim (`Vec::push(int)`, `a-b`). The list once rendered
        // it as an identifier, `Vec__push_int_`, while this compared only the
        // stored symbol and passed.
        let ours = n0xis_sources::SymbolProvider::symbol_at(&img, n0xis_contracts::Va(*body)).map(|s| s.name);
        let listed_name = f["name"].as_str().map(str::to_string);
        let exports = exported.get(&index).cloned().unwrap_or_default();
        match names.get(&index).cloned().flatten() {
            // A function exported under several names and named by none of
            // them in a `name` section has each of them; wasm-objdump keeps one
            // and the image the first, and either is the function's.
            Some(theirs) if exports.len() > 1 && exports.contains(&theirs) => {
                assert!(ours.as_ref().is_some_and(|n| exports.contains(n)), "{file}: func[{index}] is {ours:?}, not one of {exports:?}");
                assert_eq!(listed_name, ours, "{file}: func[{index}]'s listed name is its symbol's");
                c.several_export_names += 1;
            }
            Some(theirs) => {
                assert_eq!(ours.as_deref(), Some(theirs.as_str()), "{file}: func[{index}]'s name");
                assert_eq!(listed_name.as_deref(), Some(theirs.as_str()), "{file}: func[{index}]'s name in the function list");
            }
            None => {
                assert_eq!(ours, None, "{file}: func[{index}] has no name");
                assert_eq!(f["name"], format!("func_{index}"), "{file}: an unnamed function is named by its index");
            }
        }
        c.functions += 1;
    }

    // Every function's disassembly, body start to end.
    for (index, (body, _, locals, insns)) in &d {
        let got = ok(&ask("decode", json!({ "file": file, "addr": format!("{body:#x}"), "count": insns.len() + 1 })), file).clone();
        let got = got["insns"].as_array().unwrap();
        // The locals declaration first: its runs are -d's local lines.
        assert_eq!(got[0]["mnemonic"], "locals", "{file}: func[{index}] starts with its locals declaration");
        assert_eq!(hex(&got[0]["va"]), *body, "{file}: func[{index}]");
        let runs: Vec<String> = locals
            .iter()
            .map(|l| {
                let range = &l.text["local[".len()..l.text.find(']').unwrap()];
                let n = match range.split_once("..") {
                    Some((a, b)) => b.parse::<u64>().unwrap() - a.parse::<u64>().unwrap() + 1,
                    None => 1,
                };
                format!("{n} {}", l.text.split("type=").nth(1).unwrap())
            })
            .collect();
        let want = if runs.is_empty() { "locals".to_string() } else { format!("locals {}", runs.join(", ")) };
        assert_eq!(got[0]["text"], want.as_str(), "{file}: func[{index}]'s locals");
        let rest: Vec<(u64, String, String)> = got[1..]
            .iter()
            .map(|i| (hex(&i["va"]), i["bytes"].as_str().unwrap().to_string(), i["mnemonic"].as_str().unwrap().to_string()))
            .collect();
        let theirs: Vec<(u64, String, String)> = insns
            .iter()
            .map(|l| {
                let bytes = l.bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
                (l.offset, bytes, l.text.split_whitespace().next().unwrap().to_string())
            })
            .collect();
        assert_eq!(rest, theirs, "{file}: func[{index}]'s instructions");
        c.instructions += theirs.len();
        // A direct call's target is its callee's body, and an import's none:
        // the callee is the index -d prints (`call 3 <add>`), and its body the
        // offset of -d's header for that function.
        for (i, l) in got[1..].iter().zip(insns) {
            if matches!(i["mnemonic"].as_str(), Some("call" | "return_call")) {
                let callee: u32 = l.text.split_whitespace().nth(1).and_then(|n| n.parse().ok()).expect("a callee index");
                let want = d.get(&callee).map(|(offset, ..)| json!(format!("{offset:#x}"))).unwrap_or(Value::Null);
                assert_eq!(i.get("target").cloned().unwrap_or(Value::Null), want, "{file}: {}", l.text);
                c.calls += 1;
            }
        }
    }

    // Who names each function: every direct call and tail call -d shows to
    // it, and every `ref.func` of it, and nothing else — the per-body decode
    // of the whole code section, as `xref to` sweeps it. A call is a `call` or
    // `jmp` reference, a `ref.func` (a function taken as a value) a `data` one.
    let mut callers: BTreeMap<u32, Vec<u64>> = BTreeMap::new();
    let mut taken: BTreeMap<u32, Vec<u64>> = BTreeMap::new();
    for (_, _, _, insns) in d.values() {
        for l in insns {
            let mut words = l.text.split_whitespace();
            let op = words.next();
            let Some(callee) = words.next().and_then(|n| n.parse::<u32>().ok()) else { continue };
            match op {
                Some("call" | "return_call") => callers.entry(callee).or_default().push(l.offset),
                Some("ref.func") => taken.entry(callee).or_default().push(l.offset),
                _ => {}
            }
        }
    }
    // A module small enough to sweep whole per question: `xref to` is also
    // asked over the code section as an explicit window, which scans it
    // (`XrefPass`) where the default answers from the image's whole-program
    // index; both must give the same references. And every `xref from` below
    // is asked with no window, as a user asks it; on a larger module, with
    // the instruction's own bytes as the window, which is the same question
    // answered without sweeping the whole section once per call.
    let small = bytes.len() <= SMALL_MODULE;
    let code = theirs_code_section(headers_text);
    for (index, (body, ..)) in &d {
        let refs = ok(&ask("xref", json!({ "file": file, "addr": format!("{body:#x}"), "dir": "to" })), file).clone();
        let refs = refs["refs"].as_array().unwrap();
        if small && let Some((start, size)) = code {
            let swept = ok(&ask("xref", json!({ "file": file, "addr": format!("{body:#x}"), "dir": "to", "start": format!("{start:#x}"), "size": size })), file).clone();
            let key = |r: &Value| (r["from"].to_string(), r["kind"].to_string(), r["to_function"].to_string());
            let mut a: Vec<_> = refs.iter().map(key).collect();
            let mut b: Vec<_> = swept["refs"].as_array().unwrap().iter().map(key).collect();
            a.sort();
            b.sort();
            assert_eq!(b, a, "{file}: func[{index}]'s references swept over the code section are the index's");
        }
        let of_kind = |data: bool| {
            let mut got: Vec<u64> = refs.iter().filter(|r| (r["kind"] == "data") == data).map(|r| hex(&r["from"])).collect();
            got.sort_unstable();
            got
        };
        let mut want = callers.get(index).cloned().unwrap_or_default();
        want.sort_unstable();
        assert_eq!(of_kind(false), want, "{file}: the direct calls to func[{index}]");
        let mut want = taken.get(index).cloned().unwrap_or_default();
        want.sort_unstable();
        assert_eq!(of_kind(true), want, "{file}: the `ref.func`s of func[{index}]");
        for r in refs {
            assert_eq!(r["to_function"], *index, "{file}: a reference to func[{index}] names its index: {r}");
        }
    }

    // What each call, tail call and `ref.func` references, asked at the
    // instruction: the function -d names by index, at its body, or with no
    // position when it is imported; and the name -d gives it (`call 0
    // <host_log>`), where it gives one. A call to an import was once no
    // reference at all, `ok: true` with an empty list.
    let imported: Vec<u32> = entries("Import")
        .iter()
        .filter_map(|l| kind_index(l))
        .filter(|(k, _)| k == "func")
        .map(|(_, i)| i)
        .collect();
    for (index, (_, _, _, insns)) in &d {
        for l in insns {
            let mut words = l.text.split_whitespace();
            let op = words.next();
            if !matches!(op, Some("call" | "return_call" | "ref.func")) {
                continue;
            }
            let callee: u32 = words.next().and_then(|n| n.parse().ok()).expect("a function index");
            let mut from = json!({ "file": file, "addr": format!("{:#x}", l.offset), "dir": "from" });
            if !small {
                from["start"] = json!(format!("{:#x}", l.offset));
                from["size"] = json!(l.bytes.len());
            }
            let got = ok(&ask("xref", from), file).clone();
            let refs = got["refs"].as_array().unwrap();
            assert_eq!(refs.len(), 1, "{file}: func[{index}] {:#x} `{}` references one function: {got}", l.offset, l.text);
            let r = &refs[0];
            assert_eq!(r["to_function"], callee, "{file}: {:#x} `{}`: {r}", l.offset, l.text);
            assert_eq!(r["from_function"], *index, "{file}: {:#x} is in func[{index}]: {r}", l.offset);
            let body = d.get(&callee).map(|(offset, ..)| json!(format!("{offset:#x}"))).unwrap_or(Value::Null);
            assert_eq!(r.get("to").cloned().unwrap_or(Value::Null), body, "{file}: {:#x} `{}`: an import has no position: {r}", l.offset, l.text);
            assert_eq!(r["kind"], if op == Some("ref.func") { "data" } else if op == Some("call") { "call" } else { "jmp" }, "{file}: {r}");
            if let Some(name) = l.text.find('<').map(|s| &l.text[s + 1..l.text.rfind('>').expect(">")]) {
                assert_eq!(r["sym"], name, "{file}: {:#x} `{}`: {r}", l.offset, l.text);
            }
            if imported.contains(&callee) && op != Some("ref.func") {
                c.import_calls += 1;
            }
            if op == Some("ref.func") {
                c.function_refs += 1;
            }
        }
    }

    // Strings in the data segments, each at the module offset of its bytes,
    // and in memory where its segment is placed plus its offset into it.
    let strings = ok(&ask("strings", json!({ "file": file, "limit": 0 })), file).clone();
    for s in strings["strings"].as_array().unwrap() {
        let at = hex(&s["address"]);
        let seg = segments
            .iter()
            .find(|g| hex(&g["bytes_at"]) <= at && at < hex(&g["bytes_at"]) + g["len"].as_u64().unwrap())
            .unwrap_or_else(|| panic!("{file}: a string outside every data segment: {s}"));
        assert_eq!(s["section"], format!("data[{}]", seg["index"]), "{file}: {s}");
        match &seg["placement"]["placed"] {
            Value::Object(p) => {
                let address = hex(&p["address"]) + (at - hex(&seg["bytes_at"]));
                assert_eq!(s["linear_memory"], json!({ "memory": p["memory"], "address": format!("{address:#x}") }), "{file}: {s}");
            }
            _ => assert_eq!(s["linear_memory"]["not_placed"], seg["placement"]["not_placed"]["why"], "{file}: {s}"),
        }
        let len = s["size"].as_u64().unwrap() as usize;
        let text = String::from_utf8_lossy(&bytes[at as usize..at as usize + len]).into_owned();
        if s["encoding"] == "utf8" {
            assert_eq!(s["text"].as_str(), Some(text.as_str()), "{file}: the bytes at {at:#x}");
        }
        c.strings += 1;
    }
    c
}

/// Every fixture wabt reads, with its recordings.
fn recorded() -> Vec<(PathBuf, String, String, String)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(fixtures()).expect("the fixtures").flatten() {
        let path = entry.path();
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()).filter(|_| path.extension().is_some_and(|e| e == "wasm")) else { continue };
        if WABT_REFUSES.contains(&stem) {
            assert!(fixtures().join(format!("{stem}.wabt-refuses.txt")).exists(), "{stem}: wabt's refusal is recorded");
            continue;
        }
        let read = |kind: &str| std::fs::read_to_string(fixtures().join(format!("{stem}.{kind}.txt"))).unwrap_or_else(|e| panic!("{stem}.{kind}.txt: {e}"));
        out.push((path.clone(), read("headers"), read("details"), read("disassembly")));
    }
    out.sort();
    out
}

#[test]
fn every_fact_of_every_fixture_is_what_wasm_objdump_lists() {
    let modules = recorded();
    // The fixtures `build.sh` makes, but `gc`: a directory that lost one must
    // not pass by checking fewer.
    assert_eq!(modules.len(), 13, "{:?}", modules.iter().map(|m| &m.0).collect::<Vec<_>>());
    let mut total = Counts::default();
    in_project(|| {
        for (path, h, x, d) in &modules {
            let c = check_module(path, h, x, d);
            eprintln!("{}: {c:?}", path.file_name().unwrap().to_string_lossy());
            assert!(c.sections > 0 && c.functions > 0 && c.instructions > 0, "{}: nothing compared: {c:?}", path.display());
            total.sections += c.sections;
            total.imports += c.imports;
            total.exports += c.exports;
            total.functions += c.functions;
            total.memories += c.memories;
            total.tables += c.tables;
            total.elements += c.elements;
            total.data += c.data;
            total.instructions += c.instructions;
            total.calls += c.calls;
            total.import_calls += c.import_calls;
            total.function_refs += c.function_refs;
            total.strings += c.strings;
        }
    });
    eprintln!("all fixtures: {total:?}");
    // Each kind of fact is compared somewhere: a parser that stopped reading
    // one section would compare none of it, and pass.
    for (what, n) in [
        ("imports", total.imports),
        ("exports", total.exports),
        ("memories", total.memories),
        ("tables", total.tables),
        ("element segments", total.elements),
        ("data segments", total.data),
        ("calls to an import", total.import_calls),
        ("ref.funcs", total.function_refs),
        ("strings", total.strings),
    ] {
        assert!(n > 0, "no {what} compared on any fixture: {total:?}");
    }
}

/// The modules of this crate's `tests/fixtures/wasm/` that `build.sh` records,
/// built here from known source: C++ names in a `name` section, as wasm-ld
/// writes them (`names.cpp`), and every way code names a function by index,
/// with names that are not identifiers (`indexed.wat`).
fn planted_recorded() -> Vec<(PathBuf, String, String, String)> {
    ["indexed", "names-cpp"]
        .iter()
        .map(|stem| {
            let read = |kind: &str| std::fs::read_to_string(planted().join(format!("{stem}.{kind}.txt"))).unwrap_or_else(|e| panic!("{stem}.{kind}.txt: {e}"));
            (planted().join(format!("{stem}.wasm")), read("headers"), read("details"), read("disassembly"))
        })
        .collect()
}

/// Every instruction `-d` shows, decoded alone (`disasm --addr <it> --count
/// 1`): that instruction, its offset, bytes and mnemonic, however long it is.
/// A window sized for x64's 15-byte instructions cut a long `br_table` off
/// and answered no instruction, `ok: true`. Returns how many were longer
/// than 16 bytes, which the planted modules must have.
fn each_instruction_decodes_alone(path: &Path, disassembly_text: &str) -> usize {
    let file = path.to_str().expect("utf-8 path");
    let mut long = 0;
    for (index, (_, _, _, insns)) in disassembly(disassembly_text) {
        for l in insns {
            let got = ok(&ask("decode", json!({ "file": file, "addr": format!("{:#x}", l.offset), "count": 1 })), file).clone();
            let i = got["insns"].get(0).unwrap_or_else(|| panic!("{file}: func[{index}] {:#x} decoded alone: no instruction: {got}", l.offset));
            let bytes = l.bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
            assert_eq!(
                (hex(&i["va"]), i["bytes"].as_str().unwrap_or_default().to_string(), i["mnemonic"].clone()),
                (l.offset, bytes, json!(l.text.split_whitespace().next().unwrap())),
                "{file}: func[{index}] {:#x} decoded alone: {got}",
                l.offset
            );
            assert_eq!(got["function"], index, "{file}: {:#x} is in func[{index}]: {got}", l.offset);
            long += usize::from(l.bytes.len() > 16);
        }
    }
    long
}

#[test]
fn every_fact_of_every_planted_module_is_what_wasm_objdump_lists() {
    let mut total = Counts::default();
    let mut long = 0;
    in_project(|| {
        for (path, h, x, d) in &planted_recorded() {
            long += each_instruction_decodes_alone(path, d);
            let c = check_module(path, h, x, d);
            eprintln!("{}: {c:?}", path.file_name().unwrap().to_string_lossy());
            total.functions += c.functions;
            total.calls += c.calls;
            total.import_calls += c.import_calls;
            total.function_refs += c.function_refs;
        }
    });
    // What these modules are for was compared: a call to an import (in both),
    // a `ref.func`, and the functions with their non-identifier names.
    assert!(total.import_calls >= 3 && total.function_refs >= 1 && total.functions >= 9, "{total:?}");
    assert!(long >= 1, "no instruction longer than 16 bytes was decoded alone");
}

/// A wide string is found where the compiler aligned it, in linear memory,
/// whatever the parity of the module offset its bytes sit at. The same C
/// source built twice (`wide.c`; `build.sh` checks that the two data sections
/// start at offsets of different parity): `u"Hello wide string here"` is at
/// linear address 0x10000 in both, and was found in one only, because UTF-16
/// was read at even module offsets.
#[test]
fn a_wide_string_is_found_at_its_linear_memory_alignment() {
    in_project(|| {
        let mut parities = Vec::new();
        for stem in ["wide-even", "wide-odd"] {
            let path = planted().join(format!("{stem}.wasm"));
            let file = path.to_str().unwrap();
            let s = ok(&ask("strings", json!({ "file": file })), file).clone();
            let wide = s["strings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["text"] == "Hello wide string here")
                .unwrap_or_else(|| panic!("{stem}: the wide string is missing: {s}"));
            assert_eq!(wide["encoding"], "utf16le", "{stem}: {wide}");
            assert_eq!(wide["linear_memory"], json!({ "memory": 0, "address": "0x10000" }), "{stem}: {wide}");
            parities.push(hex(&wide["address"]) % 2);
            let narrow = s["strings"].as_array().unwrap().iter().find(|s| s["text"] == "narrow text one");
            assert!(narrow.is_some_and(|n| n["encoding"] == "utf8"), "{stem}: {s}");
        }
        // The pair tests what it is for: one string at an even module offset
        // and one at an odd.
        parities.sort_unstable();
        assert_eq!(parities, [0, 1], "the two builds' wide strings at module offsets of different parity");
    });
}

/// A data segment and an element segment placed by an imported global have no
/// static placement — the format allows one (`wasm-tools validate` accepts
/// both), and the global's value is the host's — and the answer says so, with
/// the global, rather than placing them. One of each placed by a constant
/// beside them is placed, so the planted module also shows the rule can say
/// "placed".
#[test]
fn a_segment_placed_by_an_imported_global_is_not_placed_and_says_why() {
    let path = planted().join("placed-by-import.wasm");
    let img = n0xis_sources::ImageSource::load(&path).expect("the planted module loads");
    let profile = n0xis_frontend::image_caps::wasm_profile(&img, false).expect("a module");
    let data = &profile["module"]["data_segments"];
    let why = data[0]["placement"]["not_placed"]["why"].as_str().unwrap_or_else(|| panic!("segment 0 is placed: {data}"));
    assert!(why.contains("imports") && why.contains("global 0") && why.contains("`env`.`base`"), "{why}");
    assert_eq!(data[1]["placement"], json!({ "placed": { "memory": 0, "address": "0x40" } }), "{data}");
    let elem = &profile["module"]["element_segments"];
    let why = elem[0]["placement"]["not_placed"]["why"].as_str().unwrap_or_else(|| panic!("element 0 is placed: {elem}"));
    assert!(why.contains("imports") && why.contains("`env`.`slot`"), "{why}");
    assert_eq!(elem[1]["placement"], json!({ "placed": { "table": 0, "at": 2 } }), "{elem}");

    // And `strings` reports the unplaced segment's text with the reason.
    in_project(|| {
        let s = ok(&ask("strings", json!({ "file": path.to_str().unwrap() })), "strings").clone();
        let unplaced = s["strings"].as_array().unwrap().iter().find(|s| s["text"] == "hosted").unwrap_or_else(|| panic!("{s}"));
        assert!(unplaced["linear_memory"]["not_placed"].as_str().is_some_and(|w| w.contains("`env`.`base`")), "{unplaced}");
        let placed = s["strings"].as_array().unwrap().iter().find(|s| s["text"] == "fixed").unwrap_or_else(|| panic!("{s}"));
        assert_eq!(placed["linear_memory"], json!({ "memory": 0, "address": "0x40" }), "{placed}");
    });
}

/// The same comparisons, on modules this crate's tests do not carry: the real
/// modules listed one path per line in the file `$N0XIS_WASM_CORPUS` names,
/// against a `wasm-objdump` run now (rung 3: an independent reader on modules
/// with no known source). A local instrument, like every test that runs a
/// tool: a missing tool or list is a failure, not a skip.
#[cfg(feature = "oracle")]
#[test]
fn every_fact_of_every_listed_module_is_what_wasm_objdump_lists() {
    let list = std::env::var("N0XIS_WASM_CORPUS").expect("N0XIS_WASM_CORPUS names a file listing modules, one path per line");
    let paths: Vec<PathBuf> = std::fs::read_to_string(&list).expect("the list").lines().filter(|l| !l.trim().is_empty()).map(PathBuf::from).collect();
    assert!(!paths.is_empty(), "{list} lists no module");
    let objdump = |flag: &str, path: &Path| -> String {
        let out = std::process::Command::new("wasm-objdump").env("LC_ALL", "C").arg(flag).arg(path).output().expect("wasm-objdump runs");
        assert!(out.status.success(), "wasm-objdump {flag} {}: {}", path.display(), String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).expect("utf-8")
    };
    in_project(|| {
        for path in &paths {
            let c = check_module(path, &objdump("-h", path), &objdump("-x", path), &objdump("-d", path));
            eprintln!("{}: {c:?}", path.display());
        }
    });
}

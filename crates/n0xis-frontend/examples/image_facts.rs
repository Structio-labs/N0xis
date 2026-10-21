// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Every fact the image layer gives the passes about one file, as canonical
//! JSON: docs/design/IMAGE_FORMATS.md §5 step 1, "Pin today".
//!
//! Usage: `image_facts <file> [<out.json>]` — run it in a directory that has
//! its own `.n0x/`, since [`n0xis_frontend::stated_functions`] looks for a PDB
//! in the project's symbol store.
//!
//! **What this proves, and what it does not.** Recorded before the seam is
//! rebuilt and again after, two recordings that agree say "unchanged" and
//! nothing more: this is n0xis compared with n0xis (rung 5). Whether a fact is
//! *right* is for the tests that pin it against an independent reader.
//!
//! **It loads the file the way every command does** — through
//! [`n0xis_frontend::source::resolve`] — and asks the image behind the
//! resolved [`Src`] directly, not through the name layers a command chains in
//! front of it (annotations, a PDB, FLIRT): those are not the image layer, and
//! the CLI side of step 1 records what they add.
//!
//! **Maps that cannot be listed are probed.** `symbol_at`, `iat_slot`,
//! `thunk_to` and `symbol_size` answer one address at a time and the readers
//! keep their maps private, so they are asked at every byte address the image
//! occupies (its module extent and every section range), and at every address
//! a listing names outside that. A key the readers hold at an address in none
//! of those (a PE import slot outside every section, say) is not seen, and the
//! probe would not say so. Measured on the step-1 sweep (495 images, 2026-10-20):
//! every address `named_functions`, `data_symbols` or `declared_entry_points`
//! lists was seen by the probe, and no listed address lay outside the spans.
//!
//! Output shape: object keys sorted, addresses as `0x…` strings, every list in
//! address order, the input path replaced by `<IMAGE>` wherever it appears.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};

use n0xis_contracts::{Symbol, Va};
use n0xis_frontend::{SourceSpec, Src};
use n0xis_sources::{ImageFormat, ImageSource, MemorySource, ModuleProvider, SourceId, SymbolProvider, read_runs};
use serde_json::{Value, json};

/// The schema of what this writes; bump it when a fact is added or reshaped,
/// so a comparison never mistakes a new instrument for a changed image.
const SCHEMA: &str = "n0xis.image_facts.v1";

/// Every section name a caller in the tree passes to `section_range` or
/// `section_range_in` as a literal (grep `section_range(_in)?\(` outside the
/// readers, 2026-10-20), and the four `Src::data_ranges_of` asks.
const NAMES_CALLERS_ASK: &[&str] = &[".text", ".rdata", ".rodata", ".data.rel.ro", ".data", ".eh_frame", ".pdata", ".note.gnu.build-id"];

/// Names a user can ask through `strings --section`/`find --section`, which
/// accept any name: the common ones of both formats, asked whether the image
/// has them or not, so an answer that appears or disappears is seen.
const NAMES_USERS_ASK: &[&str] = &[
    ".bss", ".tbss", ".tdata", ".got", ".got.plt", ".plt", ".plt.got", ".plt.sec", ".init", ".fini", ".init_array", ".fini_array",
    ".dynamic", ".dynsym", ".dynstr", ".eh_frame_hdr", ".gcc_except_table", ".idata", ".edata", ".reloc", ".rsrc", ".tls", ".CRT",
    ".xdata", ".didat",
];

/// A name no image has: the "no such section" answer is a fact too.
const ABSENT_SECTION: &str = ".n0xis-image-facts-absent";
/// A module name no image has, for the lookups that take one.
const ABSENT_MODULE: &str = "n0xis-image-facts-absent-module";

/// The most byte addresses the symbol probe and a gap read will cover. The
/// largest image in the sweep, a 178 MB shared object, spans 178 182 820 of
/// them; a header that states a larger extent is probed up to this and says so.
const PROBE_CAP: u64 = 1 << 30;

/// How far past a section's end the overlong read asks.
const READ_PAST_END: u64 = 0x1000;

/// Addresses one probe worker takes at a time.
const PROBE_CHUNK: u64 = 1 << 20;

fn main() {
    sha256_self_test();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(path) = args.first() else {
        eprintln!("usage: image_facts <file> [<out.json>]");
        std::process::exit(2);
    };
    let facts = facts_of(path);
    let mut text = String::new();
    canonical(&facts, &mut text);
    text.push('\n');
    match args.get(1) {
        Some(out) => std::fs::write(out, text).unwrap_or_else(|e| panic!("write {out}: {e}")),
        None => print!("{text}"),
    }
}

fn facts_of(path: &str) -> Value {
    let scrub = |s: &str| s.replace(path, "<IMAGE>");
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return json!({ "schema": SCHEMA, "file": { "error": scrub(&e.to_string()) } }),
    };
    let mut top = BTreeMap::new();
    top.insert("schema", json!(SCHEMA));
    top.insert("file", json!({ "sha256": Sha256::digest_hex(&bytes), "len": bytes.len() }));
    let resolved = match n0xis_frontend::source::resolve(SourceSpec { file: Some(path), ..Default::default() }) {
        Ok(r) => r,
        Err((code, message)) => {
            top.insert("load", json!({ "error": { "code": code, "message": scrub(&message) } }));
            return json!(top);
        }
    };
    let src = resolved.src;
    let Src::Static(img) = &src else {
        top.insert("load", json!({ "error": { "code": "not-static", "message": "resolve gave a source that is not a static image" } }));
        return json!(top);
    };
    let img: &ImageSource = img.as_ref();
    top.insert("load", json!({ "ok": true, "label": scrub(&resolved.label) }));
    top.insert("src", guarded(|| src_facts(&src, img, &scrub)));
    top.insert("image", guarded(|| image_facts(img, &scrub)));
    top.insert("memory", guarded(|| memory_facts(img, &bytes)));
    top.insert("symbols", guarded(|| symbol_facts(img)));
    json!(top)
}

/// A panic inside one group of facts is recorded as that group's answer, so
/// the rest of the image is still recorded and a panic that appears or goes
/// away is a difference like any other.
fn guarded(f: impl FnOnce() -> Value) -> Value {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(p) => {
            let msg = p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
            json!({ "panic": msg })
        }
    }
}

fn hex(v: u64) -> String {
    format!("0x{v:x}")
}

fn range(r: (Va, u64)) -> Value {
    json!({ "va": hex(r.0.0), "size": hex(r.1) })
}

fn opt_range(r: Option<(Va, u64)>) -> Value {
    r.map(range).unwrap_or(Value::Null)
}

fn ranges(rs: &[(Va, u64)]) -> Value {
    Value::Array(rs.iter().copied().map(range).collect())
}

fn module_json(m: &n0xis_contracts::Module, scrub: &dyn Fn(&str) -> String) -> Value {
    json!({ "name": m.name, "base": hex(m.base.0), "size": hex(m.size), "path": m.path.as_deref().map(scrub) })
}

fn symbol_json(probed: u64, s: &Symbol) -> Value {
    let mut o = BTreeMap::new();
    o.insert("va", json!(hex(probed)));
    o.insert("name", json!(s.name));
    o.insert("module", json!(s.module));
    o.insert("kind", serde_json::to_value(s.kind).unwrap_or(Value::Null));
    // Every reader keys its maps by the symbol's own address today; a symbol
    // served at an address other than its own would be a change worth seeing.
    if s.va.0 != probed {
        o.insert("symbol_va", json!(hex(s.va.0)));
    }
    json!(o)
}

/// Every section name worth asking `section_range` for on this image.
fn names_to_ask(img: &ImageSource) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = NAMES_CALLERS_ASK.iter().chain(NAMES_USERS_ASK).map(|s| s.to_string()).collect();
    names.insert(ABSENT_SECTION.to_string());
    names.extend(img.sections().into_iter().map(|(n, _, _)| n));
    if img.format() == ImageFormat::Elf {
        names.extend(img.sections_detailed().into_iter().map(|(n, _, _, _)| n));
    }
    names
}

/// The frontend's view: what `Src` answers a command, for a static file.
fn src_facts(src: &Src, img: &ImageSource, scrub: &dyn Fn(&str) -> String) -> Value {
    let own = src.modules().first().map(|m| m.name.clone()).unwrap_or_default();
    let names = names_to_ask(img);
    let by_name = |f: &dyn Fn(&str) -> Option<(Va, u64)>| -> Value {
        Value::Object(names.iter().map(|n| (n.clone(), opt_range(f(n)))).collect())
    };
    let base_for = |m: Option<&str>| match n0xis_frontend::base_for_module(src, m) {
        Ok(va) => json!({ "ok": hex(va.0) }),
        Err(e) => json!({ "error": scrub(&e) }),
    };
    let pick = match src.pick_arch(None) {
        Ok(a) => json!({ "name": a.name(), "decoder_id": a.decoder_id(), "pointer_size": a.pointer_size() }),
        Err(e) => json!({ "error": scrub(&e) }),
    };
    let slots = src.vtable_slots();
    let stated: Vec<Value> = n0xis_frontend::stated_functions(src).into_iter().map(|(s, e)| json!([hex(s.0), hex(e.0)])).collect();
    json!({
        "label": scrub(&src.label()),
        "text_range": opt_range(src.text_range()),
        "code_ranges": ranges(&src.code_ranges()),
        "code_ranges_of": {
            "none": ranges(&src.code_ranges_of(None)),
            "own_module": ranges(&src.code_ranges_of(Some(&own))),
            "absent_module": ranges(&src.code_ranges_of(Some(ABSENT_MODULE))),
        },
        "section_range": by_name(&|n| src.section_range(n)),
        "section_range_in_own_module": by_name(&|n| src.section_range_in(Some(&own), n)),
        "section_range_in_absent_module": by_name(&|n| src.section_range_in(Some(ABSENT_MODULE), n)),
        "data_ranges_of": {
            "none": ranges(&src.data_ranges_of(None)),
            "own_module": ranges(&src.data_ranges_of(Some(&own))),
            "absent_module": ranges(&src.data_ranges_of(Some(ABSENT_MODULE))),
        },
        "module_base": src.module_base().map(|v| hex(v.0)),
        "modules": src.modules().iter().map(|m| module_json(m, scrub)).collect::<Vec<_>>(),
        "base_for_module": { "none": base_for(None), "own_module": base_for(Some(&own)), "absent_module": base_for(Some(ABSENT_MODULE)) },
        "linkage": format!("{:?}", src.linkage()),
        "pointer_size": src.pointer_size(),
        "is_64": src.is_64(),
        "declared_machine": src.declared_machine(),
        "pick_arch_with_no_flag": pick,
        "rtti_refusal": src.rtti_refusal().map(|r| format!("{r:?}")),
        "vtable_slots": { "pointer_size": slots.pointer_size, "code_pointers": format!("{:?}", slots.code_pointers) },
        "stated_functions": stated,
    })
}

/// The reader's own accessors, the ones the frontend and the CLI call on
/// the image, and the format-specific ones on the format they were asked of
/// before the seam (§5 step 1's `StaticImage` and its two variants).
fn image_facts(img: &ImageSource, scrub: &dyn Fn(&str) -> String) -> Value {
    let code = img.code_ranges();
    let in_code = |va: Va| code.iter().any(|(s, n)| va.0 >= s.0 && va.0 - s.0 < *n);
    let mut o = BTreeMap::new();
    o.insert("format", json!(img.format().name()));
    o.insert("image_base", json!(hex(img.image_base().0)));
    o.insert("is_64", json!(img.is_64()));
    o.insert("pointer_size", json!(img.pointer_size()));
    o.insert("byte_order", json!(format!("{:?}", img.byte_order())));
    o.insert("machine", json!(img.machine()));
    o.insert("linkage", json!(format!("{:?}", img.linkage())));
    o.insert("module", module_json(img.module(), scrub));
    o.insert("text_range", opt_range(img.text_range()));
    // A PE section's executable flag has no accessor; whether its start is in
    // one of `code_ranges` is what a caller can learn, and is named for that.
    o.insert(
        "sections",
        json!(img
            .sections()
            .into_iter()
            .map(|(name, va, size)| json!({ "name": name, "va": hex(va.0), "size": hex(size), "start_in_code_ranges": in_code(va) }))
            .collect::<Vec<_>>()),
    );
    o.insert("named_functions", json!(img.named_functions().into_iter().map(|(va, n)| json!([hex(va.0), n])).collect::<Vec<_>>()));
    o.insert("declared_entry_points", json!(img.declared_entry_points().into_iter().map(|va| hex(va.0)).collect::<Vec<_>>()));
    o.insert(
        "codeview",
        img.codeview()
            .map(|cv| json!({ "guid": cv.guid.iter().map(|b| format!("{b:02x}")).collect::<String>(), "age": cv.age, "pdb_path": cv.pdb_path }))
            .unwrap_or(Value::Null),
    );
    match img.format() {
        ImageFormat::Pe => {
            o.insert("degraded", json!(img.degraded()));
        }
        ImageFormat::Elf => {
            let elf = img;
            o.insert(
                "sections_detailed",
                json!(elf
                    .sections_detailed()
                    .into_iter()
                    .map(|(name, va, size, x)| json!({ "name": name, "va": hex(va.0), "size": hex(size), "executable": x }))
                    .collect::<Vec<_>>()),
            );
            o.insert(
                "data_symbols",
                json!(elf
                    .data_symbols()
                    .into_iter()
                    .map(|d| json!({ "va": hex(d.va.0), "name": d.name, "size": d.size.map(hex) }))
                    .collect::<Vec<_>>()),
            );
            o.insert(
                "relocated_words",
                match elf.relocated_words() {
                    n0xis_sources::RelocatedWords::Read { words, copies } => json!({
                        "read": {
                            "words": words.iter().map(|&w| hex(w)).collect::<Vec<_>>(),
                            "copies": copies.iter().map(|&(s, e)| json!([hex(s), hex(e)])).collect::<Vec<_>>(),
                        }
                    }),
                    n0xis_sources::RelocatedWords::NotRead(why) => json!({ "not_read": format!("{why:?}") }),
                },
            );
        }
    }
    json!(o)
}

/// Every address range the image says it has, as `(start, end)`, distinct
/// and in order: what the section reads cover, and what the gaps lie between.
fn section_intervals(img: &ImageSource) -> Vec<(u64, u64)> {
    let mut out: BTreeSet<(u64, u64)> = BTreeSet::new();
    let mut add = |va: Va, size: u64| {
        if size > 0 {
            out.insert((va.0, va.0.saturating_add(size)));
        }
    };
    for (name, va, size) in img.sections() {
        add(va, size);
        if let Some((v, s)) = img.section_range(&name) {
            add(v, s);
        }
    }
    if img.format() == ImageFormat::Elf {
        for (_, va, size, _) in img.sections_detailed() {
            add(va, size);
        }
    }
    for (va, size) in img.code_ranges() {
        add(va, size);
    }
    out.into_iter().collect()
}

/// Overlapping and touching intervals as one.
fn merged(iv: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for &(s, e) in iv {
        match out.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

fn runs_json(img: &ImageSource, va: u64, len: u64) -> Value {
    match read_runs(img, Va(va), len.min(PROBE_CAP) as usize) {
        Ok(runs) => json!({
            "runs": runs.iter().map(|(at, b)| json!({ "va": hex(at.0), "len": b.len(), "sha256": Sha256::digest_hex(b) })).collect::<Vec<_>>(),
            "truncated_at_cap": len > PROBE_CAP,
        }),
        Err(e) => json!({ "error": e.to_string() }),
    }
}

/// What `MemorySource` answers: the reads every pass goes through.
fn memory_facts(img: &ImageSource, file: &[u8]) -> Value {
    let intervals = section_intervals(img);
    let union = merged(&intervals);
    let m = img.module();
    let lo = union.first().map_or(m.base.0, |f| f.0.min(m.base.0));
    let hi = union.last().map_or(m.base.0.saturating_add(m.size), |l| l.1.max(m.base.0.saturating_add(m.size)));

    let section_reads: Vec<Value> = intervals
        .iter()
        .map(|&(s, e)| {
            let whole = match img.read(Va(s), (e - s) as usize) {
                Ok(b) => json!({ "len": b.len(), "sha256": Sha256::digest_hex(&b) }),
                Err(err) => json!({ "error": err.to_string() }),
            };
            // A read asks for more than the section holds as often as not (a
            // disassembler's generous window); where it stops is the answer.
            let past_end = match img.read(Va(s), (e - s).saturating_add(READ_PAST_END) as usize) {
                Ok(b) => json!({ "len": b.len(), "sha256": Sha256::digest_hex(&b) }),
                Err(err) => json!({ "error": err.to_string() }),
            };
            json!({ "va": hex(s), "end": hex(e), "read": whole, "read_past_end": past_end, "read_runs": runs_json(img, s, e - s) })
        })
        .collect();

    // The holes between the sections, and before the first and after the last
    // within the module's extent: nothing should read there, and if something
    // starts to, that is a change.
    let mut gaps: Vec<(u64, u64)> = Vec::new();
    let mut at = lo;
    for &(s, e) in &union {
        if s > at {
            gaps.push((at, s));
        }
        at = at.max(e);
    }
    if hi > at {
        gaps.push((at, hi));
    }
    let gap_reads: Vec<Value> = gaps
        .iter()
        .map(|&(s, e)| {
            let next = match img.next_readable(Va(s), Va(e)) {
                Ok(v) => json!({ "ok": v.map(|v| hex(v.0)) }),
                Err(err) => json!({ "error": err.to_string() }),
            };
            json!({ "va": hex(s), "end": hex(e), "read_runs": runs_json(img, s, e - s), "next_readable": next })
        })
        .collect();

    // `contains` and `next_readable` at every edge: one before, at, one before
    // the end, at the end.
    let mut edges: BTreeSet<u64> = BTreeSet::new();
    for &(s, e) in &intervals {
        edges.extend([s.saturating_sub(1), s, e.saturating_sub(1), e]);
    }
    edges.extend([lo, hi]);
    let contains: Vec<Value> = edges.iter().map(|&a| json!([hex(a), img.contains(Va(a))])).collect();
    let next_readable: Vec<Value> = intervals
        .iter()
        .map(|&(s, e)| {
            let v = match img.next_readable(Va(s), Va(e)) {
                Ok(v) => json!({ "ok": v.map(|v| hex(v.0)) }),
                Err(err) => json!({ "error": err.to_string() }),
            };
            json!({ "from": hex(s), "to": hex(e), "answer": v })
        })
        .collect();
    let owner_of: Vec<Value> =
        edges.iter().map(|&a| json!([hex(a), ModuleProvider::owner_of(img, Va(a)).map(|m| m.name.clone())])).collect();

    let identity = img.identity();
    json!({
        "label": img.label(),
        "abi_name": img.abi_name(),
        "identity": {
            "present": identity.is_some(),
            // `SourceId` is a hash that is not stable across Rust releases;
            // both recordings of one comparison are built by one toolchain.
            "value": identity.map(|i| i.to_string()),
            "is_source_id_of_the_file_bytes": identity == Some(SourceId::of(file)),
        },
        // A static image is read-only; that it says so, rather than writing,
        // is part of the seam (`MemorySource::write`).
        "write": match img.write(img.image_base(), &[0]) {
            Ok(()) => json!({ "ok": true }),
            Err(err) => json!({ "error": err.to_string() }),
        },
        "code_range": opt_range(img.code_range()),
        "code_ranges": ranges(&img.code_ranges()),
        "modules": ModuleProvider::modules(img).iter().map(|m| json!({ "name": m.name, "base": hex(m.base.0), "size": hex(m.size) })).collect::<Vec<_>>(),
        "contains": contains,
        "owner_of": owner_of,
        "next_readable": next_readable,
        "section_reads": section_reads,
        "gap_reads": gap_reads,
    })
}

#[derive(Default)]
struct Hits {
    symbol_at: Vec<(u64, Symbol)>,
    iat_slot: Vec<(u64, Symbol)>,
    thunk_to: Vec<(u64, u64)>,
    symbol_size: Vec<(u64, u64)>,
}

impl Hits {
    fn ask(&mut self, img: &ImageSource, a: u64) {
        let va = Va(a);
        if let Some(s) = img.symbol_at(va) {
            self.symbol_at.push((a, s));
        }
        if let Some(s) = img.iat_slot(va) {
            self.iat_slot.push((a, s));
        }
        if let Some(t) = img.thunk_to(va) {
            self.thunk_to.push((a, t.0));
        }
        if let Some(n) = img.symbol_size(va) {
            self.symbol_size.push((a, n));
        }
    }

    fn extend(&mut self, other: Hits) {
        self.symbol_at.extend(other.symbol_at);
        self.iat_slot.extend(other.iat_slot);
        self.thunk_to.extend(other.thunk_to);
        self.symbol_size.extend(other.symbol_size);
    }
}

/// What `SymbolProvider` answers, at every address it could answer for.
fn symbol_facts(img: &ImageSource) -> Value {
    let m = img.module();
    let mut spans: Vec<(u64, u64)> = section_intervals(img);
    if m.size > 0 {
        spans.push((m.base.0, m.base.0.saturating_add(m.size)));
    }
    spans.sort_unstable();
    let spans = merged(&spans);
    let total: u64 = spans.iter().map(|(s, e)| e - s).sum();

    // The probe covers the first `PROBE_CAP` addresses, in order.
    let mut chunks: Vec<(u64, u64)> = Vec::new();
    let mut budget = PROBE_CAP;
    for &(s, e) in &spans {
        let mut at = s;
        while at < e && budget > 0 {
            let end = e.min(at.saturating_add(PROBE_CHUNK)).min(at.saturating_add(budget));
            chunks.push((at, end));
            budget -= end - at;
            at = end;
        }
    }
    let covered = |a: u64| {
        let i = chunks.partition_point(|&(_, e)| e <= a);
        chunks.get(i).is_some_and(|&(s, _)| s <= a)
    };

    // Addresses a listing names that the spans do not cover.
    let mut extra: BTreeSet<u64> = BTreeSet::new();
    extra.extend(img.named_functions().into_iter().map(|(va, _)| va.0));
    extra.extend(img.declared_entry_points().into_iter().map(|va| va.0));
    if img.format() == ImageFormat::Elf {
        extra.extend(img.data_symbols().into_iter().map(|d| d.va.0));
        if let n0xis_sources::RelocatedWords::Read { words, .. } = img.relocated_words() {
            extra.extend(words.iter().copied());
        }
    }
    let extra: Vec<u64> = extra.into_iter().filter(|&a| !covered(a)).collect();

    let workers = std::thread::available_parallelism().map_or(1, |n| n.get()).min(4);
    let next = std::sync::atomic::AtomicUsize::new(0);
    let mut hits = Hits::default();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut h = Hits::default();
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(&(s, e)) = chunks.get(i) else { break };
                        for a in s..e {
                            h.ask(img, a);
                        }
                    }
                    h
                })
            })
            .collect();
        for handle in handles {
            match handle.join() {
                Ok(h) => hits.extend(h),
                Err(p) => std::panic::resume_unwind(p),
            }
        }
    });
    for &a in &extra {
        hits.ask(img, a);
    }
    hits.symbol_at.sort_by_key(|(a, _)| *a);
    hits.iat_slot.sort_by_key(|(a, _)| *a);
    hits.thunk_to.sort_unstable();
    hits.symbol_size.sort_unstable();

    json!({
        "probe": {
            "spans": spans.iter().map(|&(s, e)| json!([hex(s), hex(e)])).collect::<Vec<_>>(),
            "addresses_in_spans": total,
            "addresses_probed_in_spans": total.min(PROBE_CAP),
            "truncated_at_cap": total > PROBE_CAP,
            "listed_addresses_outside_spans": extra.len(),
        },
        "symbol_at": hits.symbol_at.iter().map(|(a, s)| symbol_json(*a, s)).collect::<Vec<_>>(),
        "iat_slot": hits.iat_slot.iter().map(|(a, s)| symbol_json(*a, s)).collect::<Vec<_>>(),
        "thunk_to": hits.thunk_to.iter().map(|&(a, t)| json!([hex(a), hex(t)])).collect::<Vec<_>>(),
        "symbol_size": hits.symbol_size.iter().map(|&(a, n)| json!([hex(a), hex(n)])).collect::<Vec<_>>(),
        "symbol_fingerprint": img.symbol_fingerprint(),
    })
}

/// JSON with every object's keys sorted and no whitespace, whatever order the
/// map type keeps (serde_json's `preserve_order` feature is workspace-wide
/// once any crate enables it).
fn canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                canonical(&map[k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// SHA-256 (FIPS 180-4), here because the workspace carries no hash crate and
/// this instrument should not add a dependency to the tree. Checked at every
/// start against the standard's own example digests ([`sha256_self_test`]),
/// and the recording script checks the file digest against `hashlib`.
struct Sha256 {
    h: [u32; 8],
    block: [u8; 64],
    filled: usize,
    total: u64,
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
    0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
    0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
    0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Sha256 {
    fn new() -> Self {
        Sha256 {
            h: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
            block: [0; 64],
            filled: 0,
            total: 0,
        }
    }

    fn compress(h: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.filled > 0 {
            let take = (64 - self.filled).min(data.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled < 64 {
                return;
            }
            Self::compress(&mut self.h, &self.block);
            self.filled = 0;
        }
        let (blocks, rest) = data.as_chunks::<64>();
        for b in blocks {
            Self::compress(&mut self.h, b);
        }
        self.block[..rest.len()].copy_from_slice(rest);
        self.filled = rest.len();
    }

    fn finish(mut self) -> [u8; 32] {
        let bits = self.total.wrapping_mul(8);
        let mut pad = vec![0x80u8];
        pad.resize((119 - self.filled) % 64 + 1, 0);
        pad.extend_from_slice(&bits.to_be_bytes());
        self.update(&pad);
        debug_assert_eq!(self.filled, 0);
        let mut out = [0u8; 32];
        for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.h) {
            *chunk = word.to_be_bytes();
        }
        out
    }

    fn digest_hex(data: &[u8]) -> String {
        let mut s = Sha256::new();
        s.update(data);
        s.finish().iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// The example digests FIPS 180-4's own examples document (the empty string,
/// "abc", and the two-block 448-bit message), and a million `a`s fed in
/// uneven pieces so the buffering across `update` calls is exercised.
fn sha256_self_test() {
    let cases: [(&[u8], &str); 3] = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    ];
    for (input, want) in cases {
        assert_eq!(Sha256::digest_hex(input), want, "SHA-256 self-test failed on {input:?}");
    }
    let mut s = Sha256::new();
    let million = vec![b'a'; 1_000_000];
    for piece in million.chunks(7_919) {
        s.update(piece);
    }
    let got: String = s.finish().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(got, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "SHA-256 self-test failed on a million 'a's");
}

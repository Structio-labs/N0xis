// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `strings`: the text an image holds, as runs of printable UTF-8 or UTF-16LE
//! characters with their addresses ([`n0xis_core::find_strings`] over each
//! readable stretch).
//!
//! By default every file-backed section that holds no code: text read out of a
//! code section is almost always instructions that happen to print. One named
//! section, every section, or an explicit range can be asked for instead, and
//! the answer says which ranges were read. The whole list is kept for a source
//! with an identity (a file, a snapshot), so a front end paging through it, or
//! filtering it as the user types, pays for the scan once.
//!
//! **A WebAssembly module's data is its data segments** (the lead's DECISIONS
//! item 8): by default each segment's bytes are read, and every string found
//! in one is reported at its module offset (`address`, the image's own space,
//! what `mem read` reads) with its place in linear memory beside it — the
//! memory's index and the address there — or, for a segment the module places
//! nowhere statically, `not placed` and why. The module's sections, custom
//! ones included, are read only when asked for by name, with `all_sections`
//! or with a range, and their strings have module offsets only.
//!
//! **A run of text in an image is several strings where the image says so**:
//! a reference with its length ([`n0xis_core::cut_run`]). A row cut on one says
//! which (`cut_by`, first evidence). Only an image on disk can say it: a running
//! process or loose bytes have no relocation table to tell a pointer from a
//! number, and their runs stay whole. And only an image that shows it holds
//! literals a length delimits is cut at all ([`n0xis_sources::rustc_evidence`]):
//! with no such evidence no reference is looked for. The answer says which, once
//! ([`n0xis_core::LiteralCuts`]).

use std::sync::{Arc, Mutex};

use serde::Serialize;
use serde::ser::SerializeMap;

use n0xis_contracts::{Response, Va, schema};
use n0xis_core::{FoundString, LiteralCuts, LiteralRefs, NotCut, StringEncoding};
use serde_json::{Value, json};

use crate::registry::{Answer, Capability, Plugin, Registry};
use crate::source::{SourceSpec, Src, resolve};

/// How many strings one answer carries when not told.
pub const DEFAULT_STRINGS_LIMIT: usize = 1000;
/// Fewer characters than this is not a string unless asked: binutils' default.
pub const DEFAULT_MIN_CHARS: usize = 4;
/// The most an explicit range may cover; it is read whole.
pub const MAX_STRINGS_RANGE: u64 = 256 << 20;

/// A range to read: its name (a section's, a data segment's, or `range`),
/// start and size, and for a WebAssembly data segment where in linear memory
/// its bytes are placed.
type ReadRange = (String, Va, u64, Option<n0xis_sources::SegmentPlacement>);

/// What was read, and every string found in it, in address order.
struct Scanned {
    ranges: Vec<ReadRange>,
    /// Each string with the index of the range it was found in.
    strings: Vec<(FoundString, usize)>,
    /// Whether the runs were cut, and why.
    literal_cuts: LiteralCuts,
    /// What each range gave. Stated only about a running process, and about a
    /// file only when no range gave a byte.
    read: n0xis_sources::RegionCoverage,
}

/// The last list, under the key that says which question it answers.
static KEPT: Mutex<Option<(String, Arc<Scanned>)>> = Mutex::new(None);

pub struct StringTools;

impl Plugin for StringTools {
    fn name(&self) -> &str {
        "n0xis.strings"
    }

    fn register(&self, reg: &mut Registry) {
        reg.add(Capability::with_answer(
            "strings",
            "Text in the image: runs of printable UTF-8 or UTF-16LE characters, with their addresses. By default the file-backed sections that hold no code; `section`, `all_sections`, or `start`+`size` for others. In an image that shows it holds literals a length delimits (`literal_cuts`), a run is cut where a reference states a length (`cut_by`). `contains` filters (any case); `limit`/`offset` page.",
            Some(schema::v1::STRINGS),
            Box::new(strings),
        ));
    }
}

/// Which of the kept strings a page shows.
enum Shown {
    /// A stretch of the list: the usual case, and it costs nothing per row.
    Span(std::ops::Range<usize>),
    /// Those a `contains` filter let through.
    Listed(Vec<usize>),
}

/// The `data` of a `strings` answer, written without being built.
///
/// Built as JSON values, the rows of one 20 MB image (2 million with `--min 1`) came to
/// 1.9 GiB, and `json!` then made a second tree of them on the way into the answer, past
/// a 3.5 GiB ceiling. This is the kept list and which of its rows to show.
///
/// **The bytes are the value form's, whose object keys are sorted**: every struct and
/// entry below is in key order because of that, and `rows_write_what_the_value_form_wrote`
/// holds them to it. What is small and written rarely stays a value, so that it cannot
/// differ: the ranges, `literal_cuts`, what a live sweep did not read.
pub struct StringsPage {
    scanned: Arc<Scanned>,
    shown: Shown,
    count: usize,
    literal_cuts: Value,
    min: usize,
    ranges: Value,
    /// About a running process: what its sweep did not read. These keys take their
    /// places among the others ([`n0xis_sources::LiveAnswer`] flattens them in).
    coverage: serde_json::Map<String, Value>,
}

/// `{"at": ..., "kind": ...}`: [`n0xis_core::CutBy`]'s own order is the other one.
#[derive(Serialize)]
struct CutByRow {
    at: Va,
    kind: n0xis_core::CutKind,
}

/// Where a row is in linear memory ([`linear_memory`]).
#[derive(Serialize)]
#[serde(untagged)]
enum LinearMemory<'a> {
    Placed { address: String, memory: u32 },
    NotPlaced { not_placed: &'a str },
}

#[derive(Serialize)]
struct Row<'a> {
    address: Va,
    #[serde(skip_serializing_if = "Option::is_none")]
    cut_by: Option<CutByRow>,
    encoding: &'static str,
    length: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    linear_memory: Option<LinearMemory<'a>>,
    section: &'a str,
    size: usize,
    text: &'a str,
}

impl StringsPage {
    fn row(&self, at: usize) -> Row<'_> {
        let (s, i) = &self.scanned.strings[at];
        let (section, range_start, _, placement) = &self.scanned.ranges[*i];
        Row {
            address: s.address,
            cut_by: s.cut_by.map(|by| CutByRow { at: by.at, kind: by.kind }),
            encoding: s.encoding.name(),
            length: s.length,
            linear_memory: placement.as_ref().map(|p| linear_memory(p, s.address.0 - range_start.0)),
            section,
            size: s.size,
            text: &s.text,
        }
    }
}

/// The rows, one at a time.
struct Rows<'a>(&'a StringsPage);

impl Serialize for Rows<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0.shown {
            Shown::Span(span) => serializer.collect_seq(span.clone().map(|at| self.0.row(at))),
            Shown::Listed(rows) => serializer.collect_seq(rows.iter().map(|&at| self.0.row(at))),
        }
    }
}

impl Serialize for StringsPage {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("count", &self.count)?;
        map.serialize_entry("literal_cuts", &self.literal_cuts)?;
        map.serialize_entry("min", &self.min)?;
        // A map of values iterates in key order, and every one of its keys falls before
        // "strings" (a test holds this for the keys there are).
        let mut coverage = self.coverage.iter().peekable();
        while let Some((key, value)) = coverage.next_if(|(key, _)| key.as_str() < "ranges") {
            map.serialize_entry(key, value)?;
        }
        map.serialize_entry("ranges", &self.ranges)?;
        for (key, value) in coverage {
            map.serialize_entry(key, value)?;
        }
        map.serialize_entry("strings", &Rows(self))?;
        map.end()
    }
}

fn strings(args: &Value) -> Response<Answer> {
    let min = args.get("min").and_then(Value::as_u64).map_or(DEFAULT_MIN_CHARS, |v| v as usize).max(1);
    let encodings = match args.get("encoding").and_then(Value::as_str).unwrap_or("both") {
        "both" => vec![StringEncoding::Utf8, StringEncoding::Utf16le],
        "utf8" => vec![StringEncoding::Utf8],
        "utf16le" => vec![StringEncoding::Utf16le],
        other => return Response::error("bad-arg", format!("unknown encoding {other:?}; expected both, utf8 or utf16le")),
    };
    let start = match args.get("start").and_then(Value::as_str).map(Va::parse).transpose() {
        Ok(v) => v,
        Err(e) => return Response::error("bad-addr", format!("start: {e}")),
    };
    let spec = SourceSpec {
        pid: crate::registry::pid_arg(args, "pid"),
        file: args.get("file").and_then(Value::as_str),
        snapshot: args.get("snapshot").and_then(Value::as_str),
        remote_cmd: args.get("remote_cmd").and_then(Value::as_str),
        bytes: args.get("bytes").and_then(Value::as_str),
        bytes_base: start,
    };
    let resolved = match resolve(spec) {
        Ok(r) => r,
        Err((c, m)) => return Response::error(&c, m),
    };
    let ranges = match ranges(&resolved.src, args, start) {
        Ok(r) => r,
        Err((c, m)) => return Response::error(c, m),
    };
    let key = resolved.src.as_mem().identity().map(|id| format!("{id}|{min}|{encodings:?}|{ranges:?}"));
    let kept = key.as_ref().and_then(|k| KEPT.lock().ok().and_then(|kept| kept.as_ref().filter(|(had, _)| had == k).map(|(_, s)| Arc::clone(s))));
    let scanned = match kept {
        Some(s) => s,
        None => match scan(&resolved.src, ranges, min, &encodings) {
            Ok(s) => {
                let s = Arc::new(s);
                if let Some(key) = key
                    && let Ok(mut kept) = KEPT.lock()
                {
                    *kept = Some((key, Arc::clone(&s)));
                }
                s
            }
            Err(e) => return Response::error("read-failed", e),
        },
    };

    let needle = args.get("contains").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_lowercase);
    let offset = args.get("offset").and_then(Value::as_u64).map_or(0, |v| v as usize);
    let limit = args.get("limit").and_then(Value::as_u64).map_or(DEFAULT_STRINGS_LIMIT, |v| v as usize);
    let take = if limit == 0 { usize::MAX } else { limit };
    let (total, shown) = match &needle {
        None => {
            let total = scanned.strings.len();
            let from = offset.min(total);
            (total, Shown::Span(from..from.saturating_add(take).min(total)))
        }
        Some(needle) => {
            let matching = scanned.strings.iter().enumerate().filter(|(_, (s, _))| s.text.to_lowercase().contains(needle)).map(|(at, _)| at);
            let mut listed = Vec::new();
            let mut total = 0;
            for at in matching {
                if total >= offset && listed.len() < take {
                    listed.push(at);
                }
                total += 1;
            }
            (total, Shown::Listed(listed))
        }
    };
    let returned = match &shown {
        Shown::Span(span) => span.len(),
        Shown::Listed(rows) => rows.len(),
    };
    let read: Vec<Value> = scanned
        .ranges
        .iter()
        .map(|(name, va, size, placement)| {
            let mut r = json!({ "name": name, "address": va, "size": size });
            if let Some(placement) = placement {
                r["linear_memory"] = json!(linear_memory(placement, 0));
            }
            r
        })
        .collect();
    let literal_cuts = serde_json::to_value(scanned.literal_cuts).unwrap_or(Value::Null);
    let read_by_sweep = scanned.read.clone();
    let mut answer = StringsPage { scanned, shown, count: returned, literal_cuts, min, ranges: Value::Array(read), coverage: serde_json::Map::new() };
    let is_live = matches!(resolved.src, Src::Live(_) | Src::Remote(_));
    if is_live && let Ok(Value::Object(coverage)) = serde_json::to_value(&read_by_sweep) {
        answer.coverage = coverage;
    }
    // A live sweep's coverage is in the page already, so its answer is this either way,
    // and the refusal to call nothing a result is the same one.
    let swept = n0xis_sources::Swept { answer, read: read_by_sweep };
    let data = if is_live { swept.live().map(|stated| stated.answer) } else { swept.window() };
    let data = match data {
        Ok(data) => data,
        Err(nothing) => return Response::error(n0xis_sources::NOTHING_READABLE, nothing.to_string()),
    };
    Response::success(schema::v1::STRINGS, Answer::Strings(data))
        .with_source(resolved.label)
        .with_page(total, returned)
}

/// The ranges to read: `start`+`size`, one named section, or the image's
/// file-backed sections (without the ones that hold code, unless all are asked
/// for).
fn ranges(src: &Src, args: &Value, start: Option<Va>) -> Result<Vec<ReadRange>, (&'static str, String)> {
    let size = args.get("size").and_then(Value::as_u64);
    match (start, size) {
        (Some(start), Some(size)) if size > MAX_STRINGS_RANGE => {
            Err(("bad-arg", format!("a range of {size} bytes at {start} is more than {MAX_STRINGS_RANGE} read at once")))
        }
        (Some(start), Some(size)) => Ok(vec![("range".to_string(), start, size, None)]),
        (Some(_), None) | (None, Some(_)) => Err(("bad-arg", "a range needs both start and size".to_string())),
        (None, None) => {
            let Src::Static(img) = src else {
                return Err(("no-range", "only an image on disk has sections; for this source pass start and size".to_string()));
            };
            if let Some(name) = args.get("section").and_then(Value::as_str) {
                return img
                    .section_range(name)
                    .map(|(va, size)| vec![(name.to_string(), va, size, None)])
                    .ok_or_else(|| ("no-section", format!("the image has no section named {name:?}")));
            }
            let all = args.get("all_sections").and_then(Value::as_bool).unwrap_or(false);
            // A module's data is its segments, not its sections.
            if !all
                && let n0xis_sources::AddressModel::LinearMemories { segments, .. } = &img.image().machine().address_model
            {
                return Ok(segments
                    .iter()
                    .map(|s| (format!("data[{}]", s.index), s.bytes_at, s.len, Some(s.placement.clone())))
                    .collect());
            }
            let code = src.as_mem().code_ranges();
            let holds_code = |va: Va| code.iter().any(|(s, n)| va.0 >= s.0 && va.0 - s.0 < *n);
            Ok(img
                .sections()
                .into_iter()
                .filter(|(_, va, _)| all || !holds_code(*va))
                // A PE's headers are a range of their own with no name.
                .map(|(name, va, size)| (if name.is_empty() { "(headers)".to_string() } else { name }, va, size, None))
                .collect())
        }
    }
}

/// Where the byte `delta` bytes into a data segment lands in linear memory:
/// the memory and the address there, or the segment's reason for having no
/// static place.
fn linear_memory(placement: &n0xis_sources::SegmentPlacement, delta: u64) -> LinearMemory<'_> {
    match placement {
        n0xis_sources::SegmentPlacement::Placed { memory, address } => {
            LinearMemory::Placed { address: format!("{:#x}", address.wrapping_add(delta)), memory: *memory }
        }
        n0xis_sources::SegmentPlacement::NotPlaced { why } => LinearMemory::NotPlaced { not_placed: why },
    }
}

/// Every string in `ranges`, read stretch by stretch: a string never runs
/// across a gap.
fn scan(src: &Src, ranges: Vec<ReadRange>, min: usize, encodings: &[StringEncoding]) -> Result<Scanned, String> {
    // Each with the range it was found in and whether a NUL ends it.
    let mut text = Vec::new();
    let mut read = n0xis_sources::RegionCoverage::default();
    for (i, (_, start, size, placement)) in ranges.iter().enumerate() {
        let runs = n0xis_sources::read_runs(src.as_mem(), *start, *size as usize).map_err(|e| e.to_string())?;
        // `read_runs` has stepped over what would not read, so nothing is left
        // to fail here: what a range gave is the sum of its runs.
        let gave = runs.iter().map(|(_, bytes)| bytes.len()).sum();
        read.record(*start, *size as usize, Ok(gave)).map_err(|e| e.to_string())?;
        for (va, bytes) in runs {
            // Wide text is read at even addresses of the space the bytes are
            // laid out in (`find_strings`), and a data segment's bytes are laid
            // out in linear memory, not in the module: where they sit in the
            // file depends on every byte before them, so a module offset's
            // parity says nothing about the text's alignment. Scanned at the
            // segment's own coordinate and moved back to module offsets after.
            let delta = va.0.wrapping_sub(start.0);
            let laid_out = match placement {
                // The address the bytes take in their memory.
                Some(n0xis_sources::SegmentPlacement::Placed { address, .. }) => address.wrapping_add(delta),
                // An address the module computes when it runs (`memory.init`,
                // an imported base), which a producer aligns as the segment's
                // contents need: the segment's start is the one even point.
                Some(n0xis_sources::SegmentPlacement::NotPlaced { .. }) => delta,
                None => va.0,
            };
            let found = n0xis_core::find_strings(&bytes, Va(laid_out), min, encodings);
            text.extend(found.into_iter().map(|mut s| {
                s.address = Va(s.address.0.wrapping_sub(laid_out).wrapping_add(va.0));
                let ended_by_nul = bytes.get((s.address.0 - va.0) as usize + s.size) == Some(&0);
                (s, i, ended_by_nul)
            }));
        }
    }
    let (literal_cuts, refs) = literal_refs(src, &text);
    let mut strings: Vec<(FoundString, usize)> = match &refs {
        Some(refs) => text
            .into_iter()
            .flat_map(|(s, i, ended_by_nul)| n0xis_core::cut_run(s, ended_by_nul, refs, min).into_iter().map(move |piece| (piece, i)))
            .collect(),
        None => text.into_iter().map(|(s, i, _)| (s, i)).collect(),
    };
    strings.sort_by_key(|(s, _)| s.address.0);
    Ok(Scanned { ranges, strings, literal_cuts, read })
}

/// Whether `src` is an image whose runs may be cut, and if so the references that
/// cut them: no references without the evidence for looking ([`LiteralCuts`]).
///
/// The references with their lengths an image on disk states into `runs`: every
/// data pair in its sections that hold no code, and, on x86-64, every code pair
/// in its code. A run in a section that holds code is not one to cut: what looks
/// like text there is instructions that print, and a function pointer with a
/// small number beside it, which any table of them has, is not a literal.
///
/// A section or a code range that does not read gives no evidence and no error:
/// the scan has its answer, and with no evidence that answer is the run whole.
fn literal_refs(src: &Src, runs: &[(FoundString, usize, bool)]) -> (LiteralCuts, Option<LiteralRefs>) {
    let not_applied = |because| (LiteralCuts::NotApplied { because }, None);
    let Src::Static(img) = src else { return not_applied(Some(NotCut::NotAnImage)) };
    let machine = img.image().machine();
    let Some(width) = machine.address_model.pointer_width() else { return not_applied(Some(NotCut::WasmModule)) };
    let Some(because) = n0xis_sources::rustc_evidence(img.image()) else { return not_applied(None) };
    let applied = LiteralCuts::Applied { because };
    let code = src.as_mem().code_ranges();
    let holds_code = |va: Va| code.iter().any(|(s, n)| va.0 >= s.0 && va.0 - s.0 < *n);
    let mut evidence = n0xis_core::LiteralEvidence::new(runs.iter().map(|(s, ..)| s).filter(|s| !holds_code(s.address)));
    let order = machine.byte_order;
    let data: Vec<(Va, u64)> = img.sections().into_iter().map(|(_, va, size)| (va, size)).filter(|(va, _)| !holds_code(*va)).collect();
    let in_data = |va: u64| data.iter().any(|(s, n)| va >= s.0 && va - s.0 < *n);
    let how = img.address_words(&mut |at, value| {
        if in_data(at) {
            evidence.relocated_word(src.as_mem(), img.relocated_words(), at, value, width, order);
        }
    });
    if how == n0xis_sources::AddressWords::NotStated {
        return not_applied(Some(NotCut::RelocationsNotRead));
    }
    if evidence.is_empty() {
        return (applied, None);
    }
    if how == n0xis_sources::AddressWords::Stored {
        for (va, size) in &data {
            for (at, bytes) in n0xis_sources::read_runs(src.as_mem(), *va, *size as usize).unwrap_or_default() {
                evidence.stored_words(&bytes, at, width, order);
            }
        }
    }
    if machine.isa == n0xis_sources::Isa::X64
        && let Ok(arch) = src.pick_arch(None)
    {
        let ctx = n0xis_core::Ctx::new(src.as_mem(), arch.as_ref());
        for (start, size) in &code {
            let _ = evidence.x64_code_pairs(&ctx, *start, *size, how);
        }
    }
    (applied, Some(evidence.into_refs()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_core::{CutBy, CutKind};
    use n0xis_sources::{RegionCoverage, SegmentPlacement};

    fn found(address: u64, encoding: StringEncoding, text: &str, cut_by: Option<CutBy>) -> FoundString {
        FoundString { address: Va(address), encoding, length: text.chars().count(), size: text.len(), text: text.to_string(), cut_by }
    }

    fn page(coverage: serde_json::Map<String, Value>) -> StringsPage {
        let cut = CutBy { kind: CutKind::CodePair, at: Va(0x400) };
        let ranges = vec![
            (".rdata".to_string(), Va(0x1000), 64, None),
            ("data[0]".to_string(), Va(0x2000), 64, Some(SegmentPlacement::Placed { memory: 1, address: 0x8000 })),
            ("data[1]".to_string(), Va(0x3000), 64, Some(SegmentPlacement::NotPlaced { why: "an imported base".to_string() })),
        ];
        let strings = vec![
            (found(0x1000, StringEncoding::Utf8, "plain \"quoted\"\n\u{0456}", None), 0),
            (found(0x1010, StringEncoding::Utf16le, "cut", Some(cut)), 0),
            (found(0x2004, StringEncoding::Utf8, "placed", None), 1),
            (found(0x3004, StringEncoding::Utf8, "not placed", Some(cut)), 2),
        ];
        let scanned = Scanned { ranges, strings, literal_cuts: LiteralCuts::NotApplied { because: None }, read: RegionCoverage::default() };
        StringsPage {
            scanned: Arc::new(scanned),
            shown: Shown::Span(0..4),
            count: 4,
            literal_cuts: serde_json::to_value(LiteralCuts::NotApplied { because: None }).unwrap(),
            min: 1,
            ranges: json!([{ "size": 64, "name": ".rdata", "address": "0x1000" }]),
            coverage,
        }
    }

    /// What the answer always was is the value form: a map of values, whose keys are sorted.
    /// A difference here is a field in the wrong place. `scripts/answers_unchanged.py` holds
    /// the result against an older engine, which this cannot.
    #[test]
    fn rows_write_what_the_value_form_wrote() {
        for coverage in [serde_json::Map::new(), serde_json::to_value(RegionCoverage::default()).unwrap().as_object().unwrap().clone()] {
            let page = page(coverage);
            let value = serde_json::to_value(&page).unwrap();
            assert_eq!(serde_json::to_string(&page).unwrap(), serde_json::to_string(&value).unwrap());
            assert_eq!(serde_json::to_string_pretty(&page).unwrap(), serde_json::to_string_pretty(&value).unwrap());
        }
    }

    #[test]
    fn a_row_says_what_it_should() {
        let value = serde_json::to_value(page(serde_json::Map::new())).unwrap();
        let rows = value["strings"].as_array().unwrap();
        assert_eq!(rows[1]["cut_by"], json!({ "at": "0x400", "kind": serde_json::to_value(CutKind::CodePair).unwrap() }));
        assert_eq!(rows[1]["encoding"], "utf16le");
        assert_eq!(rows[2]["linear_memory"], json!({ "address": "0x8004", "memory": 1 }), "the row's place in that memory");
        assert_eq!(rows[3]["linear_memory"], json!({ "not_placed": "an imported base" }));
        assert!(rows[0].get("cut_by").is_none() && rows[0].get("linear_memory").is_none(), "absent, not null");
    }
}

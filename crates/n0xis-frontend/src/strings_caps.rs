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
//! number, and their runs stay whole.

use std::sync::{Arc, Mutex};

use n0xis_contracts::{Response, Va, schema};
use n0xis_core::{FoundString, StringEncoding};
use serde_json::{Value, json};

use crate::registry::{Capability, Origin, Plugin, Registry};
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
        reg.add(Capability::new(
            "strings",
            "Text in the image: runs of printable UTF-8 or UTF-16LE characters, with their addresses. By default the file-backed sections that hold no code; `section`, `all_sections`, or `start`+`size` for others. In an image on disk a run is cut where a reference states a length (`cut_by`). `contains` filters (any case); `limit`/`offset` page.",
            Some(schema::v1::STRINGS),
            Origin::Builtin,
            Box::new(strings),
        ));
    }
}

fn strings(args: &Value) -> Response<Value> {
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
        pid: args.get("pid").and_then(Value::as_u64).map(|v| v as u32),
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
    let matching: Vec<&(FoundString, usize)> =
        scanned.strings.iter().filter(|(s, _)| needle.as_deref().is_none_or(|n| s.text.to_lowercase().contains(n))).collect();
    let total = matching.len();
    let offset = args.get("offset").and_then(Value::as_u64).map_or(0, |v| v as usize);
    let limit = args.get("limit").and_then(Value::as_u64).map_or(DEFAULT_STRINGS_LIMIT, |v| v as usize);
    let page: Vec<Value> = matching
        .into_iter()
        .skip(offset)
        .take(if limit == 0 { usize::MAX } else { limit })
        .map(|(s, i)| {
            let (_, range_start, _, placement) = &scanned.ranges[*i];
            let mut row = json!({
                "address": s.address,
                "section": scanned.ranges[*i].0,
                "encoding": s.encoding.name(),
                "length": s.length,
                "size": s.size,
                "text": s.text,
            });
            if let Some(placement) = placement {
                row["linear_memory"] = linear_memory(placement, s.address.0 - range_start.0);
            }
            if let Some(by) = s.cut_by {
                row["cut_by"] = json!({ "kind": by.kind, "at": by.at });
            }
            row
        })
        .collect();
    let returned = page.len();
    let read: Vec<Value> = scanned
        .ranges
        .iter()
        .map(|(name, va, size, placement)| {
            let mut r = json!({ "name": name, "address": va, "size": size });
            if let Some(placement) = placement {
                r["linear_memory"] = linear_memory(placement, 0);
            }
            r
        })
        .collect();
    let answer = json!({ "count": returned, "min": min, "ranges": read, "strings": page });
    let swept = n0xis_sources::Swept { answer, read: scanned.read.clone() };
    let data = match resolved.src {
        Src::Live(_) | Src::Remote(_) => swept.live().map(|stated| serde_json::to_value(stated).unwrap_or(Value::Null)),
        Src::Static(_) | Src::Snap(_) => swept.window(),
    };
    let data = match data {
        Ok(data) => data,
        Err(nothing) => return Response::error(n0xis_sources::NOTHING_READABLE, nothing.to_string()),
    };
    Response::success(schema::v1::STRINGS, data)
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
fn linear_memory(placement: &n0xis_sources::SegmentPlacement, delta: u64) -> Value {
    match placement {
        n0xis_sources::SegmentPlacement::Placed { memory, address } => {
            json!({ "memory": memory, "address": format!("{:#x}", address.wrapping_add(delta)) })
        }
        n0xis_sources::SegmentPlacement::NotPlaced { why } => json!({ "not_placed": why }),
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
    let refs = literal_refs(src, &text);
    let mut strings: Vec<(FoundString, usize)> = text
        .into_iter()
        .flat_map(|(s, i, ended_by_nul)| n0xis_core::cut_run(s, ended_by_nul, &refs, min).into_iter().map(move |piece| (piece, i)))
        .collect();
    strings.sort_by_key(|(s, _)| s.address.0);
    Ok(Scanned { ranges, strings, read })
}

/// The references with their lengths an image on disk states into `runs`: every
/// data pair in its sections that hold no code, and, on x86-64, every code pair
/// in its code. A run in a section that holds code is not one to cut: what looks
/// like text there is instructions that print, and a function pointer with a
/// small number beside it, which any table of them has, is not a literal.
///
/// A section or a code range that does not read gives no evidence and no error:
/// the scan has its answer, and with no evidence that answer is the run whole.
fn literal_refs(src: &Src, runs: &[(FoundString, usize, bool)]) -> n0xis_core::LiteralRefs {
    let Src::Static(img) = src else { return n0xis_core::LiteralRefs::default() };
    let code = src.as_mem().code_ranges();
    let holds_code = |va: Va| code.iter().any(|(s, n)| va.0 >= s.0 && va.0 - s.0 < *n);
    let mut evidence = n0xis_core::LiteralEvidence::new(runs.iter().map(|(s, ..)| s).filter(|s| !holds_code(s.address)));
    let machine = img.image().machine();
    let Some(width) = machine.address_model.pointer_width() else { return n0xis_core::LiteralRefs::default() };
    if evidence.is_empty() {
        return n0xis_core::LiteralRefs::default();
    }
    let order = machine.byte_order;
    let data: Vec<(Va, u64)> = img.sections().into_iter().map(|(_, va, size)| (va, size)).filter(|(va, _)| !holds_code(*va)).collect();
    let in_data = |va: u64| data.iter().any(|(s, n)| va >= s.0 && va - s.0 < *n);
    let how = img.address_words(&mut |at, value| {
        if in_data(at) {
            evidence.relocated_word(src.as_mem(), img.relocated_words(), at, value, width, order);
        }
    });
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
    evidence.into_refs()
}

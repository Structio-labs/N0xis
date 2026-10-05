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

/// A range to read: its name (a section's, or `range`), start and size.
type ReadRange = (String, Va, u64);

/// What was read, and every string found in it, in address order.
struct Scanned {
    ranges: Vec<ReadRange>,
    /// Each string with the index of the range it was found in.
    strings: Vec<(FoundString, usize)>,
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
            "Text in the image: runs of printable UTF-8 or UTF-16LE characters, with their addresses. By default the file-backed sections that hold no code; `section`, `all_sections`, or `start`+`size` for others. `contains` filters (any case); `limit`/`offset` page.",
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
            json!({
                "address": s.address,
                "section": scanned.ranges[*i].0,
                "encoding": s.encoding.name(),
                "length": s.length,
                "size": s.size,
                "text": s.text,
            })
        })
        .collect();
    let returned = page.len();
    let read: Vec<Value> = scanned.ranges.iter().map(|(name, va, size)| json!({ "name": name, "address": va, "size": size })).collect();
    Response::success(schema::v1::STRINGS, json!({ "count": returned, "min": min, "ranges": read, "strings": page }))
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
        (Some(start), Some(size)) => Ok(vec![("range".to_string(), start, size)]),
        (Some(_), None) | (None, Some(_)) => Err(("bad-arg", "a range needs both start and size".to_string())),
        (None, None) => {
            let Src::Static(img) = src else {
                return Err(("no-range", "only an image on disk has sections; for this source pass start and size".to_string()));
            };
            if let Some(name) = args.get("section").and_then(Value::as_str) {
                return img
                    .section_range(name)
                    .map(|(va, size)| vec![(name.to_string(), va, size)])
                    .ok_or_else(|| ("no-section", format!("the image has no section named {name:?}")));
            }
            let all = args.get("all_sections").and_then(Value::as_bool).unwrap_or(false);
            let code = src.as_mem().code_ranges();
            let holds_code = |va: Va| code.iter().any(|(s, n)| va.0 >= s.0 && va.0 - s.0 < *n);
            Ok(img
                .sections()
                .into_iter()
                .filter(|(_, va, _)| all || !holds_code(*va))
                // A PE's headers are a range of their own with no name.
                .map(|(name, va, size)| (if name.is_empty() { "(headers)".to_string() } else { name }, va, size))
                .collect())
        }
    }
}

/// Every string in `ranges`, read stretch by stretch: a string never runs
/// across a gap.
fn scan(src: &Src, ranges: Vec<ReadRange>, min: usize, encodings: &[StringEncoding]) -> Result<Scanned, String> {
    let mut strings = Vec::new();
    for (i, (_, start, size)) in ranges.iter().enumerate() {
        let runs = n0xis_sources::read_runs(src.as_mem(), *start, *size as usize).map_err(|e| e.to_string())?;
        for (va, bytes) in runs {
            strings.extend(n0xis_core::find_strings(&bytes, va, min, encodings).into_iter().map(|s| (s, i)));
        }
    }
    strings.sort_by_key(|(s, _)| s.address.0);
    Ok(Scanned { ranges, strings })
}

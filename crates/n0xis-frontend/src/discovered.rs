// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Function discovery kept for the image a session holds, so that a front end
//! paging through the list pays for the scan once, not once per page. Measured
//! on a 159 MB library: every page of 20 000 cost the whole scan, 10.6 s each,
//! whatever its offset. Kept in two places: in this process for the session,
//! and in the project's disk cache for the next session on the same bytes.

use std::sync::{Arc, Mutex};

use n0xis_contracts::Va;
use n0xis_core::{CoreError, Ctx, Discovered};

use crate::source::Src;

/// The last image's entries, under the key that says which scan they answer.
static KEPT: Mutex<Option<(String, Arc<Discovered>)>> = Mutex::new(None);

/// The functions in the code windows `ranges` of `src` (called `label`),
/// merged in address order. A source with an identity (a file, a snapshot)
/// cannot change under the scan, so its answer is kept, in this process under
/// that identity and on disk under the code bytes; a live or remote process
/// can, so it is scanned every time. The label is never the key: it names only
/// the file, and two files of one name are two images.
///
/// This is the one answer to "which functions does this image have": `function
/// discover` and `analyze` both ask it, over the same windows
/// ([`image_code_ranges`]), with the functions the image declares in `ctx`.
pub fn discovered_ranges(ctx: &Ctx, src: &Src, label: &str, ranges: &[(Va, usize)]) -> Result<Arc<Discovered>, CoreError> {
    let id = src.as_mem().identity();
    let windows: Vec<String> = ranges.iter().map(|(start, size)| format!("{:#x}+{size:#x}", start.0)).collect();
    let key = id.map(|id| format!("{id}|{}|{}|{}", windows.join(","), ctx.arch.decoder_id(), ctx.functions.map_or(0, <[_]>::len)));
    if let Some(key) = &key
        && let Ok(kept) = KEPT.lock()
        && let Some((k, found)) = kept.as_ref()
        && k == key
    {
        return Ok(Arc::clone(found));
    }
    let mut entries = Vec::new();
    let mut scanned_bytes = 0;
    for &(start, size) in ranges.iter().filter(|(_, size)| *size > 0) {
        let part = match id {
            Some(_) => n0xis_pipeline::discovered_cached(ctx, start, size, label)?,
            None => n0xis_core::discover_entries(ctx, start, size)?,
        };
        scanned_bytes += part.scanned_bytes;
        entries.extend(part.entries);
    }
    entries.sort_by_key(|(va, _)| va.0);
    entries.dedup_by_key(|(va, _)| va.0);
    let start = ranges.first().map_or(Va(0), |(start, _)| *start);
    let found = Arc::new(Discovered { start, scanned_bytes, entries });
    if let Some(key) = key
        && let Ok(mut kept) = KEPT.lock()
    {
        *kept = Some((key, Arc::clone(&found)));
    }
    Ok(found)
}

/// The windows a whole-image function scan covers: every executable range of
/// `src`, since `.text` is not the only code on every image, or the one window
/// a caller named. `default` is the window used when the image states no
/// ranges of its own.
pub fn image_code_ranges(
    src: &Src,
    default: Option<(Va, u64)>,
    region_len: Option<usize>,
    explicit_start: Option<Va>,
    explicit_size: Option<usize>,
    fallback_start: Va,
) -> Vec<(Va, usize)> {
    crate::source::scan_ranges_or(&src.code_ranges_of(None), default, region_len, explicit_start, explicit_size, fallback_start)
        .into_iter()
        .filter(|(_, size)| *size > 0)
        .collect()
}

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

/// The functions in `[start, start + size)` of `src` (called `label`). A file
/// or a snapshot cannot change under the scan, so its answer is kept, in this
/// process and on disk; a live or remote process can, so it is scanned every
/// time.
pub fn discovered(ctx: &Ctx, src: &Src, label: &str, start: Va, size: usize) -> Result<Arc<Discovered>, CoreError> {
    if matches!(src, Src::Live(_) | Src::Remote(_)) {
        return n0xis_core::discover_entries(ctx, start, size).map(Arc::new);
    }
    let key = format!("{label}|{:#x}|{size:#x}|{}|{}", start.0, ctx.arch.decoder_id(), ctx.functions.map_or(0, <[_]>::len));
    if let Ok(kept) = KEPT.lock()
        && let Some((k, found)) = kept.as_ref()
        && *k == key
    {
        return Ok(Arc::clone(found));
    }
    let found = Arc::new(n0xis_pipeline::discovered_cached(ctx, start, size, label)?);
    if let Ok(mut kept) = KEPT.lock() {
        *kept = Some((key, Arc::clone(&found)));
    }
    Ok(found)
}

// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Function discovery kept for the image a session holds, so that a front end
//! paging through the list pays for the scan once, not once per page. Measured
//! on a 159 MB library: every page of 20 000 cost the whole scan, 10.6 s each,
//! whatever its offset.

use std::sync::{Arc, Mutex};

use n0xis_contracts::Va;
use n0xis_core::{CoreError, Ctx, Discovered};

use crate::source::Src;

/// The last image's entries, under the key that says which scan they answer.
static KEPT: Mutex<Option<(String, Arc<Discovered>)>> = Mutex::new(None);

/// What a kept scan is valid for: an image whose bytes cannot change (a file or
/// a snapshot), and the exact range and decoder it was run with. A live or
/// remote process can change under the scan, so it gets no key and is scanned
/// every time.
pub fn scan_key(src: &Src, label: &str, start: Va, size: usize, ctx: &Ctx) -> Option<String> {
    match src {
        Src::Static(_) | Src::Snap(_) => {
            Some(format!("{label}|{:#x}|{size:#x}|{}|{}", start.0, ctx.arch.decoder_id(), ctx.functions.map_or(0, <[_]>::len)))
        }
        Src::Live(_) | Src::Remote(_) => None,
    }
}

/// The functions in `[start, start + size)`: from the kept scan when `key`
/// matches it, otherwise scanned now (and kept when there is a key).
pub fn discovered(ctx: &Ctx, start: Va, size: usize, key: Option<String>) -> Result<Arc<Discovered>, CoreError> {
    let Some(key) = key else { return n0xis_core::discover_entries(ctx, start, size).map(Arc::new) };
    if let Ok(kept) = KEPT.lock()
        && let Some((k, found)) = kept.as_ref()
        && *k == key
    {
        return Ok(Arc::clone(found));
    }
    let found = Arc::new(n0xis_core::discover_entries(ctx, start, size)?);
    if let Ok(mut kept) = KEPT.lock() {
        *kept = Some((key, Arc::clone(&found)));
    }
    Ok(found)
}

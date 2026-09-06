// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! # n0xis-bitsquid — the Bitsquid/Stingray bundle-format adapter
//!
//! Bitsquid/Stingray (the engine behind several shipped games) ships game
//! assets as **archives**: a small header, then a stream of 64 KiB chunks
//! (each either raw or zlib-compressed), which decompress to an **exploded
//! package** — a flat list of entries (`type_hash` + `path_hash`, both
//! pre-computed 64-bit values baked into the file, not something this crate
//! needs to hash itself) each holding one or more *variants* (inline bytes,
//! optionally paired with a same-named `.stream` file for large payloads like
//! textures/audio).
//!
//! This is a **pluggable asset-format adapter**, not a core seam: nothing in
//! `n0xis-core` depends on it, matching the same "isolate an external system
//! behind an adapter" discipline `n0xis-arch`/`n0xis-sources` hold for ISA/OS
//! boundaries. A consumer (the CLI, or any future game-specific crate) reads
//! bytes off disk and hands them to [`open_bundle`]; this crate never touches
//! a filesystem or process itself.
//!
//! Format cross-validated from two independent, non-code sources: community
//! hex-pattern definitions for this bundle format (`archive`/
//! `exploded_package.hexpat`) and the decompiled `bsunp` tool in
//! [xyx0826/Bitsquid-Toolchain](https://github.com/xyx0826/Bitsquid-Toolchain)
//! (itself a recompile of a much older `zenhax` tool) — both describe the same
//! byte layout, which is what this module implements fresh in Rust.

mod archive;
mod cursor;
mod package;
mod repack;
mod types;

pub use archive::{compress_archive, decompress_archive};
pub use cursor::{Cursor, CursorError, Field};
pub use package::{
    BundleEntry, BundleVariant, ExplodedPackage, LuaFormat, LuaResource, lua_resource, parse_exploded_package,
};
pub use repack::patch_and_recompress;
pub use types::{TYPE_HASH_LUA, known_type_name};

use thiserror::Error;

/// Anything that can go wrong reading a Bitsquid archive/package.
#[derive(Debug, Error)]
pub enum BitsquidError {
    #[error("truncated or malformed data: {0}")]
    Truncated(&'static str),
    #[error("unexpected archive header (not a Bitsquid package or save archive)")]
    BadHeader,
    #[error("reserved field was non-zero — not a recognized archive layout")]
    BadReserved,
    #[error("zlib inflate failed: {0}")]
    Inflate(String),
}

/// Decompress an archive and parse its decompressed body as an exploded
/// package in one call — the convenience entry point most callers want.
/// `stream_bytes` is the paired `<bundle>.stream` file's contents, if one
/// exists next to the bundle (large-payload variants live there instead of
/// inline); pass `None` when no such file is present.
pub fn open_bundle(archive_bytes: &[u8], stream_bytes: Option<&[u8]>) -> Result<ExplodedPackage, BitsquidError> {
    let decompressed = decompress_archive(archive_bytes)?;
    parse_exploded_package(&decompressed, stream_bytes)
}

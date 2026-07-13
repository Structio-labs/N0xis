//! The exploded-package layout — the *decompressed* body of an
//! [`crate::archive`] for an asset bundle: a flat entry list, each entry one
//! or more variants of inline (+ optional external `.stream`) bytes. Format
//! per `exploded_package.hexpat`'s `package_t`, cross-validated against the
//! decompiled `bsunp` tool's identical read order (entry count, a 256-byte
//! magic, a throwaway `filename_t` pass, then per-entry variant headers/data).

use serde::Serialize;

use crate::cursor::{Cursor, Field};
use crate::types::known_type_name;
use crate::BitsquidError;

/// The "same for every package" magic block `exploded_package.hexpat` notes
/// but doesn't interpret — skipped, not validated (its meaning is unknown, so
/// asserting on its content would be a guess this crate refuses to make).
const PACKAGE_MAGIC_LEN: usize = 256;

/// One resource variant: some inline bytes, and — for large payloads (audio,
/// textures) — additional bytes that live in the bundle's companion
/// `<bundle>.stream` file rather than inline.
#[derive(Debug, Clone, Serialize)]
pub struct BundleVariant {
    /// Meaning not yet reverse-engineered (`variant_header_t.unknown` in the
    /// hexpat source); carried through rather than dropped.
    pub unknown: u32,
    pub inline_size: u32,
    pub stream_size: u32,
    pub inline_data: Vec<u8>,
    /// Byte offset of `inline_data` within the *decompressed archive body*
    /// (the buffer [`crate::parse_exploded_package`] was called with) —
    /// needed to patch this variant in place and recompress the archive
    /// without re-serializing the whole package structure. `#[serde(skip)]`:
    /// implementation detail, not analysis output.
    #[serde(skip)]
    pub inline_data_offset: usize,
    /// `Some` only when `stream_size > 0` *and* a `.stream` buffer was
    /// supplied to [`crate::parse_exploded_package`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_data: Option<Vec<u8>>,
}

/// One resource entry in the package.
#[derive(Debug, Clone, Serialize)]
pub struct BundleEntry {
    pub type_hash: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_name: Option<&'static str>,
    pub path_hash: u64,
    pub stream_offset: u32,
    pub variants: Vec<BundleVariant>,
}

/// A fully parsed bundle: every entry, in file order.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ExplodedPackage {
    pub entries: Vec<BundleEntry>,
}

/// Data format tag on a Lua resource variant (`lua_resource::format_t` in the
/// hexpat source).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LuaFormat {
    /// Plain Lua source text — reportedly only used in engine debug builds.
    Source,
    /// Compiled stock Lua (5.1-shaped) bytecode.
    GenericBytecode,
    /// LuaJIT 2.x bytecode (`\x1bLJ` dump format) — the format the game
    /// actually ships with, per the hexpat source's own comment.
    LuaJit2,
    /// An explicitly-reserved "bad/invalid" tag some tooling emits; carries
    /// the raw value through rather than discarding it.
    Bad(u32),
}

impl LuaFormat {
    fn from_tag(tag: u32) -> LuaFormat {
        match tag {
            0 => LuaFormat::Source,
            1 => LuaFormat::GenericBytecode,
            2 => LuaFormat::LuaJit2,
            other => LuaFormat::Bad(other),
        }
    }
}

/// A Lua variant's inline data, with its 8-byte `lua_resource::header_t`
/// already stripped off.
#[derive(Debug, Clone, Serialize)]
pub struct LuaResource {
    pub format: LuaFormat,
    pub data: Vec<u8>,
}

/// Strip a Lua variant's `{ size: u32, format: u32 }` header off its inline
/// bytes. Returns `None` if `variant`'s inline data is too short to hold the
/// header, or the declared `size` runs past what's actually present — a
/// malformed variant is reported as absent, not guessed at.
pub fn lua_resource(variant: &BundleVariant) -> Option<LuaResource> {
    let bytes = &variant.inline_data;
    if bytes.len() < 8 {
        return None;
    }
    let size = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    let format = LuaFormat::from_tag(u32::from_le_bytes(bytes[4..8].try_into().unwrap()));
    let data = bytes.get(8..8 + size)?.to_vec();
    Some(LuaResource { format, data })
}

/// Parse a decompressed archive body as an exploded package. `stream_bytes`
/// is the paired `.stream` file's contents (if present); variants whose
/// `stream_size > 0` read sequentially from it, matching the order real
/// bundles store them in (there is no per-variant seek table — the working
/// reference tool reads the `.stream` file purely sequentially too).
pub fn parse_exploded_package(decompressed: &[u8], stream_bytes: Option<&[u8]>) -> Result<ExplodedPackage, BitsquidError> {
    let mut c = Cursor::new(decompressed);
    let entries_count = c.u32().field("entries_count")? as usize;
    c.skip(PACKAGE_MAGIC_LEN).field("package magic block")?;
    // The redundant `filename_t files[entries_count]` pass — each entry
    // re-states its own filename below, so this array (16 bytes/entry) is
    // skipped rather than parsed twice.
    c.skip(entries_count.saturating_mul(16)).field("redundant filename table")?;

    let mut stream_pos = 0usize;
    let mut entries = Vec::with_capacity(entries_count.min(1 << 20));
    for _ in 0..entries_count {
        let type_hash = c.u64().field("entry.filename.type_hash")?;
        let path_hash = c.u64().field("entry.filename.path_hash")?;
        let variants_count = c.u32().field("entry.variants_count")? as usize;
        let stream_offset = c.u32().field("entry.stream_offset")?;

        let mut headers = Vec::with_capacity(variants_count.min(1 << 16));
        for _ in 0..variants_count {
            let unknown = c.u32().field("variant_header.unknown")?;
            let inline_size = c.u32().field("variant_header.inline_size")?;
            let stream_size = c.u32().field("variant_header.stream_size")?;
            headers.push((unknown, inline_size, stream_size));
        }

        let mut variants = Vec::with_capacity(headers.len());
        for (unknown, inline_size, stream_size) in headers {
            let inline_data_offset = c.pos();
            let inline_data = c.take(inline_size as usize).map_err(|_| BitsquidError::Truncated("variant inline data"))?.to_vec();
            let stream_data = if stream_size > 0 {
                stream_bytes.and_then(|sb| {
                    let end = stream_pos.checked_add(stream_size as usize)?;
                    let slice = sb.get(stream_pos..end)?;
                    stream_pos = end;
                    Some(slice.to_vec())
                })
            } else {
                None
            };
            variants.push(BundleVariant { unknown, inline_size, stream_size, inline_data, inline_data_offset, stream_data });
        }

        entries.push(BundleEntry { type_hash, type_name: known_type_name(type_hash), path_hash, stream_offset, variants });
    }

    Ok(ExplodedPackage { entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TYPE_HASH_LUA;

    fn build_package(entries: &[(u64, u64, Vec<(u32, Vec<u8>, Vec<u8>)>)]) -> (Vec<u8>, Vec<u8>) {
        // entries: (type_hash, path_hash, [(unknown, inline_bytes, stream_bytes)])
        let mut body = Vec::new();
        body.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        body.extend_from_slice(&[0u8; PACKAGE_MAGIC_LEN]);
        for (type_hash, path_hash, _) in entries {
            body.extend_from_slice(&type_hash.to_le_bytes());
            body.extend_from_slice(&path_hash.to_le_bytes());
        }
        let mut stream = Vec::new();
        for (type_hash, path_hash, variants) in entries {
            body.extend_from_slice(&type_hash.to_le_bytes());
            body.extend_from_slice(&path_hash.to_le_bytes());
            body.extend_from_slice(&(variants.len() as u32).to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes()); // stream_offset
            for (unknown, inline, streamed) in variants {
                body.extend_from_slice(&unknown.to_le_bytes());
                body.extend_from_slice(&(inline.len() as u32).to_le_bytes());
                body.extend_from_slice(&(streamed.len() as u32).to_le_bytes());
            }
            for (_, inline, streamed) in variants {
                body.extend_from_slice(inline);
                stream.extend_from_slice(streamed);
            }
        }
        (body, stream)
    }

    #[test]
    fn parses_entries_and_resolves_known_type_names() {
        let (body, stream) = build_package(&[(TYPE_HASH_LUA, 0xdead_beef, vec![(0, b"lua-inline-bytes".to_vec(), vec![])])]);
        let pkg = parse_exploded_package(&body, Some(&stream)).unwrap();
        assert_eq!(pkg.entries.len(), 1);
        assert_eq!(pkg.entries[0].type_name, Some("lua"));
        assert_eq!(pkg.entries[0].path_hash, 0xdead_beef);
        assert_eq!(pkg.entries[0].variants[0].inline_data, b"lua-inline-bytes");
    }

    #[test]
    fn unknown_type_hash_resolves_to_no_name() {
        let (body, _stream) = build_package(&[(0x1111_2222_3333_4444, 1, vec![(0, b"x".to_vec(), vec![])])]);
        let pkg = parse_exploded_package(&body, None).unwrap();
        assert_eq!(pkg.entries[0].type_name, None);
    }

    #[test]
    fn stream_variant_reads_from_the_companion_stream_buffer() {
        let (body, stream) = build_package(&[(TYPE_HASH_LUA, 1, vec![(0, b"inline".to_vec(), b"streamed-payload".to_vec())])]);
        let pkg = parse_exploded_package(&body, Some(&stream)).unwrap();
        assert_eq!(pkg.entries[0].variants[0].stream_data.as_deref(), Some(&b"streamed-payload"[..]));
    }

    #[test]
    fn missing_stream_buffer_leaves_stream_data_none_not_an_error() {
        let (body, _stream) = build_package(&[(TYPE_HASH_LUA, 1, vec![(0, b"inline".to_vec(), b"streamed-payload".to_vec())])]);
        let pkg = parse_exploded_package(&body, None).unwrap();
        assert_eq!(pkg.entries[0].variants[0].stream_data, None);
    }

    #[test]
    fn multiple_entries_and_variants_preserve_order() {
        let (body, stream) = build_package(&[
            (TYPE_HASH_LUA, 10, vec![(0, b"a".to_vec(), vec![])]),
            (0x9999, 20, vec![(0, b"b1".to_vec(), vec![]), (1, b"b2".to_vec(), vec![])]),
        ]);
        let pkg = parse_exploded_package(&body, Some(&stream)).unwrap();
        assert_eq!(pkg.entries.len(), 2);
        assert_eq!(pkg.entries[1].variants.len(), 2);
        assert_eq!(pkg.entries[1].variants[1].inline_data, b"b2");
    }

    #[test]
    fn lua_header_strip_recovers_format_and_raw_chunk() {
        let mut inline = Vec::new();
        let chunk = b"\x1bLJ\x02fake-bytecode";
        inline.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
        inline.extend_from_slice(&2u32.to_le_bytes()); // LuaJit2
        inline.extend_from_slice(chunk);
        let variant = BundleVariant { unknown: 0, inline_size: inline.len() as u32, stream_size: 0, inline_data: inline, inline_data_offset: 0, stream_data: None };
        let resource = lua_resource(&variant).unwrap();
        assert_eq!(resource.format, LuaFormat::LuaJit2);
        assert_eq!(resource.data, chunk);
    }

    #[test]
    fn truncated_package_errors_instead_of_panicking() {
        let bad = vec![5, 0, 0, 0]; // claims 5 entries, then nothing else
        assert!(parse_exploded_package(&bad, None).is_err());
    }
}

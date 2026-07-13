//! The outer archive container: a 4- or 12-byte header, then a stream of
//! 64 KiB chunks (each either stored raw or zlib-compressed) that concatenate
//! to the decompressed payload — an [`crate::ExplodedPackage`] for an asset
//! bundle. Format per `archive.hexpat`'s `archive::archive_t`, cross-checked
//! against the decompiled `bsunp` tool's identical chunk loop (seek to byte
//! 12, read a `u32` chunk size, copy raw if it's exactly 65536, else zlib
//! decompress).

use crate::cursor::{Cursor, Field};
use crate::BitsquidError;

/// Distinguishes the two `archive::header_t` shapes. Only [`AsciiHeaderKind::Package`]
/// (an asset bundle) is expected in practice for the bundle files this crate
/// targets; [`AsciiHeaderKind::Save`] (a save-game archive) is recognized so a
/// caller gets a clear error instead of a misparse, not because this crate
/// does anything else with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderKind {
    /// `04 00 00 F0` magic — an asset bundle; body starts right after it.
    Package,
    /// `crc32 packed_size unpacked_size`, 12 bytes — a save-game archive.
    Save,
}

const PACKAGE_MAGIC: [u8; 4] = [0x04, 0x00, 0x00, 0xF0];
/// The chunk size at which a chunk is stored raw instead of zlib-compressed
/// (compression bought nothing, so the game just stores it verbatim).
const RAW_CHUNK_SIZE: u32 = 65536;

fn peek_header_kind(bytes: &[u8]) -> Result<HeaderKind, BitsquidError> {
    if bytes.len() < 4 {
        return Err(BitsquidError::Truncated("archive header"));
    }
    if bytes[..4] == PACKAGE_MAGIC {
        Ok(HeaderKind::Package)
    } else if bytes.len() >= 12 {
        Ok(HeaderKind::Save)
    } else {
        Err(BitsquidError::BadHeader)
    }
}

/// Decompress an archive's chunk stream into its full decompressed payload.
/// Every chunk is walked (never truncated early) so the result is always the
/// complete body, matching this project's sound-over-complete rule.
pub fn decompress_archive(bytes: &[u8]) -> Result<Vec<u8>, BitsquidError> {
    let kind = peek_header_kind(bytes)?;
    let mut c = Cursor::new(bytes);
    match kind {
        HeaderKind::Package => c.skip(4).field("package header magic")?,
        HeaderKind::Save => c.skip(12).field("save header (crc32/packed_size/unpacked_size)")?,
    }

    let _declared_unpacked_size = c.u32().field("packed_data.unpacked_size")?;
    let reserved = c.u32().field("packed_data.reserved")?;
    if reserved != 0 {
        return Err(BitsquidError::BadReserved);
    }

    let mut out = Vec::new();
    while c.remaining() > 0 {
        let chunk_size = c.u32().field("chunk.chunk_size")? as usize;
        let chunk_bytes = c.take(chunk_size).map_err(|_| BitsquidError::Truncated("chunk data"))?;
        if chunk_size as u32 == RAW_CHUNK_SIZE {
            out.extend_from_slice(chunk_bytes);
        } else {
            let inflated = miniz_oxide::inflate::decompress_to_vec_zlib(chunk_bytes)
                .map_err(|e| BitsquidError::Inflate(format!("{e:?}")))?;
            out.extend_from_slice(&inflated);
        }
    }
    Ok(out)
}

/// Compress a decompressed body into a fresh archive: split into 64 KiB
/// pieces (matching real bundle files' own chunking, and avoiding the
/// raw/compressed ambiguity a differently-sized last chunk could hit if its
/// *compressed* size happened to equal 65536), zlib-compress each, and emit
/// the same `package` header shape [`decompress_archive`] reads. The inverse
/// of `decompress_archive` — round-trips through it byte-for-byte.
pub fn compress_archive(decompressed: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&PACKAGE_MAGIC);
    out.extend_from_slice(&(decompressed.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved

    for chunk in decompressed.chunks(RAW_CHUNK_SIZE as usize) {
        if chunk.len() as u32 == RAW_CHUNK_SIZE {
            // A full-size chunk that fails to shrink under compression is
            // stored raw, exactly like the format's own escape hatch.
            let compressed = miniz_oxide::deflate::compress_to_vec_zlib(chunk, 6);
            if compressed.len() < chunk.len() {
                out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
                out.extend_from_slice(&compressed);
            } else {
                out.extend_from_slice(&RAW_CHUNK_SIZE.to_le_bytes());
                out.extend_from_slice(chunk);
            }
        } else {
            // The final, shorter-than-64KiB chunk: always compressed. Its
            // compressed size landing on exactly 65536 bytes — which would
            // misread as "stored raw" — is a birthday-bound coincidence this
            // format has no escape hatch for either; not handled here.
            let compressed = miniz_oxide::deflate::compress_to_vec_zlib(chunk, 6);
            out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
            out.extend_from_slice(&compressed);
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn build_archive(chunks: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::new();
        for &chunk in chunks {
            let is_raw = chunk.len() as u32 == RAW_CHUNK_SIZE;
            let stored: Vec<u8> = if is_raw {
                chunk.to_vec()
            } else {
                miniz_oxide::deflate::compress_to_vec_zlib(chunk, 6)
            };
            body.extend_from_slice(&(stored.len() as u32).to_le_bytes());
            body.extend_from_slice(&stored);
        }
        let unpacked_size: u32 = chunks.iter().map(|c| c.len() as u32).sum();
        let mut archive = Vec::new();
        archive.extend_from_slice(&PACKAGE_MAGIC);
        archive.extend_from_slice(&unpacked_size.to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes()); // reserved
        archive.extend_from_slice(&body);
        archive
    }

    #[test]
    fn single_compressed_chunk_roundtrips() {
        let payload = b"hello bitsquid archive, this is a small test payload".repeat(50);
        let archive = build_archive(&[&payload]);
        let out = decompress_archive(&archive).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn multiple_chunks_concatenate_in_order() {
        let a = vec![0xAAu8; 100];
        let b = vec![0xBBu8; 200];
        let archive = build_archive(&[&a, &b]);
        let out = decompress_archive(&archive).unwrap();
        assert_eq!(&out[..100], &a[..]);
        assert_eq!(&out[100..], &b[..]);
    }

    #[test]
    fn nonzero_reserved_field_is_rejected() {
        let mut archive = Vec::new();
        archive.extend_from_slice(&PACKAGE_MAGIC);
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&1u32.to_le_bytes()); // reserved != 0
        assert!(matches!(decompress_archive(&archive), Err(BitsquidError::BadReserved)));
    }

    #[test]
    fn truncated_archive_errors_instead_of_panicking() {
        let archive = vec![0x04, 0x00, 0x00, 0xF0, 0x01, 0x00]; // way too short
        assert!(decompress_archive(&archive).is_err());
    }
}

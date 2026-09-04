// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Writing a modified variant back into a bundle file — the inverse of
//! [`crate::open_bundle`]. Scoped narrowly to the one edit this project
//! actually needs: **replace one variant's inline bytes with a same-length
//! replacement** (e.g. a single patched Lua instruction word from
//! `n0xis_lua::patch_instruction`), then re-emit a valid archive.
//!
//! Deliberately *not* a general "rebuild the whole package from a
//! `ExplodedPackage` struct" — this project's own anti-scope-creep rule: a
//! same-length in-place patch needs only recompression, not touching a single
//! offset/size field in the exploded-package structure (they're all
//! unchanged), so that's all this module does.

use crate::archive::compress_archive;
use crate::BitsquidError;

/// Replace the bytes at `[offset, offset + replacement.len())` in a
/// *decompressed* archive body with `replacement`, then recompress it into a
/// new archive file (same header shape as the original). `replacement.len()`
/// need not equal the original span's length — the exploded-package's own
/// size fields live *inside* this same decompressed body (as `inline_size` in
/// each variant header) and are not touched here, so callers doing a
/// different-length replacement must patch those fields too, in the same
/// `decompressed` buffer, before calling this. For the same-length case this
/// project actually uses (an instruction-word swap), no such extra patching
/// is needed.
pub fn patch_and_recompress(decompressed: &[u8], offset: usize, replacement: &[u8]) -> Result<Vec<u8>, BitsquidError> {
    let end = offset.checked_add(replacement.len()).ok_or(BitsquidError::Truncated("patch offset overflow"))?;
    if end > decompressed.len() {
        return Err(BitsquidError::Truncated("patch runs past end of decompressed body"));
    }
    let mut patched = decompressed.to_vec();
    patched[offset..end].copy_from_slice(replacement);
    Ok(compress_archive(&patched))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decompress_archive, parse_exploded_package};

    #[test]
    fn patch_and_recompress_roundtrips_through_decompress_and_reparse() {
        let payload = {
            let mut p = Vec::new();
            p.extend_from_slice(&1u32.to_le_bytes()); // entries_count
            p.extend_from_slice(&[0u8; 256]); // magic
            p.extend_from_slice(&0xdead_beefu64.to_le_bytes()); // filename_t.type_hash (redundant pass)
            p.extend_from_slice(&1u64.to_le_bytes()); // filename_t.path_hash
            p.extend_from_slice(&0xdead_beefu64.to_le_bytes()); // entry.type_hash
            p.extend_from_slice(&1u64.to_le_bytes()); // entry.path_hash
            p.extend_from_slice(&1u32.to_le_bytes()); // variants_count
            p.extend_from_slice(&0u32.to_le_bytes()); // stream_offset
            p.extend_from_slice(&0u32.to_le_bytes()); // unknown
            p.extend_from_slice(&8u32.to_le_bytes()); // inline_size
            p.extend_from_slice(&0u32.to_le_bytes()); // stream_size
            p.extend_from_slice(b"ORIGINAL"); // 8-byte inline payload
            p
        };
        let archive = crate::archive::tests::build_archive(&[&payload]);
        let decompressed = decompress_archive(&archive).unwrap();
        let pkg = parse_exploded_package(&decompressed, None).unwrap();
        let offset = pkg.entries[0].variants[0].inline_data_offset;
        assert_eq!(&decompressed[offset..offset + 8], b"ORIGINAL");

        let new_archive = patch_and_recompress(&decompressed, offset, b"PATCHED!").unwrap();
        let redecompressed = decompress_archive(&new_archive).unwrap();
        let repkg = parse_exploded_package(&redecompressed, None).unwrap();
        assert_eq!(repkg.entries[0].variants[0].inline_data, b"PATCHED!");
        assert_eq!(redecompressed.len(), decompressed.len(), "a same-length patch must not change the decompressed body's size");
    }

    #[test]
    fn out_of_range_offset_is_rejected() {
        let decompressed = vec![0u8; 16];
        assert!(patch_and_recompress(&decompressed, 20, b"x").is_err());
    }
}

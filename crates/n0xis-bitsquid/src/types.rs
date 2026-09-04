// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Known Bitsquid resource `type_hash` values. These are literal 64-bit
//! constants baked into every bundle file — resolving what an entry's
//! `type_hash` *means* is a table lookup, not a hash computation (unlike a
//! `path_hash`, which would need Murmur64-of-candidate-strings to resolve to
//! a human name — not implemented here; out of scope for type-based
//! extraction, which only needs `type_hash` equality). Table transcribed from
//! the `file_type_t` enum shared by community `archive.hexpat`/
//! `exploded_package.hexpat` hex-pattern patterns for this bundle format, a plain
//! constant table, not executable logic.

/// The `type_hash` for a Lua script resource — the one this crate's `bundle
/// extract --type lua` filters on.
pub const TYPE_HASH_LUA: u64 = 0xa14e8dfa2cd117e2;

const KNOWN_TYPES: &[(u64, &str)] = &[
    (0x00a3e6c59a2b9c6c, "timpani_master"),
    (0x0d972bab10b40fd3, "strings"),
    (0x18dead01056b72e9, "bones"),
    (0x27862fe24795319c, "render_config"),
    (0x2a690fd348fe9ac5, "level"),
    (0x2bbcabe5074ade9e, "input"),
    (0x3b1fa9e8f6bac374, "network_config"),
    (0x712d6e3dd1024c9c, "ugg"),
    (0x76015845a6003765, "xml"),
    (0x786f65c00a816b19, "wav"),
    (0x7ffdb779b04e4ed1, "baked_lighting"),
    (0x82645835e6b73232, "config"),
    (0x8fd0d44d20650b68, "data"),
    (0x92d3ee038eeb610d, "flow"),
    (0x931e336d7646cc26, "animation"),
    (0x99736be1fff739a4, "timpani_bank"),
    (0x9e5c3cc74575aeb5, "shader_library_group"),
    (0x9efe0a916aae7880, "font"),
    (TYPE_HASH_LUA, "lua"),
    (0xa486d4045106165c, "state_machine"),
    (0xa8193123526fad64, "particles"),
    (0xa99510c6e86dd3c2, "upb"),
    (0xad9c6d9ed1e5e77a, "package"),
    (0xad2d3fa30d9ab394, "surface_properties"),
    (0xb277b11fe4a61d37, "mouse_cursor"),
    (0xbf21403a3ab0bbb1, "physics_properties"),
    (0xcce8d5b5f5ae333f, "shader"),
    (0xcd4238c6a0c69e32, "texture"),
    (0xd8b27864a97ffdd7, "sound_environment"),
    (0xdcfb9e18fff13984, "animation_curves"),
    (0xe0a48d0be9a7453f, "unit"),
    (0xe3f0baa17d620321, "static_pvs"),
    (0xe5ee32a477239a93, "shader_library"),
    (0xeac0b497876adedf, "material"),
    (0xf7505933166d6755, "vector_field"),
    (0xf97af9983c05b950, "spu_job"),
    (0xfa4a8e091a91201e, "ivf"),
    (0xfe73c7dcff8a7ca5, "shading_environment"),
    (0x504b55235d21440e, "wwise_stream"),
    (0x535a7bd3e650d799, "wwise_bank"),
    (0xd50a8b7e1c82b110, "wwise_metadata"),
    (0xaf32095c82f2b070, "wwise_dep"),
];

/// Resolve a resource's `type_hash` to its known type name (e.g. `"lua"`),
/// or `None` for a hash this table doesn't recognize — an unknown type is
/// reported as unknown, never guessed.
pub fn known_type_name(type_hash: u64) -> Option<&'static str> {
    KNOWN_TYPES.iter().find(|(h, _)| *h == type_hash).map(|(_, name)| *name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lua_hash_resolves_to_its_name() {
        assert_eq!(known_type_name(TYPE_HASH_LUA), Some("lua"));
    }

    #[test]
    fn unknown_hash_resolves_to_none() {
        assert_eq!(known_type_name(0x1234_5678_9abc_def0), None);
    }
}

//! `n0xis-warp` — the **WARP function-identity primitive**, clean-room.
//!
//! [WARP](https://github.com/Vector35/warp) is Vector 35's Apache-2.0 format for
//! *transferring function information across binary-analysis tools*. Unlike a
//! FLIRT byte-pattern ([`n0xis_flirt`](../n0xis_flirt)), a WARP signature
//! identifies a function by a **GUID** derived from its structure, so the same
//! function matches regardless of where it is linked or how it is relocated:
//!
//! - a **basic-block GUID** is `UUIDv5(NAMESPACE_BASIC_BLOCK, normalized_bytes)`
//!   — the block's bytes with the linker-varied parts neutralized;
//! - a **function GUID** is `UUIDv5(NAMESPACE_FUNCTION, ‖ block GUIDs)`, the
//!   basic-block GUIDs concatenated in address order (highest→lowest start).
//!
//! This crate implements exactly those two hashes — plus the SHA-1 and UUIDv5
//! they stand on — with **no dependencies**, so the identity math is a pure,
//! auditable primitive with zero supply-chain surface (the same discipline as
//! `n0xis-flirt`; depend with `default-features = false` for just this). It is
//! byte-compatible with Vector 35's `warp` crate: the unit tests pin GUIDs
//! produced by that reference implementation. The default `container` feature
//! adds reading `.warp` files ([`read_warp`]), pulling in only `flate2`.
//!
//! What lives *here* is portable and verifiable. What does **not** yet live here
//! is the disassembly→`normalized_bytes` step (which relocatable-instruction
//! bytes to zero, which NOPs to drop) — that must match another tool's WARP
//! plugin byte-for-byte to interoperate, and validating it needs a another tool
//! reference. Until then this crate supplies the identity math; the normalizer
//! that feeds it is a separate, reference-validated step.
//!
//! ```
//! use n0xis_warp::{basic_block_guid, function_guid, format_guid};
//! let bb = basic_block_guid(&[0x90, 0x90]); // a two-NOP block's bytes
//! assert_eq!(format_guid(&bb), "9f28527a-16ae-5f1b-9d8b-9a036759551e");
//! let f = function_guid(&[bb]);
//! assert_eq!(f.len(), 16);
//! ```

#![forbid(unsafe_code)]

#[cfg(feature = "container")]
mod container;
#[cfg(feature = "container")]
pub use container::{read_warp, WarpFunction};

/// WARP's namespace for basic-block GUIDs (`0192a178-7a5f-7936-8653-3cbaa7d6afe7`).
pub const NAMESPACE_BASIC_BLOCK: [u8; 16] =
    [0x01, 0x92, 0xa1, 0x78, 0x7a, 0x5f, 0x79, 0x36, 0x86, 0x53, 0x3c, 0xba, 0xa7, 0xd6, 0xaf, 0xe7];

/// WARP's namespace for function GUIDs (`0192a179-61ac-7cef-88ed-012296e9492f`).
pub const NAMESPACE_FUNCTION: [u8; 16] =
    [0x01, 0x92, 0xa1, 0x79, 0x61, 0xac, 0x7c, 0xef, 0x88, 0xed, 0x01, 0x22, 0x96, 0xe9, 0x49, 0x2f];

/// The GUID of a basic block from its **normalized** bytes (relocatable
/// instructions zeroed, NOPs dropped — done by the caller). `UUIDv5` under
/// [`NAMESPACE_BASIC_BLOCK`].
pub fn basic_block_guid(normalized_bytes: &[u8]) -> [u8; 16] {
    uuid_v5(&NAMESPACE_BASIC_BLOCK, normalized_bytes)
}

/// The GUID of a function from its basic-block GUIDs, **in address order**
/// (WARP sorts highest→lowest start address). The 16-byte block GUIDs are
/// concatenated and hashed as `UUIDv5` under [`NAMESPACE_FUNCTION`]; order is
/// significant, so the caller must present the blocks already sorted.
pub fn function_guid(block_guids: &[[u8; 16]]) -> [u8; 16] {
    let mut buf = Vec::with_capacity(block_guids.len() * 16);
    for g in block_guids {
        buf.extend_from_slice(g);
    }
    uuid_v5(&NAMESPACE_FUNCTION, &buf)
}

/// Format a 16-byte GUID as a canonical lowercase UUID string
/// (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).
pub fn format_guid(g: &[u8; 16]) -> String {
    let h = |b: u8| -> [u8; 2] {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        [HEX[(b >> 4) as usize], HEX[(b & 0xf) as usize]]
    };
    let mut s = String::with_capacity(36);
    for (i, &b) in g.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        let d = h(b);
        s.push(d[0] as char);
        s.push(d[1] as char);
    }
    s
}

/// A version-5 (SHA-1, name-based) UUID: `SHA1(namespace ‖ name)`, truncated to
/// 16 bytes with the version and variant bits stamped per RFC 4122.
pub fn uuid_v5(namespace: &[u8; 16], name: &[u8]) -> [u8; 16] {
    let mut sha = Sha1::new();
    sha.update(namespace);
    sha.update(name);
    let digest = sha.finish();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out[6] = (out[6] & 0x0f) | 0x50; // version 5
    out[8] = (out[8] & 0x3f) | 0x80; // RFC 4122 variant
    out
}

/// A minimal, allocation-free SHA-1 (RFC 3174). Present so this crate carries no
/// dependency; SHA-1's collision weakness is irrelevant here — WARP uses it only
/// as a naming hash, never as a security primitive.
struct Sha1 {
    state: [u32; 5],
    len: u64,
    block: [u8; 64],
    fill: usize,
}

impl Sha1 {
    fn new() -> Self {
        Sha1 {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0],
            len: 0,
            block: [0; 64],
            fill: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add((data.len() as u64) * 8);
        while !data.is_empty() {
            let take = (64 - self.fill).min(data.len());
            self.block[self.fill..self.fill + take].copy_from_slice(&data[..take]);
            self.fill += take;
            data = &data[take..];
            if self.fill == 64 {
                self.process();
                self.fill = 0;
            }
        }
    }

    fn finish(mut self) -> [u8; 20] {
        let bitlen = self.len;
        self.update_byte(0x80);
        while self.fill != 56 {
            self.update_byte(0x00);
        }
        for i in (0..8).rev() {
            self.update_byte((bitlen >> (i * 8)) as u8);
        }
        debug_assert_eq!(self.fill, 0);
        let mut out = [0u8; 20];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn update_byte(&mut self, b: u8) {
        self.block[self.fill] = b;
        self.fill += 1;
        if self.fill == 64 {
            self.process();
            self.fill = 0;
        }
    }

    fn process(&mut self) {
        let mut w = [0u32; 80];
        for (i, wi) in w.iter_mut().take(16).enumerate() {
            let j = i * 4;
            *wi = u32::from_be_bytes([self.block[j], self.block[j + 1], self.block[j + 2], self.block[j + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let tmp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The canonical NIST/RFC 3174 SHA-1 test vector, so the hash itself is
    // pinned before anything is layered on it.
    #[test]
    fn sha1_matches_the_rfc_vector() {
        let mut s = Sha1::new();
        s.update(b"abc");
        let d = s.finish();
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    // RFC 4122 §Appendix B worked example: UUIDv5 of "www.example.com" in the
    // DNS namespace.
    #[test]
    fn uuid_v5_matches_the_rfc_dns_example() {
        const DNS: [u8; 16] =
            [0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8];
        let g = uuid_v5(&DNS, b"www.example.com");
        assert_eq!(format_guid(&g), "2ed6657d-e927-568b-95e1-2665a8aea6a2");
    }

    // Golden vectors produced by Vector 35's own `warp` crate (v1.0.1) — this is
    // what makes n0xis-warp interoperable rather than merely self-consistent.
    #[test]
    fn basic_block_guids_match_the_warp_reference() {
        assert_eq!(format_guid(&basic_block_guid(&[0x90, 0x90])), "9f28527a-16ae-5f1b-9d8b-9a036759551e");
        assert_eq!(format_guid(&basic_block_guid(b"crc32")), "a21f5545-fd05-5051-8782-0889463ef728");
        assert_eq!(format_guid(&basic_block_guid(&[0x48, 0x89, 0xf8, 0xc3])), "ecfe05d1-8b91-5b70-ac3f-51f0ace7ffc3");
    }

    #[test]
    fn function_guid_matches_the_warp_reference_and_is_order_sensitive() {
        let bb_nop = basic_block_guid(&[0x90, 0x90]);
        let bb_crc = basic_block_guid(b"crc32");
        assert_eq!(format_guid(&function_guid(&[bb_nop, bb_crc])), "382ab4b9-82dd-5c9d-9da8-a91cded3a679");
        // Order is significant — WARP concatenates blocks by address, so a
        // different order is a different function.
        assert_ne!(function_guid(&[bb_nop, bb_crc]), function_guid(&[bb_crc, bb_nop]));
    }
}

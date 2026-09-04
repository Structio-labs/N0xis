// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Detour/trampoline hook math (ROADMAP Phase 4b) — pure byte/offset
//! computation, no OS access. The actual allocation
//! (`LiveProcess::alloc_code_cave`) and the journaled writes
//! (`n0xis-project::patch`, so a bad hook is always undo-able through the
//! existing patch record, not a new unverified write path) live where OS
//! access and persistence already do — this module only computes bytes and
//! range-checks them, never silently producing a jump that would wrap or
//! land somewhere unintended (CONCEPT §3 rule 6).

use n0xis_contracts::Va;

/// The 5-byte `E9 rel32` near jump from `from` (the address the jump
/// instruction itself starts at) to `to`. `None` if `to` isn't reachable
/// with a 32-bit displacement — never truncates/wraps a jump that would
/// land somewhere other than `to`.
pub fn near_jmp(from: Va, to: Va) -> Option<[u8; 5]> {
    let next = from.get().wrapping_add(5);
    let delta = to.get() as i64 - next as i64;
    let rel32 = i32::try_from(delta).ok()?;
    let mut out = [0xE9u8, 0, 0, 0, 0];
    out[1..5].copy_from_slice(&rel32.to_le_bytes());
    Some(out)
}

/// Build a trampoline: the cave's content is the original `hook_len` bytes
/// (relocated, not modified — they still execute exactly as before) followed
/// by a jump back to `hook_at + hook_len`; the hook site's content is a jump
/// into the cave. Returns `(cave_bytes, hook_jmp_bytes)` — callers must write
/// `cave_bytes` to the cave *before* writing `hook_jmp_bytes` at `hook_at`,
/// so the redirect is never live before its landing pad is.
pub fn build_trampoline(original: &[u8], hook_at: Va, cave: Va) -> Result<(Vec<u8>, [u8; 5]), String> {
    if original.len() < 5 {
        return Err(format!("hook region must be at least 5 bytes (got {})", original.len()));
    }
    let hook_len = original.len() as u64;
    let jmp_back = near_jmp(cave.offset(hook_len), hook_at.offset(hook_len))
        .ok_or_else(|| format!("cave {cave} is not within jmp-rel32 range of the return address {hook_at}+{hook_len:#x}"))?;
    let mut cave_bytes = original.to_vec();
    cave_bytes.extend_from_slice(&jmp_back);

    let hook_jmp = near_jmp(hook_at, cave)
        .ok_or_else(|| format!("cave {cave} is not within jmp-rel32 range of the hook site {hook_at}"))?;
    Ok((cave_bytes, hook_jmp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn near_jmp_encodes_a_forward_displacement() {
        // jmp from 0x1000 (next ip 0x1005) to 0x2000 -> rel32 = 0x2000-0x1005 = 0xFFB
        let bytes = near_jmp(Va(0x1000), Va(0x2000)).unwrap();
        assert_eq!(bytes[0], 0xE9);
        assert_eq!(i32::from_le_bytes(bytes[1..5].try_into().unwrap()), 0x2000 - 0x1005);
    }

    #[test]
    fn near_jmp_refuses_an_out_of_range_target() {
        assert!(near_jmp(Va(0x1000), Va(0x1_0000_1000)).is_none());
    }

    #[test]
    fn build_trampoline_relocates_bytes_and_jumps_back() {
        let original = vec![0x90u8, 0x90, 0x90, 0x90, 0x90]; // 5 nops
        let hook_at = Va(0x1000);
        let cave = Va(0x2000);
        let (cave_bytes, hook_jmp) = build_trampoline(&original, hook_at, cave).unwrap();
        assert_eq!(&cave_bytes[..5], &original[..]);
        assert_eq!(cave_bytes.len(), 10); // 5 relocated bytes + 5-byte jmp back
        assert_eq!(cave_bytes[5], 0xE9);
        assert_eq!(hook_jmp[0], 0xE9);
        // The hook jmp must decode to exactly `cave`.
        let rel = i32::from_le_bytes(hook_jmp[1..5].try_into().unwrap());
        assert_eq!((hook_at.get() as i64 + 5 + rel as i64) as u64, cave.get());
    }

    #[test]
    fn build_trampoline_rejects_a_too_short_hook_region() {
        assert!(build_trampoline(&[0x90, 0x90], Va(0x1000), Va(0x2000)).is_err());
    }
}

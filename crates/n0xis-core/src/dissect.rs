// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Struct dissection (ROADMAP Phase 4b) — walk a live region and guess each
//! field's type from its *runtime value's shape* (does it look like a
//! pointer into mapped memory? a plausible float? just an integer?). This is
//! the dynamic, value-scanning counterpart to `typeinfer.rs`'s *static*
//! struct/field recovery, which infers field *offsets* from decompiled
//! pointer arithmetic rather than inspecting live values — the two are meant
//! to fuse once Phase 4c's provenance graph links a live struct back to the
//! code that shaped it.
//!
//! Inherently heuristic — there is no debug info to fall back on — so every
//! guess carries a `confidence` instead of a bare assertion (CONCEPT §3
//! rule 6: sound over silently overconfident).

use n0xis_contracts::Va;
use serde::Serialize;

use crate::{Ctx, CoreError, Pass};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuessedKind {
    Pointer,
    Float,
    Double,
    Integer,
    /// All-zero bytes — could be padding, a null pointer, or `0`; reported
    /// distinctly rather than guessed into any one of those.
    ZeroPadding,
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
pub struct DissectField {
    pub offset: u64,
    pub kind: GuessedKind,
    pub size: usize,
    pub raw_hex: String,
    /// `0.0..=1.0` — how much to trust this particular guess. A pointer-sized
    /// slot whose value resolves inside mapped memory is high-confidence; a
    /// value that merely *could* be a plausible float is low.
    pub confidence: f32,
}

pub struct DissectInput {
    pub start: Va,
    pub size: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct DissectArtifact {
    pub fields: Vec<DissectField>,
    /// Bytes asked for.
    pub requested: usize,
    /// Bytes actually dissected.
    ///
    /// A source read is contractually "up to `len` bytes" — it truncates at a
    /// mapping's end, and `process_vm_readv` may transfer less than asked for
    /// with no error at all. Without these two numbers a struct that ran off
    /// the end of its region is indistinguishable from a complete one: the
    /// field list simply stops, and the caller has no way to tell a short
    /// answer from a whole one. A live-memory sweep caught exactly that — a
    /// pointer field at +24 that vanished from an otherwise identical result.
    pub read: usize,
    /// `true` when fewer bytes came back than were asked for.
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DissectPass;

impl Pass for DissectPass {
    type In = DissectInput;
    type Out = DissectArtifact;

    fn name(&self) -> &'static str {
        "scan.dissect"
    }

    fn run(&self, ctx: &Ctx, input: DissectInput) -> Result<DissectArtifact, CoreError> {
        let bytes = ctx.source.read(input.start, input.size)?;
        let read = bytes.len();
        let mut fields = Vec::new();
        let mut off = 0usize;
        while off < bytes.len() {
            let chunk = &bytes[off..bytes.len().min(off + 8)];
            let (kind, size, confidence) = classify(ctx, chunk, input.start.get().wrapping_add(off as u64));
            fields.push(DissectField {
                offset: off as u64,
                kind,
                size,
                raw_hex: chunk[..size.min(chunk.len())].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
                confidence,
            });
            off += size.max(1);
        }
        Ok(DissectArtifact { fields, requested: input.size, read, truncated: read < input.size })
    }
}

/// Bytes from `addr` to the next `n`-byte boundary — `n` when `addr` is
/// already aligned, so it doubles as "how much of a field of this width may
/// start here".
fn to_boundary(addr: u64, n: u64) -> usize {
    (n - (addr % n)) as usize
}

/// Classify one slot starting at `chunk` (up to 8 bytes available), widest
/// interpretation first: an 8-byte pointer, an 8-byte double, then falling
/// back to 4-byte views. Returns `(kind, bytes consumed, confidence)`.
///
/// **Alignment gates the width, and that is not a heuristic.** The x86-64 ABI
/// aligns an N-byte scalar to N bytes, so an 8-byte reading of an address that
/// is not 8-aligned describes a field the compiler could not have placed there.
/// Without the gate a struct is read out of phase from the first mistake on:
/// measured against a live target whose layout was known from its own source,
/// a 4-byte `int` followed by a 4-byte `float` was read as one `double`
/// spanning both, and every field after it came out shifted by four bytes —
/// one of six fields right. With it, five of six.
///
/// A run of zeros stops at the next 8-byte boundary for the same reason: it is
/// padding *up to* where the next field can begin, and swallowing the boundary
/// puts everything after it out of phase again.
fn classify(ctx: &Ctx, chunk: &[u8], addr: u64) -> (GuessedKind, usize, f32) {
    let fits8 = to_boundary(addr, 8);
    let fits4 = to_boundary(addr, 4);
    if chunk.iter().all(|&b| b == 0) {
        return (GuessedKind::ZeroPadding, chunk.len().min(fits8), 0.5);
    }
    if chunk.len() >= 8 && fits8 == 8 {
        let v = u64::from_le_bytes(chunk[..8].try_into().expect("len checked"));
        if v != 0 && ctx.source.contains(Va(v)) {
            return (GuessedKind::Pointer, 8, 0.9);
        }
        let f = f64::from_le_bytes(chunk[..8].try_into().expect("len checked"));
        if plausible_float(f) {
            return (GuessedKind::Double, 8, 0.5);
        }
    }
    if chunk.len() >= 4 && fits4 == 4 {
        let v32 = u32::from_le_bytes(chunk[..4].try_into().expect("len checked"));
        if v32 != 0 && ctx.source.contains(Va(v32 as u64)) {
            // A 32-bit value landing in mapped memory is a weaker signal
            // than the 64-bit case above (more room for coincidence).
            return (GuessedKind::Pointer, 4, 0.6);
        }
        let f32v = f32::from_le_bytes(chunk[..4].try_into().expect("len checked"));
        if plausible_float(f32v as f64) {
            return (GuessedKind::Float, 4, 0.4);
        }
        return (GuessedKind::Integer, 4, 0.3);
    }
    // Nothing of a modelled width can start here. Say so, and consume only up
    // to the next boundary a field could begin on rather than guessing.
    (GuessedKind::Unknown, chunk.len().min(fits4), 0.1)
}

fn plausible_float(f: f64) -> bool {
    f.is_finite() && f != 0.0 && f.abs() > 1e-10 && f.abs() < 1e10
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    #[test]
    fn classifies_a_pointer_a_float_and_a_small_int() {
        let mut region = vec![0u8; 24];
        // +0x0: pointer into the second mapped region.
        region[0..8].copy_from_slice(&0x9000u64.to_le_bytes());
        // +0x8: a plausible float (3.5).
        region[8..16].copy_from_slice(&3.5f64.to_le_bytes());
        // +0x10: a small integer that doesn't resolve to mapped memory.
        region[16..24].copy_from_slice(&42u64.to_le_bytes());

        let snap = Snapshot::builder().region(Va(0x1000), region).region(Va(0x9000), vec![0u8; 8]).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);

        let art = DissectPass.run(&ctx, DissectInput { start: Va(0x1000), size: 24 }).unwrap();
        assert_eq!(art.fields[0].kind, GuessedKind::Pointer);
        assert_eq!(art.fields[0].offset, 0);
        assert_eq!(art.fields[1].kind, GuessedKind::Double);
        assert_eq!(art.fields[1].offset, 8);
        assert_eq!(art.fields[2].kind, GuessedKind::Integer);
        assert_eq!(art.fields[2].offset, 16);
    }

    /// A read that stops at the end of a mapping must be visible in the answer.
    ///
    /// The source contract is "up to `len` bytes", so a struct near a region
    /// boundary — or any live read `process_vm_readv` transfers only part of —
    /// comes back short. Before this, the field list simply ended and nothing
    /// distinguished it from a complete dissection: a pointer field at +24
    /// vanished from an otherwise identical result during a live sweep, and the
    /// output gave no way to know why.
    #[test]
    fn a_short_read_says_so_instead_of_ending_quietly() {
        // 20 bytes mapped, 64 asked for.
        let snap = Snapshot::builder().region(Va(0x3000), vec![7u8; 20]).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = DissectPass.run(&ctx, DissectInput { start: Va(0x3000), size: 64 }).unwrap();
        assert_eq!(art.requested, 64);
        assert_eq!(art.read, 20, "the region holds 20 bytes, so 20 is what can be dissected");
        assert!(art.truncated, "a short read must announce itself");
        assert!(art.fields.iter().all(|f| f.offset < 20));

        // And a whole read must not cry wolf.
        let art = DissectPass.run(&ctx, DissectInput { start: Va(0x3000), size: 20 }).unwrap();
        assert_eq!((art.requested, art.read), (20, 20));
        assert!(!art.truncated);
    }

    /// The layout a compiler could actually have emitted.
    ///
    /// `{ int, int, float, int pad, double }` — an `int` at +4 followed by a
    /// `float` at +8 reads, if width is chosen before alignment, as one
    /// `double` covering both, and every field after it comes out four bytes
    /// out of phase. Measured against a live target whose layout was known from
    /// its own source, that was one field of six right.
    #[test]
    fn an_eight_byte_field_cannot_begin_on_a_four_byte_boundary() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&12345i32.to_le_bytes()); // +0  int
        bytes.extend_from_slice(&678i32.to_le_bytes()); //   +4  int
        bytes.extend_from_slice(&3.5f32.to_le_bytes()); //   +8  float
        bytes.extend_from_slice(&0i32.to_le_bytes()); //     +12 padding
        bytes.extend_from_slice(&42.25f64.to_le_bytes()); // +16 double
        let snap = Snapshot::builder().region(Va(0x1000), bytes).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = DissectPass.run(&ctx, DissectInput { start: Va(0x1000), size: 24 }).unwrap();
        let got: Vec<(u64, GuessedKind, usize)> = art.fields.iter().map(|f| (f.offset, f.kind, f.size)).collect();
        assert_eq!(
            got,
            vec![
                (0, GuessedKind::Integer, 4),
                (4, GuessedKind::Integer, 4),
                (8, GuessedKind::Float, 4),
                (12, GuessedKind::ZeroPadding, 4),
                (16, GuessedKind::Double, 8),
            ]
        );
    }

    #[test]
    fn an_all_zero_slot_is_reported_as_padding_not_guessed() {
        let snap = Snapshot::builder().region(Va(0x2000), vec![0u8; 8]).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = DissectPass.run(&ctx, DissectInput { start: Va(0x2000), size: 8 }).unwrap();
        assert_eq!(art.fields[0].kind, GuessedKind::ZeroPadding);
    }
}

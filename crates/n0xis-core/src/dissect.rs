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
        let mut fields = Vec::new();
        let mut off = 0usize;
        while off < bytes.len() {
            let chunk = &bytes[off..bytes.len().min(off + 8)];
            let (kind, size, confidence) = classify(ctx, chunk);
            fields.push(DissectField {
                offset: off as u64,
                kind,
                size,
                raw_hex: chunk[..size.min(chunk.len())].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
                confidence,
            });
            off += size.max(1);
        }
        Ok(DissectArtifact { fields })
    }
}

/// Classify one slot starting at `chunk` (up to 8 bytes available), widest
/// interpretation first: an 8-byte pointer, an 8-byte double, then falling
/// back to 4-byte views. Returns `(kind, bytes consumed, confidence)`.
fn classify(ctx: &Ctx, chunk: &[u8]) -> (GuessedKind, usize, f32) {
    if chunk.iter().all(|&b| b == 0) {
        return (GuessedKind::ZeroPadding, chunk.len().min(8), 0.5);
    }
    if chunk.len() >= 8 {
        let v = u64::from_le_bytes(chunk[..8].try_into().expect("len checked"));
        if v != 0 && ctx.source.contains(Va(v)) {
            return (GuessedKind::Pointer, 8, 0.9);
        }
        let f = f64::from_le_bytes(chunk[..8].try_into().expect("len checked"));
        if plausible_float(f) {
            return (GuessedKind::Double, 8, 0.5);
        }
    }
    if chunk.len() >= 4 {
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
    (GuessedKind::Unknown, chunk.len(), 0.1)
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

    #[test]
    fn an_all_zero_slot_is_reported_as_padding_not_guessed() {
        let snap = Snapshot::builder().region(Va(0x2000), vec![0u8; 8]).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = DissectPass.run(&ctx, DissectInput { start: Va(0x2000), size: 8 }).unwrap();
        assert_eq!(art.fields[0].kind, GuessedKind::ZeroPadding);
    }
}

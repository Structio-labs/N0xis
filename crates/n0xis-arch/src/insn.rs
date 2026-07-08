//! Decoded-instruction data — the output of [`Arch::decode`](crate::Arch).

use n0xis_contracts::Va;
use serde::{Serialize, Serializer};

/// Control-flow classification of a decoded instruction. Enough for CFG
/// construction without re-deriving flow from the mnemonic in every pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InsnKind {
    /// Falls through to the next instruction.
    Seq,
    /// `call` (direct or indirect).
    Call,
    /// Unconditional branch (`jmp`).
    Jump,
    /// Conditional branch (`jcc`, `loop`, etc.).
    CondJump,
    /// `ret` / `retf`.
    Ret,
    /// `int` / `int3` / syscall-like interrupt.
    Int,
    /// Decoder produced no valid instruction here.
    Invalid,
    /// Anything else (privileged, fpu, etc.) that still falls through.
    Other,
}

/// One decoded instruction. Addresses render as hex strings (via [`Va`]); raw
/// bytes render as a spaced hex string (`"48 89 c8"`) for agent/human parity.
#[derive(Clone, Debug, Serialize)]
pub struct DecodedInsn {
    pub va: Va,
    pub len: u8,
    #[serde(serialize_with = "ser_hex_bytes")]
    pub bytes: Vec<u8>,
    /// Lowercased mnemonic, e.g. `"mov"`.
    pub mnemonic: String,
    /// Fully formatted instruction text, e.g. `"mov rax, rcx"`.
    pub text: String,
    pub kind: InsnKind,
    /// Resolved branch/call target when it is a direct near operand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<Va>,
    /// Absolute address of a RIP-relative memory operand, when present
    /// (`lea reg,[rip+d]`, `mov reg,[rip+d]`, `call [rip+d]` IAT slots, …).
    /// The seam that powers data xrefs and IAT resolution without a decoder
    /// leaking into the passes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rip_target: Option<Va>,
}

fn ser_hex_bytes<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    let hex = bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    s.serialize_str(&hex)
}

/// Failure decoding a single instruction.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid instruction at {0}")]
    Invalid(Va),
    #[error("not enough bytes to decode at {0}")]
    Truncated(Va),
}

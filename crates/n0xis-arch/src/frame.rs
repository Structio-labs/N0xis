// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Stack-frame prolog recognition — the ISA-specific shape of how a function
//! sets up its frame. Purely structural (reads only the decoded instruction
//! stream, never memory), so it lives here next to [`Arch::detect_switch`]
//! rather than in a pass: no ISA knowledge about which mnemonics mean "spill a
//! register" or "reserve stack space" should leak into `n0xis-core`.

use n0xis_contracts::Va;
use serde::{Deserialize, Serialize};

/// What the function's prolog reveals about its stack frame.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FrameInfo {
    /// Bytes reserved by a `sub rsp, imm` in the prolog (0 if none found).
    pub frame_size: u64,
    /// Whether the prolog establishes a frame pointer (`mov rbp, rsp`).
    pub uses_rbp: bool,
    /// Registers spilled to the stack in the prolog (`push reg`), in order.
    pub spilled_regs: Vec<String>,
    /// Addresses of the instructions recognized as part of the prolog.
    pub prolog: Vec<Va>,
}

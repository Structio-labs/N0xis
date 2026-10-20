// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! What a memory argument is, from an instruction's name alone: which
//! instructions take one, and the alignment that is natural for each. Both
//! `tests/references.rs` (wabt and wasm-tools leave a natural alignment out)
//! and `tests/v8.rs` (V8 does too) fill in the alignment a tool did not
//! write, so the rule is stated once, here: two copies of it had already
//! drifted apart, one stating the wait instructions' widths and one leaving
//! them to the digits of the name. These are the tests' own statement of the
//! specification, not the reader's (`src/` is not consulted).

/// Whether the instruction takes a memory argument: a load, a store, an atomic
/// read-modify-write, a wait or a notify. `atomic.fence` takes none.
pub fn is_memory_access(name: &str) -> bool {
    name.contains(".load") || name.contains(".store") || name.contains(".atomic.")
}

/// The natural alignment of a memory access, in bytes, from its name: the
/// width the name states (`i64.load16_u`: 2, `i32.atomic.rmw8.add_u`: 1,
/// `i64.atomic.rmw32.cmpxchg_u`: 4), else the width of its type (`f64.store`:
/// 8, `v128.load`: 16); a `v128.loadNxM_s/u` reads 64 bits (8).
///
/// For an atomic instruction this is the only alignment there is: the threads
/// proposal's overview (WebAssembly/threads, proposals/threads/Overview.md,
/// "Alignment") says "It is a validation error if the alignment field of the
/// memory access immediate has any other value than the natural alignment for
/// that access size", and ("Wait and Notify operators") "The wait operators
/// require an alignment of their memory access size. The notify operator
/// requires an alignment of 32 bits." So the three whose type prefix is
/// `memory` are stated outright: `memory.atomic.notify` 4,
/// `memory.atomic.wait32` 4, `memory.atomic.wait64` 8.
///
/// Known and not fixed: the width is read from the first run of digits of
/// the name, so an instruction added later whose name holds a number that is
/// not its access width would be given a wrong alignment here; both users
/// would then disagree with their tool on its every line, not agree wrongly.
pub fn natural_align(name: &str) -> u64 {
    match name {
        "memory.atomic.notify" => return 4,
        "memory.atomic.wait32" => return 4,
        "memory.atomic.wait64" => return 8,
        _ => {}
    }
    let (ty, op) = name.split_once('.').expect("a typed memory instruction");
    if ty == "v128" && op.contains('x') {
        return 8; // v128.loadNxM_s/u reads 64 bits
    }
    let digits: String = op.chars().skip_while(|c| !c.is_ascii_digit()).take_while(|c| c.is_ascii_digit()).collect();
    let bits: u64 = if digits.is_empty() { ty[1..].parse().expect("a width") } else { digits.parse().unwrap() };
    bits / 8
}

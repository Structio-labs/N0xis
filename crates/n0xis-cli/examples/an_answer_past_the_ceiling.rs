// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The CLI's own `emit`, given an answer that reaches the memory ceiling while it is
//! being written, for `tests/a_refusal_never_follows_part_of_an_answer.rs`.
//!
//! A real answer allocates next to nothing as it is written, so no stated ceiling lands
//! there reliably: the run's peak is behind it, and a ceiling that would be crossed by
//! the writing has already been crossed by the computing. So what is planted is the
//! answer, and everything else is the real thing: this file's `emit`, the real allocator
//! and the refusal the CLI gives.

#[allow(dead_code)]
#[path = "../src/emit.rs"]
mod emit;

use n0xis_contracts::Response;
use serde::ser::{Error, SerializeSeq};
use serde::{Serialize, Serializer};

#[global_allocator]
static ALLOCATOR: n0xis_core::CeilingAlloc = n0xis_core::CeilingAlloc;

/// Enough rows that the buffer has been written out several times before the last.
const ROWS: usize = 8192;
const ROW: &str = "a row of the answer, which is about sixty-four bytes long......";
/// Past the ceiling in `main`.
const TOO_MUCH: usize = 64 << 20;

#[derive(Clone, Copy, PartialEq)]
enum Last {
    TakesMemory,
    Fails,
}

struct Rows {
    last: Last,
    count: usize,
}

impl Serialize for Rows {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.count))?;
        for at in 0..self.count {
            if at + 1 == self.count {
                match self.last {
                    Last::TakesMemory => std::hint::black_box(&mut Vec::<u8>::with_capacity(TOO_MUCH)).push(1),
                    Last::Fails => return Err(S::Error::custom("a planted failure")),
                }
            }
            seq.serialize_element(ROW)?;
        }
        seq.end()
    }
}

fn refuse(ceiling: u64) {
    let refusal = Response::<serde_json::Value>::error("out-of-memory", format!("past {} MiB", ceiling >> 20));
    emit::write_refusal_past_the_ceiling(&refusal, false);
    std::process::exit(2);
}

fn main() {
    let mode = std::env::args().nth(1).expect("a mode");
    let pretty = std::env::args().any(|a| a == "--pretty");
    n0xis_core::set_memory_ceiling(Some(16 << 20), refuse);
    let (last, count) = match mode.as_str() {
        "takes-memory" | "two-answers" => (Last::TakesMemory, ROWS),
        "fails-early" => (Last::Fails, 1),
        "fails-late" => (Last::Fails, ROWS),
        other => panic!("{other}"),
    };
    let ok = emit::emit(&Response::success("n0xis.planted.v1", Rows { last, count }), pretty);
    if mode == "two-answers" {
        // The ceiling is back for what comes after, as a `serve` session's next line.
        std::hint::black_box(&mut Vec::<u8>::with_capacity(TOO_MUCH)).push(1);
        panic!("the ceiling was not back");
    }
    std::process::exit(if ok { 0 } else { 2 });
}

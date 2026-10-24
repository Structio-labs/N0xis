// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Every instruction the section-wide passes see in one file: what one
//! [`Arch::decode_range`](n0xis_arch::Arch::decode_range) over each code range
//! returns, one line per instruction, so the listing can be held against an
//! independent disassembler's.
//!
//! Usage: `sweep_listing <file> [<arch>]` — run it in a directory that has its
//! own `.n0x/`. The file is loaded the way every command loads it
//! ([`n0xis_frontend::source::resolve`]), the instruction set is the one a
//! command would pick ([`Src::pick_arch`](n0xis_frontend::Src::pick_arch)), and
//! the ranges are [`Src::code_ranges`](n0xis_frontend::Src::code_ranges), the
//! ones `xref to` and the reverse-xref index sweep.
//!
//! Output, to stdout: per range a line `# range <va> <size>`, then per
//! instruction `<va>\t<len>\t<text>`, addresses in hex.
//!
//! Written to measure the resynchronization fix of 2026-10-24 (an AArch64
//! sweep stepped one byte past an undefined word and read made-up
//! instructions until three more decodes failed), where the listing was
//! joined with `llvm-objdump -d` by address. On its own
//! this is n0xis's answer, not evidence: the join is the measurement.

use std::io::Write;

use n0xis_contracts::Va;
use n0xis_frontend::SourceSpec;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(path) = args.first() else {
        eprintln!("usage: sweep_listing <file> [<arch>]");
        std::process::exit(2);
    };
    let resolved = n0xis_frontend::source::resolve(SourceSpec { file: Some(path), ..Default::default() }).unwrap_or_else(|(code, msg)| {
        eprintln!("{code}: {msg}");
        std::process::exit(1)
    });
    let src = resolved.src;
    let arch = src.pick_arch(args.get(1).map(String::as_str)).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1)
    });
    let mem = src.as_mem();
    let out = std::io::stdout();
    let mut out = std::io::BufWriter::new(out.lock());
    for (va, size) in src.code_ranges() {
        writeln!(out, "# range 0x{:x} 0x{size:x}", va.0).unwrap();
        let bytes = mem.read(va, usize::try_from(size).unwrap_or(usize::MAX)).unwrap_or_default();
        for i in arch.decode_range(&bytes, Va(va.0), bytes.len()) {
            writeln!(out, "0x{:x}\t{}\t{}", i.va.0, i.len, i.text).unwrap();
        }
    }
}

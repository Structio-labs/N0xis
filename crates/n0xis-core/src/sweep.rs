// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`sweep_code`] — the one linear sweep over a code range, held to a bounded
//! window.
//!
//! Every section-wide pass walks a code range instruction by instruction: the
//! reverse-xref index, `xref to` over a window, `xref string`, `bindings list`,
//! `il2cpp icalls`. Each used to call [`Arch::decode_range`](n0xis_arch::Arch::decode_range) over its whole
//! range and keep the result, so every [`DecodedInsn`] of the range was alive
//! at once, three heap allocations each. Measured 2026-10-23 (getrusage
//! `maxrss`, release build of `2313b89`): about 104 MiB of RSS per MiB of code,
//! 1.73 GB for `bindings list` on 16.7 MiB of code, and a 32 MiB `.text` past
//! 3 GB. None of those passes needed the instructions together: each keeps a
//! few facts per instruction it answers with. So the range is read and decoded
//! [`SWEEP_CHUNK`] bytes at a time, and each instruction is handed to a visitor
//! and dropped with its window.
//!
//! ## Why no answer can depend on the window
//!
//! The visitor is handed exactly the instructions one `decode_range` over the
//! whole range returns, in the same order. The window is invisible by
//! construction, for these reasons:
//!
//! - **A window resumes at the start of the last instruction the previous one
//!   handed out**, which it decodes again and does not hand out again. It does
//!   not resume after it. `decode_range` resynchronizes past an undecodable
//!   instruction one byte on when it ends a run of good ones, but two bytes on
//!   when a run *begins* with it (`at += kept_bytes.max(1)`, then `at += 1`),
//!   so a window that began exactly at an undecodable byte would take a step the
//!   whole-range decode never takes, and every instruction after it could
//!   differ. A window that begins at an instruction which decodes is in the
//!   state the whole-range decode was in when it reached it. (The reverse-xref
//!   index resumed after the last kept instruction until this module existed.)
//! - **[`SWEEP_OVERLAP`] bytes past the window are read**, so an instruction
//!   that starts inside the window is decoded whole: x86 tops out at 15 bytes,
//!   the ARM encodings at 4. An instruction longer than that (a WebAssembly
//!   `br_table`) is not lost: no decoder emits an instruction its bytes end
//!   inside, and the next window starts before it.
//! - **A window that hands out nothing new is widened from the same start**
//!   (doubled), never skipped past: skipping to its end would resume at a byte
//!   the whole-range decode may never have tried.
//! - **Every read starts inside the region the first one reached**: at the
//!   range's start, or at an instruction already handed out. A source reads
//!   *up to* the length asked, cut where the region holding the address ends
//!   ([`MemorySource::read`](n0xis_sources::MemorySource::read)), so the one
//!   read the passes used to make never saw past that region, and no window
//!   does either. A short read therefore ends the sweep at once (the rule
//!   saves the widening that would otherwise reach the same answer; it
//!   changes none, and no test can tell it is there). The first read is made
//!   even for an empty range, so an unmapped start is the same error it was.
//!
//! One field is not window-stable: [`DecodedInsn::cond`] on Thumb, where the
//! decoder carries `IT`-block state from one instruction to the next and a
//! window begins with none, as `decode_range` already does after each
//! resynchronization. No visitor reads it.

use std::ops::ControlFlow;

use n0xis_arch::DecodedInsn;
use n0xis_contracts::Va;

use crate::{CoreError, Ctx};

/// Bytes of code decoded per window (1 MiB). What one window's instructions
/// cost is the sweep's whole cost, at about 100 MiB of RSS per MiB of code,
/// so this bounds every sweeping pass near 100 MB above the image itself.
pub const SWEEP_CHUNK: u64 = 1024 * 1024;

/// Bytes read past a window's end, so the instruction straddling it is decoded
/// whole (x86 instructions are at most 15 bytes).
pub const SWEEP_OVERLAP: u64 = 16;

/// Hand every instruction of the code range `[start, start + size)` to `visit`,
/// in address order, exactly as one [`Arch::decode_range`](n0xis_arch::Arch::decode_range)
/// over the whole range would return them, while holding at most `chunk`
/// bytes' worth of decoded instructions at a time ([`SWEEP_CHUNK`]; a test
/// passes others to show the answer does not depend on it).
///
/// `visit` answers [`ControlFlow::Break`] to stop the sweep early (a pass that
/// has its `limit`). `Err` only when a read fails: the first one, for a range
/// whose start is not mapped, or a later one on a source that changed under
/// the sweep.
pub(crate) fn sweep_code(
    ctx: &Ctx,
    start: Va,
    size: u64,
    chunk: u64,
    mut visit: impl FnMut(&DecodedInsn) -> ControlFlow<()>,
) -> Result<(), CoreError> {
    let chunk = chunk.max(1);
    let mut end = start.0.saturating_add(size);
    // Where the next window decodes from: the range's start, then the start of
    // the last instruction handed out (see the module comment).
    let mut from = start.0;
    // The address of the last instruction handed out; it and everything before
    // it are not handed out again.
    let mut handed: Option<u64> = None;
    let mut span = chunk;
    loop {
        let mut keep_to = from.saturating_add(span).min(end);
        let want = keep_to.saturating_add(SWEEP_OVERLAP).min(end) - from;
        let bytes = ctx.source.read(Va(from), usize::try_from(want).unwrap_or(usize::MAX))?;
        let got = bytes.len() as u64;
        if got < want {
            // The region ends here, and so does the range.
            end = from + got;
            keep_to = keep_to.min(end);
        }
        let insns = ctx.arch.decode_range(&bytes, Va(from), bytes.len());
        let mut newest = None;
        for ins in &insns {
            if ins.va.0 >= keep_to {
                break;
            }
            if handed.is_some_and(|h| ins.va.0 <= h) {
                continue;
            }
            if visit(ins).is_break() {
                return Ok(());
            }
            newest = Some(ins.va.0);
        }
        if keep_to >= end {
            return Ok(());
        }
        match newest {
            Some(va) => {
                handed = Some(va);
                from = va;
                span = chunk;
            }
            None => span = span.saturating_mul(2),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::{Arch, Arm32, Arm64, X64};
    use n0xis_sources::Snapshot;

    /// xorshift64*: bytes with every kind of instruction in them, undecodable
    /// ones included, the same on every run.
    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut s = seed | 1;
        (0..len)
            .map(|_| {
                s ^= s >> 12;
                s ^= s << 25;
                s ^= s >> 27;
                (s.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8
            })
            .collect()
    }

    /// Every field the passes read, and every other but `cond` (see the module
    /// comment), as one line per instruction.
    fn line(i: &DecodedInsn, with_cond: bool) -> String {
        let mut v = serde_json::to_value(i).unwrap();
        if !with_cond {
            v.as_object_mut().unwrap().remove("cond");
        }
        v.to_string()
    }

    fn swept(ctx: &Ctx, start: Va, size: u64, chunk: u64, with_cond: bool) -> Vec<String> {
        let mut out = Vec::new();
        sweep_code(ctx, start, size, chunk, |i| {
            out.push(line(i, with_cond));
            ControlFlow::Continue(())
        })
        .unwrap();
        out
    }

    /// The sweep hands out what one `decode_range` over the whole range
    /// returns, on every window size from one byte up, on each instruction
    /// set: the property every pass's answer rests on.
    #[test]
    fn the_sweep_is_one_whole_range_decode_at_every_window_size() {
        let arches: [(&str, Box<dyn Arch>, bool); 5] = [
            ("x86-64", Box::new(X64::new()), true),
            ("x86", Box::new(X64::x86()), true),
            ("arm64", Box::new(Arm64::new()), true),
            ("a32", Box::new(Arm32::a32()), true),
            ("thumb", Box::new(Arm32::thumb()), false),
        ];
        let base = 0x40_0000u64;
        for seed in 1..=3u64 {
            let bytes = noise(3000, seed);
            let snap = Snapshot::builder().region(Va(base), bytes.clone()).build();
            for (name, arch, with_cond) in &arches {
                let ctx = Ctx::new(&snap, arch.as_ref());
                let whole: Vec<String> = arch.decode_range(&bytes, Va(base), bytes.len()).iter().map(|i| line(i, *with_cond)).collect();
                assert!(whole.len() > 100, "{name}: the noise decodes to something");
                for chunk in (1..=70).chain([97, 1000, 4096, SWEEP_CHUNK]) {
                    let got = swept(&ctx, Va(base), bytes.len() as u64, chunk, *with_cond);
                    assert_eq!(got, whole, "{name}, seed {seed}: a {chunk}-byte window changed the sweep");
                }
            }
        }
    }

    /// A module whose `br_table` is 45 bytes, longer than [`SWEEP_OVERLAP`]
    /// and than most windows below: `wat2wasm` (wabt 1.0.42) of
    ///
    /// ```text
    /// (module
    ///   (func (export "f") (param i32) (result i32) (local i64 i64 i32)
    ///     block block block local.get 0
    ///       br_table 0 1 2 (13 more times 0 1 2) 0
    ///     end i32.const 1 return end i32.const 2 return end i32.const 3)
    ///   (func (export "g") (result i32) i32.const 5 call 0))
    /// ```
    ///
    /// `wasm-objdump -d` puts the `br_table` at 0x35 and the next instruction
    /// at 0x62.
    const LONG_BR_TABLE: [u8; 117] = [
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x02, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x60, 0x00, 0x01, 0x7f, 0x03, 0x03, 0x02, 0x00,
        0x01, 0x07, 0x09, 0x02, 0x01, 0x66, 0x00, 0x00, 0x01, 0x67, 0x00, 0x01, 0x0a, 0x4f, 0x02, 0x46, 0x02, 0x02, 0x7e, 0x01, 0x7f, 0x02, 0x40, 0x02,
        0x40, 0x02, 0x40, 0x20, 0x00, 0x0e, 0x2a, 0x00, 0x01, 0x02, 0x00, 0x01, 0x02, 0x00, 0x01, 0x02, 0x00, 0x01, 0x02, 0x00, 0x01, 0x02, 0x00, 0x01,
        0x02, 0x00, 0x01, 0x02, 0x00, 0x01, 0x02, 0x00, 0x01, 0x02, 0x00, 0x01, 0x02, 0x00, 0x01, 0x02, 0x00, 0x01, 0x02, 0x00, 0x01, 0x02, 0x00, 0x01,
        0x02, 0x00, 0x0b, 0x41, 0x01, 0x0f, 0x0b, 0x41, 0x02, 0x0f, 0x0b, 0x41, 0x03, 0x0b, 0x06, 0x00, 0x41, 0x05, 0x10, 0x00, 0x0b,
    ];

    /// The same on WebAssembly, whose decoder is exact rather than
    /// resynchronizing and whose instructions can outrun the overlap (a
    /// `br_table`, a locals declaration): the committed modules and the one
    /// above, every window size from one byte.
    #[test]
    fn a_module_sweeps_as_one_whole_range_decode_at_every_window_size() {
        use n0xis_sources::{FormatTables, MemorySource, Opened, OpenOptions};
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../n0xis-cli/tests/fixtures/wasm/");
        let mut modules: Vec<(String, Vec<u8>)> = ["names-cpp.wasm", "indexed.wasm", "wide-even.wasm", "wide-odd.wasm"]
            .iter()
            .map(|name| (name.to_string(), std::fs::read(format!("{dir}{name}")).unwrap()))
            .collect();
        modules.push(("a 45-byte br_table".into(), LONG_BR_TABLE.to_vec()));
        for (name, bytes) in modules {
            let format = n0xis_sources::recognize(&bytes).expect("a module");
            let Ok(Opened::Thin { image, tables: FormatTables::Wasm(module) }) = (format.open)(bytes, &OpenOptions::default()) else {
                panic!("{name} opens as a module")
            };
            let arch = n0xis_wasm_arch::Wasm::new(module.shared(), module.identity());
            let loaded = image.loaded_bytes();
            let ctx = Ctx::new(&loaded, &arch);
            for s in image.sections().iter().filter(|s| s.executable) {
                let window = loaded.read(s.va, s.size as usize).unwrap();
                let decoded = arch.decode_range(&window, s.va, window.len());
                if name.contains("br_table") {
                    let long = decoded.iter().find(|i| i.va == Va(0x35)).expect("the br_table");
                    assert_eq!(long.len, 0x62 - 0x35, "the br_table is decoded whole, as wasm-objdump lists it");
                }
                let whole: Vec<String> = decoded.iter().map(|i| line(i, true)).collect();
                assert!(!whole.is_empty(), "{name}: its code decodes");
                for chunk in (1..=60).chain([SWEEP_CHUNK]) {
                    assert_eq!(swept(&ctx, s.va, s.size, chunk, true), whole, "{name}: a {chunk}-byte window changed the sweep");
                }
            }
        }
    }

    /// The case the resume rule exists for, planted: a window boundary right
    /// after a good instruction that an undecodable byte follows. A window that
    /// resumed *after* the last kept instruction began a run with the bad byte
    /// and skipped two bytes where the whole-range decode skips one.
    #[test]
    fn a_window_that_ends_before_an_undecodable_byte_resumes_as_the_whole_decode_does() {
        // 0x1000: nop; 0x1001: 06 (invalid in 64-bit mode); then four nops.
        // A whole decode drops the 06 and resumes at 0x1002.
        let bytes = vec![0x90, 0x06, 0x90, 0x90, 0x90, 0x90];
        let snap = Snapshot::builder().region(Va(0x1000), bytes.clone()).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let whole: Vec<u64> = arch.decode_range(&bytes, Va(0x1000), bytes.len()).iter().map(|i| i.va.0).collect();
        assert_eq!(whole, [0x1000, 0x1002, 0x1003, 0x1004, 0x1005], "the whole-range decode resumes one byte past the 06");
        // Resuming after the nop (at the 06) is what the earlier rule did, and
        // it loses the instruction at 0x1002.
        let after: Vec<u64> = arch.decode_range(&bytes[1..], Va(0x1001), bytes.len() - 1).iter().map(|i| i.va.0).collect();
        assert_eq!(after, [0x1003, 0x1004, 0x1005], "a decode begun at the 06 skips two bytes");
        let mut got = Vec::new();
        sweep_code(&ctx, Va(0x1000), bytes.len() as u64, 1, |i| {
            got.push(i.va.0);
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(got, whole);
    }

    /// The range ends where the region holding its start does, as the single
    /// read of the whole range did, even when the next region follows without
    /// a gap; an unmapped start is an error even for an empty range, as it was.
    #[test]
    fn the_range_ends_where_its_region_does() {
        // Two regions back to back: one read at 0x1000 stops at 0x1004.
        let snap = Snapshot::builder().region(Va(0x1000), vec![0x90; 4]).region(Va(0x1004), vec![0x90; 4]).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        for chunk in [1, 2, 3, 64] {
            let mut got = Vec::new();
            sweep_code(&ctx, Va(0x1000), 8, chunk, |i| {
                got.push(i.va.0);
                ControlFlow::Continue(())
            })
            .unwrap();
            assert_eq!(got, [0x1000, 0x1001, 0x1002, 0x1003], "{chunk}-byte windows");
        }
        assert!(sweep_code(&ctx, Va(0x9000), 0, SWEEP_CHUNK, |_| ControlFlow::Continue(())).is_err());
        assert!(sweep_code(&ctx, Va(0x1000), 0, SWEEP_CHUNK, |_| ControlFlow::Continue(())).is_ok());
    }

    /// Code laid out as real code is around the shapes the passes match, with
    /// undecodable stretches between them: a call to one target, a string
    /// load, a binding registration and an icall resolution, repeatedly, each
    /// after a run of noise and the nops that bring the decoder back in step.
    struct Planted {
        snap: Snapshot,
        code: (Va, usize),
        data: (Va, usize),
        slots: (Va, usize),
        callee: Va,
        string: Va,
    }

    fn planted() -> Planted {
        const CODE: u64 = 0x10_0000;
        const DATA: u64 = 0x40_0000;
        const SLOTS: u64 = 0x50_0000;
        // The data: one binding name, one icall name, one string, each NUL-terminated.
        let mut data = Vec::new();
        let mut put = |s: &[u8]| {
            let at = DATA + data.len() as u64;
            data.extend_from_slice(s);
            data.push(0);
            at
        };
        let binding = put(b"planted_binding");
        let icall = put(b"Planted.Type::Method(System.Int32)");
        let string = put(b"a planted string");
        let mut code: Vec<u8> = Vec::new();
        let rip = |code: &Vec<u8>, len: u64, to: u64| ((to as i64) - (CODE as i64 + code.len() as i64 + len as i64)) as i32;
        let callee = CODE; // the first byte: a target every repetition calls
        code.push(0xC3);
        for rep in 0..60u64 {
            let n = (rep * 7 % 41) as usize;
            code.extend_from_slice(&noise(n, rep + 11));
            code.extend_from_slice(&[0x90; 15]);
            // lea rdx,[cfunc] ; lea rcx,[binding] ; call callee
            let d = rip(&code, 7, callee + 1);
            code.extend_from_slice(&[0x48, 0x8D, 0x15]);
            code.extend_from_slice(&d.to_le_bytes());
            let d = rip(&code, 7, binding);
            code.extend_from_slice(&[0x48, 0x8D, 0x0D]);
            code.extend_from_slice(&d.to_le_bytes());
            let d = rip(&code, 5, callee);
            code.push(0xE8);
            code.extend_from_slice(&d.to_le_bytes());
            // lea rcx,[icall] ; call callee ; test rax,rax ; mov [slot],rax
            let d = rip(&code, 7, icall);
            code.extend_from_slice(&[0x48, 0x8D, 0x0D]);
            code.extend_from_slice(&d.to_le_bytes());
            let d = rip(&code, 5, callee);
            code.push(0xE8);
            code.extend_from_slice(&d.to_le_bytes());
            code.extend_from_slice(&[0x48, 0x85, 0xC0]);
            let d = rip(&code, 7, SLOTS + 8 * rep);
            code.extend_from_slice(&[0x48, 0x89, 0x05]);
            code.extend_from_slice(&d.to_le_bytes());
            // lea rcx,[string]
            let d = rip(&code, 7, string);
            code.extend_from_slice(&[0x48, 0x8D, 0x0D]);
            code.extend_from_slice(&d.to_le_bytes());
        }
        let (code_len, data_len) = (code.len(), data.len());
        let snap = Snapshot::builder().region(Va(CODE), code).region(Va(DATA), data).region(Va(SLOTS), vec![0; 8 * 60]).build();
        Planted { snap, code: (Va(CODE), code_len), data: (Va(DATA), data_len), slots: (Va(SLOTS), 8 * 60), callee: Va(callee), string: Va(string) }
    }

    /// Every pass that sweeps gives the same answer whatever the window size:
    /// the default, and windows from one byte up, which put a boundary inside
    /// every shape the passes match. And each answer is not empty, so the
    /// sameness is about something.
    #[test]
    fn no_sweeping_pass_answers_by_its_window_size() {
        use crate::{BindingsInput, BindingsPass, IcallInput, IcallPass, StringXrefInput, StringXrefPass, XrefDir, XrefInput, XrefPass};
        let p = planted();
        let arch = X64::new();
        let ctx = Ctx::new(&p.snap, &arch);
        let (code, size) = p.code;
        let answers = |chunk: u64| -> Vec<(&'static str, String)> {
            let json = |v: serde_json::Value| v.to_string();
            let mut out = Vec::new();
            for addr in [p.callee, p.string] {
                let art = XrefPass.run_in(&ctx, XrefInput { scan_start: code, size, addr, dir: XrefDir::To }, chunk).unwrap();
                out.push(("xref to", json(serde_json::to_value(art).unwrap())));
            }
            let idx = crate::xref::build_xref_index_in(&ctx, &[(code, size as u64)], chunk);
            out.push(("xref index", json(serde_json::to_value(idx).unwrap())));
            for (query, limit) in [("planted", 100), ("a planted string", 1), ("planted", 0)] {
                let input = StringXrefInput { data_start: p.data.0, data_size: p.data.1, code_start: code, code_size: size, query: query.into(), limit };
                out.push(("xref string", json(serde_json::to_value(StringXrefPass.run_in(&ctx, input, chunk).unwrap()).unwrap())));
            }
            for window in [8, 3, 0] {
                let input =
                    BindingsInput { data_start: p.data.0, data_size: p.data.1, code_start: code, code_size: size, names: Vec::new(), window, limit: 1000 };
                out.push(("bindings", json(serde_json::to_value(BindingsPass.run_in(&ctx, input, chunk).unwrap()).unwrap())));
            }
            for (window, limit) in [(0, 0), (2, 0), (0, 7)] {
                let input = IcallInput {
                    data_start: p.data.0,
                    data_size: p.data.1,
                    code_start: code,
                    code_size: size,
                    slot_start: p.slots.0,
                    slot_size: p.slots.1,
                    window,
                    limit,
                };
                out.push(("icalls", json(serde_json::to_value(IcallPass.run_in(&ctx, input, chunk).unwrap()).unwrap())));
            }
            out
        };
        let reference = answers(SWEEP_CHUNK);
        // What was planted, so the sameness below is about real answers: 60
        // repetitions, each with two calls to the callee, one load of the
        // string, one registration of the binding (paired once: the pair is
        // the same every time) and one icall resolution with its own slot.
        let field = |i: usize, key: &str| -> serde_json::Value { serde_json::from_str::<serde_json::Value>(&reference[i].1).unwrap()[key].clone() };
        assert_eq!(field(0, "count"), 120, "xref to the callee");
        assert_eq!(field(1, "count"), 60, "xref to the string");
        assert_eq!(field(2, "edges")[p.callee.0.to_string()].as_array().map(Vec::len), Some(120), "the index's edges to the callee");
        assert_eq!((field(3, "count"), field(3, "found_unreferenced")), (1.into(), 1.into()), "`planted`: the binding name referenced, the string's middle not");
        assert_eq!(field(4, "hits")[0]["xrefs"].as_array().map(Vec::len), Some(60), "the string's 60 loads");
        assert_eq!(field(6, "count"), 1, "the binding, window 8");
        assert_eq!((field(9, "count"), field(9, "with_slot")), (60.into(), 60.into()), "every icall with its slot");
        assert_eq!((field(10, "count"), field(10, "with_slot")), (60.into(), 0.into()), "a window of 2 stops short of every store");
        assert_eq!(field(11, "count"), 7, "the limit");
        for chunk in (1..=40).chain([64, 100, 333, 4096]) {
            for ((pass, want), (_, got)) in reference.iter().zip(answers(chunk)) {
                assert_eq!(&got, want, "{pass}: a {chunk}-byte window changed the answer");
            }
        }
    }

    #[test]
    fn a_visitor_stops_the_sweep() {
        let snap = Snapshot::builder().region(Va(0x1000), vec![0x90; 64]).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let mut seen = 0;
        sweep_code(&ctx, Va(0x1000), 64, 8, |_| {
            seen += 1;
            if seen == 20 { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
        })
        .unwrap();
        assert_eq!(seen, 20);
    }
}

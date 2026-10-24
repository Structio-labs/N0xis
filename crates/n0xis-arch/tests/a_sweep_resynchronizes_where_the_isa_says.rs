// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Where a section-wide sweep picks up again after bytes that do not
//! decode, on every instruction set, held against an independent
//! disassembler.**
//!
//! [`Arch::decode_range`] is what every section-wide pass reads (the
//! reverse-xref index, `xref to`, the call targets `function discover`
//! collects). After an undecodable instruction it steps
//! [`Arch::resync_step`] bytes and tries again. A step that lands inside an
//! instruction reads made-up instructions out of its bytes and loses the real
//! ones; on AArch64 the old one-byte step never landed on a word boundary
//! again until three more decodes failed (found 2026-10-23).
//!
//! Each case below plants undecodable bytes at known places: at the start of
//! the range (a run that *begins* on one), twice in a row, and after good
//! instructions (a run that *ends* on one). The expected lists are the
//! instructions `llvm-objdump` 23.1.1 prints for the same bytes, copied from
//! its output, which is quoted above each case together with the command that
//! made it: the bytes written raw, wrapped with
//! `llvm-objcopy -I binary -O <bfd> case.bin case.o` (so no mapping symbol
//! says "data"), then
//! `llvm-objdump -D --triple=<triple> --adjust-vma=0x1000 [-M intel | --mattr=…] case.o`.
//!
//! Where n0xis answers otherwise on purpose, the difference is spelled out
//! beside the case and asserted too, so it cannot change unnoticed in either
//! direction. Two kinds, both x86 or Thumb decoder facts, not resync ones:
//! on x86 `llvm-objdump` steps past an undecodable encoding by the length its
//! own decoder read before giving up, which the architecture does not define
//! (iced gives `0f 0a 90` a length of three, LLVM two), so n0xis steps one byte;
//! and n0xis's Thumb decoder does not decode VFP, so it lists nothing where
//! `llvm-objdump` lists `vldr`.
//!
//! Calibrated 2026-10-24. Restoring the old default (one byte after a run of
//! good instructions, two when a run began on a bad one) fails five tests on
//! their own assertions: x86-64 loses the `nop` at 0x1001; i386 reads `ret` at
//! 0x1002 and loses the one at 0x1009; AArch64 lists 0x100d and 0x1011 and
//! loses 0x1010 and 0x1014; A32 lists 0x100d, 0x1011, 0x1015 and 0x101a in
//! place of four real words; Thumb lists 0x1002 and then odd addresses from
//! 0x1007 on. The x86-64 `8d c0` case passes either way: it pins the one-byte
//! step, which the old default also took there. A flat two-byte Thumb step
//! fails the Thumb case (a `nop` at 0x1002 and an `lsrs` at 0x1016, the halves
//! of two 32-bit instructions) and the width table.

use n0xis_arch::{Arch, Arm32, Arm64, X64};
use n0xis_contracts::Va;

const BASE: u64 = 0x1000;

/// `(va, len)` of every instruction one sweep over `bytes` returns.
fn swept(arch: &dyn Arch, bytes: &[u8]) -> Vec<(u64, u32)> {
    arch.decode_range(bytes, Va(BASE), usize::MAX).iter().map(|i| (i.va.0, i.len)).collect()
}

/// Little-endian bytes of 32-bit words, as an A64 or A32 stream stores them.
fn words(ws: &[u32]) -> Vec<u8> {
    ws.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// Little-endian bytes of Thumb halfwords, in stream order (a 32-bit
/// instruction is its first halfword, then its second).
fn halfwords(hs: &[u16]) -> Vec<u8> {
    hs.iter().flat_map(|h| h.to_le_bytes()).collect()
}

/// ```text
/// $ llvm-objdump -D --triple=x86_64 --adjust-vma=0x1000 -M intel x64a.o
///     1000: 06                            <unknown>
///     1001: 90                            nop
///     1002: 06                            <unknown>
///     1003: 06                            <unknown>
///     1004: 90                            nop
///     1005: 48 89 c8                      mov     rax, rcx
///     1008: 06                            <unknown>
///     1009: c3                            ret
/// ```
///
/// `06` is not an instruction in 64-bit mode, and one byte long to every
/// decoder. The old default lost the `nop` at 0x1001 (two bytes past a range
/// that began on a bad byte) and the `nop` at 0x1004 was found only because
/// the second `06` was skipped with the first.
#[test]
fn x86_64_resumes_one_byte_past_an_undecodable_byte() {
    let bytes = [0x06, 0x90, 0x06, 0x06, 0x90, 0x48, 0x89, 0xc8, 0x06, 0xc3];
    assert_eq!(swept(&X64::new(), &bytes), [(0x1001, 1), (0x1004, 1), (0x1005, 3), (0x1009, 1)]);
}

/// ```text
/// $ llvm-objdump -D --triple=x86_64 --adjust-vma=0x1000 -M intel x64b.o
///     1000: 90                            nop
///     1001: 8d c0                         <unknown>
///     1003: c3                            ret
///     1004: 90                            nop
/// ```
///
/// Differs on purpose: `8d c0` (`lea` with a register source) does not
/// decode; LLVM steps the two bytes its decoder read, n0xis one, where
/// `c0 c3 90` is `rol bl, 0x90`. Neither is the architecture's answer: an
/// undefined encoding has no length.
#[test]
fn x86_64_steps_one_byte_where_llvm_objdump_steps_what_it_read() {
    let bytes = [0x90, 0x8d, 0xc0, 0xc3, 0x90];
    let got = X64::new().decode_range(&bytes, Va(BASE), usize::MAX);
    let got: Vec<(u64, u32, &str)> = got.iter().map(|i| (i.va.0, i.len, i.mnemonic.as_str())).collect();
    assert_eq!(got, [(0x1000, 1, "nop"), (0x1002, 3, "rol")], "llvm-objdump: nop, then ret at 0x1003 and nop at 0x1004");
}

/// ```text
/// $ llvm-objdump -D --triple=i386 --adjust-vma=0x1000 -M intel x86a.o
///     1000: fe ff                         <unknown>
///     1002: c3                            ret
///     1003: 90                            nop
///     1004: 06                            push    es
///     1005: 06                            push    es
///     1006: 90                            nop
///     1007: 8d c0                         <unknown>
///     1009: c3                            ret
/// ```
///
/// In 32-bit mode every undecodable encoding is two bytes or more, so the
/// step matters both ways here. After `fe ff` at the start, one byte on is
/// `ff c3`, `inc ebx` (LLVM steps two and finds `ret`; the old default did
/// too, by its two-byte step at the start of a run). After `8d c0`, one byte
/// on is `c0 c3`, cut short by the end of the range, and one more is the
/// `ret` LLVM lists (the old default stepped two from there and lost it).
#[test]
fn x86_resumes_one_byte_past_an_undecodable_encoding() {
    let bytes = [0xfe, 0xff, 0xc3, 0x90, 0x06, 0x06, 0x90, 0x8d, 0xc0, 0xc3];
    let got = X64::x86().decode_range(&bytes, Va(BASE), usize::MAX);
    let got: Vec<(u64, u32, &str)> = got.iter().map(|i| (i.va.0, i.len, i.mnemonic.as_str())).collect();
    assert_eq!(
        got,
        [(0x1001, 2, "inc"), (0x1003, 1, "nop"), (0x1004, 1, "push"), (0x1005, 1, "push"), (0x1006, 1, "nop"), (0x1009, 1, "ret")],
        "llvm-objdump lists a ret at 0x1002 where n0xis reads inc ebx at 0x1001; from 0x1003 on the two agree"
    );
}

/// ```text
/// $ llvm-objdump -D --triple=aarch64 --adjust-vma=0x1000  a64.o
///     1000: ffffffff      <unknown>
///     1004: d503201f      nop
///     1008: ffffffff      <unknown>
///     100c: ffffffff      <unknown>
///     1010: d503201f      nop
///     1014: aa0103e0      mov     x0, x1
///     1018: d65f03c0      ret
///     101c: 0000ffff      udf     #0xffff
///     1020: 00000000      udf     #0x0
/// ```
///
/// The defect this file was written for: one byte past the undefined word at
/// 0x1000 the old sweep read made-up instructions out of the real ones' bytes.
#[test]
fn aarch64_resumes_at_the_next_word() {
    let bytes = words(&[0xffff_ffff, 0xd503_201f, 0xffff_ffff, 0xffff_ffff, 0xd503_201f, 0xaa01_03e0, 0xd65f_03c0, 0x0000_ffff, 0x0000_0000]);
    assert_eq!(swept(&Arm64::new(), &bytes), [(0x1004, 4), (0x1010, 4), (0x1014, 4), (0x1018, 4), (0x101c, 4), (0x1020, 4)]);
}

/// ```text
/// $ llvm-objdump -D --triple=armv7a --adjust-vma=0x1000 --mattr=+vfp4,+neon a32.o
///     1000: ffffffff      <unknown>
///     1004: e1a00000      mov     r0, r0
///     1008: ffffffff      <unknown>
///     100c: ffffffff      <unknown>
///     1010: e1a00000      mov     r0, r0
///     1014: e1a00001      mov     r0, r1
///     1018: e12fff1e      bx      lr
///     101c: e7f000f0      udf     #0x0
/// ```
#[test]
fn a32_resumes_at_the_next_word() {
    let bytes = words(&[0xffff_ffff, 0xe1a0_0000, 0xffff_ffff, 0xffff_ffff, 0xe1a0_0000, 0xe1a0_0001, 0xe12f_ff1e, 0xe7f0_00f0]);
    assert_eq!(swept(&Arm32::a32(), &bytes), [(0x1004, 4), (0x1010, 4), (0x1014, 4), (0x1018, 4), (0x101c, 4)]);
}

/// ```text
/// $ llvm-objdump -D --triple=thumbv7a --adjust-vma=0x1000 --mattr=+vfp4,+neon t32.o
///     1000: ffff bf00     <unknown>
///     1004: ffff ffff     <unknown>
///     1008: bf00          nop
///     100a: 4608          mov     r0, r1
///     100c: 4770          bx      lr
///     100e: de00          udf     #0x0
///     1010: ba80          <unknown>
///     1012: bf00          nop
///     1014: ed9f 0b02     vldr    d0, [pc, #8]            @ 0x20 <_binary_t32_bin_end+0x6>
///     1018: 4770          bx      lr
/// ```
///
/// A Thumb instruction's width is in its first halfword: `ffff` begins a
/// 32-bit one, so the step is four, and the `bf00` (`nop`) at 0x1002 is its
/// second half, not an instruction. `ba80` is an undefined 16-bit one, so the
/// step is two. Differs on purpose at 0x1014: the Thumb decoder here does
/// not decode VFP, so `vldr` is not listed; four bytes on is the `bx lr` LLVM
/// lists (two bytes on, `0b02`, would read as `lsrs r2, r0, #12`).
#[test]
fn thumb_resumes_past_the_width_the_first_halfword_states() {
    let bytes = halfwords(&[0xffff, 0xbf00, 0xffff, 0xffff, 0xbf00, 0x4608, 0x4770, 0xde00, 0xba80, 0xbf00, 0xed9f, 0x0b02, 0x4770]);
    assert_eq!(swept(&Arm32::thumb(), &bytes), [(0x1008, 2), (0x100a, 2), (0x100c, 2), (0x100e, 2), (0x1012, 2), (0x1018, 2)]);
}

/// The step itself, as each instruction set states it, independent of the
/// sweep around it.
#[test]
fn each_instruction_set_states_its_step() {
    let step = |a: &dyn Arch, b: &[u8]| a.resync_step(b).get();
    assert_eq!(step(&X64::new(), &[0x8d, 0xc0]), 1);
    assert_eq!(step(&X64::x86(), &[0xfe, 0xff]), 1);
    assert_eq!(step(&Arm64::new(), &[0xff; 4]), 4);
    assert_eq!(step(&Arm32::a32(), &[0xff; 4]), 4);
    // Thumb: 0b11101, 0b11110, 0b11111 in bits 15..11 begin a 32-bit
    // instruction; 0b11100 (`b`) and everything below is 16 bits.
    for (hw, width) in [(0xe800u16, 4), (0xf000, 4), (0xf800, 4), (0xffff, 4), (0xe7ff, 2), (0xba80, 2), (0x0000, 2)] {
        assert_eq!(step(&Arm32::thumb(), &hw.to_le_bytes()), width, "{hw:#06x}");
    }
    // Shorter than a halfword: the smallest Thumb step.
    assert_eq!(step(&Arm32::thumb(), &[0xff]), 2);
    assert_eq!(step(&Arm32::thumb(), &[]), 2);
}

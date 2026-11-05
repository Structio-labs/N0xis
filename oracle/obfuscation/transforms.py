#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The transformations, as text rewrites of an assembler file (`.s`) or, later,
LLVM IR (`.ll`).

The one invariant every transformation here keeps: it operates where the
symbols are still labels, so the build's own DWARF and symbol table stay correct
by construction (a function's `DW_AT_low_pc`/`high_pc` are labels, which the
assembler relocates past any bytes inserted between them). The transformed
program must still run and print what the clean build prints — a transformation
that changes behaviour is a bug, not obfuscation — which `build.py` checks by
running both.

A transformation returns the rewritten assembly and a record of what it planted
(the byte ranges it added, the functions it touched), as `Planted`, so the
scorer can show each wrong answer against bytes that are known, not guessed.

Intensity is the share of eligible functions touched; `build.py` passes at
least two values. Which functions are chosen is deterministic (every k-th),
so a re-run plants the same bytes.

Each transformation also builds a *reference twin*: the same assembly with the
planted bytes replaced by an equal count of single-byte NOPs (x86) or a `nop`
word (AArch64). The twin's code is byte-for-byte the obfuscated one except in
the planted (dead) ranges, so an independent `objdump` reads the real
instruction boundaries off the twin without the desync the obfuscated image is
built to cause. The twin runs identically too (the padding is as dead as the
junk).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class Planted:
    """What a transformation added, for the scorer to check answers against.

    `junk_labels`: pairs of local-symbol names (emitted into the assembly) that
    bracket each planted region, so `build.py` can read the region's real
    address from the linked image's symbol table — the planted bytes are known
    by address, not inferred. `touched`: the assembler labels of the functions
    the transformation changed."""

    kind: str
    touched: list = field(default_factory=list)
    junk_labels: list = field(default_factory=list)  # (lo_label, hi_label)
    note: str = ""


# Unconditional transfers after which the fall-through is dead, per syntax.
# gcc/clang emit AT&T on x86 and the GNU AArch64 mnemonics; a conditional jump
# (`je`, `b.eq`) falls through and is never matched.
_UNCOND_X86 = re.compile(r"^\s*(jmp|jmpq|ret|retq|ud2)\b")
_UNCOND_ARM = re.compile(r"^\s*(b|br|ret)\b")  # `b.eq` has a dot, so \b excludes it

_INSN = re.compile(r"^\s+\S")  # a line that is an instruction or directive, not a label
_LABEL = re.compile(r"^(\.?\w[\w.$]*):")
_FUNC_START = re.compile(r"^\s*\.cfi_startproc\b")
_FUNC_END = re.compile(r"^\s*\.cfi_endproc\b")


def _is_arm(asm: str) -> bool:
    # AArch64 gcc emits `.arch armv8-a` and uses `x0`/`w0`; x86 uses `%rax`.
    return ".arch armv8" in asm or bool(re.search(r"\bret\b", asm) and "%rax" not in asm and "%eax" not in asm)


def _func_regions(lines: list) -> list:
    """(start_index, end_index, label) for each `.cfi_startproc`..`.cfi_endproc`
    region, with the nearest preceding label as the function's name."""
    out = []
    label = None
    start = None
    for i, ln in enumerate(lines):
        m = _LABEL.match(ln)
        if m:
            label = m.group(1)
        if _FUNC_START.match(ln):
            start = i
        elif _FUNC_END.match(ln) and start is not None:
            out.append((start, i, label))
            start = None
    return out


def junk_after_transfers(asm: str, intensity: float, seed: int = 1) -> tuple:
    """J: insert bytes that never execute after each unconditional transfer in a
    chosen share of functions. The bytes are an `0xe8` (x86 `call rel32`, which a
    linear sweep reads as swallowing the four bytes that follow) or an AArch64
    word; placed after a `ret`/`jmp`, they are dead, so behaviour is unchanged
    while a linear disassembler desynchronises.

    Returns (obfuscated asm, reference asm with equal-length NOP padding,
    Planted)."""
    lines = asm.splitlines()
    arm = _is_arm(asm)
    uncond = _UNCOND_ARM if arm else _UNCOND_X86
    regions = _func_regions(lines)
    # An exact, evenly-spread share of the functions (Bresenham selection): for
    # len functions, index n is chosen when int((n+1)*intensity) > int(n*intensity),
    # which picks round(intensity*len) of them spaced across the file, so 0.5
    # really drops half even when there are only a handful.
    chosen = {n for n in range(len(regions)) if int((n + 1) * intensity) > int(n * intensity)}
    region_of = {}
    chosen_lbls = set()
    for n, (s, e, lbl) in enumerate(regions):
        if n in chosen:
            chosen_lbls.add(lbl)
            for i in range(s, e + 1):
                region_of[i] = lbl

    obf, ref, planted = [], [], Planted(kind="junk", note=f"intensity={intensity}")
    n = 0
    for i, ln in enumerate(lines):
        obf.append(ln)
        ref.append(ln)
        lbl = region_of.get(i)
        if lbl is not None and uncond.match(ln):
            n += 1
            lo, hi = f"__obf_junk_{n}_a", f"__obf_junk_{n}_b"
            if arm:
                junk_bytes = ".byte 0x1f, 0x20, 0x03, 0xd5"  # one 32-bit word, decodes as a nop-ish; a dead word desyncs nothing on fixed-width ARM but is still unreachable code a sweep lists
                pad_bytes = ".byte 0x1f, 0x20, 0x03, 0xd5"
            else:
                junk_bytes = ".byte 0xe8"  # call rel32: a linear sweep swallows the next four real bytes
                pad_bytes = ".byte 0x90"   # one nop: the reference twin decodes cleanly
            obf += [f"{lo}:", f"\t{junk_bytes}", f"{hi}:"]
            ref += [f"{lo}:", f"\t{pad_bytes}", f"{hi}:"]
            planted.touched.append(lbl)
            planted.junk_labels.append((lo, hi))
    planted.touched = sorted(set(planted.touched))
    return "\n".join(obf) + "\n", "\n".join(ref) + "\n", planted


# The registry: name -> (function, applies-to-arches, needs-reference-twin).
# Each new transformation is added here in its own commit.
TRANSFORMS = {
    "junk": {"fn": junk_after_transfers, "arches": ("x86_64", "i686", "aarch64"), "twin": True,
             "desc": "junk bytes after unconditional transfers (desynchronises a linear sweep)"},
}

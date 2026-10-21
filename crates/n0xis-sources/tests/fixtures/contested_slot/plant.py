#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Patch an x86-64 ELF shared object so the JUMP_SLOT relocation against
FROM names the slot of the JUMP_SLOT relocation against TO.

Usage: plant.py IN OUT FROM TO

Reads the section headers, `.rela.plt`, `.dynsym` and `.dynstr` itself (no
n0xis code), and refuses unless each name has exactly one JUMP_SLOT entry
and exactly one 8-byte field changes.
"""
import struct
import sys

R_X86_64_JUMP_SLOT = 7


def main():
    src, dst, frm, to = sys.argv[1:5]
    b = bytearray(open(src, "rb").read())
    assert b[:4] == b"\x7fELF" and b[4] == 2 and b[5] == 1, "an ELF64 little-endian file"
    shoff, = struct.unpack_from("<Q", b, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", b, 0x3A)
    secs = [struct.unpack_from("<IIQQQQIIQQ", b, shoff + i * shentsize) for i in range(shnum)]
    strtab_off = secs[shstrndx][4]

    def name(off, at):
        end = b.index(0, at + off)
        return b[at + off:end].decode()

    by_name = {name(s[0], strtab_off): s for s in secs}
    rela, dynsym, dynstr = by_name[".rela.plt"], by_name[".dynsym"], by_name[".dynstr"]
    entries = {}
    for i in range(rela[5] // 24):
        at = rela[4] + i * 24
        r_offset, r_info, _ = struct.unpack_from("<QQq", b, at)
        if r_info & 0xFFFFFFFF != R_X86_64_JUMP_SLOT:
            continue
        sym = r_info >> 32
        st_name, = struct.unpack_from("<I", b, dynsym[4] + sym * 24)
        entries.setdefault(name(st_name, dynstr[4]), []).append((at, r_offset))
    assert len(entries.get(frm, [])) == 1 and len(entries.get(to, [])) == 1, entries
    (frm_at, frm_slot), (_, to_slot) = entries[frm][0], entries[to][0]
    assert frm_slot != to_slot
    before = bytes(b)
    struct.pack_into("<Q", b, frm_at, to_slot)
    changed = [i for i in range(len(b)) if b[i] != before[i]]
    assert changed and max(changed) - min(changed) < 8, changed
    open(dst, "wb").write(b)
    print(f"{frm}: JUMP_SLOT at {frm_slot:#x} now names {to_slot:#x}, the slot of {to}")


main()

#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Plant an import lookup entry whose hint/name RVA lies in no section.

Usage: plant.py IN OUT DLL NAME RVA

Reads IN, a PE32, with its own header walk (no n0xis code): finds the import
descriptor naming DLL, the entry of its import lookup table
(OriginalFirstThunk) that imports NAME by name, and sets that entry to RVA.
Refuses unless DLL has exactly one descriptor, NAME exactly one entry in it,
RVA lies in no section, and exactly one 4-byte field changes. The import
address table (FirstThunk) is left as it was, so a tool that reads it instead
of the lookup table still sees NAME.
"""
import struct
import sys


def main():
    src, dst, dll, name, rva = sys.argv[1:6]
    new_rva = int(rva, 0)
    b = bytearray(open(src, "rb").read())
    assert b[:2] == b"MZ", "a PE file"
    pe, = struct.unpack_from("<I", b, 0x3C)
    assert b[pe:pe + 4] == b"PE\0\0"
    nsec, = struct.unpack_from("<H", b, pe + 6)
    opt_size, = struct.unpack_from("<H", b, pe + 20)
    opt = pe + 24
    magic, = struct.unpack_from("<H", b, opt)
    assert magic == 0x10B, "a PE32 (4-byte lookup entries)"
    import_rva, _ = struct.unpack_from("<II", b, opt + 96 + 8)
    secs = []
    for i in range(nsec):
        at = opt + opt_size + i * 40
        vsize, va, rawsize, raw = struct.unpack_from("<IIII", b, at + 8)
        secs.append((va, max(vsize, rawsize), raw))

    def off(r):
        for va, size, raw in secs:
            if va <= r < va + size:
                return raw + (r - va)
        return None

    def cstr(r):
        o = off(r)
        return bytes(b[o:b.index(0, o)]).decode()

    assert off(new_rva) is None, f"{new_rva:#x} lies in a section"
    found = []
    d = off(import_rva)
    while True:
        oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", b, d)
        if (oft, name_rva, ft) == (0, 0, 0):
            break
        if cstr(name_rva).lower() == dll.lower():
            k = 0
            while True:
                at = off(oft) + 4 * k
                entry, = struct.unpack_from("<I", b, at)
                if entry == 0:
                    break
                if entry & 0x8000_0000 == 0 and cstr(entry + 2) == name:
                    found.append((at, entry, k))
                k += 1
        d += 20
    assert len(found) == 1, found
    at, old, k = found[0]
    before = bytes(b)
    struct.pack_into("<I", b, at, new_rva)
    changed = [i for i in range(len(b)) if b[i] != before[i]]
    assert changed and max(changed) - min(changed) < 4, changed
    open(dst, "wb").write(b)
    print(f"{dll} entry {k} ({name}): hint/name RVA {old:#x} -> {new_rva:#x}, at file offset {at:#x}")


main()

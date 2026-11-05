#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Lying tables: edits made after the link, on the file's own structures.

The code is not touched (`readers.same_code` checks it); only what the file
*claims* about the code changes. The truth is the file before tampering: its
DWARF, its symbols, its bytes. Each lie reads what it needs from the file before
(`truth.py`, `objdump`), writes the tampered file, and returns the record of
what it planted; `verify` then reads the result with `readelf`, an independent
parser, and an edit it does not see stops the configuration: an edit that did
not happen would measure nothing, and would look like the engine ignoring it.

The editor is ELF64 little-endian only, which is every image this corpus has,
and refuses what it cannot rewrite faithfully instead of guessing:
a CIE with a personality or an LSDA encoding, whose pointers it would have to
relocate (none in the C programs here).

What is deliberately kept honest beside a lie: `.eh_frame_hdr` is rebuilt so its
table agrees with `.eh_frame`, and `.gnu.hash` stays valid (the swap of an export
moves value and size, not the name's slot). A lie the loader would refuse is no
lie, and a stale search table would be a second, unintended edit.
"""

from __future__ import annotations

import bisect
import os
import struct
import subprocess
from dataclasses import dataclass, field

import obf_corpus as corpus
import readers
from transforms import chosen_indices

PT_LOAD = 1
PT_NOTE = 4
PT_GNU_EH_FRAME = 0x6474E550
PT_GNU_SFRAME = 0x6474E554

_EHDR_PH = 0x20  # e_phoff, e_shoff
_EHDR_ENT = 0x36  # e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
_PHDR = struct.Struct("<IIQQQQQQ")
_SHDR = struct.Struct("<IIQQQQIIQQ")
_SYM = struct.Struct("<IBBHQQ")
_FDE_ENC_PCREL_SDATA4 = 0x1B
_STT_FUNC_GLOBAL = (1 << 4) | 2


def _align(n: int, to: int) -> int:
    return (n + to - 1) // to * to if to else n


class Elf:
    """The file as bytes, plus the headers it needs to edit them."""

    def __init__(self, path: str):
        self.b = bytearray(open(path, "rb").read())
        if self.b[:4] != b"\x7fELF" or self.b[4] != 2 or self.b[5] != 1:
            raise ValueError(f"{path}: not ELF64 little-endian")
        self.phoff, self.shoff = struct.unpack_from("<QQ", self.b, _EHDR_PH)
        self.phent, self.phnum, self.shent, self.shnum, self.shstrndx = struct.unpack_from("<HHHHH", self.b, _EHDR_ENT)

    def phdrs(self) -> list:
        out = []
        for i in range(self.phnum):
            t, fl, off, va, pa, fs, ms, al = _PHDR.unpack_from(self.b, self.phoff + i * self.phent)
            out.append({"i": i, "type": t, "flags": fl, "offset": off, "vaddr": va, "paddr": pa, "filesz": fs, "memsz": ms, "align": al})
        return out

    def write_phdr(self, p: dict):
        _PHDR.pack_into(self.b, self.phoff + p["i"] * self.phent, p["type"], p["flags"], p["offset"], p["vaddr"], p["paddr"], p["filesz"], p["memsz"], p["align"])

    def _shdr(self, i: int) -> list:
        return list(_SHDR.unpack_from(self.b, self.shoff + i * self.shent))

    def section(self, name: str) -> dict | None:
        strs = self._shdr(self.shstrndx)
        names = self.b[strs[4]:strs[4] + strs[5]]
        for i in range(self.shnum):
            s = self._shdr(i)
            end = names.index(0, s[0])
            if names[s[0]:end].decode() == name:
                return {"i": i, "addr": s[3], "offset": s[4], "size": s[5], "link": s[6], "info": s[7]}
        return None

    def section_index(self, name: str) -> int:
        s = self.section(name)
        if s is None:
            raise ValueError(f"no section {name}")
        return s["i"]

    def update_section(self, s: dict):
        raw = self._shdr(s["i"])
        raw[3], raw[4], raw[5], raw[7] = s["addr"], s["offset"], s["size"], s["info"]
        _SHDR.pack_into(self.b, self.shoff + s["i"] * self.shent, *raw)

    def bytes_of(self, s: dict) -> bytes:
        return bytes(self.b[s["offset"]:s["offset"] + s["size"]])

    def append(self, data: bytes, align: int = 8) -> int:
        """Past the current end of the file; returns the offset."""
        off = _align(len(self.b), align)
        self.b.extend(b"\0" * (off - len(self.b)))
        self.b.extend(data)
        return off

    def new_load_segment(self, data: bytes) -> tuple:
        """Map `data` read-only at a fresh address above everything, in the slot of
        a program header nothing at run time needs, so no header has to move: the
        section-table-less `PT_GNU_SFRAME` where there is one, otherwise a
        `PT_NOTE` that does not carry the ABI tag. That slot comes after the
        `PT_LOAD`s, which keeps them ascending, as the loaders require."""
        ph = self.phdrs()
        loads = [p for p in ph if p["type"] == PT_LOAD]
        abi = self.section(".note.ABI-tag")
        spare = [p for p in ph if p["type"] == PT_GNU_SFRAME] or [
            p for p in ph if p["type"] == PT_NOTE and not (abi and p["offset"] <= abi["offset"] < p["offset"] + p["filesz"])
        ]
        spare = [p for p in spare if p["i"] > loads[-1]["i"]]
        if not spare:
            raise ValueError("no program header to spare for a new segment")
        slot = spare[-1]
        al = max(p["align"] for p in loads)
        va = _align(max(p["vaddr"] + p["memsz"] for p in loads), al)
        off = self.append(data, al)
        slot.update(type=PT_LOAD, flags=4, offset=off, vaddr=va, paddr=va, filesz=len(data), memsz=len(data), align=al)
        self.write_phdr(slot)
        return va, off

    def save(self, path: str):
        with open(path, "wb") as fh:
            fh.write(self.b)
        os.chmod(path, 0o755)


# --- .eh_frame ---------------------------------------------------------------


def _uleb(b: bytes, p: int) -> tuple:
    v = s = 0
    while True:
        c = b[p]
        p += 1
        v |= (c & 0x7F) << s
        s += 7
        if not c & 0x80:
            return v, p


@dataclass
class Cie:
    raw: bytes  # the whole record, length field included
    has_z: bool


@dataclass
class Fde:
    cie: Cie
    start: int
    length: int
    rest: bytes  # the augmentation data and the call-frame instructions


def _parse_cie(raw: bytes) -> Cie:
    # raw[0:4] length, raw[4:8] id 0, then version, augmentation, ...
    aug_end = raw.index(0, 9)
    aug = raw[9:aug_end].decode()
    p = aug_end + 1
    _, p = _uleb(raw, p)  # code alignment
    _, p = _uleb(raw, p)  # data alignment: only its extent matters here
    if raw[8] == 1:
        p += 1
    else:
        _, p = _uleb(raw, p)
    enc = 0
    if aug.startswith("z"):
        _, p = _uleb(raw, p)
        for ch in aug[1:]:
            if ch == "R":
                enc = raw[p]
                p += 1
            elif ch in "SB":
                pass
            else:
                raise ValueError(f"CIE augmentation {aug!r}: its pointers would need relocating")
    if enc != _FDE_ENC_PCREL_SDATA4:
        raise ValueError(f"CIE FDE encoding {enc:#x}: not the pcrel sdata4 this editor writes")
    return Cie(raw, aug.startswith("z"))


def read_eh(elf: Elf) -> list:
    """Every record of `.eh_frame` in order, up to its terminator."""
    sec = elf.section(".eh_frame")
    data = elf.bytes_of(sec)
    out, cies = [], {}
    off = 0
    while off + 4 <= len(data):
        n = struct.unpack_from("<I", data, off)[0]
        if n == 0:
            break
        if n == 0xFFFFFFFF:
            raise ValueError("64-bit DWARF length")
        body = off + 4
        ident = struct.unpack_from("<I", data, body)[0]
        if ident == 0:
            c = _parse_cie(data[off:body + n])
            cies[off] = c
            out.append(c)
        else:
            cie = cies[body - ident]
            field_va = sec["addr"] + body + 4
            start = field_va + struct.unpack_from("<i", data, body + 4)[0]
            length = struct.unpack_from("<I", data, body + 8)[0]
            out.append(Fde(cie, start, length, data[body + 12:body + n]))
        off = body + n
    return out


def false_fde(cie: Cie, start: int, length: int) -> Fde:
    """A record stating nothing but its range: a zero-length augmentation and
    `DW_CFA_nop`s to the record alignment the linker keeps (24 bytes)."""
    rest = (b"\0" if cie.has_z else b"") + b"\0" * (7 if cie.has_z else 8)
    return Fde(cie, start, length, rest)


def _serialize_eh(records: list, va: int) -> tuple:
    """The section's bytes at `va`, and (start, record address) per FDE."""
    out = bytearray()
    where, table = {}, []
    for r in records:
        off = len(out)
        if isinstance(r, Cie):
            where[id(r)] = off
            out += r.raw
            continue
        body = off + 4
        pc = r.start - (va + body + 4)
        out += struct.pack("<IIiI", 4 + 4 + 4 + len(r.rest), body - where[id(r.cie)], pc, r.length)
        out += r.rest
        table.append((r.start, va + off))
    out += b"\0\0\0\0"
    return bytes(out), table


def _serialize_hdr(table: list, hdr_va: int, eh_va: int) -> bytes:
    """`.eh_frame_hdr` as `ld` writes it: pcrel pointer, udata4 count, a sorted
    datarel table."""
    out = struct.pack("<BBBBiI", 1, 0x1B, 0x03, 0x3B, eh_va - (hdr_va + 4), len(table))
    for start, fde_va in sorted(table):
        out += struct.pack("<ii", start - hdr_va, fde_va - hdr_va)
    return out


def write_eh(elf: Elf, records: list):
    """The records back into the image: in place where they fit, otherwise both
    sections moved to a segment of their own (`.eh_frame` is followed by other
    sections, and its `.eh_frame_hdr` table cannot grow where it is either)."""
    eh, hdr = elf.section(".eh_frame"), elf.section(".eh_frame_hdr")
    new_eh, table = _serialize_eh(records, eh["addr"])
    new_hdr = _serialize_hdr(table, hdr["addr"], eh["addr"])
    if len(new_eh) > eh["size"] or len(new_hdr) > hdr["size"]:
        # The whole new block: a header, then the records 8-aligned behind it.
        room = _align(len(new_hdr), 8)
        al = max(p["align"] for p in elf.phdrs() if p["type"] == PT_LOAD)
        va_guess = _align(max(p["vaddr"] + p["memsz"] for p in elf.phdrs() if p["type"] == PT_LOAD), al)
        new_eh, table = _serialize_eh(records, va_guess + room)
        new_hdr = _serialize_hdr(table, va_guess, va_guess + room)
        va, off = elf.new_load_segment(new_hdr.ljust(room, b"\0") + new_eh)
        if va != va_guess:
            raise ValueError("the new segment did not land where its contents were computed for")
        for s in (eh, hdr):
            elf.b[s["offset"]:s["offset"] + s["size"]] = b"\0" * s["size"]
        hdr.update(addr=va, offset=off, size=len(new_hdr))
        eh.update(addr=va + room, offset=off + room, size=len(new_eh))
    else:
        for s in (eh, hdr):
            elf.b[s["offset"]:s["offset"] + s["size"]] = b"\0" * s["size"]
        elf.b[eh["offset"]:eh["offset"] + len(new_eh)] = new_eh
        elf.b[hdr["offset"]:hdr["offset"] + len(new_hdr)] = new_hdr
        eh["size"], hdr["size"] = len(new_eh), len(new_hdr)
    elf.update_section(eh)
    elf.update_section(hdr)
    for p in elf.phdrs():
        if p["type"] == PT_GNU_EH_FRAME:
            p.update(offset=hdr["offset"], vaddr=hdr["addr"], paddr=hdr["addr"], filesz=hdr["size"], memsz=hdr["size"])
            elf.write_phdr(p)


# --- symbols -----------------------------------------------------------------


def write_symtab(elf: Elf, entries: list, strtab: bytes, first_global: int):
    """`.symtab` and `.strtab` as given, past the end of the file: neither is
    mapped, so nothing else moves. `entries`: the packed symbols, in order."""
    sym, st = elf.section(".symtab"), elf.section(".strtab")
    blob = b"".join(entries)
    sym.update(offset=elf.append(blob), size=len(blob), info=first_global)
    st.update(offset=elf.append(strtab, 1), size=len(strtab))
    elf.update_section(sym)
    elf.update_section(st)


def only_these_symbols(elf: Elf, syms: list):
    """A symbol table holding nothing else: the lie alone, no second symbol to
    contradict it. `syms`: (name, value, size)."""
    text = elf.section_index(".text")
    strtab = bytearray(b"\0")
    entries = [_SYM.pack(0, 0, 0, 0, 0, 0)]
    for name, value, size in syms:
        entries.append(_SYM.pack(len(strtab), _STT_FUNC_GLOBAL, 0, text, value, size))
        strtab += name.encode() + b"\0"
    write_symtab(elf, entries, bytes(strtab), 1)


def add_symbols(elf: Elf, syms: list):
    """The file's whole table, and these after it."""
    sym, st = elf.section(".symtab"), elf.section(".strtab")
    text = elf.section_index(".text")
    old = elf.bytes_of(sym)
    entries = [old[i:i + _SYM.size] for i in range(0, len(old), _SYM.size)]
    strtab = bytearray(elf.bytes_of(st))
    for name, value, size in syms:
        entries.append(_SYM.pack(len(strtab), _STT_FUNC_GLOBAL, 0, text, value, size))
        strtab += name.encode() + b"\0"
    write_symtab(elf, entries, bytes(strtab), sym["info"])


def set_symbol_sizes(elf: Elf, sizes: dict):
    """In place: `value -> st_size` for the `STT_FUNC` entries at those values."""
    sym = elf.section(".symtab")
    done = set()
    for off in range(sym["offset"], sym["offset"] + sym["size"], _SYM.size):
        name, info, other, shndx, value, size = _SYM.unpack_from(elf.b, off)
        if info & 0xF == 2 and value in sizes:
            _SYM.pack_into(elf.b, off, name, info, other, shndx, value, sizes[value])
            done.add(value)
    if done != set(sizes):
        raise ValueError(f"no STT_FUNC at {sorted(set(sizes) - done)}")


def swap_exports(elf: Elf, pairs: list):
    """Swap value and size between `.dynsym` entries named by `pairs`: each name
    now answers for the other's code. The name stays in its slot, so `.gnu.hash`
    still finds it."""
    sym, st = elf.section(".dynsym"), elf.section(".dynstr")
    strs = elf.bytes_of(st)
    at = {}
    for off in range(sym["offset"], sym["offset"] + sym["size"], _SYM.size):
        n = _SYM.unpack_from(elf.b, off)[0]
        at[strs[n:strs.index(0, n)].decode()] = off
    for a, b in pairs:
        ea, eb = list(_SYM.unpack_from(elf.b, at[a])), list(_SYM.unpack_from(elf.b, at[b]))
        ea[4], eb[4] = eb[4], ea[4]
        ea[5], eb[5] = eb[5], ea[5]
        _SYM.pack_into(elf.b, at[a], *ea)
        _SYM.pack_into(elf.b, at[b], *eb)


# --- what a lie reads from the file before tampering -------------------------


@dataclass
class Target:
    """A function the truth knows, with an FDE stating exactly its extent."""

    start: int
    end: int
    name: str
    boundary: int  # a true instruction boundary inside it, near the middle
    mid_insn: int  # an address inside a multi-byte instruction, near the middle
    next_start: int | None = None
    next_end: int | None = None


@dataclass
class Before:
    arch: str
    truth_file: str
    stripped: str
    targets: list = field(default_factory=list)
    fdes: list = field(default_factory=list)


def _insn_near_middle(addrs: list, ins: dict, lo: int, hi: int, arch: str) -> tuple:
    body = addrs[bisect.bisect_left(addrs, lo):bisect.bisect_left(addrs, hi)]
    if len(body) < 2:
        return None, None
    mid = (lo + hi) // 2
    boundary = min(body[1:], key=lambda a: abs(a - mid))
    multi = [a for a in body if ins[a][0] >= 2]
    if not multi:
        return None, None
    # On a variable-length ISA one byte in is inside the instruction. On AArch64
    # no address is both inside an instruction and a place a decoder can start:
    # two bytes in is the same edit, as a misaligned start.
    inside = min(multi, key=lambda a: abs(a - mid)) + (2 if arch == "aarch64" else 1)
    return boundary, inside


def read_before(arch: str, truth: dict, truth_file: str, stripped: str) -> Before:
    ins = readers.instructions(truth_file)
    addrs = sorted(ins)
    fdes = readers.fde_ranges(stripped)
    stated = {lo: hi for sec, lo, hi in fdes if sec == ".eh_frame"}
    funcs = sorted((f for f in truth["functions"] if f["tier"] == "dwarf" and f["end"]), key=lambda f: f["start"])
    b = Before(arch, truth_file, stripped, fdes=fdes)
    for i, f in enumerate(funcs):
        if stated.get(f["start"]) != f["end"]:
            continue
        boundary, inside = _insn_near_middle(addrs, ins, f["start"], f["end"], arch)
        if boundary is None:
            continue
        t = Target(f["start"], f["end"], (f["dwarf_names"] or [f"f_{f['start']:x}"])[0], boundary, inside)
        if i + 1 < len(funcs):
            nxt = funcs[i + 1]
            if stated.get(nxt["start"]) == nxt["end"]:
                t.next_start, t.next_end = nxt["start"], nxt["end"]
        b.targets.append(t)
    return b


def _chosen(items: list, intensity: float) -> list:
    keep = chosen_indices(len(items), intensity)
    return [x for n, x in enumerate(items) if n in keep]


# --- the lies ----------------------------------------------------------------
#
# A lie: (Before, intensity, out path) -> planted records. A record states the
# function it touched, the address the lie is about (`site`), and what `verify`
# must find: `fde_added`, `fde_removed`, `sym`. Every number is in the record, so
# the scorer never re-derives what was done.


def _edit_fdes(b: Before, out: str, intensity: float, edit, need_next: bool = False) -> list:
    """`edit(target, fde) -> (records replacing the FDE, planted record)`, on the
    chosen functions of those whose extent an FDE states exactly."""
    elf = Elf(b.stripped)
    records = read_eh(elf)
    targets = [t for t in b.targets if t.next_start is not None] if need_next else b.targets
    chosen = {t.start: t for t in _chosen(targets, intensity)}
    planted, new = [], []
    for r in records:
        t = chosen.get(r.start) if isinstance(r, Fde) else None
        if t is None:
            new.append(r)
            continue
        replacement, rec = edit(t, r)
        new += replacement
        rec.update(function=t.start, end=t.end, name=t.name)
        planted.append(rec)
    write_eh(elf, new)
    elf.save(out)
    return planted


def fde_add(b: Before, intensity: float, out: str) -> list:
    """A second FDE from inside the function to its end; the real one stays."""

    def edit(t, r):
        extra = false_fde(r.cie, t.boundary, t.end - t.boundary)
        return [r, extra], {"site": t.boundary, "fde_added": [[t.boundary, t.end]], "fde_removed": []}

    return _edit_fdes(b, out, intensity, edit)


def fde_split(b: Before, intensity: float, out: str) -> list:
    """The function's FDE cut in two at an instruction boundary: every byte is
    covered exactly once, so no two claims overlap."""

    def edit(t, r):
        r2 = Fde(r.cie, r.start, t.boundary - t.start, r.rest)
        extra = false_fde(r.cie, t.boundary, t.end - t.boundary)
        return [r2, extra], {"site": t.boundary, "fde_added": [[t.start, t.boundary], [t.boundary, t.end]], "fde_removed": [[t.start, t.end]]}

    return _edit_fdes(b, out, intensity, edit)


def fde_repoint(b: Before, intensity: float, out: str) -> list:
    """The FDE's start moved inside the function: the real start loses its entry."""

    def edit(t, r):
        r2 = Fde(r.cie, t.boundary, t.end - t.boundary, r.rest)
        return [r2], {"site": t.boundary, "fde_added": [[t.boundary, t.end]], "fde_removed": [[t.start, t.end]]}

    return _edit_fdes(b, out, intensity, edit)


def fde_long(b: Before, intensity: float, out: str) -> list:
    """The range runs on over the whole of the next function."""

    def edit(t, r):
        r2 = Fde(r.cie, r.start, t.next_end - t.start, r.rest)
        return [r2], {"site": t.next_start, "next_end": t.next_end, "fde_added": [[t.start, t.next_end]], "fde_removed": [[t.start, t.end]]}

    return _edit_fdes(b, out, intensity, edit, need_next=True)


def fde_short(b: Before, intensity: float, out: str) -> list:
    """The range stops at an instruction boundary inside the function."""

    def edit(t, r):
        r2 = Fde(r.cie, r.start, t.boundary - t.start, r.rest)
        return [r2], {"site": t.boundary, "fde_added": [[t.start, t.boundary]], "fde_removed": [[t.start, t.end]]}

    return _edit_fdes(b, out, intensity, edit)


def _objcopy(arch: str, *argv: str):
    tool = corpus.ARCHES[arch].strip.replace("strip", "objcopy")
    subprocess.run([tool, *argv], check=True, env=corpus.TOOL_ENV)


_NO_UNWIND = ("--remove-section", ".eh_frame", "--remove-section", ".eh_frame_hdr")


def _sym_base(b: Before, out: str) -> str:
    """The file with its symbol table and no DWARF: a reader gets what the table
    says, not what the debug information would correct it with."""
    _objcopy(b.arch, "--strip-debug", b.truth_file, out)
    return out


def _false_syms(b: Before, intensity: float) -> list:
    return [(t, f"lie_{t.mid_insn:x}", t.mid_insn, t.end - t.mid_insn) for t in _chosen(b.targets, intensity)]


def _sym_records(chosen: list) -> list:
    return [{"function": t.start, "end": t.end, "name": t.name, "site": v, "sym": [[n, v, s]]} for t, n, v, s in chosen]


def sym_mid(b: Before, intensity: float, out: str) -> list:
    """Symbols in the middle of an instruction, and no other symbol."""
    elf = Elf(_sym_base(b, out))
    chosen = _false_syms(b, intensity)
    only_these_symbols(elf, [(n, v, s) for _, n, v, s in chosen])
    elf.save(out)
    return _sym_records(chosen)


def sym_mid_full(b: Before, intensity: float, out: str) -> list:
    """The same symbols added to the file's whole table."""
    elf = Elf(_sym_base(b, out))
    chosen = _false_syms(b, intensity)
    add_symbols(elf, [(n, v, s) for _, n, v, s in chosen])
    elf.save(out)
    return _sym_records(chosen)


def sym_mid_noeh(b: Before, intensity: float, out: str) -> list:
    """A combination, labelled as one: `sym_mid` with the unwind tables gone, so no
    FDE contradicts the symbol. What FOLLOWUPS 21(a) pinned as a symbol alone."""
    _sym_base(b, out)
    _objcopy(b.arch, *_NO_UNWIND, out)
    elf = Elf(out)
    chosen = _false_syms(b, intensity)
    only_these_symbols(elf, [(n, v, s) for _, n, v, s in chosen])
    elf.save(out)
    return _sym_records(chosen)


def _long_sizes(b: Before, intensity: float) -> list:
    targets = [t for t in b.targets if t.next_start is not None]
    return [(t, t.name, t.start, t.next_end - t.start) for t in _chosen(targets, intensity)]


def _size_records(chosen: list) -> list:
    return [{"function": t.start, "end": t.end, "name": t.name, "site": t.next_start, "next_end": t.next_end, "sym": [[n, v, s]]} for t, n, v, s in chosen]


def sym_size(b: Before, intensity: float, out: str) -> list:
    """The file's own symbols, with sizes running over the next function."""
    elf = Elf(_sym_base(b, out))
    chosen = _long_sizes(b, intensity)
    set_symbol_sizes(elf, {v: s for _, _, v, s in chosen})
    elf.save(out)
    return _size_records(chosen)


def sym_size_alone(b: Before, intensity: float, out: str) -> list:
    """Only the symbols that lie, so the next function's own symbol cannot speak;
    its FDE still can."""
    elf = Elf(_sym_base(b, out))
    chosen = _long_sizes(b, intensity)
    only_these_symbols(elf, [(n, v, s) for _, n, v, s in chosen])
    elf.save(out)
    return _size_records(chosen)


def sym_size_noeh(b: Before, intensity: float, out: str) -> list:
    """A combination, labelled as one: `sym_size_alone` with the unwind tables
    gone too, which is the only way a real compile reaches the hiding FOLLOWUPS
    21(a) pinned on a planted image: nothing else declares the next function."""
    _sym_base(b, out)
    _objcopy(b.arch, *_NO_UNWIND, out)
    elf = Elf(out)
    chosen = _long_sizes(b, intensity)
    only_these_symbols(elf, [(n, v, s) for _, n, v, s in chosen])
    elf.save(out)
    return _size_records(chosen)


def noeh(b: Before, intensity: float, out: str) -> list:
    """Unwind tables gone. At full intensity both sections, by `objcopy`. At a
    share, `objcopy` has nothing to offer: the chosen functions' FDEs are dropped
    by this editor and the sections stay."""
    if intensity >= 1.0:
        _objcopy(b.arch, *_NO_UNWIND, b.stripped, out)
        return [{"function": t.start, "end": t.end, "name": t.name, "site": t.start, "whole_table": True} for t in b.targets]

    def edit(t, r):
        return [], {"site": t.start, "fde_added": [], "fde_removed": [[t.start, t.end]]}

    return _edit_fdes(b, out, intensity, edit)


def _exportable(b: Before) -> list:
    """Exported functions the truth knows, except `main`: the driver calls that
    one by name. The library is linked `-Bsymbolic`, so nothing else binds through
    `.dynsym` and the program's behaviour is the check of that."""
    dyn = [s for s in readers.symbols(b.stripped) if s["table"] == ".dynsym" and s["type"] == "FUNC" and s["ndx"] != "UND" and s["name"] != "main"]
    known = {t.start: t for t in b.targets}
    return sorted(((s["name"], known[s["value"]]) for s in dyn if s["value"] in known), key=lambda x: x[1].start)


def _exports(b: Before, intensity: float, base: str, out: str) -> list:
    elf = Elf(base)
    chosen = _chosen(_exportable(b), intensity)
    pairs = list(zip(chosen[0::2], chosen[1::2]))
    swap_exports(elf, [(a[0], c[0]) for a, c in pairs])
    elf.save(out)
    planted = []
    for (na, ta), (nb, tb) in pairs:
        planted.append({"function": ta.start, "end": ta.end, "name": na, "site": ta.start, "lying_name": nb, "export_value": {nb: ta.start, na: tb.start}, "sizes": {nb: ta.end - ta.start, na: tb.end - tb.start}})
        planted.append({"function": tb.start, "end": tb.end, "name": nb, "site": tb.start, "lying_name": na, "export_value": {}, "sizes": {}})
    return planted


def exports(b: Before, intensity: float, out: str) -> list:
    """Names swapped in `.dynsym` of a stripped shared object: the table is alone."""
    return _exports(b, intensity, b.stripped, out)


def exports_sym(b: Before, intensity: float, out: str) -> list:
    """The same with `.symtab` kept, whose names are the true ones: a second source."""
    return _exports(b, intensity, _sym_base(b, out), out)


def identity_stripped(b: Before, intensity: float, out: str) -> list:
    """The control of the lies that keep a symbol table: no edit."""
    _sym_base(b, out)
    return []


LIES = {
    "fde_add": fde_add, "fde_split": fde_split, "fde_repoint": fde_repoint, "fde_long": fde_long, "fde_short": fde_short,
    "sym_mid": sym_mid, "sym_mid_full": sym_mid_full, "sym_size": sym_size, "sym_size_alone": sym_size_alone, "sym_size_noeh": sym_size_noeh, "sym_mid_noeh": sym_mid_noeh,
    "noeh": noeh, "exports": exports, "exports_sym": exports_sym, "identity_sym": identity_stripped,
}


# --- the check that the edit happened ----------------------------------------


def verify(after: str, before_stripped: str, truth_file: str, planted: list, lie: str) -> list:
    """What `readelf` says about the tampered file against what was planted.
    Returns the failures; an empty list on a lie that planted nothing is only
    allowed for the control."""
    bad = []
    if not planted and lie != "identity_sym":
        bad.append("nothing planted")
    same, _, _ = readers.same_code(after, truth_file)
    if not same:
        bad.append("code differs from the file before tampering")
    if any(r.get("whole_table") for r in planted):
        names = {s["name"] for s in readers.sections(after)}
        if names & {".eh_frame", ".eh_frame_hdr"}:
            bad.append(f"unwind sections still there: {sorted(names & {'.eh_frame', '.eh_frame_hdr'})}")
        if readers.fde_ranges(after):
            bad.append("readelf still reads FDEs")
    wants_fde = [r for r in planted if "fde_added" in r]
    if wants_fde:
        was = {(lo, hi) for sec, lo, hi in readers.fde_ranges(before_stripped) if sec == ".eh_frame"}
        now = {(lo, hi) for sec, lo, hi in readers.fde_ranges(after) if sec == ".eh_frame"}
        added = {tuple(x) for r in wants_fde for x in r["fde_added"]}
        removed = {tuple(x) for r in wants_fde for x in r["fde_removed"]}
        if now - was != added - was:
            bad.append(f"FDEs added: readelf {sorted(now - was)[:4]} against planted {sorted(added - was)[:4]}")
        if was - now != removed - added:
            bad.append(f"FDEs removed: readelf {sorted(was - now)[:4]} against planted {sorted(removed - added)[:4]}")
    wants_sym = [x for r in planted for x in r.get("sym", [])]
    if wants_sym or "export_value" in (planted[0] if planted else {}):
        syms = readers.symbols(after)
        tab = {(s["name"], s["value"], s["size"]) for s in syms if s["table"] == ".symtab" and s["type"] == "FUNC"}
        for n, v, sz in wants_sym:
            if (n, v, sz) not in tab:
                bad.append(f"symbol {n} {v:#x}+{sz} not in .symtab")
        dyn = {(s["name"], s["value"], s["size"]) for s in syms if s["table"] == ".dynsym"}
        for r in planted:
            for n, v in r.get("export_value", {}).items():
                if (n, v, r["sizes"][n]) not in dyn:
                    bad.append(f"export {n} is not {v:#x} in .dynsym")
    return bad

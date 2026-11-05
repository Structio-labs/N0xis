# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The independent readers: everything the instrument knows about an image
that does not come from n0xis.

`readelf -SW` (sections), `readelf -sW` (symbol tables), `llvm-dwarfdump
--debug-info` (functions), `objdump -d` (PLT labels, and the bytes shown beside
a reported wrong answer). Each parser here is the only one of its kind in the
instrument, so the truth and the byte checks read an image one way.

A PE (mingw's, with DWARF) gets the same answers from the tools that read one:
the mingw `objdump -h` and `nm`, `llvm-readobj --coff-exports`; `llvm-dwarfdump`
reads its DWARF as it does an ELF's. An image's first bytes say which.
"""

from __future__ import annotations

import hashlib
import re
import subprocess

from corpus import TOOL_ENV


def run(argv: list, timeout: int = 540) -> str:
    return subprocess.run(argv, env=TOOL_ENV, check=True, capture_output=True, text=True, timeout=timeout).stdout


# --- sections ---------------------------------------------------------------

def is_pe(path: str) -> bool:
    with open(path, "rb") as fh:
        return fh.read(2) == b"MZ"


def _mingw(path: str, tool: str) -> str:
    """The mingw binutils of a PE's machine (`IMAGE_FILE_HEADER.Machine`)."""
    with open(path, "rb") as fh:
        head = fh.read(4096)
    lfanew = int.from_bytes(head[0x3C:0x40], "little")
    machine = int.from_bytes(head[lfanew + 4:lfanew + 6], "little")
    return {0x8664: "x86_64-w64-mingw32-", 0x14C: "i686-w64-mingw32-"}[machine] + tool


def _pe_sections(path: str) -> list:
    out = []
    for m in re.finditer(r"^\s*\d+\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)\s+\S+\s+(.*)$", run([_mingw(path, "objdump"), "-h", "-w", path]), re.M):
        flags = m.group(5)
        out.append({
            "name": m.group(1), "type": "PROGBITS" if "CONTENTS" in flags else "NOBITS", "addr": int(m.group(3), 16),
            "offset": int(m.group(4), 16), "size": int(m.group(2), 16), "entsize": 0, "flags": "X" if "CODE" in flags else "",
        })
    return out


def _pe_symbols(path: str) -> list:
    """The COFF symbol table as `nm` reads it (no sizes: COFF has none) under
    `.symtab`, and the export table under `.dynsym`, what a stripped PE keeps."""
    out = []
    for line in run([_mingw(path, "nm"), path]).splitlines():
        m = re.match(r"([0-9a-f]+) (\S) (.+)$", line)
        if not m:
            continue
        kind = m.group(2)
        name = m.group(3)
        out.append({
            "table": ".symtab", "name": name, "value": int(m.group(1), 16), "size": 0,
            "type": "SECTION" if name.startswith(".") else "FUNC" if kind in "Tt" else "OBJECT", "bind": "GLOBAL" if kind.isupper() else "LOCAL",
            "ndx": "ABS" if kind in "Aa" else "TEXT",
        })
    text = run(["llvm-readobj", "--file-headers", "--coff-exports", path])
    base = re.search(r"ImageBase:\s+(0x[0-9A-Fa-f]+)", text)
    for m in re.finditer(r"Export \{\s*Ordinal: \d+\s*Name: (\S*)\s*RVA: (0x[0-9A-Fa-f]+)", text):
        out.append({"table": ".dynsym", "name": m.group(1), "value": int(base.group(1), 16) + int(m.group(2), 16), "size": 0, "type": "FUNC", "bind": "GLOBAL", "ndx": "TEXT"})
    return out


def sections(path: str) -> list:
    """Every section header: name, type, addr, offset, size, flags."""
    if is_pe(path):
        return _pe_sections(path)
    out = []
    for line in run(["readelf", "-SW", path]).splitlines():
        m = re.match(r"\s*\[\s*(\d+)\]\s+(.*)$", line)
        if not m or m.group(1) == "0":
            continue
        f = m.group(2).split()
        if len(f) < 9 or not re.fullmatch(r"[0-9a-f]+", f[2]):
            continue  # the header row, or a name with a space (none here)
        flags = f[6] if len(f) == 10 else ""
        out.append({
            "name": f[0], "type": f[1], "addr": int(f[2], 16), "offset": int(f[3], 16),
            "size": int(f[4], 16), "entsize": int(f[5], 16), "flags": flags,
        })
    return out


def exec_sections(path: str) -> list:
    """Code sections with their bytes' digest: the identity two builds must
    share before one's truth is used for the other."""
    out = []
    with open(path, "rb") as fh:
        data = fh.read()
    for s in sections(path):
        if "X" not in s["flags"] or s["type"] == "NOBITS":
            continue
        body = data[s["offset"]:s["offset"] + s["size"]]
        out.append({"name": s["name"], "addr": s["addr"], "size": s["size"], "sha256": hashlib.sha256(body).hexdigest()})
    return out


def same_code(a: str, b: str) -> tuple:
    """(identical, a's code sections, b's): names, addresses, sizes and bytes."""
    sa, sb = exec_sections(a), exec_sections(b)
    return sa == sb, sa, sb


# --- symbols ----------------------------------------------------------------

def symbols(path: str) -> list:
    """Every `.symtab` and `.dynsym` entry with a value: table, name, value,
    size, type, bind, section index."""
    if is_pe(path):
        return _pe_symbols(path)
    out = []
    table = None
    for line in run(["readelf", "-sW", path]).splitlines():
        m = re.match(r"Symbol table '(\.\w+)'", line)
        if m:
            table = m.group(1)
            continue
        m = re.match(r"\s*\d+:\s+([0-9a-f]+)\s+(\d+|0x[0-9a-f]+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(?:\[[^\]]*\]\s+)?(\S+)\s*(.*)$", line)
        if not m or table is None:
            continue
        name = m.group(7).strip()
        # `.dynsym` prints `name@VERSION` / `name@@VERSION`; the name is before it.
        bare = name.split("@")[0] if table == ".dynsym" else name
        size = int(m.group(2), 0)
        out.append({
            "table": table, "name": bare, "value": int(m.group(1), 16), "size": size,
            "type": m.group(3), "bind": m.group(4), "ndx": m.group(6),
        })
    return out


# --- DWARF ------------------------------------------------------------------

_DIE = re.compile(r"^0x([0-9a-f]+):\s+(DW_TAG_\w+|NULL)")
_ATTR = re.compile(r"^\s+(DW_AT_\w+)\s+\((.*)$")
_RANGE = re.compile(r"\[0x([0-9a-f]+), 0x([0-9a-f]+)\)")


def subprograms(path: str) -> list:
    """Every `DW_TAG_subprogram` that has code: its ranges and its entry.

    The entry is `DW_AT_entry_pc` when stated, else `DW_AT_low_pc`, else the
    first range listed (the order the compiler wrote; for a function split into
    a hot and a cold part, the hot part first). A declaration, or an abstract
    instance of an inline function, has no address and is not a function with
    code; a concrete out-of-line instance (`abstract_origin` with an address)
    is one.

    `noreturn`: the compiler's `DW_AT_noreturn`, on the DIE itself or on the
    DIE its `abstract_origin`/`specification` names (where an out-of-line copy
    of an inlined function keeps its attributes).
    """
    text = run(["llvm-dwarfdump", "--debug-info", path], timeout=540)
    out = []
    cur = None  # (offset, tag, attrs) of the DIE being read
    last_attr = None
    noreturn_dies: set = set()

    def flush():
        if cur is None or cur[1] != "DW_TAG_subprogram":
            return
        a = cur[2]
        if "DW_AT_noreturn" in a:
            noreturn_dies.add(cur[0])
        ranges = []
        lo = a.get("DW_AT_low_pc")
        hi = a.get("DW_AT_high_pc")
        if lo is not None and hi is not None:
            lo_v = int(lo.split(")")[0], 16)
            hv = hi.split(")")[0]
            hi_v = int(hv, 16)
            # llvm-dwarfdump prints the absolute end; a bare offset would be
            # smaller than the start, and is added to it.
            if hi_v < lo_v:
                hi_v = lo_v + hi_v
            ranges.append((lo_v, hi_v))
        if "ranges" in a:
            ranges += a["ranges"]
        if not ranges:
            return
        entry = None
        if "DW_AT_entry_pc" in a:
            entry = int(a["DW_AT_entry_pc"].split(")")[0], 16)
        elif lo is not None:
            entry = int(lo.split(")")[0], 16)
        else:
            entry = ranges[0][0]
        name = a.get("DW_AT_linkage_name") or a.get("DW_AT_name") or a.get("DW_AT_abstract_origin") or a.get("DW_AT_specification")
        origins = [int(m.group(1), 16) for k in ("DW_AT_abstract_origin", "DW_AT_specification") if k in a for m in [re.match(r"0x([0-9a-f]+)", a[k])] if m]
        out.append({"entry": entry, "ranges": ranges, "name": _quoted(name), "die": cur[0], "origins": origins})

    for line in text.splitlines():
        m = _DIE.match(line)
        if m:
            flush()
            cur = (int(m.group(1), 16), m.group(2), {})
            last_attr = None
            continue
        if cur is None:
            continue
        m = _ATTR.match(line)
        if m:
            last_attr = m.group(1)
            cur[2][last_attr] = m.group(2)
            if last_attr == "DW_AT_ranges":
                cur[2]["ranges"] = [(int(x, 16), int(y, 16)) for x, y in _RANGE.findall(m.group(2))]
            continue
        if last_attr == "DW_AT_ranges":
            r = _RANGE.findall(line)
            if r:
                cur[2]["ranges"] += [(int(x, 16), int(y, 16)) for x, y in r]
                continue
        if line.strip() == "":
            last_attr = None
    flush()
    for sp in out:
        sp["noreturn"] = sp["die"] in noreturn_dies or any(o in noreturn_dies for o in sp["origins"])
    return out


def _quoted(v):
    if v is None:
        return None
    m = re.search(r'"(.*)"', v)
    return m.group(1) if m else v


# --- objdump ----------------------------------------------------------------

def objdump_for(path: str) -> str:
    """GNU objdump for the image's machine: the host build reads x86 only, so
    an AArch64 image goes to the cross binutils' objdump, and a PE to mingw's."""
    if is_pe(path):
        return _mingw(path, "objdump")
    machine = re.search(r"Machine:\s+(.*)", run(["readelf", "-h", path]))
    return "aarch64-linux-gnu-objdump" if machine and "AArch64" in machine.group(1) else "objdump"


def plt_labels(path: str, plt_names: list) -> dict:
    """`objdump -d`'s labels in the PLT sections: address -> `name@plt`. objdump
    synthesises them from the relocations, which makes them a reading of the
    image that is not the engine's."""
    out = {}
    for sec in plt_names:
        try:
            text = run([objdump_for(path), "-d", "-j", sec, path])
        except subprocess.CalledProcessError:
            continue
        for m in re.finditer(r"^([0-9a-f]+) <([^>]+)>:", text, re.M):
            # `<puts@plt-0x10>` is objdump placing an unlabelled address (the
            # PLT's header) relative to the next label: not a label.
            # `<.plt>` is a section's own start, named after the section.
            if re.search(r"[+-]0x[0-9a-f]+$", m.group(2)) or m.group(2).startswith("."):
                continue
            out[int(m.group(1), 16)] = m.group(2)
    return out


def disasm_around(path: str, va: int, before: int = 24, after: int = 24) -> str:
    """objdump's reading of the bytes around `va` (rung 3), for showing a
    reported wrong answer is wrong by the bytes, not by the instrument."""
    lo = max(0, va - before)
    try:
        text = run([objdump_for(path), "-d", "--insn-width=15", f"--start-address={lo:#x}", f"--stop-address={va + after:#x}", path])
    except subprocess.CalledProcessError as e:
        return f"objdump failed: {e}"
    lines = [ln for ln in text.splitlines() if re.match(r"\s*[0-9a-f]+:\s", ln) or re.match(r"^[0-9a-f]+ <", ln)]
    return "\n".join(lines)


def fde_ranges(path: str) -> list:
    """`readelf --debug-dump=frames`' FDE ranges in `.eh_frame` (and
    `.debug_frame` when present): (section, start, end). How many FDEs the
    measured file carries is what decides which rules have work to do."""
    out = []
    try:
        text = run([_mingw(path, "objdump"), "--dwarf=frames", path]) if is_pe(path) else run(["readelf", "--debug-dump=frames", path])
    except subprocess.CalledProcessError:
        return out
    section = None
    for line in text.splitlines():
        m = re.match(r"Contents of the (\S+) section", line)
        if m:
            section = m.group(1).rstrip(":")
            continue
        m = re.search(r"FDE cie=[0-9a-f]+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m:
            out.append((section, int(m.group(1), 16), int(m.group(2), 16)))
    return out


def instructions(path: str) -> dict:
    """objdump's linear disassembly of every code section: address ->
    (length, text). `--insn-width=15` keeps an instruction's bytes on one line
    (a wrapped row would read as a second, shorter instruction)."""
    out = {}
    text = run([objdump_for(path), "-d", "--insn-width=15", path], timeout=540)
    # x86 rows print bytes (`48 83 ec 08`), AArch64 rows one 32-bit word
    # (`d503233f`): the length is the hex digits over two either way.
    for m in re.finditer(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2,8} ?)+)\s*\t?(.*)$", text, re.M):
        nbytes = sum(len(tok) // 2 for tok in m.group(2).split())
        out[int(m.group(1), 16)] = (nbytes, m.group(3).strip())
    return out

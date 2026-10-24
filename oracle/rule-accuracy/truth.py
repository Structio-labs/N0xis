#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The truth for one unstripped build, read with tools that are not n0xis.

Three tiers, each named in every result so a reader knows which rung a number
stands on:

  dwarf   rung 1. Every `DW_TAG_subprogram` with code (llvm-dwarfdump): its
          entry is a function start, the range holding the entry its extent.
          The other ranges of a split function (gcc's `.cold` parts) are
          fragments: code of a function, not a start of one.
  symtab  rung 3. A `.symtab` FUNC/IFUNC symbol in a code section whose
          address no DWARF range covers: the C runtime's objects and libgcc
          carry no DWARF (`_init`, `frame_dummy`, `__x86.get_pc_thunk.bx`, ...).
          Its extent is its `st_size` when non-zero.
  plt     rung 3. A label objdump synthesises in a PLT section (`puts@plt`),
          from the relocations. Its extent runs to the next label or the
          section's end.

Names: every `.symtab`/`.dynsym` name at an address, and the PLT labels; C++
names are compared demangled, by c++filt (not the engine's demangler).

Usage: truth.py <unstripped-file> <out.json>
"""

from __future__ import annotations

import bisect
import json
import subprocess
import sys

import corpus
import readers

PLT_SECTIONS = (".plt", ".plt.sec", ".plt.got", ".iplt")


def demangle(names: list, tool: str = "c++filt") -> dict:
    """A demangler's reading of each name (identity when it is not mangled):
    GNU `c++filt`, or `llvm-cxxfilt` — two independent implementations, so a
    name the engine spells as either one reads is not counted wrong on the
    word of one demangler where the two differ (a local name's return type)."""
    if not names:
        return {}
    r = subprocess.run([tool], input="\n".join(names) + "\n", env=corpus.TOOL_ENV, capture_output=True, text=True, check=True)
    out = r.stdout.splitlines()
    assert len(out) == len(names), f"{tool} returned a different number of lines"
    return dict(zip(names, out))


def truth(path: str) -> dict:
    secs = readers.sections(path)
    code = [s for s in secs if "X" in s["flags"] and s["type"] != "NOBITS"]
    plt = [s for s in code if s["name"] in PLT_SECTIONS]

    def in_code(va: int) -> bool:
        return any(s["addr"] <= va < s["addr"] + s["size"] for s in code)

    def in_plt(va: int) -> bool:
        return any(s["addr"] <= va < s["addr"] + s["size"] for s in plt)

    # --- dwarf tier
    subs = readers.subprograms(path)
    dropped = 0
    by_entry: dict = {}
    fragments: dict = {}
    all_ranges = []
    for sp in subs:
        if not in_code(sp["entry"]):
            dropped += 1  # a tombstone (a discarded COMDAT copy, a gc'd section)
            continue
        live = [(lo, hi) for lo, hi in sp["ranges"] if hi > lo and in_code(lo)]
        holding = [r for r in live if r[0] <= sp["entry"] < r[1]]
        if not holding:
            dropped += 1
            continue
        end = holding[0][1]
        f = by_entry.setdefault(sp["entry"], {"start": sp["entry"], "ends": set(), "tier": "dwarf", "dwarf_names": set(), "noreturn": False})
        f["ends"].add(end)
        f["noreturn"] = f["noreturn"] or sp["noreturn"]
        if sp["name"]:
            f["dwarf_names"].add(sp["name"])
        for lo, hi in live:
            all_ranges.append((lo, hi))
            if lo != sp["entry"] and not (lo <= sp["entry"] < hi):
                fragments[lo] = {"start": lo, "end": hi, "of": sp["entry"]}

    # A fragment that is also some function's entry is that function.
    for e in list(fragments):
        if e in by_entry:
            del fragments[e]

    all_ranges.sort()
    # The union of every function's code, as disjoint intervals: two functions
    # can list one range (a shared cold part), so the raw list may overlap.
    merged: list = []
    for lo, hi in all_ranges:
        if merged and lo <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    starts = [r[0] for r in merged]

    def covered(va: int) -> bool:
        i = bisect.bisect_right(starts, va) - 1
        return i >= 0 and merged[i][0] <= va < merged[i][1]

    syms = readers.symbols(path)
    functions = {}
    for e, f in by_entry.items():
        ends = sorted(f["ends"])
        functions[e] = {"start": e, "end": ends[-1], "ends": ends, "tier": "dwarf", "dwarf_names": sorted(f["dwarf_names"]), "noreturn": f["noreturn"]}

    # --- symtab tier
    for s in syms:
        if s["table"] != ".symtab" or s["type"] not in ("FUNC", "IFUNC") or s["ndx"] in ("UND", "ABS"):
            continue
        va = s["value"]
        if not in_code(va) or in_plt(va) or va in functions or va in fragments or covered(va):
            continue
        functions[va] = {"start": va, "end": va + s["size"] if s["size"] else None, "ends": [va + s["size"]] if s["size"] else [], "tier": "symtab", "dwarf_names": []}

    # --- plt tier
    labels = readers.plt_labels(path, [s["name"] for s in plt])
    plt_entries = {}
    for s in plt:
        inside = sorted(a for a in labels if s["addr"] <= a < s["addr"] + s["size"])
        for i, a in enumerate(inside):
            end = inside[i + 1] if i + 1 < len(inside) else s["addr"] + s["size"]
            plt_entries[a] = {"start": a, "end": end, "ends": [end], "tier": "plt", "dwarf_names": [], "section": s["name"]}
    for a, f in plt_entries.items():
        functions.setdefault(a, f)
    # The header of a PLT (the lazy resolver's trampoline) is code no table
    # names a function: not a truth function, and not padding either.
    plt_heads = [s["addr"] for s in plt if s["addr"] not in labels]

    # --- names at each address (code sections only)
    names: dict = {}
    for s in syms:
        if s["ndx"] in ("UND", "ABS") or not s["name"] or s["type"] in ("SECTION", "FILE", "OBJECT", "TLS"):
            continue
        if in_code(s["value"]):
            names.setdefault(s["value"], set()).add(s["name"])
    for a, lab in labels.items():
        names.setdefault(a, set()).add(lab)
    all_names = sorted({n for v in names.values() for n in v})
    dem = demangle(all_names)
    dem_llvm = demangle(all_names, "llvm-cxxfilt")

    return {
        "file": path,
        "code_sections": [{"name": s["name"], "addr": s["addr"], "size": s["size"]} for s in code],
        "plt_sections": [{"name": s["name"], "addr": s["addr"], "size": s["size"]} for s in plt],
        "functions": sorted(functions.values(), key=lambda f: f["start"]),
        "fragments": sorted(fragments.values(), key=lambda f: f["start"]),
        "plt_heads": plt_heads,
        "ranges": all_ranges,
        "names": {str(a): sorted(v) for a, v in names.items()},
        "demangled": dem,
        "demangled_llvm": dem_llvm,
        "dwarf_subprograms": len(subs),
        "dwarf_dropped": dropped,
    }


def main() -> int:
    src, out = sys.argv[1], sys.argv[2]
    t = truth(src)
    json.dump(t, open(out, "w"))
    tiers = {}
    for f in t["functions"]:
        tiers[f["tier"]] = tiers.get(f["tier"], 0) + 1
    print(f"{src}: {tiers} fragments={len(t['fragments'])} dwarf subprograms={t['dwarf_subprograms']} dropped={t['dwarf_dropped']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

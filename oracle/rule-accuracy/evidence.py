#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""For every wrong start and wrong end the scorer reports, what the bytes say:
objdump's reading of the unstripped build at that address (rung 3), so a
reported wrong answer can be checked against the instructions and not only
against the instrument's own join.

Per wrong start: the truth function it lies in, the offset, the instruction
objdump decodes there (or that it is no instruction boundary of objdump's
sweep), and the instruction that ends at it. Per wrong end: the engine's end
against the truth's, and the instructions at both.

Writes RESULTS/evidence.jsonl and prints the wrong answers grouped by shape.

Usage: evidence.py [--only SUBSTR[,SUBSTR]] [--show N]
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict

import corpus
import readers


def mnem(text: str | None) -> str:
    if text is None:
        return "-"
    return text.split()[0] if text.split() else "?"


def prev_insn(ins: dict, va: int):
    for back in range(1, 16):
        i = ins.get(va - back)
        if i and i[0] == back:
            return va - back, i
    return None, None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only")
    ap.add_argument("--show", type=int, default=3)
    args = ap.parse_args()
    out = open(os.path.join(corpus.RESULTS, "evidence.jsonl"), "w")
    start_shapes = Counter()
    end_shapes = Counter()
    examples = defaultdict(list)
    cache = {}
    # A wrong start that the unstripped build's own symbol table names would
    # accuse the reference, not the engine: counted, and printed when non-zero.
    named_wrong = []
    for sp in sorted(glob.glob(os.path.join(corpus.RESULTS, "*", "*", "*", "?.summary.json"))):
        s = json.load(open(sp))
        cfg = s.get("config")
        if not cfg or (args.only and not any(x in cfg["id"] for x in args.only.split(","))):
            continue
        rows_path = sp.replace(".summary.json", ".rows.jsonl")
        rows = [json.loads(line) for line in open(rows_path)]
        bad = [r for r in rows if r["class"] in ("interior", "outside") or r["end_cmp"] in ("short", "long", "between")]
        if not bad:
            continue
        tf = s["truth_file"]
        tj = json.load(open(os.path.join(os.path.dirname(sp), f"truth-{corpus.VARIANTS[cfg['variant']]['truth']}.json")))
        noreturn = {f["start"] for f in tj["functions"] if f.get("noreturn")}
        dwarf_starts = {f["start"] for f in tj["functions"] if f["tier"] == "dwarf"}
        if tf not in cache:
            cache.clear()
            cache[tf] = readers.instructions(tf)
        ins = cache[tf]
        for r in bad:
            va = r["va"]
            ev = {"config": cfg["id"], "variant": cfg["variant"], "va": va, "sources": r["sources"], "class": r["class"]}
            if r["class"] in ("interior", "outside"):
                at = ins.get(va)
                pva, prev = prev_insn(ins, va)
                ev.update({
                    "kind": "start",
                    "inside": r.get("inside"),
                    "boundary": at is not None,
                    "at": at[1] if at else None,
                    "prev": prev[1] if prev else None,
                    "aligned16": va % 16 == 0,
                })
                owner = (r.get("inside") or {}).get("owner_names") or []
                if r["truth_names"]:
                    named_wrong.append((cfg["id"], cfg["variant"], hex(va), r["truth_names"]))
                shape = (cfg["variant"], "+".join(r["sources"]), r["class"], "boundary" if at else "mid-instruction", mnem(prev[1] if prev else None), mnem(at[1] if at else None))
                start_shapes[shape] += 1
                if len(examples[("s",) + shape]) < args.show:
                    examples[("s",) + shape].append(f"{cfg['id']} {cfg['variant']} {va:#x} in {owner[:1]} {r.get('inside')} prev=[{prev[1] if prev else None}] at=[{at[1] if at else None}]")
            else:
                te = r["truth_end"]
                end = r["end"]
                d = end - max(te) if r["end_cmp"] == "long" else end - min(te)
                at_truth_end = ins.get(max(te))
                pe_va, last_engine = prev_insn(ins, end)
                pt_va, last_truth = prev_insn(ins, min(te))
                ev.update({"kind": "end", "end_source": r["end_source"], "end": end, "truth_end": te, "delta": d, "end_cmp": r["end_cmp"],
                           "at_truth_end": at_truth_end[1] if at_truth_end else None, "last_insn_engine": last_engine[1] if last_engine else None,
                           "last_insn_truth": last_truth[1] if last_truth else None, "names": r["truth_names"]})
                # What decided the end: for a long end, the truth's last
                # instruction (a call the graph walked past?); for a short one,
                # the engine's last instruction, or none at all where the end is
                # no instruction boundary — and whether it is exactly 4 KiB from
                # the start, the window `why` builds its graph in.
                window = r["end_source"] == "not_stated" and end - va == 0x1000
                ev["window_edge"] = window
                if r["end_cmp"] == "long":
                    # A truth that ends in a call ends there because the callee
                    # does not return; the compiler says which ones it knew
                    # (`DW_AT_noreturn`), for a callee with DWARF.
                    what = mnem(last_truth[1] if last_truth else None)
                    if what.startswith("call") or what == "bl":
                        mt = re.search(r"\b([0-9a-f]+) <", last_truth[1])
                        callee = int(mt.group(1), 16) if mt else None
                        what += " to a DWARF-noreturn callee" if callee in noreturn else " to a callee DWARF does not mark noreturn" if callee in dwarf_starts else " to a callee without DWARF"
                        ev["callee"] = callee
                    shape = (cfg["variant"], r["end_source"], "long", "truth ends in " + what)
                else:
                    shape = (cfg["variant"], r["end_source"], r["end_cmp"], "engine ends after " + mnem(last_engine[1] if last_engine else None) + (" at start+0x1000" if window else ""))
                end_shapes[shape] += 1
                if len(examples[("e",) + shape]) < args.show:
                    examples[("e",) + shape].append(f"{cfg['id']} {cfg['variant']} {va:#x} {r['truth_names'][:1]} end {end:#x} truth {[hex(x) for x in te]} delta {d:+d} last-truth=[{last_truth[1] if last_truth else None}] at-truth-end=[{at_truth_end[1] if at_truth_end else None}] last-engine=[{last_engine[1] if last_engine else None}]")
            out.write(json.dumps(ev) + "\n")
    print("== wrong starts, by (variant, sources, class, boundary, previous insn, insn at start)")
    for shape, n in start_shapes.most_common():
        print(f"{n:6d}  {shape}")
        for e in examples[("s",) + shape]:
            print("          ", e)
    print(f"== wrong starts the unstripped build's symbol table names (would accuse the reference): {len(named_wrong)}")
    for x in named_wrong[:20]:
        print("          ", x)
    print("== wrong ends, by (variant, end source, short/long, what decided it)")
    for shape, n in end_shapes.most_common():
        print(f"{n:6d}  {shape}")
        for e in examples[("e",) + shape]:
            print("          ", e)
    return 0


if __name__ == "__main__":
    sys.exit(main())

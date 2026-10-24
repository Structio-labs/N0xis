#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Calibrate the instrument itself: plant wrong answers it must report, and
check the truth reader against a second reader.

1. A listing with one true start moved by one byte must score one true start
   fewer, one wrong (interior) start more, and one more missed function — the
   moved one. Done for a declared start (variant b) and a heuristic one (c).
2. A listing with one exact end moved by one byte must score one exact end
   fewer and one long end more.
3. A listing with one exact name changed must score one wrong name more.
4. The code-identity check must fail on two builds whose code differs, and on
   a copy of a stripped file with one byte of `.text` flipped.
5. The truth reader (llvm-dwarfdump) against a second reader of the same
   build (readelf's `.symtab`): every DWARF function entry should carry a
   FUNC symbol, and every FUNC symbol in `.text` should be a DWARF entry or a
   fragment or covered by DWARF. Disagreements are printed, never hidden.

Each mutation asserts that it happened before its effect is read: a mutation
that missed would pass silently, which is how a check that checks nothing
looks from the outside.

Usage: calibrate.py <config-id> (e.g. x86_64/lua/gcc-O2); the config must
have been measured by run.py. `calibrate.py --truth-all` runs check 5 alone on
every measured configuration.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import sys

import corpus
import readers
import score


def load(cfg_id: str, v: str):
    d = os.path.join(corpus.RESULTS, cfg_id)
    spec = corpus.VARIANTS[v]
    t = json.load(open(os.path.join(d, f"truth-{spec['truth']}.json")))
    m = json.load(open(os.path.join(d, f"{v}.measure.json")))
    return t, m


def move_start(m: dict, old: str, new: str) -> dict:
    m = copy.deepcopy(m)
    fs = m["discover"]["data"]["functions"]
    hit = [f for f in fs if f["va"] == old]
    assert len(hit) == 1, f"no listed start {old}"
    hit[0]["va"] = new
    w = m["why"].pop(old)
    w["data"]["function"]["found"]["start"] = new
    m["why"][new] = w
    assert new in m["why"] and old not in m["why"]
    print(f"  mutated: start {old} -> {new}")
    return m


def check(label: str, cond: bool, detail: str):
    print(f"  {'PASS' if cond else 'FAIL'}  {label}: {detail}")
    if not cond:
        global failures
        failures += 1


failures = 0


def calibrate_start(cfg_id: str, v: str, want_heuristic: bool):
    t, m = load(cfg_id, v)
    rows0, s0 = score.score(t, m)
    cand = [r for r in rows0 if r["class"] == "true" and r["tier"] == "dwarf" and r["heuristic_only"] == want_heuristic]
    assert cand, "no candidate start"
    r = cand[len(cand) // 2]
    old, new = hex(r["va"]), hex(r["va"] + 1)
    print(f"[start {cfg_id} {v}] moving a {'heuristic-only' if want_heuristic else 'declared'} true start {old} {r['sources']} by one byte")
    m1 = move_start(m, old, new)
    rows1, s1 = score.score(t, m1)
    d_true = s1["classes"].get("true", 0) - s0["classes"].get("true", 0)
    d_int = s1["classes"].get("interior", 0) - s0["classes"].get("interior", 0)
    missed0 = {x["va"] for x in s0["missed"]}
    missed1 = {x["va"] for x in s1["missed"]}
    row = [x for x in rows1 if x["va"] == r["va"] + 1][0]
    check("true starts", d_true == -1, f"{s0['classes'].get('true')} -> {s1['classes'].get('true')}")
    check("interior starts", d_int == 1, f"{s0['classes'].get('interior', 0)} -> {s1['classes'].get('interior', 0)}")
    check("missed", missed1 - missed0 == {r["va"]}, f"newly missed {[hex(x) for x in missed1 - missed0]}")
    check("the moved start is inside its own function", row.get("inside", {}).get("owner") == r["va"], f"inside {row.get('inside')}")
    kind = "heuristic_only" if want_heuristic else "any_declared"
    dw = s1["direction"].get(f"starts|{kind}|interior", 0) - s0["direction"].get(f"starts|{kind}|interior", 0)
    check(f"direction counts it under {kind}", dw == 1, f"+{dw}")


def calibrate_end(cfg_id: str, v: str, stated: bool):
    """Move one exact end by a byte: a stated one (`va`) or, `stated=False`,
    the control-flow graph's (`cfg.end`) — the two shapes an end has."""
    t, m = load(cfg_id, v)
    rows0, s0 = score.score(t, m)
    cand = [x for x in rows0 if x["class"] == "true" and x["end_cmp"] == "exact" and (x["end_source"] != "not_stated") == stated]
    if not cand:
        print(f"[end {cfg_id} {v}] no exact {'stated' if stated else 'not_stated'} end to move: not calibrated here")
        return
    r = cand[len(cand) // 2]
    va = hex(r["va"])
    m1 = copy.deepcopy(m)
    e = m1["why"][va]["data"]["function"]["found"]["end"]
    if stated:
        e["va"] = hex(int(e["va"], 16) + 1)
        new = e["va"]
        for f in m1["discover"]["data"]["functions"]:
            if f["va"] == va and "end" in f:
                f["end"] = new
    else:
        e["cfg"]["end"] = hex(int(e["cfg"]["end"], 16) + 1)
        new = e["cfg"]["end"]
    print(f"[end {cfg_id} {v}] moving the exact end of {va} ({r['end_source']}) by one byte")
    print(f"  mutated: end -> {new}")
    rows1, s1 = score.score(t, m1)
    k = f"true|{r['end_source']}"
    check("exact ends", s1["per_end"][k].get("exact", 0) - s0["per_end"][k].get("exact", 0) == -1, f"{s0['per_end'][k]} -> {s1['per_end'][k]}")
    check("long ends", s1["per_end"][k].get("long", 0) - s0["per_end"][k].get("long", 0) == 1, "")


def calibrate_name(cfg_id: str, v: str):
    t, m = load(cfg_id, v)
    rows0, s0 = score.score(t, m)
    r = [x for x in rows0 if x["name_cmp"] == "exact"][0]
    va = hex(r["va"])
    m1 = copy.deepcopy(m)
    n = m1["why"][va]["data"]["function"]["found"]["name"]
    n["name"] = n["name"] + "_planted"
    for f in m1["discover"]["data"]["functions"]:
        if f["va"] == va:
            f["name"] = n["name"]
    print(f"[name {cfg_id} {v}] renaming {va} {r['name']} -> {n['name']}")
    rows1, s1 = score.score(t, m1)
    layer = r["name_layer"]
    check("wrong names", s1["per_name"][layer].get("wrong", 0) - s0["per_name"][layer].get("wrong", 0) == 1, f"{s0['per_name'][layer]} -> {s1['per_name'][layer]}")


def calibrate_identity(cfg_id: str):
    cfg = [c for c in corpus.configs(cfg_id) if c.id == cfg_id][0]
    # Two builds whose code certainly differs: the same program at another
    # -O level. (The unwind flags are not such a pair: on AArch64 gcc they
    # leave the code byte for byte the same, which this check reports.)
    other_opt = "O0" if cfg.opt != "O0" else "O2"
    other = corpus.Config(cfg.arch, cfg.program, cfg.compiler, other_opt)
    same, _, _ = readers.same_code(cfg.file("u.g"), other.file("u.g"))
    print(f"[identity {cfg_id}] u.g against the -{other_opt} build's u.g")
    check("different builds", not same, f"same={same}")
    flipped = os.path.join(corpus.SCRATCH, "calibration-flipped")
    shutil.copy(cfg.file("u.g.stripped"), flipped)
    text = [s for s in readers.sections(flipped) if s["name"] == ".text"][0]
    with open(flipped, "r+b") as fh:
        fh.seek(text["offset"] + text["size"] // 2)
        b = fh.read(1)
        fh.seek(text["offset"] + text["size"] // 2)
        fh.write(bytes([b[0] ^ 0xFF]))
    print(f"  mutated: one byte of .text flipped at file offset {text['offset'] + text['size'] // 2:#x}")
    same, _, _ = readers.same_code(flipped, cfg.file("u.g"))
    check("one flipped byte", not same, f"same={same}")
    same, _, _ = readers.same_code(cfg.file("u.g.stripped"), cfg.file("u.g"))
    check("the real stripped file", same, f"same={same}")
    os.remove(flipped)


def cross_check_truth(cfg_id: str, build: str = "u.g"):
    """The DWARF reading against the symbol table of the same build: two
    independent readers of one file. Their disagreements are printed whole."""
    cfg = [c for c in corpus.configs(cfg_id) if c.id == cfg_id][0]
    t = json.load(open(os.path.join(corpus.RESULTS, cfg_id, f"truth-{build}.json")))
    syms = readers.symbols(cfg.file(build))
    func_syms = {s["value"] for s in syms if s["table"] == ".symtab" and s["type"] in ("FUNC", "IFUNC") and s["ndx"] not in ("UND", "ABS")}
    dwarf = {f["start"] for f in t["functions"] if f["tier"] == "dwarf"}
    frags = {f["start"] for f in t["fragments"]}
    no_sym = sorted(dwarf - func_syms)
    text = [s for s in t["code_sections"] if s["name"] == ".text"][0]
    in_text = {a for a in func_syms if text["addr"] <= a < text["addr"] + text["size"]}
    sym_not_dwarf = sorted(in_text - dwarf - frags - {f["start"] for f in t["functions"] if f["tier"] == "symtab"})
    print(f"[truth {cfg_id} {build}] {len(dwarf)} DWARF entries, {len(in_text)} FUNC symbols in .text")
    check("every DWARF entry has a FUNC symbol", not no_sym, f"{len(no_sym)} without: {[hex(x) for x in no_sym[:10]]}")
    check("every FUNC symbol in .text is a DWARF entry, a fragment or a CRT function", not sym_not_dwarf, f"{len(sym_not_dwarf)} not: {[hex(x) for x in sym_not_dwarf[:10]]}")


def main() -> int:
    if sys.argv[1:] == ["--truth-all"]:
        # The two-reader check on every measured configuration, not three.
        for cfg in corpus.configs():
            for build in ("u.g", "n.g", "x.g"):
                if os.path.exists(os.path.join(corpus.RESULTS, cfg.id, f"truth-{build}.json")):
                    cross_check_truth(cfg.id, build)
        print(f"calibration: {failures} failure(s)")
        return 1 if failures else 0
    cfg_id = sys.argv[1] if len(sys.argv) > 1 else "x86_64/lua/gcc-O2"
    calibrate_start(cfg_id, "b", want_heuristic=False)
    calibrate_start(cfg_id, "c", want_heuristic=True)
    calibrate_end(cfg_id, "b", stated=True)
    calibrate_end(cfg_id, "c", stated=False)
    calibrate_name(cfg_id, "a")
    calibrate_identity(cfg_id)
    cross_check_truth(cfg_id)
    print(f"calibration: {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Calibrate the obfuscation instrument: plant a wrong answer into a copy of a
measurement and require the scorer to report it, asserting first that the
mutation happened (a mutation that missed would pass silently — that is how a
check that checks nothing looks from the outside).

1. A disasm instruction moved onto an address that is not a true boundary must
   score one more wrong disasm instruction.
2. A true function start moved by one byte must score one more wrong start and
   one more missed function (reusing rule-accuracy's scorer).
3. The reference twin itself must decode without desync: every instruction the
   engine lists for an UNTOUCHED function (one with no planted byte in its
   extent) must be a true boundary, so the baseline wrong count there is zero —
   if the twin were wrong, the whole measurement would be.

And "wrong by the bytes": for every wrong disasm instruction the scorer counts
on the real (unmutated) measurement, print the obfuscated bytes the engine
decoded and what the reference twin's objdump says the real instruction at (or
across) that address is — so a counted wrong is checkable against the
instructions, not only the instrument's join.

Usage: obf_calibrate.py <config-id>   e.g. x86_64/calib/junk/i100
"""

from __future__ import annotations

import copy
import json
import os
import sys

import obf_corpus as corpus
import obf_score
import readers

failures = 0


def check(label: str, cond: bool, detail: str):
    global failures
    print(f"  {'PASS' if cond else 'FAIL'}  {label}: {detail}")
    if not cond:
        failures += 1


def load(cfg_id: str):
    d = os.path.join(corpus.RESULTS, cfg_id)
    build = json.load(open(os.path.join(corpus.BUILD, cfg_id, "build.json")))
    truth = json.load(open(os.path.join(d, "truth.json")))
    meas = json.load(open(os.path.join(d, "measure.json")))
    return build, truth, meas


def main() -> int:
    cfg_id = sys.argv[1] if len(sys.argv) > 1 else "x86_64/calib/junk/i100"
    build, truth, meas = load(cfg_id)
    ref = obf_score.ref_boundaries(build.get("reference_file"))
    contra = obf_score.contradiction_addrs(meas)
    irflag = obf_score.ir_flagged(meas)
    planted = build.get("planted", [])
    base = obf_score.score_disasm(truth, meas, ref, contra, irflag, planted)
    print(f"[{cfg_id}] baseline disasm wrong {base['wrong']}, discover from rule-accuracy scorer")

    # 1. Plant a wrong disasm instruction: take an aligned instruction and move
    # it onto an address that is not a true boundary (and not a planted start).
    bad_va = None
    junk_starts = {p["lo"] for p in planted}
    for a in range(min(ref) if ref else 0, (max(ref) if ref else 0)):
        if a not in ref and a not in junk_starts:
            bad_va = a
            break
    m1 = copy.deepcopy(meas)
    mutated = False
    for a, d in m1["disasm"].items():
        if d.get("ok") and d["data"].get("insns"):
            d["data"]["insns"][0]["va"] = hex(bad_va)
            mutated = True
            break
    check("the disasm mutation happened", mutated and bad_va is not None, f"moved one instruction onto {hex(bad_va) if bad_va else None} (not a boundary)")
    s1 = obf_score.score_disasm(truth, m1, ref, contra, irflag, planted)
    check("one more wrong disasm instruction", s1["wrong"] == base["wrong"] + 1, f"{base['wrong']} -> {s1['wrong']}")

    # 2. Move a true DWARF function start by one byte (rule-accuracy scorer).
    import score as ra_score
    rows0, sum0 = ra_score.score(truth, meas, readers.symbols(build["measured_file"]))
    cand = [r for r in rows0 if r["class"] == "true" and r["tier"] == "dwarf"]
    moved = False
    if cand:
        r = cand[len(cand) // 2]
        old, new = hex(r["va"]), hex(r["va"] + 1)
        m2 = copy.deepcopy(meas)
        fs = m2["discover"]["data"]["functions"]
        hit = [f for f in fs if f["va"] == old]
        if hit:
            hit[0]["va"] = new
            w = m2["why"].pop(old, None)
            if w:
                w["data"]["function"]["found"]["start"] = new
                m2["why"][new] = w
            moved = True
            rows2, sum2 = ra_score.score(truth, m2, readers.symbols(build["measured_file"]))
            d_true = sum2["classes"].get("true", 0) - sum0["classes"].get("true", 0)
            d_int = sum2["classes"].get("interior", 0) - sum0["classes"].get("interior", 0)
            check("the start mutation happened", moved, f"{old} -> {new}")
            check("one fewer true start", d_true == -1, f"{sum0['classes'].get('true')} -> {sum2['classes'].get('true')}")
            check("one more interior start", d_int == 1, f"{sum0['classes'].get('interior', 0)} -> {sum2['classes'].get('interior', 0)}")
    if not moved:
        print("  (no DWARF true start available to move: start calibration skipped)")

    # 3. The twin is a sound boundary oracle: an untouched function's decode has
    # zero desync against it.
    touched_extents = []
    dwarf = sorted((f["start"], f.get("end") or f["start"] + 0x10000) for f in truth["functions"] if f["tier"] == "dwarf")
    planted_fn_starts = set()
    for p in planted:
        for s_, e_ in dwarf:
            if s_ <= p["lo"] < e_:
                planted_fn_starts.add(s_)
                break
    untouched = [hex(s_) for s_, e_ in dwarf if s_ not in planted_fn_starts]
    zero_desync = True
    checked = 0
    for a in untouched:
        d = meas["disasm"].get(a)
        if not d or not d.get("ok"):
            continue
        checked += 1
        for ins in d["data"]["insns"]:
            va = int(ins["va"], 16)
            if va not in ref and va not in junk_starts:
                zero_desync = False
    check("untouched functions decode with no desync against the twin", zero_desync or checked == 0, f"{checked} untouched functions checked")

    # Wrong by the bytes: every counted wrong disasm instruction, obf bytes vs the twin.
    print("\n== wrong disasm instructions, by the bytes (obfuscated image vs the reference twin)")
    shown = 0
    for a, d in meas["disasm"].items():
        if not d.get("ok"):
            continue
        for ins in d["data"]["insns"]:
            va = int(ins["va"], 16)
            if va in ref or va in junk_starts:
                continue
            true_at = ref.get(va)
            # The true boundary the desync is misaligned against: the nearest ref
            # instruction that contains or precedes va.
            containing = max((b for b in ref if b <= va), default=None)
            cinfo = ref.get(containing)
            print(f"  from {a}: {ins['va']} engine=[{ins['bytes']} | {ins['text']}] "
                  f"— not a true boundary; true instruction covering it starts {hex(containing) if containing else '?'} "
                  f"[{cinfo[1] if cinfo else '?'}] len {cinfo[0] if cinfo else '?'}")
            shown += 1
            if shown >= 12:
                break
        if shown >= 12:
            break

    # Would a wrong start accuse the reference? (its own symbol table names it)
    named_wrong = [r for r in rows0 if r["class"] in ("interior", "outside") and r["truth_names"]]
    print(f"\n== wrong starts the measured file's own symbol table names (would accuse the reference): {len(named_wrong)}")

    print(f"\ncalibration: {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

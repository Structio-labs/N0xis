#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Calibrate the lying-tables instrument, in the three places it could measure
nothing and look clean:

1. The editor: `verify`, handed the file *before* tampering as if it were the
   tampered one, must fail on every lie. A check that passes on an edit that did
   not happen would let a run measure the honest file and report the engine immune.
2. The scorer: each kind of wrong answer, planted into a copy of a measurement,
   must score one more wrong, as silent; the same answer with a warning planted
   beside it must score as flagged. Each mutation asserts first that it happened.
3. The control: a configuration scored against itself must charge nothing, and a
   control with different code must be refused rather than joined.

And "wrong by the bytes": every new wrong start the configuration has is checked
against the file before tampering: its own symbol table has no function there, and
`objdump` shows what is really at that address.

Usage: lie_calibrate.py <arch/program>   e.g. x86_64/calib (measured already)
"""

from __future__ import annotations

import copy
import json
import os
import sys

import lie_score
import lying
import obf_corpus as corpus
import readers
import score as ra_score
import transforms

failures = 0


def check(label: str, cond: bool, detail: str = ""):
    global failures
    print(f"  {'PASS' if cond else 'FAIL'}  {label}{': ' + detail if detail else ''}")
    if not cond:
        failures += 1


def load(cfg_id: str) -> tuple:
    build = json.load(open(os.path.join(corpus.BUILD, cfg_id, "build.json")))
    d = os.path.join(corpus.RESULTS, cfg_id)
    return build, json.load(open(os.path.join(d, "truth.json"))), json.load(open(os.path.join(d, "measure.json")))


def calibrate_editor(prefix: str):
    print("1. the edit check fails on a file that was not edited")
    for name, t in transforms.TRANSFORMS.items():
        if not t.get("post_link") or t["post_link"] == "identity_sym":
            continue
        for tag in ("i050", "i100"):
            cid = f"{prefix}/{name}/{tag}"
            build = json.load(open(os.path.join(corpus.BUILD, cid, "build.json")))
            base = json.load(open(os.path.join(corpus.BUILD, build["base"], "build.json")))
            real = lying.verify(build["measured_file"], base["measured_file"], build["truth_file"], build["planted_lies"], t["post_link"])
            fake = lying.verify(base["measured_file"], base["measured_file"], build["truth_file"], build["planted_lies"], t["post_link"])
            check(f"{name}/{tag}", not real and bool(fake), f"on the edit {len(real)} failures, on the unedited file {len(fake)}: {fake[0][:70] if fake else ''}")


def calibrate_scorer(prefix: str):
    print("2. a planted wrong answer scores, silent or flagged")
    build, truth, meas = load(f"{prefix}/none/i100")
    sc = lambda m: lie_score.score(build, truth, m, build, truth, meas)  # noqa: E731
    base = sc(meas)
    for k in lie_score_cells():
        check(f"control against itself charges no {k}", base[k]["wrong"] == 0, str(base[k]))

    T = ra_score.Truth(truth)
    funcs = [f for f in truth["functions"] if f["tier"] == "dwarf" and f["end"] and hex(f["start"]) in meas["why"] and any(g["va"] == hex(f["start"]) for g in meas["discover"]["data"]["functions"])]
    f0 = funcs[len(funcs) // 2]
    s0, e0 = f0["start"], f0["end"]
    interior = s0 + 1
    check("the planted start is interior to a true function", T.classify(interior)[0] == "interior", hex(interior))

    def plant_start(m, sources):
        m["discover"]["data"]["functions"].append({"name": "x", "va": hex(interior)})
        m["why"][hex(interior)] = {"ok": True, "data": {"function": {"found": {"addr_is_start": True, "start": hex(interior), "end": {"source": "not_stated", "cfg": {"end": hex(e0)}}, "name": {"name": "x", "source": "fallback"}, "start_sources": sources}}}}

    m = copy.deepcopy(meas)
    plant_start(m, [{"source": "unwind", "table": "eh_frame"}])
    s = sc(m)
    check("a false declared start: one more, silent", (s["wrong_start"]["wrong"], s["wrong_start"]["silent"]) == (1, 1), str(s["wrong_start"]))
    m2 = copy.deepcopy(m)
    m2["contradictions"]["data"]["contradictions"].append({"kind": "overlap", "first": {"start": hex(s0), "end": hex(e0), "by": []}, "second": {"start": hex(interior), "end": hex(e0), "by": []}})
    s = sc(m2)
    check("the same with a place in contradictions: flagged", (s["wrong_start"]["wrong"], s["wrong_start"]["flagged"]) == (1, 1), str(s["wrong_start"]))
    m = copy.deepcopy(meas)
    plant_start(m, [{"source": "gap_sweep"}])
    s = sc(m)
    check("a false heuristic start: flagged", (s["wrong_start"]["wrong"], s["wrong_start"]["flagged"]) == (1, 1), str(s["wrong_start"]))

    m = copy.deepcopy(meas)
    was = len(m["discover"]["data"]["functions"])
    m["discover"]["data"]["functions"] = [g for g in m["discover"]["data"]["functions"] if g["va"] != hex(s0)]
    check("the unlisting happened", len(m["discover"]["data"]["functions"]) == was - 1)
    s = sc(m)
    check("a true function unlisted: missed, silent", (s["missed"]["wrong"], s["missed"]["silent"]) == (1, 1), str(s["missed"]))

    m = copy.deepcopy(meas)
    fw = m["why"][hex(s0)]["data"]["function"]["found"]
    fw["end"] = {"va": hex(e0 + 16), "source": "unwind", "table": "eh_frame"}
    s = sc(m)
    check("a declared wrong end: silent", (s["wrong_end"]["wrong"], s["wrong_end"]["silent"]) == (1, 1), str(s["wrong_end"]))
    fw["end"] = {"source": "not_stated", "cfg": {"end": hex(e0 + 16)}}
    s = sc(m)
    check("an end nobody declares, wrong: flagged", (s["wrong_end"]["wrong"], s["wrong_end"]["flagged"]) == (1, 1), str(s["wrong_end"]))

    named = [f for f in funcs if f["dwarf_names"]]
    m = copy.deepcopy(meas)
    m["why"][hex(named[0]["start"])]["data"]["function"]["found"]["name"] = {"name": "not_its_name", "source": "image", "table": "dynamic"}
    s = sc(m)
    check("a wrong name: silent", (s["wrong_name"]["wrong"], s["wrong_name"]["silent"]) == (1, 1), str(s["wrong_name"]))

    m = copy.deepcopy(meas)
    fw = m["why"][hex(s0)]["data"]["function"]["found"]
    fw["start"], fw["addr_is_start"] = hex(s0 - 16), False
    s = sc(m)
    check("why answers another function: silent", (s["why_owner"]["wrong"], s["why_owner"]["silent"]) == (1, 1), str(s["why_owner"]))
    m = copy.deepcopy(meas)
    m["why"][hex(s0)]["data"]["function"] = {"none": {"why": "planted"}}
    s = sc(m)
    check("why says no function: a refusal, flagged", (s["why_owner"]["wrong"], s["why_owner"]["flagged"]) == (1, 1), str(s["why_owner"]))

    m = copy.deepcopy(meas)
    dec = m["decomp"][hex(s0)]
    if dec.get("ok"):
        dec["data"]["end_address"] = hex(e0 + 16)
        s = sc(m)
        check("decomp's end moved off the truth: silent", (s["decomp"]["wrong"], s["decomp"]["silent"]) == (1, 1), str(s["decomp"]))
    else:
        check("decomp at the planted function answered", False, str(dec)[:100])
    m = copy.deepcopy(meas)
    m["decomp"][hex(s0)]["data"]["pseudo"].append("    changed();")
    s = sc(m)
    check("a text that changed for no named reason is not wrong", s["decomp"]["wrong"] == 0 and s["decomp"]["changed_unclassified"] == 1, str(s["decomp"]))

    m = copy.deepcopy(meas)
    m["xref_to"][hex(s0)]["data"]["refs"].append({"from": hex(interior)})
    s = sc(m)
    check("a reference the file does not have: invented", s["xref"]["invented"] == 1, str(s["xref"]))
    refs = [(a, d) for a, d in meas["xref_to"].items() if d.get("ok") and d["data"].get("refs")]
    check("the control has references to lose", bool(refs), str(len(refs)))
    if refs:
        m = copy.deepcopy(meas)
        m["xref_to"][refs[0][0]]["data"]["refs"].pop()
        s = sc(m)
        check("a reference lost", s["xref"]["lost"] == 1, str(s["xref"]))


def lie_score_cells() -> list:
    return ["wrong_start", "missed", "wrong_end", "wrong_name", "why_owner", "decomp", "xref"]


def calibrate_control(prefix: str):
    print("3. a control with different code is refused")
    build, truth, meas = load(f"{prefix}/none/i100")
    other = copy.deepcopy(build)
    other["truth_file"] = os.path.join(corpus.BUILD, prefix.split("/")[0], "lua" if "calib" in prefix else "calib", "none", "i100", "obf.g")
    if not os.path.exists(other["truth_file"]):
        check("the other program is built", False, other["truth_file"])
        return
    try:
        lie_score.score(build, truth, meas, other, truth, meas)
        check("refused", False, "it joined two different programs")
    except ValueError as e:
        check("refused", True, str(e)[:80])


def wrong_by_the_bytes(prefix: str):
    print("wrong by the bytes: each lie's false start, against the file before tampering")
    for name in ("fde_add", "fde_split", "fde_repoint", "fde_short", "sym_mid"):
        cid = f"{prefix}/{name}/i100"
        build = json.load(open(os.path.join(corpus.BUILD, cid, "build.json")))
        s = json.load(open(os.path.join(corpus.RESULTS, cid, "lies.json")))
        funcs = {x["value"] for x in readers.symbols(build["truth_file"]) if x["type"] == "FUNC" and x["table"] == ".symtab"}
        ins = readers.instructions(build["truth_file"])
        for r in build["planted_lies"][:1]:
            site = r["site"]
            check(f"{name}: no function symbol at {site:#x} in the file before", site not in funcs)
            inside = site not in ins
            print(f"    {name} {site:#x}: in function {r['name']} {r['function']:#x}..{r['end']:#x}; {'mid-instruction' if inside else 'an instruction boundary'}; new wrong starts {s['wrong_start']['wrong']}")
            print("\n".join("      " + ln[:80] for ln in readers.disasm_around(build["truth_file"], site, 8, 8).splitlines()[:6]))


def main() -> int:
    prefix = sys.argv[1] if len(sys.argv) > 1 else "x86_64/calib"
    calibrate_editor(prefix)
    calibrate_scorer(prefix)
    calibrate_control(prefix)
    wrong_by_the_bytes(prefix)
    print(f"\ncalibration: {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

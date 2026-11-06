#!/usr/bin/env python3
"""Counts per set from a behave.py run, and writes functions.tsv: one line per function per build.

Usage: report.py <run-dir>                 the counts per set; writes <run-dir>/functions.tsv
       report.py <run-dir> --against <old> which functions changed outcome, old to new, and the counts of both
       report.py <run-dir> --detail <outcome>   the bodies with that outcome, each with its first difference
"""
import collections, json, sys

SAME = ("same", "same_ext")
ORDER = ["same", "same_ext", "narrow", "differ_nan_only", "differ", "crash", "died", "no_link", "no_compile", "no_answer"]
SETS = {"emu gcc": lambda l: l.startswith("emu") and ".gcc" in l, "emu clang": lambda l: l.startswith("emu") and ".clang" in l, "held-out gcc": lambda l: l.startswith("heldout.gcc"), "held-out clang": lambda l: l.startswith("heldout.clang")}
TOTALS = {"emu": "emu", "held-out": "heldout"}


def load(run):
    return json.load(open(run + "/results.json"))


def counts(res, tool):
    for name, f in SETS.items():
        rs = [r for r in res if r["tool"] == tool and f(r["lib"])]
        c = collections.Counter(r["outcome"] for r in rs)
        printed = sum(1 for r in rs if r.get("level0"))
        width = sum(1 for r in rs if r.get("rescued_by") and r["rescued_by"][1] == "0")
        unset = sum(1 for r in rs if r.get("rescued_by") and r["rescued_by"][1] == "1")
        print(f"{name:14} {tool:6} n={len(rs):3} compiles-as-printed={printed:3} " + " ".join(f"{k}={c[k]}" for k in ORDER if c[k]) + f" | rescued: access width {width}, unset name nonzero {unset}")
    for name, prefix in TOTALS.items():
        rs = [r for r in res if r["tool"] == tool and r["lib"].startswith(prefix)]
        print(f"{name:14} {tool:6} same {sum(r['outcome'] in SAME for r in rs)} of {len(rs)}, compiles as printed {sum(1 for r in rs if r.get('level0'))} of {len(rs)}")


def tsv(run, res):
    with open(run + "/functions.tsv", "w") as w:
        for r in sorted(res, key=lambda r: (r["tool"], r["lib"], r["fn"])):
            first = (r.get("run") or {}).get("first", "")
            w.write("\t".join((r["tool"], r["lib"], r["fn"], r["outcome"], "compiles" if r.get("level0") else "does-not-compile", ",".join(r["rules"]), "" if not r.get("rescued_by") else "rescued:" + "/".join(r["rescued_by"]), r.get("level1_why", ""), first)) + "\n")


def reasons(res):
    why = collections.Counter(r.get("level1_why", "?") for r in res if r["tool"] == "n0xis" and r["outcome"] == "no_compile")
    print("-- would not compile, after the layer:", dict(why.most_common(6)))
    why = collections.Counter(r.get("level0_why", "?")[:50] for r in res if r["tool"] == "n0xis" and r.get("level0") is False)
    print("-- as printed, first error:", dict(why.most_common(6)))


def main():
    run = sys.argv[1]
    res = load(run)
    tsv(run, res)
    if "--against" in sys.argv:
        old = load(sys.argv[sys.argv.index("--against") + 1])
        print("old:")
        counts(old, "n0xis")
        print("new:")
        counts(res, "n0xis")
        was = {(r["lib"], r["fn"]): r for r in old if r["tool"] == "n0xis"}
        moved = collections.Counter()
        for r in res:
            o = was.get((r["lib"], r["fn"]))
            if r["tool"] == "n0xis" and o and o["outcome"] != r["outcome"]:
                moved[(o["outcome"], r["outcome"])] += 1
                print(f"{r['lib']:20} {r['fn']:24} {o['outcome']} -> {r['outcome']}")
        print("moved:", {f"{a}->{b}": n for (a, b), n in moved.items()})
        return
    if "--detail" in sys.argv:
        oc = sys.argv[sys.argv.index("--detail") + 1]
        for r in res:
            if r["tool"] == "n0xis" and r["outcome"] == oc:
                print(r["lib"], r["fn"], r.get("sig", "")[:70], (r.get("run") or {}).get("first", "")[:90], r.get("level1_why", "")[:80], (r.get("run") or {}).get("link_error", "")[:80])
        return
    counts(res, "source")
    counts(res, "n0xis")
    reasons(res)
    print("per function:", run + "/functions.tsv")


main()

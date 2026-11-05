#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The lying tables' tables: per lie, intensity and command, the answers the lie
made wrong, as `wrong (silent)`; flagged is the difference. Reads every `lies.json`.

Writes RESULTS/lies-report.md (every configuration) and RESULTS/lies-doc.md (the
tables for docs/VERIFICATION.md, summed over the two programs per machine), and
prints the totals.

`--bytes <config-id>` prints that configuration's silent wrong answers beside what
`objdump` reads in the file before tampering: a wrong answer shown by the bytes,
not only by the instrument's join.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from collections import defaultdict

import obf_corpus as corpus
import readers
import transforms

CELLS = ["wrong_start", "missed", "wrong_end", "wrong_name", "why_owner", "decomp", "xref"]
HEAD = ["starts", "missed", "ends", "names", "why owner", "decomp", "xref"]


def load() -> list:
    out = []
    for p in sorted(glob.glob(os.path.join(corpus.RESULTS, "*", "*", "*", "*", "lies.json"))):
        out.append(json.load(open(p)))
    return out


def lie_order() -> list:
    return [n for n, t in transforms.TRANSFORMS.items() if t.get("post_link") and not n.startswith("none")]


def cell(c: dict) -> str:
    return f"{c['wrong']} ({c['silent']})" if c["wrong"] else "0"


def row(s: dict) -> list:
    return [cell(s[k]) for k in CELLS]


def totals(rows: list) -> tuple:
    w = sum(s[k]["wrong"] for s in rows for k in CELLS if k in s)
    si = sum(s[k]["silent"] for s in rows for k in CELLS if k in s)
    return w, si


def tables(summaries: list) -> str:
    by = {s["id"]: s for s in summaries}
    out = []
    eng = summaries[0]["engine"]
    out.append(f"Engine `{eng['version']}`, sha256 `{eng['sha256']}`.\n")
    for arch in corpus.ARCHES:
        rows = [s for s in summaries if s["arch"] == arch]
        if not rows:
            continue
        out.append(f"\n### {arch}: new wrong answers against the control, `wrong (silent)`\n")
        out.append("| lie | i | planted | " + " | ".join(HEAD) + " | contradictions (control) | lies named | behaviour |")
        out.append("|" + "---|" * (len(HEAD) + 6))
        for name in lie_order():
            for tag in ("i050", "i100"):
                got = [by[f"{arch}/{p}/{name}/{tag}"] for p in corpus.PROGRAMS if f"{arch}/{p}/{name}/{tag}" in by]
                if not got:
                    continue
                ok = [s for s in got if s.get("discover_ok")]
                cells = []
                for k in CELLS:
                    w = sum(s[k]["wrong"] for s in ok)
                    si = sum(s[k]["silent"] for s in ok)
                    cells.append(f"{w} ({si})" if w else "0")
                beh = "same" if all(s["behaviour_ok"] is True for s in got) else "/".join(str(s["behaviour_ok"]) for s in got)
                contra = sum(s["contradictions"]["count"] for s in ok)
                ctl = sum(s["contradictions"]["control_count"] for s in ok)
                named = sum(s["contradictions"]["lies_named"] for s in ok)
                planted = sum(s["planted"] for s in got)
                crashes = sum(s["serve_crashes"] for s in got)
                out.append(f"| {name} | {tag[1:]} | {planted} | " + " | ".join(cells) + f" | {contra} ({ctl}) | {named} / {planted} | {beh}{' CRASHES ' + str(crashes) if crashes else ''} |")
    return "\n".join(out) + "\n"


def per_config(summaries: list) -> str:
    out = ["| config | listed | planted | " + " | ".join(HEAD) + " | decomp changed | contra | named | crashes |", "|" + "---|" * (len(HEAD) + 7)]
    for s in sorted(summaries, key=lambda s: s["id"]):
        if not s.get("discover_ok"):
            out.append(f"| {s['id']} | refused: {s.get('refused')} |")
            continue
        out.append(f"| {s['id']} | {s['listed']} | {s['planted']} | " + " | ".join(row(s)) +
                   f" | {s['decomp']['changed_unclassified']} | {s['contradictions']['count']} | {s['contradictions']['lies_named']} | {s['serve_crashes']} |")
    return "\n".join(out) + "\n"


def category(summaries: list) -> str:
    """The direction `why` was built on, on every lying image: of the facts wrong
    against the truth, how many carry a declared source."""
    agg = defaultdict(lambda: defaultdict(int))
    for s in summaries:
        if not s.get("discover_ok") or s["transform"] not in lie_order():
            continue
        for k, v in s["category"].items():
            agg[s["transform"]][k] += v
    out = ["| lie | declared starts wrong | heuristic starts wrong | declared ends wrong | heuristic ends wrong |", "|---|---|---|---|---|"]
    tot = defaultdict(int)
    for name in lie_order():
        a = agg.get(name)
        if not a:
            continue
        for k, v in a.items():
            tot[k] += v
        out.append(f"| {name} | {a['declared_starts_wrong']} / {a['declared_starts']} | {a['heuristic_starts_wrong']} / {a['heuristic_starts']} | {a['declared_ends_wrong']} / {a['declared_ends']} | {a['heuristic_ends_wrong']} / {a['heuristic_ends']} |")
    out.append(f"| all | {tot['declared_starts_wrong']} / {tot['declared_starts']} | {tot['heuristic_starts_wrong']} / {tot['heuristic_starts']} | {tot['declared_ends_wrong']} / {tot['declared_ends']} | {tot['heuristic_ends_wrong']} / {tot['heuristic_ends']} |")
    return "\n".join(out) + "\n"


def by_lie_totals(summaries: list) -> str:
    out = ["| lie | new wrong | flagged | silent |", "|---|---|---|---|"]
    all_w = all_s = 0
    for name in lie_order():
        rows = [s for s in summaries if s["transform"] == name and s.get("discover_ok")]
        w, si = totals(rows)
        all_w += w
        all_s += si
        out.append(f"| {name} | {w} | {w - si} | {si} |")
    out.append(f"| all | {all_w} | {all_w - all_s} | {all_s} |")
    return "\n".join(out) + "\n"


def show_bytes(cfg_id: str):
    build = json.load(open(os.path.join(corpus.BUILD, cfg_id, "build.json")))
    s = json.load(open(os.path.join(corpus.RESULTS, cfg_id, "lies.json")))
    before = build["truth_file"]
    for kind, ex in s["examples"].items():
        if not ex or kind.startswith("xref"):
            continue
        print(f"== {kind}")
        for a, v in list(ex.items())[:2]:
            print(f"  {a}: {json.dumps(v)[:300]}")
            print("\n".join("    " + ln[:90] for ln in readers.disasm_around(before, int(a, 16), 12, 16).splitlines()[:9]))
    for kind in ("xref_lost", "xref_invented"):
        for x in s["examples"].get(kind, [])[:2]:
            print(f"== {kind} {x}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bytes")
    args = ap.parse_args()
    if args.bytes:
        show_bytes(args.bytes)
        return 0
    summaries = load()
    if not summaries:
        print("nothing scored under", corpus.RESULTS)
        return 1
    doc = tables(summaries) + "\n### Totals, every configuration\n\n" + by_lie_totals(summaries) + "\n### The category of the source, every lying image\n\n" + category(summaries)
    open(os.path.join(corpus.RESULTS, "lies-doc.md"), "w").write(doc)
    open(os.path.join(corpus.RESULTS, "lies-report.md"), "w").write(doc + "\n### Every configuration\n\n" + per_config(summaries))
    print(by_lie_totals(summaries))
    return 0


if __name__ == "__main__":
    sys.exit(main())

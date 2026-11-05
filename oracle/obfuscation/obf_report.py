#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Read every scored configuration and print the tables: per transformation and
command, the wrong answers and — the number that matters — how many were
flagged (any warning in the answer) versus silent (`ok:true`, nothing).

Writes RESULTS/report.md (all configurations) and RESULTS/doc-tables.md (the
tables to carry into docs/VERIFICATION.md), and prints a short summary.

Usage: obf_report.py [--only SUBSTR]
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from collections import defaultdict

import obf_corpus as corpus

# The commands and the (wrong, flagged, silent) key triples each reports.
COMMANDS = ["function_discover", "disasm", "xref", "strings", "ir_deobfuscate"]


def wrong_triple(cmd: str, c: dict):
    if cmd == "function_discover":
        return c["wrong_starts"], c["wrong_flagged"], c["wrong_silent"]
    if cmd == "ir_deobfuscate":
        # The w/f/s column here is the junk hits on honest code (its base-rate
        # false alarm); detection of planted junk is reported apart.
        return c["junk_on_honest"], 0, c["junk_on_honest"]
    return c.get("wrong", 0), c.get("wrong_flagged", 0), c.get("wrong_silent", 0)


def load_summaries(only: str | None):
    out = []
    for p in sorted(glob.glob(os.path.join(corpus.RESULTS, "*", "*", "*", "*", "summary.json"))):
        s = json.load(open(p))
        if only and not any(x in s["id"] for x in only.split(",")):
            continue
        out.append(s)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only")
    args = ap.parse_args()
    summaries = load_summaries(args.only)
    if not summaries:
        print("no scored configurations under", corpus.RESULTS)
        return 0

    lines = ["# Obfuscation measurement\n"]
    eng = summaries[0]["engine"]
    lines.append(f"Engine `{eng['version']}`, sha256 `{eng['sha256']}`.\n")
    lines.append("Per configuration (architecture / program / transformation / intensity), for each command: "
                 "the wrong answers, how many carried any warning (flagged), how many were `ok:true` with nothing (silent).\n")

    header = "| config | behaviour | " + " | ".join(f"{c} w/f/s" for c in COMMANDS) + " | ir-deob det | contradictions |"
    sep = "|" + "---|" * (len(COMMANDS) + 4)
    lines += [header, sep]
    # Also aggregate by transformation.
    agg = defaultdict(lambda: defaultdict(lambda: [0, 0, 0]))
    for s in sorted(summaries, key=lambda s: s["id"]):
        cells = []
        for cmd in COMMANDS:
            w, f, si = wrong_triple(cmd, s["cmd"][cmd])
            cells.append(f"{w}/{f}/{si}")
            a = agg[s["transform"]][cmd]
            a[0] += w; a[1] += f; a[2] += si
        irc = s["cmd"]["ir_deobfuscate"]
        det = f"{irc['detected']}/{irc['planted_ranges']}"
        beh = {True: "same", False: "DIFFERS", None: "not-run"}[s["behaviour_ok"]]
        lines.append(f"| {s['id']} | {beh} | " + " | ".join(cells) + f" | {det} | {s['contradictions_count']} |")

    lines.append("\n## By transformation (summed over configurations)\n")
    lines += ["| transform | " + " | ".join(f"{c} w/f/s" for c in COMMANDS) + " |", "|" + "---|" * (len(COMMANDS) + 1)]
    for t, by_cmd in sorted(agg.items()):
        cells = [f"{by_cmd[c][0]}/{by_cmd[c][1]}/{by_cmd[c][2]}" for c in COMMANDS]
        lines.append(f"| {t} | " + " | ".join(cells) + " |")
    lines.append("\nw/f/s = wrong / of-those-flagged / of-those-silent. For `ir_deobfuscate` the "
                 "w/f/s column is false alarms on honest functions; `det` is planted-junk functions detected / present.\n")

    report = "\n".join(lines) + "\n"
    os.makedirs(corpus.RESULTS, exist_ok=True)
    open(os.path.join(corpus.RESULTS, "report.md"), "w").write(report)
    open(os.path.join(corpus.RESULTS, "doc-tables.md"), "w").write(report)
    print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())

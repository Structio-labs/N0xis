#!/usr/bin/env python3
"""The counters over big images: every class of `lint_bodies.py`, `lint_rbp.py` and `lint_signed.py`, one column per image.

Usage: big_images.py ENGINE OUTDIR LABEL=IMAGE=ADDRS...
ADDRS lists hex addresses, one a line: hold it fixed between an old and a new engine, or the two measure different functions.
Writes OUTDIR/LABEL.jsonl (every body) and OUTDIR/counts.json. Asking for no bodies is an error, not a table of zeros.
"""
import json, os, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bodies, lint_bodies, lint_rbp, lint_signed


def main():
    engine, out = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    os.makedirs(out, exist_ok=True)
    columns, extra = {}, {}
    for spec in sys.argv[3:]:
        label, image, addrs = spec.split("=")
        p = f"{out}/{label}.jsonl"
        asked, answered = bodies.run(engine, os.path.abspath(image), addrs, p)
        if not answered:
            sys.exit(f"{label}: {asked} asked, no body came back")
        columns[label] = lint_bodies.lint(p)[0]
        extra[label] = {**lint_rbp.lint(p), **lint_signed.lint(p)}
    lint_bodies.table(columns)
    for key in ("false_local_fns", "sar64", "sar64_spelled_signed"):
        print(f"{key:48}" + "".join(f"{extra[l][key]:>13}" for l in columns))
    json.dump({l: {"counts": columns[l], **extra[l]} for l in columns}, open(f"{out}/counts.json", "w"), indent=1)


main()

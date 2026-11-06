#!/usr/bin/env python3
"""Signed 64-bit compares and shifts by the bytes, against how a body prints them. A count of opportunities and of signed spellings; not a match per site.

Usage: lint_signed.py RAW.jsonl...  (files written by bodies.py)
"""
import re, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bodylib as bl

SIGNED = {"jl", "jg", "jle", "jge", "setl", "setg", "setle", "setge", "cmovl", "cmovg", "cmovle", "cmovge"}


def lint(path):
    meta, bodies = bl.rows(path)
    im = bl.Image(meta["image"])
    cmp64 = sar64 = fns_cmp = fns_ok = sar_text = cmp_text = 0
    for r in bodies:
        ins = list(im.in_range(int(r["entry"], 16), int(str(r["end"]), 0)))
        c = s = 0
        for i, (_, t) in enumerate(ins):
            mn, ops = im.parse(t)
            if mn in SIGNED and i:
                pm, pops = im.parse(ins[i - 1][1])
                if pm in ("cmp", "test", "cmpq", "testq") and re.search(r"%r[a-z0-9]+\b(?!d|w|b)", pops) and not re.search(r"%e|%r\d+d|%r\d+w|%r\d+b", pops):
                    c += 1
            if mn in ("sar", "sarq") and re.search(r"%r[a-z0-9]+\b$", ops) and not re.search(r"%e|%r\d+d", ops):
                s += 1
        cmp64 += c
        sar64 += s
        b = bl.strip_comments(r["c"])
        tc = len(re.findall(r"\(int64_t\)[^;\n]*?(?:<=|>=|<|>)", b)) + len(re.findall(r"int64_t\s+local_", b))
        cmp_text += tc
        sar_text += len(re.findall(r"\(int64_t\)[^;\n]*?>>", b))
        if c:
            fns_cmp += 1
            fns_ok += tc >= c
    return {"signed_cmp64": cmp64, "in_fns": fns_cmp, "fns_printing_as_many": fns_ok, "sar64": sar64, "sar64_spelled_signed": sar_text}


if __name__ == "__main__":
    for p in sys.argv[1:]:
        print(Path(p).name, lint(p))

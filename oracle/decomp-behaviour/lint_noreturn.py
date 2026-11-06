#!/usr/bin/env python3
"""A call to a function DWARF marks noreturn: does the body stop there? Code printed after it in the same block, with no stop mark.

Usage: lint_noreturn.py RAW.jsonl UNSTRIPPED-TWIN  (written by bodies.py; DWARF read by dwarfprotos.py, llvm-dwarfdump)
"""
import json, re, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import bodylib as bl


def lint(path, twin):
    with tempfile.NamedTemporaryFile(suffix=".json") as f:
        subprocess.run([sys.executable, str(HERE / "dwarfprotos.py"), twin, f.name], check=True, capture_output=True)
        protos = json.load(open(f.name))
    nr = {p["low"] for p in protos if p["noreturn"] and p["low"]}
    total = cont = 0
    ex = None
    for r in bl.rows(path)[1]:
        ls = [l for l in r["c"].split("\n") if l.strip()]
        for i, l in enumerate(ls):
            m = re.search(r"\b(sub_([0-9A-Fa-f]+))\(", l)
            if not m or int(m[2], 16) not in nr:
                continue
            total += 1
            nxt = ls[i + 1].strip() if i + 1 < len(ls) else ""
            if "unreachable" not in nxt and (not nxt.startswith("}") or i + 2 < len(ls)):
                cont += 1
                ex = ex or (r["entry"], l.strip()[:60], nxt[:40])
    return {"calls_to_noreturn": total, "code_after_no_stop_mark": cont, "example": ex}


if __name__ == "__main__":
    print(Path(sys.argv[1]).name, lint(sys.argv[1], sys.argv[2]))

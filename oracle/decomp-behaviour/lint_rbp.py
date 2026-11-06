#!/usr/bin/env python3
"""False stack locals: rbp used as a general register (no `mov %rsp,%rbp` in the function), memory at N(%rbp) in the bytes, and the body naming that offset as a stack local.

Usage: lint_rbp.py RAW.jsonl...  (files written by bodies.py). Prints functions and accesses, one example each. Function ends are the
engine's own `end_address`: they bound which bytes are read, nothing more. Offsets the function also reaches through rsp are not counted.
"""
import re, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bodylib as bl


def lint(path):
    meta, bodies = bl.rows(path)
    im = bl.Image(meta["image"])
    nf, nb, ex, frames = 0, 0, None, 0
    where = []
    for r in bodies:
        a = int(r["entry"], 16)
        offs, rsp_offs, frame = set(), set(), False
        for _, t in im.in_range(a, int(str(r["end"]), 0)):
            # `lea 0x80(%rsp),%rbp` sets a frame as well, the Windows habit.
            if re.search(r"mov\s+%rsp,%rbp|lea\s+(?:-?0x[0-9a-f]+)?\(%rsp\),%rbp", t):
                frame = True
            for m in re.finditer(r"(?<![\w])(-?0x[0-9a-f]+)\(%rbp[,)]", t):
                offs.add(int(m[1], 16))
            for m in re.finditer(r"(?<![\w])(-?0x[0-9a-f]+)\(%rsp[,)]", t):
                rsp_offs.add(int(m[1], 16))
            if re.search(r"(?<![\w])\(%rsp[,)]", t):
                rsp_offs.add(0)
        if frame:
            frames += 1
            continue
        # The local's name carries the offset's sign. An access through rbp printed as one (`rbp.0->field_0x18`, `*(T*)rbp.0`) is
        # not the false local, even if a stack slot of the function happens to have that offset: push and call slots do, often.
        name = lambda o: rf"\blocal_neg_{-o:x}\b" if o < 0 else rf"\blocal_{o:x}\b"
        through = lambda o: re.search(rf"\w->field_(?:neg_)?0x{abs(o):x}\b", r["c"]) or (o == 0 and re.search(r"\*\([\w ]+\*\)(?:rbp|v\d)", r["c"]))
        hit = [o for o in offs - rsp_offs if re.search(name(o), r["c"]) and not through(o)]
        if hit:
            nf += 1
            nb += len(hit)
            ex = ex or (hex(a), sorted(hit)[:3])
            where.append(hex(a))
    return {"false_local_fns": nf, "false_local_offsets": nb, "of": len(bodies), "frame_pointer_fns": frames, "example": ex, "where": where}


if __name__ == "__main__":
    for p in sys.argv[1:]:
        print(Path(p).name, lint(p))

#!/usr/bin/env python3
"""Hold `xref from` at every indirect jump of an image against what `objdump -d` shows before it.

    python3 scripts/xref_table_measure.py --new NEW [--old OLD] [--open K] IMAGE...

`objdump` says where each indirect jump is. Reading back from it, this finds the two things a table's size
and place are written in: the last `cmp <x>, <imm>` followed by `ja`/`jae` before the jump, and the last `lea
<reg>, [rip+...]` or the jump's own displacement. Then, for each jump the answer resolves:

- **agree**: as many entries as that guard lets through, from that table;
- **differ**: anything else, which is a question, so `--open K` prints the first K with the instructions;
- **no guard shown**: the back-scan found no such `cmp`, so the count cannot be held against anything.

It is a back-scan in a script, a reader of the same bytes: rung 3, raising suspicion, and each difference is
read by eye before it counts. Each engine runs in a project of its own under `ulimit -v 4194304`.
"""

import argparse
import json
import os
import re
import resource
import subprocess
import tempfile
from collections import Counter

LIMIT = 4194304 * 1024
LINE = re.compile(r"^\s*([0-9a-f]+):\t(.*)$")
JUMP = re.compile(r"^(?:notrack\s+)?(?:bnd\s+)?jmp\s+(.*)$")
CMP = re.compile(r"^cmp\s+.*,\s*(0x[0-9a-f]+)\s*$")
LEA = re.compile(r"^lea\s+\w+,\[rip\+0x[0-9a-f]+\]\s+# ([0-9a-f]+)")
DISP = re.compile(r"\*[1248]\+(0x[0-9a-f]+)\]")
ENDS = re.compile(r"^(?:ret|hlt|int3|ud2|jmp)\b")


def instructions(path):
    text = subprocess.run(["objdump", "-d", "-M", "intel", "--no-show-raw-insn", path], capture_output=True, text=True, env={**os.environ, "LC_ALL": "C"}).stdout
    out = []
    for line in text.splitlines():
        m = LINE.match(line)
        if m and m.group(2).strip():
            out.append((int(m.group(1), 16), m.group(2).strip()))
    return out


def jumps(insns):
    for i, (at, text) in enumerate(insns):
        m = JUMP.match(text)
        if m and not re.match(r"^[0-9a-f]+ <", m.group(1)) and "rip" not in m.group(1):
            yield i, at, m.group(1)


def what_objdump_shows(insns, i, operand):
    """(entries the guard lets through or None, table or None)."""
    entries = None
    table = None
    m = DISP.search(operand)
    if m:
        table = int(m.group(1), 16)
    for j in range(i - 1, max(i - 40, 0), -1):
        text = insns[j][1]
        if ENDS.match(text):
            break
        if table is None:
            lea = LEA.match(text)
            if lea:
                table = int(lea.group(1), 16)
        if entries is None and j + 1 < len(insns):
            cmp_ = CMP.match(text)
            following = insns[j + 1][1]
            if cmp_ and following.startswith(("ja ", "jae ", "jnb ")):
                limit = int(cmp_.group(1), 16)
                entries = limit + 1 if following.startswith("ja ") else limit
    return entries, table


class Engine:
    def __init__(self, binary, image):
        self.dir = tempfile.TemporaryDirectory()
        os.mkdir(os.path.join(self.dir.name, ".n0x"))
        env = {**os.environ, "N0X_NO_UPDATE_CHECK": "1", "XDG_DATA_HOME": self.dir.name}

        def limited():
            resource.setrlimit(resource.RLIMIT_AS, (LIMIT, LIMIT))

        self.p = subprocess.Popen([os.path.abspath(binary), "serve", "--file", os.path.abspath(image)], cwd=self.dir.name, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, preexec_fn=limited)
        self.p.stdout.readline()

    def ask(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def close(self):
        self.p.stdin.close()
        self.p.wait()
        self.dir.cleanup()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--new", required=True)
    ap.add_argument("--old")
    ap.add_argument("--open", type=int, default=0)
    ap.add_argument("images", nargs="+")
    a = ap.parse_args()
    for path in a.images:
        insns = instructions(path)
        listed = list(jumps(insns))
        print(f"{os.path.basename(path)}: {len(insns)} instructions, {len(listed)} indirect jumps by objdump")
        if a.old:
            old = Engine(a.old, path)
            rows = sum(len(old.ask(f"xref from --addr {at:#x}").get("data", {}).get("refs", [])) for _, at, _ in listed)
            old.close()
            print(f"  old: {rows} targets listed by `xref from` at those jumps")
        engine = Engine(a.new, path)
        tally = Counter()
        entries = Counter()
        differ = []
        samples = []
        tables = []
        bad = 0
        starts = {at for at, _ in insns}
        for i, at, operand in listed:
            data = engine.ask(f"xref from --addr {at:#x}").get("data", {})
            answer = data.get("jump_table") or {}
            shown, table = what_objdump_shows(insns, i, operand)
            if answer.get("state") != "resolved":
                tally["not resolved, objdump shows a table and a guard" if shown and table else "not resolved"] += 1
                if shown and table:
                    differ.append((at, "not resolved", shown, table, answer.get("why")))
                continue
            n = answer["entries"]
            tables.append((int(answer["table"], 16), n * (4 if "relative_to" in (data["refs"][0] if data["refs"] else {}) else 8), at))
            bad += sum(1 for r in data["refs"] if r["kind"] == "jump_table" and int(r["to"], 16) not in starts)
            entries["guarded" if answer["guarded"] else "walked"] += n
            tally["resolved guarded" if answer["guarded"] else "resolved walked"] += 1
            if len(samples) < 200:
                samples.append((at, n, shown, table, answer))
            if shown is None:
                tally["  no guard shown"] += 1
            elif shown == n and (table is None or table == int(answer["table"], 16)):
                tally["  agree"] += 1
            else:
                tally["  differ"] += 1
                differ.append((at, n, shown, table, answer))
        engine.close()
        # Two tables whose words overlap: one read past its end. Tables from the same base are one.
        unique = sorted({(b, s) for b, s, _ in tables})
        overlaps = sum(1 for (b0, s0), (b1, _) in zip(unique, unique[1:]) if b0 != b1 and b0 + s0 > b1)
        print(f"  new: {dict(sorted(tally.items()))}, entries {dict(entries)}")
        print(f"  tables overlapping the next: {overlaps} of {len(unique)}; entries landing on no instruction objdump shows: {bad}")
        for row in differ[: a.open]:
            at, n, shown, table, answer = row
            print(f"    differ at {at:#x}: answer {n}, objdump shows {shown} from {hex(table) if table else None}: {answer}")
        for at, n, shown, table, _ in samples[:: max(1, len(samples) // max(a.open, 1))][: a.open]:
            print(f"    sample {at:#x}: {n} entries, objdump shows {shown} from {hex(table) if table else None}")


if __name__ == "__main__":
    main()

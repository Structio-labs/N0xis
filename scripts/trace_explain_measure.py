#!/usr/bin/env python3
"""Hold `function trace` at depth 0 and `ir explain`'s bound against `objdump -d`.

    python3 scripts/trace_explain_measure.py --new NEW [--old OLD] [--sample N] IMAGE...

For N functions of `function discover` that state an end:

- `function trace`: `objdump` says which calls in the function name no target (`call rax`, `call [rax+8]`). A row
  with no target that is not one, or one that has no such row, is a disagreement; `kind` says what it calls them.
- `ir explain`: for each switch line, `objdump` says which `cmp <x>,<imm>` with a `ja`/`jae` straight after it is
  nearest before the jump. A bound that is not that value is **differs**, a question to read, not a verdict: the
  nearest compare is often another register's. `?` is counted apart.

Each engine runs in a project of its own under `ulimit -v 4194304`.
"""

import argparse
import bisect
import json
import os
import re
import resource
import subprocess
import tempfile
from collections import Counter

LIMIT = 4194304 * 1024
LINE = re.compile(r"^\s*([0-9a-f]+):\t(.*)$")
CMP = re.compile(r"^cmp\s+.*,\s*(0x[0-9a-f]+)\s*$")


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
    ap.add_argument("--sample", type=int, default=300)
    ap.add_argument("images", nargs="+")
    a = ap.parse_args()
    for path in a.images:
        text = subprocess.run(["objdump", "-d", "-M", "intel", "--no-show-raw-insn", path], capture_output=True, text=True, env={**os.environ, "LC_ALL": "C"}).stdout
        insns = []
        for line in text.splitlines():
            m = LINE.match(line)
            if m and m.group(2).strip():
                insns.append((int(m.group(1), 16), m.group(2).strip()))
        addrs = [i[0] for i in insns]
        indirect = {at for at, t in insns if re.match(r"^(notrack\s+)?call\s+(?!(0x)?[0-9a-f]+ <)", t) and "<" not in t.split("#")[0]}

        def nearest_guard(at):
            i = bisect.bisect_left(addrs, at)
            for j in range(i - 1, max(i - 40, 0), -1):
                m = CMP.match(insns[j][1])
                if m and j + 1 < len(insns) and insns[j + 1][1].startswith(("ja ", "jae ", "jnb ")):
                    v = int(m.group(1), 16)
                    return v if insns[j + 1][1].startswith("ja ") else v - 1
            return None

        print(os.path.basename(path), f"{len(insns)} instructions, {len(indirect)} indirect calls by objdump")
        for tag, binary in (("old", a.old), ("new", a.new)):
            if not binary:
                continue
            engine = Engine(binary, path)
            functions = [f for f in engine.ask("function discover --limit 0")["data"]["functions"] if f.get("end")]
            functions = functions[:: max(1, len(functions) // a.sample)][: a.sample]
            kinds = Counter()
            agree = extra = missed = 0
            untruncated_with_indirect = 0
            bounds = Counter()
            first = []
            for f in functions:
                start, end = int(f["va"], 16), int(f["end"], 16)
                answer = engine.ask(f"function trace --addr {start:#x} --depth 0").get("data", {})
                rows = answer.get("nodes", [{}])[0].get("calls", []) if answer.get("nodes") else []
                no_target = {int(r["from"], 16) for r in rows if "target" not in r}
                for r in rows:
                    if "target" not in r:
                        kinds[r["kind"]] += 1
                shown = {at for at in indirect if start <= at < end}
                agree += len(no_target & shown)
                extra += len(no_target - shown)
                missed += len(shown - no_target)
                if no_target and answer.get("truncated") is False:
                    untruncated_with_indirect += 1
                lines = engine.ask(f"ir explain --addr {start:#x}").get("data", {}).get("lines", [])
                for line in lines:
                    m = re.search(r"^\s*(0x[0-9a-f]+) .* bound=(\S+) -> (\d+) cases", line)
                    if not m:
                        continue
                    at, bound = int(m.group(1), 16), m.group(2)
                    guard = nearest_guard(at)
                    if bound == "?":
                        bounds["unknown, objdump shows a guard" if guard is not None else "unknown, objdump shows none"] += 1
                    elif guard == int(bound):
                        bounds["agree"] += 1
                    else:
                        bounds["differs"] += 1
                        if len(first) < 6:
                            first.append((hex(at), bound, guard))
            engine.close()
            print(f"  {tag}: {len(functions)} functions; no-target rows agree {agree}, extra {extra}, missed {missed}, called {dict(kinds)}, truncated:false with one {untruncated_with_indirect}; bounds {dict(bounds)}")
            for row in first:
                print(f"    {row}")


if __name__ == "__main__":
    main()

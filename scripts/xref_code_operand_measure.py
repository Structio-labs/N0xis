#!/usr/bin/env python3
"""Hold `xref to`'s `immediate` rows against what the linker resolved, on a fixed image built with
`-Wl,--emit-relocs`.

    python3 scripts/xref_code_operand_measure.py --new NEW [--old OLD] [--sample N] IMAGE...

On a fixed image an address in an instruction is a bare value, with nothing in the image to say so. `--emit-relocs`
keeps the relocations the linker applied to code, in tables no loader reads and the engine does not take: each
`R_X86_64_32`, `_32S`, `_64` or `R_386_32` in `.rela.text`/`.rel.text` is an address an instruction states,
known before the question. For N of their targets, evenly spread:

- **missed**: an instruction such a relocation is in, which the answer does not list;
- **false**: an `immediate` row whose instruction holds no such relocation to that target.

Each engine runs in a project of its own under `ulimit -v 4194304`.
"""

import argparse
import json
import os
import re
import resource
import subprocess
import tempfile
from collections import defaultdict

LIMIT = 4194304 * 1024
LINE = re.compile(r"^\s*([0-9a-f]+):\t")


def tool(*args):
    return subprocess.run(args, capture_output=True, text=True, errors="replace", env={**os.environ, "LC_ALL": "C"}).stdout


class Engine:
    def __init__(self, binary, image):
        self.dir = tempfile.TemporaryDirectory()
        os.mkdir(os.path.join(self.dir.name, ".n0x"))

        def limited():
            resource.setrlimit(resource.RLIMIT_AS, (LIMIT, LIMIT))

        env = {**os.environ, "N0X_NO_UPDATE_CHECK": "1", "XDG_DATA_HOME": self.dir.name}
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
    ap.add_argument("--sample", type=int, default=200)
    ap.add_argument("images", nargs="+")
    a = ap.parse_args()
    for path in a.images:
        starts = sorted(int(m.group(1), 16) for m in map(LINE.match, tool("objdump", "-d", path).splitlines()) if m)
        import bisect

        def instruction_of(slot):
            i = bisect.bisect_right(starts, slot) - 1
            return starts[i] if i >= 0 else None

        data = open(path, "rb").read()
        segments = [(int(f[2], 16), int(f[1], 16), int(f[4], 16)) for f in (l.split() for l in tool("readelf", "-lW", path).splitlines()) if len(f) >= 6 and f[0] == "LOAD"]

        def word(va, size, signed):
            for vaddr, offset, filesz in segments:
                if vaddr <= va and va + size <= vaddr + filesz:
                    v = int.from_bytes(data[va - vaddr + offset : va - vaddr + offset + size], "little", signed=signed)
                    return v & 0xFFFFFFFFFFFFFFFF
            return None

        truth = defaultdict(set)
        in_text = False
        for line in tool("readelf", "-rW", path).splitlines():
            if line.startswith("Relocation section"):
                in_text = ".rela.text'" in line or ".rel.text'" in line
                continue
            f = line.split()
            if not in_text or len(f) < 5 or f[2] not in ("R_X86_64_32", "R_X86_64_32S", "R_X86_64_64", "R_386_32"):
                continue
            # What the linker wrote there: a `REL` table keeps its addend in the word, so
            # the word is the one value both formats agree on.
            value = word(int(f[0], 16), 8 if f[2] == "R_X86_64_64" else 4, f[2] == "R_X86_64_32S")
            if value is None:
                continue
            at = instruction_of(int(f[0], 16))
            if at is not None:
                truth[value].add(at)
        targets = sorted(truth)
        targets = targets[:: max(1, len(targets) // a.sample)][: a.sample]
        print(f"{os.path.basename(path)}: {sum(len(v) for v in truth.values())} instructions state an address the linker resolved, {len(truth)} targets, asked {len(targets)}")
        for tag, binary in (("old", a.old), ("new", a.new)):
            if not binary:
                continue
            engine = Engine(binary, path)
            found = missed = false = 0
            first = []
            unlisted = []
            for t in targets:
                rows = engine.ask(f"xref to --addr {t:#x}").get("data", {}).get("refs", [])
                listed = {int(r["from"], 16) for r in rows if r["kind"] == "immediate"}
                found += len(listed & truth[t])
                missed += len(truth[t] - listed)
                unlisted.extend((hex(t), hex(m)) for m in sorted(truth[t] - listed)[:1])
                wrong = listed - truth[t]
                false += len(wrong)
                first.extend((hex(t), hex(w)) for w in sorted(wrong)[:2])
            engine.close()
            print(f"  {tag}: found {found}, missed {missed}, false {false}")
            for row in first[:6]:
                print(f"    false: {row}")
            if tag == "new":
                for row in unlisted[:6]:
                    print(f"    missed: {row}")


if __name__ == "__main__":
    main()

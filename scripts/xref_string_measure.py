#!/usr/bin/env python3
"""Hold `xref string`'s `found_unreferenced` against what `objdump` and `readelf` say reaches each string.

    python3 scripts/xref_string_measure.py --new NEW [--old OLD] [--sample N] [--terminated auto|yes|no] IMAGE...

For each ELF image, `strings -t x` gives the texts, and the last few bytes of every N-th are asked for, so most
queries start inside a longer string. Truth, from outside the tool:

- what names an address: each `# <hex>` comment in `objdump -d`, on a fixed image each hex immediate, and each
  relocation of `readelf -rW` with the value it gives;
- what an occurrence is: the query's bytes in `.rodata`, `.data.rel.ro` or `.data`, as the file holds them;
- what reaches it: an address from the start of its string to its last byte. On an image rustc built, where
  strings are cut by a length and have no NUL, only from its first byte to its last.

**said unreferenced, reached** is the defect this script exists for: the answer's `found_unreferenced` is more than
the occurrences nothing reaches. **said reached, nothing reaches** is the other direction.
"""

import argparse
import json
import os
import re
import resource
import subprocess
import tempfile

LIMIT = 4194304 * 1024
SECTIONS = {".rdata", ".rodata", ".data.rel.ro", ".data"}
COMMENT = re.compile(r"# ([0-9a-f]+)")
IMM = re.compile(r",\s*0x([0-9a-f]+)\s*$")
MAX_BEFORE = 4096


def tool(*args):
    return subprocess.run(args, capture_output=True, text=True, errors="replace", env={**os.environ, "LC_ALL": "C"}).stdout


class Engine:
    def __init__(self, binary, image):
        self.dir = tempfile.TemporaryDirectory()
        os.mkdir(os.path.join(self.dir.name, ".n0x"))
        env = {**os.environ, "N0X_NO_UPDATE_CHECK": "1", "XDG_DATA_HOME": self.dir.name}

        def limited():
            resource.setrlimit(resource.RLIMIT_AS, (LIMIT, LIMIT))

        self.p = subprocess.Popen([os.path.abspath(binary), "serve", "--file", os.path.abspath(image)], cwd=self.dir.name, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, preexec_fn=limited)
        self.p.stdout.readline()

    def ask(self, argv):
        self.p.stdin.write(json.dumps(argv) + "\n")
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
    ap.add_argument("--terminated", default="auto")
    ap.add_argument("images", nargs="+")
    a = ap.parse_args()
    for path in a.images:
        data = open(path, "rb").read()
        fixed = "EXEC" in next((l for l in tool("readelf", "-hW", path).splitlines() if "Type:" in l), "")
        rust = b"rustc version " in data or re.search(rb"/rustc/[0-9a-f]{40}/", data) is not None
        terminated = a.terminated == "yes" or (a.terminated == "auto" and not rust)
        sections = []
        for line in tool("readelf", "-SW", path).splitlines():
            f = line.replace("[ ", "[").split()
            if len(f) >= 6 and f[0].startswith("[") and f[1] in SECTIONS:
                sections.append((f[1], int(f[3], 16), int(f[4], 16), int(f[5], 16)))
        named = set()
        for line in tool("objdump", "-d", "-M", "intel", "--no-show-raw-insn", path).splitlines():
            m = COMMENT.search(line)
            if m:
                named.add(int(m.group(1), 16))
            elif fixed:
                m = IMM.search(line)
                if m:
                    named.add(int(m.group(1), 16))
        for line in tool("readelf", "-rW", path).splitlines():
            f = line.split()
            if len(f) >= 4 and f[2].endswith("_RELATIVE") and all(c in "0123456789abcdef" for c in f[3]):
                named.add(int(f[3], 16))
        # A fixed image's stored pointers, and a RELR word's value.
        import struct

        for _, va, off, size in sections:
            skip = -va % 8
            for i in range(off + skip, off + size - 7, 8):
                named.add(struct.unpack_from("<Q", data, i)[0])
        named = sorted(named)

        def reached(lo, hi):
            import bisect

            i = bisect.bisect_left(named, lo)
            return i < len(named) and named[i] < hi

        queries = []
        for name, va, off, size in sections:
            blob = data[off : off + size]
            for m in re.finditer(rb"[\x20-\x7e]{10,}", blob):
                queries.append(m.group(0)[-8:])
        queries = sorted(set(queries))
        queries = queries[:: max(1, len(queries) // a.sample)][: a.sample]
        truth = {}
        for q in queries:
            unref = 0
            for name, va, off, size in sections:
                blob = data[off : off + size]
                pos = blob.find(q)
                while pos >= 0:
                    occ = va + pos
                    start = occ
                    if terminated:
                        start = va + max(blob.rfind(b"\0", 0, pos) + 1, pos - MAX_BEFORE)
                    if not reached(start, occ + len(q)):
                        unref += 1
                    pos = blob.find(q, pos + 1)
            truth[q] = unref
        print(f"{os.path.basename(path)}: {len(queries)} queries, {'NUL-terminated' if terminated else 'cut by a length'}; truth says {sum(1 for v in truth.values() if v)} have an unreferenced occurrence")
        for tag, binary in (("old", a.old), ("new", a.new)):
            if not binary:
                continue
            engine = Engine(binary, path)
            more = less = same = refused = rows = 0
            first = []
            for q in queries:
                text = q.decode("latin-1")
                answer = engine.ask(["xref", "string", "--query", text, "--limit", "100000"])
                if not answer.get("ok"):
                    refused += 1
                    continue
                said = answer["data"]["found_unreferenced"]
                rows += sum(len(h["xrefs"]) for h in answer["data"]["hits"])
                if said > truth[q]:
                    more += 1
                    if len(first) < 5:
                        first.append((text, said, truth[q]))
                elif said < truth[q]:
                    less += 1
                    if len(first) < 5:
                        first.append((text, said, truth[q]))
                else:
                    same += 1
            engine.close()
            print(f"  {tag}: agree {same}, said unreferenced and reached {more}, said reached and nothing reaches {less}, refused {refused}, rows {rows}")
            if tag == "new":
                for row in first:
                    print(f"    {row}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Hold `xref to`'s words of data against the image's own tables, read by `readelf` and `nm`.

    python3 scripts/xref_data_measure.py --new NEW [--old OLD] [--sample N] [--open K] IMAGE...

For each ELF image:

- **truth** is every relocation `readelf -rW` lists that gives a word an address in an executable
  section of this image (RELATIVE and IRELATIVE by addend, 64/GLOB_DAT/JUMP_SLOT by the symbol
  value it prints, and RELR by the word in the file). Those in a `_ZTV` object of `nm -S` are also
  counted apart, as vtable slots;
- **missed** is a true word the answer for its target does not list;
- **false** is a `data_word` the answer lists that this truth does not have, on an image whose
  relocations decide (on a fixed image, a word the file does not hold);
- `--open K` prints K rows of each evidence, with the word read from the file, for reading by eye.

A fixed image has no relocation to hold a word against, so build it with `-Wl,--emit-relocs`: the linker
then keeps what it resolved, in tables the loader never reads and the engine does not take. Its `R_X86_64_64`
entries outside code are every stored pointer, known before the question, so a `matching_value` they do not
list is false, and one of them the answer lacks is missed.

`--sample N` asks about at most N targets, evenly spread, and says so. Each engine runs in a project of
its own, under `ulimit -v 4194304`. The answer of OLD is read the same way, so a metric that reports
zero first shows that it can report something else.
"""

import argparse
import json
import os
import resource
import struct
import subprocess
import tempfile
from collections import Counter, defaultdict

LIMIT = 4194304 * 1024


def tool(*args):
    return subprocess.run(args, capture_output=True, text=True, env={**os.environ, "LC_ALL": "C"}).stdout


class Image:
    def __init__(self, path):
        self.path = path
        self.bytes = open(path, "rb").read()
        self.segments = []
        self.fixed = "EXEC" in next((l for l in tool("readelf", "-hW", path).splitlines() if "Type:" in l), "")
        for line in tool("readelf", "-lW", path).splitlines():
            f = line.split()
            if len(f) >= 6 and f[0] == "LOAD":
                self.segments.append((int(f[2], 16), int(f[1], 16), int(f[4], 16)))
        self.code = []
        for line in tool("readelf", "-SW", path).splitlines():
            f = line.replace("[ ", "[").split()
            if len(f) >= 8 and f[0].startswith("[") and "X" in f[7] and int(f[5], 16) > 0:
                self.code.append((int(f[3], 16), int(f[5], 16)))

    def in_code(self, va):
        return any(s <= va < s + n for s, n in self.code)

    def word(self, va):
        for vaddr, offset, filesz in self.segments:
            if vaddr <= va and va + 8 <= vaddr + filesz:
                return struct.unpack_from("<Q", self.bytes, va - vaddr + offset)[0]
        return None

    def relocations(self):
        """Slot -> (target, kind) for every relocation that gives a word an address of this image."""
        out = {}
        relr = False
        skip = False
        for line in tool("readelf", "-rW", self.path).splitlines():
            if line.startswith("Relocation section"):
                relr = ".relr" in line
                # What `--emit-relocs` keeps of code and of bookkeeping is no word of data.
                skip = any(f"'.rela{s}'" in line for s in (".text", ".init", ".fini", ".eh_frame", ".sframe", ".note.stapsdt", ".gcc_except_table"))
                continue
            if skip:
                continue
            f = line.split()
            if not f:
                continue
            if relr:
                # `0016:  <entry> <address>  <symbol>`, or `<address>  <symbol>` for the
                # further words of the same bitmap.
                at = f[2] if f[0].endswith(":") and len(f) >= 3 else f[0]
                if len(at) >= 8 and all(c in "0123456789abcdef" for c in at):
                    value = self.word(int(at, 16))
                    if value is not None:
                        out[int(at, 16)] = (value, "RELR")
                continue
            if len(f) < 3 or not all(c in "0123456789abcdef" for c in f[0]):
                continue
            slot, kind = int(f[0], 16), f[2]
            if kind.endswith(("_RELATIVE", "_IRELATIVE")):
                # `<offset> <info> <type> <addend>`
                out[slot] = (int(f[3], 16), kind)
            elif kind.endswith(("_64", "_GLOB_DAT", "_JUMP_SLOT")) and len(f) >= 4:
                value = int(f[3], 16)
                addend = int(f[-1], 16) if len(f) >= 7 and f[-2] == "+" else 0
                if value:
                    out[slot] = (value + addend, kind)
        return out

    def vtable_slots(self):
        """The slots inside `_ZTV` objects, by `nm -S`."""
        slots = set()
        for args in (["nm", "-S"], ["nm", "-DS"]):
            for line in tool(*args, self.path).splitlines():
                f = line.split()
                if len(f) == 4 and "_ZTV" in f[3]:
                    start, size = int(f[0], 16), int(f[1], 16)
                    slots.update(range(start, start + size, 8))
        return slots


class Engine:
    def __init__(self, binary, image):
        self.dir = tempfile.TemporaryDirectory()
        os.mkdir(os.path.join(self.dir.name, ".n0x"))
        env = {**os.environ, "N0X_NO_UPDATE_CHECK": "1", "XDG_DATA_HOME": self.dir.name}

        def limited():
            resource.setrlimit(resource.RLIMIT_AS, (LIMIT, LIMIT))

        self.p = subprocess.Popen([binary, "serve", "--file", image], cwd=self.dir.name, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, preexec_fn=limited)
        self.p.stdout.readline()

    def ask(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def close(self):
        self.p.stdin.close()
        self.p.wait()
        self.dir.cleanup()


def measure(binary, image, truth, targets, keep_rows):
    engine = Engine(binary, image.path)
    found = set()
    false = []
    evidence = Counter()
    rows = defaultdict(list)
    for target in targets:
        answer = engine.ask(f"xref to --addr {target:#x}")
        for row in answer.get("data", {}).get("refs", []):
            kind = row.get("kind")
            if kind not in ("data_word",):
                if kind not in ("call", "jmp", "cond_jmp", "data", "branch"):
                    evidence[kind] += 1
                    rows[kind].append(row)
                continue
            slot = int(row["slot"], 16)
            evidence[row["evidence"]] += 1
            rows[row["evidence"]].append(row)
            real = truth.get(slot)
            if real and real[0] == target:
                found.add(slot)
            elif row["evidence"] == "matching_value" and image.fixed and not truth and image.word(slot) == target:
                found.add(slot)
            else:
                false.append((slot, target, row["evidence"]))
    engine.close()
    return found, false, evidence, rows if keep_rows else {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--new", required=True)
    ap.add_argument("--old")
    ap.add_argument("--sample", type=int, default=0)
    ap.add_argument("--open", type=int, default=0)
    ap.add_argument("images", nargs="+")
    a = ap.parse_args()
    for path in a.images:
        image = Image(path)
        truth = {s: t for s, t in image.relocations().items() if image.in_code(t[0])}
        vtable = image.vtable_slots() & set(truth)
        targets = sorted({t for t, _ in truth.values()})
        whole = len(targets)
        if a.sample and whole > a.sample:
            targets = targets[:: whole // a.sample + 1]
        asked = set(targets)
        wanted = {s for s, t in truth.items() if t[0] in asked}
        print(f"{os.path.basename(path)}: {len(truth)} words give code an address, {len(vtable)} of them vtable slots, {whole} targets, asked {len(targets)}")
        for tag, binary in (("old", a.old), ("new", a.new)):
            if not binary:
                continue
            found, false, evidence, rows = measure(binary, image, truth, targets, tag == "new")
            missed = wanted - found
            print(f"  {tag}: found {len(found & wanted)} of {len(wanted)}, missed {len(missed)} ({len(missed & vtable)} vtable slots of {len(vtable & wanted)}), false {len(false)}, evidence {dict(evidence)}")
            for slot, target, ev in false[:5]:
                print(f"    false: slot {slot:#x} -> {target:#x} {ev}")
            for slot in sorted(missed)[:5]:
                print(f"    missed: slot {slot:#x} -> {truth[slot][0]:#x} {truth[slot][1]}")
            if tag == "new" and a.open:
                for kind, some in rows.items():
                    print(f"    {kind}: {len(some)}")
                    for row in some[:: max(1, len(some) // a.open)][: a.open]:
                        slot = int(row["slot"], 16)
                        print(f"      {row['slot']} {row['section']} word {image.word(slot)} -> {row['to']} table {row.get('relative_to')}")


if __name__ == "__main__":
    main()

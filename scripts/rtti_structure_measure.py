#!/usr/bin/env python3
"""Hold `rtti scan` on a stripped copy of an image against `nm -S` of the image before `strip`.

    python3 scripts/rtti_structure_measure.py --new NEW [--old OLD] [--as-is] IMAGE...

For each image with `_ZTV` symbols: `strip` a copy, ask the engine about the copy, and compare with `nm`:

- **found**: a class `nm` has a defined `_ZTV` for, listed with its vptr inside that object;
- **at the wrong place**: listed, with a vptr outside the object or not two words in, where it has no virtual
  bases to move it;
- **invented**: listed, and `nm` has no such `_ZTV`;
- **missed**: `nm` has the `_ZTV`, and the class is neither listed nor counted as refused.

`__cxxabiv1` tables a copy relocation fills are the runtime's and are left out on both sides.

`--as-is` is for an image with `.dynsym` only, which cannot be held this way. It asks of the image itself, and for
each row with no `_ZTV` in `nm -D`, reads with this script's own eyes: the word before the vptr, and the name the
`type_info` points at, by `readelf -r` and the file's bytes. A row is **confirmed** when that string is the row's
mangled name. Each engine runs in a project of its own under `ulimit -v 4194304`.
"""

import argparse
import json
import os
import resource
import shutil
import struct
import subprocess
import tempfile

LIMIT = 4194304 * 1024


def tool(*args):
    return subprocess.run(args, capture_output=True, text=True, errors="replace", env={**os.environ, "LC_ALL": "C"}).stdout


def scan(binary, path):
    with tempfile.TemporaryDirectory() as d:
        os.mkdir(os.path.join(d, ".n0x"))

        def limited():
            resource.setrlimit(resource.RLIMIT_AS, (LIMIT, LIMIT))

        p = subprocess.run([os.path.abspath(binary), "rtti", "scan", "--file", os.path.abspath(path)], cwd=d, capture_output=True, text=True, preexec_fn=limited, env={**os.environ, "N0X_NO_UPDATE_CHECK": "1", "XDG_DATA_HOME": d})
        return json.loads(p.stdout)


def ztvs(path, dynamic=False):
    out = {}
    for line in tool("nm", "-D" if dynamic else "-a", "-S", path).splitlines():
        f = line.split()
        if len(f) == 4 and f[3].startswith("_ZTV") and f[2] not in "Uw":
            name = f[3].split("@")[0]
            if "__cxxabiv1" not in name:
                out[name] = (int(f[0], 16), int(f[1], 16))
    return out


class Bytes:
    def __init__(self, path):
        self.data = open(path, "rb").read()
        self.segments = []
        for line in tool("readelf", "-lW", path).splitlines():
            f = line.split()
            if len(f) >= 6 and f[0] == "LOAD":
                self.segments.append((int(f[2], 16), int(f[1], 16), int(f[4], 16)))
        self.values = {}
        relr = False
        for line in tool("readelf", "-rW", path).splitlines():
            if line.startswith("Relocation section"):
                relr = ".relr" in line
                continue
            f = line.split()
            if not f:
                continue
            if relr:
                at = f[2] if f[0].endswith(":") and len(f) >= 3 else f[0]
                if len(at) >= 8 and all(c in "0123456789abcdef" for c in at):
                    self.values[int(at, 16)] = self.word(int(at, 16))
                continue
            if len(f) >= 4 and all(c in "0123456789abcdef" for c in f[0]) and f[2].endswith("_RELATIVE"):
                self.values[int(f[0], 16)] = int(f[3], 16)
            elif len(f) >= 7 and all(c in "0123456789abcdef" for c in f[0]) and f[2].endswith("_64") and f[-2] == "+":
                self.values[int(f[0], 16)] = int(f[3], 16) + int(f[-1], 16)

    def word(self, va):
        for vaddr, offset, filesz in self.segments:
            if vaddr <= va and va + 8 <= vaddr + filesz:
                return struct.unpack_from("<Q", self.data, va - vaddr + offset)[0]
        return None

    def pointer(self, va):
        return self.values.get(va, self.word(va))

    def string(self, va):
        for vaddr, offset, filesz in self.segments:
            if va is not None and vaddr <= va < vaddr + filesz:
                at = va - vaddr + offset
                return self.data[at : self.data.index(b"\0", at)].decode("latin-1")
        return None


def moved_ok(whole, name, vptr):
    """`{name}` when the word before `vptr` holds the class's `_ZTI`, by `nm` and the file's bytes."""
    zti = next((int(l.split()[0], 16) for l in tool("nm", "-a", whole).splitlines() if l.split()[-1:] == ["_ZTI" + name[4:]]), None)
    b = Bytes(whole)
    return {name} if zti is not None and b.pointer(vptr - 8) == zti else set()


def against_nm(tag, binary, whole, stripped):
    truth = ztvs(whole)
    answer = scan(binary, stripped)
    if not answer.get("ok"):
        print(f"  {tag}: refused: {answer.get('error')}")
        return
    data = answer["data"]
    rows = [r for r in data["vtables"] if "__cxxabiv1" not in r["mangled"]]
    found = wrong = invented = 0
    seen = set()
    examples = []
    for r in rows:
        name = r["mangled"].split("@")[0]
        seen.add(name)
        if name not in truth:
            invented += 1
            examples.append(("invented", r["name"], r["vtable"]))
            continue
        at, size = truth[name]
        vptr = int(r["vtable"], 16)
        # With a virtual base the header is longer, and the vptr further in: found.
        if vptr == at + 16 or (at + 16 < vptr < at + size and name in moved_ok(whole, name, vptr)):
            found += 1
        else:
            wrong += 1
            examples.append(("place", r["name"], r["vtable"], hex(at)))
    refused = {k: v for k, v in data.items() if k.startswith("refused") and v}
    missed = len(set(truth) - seen) - sum(refused.values())
    print(f"  {tag}: nm has {len(truth)}; found {found}, at the wrong place {wrong}, invented {invented}, missed {missed}, refused {refused}")
    for e in examples[:6]:
        print(f"    {e}")


def as_is(tag, binary, path):
    truth = ztvs(path, dynamic=True)
    answer = scan(binary, path)
    data = answer.get("data", {})
    rows = data.get("vtables", [])
    extra = [r for r in rows if r["mangled"].split("@")[0] not in truth]
    b = Bytes(path)
    confirmed = 0
    bad = []
    for r in extra:
        info = b.pointer(int(r["type_descriptor"], 16))
        name = b.string(b.pointer(info + 8)) if info else None
        if name and "_ZTV" + name.lstrip("*") == r["mangled"]:
            confirmed += 1
        else:
            bad.append((r["name"], r["vtable"], name))
    refused = {k: v for k, v in data.items() if k.startswith("refused") and v}
    print(f"  {tag}: rows {len(rows)}, `nm -D` has {len(truth)}; {len(extra)} with no symbol, {confirmed} confirmed by bytes, {len(bad)} not; refused {refused}")
    for e in bad[:6]:
        print(f"    {e}")
    for r in extra[:: max(1, len(extra) // 10)][:10]:
        print(f"    {r['name'][:60]} {r['vtable']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--new", required=True)
    ap.add_argument("--old")
    ap.add_argument("--as-is", action="store_true")
    ap.add_argument("images", nargs="+")
    a = ap.parse_args()
    for path in a.images:
        print(os.path.basename(path))
        if a.as_is:
            if a.old:
                as_is("old", a.old, path)
            as_is("new", a.new, path)
            continue
        with tempfile.TemporaryDirectory() as d:
            stripped = os.path.join(d, "stripped")
            shutil.copy(path, stripped)
            subprocess.check_call(["strip", stripped])
            if a.old:
                against_nm("old", a.old, path, stripped)
            against_nm("new", a.new, path, stripped)


if __name__ == "__main__":
    main()

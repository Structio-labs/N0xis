#!/usr/bin/env python3
"""Hold one engine's answers against another's, byte for byte, by digest.

    python3 scripts/answers_unchanged.py --old OLD --new NEW IMAGE...
    python3 scripts/answers_unchanged.py --old OLD --new NEW --rows-of IMAGE...

The first form runs each command on each image, compact and `--pretty`. The second is for an image
whose whole `strings --limit 0 --min 1` is past what OLD can build under the address-space limit: OLD
gives it page by page, and the rows of its pages, joined, must be the rows NEW gives at once.

Every run is under `ulimit -v 4194304` and a stated ceiling, in a project of its own. Prints a line for each
difference and a summary with how many answers were `ok:true`: all of them refusing would be a check of nothing.
A command OLD and NEW both refuse, or both stop at the ceiling, counts as the same and says so.
Prints the sha256 of both binaries, since the comparison is only as good as its base.
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

LIMIT = 4194304 * 1024
CEILING = "3500M"
# `{f}` is the image, `{a}` an address of a function in it, or the command is skipped when it has none.
COMMANDS = [
    "strings --file {f}",
    "strings --file {f} --limit 0",
    "strings --file {f} --limit 0 --min 8 --all-sections",
    "strings --file {f} --limit 50 --offset 7 --min 2",
    "strings --file {f} --limit 0 --contains e --min 6",
    "strings --file {f} --limit 0 --encoding utf16le",
    "strings --file {f} --limit 0 --encoding utf8 --min 12",
    "strings --file {f} --limit 5 --offset 99999999",
    "strings --file {f} --section .no-such-section",
    "strings --bytes 616263640065666768 --start 0x1000 --size 9",
    "imports --file {f}",
    "function discover --file {f} --limit 200",
    "function noreturn --file {f}",
    "disasm --addr {a} --file {f} --count 40",
    "decomp pseudo --addr {a} --file {f}",
    "ir build --addr {a} --file {f}",
    "find --file {f} --string error --limit 20",
    "find --file {f} --string e --limit 0",
    "xref string --file {f} --query e --limit 0",
    "rtti scan --file {f}",
    "contradictions --file {f} --limit 0",
    "capability list",
    "scan aob --file {f} --start {a} --size 64 --pattern ??",
    "scan value --file {f} --start {a} --size 256 --type u8 --criterion unknown --save-as w --force",
]

# Differences meant to be there: a command's answer gained these keys in `data`, on purpose. Such an answer is
# compared with them taken out of NEW's `data`, every other byte as before, and printed as INTENDED with the
# reason; any other difference is still a DIFFER.
COVERAGE = ["regions_scanned", "regions_not_read", "not_read", "regions_read_short", "read_short", "searched"]
INTENDED = {
    "scan aob --file": (COVERAGE, "a file window says what it searched and did not read, as every scan does (claims audit 2026-11)"),
    "scan value --file": (COVERAGE, "a file window says what it searched and did not read, as every scan does (claims audit 2026-11)"),
}
ELAPSED = re.compile(rb'"elapsed_ms"\s*:\s*\d+')
# What a change meant to add: (command, key path in the answer, why). The key is taken out of both answers before
# they are compared, and how many it was taken from is printed, so that a difference anywhere else still shows and
# the list cannot hide a key that is not there. Only for commands whose answer is small enough to read whole.
# Named apart from INTENDED above: two branches each brought one under the same name, and the
# second replaced the first, so the script stopped at its first scan.
INTENDED_KEYS = [
    ("ir build", ("data", "end_by"), "how the graph's end was decided, in every graph: a cut one read as whole"),
]


def intended_for(args):
    cmd = " ".join(args[:2])
    return [path for c, path, _ in INTENDED_KEYS if c == cmd]


def without(text, paths):
    """`text` with each key path taken out, compact, and how many it was in."""
    import json
    try:
        v = json.loads(text)
    except ValueError:
        return text, 0
    found = 0
    for path in paths:
        node = v
        for k in path[:-1]:
            node = node.get(k) if isinstance(node, dict) else None
        if isinstance(node, dict) and path[-1] in node:
            del node[path[-1]]
            found += 1
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False).encode(), found


def limited():
    resource.setrlimit(resource.RLIMIT_AS, (LIMIT, LIMIT))


def run(binary, args, cwd):
    env = {**os.environ, "N0X_MEMORY_MAX": CEILING, "N0X_NO_UPDATE_CHECK": "1", "N0X_CONFIG_DIR": str(Path(cwd) / "config")}
    p = subprocess.Popen([binary, *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, preexec_fn=limited, env=env, cwd=cwd)
    digest, size, head, tail = hashlib.sha256(), 0, b"", b""
    paths = intended_for(args)
    if paths:
        whole = p.stdout.read()
        text, found = without(ELAPSED.sub(b'"elapsed_ms":0', whole), paths)
        digest.update(text)
        return {"exit": p.wait(), "digest": digest.hexdigest(), "size": len(whole), "head": whole[:400], "tail": whole[-400:], "intended": found}
    while chunk := p.stdout.read(1 << 20):
        # Wall time differs from run to run and says nothing about the answer. It is near the end of a
        # line, and a chunk boundary inside it would show as a difference: never silently the same.
        digest.update(ELAPSED.sub(b'"elapsed_ms":0', chunk))
        size += len(chunk)
        head = head or chunk[:400]
        tail = (tail + chunk)[-400:]
    return {"exit": p.wait(), "digest": digest.hexdigest(), "size": size, "head": head, "tail": tail, "intended": 0}


def project():
    d = Path(tempfile.mkdtemp(prefix="unchanged-", dir=Path.home() / ".cache"))
    (d / ".n0x").mkdir()
    return d


def first_function(old, image):
    d = project()
    try:
        p = run_capture(old, ["function", "discover", "--file", image, "--limit", "3"], d)
        found = re.findall(rb'"(?:address|start|va)"\s*:\s*"(0x[0-9a-f]+)"', p)
        return found[-1].decode() if found else None
    finally:
        shutil.rmtree(d, ignore_errors=True)


def run_capture(binary, args, cwd):
    env = {**os.environ, "N0X_MEMORY_MAX": CEILING, "N0X_NO_UPDATE_CHECK": "1", "N0X_CONFIG_DIR": str(Path(cwd) / "config")}
    return subprocess.run([binary, *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, preexec_fn=limited, env=env, cwd=cwd).stdout


def compare(job):
    old, new, image, addr, template, pretty = job
    if "{a}" in template and not addr:
        return None
    args = template.format(f=image, a=addr).split() + ["--quiet"] * ("capability" not in template) + ["--pretty"] * pretty
    # Each engine in its own project: a command may persist what it found, and the second must not read the first's.
    results = []
    for binary in (old, new):
        d = project()
        try:
            results.append(run(binary, args, d))
        finally:
            shutil.rmtree(d, ignore_errors=True)
    a, b = results
    same = a["digest"] == b["digest"] and a["exit"] == b["exit"]
    ok = re.search(rb'"ok"\s*:\s*true', a["head"]) is not None
    intended = next((v for k, v in INTENDED.items() if template.startswith(k)), None)
    if not same and intended:
        same = intended_only(old, new, args, intended[0]) and a["exit"] == b["exit"]
        intended = intended[1] if same else None
    return {"image": image, "cmd": " ".join(args), "same": same, "ok": ok, "size": a["size"], "old": a, "new": b, "intended": intended if not a["digest"] == b["digest"] else None}


def intended_only(old, new, args, added):
    """OLD's and NEW's answers are the same once the keys `added` are taken out of NEW's `data`."""
    answers = []
    for binary in (old, new):
        d = project()
        try:
            answers.append(json.loads(ELAPSED.sub(b'"elapsed_ms":0', run_capture(binary, args, d))))
        except ValueError:
            return False
        finally:
            shutil.rmtree(d, ignore_errors=True)
    a, b = answers
    if isinstance(b.get("data"), dict):
        for k in added:
            b["data"].pop(k, None)
    return a == b


def rows_of(text):
    """The bytes of `data.strings` in one compact answer. `,"meta"` cannot end it early: quotes in a text are escaped."""
    start = text.index(b'"strings":[') + len(b'"strings":[')
    end = text.rindex(b'],"meta":{"schema"') if b'],"meta":{"schema"' in text else text.rindex(b"]}")
    return text[start:end]


def rows_check(old, new, image):
    d = project()
    try:
        whole = run_capture(new, ["strings", "--file", image, "--limit", "0", "--min", "1", "--quiet"], d)
        if not whole.startswith(b'{"ok":true'):
            return f"{image}: new did not answer: {whole[:160]!r}"
        rows = rows_of(whole)
        digest, offset, pages, page_size, joined = hashlib.sha256(), 0, 0, 150000, 0
        while True:
            page = run_capture(old, ["strings", "--file", image, "--limit", str(page_size), "--offset", str(offset), "--min", "1", "--quiet"], d)
            if not page.startswith(b'{"ok":true'):
                return f"{image}: old page at {offset} did not answer: {page[:160]!r}"
            got = rows_of(page)
            if not got:
                break
            digest.update(b"," if pages else b"")
            digest.update(got)
            joined += len(got) + bool(pages)
            pages += 1
            offset += page_size
        same = digest.hexdigest() == hashlib.sha256(rows).hexdigest()
        return f"{image}: rows {'SAME' if same else 'DIFFER'}: old in {pages} pages, {joined} bytes; new at once, {len(rows)} bytes"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--old", required=True)
    ap.add_argument("--new", required=True)
    ap.add_argument("--rows-of", action="store_true")
    ap.add_argument("-j", type=int, default=3)
    ap.add_argument("images", nargs="+")
    args = ap.parse_args()
    for name, path in (("old", args.old), ("new", args.new)):
        print(name, hashlib.sha256(Path(path).read_bytes()).hexdigest()[:16], path)
    if args.rows_of:
        for image in args.images:
            print(rows_check(args.old, args.new, image), flush=True)
        return 0
    jobs = []
    for image in args.images:
        addr = first_function(args.old, image)
        jobs += [(args.old, args.new, image, addr, t, pretty) for t in COMMANDS for pretty in (False, True)]
    differ = done = ok = 0
    intended = {"old": 0, "new": 0}
    empty = {}
    commands = set()
    with concurrent.futures.ThreadPoolExecutor(args.j) as pool:
        for r in pool.map(compare, jobs):
            if r is None:
                continue
            done += 1
            ok += r["ok"]
            intended["old"] += r["old"]["intended"]
            intended["new"] += r["new"]["intended"]
            commands.add(re.sub(r" --addr.*| --file.*| --bytes.*", "", r["cmd"]))
            if not r["ok"]:
                key = re.sub(r" --addr.*| --file.*| --bytes.*", "", r["cmd"])
                empty[key] = empty.get(key, 0) + 1
            if r.get("intended"):
                print("INTENDED", Path(r["image"]).name, r["cmd"].replace(r["image"], "F"), "--", r["intended"], flush=True)
            if not r["same"]:
                differ += 1
                print("DIFFER", Path(r["image"]).name, r["cmd"].replace(r["image"], "F"), "old", r["old"]["exit"], r["old"]["size"], "new", r["new"]["exit"], r["new"]["size"], flush=True)
    print(f"{done} answers over {len(args.images)} images and {len(commands)} commands: {differ} differ, {ok} of them ok:true")
    print("intended keys taken out:", ", ".join(f"{c} {'.'.join(p)}" for c, p, _ in INTENDED_KEYS), f"(old {intended['old']}, new {intended['new']} answers)")
    print("not ok:true by command:", " ".join(f"{k.replace(' ', '_')}={v}" for k, v in sorted(empty.items())))
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Ask the engine about one image: every start `function discover` lists, and
for each, `why --addr <start>` — its start sources, its end with the end's
source, its name with the layer that gave it.

Exactly what a user gets: the CLI, on the file, in a project directory of its
own (a fresh `.n0x/`, so no cache or annotation of another run answers, and
nothing is written to the user's global project). No `Ctx` is built here.

Every `why` of an image goes through one `serve` session, where a process per
start reloaded the whole image each time. The session's answers were compared
with one-shot `why` before this was adopted: 1 680 answers on 9 images (small and
large ELF on all three machines, PE32+, PE32, a WebAssembly module), byte for
byte the same, 3.6 to 7 times faster.

Usage: measure.py <image> <run-dir> <out.json>
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys

import corpus


def engine_identity() -> dict:
    h = hashlib.sha256(open(corpus.ENGINE, "rb").read()).hexdigest()
    v = subprocess.run([corpus.ENGINE, "--version"], capture_output=True, text=True, env=corpus.TOOL_ENV).stdout.strip()
    return {"path": corpus.ENGINE, "sha256": h, "version": v}


def n0x(args: list, cwd: str) -> dict:
    r = subprocess.run(["timeout", "300", corpus.ENGINE] + args + ["--quiet"], cwd=cwd, capture_output=True, text=True, env=corpus.TOOL_ENV)
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": {"code": "no-envelope", "rc": r.returncode, "stdout": r.stdout[-500:], "stderr": r.stderr[-500:]}}


def why_through_serve(image: str, addrs: list, cwd: str) -> dict:
    """`why` at every address, one session, one answer per request, in lockstep
    (so no pipe can fill). A session that dies leaves what it did not answer as
    an answer with no envelope, which the scorer does not take for a function."""
    # The bound is per start: a flat one cuts a big image's session mid-list, and
    # every start it leaves unanswered then reads as a function not found.
    argv = ["timeout", str(max(500, len(addrs) // 4)), corpus.ENGINE, "serve", "--file", image]
    p = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=corpus.TOOL_ENV)
    out = {}
    p.stdout.readline()  # the session's banner
    for a in addrs:
        try:
            p.stdin.write(json.dumps(["why", "--addr", a]) + "\n")
            p.stdin.flush()
            line = p.stdout.readline()
            out[a] = json.loads(line)
        except (BrokenPipeError, json.JSONDecodeError) as e:
            out[a] = {"ok": False, "error": {"code": "no-envelope", "why": str(e)}}
    try:
        p.stdin.close()
    except BrokenPipeError:
        pass
    p.wait()
    return out


def measure(image: str, run_dir: str) -> dict:
    image = os.path.abspath(image)
    # A fresh project every time: a kept function list of an earlier file at the
    # same path must not answer for this one.
    if os.path.isdir(run_dir):
        shutil.rmtree(run_dir)
    os.makedirs(os.path.join(run_dir, ".n0x"))
    info = n0x(["project", "info"], run_dir)
    if not (info.get("ok") and info["data"].get("is_local")):
        raise SystemExit(f"measure: {run_dir} is not a local project: {info}")
    disc = n0x(["function", "discover", "--file", image], run_dir)
    if not disc.get("ok"):
        return {"image": image, "engine": engine_identity(), "discover": disc, "why": {}}
    if disc["data"].get("truncated"):
        raise SystemExit("measure: discover truncated its list")
    why = why_through_serve(image, [f["va"] for f in disc["data"]["functions"]], run_dir)
    return {"image": image, "engine": engine_identity(), "discover": disc, "why": why}


def main() -> int:
    image, run_dir, out = sys.argv[1], sys.argv[2], sys.argv[3]
    m = measure(image, run_dir)
    json.dump(m, open(out, "w"))
    n = len(m["why"])
    bad = sum(1 for w in m["why"].values() if not w.get("ok"))
    print(f"{image}: {n} starts, {bad} `why` without an answer")
    return 0


if __name__ == "__main__":
    sys.exit(main())

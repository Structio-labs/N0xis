#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Ask the engine every command the obfuscation question touches, on the
measured (obfuscated, stripped) image, in one `serve` session per image so a
process does not reload the image per call.

Commands, exactly as a user runs them:
  function discover                         the function list
  why --addr <s>        per discovered start   where each fact came from
  contradictions                            where two sources disagree (image-wide)
  strings                                   the string literals it finds
  disasm --addr <s> --count N    per truth start   a linear decode
  ir deobfuscate --addr <s>      per truth start   junk / opaque-predicate report
  decomp pseudo --addr <s>       per truth start   pseudo-C
  xref to --addr <s>             per named truth start   who calls it

Truth starts come from `truth.py` on the obfuscated unstripped build; the
measured file shares their addresses (stripping does not move code). Every call
is bounded by `timeout`; a session that dies leaves its unanswered calls as an
answer with no envelope.

Writes MEASURE/<id>.measure.json: the engine identity and every answer.

Usage: obf_measure.py <build.json> <truth.json> <out.measure.json>
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys

import obf_corpus as corpus


def engine_identity() -> dict:
    h = hashlib.sha256(open(corpus.ENGINE, "rb").read()).hexdigest()
    v = subprocess.run([corpus.ENGINE, "--version"], capture_output=True, text=True, env=corpus.TOOL_ENV).stdout.strip()
    return {"path": corpus.ENGINE, "sha256": h, "version": v}


class Serve:
    """One `serve --file <image>` session; a command is a JSON argv array, the
    answer the next line. In lockstep so no pipe fills.

    A command that crashes the engine (e.g. the known `decomp pseudo` stack
    overflow on a deep single-use chain) would otherwise kill the session and
    leave every later command in it unanswered. So a dead session is detected,
    the crashing command is recorded as a crash with the engine's exit signal,
    and the session is restarted for the commands that follow — one defect does
    not blank the rest of an image's measurement."""

    def __init__(self, image: str, cwd: str):
        self.image, self.cwd = image, cwd
        self.crashes = 0
        self._start()

    def _start(self):
        argv = ["timeout", "500", corpus.ENGINE, "serve", "--file", self.image]
        self.p = subprocess.Popen(argv, cwd=self.cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True, env=corpus.TOOL_ENV)
        self.p.stdout.readline()  # banner

    def cmd(self, argv: list) -> dict:
        try:
            self.p.stdin.write(json.dumps(argv) + "\n")
            self.p.stdin.flush()
            line = self.p.stdout.readline()
            if line == "":  # the engine closed stdout: it died on this command
                raise BrokenPipeError("empty line")
            return json.loads(line)
        except (BrokenPipeError, json.JSONDecodeError, ValueError) as e:
            rc = self.p.poll()
            if self.p.poll() is None:
                self.p.kill()
            self.p.wait()
            self.crashes += 1
            self._start()  # restart for the commands that follow
            # A negative return code is the killing signal (-11 SIGSEGV, -6 abort).
            return {"ok": False, "error": {"code": "crash", "cmd": argv, "exit": rc, "why": str(e)}}

    def close(self):
        try:
            self.p.stdin.close()
        except BrokenPipeError:
            pass
        self.p.wait()


def measure(build: dict, truth: dict, run_dir: str) -> dict:
    image = build["measured_file"]
    if os.path.isdir(run_dir):
        shutil.rmtree(run_dir)
    os.makedirs(os.path.join(run_dir, ".n0x"))
    # A fresh local project: no kept list of another file answers.
    info = json.loads(subprocess.run(["timeout", "60", corpus.ENGINE, "project", "info", "--quiet"],
                                     cwd=run_dir, capture_output=True, text=True, env=corpus.TOOL_ENV).stdout or "{}")
    if not (info.get("ok") and info["data"].get("is_local")):
        raise SystemExit(f"measure: {run_dir} is not a local project: {info}")

    s = Serve(image, run_dir)
    out = {"image": image, "engine": engine_identity()}
    out["discover"] = s.cmd(["function", "discover", "--file", image])
    out["contradictions"] = s.cmd(["contradictions", "--file", image, "--limit", "0"])
    out["strings"] = s.cmd(["strings", "--file", image])

    discovered = []
    if out["discover"].get("ok"):
        discovered = [f["va"] for f in out["discover"]["data"]["functions"]]
    out["why"] = {a: s.cmd(["why", "--addr", a]) for a in discovered}

    # Truth function starts, as addresses the measured file shares. `disasm`
    # covers the declared extent of a DWARF function only (where an end is
    # known), so a desync is measured inside the bytes the function owns — not
    # by over-running a large count across the whole image. `ir deobfuscate`,
    # `decomp` and `xref` work out their own extent, so they run on every start.
    truth_starts = []
    for f in truth["functions"]:
        if f["tier"] not in ("dwarf", "symtab"):
            continue
        end = f.get("end")
        # ~2 bytes per instruction is a safe overcount of the instruction count
        # within [start, end); min 4 for a tiny function.
        n = max(4, (end - f["start"]) // 2 + 2) if end else None
        truth_starts.append((f["start"], end, n, f.get("dwarf_names") or []))

    out["disasm"] = {}
    out["ir_deob"] = {}
    out["decomp"] = {}
    out["xref_to"] = {}
    for va, end, n, names in truth_starts:
        a = hex(va)
        if n is not None:
            out["disasm"][a] = s.cmd(["disasm", "--addr", a, "--count", str(n)])
        out["ir_deob"][a] = s.cmd(["ir", "deobfuscate", "--addr", a])
        out["decomp"][a] = s.cmd(["decomp", "pseudo", "--addr", a])
        out["xref_to"][a] = s.cmd(["xref", "to", "--addr", a])
    s.close()
    out["serve_crashes"] = s.crashes
    out["truth_starts"] = [{"va": hex(va), "end": hex(end) if end else None, "count": n, "names": names}
                           for va, end, n, names in truth_starts]
    return out


def main() -> int:
    build = json.load(open(sys.argv[1]))
    truth = json.load(open(sys.argv[2]))
    out_path = sys.argv[3]
    run_dir = os.path.join(corpus.RUNS, build["id"])
    m = measure(build, truth, run_dir)
    tmp = out_path + f".tmp{os.getpid()}"
    json.dump(m, open(tmp, "w"))
    os.replace(tmp, out_path)
    nd = len(m["why"])
    bad = sum(1 for w in m["why"].values() if not w.get("ok"))
    print(f"{build['id']}: {nd} starts, {bad} why without answer, disasm {len(m['disasm'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

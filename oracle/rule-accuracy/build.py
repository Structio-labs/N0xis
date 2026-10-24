#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Build the rule-accuracy corpus into the scratch directory.

Per configuration (arch x program x compiler x -O level), four compiles:

  u.g     unwind tables (the compiler's default), -g     -> truth of (a), (b); measured as (a)
  u.nog   the same without -g                            -> shows -g changed no code
  n.g     -fno-asynchronous-unwind-tables -fno-unwind-tables, -g   -> truth of (c)
  n.nog   the same without -g

and two strips: u.g.stripped (variant b), n.g.stripped (variant c).

Before a truth is used for a stripped file, the two must have the same code:
every executable section's name, address, size and bytes (readelf + the bytes
themselves). A configuration where they differ is recorded and not measured.

Usage: build.py [--only SUBSTR[,SUBSTR]] [--jobs N]   (N <= 2 on this machine)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import corpus
import readers


def version_of(argv0: str) -> str:
    try:
        return subprocess.run([argv0, "--version"], env=corpus.TOOL_ENV, capture_output=True, text=True, timeout=60).stdout.splitlines()[0]
    except Exception as e:  # recorded, never guessed
        return f"unknown ({e})"


def compile_one(argv: list, out: str) -> dict:
    # `timeout`: nothing here may run past the 9-minute bound.
    r = subprocess.run(["timeout", "540"] + argv, env=corpus.TOOL_ENV, capture_output=True, text=True)
    return {"argv": argv, "rc": r.returncode, "stderr": r.stderr[-2000:], "out": out if r.returncode == 0 else None}


def build_config(cfg: corpus.Config) -> dict:
    os.makedirs(cfg.dir, exist_ok=True)
    manifest_path = os.path.join(cfg.dir, "build.json")
    plan = {
        k: corpus.compile_argv(cfg, unwind=u, debug=g, out=cfg.file(k), no_exceptions=x)
        for k, (u, g, x) in corpus.builds_of(cfg.program).items()
    }
    old = json.load(open(manifest_path)) if os.path.exists(manifest_path) else {}
    variants = {v for v, spec in corpus.VARIANTS.items() if corpus.PROGRAMS[cfg.program].lang in spec["langs"]}
    if old.get("plan") == plan and old.get("ok") and set(old.get("truth_ok", {})) == variants:
        return old
    # A compile whose command is unchanged and whose output is there is kept:
    # adding a build to the plan rebuilds only that build.
    compiles = {}
    for k, argv in plan.items():
        prev = old.get("compiles", {}).get(k)
        if prev and prev.get("argv") == argv and prev.get("rc") == 0 and os.path.exists(cfg.file(k)):
            compiles[k] = prev
        else:
            compiles[k] = compile_one(argv, cfg.file(k))
    m = {"id": cfg.id, "plan": plan, "compiles": compiles, "ok": all(c["rc"] == 0 for c in compiles.values())}
    m["compiler"] = version_of(plan["u.g"][0])
    if not m["ok"]:
        json.dump(m, open(manifest_path, "w"), indent=1)
        return m
    strip = corpus.ARCHES[cfg.arch].strip
    for src in [k for k in plan if k.endswith(".g")]:
        subprocess.run([strip, "--strip-all", "-o", cfg.file(src + ".stripped"), cfg.file(src)], env=corpus.TOOL_ENV, check=True)
    m["strip"] = f"{strip} --strip-all ({version_of(strip)})"
    # The identity checks. `truth_ok` gates measurement; `nog_same` is recorded.
    checks = {}
    pairs = [(k + ".stripped", k) for k in plan if k.endswith(".g")] + [(k, k[:-4] + ".g") for k in plan if k.endswith(".nog")]
    for measured, truth in pairs:
        same, a, b = readers.same_code(cfg.file(measured), cfg.file(truth))
        checks[f"{measured} == {truth}"] = {"same": same, "sections": [s["name"] for s in a]} if same else {"same": False, "a": a, "b": b}
    m["code_identity"] = checks
    # A variant is measured only where its file's code is its truth's code.
    m["truth_ok"] = {}
    for v, spec in corpus.VARIANTS.items():
        if corpus.PROGRAMS[cfg.program].lang not in spec["langs"]:
            continue
        m["truth_ok"][v] = spec["measured"] == spec["truth"] or checks[f"{spec['measured']} == {spec['truth']}"]["same"]
    m["comment"] = readers.run(["readelf", "-p", ".comment", cfg.file("u.g")]).strip().splitlines()[1:]
    json.dump(m, open(manifest_path, "w"), indent=1)
    return m


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only")
    ap.add_argument("--jobs", type=int, default=2)
    args = ap.parse_args()
    if args.jobs > 2:
        print("build: at most 2 compiles at once on this machine", file=sys.stderr)
        return 2
    cfgs = corpus.configs(args.only)
    failed = 0
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for m in pool.map(build_config, cfgs):
            if not m["ok"]:
                failed += 1
                bad = [k for k, c in m["compiles"].items() if c["rc"] != 0]
                print(f"FAIL  {m['id']}: {bad} {m['compiles'][bad[0]]['stderr'][-400:]}", flush=True)
                continue
            ident = m["code_identity"]
            nog = "same" if all(v["same"] for k, v in ident.items() if ".nog ==" in k) else "DIFFERS"
            print(f"built {m['id']}  truth {m['truth_ok']}  -g vs no -g: {nog}", flush=True)
    print(f"{len(cfgs) - failed} of {len(cfgs)} configurations built")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

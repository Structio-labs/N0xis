#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Measure every built configuration in every variant: truth, engine, score.

For each configuration `build.py` built, and each variant whose code identity
held (a stripped file is measured against the unstripped build's DWARF only
when every code section's address and bytes are the same), writes into
RESULTS/<arch>/<program>/<compiler-opt>/:

  truth-<build>.json    the independent readers' answer (truth.py)
  <v>.measure.json      the engine's answers (measure.py)
  <v>.rows.jsonl        one row per listed start (score.py)
  <v>.summary.json      the counts

Usage: run.py [--only SUBSTR[,SUBSTR]] [--rescore]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

import corpus
import measure
import readers
import score
import truth


def truth_of(path: str, kept: str) -> dict:
    """The truth for `path`, kept beside the results under a key of the file's
    bytes and the readers' own code: a changed reader re-reads, never reuses."""
    h = hashlib.sha256()
    for f in (path, truth.__file__, readers.__file__):
        h.update(open(f, "rb").read())
    key = h.hexdigest()
    if os.path.exists(kept):
        t = json.load(open(kept))
        if t.get("key") == key:
            return t
    t = truth.truth(path)
    t["key"] = key
    json.dump(t, open(kept, "w"))
    return t


def run_config(cfg: corpus.Config, rescore: bool = False) -> list:
    bj = os.path.join(cfg.dir, "build.json")
    if not os.path.exists(bj):
        return [f"skip  {cfg.id}: not built"]
    b = json.load(open(bj))
    if not b.get("ok"):
        return [f"skip  {cfg.id}: build failed"]
    out_dir = os.path.join(corpus.RESULTS, cfg.arch, cfg.program, f"{cfg.compiler}-{cfg.opt}")
    os.makedirs(out_dir, exist_ok=True)
    log = []
    for v, spec in corpus.VARIANTS.items():
        if v not in b["truth_ok"]:
            continue  # the variant does not apply to this program's language
        if not b["truth_ok"][v]:
            log.append(f"REFUSED {cfg.id} {v}: the measured file's code differs from {spec['truth']}; its truth is not used")
            continue
        t = truth_of(cfg.file(spec["truth"]), os.path.join(out_dir, f"truth-{spec['truth']}.json"))
        image = cfg.file(spec["measured"])
        mpath = os.path.join(out_dir, f"{v}.measure.json")
        if rescore and os.path.exists(mpath):
            # The engine's answers kept from the last run, scored again: a
            # change to the scorer or the truth reader re-reads, the engine is
            # not asked twice. The engine identity inside says which build.
            m = json.load(open(mpath))
        else:
            m = measure.measure(image, os.path.join(corpus.RUNS, cfg.arch, cfg.program, f"{cfg.compiler}-{cfg.opt}", v))
            json.dump(m, open(mpath, "w"))
        rows, summary = score.score(t, m, readers.symbols(image))
        fdes = readers.fde_ranges(image)
        summary["config"] = {"id": cfg.id, "arch": cfg.arch, "program": cfg.program, "compiler": cfg.compiler, "opt": cfg.opt, "variant": v}
        summary["measured_file"] = image
        summary["truth_file"] = cfg.file(spec["truth"])
        summary["fdes_in_measured"] = sum(1 for f in fdes if f[0] == ".eh_frame")
        with open(os.path.join(out_dir, f"{v}.rows.jsonl"), "w") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        json.dump(summary, open(os.path.join(out_dir, f"{v}.summary.json"), "w"), indent=1)
        cls = summary.get("classes", {})
        log.append(f"{cfg.id} {v}: listed {summary.get('listed')} {dict(cls)} fdes {summary['fdes_in_measured']} checks {summary.get('checks')}")
    return log


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only")
    ap.add_argument("--rescore", action="store_true", help="score the kept engine answers again; do not run the engine")
    args = ap.parse_args()
    for cfg in corpus.configs(args.only):
        for line in run_config(cfg, args.rescore):
            print(line, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

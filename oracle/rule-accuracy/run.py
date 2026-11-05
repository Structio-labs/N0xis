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

An image with a summary from this engine is not measured again, and every file
is written whole or not at all, so a run cut off anywhere resumes where it was.
Images run in parallel, one configuration per worker, each in its own directory.

Usage: run.py [--only SUBSTR[,SUBSTR]] [--rescore] [--jobs N] [--budget SECONDS]
`--budget`: start nothing new after that long, and exit 3 if work is left (for a
run bounded by `timeout`: run it again to go on).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor

import corpus
import measure
import readers
import score
import truth


def dump_whole(obj, path: str, **kw) -> None:
    """Written beside it and renamed, so a killed run leaves no half a file."""
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "w") as fh:
        json.dump(obj, fh, **kw)
    os.replace(tmp, path)


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
    dump_whole(t, kept)
    return t


def engine_sha() -> str:
    return hashlib.sha256(open(corpus.ENGINE, "rb").read()).hexdigest()


def run_config(cfg: corpus.Config, rescore: bool = False, deadline: float | None = None, sha: str | None = None) -> list:
    b = corpus.manifest_of(cfg)
    if not b:
        return [f"skip  {cfg.id}: not built"]
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
        kept_summary = os.path.join(out_dir, f"{v}.summary.json")
        if not rescore and sha and os.path.exists(kept_summary) and json.load(open(kept_summary))["engine"]["sha256"] == sha:
            continue  # this engine's answer for this image is kept
        if deadline is not None and time.time() > deadline:
            log.append(f"LEFT {cfg.id} {v}")
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
            dump_whole(m, mpath)
        rows, summary = score.score(t, m, readers.symbols(image))
        fdes = readers.fde_ranges(image)
        if corpus.EXTRA is not None:
            summary["corpus_label"] = corpus.EXTRA.get("label")
        summary["config"] = {"id": cfg.id, "arch": cfg.arch, "program": cfg.program, "compiler": cfg.compiler, "opt": cfg.opt, "variant": v}
        summary["measured_file"] = image
        summary["truth_file"] = cfg.file(spec["truth"])
        summary["fdes_in_measured"] = sum(1 for f in fdes if f[0] == ".eh_frame")
        # The rows first: a summary says the image is done, so it is last.
        rows_path = os.path.join(out_dir, f"{v}.rows.jsonl")
        with open(rows_path + f".tmp{os.getpid()}", "w") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        os.replace(rows_path + f".tmp{os.getpid()}", rows_path)
        dump_whole(summary, kept_summary, indent=1)
        cls = summary.get("classes", {})
        log.append(f"{cfg.id} {v}: listed {summary.get('listed')} {dict(cls)} fdes {summary['fdes_in_measured']} checks {summary.get('checks')}")
    return log


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only")
    ap.add_argument("--rescore", action="store_true", help="score the kept engine answers again; do not run the engine")
    ap.add_argument("--jobs", type=int, default=6, help="configurations at once, each image in its own directory")
    ap.add_argument("--budget", type=float, help="seconds; start nothing new after that, and exit 3 if work is left")
    args = ap.parse_args()
    t0 = time.time()
    deadline = t0 + args.budget if args.budget else None
    sha = engine_sha()
    left = done = 0
    with ProcessPoolExecutor(max_workers=args.jobs) as pool:
        for lines in pool.map(run_config, corpus.configs(args.only), [args.rescore] * len(corpus.configs(args.only)), [deadline] * len(corpus.configs(args.only)), [sha] * len(corpus.configs(args.only))):
            for line in lines:
                if line.startswith("LEFT "):
                    left += 1
                    continue
                done += 1
                print(line, flush=True)
    print(f"run: {done} measured, {left} left, {time.time() - t0:.0f}s, {args.jobs} jobs, engine {sha[:12]}", flush=True)
    return 3 if left else 0


if __name__ == "__main__":
    sys.exit(main())

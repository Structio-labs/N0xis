#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Build, measure and score every obfuscation configuration selected: the one
entry point run_all.sh wraps in a memory-capped scope.

Per configuration it runs `obf_build` (compile -> transform -> assemble -> link
-> strip -> behaviour check), `truth.py` (rule-accuracy, on the obfuscated
unstripped build), `obf_measure` (the engine, in a `serve` session) and
`obf_score` (per-command correctness and silent/flagged). Results go under
RESULTS/<id>/; a configuration already scored by this engine is skipped, and
every file is written whole, so a cut-off run resumes.

Usage: obf_run.py [--only SUBSTR[,SUBSTR]] [--transform T[,T]] [--rescore]
                  [--budget SECONDS]
`--rescore` re-scores kept engine answers without asking the engine again (after
a scorer change). `--budget` stops starting new work after that long (exit 3 if
any is left), for a run bounded by `timeout`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time

import obf_build
import obf_corpus as corpus
import obf_measure
import obf_score
import truth as ra_truth  # rule-accuracy


def engine_sha() -> str:
    return hashlib.sha256(open(corpus.ENGINE, "rb").read()).hexdigest()


def run_config(cfg: corpus.Config, rescore: bool, sha: str) -> str:
    d = os.path.join(corpus.RESULTS, cfg.arch, cfg.program, cfg.transform, cfg.tag)
    os.makedirs(d, exist_ok=True)
    kept = os.path.join(d, "summary.json")
    if not rescore and os.path.exists(kept) and json.load(open(kept))["engine"]["sha256"] == sha:
        return f"skip  {cfg.id} (scored by this engine)"

    build_json = os.path.join(cfg.dir, "build.json")
    if not os.path.exists(build_json):
        m = obf_build.build_config(cfg)
    else:
        m = json.load(open(build_json))
        if not m.get("ok"):
            m = obf_build.build_config(cfg)
    if not m.get("ok"):
        return f"BUILD-FAIL {cfg.id}"
    if m.get("behaviour_ok") is False:
        return f"REFUSED {cfg.id}: obfuscated output differs from clean (not obfuscation)"

    truth_path = os.path.join(d, "truth.json")
    t = ra_truth.truth(m["truth_file"])
    json.dump(t, open(truth_path, "w"))

    measure_path = os.path.join(d, "measure.json")
    if rescore and os.path.exists(measure_path):
        meas = json.load(open(measure_path))
    else:
        run_dir = os.path.join(corpus.RUNS, cfg.id)
        meas = obf_measure.measure(m, t, run_dir)
        tmp = measure_path + f".tmp{os.getpid()}"
        json.dump(meas, open(tmp, "w"))
        os.replace(tmp, measure_path)

    # Score (reuse obf_score's functions).
    ref = obf_score.ref_boundaries(m.get("reference_file"))
    contra = obf_score.contradiction_addrs(meas)
    irflag = obf_score.ir_flagged(meas)
    planted = m.get("planted", [])
    summary = {
        "id": m["id"], "transform": m["transform"], "intensity": m["intensity"],
        "arch": m["arch"], "program": m["program"], "engine": meas["engine"],
        "behaviour_ok": m.get("behaviour_ok"), "planted_count": m.get("planted_count"),
        "contradictions_count": meas.get("contradictions", {}).get("data", {}).get("count"),
        "cmd": {
            "function_discover": obf_score.score_discover(m, t, meas, contra),
            "disasm": obf_score.score_disasm(t, meas, ref, contra, irflag, planted),
            "strings": obf_score.score_strings(meas, obf_score.EXPECTED_STRINGS.get(m["program"], [])),
            "xref": obf_score.score_xref(t, meas, ref, contra),
            "decomp": obf_score.score_decomp(t, meas, planted),
            "ir_deobfuscate": obf_score.score_ir_deob(t, meas, planted),
        },
    }
    tmp = kept + f".tmp{os.getpid()}"
    json.dump(summary, open(tmp, "w"), indent=1)
    os.replace(tmp, kept)
    c = summary["cmd"]
    return (f"{cfg.id}: disasm wrong {c['disasm']['wrong']}/{c['disasm']['wrong_silent']} silent, "
            f"discover wrong {c['function_discover']['wrong_starts']} recall {c['function_discover']['recall']}, "
            f"ir-deob {c['ir_deobfuscate']['detected']}/{c['ir_deobfuscate']['functions_with_planted_junk']} "
            f"fp {c['ir_deobfuscate']['false_positives_on_honest']}, contradictions {summary['contradictions_count']}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only")
    ap.add_argument("--transform")
    ap.add_argument("--rescore", action="store_true")
    ap.add_argument("--budget", type=float)
    args = ap.parse_args()
    tlist = args.transform.split(",") if args.transform else None
    cfgs = corpus.configs(args.only, tlist)
    sha = engine_sha()
    t0 = time.time()
    left = 0
    for cfg in cfgs:
        if args.budget and time.time() - t0 > args.budget:
            left += 1
            continue
        try:
            print(run_config(cfg, args.rescore, sha), flush=True)
        except Exception as e:  # a configuration that blows up is reported, not fatal
            print(f"ERROR {cfg.id}: {type(e).__name__}: {e}", flush=True)
    print(f"run: {len(cfgs) - left} attempted, {left} left, {time.time() - t0:.0f}s, engine {sha[:12]}", flush=True)
    return 3 if left else 0


if __name__ == "__main__":
    sys.exit(main())

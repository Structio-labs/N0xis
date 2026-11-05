#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Build one obfuscation configuration: compile to assembly, rewrite the
assembly, assemble and link the obfuscated image and (where the transformation
needs one) a byte-identical reference twin, strip the obfuscated image, and
check that the obfuscated program still prints exactly what the clean build
prints.

Per configuration (arch x program x transformation x intensity) it writes
BUILD/<id>/:

  clean       the untransformed build (-g), for the behaviour comparison
  obf.g       the obfuscated build with -g and symbols: the TRUTH (its own
              DWARF, correct because the transform ran where symbols are labels)
  obf.g.stripped  the obfuscated build stripped: the MEASURED file
  ref.g       the reference twin (planted bytes -> equal-count NOPs), read by an
              independent objdump for true instruction boundaries; omitted when
              the transformation does not need one
  build.json  the plan, the run outputs, the planted byte ranges (resolved to
              addresses from the linked image's symbol table), and whether the
              behaviour check held

A configuration whose obfuscated program prints something different from the
clean build is marked `behaviour_ok: false` and is NOT measured: it is not
obfuscation.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

import obf_corpus as corpus
import readers  # rule-accuracy
import transforms


def sh(argv: list, timeout: int = 540) -> subprocess.CompletedProcess:
    return subprocess.run(["timeout", str(timeout)] + argv, env=corpus.TOOL_ENV, capture_output=True, text=True)


def run_image(cfg: corpus.Config, path: str) -> dict:
    a = corpus.ARCHES[cfg.arch]
    p = corpus.PROGRAMS[cfg.program]
    if not a.can_run:
        return {"ran": False, "why": "no runner for this architecture"}
    argv = a.run + [path] + list(p.argv)
    r = subprocess.run(["timeout", "60"] + argv, env=corpus.TOOL_ENV, capture_output=True, text=True)
    return {"ran": True, "rc": r.returncode, "stdout": r.stdout, "stderr": r.stderr[-400:]}


def junk_addresses(image: str, planted_all: list) -> list:
    """Resolve the `__obf_junk_N_a/b` labels in the linked image to addresses:
    the planted byte ranges, known (not inferred) for the scorer."""
    syms = {s["name"]: s["value"] for s in readers.symbols(image) if s["name"].startswith("__obf_junk_")}
    out = []
    for p in planted_all:
        for lo_lbl, hi_lbl in p.junk_labels:
            if lo_lbl in syms and hi_lbl in syms:
                out.append({"lo": syms[lo_lbl], "hi": syms[hi_lbl], "kind": p.kind})
    return sorted(out, key=lambda r: r["lo"])


def build_config(cfg: corpus.Config) -> dict:
    T = transforms.TRANSFORMS[cfg.transform]
    needs_twin = T["twin"]
    os.makedirs(cfg.dir, exist_ok=True)
    p = corpus.PROGRAMS[cfg.program]
    srcs = p.sources_for(cfg.arch)

    m = {"id": cfg.id, "transform": cfg.transform, "intensity": cfg.intensity,
         "arch": cfg.arch, "program": cfg.program, "compiles": [], "ok": True}

    clean_objs, obf_objs, ref_objs = [], [], []
    planted_all = []
    for n, src in enumerate(srcs):
        base = f"src{n:03d}"
        s_clean = os.path.join(cfg.dir, base + ".clean.s")
        r = sh(corpus.compile_to_asm_argv(cfg, src, s_clean))
        m["compiles"].append({"src": os.path.basename(src), "rc": r.returncode, "stderr": r.stderr[-300:]})
        if r.returncode != 0:
            m["ok"] = False
            json.dump(m, open(os.path.join(cfg.dir, "build.json"), "w"), indent=1)
            return m
        asm = open(s_clean).read()
        obf_asm, ref_asm, planted = T["fn"](asm, cfg.intensity)
        planted_all.append(planted)
        s_obf = os.path.join(cfg.dir, base + ".obf.s")
        open(s_obf, "w").write(obf_asm)
        o_clean = os.path.join(cfg.dir, base + ".clean.o")
        o_obf = os.path.join(cfg.dir, base + ".obf.o")
        sh(corpus.ARCHES[cfg.arch].cc + [f"-{cfg.opt}", "-g", "-c", s_clean, "-o", o_clean])
        sh(corpus.ARCHES[cfg.arch].cc + [f"-{cfg.opt}", "-g", "-c", s_obf, "-o", o_obf])
        clean_objs.append(o_clean)
        obf_objs.append(o_obf)
        if needs_twin:
            s_ref = os.path.join(cfg.dir, base + ".ref.s")
            open(s_ref, "w").write(ref_asm)
            o_ref = os.path.join(cfg.dir, base + ".ref.o")
            sh(corpus.ARCHES[cfg.arch].cc + [f"-{cfg.opt}", "-g", "-c", s_ref, "-o", o_ref])
            ref_objs.append(o_ref)

    clean = os.path.join(cfg.dir, "clean")
    obf = os.path.join(cfg.dir, "obf.g")
    sh(corpus.assemble_and_link_argv(cfg, clean_objs, clean))
    lr = sh(corpus.assemble_and_link_argv(cfg, obf_objs, obf))
    if not os.path.exists(obf):
        m["ok"] = False
        m["link_error"] = lr.stderr[-600:]
        json.dump(m, open(os.path.join(cfg.dir, "build.json"), "w"), indent=1)
        return m
    strip = corpus.ARCHES[cfg.arch].strip
    sh([strip, "--strip-all", "-o", obf + ".stripped", obf])
    m["truth_file"] = obf
    m["measured_file"] = obf + ".stripped"
    if needs_twin:
        ref = os.path.join(cfg.dir, "ref.g")
        sh(corpus.assemble_and_link_argv(cfg, ref_objs, ref))
        m["reference_file"] = ref if os.path.exists(ref) else None

    # Behaviour: the obfuscated program prints what the clean one does.
    out_clean = run_image(cfg, clean)
    out_obf = run_image(cfg, obf)
    m["run_clean"], m["run_obf"] = out_clean, out_obf
    if out_clean.get("ran") and out_obf.get("ran"):
        m["behaviour_ok"] = out_clean["stdout"] == out_obf["stdout"] and out_clean["rc"] == out_obf["rc"]
    else:
        m["behaviour_ok"] = None  # could not run (cross arch without a runner)
    if needs_twin and m.get("reference_file"):
        out_ref = run_image(cfg, ref)
        m["run_ref"] = out_ref
        if m["behaviour_ok"] and out_ref.get("ran"):
            m["behaviour_ok"] = out_ref["stdout"] == out_clean["stdout"]

    m["planted"] = junk_addresses(obf, planted_all)
    m["planted_count"] = len(m["planted"])
    m["touched_functions"] = sorted({f for p in planted_all for f in p.touched})
    # Same code in truth and measured (stripped only drops symbols): the identity
    # rule-accuracy checks before using one build's truth for another file.
    same, _, _ = readers.same_code(obf + ".stripped", obf)
    m["truth_ok"] = {"a": True, "b": same}
    json.dump(m, open(os.path.join(cfg.dir, "build.json"), "w"), indent=1)
    return m


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only")
    ap.add_argument("--transform")
    args = ap.parse_args()
    tlist = args.transform.split(",") if args.transform else None
    cfgs = corpus.configs(args.only, tlist)
    bad = 0
    for cfg in cfgs:
        m = build_config(cfg)
        beh = m.get("behaviour_ok")
        tag = "OK" if m["ok"] else "BUILD-FAIL"
        print(f"{tag:10} {cfg.id}  planted={m.get('planted_count')} behaviour_ok={beh} truth_ok={m.get('truth_ok')}", flush=True)
        if not m["ok"] or beh is False:
            bad += 1
    print(f"build: {len(cfgs) - bad} of {len(cfgs)} ok")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

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
import shutil
import subprocess
import sys
import tempfile

import lying
import obf_corpus as corpus
import readers  # rule-accuracy
import transforms
import truth as ra_truth  # rule-accuracy


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


def run_program(cfg: corpus.Config, path: str) -> dict:
    """Run the program whose image is `path`: the image itself, or, for a shared
    object, the configuration's driver beside a copy of it."""
    if not corpus.is_shared(cfg):
        return run_image(cfg, path)
    d = tempfile.mkdtemp(dir=os.path.dirname(path))
    try:
        shutil.copy(path, os.path.join(d, corpus.SHARED_NAME))
        shutil.copy(cfg_driver(cfg), os.path.join(d, "driver"))
        return run_image(cfg, os.path.join(d, "driver"))
    finally:
        shutil.rmtree(d)


def cfg_driver(cfg: corpus.Config) -> str:
    return os.path.join(cfg.dir, "driver")


def build_post_link(cfg: corpus.Config, T: dict) -> dict:
    """A lying table: the linked file of the `base` configuration, edited. Nothing
    is compiled again. The truth is the file before tampering, and the edit is read
    back with `readelf` before anything is measured."""
    os.makedirs(cfg.dir, exist_ok=True)
    base_cfg = corpus.Config(cfg.arch, cfg.program, T["base"], 1.0)
    base_json = os.path.join(base_cfg.dir, "build.json")
    base = json.load(open(base_json)) if os.path.exists(base_json) else build_config(base_cfg)
    m = {"id": cfg.id, "transform": cfg.transform, "intensity": cfg.intensity, "arch": cfg.arch,
         "program": cfg.program, "ok": bool(base.get("ok")), "base": base_cfg.id, "planted": [], "planted_count": 0}
    if not m["ok"]:
        return m
    before, stripped = base["truth_file"], base["measured_file"]
    if corpus.is_shared(base_cfg):
        shutil.copy(cfg_driver(base_cfg), cfg_driver(cfg))
    tampered = os.path.join(cfg.dir, "tampered")
    fact = lying.read_before(cfg.arch, ra_truth.truth(before), before, stripped)
    m["planted_lies"] = lying.LIES[T["post_link"]](fact, cfg.intensity, tampered)
    m["planted_count"] = len(m["planted_lies"])
    m["eligible_functions"] = len(fact.targets)
    m["truth_file"], m["reference_file"], m["measured_file"] = before, before, tampered
    m["edit_failures"] = lying.verify(tampered, stripped, before, m["planted_lies"], T["post_link"])
    if m["edit_failures"]:
        m["ok"] = False
    # Behaviour: the tampered program prints what the file before it prints.
    out_before, out_after = run_program(base_cfg, before), run_program(cfg, tampered)
    m["run_clean"], m["run_obf"] = out_before, out_after
    if out_before.get("ran") and out_after.get("ran"):
        m["behaviour_ok"] = out_before["stdout"] == out_after["stdout"] and out_before["rc"] == out_after["rc"]
    else:
        m["behaviour_ok"] = None
    same, _, _ = readers.same_code(tampered, before)
    m["truth_ok"] = {"a": False, "b": same}
    json.dump(m, open(os.path.join(cfg.dir, "build.json"), "w"), indent=1)
    return m


def build_config(cfg: corpus.Config) -> dict:
    T = transforms.TRANSFORMS[cfg.transform]
    if T.get("post_link"):
        return build_post_link(cfg, T)
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
        obf_asm, ref_asm, planted = T["fn"](asm, cfg.intensity, tag=base)
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

    if corpus.is_shared(cfg):
        sh(corpus.driver_link_argv(cfg, clean, cfg_driver(cfg)))

    # Behaviour: the obfuscated program prints what the clean one does.
    out_clean = run_program(cfg, clean)
    out_obf = run_program(cfg, obf)
    m["run_clean"], m["run_obf"] = out_clean, out_obf
    if out_clean.get("ran") and out_obf.get("ran"):
        m["behaviour_ok"] = out_clean["stdout"] == out_obf["stdout"] and out_clean["rc"] == out_obf["rc"]
    else:
        m["behaviour_ok"] = None  # could not run (cross arch without a runner)
    if needs_twin and m.get("reference_file"):
        out_ref = run_program(cfg, ref)
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
    ap.add_argument("--family")
    args = ap.parse_args()
    tlist = args.transform.split(",") if args.transform else None
    cfgs = corpus.configs(args.only, tlist, args.family)
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

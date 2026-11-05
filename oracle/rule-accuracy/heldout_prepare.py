#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Fetch the held-out set at its exact commits and run the configure steps two
of its projects need, writing what they decide into recipes `corpus.py` reads.

Third-party build scripts, read before this was written: nginx's `auto/configure`
compiles and runs small feature tests under its `--builddir`; tmux's `autogen.sh`
runs aclocal, automake and autoreconf in its tree, and its `configure` is a usual
autoconf one. Nothing here runs a test suite, a `make` of the project, or an
installer. Run it inside a memory cap.

Usage: heldout_prepare.py   (RULE_ACCURACY_HELDOUT_SRC: where; default as in corpus.py)
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys

import corpus

ROOT = corpus.HELDOUT_SRC


def run(argv: list, cwd: str, env: dict | None = None) -> None:
    r = subprocess.run(["timeout", "500"] + argv, cwd=cwd, env=dict(corpus.TOOL_ENV, **(env or {})), capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"{argv} in {cwd} failed ({r.returncode}):\n{r.stdout[-1500:]}\n{r.stderr[-1500:]}")


def fetch() -> None:
    for name, (url, tag, commit) in corpus.HELDOUT_SOURCES.items():
        d = os.path.join(ROOT, name)
        if not os.path.isdir(d):
            run(["git", "clone", "-q", "--depth", "1", "--branch", tag, url + ".git", name], ROOT)
        got = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        if got != commit:
            raise SystemExit(f"{name}: {got} is not the pinned {commit}")
        print(f"{name}: {tag} {got}", flush=True)


def logical_lines(text: str) -> list:
    return text.replace("\\\n", " ").splitlines()


def write_recipe(project: str, arch: str, recipe: dict) -> None:
    os.makedirs(os.path.join(ROOT, "recipes"), exist_ok=True)
    json.dump(recipe, open(os.path.join(ROOT, "recipes", f"{project}-{arch}.json"), "w"), indent=1)
    print(f"{project} {arch}: {len(recipe['sources'])} sources, {len(recipe['flags'])} flags, libs {recipe['libs']}", flush=True)


def nginx(arch: str, cc_opt: list) -> None:
    src = os.path.join(ROOT, "nginx")
    objs = os.path.join(ROOT, f"nginx-objs-{arch}")
    argv = ["sh", "auto/configure", f"--builddir={objs}", "--without-http_rewrite_module", "--without-http_gzip_module"]
    if cc_opt:
        argv += ["--with-cc-opt=" + " ".join(cc_opt), "--with-ld-opt=" + " ".join(cc_opt)]
    run(argv, src)
    make = open(os.path.join(objs, "Makefile")).read()
    # A rule ends in the source it compiles, on a line of its own.
    sources = sorted({os.path.join(src, m) for m in re.findall(r"^\s+(src/\S+\.c)\s*$", make, re.M)})
    sources.append(os.path.join(objs, "ngx_modules.c"))
    incs = sorted(set(re.findall(r"-I (\S+)", make)))
    flags = []
    for i in incs:
        flags.append("-I" + (i if os.path.isabs(i) else os.path.join(src, i)))
    link = re.search(r"\$\(LINK\).*?(?=\n\n)", make, re.S).group(0)
    write_recipe("nginx", arch, {"sources": sources, "flags": flags, "libs": re.findall(r"(?<!\S)-l\S+", link)})


def tmux(arch: str) -> None:
    src = os.path.join(ROOT, "tmux")
    if not os.path.exists(os.path.join(src, "configure")):
        run(["sh", "autogen.sh"], src)
    run(["sh", "configure"], src)
    run(["bison", "-o", "cmd-parse.c", "cmd-parse.y"], src)
    make = logical_lines(open(os.path.join(src, "Makefile")).read())

    def var(name: str) -> str:
        for line in make:
            if line.startswith(name + " ="):
                return line.split("=", 1)[1]
        return ""

    def expanded(text: str) -> str:
        """`$(am__append_N)` and the like, as the Makefile assigns them."""
        return re.sub(r"\$\((am__append_\d+)\)", lambda m: expanded(var(m.group(1))), text)

    listed = (expanded(var("dist_tmux_SOURCES")) + " " + expanded(var("nodist_tmux_SOURCES"))).split()
    named = [n[:-2] + ".c" for n in listed if n.endswith(".y")] + [n for n in listed if n.endswith(".c")]
    libobjs = re.findall(r"\$\{LIBOBJDIR\}(\S+)\$U\.o", var("LIBOBJS"))
    sources = [os.path.join(src, n) for n in named] + [os.path.join(src, "compat", o + ".c") for o in libobjs]
    missing = [s for s in sources if not os.path.exists(s)]
    if missing:
        raise SystemExit(f"tmux: no such source: {missing[:5]}")
    # What the Makefile compiles with, its $(CPPFLAGS) and $(DEFS), but not the
    # warnings and `-g -O2` of its $(CFLAGS): the instrument's are the build's.
    text = " ".join(expanded(var(v)) for v in ("DEFS", "AM_CPPFLAGS", "CPPFLAGS", "LIBEVENT_CFLAGS", "LIBNCURSES_CFLAGS", "LIBTINFO_CFLAGS"))
    text = text.replace("$(sysconfdir)", "/etc").replace("$$", "$").replace("$(srcdir)", src).replace("$(top_srcdir)", src)
    flags = [f for f in shlex.split(text) if f.startswith(("-D", "-I"))] + ["-I" + src, "-I" + os.path.join(src, "compat"), "-std=gnu99"]
    libs = re.findall(r"-l\S+", var("LIBS"))
    write_recipe("tmux", arch, {"sources": sources, "flags": flags, "libs": libs})


def re2_headers() -> None:
    d = os.path.join(ROOT, "absl-include")
    os.makedirs(d, exist_ok=True)
    link = os.path.join(d, "absl")
    if not os.path.exists(link):
        os.symlink("/usr/include/absl", link)


def main() -> int:
    os.makedirs(ROOT, exist_ok=True)
    fetch()
    re2_headers()
    for arch, cc_opt in (("x86_64", []), ("i686", ["-m32"])):
        nginx(arch, cc_opt)
    tmux("x86_64")
    return 0


if __name__ == "__main__":
    sys.exit(main())

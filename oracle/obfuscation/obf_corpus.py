#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The obfuscation corpus: which programs, which architectures, which
transformations and intensities, and where everything is written.

This instrument is not a second measurement: it reuses `oracle/rule-accuracy`'s
readers (`readers.py`), its truth reader (`truth.py`) and its scorer
(`score.py`). A transformation is one more variant of the same question —
"which function-discovery answers are wrong, and does anything warn of it" —
extended to the other commands that obfuscation stresses (`disasm`, `strings`,
`xref`, `decomp`, `ir deobfuscate`, `contradictions`).

The key fact that lets the rule-accuracy scorer apply unchanged: every
transformation here runs where symbols are still labels (assembly or IR), so
the *obfuscated* build's own unstripped DWARF is correct and is the truth for
the *obfuscated* stripped image — exactly rule-accuracy's variant (a)/(b),
with the obfuscated pair in place of the clean one. Post-link transformations
(lying tables, a packer) keep the file *before* tampering as the truth.
"""

from __future__ import annotations

import glob
import os
import shutil
import sys
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
RULE_ACCURACY = os.path.join(REPO, "oracle", "rule-accuracy")
# Reuse the rule-accuracy instrument's readers, truth reader and scorer.
if RULE_ACCURACY not in sys.path:
    sys.path.insert(0, RULE_ACCURACY)

import corpus as ra  # noqa: E402  the rule-accuracy corpus (TOOL_ENV, ENGINE, _registry); named `corpus` there, so this module is `obf_corpus`

TOOL_ENV = ra.TOOL_ENV
ENGINE = os.environ.get("N0XIS", ra.ENGINE)

SCRATCH = os.environ.get("OBF_SCRATCH", os.path.expanduser("~/.cache/obfuscation"))
BUILD = os.path.join(SCRATCH, "build")
RUNS = os.path.join(SCRATCH, "runs")
RESULTS = os.path.join(SCRATCH, "results")

INTENSITIES = tuple(float(x) for x in os.environ.get("OBF_INTENSITIES", "0.5,1.0").split(","))


@dataclass(frozen=True)
class Arch:
    name: str
    cc: list          # the C compiler command (and target flags)
    strip: str
    run: list         # how to execute an image (native: []; cross: a qemu prefix)
    can_run: bool     # whether this machine can execute the image at all


ARCHES = {
    "x86_64": Arch("x86_64", ["gcc"], "strip", [], True),
    "i686": Arch("i686", ["gcc", "-m32"], "strip", [], True),
    "aarch64": Arch(
        "aarch64", ["aarch64-linux-gnu-gcc"], "aarch64-linux-gnu-strip",
        # qemu-aarch64-static with the cross sysroot's loader.
        ["qemu-aarch64-static", "-L", "/usr/aarch64-linux-gnu"],
        shutil.which("qemu-aarch64-static") is not None,
    ),
}


@dataclass(frozen=True)
class Program:
    name: str
    kind: str          # "exe" (runnable: output is compared) or "so"
    flags: tuple = ()
    libs: tuple = ()
    sources_for: object = field(default=None, compare=False)
    # A fixed input for a runnable program whose output is the behaviour check;
    # an argv list (after the binary). Empty: run with no arguments.
    argv: tuple = ()


def _calib(_arch: str) -> list:
    return [os.path.join(HERE, "calib.c")]


def _lua_sources(_arch: str) -> list:
    """The Lua 5.4.7 library (the crate ships no `lua.c`/`luac.c` main) plus the
    embedding driver `lua_main.c`, which runs a fixed script. No `LUA_USE_LINUX`
    (that pulls in readline); the script needs none of it."""
    root = os.path.join(ra._registry("lua-src-547.0.0"), "lua-5.4.7")
    lib = sorted(glob.glob(os.path.join(root, "*.c")))
    return lib + [os.path.join(HERE, "lua_main.c")]


PROGRAMS = {
    "calib": Program("calib", "exe", sources_for=_calib),
    # The Lua library embedded by lua_main.c, run on a fixed script whose printed
    # line is the behaviour check. The include path is the crate's lua dir.
    "lua": Program("lua", "exe", ("-I@LUA@",), ("-lm",), sources_for=_lua_sources),
}


def _lua_dir() -> str:
    return os.path.join(ra._registry("lua-src-547.0.0"), "lua-5.4.7")


@dataclass(frozen=True)
class Config:
    arch: str
    program: str
    transform: str
    intensity: float
    opt: str = "O1"

    @property
    def tag(self) -> str:
        return f"i{int(self.intensity * 100):03d}"

    @property
    def id(self) -> str:
        return f"{self.arch}/{self.program}/{self.transform}/{self.tag}"

    @property
    def dir(self) -> str:
        return os.path.join(BUILD, self.arch, self.program, self.transform, self.tag)


def configs(select: str | None = None, transforms: list | None = None) -> list:
    import transforms as T

    chosen = transforms or list(T.TRANSFORMS)
    out = []
    for arch in ARCHES:
        for p in PROGRAMS.values():
            for tname in chosen:
                if arch not in T.TRANSFORMS[tname]["arches"]:
                    continue
                for inten in INTENSITIES:
                    cfg = Config(arch, p.name, tname, inten)
                    if select is None or any(s in cfg.id for s in select.split(",")):
                        out.append(cfg)
    return out


def compile_to_asm_argv(cfg: Config, src: str, out_s: str) -> list:
    """Compile one source to assembly (`-S`) with debug info, so the
    transformation can rewrite it before it is assembled."""
    a = ARCHES[cfg.arch]
    p = PROGRAMS[cfg.program]
    argv = list(a.cc) + [f"-{cfg.opt}", "-g", "-S", "-fno-pic", "-fno-stack-protector"]
    argv += [f.replace("@LUA@", _lua_dir()) for f in p.flags]
    argv += ["-w", "-o", out_s, src]
    return argv


def assemble_and_link_argv(cfg: Config, objs: list, out: str, listing: str | None = None) -> list:
    a = ARCHES[cfg.arch]
    p = PROGRAMS[cfg.program]
    argv = list(a.cc) + [f"-{cfg.opt}", "-g", "-no-pie"]
    argv += objs
    argv += list(p.libs)
    argv += ["-o", out]
    return argv

# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The corpus of the rule-accuracy instrument: what is built, how, and where.

One place for every fact the other scripts share — the programs, the compilers,
the flags, the variants and the paths — so the builder, the truth reader, the
measurer and the scorer cannot disagree about which file is which build.

Sources are only ones already on this machine (the run is offline): the repo's
own `oracle/` programs and C/C++ vendored by crates in `~/.cargo/registry`.
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
ORACLE = os.path.join(REPO, "oracle")

# Scratch: builds, raw measurements, per-function rows. Never in the repo.
SCRATCH = os.environ.get("RULE_ACCURACY_SCRATCH", os.path.expanduser("~/.cache/rule-accuracy"))
BUILD = os.path.join(SCRATCH, "build")
RUNS = os.path.join(SCRATCH, "runs")
RESULTS = os.path.join(SCRATCH, "results")

# The engine measured. Pinned by path; its sha256 goes into every result.
ENGINE = os.environ.get("N0XIS", os.path.expanduser("~/.local/opt/n0xis-wasm-preview/n0xis"))

# Every external tool runs in the C locale: this machine's locale translates
# readelf/objdump output, and an English-keyed parser then reads nothing.
TOOL_ENV = dict(os.environ, LC_ALL="C", LANG="C")


def _registry(pattern: str) -> str:
    """The one directory in the cargo registry that matches `pattern`."""
    hits = sorted(glob.glob(os.path.expanduser(f"~/.cargo/registry/src/*/{pattern}")))
    if not hits:
        raise SystemExit(f"corpus: no {pattern} in ~/.cargo/registry/src (the run is offline; nothing is fetched)")
    return hits[-1]


@dataclass(frozen=True)
class Arch:
    name: str
    # The command and the flags that select the target, per compiler and language.
    cc: dict  # (compiler, lang) -> [argv prefix]
    strip: str


ARCHES = {
    "x86_64": Arch(
        "x86_64",
        {("gcc", "c"): ["gcc"], ("gcc", "c++"): ["g++"], ("clang", "c"): ["clang"], ("clang", "c++"): ["clang++"]},
        "strip",
    ),
    "i686": Arch(
        "i686",
        {
            ("gcc", "c"): ["gcc", "-m32"],
            ("gcc", "c++"): ["g++", "-m32"],
            ("clang", "c"): ["clang", "-m32"],
            ("clang", "c++"): ["clang++", "-m32"],
        },
        "strip",
    ),
    # clang has no aarch64 linker of its own configured here; it takes the
    # cross sysroot and ld.lld, so this arch also carries a second linker.
    "aarch64": Arch(
        "aarch64",
        {
            ("gcc", "c"): ["aarch64-linux-gnu-gcc"],
            ("gcc", "c++"): ["aarch64-linux-gnu-g++"],
            ("clang", "c"): ["clang", "--target=aarch64-linux-gnu", "--sysroot=/usr/aarch64-linux-gnu", "-fuse-ld=lld"],
            ("clang", "c++"): ["clang++", "--target=aarch64-linux-gnu", "--sysroot=/usr/aarch64-linux-gnu", "-fuse-ld=lld"],
        },
        "aarch64-linux-gnu-strip",
    ),
}

COMPILERS = ("gcc", "clang")
OPTS = ("O0", "O2", "Os")

# The variants. `truth` names the unstripped build whose DWARF and symbol table
# are the answer for that variant; `measured` the file the engine is handed;
# `langs` the languages it applies to.
#   a: as built (unwind tables, symbols, debug info)
#   b: the same file stripped
#   c: built with no unwind tables, stripped (the spec's three)
#   d: C++ only, beyond the spec: (c) with -fno-exceptions as well. In C++ the
#      flags of (c) leave an FDE on every function that may unwind, so (c) of a
#      C++ program is (b) again; (d) is the C++ build with no FDEs, where the
#      rules carry discovery as they do on C in (c).
VARIANTS = {
    "a": {"truth": "u.g", "measured": "u.g", "langs": ("c", "c++")},
    "b": {"truth": "u.g", "measured": "u.g.stripped", "langs": ("c", "c++")},
    "c": {"truth": "n.g", "measured": "n.g.stripped", "langs": ("c", "c++")},
    "d": {"truth": "x.g", "measured": "x.g.stripped", "langs": ("c++",)},
}
NO_UNWIND = ["-fno-asynchronous-unwind-tables", "-fno-unwind-tables"]
NO_EXCEPTIONS = ["-fno-exceptions"]


def builds_of(program: str) -> dict:
    """The compiles a program gets: name -> (unwind, debug, no_exceptions)."""
    out = {"u.g": (True, True, False), "u.nog": (True, False, False), "n.g": (False, True, False), "n.nog": (False, False, False)}
    if PROGRAMS[program].lang == "c++":
        out.update({"x.g": (False, True, True), "x.nog": (False, False, True)})
    return out


@dataclass(frozen=True)
class Program:
    name: str
    lang: str  # "c" or "c++"
    kind: str  # "so" or "exe"
    version: str
    arches: tuple
    flags: tuple = ()
    libs: tuple = ()
    # Sources per arch: a function so a source list can differ by arch.
    sources_for: object = field(default=None, compare=False)


def _oracle_c(arch: str) -> list:
    base = ["emu.c", "emu_calls.c", "emu_switch.c", "locals.c", "sysv.c", "typeflow.c", "types.c", "emu32.c", "arm64.c"]
    if arch in ("x86_64", "i686"):
        base.insert(2, "emu_fp.c")  # x86 inline assembly (`sqrtsd`); its place kept, so the command is unchanged
    if arch == "x86_64":
        base.append("emu_simd.c")  # x86 vector intrinsics
    if arch == "i686":
        base.append("i386.c")  # cdecl + stdcall
    return [os.path.join(ORACLE, f) for f in base]


def _lua(_arch: str) -> list:
    return sorted(glob.glob(os.path.join(_registry("lua-src-547.0.0"), "lua-5.4.7", "*.c")))


def _zstd_lib() -> str:
    return os.path.join(_registry("zstd-sys-2.1.0+zstd.1.5.7"), "zstd", "lib")


def _zstd(_arch: str) -> list:
    lib = _zstd_lib()
    out = []
    for d in ("common", "compress", "decompress", "dictBuilder"):
        out += sorted(glob.glob(os.path.join(lib, d, "*.c")))
    return out


def _sqlite(_arch: str) -> list:
    return [os.path.join(_registry("libsqlite3-sys-0.38.2"), "sqlite3", "sqlite3.c")]


def _libfuzzer(_arch: str) -> list:
    srcs = sorted(glob.glob(os.path.join(_registry("libfuzzer-sys-0.4.13"), "libfuzzer", "*.cpp")))
    # libFuzzer is a library around a function the user supplies; a one-line
    # target makes it a whole program (a shared object refuses its .preinit_array).
    return srcs + [os.path.join(HERE, "fuzz_target.cpp")]


def _cxx_this(_arch: str) -> list:
    return [os.path.join(ORACLE, "cxx_this.cpp")]


ALL = ("x86_64", "i686", "aarch64")
PROGRAMS = {
    "oracle_c": Program("oracle_c", "c", "so", "repo oracle/ (this commit)", ALL, sources_for=_oracle_c),
    "oracle_cxx": Program("oracle_cxx", "c++", "so", "repo oracle/cxx_this.cpp (this commit)", ALL, sources_for=_cxx_this),
    "lua": Program("lua", "c", "so", "Lua 5.4.7 (crate lua-src 547.0.0)", ALL, ("-DLUA_USE_LINUX",), ("-lm",), sources_for=_lua),
    "zstd": Program(
        "zstd",
        "c",
        "so",
        "zstd 1.5.7 (crate zstd-sys 2.1.0+zstd.1.5.7), lib/{common,compress,decompress,dictBuilder}",
        ALL,
        # No assembly: its functions carry no DWARF subprogram, so the truth
        # would have to come from the symbol table alone; no legacy formats
        # (they live in a directory the default list does not build).
        ("-DZSTD_DISABLE_ASM", "-DZSTD_LEGACY_SUPPORT=0", "-I@ZSTD@", "-I@ZSTD@/common"),
        sources_for=_zstd,
    ),
    "sqlite": Program("sqlite", "c", "so", "SQLite 3.53.2 amalgamation (crate libsqlite3-sys 0.38.2)", ("x86_64",), ("-DSQLITE_THREADSAFE=1",), ("-lm",), sources_for=_sqlite),
    "libfuzzer": Program(
        "libfuzzer",
        "c++",
        "exe",
        "libFuzzer (crate libfuzzer-sys 0.4.13) + oracle/rule-accuracy/fuzz_target.cpp",
        ("x86_64",),
        ("-std=c++17",),
        ("-lpthread",),
        sources_for=_libfuzzer,
    ),
}


@dataclass(frozen=True)
class Config:
    arch: str
    program: str
    compiler: str
    opt: str

    @property
    def id(self) -> str:
        return f"{self.arch}/{self.program}/{self.compiler}-{self.opt}"

    @property
    def dir(self) -> str:
        return os.path.join(BUILD, self.arch, self.program, f"{self.compiler}-{self.opt}")

    def file(self, which: str) -> str:
        """`u.g`, `u.nog`, `n.g`, `n.nog`, `u.g.stripped`, `n.g.stripped`."""
        return os.path.join(self.dir, which)


def configs(select: str | None = None) -> list:
    """Every build configuration, optionally filtered by a substring of its id."""
    out = []
    for arch in ALL:
        for p in PROGRAMS.values():
            if arch not in p.arches:
                continue
            for c in COMPILERS:
                for o in OPTS:
                    cfg = Config(arch, p.name, c, o)
                    if select is None or any(s in cfg.id for s in select.split(",")):
                        out.append(cfg)
    return out


def compile_argv(cfg: Config, unwind: bool, debug: bool, out: str, no_exceptions: bool = False) -> list:
    """The one compiler command for a build. `unwind=False` is variant (c)'s
    build; `debug=False` the copy that shows `-g` changes no code."""
    p = PROGRAMS[cfg.program]
    a = ARCHES[cfg.arch]
    argv = list(a.cc[(cfg.compiler, p.lang)])
    argv += [f"-{cfg.opt}"]
    if debug:
        argv += ["-g"]
    if not unwind:
        argv += NO_UNWIND
    if no_exceptions:
        argv += NO_EXCEPTIONS
    if p.kind == "so":
        argv += ["-fPIC", "-shared"]
    flags = [f.replace("@ZSTD@", _zstd_lib()) if "@ZSTD@" in f else f for f in p.flags]
    argv += flags
    argv += ["-w", "-o", out]
    argv += p.sources_for(cfg.arch)
    argv += list(p.libs)
    return argv

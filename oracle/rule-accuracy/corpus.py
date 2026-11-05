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
import json
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
    # PE through mingw (held-out set only): gcc emits DWARF there too, and
    # `readers.py` reads a PE through the mingw binutils and llvm-dwarfdump.
    "pe_x64": Arch(
        "pe_x64",
        {("gcc", "c"): ["x86_64-w64-mingw32-gcc"], ("gcc", "c++"): ["x86_64-w64-mingw32-g++"]},
        "x86_64-w64-mingw32-strip",
    ),
    "pe_x86": Arch(
        "pe_x86",
        {("gcc", "c"): ["i686-w64-mingw32-gcc"], ("gcc", "c++"): ["i686-w64-mingw32-g++"]},
        "i686-w64-mingw32-strip",
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
    # The copies without `-g` only show whether `-g` changed the code, recorded
    # for the tuned corpus: they would double the build of the held-out set.
    return {k: v for k, v in out.items() if not k.endswith(".nog")} if _SET == "heldout" else out


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
    # Flags and libraries that differ by arch (the held-out set), beside `flags`
    # and `libs`.
    flags_for: object = field(default=None, compare=False)
    libs_for: object = field(default=None, compare=False)


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
TUNED = {
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


# --- The held-out set -------------------------------------------------------
#
# Chosen by the lead apart from the tuning, from public source, at these exact
# commits, and fetched and built only once the engine of the discovery accuracy
# round was final (2026-11-05). `heldout_prepare.py` fetches them, verifies the
# commits, and runs the configure steps two of them need; it writes the recipes
# the entries below read. Measured once, with `RULE_ACCURACY_SET=heldout` and a
# scratch of its own. An engine changed after seeing the result makes the set no
# longer held out: say so and name a new one rather than measuring this again.

HELDOUT_SRC = os.environ.get("RULE_ACCURACY_HELDOUT_SRC", os.path.expanduser("~/.cache/rule-accuracy/heldout-src"))
HELDOUT_SOURCES = {
    "lz4": ("https://github.com/lz4/lz4", "v1.10.0", "ebb370ca83af193212df4dcbadcc5d87bc0de2f0"),
    "nginx": ("https://github.com/nginx/nginx", "release-1.27.3", "e7bd2557458c26839da89e694067017eeb214348"),
    "ninja": ("https://github.com/ninja-build/ninja", "v1.12.1", "2daa09ba270b0a43e1929d29b073348aa985dfaa"),
    "leveldb": ("https://github.com/google/leveldb", "1.23", "99b3c03b3284f5886f9ef9a4ef703d57373e61be"),
    "re2": ("https://github.com/google/re2", "2024-07-02", "6dcd83d60f7944926bfd308cc13979fc53dd69ca"),
    "tmux": ("https://github.com/tmux/tmux", "3.5a", "549c35b06165f6ae023115eb76f83f2cbf945395"),
}
_PE = ("pe_x64", "pe_x86")
_NO_RECIPE = "run heldout_prepare.py first (RULE_ACCURACY_HELDOUT_SRC names where it wrote)"


def _src(project: str, *names) -> list:
    return [os.path.join(HELDOUT_SRC, project, n) for n in names]


def _inc(project: str, *names) -> list:
    return ["-I" + os.path.join(HELDOUT_SRC, project, n) for n in names]


def _recipe(project: str, arch: str) -> dict:
    """What a project's own configure step decided, as `heldout_prepare.py`
    read it from the Makefile it generated: sources, flags, libraries."""
    path = os.path.join(HELDOUT_SRC, "recipes", f"{project}-{arch}.json")
    if not os.path.exists(path):
        raise SystemExit(f"corpus: no recipe {path}: {_NO_RECIPE}")
    return json.load(open(path))


def _lz4(_arch: str) -> list:
    return _src("lz4", *(f"lib/{f}.c" for f in ("lz4", "lz4file", "lz4frame", "lz4hc", "xxhash")))


_NINJA_COMMON = (
    "build", "build_log", "clean", "clparser", "debug_flags", "depfile_parser", "deps_log", "disk_interface", "dyndep", "dyndep_parser", "edit_distance",
    "eval_env", "graph", "graphviz", "json", "lexer", "line_printer", "manifest_parser", "metrics", "missing_deps", "ninja", "parser", "state", "status",
    "string_piece_util", "util", "version",
)  # fmt: skip


def _ninja(arch: str) -> list:
    """`configure.py`'s lists, without its optional `browse` (which needs python
    to generate a header and is off on Windows anyway)."""
    names = list(_NINJA_COMMON)
    if arch in _PE:
        names += ["subprocess-win32", "includes_normalize-win32", "msvc_helper-win32", "msvc_helper_main-win32"]
        return _src("ninja", *(f"src/{n}.cc" for n in names)) + _src("ninja", "src/getopt.c")
    return _src("ninja", *(f"src/{n}.cc" for n in names + ["subprocess-posix"]))


def _ninja_flags(arch: str) -> list:
    # Its `-fno-exceptions` is left to variant (d), which adds it, but on a PE:
    # without unwind tables, x86-64 mingw's g++ asks for a personality routine
    # libstdc++ does not have there (`__gxx_personality_v0`), and (c) does not link.
    base = ["-std=c++11", "-fno-rtti", "-DNINJA_PYTHON=\"python\""]
    return base + (["-fno-exceptions", "-D_WIN32_WINNT=0x0601", "-D__USE_MINGW_ANSI_STDIO=1", "-static"] if arch in _PE else ["-fvisibility=hidden", "-DUSE_PPOLL"])


_LEVELDB_CC = (
    "db/builder", "db/c", "db/db_impl", "db/db_iter", "db/dbformat", "db/dumpfile", "db/filename", "db/log_reader", "db/log_writer", "db/memtable", "db/repair",
    "db/table_cache", "db/version_edit", "db/version_set", "db/write_batch", "table/block_builder", "table/block", "table/filter_block", "table/format",
    "table/iterator", "table/merger", "table/table_builder", "table/table", "table/two_level_iterator", "util/arena", "util/bloom", "util/cache", "util/coding",
    "util/comparator", "util/crc32c", "util/env", "util/filter_policy", "util/hash", "util/logging", "util/options", "util/status", "helpers/memenv/memenv",
)  # fmt: skip


def _leveldb(arch: str) -> list:
    return _src("leveldb", *(f"{n}.cc" for n in _LEVELDB_CC + ("util/env_windows" if arch in _PE else "util/env_posix",)))


def _leveldb_flags(arch: str) -> list:
    # What its CMakeLists decides on this platform, with the optional
    # compressors and the hardware CRC off. `-fvisibility=hidden` with its
    # export macro is how it builds its shared library.
    common = ["-std=c++11", "-fno-rtti", "-DLEVELDB_SHARED_LIBRARY", "-DLEVELDB_COMPILE_LIBRARY", "-DHAVE_FULLFSYNC=0", "-DHAVE_CRC32C=0", "-DHAVE_SNAPPY=0", "-DHAVE_ZSTD=0"] + _inc("leveldb", ".", "include")
    if arch in _PE:
        # `-fno-exceptions`, its CMakeLists' flag, for the reason `_ninja_flags` says.
        return common + ["-fno-exceptions", "-DLEVELDB_PLATFORM_WINDOWS=1", "-D_UNICODE", "-DUNICODE", "-DHAVE_FDATASYNC=0", "-DHAVE_O_CLOEXEC=0"]
    return common + ["-DLEVELDB_PLATFORM_POSIX=1", "-DHAVE_FDATASYNC=1", "-DHAVE_O_CLOEXEC=1", "-fvisibility=hidden"]


_RE2_CC = (
    "util/rune", "util/strutil", "re2/bitmap256", "re2/bitstate", "re2/compile", "re2/dfa", "re2/filtered_re2", "re2/mimics_pcre", "re2/nfa", "re2/onepass",
    "re2/parse", "re2/perl_groups", "re2/prefilter", "re2/prefilter_tree", "re2/prog", "re2/re2", "re2/regexp", "re2/set", "re2/simplify", "re2/tostring",
    "re2/unicode_casefold", "re2/unicode_groups",
)  # fmt: skip


def _re2(_arch: str) -> list:
    return _src("re2", *(f"{n}.cc" for n in _RE2_CC))


def _re2_flags(_arch: str) -> list:
    # Abseil's headers, reached through a directory of their own so a cross
    # compiler does not read the host's /usr/include; its libraries stay
    # unresolved in a shared object. The project's Makefile's version script.
    return ["-std=c++17", "-pthread", "-I" + os.path.join(HELDOUT_SRC, "absl-include"), "-Wl,--version-script=" + _src("re2", "libre2.symbols")[0]] + _inc("re2", ".")


def _nginx(arch: str) -> list:
    return _recipe("nginx", arch)["sources"]


def _nginx_flags(arch: str) -> list:
    return _recipe("nginx", arch)["flags"]


def _nginx_libs(arch: str) -> list:
    return _recipe("nginx", arch)["libs"]


def _tmux(arch: str) -> list:
    return _recipe("tmux", arch)["sources"]


def _tmux_flags(arch: str) -> list:
    return _recipe("tmux", arch)["flags"]


def _tmux_libs(arch: str) -> list:
    return _recipe("tmux", arch)["libs"]


# Where a project is not on a machine, why (the report lists these):
#   nginx    not aarch64: its configure runs what it compiles, and nothing here
#            runs AArch64. No PE: its Windows build is its own and MSVC's.
#   tmux     x86-64 only: libevent and ncurses are installed for the host alone.
#   re2      no PE: Abseil is not installed for mingw, and a DLL cannot leave
#            its symbols unresolved.
HELDOUT = {
    "lz4": Program("lz4", "c", "so", "lz4 1.10.0 lib/", ALL + _PE, ("-DXXH_NAMESPACE=LZ4_",), sources_for=_lz4, flags_for=lambda _a: _inc("lz4", "lib")),
    "nginx": Program("nginx", "c", "exe", "nginx 1.27.3, no rewrite and gzip modules", ("x86_64", "i686"), sources_for=_nginx, flags_for=_nginx_flags, libs_for=_nginx_libs),
    "ninja": Program("ninja", "c++", "exe", "ninja 1.12.1", ALL + _PE, sources_for=_ninja, flags_for=_ninja_flags),
    "leveldb": Program("leveldb", "c++", "so", "LevelDB 1.23, no compressors", ALL + _PE, sources_for=_leveldb, flags_for=_leveldb_flags),
    "re2": Program("re2", "c++", "so", "RE2 2024-07-02, against the host's Abseil headers", ALL, sources_for=_re2, flags_for=_re2_flags),
    "tmux": Program("tmux", "c", "exe", "tmux 3.5a", ("x86_64",), sources_for=_tmux, flags_for=_tmux_flags, libs_for=_tmux_libs),
}

_SET = os.environ.get("RULE_ACCURACY_SET", "tuned")
if _SET not in ("tuned", "heldout"):
    raise SystemExit(f"corpus: RULE_ACCURACY_SET is `tuned` or `heldout`, not `{_SET}`")
PROGRAMS = HELDOUT if _SET == "heldout" else TUNED

# --- A corpus described from outside the repo --------------------------------
#
# `RULE_ACCURACY_EXTRA` names a JSON file listing prebuilt images, so targets
# that are not this repo's business can be measured with this instrument and no
# name of theirs in it:
#
#   {"label": "...", "entries": [{"name": "...", "lang": "c" | "c++" | "...",
#     "arch": "x86_64", "compiler": "...", "opt": "...",
#     "unstripped": "/path/with/debug/info", "stripped": "/path/stripped"}]}
#
# Each entry is measured as variant (a), its unstripped file, and (b), its
# stripped one, against the unstripped file's DWARF; `stripped` may be left out,
# and `"only_stripped": true` leaves (a) out, for a truth file that is not itself
# the image of interest.
# While it is set, these are the configurations (results go under the scratch
# as usual); with it unset nothing here is read and nothing changes.
EXTRA_PATH = os.environ.get("RULE_ACCURACY_EXTRA")
EXTRA = json.load(open(EXTRA_PATH)) if EXTRA_PATH else None


@dataclass(frozen=True)
class Config:
    arch: str
    program: str
    compiler: str
    opt: str
    # An entry of the extra corpus: its two files. None for one this repo builds.
    extra: tuple | None = None

    @property
    def id(self) -> str:
        return f"{self.arch}/{self.program}/{self.compiler}-{self.opt}"

    @property
    def dir(self) -> str:
        return os.path.join(BUILD, self.arch, self.program, f"{self.compiler}-{self.opt}")

    def file(self, which: str) -> str:
        """`u.g`, `u.nog`, `n.g`, `n.nog`, `u.g.stripped`, `n.g.stripped`."""
        if self.extra:
            return {"u.g": self.extra[0], "u.g.stripped": self.extra[1]}[which]
        return os.path.join(self.dir, which)


def configs(select: str | None = None) -> list:
    """Every build configuration, optionally filtered by a substring of its id."""
    out = []
    if EXTRA is not None:
        for e in EXTRA["entries"]:
            cfg = Config(e["arch"], e["name"], e["compiler"], e["opt"], (e["unstripped"], e.get("stripped"), e.get("only_stripped", False)))
            if select is None or any(s in cfg.id for s in select.split(",")):
                out.append(cfg)
        return out
    for arch in ARCHES:
        for p in PROGRAMS.values():
            if arch not in p.arches:
                continue
            for c in COMPILERS:
                # A compiler this arch has no command for (clang through mingw).
                if (c, p.lang) not in ARCHES[arch].cc:
                    continue
                for o in OPTS:
                    cfg = Config(arch, p.name, c, o)
                    if select is None or any(s in cfg.id for s in select.split(",")):
                        out.append(cfg)
    return out


def lang_of(program: str) -> str:
    """The source language: what the ledger keeps (c) apart by."""
    if EXTRA is not None:
        return next(e.get("lang", "?") for e in EXTRA["entries"] if e["name"] == program)
    return PROGRAMS[program].lang


def manifest_of(cfg: Config) -> dict:
    """What `run.py` needs of a configuration: `build.py`'s manifest, or for an
    entry of the extra corpus the same identity check, made here: its stripped
    file is measured against the unstripped one's truth only when their code
    is the same."""
    if not cfg.extra:
        path = os.path.join(cfg.dir, "build.json")
        return json.load(open(path)) if os.path.exists(path) else {}
    import readers  # readers imports this module for its tool environment

    unstripped, stripped, only_stripped = cfg.extra
    ok = {} if only_stripped else {"a": True}
    if stripped:
        ok["b"] = readers.same_code(stripped, unstripped)[0]
    return {"ok": True, "truth_ok": ok}


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
    if p.flags_for:
        flags += p.flags_for(cfg.arch)
    argv += flags
    argv += ["-w", "-o", out]
    argv += p.sources_for(cfg.arch)
    argv += list(p.libs)
    if p.libs_for:
        argv += p.libs_for(cfg.arch)
    return argv

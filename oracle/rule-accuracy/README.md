# How often each function-discovery rule is right

The instrument behind docs/design/WHY.md §6 items 2 and 3, and behind the section "How often
each rule is right" in [docs/VERIFICATION.md](../../docs/VERIFICATION.md), which holds the
numbers, the corpus they were measured on and the engine version. This file says what is
measured, against what, and how to run it again; it holds no numbers, so it cannot go stale
beside them.

## The question

`function discover` lists function starts; `why --addr` names, for each, every source that
found the start (a declaration of the image: an `.eh_frame` FDE, a `.pdata` entry, an export,
a PLT stub, ...; or a rule: the instruction after a declared end, the gap sweep, a call target,
a prologue), the one source of its end, and the layer that gave its name. This instrument asks,
on programs whose answer is known: how often is each source right, and do the wrong answers
concentrate in the heuristic categories (the rules) rather than the declared ones? If they do
not, the category does not predict an error, and `why` must not be read as if it did.

## The truth (never n0xis)

Every program is compiled here with `-g`; the unstripped build's DWARF is the answer. Read by
`truth.py` through `readers.py`, the only parsers of each tool's output in the instrument:

| tier | rung | what | read with |
| --- | --- | --- | --- |
| `dwarf` | 1 | every `DW_TAG_subprogram` with code: its entry (`DW_AT_entry_pc`, else `low_pc`, else the first range) is a start; the range holding the entry is its extent. Concrete out-of-line instances (`.constprop`, `.isra`, `.part`) included | `llvm-dwarfdump --debug-info` |
| fragment | 1 | the other ranges of a split function (gcc's `.cold` parts): code of a function, not the start of one | the same |
| `symtab` | 3 | a `.symtab` FUNC symbol in a code section that no DWARF range covers: the C runtime and libgcc objects, which carry no DWARF. Extent: `st_size` when non-zero | `readelf -sW` |
| `plt` | 3 | each PLT entry, as the label objdump synthesises from the relocations (`puts@plt`); extent to the next label | `objdump -d` (GNU; the aarch64 cross objdump for AArch64) |

A PLT's header (the lazy resolver's trampoline) is no truth function and no padding: a start
there is counted as `plt0`, apart from right and wrong.

Names: every `.symtab`/`.dynsym` name at the address, and the PLT labels; C++ names are
compared after `c++filt`, not the engine's demangler.

## The variants

| variant | measured file | truth from |
| --- | --- | --- |
| a | the `-g` build as built (symbols, unwind tables, debug info) | itself |
| b | that file after `strip --strip-all` | the unstripped file |
| c | a build with `-fno-asynchronous-unwind-tables -fno-unwind-tables`, stripped | its unstripped build |
| d | C++ only: (c) with `-fno-exceptions` too, stripped | its unstripped build |

(d) is beyond the three the spec named: in C++ the flags of (c) leave an FDE on every function
that may unwind, so (c) of a C++ program is (b) again, and (d) is the C++ build in which the
rules carry discovery as they do on C in (c). The ledger reports (c) for C and for C++ apart.

Before a truth is used for a stripped file, `build.py` checks that every executable section of
the two has the same name, address, size and bytes; a configuration where they differ is
refused for that variant (`REFUSED` in the log), never measured against the other build. It
also builds each configuration without `-g` and records whether the code is the same, so a
reader knows whether the `-g` build is the release build (clang has been seen to differ).

Variants (c) and (d) are what make the rules carry discovery. Each summary records how many
`.eh_frame` FDEs the measured file holds (the C runtime's objects and the linker's PLT entries
keep a few), so a variant that is not FDE-free says so.

## What a listed start is scored as

`true` (the entry of a truth function), `fragment`, `plt0`, or wrong: `interior` (inside a
truth function or fragment, at no start) or `outside` (in no truth function: padding, or code
nothing names). Per source category (`score.py`): starts produced, true, wrong, precision
(true / (true + wrong)), and the same for the starts that source alone produced. Per truth
function: found or missed, and by which sources; a missed one records whether the measured file
names it in its own symbol tables. Ends, for true starts and fragments: per end source, exact /
short / long against the truth extent. Names: per layer, `exact` (the table's name, or its
reading by `c++filt` or by `llvm-cxxfilt` — two independent demanglers, so where they differ the
engine matching either is not wrong), `spelled` (the same identity in another spelling: an
undemangled name with every character outside `[A-Za-z0-9_]` as `_`, a stub named after its
import without `@plt`, or a demangled name that differs only in how an integer template
argument is written — `(unsigned long)0` for `0ul` — and in `> >`), `wrong` (anything else, a
parameter more or fewer included), `named_where_unnamed`, `fallback_where_named` (`sub_…` where
the table has a name: an absence, not a wrong name), `fallback_unnamed`.

The direction: of the wrong starts, how many carry only heuristic sources versus any declared
one, beside each kind's base rate; of the wrong ends, `not_stated` (the control-flow graph's
end) versus a declared end.

## How the engine is asked

`measure.py` runs the CLI exactly as a user would: `function discover --file <image>`, then
`why --file <image> --addr <start>` for every listed start, in a directory with its own fresh
`.n0x/` (checked with `project info`, `is_local: true`), so no kept list of another file
answers and nothing is written to the user's global project. It records the engine's path,
sha256 and version in every result. `why` and `discover` are compared (start, end, name) as a
contract check; a disagreement is counted, not taken as truth either way.

## Calibration

`calibrate.py <config>` plants wrong answers into a copy of a measurement and requires the
scorer to report each, asserting first that the mutation happened: a true start moved by one
byte (declared, variant b; heuristic, variant c) must become one interior start, one missed
function, and one more wrong start under the right kind in the direction; an exact end moved by
one byte must become one long end; a renamed function one wrong name. The code-identity check
must fail on two different builds and on a stripped copy with one `.text` byte flipped, and
pass on the real one. The DWARF reading is checked against the same build's `.symtab` (two
readers of one file): every DWARF entry must carry a FUNC symbol, and every FUNC symbol in
`.text` must be a DWARF entry, a fragment or a CRT function; `calibrate.py --truth-all` runs
that check on every truth file of the run.

`evidence.py` then shows, for every wrong start and end, what objdump reads at that address in
the unstripped build — the function it lies in, the instruction there and the one before it —
and counts wrong starts that the unstripped build's symbol table names (which would accuse the
reference, not the engine).

## Running it

Offline; the sources are the repo's `oracle/` programs and C/C++ vendored by crates already in
`~/.cargo/registry` (`corpus.py` names each, with its version). Tools: gcc, g++, clang,
clang++, `-m32` multilib, `aarch64-linux-gnu-gcc`/`g++` with its sysroot, ld.lld, binutils
(and the aarch64 cross binutils), llvm-dwarfdump, c++filt, python3.

```
systemd-run --user --scope -q -p MemoryMax=5G --nice=19 \
    sh oracle/rule-accuracy/run_all.sh             # or: --only x86_64/lua,i686
```

Everything goes under `~/.cache/rule-accuracy/` (`RULE_ACCURACY_SCRATCH`): `build/` (the
images and each configuration's `build.json`: commands, compiler, linker, identity checks),
`runs/` (the project directories), `results/<arch>/<program>/<cc>-<opt>/` (truth, the
engine's answers, one row per listed start, the summary), `results/report.md` (every table),
`results/doc-tables.md` (the tables the ledger carries, generated), `results/totals.json`,
`results/evidence.txt` and `evidence.jsonl`, `results/calibration.txt`. The engine is
`$N0XIS` (default `~/.local/opt/n0xis-wasm-preview/n0xis`). Two compiles at a time at most;
every compile and every engine call is under `timeout`.

`run.py --rescore` scores the kept engine answers again without asking the engine (after a
change to the scorer or a reader; the kept truth is keyed on the readers' own code, so it is
re-read). To record a run: take the tables from `results/doc-tables.md` into VERIFICATION.md
with the engine's sha256 and the corpus, re-run `calibrate.py`, and read `evidence.txt` before
calling anything wrong.

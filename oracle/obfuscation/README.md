# Obfuscation corpus and measurement

The question this instrument answers: on code a compiler would never emit —
code shaped to mislead a static reader — which of the engine's answers are
confidently wrong, and does anything in the answer warn of it? The number that
matters is **silent or flagged**: of the wrong answers, how many carried any
warning (a `why` source that is only a heuristic, a place listed by
`contradictions`, a refusal, an `ir deobfuscate` finding) and how many were
`ok:true` with nothing. A confident wrong answer with no warning is the worst
shape an answer can take, because the caller has no error to branch on.

This is **not a second instrument**. It reuses `oracle/rule-accuracy`'s readers
(`readers.py`), its truth reader (`truth.py`) and its scorer (`score.py`). A
transformation is one more variant of the same question, extended to the
commands obfuscation stresses beyond function discovery.

## Why the truth survives the transformation

Every transformation here runs where the symbols are still labels — the
assembler file (`.s`) the compiler emits, or LLVM IR — so the *obfuscated*
build's own unstripped DWARF and symbol table are correct by construction (a
function's `low_pc`/`high_pc` are labels, which the assembler relocates past any
bytes inserted between them). That makes the obfuscated-stripped image a
rule-accuracy variant (b): truth from its own `-g` twin, measured on the strip.
The transformed program must still run and print exactly what the clean build
prints — a transformation that changes behaviour is a bug, not obfuscation —
which `obf_build.py` checks by running clean, obfuscated and reference builds and
comparing stdout.

For a real instruction boundary — needed where a linear disassembler
desynchronises (junk bytes, overlapping instructions) — the truth is a
**reference twin**: the same assembly with the planted dead bytes replaced by an
equal count of NOPs. Its code is byte-for-byte the obfuscated one except in the
planted (unreachable) ranges, so an independent `objdump` reads the true
boundaries off it without desync. The twin runs identically too.

Post-link transformations (lying tables, a packer) keep the file *before*
tampering as the truth.

## The transformations

Each is applied alone, at two intensities (the share of functions touched), so a
wrong answer traces to one cause. Combinations are labelled as such. Registered
in `transforms.py`, one per commit:

- **junk** — bytes that never execute after each unconditional transfer
  (`ret`/`jmp`), in a chosen share of functions: an `0xe8` on x86 (a linear
  sweep reads it as a `call` swallowing the four following bytes). Desynchronises
  a linear sweep; dead, so behaviour is unchanged.

(more transformations are added here as they land: opaque predicates, control-
flow flattening, string encryption, computed-table calls, overlapping
instructions, lying tables, a packer stub, and a forged WebAssembly name
section.)

## Build configuration and its caveats

Programs are compiled `-O1 -g -fno-pic -no-pie`. Two caveats a reader must keep:

- `-fno-pic -no-pie` makes a non-PIC build, where some branches a compiler emits
  in the C runtime's `register_tm_clones`/`deregister_tm_clones` resolve to a
  static constant. `ir deobfuscate`'s opaque-predicate rule then correctly flags
  them — a true positive of its rule, but a *false alarm for obfuscation* on
  honest startup code. The honest-code false-alarm number is reported with this
  in mind; a PIC build would show a different base rate.
- the corpus small programs are the dedicated `calib.c` and the Lua 5.4.7
  interpreter from the `lua-src` crate (run on a fixed script so its output is a
  deterministic behaviour check). zstd and the repo `oracle/` sources are shared
  objects; a runnable driver for them is not built yet, so they are not measured
  here. Said as an absence, not hidden.

## Running it

Offline. Tools: gcc (with `-m32` multilib), `aarch64-linux-gnu-gcc` and its
sysroot, `qemu-aarch64-static` to run the AArch64 images, binutils, readelf,
objdump, llvm-dwarfdump. The engine is `$N0XIS`.

```
sh oracle/obfuscation/run_all.sh --transform junk --only x86_64
python3 oracle/obfuscation/obf_calibrate.py x86_64/calib/junk/i050
```

Everything is written under `~/.cache/obfuscation` (`OBF_SCRATCH`):
`build/<id>/` (the images, the assembly, `build.json`), `runs/` (the project
directories), `results/<id>/` (truth, the engine's answers, the per-command
summary), `results/report.md` and `results/doc-tables.md`. The scored run is
resumable and every engine call is bounded by `timeout`.

## Calibration

`obf_calibrate.py <config-id>` plants a wrong answer into a copy of a
measurement and requires the scorer to report it (asserting the mutation
happened first): a disasm instruction moved off a true boundary must score one
more wrong instruction; a true function start moved by a byte must score one
more wrong start; and an *untouched* function must decode with no desync against
the twin (so the twin is a sound oracle). It then prints every wrong disasm
instruction by the bytes — the obfuscated bytes the engine decoded against the
reference twin's reading — so a counted wrong is checkable against the
instructions, and counts how many wrong starts the measured file's own symbol
table names (which would accuse the reference, not the engine). Run it at i050,
where untouched functions exist and the twin check is not vacuous.

## What is recorded in docs/VERIFICATION.md

The tables from `results/doc-tables.md` with the engine's sha256, the corpus and
the verdict on which `WHY.md`/`VERIFICATION.md` claims hold on obfuscated code.
`README` holds no numbers, so it cannot drift from them.

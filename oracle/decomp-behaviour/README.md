# Decompiled bodies, read as C and run

Does a body the engine prints behave like the source it came from? Each function of `oracle/emu*.c` and
`heldout.c` is compiled, the engine is asked for its body from the stripped library, that body is compiled
with one prelude, and both are run on the same 500 generated inputs: boundary values, seeded random, strings
and buffers, compared by return value and by the buffers afterwards.

    python3 oracle/decomp-behaviour/behave.py ENGINE OUTDIR

Prints the counts per set (`emu`, the corpus the engine's tests use; `held-out`, 41 small functions written
for this measurement before any of their bodies was read) and writes `OUTDIR/functions.tsv`, one line per
function per build. `report.py OUTDIR --against OLDDIR` lists which functions changed outcome.

Three builds of the held-out set (gcc -O1, gcc -O2, clang -O2) make 123 bodies; two gcc builds of five `emu*`
files and clang of three make 242. Every library is linked at a fixed base, so a literal address in a body is valid.

## What the numbers mean, and do not

**"Same" is an upper bound.** A body as printed rarely compiles, so it goes through a mechanical layer
(`behave.py` lists every rule): it declares names no line declares, gives a dotted name a C spelling, reads an
untyped `*x` as 64 bits, binds callees by address, spells signed relationals. That layer is a generous reader:
it decides things a person reading the body would have to guess, and it was grown by reading failures. A body
that is "same" behaves like the source *under that reading*. `compiles-as-printed` is the prelude alone.

"Rescued" counts a failing body that passes under another reading of what it left unsaid, a different width
for every untyped access or a non-zero value for a name read before it is set. A rescued body still counts as
failing: it did not say what it needs.

The source runs through the same harness as a calibration and must score full marks. Its known exceptions are
6 NaN-payload differences (operand order at -O0) and `emu_sub32_branch` on clang, where the source's signed
overflow is undefined and `-fwrapv` and clang's -O2 read it differently. `calibrate.py OUTDIR` plants a mistake
in bodies that pass (a constant +1, a branch removed, a loop removed), 30 of each; the score must fall.

The held-out set is 41 small functions by one author. It separates a defect from no defect; it does not give a
rate for real code. A fix judged on it alone is tuning, since it can be read; each class also has a counter
over big images.

## Counters over big images

    python3 oracle/decomp-behaviour/big_images.py ENGINE OUTDIR LABEL=IMAGE=ADDRS...

Asks for one body per listed address and prints, per image, how many functions show each shape:
`lint_bodies.py` (text), `lint_rbp.py` and `lint_signed.py` (text against `objdump` of the same image).
`lint_noreturn.py RAW TWIN` needs the unstripped twin's DWARF. Each shape was opened against the bytes on at
least one example, not on all: they are text matches, and a count here raises a question, it does not settle
one. Hold the address list fixed between an old and a new engine.

`attribute.py OUTDIR` names the shapes each failing behaviour body holds.

Needs gcc, clang, binutils, `x86_64-w64-mingw32-objdump` for PE images and `llvm-dwarfdump` for the noreturn counter.

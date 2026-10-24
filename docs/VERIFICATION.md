# Verification ledger

The one place the numbers live: **what has been checked, against what, on how many
cases, and what is still open**, so a proven claim, a wrong answer, an open gap and a
thing never claimed are all visible together. [README.md](../README.md) states the
support tables and three of these numbers; each is here with its method and its date.
Where the README and this file disagree, this file is the measurement and the README
sentence is the one to fix. `ROADMAP.md` keeps the history of how each number was
reached, so a figure there older than the date beside it here is history, not the
current state. The discipline behind it is in [oracle/README.md](../oracle/README.md).

**A claim is true only when a source that is not this tool says so**, and the
source is ranked:

1. an answer built to be known before the question — compiled from source with
   debug info, a value the program prints about itself, bytes planted on purpose,
   the processor's own result;
2. the producer's own artifact — the image's unwind table, RTTI strings, the
   shipped headers of that exact version;
3. an independent parser or tool — `objdump`, `nm`, `llvm-objdump`, `readelf`;
4. a second implementation of the same thing — it guesses too; raises suspicion,
   never settles;
5. the thing compared against itself — not evidence.

Status: **PROVEN** (measured against a rung-1..3 source, 0 disagreements or a
bounded/explained gap) · **OPEN** (a real gap, reproduced or suspected, not yet
closed) · **NOT CLAIMED** (needs an input or a platform not available here).

---

## October 2026: the support tables

The tables in the README, cell by cell, with their sources and counts.

**How it was measured.** 2026-10-20 and 21, on the code of 0.3.5 (`e8e67b8`; that
commit changes only the version and the changelog, and the copy measured, built just
before it, prints `0.3.4`). Four areas, each against sources outside n0xis: image
formats, instruction sets, a live process, and the sentences of the README as it then
stood. Each was then re-measured by a second pass that wrote its own targets and
checkers and tried to refute the first: formats, 100 claims re-checked, 2 refuted, 9 not re-examined; ISAs,
16 re-checked, 4 refuted, 10 not; live, 17 re-checked, 0 refuted, 12 not; those README
sentences, 28 re-checked, 2 refuted, 51 not. A refuted cell is recorded here as the
second pass measured it. A cell nobody re-examined is a first measurement only, and
says so where it carries a number.

**Where the instruments are.** Not in the repository yet: the target sources, build
scripts and checkers behind this section were kept outside version control, so these
rows cannot be re-run from a clone (Open, below).

### Formats, static file

Targets: one C file of 14 functions and one C++ file of six polymorphic classes (with
multiple inheritance), built 14 ways at `-O2` with no unwind tables
(`-fno-asynchronous-unwind-tables`), plus two PE builds with them (x64, ARM64). Every
build that runs computes the same values: natively, under the Windows compatibility
layer, under `qemu-aarch64_be-static` and under `wasmtime`.

| Image | disasm | function discover | decomp: right of 14 | xref to: code; data | rtti scan | profile, names, strings |
| --- | --- | --- | --- | --- | --- | --- |
| PE32+ x86-64, MSVC ABI (clang, lld-link) | 425/425; 40/40 branch targets | 24/35, 0 false starts; misses the entry point and 10 methods reached only through vftables; with a PDB, 35/35 starts, names and ends; `--pdata` 10/10 on the unwind build | 11 (3 wrong) | 24/24 functions, 35 sites; 2/2 | 7/7 vftables, the secondary one included | profile right; exports 14/14; the COFF symbol table is not read (10 functions `sub_`); ASCII strings 36/36 |
| PE32+ x86-64, MinGW gcc | 3 483/3 483 | 150/154 (the 4 are assembler labels), 1 false start inside a function; `--pdata` 74/74 starts and ends | 5 (8 wrong, 1 incomplete) | 98/98, 188 sites; 2/2 | **wrong**: 0 of 7 Itanium vtables, no advisory | **wrong**: 10 of 20 section names printed as `/4`, `/14`, …; 90 of 150 functions `sub_`; strings 3 128/3 128 once runs are split at CR/LF |
| PE32 x86, MSVC ABI | 462/462 | 24/35; `--pdata` refused (PE32) | 6 (7 wrong, 1 incomplete) | 24/24, 35 sites; 0/2 (absolute `push`) | 7/7 | profile right; exports 14/14; strings 42/42 |
| PE32 x86, MinGW gcc | 3 598/3 598 | 123/133; 33 false starts, every one the padding `lea esi,[esi+eiz]` | 7 (6 wrong, 1 incomplete) | 80/96 functions, 168/184 sites (the 16 are absolute immediates); 0/3 | **wrong**: 0 of 7 | **wrong**: 10 of 18 section names; import thunks unnamed; strings 3 035/3 035 after the CR/LF split |
| PE ARM64, MSVC ABI | 287/287 | 24/35; `--pdata` **wrong**: not refused, 3 of 10 functions, ends past the image | 5 (3 wrong, 6 incomplete) | 24/24, 35 sites; 0/2 (`adrp`+`add`) | 7/7 | **wrong**: `pdata_functions` 6 where the table holds 10; exports 14/14; strings 36/36 |
| ELF64 x86-64 gcc, `-no-pie` and PIE | 425/425; PIE 422/422 | 25/37 (PIE 23/35), names 25/25, ends 22/22 where the symbol has a size; the stripped copy finds the same 25 | 5 (8 wrong, 1 incomplete), both builds | 29/30 (`_start`'s `mov rdi, main`), PIE 30/30; 2/2 | 6/7: the secondary vtable is not listed | profile right; strings 33/33 |
| ELF64 x86-64 gcc, shared object | 455/455 | 4/33: calls go through PLT stubs | 8 (5 wrong, 1 incomplete; 2 read by hand) | 26/26, 50 sites; data is reached only through GOT slots, 0 direct | 6/7; the 3 derived classes `bases_unknown` | **wrong** (second pass): the export list counts local helpers and gives `.localalias` names where `.dynsym` exports the global one; PLT stubs and GOT slots unnamed |
| ELF32 i386 gcc, PIE | 624/624 | 29/41; 9 padding false starts and the `.plt` block | 6 (7 wrong, 1 incomplete; 2 read by hand) | 29/29, 52 sites; GOT-relative data 0 | 6/7 | 5 of 29 names rewritten (`.` to `_`); strings 36/36 |
| ELF64 AArch64 big-endian, clang, static | 317/317 (3 `nop` = `hint #0x0`) | 26/37, names and ends 26/26 | refused (`big-endian-image`, with a reason about RTTI); the same bytes decompile through `--bytes` | 25/25, 36 sites; 0/2 (`adr`) | refused | profile right; ASCII strings 13/13; the UTF-16BE string is not found and there is no option for it |
| Mach-O, thin (x86-64, arm64) and universal | refused (`load-failed`) | refused | refused | refused | refused | refused, in all 8 operations |
| WebAssembly (valid: `wasmtime` runs it) | 2026-10-23, stage 2: every instruction of every function agrees with `wasm-objdump -d` (below) | every body, extent, index and name (the list's own, verbatim) agree with `wasm-objdump -x`/`-d` | refused (`not-lifted`, stage 3) | calls and tail calls to and from every function, imports included, and `ref.func`, agree with `-d`; data refused (`not-lifted`) | refused (`no-native-pointers`) | profile, imports, exports, memories, tables, segments agree with `-x`; strings in the data segments with their linear-memory place (UTF-16 hits not checked by any tool) |
| Raw bytes (`--bytes`) | x86-64 404/404, ARM64 287/287 | with `--start`: 24/37, 24/35, 0 false starts | Win64 slices 11; ARM64 6 (2 wrong, 6 incomplete); SysV x86-64 0, decompiled under the Win64 convention | 20/20 (28 sites), 24/24 (35 sites) | refused (`no-image-base`) | `profile` refused; strings with `--start`/`--size` 14/14 and 1/1 UTF-16LE, refused without a range |

Sources: disasm against `llvm-objdump -d -M intel` (x86) and GNU
`aarch64-linux-gnu-objdump -M no-aliases` (ARM64), on address, bytes, mnemonic, operands
and branch target; function discover against the COFF symbol table (`llvm-readobj
--symbols`, `llvm-nm`), `llvm-readelf -sW`, `llvm-pdbutil` and `llvm-readobj --unwind`;
decomp against the C source compiled next to the pseudo-C and run on the same inputs
with the image mapped at its base, by a checker calibrated on 23 planted right and wrong
cases, with the verdicts it could not execute (base-0 images, undeclared tables, text
that does not compile) read by hand against `llvm-objdump`; xref against `llvm-objdump`
(branch targets, resolved RIP operands, `adrp`+`add` paired by register, GOT-relative
addresses by hand); rtti against `lld-link /map` and the COFF symbols (MSVC) and
`llvm-nm -C` with the vtable words read from the file (Itanium); profile against
`llvm-readobj` and `llvm-readelf`; strings against `strings -a -n 4` (`-e l`, `-e b`) over
the same bytes.

The second pass built its own probe for every format: 98 of its 100 claims held,
disasm 100% on its 9 images, x64 `--pdata` 4/4, a PDB beside its PE32+ image 18/18
starts, names and ends against `llvm-pdbutil`'s `S_GPROC32` records, MSVC RTTI 5/5 and,
on a new axis, virtual inheritance 8/8. It refuted the two shared-object cells marked above, and it did not
reproduce the decompiler totals, only their named causes.

The definitions these answers use, which are not defects: an ELF's `exports` in
`profile` are its defined FUNC symbols, local ones included (the shared-object defect
above is that); PE `image_end` is the furthest section end, not ImageBase + SizeOfImage;
`strings` keeps CR and LF inside a run and accepts non-ASCII UTF-8 and UTF-16 (106 of the
107 UTF-16 runs on the MinGW x64 image are DWARF bytes); `rtti scan`'s bases are the
direct ones on Itanium and the whole hierarchy on MSVC; an Itanium `type_descriptor` is
the vtable's type-info slot; with `--bytes`, the bytes begin at `--addr` for disasm and
decomp and at `--start` for discover and xref.

Not measured: decomp of the C++ virtual-dispatch functions, a PDB on PE32 or ARM64,
images linked against a real MSVC runtime, and Mach-O or WebAssembly code fed as
`--bytes`.

### WebAssembly modules, stage 2 (2026-10-21; re-measured 2026-10-23 after the fix round)

docs/design/WASM.md stage 2: a module opened with `--file`, before the lift. Two corpora,
compared fact by fact with wabt 1.0.42's `wasm-objdump` (rung 3) by
`crates/n0xis-cli/tests/wasm_facts_are_what_wasm_objdump_lists.rs`: sections (title, start,
end) with `-h`; imports (kind, index in its kind's space, module and name), exports (kind,
index, name, a function's body or none for an import exported again), memories (index type,
limits, shared, import), tables, the start function, element segments (table, count,
placement) and data segments (memory, size, placement, and the bytes at the module offset
given for them) with `-x`, as `profile` gives them, and `profile`'s image exports (index and
body) and folded exports (the functions exported under several names); the function list
(body offset, index, extent, and the name both as the image stores it and as the list gives
it) with `-x` and `-d`; `disasm` from every body to its end with `-d` (the locals runs, then
each instruction's offset, bytes and mnemonic; the rest of the text is the stage-1 decoder's,
which `crates/n0xis-wasm/tests/references.rs` compares with the same recordings and with
`wasm-tools print`); every `call`/`return_call`'s target, the callee's body or none for an
import; `xref to` every function's body against the direct calls and tail calls (`call`/`jmp`)
and the `ref.func`s (`data`) `-d` shows, and on a module under 64 KiB the same question swept
over the code section as a window, which must give the index's answer; `xref from` at every
call, tail call and `ref.func`: one reference, to the index `-d` names, at its body or with no
position for an import, from the function it is in, with the name `-d` prints (`call 0
<host_log>`); and each `strings` hit against its segment's placement and the file's bytes.

| Corpus | modules | sections | functions | instructions | call targets | imports | exports | data segments | strings | disagreements |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| built here from known source (`crates/n0xis-wasm/tests/fixtures`, recorded) | 13 | 119 | 123 | 4 526 | 93 (65 to an import, 3 `ref.func`) | 28 | 197 | 11 | 2 | 0 |
| planted here (`crates/n0xis-cli/tests/fixtures/wasm`: `indexed.wat`, `names.cpp`, recorded) | 2 | 19 | 10 | 134 | 10 (3 to an import, 1 `ref.func`) | 2 | 5 | 1 | 0 | 0 |
| found on this machine, no known source (an editor's parsers, a regex engine, an HTTP parser, Rust and C modules; deduplicated by content) | 46 | 408 | 6 893 | 2 366 436 | 38 249 (759 to an import, no `ref.func` in any) | 487 | 856 | 495 | 239 832 | 0 |

Two answers the real modules made the reader correct before they agreed, each a defect of
this step, not of the tools: an export named `""` was a function's name (wasm-objdump names
nothing by an empty name, and neither does the image now), and a module with no code section
answered `no-range` where its function list is known and empty (it answers an empty list with
a note now). Where a function is exported under several names and the `name` section names it
by none (26 functions in the real corpus), wasm-objdump keeps one of them and the image the
first; either is accepted, and the count is printed. `gc.wasm` is not compared: wabt 1.0.42
refuses it (`gc.wabt-refuses.txt`).

What the comparison did not see before the fix round, found by three adversarial verifiers
and each now compared above: the list rendered a name as an identifier (`Vec::push(int)` as
`Vec__push_int_`, `a-b` and `a_b` both `a_b`; 25 of the 6 893 real functions) while the test
compared only the stored symbol; a call to an imported function was no reference at all
(`ok: true`, an empty list; 759 such calls in the real corpus); a `ref.func` was not a
reference to its function; an export in `profile`'s image block had no index. Of the strings,
68 561 are UTF-8 and 171 271 UTF-16LE in the real corpus: UTF-16 is now read at even
addresses of linear memory, where a compiler aligns `char16_t` text, not of the module (two
builds of one C file, `wide.c`, whose data sit at module offsets of different parity, find the
string at linear address 0x10000 in both; before, in one). wasm-objdump lists no strings, so
the UTF-16 hits are checked by placement and byte range only; many in a parser's tables are
likely `u16` arrays, not text, and no count of real strings among them was made.

A module planted for the purpose (`crates/n0xis-cli/tests/fixtures/wasm/placed-by-import.wat`,
assembled and validated by `wasm-tools` and `wasm-validate`): its data and element segments
placed by an imported global are answered `not_placed`, naming the global and its import, and
the ones placed by a constant beside them are placed, as `-x` prints them. Every lift-dependent
command refuses a module with `not-lifted`, naming stage 3, and `--arch x64` on one is refused
(`lift_commands_refuse_a_module.rs`; with the refusal removed, `disasm --arch x64` answered
`add [rbx],eax` over a body's bytes, `ok: true`). Two modules in one project keep two names at
one offset (`two_modules_keep_their_own_names.rs`).

Planted broken modules (`crates/n0xis-cli/tests/a_malformed_module_says_what_it_holds.rs`,
each judged by `wasm-validate` and, for the trap, `wasmtime`, by hand): an out-of-order and a
repeated `name` map entry are kept as the stage-1 reader keeps them and the finding says so in
words (it said "left out", in Rust's debug spelling); a body of size 0 is listed (it was
dropped, and a module of four empty bodies listed none); a start function and an export past
the index space, and a data segment past its memory's initial size, each carry a finding; a
module naming 160 000 functions opens in well under a second (a linear search per name made it
12.9 s). Each of those tests, and each comparison above that the round added, was calibrated by
reverting its fix: 25 mutations, each failing its own assertion.

Hostile input through the new layers (`crates/n0xis-core/tests/a_corrupted_module_is_answered_by_every_layer.rs`):
2 000 corrupted copies of each of the 14 fixtures, every one that opens (7 953 of the 28 000)
asked every image answer, every body decoded, the code section decoded as one range and the
function list made, under a deadline; no panic, every decoded instruction inside a body with
the file's bytes, the list exactly the declared bodies, the largest single allocation 105.6
times the input's length (bound 304). The test found two defects of this step before it
passed: a body of size 0 was stated with an extent of 0, and decoding a range across it never
advanced.

Not measured: decompilation and every other lift (stage 3); a module as a live target (stage
4); DWARF in custom sections; the component format (refused by the reader, as a component).
Not compared: an element segment as a reference to the functions it places in a table
(`xref` lists references from code, as it does on a native image); the module identity
beside a code position, which only `profile` states.

### Instruction sets

Targets: one C file of 14 functions with a freestanding driver (raw syscalls), and a
C++ variant with six virtual calls, built with clang 23.1.1 at `-O1` and `-O2` as static
non-PIE ELF with `.eh_frame`, for x86-64, i386, AArch64, ARMv7 A32 and T32. All 10 C
builds print byte-identical output, natively or under `qemu-aarch64-static` and
`qemu-arm-static`.

| ISA | disasm, every text symbol, two oracles | function discover (21 sized symbols) | decomp: `quality` mean, fallback lines | control flow against the processor (`dispatch` on 20 inputs, `bit_walk` on 7) |
| --- | --- | --- | --- | --- |
| x86-64 | 1 562/1 562 (650 + 912) | 21/21 starts and ends at both levels, stripped copy included | `-O1` 14/14 at 1.0, 0 of 191 lines; `-O2` 13/14, 8 of 273 (the vectorized loop) | read with the selector taken as the op, 27/27 per level. **Wrong as printed** (second pass): the switch selector is a register the text never assigns; compiled and run, the printed text agrees on 3 629 of 8 640 inputs at clang `-O1`/`-O2`/`-O3`, and on 8 640 with the dropped copy put back by hand; gcc `-O2` prints the right selector, 8 640/8 640 |
| i386 | 2 090/2 090 (860 + 1 230) | 21/21 | `-O1` 14/14 at 1.0, 0 of 250; `-O2` 13/14, 8 of 333 | the same: the selector prints as `rcx` or `rdx`, a 64-bit name in a 32-bit image; 3 629 of 8 640 as printed |
| AArch64 | 1 628/1 628 against GNU objdump; `llvm-objdump -M no-aliases` agrees on 1 624, its 4 others an LLVM misprint that the encoding and LLVM's default mode settle | 21/21 | `-O1` mean 0.848 (6/14 at 1.0), 51 of 216 lines (23.6%); `-O2` 0.795 (5/14), 127 of 369 (34.4%); every load inline as `/*ldr …*/`, `cbz`/`cbnz` conditions opaque | `dispatch` 14 of 20 inputs evaluable, all 14 agree; `bit_walk` 0 of 7 evaluable; 0 disagreements |
| ARMv7 A32 | `-O1` 728/728; `-O2` 914/960: the first NEON instruction is `(bad)` and stops the sweep (44 never decoded); jump-table words decoded as instructions (8 of 8, 8 of 12) | 17/21; ends 17/17 with the symbol table, none on the stripped copy; the 4 missed are in `.symtab` and `.ARM.exidx` | `-O1` 0.935, 18.6%; `-O2` 0.912, 22.2%; 1.0 on `call_chain` with its tail call missing | **wrong**: `dispatch` 0/20 (jump-table words lifted as statements); `bit_walk` 0/7 evaluable |
| ARMv7 T32 (`--arch thumb`) | **wrong**: `-O1` 607/717, `-O2` 675/864: all 201 branch-target texts 2 or 4 bytes short (the CFG's own targets are right), 44 IT-predicated instructions printed without their condition, BFC operands; without `--arch thumb` the image is read as A32, 0 of 193 | 17/21, with 0 ends and 0 names: the symbols' Thumb bit stays in the address | **wrong**: 8 of 14 functions end early at an IT-predicated `bx lr`; `cbz`, `cbnz` and `tbb` are not branches; coverage 65.3% / 53.4%; mean 0.654 / 0.667 | **wrong**: 0/20 and 0/7 |

Sources: llvm-objdump 23 and GNU objdump on the same file (`-M intel` for x86,
`-M no-aliases` for AArch64, ARM following the `$a`/`$t`/`$d` mapping symbols), compared
after canonicalization rules applied the same way to all three texts; `llvm-nm -S` for
extents; the processor for control flow. The first pass evaluated the pseudo-C by hand
on each input; the second compiled the printed text and ran it (x86, and on AArch64
`cmpneg`, 24/24).

The `quality` field is not a correctness signal: it reports 1.0 for the x86 switch with
an unassigned selector, for a virtual tail call rendered `// indirect jump
(unrecovered)`, for AArch64 `dispatch` with an opaque condition and for A32 and T32
`call_chain` with its tail call missing. The ledger's earlier Not-claimed row said
AArch64 `decomp pseudo` reports `quality: 0.0` and falls back to `asm`; measured
2026-10-20 it takes the SSA path everywhere, at the means above, and on `oracle/arm64.c`
built with gcc 16.1 and with clang 23 at 0.17 to 1.00 (means 0.64 and 0.67 for the two
builds), with `asm` holes remaining.

Devirtualization runs on x86-64 only, as its pass documents. On x86-64 it named 4 of 4
calls correctly (placement-new into a pointer argument, a heap object from an opaque
allocator) and 0 of 6 objects built on the stack in the same function, though the
pseudo-C prints their vtable store; 0 wrong names, and the control (the object arrives
as a parameter) refused 2 of 2. The second pass: 3 of 3 per level on calls that are not
in tail position, an out-of-line constructor included, and 0 of 3 in tail position. On
i386, AArch64, A32 and T32, 0 of 10, as documented.

The second pass also refuted the stated cause of the A32 discovery misses (`vsum` is
called directly and still missed) and found, at `-O3`, an extra function at an odd
address inside `_start`. Not measured: gcc-built, PIE or dynamically linked ARM images,
`-O0` and `-Os`, disasm on the C++ images, and live use of any ISA but x86-64.

### Live process, Linux x86-64

Target: an ELF64 built here with gcc `-O0 -g -no-pie` (so its static addresses are its
run-time ones), planting values in `.data`, a pointer chain from the module through the
heap, and a second thread parked three calls deep; it takes commands from a FIFO, so a
watchpoint is armed before the write it waits for. Sources: `/proc/<pid>/mem`,
`/proc/<pid>/maps`, `nm`, `objdump`, `eu-stack` and the target's own printed values.
With Yama `ptrace_scope=1` every command needed root, since n0xis ran as the target's
sibling.

| Operation | Result | Source |
| --- | --- | --- |
| `process ps --filter` | 1 of 1: pid and name | the pid the shell started |
| `module list` | 4 of 4 file-backed objects, bases and sizes | `/proc/<pid>/maps` |
| `mem map` | 26 of 26 regions, protections exact | `/proc/<pid>/maps` |
| `mem read` | 64 of 64 bytes | `/proc/<pid>/mem` |
| `mem span` across a gap | 32 bytes to the page end, then stops at the gap | maps and mem |
| `mem write` | 2 of 2 round trips | `/proc/<pid>/mem` |
| `scan value` | 1 hit, at `nm`'s address, with the planted value | `nm` |
| `scan filter` changed / unchanged | 1 match / 0 (the control) | `/proc` and the target's output |
| `scan group`, three fields | 1 hit at `nm`'s address, offsets 0, 4, 8 | `nm`, `/proc` |
| the byte-pattern scan (`scan aob`), bounded, exact and wildcard | 1 match, at `nm`'s address | `nm`, `/proc` |
| `scan aob`, default region set | **partial**: `ok:false` (`aob-failed`) on an unreadable thread-stack arena in 3 of 3 runs, never reaching the pattern | `/proc` cannot read that region either |
| `scan pointer-path` | the planted chain present and resolving; 3 of 3 sampled paths resolve | `/proc/<pid>/mem` |
| `scan dissect` | bytes exact; an `i32` guessed `float` at confidence 0.4; counted as not matching (the layout measurement is below) | `/proc` and the planted types |
| `table add` / `table show` | a round trip through n0xis's own store; not evidence, not counted | — |
| `table pin` | refused, `live-unsupported` (Windows-only) | — |
| `patch dry-run` | the current bytes right, nothing written | `/proc/<pid>/mem` |
| `patch apply` | written and journaled | `/proc` and the journal file |
| `patch list` / `patch show` | the list matches the journal; an unknown id is a typed error; checked only against the journal n0xis wrote, as `table add`/`show` only against its own store: not evidence, not counted | the journal n0xis wrote, whose bytes `apply` and `undo` checked against `/proc` |
| `patch undo` | 4 bytes restored, the record marked undone | `/proc/<pid>/mem` |
| `debug watch --kind write` | fired; `rip` right after the store; a 5-frame caller chain | `objdump`, maps |
| `provenance trace` | function, instruction and module offset exact | `objdump`, `nm` |
| `provenance trace`, `decompiled_context` | **wrong**: the written address printed as a string literal made of its current bytes (`">BCD"`) | `/proc` against the file's bytes |
| `stack backtrace` of the parked thread | 8 of 8 frames | `eu-stack` |
| `snapshot dump` / `info` / `list`, read back | 64 of 64 bytes | `/proc` at capture |
| `mem read --remote-cmd` (`remote-serve` over a local pipe) | 64 of 64 bytes | `/proc/<pid>/mem` |
| `debug await-hit` | not measured here (it patches a code byte; measured by the claims pass below) | — |
| Windows live commands | not measured (a Linux machine) | — |

The count in the README: of these 27 rows, 2 were not measured, and 2 were checked
only against what n0xis itself wrote, `table add`/`show` (its store) and
`patch list`/`show` (its journal), which is not evidence; that leaves 23. 19 matched
their source, and 4 did not: `scan aob` on the default region set, `scan dissect`, the
`provenance trace` context, and the `table pin` refusal. The README's live entry names
these four and one more, the loop head `provenance trace` gives as the function on some
builds, which was measured on `examples/config-demo` (below), not among the 23. The
second pass re-measured 17 on its own target and refuted none; it pinned the provenance
cause (non-printable bytes print as the address, printable ones as a string). Minor: `scan value` reports `exhaustive:true` having skipped an unreadable
region, and `scan group --field` rejects hexadecimal values.

Separately, the pass over the README's former sentences re-measured 19 live commands on a
target of its own (not re-examined by a second pass): 18 agreed with `/proc/<pid>/mem`,
`/proc/<pid>/maps`, the target's printed addresses, `objdump`/`nm` and `gdb`
(`debug await-hit` fired at the printed address; `mem map` 25 of 25 ranges; `stack
backtrace` frames 0 to 4 as `gdb bt`). The one that did not is `scan dissect`: on the
six-field layout of `live_memory_exit.rs` (i32, i32, f32, f32, u64, pointer) rebuilt in
C, it returned (0,4,int) (4,4,int) (8,8,double) (16,4,int) (20,4,int) (24,8,pointer) in
4 of 4 runs, 3 of 6 right, and 2 of 6 on a second layout. The earlier 5 of 6 does not
reproduce; the fix it recorded holds, since no field crosses its alignment.

### Memory of the passes that sweep code (2026-10-23)

The passes that walk a whole code range (`xref to` with its index or over a window, `xref
string`, `bindings list`, `il2cpp icalls`, and the index `analyze` builds) used to decode the
range in one call and keep every instruction, about 104 MiB of RSS per MiB of code. They now
share one sweep (`n0xis_core::sweep`) that holds one 1 MiB window of instructions.

**How it was measured.** Peak RSS is `getrusage(RUSAGE_CHILDREN).ru_maxrss` of each run (rung
1), every run in its own `systemd-run --user --scope -p MemoryMax=4G -p MemorySwapMax=1G` and
its own directory with its own `.n0x/`, so each default `xref to` builds its index rather than
reading one. Before: a release build of `2313b89`; after: the same with the sweep. Code size
is the `.text` size `readelf -SW` and `objdump -h` give. Runs predicted past 3 GB on the old
build (104 MiB per MiB) were not started; they are marked "not run".

| Command | Input | Code | Before | After |
| --- | --- | --- | --- | --- |
| `xref to` (default: builds the index) | libQt6Gui | 7.6 MiB | 789 MiB | 140 MiB |
| `xref to` (default) | libavcodec | 16.7 MiB | 863 MiB | 179 MiB |
| `xref to` (default) | libgallium | 32.4 MiB | 926 MiB | 250 MiB |
| `xref to` (default) | libLLVM | 79.7 MiB | 1 389 MiB | 554 MiB |
| `xref to --start --size` | libLLVM, 16 MiB of `.text` | 16 MiB | 1 877 MiB | 305 MiB |
| `xref to --start --size` | libavcodec, all of `.text` | 16.7 MiB | 1 730 MiB | 145 MiB |
| `xref to --start --size` | libLLVM, all of `.text` | 79.7 MiB | not run (8.3 GB predicted) | 342 MiB |
| `xref string` | libQt6Gui | 7.6 MiB | 791 MiB | 155 MiB |
| `xref string` | libavcodec | 16.7 MiB | 1 733 MiB | 174 MiB |
| `xref string --start --size` | libgallium, two windows of 16 and 16.4 MiB | 32.4 MiB | 1 724, 1 738 MiB | 195, 202 MiB |
| `xref string` | libgallium | 32.4 MiB | not run (3.4 GB predicted; 2.9 GB recorded 2026-10-21) | 235 MiB |
| `xref string` | libLLVM | 79.7 MiB | not run (8.3 GB predicted) | 396 MiB |
| `bindings list` | libavcodec | 16.7 MiB | 1 731 MiB | 148 MiB |
| `bindings list` | libLLVM | 79.7 MiB | not run | 382 MiB |
| `il2cpp icalls` | a 12 MB PE (this tool's Windows build) | 7.5 MiB | 762 MiB | 131 MiB |
| `analyze` | libz, libpng16, libcurl, libstdc++, libcrypto | 0.2 to 4.6 MiB | 30, 39, 125, 214, 413 MiB | 30, 39, 119, 125, 135 MiB |
| `analyze` | libQt6Gui, the PE, libavcodec, libgallium | 7.5 to 32.4 MiB | 791, 763, 864, 934 MiB | 142, 145, 180, 256 MiB |

**The answers did not change.** 121 outputs recorded with both builds are byte-identical, with
no field ignored (none of them carries a timing): `xref to` by the index on ten images (three
or four addresses each, the busiest call and `lea` targets by `objdump`), `xref to` over all
of `.text` on eight, and over 16 MiB of libLLVM; `xref string` (`%s` and `error`, all hits and
the default limit) on eight; `bindings list` (all and the default limit) on eight; `il2cpp
icalls` (all, `--limit 3`, `--query`) on the PE and on a PE built here whose six resolution
sites are known (five with a slot, one without; all six found, rung 1); libgallium's `.text`
in two windows through `xref string`, `bindings list` and `xref to`; `analyze` on the nine
images above; and the reverse-xref index `analyze` and `xref to` wrote (19 files, 4 026 to
2 193 775 targets). That sameness is the tool compared with itself (rung 5): it says the
change moved no answer, not that the answers are right. Two of them were also checked
against `objdump` (rung 3): 25 717 calls and jumps to libgallium's busiest target and 33 to
libz's, the counts `xref to` gives. Wall time is unchanged within run-to-run noise (`analyze`
libQt6Gui 7.8 and 7.7 s before, 7.5 and 7.6 s after), except that `xref string` now sweeps
the code once for every occurrence of the text instead of once per occurrence: libgallium's
first window with `%s`, 112 s before and 5.6 s after.

**Guards.** `crates/n0xis-core/tests/a_code_sweep_holds_one_window.rs` runs each of the five
passes on 64 MiB of planted code with the answer planted at its end, in a child whose heap is
capped at the image plus 96 MiB: with the sweep the largest peak is 37 MiB; with the four
passes restored to `2313b89`, all five are refused (the index's first 8 MiB window asks for
88 MiB at once). The unit tests in `src/sweep.rs` show the sweep hands out what one
whole-range decode does on every window size from one byte, on random bytes for five
instruction sets, on the committed WebAssembly modules and on one planted with a 45-byte
`br_table` (where `wasm-objdump -d` puts it), and that every sweeping pass answers the same at
the default window and at 44 others; with the earlier resume rule (after the last kept
instruction, as the index did) they fail on their own assertions.

### Where a code sweep resumes after bytes that do not decode (2026-10-24)

`Arch::decode_range`, the sweep every section-wide pass reads, stepped one byte past an
undecodable instruction on every instruction set, and two when a run began on one. Each
instruction set now states the step (`Arch::resync_step`): one byte on x86, a word on AArch64
and A32, on Thumb the width the first halfword states. Reference: `llvm-objdump` 23.1.1 (rung
3), `-d -z`, with `--mattr=+vfp3,+neon` for ARMv7 (an oracle without the extension prints
VFP as data); the n0xis side is `crates/n0xis-frontend/examples/sweep_listing.rs`, one
`decode_range` over each code range, joined by address. Before: a release build of `d3ed019`;
after: the same with the change.

**Planted bytes, every instruction set** (`crates/n0xis-arch/tests/a_sweep_resynchronizes_where_the_isa_says.rs`,
rung 1 with `llvm-objdump`'s listing of the same bytes quoted beside each case): undecodable
bytes at the start of the range, twice in a row and after good instructions. The old default
fails five of the seven tests on their own assertions; a flat two-byte Thumb step fails two.

| Input | Instructions where none can begin, before → after | Inside a real instruction | Real instructions lost | Direct calls found (of `llvm-objdump`'s) |
| --- | --- | --- | --- | --- |
| 277 AArch64 shared objects, `/usr/aarch64-linux-gnu` (889 235 instructions) | 0 → 0 | 0 → 0 | 0 → 0 | not counted |
| AArch64 `.so`, gcc 16, the oracle sources and a SHA-256 constant table in `.text` | 41 → 0 | 1 → 0 | 2 → 0 | not counted |
| the same, stripped (no mapping symbols, so `llvm-objdump` decodes the table too) | 41 → 0 | 15 → 0 | 26 → 1 | not counted |
| A32 `.so`, clang 23 `-O2`, the oracle sources with their literal pools | 329 → 0 | 311 → 0 | 320 → 25 | 17 of 22 and 1 made up → 22 of 22 |
| Thumb `.so`, the same, `--arch thumb` (`.text` only; its `.plt` is A32) | 455 → 0 | 458 → 0 | 329 → 23 | 20 of 22 → 22 of 22 (and one pool word read as `bl.w` in both) |

Every instruction the change removed from these listings (41, 41, 329 and 459) is one
`llvm-objdump` does not list. Of the ones it added (28, 28, 309, 306), the ones it does not
list as instructions are data words decoded as code at their own aligned address: 26 in the
AArch64 table, 3 words of the stripped copy's table that `llvm-objdump` rejects, 14 in A32
literal pools. The instructions still lost are VFP and `dmb` in A32 and Thumb (the
ARMv7 decoder does not decode them) and on the stripped AArch64 copy one table word that
`llvm-objdump` reads as `umulh x7, x21, x28` with its should-be-one `Ra` field not all ones,
which n0xis rejects. The 17 Thumb instructions still at addresses `llvm-objdump` lists none at
are halfwords inside literal-pool words. With a flat two-byte Thumb step, 23 instructions would
be listed inside real 32-bit ones, one per VFP instruction the decoder rejects (`vldr d0, [r0,
#8]`, `ed90 0b02`, read on as `lsrs`). `function discover` finds 5 → 6 functions on each ARMv7
build; the new one is `emu_h_lvl1` in `.symtab`, called by a `bl` the old sweep lost; on the
AArch64 builds it is unchanged (136).

**x86 did not change where it was right.** The 495 images of the format-seam corpus, recorded
with both builds by `private/seam-2026-10/record.py` (`function discover`, `xref to` on two
functions, and the rest of its commands): 0 differences. The sweep listing itself, on the 478
x86 images of that corpus with at most 16 MiB of code (four larger ones not listed): the same
on 476; on two 64-bit DLLs (Wine's `msvcr100.dll` and `msvcr71.dll`) 80 and 69 instructions
gone, none an instruction `llvm-objdump` lists, and 86 and 83 new, all of them ones it lists.
Planted, the one-byte x86 step agrees with `llvm-objdump` after single-byte invalids (`06` in
64-bit mode) and not after longer ones, where `llvm-objdump` steps past the bytes its own
decoder read (two for `8d c0` and for `fe ff`): the planted i386 case lists `inc ebx` one
byte into `fe ff c3` where `llvm-objdump` lists `ret` at its third byte. That length is the
decoder's, not the architecture's (iced gives `0f 0a 90` a length of three, LLVM two).

### `why`: where each fact about an address came from (2026-10-23)

`n0x why --addr <va>` (docs/design/WHY.md, step 1) names, for the function an address is in,
every source of its start, the source of its end and the layer that named it. Each source is
recorded where its rule fires and read back, so what is measured is whether those records
are true and whether recording them moved any other answer.

**Planted (rung 1).** `crates/n0xis-core/src/discover.rs`: six images, each built so that one
rule alone can produce the start asked about — the unwind table (`a_start_only_the_unwind_table_…`),
a call (`…_a_call_reaches_…`, citing the call's address), a prologue, the instruction after a
declared end, the gap sweep — and one start that a PE export, a PDB, an FDE, a call and a
prologue all find; each answer asserted whole. Calibrated by six mutations of discovery, each
failing its test on its own assertion: keeping only the first source of a start (the
behaviour before this change), labelling the gap sweep as after-a-declared-end and the reverse,
labelling the prologue scan as the gap sweep, labelling a declaration as a prologue, citing the
last call instead of the first. The name layers: a rename planted in a project is reported as
`user` with the image's own name beside it in `also` (`why_names_the_tables_it_read.rs`); the
composition's tie rule is held by `static_names.rs`, failing when a later layer wins a tie.
`why_on_committed_images.rs` pins the whole answer on `tests/fixtures/native_pe.dll` and the
module `core.wasm`, whose tables are quoted in the test, and runs in CI.

**Against the image's own tables (rung 3).** `crates/n0xis-cli/tests/why_names_the_tables_it_read.rs`
(feature `oracle`) asks `why` about every function `function discover` lists and checks every
claim that a table states something against a reader that is not this tool: an `.eh_frame`
start or end against GNU `objdump --dwarf=frames`, a `.pdata` start or end against
`llvm-readobj --unwind`, an export against `llvm-readobj --coff-exports` and `--file-headers`,
a `.symtab` or `.dynsym` name and an `st_size` end against `llvm-nm` and `llvm-nm -D`, a module's
body, export and name against `wasm-objdump -d` and `-x`. 80 images: `oracle/sysv.c` built by
gcc, by x86_64 and by i686 mingw (with their C runtimes), `/usr/lib/libz.so.1`, `core.wasm`,
and 75 of the seam corpus chosen across its kinds (10 fixtures, 18 `/usr/lib`, 8 `/usr/bin`, 7
`/usr/lib32`, 11 Wine PE32+, 11 Wine PE32, 10 WebAssembly modules from outside this
repository; the list is `N0XIS_WHY_IMAGES` of that run). 107 885 functions.

| Claim | Checked | Wrong |
| --- | --- | --- |
| start: `unwind` `eh_frame` | 90 858 | 0 |
| start: `unwind` `pdata` | 6 998 | 0 |
| start: `export` | 4 083 | 0 |
| start: `body` | 570 | 0 |
| end: `unwind` `eh_frame` | 67 510 | 0 |
| end: `unwind` `pdata` | 6 998 | 0 |
| end: `symbol_size` `st_size` | 23 348 | 0 |
| end: `body` | 570 | 0 |
| name: `image` `dynamic` (`.dynsym`) | 23 253 | 0 |
| name: `image` `static` (`.symtab`) | 104 | 0 |
| name: `image` `exports` | 4 111 | 0 |
| name: `image` `name_section` | 103 | 0 |
| **all table claims** | **228 506** | **0** |

The empty-success sweep on the same run: every one of the 107 885 listed functions has a
non-empty `start_sources`, is the function `why` answers for its own start, and has the end
the list gives it (or `not_stated` where the list gives none). One image, a resource-only DLL
with no code section, has no list: `function discover` and `why` both refuse it `no-range`.
The checker was calibrated on its own target: labelling `.eh_frame` functions as `.pdata` gave
406 wrong claims on the first four images, labelling every image name `.dynsym` gave 24,
emptying `start_sources` 376, shifting a body's function index by one 5 on `core.wasm`.

Twice the measurement was wrong and the engine right, both in the checker's reading of
`wasm-objdump`: it read a module's exports only from a PE (28 "wrong" export names), and it
read `size=332 <J>` as no size (262 "wrong" bodies). Both were fixed in the checker, and the
claims they had flagged are among the 0 above.

**Not checked.** The rule sources — `after_declared_end` (97 210 starts on that run),
`prologue` (70 145), `call_target` (14 724), `gap_sweep` (7 012) — have no table to check
against; they are held only by the planted images. A `call_target`'s `from` could be checked
against `objdump -d` and is not yet. Names from `stub` (938), `pdb`, `managed`, `rtti`,
`flirt` and `fallback` (79 376), and ends from a PDB length, were not checked here; no image in
the run had a PDB. `why` on a live process, a snapshot or a remote one was not run.

**No other answer moved.** The seam corpus's recording (its recorder and its 495 images are
kept outside the repository, so this cannot be re-run from a clone: the image-layer facts of
`crates/n0xis-frontend/examples/image_facts.rs` and `profile`, `module list`, `function discover`, `function discover --pdata`,
`ir manifest`, `disasm`, `decomp pseudo`, `xref to`, `strings`, `rtti scan`, `symbols add`) of
495 images, and of 30 WebAssembly modules, with a release build of `cfd815c` and with this
change: 0 differences on 525 images (816 014 listed functions). That is the tool compared with
itself (rung 5): it says nothing moved, not that anything is right. The same comparison of
this change against the corpus's older baseline finds 3 233 differences on 306 images, so a
zero here is not a comparison that cannot see. The function list kept on disk changed format
(each start carries its sources): it is kept under a new key, and a list in the earlier format
does not load (`a_list_kept_in_the_earlier_format_does_not_load`).

**A trap the scout read in the code, refuted.** `Ctx::functions` can hold one start twice, with
an extent (an FDE, a `.pdata` entry) and without (an export), and the end of a control-flow
graph is looked up there by a binary search, which the standard library documents as free to
return either match; returning the one without an extent would hand a stated function to the
end heuristic. On a planted PE32 (i686 mingw: FDEs and exports, no `.pdata`, so no symbol length
answers first), `ir build` gave each exported function its FDE end. The current search returns
the last equal entry, which in a list sorted by `(start, end)` is the extent, and
`a_start_declared_with_and_without_an_extent_keeps_the_extent` now holds that on all 144
placements of the pair among 0 to 11 functions before and after it; it fails when the lookup
takes the first entry of a start. Not a wrong answer today, so nothing was changed in the
lookup. Not measured: two different extents stated for one start, where the function list takes
the smaller end and the lookup the larger.

### `contradictions`: where two sources the engine reads disagree (2026-10-24)

`n0x contradictions` (docs/design/WHY.md §6, item 1) lists every place two sources disagree:
a start with different stated ends, two stated extents that overlap, two sources naming one
address with no name in common, and the image reader's own contradictions. What is measured
is whether each reported value is what its table holds, whether every disagreement the
tables hold is reported, and whether carrying every source moved any other answer.

**Planted (rung 1).** `crates/n0xis-cli/tests/contradictions_on_planted_images.rs`, in CI, on
committed images whose tables are recorded beside them (`tests/fixtures/contradictions/`,
`plant.sh` builds them and records `objdump --dwarf=frames`, `readelf -sW` and `wasm-objdump
-x`): an ELF written in assembly with a hand-written `.eh_frame` — `ends_twice` of 8 bytes by
`.size` and 16 by its FDE, `outer`'s FDE of 16 bytes reaching past `inner`'s start, one
address `.symtab` names `symtab_name` and `.dynsym` `exported_name` — reported as exactly one
`end`, one `overlap` and one `name`; an ELF whose own tables state three ends for one start
(two FDEs of 16 and 8 bytes, two symbols of 16 and 12); a module whose name section and export
name function 1 apart and whose data segment lies past its one-page memory; `n0xis-pdb`'s
image with `main`'s `.pdata` end moved 4 bytes in, against its PDB's 139 bytes (and with the
PDB taken away, nothing to disagree with); the contested-slot ELF of `n0xis-sources`, whose
reader reports two relocations at one slot; two renames, reported as overrides of the layer
they replace and never as name contradictions; a target with no image file, on which every
kind says it was not checked. Each answer asserted whole, so an empty list fails. Calibrated
by seven mutations, each failing on its own assertion: the image layer handing over only the
first name of an address (the ELF and module name assertions, and the overrides' kind list),
the size layers left out of the ends (the ELF and PE end assertions), no overlaps, no image
findings, the user's names compared as a source (the overrides' kind list), every length one
byte long (every end assertion, and the checker below), and only the first stated length of an
address kept (the three-ends assertion). One more mutation, turning the user's arm into a no-op
arm, changed nothing, because the arm already did nothing: a mutation that missed, redone.
`no_silent_empty_answer.rs` holds the answer non-empty on the committed module `shapes.wasm`
(a data segment of memory 1 placed at 4294967300).

**Against the tables (rung 3).** `crates/n0xis-cli/tests/contradictions_are_what_the_tables_say.rs`
(feature `oracle`) reads each image's tables with tools that are not this one, works out every
disagreement among them, and requires the answer to be exactly that set: FDE ranges from GNU
`objdump --dwarf=frames`, `RUNTIME_FUNCTION`s from `llvm-readobj --unwind`, `STT_FUNC` sizes
and both tables' names from `readelf -sW`, a PDB's procedure lengths from `llvm-pdbutil dump
--symbols` with `llvm-readobj --sections`, a module's bodies, names, exports, memories and data
segments from `wasm-objdump -d` and `-x`, slots from `llvm-readobj -r`. Which tables state
extents is the engine's rule restated (`.pdata` on a PE that has one, else `.eh_frame`), and the
answer's own list of sources must equal the tables that are not empty.

535 images: the seam corpus's 495 images and 30 WebAssembly modules, `oracle/sysv.c` built by
gcc and by both mingw targets, `n0xis-pdb`'s image with its PDB as built and with the end
moved, `/usr/lib/libz.so.1`, and the four planted images. The tables held 785 789 distinct
stated extents and 203 296 named addresses; every disagreement among them is in the answer,
and every one in the answer is among them:

| Kind | Reported and in the tables | Of them, outside the planted images | Wrong | Missed |
| --- | --- | --- | --- | --- |
| `end` | 8 | 5 | 0 | 0 |
| `overlap` | 6 | 5 | 0 | 0 |
| `name` | 24 | 22 | 0 | 0 |
| `image` | 3 | 1 | 0 | 0 |

The real ones: a C library, as a 64-bit and a 32-bit build, where five functions' symbol sizes
reach past the end of their FDE — in four of them into one or two further FDEs that start
inside the symbol (the five `overlap`s), in the fifth over bytes no FDE covers; a module from
outside this repository whose 21 exported functions are exported under short names the name
section names otherwise (one function under sixteen); `eh.wasm`, one function its name section
calls `several` and its export `run`; `shapes.wasm`, its planted data segment past its memory.

One image fails the checker, and the answer is not what is wrong: on a big-endian AArch64
shared object `objdump --dwarf=frames` lists FDEs and the engine reads none — its `.eh_frame`
reader reads every length little-endian (`crates/n0xis-core/src/eh.rs`), so on a big-endian
image it finds no FDE and says nothing. The answer's sources there are `st_size` alone, which
is what the engine read; the tables show the FDEs agree with the sizes on that image, so no
contradiction was missed, but every big-endian image's unwind table is unread, by
`function discover` too. Recorded, not fixed here; fixed since, and the checker passes on that
image (below).

**Not checked.** A PE's names: on a PE the engine's name sources are its exports and a PDB
beside it, and no image here has both (the PDB fixture exports nothing), so `name` is
`not_checked` on all 153 PE images of the corpus — the answer says so; a PDB's names against
an export were never compared. Names recovered from RTTI and from signatures, a managed
index's, and the user's names against a layer's beyond the planted overrides: no image in the
run carried them (each run had a fresh project). One module (`gc.wasm`) `wasm-objdump` cannot
read; its answer was not checked. Image findings other than a data segment past its memory and
a slot two relocations bind (an export or the start function naming no function, an element
segment past its table) have no reader here. `contradictions` on a live process, a snapshot or
a remote one was not run beyond the planted bytes target.

**No other answer moved.** The seam corpus's recording (as for `why` above: kept outside the
repository) of 495 images and 30 modules, with a release build of `3a8c65a` and with this
change: 0 differences on 525 images; the comparison was shown to see a planted one-name
change. `why --addr` at every planned address of the same 525 images (the entry point and up to
three functions each, 1 681 answers): 0 differences between the two builds, and the comparison
shown to see a build without `why`. Both are the tool compared with itself (rung 5): they say
nothing moved, not that anything is right.


### Big-endian `.eh_frame` (2026-10-24)

The `.eh_frame` reader (`crates/n0xis-core/src/eh.rs`) read every length, CIE pointer and
pointer field little-endian; on a big-endian image the first length came out past the end of
the section and no FDE was read, so every answer that reads the table (`function eh`,
`function discover`, `why`, `contradictions`, a CFG's declared extents) stated nothing from it,
`ok: true`. It now reads the order the image's header states (`ImageSource::byte_order`), an
argument the reader cannot be called without.

**Planted (rung 1).** `crates/n0xis-cli/tests/big_endian_eh_frame_is_read.rs`, in CI, on
`tests/fixtures/big_endian_eh/`: one assembly file built for `aarch64_be` and for `aarch64`
(clang 23.1.1, ld.lld), three FDEs, one with a hand-written LSDA whose call-site table is
`udata4` (fixed-size fields in the image's order) with one entry landing at a labelled pad and
one with none; `plant.sh` records `readelf --debug-dump=frames`, `readelf -sW` and the header's
data encoding. `function eh` on both builds must list exactly the three FDE ranges `readelf`
lists and the one protected range at the labels' addresses; `function discover` must list each
FDE's function with the FDE's end, and `why` name `.eh_frame` among its start's sources.
`llvm-dwarfdump --eh-frame` lists the same three FDEs. Calibrated by four mutations, each
failing on its own assertion: the reader ignoring the order (the extents assertion and the
discover assertion; and in `eh.rs`'s unit tests, the big-endian twin of the unit fixture and
the `sdata4` cursor case); the caller passing little-endian whatever the image says (the same
two); the LSDA alone read little-endian, which gives landing pads at `0x180103d0` for `0x103e8`
— a wrong answer, not an empty one (the landing-pad assertion). The base build answers
`count: 0` on the big-endian image and finds `guarded` alone, by its prologue.

**Real images (rung 3).** Against `readelf --debug-dump=frames`, before and after, with a
release build of `41ab220` and of this change (each image in a fresh project):

| Image | FDEs | `function eh` | `function discover`: FDE functions listed with the FDE's end |
| --- | --- | --- | --- |
| seam corpus `vt-aarch64_be-linux-gnu.so` (and its stripped copy) | 14 | 0 → 14, exact | 2 → 14 (both) |
| `oracle/sysv.c`, `-O2 -fasynchronous-unwind-tables -shared -nostdlib` (and stripped) | 10 | 0 → 10, exact | 0 → 10 (both) |
| `oracle/cxx_this.cpp`, `-O2 -fexceptions` | 11 | 0 → 11, exact | 0 → 11 |
| a `try`/`catch` file, `-O2 -fexceptions` (and stripped) | 4 | 0 → 4, exact; regions 0 → 5 | 3 → 4 (stripped: 2 with the end → 4) |

The little-endian build of each of the last three gives the same counts with either build, and
the same `function eh` answer as the big-endian one, protected ranges included (the
compiler's call-site tables are `uleb128`; their landing pads are checked only against the
little-endian twin, which is the tool compared with itself — no tool here decodes an LSDA).
`contradictions_are_what_the_tables_say.rs` (feature `oracle`, the images given in
`N0XIS_CONTRADICTION_IMAGES`) passes on the corpus image, its stripped copy, the `try`/`catch`
build and its stripped copy, the `sysv` and `cxx_this` builds and the planted image, 0 wrong
(on the corpus image it failed before, as recorded above); `why_names_the_tables_it_read.rs`
(`N0XIS_WHY_IMAGES`) passes on the same seven and the stripped `sysv`, 0 wrong of 419 claims.

**No little-endian answer moved.** The seam corpus recorded with both builds (`record.py`: the
image facts and 12 commands per image): 1 of 495 images differs, the big-endian one (42
differences: `function discover` and `ir manifest` 2 → 14 functions, the image facts' stated
functions 0 → 14), and 0 of 30 modules. `contradictions --limit 0` on the same 525: 1 differs,
the big-endian one, whose `end` and `overlap` kinds now list `.eh_frame` among their sources
(still no contradiction). `why --addr` at the 1 681 planned addresses: 3 differ, the three on
the big-endian image, which said no listed function contained them and now name the function
and the FDE. Those are the tool compared with itself (rung 5): they say nothing else moved, not
that anything is right; the big-endian difference is what shows the comparisons can see one.

### How often each rule is right (2026-10-25)

docs/design/WHY.md §6 items 2 and 3: each source of a function start, end and name measured on
its own against programs whose answer is known, and the direction's own test — whether a wrong
answer is predicted by its source's category (a declaration of the image against a heuristic
rule). The instrument is `oracle/rule-accuracy/` (its README says how to run it again); every
number below is generated by it (`results/doc-tables.md` of the run), none copied by hand.

**The engine measured.** The installed build of main `a85a927` (it prints `0.3.5`),
`~/.local/opt/n0xis-wasm-preview/n0xis`, sha256
`e8a9c8f01ca5e7145af11d659b9f9d79beac96f2442fb680dbf1bd02759d334e`, recorded in all 276
results. Asked through the CLI as a user asks it: `function discover --file`, then `why --file
--addr` at every listed start, each image in a fresh project directory of its own.

**The truth (rung 1, with two rung-3 tiers named as such).** Every program built here with
`-g`; the unstripped build's DWARF, read by `llvm-dwarfdump` 23.1.1, is the answer: each
`DW_TAG_subprogram` with code is a function, its entry the start, the range holding the entry
its extent; the other ranges of a split function (gcc's `.cold` parts) are fragments, not
starts. Code no DWARF covers is taken from `readelf -sW` (`.symtab` FUNC symbols: the C
runtime's and libgcc's objects, "CRT" below) and from GNU objdump's PLT labels (`puts@plt`).
Names: `.symtab`/`.dynsym`, compared after `c++filt` and after `llvm-cxxfilt`. A listed start
is true (a truth function's entry), a fragment, a PLT header (`plt0`, the resolver trampoline
no table calls a function), or wrong: interior (inside a truth function or fragment) or outside
(in no truth function: padding, or a CRT function whose `st_size` is 0, which gives the truth
no extent to say "inside").

**The variants.** (a) the `-g` build as built; (b) the same file after `strip --strip-all`;
(c) built with `-fno-asynchronous-unwind-tables -fno-unwind-tables`, stripped; (d), beyond the
spec, C++ only: (c) with `-fno-exceptions` as well — in C++ the flags of (c) leave an FDE on
every function that may unwind, so (c) of a C++ program is (b) again (the tables give (c) for C
and for C++ apart). Before a truth is used for a stripped file, every executable section of
the two must have the same name, address, size and bytes: 192 of 192 did, so no variant was
refused. Each configuration was also built without `-g`: 166 of 192 pairs have the same code,
26 differ, all clang (17 configurations, on all three machines), so on those the file measured
is the `-g` build's code, not what clang emits without `-g`.

**Corpus.** Offline, sources already on the machine: the repo's `oracle/` programs as one C
shared object (`emu*.c`, `locals.c`, `sysv.c`, `typeflow.c`, `types.c`, `arm64.c`, plus
`emu_fp.c` on x86, `emu_simd.c` on x86-64, `i386.c` on i686) and `cxx_this.cpp`; Lua 5.4.7
(crate `lua-src` 547.0.0) and zstd 1.5.7 `lib/` without assembly or legacy formats (crate
`zstd-sys` 2.1.0+zstd.1.5.7) as shared objects; SQLite 3.53.2 (crate `libsqlite3-sys` 0.38.2)
as a shared object and libFuzzer (crate `libfuzzer-sys` 0.4.13, C++17, with a one-line target)
as a PIE executable, x86-64 only. Compilers: gcc 16.2.1 (x86-64, and i686 with `-m32`),
`aarch64-linux-gnu-gcc` 16.1.0, clang 23.1.1 (GNU ld 2.47 on x86; ld.lld 23.1.1 with the cross
sysroot on AArch64); `-O0`, `-O2`, `-Os`. 84 configurations, 276 measured images.

*Corpus (truth functions summed over the compiler x level builds of each).*

| arch | program | builds | DWARF functions | CRT functions | PLT entries |
|---|---|---|---|---|---|
| aarch64 | lua | 6 | 4915 | 42 | 1300 |
| aarch64 | oracle_c | 6 | 756 | 42 | 55 |
| aarch64 | oracle_cxx | 6 | 110 | 42 | 82 |
| aarch64 | zstd | 6 | 5624 | 54 | 1234 |
| i686 | lua | 6 | 4916 | 89 | 1296 |
| i686 | oracle_c | 6 | 996 | 81 | 37 |
| i686 | oracle_cxx | 6 | 110 | 51 | 69 |
| i686 | zstd | 6 | 5709 | 85 | 1219 |
| x86_64 | libfuzzer | 6 | 7908 | 70 | 790 |
| x86_64 | lua | 6 | 4915 | 36 | 1299 |
| x86_64 | oracle_c | 6 | 1056 | 39 | 40 |
| x86_64 | oracle_cxx | 6 | 110 | 36 | 70 |
| x86_64 | sqlite | 6 | 11912 | 70 | 884 |
| x86_64 | zstd | 6 | 5735 | 48 | 1220 |
| all | | 84 | 54772 | 785 | 9595 |

**Starts.** (b) lists exactly what (a) lists: no start comes from a symbol (WHY.md §5), so
stripping moves no start, only names and the source of ends.

*Starts, per variant.*

| variant | runs | listed | true | wrong (interior / outside) | fragment | plt0 | precision | DWARF fns found | CRT fns found | PLT entries found |
|---|---|---|---|---|---|---|---|---|---|---|
| a | 84 | 56846 | 55405 | 1197 (3 / 1194) | 184 | 60 | 97.9% | 54772 / 54772 | 597 / 785 | 36 / 9595 |
| b | 84 | 56846 | 55405 | 1197 (3 / 1194) | 184 | 60 | 97.9% | 54772 / 54772 | 597 / 785 | 36 / 9595 |
| c (C) | 60 | 36586 | 31298 | 5265 (5164 / 101) | 2 | 21 | 85.6% | 30934 / 46534 | 352 / 586 | 12 / 8584 |
| c (C++) | 24 | 8552 | 8391 | 20 (0 / 20) | 123 | 18 | 99.8% | 8238 / 8238 | 147 / 199 | 6 / 1011 |
| d | 24 | 7428 | 7347 | 73 (60 / 13) | 1 | 7 | 99.0% | 7226 / 7956 | 115 / 195 | 6 / 956 |

*Start sources, per variant ((b) is (a): stripping changes no start).*

Precision = true / (true + wrong); a fragment or a PLT header is neither. `alone`: the starts this source alone produced.

| variant | source | produced | true | wrong | fragment | plt0 | precision | alone produced | alone true | alone wrong |
|---|---|---|---|---|---|---|---|---|---|---|
| a | unwind:eh_frame | 55357 | 55113 | 0 | 184 | 60 | 100.0% | 1161 | 1093 | 0 |
| a | after_declared_end | 54949 | 53651 | 1122 | 176 | 0 | 98.0% | 32 | 32 | 0 |
| a | gap_sweep | 1368 | 219 | 1149 | 0 | 0 | 16.0% | 63 | 36 | 27 |
| a | call_target | 33325 | 33325 | 0 | 0 | 0 | 100.0% | 0 | 0 | 0 |
| a | prologue | 13337 | 13289 | 48 | 0 | 0 | 99.6% | 88 | 40 | 48 |
| c (C) | unwind:eh_frame | 185 | 164 | 0 | 0 | 21 | 100.0% | 29 | 8 | 0 |
| c (C) | after_declared_end | 149 | 149 | 0 | 0 | 0 | 100.0% | 15 | 15 | 0 |
| c (C) | gap_sweep | 3437 | 3027 | 408 | 2 | 0 | 88.1% | 1826 | 1416 | 408 |
| c (C) | call_target | 30255 | 26032 | 4223 | 0 | 0 | 86.0% | 22464 | 18241 | 4223 |
| c (C) | prologue | 10520 | 9886 | 634 | 0 | 0 | 94.0% | 4376 | 3742 | 634 |
| c (C++) | unwind:eh_frame | 8432 | 8291 | 0 | 123 | 18 | 100.0% | 68 | 47 | 0 |
| c (C++) | after_declared_end | 8381 | 8259 | 2 | 120 | 0 | 100.0% | 8 | 8 | 0 |
| c (C++) | gap_sweep | 84 | 76 | 8 | 0 | 0 | 90.5% | 18 | 12 | 6 |
| c (C++) | call_target | 7293 | 7293 | 0 | 0 | 0 | 100.0% | 4 | 4 | 0 |
| c (C++) | prologue | 3415 | 3403 | 12 | 0 | 0 | 99.6% | 24 | 12 | 12 |
| d | unwind:eh_frame | 50 | 43 | 0 | 0 | 7 | 100.0% | 12 | 5 | 0 |
| d | after_declared_end | 30 | 30 | 0 | 0 | 0 | 100.0% | 2 | 2 | 0 |
| d | gap_sweep | 3182 | 3173 | 8 | 1 | 0 | 99.7% | 125 | 116 | 8 |
| d | call_target | 7017 | 7009 | 8 | 0 | 0 | 99.9% | 2893 | 2885 | 8 |
| d | prologue | 3371 | 3314 | 57 | 0 | 0 | 98.3% | 163 | 106 | 57 |

The spec's table, per variant x compiler x level (every source that fired; `export`, `symbol`,
`pdb`, `body` and `stub` produced no start on any image, so they have no rate here):

*Per variant x compiler x level: true / produced per start source.*

| variant | cc | -O | unwind:eh_frame | after_declared_end | gap_sweep | call_target | prologue | wrong starts | DWARF functions found |
|---|---|---|---|---|---|---|---|---|---|
| a | clang | O0 | 13719 / 13729 | 13711 / 13711 | 36 / 40 | 10275 / 10275 | 8456 / 8464 | 12 | 13684 / 13684 |
| a | clang | O2 | 6138 / 6148 | 6073 / 6073 | 36 / 40 | 2600 / 2600 | 466 / 474 | 12 | 6103 / 6103 |
| a | clang | Os | 6863 / 6873 | 6797 / 6797 | 36 / 40 | 3283 / 3283 | 514 / 522 | 12 | 6827 / 6827 |
| a | gcc | O0 | 14565 / 14575 | 14547 / 14547 | 37 / 42 | 10576 / 10576 | 1976 / 1984 | 13 | 14514 / 14514 |
| a | gcc | O2 | 6398 / 6592 | 5191 / 6489 | 37 / 1164 | 2801 / 2801 | 1239 / 1247 | 1135 | 6306 / 6306 |
| a | gcc | Os | 7430 / 7440 | 7332 / 7332 | 37 / 42 | 3790 / 3790 | 638 / 646 | 13 | 7338 / 7338 |
| c (C) | clang | O0 | 24 / 27 | 21 / 21 | 2066 / 2069 | 7449 / 9490 | 5509 / 5515 | 2050 | 9671 / 10688 |
| c (C) | clang | O2 | 24 / 27 | 20 / 20 | 555 / 674 | 2267 / 3290 | 452 / 526 | 1216 | 2977 / 5626 |
| c (C) | clang | Os | 25 / 28 | 21 / 21 | 94 / 148 | 2778 / 3937 | 505 / 616 | 1324 | 3089 / 6167 |
| c (C) | gcc | O0 | 30 / 34 | 30 / 30 | 16 / 112 | 7749 / 7749 | 1662 / 1694 | 128 | 8331 / 11519 |
| c (C) | gcc | O2 | 30 / 34 | 27 / 27 | 231 / 288 | 2460 / 2460 | 1131 / 1379 | 303 | 3194 / 5809 |
| c (C) | gcc | Os | 31 / 35 | 30 / 30 | 65 / 146 | 3329 / 3329 | 627 / 790 | 244 | 3672 / 6725 |
| c (C++) | clang | O0 | 3002 / 3005 | 3001 / 3001 | 15 / 16 | 2826 / 2826 | 2947 / 2949 | 3 | 2996 / 2996 |
| c (C++) | clang | O2 | 482 / 485 | 478 / 478 | 14 / 15 | 333 / 333 | 14 / 16 | 3 | 477 / 477 |
| c (C++) | clang | Os | 665 / 668 | 661 / 661 | 14 / 15 | 505 / 505 | 9 / 11 | 3 | 660 / 660 |
| c (C++) | gcc | O0 | 3006 / 3009 | 3003 / 3003 | 11 / 12 | 2827 / 2827 | 314 / 316 | 3 | 2995 / 2995 |
| c (C++) | gcc | O2 | 510 / 636 | 499 / 621 | 11 / 14 | 341 / 341 | 108 / 110 | 5 | 497 / 497 |
| c (C++) | gcc | Os | 626 / 629 | 617 / 617 | 11 / 12 | 461 / 461 | 11 / 13 | 3 | 613 / 613 |
| d | clang | O0 | 7 / 8 | 5 / 5 | 1904 / 1904 | 2751 / 2757 | 2869 / 2871 | 8 | 2862 / 2922 |
| d | clang | O2 | 7 / 8 | 5 / 5 | 60 / 60 | 299 / 300 | 14 / 16 | 3 | 314 / 445 |
| d | clang | Os | 7 / 8 | 5 / 5 | 38 / 38 | 457 / 458 | 10 / 22 | 13 | 461 / 613 |
| d | gcc | O0 | 8 / 10 | 7 / 7 | 1007 / 1015 | 2751 / 2751 | 310 / 316 | 14 | 2785 / 2920 |
| d | gcc | O2 | 7 / 8 | 4 / 4 | 85 / 86 | 310 / 310 | 100 / 122 | 22 | 353 / 467 |
| d | gcc | Os | 7 / 8 | 4 / 4 | 79 / 79 | 441 / 441 | 11 / 24 | 13 | 451 / 589 |

*Starts, per variant x arch.*

| variant arch | runs | listed | true | wrong (interior / outside) | fragment | plt0 | precision | DWARF fns found | CRT fns found | PLT entries found |
|---|---|---|---|---|---|---|---|---|---|---|
| a aarch64 | 24 | 11591 | 11540 | 51 (3 / 48) | 0 | 0 | 99.6% | 11405 / 11405 | 135 / 180 | 0 / 2671 |
| a i686 | 24 | 13114 | 11930 | 1146 (0 / 1146) | 14 | 24 | 91.2% | 11731 / 11731 | 187 / 306 | 12 / 2621 |
| a x86_64 | 36 | 32141 | 31935 | 0 (0 / 0) | 170 | 36 | 100.0% | 31636 / 31636 | 275 / 299 | 24 / 4303 |
| c (C) aarch64 | 18 | 8154 | 7736 | 418 (382 / 36) | 0 | 0 | 94.9% | 7651 / 11295 | 85 / 138 | 0 / 2589 |
| c (C) i686 | 18 | 12048 | 7408 | 4620 (4555 / 65) | 2 | 18 | 61.6% | 7243 / 11621 | 153 / 255 | 12 / 2552 |
| c (C) x86_64 | 24 | 16384 | 16154 | 227 (227 / 0) | 0 | 3 | 98.6% | 16040 / 23618 | 114 / 193 | 0 / 3443 |
| c (C++) aarch64 | 6 | 152 | 140 | 12 (0 / 12) | 0 | 0 | 92.1% | 110 / 110 | 30 / 42 | 0 / 82 |
| c (C++) i686 | 6 | 146 | 132 | 8 (0 / 8) | 0 | 6 | 94.3% | 110 / 110 | 22 / 51 | 0 / 69 |
| c (C++) x86_64 | 12 | 8254 | 8119 | 0 (0 / 0) | 123 | 12 | 100.0% | 8018 / 8018 | 95 / 106 | 6 / 860 |
| d aarch64 | 6 | 44 | 30 | 14 (2 / 12) | 0 | 0 | 68.2% | 6 / 110 | 24 / 42 | 0 / 79 |
| d i686 | 6 | 41 | 31 | 9 (8 / 1) | 0 | 1 | 77.5% | 11 / 110 | 20 / 50 | 0 / 67 |
| d x86_64 | 12 | 7343 | 7286 | 50 (50 / 0) | 1 | 6 | 99.3% | 7209 / 7736 | 71 / 103 | 6 / 810 |

**Ends,** for true starts and fragments, against the truth extent. `not_stated` is the end
`why` gives where nothing states one: the control-flow graph's.

*Ends, per variant.*

| variant | start class / end source | exact | short | long | between | no end | no truth end |
|---|---|---|---|---|---|---|---|
| a | fragment: symbol_size:st_size | 184 | 0 | 0 | 0 | 0 | 0 |
| a | true: not_stated | 0 | 0 | 0 | 0 | 0 | 265 |
| a | true: symbol_size:st_size | 54972 | 0 | 0 | 0 | 0 | 0 |
| a | true: unwind:eh_frame | 22 | 0 | 14 | 0 | 0 | 132 |
| b | fragment: unwind:eh_frame | 184 | 0 | 0 | 0 | 0 | 0 |
| b | true: not_stated | 27 | 0 | 0 | 0 | 0 | 265 |
| b | true: symbol_size:st_size | 14566 | 0 | 0 | 0 | 0 | 0 |
| b | true: unwind:eh_frame | 40401 | 0 | 14 | 0 | 0 | 132 |
| c (C) | fragment: not_stated | 0 | 0 | 2 | 0 | 0 | 0 |
| c (C) | true: not_stated | 25014 | 761 | 1828 | 0 | 0 | 183 |
| c (C) | true: symbol_size:st_size | 3348 | 0 | 0 | 0 | 0 | 0 |
| c (C) | true: unwind:eh_frame | 86 | 0 | 6 | 0 | 0 | 72 |
| c (C++) | fragment: unwind:eh_frame | 123 | 0 | 0 | 0 | 0 | 0 |
| c (C++) | true: not_stated | 20 | 0 | 0 | 0 | 0 | 80 |
| c (C++) | true: symbol_size:st_size | 550 | 0 | 0 | 0 | 0 | 0 |
| c (C++) | true: unwind:eh_frame | 7713 | 0 | 2 | 0 | 0 | 26 |
| d | fragment: not_stated | 1 | 0 | 0 | 0 | 0 | 0 |
| d | true: not_stated | 6939 | 24 | 41 | 0 | 0 | 67 |
| d | true: symbol_size:st_size | 233 | 0 | 0 | 0 | 0 | 0 |
| d | true: unwind:eh_frame | 17 | 0 | 2 | 0 | 0 | 24 |

**Names,** per layer. `exact`: the table's text or a demangler's reading of it. `spelled`: the
same identity in another spelling — an undemangled name with `.` as `_` (`luaD_throw_cold`), a
stub named after its import without `@plt`, a demangled name that differs from a demangler's
reading only in how an integer template argument is written (`(unsigned long)0` for `0ul`) or
in `> >`. `fallback_where_named`: `sub_…` where the table has a name, an absence, not a wrong name.

*Names, per variant.*

| variant | layer | exact | spelled | wrong | named_where_unnamed | fallback_where_named | fallback_unnamed |
|---|---|---|---|---|---|---|---|
| a | fallback | 0 | 0 | 0 | 0 | 24 | 1257 |
| a | image:static | 53802 | 1424 | 327 | 0 | 0 | 0 |
| a | stub | 0 | 12 | 0 | 0 | 0 | 0 |
| b | fallback | 0 | 0 | 0 | 0 | 41011 | 1257 |
| b | image:dynamic | 14566 | 0 | 0 | 0 | 0 | 0 |
| b | stub | 0 | 12 | 0 | 0 | 0 | 0 |
| c (C) | fallback | 0 | 0 | 0 | 0 | 27952 | 5286 |
| c (C) | image:dynamic | 3348 | 0 | 0 | 0 | 0 | 0 |
| c (C++) | fallback | 0 | 0 | 0 | 0 | 7958 | 38 |
| c (C++) | image:dynamic | 550 | 0 | 0 | 0 | 0 | 0 |
| c (C++) | stub | 0 | 6 | 0 | 0 | 0 | 0 |
| d | fallback | 0 | 0 | 0 | 0 | 7109 | 80 |
| d | image:dynamic | 233 | 0 | 0 | 0 | 0 | 0 |
| d | stub | 0 | 6 | 0 | 0 | 0 | 0 |

**The direction.** Of the wrong starts, how many carry only heuristic sources and how many any
declared one, beside each kind's base; of the wrong ends, `not_stated` against a declared end.

*The direction, per variant (strict: a wrong start is interior or outside).*

| variant | wrong starts: heuristic only | wrong starts: any declared | heuristic-only starts wrong | declared starts wrong | wrong ends: heuristic (`not_stated`) | wrong ends: declared | heuristic ends wrong | declared ends wrong |
|---|---|---|---|---|---|---|---|---|
| a | 1197 | 0 | 1197 / 1489 (80.4%) | 0 / 55357 (0.0%) | 0 | 14 | 0 / 0 (-) | 14 / 55008 (0.0%) |
| b | 1197 | 0 | 1197 / 1489 (80.4%) | 0 / 55357 (0.0%) | 0 | 14 | 0 / 27 (0.0%) | 14 / 54981 (0.0%) |
| c (C) | 5265 | 0 | 5265 / 36401 (14.5%) | 0 / 185 (0.0%) | 2589 | 6 | 2589 / 27603 (9.4%) | 6 / 3440 (0.2%) |
| c (C++) | 20 | 0 | 20 / 120 (16.7%) | 0 / 8432 (0.0%) | 0 | 2 | 0 / 20 (0.0%) | 2 / 8265 (0.0%) |
| d | 73 | 0 | 73 / 7378 (1.0%) | 0 / 50 (0.0%) | 65 | 2 | 65 / 7004 (0.9%) | 2 / 252 (0.8%) |

*The direction, per variant x arch.*

| variant arch | wrong starts: heuristic only | wrong starts: any declared | heuristic-only starts wrong | declared starts wrong | wrong ends: heuristic (`not_stated`) | wrong ends: declared | heuristic ends wrong | declared ends wrong |
|---|---|---|---|---|---|---|---|---|
| a aarch64 | 51 | 0 | 51 / 78 (65.4%) | 0 / 11513 (0.0%) | 0 | 0 | 0 / 0 (-) | 0 / 11420 (0.0%) |
| a i686 | 1146 | 0 | 1146 / 1219 (94.0%) | 0 / 11895 (0.0%) | 0 | 6 | 0 / 0 (-) | 6 / 11845 (0.1%) |
| a x86_64 | 0 | 0 | 0 / 192 (0.0%) | 0 / 31949 (0.0%) | 0 | 8 | 0 / 0 (-) | 8 / 31743 (0.0%) |
| c (C) aarch64 | 418 | 0 | 418 / 8070 (5.2%) | 0 / 84 (0.0%) | 759 | 0 | 759 / 6719 (11.3%) | 0 / 939 (0.0%) |
| c (C) i686 | 4620 | 0 | 4620 / 11953 (38.7%) | 0 / 95 (0.0%) | 1138 | 6 | 1138 / 6179 (18.4%) | 6 / 1159 (0.5%) |
| c (C) x86_64 | 227 | 0 | 227 / 16378 (1.4%) | 0 / 6 (0.0%) | 692 | 0 | 692 / 14705 (4.7%) | 0 / 1342 (0.0%) |
| c (C++) aarch64 | 12 | 0 | 12 / 18 (66.7%) | 0 / 134 (0.0%) | 0 | 0 | 0 / 0 (-) | 0 / 110 (0.0%) |
| c (C++) i686 | 8 | 0 | 8 / 27 (29.6%) | 0 / 119 (0.0%) | 0 | 0 | 0 / 6 (0.0%) | 0 / 111 (0.0%) |
| c (C++) x86_64 | 0 | 0 | 0 / 75 (0.0%) | 0 / 8179 (0.0%) | 0 | 2 | 0 / 14 (0.0%) | 2 / 8044 (0.0%) |
| d aarch64 | 14 | 0 | 14 / 20 (70.0%) | 0 / 24 (0.0%) | 0 | 0 | 0 / 0 (-) | 0 / 6 (0.0%) |
| d i686 | 9 | 0 | 9 / 39 (23.1%) | 0 / 2 (0.0%) | 0 | 0 | 0 / 6 (0.0%) | 0 / 12 (0.0%) |
| d x86_64 | 50 | 0 | 50 / 7319 (0.7%) | 0 / 24 (0.0%) | 65 | 2 | 65 / 6998 (0.9%) | 2 / 234 (0.9%) |

The spec calls a start inside a true function wrong; a `.cold` fragment is one, and the strict
table above keeps fragments and PLT headers apart. Counted as wrong, they are all declared (an
FDE states each):

*The direction, broad reading (a `.cold` fragment and a PLT header counted as wrong starts too).*

| variant | heuristic-only starts wrong | declared starts wrong |
|---|---|---|
| a | 1197 / 1489 (80.4%) | 244 / 55357 (0.4%) |
| b | 1197 / 1489 (80.4%) | 244 / 55357 (0.4%) |
| c (C) | 5267 / 36401 (14.5%) | 21 / 185 (11.4%) |
| c (C++) | 20 / 120 (16.7%) | 141 / 8432 (1.7%) |
| d | 74 / 7378 (1.0%) | 7 / 50 (14.0%) |

**Verdict: the category predicts the error, on this corpus, for starts and for ends.** No wrong
start carries a declared source: 0 of 55 357 declared starts in (a) and (b), 0 of 8 617 in
(c), 0 of 50 in (d), against 1 197 of 1 489 heuristic-only starts in (a), 5 285 of 36 521 in
(c) (C and C++ together) and 73 of 7 378 in (d). Declared ends are wrong 14 times in 55 008
(a), 8 in 11 705 (c), 2 in 252 (d) — every one of them a PLT entry, below — against 2 589 of
27 623 `not_stated` ends in (c). Three limits on reading it: (1) under the broad reading the
declared side is not clean — 244 declared starts in (a) are `.cold` fragments or PLT headers,
and in (c) of C, where few declarations remain, 21 of 185 declared starts are PLT headers; the
declared errors are of two shapes only, both an FDE that describes code which is not one
function; (2) the heuristic error rate is not one number: by machine, 1.4% of heuristic-only
starts in (c) of C are wrong on x86-64, 5.2% on AArch64, 38.7% on i686, and four shapes make
almost all of them (below), so a per-rule rate without the machine would mislead; (3) in (a)
and (b) the heuristics can only be wrong where the declarations leave gaps — a declared extent
suppresses every rule inside it — so their 80% there is the error rate of the gaps, not of the
rules. A category therefore says where to doubt; it is not a probability, and no rate here
should be quoted without its machine, its corpus and this engine.

**Wrong-answer classes found** (not fixed here; each shown by the bytes, objdump on the
unstripped build, before being called wrong; 0 of the wrong starts is an address the
unstripped build's own symbol table names, so none accuses the reference):

1. *i386: a call to the next instruction is taken as a function.* clang's position-independent
   code reads its own address with `call 1f; 1: pop %eax`; `call_target` lists the `pop` as a
   function start. 4 223 wrong starts in (c), 8 in (d); every i686 clang build.
   `i686/lua/clang-O0`: `lua_checkstack` at `0x4ea0` (`push %ebp`), `4ea7: e8 00 00 00 00
   call 4eac`, `4eac: 58 pop %eax` — listed as `sub_4EAC`.
2. *i386: alignment filler of the `lea 0x0(%esi,%eiz,1),%esi` family is taken as code.* gas pads
   i386 code with `lea`/`mov %esi,%esi` no-ops, which discovery's filler test (`nop`, `int3`)
   does not know; after a declared end it lists the filler as the next function. 1 146 wrong
   starts in each of (a) and (b) (`after_declared_end`+`gap_sweep`: 1 126 in the i686 gcc `-O2`
   builds, 4 in each other i686 build, in the C runtime's own objects), 73 in (c), 1 in (d). `i686/lua/gcc-O2`: `503a: c3 ret`, `503b: 2e 8d 74 26 00 lea
   %cs:0x0(%esi,%eiz,1),%esi`, `f_call` at `0x5040` — listed `sub_503B`.
3. *x86-64: the `sub rsp, imm8` prologue pattern (`48 83 ec`) matches inside a function* when
   it falls on a 16-byte boundary: after `push`/`mov` of the function's own prologue, or deeper
   in the body. 227 wrong starts in (c), 43 in (d). `x86_64/lua/gcc-O2`: `luaL_newmetatable` at
   `0xcb80` (`push %rbp … push %rbx; mov %rdi,%rbx`), `cb90: 48 83 ec 08 sub $0x8,%rsp` listed
   as a function.
4. *AArch64: `stp x29, x30, [sp, #-N]!` inside a body* (a frame set up after an early-exit
   test) listed as a function: 367 in (c), 2 in (d); and *a function that begins with `paciasp`
   listed 4 bytes in,* at its `stp`: 48 in each of (a), (b), (c) and 12 in (d), the C runtime's
   `_init`/`_fini` (`6986c: paciasp`, `69870: stp` listed as `sub_69870`; the real start found
   only for `_init`, through the instruction after a declared end).
5. *The gap sweep inside a function,* after an unconditional `jmp` whose fall-through is reached
   another way (a backward branch, a jump table): 343 in (c), 328 of them on i686
   (`i686/lua/clang-O2`: `0x32af5`, `luaV_finishOp+0xb5`, after `jmp 32acf`), 7 in (d), 3 in (a).
6. *An end nothing states runs past a call that does not return.* 1 678 of the 2 589 wrong
   `not_stated` ends in (c) (216 of them on to the window's edge): the truth function ends at a
   call whose callee the compiler marks `DW_AT_noreturn` (`luaG_runerror`, `luaD_throw`,
   `luaX_syntaxerror`, …), at i686's `__stack_chk_fail_local`, or at `__stack_chk_fail@plt` —
   779 of the last on i686 and AArch64, where PLT stubs are not decoded (the reader says so:
   x86-64 only), against 11 on x86-64.
   `x86_64/lua/gcc-O2`: `luaK_concat` ends at `0x1079c` after `call luaX_syntaxerror`; `why`
   says `0x107a7`, through the padding and the whole of `luaK_getlabel`.
7. *An end nothing states is the 4 KiB graph window.* `why` builds the graph of a start with
   no stated end over 4 096 bytes; a longer function's end comes out as the window's edge (495
   ends in (c) are exactly start + `0x1000`, mid-instruction) or the last block inside it (227
   more), stated as the end with nothing to say it is a cut. Every short `not_stated` end but 39
   in (c) is a function longer than 4 KiB.
8. *The linker's PLT FDEs are read as functions.* GNU ld writes one FDE over all of `.plt` and
   one over `.plt.got`; the first makes the PLT header a function (`plt0`, 60 in (a)) whose
   extent swallows every lazy stub, the second makes the first `.plt.got` stub a function that
   ends after the last: every one of the 38 wrong declared ends (14 in (a), 14 in (b), 8 in (c),
   2 in (d)) is such a stub — `x86_64/zstd/gcc-O2`, FDE `0x8dc0..0x8de0` over four 8-byte
   stubs, `ZSTD_trace_decompress_end@plt` listed as ending at `0x8de0` for `0x8dc8`.
9. *The Itanium demangler (crate `cpp_demangle` 0.5.1) gives wrong signatures.* 327 listed names
   of libFuzzer (251 distinct symbols) differ from both `c++filt` and `llvm-cxxfilt` beyond
   spelling: 139 lose a parameter (`basic_string<std::allocator<char> >(std::allocator<char>
   const&)` for `…(char const*, std::allocator<char> const&)`, the forwarding constructors), 102
   differ otherwise (`&&` dropped from a pack expansion, `, >` for an empty pack), 10 gain one
   (`void std::_Construct<double, >(double*, &&)` for `void std::_Construct<double>(double*)`).
   A third-party defect; the lead decides whether it goes to the dependency-defects record.

**Absences (not wrong answers, measured).** The `stub` start source never fired: 0 of 9 595
PLT entries is listed as a stub — the image reader names stubs but does not hand them to
discovery as starts — and a call into `.plt` from `.text` is dropped by `call_target`, which
keeps only targets in the scan window of the call (each code section is its own window), so
in (a) 36 PLT entries are found at all, each by an FDE. No start comes from a symbol: in (c) of C,
10 634 of the 15 600 DWARF functions missed are named by the stripped file's own `.dynsym`.
188 CRT functions are missed even in (a) with `.symtab` (`_fini`, 4-byte aligned in `.fini`,
on every machine; four more of i686's). 24 `.plt.got` stubs are listed `sub_…` where objdump labels them: each jumps through a `GLOB_DAT` slot (a function
the image defines, `lua_newstate`, or a weak undefined one, `ZSTD_trace_decompress_end`), which
the stub reader does not bind to a name.

*Missed truth functions.*

| variant | DWARF missed | of them in the measured file's `.dynsym` | CRT missed | PLT entries missed |
|---|---|---|---|---|
| a | 0 | 0 | 188 | 9559 |
| b | 0 | 0 | 188 | 9559 |
| c (C) | 15600 | 10634 | 234 | 8572 |
| c (C++) | 0 | 0 | 52 | 1005 |
| d | 730 | 315 | 80 | 950 |

**Calibration.** `calibrate.py` on three configurations of three machines
(`x86_64/lua/gcc-O2`, `i686/zstd/clang-Os`, `aarch64/lua/gcc-O2`), 60 checks, 0 failures, each
mutation asserted to have happened before its effect is read: a declared true start moved by
one byte (variant b) and a heuristic one (variant c) each become exactly one interior start
inside their own function, one newly missed function, and one more wrong start under the right
kind in the direction; an exact stated end and an exact `not_stated` end moved by one byte each
become one long end; a renamed function one wrong name; the code-identity check fails on
another `-O` level's build and on a stripped copy with one `.text` byte flipped, and passes on
the real stripped file. The DWARF reading against the same file's `.symtab` (two readers): on
all 192 truth files, every DWARF entry carries a FUNC symbol and every FUNC symbol in `.text`
is a DWARF entry, a fragment or a CRT function (384 checks, 0 failures). Four times the
instrument, not the engine, was wrong, each found before a number was recorded: it read
objdump's `<puts@plt-0x10>` and `<.plt>` (an unlabelled address placed relative to a label, and
a section's own start) as PLT entries; it counted the engine's `luaD_throw_cold` for
`luaD_throw.cold` and `(unsigned long)0` for `0ul` as wrong names (now `spelled`: 1 424 in (a));
it took `c++filt` alone as the reading of a name, where `llvm-cxxfilt` reads 22 of them as the
engine does (a local name's return type, which one prints and the other does not); and its first
calibration assumed the unwind flags always change the code, which on AArch64 gcc they do not
(the identity check said "same", rightly; the calibration now pairs two `-O` levels).
The `why`/`discover` contract checks (start, end, name of every listed function) found 0
disagreements on 276 images: the tool against itself, rung 5.

**Not measured.** PE images (`.pdata`, exports, PDB), so the `unwind:pdata`, `export` and `pdb`
sources have no rate; `symbol`, `body` and `stub` produced no start; WebAssembly, ARM32/Thumb,
big-endian images; the `rtti`, `flirt`, `pdb`, `managed` and `user` name layers (no image
carried them); `analyze` and the function lists of a live process. `why` does not cite any of
these numbers; that is the lead's decision.

### The three numbers the README quotes

1. **The decoder: 10 498 instructions on 10 images, every difference a documented
   alias.** The formats table's disasm column: 425 + 3 483 + 462 + 3 598 + 287 + 425 +
   422 + 455 + 624 + 317. The differences are 14 `xchg ax,ax` read as `nop` (MinGW x64)
   and 3 `nop` against `hint #0x0` (big-endian AArch64). The second pass, on its own 9
   images (141, 195, 110, 3 328, 3 447, 244, 209, 417, 126 instructions): all agree, the
   only differences 6 `hint #0x0`. The ISA table's counts are separate and not in the
   10 498.
2. **Live: 19 of 23 operations matched their source.** The count is under Live
   process, above. It was first given as 20 of 24, counting `patch list`/`show`, which
   was checked only against the journal n0xis wrote.
3. **The decompiler: 5 to 11 of 14 functions right per image, on 9 images**: 11 PE32+
   MSVC ABI, 8 ELF64 shared object, 7 PE32 MinGW, 6 ELF32 i386, 6 PE32 MSVC ABI, 5 each
   ELF64 `-no-pie`, ELF64 PIE, PE32+ MinGW and PE ARM64. The method is under Formats.
   Of the 126 verdicts (9 images, 14 functions each), 33 were not executed, where the
   output could not be run (base-0 images, undeclared tables, text that does not
   compile): 24 were read by hand against `llvm-objdump`, and 9 were judged incomplete
   from the placeholders the text holds (`/*imul esi*/`, `/*cond(cbz)*/`, …); 4 of the
   58 right ones are among the 24. The second pass confirmed the named causes on functions of its own and
   did not reproduce these totals: they are a first measurement.

### Wrong answers with `ok:true`, October 2026

Images, names and sections:
- `rtti scan` on a MinGW PE, whose classes carry Itanium RTTI: 0 of 7 vtables, x64 and
  i386, with no advisory (second pass: 0 of 4).
- `function discover --pdata` on an ARM64 PE: not refused, 3 of 10 functions, with ends
  taken from the unwind words (`0x140a00015`, megabytes past the image); `profile`'s
  `pdata_functions` 6 against 10, the 8-byte entries read as 12-byte x64 ones (second
  pass: 1 of 4 functions, 2 against 4).
- `profile` on a MinGW PE: section names longer than 8 bytes print as the string-table
  reference (`/4`, `/29`, …), 10 of 20 (x64) and 10 of 18 (i386); `strings` resolves the
  same names.
- `profile` on an ELF shared object: its export list counts local helpers (`_init`,
  `frame_dummy`, …) and gives a GCC `.localalias` name for each C++ function that has
  one (4 and 6 on two builds) where `.dynsym` exports the global name; `decomp` titles
  those functions `[clone .localalias]`.
- `function discover` on GCC i386: the padding `lea esi,[esi+eiz]` listed as functions,
  9 on ELF32 and 33 on MinGW i386; one start inside a function on MinGW x64 (not
  reproduced by the second pass). With `.eh_frame` present it is the same: on a GCC 16
  `-O2` PIE 3 padding runs (`lea 0x0(%esi,%eiz,1),%esi`, `lea 0x0(%esi),%esi`) and the
  `.plt` block are listed as functions and `deregister_tm_clones` is given no end (the check of the
  README, 2026-10-21, against `llvm-nm` and `llvm-readelf -S`; not re-examined).
- Dots in symbol names become underscores: 5 of 29 on ELF32 (`__x86.get_pc_thunk.bx`
  printed as `__x86_get_pc_thunk_bx`), `CSWTCH.12`, gcc's `sel9.cold`; the three
  `__x86.get_pc_thunk.*` on the GCC 16 PIE with `.eh_frame` as well.
- `function discover` on big-endian AArch64 with `.eh_frame`: functions its FDEs declare
  are missed, 5 of 6 found on one build (the function reached only through a table of
  pointers is missed) and 0 of 2 on another, where the little-endian builds of the same
  sources give 6 of 6 and 2 of 2 (clang 23 with lld, static; against `llvm-dwarfdump
  --eh-frame` and `llvm-nm`; the check of the README, 2026-10-21, reproduced the same
  day). The formats table's big-endian row was built without unwind tables, so its
  26/37 does not measure this. **Fixed 2026-10-24** (`.eh_frame` was not read at all on a
  big-endian image; "Big-endian `.eh_frame`" above). Those two builds are no longer on the
  machine and were not re-measured; four other big-endian builds were.
- `rtti scan` accepts an all-zero `NOBITS` `_ZTV` symbol as a vtable (2, planted by the
  ISA targets' own stubs; not re-examined).

The decompiler:
- A pass-through register argument is dropped from the call: `n0_caller1` on all 9
  images; the second pass found it on a new shape too (gcc and clang `-O1`, through the
  PLT: `caller(void)` calling with no arguments, quality 1.0).
- A structured loop tests a value its body defines later: GCC's `strlen` and `wide_len`
  on ELF64, PIE, the shared object and MinGW x64; on PE32 MSVC `strlen` is off by one,
  having lost the `lea` after the final compare.
- GCC's interprocedural register allocation keeps values in caller-saved registers
  across calls inside one unit, and the pseudo-C reads them as never-assigned names:
  `caller2`, `uses_farewell` and `run` on ELF64, PIE and MinGW x64, all right once rebuilt
  with `-fno-ipa-ra`.
- An arithmetic shift prints as `>>` on `uint64_t`, on every 64-bit image (`a = -1`
  gives `0x1fffffffffffffff` where the processor gives `0xffffffffffffffff`).
- A 64-bit magic-number multiply prints as a 32-bit product (`0xaaaaaaab * (uint32_t)rcx`).
- A subscript of `void*` loses its element width (`wide_len`; the `select` tables are
  counted incomplete for it).
- On i386, a pushed argument becomes a store to `local_neg_4` and the call prints with
  none (4 of 14 per image); stack arguments are read through a never-defined `esp.1`;
  64-bit results return only `eax`.
- On ARM64, an `adrp`+`add` address prints as the string at the page base plus an
  offset, naming the wrong object.
- On x86-64 and i386, a switch on a register the text never assigns, at quality 1.0:
  3 629 of 8 640 inputs right as printed (above).
- On x86-64, a virtual call in tail position decompiles to `// indirect jump
  (unrecovered)` with no return, at quality 1.0.
- On A32, a `subs`/`bne` countdown loop printed as a pre-test `while (r1.1 != 1)` at
  quality 1.0: one iteration short, 6 of 7 inputs against `qemu-arm` wrong; AArch64 prints
  the same structure.
- On A32 and T32: jump-table words lifted as statements; the tail call `b dispatch`
  dropped at quality 1.0; `cmp r0,#0; moveq r0,#0` printed as `r0.1 = __umin(r0, 0x0)`.
- On T32: an IT-predicated `bx lr` ends the function (8 of 14); `cbz`, `cbnz` and `tbb`
  not branches; the disassembly text wrong as in the ISA table; symbols never attached.
- Raw x86-64 bytes are decompiled under the Win64 convention: SysV code 0 of 14.

A live process:
- `provenance trace`'s `decompiled_context` prints a written address as a string
  literal of the bytes there when they are printable (`*(uint32_t*)(">BCD")` for an
  `i32` at `0x404090`).
- `provenance trace`'s `function_va` on `examples/config-demo`: the function's start on
  gcc `-O2`, but the loop head on clang `-O2` (`decrypt_config` at `0x1190`, answered
  `0x11b0`) and gcc `-O1` (`0x11ab`, answered `0x11e0`), with no note; on clang the
  context leaves out the key update. The store itself was right on all three.

Missed, answered `ok` with less: without unwind tables, the methods reached only
through vtables (10 or 11 per image), the MSVC-ABI entry point (3 images) and all but 4
of a shared object's 33 functions; data references held in absolute immediates (PE32
0 of 2, MinGW i386 0 of 3 and 16 function-address sites, one in an ELF `_start`), in
`adrp`+`add` (0 of 2) or `adr` (0 of 2), or through the i386 GOT; Itanium secondary
vtables (6 of 7 on every ELF); every Itanium class of a stripped image (gcc and clang
`-O2`: 0 classes, no note, against 3 of 3 unstripped); names that only the COFF symbol
table holds (10 to 90 functions `sub_` per image); PLT stubs and GOT slots; a big-endian
UTF-16 string; A32 functions never called directly (4 of 21); code after the first ARM
NEON instruction.

---

## Proven

| Check | Source | Rung | Cases | Result |
| --- | --- | --- | --- | --- |
| Decoder instruction boundaries (x86) | `objdump` | 3 | 20 000 + 20 000 + 60 000 insns | 0 disagreements; the only 2 are inside an ASCII string in `.text` where `objdump` itself decodes `(bad)`. Re-run 2026-10-20: 20 000 of 20 000 on libc and on a 32-bit system DLL of the Windows compatibility layer, 0 length disagreements, 0 boundaries either side alone. The browser binary has since been updated (338 885 720 bytes) and still has 2 length disagreements, inside the same embedded string; there `disasm --count 60000` stopped at 20 005 instructions with no note (Open) |
| Decoder mnemonics (AArch64) | `llvm-objdump` | 3 | 148 insns (2026-10-20; 147 when first recorded) | 0 fail to decode; 30 name differences, each a documented architecture alias: 12 `mov`/`orr`, 8 `cmp`/`subs`, 3 `b.hs`/`b.cs`, 2 `mov`/`movz`, 2 `mov`/`dup`, 1 each `mul`/`madd`, `mov`/`movn`, `mov`/`add` (clang `-O2` of `oracle/arm64.c`; first recorded as 28, and the test's own comment records 148/29 from 2026-09-10). Compiler output of two levels in October: 1 628 of 1 628 (ISAs, above) |
| Decoder encoding space (AArch64) | `llvm-mc --mattr=+all` | 3 | 600 deterministic words | 48 (8.0%) reserved words read as instructions, held by a bound that fails if it grows; 7 (1.2%) real insns rejected — stated, not hidden. Reproduced 2026-10-20 with llvm-mc 23.1.1: 241 / 304 / 48 / 7. The 7 are six load/store-exclusive or acquire/release forms (`ldxp`, `ldxr`, `stlrh`, `stlxr`, `stxr`, `ldar`) and one compare-and-swap (`casat`), and all 7 draw llvm-mc's "potentially undefined instruction encoding" warning. The bound is behind `--features oracle`, so CI does not run it |
| Emulator vs the processor | the CPU (planted inputs) | 1 | 20 400+ comparisons (leaf, FP, calls, Win64, 32-bit, switch, packed SIMD) | 0 disagreements. The oracle harnesses now attach the symbol table the real pipeline uses (`.with_symbols`) — a starved `Ctx::new` had left `the_emulator_follows_a_call` stubbing 48 calls it should follow; with symbols it steps into 1 664 callee frames, not 1 616 (2026-09-14). |
| Emulator, ELF32 axis | the CPU | 1 | 3 888 (gcc/clang × O0/O1/O2/Os + PE32/mingw) | 0 disagreements — this axis had **never run** before 2026-09-11 (a malformed argv skipped it); now live |
| AArch64 lift vs the processor | the CPU, under `qemu-aarch64-static` | 1 | 960 answers over 120 function builds | 526 reproduced, 0 disagreements, 434 not modelled (see OPEN: `-O0`, extending-add) |
| Function extents | the image's own unwind table (`objdump --dwarf=frames`; `llvm-dwarfdump --eh-frame` in October) | 2 | 10 + 3 777 + 15 467 + 14 355 FDEs | Re-measured 2026-10-20: 10 of 10 on the oracle shape; libc's 3 777 FDEs all listed, **3 775 exact and 2 not** (`setcontext`, `__clone`: each symbol spans 2–3 FDEs and n0xis ends it at the symbol's `st_size`, while the inner FDE starts are listed too, so two pairs of extents overlap; see Open); 15 467 of 15 467 and 14 355 of 14 355 on two large C++ libraries. First recorded as 3 787 exact |
| Exported entry points | `nm -D` | 3 | 10/10 + 2 323/2 323 | 0 missed; reproduced 2026-10-20 |
| Cross-references & call graph | `objdump` disassembly | 3 | 4 739 refs; 304 call sites; 464 branch targets | none missed, none invented, both directions. Re-measured 2026-10-20: the six busiest targets of today's libc hold 4 739 references (1 578, 1 330, 605, 453, 392, 381; 4 733 on the libc of the first measurement); 304 and 464 reproduced exactly |
| Recovered struct fields | `gcc -g` DWARF | 1 | 15 field offsets over 10 functions | every one a real member; none invented; reproduced 2026-10-20 |
| Static CFG invariants (x64) | the image's tables | 2 | 92 001 edges | 0 violations. The images behind this number were not recorded, so it cannot be re-run. Substitutes, 2026-10-20: x64 libc, 143 693 edges, none off an `objdump` instruction boundary, 8 leaving their FDE (all inside `setcontext` and `__clone`, within the symbol extents); a 64-bit system PE DLL, 2 795 of 2 795 `.pdata` extents and 35 554 edges with 0 violations |
| Static CFG invariants (ARM64) | symbol table | 2/3 | 2 381 extents, 46 757 edges | extents exact, 0 violations. The 2.9 MB library measured is not on the machine used in October. Substitute, 2026-10-20: a 2.2 MB AArch64 libc, 3 555 of 3 555 extents equal to `st_size`, 86 889 edges, 0 violations (inside the extent, 4-byte aligned) |
| Static CFG invariants (32-bit PE) | `.eh_frame` (independent parser) | 3 | 422 entries, 34 149 edges, 3 889 FDEs | 0 missed, every extent exact. The image was not recorded. Substitute, 2026-10-20: a 32-bit system DLL of the Windows compatibility layer, with `.eh_frame` and no `.pdata`: 1 298 of 1 298 exported code addresses (`llvm-readobj --coff-exports`, 93 forwarders excluded), 35 272 edges with 0 violations, 2 803 FDEs with 0 missed, 2 803 exact, 0 starts inside another FDE's extent |
| Recovered signatures | `oracle/` (compiled here, answer known) | 1 | 20/20 on the two x86-64 shapes (2026-10-20) | arg count, register file, return class correct: `oracle/expect.json` now holds 10 functions per shape (12/12 when first recorded). Rebuilt with gcc/mingw `-O1` and clang `-O2`, 40 of 40. i386 10 of 10 as recorded, and all 12 known-open gaps still open; recorded gaps (cdecl arity, x87 return) fail the test if they quietly close. Behind `--features oracle`, so not run in CI |
| Recovered C++ classes (RTTI) | the image's own type-descriptor strings; `llvm-nm -D` `_ZTV` symbols; `lld-link /map`; a second MSVC RTTI reader written for the check | 2; 3; 2; 4 | 93 + 97 + 152 vtables (MSVC), 269 (Itanium) | every recovered name present in the image's strings. Re-measured 2026-10-20, addresses as well as names: 269 of 269 at `_ZTV+16` on the same 64-bit C++ library; the 32-bit GNU C++ runtime 152 of 152 at `_ZTV+8`, the 27 refused for virtual bases exactly the 27 with a VTT; the 32-bit C++ runtime of the Windows compatibility layer 93, equal to the second reader's 93 (rung 4); two MSVC-built PE32+ DLLs (0.4 MB, 3.6 MB) 87 of 87 and 12 of 12 against that reader (rung 4). clang++ 23 with lld-link does emit MSVC RTTI, and its `/map` states each vftable before the question: 4 of 4 on both dialects, and 7 of 7 on x64, x86 and ARM64 in the format table above. The 97 and 152 images were not recorded; the compatibility layer's own x64 C++ runtimes give 0, plausibly correctly, since their locator offsets are filled at load time |
| Live memory (Linux) | `/proc/<pid>/mem`, planted values | 1 | 29/31 commands (`live_memory_exit.rs`, as first recorded) | one wrong, found and fixed; 2 are Windows-only and refuse saying so. The harness runs in CI and passed there on 2026-10-20 (run 39484775130, 6 tests) and locally on 2026-10-21, but it does not produce the 29/31 count, which is its first recording only; of `scan dissect` it asserts only the bytes at +0 and that the word at +24 is a pointer. In October 2026 two independent targets were measured as well (above): 19 of 23 operations, and 18 of 19 commands. The one fixed, `scan dissect`, reads 3 of 6 fields of this harness's own layout, not the 5 of 6 recorded after its fix |
| Live memory (Windows 11) | the target process itself | 1 | 21/23 checks | 0 wrong; `stack backtrace` is Linux-only. Re-checked 2026-10-04 with `oracle/windows/run.sh`: 12/12, and the Linux and Windows builds agree on the same PE; two of the 12 are `provenance trace` on its own Windows target (the writing function, and the writing statement). Not re-run in October 2026 |
| CLI ↔ registry front doors agree | the tool's two doors, one question | 5→contract | 4 pairs | agree; a Windows JSON-escaping bug in the *test* found and fixed 2026-09-11 |
| Discontiguous functions (hot/cold split `<fn>.cold`) | the processor, under gcc-14 `-O2` | 1 | a_switch, all levels | 768 agree, 0 disagree, 0 not modelled; the `.cold` partition folds into its parent so the switch default has a successor (fixed 2026-09-13, was 46/0/2 at `-O2`) |
| Section reads (ELF) | `readelf -SW` offsets, the file's own bytes | 2/3 | 204 692 file-backed sections in 9 367 ELF files on one system | 0 read wrongly (348 in the first 2 000 files before the `.tbss` fix below); a local sweep, `elf_reads_agree_with_readelf.rs` |
| Strings (`strings`) | a fixture with planted strings (`nm`, `readelf`); binutils `strings`; an independent disassembler's string search | 1; 3; 4 | 3 planted strings and one too short; 15 304 binutils strings over four system images (14 UTF-16); 22 822 of the disassembler's over five ELF and PE images (4 486 UTF-16) | each planted string at its address in its encoding; none of either tool's strings missed; every ASCII string of ours one of theirs (cut at line breaks for binutils). The disassembler found one wide string dropped by the first rule for ASCII read as UTF-16, fixed and pinned by a test. Past ASCII there is no oracle: a bound on the count over binutils' catches binary data read as text, and caught the first UTF-16 rule (10 625 against 11) |
| Byte windows across gaps (`mem span`) | `readelf -SW`, `llvm-readobj --sections`; a live process's planted pages | 3; 1 | 4 windows on an ELF and a PE fixture, plus an empty one; one live window over an unmapped page | every stretch and every gap where the section tables put them, bytes identical to the files' own; live, both stretches and the hole exactly as planted |
| Range-scoped IL2CPP managed-name attachment (PE) | a committed fixture PE (`native_pe.dll`) | 2 | 6 tests | bind + attach through the single-address and the range path; deterministic (no self-image, no toolchain), gates CI on both OSes, calibrated (2026-09-14) |
| An IL2CPP index names only the binary it was imported for | `nm`/`objdump` on a second fixture PE | 3 | cross-binary test | import an index for A, analyse B → B keeps its real symbol, no fabricated managed name. Provenance (build-id / `.text` fingerprint) gates auto-attach; a mismatch or a provenance-less index does not attach. Found by the gcc-14 hunt; fixed and calibrated 2026-09-14 |
| PDB function names, addresses and lengths | a PE and PDB built here from known source; `llvm-pdbutil` | 1; 3 | 5 functions of the source, 43 function addresses | exact: every name, address and stated length, including the static only its module's stream holds; the public table's count |
| PDB names on real images | five system DLLs and their vendor's public PDBs; `llvm-pdbutil`, `llvm-undname` | 2; 3 | 18 927 function addresses | every address listed; 18 868 named as `llvm-undname` reads the name, up to template arguments; each of the other 59 differs in spelling only: a special member's wording (22), a name left undemangled (35), a templated constructor spelled `ctor<>` (2). See Open |
| Which PDB belongs to an image | the images' own CodeView records | 2 | 5 images | each matched by its PDB's debug-information age (1); the information-stream ages (2, 4, 3, 3, 2) would have refused all five. A raised information age on the fixture still matches; a changed GUID or age is refused |

### Confident-wrong-answer regressions closed (calibrated)

A pass over the tool's own output found defects that *compiled and passed the
suite* yet returned a confident wrong answer — the worst shape, since the caller
has no error to branch on. Each was fixed and guarded by a test that fails on its
own line if the fix is reverted (rung 1: the right answer is known from the
source's meaning before the question is asked). Recorded here because a tool that
claims reliability must show its wrong answers being found and fenced, not hide
them.

| Was wrong | Now | Guard |
| --- | --- | --- |
| A search / rotated / middle-exit loop decompiled to the wrong result — the loop returned its sentinel instead of the found index at `-O0`, an off-by-one at `-O2` | `break` targets the block the loop actually lays out after itself; a conditional-exit latch routes to do/while | 3 calibrated tests (the loop body had had no external-truth test — "a layer whose only test is itself") |
| The MCP door reimplemented decoder/architecture and symbol selection and had drifted from the CLI — wrong arch on a non-x64 image, missing symbol chain, a mismatched error code | the door delegates to the shared registry, so both front doors answer one question one way | 5 cross-door parity tests |
| `provenance trace`, on a function it failed to locate, emitted a hardcoded false cause ("a leaf with no prologue") regardless of the real reason | a full-range fallback finds the writer wherever it is, or the answer says honestly that no recovered function covers the address | calibrated test (an unaligned leaf after a tail call is found, not fabricated) |
| An AVX self-xor accumulator (`vpxor xmm,xmm,xmm`, which zeroes) was read as up to four phantom `double` parameters | a self-annihilating `xor`/`sub` (both operands the same value) is recognised as a constant, not a live-in use | calibrated test (a real subtract and a genuine FP parameter are untouched) |
| A non-x64 file analysed without `--arch` decoded as x86-64 across six commands — phantom `sub_` from an x86 prologue pattern inside ARM bytes | file-analysing commands pick the decoder through the header-bearing source (`Src::pick_arch`), which cannot ignore the declared machine | calibrated test on the real header→decoder path (revert → arm64 flips to x86-64); verified the parsers' machine strings intersect what the selector accepts |
| An externally loaded signature with too few fixed bytes named unrelated code confidently (a `jmp rel32` trimmed to a lone `e9` matched every `0xe9`) | the runtime matcher refuses a name below the same fixed-byte floor `sig gen` already enforces (one named constant for both) | calibrated test; the shipped corpus's minimum is exactly the floor and the end-to-end oracle still matches, so no real name was suppressed |
| On AArch64, whether register 31 meant `sp` or `xzr` was decided from the instruction *class* in the def-use path and disagreed with the lift in four operand positions — `cmp`/`subs` recorded a write to `sp`, the stack-realign `and sp,…` recorded a write to `xzr`, the extended `add …,sp,…` read the wrong register | both the def-use path and the lift read that fact from the operand's kind in the decoder definition (`Rd_SP`/`Rn_SP`), so they cannot drift | calibrated test over the four fixed positions plus a guard that the already-correct positions do not shift, each word disassembled by llvm-mc / aarch64 objdump (rung 3) |
| A pre-/post-indexed AArch64 load/store's base-register writeback (`stp …,[sp,#-192]!` does `sp -= 192`; `ldr …,[x1],#8` does `x1 += 8`) was modelled nowhere, so a pointer loop decompiled with its pointers loop-invariant and returned the unadvanced pointer | the base update is recovered as `base := base ± K` (the delta is fully determined by the encoding), from one source shared by the def-use path, the lift and frame analysis | K calibrated against an independent disassembler (rung 3): ten planted words spanning both signs, both pair scales, and the PAuth forms, each asserting the recovered delta equals the printed offset |
| `profile --exports` listed forwarded exports at the address of their `MODULE.Function` string and counted them as code; the loader put the same strings in its symbol map, so the decompiler titled them and `sig gen` fingerprinted them (126 of 1 554 signatures on a 0.9 MB x64 system DLL, 538 over eight images) | one export-table reader classifies every entry as a local address or a forwarder with no address; loader and `profile` both use it. 0 forwarder signatures and 0 forwarder symbols on 1 600 PE images (20 259 before); all 591 forwarders on nine images carry the exact string an independent reader prints, no other export carries one (`082a4a4`, `5fd4eda`) | synthetic PE with one forwarder (each assertion fails on its own line with the fix reverted); a test that fails when loader and `profile` disagree |
| `analyze` found its functions without the ones the image declares: 4 130 on a Rust binary whose `.eh_frame` declares 6 730, 116 331 on a C++ library declaring 123 192. Its signature names, propagated types, class layouts and warm-up all skipped the rest | `analyze` and `function discover` take one list from one helper: every executable range, with the declared functions. Against the images' own unwind tables (readelf), every FDE start is listed on all three (6 730, 15 467, 123 192). The 4, 5 and 16 listed starts with no FDE are all functions: CRT helpers (named by the symbol table, or stored in `.init_array`/`.fini_array`), `_init`, targets of a direct `call` or tail `jmp` (objdump), and one AVX-512 assembly routine. The one false start found, an `endbr64` where a `setjmp` call returns, is no longer listed. On a PE `analyze` first kept `.pdata` alone (2 949 against 3 198 on the Windows test binary, 6 681 against 8 258 on a cross-built one); it now takes the same helper there | `analyze_counts_what_discover_lists.rs` (fails before the fix: 1 569 against 2 069; on the Windows job, 2 949 against 3 198) |
| `annotate var` / `vartype` stored a rename or a type under any name and answered `ok`: a name that is not a variable, or a type on a value the decompiler never types, changed nothing | With the image (`--file`, or the session's), the name is checked against `decomp pseudo`'s `variables` in all three styles: not a variable → `not-a-variable`; a shown name → stored under its key; a type on a value → `takes-no-type`. Without one, `meta.note` says it was not checked | `annotate_var_names_a_variable.rs` (fails with the check off) |
| Reads under an ELF's zero-fill TLS section (`.tbss`) answered `ok` with no bytes. The linker gives it the address the following sections also start at, since it takes no room in the image, and it was mapped first: `.init_array`, `.fini_array`, the start of `.data.rel.ro`, `.dynamic`, `.got` and `.data` read empty in 568 of 9 386 ELF files on one system | `.tbss` stays in the section table (`profile` lists it) and out of the address map. Against the bytes at `readelf -SW`'s offsets: 348 sections read wrongly in the first 2 000 files before, none of 204 692 in all 9 367 after | `elf_tls_layout.rs` on a checked-in fixture (with `.tbss` mapped, `.init_array` reads `[]`); the sweep `elf_reads_agree_with_readelf.rs` behind `--features oracle` |
| A long-running process (one MCP server) answered a file with another file's facts: the memos kept between requests (unwind map, function list, reverse-xref index, vtable maps, callee types) were keyed by the source's label, `static:<file name>`, the same for two files of one name. `function discover` on a file with 10 functions answered 4 with `ok`, after another file of that name | Sources carry an identity made from their content (`SourceId`); every one of those memos is keyed by it, and a live process, which has none, is never kept | `same_name_is_not_same_image.rs`: two files of one name asked in turn in one process, each answer equal to a fresh process's |
| In a `serve` session, `find --bytes <pattern>` searched the project's default file instead of the session's (the pattern was taken for an inline-bytes source), and `dump save` stored the whole session image as a note, both `ok:true`; a command reading stdin hung the session | a session decides "names its own source" from the command's argument ids, not flag spellings, and adds `--file` only where a source argument of that id exists; reading stdin inside a session is refused with `stdin-is-session-channel` (`082a4a4`, `5fd4eda`) | session tests with planted bytes and a decoy project; a stored note read back exactly; a deadline so a hang fails |
| `guide` said, in one sentence for the whole catalog, that a command reading a target accepts any of `--pid`, `--file`, `--snapshot`, `--remote-cmd` and `--bytes`. Measured 2026-10-20 against every command's `--help`: `--pid` 69, `--file` 54, `--snapshot` 29, `--remote-cmd` 29 of 117, and `disasm --snapshot` answered `unexpected argument` | each command's `sources` in the guide is read from its own argument definitions: `--pid` 69, `--file` 53, `--snapshot` 29, `--remote-cmd` 29, `--bytes` 19 of 117; all five 18, none 39. A count of the spellings in `--help` gives `--file` 54 and `--bytes` 23, because five arguments are data spelled like a source and are no target: `dump save --file` (the file stored as the dump's payload), `find --bytes` (the pattern searched for), and `mem write --bytes`, `patch dry-run --bytes`, `patch apply --bytes` (the bytes written). Where `--pid`, `--file`, `--snapshot` and `--remote-cmd` are all taken (29 commands), `decomp pseudo` gave the same 18 lines on each | `guide_states_each_commands_sources.rs`: each command's `sources` against its `--help`, a source it does not state refused by the parser by name, and the reference's Sources lines against the guide. With the old claim restored (all five on every command that takes one), it fails on its own assertion, listing e.g. `disasm` stating `--snapshot` |

The narrative behind each row, with every caveat, is in `ROADMAP.md`; the number is
here. If a README sentence and a row here disagree, the row is the measurement and the
sentence is stale.

## Open

| Gap | State | Where |
| --- | --- | --- |
| AArch64 **lift `-O0`** | Unmeasured: `-O0` reproduced 0 of 240 because stack stores are not lifted; the "526 of 960" figure rests on `-O1/-O2/-Os` only. Not "55% coverage" of AArch64 generally. | AArch64 lift oracle |
| AArch64 extending-register add | The dominant remaining `Unlifted` at optimised levels (`add x0, x0, w2, uxth`). | AArch64 lift oracle |
| `function discover` lists chained unwind fragments as functions | Measured 2026-10-04. An unwind entry flagged `UNW_FLAG_CHAININFO` continues another function (confirmed with `llvm-readobj --unwind`), yet `--pdata` lists every such entry as a function: 43 / 1 672 / 1 155 / 373 on four PE32+/MSVC system DLLs (0.9 / 2.6 / 1.4 / 2.0 MB), none of them a function the matching PDB names. The prologue scan lists the same fragments (all of them on three DLLs, 1 669 of 1 672 on the fourth). | PDB oracle, ROADMAP gap-closing item 1 |
| Functions a PDB names that discovery misses | Measured 2026-10-04 on the same four DLLs: 41 / 14 / 20 / 10 function publics found by neither discovery mode. Not yet triaged: each is either a missed function or a public flagged as code that does not start a function. | PDB oracle, ROADMAP gap-closing item 1 |
| `provenance trace` names neither the function nor the global | Measured 2026-10-05 on Linux with `examples/config-demo` built `-O2 -g`: the write's address, the instruction (`objdump`: the byte store at `decrypt_config+0x36`) and the containing function are right, but `function_name` is `null` and the statements read `*(uint8_t*)((rdi.1 + v2)) = …`, although the ELF's symbol table names `config` and `decrypt_config`. The README says so beside its example. Re-measured 2026-10-20 on three builds of the same source: the store is right on all three, the function only on gcc `-O2`; clang `-O2` and gcc `-O1` answer the loop head (listed under wrong answers above). | `nm` and `objdump` on the same binary |
| Data exports reach `sig gen` | Measured 2026-10-05: `named_functions()` still includes named exports outside executable sections, 4 814 of 152 546 across 123 images (9 on one x64 system DLL), so a data export can be fingerprinted as code. | Section flags of the image |
| `decomp pseudo` on a non-executable address | Measured 2026-10-05: it decodes the bytes as code and answers `ok:true` with no note, where `disasm` adds one. | Section flags of the image |
| An ELF's headers read as unmapped | Measured 2026-10-05: `mem read --file` at the image base answers "not mapped", while the first `PT_LOAD` maps the ELF header and program headers there (`readelf -l`), and a PE image maps its headers. The ELF map follows sections, not segments; mapping the headers would make small constants in a position-independent image look like addresses, so it is left as is until the pointer checks that use the same map can be held apart. | `readelf -l` on the same file |
| Disk caches of one function's decompilation across files of one name | Not measured. The `ir-cache` and `decomp-cache` keys are the source's label, the decoder and the function's own bytes, so two files of one name sharing one project, with an identical function at one address but different callees or names around it, could share an entry. Within a project made per target (as the GUI makes them) it cannot arise. | A test with two such files and one project |
| MSVC names: a negative template literal, and three kinds left undemangled | Measured 2026-10-07 against `llvm-undname` on the names of five system DLLs' PDBs: `$0?IAAAAAAAAAAAAAAA@` is shown as `0` where it is -9223372036854775808 (wrong); `noexcept` function pointers (`_E`), `nullptr_t` (`$$T`) and rvalue references (`$$Q`) are left as the raw name (not wrong, unread). | `llvm-undname` |
| `--file /dev/stdin` inside a session | Not guarded: given explicitly in a `serve` session, it would read the request channel as a file. Not measured beyond reading the code. | Session test |
| The October 2026 instruments are not in the repository | The target sources, build scripts and checkers behind the October 2026 section were kept outside version control. Until they are checked in under `oracle/`, those rows cannot be re-run from a clone. | `oracle/` |
| Every wrong answer with `ok:true` listed under October 2026 | Open until each is fixed or refused with a typed error; listed once, there, with its counts. | October 2026, above |
| A function whose symbol spans several FDEs | Measured 2026-10-20: 2 of libc's 3 777 FDEs (`setcontext`, `__clone`) end at the symbol's `st_size`, and their inner FDE starts are listed as functions too, so two pairs of extents overlap. | `llvm-dwarfdump --eh-frame`, `llvm-nm -S` |
| `disasm` stops after `(bad)` without saying so | Measured 2026-10-20: `--count 60000` on the stripped browser binary returned 20 005 instructions, stopping at the `(bad)` inside an embedded string, with no note and no truncation flag. | `objdump` over the same range |
| `disasm` decodes past a PE section's `VirtualSize` | Measured 2026-10-20: it keeps decoding the file's zero padding (44 extra `add [rax],al` on one DLL), where `objdump` stops at `VirtualSize`. | `objdump`, the section table |
| `scan aob` over the default region set | Measured 2026-10-20 on two targets: it fails with `aob-failed` on a mapped but unreadable region (a thread-stack arena, which `/proc` also cannot read) and never reaches the pattern, while `scan value` and `scan group` skip the same region. `scan value` then reports `exhaustive:true`. | `/proc/<pid>/mem` |
| `scan dissect` field types | Measured 2026-10-20: 3 of 6 fields on the harness's six-field layout (two floats read as one double, a u64 as two ints), 2 of 6 on a second layout; offsets never cross alignment. | a C target of known layout |
| `--explain` entries without an address | Measured 2026-10-20: 8 of 12 entries on one MinGW function carry an address; the 4 without are two constant folds and two dead-phi removals. Whether every rewrite is recorded is not measured. | — |

## Not claimed (needs an input/platform not present)

| Capability | What it needs |
| --- | --- |
| `aot symbols` (.NET NativeAOT method maps) | A NativeAOT build; there is no .NET toolchain on the machine the October 2026 pass used. |
| LuaJIT bytecode | A LuaJIT 2.0 dump; a 2.1 dump is refused with a typed error (measured 2026-10-20), and no 2.0 toolchain was present. |
| `--remote-cmd` over SSH | Measured only with a local argv (2026-10-20: `remote-serve` over a pipe, 64 of 64 bytes); the SSH transport itself was not. |
| `il2cpp import` / `symbols` | An external dumper's index. |
| `il2cpp obj` / `classes` | A live managed process. |

## Notes on how CI verifies vs how it does not

The processor/objdump/unwind-table oracle tests **compile code with the host
toolchain** and compare against a host-derived reference, so their result depends
on the compiler version — a different gcc emits a construct the IR does not model,
and the test rightly fails. They are **local instruments**, behind
`--features oracle`, and do not gate CI (which runs the rustc-only tests). Run the
full ledger locally:

```sh
cargo test --workspace --features n0xis-core/oracle,n0xis-cli/oracle,n0xis-sources/oracle,n0xis-wasm/oracle
```

A "green CI" therefore means the deterministic suite passed, **not** that every
row above was re-checked on that runner. The oracle rows are re-checked wherever
the toolchain is pinned.

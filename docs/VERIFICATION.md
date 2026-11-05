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

### How often each rule is right (2026-11-05)

docs/design/WHY.md §6 items 2 and 3: each source of a function start, end and name measured on
its own against programs whose answer is known, and the direction's own test — whether a wrong
answer is predicted by its source's category (a declaration of the image against a heuristic
rule). The instrument is `oracle/rule-accuracy/` (its README says how to run it again); every
number below is generated by it (`results/doc-tables.md` and `before-after.md` of the run).

**What this measures, and what it does not.** Function boundaries and names only: where a
function starts, where it ends, what it is called. It says nothing about whether a function's
decompiled body is right.

**The engines measured.** The tuned corpus was first measured on 2026-10-25 and its wrong answers
were then fixed, so **its figures below cannot show that the fixes generalize**; that is what the
held-out set further down is for. *Before:* a clean checkout of main `4348933` built here,
sha256 `2d92d2dd2bbffdc6d6ee423c3b18b181e2d80debd79624ba6cdd36fa64610597`; its 276 results
reproduce every table recorded for `a85a927`, byte for byte (the commit between changed no
engine code). *After:* the engine of this round, sha256
`2447860cb17f121940e83327fd32472db5ae40a1e297f13b3abb38262a0f96f6`. Both asked through the CLI
as a user asks it: `function discover --file`, then `why --file --addr` at every listed start,
each image in a fresh project directory of its own, and both scored by one scorer.

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
no extent to say "inside"). **Two definitions of a wrong start are reported beside each other:**
*strict*, today's, in which a fragment and a PLT header are neither right nor wrong, and *broad*,
which counts both as wrong (on the base, 244 of the 55 357 declared starts of (a)).

**The variants.** (a) the `-g` build as built; (b) the same file after `strip --strip-all`;
(c) built with `-fno-asynchronous-unwind-tables -fno-unwind-tables`, stripped; (d), beyond the
spec, C++ only: (c) with `-fno-exceptions` as well — in C++ the flags of (c) leave an FDE on
every function that may unwind, so (c) of a C++ program is (b) again (the tables give (c) for C
and for C++ apart). Before a truth is used for a stripped file, every executable section of
the two must have the same name, address, size and bytes: 192 of 192 did, so no variant was
refused. Each configuration was also built without `-g`: 166 of 192 pairs have the same code,
26 differ, all clang (17 configurations, on all three machines), so on those the file measured
is the `-g` build's code, not what clang emits without `-g`.

**Corpus (tuned).** Offline, sources already on the machine: the repo's `oracle/` programs as one C
shared object (`emu*.c`, `locals.c`, `sysv.c`, `typeflow.c`, `types.c`, `arm64.c`, plus
`emu_fp.c` on x86, `emu_simd.c` on x86-64, `i386.c` on i686) and `cxx_this.cpp`; Lua 5.4.7
(crate `lua-src` 547.0.0) and zstd 1.5.7 `lib/` without assembly or legacy formats (crate
`zstd-sys` 2.1.0+zstd.1.5.7) as shared objects; SQLite 3.53.2 (crate `libsqlite3-sys` 0.38.2)
as a shared object and libFuzzer (crate `libfuzzer-sys` 0.4.13, C++17, with a one-line target)
as a PIE executable, x86-64 only. Compilers: gcc 16.2.1 (x86-64, and i686 with `-m32`),
`aarch64-linux-gnu-gcc` 16.1.0, clang 23.1.1 (GNU ld 2.47 on x86; ld.lld 23.1.1 with the cross
sysroot on AArch64); `-O0`, `-O2`, `-Os`. 84 configurations, 276 measured images.

**These counts are not independent samples.** Six codebases, each built up to six ways on up to
three machines, so a function counted 54 772 times here is far fewer functions; and (b) is (a)'s
code stripped. No total below sums variants, and the per-codebase tables are the honest grain.

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

**Before and after.** Each cell before → after. Recall is the DWARF functions found, of all in
that row. The fixes, each with its own planted test (`discovery_on_planted_images.rs`, every one
calibrated by reverting the fix): (A) an ELF `STT_FUNC` symbol with a size, in code, is a declared
start; (B) the rules walk over i386's `lea` padding; (C) `call next; pop` is not a call; (D) a graph
cut by its window says so; (E) an FDE over a PLT section is no function's; (P) `paciasp` is an
entry pattern; (F) a branch into filler means the code goes on; (G) a section's start brackets the
sweep; (H) an entry pattern the code before runs on into is no entry.

*Before and after: starts, per variant x codebase.*

| variant | codebase | listed | true | wrong, strict | fragment + plt0 | precision, strict | precision, broad | recall: DWARF fns |
|---|---|---|---|---|---|---|---|---|
| a | libfuzzer | 8107 → 8095 | 7978 → 7972 | 0 → 0 | 129 → 123 | 100.0% → 100.0% | 98.4% → 98.5% | 7908 / 7908 (100.0%) → 7908 / 7908 (100.0%) |
| a | lua | 15448 → 14909 | 14879 → 14897 | 545 → 0 | 24 → 12 | 96.5% → 100.0% | 96.3% → 99.9% | 14746 / 14746 (100.0%) → 14746 / 14746 (100.0%) |
| a | oracle_c | 3089 → 2957 | 2930 → 2957 | 147 → 0 | 12 → 0 | 95.2% → 100.0% | 94.9% → 100.0% | 2808 / 2808 (100.0%) → 2808 / 2808 (100.0%) |
| a | oracle_cxx | 445 → 443 | 413 → 443 | 20 → 0 | 12 → 0 | 95.4% → 100.0% | 92.8% → 100.0% | 330 / 330 (100.0%) → 330 / 330 (100.0%) |
| a | sqlite | 12024 → 12012 | 11985 → 11979 | 0 → 0 | 39 → 33 | 100.0% → 100.0% | 99.7% → 99.7% | 11912 / 11912 (100.0%) → 11912 / 11912 (100.0%) |
| a | zstd | 17733 → 17254 | 17220 → 17238 | 485 → 0 | 28 → 16 | 97.3% → 100.0% | 97.1% → 99.9% | 17068 / 17068 (100.0%) → 17068 / 17068 (100.0%) |
| b | libfuzzer | 8107 → 8095 | 7978 → 7972 | 0 → 0 | 129 → 123 | 100.0% → 100.0% | 98.4% → 98.5% | 7908 / 7908 (100.0%) → 7908 / 7908 (100.0%) |
| b | lua | 15448 → 14912 | 14879 → 14896 | 545 → 4 | 24 → 12 | 96.5% → 100.0% | 96.3% → 99.9% | 14746 / 14746 (100.0%) → 14746 / 14746 (100.0%) |
| b | oracle_c | 3089 → 2960 | 2930 → 2957 | 147 → 3 | 12 → 0 | 95.2% → 99.9% | 94.9% → 99.9% | 2808 / 2808 (100.0%) → 2808 / 2808 (100.0%) |
| b | oracle_cxx | 445 → 446 | 413 → 443 | 20 → 3 | 12 → 0 | 95.4% → 99.3% | 92.8% → 99.3% | 330 / 330 (100.0%) → 330 / 330 (100.0%) |
| b | sqlite | 12024 → 12012 | 11985 → 11979 | 0 → 0 | 39 → 33 | 100.0% → 100.0% | 99.7% → 99.7% | 11912 / 11912 (100.0%) → 11912 / 11912 (100.0%) |
| b | zstd | 17733 → 17257 | 17220 → 17237 | 485 → 4 | 28 → 16 | 97.3% → 100.0% | 97.1% → 99.9% | 17068 / 17068 (100.0%) → 17068 / 17068 (100.0%) |
| c (C) | lua | 13290 → 13670 | 10613 → 13272 | 2670 → 396 | 7 → 2 | 79.9% → 97.1% | 79.9% → 97.1% | 10499 / 14746 (71.2%) → 13123 / 14746 (89.0%) |
| c (C) | oracle_c | 1243 → 2956 | 970 → 2953 | 264 → 3 | 9 → 0 | 78.6% → 99.9% | 78.0% → 99.9% | 851 / 2808 (30.3%) → 2804 / 2808 (99.9%) |
| c (C) | sqlite | 8985 → 10580 | 8865 → 10545 | 120 → 34 | 0 → 1 | 98.7% → 99.7% | 98.7% → 99.7% | 8837 / 11912 (74.2%) → 10497 / 11912 (88.1%) |
| c (C) | zstd | 13068 → 16552 | 10850 → 16488 | 2211 → 62 | 7 → 2 | 83.1% → 99.6% | 83.0% → 99.6% | 10747 / 17068 (63.0%) → 16324 / 17068 (95.6%) |
| c (C++) | libfuzzer | 8107 → 8095 | 7978 → 7972 | 0 → 0 | 129 → 123 | 100.0% → 100.0% | 98.4% → 98.5% | 7908 / 7908 (100.0%) → 7908 / 7908 (100.0%) |
| c (C++) | oracle_cxx | 445 → 446 | 413 → 443 | 20 → 3 | 12 → 0 | 95.4% → 99.3% | 92.8% → 99.3% | 330 / 330 (100.0%) → 330 / 330 (100.0%) |
| d | libfuzzer | 7288 → 7317 | 7231 → 7308 | 50 → 8 | 7 → 1 | 99.3% → 99.9% | 99.2% → 99.9% | 7178 / 7626 (94.1%) → 7256 / 7626 (95.1%) |
| d | oracle_cxx | 140 → 445 | 116 → 442 | 23 → 3 | 1 → 0 | 83.5% → 99.3% | 82.9% → 99.3% | 48 / 330 (14.5%) → 330 / 330 (100.0%) |
*Before and after: per source, per variant x arch.*

| variant arch | source | produced | true | wrong | precision, strict | recall: DWARF fns |
|---|---|---|---|---|---|---|
| a aarch64 | unwind:eh_frame | 11513 → 11513 | 11513 → 11513 | 0 → 0 | 100.0% → 100.0% | 100.0% → 100.0% |
| a aarch64 | symbol | 0 → 11441 | 0 → 11441 | 0 → 0 | - → 100.0% | 0.0% → 100.0% |
| a aarch64 | after_declared_end | 11185 → 11196 | 11185 → 11196 | 0 → 0 | 100.0% → 100.0% | 97.2% → 97.2% |
| a aarch64 | gap_sweep | 6 → 0 | 3 → 0 | 3 → 0 | 50.0% → - | 0.0% → 0.0% |
| a aarch64 | call_target | 5879 → 5879 | 5879 → 5879 | 0 → 0 | 100.0% → 100.0% | 51.3% → 51.3% |
| a aarch64 | prologue | 3551 → 3551 | 3503 → 3551 | 48 → 0 | 98.6% → 100.0% | 30.5% → 30.5% |
| a i686 | unwind:eh_frame | 11895 → 11859 | 11857 → 11845 | 0 → 0 | 100.0% → 100.0% | 100.0% → 100.0% |
| a i686 | symbol | 0 → 11847 | 0 → 11833 | 0 → 0 | - → 100.0% | 0.0% → 100.0% |
| a i686 | after_declared_end | 11864 → 11860 | 10730 → 11848 | 1122 → 0 | 90.5% → 100.0% | 90.3% → 99.8% |
| a i686 | gap_sweep | 1218 → 120 | 72 → 120 | 1146 → 0 | 5.9% → 100.0% | 0.0% → 0.0% |
| a i686 | call_target | 6171 → 6171 | 6171 → 6171 | 0 → 0 | 100.0% → 100.0% | 51.1% → 51.1% |
| a x86_64 | unwind:eh_frame | 31949 → 31889 | 31743 → 31719 | 0 → 0 | 100.0% → 100.0% | 100.0% → 100.0% |
| a x86_64 | symbol | 0 → 31889 | 0 → 31719 | 0 → 0 | - → 100.0% | 0.0% → 100.0% |
| a x86_64 | after_declared_end | 31900 → 31859 | 31736 → 31695 | 0 → 0 | 100.0% → 100.0% | 99.9% → 99.9% |
| a x86_64 | gap_sweep | 144 → 144 | 144 → 144 | 0 → 0 | 100.0% → 100.0% | 0.0% → 0.0% |
| a x86_64 | call_target | 21275 → 21275 | 21275 → 21275 | 0 → 0 | 100.0% → 100.0% | 67.1% → 67.1% |
| a x86_64 | prologue | 9786 → 9786 | 9786 → 9786 | 0 → 0 | 100.0% → 100.0% | 30.5% → 30.5% |
| b aarch64 | unwind:eh_frame | 11513 → 11513 | 11513 → 11513 | 0 → 0 | 100.0% → 100.0% | 100.0% → 100.0% |
| b aarch64 | symbol | 0 → 4046 | 0 → 4046 | 0 → 0 | - → 100.0% | 0.0% → 35.4% |
| b aarch64 | after_declared_end | 11185 → 11185 | 11185 → 11185 | 0 → 0 | 100.0% → 100.0% | 97.2% → 97.2% |
| b aarch64 | gap_sweep | 6 → 36 | 3 → 22 | 3 → 14 | 50.0% → 61.1% | 0.0% → 0.0% |
| b aarch64 | call_target | 5879 → 5879 | 5879 → 5879 | 0 → 0 | 100.0% → 100.0% | 51.3% → 51.3% |
| b aarch64 | prologue | 3551 → 3551 | 3503 → 3551 | 48 → 0 | 98.6% → 100.0% | 30.5% → 30.5% |
| b i686 | unwind:eh_frame | 11895 → 11859 | 11857 → 11845 | 0 → 0 | 100.0% → 100.0% | 100.0% → 100.0% |
| b i686 | symbol | 0 → 4298 | 0 → 4298 | 0 → 0 | - → 100.0% | 0.0% → 36.5% |
| b i686 | after_declared_end | 11864 → 11836 | 10730 → 11824 | 1122 → 0 | 90.5% → 100.0% | 90.3% → 99.8% |
| b i686 | gap_sweep | 1218 → 144 | 72 → 144 | 1146 → 0 | 5.9% → 100.0% | 0.0% → 0.0% |
| b i686 | call_target | 6171 → 6171 | 6171 → 6171 | 0 → 0 | 100.0% → 100.0% | 51.1% → 51.1% |
| b x86_64 | unwind:eh_frame | 31949 → 31889 | 31743 → 31719 | 0 → 0 | 100.0% → 100.0% | 100.0% → 100.0% |
| b x86_64 | symbol | 0 → 6222 | 0 → 6222 | 0 → 0 | - → 100.0% | 0.0% → 19.6% |
| b x86_64 | after_declared_end | 31900 → 31859 | 31736 → 31695 | 0 → 0 | 100.0% → 100.0% | 99.9% → 99.9% |
| b x86_64 | gap_sweep | 144 → 144 | 144 → 144 | 0 → 0 | 100.0% → 100.0% | 0.0% → 0.0% |
| b x86_64 | call_target | 21275 → 21275 | 21275 → 21275 | 0 → 0 | 100.0% → 100.0% | 67.1% → 67.1% |
| b x86_64 | prologue | 9786 → 9786 | 9786 → 9786 | 0 → 0 | 100.0% → 100.0% | 30.5% → 30.5% |
| c (C) aarch64 | unwind:eh_frame | 84 → 84 | 84 → 84 | 0 → 0 | 100.0% → 100.0% | 0.1% → 0.1% |
| c (C) aarch64 | symbol | 0 → 3936 | 0 → 3936 | 0 → 0 | - → 100.0% | 0.0% → 34.7% |
| c (C) aarch64 | after_declared_end | 74 → 3755 | 74 → 3754 | 0 → 1 | 100.0% → 100.0% | 0.2% → 32.6% |
| c (C) aarch64 | gap_sweep | 35 → 1005 | 20 → 957 | 15 → 48 | 57.1% → 95.2% | 0.2% → 8.3% |
| c (C) aarch64 | call_target | 5873 → 5873 | 5873 → 5873 | 0 → 0 | 100.0% → 100.0% | 51.8% → 51.8% |
| c (C) aarch64 | prologue | 3896 → 3625 | 3493 → 3529 | 403 → 96 | 89.7% → 97.4% | 30.7% → 30.7% |
| c (C) i686 | unwind:eh_frame | 95 → 65 | 77 → 65 | 0 → 0 | 100.0% → 100.0% | 0.0% → 0.0% |
| c (C) i686 | symbol | 0 → 4188 | 0 → 4188 | 0 → 0 | - → 100.0% | 0.0% → 35.9% |
| c (C) i686 | after_declared_end | 69 → 4235 | 69 → 4235 | 0 → 0 | 100.0% → 100.0% | 0.0% → 35.6% |
| c (C) i686 | gap_sweep | 3222 → 3377 | 2827 → 3104 | 393 → 271 | 87.8% → 92.0% | 23.9% → 25.6% |
| c (C) i686 | call_target | 10373 → 6150 | 6150 → 6150 | 4223 → 0 | 59.3% → 100.0% | 51.6% → 51.6% |
| c (C) i686 | prologue | 4 → 2 | 0 → 0 | 4 → 2 | 0.0% → 0.0% | 0.0% → 0.0% |
| c (C) x86_64 | unwind:eh_frame | 6 → 3 | 3 → 3 | 0 → 0 | 100.0% → 100.0% | 0.0% → 0.0% |
| c (C) x86_64 | symbol | 0 → 5892 | 0 → 5892 | 0 → 0 | - → 100.0% | 0.0% → 24.9% |
| c (C) x86_64 | after_declared_end | 6 → 5887 | 6 → 5887 | 0 → 0 | 100.0% → 100.0% | 0.0% → 24.8% |
| c (C) x86_64 | gap_sweep | 180 → 4575 | 180 → 4538 | 0 → 34 | 100.0% → 99.3% | 0.7% → 18.8% |
| c (C) x86_64 | call_target | 14009 → 14009 | 14009 → 14009 | 0 → 0 | 100.0% → 100.0% | 59.2% → 59.2% |
| c (C) x86_64 | prologue | 6620 → 6437 | 6393 → 6393 | 227 → 44 | 96.6% → 99.3% | 26.7% → 26.7% |
| c (C++) aarch64 | unwind:eh_frame | 134 → 134 | 134 → 134 | 0 → 0 | 100.0% → 100.0% | 100.0% → 100.0% |
| c (C++) aarch64 | symbol | 0 → 110 | 0 → 110 | 0 → 0 | - → 100.0% | 0.0% → 100.0% |
| c (C++) aarch64 | after_declared_end | 105 → 105 | 105 → 105 | 0 → 0 | 100.0% → 100.0% | 78.2% → 78.2% |
| c (C++) aarch64 | gap_sweep | 0 → 9 | 0 → 6 | 0 → 3 | - → 66.7% | 0.0% → 0.0% |
| c (C++) aarch64 | call_target | 6 → 6 | 6 → 6 | 0 → 0 | 100.0% → 100.0% | 0.0% → 0.0% |
| c (C++) aarch64 | prologue | 22 → 22 | 10 → 22 | 12 → 0 | 45.5% → 100.0% | 3.6% → 3.6% |
| c (C++) i686 | unwind:eh_frame | 119 → 113 | 113 → 113 | 0 → 0 | 100.0% → 100.0% | 100.0% → 100.0% |
| c (C++) i686 | symbol | 0 → 110 | 0 → 110 | 0 → 0 | - → 100.0% | 0.0% → 100.0% |
| c (C++) i686 | after_declared_end | 114 → 108 | 112 → 108 | 2 → 0 | 98.2% → 100.0% | 92.7% → 94.5% |
| c (C++) i686 | gap_sweep | 26 → 36 | 18 → 36 | 8 → 0 | 69.2% → 100.0% | 0.0% → 0.0% |
| c (C++) i686 | call_target | 21 → 21 | 21 → 21 | 0 → 0 | 100.0% → 100.0% | 0.0% → 0.0% |
| c (C++) x86_64 | unwind:eh_frame | 8179 → 8161 | 8044 → 8038 | 0 → 0 | 100.0% → 100.0% | 99.8% → 99.8% |
| c (C++) x86_64 | symbol | 0 → 330 | 0 → 330 | 0 → 0 | - → 100.0% | 0.0% → 4.1% |
| c (C++) x86_64 | after_declared_end | 8162 → 8148 | 8042 → 8028 | 0 → 0 | 100.0% → 100.0% | 99.7% → 99.7% |
| c (C++) x86_64 | gap_sweep | 58 → 58 | 58 → 58 | 0 → 0 | 100.0% → 100.0% | 0.1% → 0.1% |
| c (C++) x86_64 | call_target | 7266 → 7266 | 7266 → 7266 | 0 → 0 | 100.0% → 100.0% | 90.3% → 90.3% |
| c (C++) x86_64 | prologue | 3393 → 3393 | 3393 → 3393 | 0 → 0 | 100.0% → 100.0% | 41.7% → 41.7% |
| d aarch64 | unwind:eh_frame | 24 → 24 | 24 → 24 | 0 → 0 | 100.0% → 100.0% | 0.0% → 0.0% |
| d aarch64 | symbol | 0 → 110 | 0 → 110 | 0 → 0 | - → 100.0% | 0.0% → 100.0% |
| d aarch64 | after_declared_end | 15 → 105 | 15 → 105 | 0 → 0 | 100.0% → 100.0% | 1.8% → 78.2% |
| d aarch64 | gap_sweep | 0 → 9 | 0 → 6 | 0 → 3 | - → 66.7% | 0.0% → 0.0% |
| d aarch64 | call_target | 6 → 6 | 6 → 6 | 0 → 0 | 100.0% → 100.0% | 0.0% → 0.0% |
| d aarch64 | prologue | 24 → 22 | 10 → 22 | 14 → 0 | 41.7% → 100.0% | 3.6% → 3.6% |
| d i686 | unwind:eh_frame | 2 → 1 | 1 → 1 | 0 → 0 | 100.0% → 100.0% | 0.0% → 0.0% |
| d i686 | symbol | 0 → 110 | 0 → 110 | 0 → 0 | - → 100.0% | 0.0% → 100.0% |
| d i686 | after_declared_end | 1 → 106 | 1 → 106 | 0 → 0 | 100.0% → 100.0% | 0.0% → 94.5% |
| d i686 | gap_sweep | 15 → 37 | 14 → 37 | 1 → 0 | 93.3% → 100.0% | 10.0% → 0.0% |
| d i686 | call_target | 28 → 20 | 20 → 20 | 8 → 0 | 71.4% → 100.0% | 0.0% → 0.0% |
| d x86_64 | unwind:eh_frame | 24 → 12 | 18 → 12 | 0 → 0 | 100.0% → 100.0% | 0.0% → 0.0% |
| d x86_64 | symbol | 0 → 328 | 0 → 328 | 0 → 0 | - → 100.0% | 0.0% → 4.2% |
| d x86_64 | after_declared_end | 14 → 329 | 14 → 329 | 0 → 0 | 100.0% → 100.0% | 0.0% → 4.2% |
| d x86_64 | gap_sweep | 3167 → 3280 | 3159 → 3279 | 7 → 0 | 99.8% → 100.0% | 40.5% → 41.7% |
| d x86_64 | call_target | 6983 → 6983 | 6983 → 6983 | 0 → 0 | 100.0% → 100.0% | 90.0% → 90.0% |
| d x86_64 | prologue | 3347 → 3312 | 3304 → 3304 | 43 → 8 | 98.7% → 99.8% | 42.1% → 42.1% |

**Starts, after.**

*Starts, per variant (each row its own; (b) is (a)'s code stripped, so no total counts both).*

| variant | runs | listed | true | wrong, strict (interior / outside) | fragment | plt0 | wrong, broad | precision, strict | precision, broad | recall: DWARF fns | recall: CRT fns | recall: PLT entries |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| a | 84 | 55670 | 55486 | 0 (0 / 0) | 184 | 0 | 184 | 100.0% | 99.7% | 54772 / 54772 (100.0%) | 714 / 785 (91.0%) | 0 / 9595 (0.0%) |
| b | 84 | 55682 | 55484 | 14 (14 / 0) | 184 | 0 | 198 | 100.0% | 99.6% | 54772 / 54772 (100.0%) | 712 / 785 (90.7%) | 0 / 9595 (0.0%) |
| c (C) | 60 | 43758 | 43258 | 495 (495 / 0) | 5 | 0 | 500 | 98.9% | 98.9% | 42748 / 46534 (91.9%) | 510 / 586 (87.0%) | 0 / 8584 (0.0%) |
| c (C++) | 24 | 8541 | 8415 | 3 (3 / 0) | 123 | 0 | 126 | 100.0% | 98.5% | 8238 / 8238 (100.0%) | 177 / 199 (88.9%) | 0 / 1011 (0.0%) |
| d | 24 | 7762 | 7750 | 11 (11 / 0) | 1 | 0 | 12 | 99.9% | 99.8% | 7586 / 7956 (95.3%) | 164 / 195 (84.1%) | 0 / 956 (0.0%) |
*Starts, per variant x codebase.*

| variant codebase | runs | listed | true | wrong, strict (interior / outside) | fragment | plt0 | wrong, broad | precision, strict | precision, broad | recall: DWARF fns | recall: CRT fns | recall: PLT entries |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| a libfuzzer | 6 | 8095 | 7972 | 0 (0 / 0) | 123 | 0 | 123 | 100.0% | 98.5% | 7908 / 7908 (100.0%) | 64 / 70 (91.4%) | 0 / 790 (0.0%) |
| a lua | 18 | 14909 | 14897 | 0 (0 / 0) | 12 | 0 | 12 | 100.0% | 99.9% | 14746 / 14746 (100.0%) | 151 / 167 (90.4%) | 0 / 3895 (0.0%) |
| a oracle_c | 18 | 2957 | 2957 | 0 (0 / 0) | 0 | 0 | 0 | 100.0% | 100.0% | 2808 / 2808 (100.0%) | 149 / 162 (92.0%) | 0 / 132 (0.0%) |
| a oracle_cxx | 18 | 443 | 443 | 0 (0 / 0) | 0 | 0 | 0 | 100.0% | 100.0% | 330 / 330 (100.0%) | 113 / 129 (87.6%) | 0 / 221 (0.0%) |
| a sqlite | 6 | 12012 | 11979 | 0 (0 / 0) | 33 | 0 | 33 | 100.0% | 99.7% | 11912 / 11912 (100.0%) | 67 / 70 (95.7%) | 0 / 884 (0.0%) |
| a zstd | 18 | 17254 | 17238 | 0 (0 / 0) | 16 | 0 | 16 | 100.0% | 99.9% | 17068 / 17068 (100.0%) | 170 / 187 (90.9%) | 0 / 3673 (0.0%) |
| b libfuzzer | 6 | 8095 | 7972 | 0 (0 / 0) | 123 | 0 | 123 | 100.0% | 98.5% | 7908 / 7908 (100.0%) | 64 / 70 (91.4%) | 0 / 790 (0.0%) |
| b lua | 18 | 14912 | 14896 | 4 (4 / 0) | 12 | 0 | 16 | 100.0% | 99.9% | 14746 / 14746 (100.0%) | 150 / 167 (89.8%) | 0 / 3895 (0.0%) |
| b oracle_c | 18 | 2960 | 2957 | 3 (3 / 0) | 0 | 0 | 3 | 99.9% | 99.9% | 2808 / 2808 (100.0%) | 149 / 162 (92.0%) | 0 / 132 (0.0%) |
| b oracle_cxx | 18 | 446 | 443 | 3 (3 / 0) | 0 | 0 | 3 | 99.3% | 99.3% | 330 / 330 (100.0%) | 113 / 129 (87.6%) | 0 / 221 (0.0%) |
| b sqlite | 6 | 12012 | 11979 | 0 (0 / 0) | 33 | 0 | 33 | 100.0% | 99.7% | 11912 / 11912 (100.0%) | 67 / 70 (95.7%) | 0 / 884 (0.0%) |
| b zstd | 18 | 17257 | 17237 | 4 (4 / 0) | 16 | 0 | 20 | 100.0% | 99.9% | 17068 / 17068 (100.0%) | 169 / 187 (90.4%) | 0 / 3673 (0.0%) |
| c (C) lua | 18 | 13670 | 13272 | 396 (396 / 0) | 2 | 0 | 398 | 97.1% | 97.1% | 13123 / 14746 (89.0%) | 149 / 167 (89.2%) | 0 / 3895 (0.0%) |
| c (C) oracle_c | 18 | 2956 | 2953 | 3 (3 / 0) | 0 | 0 | 3 | 99.9% | 99.9% | 2804 / 2808 (99.9%) | 149 / 162 (92.0%) | 0 / 132 (0.0%) |
| c (C) sqlite | 6 | 10580 | 10545 | 34 (34 / 0) | 1 | 0 | 35 | 99.7% | 99.7% | 10497 / 11912 (88.1%) | 48 / 70 (68.6%) | 0 / 884 (0.0%) |
| c (C) zstd | 18 | 16552 | 16488 | 62 (62 / 0) | 2 | 0 | 64 | 99.6% | 99.6% | 16324 / 17068 (95.6%) | 164 / 187 (87.7%) | 0 / 3673 (0.0%) |
| c (C++) libfuzzer | 6 | 8095 | 7972 | 0 (0 / 0) | 123 | 0 | 123 | 100.0% | 98.5% | 7908 / 7908 (100.0%) | 64 / 70 (91.4%) | 0 / 790 (0.0%) |
| c (C++) oracle_cxx | 18 | 446 | 443 | 3 (3 / 0) | 0 | 0 | 3 | 99.3% | 99.3% | 330 / 330 (100.0%) | 113 / 129 (87.6%) | 0 / 221 (0.0%) |
| d libfuzzer | 6 | 7317 | 7308 | 8 (8 / 0) | 1 | 0 | 9 | 99.9% | 99.9% | 7256 / 7626 (95.1%) | 52 / 67 (77.6%) | 0 / 742 (0.0%) |
| d oracle_cxx | 18 | 445 | 442 | 3 (3 / 0) | 0 | 0 | 3 | 99.3% | 99.3% | 330 / 330 (100.0%) | 112 / 128 (87.5%) | 0 / 214 (0.0%) |
*Start sources, per variant ((b) is (a)'s code stripped, left out).*

Precision, strict = true / (true + wrong), where a fragment or a PLT header is neither; broad counts both as wrong. Recall = the DWARF functions this source found, of all the DWARF functions in the row. `alone`: the starts this source alone produced.

| variant | source | produced | true | wrong | fragment | plt0 | precision, strict | precision, broad | recall: DWARF fns | alone produced | alone true | alone wrong |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| a | unwind:eh_frame | 55261 | 55077 | 0 | 184 | 0 | 100.0% | 99.7% | 54772 / 54772 (100.0%) | 13 | 13 | 0 |
| a | symbol | 55177 | 54993 | 0 | 184 | 0 | 100.0% | 99.7% | 54772 / 54772 (100.0%) | 21 | 21 | 0 |
| a | after_declared_end | 54915 | 54739 | 0 | 176 | 0 | 100.0% | 99.7% | 54386 / 54772 (99.3%) | 8 | 8 | 0 |
| a | gap_sweep | 264 | 264 | 0 | 0 | 0 | 100.0% | 100.0% | 0 / 54772 (0.0%) | 108 | 108 | 0 |
| a | call_target | 33325 | 33325 | 0 | 0 | 0 | 100.0% | 100.0% | 33076 / 54772 (60.4%) | 0 | 0 | 0 |
| a | prologue | 13337 | 13337 | 0 | 0 | 0 | 100.0% | 100.0% | 13126 / 54772 (24.0%) | 64 | 64 | 0 |
| c (C) | unwind:eh_frame | 152 | 152 | 0 | 0 | 0 | 100.0% | 100.0% | 12 / 46534 (0.0%) | 8 | 8 | 0 |
| c (C) | symbol | 14016 | 14016 | 0 | 0 | 0 | 100.0% | 100.0% | 13976 / 46534 (30.0%) | 2428 | 2428 | 0 |
| c (C) | after_declared_end | 13877 | 13876 | 1 | 0 | 0 | 100.0% | 100.0% | 13691 / 46534 (29.4%) | 10 | 10 | 0 |
| c (C) | gap_sweep | 8957 | 8599 | 353 | 5 | 0 | 96.1% | 96.0% | 8361 / 46534 (18.0%) | 1477 | 1120 | 352 |
| c (C) | call_target | 26032 | 26032 | 0 | 0 | 0 | 100.0% | 100.0% | 25834 / 46534 (55.5%) | 15075 | 15075 | 0 |
| c (C) | prologue | 10064 | 9922 | 142 | 0 | 0 | 98.6% | 98.6% | 9780 / 46534 (21.0%) | 1452 | 1310 | 142 |
| c (C++) | unwind:eh_frame | 8408 | 8285 | 0 | 123 | 0 | 100.0% | 98.5% | 8224 / 8238 (99.8%) | 15 | 12 | 0 |
| c (C++) | symbol | 550 | 550 | 0 | 0 | 0 | 100.0% | 100.0% | 550 / 8238 (6.7%) | 0 | 0 | 0 |
| c (C++) | after_declared_end | 8361 | 8241 | 0 | 120 | 0 | 100.0% | 98.6% | 8181 / 8238 (99.3%) | 2 | 2 | 0 |
| c (C++) | gap_sweep | 103 | 100 | 3 | 0 | 0 | 97.1% | 97.1% | 10 / 8238 (0.1%) | 39 | 36 | 3 |
| c (C++) | call_target | 7293 | 7293 | 0 | 0 | 0 | 100.0% | 100.0% | 7242 / 8238 (87.9%) | 4 | 4 | 0 |
| c (C++) | prologue | 3415 | 3415 | 0 | 0 | 0 | 100.0% | 100.0% | 3346 / 8238 (40.6%) | 18 | 18 | 0 |
| d | unwind:eh_frame | 37 | 37 | 0 | 0 | 0 | 100.0% | 100.0% | 0 / 7956 (0.0%) | 5 | 5 | 0 |
| d | symbol | 548 | 548 | 0 | 0 | 0 | 100.0% | 100.0% | 548 / 7956 (6.9%) | 41 | 41 | 0 |
| d | after_declared_end | 540 | 540 | 0 | 0 | 0 | 100.0% | 100.0% | 512 / 7956 (6.4%) | 2 | 2 | 0 |
| d | gap_sweep | 3326 | 3322 | 3 | 1 | 0 | 99.9% | 99.9% | 3223 / 7956 (40.5%) | 190 | 186 | 3 |
| d | call_target | 7009 | 7009 | 0 | 0 | 0 | 100.0% | 100.0% | 6962 / 7956 (87.5%) | 2692 | 2692 | 0 |
| d | prologue | 3334 | 3326 | 8 | 0 | 0 | 99.8% | 99.8% | 3258 / 7956 (41.0%) | 69 | 61 | 8 |
*Start sources, per variant x codebase.*

Precision, strict = true / (true + wrong), where a fragment or a PLT header is neither; broad counts both as wrong. Recall = the DWARF functions this source found, of all the DWARF functions in the row. `alone`: the starts this source alone produced.

| variant codebase | source | produced | true | wrong | fragment | plt0 | precision, strict | precision, broad | recall: DWARF fns | alone produced | alone true | alone wrong |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| a libfuzzer | unwind:eh_frame | 8065 | 7942 | 0 | 123 | 0 | 100.0% | 98.5% | 7908 / 7908 (100.0%) | 0 | 0 | 0 |
| a libfuzzer | symbol | 8065 | 7942 | 0 | 123 | 0 | 100.0% | 98.5% | 7908 / 7908 (100.0%) | 0 | 0 | 0 |
| a libfuzzer | after_declared_end | 8057 | 7937 | 0 | 120 | 0 | 100.0% | 98.5% | 7898 / 7908 (99.9%) | 0 | 0 | 0 |
| a libfuzzer | gap_sweep | 24 | 24 | 0 | 0 | 0 | 100.0% | 100.0% | 0 / 7908 (0.0%) | 6 | 6 | 0 |
| a libfuzzer | call_target | 7260 | 7260 | 0 | 0 | 0 | 100.0% | 100.0% | 7242 / 7908 (91.6%) | 0 | 0 | 0 |
| a libfuzzer | prologue | 3342 | 3342 | 0 | 0 | 0 | 100.0% | 100.0% | 3309 / 7908 (41.8%) | 6 | 6 | 0 |
| a lua | unwind:eh_frame | 14823 | 14811 | 0 | 12 | 0 | 100.0% | 99.9% | 14746 / 14746 (100.0%) | 3 | 3 | 0 |
| a lua | symbol | 14799 | 14787 | 0 | 12 | 0 | 100.0% | 99.9% | 14746 / 14746 (100.0%) | 6 | 6 | 0 |
| a lua | after_declared_end | 14779 | 14769 | 0 | 10 | 0 | 100.0% | 99.9% | 14691 / 14746 (99.6%) | 1 | 1 | 0 |
| a lua | gap_sweep | 54 | 54 | 0 | 0 | 0 | 100.0% | 100.0% | 0 / 14746 (0.0%) | 24 | 24 | 0 |
| a lua | call_target | 8691 | 8691 | 0 | 0 | 0 | 100.0% | 100.0% | 8620 / 14746 (58.5%) | 0 | 0 | 0 |
| a lua | prologue | 3656 | 3656 | 0 | 0 | 0 | 100.0% | 100.0% | 3619 / 14746 (24.5%) | 13 | 13 | 0 |
| a oracle_c | unwind:eh_frame | 2868 | 2868 | 0 | 0 | 0 | 100.0% | 100.0% | 2808 / 2808 (100.0%) | 3 | 3 | 0 |
| a oracle_c | symbol | 2847 | 2847 | 0 | 0 | 0 | 100.0% | 100.0% | 2808 / 2808 (100.0%) | 3 | 3 | 0 |
| a oracle_c | after_declared_end | 2720 | 2720 | 0 | 0 | 0 | 100.0% | 100.0% | 2648 / 2808 (94.3%) | 3 | 3 | 0 |
| a oracle_c | gap_sweep | 54 | 54 | 0 | 0 | 0 | 100.0% | 100.0% | 0 / 2808 (0.0%) | 24 | 24 | 0 |
| a oracle_c | call_target | 204 | 204 | 0 | 0 | 0 | 100.0% | 100.0% | 138 / 2808 (4.9%) | 0 | 0 | 0 |
| a oracle_c | prologue | 303 | 303 | 0 | 0 | 0 | 100.0% | 100.0% | 262 / 2808 (9.3%) | 14 | 14 | 0 |
| a oracle_cxx | unwind:eh_frame | 357 | 357 | 0 | 0 | 0 | 100.0% | 100.0% | 330 / 330 (100.0%) | 5 | 5 | 0 |
| a oracle_cxx | symbol | 343 | 343 | 0 | 0 | 0 | 100.0% | 100.0% | 330 / 330 (100.0%) | 6 | 6 | 0 |
| a oracle_cxx | after_declared_end | 325 | 325 | 0 | 0 | 0 | 100.0% | 100.0% | 294 / 330 (89.1%) | 2 | 2 | 0 |
| a oracle_cxx | gap_sweep | 54 | 54 | 0 | 0 | 0 | 100.0% | 100.0% | 0 / 330 (0.0%) | 24 | 24 | 0 |
| a oracle_cxx | call_target | 33 | 33 | 0 | 0 | 0 | 100.0% | 100.0% | 0 / 330 (0.0%) | 0 | 0 | 0 |
| a oracle_cxx | prologue | 73 | 73 | 0 | 0 | 0 | 100.0% | 100.0% | 37 / 330 (11.2%) | 12 | 12 | 0 |
| a sqlite | unwind:eh_frame | 11979 | 11946 | 0 | 33 | 0 | 100.0% | 99.7% | 11912 / 11912 (100.0%) | 0 | 0 | 0 |
| a sqlite | symbol | 11979 | 11946 | 0 | 33 | 0 | 100.0% | 99.7% | 11912 / 11912 (100.0%) | 0 | 0 | 0 |
| a sqlite | after_declared_end | 11975 | 11943 | 0 | 32 | 0 | 100.0% | 99.7% | 11906 / 11912 (99.9%) | 1 | 1 | 0 |
| a sqlite | gap_sweep | 24 | 24 | 0 | 0 | 0 | 100.0% | 100.0% | 0 / 11912 (0.0%) | 6 | 6 | 0 |
| a sqlite | call_target | 8074 | 8074 | 0 | 0 | 0 | 100.0% | 100.0% | 8068 / 11912 (67.7%) | 0 | 0 | 0 |
| a sqlite | prologue | 3185 | 3185 | 0 | 0 | 0 | 100.0% | 100.0% | 3163 / 11912 (26.6%) | 7 | 7 | 0 |
| a zstd | unwind:eh_frame | 17169 | 17153 | 0 | 16 | 0 | 100.0% | 99.9% | 17068 / 17068 (100.0%) | 2 | 2 | 0 |
| a zstd | symbol | 17144 | 17128 | 0 | 16 | 0 | 100.0% | 99.9% | 17068 / 17068 (100.0%) | 6 | 6 | 0 |
| a zstd | after_declared_end | 17059 | 17045 | 0 | 14 | 0 | 100.0% | 99.9% | 16949 / 17068 (99.3%) | 1 | 1 | 0 |
| a zstd | gap_sweep | 54 | 54 | 0 | 0 | 0 | 100.0% | 100.0% | 0 / 17068 (0.0%) | 24 | 24 | 0 |
| a zstd | call_target | 9063 | 9063 | 0 | 0 | 0 | 100.0% | 100.0% | 9008 / 17068 (52.8%) | 0 | 0 | 0 |
| a zstd | prologue | 2778 | 2778 | 0 | 0 | 0 | 100.0% | 100.0% | 2736 / 17068 (16.0%) | 12 | 12 | 0 |
| c (C) lua | unwind:eh_frame | 53 | 53 | 0 | 0 | 0 | 100.0% | 100.0% | 0 / 14746 (0.0%) | 3 | 3 | 0 |
| c (C) lua | symbol | 2772 | 2772 | 0 | 0 | 0 | 100.0% | 100.0% | 2772 / 14746 (18.8%) | 423 | 423 | 0 |
| c (C) lua | after_declared_end | 2788 | 2788 | 0 | 0 | 0 | 100.0% | 100.0% | 2745 / 14746 (18.6%) | 5 | 5 | 0 |
| c (C) lua | gap_sweep | 3497 | 3186 | 309 | 2 | 0 | 91.2% | 91.1% | 3122 / 14746 (21.2%) | 996 | 685 | 309 |
| c (C) lua | call_target | 8691 | 8691 | 0 | 0 | 0 | 100.0% | 100.0% | 8620 / 14746 (58.5%) | 5116 | 5116 | 0 |
| c (C) lua | prologue | 3743 | 3656 | 87 | 0 | 0 | 97.7% | 97.7% | 3619 / 14746 (24.5%) | 831 | 744 | 87 |
| c (C) oracle_c | unwind:eh_frame | 63 | 63 | 0 | 0 | 0 | 100.0% | 100.0% | 12 / 2808 (0.4%) | 3 | 3 | 0 |
| c (C) oracle_c | symbol | 2652 | 2652 | 0 | 0 | 0 | 100.0% | 100.0% | 2652 / 2808 (94.4%) | 223 | 223 | 0 |
| c (C) oracle_c | after_declared_end | 2562 | 2562 | 0 | 0 | 0 | 100.0% | 100.0% | 2501 / 2808 (89.1%) | 3 | 3 | 0 |
| c (C) oracle_c | gap_sweep | 182 | 179 | 3 | 0 | 0 | 98.4% | 98.4% | 106 / 2808 (3.8%) | 32 | 29 | 3 |
| c (C) oracle_c | call_target | 204 | 204 | 0 | 0 | 0 | 100.0% | 100.0% | 138 / 2808 (4.9%) | 28 | 28 | 0 |
| c (C) oracle_c | prologue | 303 | 303 | 0 | 0 | 0 | 100.0% | 100.0% | 262 / 2808 (9.3%) | 14 | 14 | 0 |
| c (C) sqlite | symbol | 1644 | 1644 | 0 | 0 | 0 | 100.0% | 100.0% | 1640 / 11912 (13.8%) | 395 | 395 | 0 |
| c (C) sqlite | after_declared_end | 1642 | 1642 | 0 | 0 | 0 | 100.0% | 100.0% | 1638 / 11912 (13.8%) | 2 | 2 | 0 |
| c (C) sqlite | gap_sweep | 1701 | 1696 | 4 | 1 | 0 | 99.8% | 99.7% | 1663 / 11912 (14.0%) | 278 | 273 | 4 |
| c (C) sqlite | call_target | 8074 | 8074 | 0 | 0 | 0 | 100.0% | 100.0% | 8068 / 11912 (67.7%) | 4852 | 4852 | 0 |
| c (C) sqlite | prologue | 3215 | 3185 | 30 | 0 | 0 | 99.1% | 99.1% | 3163 / 11912 (26.6%) | 393 | 363 | 30 |
| c (C) zstd | unwind:eh_frame | 36 | 36 | 0 | 0 | 0 | 100.0% | 100.0% | 0 / 17068 (0.0%) | 2 | 2 | 0 |
| c (C) zstd | symbol | 6948 | 6948 | 0 | 0 | 0 | 100.0% | 100.0% | 6912 / 17068 (40.5%) | 1387 | 1387 | 0 |
| c (C) zstd | after_declared_end | 6885 | 6884 | 1 | 0 | 0 | 100.0% | 100.0% | 6807 / 17068 (39.9%) | 0 | 0 | 0 |
| c (C) zstd | gap_sweep | 3577 | 3538 | 37 | 2 | 0 | 99.0% | 98.9% | 3470 / 17068 (20.3%) | 171 | 133 | 36 |
| c (C) zstd | call_target | 9063 | 9063 | 0 | 0 | 0 | 100.0% | 100.0% | 9008 / 17068 (52.8%) | 5079 | 5079 | 0 |
| c (C) zstd | prologue | 2803 | 2778 | 25 | 0 | 0 | 99.1% | 99.1% | 2736 / 17068 (16.0%) | 214 | 189 | 25 |
| c (C++) libfuzzer | unwind:eh_frame | 8051 | 7928 | 0 | 123 | 0 | 100.0% | 98.5% | 7894 / 7908 (99.8%) | 10 | 7 | 0 |
| c (C++) libfuzzer | symbol | 220 | 220 | 0 | 0 | 0 | 100.0% | 100.0% | 220 / 7908 (2.8%) | 0 | 0 | 0 |
| c (C++) libfuzzer | after_declared_end | 8043 | 7923 | 0 | 120 | 0 | 100.0% | 98.5% | 7887 / 7908 (99.7%) | 0 | 0 | 0 |
| c (C++) libfuzzer | gap_sweep | 34 | 34 | 0 | 0 | 0 | 100.0% | 100.0% | 10 / 7908 (0.1%) | 6 | 6 | 0 |
| c (C++) libfuzzer | call_target | 7260 | 7260 | 0 | 0 | 0 | 100.0% | 100.0% | 7242 / 7908 (91.6%) | 4 | 4 | 0 |
| c (C++) libfuzzer | prologue | 3342 | 3342 | 0 | 0 | 0 | 100.0% | 100.0% | 3309 / 7908 (41.8%) | 6 | 6 | 0 |
| c (C++) oracle_cxx | unwind:eh_frame | 357 | 357 | 0 | 0 | 0 | 100.0% | 100.0% | 330 / 330 (100.0%) | 5 | 5 | 0 |
| c (C++) oracle_cxx | symbol | 330 | 330 | 0 | 0 | 0 | 100.0% | 100.0% | 330 / 330 (100.0%) | 0 | 0 | 0 |
| c (C++) oracle_cxx | after_declared_end | 318 | 318 | 0 | 0 | 0 | 100.0% | 100.0% | 294 / 330 (89.1%) | 2 | 2 | 0 |
| c (C++) oracle_cxx | gap_sweep | 69 | 66 | 3 | 0 | 0 | 95.7% | 95.7% | 0 / 330 (0.0%) | 33 | 30 | 3 |
| c (C++) oracle_cxx | call_target | 33 | 33 | 0 | 0 | 0 | 100.0% | 100.0% | 0 / 330 (0.0%) | 0 | 0 | 0 |
| c (C++) oracle_cxx | prologue | 73 | 73 | 0 | 0 | 0 | 100.0% | 100.0% | 37 / 330 (11.2%) | 12 | 12 | 0 |
| d libfuzzer | unwind:eh_frame | 12 | 12 | 0 | 0 | 0 | 100.0% | 100.0% | 0 / 7626 (0.0%) | 0 | 0 | 0 |
| d libfuzzer | symbol | 218 | 218 | 0 | 0 | 0 | 100.0% | 100.0% | 218 / 7626 (2.9%) | 6 | 6 | 0 |
| d libfuzzer | after_declared_end | 224 | 224 | 0 | 0 | 0 | 100.0% | 100.0% | 218 / 7626 (2.9%) | 0 | 0 | 0 |
| d libfuzzer | gap_sweep | 3256 | 3255 | 0 | 1 | 0 | 100.0% | 100.0% | 3223 / 7626 (42.3%) | 157 | 156 | 0 |
| d libfuzzer | call_target | 6977 | 6977 | 0 | 0 | 0 | 100.0% | 100.0% | 6962 / 7626 (91.3%) | 2692 | 2692 | 0 |
| d libfuzzer | prologue | 3263 | 3255 | 8 | 0 | 0 | 99.8% | 99.8% | 3223 / 7626 (42.3%) | 57 | 49 | 8 |
| d oracle_cxx | unwind:eh_frame | 25 | 25 | 0 | 0 | 0 | 100.0% | 100.0% | 0 / 330 (0.0%) | 5 | 5 | 0 |
| d oracle_cxx | symbol | 330 | 330 | 0 | 0 | 0 | 100.0% | 100.0% | 330 / 330 (100.0%) | 35 | 35 | 0 |
| d oracle_cxx | after_declared_end | 316 | 316 | 0 | 0 | 0 | 100.0% | 100.0% | 294 / 330 (89.1%) | 2 | 2 | 0 |
| d oracle_cxx | gap_sweep | 70 | 67 | 3 | 0 | 0 | 95.7% | 95.7% | 0 / 330 (0.0%) | 33 | 30 | 3 |
| d oracle_cxx | call_target | 32 | 32 | 0 | 0 | 0 | 100.0% | 100.0% | 0 / 330 (0.0%) | 0 | 0 | 0 |
| d oracle_cxx | prologue | 71 | 71 | 0 | 0 | 0 | 100.0% | 100.0% | 35 / 330 (10.6%) | 12 | 12 | 0 |

The spec's table, per variant x compiler x level (every source that fired; `export`, `pdb`, `body`
and `stub` produced no start on any image here, so they have no rate):

*Per variant x compiler x level: true / produced per start source.*

| variant | cc | -O | unwind:eh_frame | symbol | after_declared_end | gap_sweep | call_target | prologue | wrong starts | DWARF functions found |
|---|---|---|---|---|---|---|---|---|---|---|
| a | clang | O0 | 13713 / 13713 | 13705 / 13705 | 13704 / 13704 | 44 / 44 | 10275 / 10275 | 8464 / 8464 | 0 | 13684 / 13684 |
| a | clang | O2 | 6132 / 6132 | 6124 / 6124 | 6065 / 6065 | 44 / 44 | 2600 / 2600 | 474 / 474 | 0 | 6103 / 6103 |
| a | clang | Os | 6857 / 6857 | 6849 / 6849 | 6788 / 6788 | 44 / 44 | 3283 / 3283 | 522 / 522 | 0 | 6827 / 6827 |
| a | gcc | O0 | 14559 / 14559 | 14540 / 14540 | 14544 / 14544 | 44 / 44 | 10576 / 10576 | 1984 / 1984 | 0 | 14514 / 14514 |
| a | gcc | O2 | 6392 / 6576 | 6371 / 6555 | 6311 / 6487 | 44 / 44 | 2801 / 2801 | 1247 / 1247 | 0 | 6306 / 6306 |
| a | gcc | Os | 7424 / 7424 | 7404 / 7404 | 7327 / 7327 | 44 / 44 | 3790 / 3790 | 646 / 646 | 0 | 7338 / 7338 |
| c (C) | clang | O0 | 22 / 22 | 2336 / 2336 | 2350 / 2350 | 3566 / 3567 | 7449 / 7449 | 5515 / 5515 | 1 | 10460 / 10688 |
| c (C) | clang | O2 | 22 / 22 | 2336 / 2336 | 2300 / 2300 | 937 / 973 | 2267 / 2267 | 458 / 472 | 50 | 5069 / 5626 |
| c (C) | clang | Os | 23 / 23 | 2336 / 2336 | 2302 / 2302 | 614 / 658 | 2778 / 2778 | 511 / 534 | 67 | 5364 / 6167 |
| c (C) | gcc | O0 | 28 / 28 | 2336 / 2336 | 2351 / 2352 | 627 / 705 | 7749 / 7749 | 1668 / 1668 | 78 | 10368 / 11519 |
| c (C) | gcc | O2 | 28 / 28 | 2336 / 2336 | 2289 / 2289 | 2056 / 2166 | 2460 / 2460 | 1137 / 1218 | 186 | 5551 / 5809 |
| c (C) | gcc | Os | 29 / 29 | 2336 / 2336 | 2284 / 2284 | 799 / 888 | 3329 / 3329 | 633 / 657 | 113 | 5936 / 6725 |
| c (C++) | clang | O0 | 3001 / 3001 | 179 / 179 | 2998 / 2998 | 19 / 19 | 2826 / 2826 | 2949 / 2949 | 0 | 2996 / 2996 |
| c (C++) | clang | O2 | 481 / 481 | 42 / 42 | 474 / 474 | 18 / 18 | 333 / 333 | 16 / 16 | 0 | 477 / 477 |
| c (C++) | clang | Os | 664 / 664 | 44 / 44 | 657 / 657 | 18 / 18 | 505 / 505 | 11 / 11 | 0 | 660 / 660 |
| c (C++) | gcc | O0 | 3005 / 3005 | 179 / 179 | 3000 / 3000 | 15 / 16 | 2827 / 2827 | 316 / 316 | 1 | 2995 / 2995 |
| c (C++) | gcc | O2 | 509 / 632 | 54 / 54 | 498 / 618 | 15 / 16 | 341 / 341 | 110 / 110 | 1 | 497 / 497 |
| c (C++) | gcc | Os | 625 / 625 | 52 / 52 | 614 / 614 | 15 / 16 | 461 / 461 | 13 / 13 | 1 | 613 / 613 |
| d | clang | O0 | 6 / 6 | 179 / 179 | 182 / 182 | 1859 / 1859 | 2751 / 2751 | 2871 / 2871 | 0 | 2922 / 2922 |
| d | clang | O2 | 6 / 6 | 42 / 42 | 41 / 41 | 115 / 115 | 299 / 299 | 16 / 16 | 0 | 372 / 445 |
| d | clang | Os | 6 / 6 | 44 / 44 | 43 / 43 | 81 / 81 | 457 / 457 | 12 / 12 | 0 | 509 / 613 |
| d | gcc | O0 | 7 / 7 | 179 / 179 | 181 / 181 | 992 / 993 | 2751 / 2751 | 312 / 313 | 2 | 2863 / 2920 |
| d | gcc | O2 | 6 / 6 | 52 / 52 | 46 / 46 | 165 / 167 | 310 / 310 | 102 / 109 | 8 | 417 / 467 |
| d | gcc | Os | 6 / 6 | 52 / 52 | 47 / 47 | 110 / 111 | 441 / 441 | 13 / 13 | 1 | 503 / 589 |
*Starts, per variant x arch.*

| variant arch | runs | listed | true | wrong, strict (interior / outside) | fragment | plt0 | wrong, broad | precision, strict | precision, broad | recall: DWARF fns | recall: CRT fns | recall: PLT entries |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| a aarch64 | 24 | 11585 | 11585 | 0 (0 / 0) | 0 | 0 | 0 | 100.0% | 100.0% | 11405 / 11405 (100.0%) | 180 / 180 (100.0%) | 0 / 2671 (0.0%) |
| a i686 | 24 | 12004 | 11990 | 0 (0 / 0) | 14 | 0 | 14 | 100.0% | 99.9% | 11731 / 11731 (100.0%) | 259 / 306 (84.6%) | 0 / 2621 (0.0%) |
| a x86_64 | 36 | 32081 | 31911 | 0 (0 / 0) | 170 | 0 | 170 | 100.0% | 99.5% | 31636 / 31636 (100.0%) | 275 / 299 (92.0%) | 0 / 4303 (0.0%) |
| c (C) aarch64 | 18 | 11009 | 10865 | 144 (144 / 0) | 0 | 0 | 144 | 98.7% | 98.7% | 10729 / 11295 (95.0%) | 136 / 138 (98.6%) | 0 / 2589 (0.0%) |
| c (C) i686 | 18 | 11194 | 10919 | 273 (273 / 0) | 2 | 0 | 275 | 97.6% | 97.5% | 10703 / 11621 (92.1%) | 216 / 255 (84.7%) | 0 / 2552 (0.0%) |
| c (C) x86_64 | 24 | 21555 | 21474 | 78 (78 / 0) | 3 | 0 | 81 | 99.6% | 99.6% | 21316 / 23618 (90.3%) | 158 / 193 (81.9%) | 0 / 3443 (0.0%) |
| c (C++) aarch64 | 6 | 155 | 152 | 3 (3 / 0) | 0 | 0 | 3 | 98.1% | 98.1% | 110 / 110 (100.0%) | 42 / 42 (100.0%) | 0 / 82 (0.0%) |
| c (C++) i686 | 6 | 150 | 150 | 0 (0 / 0) | 0 | 0 | 0 | 100.0% | 100.0% | 110 / 110 (100.0%) | 40 / 51 (78.4%) | 0 / 69 (0.0%) |
| c (C++) x86_64 | 12 | 8236 | 8113 | 0 (0 / 0) | 123 | 0 | 123 | 100.0% | 98.5% | 8018 / 8018 (100.0%) | 95 / 106 (89.6%) | 0 / 860 (0.0%) |
| d aarch64 | 6 | 155 | 152 | 3 (3 / 0) | 0 | 0 | 3 | 98.1% | 98.1% | 110 / 110 (100.0%) | 42 / 42 (100.0%) | 0 / 79 (0.0%) |
| d i686 | 6 | 149 | 149 | 0 (0 / 0) | 0 | 0 | 0 | 100.0% | 100.0% | 110 / 110 (100.0%) | 39 / 50 (78.0%) | 0 / 67 (0.0%) |
| d x86_64 | 12 | 7458 | 7449 | 8 (8 / 0) | 1 | 0 | 9 | 99.9% | 99.9% | 7366 / 7736 (95.2%) | 83 / 103 (80.6%) | 0 / 810 (0.0%) |

**Ends,** for true starts and fragments, against the truth extent. `not_stated` is the end
`why` gives where nothing states one: the control-flow graph's. `not_stated(cut)` is a graph cut
by its window, which states no end: an absence, counted apart from right and wrong.

*Ends, per variant.*

| variant | start class / end source | exact | short | long | between | no end | no truth end |
|---|---|---|---|---|---|---|---|
| a | fragment: symbol_size:st_size | 184 | 0 | 0 | 0 | 0 | 0 |
| a | true: not_stated | 0 | 0 | 0 | 0 | 0 | 361 |
| a | true: symbol_size:st_size | 54993 | 0 | 0 | 0 | 0 | 0 |
| a | true: unwind:eh_frame | 0 | 0 | 0 | 0 | 0 | 132 |
| b | fragment: unwind:eh_frame | 184 | 0 | 0 | 0 | 0 | 0 |
| b | true: not_stated | 46 | 0 | 0 | 0 | 0 | 361 |
| b | true: symbol_size:st_size | 14566 | 0 | 0 | 0 | 0 | 0 |
| b | true: unwind:eh_frame | 40379 | 0 | 0 | 0 | 0 | 132 |
| c (C) | fragment: not_stated | 2 | 0 | 3 | 0 | 0 | 0 |
| c (C) | true: not_stated | 26121 | 284 | 1657 | 0 | 0 | 283 |
| c (C) | true: not_stated(cut) | 0 | 0 | 0 | 0 | 745 | 0 |
| c (C) | true: symbol_size:st_size | 14016 | 0 | 0 | 0 | 0 | 0 |
| c (C) | true: unwind:eh_frame | 80 | 0 | 0 | 0 | 0 | 72 |
| c (C++) | fragment: unwind:eh_frame | 123 | 0 | 0 | 0 | 0 | 0 |
| c (C++) | true: not_stated | 26 | 0 | 0 | 0 | 0 | 104 |
| c (C++) | true: symbol_size:st_size | 550 | 0 | 0 | 0 | 0 | 0 |
| c (C++) | true: unwind:eh_frame | 7709 | 0 | 0 | 0 | 0 | 26 |
| d | fragment: not_stated | 1 | 0 | 0 | 0 | 0 | 0 |
| d | true: not_stated | 6994 | 3 | 39 | 0 | 0 | 105 |
| d | true: not_stated(cut) | 0 | 0 | 0 | 0 | 24 | 0 |
| d | true: symbol_size:st_size | 548 | 0 | 0 | 0 | 0 | 0 |
| d | true: unwind:eh_frame | 13 | 0 | 0 | 0 | 0 | 24 |

**Names,** per layer. `exact`: the table's text or a demangler's reading of it. `spelled`: the
same identity in another spelling — an undemangled name with `.` as `_` (`luaD_throw_cold`), a
stub named after its import without `@plt`, a demangled name that differs from a demangler's
reading only in how an integer template argument is written (`(unsigned long)0` for `0ul`) or
in `> >`. `fallback_where_named`: `sub_…` where the table has a name, an absence, not a wrong name.

*Names, per variant.*

| variant | layer | exact | spelled | wrong | named_where_unnamed | fallback_where_named | fallback_unnamed |
|---|---|---|---|---|---|---|---|
| a | image:static | 53919 | 1424 | 327 | 0 | 0 | 0 |
| b | fallback | 0 | 0 | 0 | 0 | 41102 | 14 |
| b | image:dynamic | 14566 | 0 | 0 | 0 | 0 | 0 |
| c (C) | fallback | 0 | 0 | 0 | 0 | 29307 | 435 |
| c (C) | image:dynamic | 14016 | 0 | 0 | 0 | 0 | 0 |
| c (C++) | fallback | 0 | 0 | 0 | 0 | 7988 | 3 |
| c (C++) | image:dynamic | 550 | 0 | 0 | 0 | 0 | 0 |
| d | fallback | 0 | 0 | 0 | 0 | 7203 | 11 |
| d | image:dynamic | 548 | 0 | 0 | 0 | 0 | 0 |

**The direction.** Of the wrong starts, how many carry only heuristic sources and how many any
declared one, beside each kind's base; of the wrong ends, `not_stated` against a declared end.

*The direction, per variant (strict: a wrong start is interior or outside).*

| variant | wrong starts: heuristic only | wrong starts: any declared | heuristic-only starts wrong | declared starts wrong | wrong ends: heuristic (`not_stated`) | wrong ends: declared | heuristic ends wrong | declared ends wrong | heuristic ends cut (no end stated) |
|---|---|---|---|---|---|---|---|---|---|
| a | 0 | 0 | 0 / 361 (0.0%) | 0 / 55309 (0.0%) | 0 | 0 | 0 / 0 (-) | 0 / 54993 (0.0%) | 0 |
| b | 14 | 0 | 14 / 421 (3.3%) | 0 / 55261 (0.0%) | 0 | 0 | 0 / 46 (0.0%) | 0 / 54945 (0.0%) | 0 |
| c (C) | 495 | 0 | 495 / 29590 (1.7%) | 0 / 14168 (0.0%) | 1941 | 0 | 1941 / 28062 (6.9%) | 0 / 14096 (0.0%) | 745 |
| c (C++) | 3 | 0 | 3 / 133 (2.3%) | 0 / 8408 (0.0%) | 0 | 0 | 0 / 26 (0.0%) | 0 / 8259 (0.0%) | 0 |
| d | 11 | 0 | 11 / 7177 (0.2%) | 0 / 585 (0.0%) | 42 | 0 | 42 / 7036 (0.6%) | 0 / 561 (0.0%) | 24 |
*The direction, per variant x arch.*

| variant arch | wrong starts: heuristic only | wrong starts: any declared | heuristic-only starts wrong | declared starts wrong | wrong ends: heuristic (`not_stated`) | wrong ends: declared | heuristic ends wrong | declared ends wrong | heuristic ends cut (no end stated) |
|---|---|---|---|---|---|---|---|---|---|
| a aarch64 | 0 | 0 | 0 / 48 (0.0%) | 0 / 11537 (0.0%) | 0 | 0 | 0 / 0 (-) | 0 / 11441 (0.0%) | 0 |
| a i686 | 0 | 0 | 0 / 121 (0.0%) | 0 / 11883 (0.0%) | 0 | 0 | 0 / 0 (-) | 0 / 11833 (0.0%) | 0 |
| a x86_64 | 0 | 0 | 0 / 192 (0.0%) | 0 / 31889 (0.0%) | 0 | 0 | 0 / 0 (-) | 0 / 31719 (0.0%) | 0 |
| c (C) aarch64 | 144 | 0 | 144 / 6989 (2.1%) | 0 / 4020 (0.0%) | 531 | 0 | 531 / 6563 (8.1%) | 0 / 3948 (0.0%) | 246 |
| c (C) i686 | 273 | 0 | 273 / 6941 (3.9%) | 0 / 4253 (0.0%) | 966 | 0 | 966 / 6322 (15.3%) | 0 / 4253 (0.0%) | 223 |
| c (C) x86_64 | 78 | 0 | 78 / 15660 (0.5%) | 0 / 5895 (0.0%) | 444 | 0 | 444 / 15177 (2.9%) | 0 / 5895 (0.0%) | 276 |
| c (C++) aarch64 | 3 | 0 | 3 / 21 (14.3%) | 0 / 134 (0.0%) | 0 | 0 | 0 / 6 (0.0%) | 0 / 110 (0.0%) | 0 |
| c (C++) i686 | 0 | 0 | 0 / 37 (0.0%) | 0 / 113 (0.0%) | 0 | 0 | 0 / 6 (0.0%) | 0 / 111 (0.0%) | 0 |
| c (C++) x86_64 | 0 | 0 | 0 / 75 (0.0%) | 0 / 8161 (0.0%) | 0 | 0 | 0 / 14 (0.0%) | 0 / 8038 (0.0%) | 0 |
| d aarch64 | 3 | 0 | 3 / 21 (14.3%) | 0 / 134 (0.0%) | 0 | 0 | 0 / 6 (0.0%) | 0 / 110 (0.0%) | 0 |
| d i686 | 0 | 0 | 0 / 38 (0.0%) | 0 / 111 (0.0%) | 0 | 0 | 0 / 6 (0.0%) | 0 / 111 (0.0%) | 0 |
| d x86_64 | 8 | 0 | 8 / 7118 (0.1%) | 0 / 340 (0.0%) | 42 | 0 | 42 / 7024 (0.6%) | 0 / 340 (0.0%) | 24 |
*The direction, broad reading (a `.cold` fragment and a PLT header counted as wrong starts too).*

| variant | heuristic-only starts wrong | declared starts wrong |
|---|---|---|
| a | 0 / 361 (0.0%) | 184 / 55309 (0.3%) |
| b | 14 / 421 (3.3%) | 184 / 55261 (0.3%) |
| c (C) | 500 / 29590 (1.7%) | 0 / 14168 (0.0%) |
| c (C++) | 3 / 133 (2.3%) | 123 / 8408 (1.5%) |
| d | 12 / 7177 (0.2%) | 0 / 585 (0.0%) |

**Verdict: on this corpus the category still predicts the error, for starts and for ends.** No
wrong start carries a declared source (0 of 55 309 in (a), 55 261 in (b), 14 168 in (c) of C, 8 408
in (c) of C++, 585 in (d)) and no declared end is wrong, against 14 of 421 heuristic-only starts
in (b), 495 of 29 590 in (c) of C, 3 of 133 in (c) of C++, 11 of 7 177 in (d), and 1 941 of 28 062
`not_stated` ends in (c) of C. Limits on reading it: (1) under the broad reading the declared side
is not clean: 184 declared starts in (a) and (b) and 123 in (c) of C++ are `.cold` fragments, an
FDE or a symbol stating code that is not one function; (2) **a declared source is what the table
says, not the truth** (below): these tables were written by the compilers that built them, and
nothing here says what an obfuscated or hand-edited one does; (3) the rate is not one number:
heuristic-only starts in (c) of C are wrong 0.5% of the time on x86-64, 2.1% on AArch64, 3.9% on
i686; (4) these figures are on the corpus the fixes were tuned on. A category says where to doubt;
it is not a probability, and no rate here should be quoted without its machine, its corpus and
this engine.

**A declared source is a claim.** `lying.so` plants what an unwind table and a symbol table can
state falsely, and the test `a_lying_table_is_repeated_and_contradicted_only_where_a_second_source_speaks`
pins what the engine answers. An FDE stating `+0x04..+0x14` for a function at `+0x00`, with
nothing else speaking about it: `function discover` lists `+0x04`, `why` says `unwind` `eh_frame`
for its start and end, `contradictions` says nothing. A symbol at `+0x44`, the middle of an
instruction: listed, named, `why` says `symbol`, `contradictions` says nothing. A symbol whose size
runs over the next function: that function is **no longer listed** (before symbols declared starts
it was), `why` at it answers the symbol's function, `contradictions` says nothing. Only where a
second source speaks does the answer change: a true `.size` and a lying FDE are an `overlap`; a
true FDE and a lying `.size` are an `end`, and the size still gives the end `why` shows. So a lying
table silently produces wrong functions, and on such an image every number above means nothing.

**What the fixes did,** by the instruction at each wrong start (`evidence.py`, objdump on the
unstripped build):

1. *i686 `call next; pop`.* 4 223 wrong starts in (c), 8 in (d) → 0. `call_target`'s precision in
   (c) of C 86.0% → 100.0%. `__x86.get_pc_thunk.*` stay listed; a call to the next instruction that
   does not pop stays a call.
2. *i386 `lea` padding.* A self-`lea` listed as a function: 1 146 in (a) and in (b), 73 in (c), 1 in
   (d) → 0 in all. `mov %edi,%edi` is deliberately not padding: it is the first instruction of a
   hot-patchable 32-bit Windows function.
3. *Starts from symbols.* DWARF functions missed in (c) of C that the stripped file's `.dynsym`
   names: 10 634 → 0; in (d) 315 → 0. Recall in (c) of C 66.5% → 91.9%. On 10 images, 2 098 `symbol`
   claims of `why` against `llvm-nm`: 0 wrong.
4. *The window reported as an end.* Ends at exactly start + 4 KiB: 722 in (c) (495 short, 227 long)
   and 24 in (d) → 6 and 0, those six a terminator that happens to end there. `not_stated` now says
   `cut` on 745 in (c), 24 in (d), an absence. Wrong `not_stated` ends in (c) of C 2 589 → 1 941.
5. *PLT FDEs.* `plt0` starts 60 → 0 in (a), and every wrong declared end (14 in (a), 14 in (b), 8 in
   (c), 2 in (d)) → 0. **The cost:** the 36 PLT entries an FDE found in (a) are no longer listed: 0
   of 9 595 are now. The stubs stay named where they are called.
6. *`paciasp`.* A function listed 4 bytes in: 48 in (a) and (b), 36 and 12 in (c), 12 in (d) → 0.
7. *Prologues inside a function.* `sub rsp` on x86-64 227 → 44 in (c), 43 → 8 in (d); `stp` on
   AArch64 367 → 96 in (c), 2 → 0 in (d). No true start was lost to the rule that does it, on this
   corpus.
8. *The gap sweep.* Now the largest class: 352 interior starts in (c) (343 before; item A gives it
   far more gaps to sweep, and its precision still went 88.1% → 96.0%), 271 on i686, jump-table cases
   after a `jmp`. **Refused:** not arming the sweep after a `jmp` would remove 225 of them and 225
   true starts (x86-64: 159 true for 10 wrong); it was measured and left out.

**Worse, reported:** (b) gained 14 wrong starts where it had 3: `call_weak_fn`'s `ret` on AArch64,
which the section-start bracket (G) reaches in the C runtime's hand-written code, 2 of them at odd
addresses. (c) of C++ gained 3 the same way. `plt` recall 36 → 0 (above).

**Still wrong, and not fixed here.** (1) An end nothing states runs past a call that does not return:
1 657 long `not_stated` ends in (c) of C (`__stack_chk_fail@plt` on i686 and AArch64, where stubs
are not decoded). (2) 284 short ends, the last block inside the window, which a graph cannot tell
from a real end. (3) *The gap sweep steps one byte over what does not decode, on every machine:*
on AArch64 that lists odd addresses (17 in (c)); `Arch::resync_step` states the right step and the
sweep does not ask it. (4) The Itanium demangler (crate `cpp_demangle` 0.5.1) gives wrong signatures:
327 names of libFuzzer in (a), unchanged; a third-party defect the lead decides on.

**Absences (not wrong answers, measured).** The `stub` start source never fired: the image reader
names stubs but does not hand them to discovery. 24 `.plt.got` stubs are not bound to a name.

*Missed truth functions.*

| variant | DWARF missed | of them in the measured file's `.dynsym` | CRT missed | PLT entries missed |
|---|---|---|---|---|
| a | 0 | 0 | 71 | 9595 |
| b | 0 | 0 | 73 | 9595 |
| c (C) | 3786 | 0 | 76 | 8584 |
| c (C++) | 0 | 0 | 22 | 1011 |
| d | 370 | 0 | 31 | 956 |

**Calibration.** `calibrate.py` on three configurations of three machines (`x86_64/lua/gcc-O2`,
`i686/zstd/clang-Os`, `aarch64/lua/gcc-O2`), 0 failures on this run, each mutation asserted to have
happened before its effect is read: a declared true start moved by one byte (variant b) and a
heuristic one (variant c) each become exactly one interior start inside their own function, one
newly missed function, and one more wrong start under the right kind in the direction; an exact
stated end and an exact `not_stated` end moved by one byte each become one long end; a renamed
function one wrong name; the code-identity check fails on another `-O` level's build and on a
stripped copy with one `.text` byte flipped, and passes on the real stripped file. Four times in the
first run the instrument, not the engine, was wrong, each found before a number was recorded: it
read objdump's `<puts@plt-0x10>` and `<.plt>` as PLT entries; it counted the engine's
`luaD_throw_cold` for `luaD_throw.cold` as a wrong name; it took `c++filt` alone as the reading of a
name; and its first calibration assumed the unwind flags always change the code. A fifth this round:
it scored an end `why` does not state as wrong in the direction, which no engine had yet exercised;
it is now an absence, and both engines were scored again with it. The `why`/`discover` contract
checks found 0 disagreements on 276 images: the tool against itself, rung 5.

### Held-out corpus (measured once, on the final engine)

**The test of whether the fixes generalize.** Six public codebases the lead chose apart from the
tuning, fetched and built only once the engine above was final, at the commits
`oracle/rule-accuracy/README.md` records: lz4 v1.10.0, nginx release-1.27.3, ninja v1.12.1, LevelDB
1.23, RE2 2024-07-02, tmux 3.5a. All six built. Not on every machine, each for a stated reason:
nginx has no AArch64 (its configure runs what it compiles) and no PE (its Windows build is its own);
tmux is x86-64 only (libevent and ncurses are installed for the host alone); RE2 has no PE (no Abseil
for mingw, and a DLL cannot leave symbols unresolved). PE32+ and PE32 through mingw gcc for lz4,
ninja and LevelDB: gcc writes DWARF there, `llvm-dwarfdump` reads it, and the addresses agree with
`llvm-readobj --unwind`, so **this is the first measurement of `.pdata` and `export` starts.** 108
configurations, 390 images, 282 of 282 stripped-against-truth code checks the same. Same tools as
above, mingw gcc 16.2.0.

Measured once with the final engine, sha256 `2447860c…`, and **the engine was not changed after**. The
base engine was measured on the same images afterwards, for the before column; neither fix nor rule
was tuned against this set. One instrument fault was found reading the result and fixed before this
was recorded: the new PE reader took a global named with a dot (`T
.weak.__register_frame_info.hmod_libgcc`) for a section's symbol, so 18 `.pdata` starts that `nm` and
objdump call functions were scored wrong. The kept answers were scored again; nothing was measured
twice. 0 `why`/`discover` contract differences.

*Before and after: starts, per variant x codebase.*

| variant | codebase | listed | true | wrong, strict | fragment + plt0 | precision, strict | precision, broad | recall: DWARF fns |
|---|---|---|---|---|---|---|---|---|
| a | leveldb | 32524 → 31569 | 30787 → 30802 | 958 → 0 | 779 → 767 | 97.0% → 100.0% | 94.7% → 97.6% | 29986 / 29986 (100.0%) → 29986 / 29986 (100.0%) |
| a | lz4 | 5586 → 5245 | 5215 → 5245 | 359 → 0 | 12 → 0 | 93.6% → 100.0% | 93.4% → 100.0% | 4899 / 4899 (100.0%) → 4899 / 4899 (100.0%) |
| a | nginx | 16387 → 15528 | 15505 → 15523 | 865 → 0 | 17 → 5 | 94.7% → 100.0% | 94.6% → 100.0% | 15400 / 15400 (100.0%) → 15400 / 15400 (100.0%) |
| a | ninja | 62800 → 61379 | 59721 → 59746 | 1437 → 3 | 1642 → 1630 | 97.7% → 100.0% | 95.1% → 97.3% | 58162 / 58162 (100.0%) → 58162 / 58162 (100.0%) |
| a | re2 | 37357 → 37019 | 36595 → 36614 | 345 → 0 | 417 → 405 | 99.1% → 100.0% | 98.0% → 98.9% | 36447 / 36447 (100.0%) → 36447 / 36447 (100.0%) |
| a | tmux | 12600 → 12594 | 12586 → 12586 | 0 → 0 | 14 → 8 | 100.0% → 100.0% | 99.9% → 99.9% | 12545 / 12545 (100.0%) → 12545 / 12545 (100.0%) |
| b | leveldb | 32524 → 31572 | 30787 → 30802 | 958 → 3 | 779 → 767 | 97.0% → 100.0% | 94.7% → 97.6% | 29986 / 29986 (100.0%) → 29986 / 29986 (100.0%) |
| b | lz4 | 5586 → 5248 | 5215 → 5245 | 359 → 3 | 12 → 0 | 93.6% → 99.9% | 93.4% → 99.9% | 4899 / 4899 (100.0%) → 4899 / 4899 (100.0%) |
| b | nginx | 16387 → 15528 | 15505 → 15523 | 865 → 0 | 17 → 5 | 94.7% → 100.0% | 94.6% → 100.0% | 15400 / 15400 (100.0%) → 15400 / 15400 (100.0%) |
| b | ninja | 62800 → 61382 | 59721 → 59745 | 1437 → 7 | 1642 → 1630 | 97.7% → 100.0% | 95.1% → 97.3% | 58162 / 58162 (100.0%) → 58162 / 58162 (100.0%) |
| b | re2 | 37357 → 37022 | 36595 → 36614 | 345 → 3 | 417 → 405 | 99.1% → 100.0% | 98.0% → 98.9% | 36447 / 36447 (100.0%) → 36447 / 36447 (100.0%) |
| b | tmux | 12600 → 12594 | 12586 → 12586 | 0 → 0 | 14 → 8 | 100.0% → 100.0% | 99.9% → 99.9% | 12545 / 12545 (100.0%) → 12545 / 12545 (100.0%) |
| c (C) | lz4 | 3652 → 5174 | 2883 → 5113 | 766 → 61 | 3 → 0 | 79.0% → 98.8% | 78.9% → 98.8% | 2597 / 4899 (53.0%) → 4769 / 4899 (97.3%) |
| c (C) | nginx | 13133 → 9557 | 9461 → 9514 | 3658 → 41 | 14 → 2 | 72.1% → 99.6% | 72.0% → 99.6% | 9367 / 15400 (60.8%) → 9402 / 15400 (61.1%) |
| c (C) | tmux | 9563 → 9492 | 9446 → 9446 | 110 → 45 | 7 → 1 | 98.8% → 99.5% | 98.8% → 99.5% | 9414 / 12545 (75.0%) → 9414 / 12545 (75.0%) |
| c (C++) | leveldb | 30809 → 30204 | 29634 → 29656 | 620 → 5 | 555 → 543 | 98.0% → 100.0% | 96.2% → 98.2% | 28838 / 29986 (96.2%) → 28845 / 29986 (96.2%) |
| c (C++) | ninja | 62003 → 60818 | 59315 → 59341 | 1235 → 36 | 1453 → 1441 | 98.0% → 99.9% | 95.7% → 97.6% | 57756 / 58162 (99.3%) → 57758 / 58162 (99.3%) |
| c (C++) | re2 | 37354 → 37010 | 36583 → 36602 | 354 → 3 | 417 → 405 | 99.0% → 100.0% | 97.9% → 98.9% | 36435 / 36447 (100.0%) → 36435 / 36447 (100.0%) |
| d | leveldb | 23981 → 27424 | 20567 → 27337 | 3409 → 84 | 5 → 3 | 85.8% → 99.7% | 85.8% → 99.7% | 19795 / 29733 (66.6%) → 26535 / 29733 (89.2%) |
| d | ninja | 63355 → 59043 | 57602 → 57859 | 4627 → 70 | 1126 → 1114 | 92.6% → 99.9% | 90.9% → 98.0% | 56063 / 57744 (97.1%) → 56284 / 57744 (97.5%) |
| d | re2 | 37724 → 34206 | 32624 → 34115 | 5096 → 89 | 4 → 2 | 86.5% → 99.7% | 86.5% → 99.7% | 32515 / 35785 (90.9%) → 33974 / 35785 (94.9%) |
*Starts, per variant (each row its own; (b) is (a)'s code stripped, so no total counts both).*

| variant | runs | listed | true | wrong, strict (interior / outside) | fragment | plt0 | wrong, broad | precision, strict | precision, broad | recall: DWARF fns | recall: CRT fns | recall: PLT entries |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| a | 108 | 163334 | 160516 | 3 (0 / 3) | 2815 | 0 | 2818 | 100.0% | 98.3% | 157439 / 157439 (100.0%) | 3077 / 3163 (97.3%) | 0 / 16684 (0.0%) |
| b | 108 | 163346 | 160515 | 16 (13 / 3) | 2815 | 0 | 2831 | 100.0% | 98.3% | 157439 / 157439 (100.0%) | 3076 / 3163 (97.2%) | 0 / 16684 (0.0%) |
| c (C) | 42 | 24223 | 24073 | 147 (147 / 0) | 3 | 0 | 150 | 99.4% | 99.4% | 23585 / 32844 (71.8%) | 488 / 549 (88.9%) | 0 / 4099 (0.0%) |
| c (C++) | 66 | 128032 | 125599 | 44 (21 / 23) | 2389 | 0 | 2433 | 100.0% | 98.1% | 123038 / 124595 (98.8%) | 2561 / 2614 (98.0%) | 0 / 12585 (0.0%) |
| d | 66 | 120673 | 119311 | 243 (220 / 23) | 1119 | 0 | 1362 | 99.8% | 98.9% | 116793 / 123262 (94.8%) | 2518 / 2587 (97.3%) | 0 / 12127 (0.0%) |
*Starts, per variant x codebase.*

| variant codebase | runs | listed | true | wrong, strict (interior / outside) | fragment | plt0 | wrong, broad | precision, strict | precision, broad | recall: DWARF fns | recall: CRT fns | recall: PLT entries |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| a leveldb | 24 | 31569 | 30802 | 0 (0 / 0) | 767 | 0 | 767 | 100.0% | 97.6% | 29986 / 29986 (100.0%) | 816 / 833 (98.0%) | 0 / 7808 (0.0%) |
| a lz4 | 24 | 5245 | 5245 | 0 (0 / 0) | 0 | 0 | 0 | 100.0% | 100.0% | 4899 / 4899 (100.0%) | 346 / 364 (95.1%) | 0 / 1250 (0.0%) |
| a nginx | 12 | 15528 | 15523 | 0 (0 / 0) | 5 | 0 | 5 | 100.0% | 100.0% | 15400 / 15400 (100.0%) | 123 / 139 (88.5%) | 0 / 1603 (0.0%) |
| a ninja | 24 | 61379 | 59746 | 3 (0 / 3) | 1630 | 0 | 1633 | 100.0% | 97.3% | 58162 / 58162 (100.0%) | 1584 / 1600 (99.0%) | 0 / 2421 (0.0%) |
| a re2 | 18 | 37019 | 36614 | 0 (0 / 0) | 405 | 0 | 405 | 100.0% | 98.9% | 36447 / 36447 (100.0%) | 167 / 181 (92.3%) | 0 / 2356 (0.0%) |
| a tmux | 6 | 12594 | 12586 | 0 (0 / 0) | 8 | 0 | 8 | 100.0% | 99.9% | 12545 / 12545 (100.0%) | 41 / 46 (89.1%) | 0 / 1246 (0.0%) |
| b leveldb | 24 | 31572 | 30802 | 3 (3 / 0) | 767 | 0 | 770 | 100.0% | 97.6% | 29986 / 29986 (100.0%) | 816 / 833 (98.0%) | 0 / 7808 (0.0%) |
| b lz4 | 24 | 5248 | 5245 | 3 (3 / 0) | 0 | 0 | 3 | 99.9% | 99.9% | 4899 / 4899 (100.0%) | 346 / 364 (95.1%) | 0 / 1250 (0.0%) |
| b nginx | 12 | 15528 | 15523 | 0 (0 / 0) | 5 | 0 | 5 | 100.0% | 100.0% | 15400 / 15400 (100.0%) | 123 / 139 (88.5%) | 0 / 1603 (0.0%) |
| b ninja | 24 | 61382 | 59745 | 7 (4 / 3) | 1630 | 0 | 1637 | 100.0% | 97.3% | 58162 / 58162 (100.0%) | 1583 / 1600 (98.9%) | 0 / 2421 (0.0%) |
| b re2 | 18 | 37022 | 36614 | 3 (3 / 0) | 405 | 0 | 408 | 100.0% | 98.9% | 36447 / 36447 (100.0%) | 167 / 181 (92.3%) | 0 / 2356 (0.0%) |
| b tmux | 6 | 12594 | 12586 | 0 (0 / 0) | 8 | 0 | 8 | 100.0% | 99.9% | 12545 / 12545 (100.0%) | 41 / 46 (89.1%) | 0 / 1246 (0.0%) |
| c (C) lz4 | 24 | 5174 | 5113 | 61 (61 / 0) | 0 | 0 | 61 | 98.8% | 98.8% | 4769 / 4899 (97.3%) | 344 / 364 (94.5%) | 0 / 1250 (0.0%) |
| c (C) nginx | 12 | 9557 | 9514 | 41 (41 / 0) | 2 | 0 | 43 | 99.6% | 99.6% | 9402 / 15400 (61.1%) | 112 / 139 (80.6%) | 0 / 1603 (0.0%) |
| c (C) tmux | 6 | 9492 | 9446 | 45 (45 / 0) | 1 | 0 | 46 | 99.5% | 99.5% | 9414 / 12545 (75.0%) | 32 / 46 (69.6%) | 0 / 1246 (0.0%) |
| c (C++) leveldb | 24 | 30204 | 29656 | 5 (5 / 0) | 543 | 0 | 548 | 100.0% | 98.2% | 28845 / 29986 (96.2%) | 811 / 833 (97.4%) | 0 / 7808 (0.0%) |
| c (C++) ninja | 24 | 60818 | 59341 | 36 (13 / 23) | 1441 | 0 | 1477 | 99.9% | 97.6% | 57758 / 58162 (99.3%) | 1583 / 1600 (98.9%) | 0 / 2421 (0.0%) |
| c (C++) re2 | 18 | 37010 | 36602 | 3 (3 / 0) | 405 | 0 | 408 | 100.0% | 98.9% | 36435 / 36447 (100.0%) | 167 / 181 (92.3%) | 0 / 2356 (0.0%) |
| d leveldb | 24 | 27424 | 27337 | 84 (84 / 0) | 3 | 0 | 87 | 99.7% | 99.7% | 26535 / 29733 (89.2%) | 802 / 824 (97.3%) | 0 / 7590 (0.0%) |
| d ninja | 24 | 59043 | 57859 | 70 (47 / 23) | 1114 | 0 | 1184 | 99.9% | 98.0% | 56284 / 57744 (97.5%) | 1575 / 1591 (99.0%) | 0 / 2307 (0.0%) |
| d re2 | 18 | 34206 | 34115 | 89 (89 / 0) | 2 | 0 | 91 | 99.7% | 99.7% | 33974 / 35785 (94.9%) | 141 / 172 (82.0%) | 0 / 2230 (0.0%) |
*Starts, per variant x arch.*

| variant arch | runs | listed | true | wrong, strict (interior / outside) | fragment | plt0 | wrong, broad | precision, strict | precision, broad | recall: DWARF fns | recall: CRT fns | recall: PLT entries |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| a aarch64 | 24 | 29516 | 29516 | 0 (0 / 0) | 0 | 0 | 0 | 100.0% | 100.0% | 29317 / 29317 (100.0%) | 199 / 199 (100.0%) | 0 / 4663 (0.0%) |
| a i686 | 30 | 37879 | 37237 | 0 (0 / 0) | 642 | 0 | 642 | 100.0% | 98.3% | 36923 / 36923 (100.0%) | 314 / 373 (84.2%) | 0 / 5396 (0.0%) |
| a pe_x64 | 9 | 22874 | 22176 | 0 (0 / 0) | 698 | 0 | 698 | 100.0% | 96.9% | 20774 / 20774 (100.0%) | 1402 / 1402 (100.0%) | 0 / 0 (-) |
| a pe_x86 | 9 | 22725 | 21895 | 3 (0 / 3) | 827 | 0 | 830 | 100.0% | 96.3% | 20980 / 20980 (100.0%) | 915 / 918 (99.7%) | 0 / 0 (-) |
| a x86_64 | 36 | 50340 | 49692 | 0 (0 / 0) | 648 | 0 | 648 | 100.0% | 98.7% | 49445 / 49445 (100.0%) | 247 / 271 (91.1%) | 0 / 6625 (0.0%) |
| c (C) aarch64 | 6 | 1211 | 1188 | 23 (23 / 0) | 0 | 0 | 23 | 98.1% | 98.1% | 1140 / 1174 (97.1%) | 48 / 48 (100.0%) | 0 / 425 (0.0%) |
| c (C) i686 | 12 | 6154 | 6126 | 27 (27 / 0) | 1 | 0 | 28 | 99.6% | 99.5% | 5996 / 8872 (67.6%) | 130 / 156 (83.3%) | 0 / 1214 (0.0%) |
| c (C) pe_x64 | 3 | 787 | 786 | 1 (1 / 0) | 0 | 0 | 1 | 99.9% | 99.9% | 660 / 688 (95.9%) | 126 / 126 (100.0%) | 0 / 0 (-) |
| c (C) pe_x86 | 3 | 749 | 742 | 7 (7 / 0) | 0 | 0 | 7 | 99.1% | 99.1% | 664 / 688 (96.5%) | 78 / 81 (96.3%) | 0 / 0 (-) |
| c (C) x86_64 | 18 | 15322 | 15231 | 89 (89 / 0) | 2 | 0 | 91 | 99.4% | 99.4% | 15125 / 21422 (70.6%) | 106 / 138 (76.8%) | 0 / 2460 (0.0%) |
| c (C++) aarch64 | 18 | 28297 | 28287 | 10 (10 / 0) | 0 | 0 | 10 | 100.0% | 100.0% | 28137 / 28143 (100.0%) | 150 / 151 (99.3%) | 0 / 4238 (0.0%) |
| c (C++) i686 | 18 | 28867 | 28228 | 0 (0 / 0) | 639 | 0 | 639 | 100.0% | 97.8% | 28047 / 28051 (100.0%) | 181 / 217 (83.4%) | 0 / 4182 (0.0%) |
| c (C++) pe_x64 | 6 | 21217 | 20715 | 10 (10 / 0) | 492 | 0 | 502 | 100.0% | 97.6% | 19440 / 20086 (96.8%) | 1275 / 1276 (99.9%) | 0 / 0 (-) |
| c (C++) pe_x86 | 6 | 20870 | 20226 | 24 (1 / 23) | 620 | 0 | 644 | 99.9% | 96.9% | 19393 / 20292 (95.6%) | 833 / 837 (99.5%) | 0 / 0 (-) |
| c (C++) x86_64 | 18 | 28781 | 28143 | 0 (0 / 0) | 638 | 0 | 638 | 100.0% | 97.8% | 28021 / 28023 (100.0%) | 122 / 133 (91.7%) | 0 / 4165 (0.0%) |
| d aarch64 | 18 | 26199 | 26033 | 166 (166 / 0) | 0 | 0 | 166 | 99.4% | 99.4% | 25895 / 27698 (93.5%) | 138 / 142 (97.2%) | 0 / 4077 (0.0%) |
| d i686 | 18 | 26322 | 26293 | 26 (26 / 0) | 3 | 0 | 29 | 99.9% | 99.9% | 26127 / 27608 (94.6%) | 166 / 208 (79.8%) | 0 / 4037 (0.0%) |
| d pe_x64 | 6 | 21217 | 20715 | 10 (10 / 0) | 492 | 0 | 502 | 100.0% | 97.6% | 19440 / 20086 (96.8%) | 1275 / 1276 (99.9%) | 0 / 0 (-) |
| d pe_x86 | 6 | 20870 | 20226 | 24 (1 / 23) | 620 | 0 | 644 | 99.9% | 96.9% | 19393 / 20292 (95.6%) | 833 / 837 (99.5%) | 0 / 0 (-) |
| d x86_64 | 18 | 26065 | 26044 | 17 (17 / 0) | 4 | 0 | 21 | 99.9% | 99.9% | 25938 / 27578 (94.1%) | 106 / 124 (85.5%) | 0 / 4013 (0.0%) |
*Start sources, per variant ((b) is (a)'s code stripped, left out).*

Precision, strict = true / (true + wrong), where a fragment or a PLT header is neither; broad counts both as wrong. Recall = the DWARF functions this source found, of all the DWARF functions in the row. `alone`: the starts this source alone produced.

| variant | source | produced | true | wrong | fragment | plt0 | precision, strict | precision, broad | recall: DWARF fns | alone produced | alone true | alone wrong |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| a | unwind:eh_frame | 139374 | 137257 | 0 | 2117 | 0 | 100.0% | 98.5% | 136665 / 157439 (86.8%) | 30 | 22 | 0 |
| a | unwind:pdata | 21722 | 21024 | 0 | 698 | 0 | 100.0% | 96.8% | 20774 / 157439 (13.2%) | 21 | 10 | 0 |
| a | export | 1794 | 1794 | 0 | 0 | 0 | 100.0% | 100.0% | 1780 / 157439 (1.1%) | 0 | 0 | 0 |
| a | symbol | 117186 | 115896 | 0 | 1290 | 0 | 100.0% | 98.9% | 115685 / 157439 (73.5%) | 13 | 13 | 0 |
| a | after_declared_end | 160661 | 157904 | 0 | 2757 | 0 | 100.0% | 98.3% | 156931 / 157439 (99.7%) | 13 | 13 | 0 |
| a | gap_sweep | 2016 | 2016 | 0 | 0 | 0 | 100.0% | 100.0% | 0 / 157439 (0.0%) | 676 | 676 | 0 |
| a | call_target | 103742 | 103739 | 3 | 0 | 0 | 100.0% | 100.0% | 102217 / 157439 (64.9%) | 62 | 59 | 3 |
| a | prologue | 32005 | 32005 | 0 | 0 | 0 | 100.0% | 100.0% | 31756 / 157439 (20.2%) | 66 | 66 | 0 |
| c (C) | unwind:eh_frame | 162 | 162 | 0 | 0 | 0 | 100.0% | 100.0% | 95 / 32844 (0.3%) | 12 | 12 | 0 |
| c (C) | unwind:pdata | 110 | 110 | 0 | 0 | 0 | 100.0% | 100.0% | 95 / 32844 (0.3%) | 3 | 3 | 0 |
| c (C) | export | 858 | 858 | 0 | 0 | 0 | 100.0% | 100.0% | 844 / 32844 (2.6%) | 396 | 396 | 0 |
| c (C) | symbol | 2574 | 2574 | 0 | 0 | 0 | 100.0% | 100.0% | 2556 / 32844 (7.8%) | 321 | 321 | 0 |
| c (C) | after_declared_end | 2776 | 2776 | 0 | 0 | 0 | 100.0% | 100.0% | 2675 / 32844 (8.1%) | 5 | 5 | 0 |
| c (C) | gap_sweep | 3183 | 3110 | 70 | 3 | 0 | 97.8% | 97.7% | 2889 / 32844 (8.8%) | 1303 | 1231 | 69 |
| c (C) | call_target | 17750 | 17750 | 0 | 0 | 0 | 100.0% | 100.0% | 17509 / 32844 (53.3%) | 12259 | 12259 | 0 |
| c (C) | prologue | 5803 | 5725 | 78 | 0 | 0 | 98.7% | 98.7% | 5632 / 32844 (17.1%) | 1864 | 1787 | 77 |
| c (C++) | unwind:eh_frame | 98835 | 96940 | 0 | 1895 | 0 | 100.0% | 98.1% | 96481 / 124595 (77.4%) | 261 | 214 | 0 |
| c (C++) | unwind:pdata | 12866 | 12377 | 0 | 489 | 0 | 100.0% | 96.2% | 12149 / 124595 (9.8%) | 94 | 80 | 0 |
| c (C++) | export | 936 | 936 | 0 | 0 | 0 | 100.0% | 100.0% | 936 / 124595 (0.8%) | 556 | 556 | 0 |
| c (C++) | symbol | 9875 | 9875 | 0 | 0 | 0 | 100.0% | 100.0% | 9869 / 124595 (7.9%) | 0 | 0 | 0 |
| c (C++) | after_declared_end | 111339 | 109014 | 0 | 2325 | 0 | 100.0% | 97.9% | 108272 / 124595 (86.9%) | 2 | 2 | 0 |
| c (C++) | gap_sweep | 9163 | 9128 | 30 | 5 | 0 | 99.7% | 99.6% | 7628 / 124595 (6.1%) | 964 | 931 | 30 |
| c (C++) | call_target | 85992 | 85989 | 3 | 0 | 0 | 100.0% | 100.0% | 84708 / 124595 (68.0%) | 5770 | 5767 | 3 |
| c (C++) | prologue | 26848 | 26837 | 11 | 0 | 0 | 100.0% | 100.0% | 26683 / 124595 (21.4%) | 151 | 140 | 11 |
| d | unwind:eh_frame | 13371 | 12753 | 0 | 618 | 0 | 100.0% | 95.4% | 12390 / 123262 (10.1%) | 139 | 128 | 0 |
| d | unwind:pdata | 12866 | 12377 | 0 | 489 | 0 | 100.0% | 96.2% | 12149 / 123262 (9.9%) | 94 | 80 | 0 |
| d | export | 936 | 936 | 0 | 0 | 0 | 100.0% | 100.0% | 936 / 123262 (0.8%) | 556 | 556 | 0 |
| d | symbol | 9771 | 9771 | 0 | 0 | 0 | 100.0% | 100.0% | 9765 / 123262 (7.9%) | 1148 | 1148 | 0 |
| d | after_declared_end | 35854 | 34765 | 5 | 1084 | 0 | 100.0% | 97.0% | 34148 / 123262 (27.7%) | 7 | 7 | 0 |
| d | gap_sweep | 32238 | 32142 | 84 | 12 | 0 | 99.7% | 99.7% | 30658 / 123262 (24.9%) | 2910 | 2822 | 78 |
| d | call_target | 84674 | 84671 | 3 | 0 | 0 | 100.0% | 100.0% | 83417 / 123262 (67.7%) | 39701 | 39698 | 3 |
| d | prologue | 26692 | 26535 | 157 | 0 | 0 | 99.4% | 99.4% | 26391 / 123262 (21.4%) | 1602 | 1446 | 156 |
*Ends, per variant.*

| variant | start class / end source | exact | short | long | between | no end | no truth end |
|---|---|---|---|---|---|---|---|
| a | fragment: symbol_size:st_size | 1290 | 0 | 0 | 0 | 0 | 0 |
| a | fragment: unwind:eh_frame | 827 | 0 | 0 | 0 | 0 | 0 |
| a | fragment: unwind:pdata | 698 | 0 | 0 | 0 | 0 | 0 |
| a | true: not_stated | 0 | 0 | 0 | 0 | 0 | 2181 |
| a | true: symbol_size:st_size | 115896 | 0 | 0 | 0 | 0 | 0 |
| a | true: unwind:eh_frame | 20980 | 0 | 0 | 0 | 0 | 435 |
| a | true: unwind:pdata | 20774 | 0 | 0 | 0 | 0 | 250 |
| b | fragment: unwind:eh_frame | 2117 | 0 | 0 | 0 | 0 | 0 |
| b | fragment: unwind:pdata | 698 | 0 | 0 | 0 | 0 | 0 |
| b | true: not_stated | 53 | 0 | 0 | 0 | 0 | 2181 |
| b | true: symbol_size:st_size | 12449 | 0 | 0 | 0 | 0 | 0 |
| b | true: unwind:eh_frame | 124373 | 0 | 0 | 0 | 0 | 435 |
| b | true: unwind:pdata | 20774 | 0 | 0 | 0 | 0 | 250 |
| c (C) | fragment: not_stated | 0 | 0 | 3 | 0 | 0 | 0 |
| c (C) | true: not_stated | 19439 | 79 | 1067 | 0 | 0 | 358 |
| c (C) | true: not_stated(cut) | 0 | 0 | 0 | 0 | 284 | 0 |
| c (C) | true: symbol_size:st_size | 2574 | 0 | 0 | 0 | 0 | 0 |
| c (C) | true: unwind:eh_frame | 132 | 0 | 0 | 0 | 0 | 30 |
| c (C) | true: unwind:pdata | 95 | 0 | 0 | 0 | 0 | 15 |
| c (C++) | fragment: not_stated | 1 | 0 | 4 | 0 | 0 | 0 |
| c (C++) | fragment: unwind:eh_frame | 1895 | 0 | 0 | 0 | 0 | 0 |
| c (C++) | fragment: unwind:pdata | 489 | 0 | 0 | 0 | 0 | 0 |
| c (C++) | true: not_stated | 13987 | 5 | 395 | 0 | 0 | 1839 |
| c (C++) | true: not_stated(cut) | 0 | 0 | 0 | 0 | 38 | 0 |
| c (C++) | true: symbol_size:st_size | 9875 | 0 | 0 | 0 | 0 | 0 |
| c (C++) | true: unwind:eh_frame | 86708 | 0 | 0 | 0 | 0 | 375 |
| c (C++) | true: unwind:pdata | 12149 | 0 | 0 | 0 | 0 | 228 |
| d | fragment: not_stated | 5 | 1 | 5 | 0 | 0 | 0 |
| d | fragment: not_stated(cut) | 0 | 0 | 0 | 0 | 1 | 0 |
| d | fragment: unwind:eh_frame | 618 | 0 | 0 | 0 | 0 | 0 |
| d | fragment: unwind:pdata | 489 | 0 | 0 | 0 | 0 | 0 |
| d | true: not_stated | 75703 | 35 | 6349 | 0 | 0 | 1873 |
| d | true: not_stated(cut) | 0 | 0 | 0 | 0 | 450 | 0 |
| d | true: symbol_size:st_size | 9771 | 0 | 0 | 0 | 0 | 0 |
| d | true: unwind:eh_frame | 12417 | 0 | 0 | 0 | 0 | 336 |
| d | true: unwind:pdata | 12149 | 0 | 0 | 0 | 0 | 228 |
*The direction, per variant (strict: a wrong start is interior or outside).*

| variant | wrong starts: heuristic only | wrong starts: any declared | heuristic-only starts wrong | declared starts wrong | wrong ends: heuristic (`not_stated`) | wrong ends: declared | heuristic ends wrong | declared ends wrong | heuristic ends cut (no end stated) |
|---|---|---|---|---|---|---|---|---|---|
| a | 3 | 0 | 3 / 2184 (0.1%) | 0 / 161150 (0.0%) | 0 | 0 | 0 / 0 (-) | 0 / 157650 (0.0%) | 0 |
| b | 16 | 0 | 16 / 2250 (0.7%) | 0 / 161096 (0.0%) | 0 | 0 | 0 / 53 (0.0%) | 0 / 157596 (0.0%) | 0 |
| c (C) | 147 | 0 | 147 / 20519 (0.7%) | 0 / 3704 (0.0%) | 1146 | 0 | 1146 / 20585 (5.6%) | 0 / 2801 (0.0%) | 284 |
| c (C++) | 44 | 0 | 44 / 15377 (0.3%) | 0 / 112655 (0.0%) | 400 | 0 | 400 / 14387 (2.8%) | 0 / 108732 (0.0%) | 38 |
| d | 243 | 0 | 243 / 83729 (0.3%) | 0 / 36944 (0.0%) | 6384 | 0 | 6384 / 82087 (7.8%) | 0 / 34337 (0.0%) | 450 |
*The direction, broad reading (a `.cold` fragment and a PLT header counted as wrong starts too).*

| variant | heuristic-only starts wrong | declared starts wrong |
|---|---|---|
| a | 3 / 2184 (0.1%) | 2815 / 161150 (1.7%) |
| b | 16 / 2250 (0.7%) | 2815 / 161096 (1.7%) |
| c (C) | 150 / 20519 (0.7%) | 0 / 3704 (0.0%) |
| c (C++) | 49 / 15377 (0.3%) | 2384 / 112655 (2.1%) |
| d | 255 / 83729 (0.3%) | 1107 / 36944 (3.0%) |

**What it says.** The fixes held on code they were not tuned against. Stripped C with no unwind
tables, base → final: wrong starts 4 534 → 147, right ones 21 790 → 24 073, precision 82.8% → 99.4%,
recall 65.1% → 71.8%. Stripped C++ with no unwind tables or exceptions: 13 132 → 243, 89.4% → 99.8%,
87.9% → 94.8%. As built: 3 964 → 3, recall 100%. By class, all of (c) and (d): a self-`lea` listed
as a function 2 291 and 1 273 → 0 (and 3 903 in (a) and (b) → 0); the `pop` of `call next; pop` 3 929
and 11 070 → 0; `sub rsp` inside a function on x86-64 200 → 73 and 109 → 12; `stp` inside one on
AArch64 70 → 1 and 460 → 122; ends at exactly the 4 KiB window 328 → 8 and 443 → 12. **No declared
source gave a wrong start or a wrong end, on any variant,** PE tables included.

**Where it is worse than the tuned corpus, plainly.** (1) *Recall of stripped C with no unwind
tables:* 71.8% here against 91.9%. A file with few exported functions gains little from symbols:
nginx 61.1%, tmux 75.0%, both executables, against lz4 97.3%, a library that exports its API. On the
tuned corpus of shared libraries that fix looked larger than it is for a program. (2) *Ends nothing
states:* 7.8% wrong in (d) (6 384 of 82 087), 16.8% on i686, against 0.6% on the tuned corpus; the
noreturn class, unfixed. (3) *The gap sweep inside a function:* 68 → 79 and 32 → 58 here too, more
gaps to sweep. (4) (b) has 13 interior starts where it had 10, the section-start bracket in the C
runtime on AArch64. (5) 4 988 wrong names in (a), of RE2 (4 148), ninja and LevelDB, in the C++
demangling layer: counted, not examined one by one. 47 `stub` names on PE count as wrong where the
image's import is `_fileno` and `nm` has mingw's alias `fileno`: the engine names the import.

**Not independent of the first corpus in everything.** The same compilers, the same flags, the same
machines. Nothing here says how these rules do on another compiler or an obfuscated file. Rust
programs are measured apart.

**Not measured.** PE `.pdata`, exports and PDB on the tuned corpus; big-endian images; ARM32/Thumb
and WebAssembly; the `rtti`, `flirt`, `pdb`, `managed` and `user` name layers (no image carried
them); `analyze` and the function lists of a live process. `why` does not cite any of these
numbers; that is the lead's decision.

### Obfuscated code: the first transformation measured (2026-11-05)

The question (`docs/design/OBFUSCATED.md`): on code shaped to mislead a static reader, which answers
are confidently wrong, and does anything warn of it? The instrument is `oracle/obfuscation/`, which
reuses this one's readers, truth reader and scorer — a transformation is one more variant, not a
second instrument. Engine `n0xis-0.3.5` (the wasm preview build), sha256
`da8b1dc53326ca3bc54fc996843232d6fb6891cd684f86a0ec29a2a539529fa7`. **Only the first transformation
is measured: junk bytes after unconditional transfers.** The rest (opaque predicates, flattening,
string encryption, computed-table calls, overlapping instructions, lying tables, a packer stub),
WebAssembly, combinations, and the owner's projects are **not measured here** — stated as absences
below.

**Method.** The transformation runs on the assembly the compiler emits, where symbols are still
labels, so the *obfuscated* build's own unstripped DWARF is correct by construction and is the truth
for the obfuscated stripped image (rule-accuracy's variant a/b with the obfuscated pair). For the
instruction boundary, where a linear disassembler desynchronises, the truth is a reference twin: the
same assembly with the planted dead bytes replaced by equal-length NOPs, read by GNU `objdump`
(rung 3) — byte-for-byte the obfuscated image outside the planted ranges, checked. Every obfuscated
and twin build printed exactly the clean build's output (behaviour preserved). Corpus: a dedicated
`calib.c` (5 functions) and the Lua 5.4.7 interpreter embedded by a driver (~780 listed functions),
`-O1 -g -fno-pic -no-pie`, on x86-64, i686 and AArch64 (run under qemu), at intensities 0.5 and 1.0,
each against an identity baseline. The number that matters is **silent or flagged**: of the wrong
answers, how many carried any warning (a place in `contradictions`, an `ir deobfuscate` junk finding
at the address, a refusal) versus `ok:true` with nothing.

*Per command, junk versus the baseline (w = wrong, of those s = silent, i.e. `ok:true` with no warning).*

| config (intensity) | function discover w (s) | disasm w (s) | strings w | xref w | ir-deob planted detected | contradictions |
|---|---|---|---|---|---|---|
| x86_64 calib — baseline | 0 | 0 | 0 | 0 | 0 / 0 | 0 |
| x86_64 calib junk 0.5 | 1 (0) | 5 (5) | 0 | 0 | 0 / 6 | 0 |
| x86_64 calib junk 1.0 | 1 (0) | 5 (5) | 0 | 0 | 0 / 6 | 0 |
| x86_64 lua — baseline | 0 | 0 | 0 | 0 | 0 / 0 | 0 |
| x86_64 lua junk 0.5 | 0 | 1119 (1111) | 0 | 4 (4) | 0 / 1582 | 0 |
| x86_64 lua junk 1.0 | 2 (0) | 2162 (2151) | 0 | 5 (5) | 0 / 2829 | 0 |
| i686 calib junk 1.0 | 0 | 3 (3) | 0 | 0 | 0 / 6 | 0 |
| i686 lua junk 0.5 | 0 | 1363 (1358) | 0 | 7 (7) | 0 / 1589 | 0 |
| i686 lua junk 1.0 | 0 | 2810 (2805) | 0 | 9 (9) | 0 / 2821 | 0 |
| aarch64 calib junk 1.0 | 1 (0)* | 0 | 0 | 0 | 0 / 8 | 0 |
| aarch64 lua junk 1.0 | 1 (0)* | 0 | 0 | 0 | 0 / 2785 | 0 |

*The one AArch64 discover wrong is in the baseline too (not caused by junk). Recall is unchanged by
junk on every configuration. The ir-deob column is planted junk sites detected / planted. The full
tables are `oracle/obfuscation/results/doc-tables.md`, regenerated with the engine's sha.

**What breaks, and whether it is silent.**

- *`disasm` is the loud failure, and it is silent.* A linear decode that passes a junk `0xe8` reads it
  as a `call rel32` and swallows the four bytes after it, then emits confident fictitious instructions
  until it resynchronises: 5 on the small program, ~1 100–2 800 on Lua, and **~99.5% carried no
  warning** (`contradictions` 0 on every configuration, no `ir deobfuscate` junk finding at the
  address). Example (x86-64 `calib`): a decode from `add_two` (`0x401140`) reaches `0x401149` and
  prints `inc dword ptr [rbp+0F0678FFh]`; the twin shows the real instruction there starts at
  `0x401145` (`mov eax,-1`, 5 bytes). The planted byte sits inside the function's *own* declared
  extent, so its declared end falls mid-(decoded)-instruction, yet nothing cross-checks the two.
- *`function discover` stays almost right, and its few wrong answers are flagged by category.* The
  `0xe8` seen as a `call` adds a spurious call target: 1 wrong start on `calib`, 2 on Lua at 1.0,
  each carrying only the heuristic source `call_target` — so `why` marks them heuristic. Recall never
  dropped (no true function was lost).
- *`ir deobfuscate` detects none of this junk.* 0 of every planted site (1 582 / 2 829 / … ), because
  the bytes are unreachable — after an unconditional transfer — and its analysis is over the reachable
  CFG, which never includes them. Its junk findings (34 on clean x86-64 Lua, 33 under junk) are
  `mov eax,eax` self-movs in honest code; its opaque-predicate findings (2 on `calib`, 2–3 on Lua) are
  the C runtime's `register_tm_clones`/`deregister_tm_clones` branches, which resolve to a constant in
  this non-PIC build — a true positive of the rule, a false alarm for "obfuscation". Neither moved
  materially under junk.
- *AArch64 is immune by construction.* Fixed-width 32-bit instructions mean a dead aligned word
  desynchronises nothing; `disasm` wrong is 0 there. Junk-after-transfer is a variable-length-ISA
  attack. Recorded so the zero is understood, not mistaken for a pass of a test that was never run.
- *`xref` gains fictitious call edges from the junk.* The `0xe8` read as `call`, and desynced
  decodes, produce confident call references the program does not have: 4 and 5 on x86-64 Lua (0.5,
  1.0), 7 and 9 on i686 Lua, 0 on `calib` and 0 in every baseline — all silent. Example (x86-64 Lua):
  `xref to 0x40c081` lists a `call` from `0x40bfbe`, where the reference twin has a `nop` (the planted
  dead byte); others originate at addresses that are no instruction boundary at all. This surfaced
  only after fixing the scorer, which first read only x86 `call`/`jmp` and so counted every AArch64
  `bl`/`b` as wrong — the metric accusing the engine; corrected, then both sides re-measured, and the
  baseline fell to 0.
- *`strings` and `decomp` are controls here* and are unaffected: 0 wrong strings; pseudo-C returned
  for every function; 0 engine crashes on this corpus (a stack overflow found later on this engine, since
  fixed, did not trigger here; the harness isolates and records a crash if one occurs).

**Verdict on the claims this corpus can test.**

1. *"On this corpus the category still predicts the error"* (the rule-accuracy verdict above) **holds
   for `function discover` on junk** — every junk-induced wrong start is heuristic-only — **but it is
   scoped to discovery.** `disasm` and the other commands carry no provenance category at all, so
   their wrong answers on obfuscated code are silent by construction: a category cannot predict an
   error on an answer it does not label. The single most common confident wrong answer here, the
   desynced `disasm` instruction, has no `why` and no category.
2. *The `OBFUSCATED.md` §1 aim* — "a start that does not decode, an unwind range ending
   mid-instruction, a call into the middle of a declared function, overlapping decodes ... become
   kinds of `contradictions`" — **does not hold yet.** `contradictions` returned 0 on every junk
   configuration though a declared extent's last bytes decode as an instruction crossing its end. The
   engine does not yet cross-check a declared boundary against the decode. This is a gap to close, not
   a regression.
3. *The limit "a declared source is what the table says, not the truth; nothing here says what an
   obfuscated or hand-edited one does"* is only **partly** addressed: this round measures a non-table
   transformation (junk in the stream). The table-lying transformations it names remain unmeasured.

**Calibration.** `oracle/obfuscation/obf_calibrate.py` on the single-file `calib`, 0 failures: a
disasm instruction moved off a true boundary scores one more wrong; a true start moved a byte scores
one more wrong start and one fewer true; the twin is byte-identical to the obfuscated image outside
the planted ranges; every counted wrong `disasm` instruction is shown by the bytes against the twin;
0 wrong starts are named by the measured file's own symbol table (none would accuse the reference).
The byte-identity check also caught a real instrument bug on the first *multi-file* run: the planted
labels reset per source file and collided across objects, so `build.json`'s planted-range addresses
came out wrong (the disasm/discover numbers are invariant to this — a junk start is always a true
boundary of the twin — but `decoded_dead_bytes` and that check were not). The labels are now unique
per file, and on a rebuilt x86-64 Lua at intensity 1.0 the twin differs from the obfuscated image in 0
bytes outside the planted ranges, with the same counts. The other Lua configurations were not rebuilt after
the fix.

Two measurement bugs the instrument found in itself this round, both fixed before any number was
recorded: the xref scorer first matched only x86 `call`/`jmp`, so every AArch64 `bl`/`b` read as a
wrong reference (10 on `calib`, the metric accusing the engine) — corrected to the AArch64 mnemonics,
then re-measured to 0; and a desynced disasm instruction was first credited as "flagged" when its
function merely had an unrelated opaque-predicate hit — corrected to flag only when a warning names
the instruction's own address.

**Not measured (absences, not results).** Opaque predicates, control-flow flattening, string
encryption, computed-table calls, overlapping instructions, lying tables (fake/removed unwind
entries, false function symbols and sizes, renamed exports), a packer stub (and `upx`, not installed);
WebAssembly including a forged name section; combinations; copies of the owner's projects (held out
until their measurement is done). The harness registers one transformation at a time; `junk` and the
`none` baseline are the only ones built.

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

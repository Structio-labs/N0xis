# N0xis

**From a hardware watchpoint in a live process to the exact decompiled statement that changed the value.**

Memory scanners find the *address*. Decompilers explain the *code*. **N0xis connects them.**

<!-- ▶ HERO GIF GOES HERE — record `provenance trace` running live and drop it at docs/assets/provenance.gif, then:  ![demo](docs/assets/provenance.gif) -->

```console
$ n0x provenance trace --pid 9348 --addr 0x7ff68bef3010 --kind write
```
```jsonc
"function_va": "0x7ff68bef1580",          // containing function, auto-resolved
"decompiled_context": [
  "rax.2 = (*(uint32_t*)(0x7ff68bef3010) - 0x1);",
  "*(uint32_t*)(0x7ff68bef3010) = rax.2;"  // ← the statement that moved your value
]
```

That is the source's `hp -= 1;`, recovered from a running process — the watched address
appears in the statement. Verified on Windows **and** Linux.

A "find what accesses this" scan normally stops at a raw disassembly line, and a
decompiler normally has no live-watchpoint input at all. This is the two halves
joined: the watchpoint hit is resolved through the same SSA pipeline that
decompiles the file.

## Install

Prebuilt binaries for Linux and Windows — **[latest release](https://github.com/Structio-labs/N0xis/releases/latest)**.

```sh
curl -LO https://github.com/Structio-labs/N0xis/releases/latest/download/n0xis-linux-x86_64
chmod +x n0xis-linux-x86_64 && ./n0xis-linux-x86_64 --version
```

Or build it: `cargo build --workspace --release` (Windows and Linux; no MSVC Build Tools
needed — `rust-toolchain.toml` pins the gnu host).

## Quickstart

Every command prints **one** JSON object — argument errors included: `{"ok":true,"data":…,"meta":…}` or
`{"ok":false,"error":…}`. Add `--pretty` to read it; the exit code is non-zero on failure.

```sh
n0x doctor                                                    # environment check
n0x profile --file game.exe                                   # triage: sections, exports, engine hints
n0x function discover --file game.exe --pdata                 # exact .pdata discovery
n0x decomp pseudo --file game.exe --addr 0x140012a00 --style ssa --pretty
n0x provenance trace --pid 4821 --addr 0x1a2b3c40 --kind write --pretty
```

The same commands run on a live `--pid`, a static `--file`, a captured `--snapshot`, or a
remote process over SSH. It is ordinary Unix plumbing —
`n0x function discover --file game.exe --pdata | jq -r '.data.functions[].va'` feeds the next
command. `n0x guide` lists all 113 commands, generated from the binary so it never drifts — and a test
fails the build if this number does.

**From an agent:** point any MCP client at `n0xis-mcp` — 25 tools returning the identical
`{ok,data,meta}` envelope, JSON-RPC over stdio.

```json
{ "mcpServers": { "n0xis": { "command": "/path/to/n0xis-mcp" } } }
```

## What it does

- **Decompile** — an optimizing SSA decompiler (Memory-SSA, phi-web variable coalescing,
  complete SSA destruction, exact branch conditions) whose **optimizer reports every rewrite it
  made** (`--explain`: which sub-pass changed what, at which address), not a black-box answer.
- **Scan live memory** — value/pointer/AOB scanning with snapshot-backed narrowing, freeze,
  code-cave hooks. the full scan → narrow → freeze → patch loop.
- **Watch & explain** — software / hardware / conditional breakpoints and a real cross-process
  unwound call stack; the raw material provenance is built on.
- **Recover names** — C++ classes from RTTI on both ABIs (MSVC `.rdata` chains and Itanium
  `_ZTV` symbols), .NET NativeAOT `RVA ↔ Namespace.Type.Method`, LuaJIT, Bitsquid, IL2CPP —
  so a stripped image reads as source, not `sub_XXXX`.
- **Persist & diff** — `.n0xt` tables, versioned annotations, content-addressed caching,
  function/version diffing.

Windows **and** Linux, PE **and** ELF, one pipeline — static files, live processes, snapshots
and remote targets all flow through the same passes and the same versioned JSON.

There is no ML nondeterminism in the core, ever. A desktop GUI lives in a separate repo:
**[n0xis-gui](https://github.com/Structio-labs/n0xis-gui)**.

## Status

**Alpha.** Every claim below is a measurement against a source outside the tool — the kernel,
the image's own tables, or the target process itself. Where there is no such source, it says so,
because *implemented* and *verified* are not the same claim.

**Live memory**, against a disposable target that plants known values:
- **Linux — 29 of 31 commands measured against `/proc/<pid>/mem`, one wrong and fixed.** The
  other two are Windows-only and refuse saying so. The one wrong was `scan dissect`, which
  chose a field's width before its alignment and so read a struct four bytes out of phase from
  its first mistake on: one field of six right against a layout known from its own source, five
  of six after.
- **Windows 11 — 21 of 23 checks measured, 0 wrong**, with the target itself as the oracle.
  `ui focus` correctly finds no window on a console target; `stack backtrace` is
  **Linux-only** — the one place the Linux adapter is ahead.

**The decoder**, against an independent disassembler — the floor everything else stands on,
and until now checked only by the passes built on top of it, which all read the same stream:
- x86: instruction **boundaries** compared with `objdump`. Three purpose-built shapes exact,
  **20 000 instructions of a shared library and 20 000 of a 32-bit system DLL, zero
  disagreements** and zero boundaries either side had alone. Widened to **60 000 instructions
  of a 334 MB stripped browser binary: 2 disagreements, both inside an ASCII string embedded
  in `.text`** where the reference itself decodes `(bad)` — not code, and neither reading is
  the right one.
- AArch64: **mnemonics** compared with `llvm-objdump` (fixed-width encodings make boundaries
  vacuous). See the ARM64 line below.
- AArch64, **the encoding space rather than compiler output**: 600 deterministic words judged
  by `llvm-mc --mattr=+all` and by n0xis. 241 both call an instruction, 304 both reject —
  and **48 (8.0%) are reserved encodings n0xis reads as instructions**, with 7 (1.2%) real
  instructions it rejects (mostly LSE atomics). Three of the 48 were decoded by hand and are
  genuinely UNALLOCATED. That gap is **held by a bound that fails if it grows**, and stated
  here rather than left out: a reserved word read as an instruction turns data into a
  plausible program.

**Function extents**, against the image's own unwind table and the linker's export list:
- every FDE's `start..end` from `objdump --dwarf=frames` equal to the recovered extent —
  **3 787 compared on this machine (10 + libc's 3 777), start and end, exact**; separately
  measured at 15 467 and 14 355 on two large libraries.
- **0 exported entry points missed** by the function list: 10 of 10 on the oracle shape and
  **2 323 of 2 323 inside libc's scanned window**.

**Cross-references and the call graph**, against the disassembly of a source that is not this
tool:
- **4 733 references across the six busiest targets of a system C library — none missed and
  none invented**, in both directions. `call`, tail-call `jmp` and RIP-relative data
  references are each labelled by `kind`, and each was compared against what `objdump` shows.
- **304 call sites across 100 functions — none missed and none invented**, with each
  function's extent taken from the unwind table rather than from a symbol boundary, and a
  tail call (including a *conditional* one) counted as the call it is.
- **464 branch targets across 100 functions, every one of them the start of a basic block.**
  A target the splitter misses leaves two blocks fused, so an edge that exists in the program
  does not exist in the graph — and nothing above it can notice.

**Recovered struct fields**, against the compiler that laid the struct out:
- `gcc -g` states every member's offset; **15 recovered field offsets across 10 functions,
  every one a real member — none invented.** One-directional on purpose: an optimizer folds
  and drops field accesses, so a member that never appears is the compiler's doing, not a miss.

**Static analysis**, against the extents and tables the image declares:
- x64 ELF and PE: function extents exact, 0 CFG-invariant violations over 92 001 edges.
- **ARM64 — decoder and CFG verified, decompiler not.** 2 381 of 2 381 function extents exactly
  equal to the symbol table, 0 violations across 46 757 CFG edges. The decoder is now checked
  against **LLVM's own AArch64 disassembler** over compiler output built for the purpose
  (`oracle/arm64.c` at `-O2`): **147 instructions, 147 shared addresses, 0 failures to decode,
  and every one of the 28 name differences a documented architecture alias** (`mov`/`orr`,
  `cmp`/`subs`, `b.hs`/`b.cs`, …), each listed in the test rather than forgiven in bulk. The
  AArch64 lift/SSA is still not built, so `decomp pseudo` reports `quality: 0.0` and falls back
  to `asm` nodes. The optimizing decompiler is **x64-only**.
- 32-bit PE: 422 of 422 exported entry points discovered, 0 violations over 34 149 edges.
  On a 32-bit image with **no exception table at all**, checked against the 3 889 `.eh_frame`
  FDEs an independent parser reads out of it: **0 missed, every extent exact, 0 entries interior
  to a known function.** The rule was written against x64 exception tables and holds on an
  architecture that has none.

**Recovered signatures**, against targets compiled here whose answer is known before the
question is asked (`oracle/`):
- **12 of 12 on both x86-64 ABIs** — parameter count, which register file each parameter
  arrives in, and return class, including both orders of a mixed integer/floating signature
  (System V and Win64 count their two argument register files by different rules).
- 32-bit `cdecl` states no arity on the way out and passes nothing in a register, so the
  parameter list reads `()` — C for *unspecified* — and not `(void)`, which would be a claim
  that there are none. The x87 return this lift does not model reads `/*unknown*/`, not `void`.
  Both gaps are recorded in `oracle/expect.json` with their reason, and the test **fails if one
  quietly closes**, so a recorded limitation cannot rot into folklore.

**Recovered C++ classes**, against the image's own type-descriptor strings:
- **93 vtables on a 32-bit C++ runtime (0 before), 97 and 152 on two 64-bit ones, 269 on an
  ELF through the Itanium path — and every recovered name present in the image's own
  strings**, so none is invented. Both MSVC dialects have planted regression fixtures
  (`oracle/rtti32.c`, `oracle/rtti64.S`), because no compiler here emits MSVC RTTI.

**Not verified, and not claimed:** `il2cpp import` / `symbols` need an external dumper's index;
`il2cpp obj` / `classes` need a live managed process. The versioned JSON contract has not been
road-tested by outside users — expect shapes to move.

## Docs

- **[docs/CLI_COMMANDS.md](docs/CLI_COMMANDS.md)** — every command (the inventory is generated
  from the binary), the schema id each emits, and the caveats behind each claim. Arguments live
  in `n0x guide` and `--help`, which are generated too.
- **[oracle/README.md](oracle/README.md)** — the corpus of targets whose answer is known
  before the question is asked, how the ranking of sources works, and how to add a shape.
- **[CONCEPT.md](CONCEPT.md)** — architecture: adapters, passes, seams.
- **[ROADMAP.md](ROADMAP.md)** — build history and the analysis capabilities still missing.
- **[MAP.md](MAP.md)** — the 15-crate workspace layout.
- **[docs/COMMUNITY_ROADMAP.md](docs/COMMUNITY_ROADMAP.md)** ·
  **[docs/PRODUCT_POLICY.md](docs/PRODUCT_POLICY.md)** · **[CONTRIBUTING.md](CONTRIBUTING.md)**

## License

N0xis is **source-available** software, developed under the Structio name.

- **Free for noncommercial use** — personal projects, research, education, CTFs, hobby reverse
  engineering, and use by noncommercial organizations, under the
  [PolyForm Noncommercial License 1.0.0](LICENSE).
- **Commercial use requires a paid license** — see [COMMERCIAL.md](COMMERCIAL.md).

Versions up to and including 0.2.1 were released under AGPL-3.0 and remain available under
those terms. This license applies to 0.3.0 and later.

Not sure whether your use case is commercial? Open an issue or email <structio.dev@gmail.com> —
I'd rather answer a question than chase a violation.

# Verification ledger

The one place that says **what has been checked, against what, and what is still
open** — so a proven claim, an open gap, and a thing never claimed are all visible
together. It is a status board, not a re-copy of the numbers: each row points at
where the measurement lives (README §Status, `ROADMAP.md`, or `oracle/README.md`),
and the discipline behind it is in [oracle/README.md](../oracle/README.md).

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

## Proven

| Check | Source | Rung | Cases | Result |
| --- | --- | --- | --- | --- |
| Decoder instruction boundaries (x86) | `objdump` | 3 | 20 000 + 20 000 + 60 000 insns | 0 disagreements; the only 2 are inside an ASCII string in `.text` where `objdump` itself decodes `(bad)` |
| Decoder mnemonics (AArch64) | `llvm-objdump` | 3 | 147 insns | 0 fail to decode; 28 name differences, each a documented architecture alias |
| Decoder encoding space (AArch64) | `llvm-mc --mattr=+all` | 3 | 600 deterministic words | 48 (8.0%) reserved words read as instructions, held by a bound that fails if it grows; 7 (1.2%) real insns rejected — stated, not hidden |
| Emulator vs the processor | the CPU (planted inputs) | 1 | 20 400+ comparisons (leaf, FP, calls, Win64, 32-bit, switch, packed SIMD) | 0 disagreements. The oracle harnesses now attach the symbol table the real pipeline uses (`.with_symbols`) — a starved `Ctx::new` had left `the_emulator_follows_a_call` stubbing 48 calls it should follow; with symbols it steps into 1 664 callee frames, not 1 616 (2026-09-14). |
| Emulator, ELF32 axis | the CPU | 1 | 3 888 (gcc/clang × O0/O1/O2/Os + PE32/mingw) | 0 disagreements — this axis had **never run** before 2026-09-11 (a malformed argv skipped it); now live |
| AArch64 lift vs the processor | the CPU, under `qemu-aarch64-static` | 1 | 960 answers over 120 function builds | 526 reproduced, 0 disagreements, 434 not modelled (see OPEN: `-O0`, extending-add) |
| Function extents | the image's own unwind table (`objdump --dwarf=frames`) | 2 | 3 787 + 15 467 + 14 355 FDEs | start and end exact |
| Exported entry points | `nm -D` | 3 | 10/10 + 2 323/2 323 | 0 missed |
| Cross-references & call graph | `objdump` disassembly | 3 | 4 733 refs; 304 call sites; 464 branch targets | none missed, none invented, both directions |
| Recovered struct fields | `gcc -g` DWARF | 1 | 15 field offsets over 10 functions | every one a real member; none invented |
| Static CFG invariants (x64) | the image's tables | 2 | 92 001 edges | 0 violations |
| Static CFG invariants (ARM64) | symbol table | 2/3 | 2 381 extents, 46 757 edges | extents exact, 0 violations |
| Static CFG invariants (32-bit PE) | `.eh_frame` (independent parser) | 3 | 422 entries, 34 149 edges, 3 889 FDEs | 0 missed, every extent exact |
| Recovered signatures | `oracle/` (compiled here, answer known) | 1 | 12/12 on both x86-64 ABIs | arg count, register file, return class correct; recorded gaps (cdecl arity, x87 return) fail the test if they quietly close |
| Recovered C++ classes (RTTI) | the image's own type-descriptor strings | 2 | 93 + 97 + 152 vtables (MSVC), 269 (Itanium) | every recovered name present in the image's strings |
| Live memory (Linux) | `/proc/<pid>/mem`, planted values | 1 | 29/31 commands | one wrong, found and fixed; 2 are Windows-only and refuse saying so |
| Live memory (Windows 11) | the target process itself | 1 | 21/23 checks | 0 wrong; `stack backtrace` is Linux-only |
| CLI ↔ registry front doors agree | the tool's two doors, one question | 5→contract | 4 pairs | agree; a Windows JSON-escaping bug in the *test* found and fixed 2026-09-11 |
| Discontiguous functions (hot/cold split `<fn>.cold`) | the processor, under gcc-14 `-O2` | 1 | a_switch, all levels | 768 agree, 0 disagree, 0 not modelled; the `.cold` partition folds into its parent so the switch default has a successor (fixed 2026-09-13, was 46/0/2 at `-O2`) |
| Range-scoped IL2CPP managed-name attachment (PE) | a committed fixture PE (`native_pe.dll`) | 2 | 6 tests | bind + attach through the single-address and the range path; deterministic (no self-image, no toolchain), gates CI on both OSes, calibrated (2026-09-14) |
| An IL2CPP index names only the binary it was imported for | `nm`/`objdump` on a second fixture PE | 3 | cross-binary test | import an index for A, analyse B → B keeps its real symbol, no fabricated managed name. Provenance (build-id / `.text` fingerprint) gates auto-attach; a mismatch or a provenance-less index does not attach. Found by the gcc-14 hunt; fixed and calibrated 2026-09-14 |

The full prose, with every caveat, is in the [README §Status](../README.md#status)
and `ROADMAP.md`. Numbers here are that same measured state, not a second copy to
drift — if a row and the README disagree, the README/ROADMAP measurement wins and
this row is stale.

## Open

| Gap | State | Where |
| --- | --- | --- |
| AArch64 **lift `-O0`** | Unmeasured: `-O0` reproduced 0 of 240 because stack stores are not lifted; the "526 of 960" figure rests on `-O1/-O2/-Os` only. Not "55% coverage" of AArch64 generally. | AArch64 lift oracle |
| AArch64 extending-register add | The dominant remaining `Unlifted` at optimised levels (`add x0, x0, w2, uxth`). | AArch64 lift oracle |

## Not claimed (needs an input/platform not present)

| Capability | What it needs |
| --- | --- |
| The optimizing decompiler on AArch64 | The lift/SSA is not built; `decomp` falls back to `asm` (`quality: 0.0`). Decoder + CFG are verified (above); the decompiler is x64-only. |
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
cargo test --workspace --features n0xis-core/oracle,n0xis-cli/oracle,n0xis-sources/oracle
```

A "green CI" therefore means the deterministic suite passed, **not** that every
row above was re-checked on that runner. The oracle rows are re-checked wherever
the toolchain is pinned.

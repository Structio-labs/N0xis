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
| Live memory (Windows 11) | the target process itself | 1 | 21/23 checks | 0 wrong; `stack backtrace` is Linux-only. Re-checked 2026-10-04 with `oracle/windows/run.sh`: 12/12, and the Linux and Windows builds agree on the same PE |
| CLI ↔ registry front doors agree | the tool's two doors, one question | 5→contract | 4 pairs | agree; a Windows JSON-escaping bug in the *test* found and fixed 2026-09-11 |
| Discontiguous functions (hot/cold split `<fn>.cold`) | the processor, under gcc-14 `-O2` | 1 | a_switch, all levels | 768 agree, 0 disagree, 0 not modelled; the `.cold` partition folds into its parent so the switch default has a successor (fixed 2026-09-13, was 46/0/2 at `-O2`) |
| Section reads (ELF) | `readelf -SW` offsets, the file's own bytes | 2/3 | 204 692 file-backed sections in 9 367 ELF files on one system | 0 read wrongly (348 in the first 2 000 files before the `.tbss` fix below); a local sweep, `elf_reads_agree_with_readelf.rs` |
| Byte windows across gaps (`mem span`) | `readelf -SW`, `llvm-readobj --sections`; a live process's planted pages | 3; 1 | 4 windows on an ELF and a PE fixture, plus an empty one; one live window over an unmapped page | every stretch and every gap where the section tables put them, bytes identical to the files' own; live, both stretches and the hole exactly as planted |
| Range-scoped IL2CPP managed-name attachment (PE) | a committed fixture PE (`native_pe.dll`) | 2 | 6 tests | bind + attach through the single-address and the range path; deterministic (no self-image, no toolchain), gates CI on both OSes, calibrated (2026-09-14) |
| An IL2CPP index names only the binary it was imported for | `nm`/`objdump` on a second fixture PE | 3 | cross-binary test | import an index for A, analyse B → B keeps its real symbol, no fabricated managed name. Provenance (build-id / `.text` fingerprint) gates auto-attach; a mismatch or a provenance-less index does not attach. Found by the gcc-14 hunt; fixed and calibrated 2026-09-14 |

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
| In a `serve` session, `find --bytes <pattern>` searched the project's default file instead of the session's (the pattern was taken for an inline-bytes source), and `dump save` stored the whole session image as a note, both `ok:true`; a command reading stdin hung the session | a session decides "names its own source" from the command's argument ids, not flag spellings, and adds `--file` only where a source argument of that id exists; reading stdin inside a session is refused with `stdin-is-session-channel` (`082a4a4`, `5fd4eda`) | session tests with planted bytes and a decoy project; a stored note read back exactly; a deadline so a hang fails |

The full prose, with every caveat, is in the [README §Status](../README.md#status)
and `ROADMAP.md`. Numbers here are that same measured state, not a second copy to
drift — if a row and the README disagree, the README/ROADMAP measurement wins and
this row is stale.

## Open

| Gap | State | Where |
| --- | --- | --- |
| AArch64 **lift `-O0`** | Unmeasured: `-O0` reproduced 0 of 240 because stack stores are not lifted; the "526 of 960" figure rests on `-O1/-O2/-Os` only. Not "55% coverage" of AArch64 generally. | AArch64 lift oracle |
| AArch64 extending-register add | The dominant remaining `Unlifted` at optimised levels (`add x0, x0, w2, uxth`). | AArch64 lift oracle |
| `function discover` lists chained unwind fragments as functions | Measured 2026-10-04. An unwind entry flagged `UNW_FLAG_CHAININFO` continues another function (confirmed with `llvm-readobj --unwind`), yet `--pdata` lists every such entry as a function: 43 / 1 672 / 1 155 / 373 on four PE32+/MSVC system DLLs (0.9 / 2.6 / 1.4 / 2.0 MB), none of them a function the matching PDB names. The prologue scan lists the same fragments (all of them on three DLLs, 1 669 of 1 672 on the fourth). | PDB oracle, ROADMAP gap-closing item 1 |
| Functions a PDB names that discovery misses | Measured 2026-10-04 on the same four DLLs: 41 / 14 / 20 / 10 function publics found by neither discovery mode. Not yet triaged: each is either a missed function or a public flagged as code that does not start a function. | PDB oracle, ROADMAP gap-closing item 1 |
| `provenance trace` names neither the function nor the global | Measured 2026-10-05 on Linux with `examples/config-demo` built `-O2 -g`: the write's address, the instruction (`objdump`: the byte store at `decrypt_config+0x36`) and the containing function are right, but `function_name` is `null` and the statements read `*(uint8_t*)((rdi.1 + v2)) = …`, although the ELF's symbol table names `config` and `decrypt_config`. The README says so beside its example. | `nm` and `objdump` on the same binary |
| Data exports reach `sig gen` | Measured 2026-10-05: `named_functions()` still includes named exports outside executable sections, 4 814 of 152 546 across 123 images (9 on one x64 system DLL), so a data export can be fingerprinted as code. | Section flags of the image |
| `decomp pseudo` on a non-executable address | Measured 2026-10-05: it decodes the bytes as code and answers `ok:true` with no note, where `disasm` adds one. | Section flags of the image |
| An ELF's headers read as unmapped | Measured 2026-10-05: `mem read --file` at the image base answers "not mapped", while the first `PT_LOAD` maps the ELF header and program headers there (`readelf -l`), and a PE image maps its headers. The ELF map follows sections, not segments; mapping the headers would make small constants in a position-independent image look like addresses, so it is left as is until the pointer checks that use the same map can be held apart. | `readelf -l` on the same file |
| `--file /dev/stdin` inside a session | Not guarded: given explicitly in a `serve` session, it would read the request channel as a file. Not measured beyond reading the code. | Session test |

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

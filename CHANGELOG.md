# Changelog

All notable changes to N0xis are recorded here. Versions follow
[Semantic Versioning](https://semver.org); dates are ISO-8601.

## [0.2.1] — 2026-08-31

The decompiler jump: from a Memory-SSA foundation to **source-level
readable pseudocode with C++ class recovery**, verified rung by rung on
real AAA game binaries **and** system libraries (see `ROADMAP.md`). Every
item below was confirmed on a real target under the verify-before-✅ rule —
no ML nondeterminism, sound over complete throughout. 56 commits.

### Alias / points-to (Rung 2)

- **2a — escape analysis.** A stack slot whose address never becomes a value
  cannot be touched by a call, a foreign-base store, or an unknown-address
  store — so store-to-load forwarding now survives calls (the block on
  call-heavy real code). Sound on both ABIs, including the System V red zone
  and the Win64 shadow space. Cross-block forwarding on `CompressToolsLib.dll`
  jumped 0 → 28 of 400 functions.
- **2b — global (distinct-constant) disambiguation.** Two different absolute
  addresses provably cannot alias, so a store to global A no longer clobbers a
  value available at global B. Sound at every boundary (a register store still
  clobbers a global; a call still clobbers all globals).
- **2c — heap-allocation disambiguation.** Two distinct heap allocations never
  overlap, so a store through one does not clobber a value available at the
  other. Allocation bases are the results of curated allocator calls (malloc/
  calloc/`operator new`/`HeapAlloc`/OpenSSL `CRYPTO_*alloc`/…; `realloc`/`free`
  excluded). The points-to gap other tools were ahead on — closed.

### C++ RTTI / class recovery (Rung 7a)

- **MSVC RTTI vtable → class recovery.** `rtti scan` walks `.rdata`'s
  COL→TypeDescriptor chains, validated by the COL self-reference. On `Kenshi`
  it recovers **3055** vtables; on STALKER 2 (UE5), **561**.
- **Into the decompiler.** A vtable constant renders `&Class::vtable`; a
  constructor's `this` types to its class (`std::exception *rcx`, not
  `struct_rcx_0 *rcx`); templated names demangle fully (`std::vector<int>`);
  and the **base-class inheritance graph** is reconstructed from the RTTI
  class-hierarchy descriptor (`std::bad_array_new_length : std::bad_alloc,
  std::exception`; STALKER 2's 5-level ICU chains). Verified against known STL
  ground truth.

### Readable variables & types (Rung 3)

- **3b — parameters named in the body** (`rcx.0` → `rcx`).
- **3c — SSA-version coalescing**: a register's phi-web collapses to one named
  variable (the a source-level decompiler readable-locals win); guarded by liveness +
  interference so the lost-copy / swap / pre-update hazards are refused.
- **3d — complete SSA destruction** via edge copies (critical edges split), so
  no phi destination renders undefined.
- **3e — a source-style typed-locals declaration block** at the top of the
  function.
- **3f — signedness inference from use** (a value compared with `jl`/divided
  with `idiv`/arithmetic-shifted is signed).

### Calling conventions (Rung 4)

- **4b — lift-padding call arguments dropped.**
- **4c/4d — ABI-aware argument recovery and call sites**: System V **and**
  Win64, selected from the source (`sysv` for ELF, `win64` for PE) — an ELF's
  parameters and call sites recover the System V registers, and caller-saved
  `rsi`/`rdi` are correctly invalidated across a System V call.

### Expression & idiom quality (Rung 5)

- **5b — stack-canary recognition** (`__stack_guard(...)`).
- **5c — SSE data-move lift** (`movups`/`movdqu`/`movaps`/`movdqa` → 128-bit
  moves; ~4272 `// asm:` lines removed).
- **5d — `setcc` condition reconstruction**; **5e — `cmovcc` → ternary
  select**; **5f — `min`/`max` idiom fold**.
- **5g — immediate rotate lift** (`rol`/`ror` → shift/shift/or, laying hash
  mixes bare); **5h — the intrinsic layer** (bit-scan, SSE mask/compare, scalar
  and packed FP, int↔FP conversions — the `// asm:` census collapses from
  thousands to a handful); **5i — BMI/BMI2 + sign-extend** (`shlx`/`bzhi`/
  `mulx`/`cdqe`/`btr`…, from the STALKER 2 newer-ISA finding).

### Readability structuring (Rung 6)

- **6a — `switch` dispatcher + case recovery** (real `switch (rax) { case
  0xK: }`).
- **6b — tail-duplicate shared return regions** (residual gotos ~halved).
- **6c — invert empty-then ifs / drop empty else** (empty-then ifs 398 → 15).
- **6d — `do/while`** when the loop header is an inner branch.
- **6e — negative struct-field offsets read signed** (`field_neg_0x8`, not the
  two's-complement giant hex).
- **6f — else-if chains** (`else { if }` → `else if`).
- **6g — `for`-loop recovery** by induction-step hoisting, verified against
  ground-truth compiled C (gcc/clang -O1/-O2).

### Architectures & formats

- **32-bit i386 (PE32)** — correct decode instead of the previous silent
  mis-decode-as-x64 (the worst class of agent-native bug).
- **AArch32 (ARMv7)** — a full A32 + Thumb lift with predication and sound
  Thumb IT-block handling, shift and shifted-index memory; for the 32-bit ARM
  TV-box target.
- **Static ELF loading** as a first-class source alongside PE.

### Verification breadth

- Beyond games: a final regression sweep decompiled **1000/1000 functions with
  0 errors** across 10 binaries — Kenshi, STALKER 2, Factorio, and the system
  set `ls`/`openssl`/`libcrypto`/`sqlite3`/`git`/`libc` (avg quality
  0.960–0.998). The static pipeline is robust well beyond the game corpus.

## [0.1.1] — 2026-08-30

Decompiler analysis-depth: three verified rungs on the path to
source-level pseudocode (see `ROADMAP.md`). Every item was confirmed on
real Win64 binaries, not just unit tests.

### Added / Improved

- **Rung 5a — branch conditions from arithmetic flags.** A `Jcc` after a
  result-keeping op (`dec ecx; jne`, `sub rax,rbx; je`, `and edx,edx; jne`)
  now reconstructs its condition instead of rendering `/*cond(jne)*/`.
  Loop latches get a visible condition again — on `CompressToolsLib.dll`,
  69 of 75 loop headers now carry a real condition (e.g.
  `while ((*(uint8_t*)(rdx.0 + rbx.3) != 0x0))`). Sound-conservative: only
  `je`/`jne` are recovered (sign/magnitude branches depend on carry/overflow
  the result alone doesn't carry and stay opaque), and 8/16-bit or memory
  destinations stay opaque.
- **Rung 4a — precise register-argument arity (Win64).** A register counts
  as a parameter only when used outside a bare pass-through call argument, so
  the lift's fixed four-register call convention no longer pegs every calling
  function at `(rcx, rdx, r8, r9)`. On `CompressToolsLib.dll` the arity-4 rate
  dropped from ~100% to a realistic 0–4 spread. A demangled C++ prototype is
  now used verbatim as the signature instead of being wrapped into a garbled
  `uint32_t <prototype>(uint64_t rcx, …)`.
- **Rung 3a — parameter typing from use.** A parameter's signature type is
  inferred from how it is used: a dereferenced pointer reads `struct_rcx_0 *rcx`
  (the C++ `this`) or `void *`; a known-Win32 argument gets its API type
  (`HANDLE`, `LPCWSTR`, …); otherwise `uint64_t`. 87 of 120 functions on
  `CompressToolsLib.dll` recover a pointer/struct parameter type.

### Notes

- Argument-arity recovery is Win64-register-specific; System V (`rdi`/`rsi`/…)
  and whole-program call-site agreement are tracked follow-ons.
- The known-API parameter-type path is unit-tested but not yet confirmed
  firing on a real target (the corpus dereferences its pointer params, so the
  struct rule wins by precedence).

## [0.1.0]

Initial v1 pipeline: static PE/ELF + live-memory analysis, optimizing SSA
decompiler with Memory-SSA (Rung 1), watchpoint→decompiled-statement
provenance, managed-runtime name recovery (IL2CPP / .NET NativeAOT / LuaJIT /
Bitsquid), and journaled patching — one `{ok,data,meta}` contract over CLI and
MCP.

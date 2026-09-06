# Changelog

All notable changes to N0xis are recorded here. Versions follow
[Semantic Versioning](https://semver.org); dates are ISO-8601.

## [Unreleased]

### The hidden return slot survives a stack spill (Phase 10)

- **A large-object getter parks its result buffer on the stack.** The x64 ABI
  marker for a by-value return — the function hands the caller's buffer back in
  `rax` — was matched through copies and phis, but not through **memory**.
  `QFontIconEngine::scaledPixmap` spills the buffer for the length of the
  function and returns the reload, so nothing in the copy graph connects the
  returned value to the argument register, and the function looked like an
  ordinary method whose `this` was the buffer. The marker now tracks the *slot*
  the buffer was stored into, and the reload out of it counts.
- **Measured, same binary and build, over 1 460 methods:** resolved virtual
  calls **83 → 88**; the `sizeof` oracle over 21 public Qt classes **17 → 18**
  inside the true object size — `QMovie` was one of these getters. Typed class
  fields **89 → 90**, propagated parameters **105 → 106**.
- **Two correct refusals confirmed while measuring, not worked around.** A
  dispatch like `(*this->d->field_0x1a8)(…)` where `QTextDocumentPrivate`'s
  whole vtable is 11 slots is a call through a **function-pointer field of the
  object**, not a virtual call; the vtable-bound check refuses it, and that is
  the right answer rather than a gap. The `operator=` family genuinely returns
  `*this`, so the argument shift can mis-fire there — the layout oracle is the
  check that would catch it, and it did not.

### A virtual call's own target was being deleted as dead code (Phase 10)

- **`stmt_read_exprs` never yielded an indirect call's target.** Use-counting
  therefore saw zero uses of the variable a C++ virtual dispatch loads the vptr
  into — its only consumer *is* the call target — and dead-code elimination
  deleted the load. What survived was a call through a variable nothing defined,
  which cost three things at once: the argument register it came from dropped out
  of the recovered arity, the class that register identified was lost, and the
  dispatch could not be resolved. Measured on a Qt shared library: **232 of 274**
  unresolved virtual dispatches were exactly this.
- **`this` is argument *one* in a member function that returns by value.** The
  x64 ABI puts the caller's result buffer in the first argument register and
  shifts `this` to the second. That was already detected — and used only to
  *refuse* the function, which threw the class away for everything it did,
  including the virtual calls it makes on `this`. It is now read as what it is: a
  shift. `QFontIconEngine::pixmap()` recovers `(QPixmap *ret, QFontIconEngine
  *this, …)` and its dispatch resolves. Every by-value getter — `pixmap()`,
  `toImage()`, `text()` — is this shape.
- **Devirtualization sees through a phi whose inputs agree.** The compiler's own
  devirtualization guard (`if (slot != &known) call *slot; else call known;`)
  puts the vptr in a phi, and the definition map was built from assignments only,
  so the walk stopped at the join. A phi is now folded when **every** incoming
  value has a defining expression and they are all structurally equal — a phi
  whose inputs disagree is left alone.
- **Measured, same binary and build, over 1 460 methods:** resolved virtual calls
  **65 → 83**, in **55 → 68** functions; dispatches still rendered
  `(*x->field_0xNN)(…)` **277 → 266**. Class layouts: **373 → 382** classes,
  **3 360 → 3 943** methods, **2 363 → 2 467** fields; whole-program propagated
  parameters **84 → 105**. The `sizeof` oracle over 21 public Qt classes is
  **unchanged at 17 of 21** — the shift's known false positive is `operator=`,
  which genuinely returns `*this`, and the oracle is what would have caught it.

### AVX data movement is lifted, not printed as assembly (Phase 10, item 4)

- **The VEX/EVEX spelling of a move now lifts like the legacy one.** `movups`,
  `movdqa` and friends had been lowered to load/store/copy for a while; their
  `v`-prefixed forms had not, so on any binary a modern compiler emits they came
  out as `// asm:` nodes — holes the SSA cannot see through. Added `vmovdqa`,
  `vmovdqu` (and the AVX-512 `32`/`64`/`8`/`16` element-size spellings),
  `vmovaps`, `vmovapd`, `vmovups`, `vmovupd`, the non-temporal `movntdq` family,
  and the cross-domain scalars `vmovq`/`vmovd`/`vmovsd`/`vmovss`. Width comes
  from the register operand, so a 256-bit `vmovdqa ymm0, [rax]` is a 256-bit
  load rather than a guess.
- **`endbr64` and `vzeroupper` lower to nothing.** The first is a CET landing
  pad — architecturally a `nop`. The second clears the lanes above 128 bits,
  which this model does not represent at all (a vector register is one SSA name,
  no lanes), so there is nothing here for it to clear.
- **A masked EVEX move is deliberately refused.** With a `{k}` operand the move
  is conditional per element; lifting it as an unconditional one would state
  which bytes changed when the mask decides that at run time.
- **Measured over 1 460 methods of a Qt shared library:** `// asm:` nodes
  **14 268 → 6 655**, and the functions carrying any at all **1 460 → 646** — 814
  of them are now lifted end to end. Recovered class fields **2 084 → 2 363**: a
  16-byte `vmovdqu [rdi], xmm0` is a field write, and every one of them used to
  be invisible. Parameters carrying a type at all **21 193 → 22 103**.
- **`typeflow_propagated_params` reads 100 → 84, and that is the metric being a
  delta, not a regression.** It is `now_typed − locally_typed`: 910 more
  parameters are typed *locally* than before, so fewer of them need propagation
  to fill in. The absolute count is reported above for exactly this reason.
- **What it did not buy, stated rather than omitted.** The unlifted AVX was the
  leading suspect for the virtual dispatches that stay unresolved even where the
  class and its vtable are both known. It was not the cause: over the same 1 460
  methods, unresolved dispatches through a field are **277 before and 277
  after**. The class layout oracle is likewise unchanged at 17 of 21 Qt classes
  inside the true object size — with one honest movement, `QTextDocument`'s
  extent growing `0x18` → `0x20` because the by-value return buffer it already
  mis-attributed at `+0x10` is now seen at its real 16-byte width.

### The `this` seed reads the symbol table Linux actually has (Phase 10 / 3b)

- **`own_this_class` demangles.** The seed that types a method's `this` read the
  **raw** symbol, and the only mangling it understood was MSVC's. An ELF symbol
  table hands out `_ZNK7QPixmap6isNullEv`, in which no `Class::method` test
  matches anything, so on Linux the seed fired only on the names N0xis's own
  vtable walk had synthesized — **69** of them on `libQt6Gui.so.6`, against
  **9 782** mangled method symbols sitting unread in the same table. It now runs
  the same demangle the layout pass already did, and shares one implementation
  with it, so the class a signature claims and the class a layout files fields
  under cannot disagree. Whole-program **propagated parameters 13 → 100**;
  layout **2 682 → 3 331 methods**, **353 → 369 classes**, **2 036 → 2 084
  fields**, **85 → 88 typed**.
- **A const-qualified Itanium symbol proves non-staticness.** A static member
  function has no `this` to qualify, so `_ZNK…` (or `_ZNV…`) *cannot* be a
  static — the first positive evidence of member-ness that exists on ELF, where
  nothing else in a symbol distinguishes `QPixmap::isNull() const` from a free
  function. It is what lets a class with no vtable of its own contribute
  ordinary methods, not just constructors. The converse is not claimed: a plain
  `_ZN…` may be either, and stays refused unless RTTI recovered a vtable for the
  class.
- **The hidden return slot is caught where it actually occurs.** The `sret`
  refusal matched the returned value by SSA identity, which real code defeats
  two different ways: `QScreen::manufacturer() const` spills the `QString`
  buffer across a virtual call and reloads it, and `QAction::toolTip() const`
  hands it back through a **phi** of `this` and a stack reload. Both filed
  `QString`'s `+0x10` under a 16-byte class. The refusal now matches on the
  first-argument **register** and follows phis, and it moved into `typeinfer`
  too — the signature was typing that buffer `QTextDocument *`. Against `sizeof`
  from the real Qt headers, over 21 public classes: **14 → 17 layouts inside the
  true object size**; every one of the 4 remaining over-reports is a single
  field contributed by a single method (`methods: 1`, against 9–70 for the real
  fields).
- **The over-reports were not what the previous pass said they were.** They were
  attributed to static member functions; the measurement says otherwise — each
  one is a by-value return whose buffer reached `rax` by a route the marker did
  not follow. Two of the three fixed here were found that way, not by argument.
- **Devirtualization through a field, re-measured.** A/B over 1 460 `libQt6Gui`
  methods, the same binary and build, only `.n0x/class-layout.json` present or
  absent, counting dispatches still rendered `(*x->field_0xNN)(…)`:
  **283 → 277**. On the previous build the same A/B moved **310 → 310**.

### A class has one field layout, not one per method (Phase 10, 3b's last ⬜)

- **`function layout` / `analyze --layout`.** Field recovery was per function and
  named after the register a pointer arrived in (`struct_rdi_0`), so a class was
  described by as many disjoint half-layouts as it had methods and nothing it
  learned survived leaving the function. Keyed on the **class** instead, every
  method's observations merge into one field set, persisted to
  `.n0x/class-layout.json`. On `libQt6Gui.so.6`: 22 413 functions → **2 682
  methods, 353 classes, 2 036 fields**.
- **Fields get types, from three kinds of evidence.** An embedded sub-object
  (`&this->f` handed to a constructor), a pointer field (`this->f` handed to a
  member function as its `this`), and a class-typed value stored in. Verified
  against `sizeof` compiled from the real Qt headers: of 21 public classes,
  **19 layouts came out inside the true object size**; `QImage+0x10` is a
  `QImageData *` (agreed by 104 methods), `QWindow+0x8` a `QWindowPrivate *`,
  `QFontIconEngine+0x30` an embedded `QPixmap` — all exactly as the headers say.
- **A dispatch through a field resolves.** `this->impl->method()` — the shape
  that survived the first devirtualization pass unresolved, because the class of
  `impl` is stated nowhere in the calling function — now devirtualizes, using a
  pointer field's type from the layout. A/B over 1 156 `libQt6Gui` methods, same
  binary and build, only `.n0x/class-layout.json` present or absent: **0 → 4
  resolved virtual calls**. `QAction::~QAction` dispatches slot `0x20` of its
  `QActionPrivate *` d-pointer, and two lines earlier the compiler's *own*
  devirtualization guard loads the very address we resolve to — the code under
  analysis independently states the answer. An *embedded* sub-object is
  deliberately refused there: its first word is its own vptr, so treating
  `Widget` and `Widget *` alike would resolve a slot of the wrong table with
  full confidence.
- **`analyze` no longer analyzes with a stale context.** It built one `Ctx` up
  front and kept using it, so the whole-program phases read the binary as if the
  RTTI and signature phases — which had just written names into `.n0x/` — had not
  run. Rebuilding it after those phases: layout methods **960 → 2 682**,
  propagated parameters **3 → 13**, on the same target.
- **The class comes from the function's own symbol and never from its first
  parameter's type.** A derived class's method has a `this` that legitimately
  *is* a base-class pointer, so reading the parameter files every derived field
  under the base: it put a `QImage` at `+0x30` of a `QPlatformPixmap` the header
  says is `0x28` bytes, and inflated the `0x20`-byte `QRhiResource` to an extent
  of `0x1e20` across 145 "methods". Keyed on the symbol: `0x30` across 7.
- **The x64 hidden return slot is refused.** A function returning a large object
  by value receives the caller's result buffer in the first argument register,
  not `this`, and no Itanium symbol says so — `QTextDocument::toPlainText() const`
  filed `QString`'s fields under `QTextDocument`. The ABI requires such a
  function to hand that buffer back in `rax`, so returning your own first
  argument is now a refusal.

### Virtual calls resolve to a method (Phase 10's last ❌)

- **Devirtualization.** `(*rax.1->field_0x8)(rcx, …)` now renders
  `webrtc__rtcp__Tmmbn__vf1(rcx, …)` on a real binary: the object's class × that
  class's RTTI vtable × the slot, read out of the image and rewritten to a direct
  call, and reported in the artifact as `data.devirtualized`. Runs on the **raw**
  SSA — expression propagation destroys the recognizable dispatch shape — and
  re-optimizes afterwards so every style shows it.
- **`this` is now typed in ordinary methods, not only constructors.** A function
  whose own recovered name is `Class::…`, where `Class` is one RTTI found a vtable
  for, gets parameter 0 typed `Class *`. This was the missing seed: without it,
  **0 of 199** sampled methods of the Qt desktop PE had a class-typed parameter, so
  devirtualization had nothing to look a vtable up by. With it, 86 of 199 — and
  portable typed parameters across 8 000 functions went 457 → 1 365, doing more
  for type propagation than propagation itself.
- **Two wrong answers found by reading the output.** A slot past a class's last
  method silently read the **next class's vtable** (now bounded by the next known
  vtable's start), and identical-code folding meant one implementation carried
  another class's name (a dispatch is now named by the class it goes *through*,
  with the folded symbol kept as `implementation`).

### Interprocedural analysis (Phase 10 priority 3)

- **Function summaries** (`function summary`) — the substrate the whole-program
  passes read instead of re-analyzing a callee once per question: does it return,
  what types are its parameters and result, which volatile registers it clobbers
  (and whether that set is complete), whom it calls, and what about it is unknown.
  Using the noreturn fixpoint's own predicate for `returns` — rather than a second
  implementation of it — immediately produced the **real-corpus proof that
  whole-program noreturn propagation fires**, which had been open since August:
  on `libQt6Core.so.6`, `qt_assert` and `qt_assert_x` are flagged only because
  `QMessageLogger::fatal` was proven first, and all three are `Q_NORETURN` in Qt's
  own headers.
- **Whole-program type propagation** (`function typeflow`, persisted by
  `analyze --typeflow`) — a class recovered in one function now reaches the
  functions that touch the same object, along the call graph, to a fixpoint. Only
  *portable* type names travel: a recovered struct's name is per-function
  (`struct_rdi_0`), and letting it cross would make two unrelated callers compare
  **equal** and merge two different objects. A locally proven type is never
  overwritten by a caller's claim; two propagated claims that disagree leave the
  slot unknown. Verified end to end: with the store, `sub_140016054` in
  `Updater.exe` renders `DWORD r9` where without it the same function renders
  `uint64_t r9`. The yield is currently bounded by how many parameters carry a
  portable type at all (457 across 8 000 functions of the Qt desktop PE), so the next lever is
  richer type seeds rather than more propagation.


### CFG fidelity: exact function extents and exception edges (Phase 10 priority 0)

- **ELF function extents are facts now, not heuristics.** `Elf64_Sym.st_size` is the
  linker's own answer and the analysis was re-deriving it. New
  `SymbolProvider::symbol_size` (PE keeps the `None` default) makes `CfgPass` cut exactly
  there and `DiscoverPass` report it. Measured on `libQt6Core.so.6` against `st_size` as
  the oracle: exact boundaries **87.7% → 100.0%**, over-extended **9 → 0**, short **29 → 0**.
- **Exception edges** — priority 0's last missing piece, closed for ELF. A landing pad has
  no incoming branch (the unwinder enters it), so it was an unreachable island. `function eh`
  recovers `(try range → landing pad)` from `.eh_frame` FDEs and `.gcc_except_table` LSDAs;
  the CFG makes each pad a block leader and gives every block overlapping a protected range
  an `eh` successor; the renderer labels it. FDE count verified **identical to
  `readelf --debug-dump=frames`** (14 355), with 8 394 protected regions and 3 093 functions
  carrying pads. Unmodeled pointer encodings yield no region rather than a wrong address.
  PE `.xdata` scope tables are the sibling follow-on.


### Signature naming reaches the whole product (Phase 10 item 8)

- **`analyze --flirt <db.npat>…` persists its matches** into `.n0x/flirt-symbols.json`, so
  the function list, `xref`, the decompiler and the GUI all render library names with **no
  flag of their own**. Until now `--flirt` existed only on `decomp pseudo`, one function at
  a time, so the matcher looked like a decompiler option instead of the triage tool it is.
  The stakes, measured: a *five-line* C program linked statically and stripped discovers
  **1 436 functions, exactly one of which is the author's**.
- **Corpora chain.** `--flirt` is repeatable and merges; two corpora that disagree about
  the same bytes leave the function anonymous rather than guessing. `--flirt` also reached
  `function discover` and `ir manifest` for one-shot use without a project.
- **`sig gen` self-validates the corpus it emits** — it builds the database it would ship,
  replays the matcher against every function of the reference, and drops any signature that
  would name a different one. This closed a real false-name bug found by a ground-truth exit
  test: glibc's `__chk_fail` and `__stack_chk_fail` differ only in wildcarded displacements,
  and an alias on the glue list removed one side, so every `__stack_chk_fail` in every
  target was named `__chk_fail`. Cost of the fix on glibc: 1 signature of 1 070.
- **PLT stubs are no longer signed** (a regression from this release's ELF import work):
  a stub's bytes embed its PLT relocation index, which is specific to one binary's link
  order. The shipped zlib corpus regenerates byte-identical.
- **Verified against ground truth**: signatures learned from one statically-linked
  symbolized program, applied to a *different* stripped one — **639 of 1 438 functions
  named, all 639 correct, 0 wrong**, checked against the linker's own symbol table.


### ELF import resolution — the seam every callee-name analysis reads

- **GOT slots now resolve to import names.** `StaticElf::iat_slot` was a stub
  returning `None`, so on Linux targets every import call decompiled as
  `(**(uint64_t*)(0x6e1a78))(…)` — and, less visibly, the known-API signature
  table, thunk/tail-call recognition and noreturn CFG closure *never fired at
  all*, because each is keyed on a resolved callee name. Built from the dynamic
  relocations (`GLOB_DAT` + `JUMP_SLOT`, x86-64/i386/AArch64/ARM), with the
  provider library taken from `.gnu.version_r` (`getenv@GLIBC_2.2.5` →
  `libc.so.6`) and an honest `extern` when a binary carries none.
- **PLT stubs are named after the import they jump to**, so lazy-bound and
  `-fno-plt` binaries behave the same — the shape that matters on a *stripped*
  executable, where the call is a direct `call` to a stub. Covers `.plt`,
  `.plt.got` and `.plt.sec` (CET `endbr64`) without assuming an entry size.
- **The noreturn table learned the glibc/Itanium names** it needed to be useful
  on ELF: `__stack_chk_fail`, `__assert_fail`, `_Unwind_Resume`, `__cxa_throw`,
  `_ZSt9terminatev`, `pthread_exit`, `exit`, and the `std::__throw_*` family
  matched by mangled shape. `error(3)` is excluded on purpose — it returns when
  `status == 0`.
- **Effect, against ELF `.symtab` sizes as ground truth** (`libQt6Core.so.6`,
  309 functions with a true size): exact function boundaries **76.4% → 87.7%**,
  over-extended functions **62 → 9**, total overshoot **20 356 B → 1 771 B**.
  `_Z9qBadAllocv` had measured 1 139 B against a true 55 B, swallowing ~20
  neighbours. Zero PE regression.

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

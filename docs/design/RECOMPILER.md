# Design: static recompilation

**Status: Accepted 2026-10-19 (the open decisions are decided in §6). Nothing here is built
yet.**
Expands ROADMAP gap-closing item 11. Depends on [`ISA_AND_LIFT.md`](ISA_AND_LIFT.md) (an
exact lift) and [`IMAGE_FORMATS.md`](IMAGE_FORMATS.md) (every function entry, every import by
library). A file reference by bare name is to `crates/n0xis-arch/src/`,
`crates/n0xis-core/src/` or `crates/n0xis-core/tests/`; `ROADMAP.md` is at the repository
root.

## 1. What it is and is not

A recompiler translates a whole program's machine code into C that compiles for another
processor and computes the same thing. It is an engine capability: it works on any image the
loaders read and any ISA whose lift is exact.

It is **not** decompilation. Pseudo-C is written for a reader and approximates by design; one
wrong line breaks a program without an error. The recompiler emits the exact lift
mechanically — one C statement per IR statement, over the guest's register file and its own
address space — and leaves optimisation to the C compiler. That holds for the machine-level
statements only: the IR's ABI view of a call (arguments, a result register, clobber markers)
is not emitted (§6.5), and an operation the IR defines but C leaves undefined goes through a
helper with the IR's meaning (§4).

It is **not** a platform port. What the program calls outside itself (an operating system's
libraries) is a boundary the recompiler declares; providing those functions is a separate
project per target, outside this repository.

## 2. Shape

A new crate, `n0xis-recomp`, a consumer of the pipeline like the CLI is:

- **Input:** an image through the format seam, an `Arch` with its table of lift forms
  measured exact (§6.7; no such mark exists in the code yet), the function list (symbols,
  discovery, metadata units), the import list grouped by library.
- **Output:** a C translation unit per function group, a header declaring the guest state
  and the boundary, and a manifest (functions, their guest addresses, what was refused and
  why). A runtime outside this repository reads the header's state layout and the manifest,
  so both are versioned schemas in `n0xis-contracts` (CONCEPT §8), and the crate is reached
  through the CLI and MCP and registered in the capability registry like any capability
  (CONCEPT §3 item 5, §4).
- **Refusal is a result:** an instruction without an exact lift refuses its whole function,
  reported with the address and the instruction (§6.1); an indirect jump whose targets are
  not all known is refused and reported with its address; nothing is approximated.
  Self-modifying code has no static signature, so it is caught at run time: a store into a
  translated code range is a reported fault (a call to a cache-maintenance import is a static
  hint).

## 3. The guest model

- **Registers:** a struct of the ISA's architectural state — registers, flag bits and
  execution state — generated from one per-ISA declaration and the only place guest state
  lives (§6.3); each function takes it by pointer (§6.2). The IR has no flag bits yet (flags
  are values, `microir.rs:208-220`) and the A32 register file has no status, floating-point
  or mode register (`arm32.rs:59-76`), so the struct waits on ISA_AND_LIFT's flag bits (§3
  item 2, built in its §6 step 1) and its VFP register model and FPSCR (§8.2, built in its §6
  step 3). It carries no mode before §5 step 3 here: ISA_AND_LIFT §8.4 makes the mode at an
  address a fact of the image, known statically for each translated instruction, and defers
  the mode as state to that step.
- **Memory:** the guest's address space as a host region; a 32-bit guest's pointer is a
  32-bit offset into it, so 32-bit pointers stay 32-bit on a 64-bit host. A 64-bit guest's
  addresses do not fit one offset region (the emulator's own x86-64 layout puts the stack top
  at `0x7fff_0000_0000` and the `fs` base at `0x7f00_0000_0000`, `emulate.rs:55, 67`): it
  needs identity mapping or a page map, not decided. Loads and stores go through one inline
  accessor pair per width, with the guest's byte order, which the IR does not carry yet —
  `Load` and `Store` have none (`microir.rs:193-197, 309-313`) and the emulator is
  little-endian only (`emulate.rs:304, 309`); on A32, `setend` makes data byte order
  execution state.
- **Calls:** a direct call is a C call followed by the return-target check of §6.1; an
  indirect call or jump goes through a dispatch table from guest address to translated
  function, generated from every known entry; a miss is a reported fault, not a crash.
- **The boundary:** each import becomes an extern C function with the guest-state signature;
  the manifest lists them by library. Who implements them is not this crate's concern.
- **Non-local control flow:** `setjmp`/`longjmp`-style exception unwinding across translated
  code must land on the translated continuation; decided in §6.1.
- **Threads:** the model is single-threaded. A threaded program built here needs one state per
  guest thread and the exclusive loads and stores (`ldrex`/`strex` on A32) mapped to host
  atomics; not designed yet.

## 4. Verification

- **Rung 1, per function:** functions of a program built here from known source are
  translated, compiled for a different architecture, and must leave the same guest state as
  the original running on its own processor (qemu with the guest's CPU model named, and a
  physical board where one exists) over randomised inputs: every register, the callee-saved
  ones included, the flags, and the memory written. Comparing the return value alone passes a
  translation that clobbers a callee-saved register. This is the processor oracle the lift
  uses, one level up, and on A32 it has to be extended first: no A32 oracle follows a call
  (`CallPolicy::Execute` appears only in x86 tests); both A32 oracles name no CPU model and
  run 32-bit code on the emulator's 64-bit default stack top and word
  (`a32_memory_agrees_with_the_processor.rs:385, 420`,
  `a32_media_agrees_with_the_processor.rs:209, 238`); and the memory oracle avoids inputs that
  wrap (`a32_memory_agrees_with_the_processor.rs:28-35`). Nothing on AArch32 is checked
  against a physical processor yet (`ROADMAP.md:1348-1349`).
- **C against the IR:** one C statement per IR statement is exact only where each emitted
  operation means in C what it means in the IR, and C leaves some undefined that the IR
  defines: a `uint32_t` shifted left by a count of 32 read at run time comes back unchanged
  on the x86-64 host (`shl` keeps the count's low five bits, here 0, so 1 gives 1 and
  `0xdeadbeef` gives `0xdeadbeef`; gcc 16.2.1 and clang 23.1.1, `-O2`), while
  `Shift::apply` defines 0 (`microir.rs:116-152`); signed overflow, `INT_MIN / -1` and an
  out-of-range float-to-integer conversion are undefined too. Guards: one exhaustive match
  from IR operation to C helper with no wildcard arm, so a new operation does not compile
  without its helper; every rung-1 build with `-fsanitize=undefined,float-cast-overflow
  -fsanitize-trap=undefined,float-cast-overflow` and `-ffp-contract=off` (the shift above
  traps under it, checked; `float-cast-overflow` is named because gcc leaves it out of
  `undefined`: under `-fsanitize=undefined -fsanitize-trap=undefined` gcc runs `(int)3e9f`
  to exit 0 while it traps `INT_MIN / -1` and `INT_MAX + 1`, and clang traps all three,
  volatile inputs at `-O2`); and a differential of the emitted C against the emulator on the
  same artifact (§6.6), beside the processor comparison.
- **Whole program:** a program built here, translated entirely, produces the same output as
  the original for the same input.
- Real images are measured outside this repository; nothing specific to one of them lands
  here.

## 5. Order of work

1. Exact lift prerequisites (`ISA_AND_LIFT.md` §6, items 1–3), aimed at one ISA (A32) but not
   confined to it: item 1 moves x64 and arm64 to the new IR first. This design asks item 1 to
   include the call and return facts (§6.5) and conditions attached at lift time (§6.6), and
   item 3 the form identifier (§6.7); of these, ISA_AND_LIFT so far states only the typed
   transfer of its one `Return` (its §8.3).
2. The guest model and the emitter for straight-line code and direct calls; rung 1 on small
   functions built here.
3. Dispatch for indirect control flow; jump tables; the A32/Thumb mode of an indirect
   transfer and in-function mode switches as execution state, which ISA_AND_LIFT §8.4 defers
   to this step (a dispatch key carries the Thumb bit, and `bx` to an odd address switches
   instruction set).
4. Whole programs built here; the boundary manifest.
5. A real image, in its own project.

## 6. Decisions

Decided 2026-10-19; every file reference and measurement below was re-checked on 2026-10-20.
Items 1–4 are the draft's open questions; 5–7 were raised by its review. Each states the
decision, why, what would change it, and when it is built. "Measured" means on code built here
from the source named, on an x86-64 host, with clang 23.1.1, gcc 16.2.1 (16.1.0 for the
aarch64 cross compiler), zig 0.16.0 and qemu-arm 11.1.1.

1. **Non-local control flow** (`setjmp`/`longjmp`, SjLj exception registration, table-driven
   unwinding). Every translated return writes the guest's actual return target (the `lr`
   value, the popped word) into the state. A tail call, a `Return` whose transfer is a
   `Transfer::TailCall` (decision 5), is not such a return: control goes to its call's target,
   emitted as decision 2's `musttail`, and nothing is written as the return target. After
   every call the caller compares the return target with its own return site; on a mismatch
   it returns at once, and a dispatcher at the bottom of the host stack enters the function
   that owns the target through that function's entry switch (its start, every return site,
   every address-taken block, every landing pad). Until §5 step 4 builds the dispatcher, a
   mismatch is a reported fault naming the guest target, never a silent return. A table of
   known names is only an early refusal of what it recognises, not the guard. At the
   boundary, the caller presets the return target to its own return site before every import
   call, and only an import that transfers elsewhere (`longjmp`, a context switch) overwrites
   it. A tail call to an import is not a `musttail` across the platform boundary, which would
   leave no return site to preset: it is translated as an import call followed by a return,
   the translated function presetting the return target as before every import call, and
   returning the import's value. That call site has no guest address (no guest instruction
   follows a tail call), so the value preset there is a sentinel the boundary contract
   reserves for "the calling translated function's own continuation", never a guest address,
   and the check after the import compares with that sentinel; an import that transfers elsewhere
   (`longjmp`) still overwrites the return target, as the boundary contract says. An
   instruction without an exact lift refuses its whole function, reported with the address
   and the instruction. The check is sound only because decision 3 keeps every guest value in
   the struct: a target that matches by coincidence (a coroutine resuming at the same call
   site in another activation's host frame) still continues correctly.
   - **Why:**
     - The defect class is a return that goes somewhere other than its caller, and the IR
       cannot yet say where a return goes: `Return` carries a value, not a target
       (`microir.rs:321`); A32 `pop {…, pc}` drops the loaded `pc` and returns `r0`
       (`arm32.rs:538, 550-551`); x64 `ret` pops nothing (`x64_lift.rs:1236-1238`). A check
       at the one place the class happens covers constructs nobody listed; a name table like
       `noreturn.rs:90-92` cannot see a statically linked, stripped `longjmp`.
     - The constructs exist in code built here, and are the rung-1 fixtures of §5 step 4. A
       static ARMv6 program built with `zig cc -target arm-linux-musleabi
       -mcpu=arm1176jzf_s` calls its C library's own `setjmp`/`longjmp` and exits with the
       planted value under `qemu-arm-static -cpu arm1176`; a static C++ program built the
       same way catches its exception through the image's own EHABI unwinder, whose
       install-context ends in `ldr lr, [lr, #60]; bx lr`, which the A32 lift turns into
       `Return(r0)` (`arm32.rs:1626-1627`). With clang's `-fsjlj-exceptions`
       (`--target=armv6-none-eabi`), the landing-pad dispatch follows the epilogue with no
       incoming branch and ends in `mov pc, r0`, which `classify` reads as sequential
       (`arm32.rs:305-313`).
     - The whole function is refused because a wrong translation is worse than a missing one,
       and a refusal is a result (§2). Its cost, measured: that C library's `longjmp` holds
       restore paths for coprocessors it selects at run time from hwcap (`ldc p2`, `vldmia`,
       `ldcl p1`), so it is refused, and a whole program that links it cannot be translated
       completely, until those instructions lift exactly.
   - **Would change it:** a program built here making a non-local transfer whose target is
     neither a return site nor a recoverable entry; the compare costing a material amount on a
     benchmark built here (not measured); decision 3 letting C locals carry guest state. The
     refusal of whole functions is revisited only with a measured count of refused functions
     on programs built here.
   - **When:** the return target enters the IR with decision 5, asked of ISA_AND_LIFT §6
     step 1; the compare and the reported fault at §5 step 2; the dispatcher and entry
     recovery at §5 step 4, from ELF LSDAs, which the CFG already reads (`eh.rs:229`,
     `ir.rs:942-953`), and from ARM EHABI tables and SjLj contexts, which nothing reads yet.
     The name table reads names through the typed decoration of IMAGE_FORMATS §7.1: where C
     symbols carry a leading underscore, C `longjmp` would otherwise match the entry for C
     `_longjmp` only by accident, and C `_longjmp` and `siglongjmp`, spelled `__longjmp` and
     `_siglongjmp`, would match nothing (the table at `noreturn.rs:90-92` is compared by whole
     name, `:134`).

2. **One C function per guest function.** Every translated function has one signature: the
   state pointer, the guest memory base (decision 3) and an entry index. Edges inside it are
   `goto`; blocks entered from outside it (return sites, landing pads, address-taken blocks)
   are cases of an entry switch; every guest tail call and every dispatch is a guaranteed tail
   call (`musttail`), except a tail call to an import, which is an import call followed by a
   return (decision 1); decision 1's check follows every call. The emitted header carries
   `#if !__has_attribute(musttail)` / `#error`. The hosts measured to compile both a direct
   and a table-indexed `musttail` to a jump are recorded beside the emitter — x86-64 (Linux
   and both Windows triples), i686, AArch64, A32 and RISC-V 64 with clang, x86-64 with gcc,
   all at `-O0` — and so are those that refuse: PPC32 and MIPS32 with clang refuse with a
   build error, at `-O0` and `-O2`, every `musttail` measured that stays a call (direct to a
   function in the same translation unit or in another, and table-indexed; a same-unit call
   builds only where the callee is inlined and no call is left), and wasm32 needs
   `-mtail-call`. For such a host the fallback is a trampoline at each call site (the callee
   hands back a continuation and the caller loops), not built until a host needs it.
   - **Why:**
     - The pipeline is per function — `LiftedFunction` (`lift.rs:39-43`), `SsaArtifact` with
       the CFG's call sites (`ssa.rs:70-80`), one emulator activation per call
       (`emulate.rs:629-634`) — so emitted C and the emulator compare unit for unit, and the
       C compiler optimises across a whole function.
     - The draft's reason for one function per block was tail calls the C compiler cannot
       guarantee. Measured, they are guaranteed on the hosts above, and where they are not,
       the build fails instead of the host stack growing at run time: clang for wasm32
       without `-mtail-call` warns that it ignores `musttail`, emits ordinary calls and exits
       0, and the header guard turns that into an error. Silent stack growth is the trap the
       emulator already met: a cycle of tail calls recursed until the host stack ran out
       (`emulate.rs:488-494`).
     - Entering a block in the middle of a function, the other merit of per-block
       translation, is the entry switch decision 1 needs anyway.
   - **Would change it:** the largest function of a program built here compiling too slowly
     or being too large as one C function (not measured); a measured class of functions
     needing so many entries that the switch dominates; a function of a program built here
     that this shape refuses and per-block translation would take — then per block for those
     functions only, with their count recorded. Minimum compiler versions are not checked.
   - **When:** §5 step 2 (straight-line code and direct calls); the entry switch and dispatch
     at §5 step 3. An A32 tail call exists only as CFG metadata today — `Arm32` does not
     override `lift_tail_call`, whose default (`n0xis-arch/src/lib.rs:321-323`) keeps `b` as
     no statement (`arm32.rs:1619-1622`) — so it needs its statement from the lift first, a
     `Return` whose transfer is a `Transfer::TailCall` (decision 5).

3. **All guest state in the struct.** The struct is the only home of guest state: no emitted
   local holds a guest value across a call or into an entry block (a temporary inside one
   statement is fine). The state pointer is a `restrict` parameter of decision 2's signature;
   the guest memory base is a parameter beside it and is not `restrict`: measured, that
   changes nothing (below). The struct's layout is generated from one per-ISA declaration of
   the architectural state and versioned with the boundary contract (§2), which states two
   rules: the state is not inside guest memory, checked at startup; and every host function
   that can read or write guest state reaches it only through a pointer it is given as an
   argument, never through a global. A `restrict` promise holds for the whole execution of
   the function, its callees included (C11 6.7.3.1, from the standard's text, not checked
   here), so the second rule is what keeps it true; only review can check it, and the
   contract says so.
   - **Why:**
     - The struct is the boundary: imports, the dispatcher and decision 1's re-entry are
       correct only if nothing outside it holds guest state at a call or an entry. The
       emulator has been bitten twice by a register file that did not hold what the machine
       held: keeping only SSA names made a call's entry state unrecoverable
       (`emulate.rs:412-420`), and an argument the optimiser folded into its call left the
       register never holding the value, with no error (`emulate.rs:458-469`).
     - `restrict` gives the C compiler the register promotion locals would, without the
       emitter restating call semantics, but only in this form. Measured on two guest
       add-and-store statements over the struct and a byte-addressed guest memory, followed by
       a call that is passed the state pointer, as every translated call is, with gcc and
       clang at `-O2`: with nothing `restrict`, both reload the struct's fields after each
       guest store; with the state `restrict` and the base a parameter, neither does, whether
       or not the base is `restrict` too; with the base read from a global, gcc reloads
       whether or not the state is `restrict`, and also when the base is first copied into a
       `restrict` local. Without such a call (one not passed the state, or none), gcc with the
       state `restrict` does not reload in the global-base case either. The struct is written
       back before the call, which decision 1 needs. So, with the state `restrict`, `restrict`
       on the base changes nothing when the base is a parameter, and a `restrict` local copy
       of a global base does not help: the base stays a plain parameter, and the contract
       states no rule for guest memory, which only a `restrict` base would need.
     - Neither shape's speed is measured, so the simpler one stands until a benchmark built
       here says otherwise.
   - **Would change it:** a benchmark built here showing a hot loop still reloading guest
     registers in this form, and a prototype with locals measurably faster; or a runtime that
     has to place the state inside guest memory, which rules out `restrict`.
   - **When:** §5 step 2. The layout cannot come from one declaration yet: the A32 register
     file is `r0`–`r15` only (`arm32.rs:59-76`), no register file holds vector registers
     (`n0xis-arch/src/lib.rs:101-103`), and flags are values, not bits
     (`microir.rs:208-220`); it waits on the flag bits of ISA_AND_LIFT §3 item 2 (its §6
     step 1) and the VFP register model and FPSCR of its §8.2 (its §6 step 3). The mode joins
     the layout at §5 step 3 (§3 above).

4. **Floating point: bit-exact to the guest's unit.** Host arithmetic for the basic
   operations, which IEEE 754 rounds correctly where each operation is computed in its own
   format and not in a wider one (x87), plus per-guest helpers
   where the standard leaves a choice or C leaves the result undefined: the NaN returned and
   the default NaN, flush-to-zero and default-NaN modes, and every float-to-integer
   conversion, which goes only through a helper. The guest's FP control state (rounding,
   flush-to-zero, default NaN) is execution state in the IR, known statically at each FP
   instruction or the function is refused; a non-default guest rounding mode is refused until
   a helper that carries its rounding per operation is measured on gcc and clang; reads of the
   FP status flags are refused until they are modelled. Contraction is guarded inside the
   emitted code: the header has `#ifdef __FAST_MATH__` / `#error`, and each translation unit
   has a startup probe, compiled under that unit's own flags, that computes `a*b+c` from
   volatile inputs whose fused and unfused results differ and refuses to run if they do.
   `#pragma STDC FP_CONTRACT OFF` and `-ffp-contract=off` are still emitted, but they are not
   the guard. Excess precision is guarded in the header too: `#if FLT_EVAL_METHOD != 0` /
   `#error`, and `#if defined(__i386__) && !defined(__SSE2_MATH__)` / `#error`, because clang
   reports `FLT_EVAL_METHOD` 0 for 32-bit x86 with SSE but not SSE2 while it computes
   `double` on x87 (on 32-bit x86, gcc passes both with `-msse2 -mfpmath=sse` and fails both
   by default and with `-msse2` alone). Soft-float only for a format the host lacks (x87's
   80-bit values). VFPv2's short-vector length and stride are decode facts that ISA_AND_LIFT
   §8.2 and §8.4 state, not part of this decision.
   - **Why:**
     - A result one bit off is a confident wrong answer for any program that prints or
       compares those bits, so the guest's unit is the reference. Measured: `0*inf` in
       binary32 is `0xffc00000` on the x86-64 host and `0x7fc00000` from ARMv6 VFP code
       (`vmul.f32`, built with `zig cc -target arm-linux-musleabihf -mcpu=arm1176jzf_s`)
       under `qemu-arm-static -cpu arm1176`; `(int)3e9f` is -2147483648 and 2147483647, and
       `(int)NaN` is -2147483648 and 0.
     - C does not deliver the host half reliably on its own. gcc ignores
       `#pragma STDC FP_CONTRACT` and, in its default GNU mode, fuses even
       `t = a*b; return t + c;` into `fmadd` (aarch64); clang honours the pragma, but
       `-ffp-contract=fast` and `-ffast-math` override it. gcc also ignores
       `#pragma STDC FENV_ACCESS`: `1.0f / 3.0f` between `fesetround(FE_DOWNWARD)` and
       `fesetround(FE_TONEAREST)` comes out rounded to nearest at `-O0` and `-O2`, where it is
       folded at compile time, and at `-O2 -frounding-math`, where the division is moved after
       both calls; clang gives the downward result. So switching the host's rounding mode
       around plain C arithmetic is ruled out. Nor does every host compute in the
       operation's format: from `volatile double` inputs, `1e308 * 10 / 10` is inf on the
       x86-64 host and `1e+308` with `gcc -m32 -O2` (`FLT_EVAL_METHOD` 2, x87) and with
       `clang -m32 -O2 -march=pentium3`, which reports `FLT_EVAL_METHOD` 0; `clang -m32`
       defaults to `pentium4` and gives inf. i686 is one of decision 2's hosts. Checked on
       those builds: the `__SSE2_MATH__` guard fails every one that gives `1e+308`, the
       `FLT_EVAL_METHOD` guard misses clang's, and both pass every build that gives inf.
     - The IR models no FP control state ("the rounding mode is not modelled anywhere in this
       IR", `x64_lift.rs:1740-1742`), and the emulator already gets one rounding case wrong:
       `__cvtsd2si` and `__cvtss2si`, which round by MXCSR, are evaluated as truncation
       (`emulate.rs:1524-1525`). On the x86-64 host, 2.7, 3.5 and -2.7 convert to 3, 4 and
       -3 with `cvtsd2si` and to 2, 3 and -2 with `cvttsd2si`; no oracle source or test uses
       a rounding conversion, so the defect is latent.
   - **Would change it:** the runtime host's FP control, set to the guest's mode, giving
     identical bits on the boundary inputs against the guest's CPU model (the helpers then
     shrink to conversions and NaN choice); the helpers costing a material amount on an
     FP-heavy program built here (then soft-float is measured against them); no program built
     here writing FP control (then the execution state reduces to asserting the default mode
     at entry).
   - **When:** once A32 VFP decodes (ISA_AND_LIFT §6 step 3; today no VFP instruction decodes
     on A32, `ROADMAP.md:1287-1288`), measured on qemu with the guest's CPU model named and
     inputs at every boundary: NaN, signed zero, denormals, infinities, overflow, rounding
     ties. The A32 oracles run qemu with no `-cpu`
     (`a32_memory_agrees_with_the_processor.rs:385`,
     `a32_media_agrees_with_the_processor.rs:209`); that default model runs the ARMv7-only
     `movw`, which `-cpu arm1176` refuses with SIGILL, so an FP oracle for ARMv6 code has to
     name its model.

5. **Machine-level call and return facts are stated by the lift**, once, behind the ISA seam,
   shaped per ISA. Where control goes is the typed transfer of the one `Return` of
   ISA_AND_LIFT §8.3, beside its optional condition, and no field holds the callee twice:
   `Transfer::Return { value, target }` for a return, whose value is the ABI view and whose
   target is the machine view, the `lr` value or the popped word; `Transfer::TailCall(Call)`
   for a tail call, the call itself, whose target is where control goes. A tail call carries
   no separate target and writes no return target (decision 1). It is emitted as decision 2's
   `musttail`, or, to an import, as an import call followed by a return, with the preset every
   import call has (decision 1). A conditional return (`popne {…, pc}`) is a `Return` with a
   condition and a `Transfer::Return`, and a conditional tail call one with a condition and a
   `Transfer::TailCall`. On A32 the link is the register write the instruction performs — an
   `Assign` of `lr` at `bl`/`blx`, and at a separate `mov lr, pc` or `add lr, pc, #k` — not a
   field on `Call`, so the ARMv4 indirect-call idiom states its link where it happens. On x86
   `Call` carries the pushed word and the callee's entry stack pointer as a field, because the
   decompiler's per-function view needs a call that leaves the stack pointer where it was. The
   ABI view (arguments, result register, clobber markers) stays, labelled as such, and the
   emitter ignores it. Any `Arch` method exposing these facts is required, with no default.
   - **Why:**
     - One fact, one place. Today the emulator restates x86's call: it seeds `rsp`, `esp` and
       `sp` at entry whatever the ISA (`emulate.rs:599-601`), reads `rsp` by name at a call
       and pushes the return address itself (`emulate.rs:872-883`). Read, not run: an A32
       call under `CallPolicy::Execute` would take the callee's stack pointer from the value
       `rsp` was seeded with, not from the `sp` the caller has moved. Every test that follows
       a call is x86 (`the_emulator_follows_a_call.rs:330`,
       `how_far_the_emulator_reaches.rs:191`,
       `thirty_two_bit_code_agrees_with_the_processor.rs:458`), and only `X64` implements
       `Arch::stack_pointer` (`x64.rs:786`; the default, `n0xis-arch/src/lib.rs:475`, is
       `None`). An emitter built the same way would copy that drift.
     - The IR's calls are ABI claims, not machine operations: `Call { target, args, ret }`
       and `Return(Option<MicroExpr>)` (`microir.rs:314-321`). A32 `bl` becomes a `Call`
       reading `r0`–`r3` and returning `r0`, after which `lr`, `r1`–`r3` and `r12` are set
       to the clobber marker (`arm32.rs:1630-1642`), so the callee is never given its return
       address.
     - On A32 the link and the transfer can be different instructions
       (`mov lr, pc; ldr pc, [rX]`, still sequential in the CFG, `ROADMAP.md:1336-1337`;
       ISA_AND_LIFT §4). A link field on `Call` would stay empty for that idiom or make the
       lift reach back across instructions.
   - **Would change it:** carrying these facts in the statements changing an existing
     call-oracle answer or a decompiler golden output; then they become a separate
     per-instruction annotation.
   - **When:** asked of ISA_AND_LIFT §6 step 1, whose §8.3 gives `Return` its typed transfer
     and which does not list the other facts yet; before §5 step 2 here, with the x64 and i386
     call oracles and the decompiler goldens shown unchanged.

6. **The emitter reads the lifted IR, joined with the CFG** — not the SSA artifact, and never
   the optimised one. No emitter is built before ISA_AND_LIFT §6 step 1, and each condition
   is attached at lift time as an expression over flag bits (asked of ISA_AND_LIFT §3.2, which
   does not say it yet), so the emulator, the emitter and the decompiler read one rule. When
   the emitter is built, the emulator gains execution of that same artifact, so the
   differential of emitted C against the emulator compares one input; if that is not done, the
   record states that the differential crosses SSA construction and cannot localise a
   disagreement to the emitter.
   - **Why:**
     - The optimised artifact is unsound for shared machine state: the optimiser folds an
       argument into its call and deletes the assignment (`emulate.rs:458-469`), and builds
       `MicroExpr::Call` by propagation (`microir.rs:221-231`).
     - The SSA artifact synthesises each branch condition from the flags value that reaches
       the branch (`ssa.rs:779-785`) and resolves the `setcc:` markers of A32 predication the
       same way (`ssa.rs:250-254`, `arm32.rs:802-816`). Emitting from it needs the flags
       copied into the state at every flag-setting point — a second implementation of the
       condition tables, for a flag model ISA_AND_LIFT §3.2 is replacing. Blocks the SSA walk
       never reached also keep their pre-SSA names (`ssa.rs:767-777`).
     - The emulator executes `SsaBlock`s (`emulate.rs:451, 498`) and takes a branch's
       condition from `block.condition` (`emulate.rs:929-930`), while a `LiftedBlock` is
       `{ id, stmts }` with no terminator, successor or condition (`lift.rs:30-33`). Only one
       artifact under both lets a disagreement point at the emitter.
   - **Would change it:** ISA_AND_LIFT keeping conditions synthesised at SSA time from the
     compare that reaches the branch; then the emitter reads the SSA artifact, with a test
     that its condition table and `branch_condition` agree.
   - **When:** after ISA_AND_LIFT §6 step 1 (flags as bits, and the conditions at lift time
     asked of it); the emitter and the emulator's execution of the same artifact at §5 step 2
     here.

7. **What "exact" means, and where the mark lives.** Each lift arm returns a form identifier,
   with no default. A form includes the operand classes that change semantics on A32: `pc` as
   an operand or destination, a register- or immediate-shifted operand, flag setting, the
   condition. A checked-in table of exact (ISA, form) entries is written from the processor
   harness; a stale entry fails a test, and the count is printed and bounded. The recompiler
   refuses any instruction whose form is not in the table and reports its address, which
   refuses its function (decision 1). The syntactic walk (no `Unlifted`, no `Unknown` other
   than the clobber marker, no `OpaqueFlags` that is read) stays only as a precondition beside
   the table, not as the mark, and no interim table gets a form classifier of its own.
   - **Why:**
     - Exactness is measured, not asserted, and no mark exists in the code: no field, type or
       `Arch` method marks a lift form exact (`is_exact` appears only in test names, and the
       `Exact` variants in `n0xis-arch`, `microir.rs:372` and `arm64.rs:475`, describe a read
       set, not a lift). The syntactic walk alone admits forms known to be inexact: A32
       results are not held at 32 bits, so `add r0, r0, r12` with `r12 = 0xffffffff` gives
       `0x1fffffffe` in emulation (`ROADMAP.md:1333-1336`), and the A32 memory oracle picks
       inputs that never wrap (`a32_memory_agrees_with_the_processor.rs:28-35`), so it cannot
       certify those forms.
     - A table keyed by a classifier of its own would be a second classification of
       instructions beside the lift's arms — one fact derived in two places, "the shape every
       drift in this project has taken" (`microir.rs:42-43`). A form named by the arm removes
       it, and the compiler asks every new arm for one.
     - It costs nothing extra: §5 step 1 needs ISA_AND_LIFT §6 items 1–3, and item 3
       rewrites every A32 lift arm on the new IR before any recompiler code exists.
   - **Would change it:** ISA_AND_LIFT's harness measuring per instruction family rather than
     per form; then the table keys on what is measured.
   - **When:** with the A32 lift rebuild, ISA_AND_LIFT §6 step 3, which is asked for the form
     identifier and does not list it yet; the table is filled from the harness of
     ISA_AND_LIFT §5 item 3, generalised in its §6 step 4.

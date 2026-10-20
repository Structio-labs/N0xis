# Design: instruction sets, the exact lift, and how both are verified

**Status: Accepted 2026-10-19 (the open decisions are decided in §8).**
Companion to [`CONCEPT.md`](../../CONCEPT.md) §5.2 (the ISA seam; its trait sketch is older
than the trait, whose `decode` returns a `Result` and whose `lift` takes the ABI,
`crates/n0xis-arch/src/lib.rs:237`, `:305`) and to
[`IMAGE_FORMATS.md`](IMAGE_FORMATS.md). It decides three things the code has been deciding
case by case: who owns each decoder, what the micro-IR must be able to say, and one way to
prove a decoder and a lift right that every ISA uses. A file under `crates/` is named alone
where no other file there shares its name; `ROADMAP.md` and `CONCEPT.md` are at the
repository root.

## 1. Why — what grew without a plan

Two days of measuring A32 against LLVM and qemu turned it from "decode only" into a lift —
by fixing what each measurement exposed:

- **The decoder is a crate we work around.** `arm32.rs` (1 732 lines of code, 1 268 of
  tests) plus `arm32/own.rs` (821) now contain: a pre-rejection and a panic guard for words
  the crate panics on, an own decoder for the whole media class and the halfword
  multiplies, a rewrite of the `Invalid` the crate returns for the hint space, a shape check
  for a phantom operand, and corrections for addressing modes and `adr` it reports wrongly.
  Each defect is stated beside its workaround (`arm32.rs:131-164`, `:201-252`, `:465-471`,
  `:877-883`) or in the media instrument's header (`a32_media_agrees_with_llvm_mc.rs:7-10`).
  It still decodes **no VFP**, so a function walk stops at the first floating-point
  instruction.
- **The micro-IR cannot say what an exact lift needs**, so each lift invents a way around:
  - variables carry no width, so every 32-bit result needs an explicit cast;
  - flags are one value with two operands, so a carry or an overflow after an addition, or
    the carry `adc` reads, cannot be stated;
  - there is no conditional store, so `strne` stays `asm`;
  - there is no rotate and no count-leading-zeros, so each lift spells them its own way: x64
    writes a 32- or 64-bit rotate as two shifts and an or and `lzcnt` as an intrinsic the
    emulator does not evaluate, while A32 (`ror`, `rrx`, `clz`) and AArch64 leave them as
    `asm`;
  - two-destination instructions use private temporary names per lift.
- **Control flow is classified by matching instruction text.** On A32, `mov lr, pc`
  contains "mov", "pc" and "lr" and so is classified as a return, which ends the walk at
  every ARMv4-style indirect call. Writes to `pc` other than a few known shapes are
  sequential, so the walk runs into jump-table data. The CFG has no conditional return or
  conditional indirect jump at all, on any ISA.
- **Verification is one file per instruction family** (`a32_media_agrees_with_llvm_mc`,
  `a32_memory_agrees_with_llvm_mc`, two processor oracles). Each is good; together they are a
  pattern repeated by hand, and the reference's extensions are whatever its triple defaults
  to: the two llvm-mc instruments name three triples and pass no `-mattr`
  (`a32_media_agrees_with_llvm_mc.rs:191`, `a32_memory_agrees_with_llvm_mc.rs:234`).
  llvm-mc 23.1.1 rejects VFP words at `armv6-none-eabi`, and decodes them at
  `armv7ve-none-eabi` and, for VFPv2, at `armv6-none-eabi` given `-mattr=+vfp2`;
  `thumbv7-none-eabi` decodes their T32 forms. A comparison over VFP words at
  `armv6-none-eabi` would count them as rejected by both sides; neither instrument's word set
  holds a VFP word today.

## 2. Decoders: own the table where the crate is the problem

**Rule:** a decoder crate is used where it is right and measured right; where measurement
shows it wrong across a class, the class gets an owned decoder — **one owner per encoding
space**, so no word's answer depends on which decoder failed first (`own.rs` already works
this way).

**Proposal for A32:** replace the crate for A32 entirely with one owned decode table,
generated from or checked against the architecture's own encoding tables, and verified word
by word against llvm-mc with the target's extensions enabled. Keep the crate for Thumb until
the same measurement says otherwise. Add VFPv2/VFPv3 (and later NEON) to the owned table.
x64 (iced) and AArch64 (disarm64) keep their crates; AArch64's measured reserved-encoding
gap stays bounded by its test.

**The long-term lever is unchanged:** a SLEIGH-specification backend behind `trait Arch`
(gap-closing item 3) pays decode and lift once for every ISA that has a specification. An
owned A32 table is the right step now because the recompiler needs A32 exact
([`RECOMPILER.md`](RECOMPILER.md) §5 step 1); whether SLEIGH later replaces it is decided by
the same verification harness (§5), not by preference.

## 3. What the micro-IR must say

Each change below closes a class, not an instance.

1. **Width on the value, not a cast per lift.** A register's SSA version carries its width;
   arithmetic is defined modulo that width in the one evaluator rule. `Shift::apply` is
   already one rule for shifts and takes a width (`microir.rs:133`), but its three callers
   pass a fixed one, never the operation's: 64 in the emulator, 128 in the fold and the
   value-set analysis (`emulate.rs:1634`, `optimize.rs:263`, `valueset.rs:188`). The renderer
   prints a cast only where C's own rules would not truncate. This replaces "cast every
   result", which the held 32-bit A32 fix does; the fix no longer applies to the tree, and §8
   decides how it and its processor oracle land. Meanwhile A32 mixes two rules: its own
   decoder holds results at 32 bits (`own.rs:760`, `:798`) and the crate path does not
   (`arm32.rs:864`).
2. **Flags as named bits with an exact producer.** Carry, overflow, negative and zero, each
   a value; an add-with-carry shape with three inputs; per-ISA condition tables read the
   bits. Saturation and SIMD-greater-or-equal flags are their own variables, not the
   condition flags.
3. **A condition on effects.** `Store`, `Call` and `Return` carry an optional condition: the
   emulator skips a false one, forwarding treats it as "may happen" (clobbers, defines no
   value), and the renderer prints `if (c) …`. This covers predicated stores, conditional
   returns and conditional calls on every ISA without splitting blocks.
4. **One spelling per operation:** rotate, count-leading-zeros and byte reverse each get one
   spelling every lift uses. Today a byte reverse is exact in two (the `__bswap` intrinsic on
   x64, masks and shifts on A32: `x64_lift.rs:1306-1309`, `own.rs:800-817`), a 32- or 64-bit
   rotate is two shifts and an or on x64 and `asm` on A32 and AArch64 (`x64_lift.rs:2009-2074`,
   `arm32.rs:556-566`, `arm64_lift.rs:1237-1243`), and count-leading-zeros has no evaluated
   form. Anything else rare goes through a named intrinsic with a stated semantics, never an
   `Unknown`; that mechanism exists (`CallTarget::Intrinsic`, `microir.rs:295`, evaluated by
   name in `emulate.rs:1105`).
5. **Multiple destinations** through one convention (a tuple result bound to named
   outputs), used by every lift.
6. **Execution state** where the ISA has it: the A32/Thumb mode as state a branch can
   change (`bx` to an odd address), so interworking is a fact of the IR, not a choice made
   before decoding.
7. **The space of a memory access, inside its address.** A load or a store names the space
   its address indexes: the image's own space (today's flat meaning, the only one a native
   lift emits) or a WebAssembly linear memory, with its index, its address type, the dynamic
   base and the static offset. The static offset stays beside the base and is never folded
   into an addition: a wasm access traps where the same sum computed by `i32.add` wraps. The
   address field is replaced under a new name, so the compiler lists every reader, and its
   type is not called `AddressSpace`, which already names what an imported dump's numbers
   index (`crates/n0xis-il2cpp/src/lib.rs:90`). Forwarding and aliasing key on (space, base,
   offset) in one function, and two spaces never alias; today forwarding keys a slot by the
   address expression alone (`optimize.rs:632-657`). A linear-memory access may trap, and the
   trap is part of the answer: the access is an effect that dead-code elimination does not
   delete. The micro-IR has no such space today (`microir.rs:193-197, 309-313`). No lift emits
   a linear-memory access before WASM.md stage 3, so from §6 step 1 until then the space has
   readers but no producer. Step 1 still carries a calibrated unit test on hand-built IR: a
   store through one space and a load through another, at the same address and offset, are
   neither forwarded nor aliased, and through the same space they are. The lift-level tests,
   among them those against wasmtime, come with WASM.md stage 3. §8.4 defers the mode as state
   because nothing would read or check it; the space is built in step 1 regardless, because it
   replaces the address field of `Store`, whose sites the condition of item 3 changes too, so
   one pass edits them instead of two. Decided in [`WASM.md`](WASM.md) §5, decision 2, which
   gives the measurement behind each part; its *Built* gives that reason.

## 4. Control flow is classified from operands, in the shared seam

- Classification answers from the decoded operands, never from text. There is no
  `Arch::classify` today: each arch classifies privately, and the answer travels as
  `DecodedInsn.kind` (`insn.rs:13-30`).
- The shared classification gains **conditional return** and **conditional indirect jump**,
  and the CFG gives both a fall-through edge.
- An **indirect call** is recognised by the link register being written with the return
  address before the jump (`mov lr, pc` / `add lr, pc, #k` on A32), by a rule in the arch,
  not by the pass seeing the previous instruction.
- **Jump tables** get a third kind: a computed table of branches (`add pc, pc, rX, lsl #2`).
  Detection is shared across ISAs; AArch64 gets it too. Table words are data and never
  become blocks.
- Data processing that writes `pc` is a jump, never an assignment to a register named pc.

## 5. One verification harness for every ISA

A decoder and a lift are proved right the same way on every ISA:

1. **Decode against an independent disassembler** over the whole encoding space where it is
   enumerable (2^32 A32 words; for Thumb, 2^16 − 3·2^11 16-bit and 3·2^27 32-bit encodings, a
   32-bit one being any whose first halfword starts `11101`, `11110` or `11111`, each also
   under the `IT` state, because inside an `IT` block a 16-bit flag-setting encoding means its
   non-flag form, `arm32.rs:1241-1254`; stratified where not), with the target's extensions
   declared in one place per target. Asymmetric rows (one side accepts) must be zero or
   recorded with the reason. A word the architecture calls UNPREDICTABLE and llvm-mc accepts
   is decoded as llvm-mc decodes it, so the comparison keeps agreeing, and is never lifted,
   its effects stated as unknown; `own.rs` already follows that rule (`own.rs:35-36`).
   The harness reports the count of such words as a floor, since llvm-mc does not flag every
   UNPREDICTABLE choice, as the memory instrument already says
   (`a32_memory_agrees_with_llvm_mc.rs:23-25`).
2. **Totality**: every word, no panic, no answer without its envelope (the A32 guard's
   exhaustive test, generalised).
3. **Semantics against a processor**: functions built here, run under qemu (and, where a
   board exists, on the processor itself), compared answer by answer with the IR's own
   evaluation, with inputs that cross every width boundary. Zero wrong; "not modelled" is
   counted and explained.
4. **Real-image sweep**: a stated, reproducible binary that anyone can obtain (a system
   library), its whole code section, decode and lift coverage reported.

The harness is one crate of tooling with per-ISA tables, not one test file per family.

## 6. Order of work

1. The IR changes in §3, items 1–3 and 7 (width, flags, conditional effects, the space of a
   memory access), and the `Return`'s typed transfer (§8.3), with x64 and arm64 moved to them
   first and shown unchanged by the existing oracles. Preceded by the held 32-bit fix with its
   oracle (§8.1) and, separately, the Thumb `blx` fix (§8.2); joined by the part of step 2
   that conditional effects need, the conditional return's fall-through edge and the
   conditional jump to a function entry (§8.3). Two findings are fixed in this step, since the
   IR's shape changes in it: the comment on `MicroExpr::Call` says a lift never produces one,
   a lifted call being always a `MicroStmt::Call` (`microir.rs:221-227`), while the x64 lift
   already builds intrinsic calls as values (`x64_lift.rs:194-195`, through
   `MicroExpr::intrinsic`, `microir.rs:274-276`) and §8.3 puts a lifted tail call in a
   `Return`'s transfer; and the schema name `n0xis.ir.ssa.v1`
   (`crates/n0xis-contracts/src/schema.rs:86`), which no code uses, is removed, and the
   comments and the CONCEPT §6 line that still give the SSA artifact that name are reworded
   without it (`ssa.rs:5, 69, 78, 88`, `microir.rs:191`, `CONCEPT.md:285`).
2. The shared control-flow changes in §4.
3. The owned A32 decode table with VFP, under the harness in §5; the A32 lift rebuilt on the
   new IR (the load/store/jump-table sketch is an input, not merged as it is).
4. The harness generalised; Thumb measured under it.

The mode at an address (§8.4) is not a step of this order: it is built with
[`IMAGE_FORMATS.md`](IMAGE_FORMATS.md) §5 step 2, the one `Machine` table, starting with
§8.4's sub-decision on where the mode enters the ISA seam.

## 7. Done when

- No lift contains a width cast that the IR rule makes redundant; an exact A32 function
  renders with no more casts than its C source would need.
- `adc`, `sbc`, the signed and unsigned conditions after any compare, and predicated
  stores lift on A32 with zero wrong answers under qemu.
- No CFG of a program built here with jump tables contains a block made of table data, and
  no classification reads instruction text, a mnemonic string the decoder supplies included.
  AArch64's classification by mnemonic (`arm64.rs:196-215`) is a known exception, removed
  when the AArch64 lift is rebuilt, not before.
- One harness command verifies decode, totality and semantics for x64, AArch64, A32 and
  Thumb.

## 8. Decisions

Each decision states what is decided, why, what would change it and when it is built; where it
changes a proposal above, it says so.

1. **Width on SSA values (proposed) or on every expression node?** On every operation node.

   **Decision.** `Binary`, `Unary`, `Select` and an intrinsic's result carry a width, as
   `Const`, `Load`, `Cast` and `Store` already do. This amends §3 item 1, which put the width
   on the SSA value.
   - A node carries its operand width, and its result width follows from the operator: a
     comparison gives 1 bit, everything else the operand width. `Compare` carries its
     operand width too. A shift states its value's width and reads the count as it is.
   - A variable's width has one source: the register file for a register, a declaration
     beside the temporary for a lift temporary. The `Assign` constructor refuses a value whose
     width differs from its destination's. The x64 and AArch64 32-bit write stays an explicit
     zero-extending `Cast`, because that is what the processor does.
   - Vector bitwise nodes are 128 bits wide; the evaluator refuses wider ones.
   - The text of `n0xis.opt.delta.v1` entries changes, since they carry IR as Debug strings
     (`optimize.rs:353`).
   - The held 32-bit A32 fix and its processor oracle land together or not at all, the fix
     rebased onto the tree, before the IR change. This is approved in principle; each
     expectation they change is still listed and checked against the processor when they
     land. Until then ROADMAP keeps the class's scope "in emulation" (`ROADMAP.md:1333-1336`).

   **Why.**
   - One expression's width is decided in several places today, and they disagree on a node
     without a cast: the emulator runs a bitwise `Binary` at 128 bits and any other at 64
     (`emulate.rs:1026-1039`), the constant fold takes the left literal's width
     (`optimize.rs:330`), flags infer it from the expression's root (`flags.rs:32-45`), and
     type inference falls back to the machine word (`typeinfer.rs:837-848`). A width on the
     node replaces them, and a node built without one does not compile.
   - The width cannot be derived from the operands instead: lifts produce literals narrower
     than their operation, which is the fold's recorded wrong answer,
     `mov eax, 0x1ff; shl rax, 53` folded at the literal's 32 bits to zero
     (`optimize.rs:217-234`).
   - The released A32 lift does not hold its results at 32 bits (v0.3.4 lifts `add` as a plain
     `Binary`), so in emulation they carry past bit 31 (`ROADMAP.md:1333-1336`); holding the
     fix until the refactor is done would keep that class open for the whole refactor.

   **What would change it.** The migration measuring far larger than the lines grep finds in
   `crates/` today, constructions and patterns together (372 match `MicroExpr::binary(`,
   `MicroExpr::Binary(` or `bin(BinOp`; 46 match `MicroExpr::unary(` or `MicroExpr::Unary(`):
   the held casts then stay longer, under a calibrated test that the evaluator rules agree on
   every node of the fixtures built here. The IR change being able to land before anything
   else ships from main: landing the held fix first would then only be churn. Lane-wise
   vector arithmetic moving from intrinsics into `Binary` nodes (packed bitwise operations
   already are `Binary`, `x64_lift.rs:494-500`): the width would first need a stated meaning
   per lane.

   **Built.** The held fix and its oracle first; then §6 step 1, where x64 and AArch64 move to
   node widths before A32 and are shown unchanged by the existing processor oracles and the
   held one. On the way, the per-lift casts the node width makes redundant,
   `flags::value_width`, the fold's left-literal guess and the held fix's own width rule are
   deleted.

2. **An owned A32 table now, or wait for the SLEIGH backend and keep patching the crate?** An
   owned table now; a SLEIGH backend competes later on the same harness.

   **Decision.** In this order:
   - First the VFP register model goes into the register file: single and double registers
     aliased onto one full register (quad registers later), the count of `d16`–`d31` set by
     the declared floating-point version, and FPSCR. Then VFPv2/v3 is decoded for A32 and T32
     in one table. Its register reads and writes are exact only under a stated precondition,
     FPSCR.LEN = 0 and STRIDE = 1 at entry and no `vmsr fpscr` in the function that changes
     them, and are otherwise bound over the whole bank. A hard-float AAPCS variant, chosen
     from the image's own flags, makes calls state their VFP reads and clobbers; today the
     convention models no float register (`arm32.rs:99`) and nothing in `crates/` reads an
     image's float-ABI attributes.
   - The remaining A32 integer classes move off the crate while the A32 lift is rebuilt (§6
     step 3), so the operand plumbing is rewritten once; each move deletes the workaround it
     replaces.
   - T32 moves onto the same owned operand plumbing in that rebuild, instead of staying on
     the crate's types behind an adapter.
   - Separately and now, as a defect: the Thumb `blx` target is computed from `va + 4` without
     aligning that base to 4 (`arm32.rs:327-337`). On a shared object built here (clang 23,
     ld.lld), a `blx` at an address that is not a multiple of 4 names a target 2 bytes past the
     import stub llvm-objdump names, and the decompiler renders a call to that address. Its
     gate compares the resolved target with llvm-objdump's on such an object, a `blx` at an
     address that is 2 modulo 4 beside one at 0 modulo 4 as the control. The llvm-mc
     instruments cannot fail on it: llvm-mc is given no address, so it prints the same relative
     text at either alignment, as n0xis does, and only the resolved target
     (`DecodedInsn.target`) is wrong; neither instrument judges a branch either (the memory
     instrument leaves them out, `a32_memory_agrees_with_llvm_mc.rs:210-212`).

   The gate is the exhaustive A32 decode test and the llvm-mc instruments, with the
   extensions declared once, plus a qemu check of the vector-length precondition with the
   cores that differ declared.

   This amends §2, which kept the crate for all of Thumb: T32's VFP is in the owned table and
   T32's operands move to the owned plumbing, so the crate keeps only Thumb's integer decode
   until the same measurement says otherwise.

   **Why.**
   - The crate refuses every coprocessor-10/11 word in both instruction sets (yaxpeax-arm
     0.5.0, `src/armv7.rs:3085-3088`, `:3194-3197`, `src/armv7/thumb.rs:4266-4293`), and a
     walk ends at the first word it cannot decode (`arm32.rs:1710-1726`). A SLEIGH backend
     does not exist yet (ROADMAP gap-closing item 3), so waiting for one keeps every A32 and
     Thumb walk stopping at the first floating-point instruction for an open-ended time.
   - The crate is the problem across most A32 classes, not one: the panic guard, the hint
     rewrite, the `mvn` operand drop and the text corrections are each a way around it
     (`arm32.rs:165-273`). The A32 lift is rebuilt on the new IR anyway, so building it on
     owned, typed operands rewrites the plumbing once instead of twice.
   - VFP is not independent of §3. Which registers a VFP data-processing word writes depends
     on FPSCR.LEN: measured under qemu-arm 11.1.1 on a program assembled here, one
     `vadd.f32 s24, s8, s16` with LEN = 1 also wrote `s25` on `-cpu arm1176` and `cortex-a8`,
     left it alone with LEN = 0, and raised SIGILL on `cortex-a15`. A register the model lacks
     would read as an entry version, which the IR takes as evidence of a parameter
     (`microir.rs:346-348`), and a single register written into a double one is the width
     question of decision 1.

   **What would change it.** A SLEIGH-based `Arch` passing the §5 harness on A32 (VFP
   declared, no asymmetric rows, no wrong answer under qemu) before the integer classes have
   moved; a release of the crate that decodes VFP and fixes its open defects on every word;
   the owned integer table measuring far costlier than the plumbing it replaces, in which case
   the work stops after the VFP step and the crate keeps the integer space under its guards.

   **Built.** The `blx` fix now; the rest in §6 step 3, after the width change of §6 step 1.

3. **Conditional effects as a field on `Store`/`Call`/`Return` (proposed) or a general
   conditional statement?** A field on `Store` and `Return`; a conditional call that is not
   a tail call is decided with §3 item 5.

   **Decision.** `Store` and `Return` carry an optional condition; a register written under a
   condition stays `dst = c ? v : dst`. There is one `Return` statement, with that optional
   condition and a typed transfer that says where control goes, which
   [`RECOMPILER.md`](RECOMPILER.md) §6 item 5 asks of the lift; no field holds the callee
   twice. `Transfer::Return { value, target }` is a return: the value is the ABI view and the
   target the machine view, the return address. `Transfer::TailCall(Call)` is a tail call: the
   call itself, whose target is where control goes; it carries no separate target, writes no
   return target and defines no register. A conditional tail call is a `Return` with a
   condition and a `Transfer::TailCall`. Beside §4's conditional return and conditional
   indirect jump, the CFG gets a kind for a conditional jump to a function entry, with a
   fall-through edge; a conditional return gets its fall-through edge too and no longer ends
   the function (today a return past the last forward branch target cuts it,
   `ir.rs:520-523`). This amends §3 item 3, which also put the condition on `Call`.
   - Every expression of a statement is visited through one function in `microir.rs` that
     destructures every field, for reading, mapping and renaming, and every walker goes
     through it: `stmt_read_exprs`, `collect_stmt_vars`, `stmt_uses`, `map_stmt_exprs` and
     the SSA renamer.
   - Every pass that keys on `MicroStmt::Call` also sees the `Call` of a `Transfer::TailCall`,
     reaching both through that one function. These are the patterns on `MicroStmt::Call`
     outside tests in `n0xis-core`: SSA construction (`ssa.rs:121, 172, 320, 462`), the
     optimiser (`optimize.rs:162, 462, 540, 558, 805, 878, 950`), type inference
     (`typeinfer.rs:397, 479, 648, 823, 1010, 1081, 1466`), devirtualisation
     (`devirt.rs:284, 320, 575, 587`), class layout (`classlayout.rs:642, 771`), coalescing
     (`coalesce.rs:83, 96`), the emulator (`emulate.rs:746`), the renderer
     (`n0xis-core/src/render.rs:962`), constant naming (`decomp.rs:826`), type propagation
     (`typeprop.rs:230`) and the value-set analysis (`valueset.rs:244`).
   - A calibrated guard over the parsed source of `n0xis-core` and `n0xis-arch`, not a line
     regex, forbids any other walker and any `..` over `Store` or `Return`, with an exemption
     list that carries reasons.
   - The CFG's terminator kind and the statement's condition both come from
     `DecodedInsn.cond`, never computed separately.

   **Why.**
   - The effects compilers predicate are stores and returns, and neither defines a register:
     clang 23 at `-O2` for ARMv6 compiles `if (p) *p = v` to `cmp r0, #0; strne r1, [r0]` and
     an early return to `bxeq lr`. A general conditional statement needs a merge inside a
     block, which SSA renaming, a straight-line walk per block (`ssa.rs:363`), does not have;
     splitting the block fails too, because blocks are found by their start address
     (`emulate.rs:924-926`) and an instruction's test and effect share one.
   - The conditional tail call is a wrong answer today, measured on code built here. On x64,
     `if (c) return g(c); return 0;` (`testl %edi, %edi; jne g@plt; xorl %eax, %eax; retq`)
     renders as `// (cjmp without resolved successors)` and `return 0x0;` at quality 1.0, and
     the Thumb build (`it ne; bne.w` to a thunk) loses the call as well. As a conditional
     `Return` with a `Transfer::TailCall` it needs no conditional definition.
   - A field alone is not enough: the generic walkers match `Store { addr, value, .. }`
     (`optimize.rs:549`, `ssa.rs:168`, `ssa.rs:458`; 17 such patterns outside tests, all in
     `n0xis-core`, where two other `Store` patterns also end in `..`, `optimize.rs:540, 927`),
     so a condition would be invisible to use counting, renaming and dead-code removal, the
     class `optimize.rs:550-556` records for an indirect call's target.
   - The one visitor is required for calls as well. A tail call puts a `Call` in a `Return`'s
     transfer, a third place for a call beside its own statement and an assignment of its
     result, and the passes keyed on `MicroStmt::Call` do not all look there: use
     collection takes a `Return`'s operand as no use (`ssa.rs:452-453, 473`), so the call's
     arguments would read as unconsumed, and devirtualisation and class layout match the
     first two places only (`devirt.rs:575-576`, `classlayout.rs:771-772`).

   **What would change it.** A corpus built here with gcc from known source showing that
   predicated calls other than tail calls are common: the call's condition and §3 item 5 then
   come together, and sooner. An instruction needing several effects to happen all or none,
   beyond a store and its write-back. The guard needing so many exemptions that it stops
   describing the code: a separate guarded variant, which every exhaustive match has to
   answer, is then the better shape.

   **Built.** §6 step 1 (the field, the `Return`'s typed transfer, the one walker, the guard),
   together with the part of §6 step 2 it needs: the conditional return's fall-through edge
   and the conditional jump to a function entry. The gate is that both measured fixtures
   render the call.

4. **Are the A32 mode and other execution state part of this phase or deferred to the
   recompiler?** The mode at an address is part of this phase, as a fact of the image; a mode
   change as IR state is deferred to the recompiler's dispatch.

   **Decision.** The mode at an address comes from these sources, in rank order:
   - the ELF mapping symbols (`$a`, `$t`, `$d`) where present, which give the mode per
     address range and mark data inside code;
   - the symbol's own Thumb indication, bit 0 of an ELF symbol's value or the
     `N_ARM_THUMB_DEF` flag of a Mach-O symbol, stripped before the name is joined;
   - the machine: PE `0x01c4` (ARMNT) is Thumb only, as a DLL linked here shows
     ([`IMAGE_FORMATS.md`](IMAGE_FORMATS.md) §1); for `0x01c2` (THUMB) that is not verified
     here, since the sources read here only name the constant (goblin 0.10.7,
     `src/pe/header.rs:776-780`; LLVM 23.1.1, `BinaryFormat/COFF.h:121`);
   - the direct call edge, once the `blx` target is fixed (decision 2): `bl` keeps the mode,
     `blx` with an immediate switches it.

   PLT stubs and linker thunks get their own mode. Of the other execution state, FPSCR.LEN and
   STRIDE are stated now, as decision 2's precondition or as bound reads and writes. The mode
   bit of an indirect transfer and a mode switch inside a function stay deferred to the
   recompiler's dispatch. This narrows §3 item 6, which made the mode IR state in this phase.

   **First sub-decision of the step that builds it: where the mode enters the ISA seam.**
   `Arch::decode` takes no mode (`crates/n0xis-arch/src/lib.rs:237`), and one `Arch` is
   chosen per source (`crates/n0xis-frontend/src/source.rs:231-233`). Either `decode` gains a
   mode parameter, which changes the public trait, every implementation and every caller; or
   the frontend keeps a map of modes per source and two `Arch` objects, which keeps the trait
   but ends "one `Arch` per source" for every caller that holds one. It is decided when the
   step starts, from a count of the call sites each shape touches.

   **Why.**
   - A wrong mode is a confident wrong answer today, not a recompiler problem. Measured on a
     Thumb function in a shared object built here (clang 23, ld.lld): decoded at its even
     address without `--arch`, it answers `ok: true` with A32 instructions under a `sub_`
     name, and at its symbol's odd address it gets its name and still the A32 decode. By the
     format's own constant every ARMNT PE is affected too: `0x01c4` is Thumb-2 (goblin
     0.10.7, `src/pe/header.rs:654-658`) and maps to the A32 decoder (`static_pe.rs:333`).
   - The producer states the mode per range, not per image: a Thumb-only shared object built
     here carries `$a`, `$t` and `$d` from ld.lld, and its PLT entries are A32 with data
     inside them.
   - Mode as mutable IR state has no reader today: the mode is chosen once, before decoding
     (`arm32.rs:104-112`), and one `Arch` decodes a whole source
     (`n0xis-frontend/src/source.rs:231-233`). The only consumer this plan names is a
     dispatcher that follows an indirect transfer into code of the other mode, the
     recompiler's dispatch ([`RECOMPILER.md`](RECOMPILER.md) §5 step 3). Built now, it would
     be state with no reader and no oracle.

   **What would change it.** A program built here that switches mode inside one function
   (linker interworking veneers do: `bx pc` from Thumb, `add rX, pc, #1; bx rX` from A32)
   would put a per-edge mode into the CFG now, though still not into IR state. RECOMPILER.md
   §6 item 2's per-block fallback being taken for the functions its one-function shape
   refuses, or the emulator having to follow interworking calls into the other mode, would
   need the transfer's mode bit sooner.

   **Built.** With [`IMAGE_FORMATS.md`](IMAGE_FORMATS.md) step 2 (one `Machine` table),
   starting with the sub-decision above; FPSCR.LEN and STRIDE with the VFP decode (§6 step 3);
   the transfer's mode bit with RECOMPILER.md §5 step 3.

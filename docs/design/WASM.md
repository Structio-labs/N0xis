# Design: a WebAssembly front end

**Status: Accepted 2026-10-19 (the open decisions are decided in §5). Stage 1 is done: the
WebAssembly 3.0 binary format with threads and legacy exception handling. Stages 2–4 wait on the
format seam of
[`IMAGE_FORMATS.md`](IMAGE_FORMATS.md) and the IR changes of
[`ISA_AND_LIFT.md`](ISA_AND_LIFT.md).**

## 1. Why

- **No command reads WebAssembly yet.** A `.wasm` file is refused at the first step
  (`crates/n0xis-sources/src/static_image.rs:37-40`; the stage-1 reader is wired to no
  command), and the managed-runtime work already needs it: a WebGL build of a managed runtime
  keeps its code in a `.wasm` module, and an imported index into that module is refused
  (`crates/n0xis-frontend/src/il2cpp_caps.rs:214-216`) because there is no front end to
  resolve it (`crates/n0xis-il2cpp/src/lib.rs:99-104`).
- **It is the engine's job, not tooling around it:** a container format and an instruction
  set, the two seams the documents above define.
- **It is the cheapest ISA to verify.** Test modules are built here from known source
  (`clang --target=wasm32`, `wasm-ld`, hand-written `.wat`); an independent decoder exists
  (`wasm-tools`, `wasm-objdump`); and an independent execution engine (`wasmtime`) is the
  processor oracle, so no processor emulator is needed (the side under test is still the IR's
  own evaluator, `crates/n0xis-core/src/emulate.rs`).
- **It fits the engine's thesis.** A module running in a browser page is a live target: its
  bytes and its linear memory are reachable through the browser's debugging protocol. Stage 4's
  goal is that a watch on linear memory is answered with the statement that wrote it, the loop
  the native path offers with a hardware watchpoint on a process (`provenance trace`,
  `crates/n0xis-cli/src/main.rs:1252-1254`). The protocol offers no data watchpoint, so how a
  write is attributed is decision 3 (§5), measured so far only on V8's inspector.

## 2. What is different about this ISA

- **A stack machine with typed, structured code.** No registers: values live on an operand
  stack and in typed locals. Control flow is structured (`block`, `loop`, `if`, `br` to a label
  depth, `br_table`), so a CFG is derived exactly, never guessed, and there is no data inside
  code.
- **Separate spaces.** Code is not addressable; a function is an index. Each linear memory is
  its own 32-bit (or, with memory64, 64-bit) address space starting at 0, and a module may have
  several (`crates/n0xis-wasm/tests/fixtures/shapes.wat:21-25` declares three). Indirect calls
  go through a table and are checked against a type signature, and a C function pointer stored
  in linear memory is a slot of that table, not a function index: in the committed C fixture
  `operations[]` holds 1, 2, 3, and those slots hold functions 3, 4, 5
  (`crates/n0xis-wasm/tests/fixtures/ctarget.c:45`, `ctarget-O2.details.txt:119-123, 149-153`).
- **Names often survive.** The `name` custom section names functions, locals and globals, and
  also the module, labels, types, tables, memories and element and data segments (stage 1 reads
  them all, `crates/n0xis-wasm/src/names.rs:48-66`); DWARF may travel in custom sections.

## 3. Stages

1. **Reader and decoder (done).** A crate of its own, `n0xis-wasm`, bytes in and owned facts
   out, like the PDB reader: every section, the index spaces, the `name` section, and every
   instruction of the WebAssembly 3.0 binary format (typed references, garbage-collected types,
   tail calls, exception handling with `exnref`, relaxed SIMD, memory64, multiple memories), with
   the threads proposal (shared memories, the atomic instructions) and legacy exception handling
   (`try`, `catch`, `delegate`, `rethrow`), under the hostile-input contract. Shared-everything
   threads, stack switching, wide arithmetic, custom page sizes and the component format are
   refused where met (`crates/n0xis-wasm/src/lib.rs:34-40`). No pipeline wiring and no commands
   yet.
2. **An `Image` for modules** (needs the format seam): imports grouped by module, each reached
   by its function index (decision 1), exports, functions as declared starts with exact
   extents, data segments with a constant offset as the initial linear memory, the function and
   table index spaces exposed so a call target is a function, not an address. A data or element
   segment placed by an imported global has no static placement, and the image says so rather
   than place it: the format allows one (`wasm-tools validate` accepts
   `(data (global.get $imported) …)` and `(elem (global.get $imported) …)`), and the reader
   keeps every offset as an unevaluated expression (`crates/n0xis-wasm/src/module.rs:225, 252`).
3. **An `Arch` with a stack-machine lift** (needs the IR changes of ISA_AND_LIFT.md §6 step 1,
   among them that document's §3 item 7, the linear-memory space of decision 2):
   the operand stack becomes SSA values at decode time, locals become variables with their
   declared widths, structured control becomes the CFG, linear-memory loads and stores become
   loads and stores whose address names its memory (decision 2; the micro-IR has no such space
   today, `crates/n0xis-arch/src/microir.rs:193-197, 309-313`), `call_indirect` a dispatch
   through the table restricted to the functions of the right signature. The element segments
   are a table's whole contents only when nothing else writes it: a table that is imported,
   exported or written by `table.set`, `table.grow`, `table.init`, `table.copy` or `table.fill`
   (all decoded, `crates/n0xis-wasm/src/instr.rs:859, 1071-1076`) may also hold whatever the
   host or the code stores, and the dispatch says so. Decompiled output then goes through the
   existing passes.
4. **A live source:** a module and its linear memory read from a page through the browser's
   debugging protocol, so scans, watches and provenance work on it.

## 4. Verification, per stage

- **Stage 1:** hand-written `.wat` fixtures that state every instruction (known before asked);
  `wasm-objdump -x`/`-d` and `wasm-tools print` over every fixture (independent tool); a test
  that fails if any decoded opcode never appears in a fixture; at least 2 000 corrupted copies
  per fixture, no panic, and no single allocation larger than `2 * size_of::<Located>()` bytes
  per byte of input (`crates/n0xis-wasm/tests/mutated.rs:15-20, 290, 319`).
- **Stage 2:** every fact against `wasm-objdump -x` on modules built here.
- **Stage 3:** functions of modules built here from C, run under `wasmtime` and under the IR's
  own evaluation with randomized inputs: zero wrong answers, "not modelled" counted.
- **Stage 4:** a planted value in a page's linear memory found, watched and traced to the
  function and statement that wrote it, checked against the module's source.

## 5. Decisions

Decided 2026-10-19. The measurements named below were taken on small modules built here from
hand-written text or C, with wasmtime 49.0.3, wabt 1.0.42, wasm-tools 1.262.0, clang 23.1.1
and V8's inspector as node v26.10.0 ships it.

1. **Function identity: the index is the identity, and the body's module offset is the
   position.** No synthetic address anywhere. The pipeline keys a defined function by the byte
   offset of its body in the module and each instruction by its own offset, as a `Va` of the
   image's code space; `Va`'s documented meaning (`crates/n0xis-contracts/src/types.rs:12`)
   widens from a virtual address to a position in the image's own space. Every wasm answer
   carries the function index beside the position. An imported function has an index and
   never a position. The table from index to offset lives once, in the wasm image. A function
   starts at its body, the locals declaration, at least one byte before its first instruction;
   its decoded stream begins with that declaration (which also states that declared locals
   start at zero), so the CFG's entry is an instruction, as the pipeline requires
   (`crates/n0xis-core/src/ir.rs:276-278`). Three further parts:
   - **The annotation store gains a target scope before any wasm annotation is written**,
     keyed by the module's identity (its `build_id` section, else a hash of its bytes). Today
     it is one map per project keyed by the address alone
     (`crates/n0xis-project/src/annotate.rs:11-13, 489-492`), and every module's code sits at
     small offsets, so two modules in one project would share keys and a rename would land on
     another function.
   - **One `CallTarget` change covers the three wasm callees:** a defined function as
     `Direct { va }` with its body's offset, an import by its function index, and a table
     dispatch carrying the table, the slot expression and the expected type, resolved through
     the table and checked against the signature. Neither the emulator nor the naming passes
     read a slot as an address, which is what `Indirect` means today: it is evaluated as an
     image address (`crates/n0xis-core/src/emulate.rs:831-838`) and its constants are named
     as image addresses (`crates/n0xis-core/src/decomp.rs:826-830`), so a slot lifted as
     `Indirect` would be looked up as the body at that module offset, with no signature check.
   - **On the wire a code position is (module identity, module offset)**, with the function
     index beside it. *Stage 2 (decided 2026-10-23):* every stage-2 command answers about one
     module, the one `meta.source` names, so the identity is not repeated on each answer yet;
     it goes on the wire, as a field of the envelope's `meta`, with the first door that can
     answer about two modules at once (a stage-4 session). The annotation store already keys by
     it. The name of an unnamed function gets one home first; it is formatted in
     five places with two spellings (`sub_{:X}` at `crates/n0xis-core/src/discover.rs:123,
     300` and `summary.rs:186`, `sub_{:x}` at `crates/n0xis-core/src/render.rs:306` and
     `decomp.rs:521`).

   *Why.* (a) The format and every independent source use exactly these two coordinates.
   `call`, exports, element segments and the `name` section name a function by its index
   (`crates/n0xis-wasm/src/instr.rs:841`, `module.rs:136, 231`, `names.rs:52`). An instruction
   is a module offset to `wasm-objdump -d`, to wasmtime's backtrace and to V8's inspector,
   whose stack trace prints both as `wasm-function[index]:offset`; DWARF counts from the code
   section's start (`llvm-dwarfdump` against `wasm-objdump -h`), a constant the image adds
   once. The stage-1 tests already pin each body's start and index against two independent
   tools (`crates/n0xis-wasm/tests/references.rs:1334-1335, 1402-1403`). (b) A synthetic address is a
   number nothing outside N0xis states, so no source but N0xis could confirm an answer
   carrying it, which CONCEPT §3 rule 7 does not accept; and the first saved rename would
   freeze it into `annotations.json`. (c) An index key alone forks every address-keyed
   interface (the CFG's entry, the function list and the no-return set are `Va`s:
   `crates/n0xis-core/src/ir.rs:33-34`, `crates/n0xis-core/src/lib.rs:173, 210`) and leaves
   the instructions inside a function without a coordinate.

   *What would change it.* The browser itself reporting wasm code positions in a coordinate
   that no constant stated by the module or the protocol converts to module offsets; V8's
   inspector does not (it reports an instruction at its module offset, a function at its
   body's start and the code section's offset), and the browser is measured in the stage-4
   spike. The format seam making function identity a typed reference for every format, which
   would make an index key cheap. Modules analysed after instrumentation or rewriting, whose
   positions would need a stated map back to the original.

   *Built.* Stage 2 builds the table from index to offset, the module identity, imports by
   index and the one home of the fallback name, and the annotation scope before any wasm
   annotation is written. It needs the format seam's `imports()` (IMAGE_FORMATS.md §2) to
   reach an import by its index, since a wasm import has no stub or slot address
   (`call 0 <host_report>` names a function with no body,
   `crates/n0xis-wasm/tests/fixtures/ctarget-O2.disassembly.txt:425` and
   `ctarget-O2.details.txt:21-23`); the seam's sketch carries that reach as `Reach::Index(n)`,
   so IMAGE_FORMATS.md §5 step 3 builds the trait with it. The `CallTarget` change lands once,
   for all three callees, with the stage-3 lift.

2. **Linear memory's address space: both of the document's options, each where it fits.**
   Image-wide, for code: a wasm image states once that its `Va` positions are module offsets
   and hold no data. Per access, for data: a load or a store carries its space inside its
   address. The address field is replaced, under a new name, by a typed reference that is
   either the image's space (today's flat meaning, the only form a native lift emits) or a
   linear memory, with its index, its address type, the dynamic base and the static offset
   kept unwrapped. Forwarding and aliasing key on (space, base, offset) in one function, and
   two spaces never alias. The type is not called `AddressSpace`, which already names a
   different fact, what an imported dump's numbers index (the one `enum AddressSpace` in
   `crates/`). Three further parts:
   - **A linear-memory access may trap, and the trap is part of the answer:** the access is
     an effect that dead-code elimination does not delete.
   - **Tables are not a linear-memory space.** `call_indirect` and `return_call_indirect` go
     through the table dispatch of decision 1; `table.get`, `table.set`, `table.grow`,
     `table.fill`, `table.copy` and `table.init` are statements of their own on the table
     index space, never loads or stores.
   - **A memory's live and snapshot identity is (instance, memory index).** Module-relative
     indices serve static analysis only.

   Calibrated tests guard it: a store to one memory and a load from another at the same
   address are not forwarded; the wasm lift emits no image-space access; the offset case below
   agrees with wasmtime; a lifted `i32.load; drop` traps where wasmtime traps, and the test
   fails when the access is removed.

   *Why.* (a) A tag beside the address would change nothing for forwarding, which keys a slot
   by the address expression alone (`crates/n0xis-core/src/optimize.rs:632-657`, compared at
   `:722-724`). The patterns that bind `addr` and skip the rest with `..` (49 single-line ones
   in `crates/*/src` on 2026-10-20, `optimize.rs:927` among them) would keep compiling and
   keep ignoring it, so with two memories a store to memory 1 at address 8 would be forwarded
   to a load from memory 0 at address 8. A renamed field makes the compiler list every
   reader. (b) The static offset must not become an addition: an `i32` base of `0xFFFFFFF8`
   loaded with `offset=16` traps under wasmtime (at wasm address `0x100000008`) and under V8,
   while the same sum computed by `i32.add` wraps and reads the word planted at address 8.
   (c) Dead-code elimination removes an assignment nobody reads (`optimize.rs:1337-1352`),
   yet `local.get 0; i32.load; drop; i32.const 7` returns 7 for 0 and traps for 70000 under
   wasmtime: a lift that bound the dropped load to a temporary would answer 7 where the
   engine traps. An image-wide rule alone could not say which of several memories an access
   reads.

   *What would change it.* The project refusing multi-memory modules and deciding that no
   answer ever shows a linear-memory address (no scan, watch or provenance on wasm data),
   which stage 4 contradicts.

   *Built.* With ISA_AND_LIFT.md §6 step 1, which edits the same `Store` sites: one pass
   instead of two, because that document's decision 3 (§8) adds its condition as a field on
   `Store` (a general conditional statement would not have touched those sites). That
   document lists the space among its IR changes as §3 item 7, and its step 1 builds it with
   a calibrated unit test on hand-built IR, since no lift emits a linear-memory access before
   stage 3: a store through one space and a load through another, at the same address and
   offset, are neither forwarded nor aliased, and through the same space they are. The table
   statements and the lift-level tests, the other three above, land with the stage-3 lift; the
   live and snapshot identity in stage 4.

3. **The live source lives outside the engine.** A bridge process, with capture as its first
   increment: the module's bytes and an image of its linear memory saved to files, which
   N0xis reads as a module and as a snapshot. Reading a memory natively from the browser's own
   process is at most a later speed path for scans, to be measured. Four further parts:
   - **The bridge speaks a new versioned contract in `n0xis-contracts` for an external live
     source**, which states what it serves: the module's bytes and identity, and each memory
     with its index, address type and current size. The internal transport between two N0xis
     processes keeps its invariant, unversioned and never surfaced
     (`crates/n0xis-sources/src/remote.rs:14-17`).
   - **The bridge's code lives in its own repository**, outside the engine's workspace, as the
     plugin that reads `.warp` files does (`MAP.md:56-60`), so the engine gains no network
     client.
   - **A hit is shaped now:** module identity, module offset, function index and the store's
     operand values. N0xis computes the effective address from its own decode (memory index,
     base plus the unwrapped static offset), so the bridge never decodes wasm. Left for the
     stage-4 spike: the same measurement in the browser itself, the cost of a breakpoint on
     every store, and whether a memory's buffer moves when it grows.
   - **Every capture and every hit names the module identity and the instance.** The
     capture's snapshot is a new schema version with a space per region (`n0xis.snapshot.v1`
     regions are a flat base and bytes, `crates/n0xis-sources/src/snapshot.rs:18-23`), a
     contract change of its own.

   *Why.* (a) The engine has no network client (`Cargo.lock` holds no HTTP or WebSocket
   client), and the project's precedent for extension is a separate process speaking a small
   protocol (a registered plugin is an executable that reads one JSON request on stdin and
   answers on stdout, `crates/n0xis-sources/src/plugin.rs:4-15`, registered through the same
   `Plugin` trait as the built-in capabilities, `crates/n0xis-frontend/src/registry.rs:2543,
   2583-2591`), which also keeps the browser protocol's churn and its trust surface in a
   process that can be replaced. (b) The live seam is shaped
   like a process: `LiveTarget` asks for a pid, a main module, a text range and sections by
   name (`crates/n0xis-sources/src/target.rs:73-87`), and `debug watch` arms a hardware
   watchpoint on a pid (`crates/n0xis-cli/src/main.rs:1163-1165, 1209-1211`); a page cannot
   answer these honestly. (c) A code breakpoint gives a hit what it needs, and it is the route
   measured: the protocol definition V8's inspector serves names no watchpoint or memory
   access, while it returns a module's bytecode and reports its `build_id` section and its
   code section's offset. A breakpoint at an `i32.store offset=4` paused at the store's module
   offset with the base (100) and the value (`0x1234`) on the expression stack, and the value
   then stood at address 104. The same bytes compiled twice were reported under one script
   id, so an id names bytes, not an instance.

   *What would change it.* A stage-4 measurement showing that pipe round trips make scans of
   linear memory impractical (bytes per second through the bridge against in-process),
   together with a decision to accept a network client in the engine. The spike finding no
   way to attribute a linear-memory write to a code position in the browser itself: capture
   is then the whole of stage 4. A decision to ship one artifact only.

   *Built.* Stage 4: capture first, with the snapshot's new schema version; then the contract
   and the bridge in its own repository.

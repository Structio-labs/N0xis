# WebAssembly fixtures whose contents are known in advance

Every module here is built on this machine from the source beside it by
`build.sh`, which also records what three independent tools say about it. No
module comes from anywhere else.

| Module | Built from | What it holds |
|---|---|---|
| `ctarget-O0.wasm`, `ctarget-O2.wasm` | `ctarget.c`, `clang --target=wasm32 -O0`/`-O2 -nostdlib -Wl,--no-entry -Wl,--export-all` | 23 functions: arithmetic of every integer kind, 64-bit integers and doubles, loops over an array and a linked list, a struct through a pointer, a load and a store of every width (all 23 load and store opcodes at both levels), a switch that keeps a `br_table`, calls through a function pointer table (`call_indirect`), globals, two imports. The linker pads every relocated index to five bytes. |
| `cthreads-O2.wasm` | `cthreads.c`, `clang --target=wasm32 -O2 -pthread -nostdlib -Wl,--no-entry -Wl,--export-all -Wl,--shared-memory -Wl,--import-memory -Wl,--max-memory=262144` | C11 atomics and threads: the 24 functions of the source (`_Atomic` variables of 8, 16, 32 and 64 bits loaded, stored, added, subtracted, and-ed, or-ed, xor-ed, exchanged and compare-exchanged, a fence, the wait and notify builtins, `_Thread_local` variables, initialised data) and the three the linker adds (`__wasm_init_memory`, with `memory.init`, `data.drop`, `memory.fill` and an atomic flag; `__wasm_init_tls`; `__wasm_call_ctors`): 27 functions, 23 distinct `0xFE` opcodes. The memory is an imported shared one, of at most 4 pages (`--max-memory=262144`); the linker gives it a minimum of 2, so the minimum and the maximum differ. |
| `ceh-legacy-O2.wasm`, `ceh-exnref-O2.wasm` | `ceh.cpp`, `clang++ --target=wasm32 -O2 -fwasm-exceptions -fno-rtti -nostdlib -Wl,--no-entry -Wl,--export-all -Wl,--allow-undefined`, the second with `-mllvm -wasm-use-legacy-eh=false` | C++ exceptions without a standard library: `try`/`catch (...)`, a destructor run during unwinding, a `try` nested in a handler, a rethrow, a throw through `__builtin_wasm_throw`. The two host functions, the runtime's functions and the C++ tag are imports (seven in all). The first uses the legacy instructions (`try`, `catch`, `catch_all`, `rethrow`, `throw`), the second the `exnref` ones (`try_table` with `catch`, `catch_all` and `catch_all_ref` clauses, `throw_ref`, `throw`). |
| `core.wasm` | `core.wat`, `wasm-tools parse` | Every opcode outside the SIMD space (183 one-byte, 18 under `0xFC`), with constants at their extremes, every float class, unaligned accesses and a 32-bit offset at its maximum. |
| `simd.wasm` | `simd.wat`, `wasm-tools parse` | Every opcode of the `0xFD` space (236), lane indices across their ranges. |
| `shapes.wasm` | `shapes.wat`, `wasm-tools parse` | The module's structure: an import of every kind, imports ahead of definitions in every index space, a 64-bit memory with an offset past 4 GiB, three memories, a 64-bit table, all eight element and three data segment forms, a start function, an export of every kind, multiple results, a typed `select`, and a name for everything the name section names (labels included). |
| `threads.wasm` | `threads.wat`, `wasm-tools parse` | Every opcode of the `0xFE` space (67), over four memories: an imported shared memory, a shared 64-bit memory, one that is not shared and a shared one defined in the module. Natural alignments throughout, memory indices in the memory arguments, atomic offsets past 4 GiB on the 64-bit memory (up to 2^64 - 4), wait and notify on every memory. |
| `refs.wasm` | `refs.wat`, `wasm-tools parse` | Typed function references and tail calls, in what wabt also reads: `return_call`, `return_call_indirect` on two tables, `call_ref`, `return_call_ref`, `ref.as_non_null`, `br_on_null`, `br_on_non_null`, `ref.func`, `ref.null` of a concrete type, typed `select` with reference types; a table of `(ref null 1)` and one of `(ref 1)`, each with an initial value (the `0x40 0x00` table form), and a `table.copy 1 2` from the second into the first, whose destination and source differ; globals of typed reference types; element segments of forms 5, 6 and 7 of a concrete type; parameters and locals of `(ref null 1)`, `(ref 1)`, `(ref func)` and `(ref extern)`. |
| `gc.wasm` | `gc.wat`, `wasm-tools parse` | Garbage-collected types and every opcode of the `0xFB` space (31), plus `ref.eq`: an empty recursion group, explicit groups of three and of one, bare types; final and non-final subtypes, with and without a supertype; a structure with a field of every storage type, immutable and mutable, an empty one; arrays of packed, numeric, vector and reference elements; `array.copy` within one type and between two (`array.copy 10 8`, into the mutable array of `(ref null $node)` from the immutable one of `(ref null $tree)`); `ref.test` and `ref.cast` in both nullabilities with abstract and concrete targets, `br_on_cast` and `br_on_cast_fail` in the three nullability combinations validation allows; `ref.null` of every abstract heap type; parameters and locals of every abstract reference type; globals initialised with GC and extended constant expressions; a data count section; an element segment of a concrete GC type; a name for every type and structure field. |
| `eh.wasm` | `eh.wat`, `wasm-tools parse` | Exception handling with `exnref`: five tags of four types (one imported, one exported), `throw`, `throw_ref`, `try_table` with no clause, with each clause kind and with all four at once, nested `try_table`s, block types of all three kinds, `exnref` locals, `ref.null exn`, tag names. |
| `eh-legacy.wasm` | `eh-legacy.wat`, `wasm-tools parse` | Legacy exception handling: `try` with one handler, several, `catch_all` alone, both and none; `delegate` to an enclosing `try`, to a `block` and to the function's own label; `rethrow` from a handler and from blocks nested in one; `try`s nested three deep; block types of all three kinds and one with a parameter. |
| `relaxed.wasm` | `relaxed.wat`, `wasm-tools parse` | The twenty relaxed SIMD opcodes (`0xFD` 0x100 to 0x113), each once, then chained. |

The `.wat` bodies are written one instruction per line in the crate's canonical
spelling (`src/instr.rs`), so `tests/instructions.rs` reads the expected
instructions from the text itself: indices only, branch targets as depths, a
block with parameters or several results as `(type N)`. The numeric and SIMD
runs were laid out with the operand types of wabt's opcode table so that the
modules validate; their names and immediates are the ones written in the
files. Like `ctarget.c`, `cthreads.c` and `ceh.cpp` state at the top the shape
of the line that defines each of their functions, so a test can find them all.

Every module is accepted by three validators, and `build.sh` fails if one
refuses: `wasm-tools validate --features all`, V8 (`node v8dis.mjs
--validate`, which compiles it with `new WebAssembly.Module`, no flags) and
wabt's `wasm-validate --enable-all`, wabt and V8 each except for a module
listed in `build.sh` as one it refuses (`gc.wasm` for wabt, none for V8). Of the reference types wabt reads only
`funcref`, `externref`, `exnref`, `(ref func)`, `(ref extern)` and those of a
type index, so it cannot read `gc.wasm` at all; for that module its refusal is
recorded instead, and every other module keeps to what wabt reads.

What the tools say, recorded for each `<name>.wasm`, with clang 23.1.1,
wasm-tools 1.262.0, wabt 1.0.42 and node 26.10.0 (V8 14.6.202.34):

- `<name>.headers.txt`: `wasm-objdump -h` (wabt);
- `<name>.details.txt`: `wasm-objdump -x`;
- `<name>.disassembly.txt`: `wasm-objdump -d`;
- `<name>.wabt-refuses.txt`, in place of those three for a module wabt cannot
  read (`gc.wasm`): what `wasm-objdump -h` prints on stderr, then its exit
  status, so that the absence of wabt's answer is itself recorded; `build.sh`
  fails if wabt starts reading the module;
- `<name>.print.txt`: `wasm-tools print -p` of a copy with the custom sections
  stripped, so that every index prints as a number;
- `<name>.v8.txt`: V8's own disassembly of the same stripped copy, made by
  `v8dis.mjs` through node's inspector (`Debugger.disassembleWasmModule`), one
  line of V8's text per line, each prefixed with the byte offset V8 gives it
  in hexadecimal; `build.sh` makes it twice and requires the same bytes both
  times;
- `<name>.v8-refuses.txt`, in place of `<name>.v8.txt` for a module V8 refuses
  (none today: V8 compiles every one): what `v8dis.mjs` prints on stderr when
  it disassembles the stripped copy, then its exit status, in the shape of
  wabt's refusal and written by the same function of `build.sh`
  (`record_refusal`); the status must be 1, V8's refusal. `build.sh` fails,
  leaving no record, if V8 starts compiling the module (status 0) or if
  `v8dis.mjs` itself fails (status 2, a missing file for one), which is no
  verdict. `sh build.sh --v8-refusal
  MODULE.wasm RECORD` writes such a record for any module, which
  `tests/v8.rs` (`--features oracle`) uses to check that it reads exactly
  what `build.sh` writes.

`tests/references.rs` compares the reader with these recordings and lists, with
the source that settles each, the lines where a tool is wrong. With the
`oracle` feature, `tests/oracle.rs` runs `build.sh` again into a fresh
directory and fails if any module or recording differs from the one here.
Rebuild and re-record with:

    sh build.sh

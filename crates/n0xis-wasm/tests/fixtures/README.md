# WebAssembly fixtures whose contents are known in advance

Every module here is built on this machine from the source beside it by
`build.sh`, which also records what two independent tools say about it. No
module comes from anywhere else.

| Module | Built from | What it holds |
|---|---|---|
| `ctarget-O0.wasm`, `ctarget-O2.wasm` | `ctarget.c`, `clang --target=wasm32 -O0`/`-O2 -nostdlib -Wl,--no-entry -Wl,--export-all` | 23 functions: arithmetic of every integer kind, 64-bit integers and doubles, loops over an array and a linked list, a struct through a pointer, a load and a store of every width (all 23 load and store opcodes at both levels), a switch that keeps a `br_table`, calls through a function pointer table (`call_indirect`), globals, two imports. The linker pads every relocated index to five bytes. |
| `core.wasm` | `core.wat`, `wasm-tools parse` | Every opcode outside the SIMD space (183 one-byte, 18 under `0xFC`), with constants at their extremes, every float class, unaligned accesses and a 32-bit offset at its maximum. |
| `simd.wasm` | `simd.wat`, `wasm-tools parse` | Every opcode of the `0xFD` space (236), lane indices across their ranges. |
| `shapes.wasm` | `shapes.wat`, `wasm-tools parse` | The module's structure: an import of every kind, imports ahead of definitions in every index space, a 64-bit memory with an offset past 4 GiB, three memories, a 64-bit table, all eight element and three data segment forms, a start function, an export of every kind, multiple results, a typed `select`, and a name for everything the name section names (labels included). |

The `.wat` bodies are written one instruction per line in the crate's canonical
spelling (`src/instr.rs`), so `tests/instructions.rs` reads the expected
instructions from the text itself. The numeric and SIMD runs were laid out with
the operand types of wabt's opcode table so that the modules validate; their
names and immediates are the ones written in the files. All five validate with
`wasm-tools validate --features all`.

What the tools say, recorded for each `<name>.wasm`:

- `<name>.headers.txt`: `wasm-objdump -h` (wabt 1.0.42);
- `<name>.details.txt`: `wasm-objdump -x`;
- `<name>.disassembly.txt`: `wasm-objdump -d`;
- `<name>.print.txt`: `wasm-tools print -p` (1.262.0) of a copy with the custom
  sections stripped, so that every index prints as a number.

`tests/references.rs` compares the reader with these recordings and lists, with
the source that settles each, the lines where a tool is wrong. With the
`oracle` feature, `tests/oracle.rs` runs `build.sh` again into a fresh
directory and fails if any module or recording differs from the one here.
Rebuild and re-record with:

    sh build.sh

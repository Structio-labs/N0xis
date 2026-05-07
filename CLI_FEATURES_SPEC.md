---
tags: [spec, cli, ir, roadmap, project/n0x]
aliases: [CLI Spec, Feature Spec]
---

> Navigation: [[MAP|Map]] · **CLI Spec** · [[BACKEND_SPEC|Backend Spec]] · [[n0x-cli-rs/README|CLI README]] · [[n0x-cli-rs/DEVLOG|CLI DevLog]]

# N0x CLI Feature Specification 

> Implementation lives in the Rust crate at [[n0x-cli-rs/README|n0x-cli-rs]]. Chronological change log: [[n0x-cli-rs/DEVLOG]].

## Implementation Progress (Live)

- [x] Rust CLI scaffold (`n0x-cli-rs`)
- [x] JSON output contract (`ok/data/meta`, `ok/error`)
- [x] `process ps`
- [x] `target attach|detach|info`
- [x] `module list`
- [x] `mem read|write|map`
- [x] `mem map` filters (`--state`, `--kind`, `--protect`)
- [x] `disasm`
- [x] `xref to|from`
- [x] `doctor` readiness checks
- [x] `function list|info` (export-based v1)
- [x] `function discover` (heuristic v1 for non-exported entries)
- [x] `xref --kind` filters (`call|jmp|lea`)
- [x] `xref string` (query -> string refs -> LEA xrefs)
- [x] `function trace --depth` (call/jmp tree v1)
- [x] `selection save|list|show|xref` (persist ranges + xref report file)
- [x] Per-project state via `.n0x/` (walk-up discovery, falls back to global `%LocalAppData%/n0x/`). Fixes the cross-project state-collision bug — `session.json` and `selections.json` now live next to the project, not globally.
- [x] `init`, `project info`, `dump save|list|show|rm` (single per-project shim + persistent AI dump store under `.n0x/dumps/{ir,pseudo,hex,raw,note}/`)
- [x] `install.ps1` — release build → user-writable install dir (default `D:\Apps\N0x\bin\n0x.exe`) → User PATH (idempotent). Same script with `-Scope Machine -Dest 'D:\Program Files\N0x'` for the eventual all-users release ship.
- [x] Patch pipeline (`patch dry-run|apply|list|show|undo`) with persistent undo log under `.n0x/patches/patch-<id>.json`; `list` supports `--status` filtering, `show` returns a single record by id, `undo` can target explicit `--id` or latest record, with safety check on current bytes (override via `--force`)
- [ ] Interactive TUI pane layout (another tool-like)

## Decompilation / IR Layer Plan

- [x] Define IR schema v1 (`n0x.ir.v1`: `function`, `blocks`, `successors`, `instructions`, `callsites`, `reads_regs`, `writes_regs`, `reads_mem`, `writes_mem`)
- [x] Add `ir build --addr <a> --size <n>` (JSON output)
- [x] Add basic CFG extraction from disassembly (leaders + successors per block)
- [x] Add instruction lifting metadata (register read/write + memory access hints via `iced_x86::InstructionInfoFactory`)
- [x] Add callsite model v1 (`direct`, `indirect`, `tail`)
- [x] Extend callsite model with `import` (IAT-resolved indirect call) and `tail-import` (jmp through IAT thunk)
- [x] Add data-flow links (`def-use` per basic block, intra-block writer indices)
- [x] Add `ir explain --addr <a>` summarizer for AI consumption (CFG stats + back-edge detection + call list with arg hints)
- [x] Add `ir cfg --addr <a>` lightweight adjacency view
- [x] Function boundary auto-detection (`--no-auto-end` opts out)
- [x] Tail-call detection (unconditional `jmp` outside function body)
- [x] Win64 ABI argument hints per callsite (`rcx/rdx/r8/r9` last-writer in same block)
- [x] Stack frame summary (frame size, spilled regs, prolog excerpt, `uses_rbp`)
- [x] Symbol resolution for callsite targets (owner-module exports → `module!name`)
- [x] View levels for `ir build`: `full | minimal | cfg | block` (`--view`)
- [x] Block slicing (`--block <id>`) and address range filter (`--range 0xA-0xB`) for `ir build`
- [x] Same view/block knobs piped through `selection ir`
- [x] Cross-module symbol resolution (resolve into all loaded modules + IAT)
- [x] `ir manifest --module M` (lightweight per-function index with quality scores). Sources: `exports | discover | both`. Per-entry: `address`, `name`, `source`, `instruction_count`, `block_count`, `returns`, `indirect_branches`, `tail_calls`, `callsites`, `frame_size`, `end_address`, `quality` (0.0..=1.0), `flags[]` (`leaf | has-switch | has-import | tail | stub | runaway | no-frame | no-return`). Filters: `--filter <substr>`, `--min-quality F`, `--limit N`. Sort: `--sort quality|address`.
- [ ] Optional binary on-disk cache (postcard/bincode) for analyzed modules
- [ ] Optional `--format msgpack` wire mode for cases where JSON size becomes a bottleneck
- [x] Constant tracking lite (`mov reg, imm` / `xor reg,reg` / `lea reg,[rip+disp]` → per-block register-immediate map; surfaced on `def_use.const_val` and `arg_hints.const_val`)
- [x] Switch / jump-table reconstruction (best-effort hints: `mem-indexed` and MSVC `reg-rel32` patterns; emits `IrSwitch { at, kind, table?, index_reg?, scale, bound?, cases? }`)
- [x] Memory-side switch resolution: reads the dispatch table from the live process, materializes case targets, attaches them as `kind: "switch"` successors with `case_index` on the dispatching block (`--no-switch-resolve` to opt out, `--switch-cap N` to cap)
- [x] DOT export of CFG for visualization (`ir dot --addr <a>`) — `n0x.ir.dot.v1` with Graphviz DOT body (`dot`) + graph stats (`block_count`, `edge_count`)
- [x] Backward slicing (`ir slice --addr <a> --reg <r>`) — `n0x.ir.slice.v1` (`seed`, `nodes[]`, `deps[]`, `roots[]`). Seed = nearest writer of the queried register at/preceding `--addr`; traversal follows instruction `def_use` links.
- [x] `decomp pseudo --addr <a>` — template-based pseudo-C v0. Lifts each instruction over the existing IR + symbol/IAT/frame/arg-hint context. Output schema `n0x.decomp.pseudo.v1` with `signature`, `pseudo[]` (line-by-line), `locals[]` (stack slots tracked from rsp-relative accesses), `quality` (% converted), `flags[]` (`has-switch | has-indirect | has-tail | has-loop | structured | structured-partial | low-coverage`), `instruction_count`, `converted_count`. Honors all `IrBuildArgs` (auto-end, view restrictions, switch resolve)
- [x] Structured control reconstruction (`decomp pseudo --style structured`, default): dominators + post-dominators (iterative fixed point) → immediate dominators → natural-loop detection via back-edges. Emits real `if (cond) { ... } else { ... }` with `ipdom` as the merge point, top-test `while (cond) { ... }` (with cheap structural negation when the loop-exit arm is the cjmp-true branch), and a generic `while (1) { ... break; ... }` fallback for irreducible/multi-exit loops. Back-edges to enclosing headers become `continue;`, edges to a known loop-exit become `break;`. Anything the reducer can't classify falls back to a labelled `goto block_N;` and bumps `structured-fallbacks` in the header comment + `structured-partial` flag. `--style goto` keeps the original always-correct labelled form for diffing.
- [x] Structured v2 patterns (folded into the same `structured` style, no flag change for AI consumers):
  - `do { ... } while (cond);` for bottom-test loops where the back-edge originates from a `cjmp` tail inside the body and the header itself is not a cjmp.
  - `for (; cond; step)` recovery for top-test loops with a single non-cjmp latch whose body tail matches a counter-step pattern (`x++`, `x--`, `x += k`, `x -= k`, `x = x ± k`).
  - Short-circuit `&&` / `||` fold of 2-block cjmp chains where the inner guard has a single predecessor (= the outer cjmp), no side-effecting body, and shares an arm with the outer cjmp. Covers AND-true, AND-false, OR-true, OR-mirror.
- [x] Add selection integration: `selection ir --name <id> [--out <file>] [--explain]`
- [x] Add quality score/confidence per recovered function/edge — function-level `quality` already emitted in `ir manifest`; edge-level `successors[].confidence` now emitted in `n0x.ir.v1` / `n0x.ir.cfg.v1` and surfaced in DOT edge labels (`q=...`) for `ir dot`

### IR Schema v1 (`n0x.ir.v1`)

```
IrFunction {
  schema, address, end_address,
  instruction_count, block_count,
  blocks: [IrBlock], callsites: [IrCallsite],
  returns, indirect_branches, tail_calls,
  frame: IrFrameSummary,
  switches: [IrSwitch]            // optional, omitted when empty
}
IrBlock { id, address, end_address, terminator, successors, instructions }
IrSuccessor { to, kind: fall|jmp|cjmp-true|cjmp-false|switch, case_index? }
                                   // case_index set when kind == "switch"
IrSwitch { at, kind: mem-indexed|reg-rel32, table?, index_reg?, scale, bound?, cases?[] }
                                   // cases[] populated by memory-side
                                   // resolution (reads the table from the
                                   // live process, attaches each as a
                                   // "switch" successor on the dispatching
                                   // block)
IrInstr {
  address, len, text,
  kind: call|icall|jmp|ijmp|cjmp|ret|int|tail-call|tail-import|other,
  target?, target_name?,           // target_name set for direct cross-module
                                   // calls (via global symbol map) and for
                                   // indirect calls/jmps resolved via the
                                   // owner-module IAT
  reads_regs[], writes_regs[],
  reads_mem[IrMemAccess], writes_mem[IrMemAccess],
  def_use: [DefUseEntry]
}
IrMemAccess { base?, index?, scale, displacement }
IrCallsite {
  from,
  kind: direct|indirect|tail|import|tail-import,
  target?, target_name?, instruction,
  arg_hints: [ArgHint { reg, def_addr?, def_text?, const_val? }]
                                   // Win64 ABI rcx/rdx/r8/r9
}
IrFrameSummary { frame_size, uses_rbp, spilled_regs[], prolog[] }
DefUseEntry {
  reg, def_index, def_addr, const_val?
}                                  // const_val: per-block immediate
                                   // tracker (mov/xor/lea-rip)
IrSwitch {
  at, kind: mem-indexed|reg-rel32,
  table?, index_reg?, scale, bound?
}
```

### Sibling schemas

- `n0x.ir.cfg.v1` — lightweight adjacency view from `ir cfg`.
- `n0x.ir.explain.v1` — short text summary from `ir explain` / `selection ir --explain`.
- `n0x.ir.manifest.v1` — per-module index of recovered functions with quality scoring and categorical flags. Designed as the AI's "first page" of a module: read once, drill into specific addresses via `ir build --addr`.
- `n0x.decomp.pseudo.v1` — pseudo-C view (default `--style structured`, opt-out `--style goto`). Lifted instruction lines, stack-local naming, name-resolved direct/import calls. Structured mode emits real `if/else`, `while`, `do-while`-style constructs reconstructed from CFG via dominators / post-dominators / natural loops, with `continue` and `break` for back-edges and loop exits. `quality` is the fraction of instructions successfully converted (unconverted ones become `// asm: ...`). `flags[]` includes `structured` whenever the structural pass ran; `structured-partial` if any region had to fall back to `goto block_N;`. Drives natural-language reasoning by AI without forcing a full assembler reading.

## 1) Goal

Build a full-featured CLI for reverse engineering and game analysis that:
- works both for humans (interactive TUI mode),
- and for neural agents (deterministic machine-readable mode).

The CLI must support workflows similar to another tool/another tool core tasks, including:
- cross references (xrefs),
- disassembly/code view,
- symbol/function navigation,
- memory inspection and patching,
- automation scripting.

---

## 2) Operating Modes

### 2.1 Interactive Mode (TUI)
- Split panes:
  - Left: symbols/functions/modules/xrefs list.
  - Right: disassembly / pseudocode / hex view.
  - Bottom: logs + command input.
- Keyboard-driven navigation:
  - arrows, page up/down, enter, back, search, go-to.
- Context actions:
  - jump to xref source/target,
  - rename symbol/function,
  - set/remove breakpoints,
  - patch bytes.

### 2.2 Agent Mode (Non-interactive)
- No ANSI by default.
- Pure JSON output via `--json`.
- Stable exit codes and error schema.
- Deterministic field names for easy LLM parsing.

---

## 3) CLI Command Surface

## 3.1 Session / Target
- `n0x session new`
- `n0x session open <path>`
- `n0x session save <path>`
- `n0x target list`
- `n0x target attach --pid <pid>`
- `n0x target detach`
- `n0x target info`

## 3.2 Process / Modules / Memory Map
- `n0x process ps [--filter ...] [--sort ...]`
- `n0x module list`
- `n0x module info --name <module>`
- `n0x mem map`
- `n0x mem region --addr <hex>`

## 3.3 Hex / Memory IO
- `n0x mem read --addr <hex> --size <n>`
- `n0x mem write --addr <hex> --bytes "48 8B 01 ..."`
- `n0x mem dump --start <hex> --end <hex> --out <file>`
- `n0x mem search --pattern "48 8B ?? ??"`

## 3.4 Disassembly / Analysis
- `n0x disasm --addr <hex> --count <n>`
- `n0x disasm function --name <symbol>`
- `n0x function list`
- `n0x function info --name <symbol>`
- `n0x cfg show --func <symbol>` (control flow graph summary)

## 3.5 Cross References (Critical)
- `n0x xref to --addr <hex|symbol>`
- `n0x xref from --addr <hex|symbol>`
- `n0x xref graph --addr <hex|symbol>`
- Each xref item should include:
  - source address/function,
  - target address/function,
  - xref type (`call`, `jump`, `data-read`, `data-write`, `import`, `string-ref`),
  - module/section context.

## 3.6 Symbols / Metadata
- `n0x symbol list [--kind function|import|string|global]`
- `n0x symbol rename --old <name> --new <name>`
- `n0x comment set --addr <hex> --text "..."`
- `n0x label set --addr <hex> --name <label>`

## 3.7 Patch / Undo
- `n0x patch bytes --addr <hex> --bytes "..."`
- `n0x patch nop --addr <hex> --count <n>`
- `n0x patch asm --addr <hex> --instruction "..."`
- `n0x patch list`
- `n0x patch undo --id <id>`
- `n0x patch apply --out <file>`

## 3.8 Debug (Optional Stage 2)
- `n0x dbg break add --addr <hex>`
- `n0x dbg break list`
- `n0x dbg run | pause | stepi | stepover | continue`
- `n0x dbg regs`
- `n0x dbg stack`

## 3.9 Search & Intelligence
- `n0x find string --query "..."`
- `n0x find immediate --value <hex|int>`
- `n0x find api --name "CreateFileW"`
- `n0x yara scan --rule <file>`

## 3.10 Scripting / Automation
- `n0x script run <file.ts|file.py>`
- `n0x script eval "<expr>"`
- `n0x macro record <name>`
- `n0x macro play <name>`

---

## 4) Output Contracts (Required for Neural Agent)

## 4.1 Global Output Flags
- `--json` machine-readable output.
- `--pretty` pretty JSON (for humans).
- `--quiet` suppress non-essential text.
- `--no-color` disable ANSI.
- `--timeout-ms <n>` hard timeout for long calls.

## 4.2 Error Contract
Every error should be emitted as:

```json
{
  "ok": false,
  "error": {
    "code": "ACCESS_DENIED",
    "message": "Cannot open process 1234",
    "hint": "Run elevated or enable SeDebugPrivilege"
  }
}
```

## 4.3 Success Contract
Every success should include:

```json
{
  "ok": true,
  "data": {},
  "meta": {
    "elapsedMs": 12,
    "targetPid": 1234,
    "timestamp": "2026-05-07T15:00:00.000Z"
  }
}
```

---

## 5) Event Streaming

CLI should support live event streaming:
- `n0x events tail`
- `n0x events tail --json`
- `n0x events subscribe process_exit,module_load,breakpoint_hit`

Event types:
- `process_exit`
- `module_load`
- `module_unload`
- `thread_create`
- `breakpoint_hit`
- `memory_protection_change`
- `log_info`, `log_warn`, `log_error`

---

## 6) Cross Reference Data Model

```json
{
  "ok": true,
  "data": {
    "query": {
      "kind": "symbol",
      "value": "sub_180107184"
    },
    "xrefs": [
      {
        "from": {
          "address": "0x1801072B0",
          "function": "sub_180107204",
          "module": "game.exe"
        },
        "to": {
          "address": "0x180107184",
          "function": "sub_180107184",
          "module": "game.exe"
        },
        "type": "call",
        "section": ".text"
      }
    ]
  }
}
```

---

## 7) Performance Requirements

- Process list: < 150 ms for 2k+ rows.
- Xref query: < 300 ms typical function scope.
- Disasm fetch (100 instructions): < 100 ms cached.
- Hex read (4 KB): < 50 ms local target process.
- Streamed output should support pagination / cursoring.

---

## 8) Security Requirements

- Explicit privilege checks and clear error messages.
- Safe write-path with dry-run mode:
  - `--dry-run` for patch/memory writes.
- Optional audit log:
  - operation, target pid, address range, timestamp, operator/session id.
- Guard rails:
  - deny writes to protected ranges unless `--force`.

---

## 9) Suggested Internal Architecture

- `core/`
  - process service
  - memory service
  - disasm service
  - xref/index service
  - symbol service
- `cli/`
  - command parser
  - renderer (tui/plain/json)
  - output contracts
- `transport/`
  - local native bridge (Tauri/Rust or Node native addon)
  - optional gRPC/IPC backend

---

## 10) MVP Priority (Implementation Order)

1. Session + target attach/detach.
2. Process/module/memory-map commands.
3. `mem read/write/search`.
4. `disasm` + function list.
5. `xref to/from` (must-have).
6. JSON output contracts + stable error codes.
7. TUI split-pane navigation.
8. Patch pipeline + undo.
9. Event stream + automation scripts.

---

## 11) Minimum “another tool-like” Parity for First Release

To match your screenshot workflow (xrefs + right-side code view), first release must include:
- function/symbol list pane,
- xref pane (calls to/from selected symbol),
- main code pane (disassembly with jump navigation),
- quick jump (`g` / `goto`) by address/symbol,
- inline comments + labels,
- searchable command palette.

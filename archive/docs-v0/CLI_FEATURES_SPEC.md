---
tags: [spec, cli, ir, roadmap, project/n0x]
aliases: [CLI Spec, Feature Spec]
---

> Navigation: [[PROJECTS|Map]] · **CLI Spec** · [[BACKEND_SPEC|Backend Spec]] · [[n0x-cli-rs/README|CLI README]] · [[n0x-cli-rs/DEVLOG|CLI DevLog]]

# N0x CLI Feature Specification 

> Implementation lives in the Rust crate at [[n0x-cli-rs/README|n0x-cli-rs]]. Chronological change log: [[n0x-cli-rs/DEVLOG]].

## Implementation Progress (Live)

- [x] Rust CLI scaffold (`n0x-cli-rs`)
- [x] JSON output contract (`ok/data/meta`, `ok/error`)
- [x] `process ps`
- [x] `target attach|detach|info`
- [x] `module list` (live: enumerate loaded modules; **`--file`**: synthetic single-module list for one PE — preferred base, **`SizeOfImage`**, path; **`data.pid`** null, **`peFile`** set)
- [x] `mem read|write|map` (**`mem read --file`**: image bytes via **`IrSource`**; **`mem write`** / **`mem map`** live-only)
- [x] `mem map` filters (`--state`, `--kind`, `--protect`)
- [x] `disasm` (**`--file`** or **`--pid`** / session; static VA = preferred image base + RVA)
- [x] `xref to|from` (**`--file`**: scan window via **`IrSource::read`**)
- [x] `doctor` readiness checks
- [x] `function list|info` (**`--file`**: exports from one PE on disk)
- [x] `function discover` (**`--file`**: heuristic discover on contiguous virtual image)
- [x] `xref --kind` filters (`call|jmp|lea`)
- [x] `xref string` (live: **`--module`**; static: **`--file`**, optional **`--module`** label; contiguous **`SizeOfImage`** scan + LEA xrefs in **`.text`**)
- [x] `function trace --depth` (call/jmp tree v2; **`--file`** or live **`--pid`** + **`--module`**; static path uses same limits / **`--addr-rva`** against preferred base): **`--addr-rva`** treats `--addr` as a PE image RVA for `--module` (`resolved VA = loaded base + addr`); success JSON includes resolved `root` and optional `addrRva`. Schema `n0x.function.trace.v2` — `limits` (`maxNodes`, `maxTimeMs`, `maxEdgesTotal`; `0` = unlimited), `truncated` + `truncateReason` (`max_nodes` \| `max_time_ms` \| `max_edges_total`), `stats` (setup/walk ms, queue metrics), optional `reportPath`, plus `trace[]`. NDJSON sidecar via `--report PATH` (`n0x.function.trace.report.v1` lines: `header` \| `node` \| `footer`) with `--report-flush-every` / `--report-flush-ms`.
- [x] `selection save|list|show|xref` (persist ranges + xref report file) — **live only** (records hold **`pid`** + absolute VAs; no **`--file`**). For static PE workflows use **`ir build --file --range …`** instead of named selections.
- [x] Per-project state via `.n0x/` (walk-up discovery, falls back to global `%LocalAppData%/n0x/`). Fixes the cross-project state-collision bug — `session.json` and `selections.json` now live next to the project, not globally.
- [x] `init`, `project info`, `dump save|list|show|rm` (single per-project shim + persistent AI dump store under `.n0x/dumps/{ir,pseudo,hex,raw,note}/`)
- [x] `install.ps1` — release build → user-writable install dir (default `D:\Apps\N0x\bin\n0x.exe`) → User PATH (idempotent). Same script with `-Scope Machine -Dest 'D:\Program Files\N0x'` for the eventual all-users release ship.
- [x] Patch pipeline (`patch dry-run|apply|list|show|undo`) with persistent undo log under `.n0x/patches/patch-<id>.json`; `list` supports `--status` filtering, `show` returns a single record by id, `undo` can target explicit `--id` or latest record, with safety check on current bytes (override via `--force`)
- [x] **Debugger (`debug await-hit`, Windows x64 target, x64 CLI)** — програмний **`int3`**, блокування **`WaitForDebugEvent`** до відповідного **`EXCEPTION_BREAKPOINT`** або **`--timeout-ms`**, **`DebugActiveProcessStop`** + відновлення байта. Структури: **`n0x.debug.await_hit.v1`** (stdout), **`n0x.debug.hit.v1`** (поле **`hit`**), **`n0x.debug.await_hit.report.v1`** (рядковий звіт через **`--report`**). Обмеження зараз: **один** SB, **немає** HW BP / окремих `attach`; **не сумісний** із CE/another debugger на тому ж PID; відхиляє **не-x64** цілі. При збої CLI евристично ставить **`error.code`** для агента (`DEBUG_ATTACH_DENIED_OR_BUSY`, …); повний **`GetLastError`** у полі JSON — [ ] план. Див. [[n0x-cli-rs/DEBUGGER_BREAKPOINTS_ROADMAP|DEBUGGER_BREAKPOINTS_ROADMAP]].
- [ ] Interactive TUI pane layout (another tool-like)

### Static-first RE (`--file` — single PE)

- **One PE per invocation**: static mode uses the PE **preferred `ImageBase`** and on-disk sections (or a contiguous **`SizeOfImage`** buffer). There is **no** real loaded base, ASLR slide, or sibling-DLL list.
- **Symbols**: exports + this module’s **IAT** only — not the full multi-module symbol closure of a live process.
- **Still live-only**: `process ps`, `target *`, `mem map`, `mem write`, `patch *`, `debug await-hit`, and **`selection *`** (selection JSON stores **`pid`** + absolute VAs).

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
- [x] `ir manifest --module M` (lightweight per-function index with quality scores; live **`--module`** required; **`--file`**: single PE, optional display **`--module`**; per-function reads via **`IrSource::read`**). Sources: `exports | discover | both`. Per-entry: `address`, `name`, `source`, `instruction_count`, `block_count`, `returns`, `indirect_branches`, `tail_calls`, `callsites`, `frame_size`, `end_address`, `quality` (0.0..=1.0), `flags[]` (`leaf | has-switch | has-import | tail | stub | runaway | no-frame | no-return`). Filters: `--filter <substr>`, `--min-quality F`, `--limit N`. Sort: `--sort quality|address`.
- [ ] Optional binary on-disk cache (postcard/bincode) for analyzed modules
- [ ] Optional `--format msgpack` wire mode for cases where JSON size becomes a bottleneck
- [x] Constant tracking lite (`mov reg, imm` / `xor reg,reg` / `lea reg,[rip+disp]` → per-block register-immediate map; surfaced on `def_use.const_val` and `arg_hints.const_val`)
- [x] Switch / jump-table reconstruction (best-effort hints: `mem-indexed` and MSVC `reg-rel32` patterns; emits `IrSwitch { at, kind, table?, index_reg?, scale, bound?, cases? }`)
- [x] Static / file-backed PE analysis for IR + pseudo-decomp: **`--file <path>`** on **`IrBuildArgs`** (mutually exclusive with **`--pid`**). **`--addr`** is interpreted as a VA in the PE's **preferred** image base (from optional header). Exports + import directory populate symbol/IAT maps; **`resolve_switches`** reads jump-table bytes via the same **`IrSource::read`** path as live **`ReadProcessMemory`** (no second implementation).
- [x] Memory-side switch resolution: reads the dispatch table from the **IR source** (live process or static PE image), materializes case targets, attaches them as `kind: "switch"` successors with `case_index` on the dispatching block (`--no-switch-resolve` to opt out, `--switch-cap N` to cap)
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
- Long-running commands may print human-readable **`[n0x]` progress lines on stderr** (stdout remains JSON-only for parsers). Suppress with global **`--quiet`**.
- Stable exit codes and error schema.
- Deterministic field names for easy LLM parsing.

---

## 3) CLI Command Surface (implemented: `n0x-cli-rs`)

The shipping binary is built from crate **`n0x-cli-rs`**. After `cargo build` it is typically `target/debug/n0x-cli-rs.exe` (dev) or copied to **`n0x.exe`** on PATH via `install.ps1`. **`--help`** shows the binary name **`n0x`** — examples below use `n0x` as the verb; substitute your path when running from the build tree.

### 3.0 Global flags (all subcommands)
- `--json` — emit the `{ ok, data|error, meta }` envelope on stdout for successful commands (and structured errors).
- `--pretty` — pretty-print JSON.
- `--quiet` — suppress `[n0x] …` human progress lines on stderr for long-running commands (stdout JSON unchanged).

Per-command timeouts exist only where explicitly documented (e.g. `debug await-hit --timeout-ms`).

### 3.1 `debug` (optional; Windows x64 target + x64 CLI build)
- `debug await-hit` — software `int3`, `WaitForDebugEvent`, JSON `n0x.debug.await_hit.v1` + embedded hit payload; optional NDJSON `--report`. Requires `--module`, `--addr` (or `--addr-rva` + `--addr`), optional `--pid`, `--instruction` / `--instruction-file`, `--timeout-ms`, `--stack-qwords`.

### 3.2 `process`
- `process ps` — optional `--filter` (substring on process name, exe path, or pid string).

### 3.3 `target`
- `target attach --pid`, `target detach`, `target info` — session `attachedPid` stored under `.n0x/` (walk-up) or `%LocalAppData%/n0x/`.

### 3.4 `module`
- `module list` — live: `--pid` or session target → loaded modules. Static: `--file <PE>` → **one** synthetic row (preferred image base, `SizeOfImage`, path); `data.pid` is JSON `null`, `peFile` set.

### 3.5 `mem`
- `mem read` — live (`--pid` / session) **or** static `--file` (bytes through the same `IrSource` path as IR). `--addr`, `--size`.
- `mem write` — live only (`--addr`, `--bytes`, optional `--pid`).
- `mem map` — live only; `--limit`, optional `--state`, `--kind`, `--protect` filters.

### 3.6 `disasm`
- `disasm` — `--addr`, `--count`; live **or** `--file` (VA must lie in a mapped section for static PE).

### 3.7 `xref`
- `xref to` / `xref from` — `--addr`, `--start`, `--size`, optional `--kind`; live **or** `--file`. For static PE, `--start` must be inside a **section** (not necessarily the bare `ImageBase` if headers sit outside the first section).
- `xref string` — live: `--module` (substring) + `--query`. Static: `--file`, `--query`; `--module` optional label for JSON.

### 3.8 `function`
- `function list` — exports; live **or** `--file`.
- `function info` — `--name`; live **or** `--file`.
- `function discover` — heuristic `.text` scan; live needs `--module`, static `--file` (optional `--module` label).
- `function trace` — `--addr` / `--addr-rva`, `--depth`, resource limits, optional `--report`; live needs `--module`, static `--file`.

### 3.9 `selection` (live only)
- `selection save|list|show|xref|ir` — saved ranges store a **`pid`** + absolute VAs; no `--file` mode. For static PE workflows use `ir build --file --range …` instead.

### 3.10 `patch`
- `patch dry-run|apply|list|show|undo` — persistent journal under `.n0x/patches/` (`dry-run` compares bytes without writing).

### 3.11 `ir`
- `ir build|explain|cfg|dot` — shared **`IrBuildArgs`**: `--pid` xor `--file`, `--addr`, `--size`, `--view`, `--block`, `--range`, switch-resolution flags, etc.
- `ir slice` — `--addr`, `--size`, `--reg` (+ same `IrBuildArgs` / `--file` as above).
- `ir manifest` — `--source exports|discover|both`, `--limit`, `--filter`, `--min-quality`, `--sort`, per-function `--size`. Live: **`--module`** required. Static: **`--file`**, optional `--module` display name.

### 3.12 `decomp`
- `decomp pseudo` — flattens the same **`IrBuildArgs`** as `ir build`; `--style goto|structured`.

### 3.13 `doctor`
- `doctor` — optional `--dll-path`, `--pid` for extra checks.

### 3.14 `init` / `project`
- `init` — create `.n0x/`, `project.toml`, dumps skeleton, `n0x.cmd` shim.
- `project info` — resolved project root and storage paths.

### 3.15 `dump`
- `dump save|list|show|rm` — anchors under `.n0x/dumps/<kind>/` (`ir`, `pseudo`, `hex`, `raw`, `note`).

### 3.99) Ideas backlog (not in `n0x-cli-rs` today — still useful product targets)

These **do not** exist as subcommands yet; they came from early sketches and remain a **roadmap** (or future TUI features), not something agents should call now:

- First-class **session** objects (`session new|open|save`) — today: implicit session via `target attach` + `selections.json` / `session.json`.
- `module info`, `mem region`, `mem dump`, `mem search` as dedicated verbs.
- `disasm function --name`, standalone `cfg show` (today: `ir cfg` / `ir build --view cfg`).
- `xref graph` (today: `ir dot` for Graphviz export; no interactive graph CLI).
- Project-wide **symbols** / comments / labels CRUD.
- Rich **debugger** REPL (`dbg run|stepi|regs|stack`) — today only the narrow `debug await-hit` workflow.
- Global **find** / Yara, **script/macro** runner, **`events tail`** stream.

When any of the above ships, add it under §3 with real flags and move it from §3.99.

---

## 4) Output Contracts (Required for Neural Agent)

## 4.1 Global Output Flags
- `--json` machine-readable output.
- `--pretty` pretty JSON (for humans).
- `--quiet` suppress non-essential stderr progress (`[n0x]` lines); does not change stdout JSON contracts.

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

## 5) Event Streaming (not implemented)

Live **`n0x events tail`** / subscribe was a design sketch. There is **no** generic event stream in `n0x-cli-rs` today. Closest structured “stream” is optional NDJSON sidecars (`function trace --report`, `debug await-hit --report`). See **§3.99** for other backlog items.

---

## 6) Cross Reference Data Model

Illustrative composite (actual JSON shapes differ per command — use `xref to|from|string` and the IR schemas in crate docs as ground truth):

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

- Explicit privilege checks and clear error messages where Win32 APIs fail.
- Safe write-path: use **`patch dry-run`** before **`patch apply`**; undo metadata is persisted and **`patch undo`** can restore prior bytes (with a guard unless `--force`).
- Optional future: audit log (operation, pid, address range, timestamp).

---

## 9) Suggested Internal Architecture

High-level sketch for a future split UI + services stack. **Today** the Windows RE surface lives in a single **`n0x-cli-rs`** binary (`src/main.rs` + modules); there is no separate `transport/` layer in-repo yet.

- `core/` — process/memory/disasm/xref/IR services (conceptual; currently inlined in the crate).
- `cli/` — clap parsing + JSON emit (current crate root).
- `transport/` — reserved for Tauri / IPC when the React frontend attaches to the same contracts.

---

## 10) MVP vs current crate (2026)

The numbered “implementation order” list below is **historical**. For **what actually exists today**, treat **Implementation Progress (Live)** near the top of this file and **§3) CLI Command Surface** as canonical. Remaining large items from the original MVP spirit:

- Interactive **TUI** (split panes, palette) — still open; see checklist “Interactive TUI pane layout”.
- **Event stream** / scripting host — not built; see **§5** and **§3.99**.

---

## 11) Minimum “another tool-like” Parity for First Release

UI / TUI targets (comments, labels, `goto` palette) — **not** the current headless CLI. Headless parity today is covered by **`disasm`**, **`xref`**, **`function`**, **`ir`**, **`decomp pseudo`**, **`patch`**, **`selection`**, and static **`--file`** workflows per **§3**.

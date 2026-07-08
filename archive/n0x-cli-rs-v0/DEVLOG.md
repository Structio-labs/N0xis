---
tags: [devlog, cli, rust, history, project/n0x]
aliases: [CLI DevLog, DevLog]
---

> Navigation: [[PROJECTS|Map]] · [[CLI_FEATURES_SPEC|CLI Spec]] · [[README|CLI README]] · **DevLog**

# N0x CLI Dev Log

> Companion files: [[CLI_FEATURES_SPEC]] (the plan), [[README|CLI README]] (user-facing usage).

## 2026-05-08

### Added — Static PE --file for IR and decomp pseudo

- Crate module **`static_pe`**: load a PE from disk with goblin; **`read_va(va, size)`** maps virtual addresses using the optional header **preferred image base** + section table (raw size limits mirror short `ReadProcessMemory` reads); **`symbol_map` / `iat_map`** align with the live path (`module!export`, `DLL!import`).
- **`IrBuildArgs --file <PATH>`** (mutually exclusive with **`--pid`**): **`IrSource::Static`** vs **`IrSource::Live`** in **`build_ir_for_args`**. **`--addr`** must be a VA in that preferred mapping (not the rebased runtime base — use **`--pid`** for ASLR’d targets).
- **`resolve_switches`** already uses **`source.read(table, …)`** — jump tables resolve from process memory or from on-disk section bytes identically.
- **`decomp pseudo`** now uses **`build_ir_for_args`** (same source dispatch as **`ir build`**); **`meta.targetPid`** is **`null`** when static.

### Added — Static-first RE surface (single PE, read-only)

Unified byte source **`IrSource::from_pid_or_file`** for analysis commands that only need bytes + PE metadata:

- **`module list --file`**: one synthetic **`ModuleInfo`** (preferred base, **`SizeOfImage`**, path); **`data.pid`** **`null`**, **`peFile`** set.
- **`mem read --file`**, **`disasm --file`**, **`xref to|from|string --file`**: read through **`IrSource::read`** (live RPM vs static **`read_va`**); static responses may include **`peFile`**; **`xref string`** on static uses **`contiguous_virtual_image`** + shared **`xref_string_bytes`** helper.
- **`ir manifest --file`**: exports / discover / both over one **`StaticPe`**; live path still requires **`--module`**; per-function bytes via **`source.read`**.
- **`function list|info|discover|trace --file`**: already on **`IrSource`**; **`trace_functions`** match arm fixed so **`source`** is not moved before reuse (`match &source` + explicit **`Ok::<_, anyhow::Error>`**).
- **`collect_exports_from_static_pe`** iterates **`symbol_map()`** (private **`exports`** field on **`StaticPe`**).

**Live-only (unchanged):** **`patch`**, **`mem write`**, **`mem map`**, **`debug await-hit`**, **`target`**, **`process ps`**, all **`selection *`** — semantics tied to a real process or debugger session.

### Fixed — `debug await-hit`: `DebugSetProcessKillOnExit` order

- **`DebugSetProcessKillOnExit(false)`** must run **after** successful **`DebugActiveProcess`** (per Win32 contract). Earlier order caused immediate failure (`DebugSetProcessKillOnExit(false) failed`).
- Top-level **`emit_error`** now uses **`classify_n0x_failure_message`** for selected substrings (**`DEBUG_ATTACH_DENIED_OR_BUSY`**, **`PROCESS_OPEN_DENIED`**, **`UNSUPPORTED_PROCESS_ARCH`**, …) plus optional **`hint`**.

### Added — `debug await-hit` (Win32, optional debugger add-on)

- Subcommand **`n0x debug await-hit`** (target process **x64**, host build **x86_64**): patches one byte **`0xCC`**, attaches with **`DebugActiveProcess`**, waits for **`EXCEPTION_BREAKPOINT`** at the chosen VA (**`--module` + `--addr`**, or **`--addr-rva`**) until **`--timeout-ms`**, captures **`GetThreadContext`** + **`stackQwordsFromRsp`**, restores the byte and **`DebugActiveProcessStop`**.
- Schemas **`n0x.debug.await_hit.v1`**, **`n0x.debug.hit.v1`**, NDJSON **`n0x.debug.await_hit.report.v1`** via **`--report`**. **`--instruction` / `--instruction-file`** fills **`awaitUser`** for human-in-loop prompts (`stderr` + JSON + report).
- `windows-sys` feature **`Win32_System_Kernel`** enabled for **`GetThreadContext`** / **`CONTEXT`**.

### Added — `function trace --addr-rva`

- **`--addr`** remains the absolute virtual address of the entry instruction. **`--addr-rva`** switches interpretation: **`--addr`** is a PE image RVA for the chosen **`--module`**, resolved as **`loaded_base + addr`** before `.text` slicing and CFG walk.
- Success JSON: **`root`** is always the resolved VA; **`addrRva`** is present when `--addr-rva` was used (echo of the hex you passed). NDJSON report `header` may include **`addrRva`**.

### Added — `function trace` v2 (limits, truncation JSON, NDJSON `--report`)

- **Breaking defaults** (override with flags): `max_nodes=8192`, `max_time_ms=120000`, `max_edges_total=262144`. Any limit **`0`** means unlimited (previous behaviour — **OOM/time risk** on huge graphs).
- Success payload schema **`n0x.function.trace.v2`**: `limits`, `truncated`, `truncateReason`, `stats` (`setupElapsedMs`, `walkElapsedMs`, queue/skip counters), `reportPath`, `trace[]`.
- **`--report <path>`**: append-only NDJSON (`header` → repeated `node` → `footer`), periodic flush via **`--report-flush-every`** (default 50) and **`--report-flush-ms`** (default 2000). Stdout JSON stays agent-safe; file captures full node stream within limits.
- **stderr**: explains active numeric limits; reminds `0 = unlimited`.

### Added — stderr progress for long operations (`--quiet` to suppress)

- Global flag **`--quiet`**: suppresses progress lines on stderr.
- **`function discover`** and **`function trace`** now emit `[n0x] …` milestones on stderr (module resolve, large `ReadProcessMemory`, `.text` scan progress every ~4 MiB, trace queue heartbeat ~900 ms).
- **`ir manifest`** discover path keeps stderr silent (pass-through `noop` progress) to avoid noise when listing hundreds of functions.

### Fixed — `install.ps1` PATH dedupe on older PowerShell

- Replaced `Path.TrimEndingDirectorySeparator` (not available on Windows PowerShell 5.1) with a small `TrimEnd('\\','/')` normalizer so PATH registration works everywhere.

## 2026-05-07

### Added — Decomp Structured v2 (`decomp pseudo --style structured`)
Three new structural patterns recovered on top of the v1 dominator/loop emitter,
all wired into the same `n0x.decomp.pseudo.v1` schema with the existing
`structured` flag (no contract change for AI consumers):

- **`do { … } while (cond);`** — bottom-test loops where the loop header is not
  itself a `cjmp`, but the unique back-edge source `T` inside the body is. We
  detect when one arm of `T`'s `cjmp` returns to the header (continue) and the
  other leaves the body (exit), then emit `do { body } while (cond)` with
  natural negation if the back-arm is the false-arm.
- **`for (; cond; step)`** — refinement of the existing top-test `while`. When
  there is exactly one back-edge into the header from a non-`cjmp` latch `L`,
  and the tail of `L`'s lifted body matches a counter-step heuristic
  (`x++`, `x--`, `x += k`, `x -= k`, `x = x ± k`), we promote `while (cond)`
  to `for (; cond; step)` and skip emitting the latch as a separate basic
  block.
- **Short-circuit `&&` / `||`** — fold a 2-block guard chain into a single
  condition. The inner guard `B` must be a pure `cjmp` block with exactly one
  predecessor (= the outer cjmp `A`), no side-effecting body lines, and an
  outgoing arm shared with `A` (the merge). Patterns recovered:
  - AND-true: `A(t=B, f=M), B(t=Body, f=M)` → `(condA) && (condB)`
  - AND-false: `A(t=B, f=M), B(t=M, f=Body)` → `(condA) && !(condB)`
  - OR-true: `A(t=Body, f=B), B(t=Body, f=M)` → `(condA) || (condB)`
  - OR-mirror: `A(t=Body, f=B), B(t=M, f=Body)` → `(condA) || !(condB)`

Verified against `explorer.exe sub_7FF66214146C` (973 instructions, 108 blocks,
12 loops): two genuine `do { … } while ((int64_t)rcx < (int64_t)rN);` shapes
recovered from real bottom-test loops, two `||` short-circuit folds, plus all
existing top-test `while`s preserved. `structured-partial` flag still set on
this function due to 11 irreducible regions (fallback `while(1) { … goto … }`),
which is the expected v2 behaviour — v2 is additive, never regresses.

### Added — Patch pipeline v1 (`patch dry-run|apply|undo`)
- New top-level command group: `patch`.
- `patch dry-run --addr <a> --bytes "<hex...>"`:
  - Reads current bytes without writing.
  - Returns `wouldChange`, `diffBytes`, `currentHex`, `desiredHex`.
- `patch apply --addr <a> --bytes "<hex...>"`:
  - Reads original bytes, writes desired bytes, verifies post-write.
  - Persists undo metadata as `.n0x/patches/patch-<id>.json` with:
    - `before_hex`
    - `after_hex`
    - `pid`, `address`, `size`, `status`.
- `patch undo [--id <id>] [--force]`:
  - Restores `before_hex` from either explicit id or latest patch record.
  - Safety guard: current memory must still match recorded `after_hex` unless `--force`.
  - Verifies bytes after undo and marks record `status=undone`.
- Storage is project-aware via `.n0x/` walk-up. If no local project root exists, falls back to global `%LocalAppData%/n0x/patches`.
- Verified end-to-end against `explorer.exe`: dry-run → apply (1 byte) → undo, with successful verification and persisted patch record path.

### Added — Patch pipeline v1.1 (`patch list`)
- New subcommand: `patch list [--status applied|undone] [--limit N]`.
- Reads records from `.n0x/patches/` (project-local via walk-up, global fallback when no `.n0x`).
- Returns latest-first list of `PatchRecord` items for quick audit/replay decisions.
- Verified against previously created patch record:
  - `patch list` returned the `undone` record with id/address/bytes/status.
  - `patch list --status applied` correctly returned zero items for the test case.

### Added — Patch pipeline v1.2 (`patch show`)
- New subcommand: `patch show --id <patch-id>`.
- Returns full `PatchRecord` payload (`n0x.patch.show.v1`) for an explicit record id.
- Verified against existing record `1778182458887` (status `undone`, before/after bytes intact).

### Added — IR Layer v1.10 — edge confidence on CFG successors
- Extended `IrSuccessor` with `confidence: f32` (0.0..=1.0), emitted in both:
  - `n0x.ir.v1` (`blocks[].successors[]`)
  - `n0x.ir.cfg.v1` (`cfg.blocks[].successors[]`)
- Confidence heuristic (`edge_confidence`) is kind-aware:
  - `fall` = 0.99
  - `jmp` = 0.98
  - `cjmp-true|cjmp-false` = 0.95
  - `switch` = 0.85 for indexed cases (0.75 generic fallback)
  - default = 0.80
- Updated all edge producers:
  - direct IR builder (`jmp`, `cjmp-*`, `fall`)
  - memory-side switch materialization path in `main.rs` (`resolve_switches`, `kind:\"switch\"`)
- DOT export integration: `ir dot` now annotates every edge label with `q=<confidence>` for visual triage.
- Verified on `explorer.exe` function `0x7FF6620A146C`: `ir cfg` shows per-edge confidence values and `ir dot` includes `q=...` labels on all seven edges.

### Added — IR Layer v1.9 — DOT CFG export (`ir dot`)
- New schema: `n0x.ir.dot.v1`.
- Added `ir::dot(func)` in `src/ir.rs`, producing:
  - Graph-level metadata (`address`, `end_address`, `block_count`, `edge_count`),
  - `dot` string ready for Graphviz tooling (`dot`, `xdot`, Mermaid conversion pipelines).
- DOT content:
  - One node per IR block: `B{id}`, start address, terminator kind, instruction count.
  - One directed edge per successor, labeled by successor kind (`fall`, `jmp`, `cjmp-*`, `switch`), with `#<case_index>` for switch edges.
- Added CLI subcommand: `ir dot --addr <hex>` (same build knobs as `ir build`: size, resolve, switch resolution, etc.).
- Verified on `explorer.exe` (`0x7FF6620A146C`): 6 blocks / 7 edges, including loop back-edge and branch labels in generated DOT.

### Added — IR Layer v1.8 — backward register slicing (`ir slice`)
- New IR API in `src/ir.rs`:
  - Schema constant: `n0x.ir.slice.v1`.
  - `ir::slice(func, addr, reg)` producing:
    - `seed` (nearest writer of queried register at/preceding `addr`),
    - `nodes[]` (instruction records in the slice),
    - `deps[]` (in-slice def-use edges by source address),
    - `roots[]` (nodes with no in-slice dependencies),
    - summary counts (`node_count`, `edge_count`).
- Seed selection logic is robust to register width aliases (`rax/eax/ax/al`, `rcx/ecx/cl`, `r8/r8d/r8w/r8b`, etc.) via normalization.
- Traversal is backward and recursive over existing `def_use` links already emitted by the IR builder, so the slice stays deterministic and cheap (no extra disassembly pass).
- New CLI command: `ir slice --addr <hex> --reg <name>` using the same `IrBuildArgs` surface (`--size`, `--no-auto-end`, symbol/switch options, etc.).

### Added — Per-project state & dumps (`.n0x/` "door")
- New module `src/project.rs` implementing the project-root abstraction:
  - Walk-up detection (`find_local`) from cwd to locate the nearest `.n0x/` directory, mirroring how `git` discovers `.git/`.
  - `resolve()` returns the local `.n0x/` when found, otherwise the global `%LocalAppData%/n0x/` (preserving v0 behaviour for unbound invocations).
  - `init()` bootstraps the project skeleton: `project.toml` (hand-rolled minimal TOML codec, no extra crate dep), `dumps/{ir,pseudo,hex,raw,note}/`, `ir-cache/`, and a single `.n0x/n0x.cmd` shim that hard-codes the absolute path of the running binary so the project becomes usable from anywhere inside its tree.
- **Bug fix (state collision across projects)**: `session_path()` and `selections_path()` now go through `project::resolve()` instead of unconditionally writing to global app data. Two projects no longer overwrite each other's attached PID / saved selections. Verified by initializing `.n0x/` in `D:\Steam\steamapps\common\Unrailed! 2 Back on Track\` and confirming `target attach --pid <ep>` writes `<project>\.n0x\session.json`, while a CLI invocation from `D:\` (no `.n0x/` ancestor) still resolves to the global directory (`isLocal: false`).
- New CLI surface:
  - `n0x init [--dir <p>] [--name <s>] [--core <path>]` (schema `n0x.project.init.v1`).
  - `n0x project info` (schema `n0x.project.info.v1`) — reports root, `isLocal`, all per-project storage paths, and the loaded `project.toml`.
  - `n0x dump save|list|show|rm` (schemas `n0x.dump.save.v1` / `n0x.dump.list.v1` / `n0x.dump.show.v1` / `n0x.dump.rm.v1`). Save reads stdin by default (also `--file`, `--content`), enabling AI-friendly piping like `n0x ir explain --addr X --json | n0x dump save --name hotpath --kind ir`. List walks every kind (or one via `--kind`) and reports name + path + size. Show emits text content for `ir|pseudo|hex|note`, hex preview for `raw` (capped by `--preview <N>`).
- Verified end-to-end against an Unrailed-2 project tree: init → shim invocation from project root → `target attach` (state landed in project) → `ir explain | dump save` → `dump list` → `dump show` from a deep `.n0x\dumps\ir\` subdir (walk-up still finds the right root).

### Added — Decompilation / IR Layer v1.7 — structured control reconstruction
- New `pseudo::Style` enum (`Goto` / `Structured`), wired through `pseudo::render_with` and a fresh `--style {goto,structured}` flag on `decomp pseudo` (default `structured`, with `--style goto` kept for diffing / fallback).
- Implemented full structural pass in `pseudo.rs`:
  - **Dominators** via iterative fixed-point on the forward CFG.
  - **Post-dominators** via the same algorithm on a reversed CFG augmented with a synthetic exit collecting every `ret`/`tail-call`/`tail-import`/`int`/no-successor block.
  - **Immediate (post-)dominators** picked as the unique deepest non-self dominator from each set (every other dominator must dominate the candidate).
  - **Natural loops** detected via back-edges (`(u → h)` where `h ∈ dom[u]`); per-header body computed by reverse-walking from `u` until `h` is hit. Multiple back-edges to the same header are unioned.
- Per-block re-lifting (`lift_blocks_for_structured`) decodes the function once, drops the trailing `Jcc` / `jmp` of every block (so structural emission doesn't fight the goto lifter), and captures the `cjmp` condition string per block.
- Recursive descent emitter (`emit_node` + `emit_block_body_and_terminator` + `emit_if_else` + `emit_loop` + `emit_switch`):
  - `cjmp` blocks render as `if (cond) { ... } else { ... }` with `ipdom` as the merge stop, then continue from the merge.
  - Loop headers with `cjmp` and one in-body / one out-of-body successor render as **top-test** `while (cond) { ... }`, with `negate_cond` flipping the condition when the cjmp-true arm is the loop exit.
  - Other loops fall back to `while (1) { ... }` with break/continue.
  - Back-edges to any header on `loop_stack` become `continue;`; edges to the active loop's resolved exit successor become `break;`.
  - `switch` blocks emit a labelled `switch (...) { case k: ... break; }` with `ipdom` as merge.
  - Anything else (irreducible CFG, missing ipdom, re-entry into a visited node) falls back to `goto block_N;` and bumps `structured-fallbacks` in the per-function header comment + adds the `structured-partial` flag.
- New flag set in `PseudoFunction.flags`: `structured`, `has-loop`, `structured-partial` alongside the existing `has-switch / has-indirect / has-tail / low-coverage`.
- Header comment now reports `block_count`, `loops` count and `structured-fallbacks` count for quick AI triage.

### Verified
- `cargo build` clean (only pre-existing `dead_code` allowances on `flatten` / `render`).
- `decomp pseudo --addr 0x7FF6620A146C --style structured` against `explorer.exe`: 31 instructions / 6 blocks / 1 loop, **0 fallbacks**. Output has a clean `if (rcx == 0) { ... } else { ... while (*(uint16_t*)(rcx + rax*2) != r9) { ... } }` shape with proper merge at `block_5`.
- `decomp pseudo --addr 0x7FF6620A187C --style structured`: 192 instructions / 45 blocks / 9 loops, **0 fallbacks**. Every nested `if`/`while` recovered cleanly.

### Added
- Initialized Rust CLI backend crate: `n0x-cli-rs`.
- Added global output flags:
  - `--json`
  - `--pretty`
- Implemented command groups:
  - `process ps [--filter ...]`
  - `target attach|detach|info`
  - `mem read|write`
- `mem map`
  - `disasm`
  - `xref to`
  - `xref from`
  - `module list`
- `function list|info|discover|trace`
- `selection save|list|show|xref`
- JSON error path now respects CLI flags (`--json`, `--pretty`) for runtime failures.
- Added `doctor` command for environment/readiness checks.

### Behavior Notes
- Session target PID is persisted and reused when `--pid` is omitted.
- `disasm` uses `iced-x86` and emits branch metadata.
- `xref to` finds branch instructions that target a given address.
- `xref from` inspects a specific source address and returns decoded outgoing near branch target.
- `module list` uses ToolHelp API (`CreateToolhelp32Snapshot`, `Module32FirstW`, `Module32NextW`).
- `function list|info` builds a first-level function index from PE exports of loaded modules.
- `function discover` adds heuristic discovery of non-exported function entry points in `.text`.
- `mem map` now supports filters (`--state`, `--kind`, `--protect`).
- `function trace` adds call/jmp tree traversal with depth limit.
- `xref to|from` now supports `--kind` (`call|jmp|lea`) filtering.
- `xref string` resolves string query hits and LEA-based code references.
- `selection` workflow persists ranges and can generate dedicated xref report files.

### Usage Examples
```powershell
./target/debug/n0x-cli-rs.exe process ps --filter steam --json --pretty
./target/debug/n0x-cli-rs.exe target attach --pid 13140 --json
./target/debug/n0x-cli-rs.exe module list --json --pretty
./target/debug/n0x-cli-rs.exe function list --module UnrailedGodot --limit 100 --json --pretty
./target/debug/n0x-cli-rs.exe function info --name GodotMain --module UnrailedGodot --json --pretty
./target/debug/n0x-cli-rs.exe function discover --module UnrailedGodot --limit 200 --json --pretty
./target/debug/n0x-cli-rs.exe function trace --module KERNEL32 --addr 0x7FF967F81008 --depth 2 --json --pretty
./target/debug/n0x-cli-rs.exe mem map --limit 128 --json --pretty
./target/debug/n0x-cli-rs.exe mem map --state MEM_COMMIT --kind MEM_IMAGE --protect EXECUTE --json --pretty
./target/debug/n0x-cli-rs.exe disasm --addr 0x180100000 --count 20 --json --pretty
./target/debug/n0x-cli-rs.exe xref to --addr 0x180107184 --start 0x180100000 --size 65536 --json --pretty
./target/debug/n0x-cli-rs.exe xref from --addr 0x1801072B0 --start 0x180100000 --size 65536 --json --pretty
./target/debug/n0x-cli-rs.exe xref to --addr 0x180107184 --start 0x180100000 --size 65536 --kind call --json --pretty
./target/debug/n0x-cli-rs.exe xref string --module KERNEL32 --query "CreateFileW" --limit 5 --json --pretty
./target/debug/n0x-cli-rs.exe selection save --name gs_hotpath --pid 13140 --module KERNEL32 --start 0x7FF967F81008 --end 0x7FF967F81200 --note "candidate hotpath" --json --pretty
./target/debug/n0x-cli-rs.exe selection list --json --pretty
./target/debug/n0x-cli-rs.exe selection show --name gs_hotpath --json --pretty
./target/debug/n0x-cli-rs.exe selection xref --name gs_hotpath --out gs_hotpath_xrefs.json --json --pretty
./target/debug/n0x-cli-rs.exe doctor --dll-path "D:\Steam\steamapps\common\Unrailed! 2 Back on Track\data_UnrailedGodot_windows_x86_64\UnrailedGodot.dll" --json --pretty
```

### Documentation Workflow
- After each implementation batch, update:
  - `README.md` for user-facing usage.
  - `DEVLOG.md` for chronological change tracking.


### Known Gaps
- No full TUI pane layout yet (currently command mode only).
- Discover mode is heuristic and may include false positives; symbol quality improves in later iterations.
- `xref` currently checks near-branch relationships in scanned bytes; deeper semantic xrefs need CFG/symbol index.
- `doctor` is a practical readiness check, not a full diagnostics subsystem yet.
- Decompilation/IR layer v1 implemented (see below); pseudo-C and def-use are still TODO.

## Decompilation / IR Layer v1 (`src/ir.rs`)

- New module `src/ir.rs` produces `n0x.ir.v1` JSON.
- Commands:
  - `ir build --addr <hex> [--size N] [--pid P]` -- decode bytes from `addr`, split into basic blocks, emit full IR.
  - `ir explain --addr <hex> [--size N]` -- short AI-friendly summary: instruction/block counts, returns, indirect branches, callsite list, back-edge (loop) count.
  - `selection ir --name <id> [--out <file>] [--explain]` -- IR over a saved selection range.
- CFG construction: leaders are first instruction, branch targets, instructions following branches/returns. Successors per block: `fall`, `jmp`, `cjmp-true`, `cjmp-false`.
- Instruction lifting via `iced_x86::InstructionInfoFactory`:
  - per-instruction `reads_regs` / `writes_regs` (full-register canonicalised, e.g. `eax` -> `rax`).
  - per-instruction `reads_mem` / `writes_mem` with `base/index/scale/displacement`.
- Callsites recorded with `direct`/`indirect` kind; do not split blocks (call returns to next instruction).
- Validated on running `explorer.exe`: a discovered prolog at `0x7FF73F31146C` produced 71 blocks / 246 instructions / 6 back-edges / 10 callsites.

## Decompilation / IR Layer v1.1

Significant upgrades to the IR module:

- **Function boundary auto-detection**: `ir build` / `ir explain` no longer over-decode past the actual function. Linear decoding stops once the current IP is past every known forward leader and a hard terminator (ret/int/jmp-out-of-range) is hit. Opt out via `--no-auto-end`. Default `--size` raised to 4096 (now used as a hard cap, not a target).
- **Tail-call detection**: unconditional `jmp` whose target is outside `[start_ip, end_ip)` is reclassified as `tail-call`; counted in `tail_calls`; recorded as a `kind: "tail"` callsite.
- **Win64 ABI argument hints**: every callsite carries `arg_hints` listing the last instruction in the same basic block that wrote `rcx`, `rdx`, `r8`, or `r9` (`def_addr` + `def_text`). Volatile registers are invalidated after each call.
- **Per-instruction def-use within block**: each `IrInstr.def_use` lists `{reg, def_index, def_addr}` for every register read whose latest writer lives in the same block.
- **Stack frame summary** (`IrFrameSummary`): scans first ~16 instructions for prolog patterns; reports `frame_size`, `uses_rbp`, `spilled_regs`, raw `prolog` excerpt.
- **Symbol resolution v1**: callsites whose direct target falls into the owner-module exports get `target_name` filled as `module!name`. Opt out via `--no-resolve`.
- **`ir cfg --addr`** new command: lightweight adjacency-only view (no instruction dump) for fast CFG inspection / future TUI.
- **Validation**: same `0x7FF73F31146C` entry now correctly produces 31 instructions / 6 blocks / 1 back-edge / 2 callsites with arg hints (`rcx=mov rcx,r10`, `rcx=xor rcx,rsp`) / detected `frame_size=0x78`.

## Decompilation / IR Layer v1.2 — slicing / view levels

Driven by the practical reality that an AI agent (or a UI pane) cannot read megabytes of IR at once: every IR command now lets the caller pick how much detail to materialize.

- **`--view <level>`** on `ir build` and `selection ir`:
  - `full` (default) — current behaviour, the entire `n0x.ir.v1` payload.
  - `minimal` — `n0x.ir.minimal.v1`: function meta + frame summary + block adjacency + full callsite list, **no per-instruction bodies**. Ideal for navigation / overview.
  - `cfg` — alias for `n0x.ir.cfg.v1` (lightweight adjacency).
  - `block` — `n0x.ir.block.v1`: a single block with its instructions (requires `--block <id>`).
- **`--block <id>`** filter applies to `full` view too — keeps only the chosen block but with full instruction detail.
- **`--range 0xA-0xB`** instruction/block address filter: drops blocks fully outside the range and trims instructions inside borderline blocks. Also filters callsites by their `from` address.
- Same flags piped through `selection ir`, so saved selections inherit slicing.
- Rationale documented in `CLI_FEATURES_SPEC.md`: the CLI is the database, the agent / UI is the client. JSON stays the wire format; binary cache (postcard) is reserved for future on-disk reuse, not the AI channel. BSON/protobuf were considered and rejected for the AI channel because LLMs cannot consume binary directly without a translation step that the CLI itself already provides.

## Decompilation / IR Layer v1.3 — cross-module symbols, IAT, switch hints, constant tracking

Three pieces shipped together because they share the same `build_function_ir` pass:

### Cross-module symbol resolution
- `build_symbol_map_for_addr` no longer filters to the owner module; it walks **every** loaded module's PE export table and returns a unified `absolute_addr → "Module!Name"` map.
- Effect: a direct `call rel32` from `app.exe` into a thunk that lands in `kernel32!FooBar` now resolves; the IR `target_name` is filled and `ir explain` prints the named call.

### IAT resolution for indirect call/jmp
- New helper `build_iat_map_for_addr(pid, addr)`: parses the owner module's PE imports from disk and produces `iat_slot_addr → "DLL!Name"`, where `iat_slot_addr = module_base + import.rva`.
- `BuildOptions` gained `iat: Option<&SymbolMap>`. When the dispatcher is `call qword ptr [rip+disp]` or `jmp qword ptr [rip+disp]` (rip-relative memory operand), `ir.rs` now computes the slot via `Instruction::ip_rel_memory_address()` and looks it up.
- Two new callsite kinds:
  - `import` — IAT-resolved indirect call.
  - `tail-import` — IAT-resolved indirect jmp (PLT-style import thunk). The block terminator is also relabeled `tail-import` and counts toward `tail_calls`.
- The IrInstr's `target` is set to the IAT slot address (not the runtime function pointer), so the agent sees exactly which import slot was hit.

### Switch / jump-table hints
- New top-level `IrFunction.switches: Vec<IrSwitch>` (omitted when empty). Two patterns currently detected:
  - `mem-indexed` — `jmp [rip+disp + idx*scale]` with absolute pointers in the table. Table base, index register, and scale all read directly off the dispatching instruction.
  - `reg-rel32` — MSVC `lea base,[rip+disp]; movsxd r,[base+idx*4]; add r,base; jmp r`. Best-effort backward scan of the dispatching block to recover the LEA table base and the `[base+idx*scale]` index/scale.
- Bound recovery: `scan_bound` walks back inside the same block looking for the most recent `cmp idx, imm` / `sub idx, imm` and reports the immediate as `bound`.
- Memory-side resolution (actually reading the table out of process memory and emitting the case-target list) is intentionally deferred — `ir.rs` stays a pure analyzer; a follow-up command in `main.rs` can consume `IrSwitch.table + bound + scale` and call `read_memory`.

### Constant tracking lite (per block)
- A small `consts: HashMap<String, String>` runs alongside `last_def` inside each basic block.
- Updated by `const_def(ins)`: `mov reg, imm*` (any immediate-OpKind), `xor reg, reg` (zeroing idiom), `lea reg, [rip+disp]` (rip-relative pointer constant — switch-table base, string pointer, vtable, etc.).
- Invalidated on any other write to the register; volatile registers (`rax`, `rcx`, `rdx`, `r8`, `r9`, `r10`, `r11`) are cleared on every call/icall, mirroring `last_def`.
- Surfaced in two places:
  - `DefUseEntry.const_val` — when an instruction reads a register whose constant is currently known.
  - `ArgHint.const_val` — at `Win64` ABI argument snapshot time. `ir explain` prefers `const_val` over `def_text` when rendering the call line, so `r8=0x0` shows up instead of `r8=xor r8d,r8d`.

### Schema bumps (still `n0x.ir.v1`, additive only)
- `IrCallsite.kind` may now be `import` or `tail-import`.
- `IrInstr.kind` may be `tail-import`.
- `DefUseEntry` and `ArgHint` gained optional `const_val`.
- `IrFunction` gained optional `switches: [IrSwitch]`.
- `IrSwitch { at, kind: mem-indexed|reg-rel32, table?, index_reg?, scale, bound? }`.

### Verified
- `cargo build` clean.
- Smoke-tested against `explorer.exe`: `ir explain` now renders argument constants like `r8=0x0` (constant tracker firing on `xor r8d,r8d`).

## Decompilation / IR Layer v1.4 — memory-side switch resolution

Completes the switch story started in v1.3: actual case-target recovery from the running process so the CFG no longer dead-ends at indirect dispatchers.

### Resolver
- New `resolve_switches(pid, &mut IrFunction, hard_cap, symbols)` in `main.rs`. Runs after `ir::build_function_ir` and after symbol resolution.
- For each `IrSwitch`:
  - `mem-indexed` — reads `n * 8` bytes from `table` and reinterprets each chunk as an absolute u64 pointer.
  - `reg-rel32` — reads `n * 4` bytes from `table` as `i32` offsets relative to the table base (matches MSVC layout).
  - `n` is the recovered `bound` if known, otherwise the hard cap (`--switch-cap`, default `256`).
- Sanity filter: drops zero entries (table sentinels). When `bound` is unknown the resolver refuses to follow targets that fall outside the function body unless they're known symbols — prevents slurping adjacent unrelated data.
- Successful resolution mutates the function:
  - `IrSwitch.cases` filled with `["0x...", ...]` in dispatch order.
  - The dispatching block (matched by terminator instruction address) gets `kind:"switch"` successors with `case_index: <i>` for every case, **and** its terminator is relabeled from `ijmp` to `switch`.

### Schema bumps (additive, still `n0x.ir.v1`)
- `IrSuccessor` gained optional `case_index: usize` (only present when `kind == "switch"`).
- `IrSuccessor.kind` may now be `"switch"`.
- `IrBlock.terminator` may now be `"switch"`.
- `IrSwitch` gained optional `cases: [String]` (omitted while unresolved).

### CLI flags
- `--no-switch-resolve` — opt out of memory-side resolution (e.g. when offline analysing exported symbols only).
- `--switch-cap N` — hard ceiling on case-count per switch when the bound is unknown. Default `256`.
- Available on `ir build`, `ir explain`, `ir cfg`. Always-on (cap 256) for `selection ir`.

### Verified
- `cargo build` clean.
- Detector + resolver pipeline confirmed end-to-end against `explorer.exe`. Most discovered prologs in the smoke set don't actually contain switches inside their auto-bounded body; the resolver correctly produces empty `cases` for those and leaves the CFG unchanged. When a switch IS detected, the dispatcher block receives N `kind:"switch"` successors and the AI / UI gets a fully connected CFG.

## Decompilation / IR Layer v1.5 — `ir manifest`

The "first page" of a module for AI/UI consumption: a per-function index with
quality scoring and categorical flags. The agent reads the manifest once,
prioritises by `quality`, then drills into specific entries via `ir build
--addr`.

### Command surface
- `ir manifest --module M [--source exports|discover|both] [--limit N] [--filter <substr>] [--min-quality F] [--size N] [--sort quality|address]`
- Defaults: `source=exports`, `limit=200`, `size=4096`, `sort=quality`.
- `both` deduplicates by entry-point address with `export` winning over `discover`.

### Output schema (`n0x.ir.manifest.v1`)
- Top-level: `{ schema, module, source, candidates, analyzed, skipped, returned, entries: [...] }`
- Per-entry: `{ address, name, source, instruction_count, block_count, returns, indirect_branches, tail_calls, callsites, frame_size, end_address, quality, flags[] }`.
- Manifest production reuses `ir::build_function_ir` with `auto_end=true`, `symbols=None`, `iat=None` and `--no-switch-resolve` semantics — fast path, no per-entry memory roundtrips beyond the initial bytes read. Switch detection still runs (it's free during the build pass) but resolution is skipped.

### Quality scoring (`ir::quality_score`)
Additive 0.0..=1.0 over: prolog presence (frame_size>0 OR uses_rbp OR spilled_regs), at least one return, multi-block CFG, plausible instruction count (5..=2000), at least one callsite, sane indirect-branch count, non-empty body, terminating control flow.

### Flags (`ir::flags`)
`leaf` (no callsites), `has-switch`, `has-import` (any `import`/`tail-import` callsite), `tail` (tail_calls>0), `stub` (<5 instructions), `runaway` (>2000 instructions), `no-frame`, `no-return`.

### Verified
- `cargo build` clean.
- `explorer.exe` discover sample (50 entries): all real prologs pass at q=0.85+, `--min-quality 0.85` filtered out 11/50 small fragments.
- `kernel32` exports `--filter createfile`: classic Win10/11 thunk exports (`CreateFileW`, `CreateFileA`, `CreateFile2`, `CreateFile3`, `CreateFileMappingW`) correctly tagged `[leaf, stub, no-frame, no-return]` q=0.15; real implementations (`CreateFileMappingA`, `CreateFileTransactedW`, `LZCreateFileW`, `CreateFileMappingNumaA`) correctly tagged q=1.0. The flag system instantly tells the AI which exports are forwarders vs. real bodies — exactly the disambiguation needed before calling `ir build`.

## Decompilation / IR Layer v1.6 — `decomp pseudo` (template-based v0)

The capstone of the analysis side: a readable C-like view of any function the
agent or UI is currently looking at. Lives in a new module `src/pseudo.rs` and
is reachable via the new top-level command `decomp pseudo`.

### Approach
- Re-decodes the same byte window with iced-x86, indexed by an already-built
  `IrFunction` plus its symbol/IAT maps.
- Per-instruction `lift_instruction()` dispatches on `Mnemonic` and emits one
  or more high-level lines. Operand classifier (`format_operand`,
  `format_memory`, `format_lea_target`) handles the common Win64 patterns:
  - rip-relative reads/writes resolve to `*(uintN_t*)0xADDR` or to
    `&module!symbol` when the cross-module symbol map has a hit;
  - rsp-relative accesses are tracked as named stack locals
    (`local_<offset>`) and surface in `PseudoLocal[]` with access counts;
  - calls become `name(rcx, rdx, r8, r9)`, with `name` taken from the IR
    callsite's `target_name` (covers both global-symbol and IAT routes), or
    falling back to `sub_<addr>` for direct calls and to a function-pointer
    invocation for indirect ones;
  - tail calls / tail-imports become `return name(...);  // tail-call`;
  - Jcc instructions read the most-recent `cmp`/`test` and lower into proper
    C-style conditions (signed/unsigned variants, `(reg & mask) != 0` after
    `test`, etc.);
  - `xor reg,reg` zeroing idiom is recognized.
- Anything we don't yet handle is preserved as `// asm: <original>` so the
  output never silently drops semantics.

### Output schema (`n0x.decomp.pseudo.v1`)
- `{ schema, address, end_address, signature, pseudo: [String], locals: [{ offset, access_count, size_hint }], quality, flags[], instruction_count, converted_count }`.
- `signature` is currently fixed Win64-style `void sub_X(rcx, rdx, r8, r9)`;
  proper arity recovery is future work.
- `flags`: `has-switch`, `has-indirect`, `has-tail`, `low-coverage`.

### CLI
- `decomp pseudo --addr <hex>` plus the full `IrBuildArgs` set (`--size`,
  `--no-auto-end`, `--no-resolve`, `--no-switch-resolve`, `--switch-cap`,
  `--view`, `--block`, `--range`).

### Verified
- `cargo build` clean (one informational `flatten` helper kept under
  `#[allow(dead_code)]` for future UI/file-dump use).
- `explorer.exe sub_7FF6620A146C`: 31/31 instructions converted (q=1.0), 7
  stack locals named, blocks labelled, the wide-string loop in block_2 reads
  recognisably as `rax++; if (*(uint16_t*)(rcx + rax*2) != 0) goto block_2;`,
  and the prolog-frame canary pattern (`rax = *(uint64_t*)0x...; rax ^= rsp;
  local_60 = rax;`) is intact.
- `kernel32!CreateFileMappingA`: cross-module callee names propagate
  end-to-end (`rax = KERNEL32.DLL__Basep8BitStringToDynamicUnicodeString(...)`),
  unresolved indirect calls fall back to `(*(uint64_t*)0xADDR)(...)` so the
  call-shape is still readable.

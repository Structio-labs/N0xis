---
tags: [readme, cli, rust, backend, project/n0x]
aliases: [CLI README, n0x-cli-rs README]
---

> Navigation: [[PROJECTS|Map]] · [[CLI_FEATURES_SPEC|CLI Spec]] · [[BACKEND_SPEC|Backend Spec]] · **CLI README** · [[DEVLOG]]

# n0x-cli-rs

> **ARCHIVED v0 — superseded.** This describes the abandoned first implementation and
> its framing, not the current project. See the repository root `README.md` / `CONCEPT.md`
> for what N0xis actually is today.

Rust backend CLI for N0x (JSON-capable).

> Roadmap and command surface: [[CLI_FEATURES_SPEC]]. Chronological change log: [[DEVLOG]].

## Build

```powershell
cargo build
```

## Install (release build → PATH)

`install.ps1` builds in release mode, copies the binary to a chosen install root, and registers that root on PATH. Idempotent — safe to re-run after every code change.

```powershell
# Dev install: D:\Apps\N0x\bin\n0x.exe, User PATH, no UAC.
.\install.ps1

# Custom location, still no admin:
.\install.ps1 -Dest D:\Tools\N0x

# Real release for all users (run from elevated PowerShell):
.\install.ps1 -Dest 'D:\Program Files\N0x' -Scope Machine

# Refresh PATH only, skip cargo:
.\install.ps1 -NoBuild
```

After install, open a new shell and use the binary by name from anywhere — the per-project `.n0x/` walk-up still routes session/selections/dumps into the project tree.

### Long-running commands (stderr feedback)

Some commands can take tens of seconds on large modules (for example `function discover`, `function trace`, `ir manifest` when discovering). While working, they print human-readable lines on **stderr** prefixed with `[n0x]` — **stdout stays valid JSON** when you pass `--json`, so agents can ignore stderr and users still see progress.

Optional **`debug await-hit`** blocks for up to **`--timeout-ms`** (often minutes) waiting for execution to hit one breakpoint; stderr shows the **`--instruction`** line so a human knows what to do in the target app while the debugger is armed.

Suppress those messages with the global flag **`--quiet`**.

## Live vs static (`--pid` vs `--file`)

| Area | Live (`--pid` or session) | Static (`--file <PE>`) |
|------|---------------------------|-------------------------|
| Address space | Real ASLR base + full process memory | **Preferred** PE **`ImageBase`** + on-disk sections only (**no** runtime rebasing) |
| Modules / symbols | All loaded modules, real IAT | This PE’s exports + import table only |
| **`meta.targetPid` / `data.pid`** | Numeric PID | JSON **`null`** |
| **`peFile` in `data`** | Usually omitted | Set where useful for agents |

**Read-only commands** that accept **`--file`**: `module list`, `mem read`, `disasm`, `xref to|from|string`, `function list|info|discover|trace`, `ir build|explain|cfg|dot|slice|manifest`, `decomp pseudo`.

**Live-only:** `process ps`, `target *`, `mem map`, `mem write`, `patch *`, `debug await-hit`, `selection *`.

```powershell
# Same DLL entirely offline (VAs = preferred image base + RVA)
$pe = "D:\Steam\steamapps\common\Unrailed! 2 Back on Track\data_UnrailedGodot_windows_x86_64\UnrailedGodot.dll"
./target/debug/n0x-cli-rs.exe module list --file $pe --json --pretty
./target/debug/n0x-cli-rs.exe disasm --file $pe --addr 0x180001000 --count 16 --json --pretty
./target/debug/n0x-cli-rs.exe mem read --file $pe --addr 0x180001000 --size 64 --json --pretty
./target/debug/n0x-cli-rs.exe xref string --file $pe --query "Godot" --limit 3 --json --pretty
./target/debug/n0x-cli-rs.exe function list --file $pe --limit 20 --json --pretty
./target/debug/n0x-cli-rs.exe ir manifest --file $pe --source exports --limit 30 --json --pretty
```

## Quick Start

```powershell
# list processes
./target/debug/n0x-cli-rs.exe process ps --json --pretty

# attach session target
./target/debug/n0x-cli-rs.exe target attach --pid 13140 --json
./target/debug/n0x-cli-rs.exe target info --json --pretty

# list modules of attached process
./target/debug/n0x-cli-rs.exe module list --json --pretty

# list exported function symbols (first-level function index)
./target/debug/n0x-cli-rs.exe function list --module UnrailedGodot --limit 100 --json --pretty

# inspect a single function symbol
./target/debug/n0x-cli-rs.exe function info --name GodotMain --module UnrailedGodot --json --pretty

# heuristic discovery for non-exported functions in module .text
./target/debug/n0x-cli-rs.exe function discover --module UnrailedGodot --limit 200 --json --pretty

# memory map (regions, protection, type)
./target/debug/n0x-cli-rs.exe mem map --limit 128 --json --pretty

# memory map with filters
./target/debug/n0x-cli-rs.exe mem map --state MEM_COMMIT --kind MEM_IMAGE --protect EXECUTE --json --pretty

# read memory (uses attached target when --pid omitted)
./target/debug/n0x-cli-rs.exe mem read --addr 0x7FF700000000 --size 64 --json --pretty

# write memory
./target/debug/n0x-cli-rs.exe mem write --addr 0x7FF700000000 --bytes "90 90" --json

# disassemble region
./target/debug/n0x-cli-rs.exe disasm --addr 0x7FF700000000 --count 40 --json --pretty

# find cross-references to target address in scan window
./target/debug/n0x-cli-rs.exe xref to --addr 0x180107184 --start 0x180100000 --size 65536 --json --pretty

# inspect outgoing branch xrefs from one instruction address
./target/debug/n0x-cli-rs.exe xref from --addr 0x1801072B0 --start 0x180100000 --size 65536 --json --pretty

# xrefs with kind filter
./target/debug/n0x-cli-rs.exe xref to --addr 0x180107184 --start 0x180100000 --size 65536 --kind call --json --pretty
./target/debug/n0x-cli-rs.exe xref to --addr 0x1801ABCDE --start 0x180100000 --size 65536 --kind lea --json --pretty

# search string and resolve LEA xrefs in module
./target/debug/n0x-cli-rs.exe xref string --module KERNEL32 --query "CreateFileW" --limit 5 --json --pretty

# trace function call/jmp tree (v2: safe defaults + trunc stats + optional NDJSON `--report`)
# Defaults: max_nodes=8192, max_time_ms=120000, max_edges_total=262144. Use 0 for unlimited (OOM risk).
# `--addr` is an absolute VA; use `--addr-rva` when `--addr` is a PE image RVA (resolved as module_base + addr). JSON echoes `addrRva` when that flag is set.
./target/debug/n0x-cli-rs.exe function trace --module KERNEL32 --addr 0x7FF967F81008 --depth 2 --json --pretty
./target/debug/n0x-cli-rs.exe function trace --module KERNEL32 --addr-rva --addr 0x1A2B0 --depth 2 --json --pretty

# Debugger add-on: one software breakpoint → wait → JSON registers + stack preview (`n0x.debug.await_hit.v1`; Windows x64 target; no a memory scanner attached to same PID).
# Replace RVA with something real for your exe; RVA 0x1000 below is illustrative only:
./target/release/n0x-cli-rs.exe debug await-hit --module KERNEL32.dll --addr-rva --addr 0x1000 --instruction "Trigger the code path once" --timeout-ms 180000 --stack-qwords 24 --report $env:TEMP/n0x-await-hit.ndjson --json --pretty

# Stream node records to disk (stdout JSON still compact summary + trace[] capped by limits):
./target/debug/n0x-cli-rs.exe function trace --module KERNEL32 --addr 0x7FF967F81008 --depth 2 --report D:\\temp\\kernel32_trace.ndjson --json --pretty

# save selection range for agent workflow
./target/debug/n0x-cli-rs.exe selection save --name gs_hotpath --pid 13140 --module KERNEL32 --start 0x7FF967F81008 --end 0x7FF967F81200 --note "candidate hotpath" --json --pretty
./target/debug/n0x-cli-rs.exe selection list --json --pretty
./target/debug/n0x-cli-rs.exe selection show --name gs_hotpath --json --pretty
./target/debug/n0x-cli-rs.exe selection xref --name gs_hotpath --out gs_hotpath_xrefs.json --json --pretty

# Static IR / decomp from a PE on disk (--addr = VA in the PE's *preferred* image base, see linker Optional Header ImageBase)
./target/debug/n0x-cli-rs.exe ir build --file "D:\path\YourModule.dll" --addr 0x180001000 --json --pretty
./target/debug/n0x-cli-rs.exe decomp pseudo --file "D:\path\YourModule.dll" --addr 0x180001000 --style structured --pretty

# build IR (auto-end + symbol resolve + arg hints + frame summary)
./target/debug/n0x-cli-rs.exe ir build --addr 0x7FF73F31146C --json --pretty

# light navigation view (no instruction bodies)
./target/debug/n0x-cli-rs.exe ir build --addr 0x7FF73F31146C --view minimal --pretty

# adjacency-only CFG view
./target/debug/n0x-cli-rs.exe ir cfg --addr 0x7FF73F31146C --pretty

# Graphviz DOT export for CFG visualization
./target/debug/n0x-cli-rs.exe ir dot --addr 0x7FF73F31146C --pretty

# drill into a single block
./target/debug/n0x-cli-rs.exe ir build --addr 0x7FF73F31146C --view block --block 5 --pretty

# slice by address range (filter blocks + instructions + callsites)
./target/debug/n0x-cli-rs.exe ir build --addr 0x7FF73F31146C --range 0x7FF73F3114B8-0x7FF73F3114F2 --pretty

# disable memory-side switch resolution (return only static switch hints)
./target/debug/n0x-cli-rs.exe ir build --addr 0x7FF73F31146C --no-switch-resolve --pretty

# cap case-count when switch bound is unknown
./target/debug/n0x-cli-rs.exe ir build --addr 0x7FF73F31146C --switch-cap 64 --pretty

# backward slice for one register at/near an address
./target/debug/n0x-cli-rs.exe ir slice --addr 0x7FF73F311499 --reg rax --pretty

# manifest: per-module index of recovered functions with quality + flags
./target/debug/n0x-cli-rs.exe ir manifest --module explorer.exe --source discover --limit 50 --sort quality --pretty

# manifest exports filtered by name and minimum quality (drops thunks/stubs)
./target/debug/n0x-cli-rs.exe ir manifest --module kernel32 --source exports --filter createfile --min-quality 0.5 --pretty

# pseudo-C decomp with structured control reconstruction (default): real
# `if/else`, `while`, and `do-while`-style constructs lifted from the CFG via
# dominators + post-dominators + natural-loop detection
./target/debug/n0x-cli-rs.exe decomp pseudo --addr 0x7FF73F31146C --pretty

# always-correct goto fallback (every block becomes a label, no recovery)
./target/debug/n0x-cli-rs.exe decomp pseudo --addr 0x7FF73F31146C --style goto --pretty

# AI-friendly IR summary (block/loop/callsite stats + frame)
./target/debug/n0x-cli-rs.exe ir explain --addr 0x7FF73F31146C --json --pretty

# IR over a saved selection (use --explain for short summary, --out to dump JSON file)
./target/debug/n0x-cli-rs.exe selection ir --name gs_hotpath --explain --json --pretty
./target/debug/n0x-cli-rs.exe selection ir --name gs_hotpath --view minimal --pretty
./target/debug/n0x-cli-rs.exe selection ir --name gs_hotpath --out gs_hotpath_ir.json --json

# initialize a per-project `.n0x/` directory (state stays local to this project)
./target/debug/n0x-cli-rs.exe init --name unrailed --pretty

# from inside the project, the generated shim is the only "door" you need:
.\.n0x\n0x.cmd project info --pretty
.\.n0x\n0x.cmd target attach --pid 7800

# pipe analysis results into the per-project dump store as anchors for the AI
.\.n0x\n0x.cmd ir explain --addr 0x7FF6620A146C --json | .\.n0x\n0x.cmd dump save --name hotpath --kind ir
.\.n0x\n0x.cmd dump list --pretty
.\.n0x\n0x.cmd dump show --name hotpath --kind ir --pretty

# safe patch workflow: inspect -> apply -> undo
./target/debug/n0x-cli-rs.exe patch dry-run --addr 0x7FF6620A146C --bytes "90" --pretty
./target/debug/n0x-cli-rs.exe patch apply --addr 0x7FF6620A146C --bytes "90" --pretty
./target/debug/n0x-cli-rs.exe patch list --pretty
./target/debug/n0x-cli-rs.exe patch list --status applied --pretty
./target/debug/n0x-cli-rs.exe patch show --id 1778182458887 --pretty
./target/debug/n0x-cli-rs.exe patch undo --pretty
# or undo a specific record:
./target/debug/n0x-cli-rs.exe patch undo --id 1778182458887 --pretty

# health checks (optionally include a known DLL path)
./target/debug/n0x-cli-rs.exe doctor --dll-path "D:\Steam\steamapps\common\Unrailed! 2 Back on Track\data_UnrailedGodot_windows_x86_64\UnrailedGodot.dll" --json --pretty
```

## Implemented MVP Commands

- `process ps`
- `module list` (live: **`--pid`** / session; static: **`--file`** → one synthetic module + **`peFile`**)
- `function list|info|discover|trace` (**`--file`** for export list / discover / trace on disk; live trace still needs **`--module`**)
- `debug await-hit` (**Windows x64**, optional workflow; **`n0x.debug.await_hit.v1`** / **`n0x.debug.hit.v1`**)
- `target attach|detach|info`
- `mem map|read|write` (**`mem read --file`** reads from the PE image at a VA inside a section; **`mem map` / `mem write`** remain live-only)
- `disasm` (**`--file`** or **`--pid`**)
- `xref to|from|string` (live **`xref string`** needs **`--module`**; static **`--file`** builds a **`SizeOfImage`** buffer for scanning)
- `selection save|list|show|xref|ir` (**live only** — selections store a **`pid`** + absolute VAs; use **`ir build --file --range …`** for static anchors)
- `ir build|explain|cfg|dot|slice|manifest` (`dot` schema: `n0x.ir.dot.v1`, `slice` schema: `n0x.ir.slice.v1`). Every CFG edge now carries `confidence` (0.0..=1.0) in `successors[]`; `ir dot --addr <a>` also prints it in edge labels as `q=...` for quick visual triage. `ir slice --addr <a> --reg <r>` computes a backward register slice in the recovered function: nearest writer seed for `<r>` at/preceding `<a>`, then recursive traversal over instruction `def_use` links (`nodes[]`, `deps[]`, `roots[]`, `seed`). **`IrBuildArgs`** and matching read-only peers accept **`--file <path.pe>`** so analysis runs offline at the PE **preferred image-base VA** (mutually exclusive with **`--pid`**). **`ir manifest --file`** indexes one PE (**`--module`** optional label); live **`ir manifest`** still requires **`--module`**. `ir manifest` produces the n0x.ir.manifest.v1 per-module index with function-level `quality` (0..=1) and categorical `flags` (`leaf | has-switch | has-import | tail | stub | runaway | no-frame | no-return`) — read this first to prioritise functions before drilling in with `ir build --addr` (live or `--file`).
- `decomp pseudo` — pseudo-C lifter (n0x.decomp.pseudo.v1). Default `--style structured` runs a full structural pass over the CFG (dominators, post-dominators via reversed CFG with synthetic exit, natural-loop detection via back-edges, recursive descent emitter) and produces real `if (cond) { ... } else { ... }` (merge at ipdom), top-test `while (cond) { ... }` (with cheap structural negation when the cjmp-true arm is the loop exit), bottom-test `do { ... } while (cond);` (back-edge from a cjmp tail when the header itself is non-cjmp), `for (; cond; step)` recovery (top-test loop with a single non-cjmp latch whose body tail matches a counter-step like `x++ / x-- / x += k`), short-circuit `&&` / `||` fold of 2-block cjmp chains where the inner guard is a pure single-predecessor cjmp sharing a merge arm with the outer cjmp (covers AND-true, AND-false, OR-true, OR-mirror), and a generic `while (1) { ... break; ... }` fallback for irreducible / multi-exit loops. Back-edges to enclosing headers become `continue;`, edges to the active loop's resolved exit become `break;`. Anything unclassified falls back to a labelled `goto block_N;` and increments `structured-fallbacks` (visible in the function header comment + as the `structured-partial` flag). `--style goto` keeps the always-correct labelled form for diffing. Named stack locals, cross-module call names, lifted Jcc conditions. Reuses every IR enrichment (symbols / IAT / frame / arg hints / constant tracker / switch resolution). Anything unhandled by the v0 templates falls through as a `// asm: ...` line so semantics are never silently dropped. Symbol resolution covers **all loaded modules** for direct call/jmp targets and the owner module's **IAT** for `call/jmp [rip+disp]`. Block-local **constant tracker** populates `const_val` on def-use entries and arg hints for `mov reg,imm` / `xor reg,reg` / `lea reg,[rip+disp]`. Detected `switch` dispatches are surfaced as `IrFunction.switches[]` with table base, index register, scale, bound, and (after memory-side resolution) the actual `cases[]` of absolute case-target addresses. Resolved cases are also attached as `kind:"switch"` successors with `case_index` on the dispatching block, so the CFG no longer dead-ends at indirect dispatchers. Opt out via `--no-switch-resolve`; cap unknown-bound resolution via `--switch-cap N` (default 256).
- `init` — bootstrap a `.n0x/` project directory (one shim, walk-up state discovery, `project.toml`, `dumps/` skeleton).
- `project info` — show resolved project root, `isLocal` flag, all per-project storage paths, and parsed `project.toml`.
- `dump save|list|show|rm` — persistent dump store at `.n0x/dumps/<kind>/<name>.<ext>`. Kinds: `ir | pseudo | hex | raw | note`. `dump save` defaults to stdin so any other CLI command's JSON output can be piped straight into a named anchor.
- `patch dry-run|apply|list|show|undo` — safe memory patch workflow. `dry-run` reports current vs desired bytes and diff size without writing. `apply` writes bytes and creates undo record at `.n0x/patches/patch-<id>.json` (`before_hex` + `after_hex`). `list` returns recent records (latest first), optional `--status applied|undone` filter. `show` returns one record by id (full metadata + before/after bytes). `undo` restores either explicit `--id` or latest record, with guard that current bytes still match recorded `after_hex` unless `--force`.
- `doctor`

## Notes

- Session/selections/dumps are project-local when `.n0x/` exists in the cwd ancestry (walk-up lookup), otherwise they fall back to `%LocalAppData%/n0x/`.
- JSON output contract follows `{ ok, data, meta }` for successful calls and `{ ok, error }` for failures.
- Current disassembly/xref implementation assumes x64 decoding.

## Ongoing Documentation

- `DEVLOG.md` — chronological log of what was added.


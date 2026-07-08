# N0x — Preserved CLI Command Surface (from v0)

Snapshot of the **v0 CLI** captured on 2026-07-08 before the rewrite. This is the
**compatibility contract**: the new implementation must keep these verbs, flags
and the JSON envelope so existing agent workflows and the global `n0x` shim keep
working. New commands may be *added*; existing ones should not silently change
shape.

> Source of truth for behavior: the archived binary in
> [`../archive/n0x-cli-rs-v0/`](../archive/n0x-cli-rs-v0/). This file is the
> human/agent-facing index.

## Global conventions

- Binary name: `n0x` (installed globally, per-project shim `n0x.cmd`).
- Global flags (available on every command):
  - `--json` — strict JSON-only stdout.
  - `--pretty` — pretty-printed JSON.
  - `--quiet` — suppress `[n0x]` stderr progress (stdout stays machine-parseable).
- Output envelope: every command emits `{ ok, data, meta }` on success or
  `{ ok: false, error }` on failure. In-progress feedback → stderr, prefixed `[n0x]`.
- Source selection (analysis commands): `--pid <PID>` (live process) **XOR**
  `--file <PATH>` (PE on disk). When omitted, the active attached session/PID is
  resolved from the `.n0x/` project. `--file` addresses use the PE's *preferred*
  image base; live/ASLR modules require `--pid`.

## Command tree

### `process`
- `process ps [--filter <substr>]` — list processes.

### `module`
- `module list [--pid <PID>] [--file <PATH>]` — list loaded modules (live) or a
  single PE (`--file`).

### `function`
- `function list [--pid|--file] [--module <m>] [--query <q>] [--limit 200]` — exports/known functions.
- `function info --name <NAME> [--pid|--file] [--module <m>]` — resolve a function by name.
- `function discover [--pid|--file] [--module <m>] [--limit 200]` — heuristic prolog-scan function discovery.
- `function trace --addr <hex> [--pid|--file] [--module <m>] [--addr-rva]`
  `[--depth 2] [--max-nodes 8192] [--max-time-ms 120000] [--max-edges-total 262144]`
  `[--report <PATH>] [--report-flush-every 50] [--report-flush-ms 2000]`
  — CFG/call trace walk with budgets and streaming report.

### `selection` — named address ranges persisted in `.n0x/`
- `selection save --name <N> --module <m> --start <hex> --end <hex> [--pid] [--note <s>]`
- `selection list`
- `selection show --name <N>`
- `selection xref --name <N> [--out <PATH>]`
- `selection ir --name <N> [--out <PATH>] [--explain] [--view full|minimal|cfg|block] [--block <id>]`

### `target` — live attach session (persisted in `.n0x/`)
- `target attach --pid <PID>`
- `target detach`
- `target info`

### `mem`
- `mem read --addr <hex> --size <N> [--pid|--file]`
- `mem write --addr <hex> --bytes "90 90 C3" [--pid]`
- `mem map [--pid] [--limit 256] [--state <s>] [--kind <t>] [--protect <p>]` — VirtualQueryEx region map.

### `patch` — memory patching with persisted undo under `.n0x/patches/`
- `patch dry-run --addr <hex> --bytes "<hex>" [--pid]`
- `patch apply   --addr <hex> --bytes "<hex>" [--pid]`
- `patch list [--status applied|undone] [--limit 100]`
- `patch show --id <id>`
- `patch undo [--id <id>] [--pid] [--force]`

### `disasm`
- `disasm --addr <hex> [--count 20] [--pid|--file]` — linear disassembly.

### `xref`
- `xref to     --addr <hex> --start <hex> --size <N> [--pid|--file] [--kind <k>]` — who references `--addr`.
- `xref from   --addr <hex> --start <hex> --size <N> [--pid|--file] [--kind <k>]` — what `--addr` references.
- `xref string --query <q> [--module <m>] [--pid|--file] [--limit 5]` — string search + refs.

### `doctor`
- `doctor [--pid <PID>] [--dll-path <PATH>]` — environment/readiness check.

### `ir` — intermediate representation
Shared build flags on `build|explain|cfg|dot|slice`:
`[--pid|--file] --addr <hex> [--size 4096] [--no-auto-end] [--no-resolve]`
`[--no-switch-resolve] [--switch-cap 256] [--view full|minimal|cfg|block] [--block <id>] [--range 0xSTART-0xEND]`
- `ir build`   — full IR (`n0x.ir.v1`): blocks, def-use, callsites, frame, switches.
- `ir explain` — human-readable summary (`n0x.ir.explain.v1`).
- `ir cfg`     — CFG only (`n0x.ir.cfg.v1`).
- `ir dot`     — Graphviz DOT (`n0x.ir.dot.v1`).
- `ir slice --reg <REG>` — backward register slice (`n0x.ir.slice.v1`).
- `ir manifest [--pid|--file] [--module <m>] [--source exports|discover|both]`
  `[--limit 200] [--filter <s>] [--min-quality <f>] [--size 4096] [--sort quality|address]`
  — per-function index with quality scoring (`n0x.ir.manifest.v1`).

### `decomp`
- `decomp pseudo --addr <hex> [build flags…] [--style goto|structured]`
  — pseudo-C (`n0x.decomp.pseudo.v1`). **This is the surface the rewrite most
  extends**: add an SSA/optimized style (see ROADMAP Phase 3).

### Project / storage
- `init [--dir <d>] [--name <n>] [--core <path>]` — create `.n0x/` project (config, `n0x.cmd` shim, `dumps/`).
- `project info` — resolved project root / config / storage paths.
- `dump save --name <N> --kind ir|pseudo|hex|raw|note [--file|--content|stdin] [--force]`
- `dump list [--kind <k>]`
- `dump show --name <N> [--kind <k>] [--preview 256]`
- `dump rm --name <N> [--kind <k>]`
- `guide` — built-in quick-reference.

### `debug` (opt-in Win32 debugger workflow)
- `debug await-hit --module <m> --addr <hex> [--pid] [--addr-rva] [--instruction <s>|--instruction-file <p>]`
  `[--timeout-ms 120000] [--stack-qwords 32] [--report <PATH>]`
  — set an `int3`, block until `EXCEPTION_BREAKPOINT`, emit a structured hit report, restore + detach.

## JSON schemas emitted by v0 (to preserve / version forward)

| Schema id | Produced by |
|---|---|
| `n0x.ir.v1` | `ir build` |
| `n0x.ir.cfg.v1` | `ir cfg` |
| `n0x.ir.dot.v1` | `ir dot` |
| `n0x.ir.slice.v1` | `ir slice` |
| `n0x.ir.manifest.v1` | `ir manifest` |
| `n0x.ir.explain.v1` | `ir explain` |
| `n0x.decomp.pseudo.v1` | `decomp pseudo` |
| `n0x.debug.await_hit.v1` | `debug await-hit` |

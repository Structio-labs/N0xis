---
tags: [moc, index, project/n0xis]
aliases: [Index, Project Map, Hub, MOC]
---

# N0xis — Project Map

Central navigation hub (map-of-content) for **N0xis** — an agent-native reverse-engineering + live-memory toolkit. Open this folder (`D:\Projects\N0x\`) as an **Obsidian vault** for backlinks, the graph view, and bidirectional navigation across every document below.

N0xis (pronounced "Noxis") ships one binary invocable as either **`n0xis`** or **`n0x`**. It is an RE / dynamic-analysis toolkit — static analysis + first-class live memory + provenance — not a cheat/trainer maker. Status: **alpha**, AGPL-3.0-only, public at `github.com/LargoScript/n0xis`.

> Navigation: [[README]] · [[CONCEPT]] · [[ROADMAP]] · [[CLI_COMMANDS|CLI reference]] · [[KILLER_FEATURES]] · [[PRODUCT_POLICY]] · [[COMMUNITY_ROADMAP]] · [[docs/n0xhud/CONCEPT|N0xHUD concept]] · [[docs/n0xhud/ROADMAP|N0xHUD roadmap]] · [[CONTRIBUTING]]

---

## High-level architecture

Three frontends drive **one** analysis engine. Everything goes in and comes back as the same JSON envelope, so a human at a terminal, an MCP client, and the companion window all speak to identical code paths.

### Frontends (3)
- **`n0xis` (alias `n0x`)** — the CLI. Thin clap frontend. See [[CLI_COMMANDS]].
- **`n0xis-mcp`** — MCP server over stdio; same `{ok,data,meta}` envelope, tool names mirror CLI verbs; plus `capability_list` / `capability_run`, through which every registered capability is reachable without a per-command tool.
- **`n0xis-hud` (N0xHUD)** — a config-driven, always-on-top companion window over the same crates. Runtime instrumentation / live-memory analysis with an on-screen face — **not** an in-game overlay, **not** a trainer. See [[docs/n0xhud/CONCEPT|N0xHUD concept]].

### The pass pipeline (source → arch → core → project)
```
source adapter  →  arch decode  →  core analysis passes  →  project (.n0x/) persistence
  (I/O + OS)       (ISA trait)      (pure, no I/O, no OS)      names/types/patches/tables
                         └──────── n0xis-pipeline wires all three + content-addressed caching ────────┘
```
`cargo test -p n0xis-core` links **zero** Windows/OS crates — the boundary law that keeps analysis pure and portable.

### The source-adapter seam
Analysis commands take **exactly one** target source, or fall back to the `.n0x/` session default:
`--pid` (live process) · `--file` (static PE) · `--snapshot <name>` (reloaded capture) · `--remote-cmd "<argv>"` (SSH/Tailscale remote agent) · `--bytes "<hex>"` (inline, some commands). Same passes run against any of them.

### The 13 crates (Cargo workspace, members = `crates/*`)
| Crate | Role | Depended on by core? |
|---|---|---|
| `n0xis-contracts` | All wire schemas (`n0xis.*.vN`) + shared value types (`Va`, `Symbol`, `Reg`). Single source of truth. | — |
| `n0xis-arch` | ISA abstraction (`trait Arch`) + **X64** (iced-x86, full pipeline) + **Arm64** (disarm64; CFG/discover/xref/goto+structured decomp). SSA-opt & flag-precise conditions are x64-only. | — |
| `n0xis-sources` | Input adapters: `LiveProcess` (Win32), `StaticPe` (goblin), `Snapshot`, `RemoteAgent`, plus `debug` (sw/hw breakpoints, unwind) and `input` (injection probe). | — |
| `n0xis-core` | Pure analysis passes — CFG/SSA/opt/DCE/typeinfer/structure/render/xref/slice/scan/aob/pointer/dissect/valueset/deobfuscate/diff/provenance/gamegrep/constident/bindings/sigvalidate/structural/ui_locate. **No I/O, no OS.** | — |
| `n0xis-project` | `.n0x/` analysis DB: names/types/comments (annotate), selections, patches, dumps, `.n0xt` tables, session, ir-cache. | — |
| `n0xis-pipeline` | Wires source + arch + project into core; content-addressed artifact caching. | — |
| `n0xis-frontend` | The shared frontend seam every frontend goes through: source resolution (`--pid`/`--file`/`--snapshot`/`--remote-cmd`/`--bytes` + the `.n0x/` session default), ISA selection, argument parsing, and the **capability registry** (built-in analysis and external plugins register through one `Plugin` trait; `build_registry()` is the single composition point). | — |
| `n0xis-cli` | Clap frontend (binary `n0xis`, alias `n0x`). | — |
| `n0xis-mcp` | MCP server frontend (binary `n0xis-mcp`). | — |
| `n0xis-hud` | N0xHUD companion-window frontend (binary `n0xis-hud`). | — |
| `n0xis-bitsquid` | Bitsquid/Stingray bundle format adapter. | **No** |
| `n0xis-lua` | Offline LuaJIT 2.0 bytecode disassembler/patcher. | **No** |
| `n0xis-luajit` | Live LuaJIT VM introspection (GCstr discovery in a running process). | **No** |

### Status at a glance (verify against [[ROADMAP]] before quoting)
- **Phases 1–7: done.** Phase 3 optimizing SSA decompiler is the main; 4b live memory (scanner-class); 4c provenance (principal); 5 MCP; 6 persistence/caching/snapshot/remote/perf; 7 ARM64 + value-set + deobfuscation + diffing.
- ⚠️ **ARM64 caveat (standing):** implemented and self-tested, **not** verified to x64's standard. Say "implemented and self-tested," never "working/verified."
- **Phase 8 (spec-first method tooling):** 6/7 named commands landed + hex-everywhere audit closed (merged into `main`). ⬜ **Region caching as a built-in scan option is the single open item.**
- **Phase 9 (UI-layer localization):** `ui locate`, the structural-predicate scan primitive, and `debug watch --when` are **implemented in the working tree, uncommitted, and pending live-target validation.** Unit-tested on synthetic buffers; the decisive live appearance-correlation test has **not** run. Say "implemented, pending live validation," never "verified." See [[docs/PHASE9_UI_LOCATE_BRIEF|Phase 9 brief]].

The **installed** binary reports **77 leaf commands** via `n0x guide` (auto-generated from the clap tree, so it never drifts); the **working tree** is at **87** — Phases 9/11 plus `capability list` / `capability run` (counted as `"path"` entries in `n0x guide --brief`).

Of those 87, **41 are backed by the capability registry** (`n0xis-frontend::registry`), where the CLI and MCP handlers are argument mapping over one shared implementation; the rest still carry a per-frontend handler each. See the ROADMAP's "Engineering hardening" section for the migration state.

---

## Document index

| Document | Role | Audience |
|---|---|---|
| [MAP.md](MAP.md) — [[MAP]] | This hub — map of content, architecture summary, navigation | everyone |
| [README.md](README.md) — [[README]] | Project front door: what it is, install/build, quick start | everyone |
| [CONCEPT.md](CONCEPT.md) — [[CONCEPT]] | Vision & design philosophy (agent-native RE, positioning, GUI stance) | dev, reviewer, agent |
| [ROADMAP.md](ROADMAP.md) — [[ROADMAP]] | Phase-by-phase plan + live status (legend 🎯✅⏳⬜⚠️) | dev, agent |
| [docs/CLI_COMMANDS.md](docs/CLI_COMMANDS.md) — [[CLI_COMMANDS]] | **Current** command reference — every leaf command, args, schemas | agent, dev, user |
| [docs/KILLER_FEATURES.md](docs/KILLER_FEATURES.md) — [[KILLER_FEATURES]] | What N0xis does that any other reverse-engineering tool/CE don't (honest, fact-checked) | evaluator, agent |
| [docs/PRODUCT_POLICY.md](docs/PRODUCT_POLICY.md) — [[PRODUCT_POLICY]] | Positioning, scope, and ethics — RE/dynamic-analysis, single-player | contributor, user |
| [docs/COMMUNITY_ROADMAP.md](docs/COMMUNITY_ROADMAP.md) — [[COMMUNITY_ROADMAP]] | Community/backlog items and how contributions slot in | contributor |
| [docs/PHASE9_UI_LOCATE_BRIEF.md](docs/PHASE9_UI_LOCATE_BRIEF.md) — [[docs/PHASE9_UI_LOCATE_BRIEF\|Phase 9 brief]] | Phase 9 design + definition-of-done (incl. the live §9.3 test still owed) | dev, agent |
| [docs/n0xhud/CONCEPT.md](docs/n0xhud/CONCEPT.md) — [[docs/n0xhud/CONCEPT\|N0xHUD concept]] | N0xHUD design & rationale (companion window, not overlay) | dev, agent |
| [docs/n0xhud/ROADMAP.md](docs/n0xhud/ROADMAP.md) — [[docs/n0xhud/ROADMAP\|N0xHUD roadmap]] | N0xHUD phase plan + landed-vs-open status | dev, agent |
| [CONTRIBUTING.md](CONTRIBUTING.md) — [[CONTRIBUTING]] | How to build, test, and contribute; CLA note for outside PRs | contributor |

> Archived v0 documentation lives under [`archive/`](archive/) (`archive/README.md`, `archive/docs-v0/`, `archive/n0x-cli-rs-v0/`). It describes the superseded React/Tauri frontend and the old `n0x-cli-rs` crate — **superseded, do not cite it.** The current command reference is [[CLI_COMMANDS]] (`docs/CLI_COMMANDS.md`), which was renamed from the old `CLI_COMMANDS_v0.md` and is now the live reference, not a frozen snapshot.

---

## By topic

### Static analysis & the decompiler
The Phase 3 optimizing SSA decompiler is the main. Build IR, decompile to pseudo-C, slice, xref, discover/trace functions, diff.
- Commands: `ir {build,explain,dot,slice,manifest,value-set,deobfuscate}`, `decomp pseudo --style goto|structured|ssa`, `function {discover,trace}`, `xref {to,from,string}`, `diff functions`. Full detail in [[CLI_COMMANDS]].
- ISA support: x64 (full) and ARM64 (⚠️ implemented and self-tested; SSA-opt & flag-precise conditions x64-only) — [[ROADMAP]] Phase 7.
- Where it lives: `n0xis-arch` (decode) + `n0xis-core` (passes).

### Dynamic memory / live analysis (a memory scanner class)
Value scanning with true snapshot-backed narrowing, AOB, pointer paths, region dissect, patches with an undo journal, tables, breakpoints/watchpoints.
- Commands: `scan {value,filter,aob,pointer-path,dissect}`, `mem {read,write,map}`, `patch {dry-run,apply,list,show,undo,detour}`, `table {add,list,show,rm,freeze}`, `debug {await-hit,watch,attach}`. See [[CLI_COMMANDS]].
- ⬜ Region caching as a built-in scan option is the one open Phase 8 item ([[ROADMAP]]).

### Provenance (Phase 4c principal)
Watchpoint × decompiler: arm a hardware watchpoint on a value, wait for one real hit, and explain the exact decompiled statement responsible — with a true cross-process x64 caller chain from `.pdata`/`.xdata`.
- Command: `provenance trace` (also exposed over MCP). See [[CLI_COMMANDS]] and [[KILLER_FEATURES]].

### Game-engine assets & LuaJIT
Bitsquid/Stingray bundles + offline and live LuaJIT introspection.
- Commands: `bundle {list,extract,repack}`, `lua {disasm,patch,strings,table,combo,seedscan}`. See [[CLI_COMMANDS]].
- Crates: `n0xis-bitsquid`, `n0xis-lua` (offline), `n0xis-luajit` (live GCstr discovery) — none depended on by core.

### Spec-first method tooling (Phase 8)
Turning a repeatable RE methodology's recipes into commands: `game grep`, `locate by-transition`, `input probe`, `const identify`, `bindings list`, `sig validate`. 6/7 landed and merged into `main`. See [[CLI_COMMANDS]].

### UI-layer localization (Phase 9 — working tree)
Hit-test a live target's own retained scene-graph AABBs from outside — no graphics-API hooking, no frame capture. `ui locate --rect` (CLI + MCP), built on the internal `scan structural` primitive (`n0xis.scan.structural.v1` — a core primitive, **not** a runnable CLI subcommand), plus the conditional HW watchpoint `debug watch --when`. ⚠️ Implemented, unit-tested, **uncommitted, pending live validation.** See [[docs/PHASE9_UI_LOCATE_BRIEF|Phase 9 brief]].

### N0xHUD (companion window)
The interactive, on-screen face of the same engine: a config-driven always-on-top `eframe`/`egui` window (`.n0x/hud.toml`), a process-watcher auto-apply loop, global hotkeys via a low-level keyboard hook, write & freeze, Interception kernel-driver actuation, stratagem/sequence macros, and a process-based plugin protocol (`on_launch`/`toggle_on`/`toggle_off`/`poll` JSON over a spawned plugin's stdio) for game-specific automation — the engine itself stays game-agnostic; all per-game logic (e.g. reading a generator seed live and recomputing/actuating a deterministic sequence) lives in an external plugin process, not compiled in. Framed as runtime instrumentation, never a trainer. See [[docs/n0xhud/CONCEPT|N0xHUD concept]] and [[docs/n0xhud/ROADMAP|N0xHUD roadmap]].

### The agent contract — `{ok,data,meta}`
Every command emits exactly one JSON object: `{"ok":true,"data":{…},"meta":{"schema":"n0xis.*.vN",…}}` on success, `{"ok":false,"error":{…}}` on failure. `--pretty` indents; non-zero exit on `ok:false`; stderr progress is prefixed `[n0x]` (safe to ignore in scripts). New v1 schemas are `n0xis.*.vN`; a few ported shapes keep the archived `n0x.*.v1` id for back-compat. `meta.schema` names the payload shape and is defined once in `n0xis-contracts`. The same envelope is what the MCP server returns as a string. See [[CLI_COMMANDS]] (envelope + schema map) and [[CONCEPT]].

---

## Working modes

| Goal | Read first | Then |
|---|---|---|
| First run — understand & try it | [[README]] | [[CLI_COMMANDS]] → run `n0x guide` |
| Continue implementation | [[ROADMAP]] | [[CLI_COMMANDS]] → the relevant crate under `crates/` |
| Drive it from an agent (CLI or MCP) | [[CLI_COMMANDS]] (envelope + schemas) | `n0x guide` (auto-generated catalog) → [[KILLER_FEATURES]] |
| Onboard into the project | [[MAP]] (this file) | [[CONCEPT]] → [[ROADMAP]] → [[CONTRIBUTING]] |
| Contribute / open a PR | [[CONTRIBUTING]] | [[PRODUCT_POLICY]] → [[COMMUNITY_ROADMAP]] |
| Work on N0xHUD | [[docs/n0xhud/CONCEPT\|N0xHUD concept]] | [[docs/n0xhud/ROADMAP\|N0xHUD roadmap]] → `crates/n0xis-hud/src/` |

---

## Conventions for this vault

- The auto-generated `n0x guide` (from the live clap tree) is the source of truth for the command catalog — [[CLI_COMMANDS]] mirrors it in prose but the binary never drifts.
- Keep **"implemented and self-tested"** strictly distinct from **"verified."** ARM64 and Phase 9 `ui locate` are the standing examples: self-tested, not live-verified.
- Roadmap legend everywhere: 🎯 milestone · ✅ done · ⏳ in progress · ⬜ todo · ⚠️ caveat.
- This hub only references — it never duplicates content. If a fact lives in two places, one of them is wrong.

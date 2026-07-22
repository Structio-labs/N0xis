# N0xis — Concept & Architecture (v1)

> Status: **alpha** — implemented through ROADMAP Phase 9 (Phases 1–8 committed to
> `main`; Phase 9 lives in the working tree). This is the design/architecture doc,
> but no longer a greenfield plan: the shape described below is **built, not merely
> proposed** — verify any specific "done" against the code and [`ROADMAP.md`](ROADMAP.md).
> v0 is archived in [`archive/`](archive/).
> Companion docs: [`ROADMAP.md`](ROADMAP.md) · [`docs/CLI_COMMANDS.md`](docs/CLI_COMMANDS.md).
> Created 2026-07-08.

---

## 1. What N0xis is

N0xis is an **reverse-engineering and live-memory toolkit** for
x64 Windows (primary target: game binaries), driven entirely through a stable CLI
+ MCP contract. It analyzes both **files on disk** (static PE) and **live
processes** (runtime memory) through one and the same analysis pipeline.

It is a **synthesis of two worlds that today live apart**:

1. The **other tools** — another tool / another tool-a source-level decompiler / another tool: static analysis,
   optimizing decompiler, types, xrefs.
2. **a memory scanner and its kin** — full *dynamic* memory work: value scanning,
   pointer-path scanning, AOB scanning, struct dissection, code injection,
   freeze/write, hooks, and a persistent *cheat table*.

No other does both well: CE finds runtime *values* but can't explain the
*code*; the RE tools explain code but treat the running process as a second-class
afterthought. N0xis fuses them, and does it **contract-first (CLI + MCP first)** —
a GUI is **deferred, not forbidden** (see §2).

> **The best reverse-engineering *and live-memory* backend for autonomous agents**
> — deterministic, inspectable, contract-first, equally at home on a live process
> and a static file, aiming to match every other feature and beat it on the
> static⇄dynamic seam.

## 2. The one-line thesis (and why it beats other tools)

What exists elsewhere are **GUI-first**; scripting/automation is bolted on top of an
interactive core. Their decompiler microcode is a black box: you see the final C,
not the reasoning. N0xis inverts this:

- **Contract-first (GUI deferred, not forbidden).** Every capability is a CLI verb
  + MCP tool that returns a versioned JSON artifact (`ok/data/meta`). A human reads
  it; an agent parses it. There is no hidden interactive state. A GUI is **not now,
  but not never** — the earlier "GUI-never" absolutism is retired. If a GUI lands it
  is a *thin visualization layer over these same `ok/data/meta` artifacts*, never a
  rewrite of the CLI/MCP core. **N0xHUD already exists as a third frontend of exactly
  that shape** — a config-driven always-on-top companion window over the same crates
  (see §4) — proving the contract-first core carries a windowed surface without ever
  becoming GUI-first.
- **Explainable decompilation.** Every analysis pass emits an *inspectable*
  artifact: raw IR, SSA form, the propagation/DCE delta, recovered types, the
  structured control tree. An agent can ask "why is this condition `x > 4`?" or
  "what did DCE remove?" — impossible to ask a source-level decompiler.
- **One pipeline, live + static.** Runtime and file analysis differ only in which
  *adapter* supplies bytes/symbols. The SSA→opt→types→render pipeline is byte-for-byte
  the same. (v0 already proved this with `IrSource`; v1 makes it a first-class seam.)
- **Deterministic & reproducible.** Same input → same output, no ML nondeterminism
  in the core. Agents can diff runs and trust anchors.

### 2.1 The north-star — one model, many projections

A sharper way to state all of the above, and the direction the architecture is
converging on: **N0xis is not "a decompiler." It is a deterministic model of a
binary program — of which decompilation, provenance, live-memory analysis,
watchpoints, and agent workflows are all *projections of one graph*, differing
only in which view you ask for, not in which tool you reach for.**

Be precise about what is true *today* versus where this points, because the
distinction is load-bearing (project law §6 — never overclaim):

- **True now.** The unification is real at the level of **one analysis core + one
  versioned contract + one source-adapter seam.** Runtime vs. static is a choice of
  adapter, not an `if` in the analysis; `provenance` already projects a *live*
  watchpoint hit back onto the *static* decompiler pipeline (`VA → module+RVA →
  function → decompiled block`). Those are genuinely different views of the same
  process.
- **Not yet.** There is no single *materialized* program-model object that every
  capability reads and mutates. Artifacts are **recomputed projections from the
  source bytes**, content-addressed and cached — not slices of a resident graph.
  The persistent truth today (`.n0x/`: names, types, comments, `.n0xt` tables,
  provenance links) is a thin layer, not a full model.

The direction — and why the analysis-depth work in [`ROADMAP.md`](ROADMAP.md)
(Phase 10: Memory SSA, interprocedural summaries) matters *beyond* decompiler
prettiness — is to **let `.n0x/` accumulate a derived, invalidatable summary layer
that *is* the model**, while keeping every artifact content-addressed and
recomputable. That is the deliberate fork away from other tools: another tool / another tool /
another tool carry a *mutable* analysis database and inherit its signature failure
— the database drifting out of sync with reality. N0xis holds **sound over
complete**: the model is a *cache of summaries over a deterministic pipeline*,
never a mutable source of truth that can silently go stale — you can always
recompute and verify.

This is a stronger, more defensible position than "another RE tool" — **on the
explicit condition that it is stated exactly this honestly**: a unified pipeline +
contract + growing summary layer, *materializing toward* a full program model, not
a finished one.

## 3. Non-negotiable principles (project law)

These derive from the global engineering rules and are binding on every module:

1. **Modularity through contracts, not coupling.** Every module is usable and
   swappable on its own. Modules talk through stable contracts (trait / schema /
   API), never through hidden internal state. The core depends on *abstractions*;
   concrete implementations (a specific ISA, a specific data source, a specific
   frontend) are pluggable.
2. **Adapters isolate the outside world.** Anything OS-specific, format-specific,
   or process-specific lives behind an adapter trait. The analysis core never calls
   `ReadProcessMemory` or `goblin` directly.
3. **Single source of truth.** A contract duplicated across two sides (a JSON
   schema, a helper, a constant) is a bug — extract it. All schemas live in one
   crate; all tunables live in config/constants, never inline.
4. **Anti-hardcode.** No magic literals, paths, caps, ABI facts, or register
   names baked into logic. They live in named constants, an ISA descriptor, or
   config. Throwaway scripts are exempt.
5. **Powerful CLI *and* MCP.** Both are first-class frontends over the same core
   API. Neither is an afterthought. (N0xHUD is a third, thinner frontend of the
   same core — a window over the engine, not a parallel implementation.)
6. **Never silently lose semantics.** Any instruction/pattern the analysis can't
   raise is preserved verbatim (as an `asm` node / comment) with a confidence
   marker — output is always *sound*, even when incomplete.

## 4. Architecture: layers & seams

```
FRONTENDS (output-side adapters)  ──── one stable core API + JSON contracts ────▶
    n0xis-cli    thin clap frontend (binary: n0xis, alias n0x)
    n0xis-mcp    MCP server — agent tools
    n0xis-hud    N0xHUD — config-driven companion window over the same crates
        │
        ▼
n0xis-pipeline
    PassManager — schedules passes, caches artifacts, incremental recompute
        │
        ▼
n0xis-core   (pure analysis — NO I/O, NO OS)
    static:   decode → cfg → ir → ssa → propagate/fold → dce
              → type-infer → control-structure → render(pseudo-C)
    dynamic:  value-scan / pointer-path / AOB / struct-dissect / diff
              / provenance / structural-predicate / ui-locate
    depends only on the seams below (traits, never concrete impls):
        ├── n0xis-arch      trait Arch          (+ X64 iced-x86, ARM64 disarm64)
        └── n0xis-sources   MemorySource / SymbolProvider / ModuleProvider
                            impls: LiveProcess, StaticPe, Snapshot, RemoteAgent
        │
        ▼
n0xis-project    .n0x/ analysis DB — names, types, notes, patches, .n0xt tables

n0xis-contracts  all wire schemas + shared types — single source of truth
                 (depended on by every crate above)
```

### Crates (Cargo workspace — 12 members, `crates/*`)

| Crate | Responsibility | Depends on | Never touches |
|---|---|---|---|
| `n0xis-contracts` | All wire schemas (`n0xis.*.vN`), shared value types (`Va`, `Symbol`, `Reg`). Single source of truth. | serde | everything else |
| `n0xis-arch` | ISA abstraction (`trait Arch`) + `X64` impl (iced-x86): decode, lift-to-microIR, register model, calling conventions. `Arm64` (disarm64) is **implemented and self-tested** (CFG/discover/xref/goto+structured decompile); SSA optimization + flag-precise conditions stay x64-only, and ARM64 is **not yet verified to x64's standard**. | contracts, iced-x86, disarm64 | OS, I/O, sources |
| `n0xis-sources` | Input adapters: `MemorySource` / `SymbolProvider` / `ModuleProvider` + `LiveProcess` (Win32), `StaticPe` (goblin), `Snapshot`, `RemoteAgent` (SSH/Tailscale). Also the `debug` (sw/hw breakpoints, cross-process unwind) and `input` (injection probe) adapters. | contracts, windows-sys, goblin | analysis logic |
| `n0xis-core` | Pure analysis passes over `Arch` + source traits: CFG, IR, **SSA, propagation, DCE**, type inference, control structuring, pseudo-C render, xref, slice, plus the dynamic passes (scan/aob/pointer/dissect/valueset/deobfuscate/diff/provenance/gamegrep/constident/bindings/sigvalidate/structural/ui_locate). **No I/O, no OS.** | contracts, arch (trait), sources (traits) | concrete adapters |
| `n0xis-project` | `.n0x/` analysis database: functions, names, types, comments, selections, patches, dumps, `.n0xt` tables, session, ir-cache. Versioned truth. | contracts | analysis logic |
| `n0xis-pipeline` | Wires a source + arch + project into the core; `PassManager` schedules/caches passes (content-addressed artifacts). | all core-side crates | frontend concerns |
| `n0xis-cli` | Thin clap frontend → pipeline calls → JSON. The living command surface ([`docs/CLI_COMMANDS.md`](docs/CLI_COMMANDS.md)); the ported v0 commands live on inside that same current reference. | pipeline, contracts | analysis internals |
| `n0xis-mcp` | MCP server exposing the same pipeline as agent tools (same `ok/data/meta` envelope). | pipeline, contracts | analysis internals |
| `n0xis-hud` | **N0xHUD** — a config-driven, always-on-top **companion window** (eframe/egui) over the same crates: process-watcher auto-apply, write & freeze, global hotkeys, Interception-driver actuation, sequence/stratagem input macros, and the Helldivers interact-combo auto-solver. A third frontend / runtime-instrumentation surface — **not** an in-game overlay or an injection layer. | sources, project, core, contracts (+ eframe/egui, windows) | the CLI/MCP dispatch; core analysis internals |
| `n0xis-bitsquid` | Bitsquid/Stingray bundle format adapter (archives, resource types). Pluggable game-format adapter. | contracts | core (never depended on by it) |
| `n0xis-lua` | Offline LuaJIT 2.0 bytecode dump decoder/patcher (header, prototypes, instructions, constants). Pluggable scripting-format adapter. | serde | core, OS |
| `n0xis-luajit` | Live LuaJIT VM introspection: finds/decodes GC objects (starting with `GCstr`) directly in a running process's heap via `MemorySource`, no per-string hand-picked byte pattern. Sibling to `n0xis-lua` (live vs. offline), not a dependency of it. | contracts, sources (traits) | core, concrete OS calls |

**Test of correct boundaries:** you can `cargo test -p n0xis-core` with a mock
in-memory `MemorySource` and a mock `Arch`, with zero Windows APIs linked. If you
can't, a boundary leaked.

## 5. The three key seams (in detail)

### 5.1 Source seam — `n0xis-sources`

Replaces v0's `enum IrSource { Live, Static }` with traits:

```rust
pub struct Va(pub u64);            // typed virtual address (contracts)
pub struct Symbol { pub va: Va, pub module: String, pub name: String, pub kind: SymKind }

pub trait MemorySource {
    fn read(&self, va: Va, len: usize) -> Result<Vec<u8>>;
    fn contains(&self, va: Va) -> bool;
    fn write(&self, va: Va, bytes: &[u8]) -> Result<()>;   // live-only; StaticPe errors
}
pub trait SymbolProvider { fn symbol_at(&self, va: Va) -> Option<Symbol>;
                           fn iat_slot(&self, va: Va) -> Option<Symbol>; }
pub trait ModuleProvider  { fn modules(&self) -> &[Module];
                            fn owner_of(&self, va: Va) -> Option<&Module>; }
```

Implementations: `LiveProcess(pid)`, `StaticPe(path)`, `Snapshot` (cached
memory dump for reproducible offline runs), and `RemoteAgent` (analysis over SSH/
Tailscale to another machine — a natural fit for the existing PC-to-PC setup).
**Runtime vs static stops being an `if` in analysis; it's a choice of adapter.**

### 5.2 ISA seam — `n0xis-arch`

```rust
pub trait Arch {
    fn decode(&self, bytes: &[u8], va: Va) -> DecodedInsn;
    fn lift(&self, insn: &DecodedInsn) -> Vec<MicroStmt>;  // → arch-neutral micro-IR
    fn regs(&self) -> &RegisterFile;
    fn calling_conventions(&self) -> &[CallConv];
}
```

`X64` is the reference impl, but *all* x64/Win64 knowledge (arg regs, volatile
regs, ABI, flag semantics) lives here — never in the passes. This is the seam that
made **`Arm64`** possible (implemented and self-tested via disarm64: CFG / discover
/ xref / goto+structured decompile) without rewriting analysis. Honest caveat:
ARM64 is **not yet verified to x64's standard** — a real `reg_access` bug (sp vs.
xzr for register 31) surfaced only against genuine LLVM output — and SSA
optimization + flag-precise conditions remain x64-only.

### 5.3 Pass seam — `n0xis-core`

Every analysis step is a pass with a typed input/output contract, à la LLVM /
Bevy systems:

```rust
pub trait Pass {
    type In;  type Out;
    fn name(&self) -> &'static str;                 // stable id, schema-linked
    fn run(&self, ctx: &Ctx, input: Self::In) -> Result<Self::Out>;
}
```

The canonical pipeline:

```
decode ─▶ cfg ─▶ lift(micro-IR) ─▶ ssa-construct ─▶ propagate/fold ─▶ dce
       ─▶ type-infer ─▶ control-structure ─▶ render(pseudo-C)
```

Each pass emits a schema'd artifact the frontends can request individually.

## 6. The decompiler pipeline (the main capability)

This is where v0 was weakest (a linear instruction transliterator: `mov`→`dst=src`,
registers printed as `rax`/`rcx` verbatim, conditions from a fragile "last cmp"
heuristic). v1 makes the optimizing IR the core, structured as real passes:

1. **micro-IR lift** — each instruction → typed expression/statement tree (via
   `Arch::lift`), not strings. Flags modeled explicitly as values.
2. **SSA construction** — dominance-frontier phi insertion + renaming. Genuine SSA,
   not per-block value numbering. Artifact: `n0xis.ir.ssa.v1`.
3. **Optimization passes** (to fixpoint, budgeted):
   - copy propagation, constant propagation + folding,
   - **expression propagation** — the readability win: `rax=f(); x=*(rax+8)` collapses
     to `x = *(f()+8)`, and field access becomes `state->count`-style;
   - **DCE** — liveness-based removal of dead defs, dead spills, unused flag computations.
   - Artifact: `n0xis.opt.delta.v1` (what each pass changed — the "explainable" bit).
4. **Type inference** — stack-slot coalescing into named locals, size/signedness
   from access + branch context, struct/field recovery, propagation across calls
   and known API signatures. Kills v0's blanket `uint64_t` + `local_XX`.
5. **Signature recovery** — real arity and return type (which of rcx/rdx/r8/r9/stack
   are read before write; whether rax is consumed by callers) instead of the fixed
   `void sub_X(uint64_t rcx, rdx, r8, r9)`.
6. **Control structuring** — port v0's already-good dominator/post-dominator +
   natural-loop + `if/else`/`while`/`for`/`do-while` + `&&`/`||` reconstruction as a
   pass consuming the *optimized* IR (v0 ran it over raw instructions).
7. **Render** — pseudo-C from the optimized, typed, structured IR.

Because the source is an adapter, this whole chain runs identically on a **live
process** and a **static file** — satisfying "works at runtime too" by construction.

## 7. Capabilities vs another tool / another tool / another tool

| Axis | What exists elsewhere | N0xis |
|---|---|---|
| Primary interface | GUI; scripting bolted on | CLI + MCP contract (GUI deferred, not never) |
| Decompiler internals | black-box microcode | every pass emits inspectable JSON |
| Live + static | separate tools/flows | one pipeline, adapter-selected |
| Determinism | mostly | strict, reproducible core |
| Agent ergonomics | plugin-in-GUI | native MCP tools + stable schemas |
| Extensibility | plugin API | swappable adapters (source/arch/pass) |

We do **not** try to out-a source-level decompiler a source-level decompiler on raw decompiler maturity (20 yrs of
microcode opts). We win where they're structurally weak: agent-native, inspectable,
unified live/static, reproducible. If a GUI ever lands, it rides on top of these same
artifacts (N0xHUD is the existing proof) rather than displacing the contract.

## 8. Expectations / definition of done (per capability)

- **Sound before pretty.** Never emit wrong pseudo-C; degrade to labeled/asm.
- **Every pass is independently testable** with mock sources/arch, no OS linked.
- **Every output is a versioned schema** in `n0xis-contracts`; breaking a schema
  bumps its `vN`.
- **The CLI surface is documented in [`docs/CLI_COMMANDS.md`](docs/CLI_COMMANDS.md)**
  — the current, living command reference (not a frozen v0 snapshot). The ported v0
  commands live on inside that same reference, and new capabilities are additive.
- **Parity gate:** the rewrite is not "done" until `ir build`, `disasm`,
  `function discover`, `xref`, switch resolution and `decomp pseudo` match or beat
  v0 output on a fixed corpus of test functions (captured from the archived binary).
- **Quality bar for pseudo-C:** on the motivating example
  ([`archive/docs-v0/Decompile.txt`](archive/docs-v0/Decompile.txt)) no bare
  `rax`/`rcx` in the common path; memory dereferences resolved to named
  fields/locals; conditions provably correct under intervening flag writes.

---

## 9. Dynamic memory layer (a memory scanner class) — a first-class peer

Dynamic memory work is **not a side feature** — it is a peer of static analysis and
shares the same adapter + pass + contract model. It lives mostly in `n0xis-core`
(scan/diff algorithms are pure) over the `MemorySource` adapter, with the live
Win32 bits in `n0xis-sources`.

Feature parity target (match CE, then beat it):

- **Value scanning** — exact / unknown-initial / increased / decreased / changed /
  unchanged / range, over typed views (i8..i64, f32/f64, string, AOB). Iterative
  filtering of a result set across snapshots.
- **Pointer-path scanning** — find stable multi-level pointer chains
  (`[[base+a]+b]+c`) that survive restarts/ASLR; rescan/validate them.
- **AOB (array-of-bytes) scanning** — signature scan with wildcards; used for
  code-cave/anchor discovery and version-resilient hooking.
- **Struct dissection** — walk a region as a struct, infer field sizes/types
  (fused with static type recovery — see killer feature).
- **Write / freeze** — one-shot write, continuous freeze, and script-driven writes.
- **Code injection / patching** — the existing `patch` surface + code caves +
  detour/trampoline hooks, all with persisted undo.
- **Hooks / timers** — value-change watchpoints (HW breakpoints, incl. conditional
  `--when reg=value`), periodic re-scan; a speedhack-style time hook is a later stretch.

Every one of these is a CLI verb + MCP tool returning a schema'd artifact — so an
agent can drive a full scan→filter→freeze loop headlessly. N0xHUD (§4) puts an
interactive, always-on-top face on the same write/freeze/watch machinery for
in-the-moment runtime instrumentation.

## 10. Own table format — `.n0xt` (a superset of CE `.CT`)

The persistent artifact of a session, stored in `.n0x/tables/`. It is CE's cheat
table plus everything the RE side knows:

- Entries: address / typed pointer-path / AOB signature, value type, description,
  hotkeys, groups.
- Scripts (enable/disable) — but sandboxed and declarative where possible.
- **The N0xis superset:** each entry can link to its **recovered function**,
  **recovered struct + field**, and **value provenance** (what code writes/reads it),
  plus a **verification state** (last confirmed live, on which module version/hash).
- Deterministic, diffable, agent-authorable text format (TOML/JSON core, not opaque
  binary), versioned like every other contract in `n0xis-contracts`.

## 11. Killer features — a portfolio + a standing synthesis loop

There is **not one killer feature — there is a growing portfolio of them**, and,
more importantly, a **standing process** that produces them. This is a core operating
mode of the project, not a one-off design decision:

> **The synthesis loop:** for each capability area, the agent (a) maps what the
> other tools do (BN / another tool / another tool / a memory scanner / others), (b) maps what we do,
> (c) finds the gap no other fills — usually on the static⇄dynamic seam, (d)
> proposes a feature that *surpasses* them, and (e) records it, its rationale, and
> its status. This runs continuously as the project matures.

The living registry of these features (with the per-capability third party analysis)
is **[`docs/KILLER_FEATURES.md`](docs/KILLER_FEATURES.md)** — the single source of
truth for the portfolio. It is expected to grow; CONCEPT only names the principal.

### Principal (#1): Provenance-Driven Memory Intelligence

The one thing no other can do, because none spans both worlds:

> **Any runtime value auto-resolves to its meaning, and any intent auto-resolves to
> a verified change — by fusing dynamic scanning with the SSA decompiler.**

- **Value → meaning (provenance).** Scan for a value; N0xis runs *find-what-accesses*
  (HW breakpoints), resolves each `VA → module+RVA → recovered function`, decompiles
  it, and returns a **provenance graph**: *"this is `hp`, field `+0x68` of `Player`,
  written by `sub_X` as `max_hp - damage`, from the combat tick."* CE gives an
  address; RE tools give code; N0xis gives the explained, typed causal chain — as JSON.
- **Intent → verified change.** NL intent ("freeze HP", "one-hit kill") → locate
  value/code via the fused model → synthesize patch/table entry → apply → **verify
  live** → record in `.n0xt` with provenance.

Why it wins: it collapses the manual static⇄dynamic bridge into one automated,
explainable, agent-native operation — the reason the two worlds must share one core.
Other candidates in the portfolio (version-resilient anchors, typed pointer-path
fusion, snapshot-diff causal attribution, cross-version binary diffing, UI-layer
localization, …) live in the registry.

## 12. Naming & compatibility policy

The project is named **N0xis** (pronounced "Noxis") — chosen 2026-07-08 (candidates
considered: N0xRE, N0xZ, BinaryZ, BinaryX; `n0xis` verified free on crates.io / npm /
PyPI and on the `.io` / `.dev` / `.app` domains). The name reads as a real,
brandable token, keeps the `n0x` visual lineage, and carries fitting connotations
("noxious" + phonetically near "nexus" — the static⇄dynamic *fusion* thesis).

Token policy (to keep brand consistent without breaking existing installs):

- **Brand / prose / crates:** `N0xis`, crates `n0xis-*`.
- **CLI binary:** primary `n0xis`, kept invocable as **`n0x`** (alias) so the
  installed global shim and existing `n0x.cmd` files keep working.
- **New v1 wire schemas:** `n0xis.*.vN`. The ported v0 schemas remain `n0x.*`
  (back-compat, reserved in [`n0xis-contracts` `schema.rs`](crates/n0xis-contracts/src/schema.rs);
  a few are still **live** — e.g. `n0x.decomp.pseudo.v1`, used by `decomp pseudo`).
  The current command reference is [`docs/CLI_COMMANDS.md`](docs/CLI_COMMANDS.md).
- **Kept as-is for back-compat:** the project dir `.n0x/`, the `n0x.cmd` shim, and
  the `.n0xt` table extension (reads as "n0x table").
- **License:** **AGPL-3.0-only**; the repo is public (a commercial license is
  available on request).
- **GitHub:** the public repo lives at
  [`github.com/LargoScript/n0xis`](https://github.com/LargoScript/n0xis) (the bare
  `n0xis` username is a dormant squatter, so the project ships under the author's
  account rather than a dedicated org).

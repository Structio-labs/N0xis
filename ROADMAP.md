# N0xis — Roadmap (v1 rewrite)

> Companion to [`CONCEPT.md`](CONCEPT.md). Strategy: **full rewrite** into a Cargo
> workspace, porting the sound parts of v0 ([`archive/`](archive/)) rather than
> re-deriving them from a blank page. Each phase ends with the tool **buildable and
> usable** — no phase leaves `main`/CLI broken.

Legend: 🎯 milestone · ✅ done · ⏳ in progress · ⬜ todo.

---

## Phase 0 — Reset & docs ✅
- ✅ Archive v0 to `archive/` (code + docs).
- ✅ Delete the web/Tauri frontend prototype entirely.
- ✅ Preserve the CLI surface → [`docs/CLI_COMMANDS_v0.md`](docs/CLI_COMMANDS_v0.md).
- ✅ Concept + roadmap.

## Phase 1 — Workspace skeleton & seams ✅
Goal: the empty-but-correct architecture. No analysis yet; the boundaries exist.
- ✅ Cargo workspace with all 8 crates from CONCEPT §4 (`crates/*`).
- ✅ `n0xis-contracts`: `Va` (hex-string wire form), `Symbol`, `Module`, `Reg`, the
  `ok/data/meta` `Response` envelope, and v0 + v1 schema ids reserved.
- ✅ `n0xis-sources`: `MemorySource` / `SymbolProvider` / `ModuleProvider` traits +
  the in-memory `Snapshot` mock — no OS code (windows-sys/goblin gated to Phase 2).
- ✅ `n0xis-arch`: `trait Arch` + `X64` decoding real insns via iced-x86 (flow
  classification, direct-branch targets, Win64 reg/CC model); `lift` stubbed for P3.
- ✅ `n0xis-core`: `trait Pass`, `Ctx`, and the `DecodePass`.
- ✅ `n0xis-pipeline`: thin façade wiring source+arch into the core.
- ✅ `n0xis-cli`: clap skeleton, binary `n0xis`; `doctor`, `guide`, `init`,
  `project info`, and a `disasm --bytes` demo driving the full pipeline.
- ✅ **Exit test PASSING:** `cargo test -p n0xis-core` runs over the `Snapshot` mock;
  `cargo tree -p n0xis-core` contains zero windows/OS crates. The boundary holds.

> Build note: this machine's default Rust toolchain is `stable-x86_64-pc-windows-gnu`
> (bundled linker, no MSVC Build Tools needed); pinned in `rust-toolchain.toml`.
> Build/test from PowerShell or Git Bash both work with it.

## Phase 2 — Port the proven v0 analysis (parity) 🎯
Goal: match v0 on the boring-but-hard foundations, now behind clean seams.
- ⬜ `LiveProcess` (Win32 RPM/VirtualQueryEx/ToolHelp) + `StaticPe` (goblin) adapters.
- ⬜ Linear disasm (`disasm`), CFG + block/def-use IR (`ir build/cfg/dot/explain`).
- ⬜ Function discovery (prolog scan), export/IAT symbol + import resolution.
- ⬜ Switch/jump-table detection **and** memory-side resolution.
- ⬜ Frame analysis, backward register slice (`ir slice`), `ir manifest` + quality.
- ⬜ `xref to/from/string`, `mem read/write/map`, `patch *`, `selection *`,
  `dump *`, `function trace`, `debug await-hit`.
- **Exit test (parity gate):** golden-output diff vs the archived binary on a fixed
  corpus of functions for `ir build`, `disasm`, `discover`, `xref`, switch cases.

## Phase 3 — Optimizing decompiler 🎯
Goal: the reason for the rewrite. Pseudo-C that reads like C. All as `n0xis-core` passes.
- ⬜ **micro-IR lift** in `n0xis-arch::lift` — typed expr/stmt trees, flags modeled as values.
- ⬜ **SSA construction** — dominance-frontier phi insertion + renaming → `n0xis.ir.ssa.v1`.
- ⬜ **Propagation + folding** — copy/const/expression propagation, constant folding
  → collapses `rax=f(); x=*(rax+8)` to `x=*(f()+8)`. Emits `n0xis.opt.delta.v1`.
- ⬜ **DCE** — liveness-based removal of dead defs / spills / unused flag computations.
- ⬜ **Control structuring** — port v0's dominator/loop/`if`/`while`/`for`/`do-while`/
  `&&`/`||` reconstruction, now over the *optimized* IR.
- ⬜ **Render** pseudo-C from optimized + structured IR. New style on `decomp pseudo`
  (`--style ssa`), v0 `goto`/`structured` kept.
- **Exit test:** on [`archive/docs-v0/Decompile.txt`](archive/docs-v0/Decompile.txt)
  — no bare `rax`/`rcx` in the common path; loads resolved to named locals/fields;
  conditions correct under intervening flag writes.

## Phase 4 — Types & signatures 🎯
Goal: kill blanket `uint64_t` / `local_XX` / fixed 4-arg `void` signatures.
- ⬜ Stack-slot coalescing into named locals; size/signedness inference from access +
  branch context.
- ⬜ Struct/field recovery (`state->count` instead of `*(uint32_t*)(rax+0x68)`).
- ⬜ Real arity + return-type recovery; type propagation across calls.
- ⬜ Known-API signature library (Win32 + CRT) feeding argument types + names.
- ⬜ C++/Rust symbol demangling.
- **Exit test:** recovered signatures + named fields on a labeled sample set.

## Phase 4b — Dynamic memory layer (a memory scanner class) 🎯
Goal: first-class dynamic memory work as a peer of static analysis (CONCEPT §9).
- ⬜ Typed value scanning + iterative filtering (exact/unknown/increased/decreased/
  changed/range) over `MemorySource`; pure scan/diff in `n0xis-core`.
- ⬜ Pointer-path scanner (stable multi-level chains, ASLR-resilient rescan).
- ⬜ AOB signature scanning with wildcards.
- ⬜ Struct dissection (fused with Phase 4 type recovery).
- ⬜ Freeze/write, code caves + detour/trampoline hooks (extends `patch`, persisted undo).
- ⬜ Value-change watchpoints via hardware breakpoints.
- ⬜ **`.n0xt` table format** (CONCEPT §10) in `n0xis-contracts`; `table *` CLI verbs.
- **Exit test:** headless scan→filter→freeze loop on a live target, results saved to `.n0xt`.

## Phase 4c — Killer feature: Provenance-Driven Memory Intelligence 🎯
Goal: fuse the two worlds (CONCEPT §11) — the core capability.
- ⬜ **Value → meaning:** scan → find-what-accesses (HW breakpoints) → `VA→module+RVA→
  function` → SSA decompile → typed provenance graph (`n0xis.provenance.v1`).
- ⬜ **Intent → verified change:** NL intent → locate value/code via the fused model →
  synthesize patch/table entry → apply → verify live → record with provenance.
- ⬜ Runtime⇄static address reconciliation (ASLR base handling) as a reusable service.
- **Exit test:** agent goes "find & freeze HP" → explained provenance + verified freeze
  entry in `.n0xt`, end-to-end, no human bridging static/dynamic.

## Phase 5 — MCP frontend (the moat) 🎯
Goal: agent-native interface as a first-class citizen (PRODUCT_POLICY §3: "Powerful CLI *and* MCP").
- ⬜ `n0xis-mcp` server exposing the pipeline as MCP tools over the same core API.
- ⬜ Tools mirror CLI verbs + return the same schemas; add "explain" tools that
  surface `n0xis.opt.delta.v1` / SSA / structuring reasoning to the agent.
- ⬜ Session/attach state shared with CLI via `n0xis-project`.
- **Exit test:** an agent drives attach → discover → decompile → explain end-to-end
  through MCP only.

## Phase 6 — Persistence, incremental, performance 🎯
- ⬜ `n0xis-project` analysis DB as versioned truth (names/types/comments/patches).
- ⬜ `PassManager` artifact caching + incremental recompute (don't rebuild IR per call).
- ⬜ Snapshot source (reproducible offline runs); `RemoteAgent` source over SSH/Tailscale.
- ⬜ Perf pass on hot paths (manifest over large modules).

## Phase 7+ — Capabilities beyond the v0 port ⬜
- ⬜ Value-set / light alias analysis (better jump tables, pointer reasoning).
- ⬜ Multi-arch via `trait Arch` (ARM64 first candidate).
- ⬜ Deobfuscation passes (pattern-based, as optional pipeline stages).
- ⬜ Diffing two binaries/versions at the IR/pseudo level (agent-friendly change reports).

---

## Sequencing notes
- **Phases 1–2 are non-negotiable prerequisites** — the optimizing decompiler
  (Phase 3) has nowhere to live until the pass pipeline and adapters exist.
- **Phase 3 is the first user-visible payoff** and the original motivation; prioritize
  it immediately after parity.
- **MCP (Phase 5)** can start as soon as the core API stabilizes (after Phase 3) — it's
  a thin frontend, and it's the biggest capability, so don't defer it to the end.
- The ISA seam (`trait Arch`) is built in Phase 1 **even with one implementation**, so
  x64 knowledge never leaks back into the passes (the mistake that sank v0).

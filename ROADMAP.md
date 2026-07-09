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

## Phase 2 — Port the proven v0 analysis (parity) ✅
Goal: match v0 on the boring-but-hard foundations, now behind clean seams.
- ✅ `StaticPe` (goblin) adapter — `MemorySource`+`SymbolProvider`+`ModuleProvider`,
  behind the `static-pe` feature.
- ✅ `LiveProcess` (Win32 RPM/VirtualQueryEx/ToolHelp) adapter behind the `live`
  feature; `process ps`, `module list` (live+static), `disasm --pid/--file/--bytes`
  all run the *same* pipeline over the chosen source. Boundary still holds
  (`cargo tree -p n0xis-core` = zero OS crates).
- ✅ CFG + block/def-use IR (`ir build`, `ir explain`) — leaders→blocks→edges
  (fall/jmp/cjmp/tail), per-insn reg reads/writes + intra-block def-use, auto
  end-of-function detection, call-target naming via the symbol seam. New arch
  seam `Arch::reg_access` keeps the iced decoder out of the pass. (`ir cfg/dot`
  presentations + switch/frame/slice/manifest are follow-on slices.)
- ✅ Function discovery (prolog scan) — `function discover` over `.text`
  (via source `text_range()`), prolog patterns supplied by `Arch::prologues`.
  (`function list/info` + export/IAT enumeration verbs are a follow-on.)
- ✅ `xref to/from` — branch + RIP-relative data refs via `DecodedInsn.target`
  / new `DecodedInsn.rip_target` arch field (no byte patterns in the pass).
- ✅ `xref string` — searches a data window for a byte needle and a code window
  for `lea`-style `rip_target` hits on each match (`n0xis-core::StringXrefPass`,
  reusing `XrefEntry`); only matches with ≥1 referencing instruction are
  reported. New `StaticPe`/`LiveProcess::section_range(name)` generalizes the
  existing `.text`-only lookup to any named section, so the data window
  defaults to `.rdata` (falling back to `.text`) while the code window stays
  `.text` — the two live in different sections. Verified on a real PE: found
  `n0xis.xref.string.v1` and error-message literals with their exact `lea`
  call sites, including one string referenced from 7 different places.
  (Relocation-aware/recursive scan remain follow-on.)
- ✅ Switch/jump-table detection **and** memory-side resolution — arch seam
  `Arch::detect_switch` recognizes the two x64 idioms (mem-indexed absolute-ptr
  tables, MSVC reg-rel32 tables); `n0xis-core::resolve_switch` reads the table
  through the `MemorySource` seam and emits resolved case targets as CFG
  successors, closing indirect branches. A new optional `MemorySource::code_range`
  gates cases to executable code (rejects `.rdata` misreads). Same code path over
  live + static (the edge). Verified on a real PE: e.g. a reg-rel32 dispatch
  resolved to its exact case targets read from the jump table.
- ✅ CFG presentations — `ir dot` (Graphviz; block nodes + successor edges,
  memory-resolved `switch-case` targets drawn as dashed external nodes so
  indirect flow is visible) and `ir slice` (backward register slice over the
  block/def-use chains: normalizes the query reg via a new `Arch::normalize_reg`
  seam so `eax`/`ax`/`al` hit a `rax` def, finds the seed writer at/before the
  query point, walks def-use edges back to the roots). Both are pure views over
  the `CfgArtifact` (`n0xis-core::dot`/`slice`). Verified on a real PE: a switch
  dispatch renders its 5 resolved cases as edges; a `call` slices back to the
  `sub rsp` that set up its frame. (Slice is intra-block until SSA in Phase 3.)
- ✅ Frame analysis + `ir manifest` — a new `Arch::analyze_frame` seam scans a
  function's prolog (purely structural, no memory) and recovers `frame_size`
  (`sub rsp, imm`), `uses_rbp` (`mov rbp,rsp`), and `spilled_regs` (`push reg`),
  surfaced as `CfgArtifact.frame` and an `ir explain` line. `ir manifest`
  (`n0xis-core::ManifestPass`) batches `DiscoverPass` candidates through
  `CfgPass` and reduces each to a triage entry — counts, frame, a ported
  0.0..=1.0 quality score, and flags (`leaf`/`has-switch`/`stub`/`no-frame`/
  `no-return`/…) — so an agent can rank thousands of discovered candidates
  before spending a full `ir build` on any one. Verified on a real PE: 22
  candidates scored, well-formed functions at 0.85–1.0, a switch dispatcher
  correctly flagged `has-switch`+`no-return` at 0.55.
- ✅ `mem read` (any source) / `mem write` / `mem map` (live, VirtualQueryEx
  region walk); `LiveProcess::write` flips page protection (VirtualProtectEx)
  and restores it, so code pages are patchable.
- ✅ `patch dry-run/apply/list/show/undo` — journaled under `.n0x/patches/`
  (`n0xis-project::patch`), read→write→verify on apply, safety-checked undo
  with `--force`. Verified live: apply flipped bytes, undo restored them.
- ✅ `selection *` (`save`/`list`/`show`/`clear`) + `dump *` (`save`/`list`/
  `show`/`rm`) — agent working primitives under `.n0x/`, same storage-only
  split as `patch`. `n0xis-project::selection` persists named `[start,end)`
  ranges to `selections.json` (overwrite-by-name, case-insensitive lookup);
  `n0xis-project::dump` persists artifacts to `dumps/<kind>/<name>.<ext>`
  (`ir`/`pseudo`/`hex`/`raw`/`note` kinds, already scaffolded by `init`) with
  overwrite protection (`--force` to bypass). Verified end-to-end via the
  compiled CLI in a scratch `.n0x/` project: save/list/show/clear and the
  full dump CRUD including a refused-then-forced overwrite.
- ✅ `debug await-hit` — arms a software breakpoint (`int3`) via the Win32
  debug API, blocks until it fires or times out, and reports the hitting
  thread's full GPR + stack snapshot. New `n0xis-sources::debug` (gated behind
  the same `live` feature as `LiveProcess`, but a standalone flow — a debug
  session needs its own `DebugActiveProcess` attach, not the read/write handle
  `LiveProcess` already holds). Every mutation (the patched byte, the debug
  attach) is an RAII guard, so the byte is restored and the debugger detached
  on *every* exit path — hit, timeout, or error — with no manual bookkeeping
  per early-return, unlike v0. Verified on a real live process: attached to a
  `powershell.exe` calling `kernel32!Sleep(150)` in a loop, the reported `rcx`
  was exactly `150`; ran twice in a row to confirm the restore is clean, not a
  one-shot; process kept accumulating CPU time (proof it resumed correctly).
- ✅ `function trace` — BFS call-graph walk from a root (`n0xis-core::TracePass`),
  built compositionally on `CfgPass`: each visited function's end is found via
  its existing `auto_end` heuristic (an improvement over v0, which bounded a
  function's body crudely at "the next known function start" from a separate
  discovery pass). Depth and `max_nodes` caps, dedup via a visited-set so a
  shared callee is reported once at its shallowest depth, and an `unreadable`
  flag on nodes whose bytes couldn't be decoded (e.g. an IAT thunk) instead of
  aborting the walk. Verified on a real PE: a 13-callsite root walked to 26
  deduplicated nodes across depth 0–3, `--addr-rva` resolved to the same root
  as the absolute-VA form, and `--max-nodes` truncation reported correctly.
- ✅ **Exit test (parity gate)** — [`scripts/parity_gate.py`](scripts/parity_gate.py)
  builds the archived v0 CLI standalone (now excluded from the workspace,
  `Cargo.toml`) and runs both tools against the same PE, comparing what must
  hold regardless of schema/formatter: `function discover` address-set
  overlap, per-function `ir build` block/instruction/callsite counts,
  `disasm` address+length+mnemonic sequences (compared via each side's
  *formatted text*, not v1's semantic `mnemonic` field — iced-x86
  canonicalizes some encodings, e.g. the `66 90` NOP-alias reports as `"nop"`
  even though its text still says `xchg ax,ax`), and `xref to` from-address
  sets. Run repeatedly across ten random samples (25–60 functions each): zero
  gating failures. Along the way it caught two real switch-resolution
  divergences — both in v1's favor: v0 over-reads a table past its real end
  into adjacent garbage (the bug `code_range()` exists to fix, confirmed here
  on a real function where v1's 15 cases are an exact prefix of v0's 60,
  the rest garbage); and v0 fails to resolve a table entirely (empty) where
  v1 correctly resolves 55 valid, self-consistent case targets. Switch
  *case-content* agreement is therefore tracked as informational, not
  gating — v0's resolver is demonstrably less correct, so exact agreement is
  the wrong acceptance criterion; structural presence/absence still gates.

## Phase 3 — Optimizing decompiler 🎯 ✅
Goal: the reason for the rewrite. Pseudo-C that reads like C. All as `n0xis-core` passes.
- ✅ **micro-IR lift** — `n0xis-arch::microir` (`MicroExpr`/`MicroStmt`, flags modeled
  as a real value under one variable namespace shared with registers) + `X64::lift`
  covers the v0-parity mnemonic set (mov family, arithmetic, `lea`, `cmp`/`test`,
  `push`/`pop`, `call`/`ret`) via `x64_lift.rs`. New seam `Arch::branch_condition`
  turns a `Jcc` + whatever dataflow value reaches it for `"flags"` into an exact
  condition — the key design move: **every** flag-touching instruction (not just
  `cmp`/`test`) writes `"flags"`, so a later `Jcc` structurally cannot reuse a stale
  compare across an intervening flag-setter (v0's exact bug) — it gets a Win64-clobber
  invalidation after `call`s too (an accuracy gain over v0, which never modeled that).
- ✅ **SSA construction** (`n0xis-core::SsaPass`, over a new `LiftPass`) — real
  dominance-frontier phi insertion + Cytron-style renaming (shared `dom.rs`: forward
  + post-dominators, dominance frontier, dom-tree, reused later by structuring).
  `SsaBlock.condition` is synthesized once per block from the reaching `"flags"` SSA
  value via `Arch::branch_condition` — structurally correct, not a heuristic.
- ✅ **Propagation + folding + DCE** (`n0xis-core::OptimizePass`, one `n0xis.opt.delta.v1`
  artifact per CONCEPT §6's grouping) — copy-prop (chases `x=y` chains and
  same-valued phis), constant folding (typed, width-aware), and **expression
  propagation**: a new `MicroExpr::Call` variant lets a single-use call result inline
  directly into its sole consumer, collapsing `rax=f(); x=*(rax+8)` to `x=*(f()+8)`
  exactly as specified — restricted to same-block/single-use/no intervening
  `Call`/`Store` (the one place this pass is deliberately conservative: no alias
  analysis yet to prove a `Load`/`Call` safe to reorder past a side effect). DCE never
  removes `Call`/`Store` (only dead `Assign`/phi defs) — a call's side effect is never
  assumed droppable just because its result went unused.
- ✅ **Control structuring** (`n0xis-core::structure`) — ported v0's dominator/
  post-dominator/natural-loop/`if`-`else`-with-`&&`/`||`-folding/`for`/`while`/
  `do-while` recursive-descent emitter verbatim in shape, but driving it off
  `SsaBlock`s (real per-block conditions, typed negation via `render::negate_condition`)
  instead of v0's raw re-lifted instruction text + mutable "last compare". Falls back
  to `goto` on anything irreducible, same as v0.
- ✅ **Render** — `n0xis-core::render` (typed `MicroExpr`/`MicroStmt` → pseudo-C text,
  shared by all three styles) + `DecompPass` orchestrator. `decomp pseudo --style
  goto|structured|ssa` on `n0xis-cli` (the command didn't exist in v1 yet — added
  here): `goto` = flat labeled blocks over SSA (no structuring/optimization); `structured`
  = control-structured over SSA (no optimization); `ssa` = structured + optimized (the
  main). All three already get exact per-branch conditions — that correctness fix
  isn't gated behind `--style ssa`, only the expression-collapsing prettification is.
  Reuses the v0 schema `n0x.decomp.pseudo.v1` (additive style, not a new capability).
- ✅ **Exit test** — [`crates/n0xis-core/tests/phase3_exit.rs`](crates/n0xis-core/tests/phase3_exit.rs).
  The original binary behind [`archive/docs-v0/Decompile.txt`](archive/docs-v0/Decompile.txt)
  isn't in the repo, so this reconstructs its motivating shape as synthetic x64 (a call
  result whose fields get read twice at `+0x68`/`+0x6C`, exactly like the transcript,
  plus a branch separated from its guard by another flag-touching instruction across a
  real block boundary) and asserts against the real `n0xis-cli` pipeline: no bare
  (un-versioned) `rax`/`rcx`/`rdx` anywhere in the rendered body, the call site inlined/
  named, and the cross-block stale-compare case rendering an honest placeholder instead
  of a wrong reused condition. Verified end-to-end on `n0xis.exe` itself too (`decomp
  pseudo --file`): `ssa` style correctly DCE'd a prologue/epilogue `rsp` adjustment pair
  that cancels out and is never observed, which `goto`/`structured` show un-optimized.

## Phase 4 — Types & signatures 🎯 ✅
Goal: kill blanket `uint64_t` / `local_XX` / fixed 4-arg `void` signatures.
- ✅ **Stack-slot coalescing + struct/field recovery** — one `n0xis-core::TypeInferPass`
  over the optimized SSA blocks (`typeinfer.rs`). Both recoveries key off the *same*
  address shape (`Var(base) ± Const(offset)`, ported straight from `render.rs`'s own
  local-recognition helper so the two can never disagree): a `rsp`/`rbp`-rooted base
  coalesces every access at one offset into a single [`LocalVar`] (size = the widest
  access seen, signed if *any* access was), sized/signed from access context exactly as
  ROADMAP asked; any other named base gets a [`RecoveredType`] and renders as
  `base->field_0x68` instead of raw pointer arithmetic. The struct case only fires on a
  bare `Var + Const` address — precisely the shape that survives `OptimizePass` when a
  pointer is dereferenced *more than once* (single-use pointers get inlined into their
  sole consumer instead, per Phase 3), so it lines up exactly with what a human would
  call "a struct pointer" without any threshold heuristics.
- ✅ **Real arity + return-type recovery** — arity is exactly which of `rcx.0`/`rdx.0`/
  `r8.0`/`r9.0` are ever read anywhere in the function (Win64 args are positional, so a
  gap in the middle — e.g. `r8` used, `rdx` not — still yields arity 3, not 2: the ABI
  can't skip a slot). Return type is `void` unless some `Return` carries something other
  than the untouched entry `rax.0` — verified on real code in `n0xis.exe` itself (one
  function correctly recovered as `sub_...(void)`, others as `uint32_t`/`uint64_t`
  returns with narrower arity than the old fixed 4). Register-args only; stack-passed
  args 5+ are an explicit documented follow-on (would need precise `rsp`-delta tracking
  through `push`/`sub rsp,N` prologues, which Phase 3's lift deliberately doesn't model
  yet — sound to defer rather than guess, CONCEPT §3 rule 6).
- ✅ **Known-API signature library** (`signatures.rs`) — one small, extensible static
  table (~30 common kernel32/CRT entries: `CreateFileW`, `VirtualAlloc`, `HeapAlloc`,
  `malloc`/`memcpy`/`fopen`, …) keyed by bare function name. A matched call site trims
  the generic 4-register arg dump to the real arity and names each argument inline
  (`CreateFileW(/*lpFileName*/ rcx.0, /*dwDesiredAccess*/ rdx.0)`) and casts the result to
  the known return type (`(HANDLE)CreateFileW(...)`) — "type propagation across calls,"
  scoped to what's honestly knowable without a real type system.
- ✅ **C++/Rust/MSVC demangling** (`demangle.rs`, new deps `rustc-demangle` +
  `msvc-demangler` + `cpp_demangle` — verified none pull in windows/goblin, the
  `n0xis-core` boundary test still holds) — tried in that order, falls through to the
  original name unchanged on no match. Wired into `RenderNames::callee`: a genuinely
  demangled C++/Rust name renders as-is (`Foo::bar<T>`, not C-identifier-sanitized, same
  as real decompilers); a plain `module!function` import keeps the existing `__`
  treatment.
- ✅ **Exit test** — [`crates/n0xis-core/tests/phase4_exit.rs`](crates/n0xis-core/tests/phase4_exit.rs),
  a synthetic labeled sample set (no existing labeled corpus in-repo, same gap Phase 3's
  exit test hit): niladic `void` function, single-register-arg function, a
  skipped-middle-register arity case, a local referenced at two sites staying one name,
  a two-field struct pointer, and a known-API call site — each with ground truth known
  by construction, checked against the real `CfgPass → SsaPass → OptimizePass →
  TypeInferPass → DecompPass` pipeline. All pass; zero regressions across the 56 tests in
  `n0xis-core` (up from Phase 3's 49) and zero warnings workspace-wide.

## Phase 4b — Dynamic memory layer (a memory scanner class) 🎯 ✅
Goal: first-class dynamic memory work as a peer of static analysis (CONCEPT §9).
- ✅ **Typed value scanning + iterative filtering** — `n0xis-core::ScanPass`/`FilterPass`
  (`scan.rs`): exact/in-range/unknown first scan, then increased/decreased/changed/
  unchanged/exact/in-range rescan against the previous match set. Pure over the
  `MemorySource` seam (region enumeration is the OS-specific part, stays in
  `n0xis-sources`/`n0xis-cli`). `n0xis.scan.v1`.
- ✅ **Pointer-path scanner** — `n0xis-core::PointerPathPass` (`pointer.rs`), built
  *compositionally* on `ScanPass` rather than a bespoke reverse-pointer index:
  "what points near X" **is** a value scan for X (± a plausible struct-offset window),
  so each BFS level is one more `ScanPass` run. Terminates a chain once a hit lands in
  a caller-supplied static root (a module's address range survives ASLR as
  `module+offset`); `resolve_pointer_path` re-walks a discovered chain forward for the
  "ASLR-resilient rescan" ROADMAP asks for. `n0xis.scan.pointer_path.v1`.
- ✅ **AOB signature scanning** — `n0xis-core::AobScanPass` (`aob.rs`), `?`/`??`
  wildcards. `n0xis.scan.aob.v1`.
- ✅ **Struct dissection** — `n0xis-core::DissectPass` (`dissect.rs`): heuristically
  types each slot of a *live* region from its runtime value's shape (resolves inside
  mapped memory → pointer; plausible float; else integer; all-zero → padding), each
  guess carrying a `confidence` rather than a bare assertion. The dynamic counterpart
  to Phase 4's *static* struct/field recovery (`typeinfer.rs`), not yet fused (that
  fusion is Phase 4c's provenance graph).
- ✅ **`.n0xt` table format** (CONCEPT §10) — types in `n0xis-contracts::table` (a
  wire contract like every other schema'd type, not project-local): `TableLocator`
  (`Address` / `PointerPath` / `Aob`, increasing ASLR/patch resilience), the N0xis
  superset (`Provenance`, `VerificationState` — both optional, unpopulated until
  Phase 4c). Persistence in `n0xis-project::table` (`.n0x/tables/<name>.n0xt`, JSON),
  mirroring the existing `selection`/`patch` storage-only split. Deliberately
  **excludes** a memory scanner's scriptable enable/disable (arbitrary code execution in
  the target — out of scope, `groups`/`hotkey` leave room to grow toward it later).
- ✅ **Freeze + code caves + detour/trampoline hooks** — `table freeze` is a bounded
  write-loop over the already-proven `LiveProcess::write`. Hooking is built to bound
  risk: `LiveProcess::alloc_code_cave` (`VirtualAllocEx`, RWX) + a **pure**
  `n0xis-core::build_trampoline` (`trampoline.rs`) that range-checks every `jmp rel32`
  before ever producing bytes — refuses outright rather than writing a jump that would
  silently wrap/miss — and `X64::decode_stream` finds a whole-instruction-aligned hook
  length (never splits an instruction). The hook-site overwrite (the only *destructive*
  part — the cave is fresh memory) goes through the existing `patch` journal, so it's
  undo-able through the same record `patch apply` already produces. Verified live: the
  range check correctly *refused* a cave `VirtualAllocEx` placed far from the hook site
  rather than writing a corrupted jump — the safety property working as designed.
- ✅ **Value-change watchpoints via hardware breakpoints** — `n0xis-sources::debug`
  gains `await_watchpoint_hit`/`WatchKind` (Execute/Write/ReadOrWrite — x86 has no
  hardware read-only mode, so the API doesn't invent one): arms DR0/DR7 across every
  thread of the target (`CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`), reuses the same
  `WaitForDebugEvent`/RAII-guard shape as the Phase 2 software breakpoint, restores
  every thread's original debug registers on drop. **Found and fixed a real Windows
  FFI bug along the way**: `windows-sys`'s `CONTEXT` is `#[repr(C)]` with no explicit
  16-byte alignment, but the kernel performs an aligned XMM save/restore into it during
  `Get`/`SetThreadContext` — a stack-allocated `CONTEXT` can land under-aligned
  depending on surrounding code and fault with `ERROR_NOACCESS` (998), intermittently
  and call-site-dependently (this affected the *existing* Phase 2 software-breakpoint
  path too, not just the new code — just hadn't manifested yet). Fixed with a
  `#[repr(C, align(16))]` wrapper (`AlignedContext`) used at every `CONTEXT` site.
  Verified live end-to-end on a real spawned process: the watchpoint fired on the
  target's own write instruction, reporting the exact `rip` (`scan_target.exe+0x1862`)
  and full register/stack state, and the target resumed running correctly afterward.
- ✅ **Exit test** — [`crates/n0xis-pipeline/tests/phase4b_exit.rs`](crates/n0xis-pipeline/tests/phase4b_exit.rs)
  (behind `--features live`, same opt-in-for-OS-tests convention as `n0xis-sources`
  itself): spawns a real disposable process, writes a known value via the proven
  `LiveProcess::write`, `ScanPass`-finds it, writes an increased value, `FilterPass`
  narrows to exactly that address, persists the result as a real `.n0xt` file via
  `n0xis-project::table`, reloads it from disk to prove persistence (not just
  in-process state), then runs a bounded freeze loop and confirms the value stuck.
  Passed 3/3 runs with no leaked processes. Additionally verified manually end-to-end
  via the compiled CLI against a real running process: `scan value` (unknown) → `scan
  filter` (increased) correctly narrowed 4 candidates to exactly the one live counter;
  `scan dissect` correctly classified a real heap pointer (0.9 confidence) next to a
  plain integer; `table add`/`table freeze` persisted and drove a real live write loop;
  `debug watch` caught a real hardware trap.

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

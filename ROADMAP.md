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

## Phase 4c — Killer feature: Provenance-Driven Memory Intelligence 🎯 ✅
Goal: fuse the two worlds (CONCEPT §11) — the core capability.
- ✅ **Value → meaning** — `n0xis-core::ProvenancePass` (`provenance.rs`): given one or
  more `(instruction_va, access_kind)` hits (typically from Phase 4b's `debug watch`),
  resolves each to `module+rva` (`Module::rva`), then walks discovered function
  candidates backward from the hit address, building each one's CFG until one's extent
  actually covers it (bounded search, `MAX_CANDIDATES_TRIED`) — the `VA→module+RVA→
  function` chain. Runs the found function through `--style ssa` (`DecompPass`) and
  extracts exactly the rendered block containing the hit (structure.rs already tags
  every block with a `// block_N: 0xADDR` header; this greps between that marker and
  the next one) — the typed `n0xis.provenance.v1` graph. Every field is `Option`/empty
  rather than a guess when a step doesn't resolve (CONCEPT §3 rule 6). **No other
  does this**: confirmed via the earlier fact-check research — a memory scanner's
  "find what accesses this address" stops at a raw disassembly line; other tools'
  decompilers have no live-watchpoint integration at all.
- ✅ **Intent → verified change** — not a new NLP engine (the "intent" side is the
  agent driving existing CLI verbs); what Phase 4c adds is the missing link: `.n0xt`'s
  `Provenance`/`VerificationState` fields (defined in Phase 4b but always empty until
  now) get populated for real. New `provenance trace --pid --addr --kind [--save-to-table
  --entry]` arms a watchpoint (Phase 4b), explains the hit (this phase), and — when
  asked — records the explanation onto a real table entry with a verification
  timestamp, reusing the same `patch`/`table` apply-then-verify pattern Phase 2/4b
  already proved (`table freeze`'s bounded write-loop is the "apply"; a subsequent
  `mem read`/`scan filter` is the "verify" — already-existing primitives, now
  provenance-annotated instead of bare).
- ✅ **Runtime⇄static address reconciliation** — `n0xis-core::aslr` (`rebase`/`rva_of`/
  `va_at`): re-expresses an address computed against one module base (a live, rebased
  process) as the equivalent address against another (a static file's preferred base,
  or a different live run after a restart) — the ASLR-resilient rescan primitive,
  factored out as its own tested unit rather than inlined ad hoc at each call site.
- ✅ **Exit test** — [`crates/n0xis-pipeline/tests/phase4c_exit.rs`](crates/n0xis-pipeline/tests/phase4c_exit.rs)
  (`--features live`): compiles a tiny known Rust target at test time (`rustc` is
  guaranteed present), spawns it, arms a real hardware watchpoint on its counter,
  catches a real write, fuses it through `ProvenancePass`, and asserts the decompiled
  explanation actually shows the increment (not just a bare address) — then freezes the
  value and records the explanation onto a real `.n0xt` entry, reloading it from disk
  to confirm the provenance and verification timestamp survived the round trip.
  Passed 3/3 runs. **Verified manually against the compiled CLI too**: `provenance
  trace --pid <p> --addr <hex> --kind write` against a real spawned process returned
  `decompiled_context: ["*rax.2 = (*rax.2 + 0x1);", ...]` — the exact source-level
  statement (`*ptr += 1;`) automatically recovered from a live memory write, with the
  subsequent `Duration::from_millis(500)` call visible right below it. Along the way,
  found and fixed a real bug in the function-resolution path: it was scanning from the
  module *base* (the PE header page, a separate small VAD region) instead of `.text`,
  silently truncating the scan to 4096 bytes; generalized `LiveProcess::section_range`
  into `section_range_of` (any module, not just the main one) to fix it.

## Phase 5 — MCP frontend (the moat) 🎯 ✅
Goal: agent-native interface as a first-class citizen (PRODUCT_POLICY §3: "Powerful CLI *and* MCP").
- ✅ `n0xis-mcp` server exposing the same `n0xis-core`/`n0xis-sources` capabilities the
  CLI drives, as MCP tools, built on the official [`rmcp`](https://docs.rs/rmcp) SDK's
  macro pattern (`#[tool_router]`/`#[tool_handler(router = self.tool_router)]`) over
  stdio transport. Binary: `n0xis-mcp`, spawned by an MCP client and driven over
  JSON-RPC on stdin/stdout (`ServerHandler::serve(rmcp::transport::stdio())`).
- ✅ **Tools mirror CLI verbs + return the same schemas**: 15 tools in `crates/n0xis-mcp/
  src/tools.rs` — `doctor`, `process_ps`, `attach`, `module_list`, `disasm`,
  `function_discover`, `function_trace`, `decomp_pseudo` (goto/structured/ssa),
  `xref`, `xref_string`, `mem_read`, `mem_write`, `provenance_trace`, and the two
  "explain" tools below. Every tool returns the exact serialized `{ok,data,meta}`
  envelope (`n0xis_contracts::Response`) `n0xis-cli`'s `emit()` prints — an agent's
  parsing code is identical whether it called the CLI or MCP (CONCEPT §3 rule 5).
  Argument resolution (`pid`/`file` → a live/static source) lives in `n0xis-mcp::source`
  — a scoped-down sibling of the CLI's `build_source` (no inline `--bytes`; MCP tool
  calls always name a real target), not a shared crate yet since `n0xis-cli` is a
  binary with no lib target — documented as worth hoisting into `n0xis-pipeline` if a
  third frontend ever needs the same seam, rather than preemptively.
  **Scoped out of this pass** (documented follow-on, not a silent gap): the CLI verbs
  whose state today is bridged file-to-file across independent CLI invocations
  (`scan value`/`filter`, `.n0xt` `table *`, `patch *`, `debug watch`) — an MCP server
  is a long-lived process, so they deserve in-memory session state rather than a
  straight port of the CLI's per-invocation file bridging; that's a separate design
  decision from wiring the transport up in the first place.
- ✅ **"Explain" tools surfacing decompiler reasoning**: `decomp_pseudo(style="ssa")`
  already inlines the per-pass optimization delta (`PseudoFunction::delta`); on top of
  that, `explain_opt_delta` runs the same pipeline and returns *only* `n0xis.opt.delta.v1`
  (each entry: pass name, address, summary of what changed — copy/const/expr
  propagation, DCE) — a dedicated "why" tool distinct from getting the full pseudo-C.
  `provenance_trace` is the principal explain tool (Phase 4c's fusion, now reachable over
  MCP): arms a real hardware watchpoint and returns the exact decompiled statement
  responsible for a live memory access.
- ✅ **Session/attach state shared with CLI via `n0xis-project`**: new `n0xis-project::
  session` module (`.n0x/session.json`, same storage-only split as `selection`/`table`)
  — `attach` (pid or file) records the session default; every other tool falls back to
  it when `pid`/`file` is omitted, and the CLI reads the same file in the same
  `.n0x/` project.
- ✅ **Exit test** — [`crates/n0xis-mcp/tests/phase5_exit.rs`](crates/n0xis-mcp/tests/phase5_exit.rs):
  spawns the *real* `n0xis-mcp` binary as a child process and drives it over raw
  JSON-RPC/stdio — the same way an actual MCP client would, proving the transport
  wiring rather than just the tool function bodies — against a real, disposable
  Windows process (compiled at test time via `rustc`, same trick as `phase4c_exit.rs`).
  Drives `attach{pid}` → `function_discover{}` (pid resolved from the session default,
  not repeated) → `decomp_pseudo{addr,style:"ssa"}` → `explain_opt_delta{addr}`, and
  also asserts `.n0x/session.json` was actually written to disk by `attach` (the
  CLI-sharing contract, not just an in-memory convenience). 1/1 passing; zero warnings
  workspace-wide.

## Phase 6 — Persistence, incremental, performance 🎯 ✅
This phase bundled four independent sub-goals of very different weight (see the
sequencing note below); artifact caching landed first as the namesake "incremental"
feature, then the analysis DB, then the two new sources, then the perf pass.
- ✅ **`n0xis-project` analysis DB as versioned truth** (names/types/comments; patches
  already had their own versioned journal since Phase 2, so this is the missing half).
  New `n0xis-project::annotate` (`.n0x/annotations.json`) — `set_name`/`set_type`/
  `set_comment(va, Option<value>)` append a history entry (field, old, new, unix)
  **iff the value actually changed** (idempotent re-sets don't grow history), and
  `None` clears a field while still recording that it was cleared — nothing is ever
  silently overwritten. CLI: `annotate name|type|comment --addr --value`, `annotate
  show|list|rm`. MCP: `annotate_set`/`annotate_get`/`annotate_list`. New schema
  `n0xis.annotation.v1`.
- ✅ **`PassManager` artifact caching + incremental recompute** (don't rebuild IR per
  call) — the hard part of this phase, since correctness under cache invalidation is
  one of the two hard problems in CS. Solved with **content-addressed caching**
  instead of dependency tracking: `n0xis-pipeline::cfg_cached` hashes the source's
  label + `CfgInput` + **the actual bytes `CfgPass` would decode** (read once, up
  front) into the cache key, so the cache can never silently hand back a stale
  artifact — if the bytes at that address changed since the last call (self-modifying
  code, a hot-patched function, a redeployed DLL), the hash changes and it's a miss,
  never a wrong hit (CONCEPT §3 rule 6: never silently give stale data). Storage:
  `n0xis-project::ir_cache` (`.n0x/ir-cache/<hash>.json`, raw-string get/put/clear,
  same storage-only split as `selection`/`session`/`table` — it doesn't know what an
  artifact *is*, keeping `n0xis-core` types out of `n0xis-project`). Required adding
  `Deserialize` to `CfgArtifact`'s whole type chain (`CfgBlock`/`IrInsn`/`DefUse`/
  `Callsite`/`Successor`/`CfgStats`, plus `n0xis-arch::{InsnKind,FrameInfo}` and
  `n0xis-core::switch::ResolvedSwitch`) since until now every artifact only needed to
  serialize *out* to JSON, never round-trip back. Wired into both frontends: CLI's
  `ir build/explain/dot/slice` and `decomp pseudo` (`finish_ir`/`finish_slice`/
  `finish_decomp` in `main.rs`), and MCP's `decomp_pseudo`/`explain_opt_delta`.
  **Verified two ways**: an OS-free exit test
  ([`crates/n0xis-pipeline/tests/phase6_exit.rs`](crates/n0xis-pipeline/tests/phase6_exit.rs))
  proves miss→hit→invalidate-on-changed-bytes→hit-again against `Snapshot`, and a
  manual run of the compiled `n0xis.exe` twice against itself as a static PE showed
  the cache file's mtime *not* changing on the second call (byte-identical output,
  proving it actually skipped recomputation, not just returned an equivalent value).
  **Scoped out, documented follow-on**: `TracePass`/`ManifestPass`'s internal
  per-candidate `CfgPass` calls stay uncached (caching lives at the frontend-facing
  call sites, not inside pass-composes-pass internals — keeps `n0xis-core` free of
  any cache-awareness); only `CfgPass` is cached so far, not every pass — mechanical
  to extend (same `cfg_cache_key` shape, different `Out` type) once a second pass
  actually needs it.
- ✅ **Snapshot source (reproducible offline runs)**. `n0xis-sources::Snapshot` gained
  `Serialize`/`Deserialize` (it was already the OS-free test double since Phase 1;
  this made it round-trip through JSON byte-for-byte, region/module/symbol data
  included). New `snapshot dump --pid|--file --start --size --name` captures a byte
  range (+ modules when resolvable) into `.n0x/dumps/snapshot/<name>.json` (a new
  `DUMP_KINDS` entry — reused `n0xis-project::dump`'s existing generic store rather
  than inventing new storage); `snapshot info`/`snapshot list` inspect it. `--snapshot
  <name>` is now a source option alongside `--pid`/`--file`/`--bytes` on every
  CfgPass-driving CLI verb (`ir build/explain/dot/slice`, `decomp pseudo`, `function
  discover/trace`, `xref to/from/string`, `mem read`) and the matching MCP tools —
  reloading one and re-running the same analysis produces byte-identical output,
  verified manually against a real captured `.text` slice of the compiled `n0xis.exe`.
- ✅ **`RemoteAgent` source over SSH/Tailscale**. New `n0xis-sources::remote`: a tiny
  newline-JSON wire protocol (`read`/`write`/`contains`/`label`/`quit`), generic over
  *how* the remote-serve process is reached — `RemoteAgent::connect(argv)` just spawns
  `argv` and speaks the protocol over its piped stdio, so `["ssh", "user@host", "n0xis",
  "remote-serve", "--pid", "1234"]` reaches a real remote machine and a bare local argv
  is exactly what the tests use to prove the protocol without a second machine (SSH is
  one possible argv prefix, never hardcoded — anti-hardcode policy). `serve_stdio` is
  the server half, generic over any `MemorySource` (protocol-tested against `Snapshot`,
  OS-free) so the CLI's new `remote-serve --pid <p>` command just wires it to a real
  `LiveProcess`. `--remote-cmd "<argv string>"` is a source option everywhere
  `--snapshot` is. **Real bug found+fixed along the way**: the first implementation
  used the `shell-words` crate (POSIX shell-word splitting) to parse `--remote-cmd`,
  which silently ate every backslash in Windows paths (`D:\tools\n0xis.exe` →
  `D:toolsn0xis.exe`) — this tool is Windows-first, so POSIX escaping is the wrong
  model entirely; replaced with `n0xis_sources::split_command_line`, a small
  no-escape-sequences splitter (only `"..."` for spaces) that treats `\` as always
  literal. Caught by `crates/n0xis-cli/tests/phase6_remote_exit.rs`, which spawns the
  *real* compiled `n0xis` binary as `remote-serve` against a real disposable process
  and asserts `mem read --remote-cmd "..."` returns byte-identical output to a direct
  `mem read --pid`.
- ✅ **Perf pass on hot paths (manifest over large modules)**. Profiled `function
  discover` and `ir manifest` against a real 2.5 MB system DLL (`ntdll.dll`, 4428
  discovered functions) at several candidate-count limits. Result: linear scaling
  with candidate count in both debug and release builds (no quadratic behavior found)
  — release-mode `ir manifest` over *all* 4428 candidates completes in ~2.3s, discover
  alone in ~0.36s. No bottleneck requiring a fix at this scale; documented here as the
  exit criteria for this bullet rather than manufacturing a change where profiling
  found none needed.

## Phase 7 — Capabilities beyond the v0 port 🎯 ✅ (ARM64 ⚠️ needs more real-world verification)
All four items landed in one pass, each a real, tested, CLI-wired capability —
not stubs. None of them required touching `n0xis-core`'s existing passes; every
one is additive, matching the modularity law CONCEPT §3 sets out. **One caveat,
called out where it applies below**: ARM64 support is implemented and passes
its own test suite, but "passes its own tests" and "verified" are not the same
claim — a real bug (see the ARM64 bullet) was found only by testing against
genuine compiler output, after the first pass had already been reported as
verified. Don't repeat that mistake when reading this phase as "done."

- ⚠️ **Multi-arch via `trait Arch`, ARM64 first candidate — implemented,
  *not yet* verified enough to call solid.** The biggest item, and the seam's
  first real test since Phase 1. New `n0xis_arch::Arm64`, backed by
  [`disarm64`](https://docs.rs/disarm64) (a pure-Rust, no-`unsafe`,
  no-allocation AArch64 decoder generated from the ARM spec — the same
  "reuse a mature decoder" choice `X64` made with `iced-x86`). **Deliberately,
  honestly scoped** (CONCEPT §3 rule 6 — sound over complete, the same
  discipline `Arch`'s own trait defaults already establish):
  - `decode`/`decode_stream`: full coverage — every 4-byte AArch64 word
    decodes (or reports `Invalid`/`Truncated`), never silently drops bytes.
  - `reg_access`: implemented for the base integer ISA a compiler actually
    emits (data-processing, loads/stores, branches) via `InsnClass`-gated
    fixed-bit-position extraction (Rd/Rn/Rm/Rt at ARM64's well-known,
    regular field positions) — SIMD/FP/SVE/SME/crypto/system-register/atomic
    classes report empty reads/writes, the same sound-but-empty default the
    trait itself defines for an ISA with no override.
  - `lift`/`branch_condition`: **not** overridden — kept at the trait's sound
    defaults (`Unlifted` / a placeholder condition). CFG, discovery, xrefs,
    and `goto`/`structured` decompilation all work correctly; the optimized
    `--style ssa` pass and flag-precise condition recovery are x64-only today
    — a comparable-sized effort to `microir.rs`/`x64_lift.rs`, a documented
    follow-on, not a silent gap.
  - `detect_switch`: not implemented (ARM64's jump-table idioms differ from
    x64's two; a third pattern-recognizer, not attempted).
  - `prologues()`/`analyze_frame`: a few common exact `stp x29, x30,
    [sp, #-N]!` encodings for discovery, plus a structural (not byte-prefix)
    recognizer for the standard frame-pointer prolog.
  - **What's actually been checked, and why "verified" would overclaim it.**
    The first pass (19 unit tests, hand-picked instruction words cross-checked
    against `disarm64`'s own regression suite so the *encodings* were at least
    real) plus
    [`crates/n0xis-core/tests/arm64_exit.rs`](crates/n0xis-core/tests/arm64_exit.rs)
    (`CfgPass` — zero changes made to it — building a correct 3-block CFG
    over those bytes) all passed and were reported as "verified." **That was
    premature.** Cross-compiling a real Rust program to a real AArch64 object
    (`rustc --target aarch64-linux-android --emit=obj`, genuine LLVM-generated
    code, no hand-picked bytes) immediately surfaced a real bug none of those
    19 tests caught: `reg_access`'s `sp`-vs-`xzr` selection for register 31
    was backwards for every register-form ALU/branch operand, so `xzr`-using
    idioms LLVM actually emits (`madd x9, x9, x10, xzr`, `orr x0, xzr, xzr` as
    `mov #0`) were misreported as touching the stack pointer. Fixed, and three
    regression tests were added using the exact real encodings that caught it
    (`madd_reads_xzr_not_sp_for_a_discarded_accumulator`,
    `orr_with_xzr_operands_reads_xzr_not_sp`,
    `addsub_imm_is_the_one_class_that_really_can_read_and_write_sp`), but this
    is one ad hoc test against three small functions from one artificial
    program — **not** a live ARM64 process, **not** a real-world binary of any
    size, and the SIMD/FP/crypto/SVE code paths have never been exercised even
    once, only reasoned about. Status: implemented, passes its own test suite,
    wired into the CLI as `--arch arm64|x64` — genuinely usable for
    exploration, but **needs substantially more real-world verification**
    before the base integer ISA coverage should be trusted the way `X64`'s
    is. Tracked as open, real work in
    [docs/COMMUNITY_ROADMAP.md](docs/COMMUNITY_ROADMAP.md).
- ✅ **Value-set / light alias analysis** — new `n0xis-core::valueset`
  (`ValueSetPass`, `n0xis.value_set.v1`): a bounded (capped at 8 tracked
  values per variable, capped at 20 fixpoint iterations) dataflow over SSA,
  computing each SSA variable's possible concrete values — `Top` the instant
  anything is unknown (a load, a call result, a merge that would exceed the
  cap), never a guess. `alias(a, b, sets)` answers `NoAlias`/`MustAlias`/
  `MayAlias` between two address expressions, resolving the common
  `Var(base) ± Const(offset)` shape (`typeinfer.rs`'s own struct/field
  shape) to disambiguate distinct fields of the same struct. Wired into the
  CLI as `ir value-set`; 5 tests, including "a load must never resolve to a
  finite value set" (the load-is-unknown soundness invariant, tested
  directly, not just asserted in a doc comment).
- ✅ **Deobfuscation passes, pattern-based** — new `n0xis-core::deobfuscate`
  (`DeobfuscatePass`, `n0xis.deobfuscate.v1`), two independent, narrow,
  high-confidence techniques (not an attempt at general deobfuscation —
  control-flow flattening/VM-based protectors are a different, larger
  problem, not attempted, the same scope split `detect_switch` draws):
  junk-instruction detection (`mov reg,reg`, `xchg reg,reg`, `push`/`pop`
  pairs that cancel out, `add/sub/or reg,0` identity arithmetic — structural,
  no dataflow needed) and opaque-predicate detection (a conditional branch
  whose condition `ValueSetPass` can *prove* constant — one successor edge is
  dead code disguised as a branch). Reported, not silently rewritten, per
  CONCEPT §3 rule 6. Wired into the CLI as `ir deobfuscate`; 7 tests, each
  with a matching "must never false-positive" counterpart (a real
  cross-register move, a real non-zero add, a real branch on an unmodeled
  input are all asserted clean).
- ✅ **Diffing two binaries/versions at the IR/pseudo level** — new
  `n0xis-core::diff` (`DiffPass`, `n0xis.diff.v1`): a classic LCS-based
  line diff (bounded — falls back to a whole-block replace past 2M
  table cells rather than growing unbounded) over any two line sequences, in
  practice two `PseudoFunction`s' `pseudo` output. Reports `Equal`/`Insert`/
  `Delete` hunks plus a similarity score — the literal "agent-friendly
  change report" this bullet asks for (an agent gets "line 3 changed from
  `rax.1 = 0x5` to `rax.1 = 0xa`", not a raw two-blob dump). Wired into the
  CLI as `diff functions --a-file/--a-pid/--a-bytes --a-addr --b-file/
  --b-pid/--b-bytes --b-addr`; 5 tests. **Scoped out, documented follow-on**:
  this diffs *one already-identified pair* of functions — automatically
  matching every function across two whole binaries (name matching where
  symbols exist, structural-similarity matching where they don't) is a
  substantially larger problem of its own (an entire category of dedicated
  tools — a structural diff tool, a structural diff tool — exists just for this), not attempted here.

**GUI**: explicitly deferred, not abandoned — user's own framing: "GUI-потім.
Не зараз, але не 'ніколи'" (GUI later. Not now, but not "never"). No phase
number assigned yet; CONCEPT's "GUI-never" framing (CLI/MCP only) reflected the
project's original scope, not a permanent constraint. When it's picked up, it
should be its own phase (a thin visualization layer over the existing
`ok/data/meta` artifacts — CFG/DOT rendering, decompiled output, the analysis
DB — not a rewrite of the analysis core, which stays CLI/MCP-drivable
regardless).

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

# N0xis — Roadmap (v1 rewrite)

> Companion to [`CONCEPT.md`](CONCEPT.md). Strategy: **full rewrite** into a Cargo
> workspace, porting the sound parts of v0 rather than
> re-deriving them from a blank page. Each phase ends with the tool **buildable and
> usable** — no phase leaves `main`/CLI broken.

Legend: 🎯 milestone · ✅ done · ⏳ in progress · ⬜ todo · ⚠️ caveat.

---

## Phase 1 — Workspace skeleton & seams ✅
Goal: the empty-but-correct architecture. No analysis yet; the boundaries exist.
- ✅ Cargo workspace with the 8 core crates CONCEPT §4 originally specified
  (`crates/*`) — the 4 companion crates (`hud`/`bitsquid`/`lua`/`luajit`) were
  added in later phases (see the companion-tooling section; 12 crates today).
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
  The original binary behind the v0 decompiler transcript
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
  unchanged/exact/in-range rescan. Pure over the `MemorySource` seam (region
  enumeration is the OS-specific part, stays in `n0xis-sources`/`n0xis-cli`).
  `n0xis.scan.v1`.
  - ⚠️→✅ **Snapshot-backed narrowing (the correct scanning model), reworked 2026-07.**
    The first cut materialized one match per hit and, on a common value (i32 `4`
    in a game → millions of hits), capped at 200 000 via `break 'regions` — which
    silently *stopped scanning every higher-address region*, so the real target
    usually wasn't even looked at and no rescan could recover it. A partial,
    order/timing-dependent working set returned as if usable — a direct
    sound-over-complete violation (found in real use, not a unit test: a live
    `scan` reported exactly `200000` + `truncated:true`). Rebuilt the way Cheat
    Engine actually works: the first scan **never truncates** — `exact`/`in-range`
    store surviving offsets, `unknown` stores the region bytes densely
    (`ScanState::{Dense,Sparse}`) so a rescan knows the old value at every position
    without an up-front address list; a rescan re-reads each region, narrows, and
    keeps survivors' latest values; addresses are materialized only on demand,
    bounded by a display budget; the full working set persists compactly (binary
    `ScanState::encode`, `.n0x/dumps/scan/*.bin`, not fat JSON). Verified live:
    exact i32==0 over a real process now reports the true `total_matches`
    (7.8M across 931 regions, no cap) and the `unknown → changed` flow narrows a
    real target from a snapshot. New exit coverage in `phase4b_exit.rs` drives
    the `unknown→changed` path against a real spawned process.
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
- ✅ **Cross-process x64 stack unwinding (true caller chain), added 2026-07.** A
  hardware watchpoint lands *mid-function*, where `[rsp]` is not the return
  address — so the raw stack window couldn't name the caller of a writing
  instruction (the wall a live RE session hit: the specific caller of a generic
  clamping setter was unreachable). `n0xis-sources::unwind` is a **from-scratch,
  dependency-free cross-process reimplementation of `RtlVirtualUnwind`**: it reads
  the target's own `.pdata` (`RUNTIME_FUNCTION`) + `.xdata` (`UNWIND_INFO`) and
  replays the UWOP unwind codes, honoring the prologue-position rule (codes for
  not-yet-executed prologue instructions are skipped), `UNW_FLAG_CHAININFO`, leaf
  functions, and machine frames, across modules. Deliberately **not** `dbghelp`
  (a stateful C symbol API foreign to this crate's direct `windows-sys` style) —
  the pure unwinder is also unit-testable against a synthetic PE with zero OS
  calls, the same boundary discipline the rest of the analysis holds. `capture_hit`
  now fills `BreakpointHit.frames`, auto-surfaced by `debug watch`/`debug
  await-hit`. Verified live: `debug watch` on a real target returned a full
  12-frame chain (`leaf→mid→top→main→CRT→KERNEL32→ntdll`), cross-module, from a
  mid-function watchpoint hit — exit test
  [`crates/n0xis-pipeline/tests/unwind_exit.rs`](crates/n0xis-pipeline/tests/unwind_exit.rs).
  Documented follow-on: `provenance trace` can now consume a real return address
  to trace the writer's caller through the SSA pipeline (the natural next
  integration); and a separate **provenance detach/re-attach hang** remains to be
  root-caused.
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

## Phase 4c — Provenance-Driven Memory Intelligence 🎯 ✅
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
- ✅ **Tools mirror CLI verbs + return the same schemas**: 14 tools in `crates/n0xis-mcp/
  src/tools.rs` at this phase's exit — `doctor`, `process_ps`, `attach`, `module_list`,
  `disasm`, `function_discover`, `function_trace`, `decomp_pseudo` (goto/structured/ssa),
  `xref`, `xref_string`, `mem_read`, `mem_write`, `provenance_trace`, and the
  `explain_opt_delta` tool below (`provenance_trace`, the other "explain" tool, is
  already named above). (Later phases add `annotate_set`/`annotate_get`/`annotate_list`
  in Phase 6 and `ui_locate`/`ui_windows`/`ui_screenshot`/`ui_focus` in Phase 9, for
  **21** exposed tools in the working tree.)
  Every tool returns the exact serialized `{ok,data,meta}`
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

## Phase 8 — Method tooling: spec-first RE 🎯 ⏳ (merged to main `a0a9168` — all 6 named commands + the hex-everywhere audit done; still ⏳ solely for the one ⬜ item, region caching as a built-in scan option)
Goal: turn a real RE campaign's post-mortem into tools. That campaign
(auto-solving a game's directional interact-combo mini-game) succeeded — and
**~90% of the effort went into
reverse-engineering runtime *state* to recover information that was
declaratively *specified* in the game's own scripts and data**. The finished
solver reads 4 bytes from memory (a seed) and computes the rest.

Every item below traces to a **specific, named failure** from that campaign, not
to speculation. Ordered by (pain avoided × generality), which is also roughly
dependency order.

- ✅ **`game grep <concept>` — search a target's scripts/data/strings for a
  feature's vocabulary** *(fixes RE_METHOD F2 — the campaign's root cause)*.
  Rank extracted script files + data + binary strings by vocabulary-cluster
  density for a concept, print hits with context. Builds on what already exists
  (`bundle list/extract`, `lua disasm`, `xref string`) — the missing piece is
  the *search-and-rank* front door, not the readers.
  **Why first**: this is literally the thing that cracked the campaign, and it
  was hand-rolled in throwaway Python. One grep for `combo|interact|stratagem`
  found the component, the algorithm module, the RNG class, and every data
  template in ~30 minutes — after weeks of native RE had found none of it.
  Highest payoff on this list.
  Scope note: ranking is the interesting part (a file mentioning 5 of the
  concept's words matters more than one mentioning a word 50 times); engine
  detection ("is there a script layer at all, and where") belongs here too.

- ✅ **`locate --by-transition` — the diff locator as a first-class workflow**
  *(formalizes RE_METHOD W1; fixes F7's repetition)*. Snapshot → wait for the
  operator to toggle exactly one thing → rescan → diff → filter survivors by a
  structural predicate → report. The pieces exist (`scan value --criterion
  unknown`, `scan filter --criterion changed`); what's missing is the *workflow*
  as one command, including the operator-in-the-loop pause and the
  structural-predicate filter over survivors.
  **Why**: this was the **only** localization technique that ever worked, across
  the entire campaign — every single successful find used it, and it returned
  *exactly one* result each time, where static value-matching returned 651,
  1025, and 1844 false positives. It was hand-rolled three separate times.
  The principle it encodes: *the change is the signal; the value is not.*

- ✅ **`input probe --pid <p>` — verify the actuation path before building on it**
  *(fixes RE_METHOD F4)*. Try each injection method (SendInput / keybd_event /
  Interception / raw HID) against a live target and report which ones it
  actually registers.
  **Why**: an entire input feature was built, shipped, and believed working —
  and had **never once registered in the game**, which filters injected input
  (`LLKHF_INJECTED`). Discovered only at the very end, after the read half was
  already perfect. A one-key probe on day one would have caught it.
  The general rule this encodes: a memory tool has a **read** half and a
  **write** half — prove each independently *before* integrating.

- ✅ **`const identify` — recognize canonical magic constants** *(automates
  RE_METHOD W3)*. Match constants in decompiled output/data against a table of
  well-known algorithm fingerprints: LCG multipliers (e.g. `1664525`/`1013904223`
  → Numerical Recipes), hash seeds (`0x5bd1e995` → MurmurHash2, FNV/xxhash/CRC
  polys), float normalizers (`1/2^32`).
  **Why**: recognizing two constants by memory identified two whole algorithms
  instantly, with zero reversing — the LCG *is* the combo generator, and the
  Murmur2 hit correctly told us we were looking at a texture-atlas lookup (i.e.
  the wrong layer). This is cheap to automate and pays off on every campaign.

- ✅ **`bindings list --module <m>` — enumerate a script VM's native bindings**
  *(generalizes RE_METHOD W2)*. Find registration calls and pair each name
  string with its C function pointer.
  **Why**: finding `Math.next_random`'s native implementation took ~20 minutes
  by hand — string → RIP-relative xref → `register(L, ns, "name", cfunc)` → the
  function pointer is right there as an argument. That's a mechanical lookup
  masquerading as reverse engineering. It turns "where is the native
  implementation of X" into a query, and it's exactly the bridge the spec-first
  ladder (below) needs between rung 2 (scripts) and rung 4 (native code).

- ✅ **`sig validate` — refuse to bless a signature from <3 independent samples**
  *(fixes RE_METHOD F3)*. Given a candidate signature and ≥2 instances, report
  which bytes are *actually* invariant; refuse (or loudly flag) a signature
  derived from fewer than 3 **deliberately-varied** samples, and ask which axis
  was varied.
  **Why**: a marker (`0xCF` at `+0x18`) matched two live instances and was
  **shipped** — the two were repeated test missions sharing a generated-level
  seed, i.e. a coincidence promoted to an invariant. A third instance on a new
  map broke it. Same class of error twice more (`state == 0` = "active", refuted
  in one minute; a structural scan whose false-positive math assumed *uniformly
  random* memory, giving 1844 hits in 4 MB). This is a guardrail against a bias
  that demonstrably ships bugs.
  Scope note: the useful output isn't pass/fail, it's *which bytes vary* — that
  turns a broken signature into a corrected one.

- ⏳ **Ergonomics + scan resilience** *(fixes RE_METHOD F6/F7)*. Small, but each
  one cost real debugging rounds:
  - ✅ Live scans **skip unreadable regions and continue**, never abort. Region
    lists are inherently racy (a region enumerated is not a region readable —
    the target allocates/frees constantly); one transiently-freed region aborted
    a whole scan and the background solver silently found nothing while looking
    healthy. Also: "0 results" must be distinguishable from "the scan died".
  - ✅ Accept **hex** for `--min`/`--max` (and anywhere else taking an
    address/value). Hand-converting hex→decimal produced wrong ranges twice,
    each time burning a scan round on an address that wasn't even close.
  - ⬜ **Region caching** as a built-in scan option rather than per-caller
    hand-rolling (full-address-space rescans per poll are the default failure
    mode otherwise). **The one remaining Phase 8 item** — everything else in this
    phase is done and on `main`.

> **Implementation notes (2026-07-17) — the six named commands landed.** All
> follow the crate discipline the earlier phases set: the *algorithm* is a pure,
> unit-tested module (OS-free where possible, so the `n0xis-core` boundary test
> still shows zero windows crates in its tree), and the CLI is thin wiring over
> it. Every command emits the standard `ok/data/meta` envelope with its own v1
> schema id (`n0xis.{game.grep,locate.transition,input.probe,const.identify,
> bindings,sig.validate}.v1`). +17 new core unit tests, all green; each command
> verified end-to-end against the compiled `n0xis.exe`.
>
> - **`game grep`** → `n0xis-core::gamegrep` (pure `rank()`), CLI `game grep
>   <concept> --dir <path>…`. The scoring *is* the feature: cluster **breadth**
>   (distinct concept terms present) is squared and weighted so it always
>   outranks raw frequency, with a log-damped frequency tail only breaking ties —
>   exactly the ROADMAP scope note ("5 words beats one word ×50"). The CLI walks
>   the corpus, auto-decoding LuaJIT bytecode files to text (name + string
>   constants + rendered instructions) via `n0xis-lua`, falling back to UTF-8 or
>   printable-ASCII-run extraction for other files. Verified: the 3-distinct-term
>   algorithm file outranked a config (2 terms) and a UI file repeating one term
>   ×7.
> - **`locate by-transition`** → CLI orchestration composing the existing
>   `ScanPass` (unknown snapshot) + `FilterPass` (changed/increased/decreased) —
>   no new pass, the transition workflow *is* the composition. Pauses for the
>   operator (stdin) or a fixed `--wait-ms` (agent/scripted), applies an optional
>   structural predicate (`--expect`/`--min`/`--max`) as a second filter, and
>   persists the working set so `scan filter` can keep narrowing. Both underlying
>   passes already skip unreadable regions (F6-safe). Verified live: 13.6M
>   snapshot → changed rescan narrowed to 19k, with a "toggle again to narrow"
>   note and a saved dump.
> - **`input probe`** → `n0xis-sources::input` (behind `live`), CLI `input probe`.
>   Installs its own `WH_KEYBOARD_LL` hook — the exact vantage point a game's
>   anti-injection filter uses — actuates a benign key (VK_F15) through each
>   method, and reports per method whether the OS input stack saw it **and
>   whether it carried `LLKHF_INJECTED`**. `SendInput`/`keybd_event` are actively
>   exercised; `Interception`/raw-HID availability is *detected* (LoadLibrary
>   probe / honest "needs a driver") rather than faked. Verified live: both
>   active methods delivered **with** the injected flag — the exact F4 finding,
>   now catchable on day one, with the recommendation pointing at the
>   driver-based fix.
> - **`const identify`** → `n0xis-core::constident` (a flat fingerprint table +
>   `identify_u64`/`identify_f64`). Recognizes LCG multipliers/increments
>   (Numerical Recipes, MSVC, glibc, PCG), hash seeds (MurmurHash2/3, FNV,
>   xxHash), CRC-32/32C polynomials, golden-ratio/SplitMix, and `1/2^n` float
>   normalizers; a 32-bit fingerprint also matches the value's low 32 bits
>   (sign/zero-extension in a 64-bit decompilation). CLI takes `--value`, a
>   function (`--addr` + source → decompile → scan its literals), or a Lua chunk
>   (`--lua` → its number pool). Verified: `0x5bd1e995`→MurmurHash2,
>   `1664525`→NR-LCG, `2.328e-10`→`1/2^32`, `42`→nothing.
> - **`bindings list`** → `n0xis-core::bindings` (`BindingsPass`), CLI `bindings
>   list`. One linear sweep of the decoded `.text` indexes every `lea reg,[name]`
>   whose target is a valid identifier in `.rdata`, then pairs each with the
>   nearest `lea reg,[cfunc]` landing in executable code — the W2 walk, with a
>   confidence (proximity + a nearby `call`) rather than a claimed certainty.
>   (The first cut was O(names×insns) and hung on a real module; the indexed
>   sweep is the "index once" perf discipline from earlier phases.) Verified on
>   `n0xis.exe`: found real name→pointer pairs (`GetTempPath2W`,
>   `SetThreadDescription`) with a call between the loads.
> - **`sig validate`** → `n0xis-core::sigvalidate` (pure `validate()`), CLI `sig
>   validate`. Reports per-offset invariance across ≥2 samples, derives the
>   honest signature (agreed bytes fixed, the rest `??`), audits a proposed
>   signature for false-invariants/contradictions/loose-wildcards, and **refuses
>   to bless** unless there are ≥3 samples *and* a varied axis is named. Samples
>   come from `--sample` hex, files, or live/static reads. Verified: N=2 refused
>   even when the bytes agree (the exact F3 trap), N=3 varied blessed with the
>   right derived mask, and a false-invariant signature audited and blocked.
>
> **Follow-up (2026-07-18) — hex-everywhere audit closed.** Every numeric CLI
> field that represents a byte length or a scan bound now accepts hex
> (`0x1000`) as well as decimal, via two new clap `value_parser`s
> (`parse_hex_or_decimal_usize`/`_u64` for sizes/offsets, `parse_hex_or_decimal_f64`
> for scan values, which still falls through to a real float since a criterion
> can compare against `3.14`) applied to all 22 `--*size`/`--len`/`--max-bytes`
> fields, `--max-offset`, and all 9 `--value`/`--min`/`--max` fields across
> `scan`/`locate`/`table freeze`. `--addr`/`--start` already had this via
> `Va::parse`; this closes the gap RE_METHOD F7 named for everything else that
> takes a byte count or a bound. Verified: `mem read --size 0x100`,
> `scan pointer-path --max-offset 0x2000`, and `scan value --value 3.14` all
> parse correctly; a garbage value reports a clear clap-level error instead of
> a silent misparse. **Still open:** region caching as a built-in scan option
> (bullet 3 above) is the one remaining Phase 8 item.

> **Follow-up (2026-07-18) — `guide` reworked into an agent capability
> catalog.** The old `guide` was a hand-maintained prose list that drifted from
> the binary. It now walks the real clap command tree via `CommandFactory`, so
> the catalog is generated from the actual definitions and *cannot* drift: every
> leaf command (77 in the installed binary at this point) with its full path,
> summary, and per-argument detail (name, required, takes-value, choices),
> grouped into curated categories, plus a preamble (usage model, global flags,
> the `--pid/--file/--snapshot/…` source model, envelope shape) and hand-written
> **workflow recipes** — the spec-first ladder, transition-diff localization,
> provenance-explain, input-probe-before-build, sig-validate, const-identify,
> decompile — that teach an agent *how* to compose the verbs, not just what they
> are. `guide <topic>` filters; `--brief` drops per-arg detail. clap `--help`
> stays as the human per-command usage. This is the discovery surface an AI agent
> reads first. (Phase 9's `ui locate`/`windows`/`screenshot`/`focus` bring a
> rebuild to 81 leaf commands.)

**The re-framing this phase encodes** (RE_METHOD's "spec-first ladder") — climb
it **top-down**, each rung cheaper and more stable than the one below:

| # | Layer | Gives you | Cost |
|---|---|---|---|
| 1 | Data / config | templates, tables, tuning — declarative truth | trivial |
| 2 | Script layer | the algorithm, readable | low |
| 3 | Native bindings | only what scripts call into — findable *by name* | low |
| 4 | Native code | one specific function | medium |
| 5 | Runtime memory | only the irreducible inputs (seeds, handles) | high, brittle |

The campaign climbed it backwards (5→1). Corollary the tools should encourage:
**minimize the memory read surface** — every byte read from a live process is
transient, ASLR'd, version-fragile and race-prone; prefer *computed* over
*observed* wherever the game itself derives the value.

**GUI**: explicitly deferred, not abandoned — user's own framing: "GUI-потім.
Не зараз, але не 'ніколи'" (GUI later. Not now, but not "never"). No phase
number assigned yet; the original "GUI-never" framing (CLI/MCP only) reflected
the project's original scope, not a permanent constraint — CONCEPT §2 now retires
it explicitly. When it's picked up, it
should be its own phase (a thin visualization layer over the existing
`ok/data/meta` artifacts — CFG/DOT rendering, decompiled output, the analysis
DB — not a rewrite of the analysis core, which stays CLI/MCP-drivable
regardless).

---

## Phase 9 — Seeing what the target sees: UI-layer localization 🎯 ⏳

> **Status (2026-07-22) — committed to branch `feat/phase9-ui-locate` (`fbf7a5f`),
> not yet merged to `main`.** Every ⚠️ item below is **implemented and self-tested**
> (unit tests over synthetic snapshots — the AABB predicate, the overlap maths, the
> mirrored-dword relation, the real 348k-noise sample) and the GDI capture path is
> mspaint-verified, but the decisive **live-target validation** — the §9.3
> appearance-correlation test on a running game — **has not been run**. Read the ⚠️ markers as *implemented, pending live
> validation*, never *verified to `X64`'s standard* (same discipline as the ARM64
> caveat in Phase 7).

Goal: close the last gap the combo campaign hit — **there is no way to get from
"the thing I can see on screen" to "the memory that drives it."**

Like Phase 8, every item traces to a **named failure from a real campaign**
(2026-07-20, universalizing the interact-combo solver — full post-mortem in the
game's `AUTO_COMBO_PLAN.md` §12; that planning doc is not tracked in this repo —
see the companion-tooling doc-debt note below). Context: the solver was finished
and working via *computed* combos (template + seed), but the operator wanted the
more general path — read the arrows the game is drawing, which would cover object
types no catalogue knows. That hunt failed four separate ways, and each failure
names a missing tool.

- ⚠️ **`debug watch --when <reg>=<value>` — conditional hardware breakpoint**
  *(implemented 2026-07-20; working tree — the guarded path has not been
  re-validated live since the `MAX_CONDITION_MISSES` guard was added: the
  motivating "killed the game" story below is the failure that *prompted* the
  guard, not a passing post-guard run)*. Non-matching hits are resumed with the watchpoint still
  armed, so a specific call can be singled out.
  **Why**: an execute breakpoint on a UI draw routine returned the *same*
  high-frequency caller (`r9=6`) on six consecutive arms — the interesting call
  (`r9=4`, the four-arrow draw) was unreachable by re-arming and hoping.
  **Ships with a hard safety limit** (`MAX_CONDITION_MISSES = 300`), because the
  first version of exactly this feature **killed the game**: a per-frame
  function turns every non-matching hit into a full stop/inspect/resume
  round-trip, effectively single-stepping the target. The limit aborts with an
  explanation instead of grinding the process to death.
  **Rule this encodes**: conditional traps are for *rare* events (a write to one
  address). On a hot site, filtering costs more than it saves — the guard makes
  that failure loud instead of fatal.

- ⚠️ **`ui locate --rect <x0,y0,x1,y1>` — screen region → candidate addresses**
  — implemented and wired (CLI `ui locate` + MCP `ui_locate`), pending live
  validation *(the operator's own proposal; fixes the campaign's terminal dead end)*.
  **Implementation brief**:
  [`docs/PHASE9_UI_LOCATE_BRIEF.md`](docs/PHASE9_UI_LOCATE_BRIEF.md) — spec,
  verified offsets, rejected alternatives, validation plan.
  Enumerate live structures whose stored bounding box intersects a
  caller-supplied screen rectangle, and report their addresses. A hit-test over
  the target's own retained scene graph, performed from outside.
  **Why it's feasible, not speculative**: the draw path was already decompiled
  during the campaign, and UI elements keep their own AABB in memory —
  `+0xa4/+0xa8/+0xac` min, `+0xb0/+0xb4/+0xb8` max, `+0xbc` radius, `+0xa0`
  dirty flag (from `sub_1400ce800`, the arrow vertex-buffer builder). The game
  already answers "what occupies this part of the screen"; nothing needs to be
  inferred from pixels.
  **Why it matters**: this is the only remaining route to the arrow widgets.
  Blind scanning is exhausted — direction arrays were searched in six encodings
  (u8/u32 enums, LuaJIT doubles, rotation in radians and degrees), as Lua string
  arrays, and differentially (two open snapshots intersected, minus closed).
  All returned zero, because the arrows are **separate widgets**: their
  directions are not adjacent in memory, so no contiguous-array search can ever
  find them. Structure-by-address is the wrong question; **position-by-region**
  is the right one.
  **Explicitly not required**: graphics-API hooking, frame capture, or reading
  pixels. Those were considered and rejected — they add a rendering dependency
  to a memory tool, and the operator had already ruled out screen-reading
  (arrow positions move in multiplayer). Reading widget *data* is immune to that.
  Design notes: the AABB init sentinel (`FLT_MAX` ×3) is **not** a usable
  signature — it is transient, overwritten with real bounds within the same
  frame rebuild (verified live: zero hits while the window was open). Candidate
  enumeration must therefore test *plausible screen-space bounds*, not a fixed
  byte pattern. An interactive overlay for drawing the rectangle is a GUI
  concern (see the deferred-GUI note above); the command itself should take
  coordinates, so it stays CLI/MCP-drivable.
  > **Implemented (2026-07-21).** `n0xis-core::ui_locate` (`UiLocatePass`,
  > `n0xis.ui.locate.v1`), a thin configuration of the new structural-scan
  > primitive (below) for one shape: the seven contiguous `f32`s of an AABB +
  > radius. Wired into the CLI (`ui locate`) and MCP (`ui_locate`, verified via
  > `tools/list`). Read-only throughout — `ReadProcessMemory` over the
  > committed-writable region set only, no breakpoints / writes / thread
  > suspension (brief §7). The AABB layout is a passed-in `AabbLayout` config
  > value (`STINGRAY` = `min.x@+0xa4 … radius@+0xbc`), not inlined — a
  > different build/engine gets a different layout, per the anti-hardcode rule.
  > - **`--space auto|screen|ndc`** is *observable, not assumed* (brief §4):
  >   `auto` runs a permissive bound and reports the `observed_range` across
  >   every plausible AABB, so the operator can see which space the numbers are
  >   in; `screen`/`ndc` apply a concrete bound.
  > - **Plausibility ≠ relevance.** `aabb_plausible` (finite, `min<=max`,
  >   in-bound, radius consistent with the half-diagonal, **and a per-space
  >   size floor**) is the engine-level "is this a real box"; `rect_overlap` is
  >   the query-specific "does it touch the rect". Real bug found in testing: a
  >   first cut without the size floor returned **~348k** hits on an *empty*
  >   process — arbitrary memory is full of runs that decode as valid-but-
  >   sub-pixel boxes passing every other check. A one-pixel (screen) /
  >   one-thousandth (NDC) minimum extent is what makes it a shape test, not a
  >   finiteness test. (`auto` stays deliberately permissive — that's its job.)
  > - **Spatial-diff filter** (`--save-as` / `--exclude-from`, the operator's
  >   own idea): save a query over a rect where the widget is *absent*, then
  >   `--exclude-from` it in a query where the widget is *present*. What's left
  >   drops any ambient/global structure whose (mis)computed box overlaps every
  >   rect. Persisted as a new `ui_locate` dump kind; the exclude set loads
  >   *before* the (tens-of-seconds) scan so a bad name fails fast, not after.
  > - Unit-tested per brief §9.1 (synthetic AABB at a known offset, exact
  >   overlap maths, `FLT_MAX`-sentinel rejection, the real 348k-noise sample,
  >   a flat-z 2D widget accepted). **Not** validated against the live game —
  >   the §9.3 appearance-correlation test needs the running target and is the
  >   remaining acceptance step, called out honestly rather than claimed.

- ⚠️ **Structural-predicate scanning as a first-class primitive** — implemented
  as a core-internal primitive (`n0xis-core::structural`, **not** a standalone
  CLI subcommand), pending live validation *(generalizes
  the above; also fixes a limitation hit repeatedly in the campaign)*. `scan
  aob` cannot express "four dwords where `d0 == d3` and `d1 == d2`", nor "six
  floats forming a valid bounding box" — both were needed and both had to be
  abandoned. AOB patterns match *constants*; what was wanted was *relations*
  between fields.
  **Why**: every localization attempt that failed for lack of expressiveness
  failed here. It is the scanning counterpart to `locate --by-transition`: that
  one encodes *the change is the signal*; this one encodes *the shape is the
  signal*.
  > **Implemented (2026-07-21).** `n0xis-core::structural` (`StructuralScanPass`,
  > `n0xis.scan.structural.v1`): reads a list of typed `FieldSpec`s at each
  > aligned position in a window and hands them to a caller-supplied predicate
  > `Fn(&[ScanValue]) -> Option<f64>` (score), which decides accept/reject by
  > *relations between the fields* rather than any fixed constant. `ui locate`'s
  > AABB test is its first consumer; the mirrored-dword relation
  > (`d0==d3 && d1==d2`) the campaign needed is a unit test. Sound-over-complete:
  > `candidates_tested`/`bytes_scanned` always cover the whole window, so "0
  > matches" can never be confused with "gave up partway" (RE_METHOD F6).
  > **Not** a runnable `scan structural` subcommand — it is `ui locate`'s
  > internal engine. (The guide's `guide_category` now has a `ui` arm, so the
  > `ui *` commands group under "UI-layer localization (Phase 9)" in the
  > auto-catalog rather than "Other".)

- ⚠️ **Agent target-selection tooling — `ui windows` / `ui screenshot` /
  `ui focus`** — implemented and mspaint-verified, **needs real-target testing**
  *(the operator's proposal: an agent driving `ui locate` needs to
  see the target and name a window before it can choose a rect)*. The `ui
  locate` brief's no-pixels rule governs how widgets are *found* (by their data,
  not their appearance); it does not forbid *showing the operator/agent the
  window so they can pick a rectangle* — a distinct, read-only concern.
  - **`ui windows --pid <p>`** — enumerate a process's top-level windows
    (title, class, on-screen rect), so an agent can name the game window rather
    than guess an HWND. Read-only.
  - **`ui screenshot --pid <p> [--out <png>]`** — capture the target window to
    a PNG (or base64 in the envelope) via external Win32 only (no injection, no
    D3D hook). **The load-bearing risk**: GDI `BitBlt`/`PrintWindow` return an
    all-black frame for many DirectX-accelerated windows, and an agent must
    never mistake a black capture for "the UI is empty" — so the command must
    *detect and report* a blank capture rather than hand back a misleading image.
  - **`ui focus --pid <p> --hwnd <h>`** — bring a window forward (window
    selector). Unlike the rest of Phase 9 this is **not** purely read-only (it
    activates a window on the target); it is labeled as such in the command
    contract. Marked "if needed" by the operator.
  > **Implemented (2026-07-21).** `n0xis-sources::window` (behind `live`), wired
  > into both the CLI (`ui windows|screenshot|focus`) and MCP (`ui_windows`/
  > `ui_screenshot`/`ui_focus`, verified via `tools/list`). Backed by a research
  > pass on Windows capture (GDI / PrintWindow / DXGI-DDA / WGC) that decided the
  > dependency budget up front.
  > - **`ui windows`** — `EnumWindows` filtered by pid, best-guess game window
  >   first (visible, non-tool, non-cloaked, largest). Reports all three rects
  >   unambiguously — `rect_window` (raw, DWM-shadow-inflated), `rect_frame`
  >   (`DWMWA_EXTENDED_FRAME_BOUNDS`, the canonical one), `rect_client` (client
  >   in screen coords) — plus per-window DPI, and sets per-monitor-v2 DPI
  >   awareness so coordinates are physical pixels (`meta.coords`).
  > - **`ui screenshot`** — GDI window-DC `BitBlt` + `PrintWindow(PW_RENDERFULLCONTENT
  >   | PW_CLIENTONLY)`, `--method auto|window-dc|printwindow`, into a
  >   client-sized top-down BGRA→RGBA buffer (alpha forced to 255 — the #1
  >   self-inflicted false-black). Ships the **blank-frame contract**: pre-flight
  >   (minimized / cloaked / `GetWindowDisplayAffinity` / off-screen → specific
  >   reason), a luma/distinct-color classifier (`Ok`/`Suspect`/`BlankBlack`/
  >   `BlankUniform`), and a top-level `confidence` (`ok`/`low`/`blank`) so a
  >   near-blank `Suspect` frame is never served as crisp. A blank capture is
  >   returned as `ok:true, data.blank:true` (the envelope's failure arm carries
  >   no diagnostics) with a loud "do not treat as empty UI" note.
  > - **`ui focus`** — `SetForegroundWindow` via the `AttachThreadInput`
  >   workaround (no injection), verified with `GetForegroundWindow` (the return
  >   value lies). An explicit `--hwnd` is checked to actually belong to `--pid`.
  > - **Verified live** on `mspaint`: `ui windows` ranked the paint window first;
  >   `ui screenshot` produced a real non-blank, client-aligned PNG
  >   (`confidence:ok`, 1076×575 matching the client rect); `ui focus` reached
  >   `foreground:true`. Two capture-alignment bugs (window-vs-client origin) and
  >   a conditional DIB leak, found by an adversarial review, were fixed and
  >   re-verified.
  > - **Documented follow-on (the honest gap):** GDI/PrintWindow are **blank for
  >   flip-model / DirectComposition** DirectX windows — which many modern games
  >   are. The correct path there is Windows.Graphics.Capture (or DXGI Desktop
  >   Duplication), which requires the heavy `windows` crate (WinRT/DXGI/D3D11 —
  >   windows-sys has none of it). Not done here; the tool reports the blank
  >   honestly instead, so a flip-model target is a *known, visible* limitation
  >   rather than a silent wrong answer. This is the next rung of Phase 9 —
  >   tracked as its own ⬜ item below.

- ⬜ **Flip-model / DirectComposition capture — WGC or DXGI Desktop Duplication**
  *(promotes the `ui screenshot` follow-on note above from prose to a tracked
  item: "reports blank honestly" is the floor, not the finish line)*. Modern
  DirectX games render flip-model, where GDI `BitBlt`/`PrintWindow` come back
  black; the correct capture path is Windows.Graphics.Capture (or DXGI Desktop
  Duplication), which pulls in the heavy `windows` crate (WinRT/DXGI/D3D11 —
  `windows-sys` has none of it). Scoped as its own item so the dependency-budget
  call — add `windows` only behind the `live` feature, keep the `n0xis-core`
  boundary OS-free — is made deliberately, not smuggled in alongside something
  else. Until it lands, a flip-model target stays a *known, visible* limitation
  rather than a silent wrong answer.

- ⬜ **Exit test — the live acceptance gate that flips ⚠️ → ✅.** The §9.3
  appearance-correlation test on a **running DirectX game** (per the brief): open
  a UI element at a known screen rect, `ui locate --rect` it, then move/toggle the
  element and confirm the returned addresses track its real bounding box — and
  that the spatial-diff `--exclude-from` flow drops ambient structure. This is the
  single outstanding step for the whole phase: every ⚠️ item above reads
  "implemented, pending live validation" *because this has not been run yet*. No
  synthetic substitute counts — passing unit tests and an mspaint capture are
  necessary, not sufficient (the exact lesson Phase 7's ARM64 caveat records).

---

## Phase 10 — Decompiler analysis depth (true x64 parity with other tools) 🎯 ⬜

The honest reframing this phase exists to encode: **parity with another tool /
another tool is not the presence of components — it is analysis quality.** N0xis already
has the full *plumbing* (decode → CFG → dominance → SSA → optimize → structure →
render), and on that plumbing it holds x64 parity. But a real decompiler is the
*90%* that comes after: the long tail of interprocedural analysis, memory
modeling, and compiler-idiom coverage that turns "we built SSA" into "we chewed
ten years of edge cases." On *that* axis N0xis is early even restricted to x64.
This phase is that work. It is deliberately **not** one sprint; sequence by
leverage, ship incrementally, and never mark a dimension done until it holds on a
real x64 corpus (not synthetic samples).

### Where we stand (capability maturity)

Legend: ✅ production · 🚧 partial / early · ❌ missing.

| Component | Status |
|---|---|
| Decode (x64, iced-x86) | ✅ production |
| CFG | ✅ production *(but see the CFG-fidelity debt in priority 0)* |
| Dominance / SSA | ✅ production |
| Control structuring | ✅ production |
| Optimizer (copy/const/expr-prop, DCE) | ✅ production |
| Renderer (pseudo-C) | ✅ production |
| Switch / jump-table recovery | ✅ present — 2 x64 idioms, memory-resolved (narrower idiom set than other tools) |
| Type recovery | 🚧 **per-function** — typed locals block, phi-web coalescing, struct-field/arity/return + ~30 API sigs + **C++ class from RTTI** (`this` typed to its class, vtable naming, template demangling, **inheritance graph**). **Whole-program type propagation** (a recovered struct flowed to every function that uses it) is the core gap vs other tools |
| Alias analysis | 🚧 **intraprocedural points-to** — escape analysis (2a), global distinct-constant (2b) and **heap-allocation** (2c) disambiguation; `Top` on loads through unknown pointers. Whole-program/distinct-parameter points-to still missing |
| Tail-call detection | ✅ 2026-08-06 — edge class **+ semantic promotion** (`jmp func` and IAT-thunk `jmp [__imp_X]` lower to `call`+`return`, render `return f(...)`); verified on real PEs |
| noreturn analysis | ✅ import calls (`ExitProcess`/`abort`/`_CxxThrowException`/…) end a block **and the function** (2026-07-22, firing on real binaries 2026-08-06 via the IAT-keying fix); ✅ whole-`.pdata`-set noreturn **detection** — `call`- *and* `jmp`(tail-call)-to-noreturn — verified on a real binary (`function noreturn`, 2026-08-29 — `CompressToolsLib.dll`: 10 functions incl. a `jmp TerminateProcess`, cross-checked); ⏳ the call-graph **propagation** step (a `sub_XXXX` flagged via another flagged `sub_XXXX`) fired in 0/14 real DLLs, unit-tested only, pending a real-corpus positive |
| Import-name resolution | ✅ 2026-08-06 — direct, IAT-slot and thunk callees resolve to `module!name`; imports render by name and reach the known-API signature table |
| Compiler-idiom recovery | 🚧 growing — `const identify`, junk, opaque predicates, **stack-canary, `min`/`max`, magic-division, rotates, `cmov`→`?:`, full intrinsic layer (SSE/bit-scan/FP), BMI/BMI2** (Rung 5b–5i) |
| Memory SSA | ✅ Rung 1 — intra- and cross-block store-to-load forwarding + dead-store elimination, on escape analysis; verified on real Win64/MSVC and Linux/GCC |
| Interprocedural propagation | 🚧 partial — whole-program noreturn IPA + call-site name/ABI resolution; **whole-program type propagation still missing** (the core remaining gap) |
| Exception-edge recovery | ❌ missing — `.xdata` parsed for unwinding only |
| Indirect / virtual call resolution | 🚧 partial — RTTI vtable constants **named** (`&Class::vtable`), `this` typed to its class; last-hop **devirtualization** (slot→method) still ⬜ (needs whole-program `this`-type flow) |
| SIMD / FP lift | ✅ Rung 5c/5h — SSE data moves as 128-bit ops + a full intrinsic layer (packed/scalar FP, pack/shuffle, conversions); FP *compares* left opaque |
| PDB / type ingestion | ❌ missing (corpus is stripped game builds — deliberately low priority) |
| C++ RTTI / vtable / class recovery | ✅ Rung 7a — MSVC RTTI scan, vtable naming, `this`-typing, **full template demangling, base-class inheritance graph** (Kenshi 3055 / STALKER 2 561 vtables). Whole-program class-graph propagation into every method still ⬜ |
| Library-function identification (FLIRT-class) | ❌ missing — statically-linked CRT/STL/runtime code is decompiled by hand; `sig validate` is the primitive, but there is no shipped signature library or auto-apply |
| Calling-convention & argument recovery | 🚧 early — arity + return only; CC is *assumed* x64-fastcall, no `this`call/vectorcall/variadic detection |
| Stack-frame reconstruction (SP-delta, FPO) | 🚧 partial — locals recovered, but no explicit frame model, no frame-pointer-omission handling, no stack arrays/spills as typed variables |
| Output readability (goto-elim, `&&`/`\|\|`, `?:`, loop forms) | ✅ Rung 6 — `switch`, `&&`/`\|\|`, `?:`, `if`/`else if`, `for`/`while`/`do-while`, tail-duplication (residual gotos ~halved). Residual shared-body gotos on irreducible merges remain |
| Signedness recovery | 🚧 Rung 3f/5 — signed vs unsigned comparisons render distinctly; stack-local signedness inferred from use. Register-variable signedness still ⬜ |
| Global / data-segment typing | 🚧 early — `xref`/`xref string` exist, but globals are untyped and data-flow does not reach the decompiler |

### Where other tools still lead — the honest gap map (2026-08-31, v0.2.1)

With Rungs 1–7a landed, the *local* decompilation quality is measured against the
free other tools on x64 (cleaner ABI-stripped output, C++ RTTI class + inheritance
recovery, alias 2a/2b/2c). What another tool and another tool still lead on is **not**
per-function analysis — it is breadth, scale, and surface:

- **Whole-program type propagation — the one *core-decompilation* gap.** N0xis
  recovers types **per function**; a `struct_rcx_0` recovered in one function is
  not yet flowed to every other function that touches the same object. other tools
  keep a persistent, call-graph-wide type database that binds hundreds of
  functions into one class model. This is the next big rung (see priority 3 →
  extended below) and the honest reason "massive C++" still favours other tools.
- **GUI — "eyes and hands."** Graph view, click-to-rename, an interactive type
  manager, xref navigation, instant re-analysis, undo. N0xis is headless
  (CLI/MCP) by design; a GUI is deferred, not ruled out, and can be built over
  the JSON/MCP surface.
- **Architecture breadth.** N0xis: x64 (mature), i386, AArch64 (early), AArch32
  (new). another tool (~40 ISAs via SLEIGH) and BN cover MIPS/PPC/RISC-V/SPARC and the
  long tail. See the strategy below — this is a *seam* question, not a rewrite.
- **File formats.** PE + ELF today; no Mach-O, no firmware loaders. A format
  seam (Phase 15 debt) closes this the same way `trait Arch` closed the ISA one.
- **Maturity on adversarial / varied code** and a plugin/type-library ecosystem
  (another tool GDT, FunctionID/FLIRT, OOAnalyzer; the reference implementation's Python object model). N0xis is
  young; `sound over complete` keeps it honest, but idiom/edge-case coverage is
  narrower and there is no shipped signature/type-library yet.

Everything above is breadth/scale/surface **except** whole-program type
propagation, which is the single remaining *core* decompilation gap — so it
ranks first among the additions.

### Overcoming the architecture-breadth limit — the seam strategy

Arch breadth is two separable costs, and only one is expensive:

- **Decode** is cheap — a Rust decoder crate per ISA behind the existing
  `trait Arch` seam (already: iced-x86 for x64/i386, disarm64 for AArch64,
  yaxpeax-arm for AArch32; the yaxpeax family also ships mips/ppc/riscv decoders).
- **Semantics (the lift, decoded-insn → MicroIR)** is the real per-arch work.

Two ways to pay it, and they compose:

1. **Hand-lift the few high-value ISAs** (current path) — premium, sound,
   `O(arch)` effort. Worth it for RISC-V (small, clean, rising) and MIPS
   (consoles/embedded); each is far smaller than x64.
2. **Ingest another tool SLEIGH → P-code → MicroIR — the breadth multiplier.** SLEIGH
   is a declarative ISA-semantics language with **~40 shipped specs**; one
   `SleighArch` backend behind `trait Arch` that loads a `.sla` and lowers P-code
   to MicroIR unlocks the whole matrix at "sound-but-generic" quality, while the
   hand-lifted arches stay premium. This is exactly the modular-on-the-Code-seam
   principle: SLEIGH is just another `Arch` plugin. (Apache-2.0 specs; the lower
   is P-code→MicroIR, a bounded one-time integration.)

**VMs/emulators (Unicorn/QEMU/Qiling) are orthogonal — dynamic, not static.**
They *execute* foreign-arch code; they do not produce pseudocode, so they do not
substitute for a lifter. Where they *do* expand reach: (a) the **live-analysis
seam on non-x86 devices** (e.g. the ARM TV-box), (b) the **concolic/symbolic
engine** (Rung 7 / item 12) for deobfuscation and computed-target resolution, and
(c) a differential oracle to validate a new lift against real execution. So the
answer to "expand via VMs?" is: **yes for the dynamic and verification sides, no
for the static decompiler** — the static path still needs a decoder + a
lift/SLEIGH-ingest per ISA.

### The gap in detail (what parity actually requires)

| Analysis | What real parity needs | N0xis today |
|---|---|---|
| Exception edges | parse `.xdata` EH handlers → try/catch/finally edges in the CFG | ❌ `.pdata`/`.xdata` read for **unwinding only**; no EH edges in the graph |
| Tail-call detection | recognize `jmp func` as call+return, resolve callee, render `return f(...)` | ✅ *(2026-08-06)* both shapes — a direct `jmp` out of the function **and** an import thunk's `jmp qword ptr [__imp_X]` (previously mis-classified `ijmp`, "indirect jump (unrecovered)") — terminate as `tail-call` and lower to `call`+`return` via the new `Arch::lift_tail_call` seam, so every style renders `return f(...)`. Verified on real PEs (`version.dll` thunk → `return …GetFileVersionInfoSizeW(…)`; 15/400 notepad, 52/400 dxgi functions carry the `tail` flag) |
| noreturn analysis | detect + **interprocedurally** prune fall-through in callers | 🚧 ✅ *(2026-07-22)* a call to a well-known noreturn import (`ExitProcess`/`abort`/`TerminateProcess`/`_CxxThrowException`/`__fastfail`/…, `n0xis-core::noreturn`) now ends its block like a `ret` (`terminator: "call-noreturn"`, zero successors) — closes the CFG so `ir manifest`'s pre-existing `no-return` flag becomes accurate for free on this case. ✅ *(2026-08-06)* `truncate_to_function` (the whole-function-end heuristic) now knows about calls too, so a function no longer over-extends past a noreturn call — and the whole mechanism fires on real binaries for the first time (it needed the IAT-keying fix; `vcruntime140.dll` 0 → 33 functions flagged `calls-noreturn`). ⏳ *(2026-08-29)* **whole-program propagation** — the `NoReturnPropagatePass` call-graph fixpoint (`function noreturn`) is built and feeds `Ctx::with_noreturn` back into CFG fall-through pruning; sound-over-complete. **Detection** is verified on a real binary (`CompressToolsLib.dll`: 9 functions, cross-checked via `ir build`); the **propagation** step itself is unit-tested only and awaits a real-corpus positive before ✅. **Still open**: a *tail-call* to a proven-noreturn function (read conservatively as returning today). |
| Indirect call resolution | devirtualize `call [reg+off]` via vtable/type analysis | ❌ only IAT/direct resolved; value-set gives `Top` on loads |
| Switch recovery | many idioms (dense / sparse / multi-level / bounds-checked) | ✅ 2 x64 idioms, memory-resolved, `code_range`-gated |
| Jump-table recovery | + relocation-aware | ✅ same 2 idioms; narrower than other tools |
| Alias analysis | a real memory-alias oracle | 🚧 light/bounded (`ValueSetPass::alias`, `Var±Const` only, `Top` on load) |
| Memory SSA | SSA over memory (versioned store/load) | ❌ SSA over registers/flags only — **why** expr-prop is conservative |
| Interprocedural propagation | types / values / CC across the call graph | ❌ intraprocedural; only the ~30-entry API table crosses a call |
| Compiler idioms | magic-division, `rep`-string→`mem*`, stack canary, strlen-inlining, cmov→min/max, SSE idioms, … | 🚧 a handful (`const identify`, junk, opaque predicates) |
| C++ RTTI / vtables | parse MSVC (`RTTICompleteObjectLocator`, `type_info`) and Itanium RTTI → class names, base-class graph, vtable→method typing; feed devirtualization | ❌ none — the single biggest lever for a C++ game corpus (another tool "class informer", another tool RTTI analyzer) |
| Library-function ID | a signature DB (another tool FLIRT / another tool Function-ID) that names statically-linked CRT/STL/runtime code instead of decompiling it | ❌ `sig validate` supplies the invariance primitive; no shipped library, no auto-apply pass |
| Calling convention | classify the CC and recover arg count/types by entry-liveness + call-site agreement; detect variadic and `this` | 🚧 arity + return only; CC assumed, so an un-prototyped function renders guessed arguments |
| Stack frame | SP-delta tracking across the function, FPO-function handling, stack arrays/spills surfaced as typed locals | 🚧 locals only; no frame reconstruction, no FPO |
| Readability | eliminate gotos, recover `&&`/`\|\|` from short-circuit CFG diamonds, `?:`, and `for`/`while`/`do` + `break`/`continue` | 🚧 structures reducible CFGs; the readability passes other tools polished for a decade are not built |
| Signedness | infer signed/unsigned from flag use and operation shape; render the right operators and casts | ❌ none |

### Prioritized plan (ordered by leverage × cost, not size)

0. ⏳ **CFG fidelity — the correctness debt. Do this first.** Interprocedural
   `noreturn` propagation, tail-call promotion, exception edges. It is *cheap* —
   the data already exists (`.xdata` is already parsed for the unwinder; `no-return`
   and `tail` are already computed) — and it is **correctness, not prettiness**.
   Memory SSA over a wrong CFG is precise nonsense: for a *sound-over-complete* tool
   (CONCEPT §3 rule 6), a wrong control graph yields *confidently-wrong* C, which is
   worse than an honest `asm` node.
   - ✅ *(2026-07-22)* **Known-noreturn-import CFG fix landed** — a call to a
     well-known noreturn API (`ExitProcess`/`abort`/`TerminateProcess`/
     `_CxxThrowException`/`__fastfail`/…, new `n0xis-core::noreturn`, mirroring
     `signatures.rs`'s table shape) now ends its block (`terminator:
     "call-noreturn"`, zero successors, new `CfgStats.noreturn_calls`) instead of
     treating dead bytes after it as reachable. Required fixing a real,
     independently-discovered gap along the way: `target_name` resolution only
     ever consulted `ins.target` (a direct near-branch operand), never
     `ins.rip_target`/`SymbolProvider::iat_slot` — so the overwhelming common
     case (an import called through the IAT, `call qword ptr [rip+disp]`) never
     resolved a name at all; fixed with an `.or_else` fallback at the same site.
     Wired into `structure.rs`'s post-dominator exit-set (load-bearing — a
     noreturn-call block with zero successors must be a recognized graph exit or
     `ipdom` corrupts silently for blocks that dominate it) and its goto-render
     arm, plus `decomp.rs`'s flat-goto renderer, plus a new `manifest.rs`
     `"calls-noreturn"` triage flag. 8 new tests (2 in `noreturn.rs`, 3 in
     `ir.rs` — including one proving the IAT/`rip_target` fallback fires via a
     new `Snapshot::iat_symbol` test builder — 1 in `manifest.rs` proving the
     existing `no-return` flag becomes accurate for this case for free, plus
     the pre-existing suite unchanged), `n0xis-core` lib tests 114→122, zero
     regressions. **Still open, this pass deliberately didn't attempt**:
     propagating noreturn-ness across N0xis's *own discovered* functions (a
     whole-program call-graph fixpoint — the deeper, second noreturn sub-item);
     `truncate_to_function` (the whole-function-end heuristic) still doesn't
     know about calls, so a function's reported `end` may still over-extend past
     a noreturn call even though the per-block CFG is now correct; tail-call
     promotion and exception-edge recovery (this bullet's other two sub-items)
     are untouched.
   - ✅ *(2026-08-06)* **Tail-call promotion + the two bugs that made the
     2026-07-22 fix dead on real binaries.** Three landings, in the order they
     were found:
     1. **Tail-call promotion.** `jmp` leaving the function used to lift to
        *nothing* (the CFG edge was the whole story), so a `tail-call` block
        rendered no terminator at all — the call and its returned value were
        silently dropped from the pseudo-C. New `Arch::lift_tail_call` seam
        (default = `lift`, i.e. no promotion, so ARM64 stays honest rather
        than synthesizing a call it can't lower; x64 overrides) lowers it to
        `Call` + `Return`, and `LiftPass` routes a `tail-call` block's
        terminating instruction through it. Every style now renders
        `return f(...)`; the optimizing styles collapse it to one expression.
        Also recognized: an **import thunk** (`jmp qword ptr [__imp_X]`) is a
        tail call, not an unrecoverable `ijmp` — the branch is indirect but
        the callee is known by name. `truncate_to_function` now also ends a
        function at a noreturn call (the follow-on the 2026-07-22 pass
        explicitly left open).
     2. **The IAT map was keyed by the wrong address — so *no* import name
        ever resolved on a real PE.** `StaticPe` keyed its IAT map by goblin's
        `Import::rva`, which is the *hint/name-table* entry, not the IAT slot
        (that's `Import::offset`, an RVA despite the name). Every consumer of
        callee names was therefore dead on real targets while passing its
        synthetic unit tests: the noreturn CFG closure above, the ~30-entry
        known-API signature table, thunk recognition. One-line fix; the effect
        is corpus-wide (`vcruntime140.dll`: **0 → 33** functions flagged
        `calls-noreturn`). The lesson is the Phase 7 ARM64 lesson again —
        a synthetic `Snapshot` fixture proves the *code path*, never the
        *data*.
     3. **The IR cache served pre-upgrade artifacts.** `cfg_cache_key` hashed
        the target (label + input + bytes) but nothing about the *analyzer*,
        so an improved pass was masked by its own cache — the exact stale-data
        failure CONCEPT §3 rule 6 forbids, and it cost real debugging time
        here. The key now includes an analysis fingerprint (crate version +
        the running executable's mtime): stable across runs of a released
        binary, automatically different after every rebuild.
     Plus: an import call now renders by **name** (`kernel32__CloseHandle(…)`)
     instead of `(*(uint64_t*)(0x14002a3e8))(…)` — the new `Callsite.via_slot`
     (optional, additive to `n0xis.ir.cfg.v1`) carries the slot the callee was
     reached through, which also lets the known-API signature table fire on
     IAT calls for the first time; and a module name is now sanitized into a
     valid C identifier (`api-ms-win-…dll!X` was rendering dashes and dots
     into "pseudo-C"). 9 new tests (3 `ir.rs`, 2 `x64_lift.rs`, 3 `render.rs`,
     1 `decomp.rs`), `n0xis-core` lib 131→138, `n0xis-arch` 22→24, workspace
     green, clippy clean. **Still open in this bullet**: whole-program
     noreturn propagation across N0xis's own discovered functions, and
     exception-edge recovery.
   - ⏳ *(2026-08-29)* **Whole-program noreturn propagation — the call-graph
     fixpoint.** The deeper noreturn sub-item the two passes above left open. A
     game rarely calls `ExitProcess`/`abort` directly; it wraps them in its own
     `FatalError`/`Assert`/`Panic` helper — a stripped `sub_XXXX`, not a named
     import — and calls *that* everywhere, so until the wrapper is itself known
     noreturn every caller kept a dead fall-through. New
     `crate::NoReturnPropagatePass` (`crates/n0xis-core/src/noreturn_ipa.rs`)
     runs a **monotone fixpoint over the call graph**: a function *returns* iff
     its CFG has a reachable returning exit (a `ret`, or any exit it cannot
     prove non-returning); seed with the noreturn imports, then re-derive every
     function's CFG with the growing noreturn set fed in via the new
     `Ctx::with_noreturn`, so a `call` to a now-known-noreturn `sub_XXXX` ends
     its block exactly like a `call ExitProcess`. Repeats until no function
     flips — the set only grows and each function flips once, so it converges in
     ≤ *N* rounds. **Sound over complete**: a function is flagged only when
     *provably* noreturn (every ambiguous exit — a tail-call, an unresolved
     indirect branch, an edge leaving the analyzed window — is read as "may
     return"), so the pass prunes only dead paths, never a live one. Exposed as
     `function noreturn` (CLI + MCP + registry capability
     `n0xis.function.noreturn.v1`), which prefers the exact `.pdata` function
     table over a prologue scan so the whole-program set is actually
     whole-program (3 425 functions enumerated on a real `ucrtbase.dll`). 4 new
     tests (direct wrapper, 2-level chain propagation, a returning function is
     not flagged, and the flagged set feeding back into a caller's CFG closure).
     **Verification status (why this is ⏳, not ✅).** noreturn *detection* over
     the whole `.pdata` function set is **verified on a real binary**: on
     `CompressToolsLib.dll` (Kenshi) it flags 9 functions, each cross-checked
     with `ir build` to be a single `call-noreturn` block ending in
     `_invalid_parameter_noinfo_noreturn` with no reachable `ret`. But every one
     of those 9 is a *direct import caller*. A follow-up added **tail-call →
     noreturn** handling (MSVC compiles a throw/abort wrapper as `jmp <helper>`,
     not `call; ret`; the old pass read every tail-call as "may return"),
     verified on the same binary — a 10th function, `0x18001e3ac`, is now flagged
     because its sole exit is `jmp TerminateProcess` (cross-checked with
     `ir build`). But every flagged function across **14 real x64 C++ DLLs**
     (Kenshi's OGRE stack, CompressToolsLib, …) is still a *direct* import/tail
     caller — the novel cross-function **propagation** step (a `sub_XXXX` flagged
     because it calls another flagged `sub_XXXX`) fired in **0 of 14** and is so
     far only **unit-tested on a synthetic chain** (`rounds == 2` is a
     confirmation round, *not* proof propagation fired). This is itself a real
     finding: on this corpus the noreturn wrappers are *leaves* — compilers
     rarely emit a function whose only exit is a call to another noreturn helper.
     Per the project rule — ✅ only on a real-data *positive* — the propagation
     step stays ⏳ until a genuine instance is confirmed on a real binary.
     **Still open in priority 0**: exception-edge recovery (`.xdata` EH handlers
     → try/catch/finally edges).
1. 🚧 **Memory SSA — the representation that lifts the stop-crank.** Expression
   propagation is conservative *today only because* nothing can prove a load/call
   safe to move past a store. Memory SSA is what unblocks everything downstream.
   Built incrementally — see **the analysis-depth staged plan** below; stage
   **1a (intra-block store-to-load forwarding) is landed and verified**
   *(2026-08-29)*.
2. ⬜ **Light points-to / alias, on top of Memory SSA.** Co-evolves with type
   recovery — chicken-and-egg: alias precision needs types, type recovery needs
   alias. Climb 1–2 together; neither is precise alone.
3. ⬜ **Function-summary IPA + whole-program type propagation — now the #1 core
   gap vs other tools.** Two layers. (a) **Summaries**: per-function returns /
   `noreturn` / clobber set / arg & return types / side effects — composes with
   the existing `ManifestPass`, an extension not a new subsystem. (b) **Whole-program
   type propagation** (the layer other tools lead on): a persistent, call-graph-wide
   type store so a `struct` recovered in one function — or a class recovered from
   RTTI — is *flowed to every function that touches the same object* (callee arg
   types ⇄ caller arg values, return types ⇄ consumers, field layouts unified
   across all users). This is what turns N0xis's *per-function* type recovery
   (Rung 3, verified) into the one class model over hundreds of functions that
   other tools build — the honest reason "massive C++" still favours them. Builds on the
   RTTI class graph (Rung 7a) + the summary layer here; it is the single remaining
   *core-decompilation* gap (everything else other tools lead on is breadth/GUI/
   maturity — see "Where other tools still lead" above), so it ranks first.
4. ⬜ **SIMD / FP lift — a floor-fixer for *this* corpus.** For a *general*
   decompiler this is mere coverage (rank low). For N0xis's corpus (game engines)
   it is a floor problem: `movaps`/`mulps`/`addps`/`sqrtss`/`movss` appear every few
   lines, and today those functions decompile half to `asm` nodes. Ranked up
   accordingly.
5. ⬜ **PDB / type ingestion — corpus-dependent rank.** High value for
   system/Microsoft binaries (public symbol servers short-circuit type recovery with
   ground truth); **low for stripped game builds**. Rank it above SIMD for system-DLL
   work, below it for game work.
6. ⬜ **Compiler-idiom library — the endless backlog.** The "hundreds of idioms"
   that are 20 years of a source-level decompiler/another tool rules. Each idiom is independent and
   individually cheap; grow the library continuously. Never "done."
7. 🚧 **C++ RTTI / vtable / class recovery — the highest-leverage addition for
   *this* corpus.** Game engines are deep-hierarchy C++ with pervasive virtual
   dispatch, and the class graph is *already in the binary*: MSVC RTTI
   (`RTTICompleteObjectLocator` → `type_info` → base-class array) and Itanium RTTI
   encode names, bases and vtable layout directly. Parsing it names classes, types
   each vtable slot to its method, and — composed with priorities 0–1 — turns
   `call qword ptr [rax+0x40]` into a *resolved* virtual call, closing the ❌
   "indirect / virtual call resolution" gap the value-set pass cannot. It is both a
   substantial feature (another tool's class informer, another tool's RTTI analyzer) and a
   floor-raiser specific to the corpus, so it ranks at the top of the additions.
   - ✅ *(2026-08-30, verified)* **RTTI scan → decompiler composition.** The
     `rtti scan` COL→TypeDescriptor walk is now threaded onto `Ctx` as a
     vtable-address → class-name map (frontend scans `.rdata` once), and two
     consumers turn it into readable C++: **(a)** a vtable constant renders
     `&Class::vtable` instead of an opaque `(void*)0x…`, naming the object a
     store initializes; **(b)** a function that installs a vtable into `*this`
     at offset 0 — the constructor — types that parameter as the class, so
     `struct_rcx_0 *rcx` reads `std::exception *rcx`. Sound on non-MSVC/non-PE
     targets (no `.rdata` ⇒ empty map ⇒ output unchanged; **verified zero on
     Factorio ELF**). **Verified on three PE/MSVC binaries:** Kenshi
     `CompressToolsLib.dll` — 94/815 functions carry a named vtable across 27
     classes (`std::exception`@0x180021548 cross-checked vs `rtti scan`; user
     classes `FileIOStream`/`WaveletDecodeLayer`/…), `sub_1800010d0` →
     `std::exception *rcx`; Kenshi `kenshi_x64.exe` — 24/60 with
     `AnimationEvent`/Ogre allocators; **STALKER 2 (UE5)** `Stalker2-Win64-Shipping.exe`
     — 561 vtables (432 cleanly demangled ICU classes), `sub_140cecb83` →
     `icu_64::GregorianCalendar *rcx` with `*rcx = &icu_64::GregorianCalendar::vtable`.
   - ✅ *(2026-08-30, verified)* **Full templated-name demangling.** A RTTI
     TypeDescriptor name for a template is wrapped back into its `??_R0<type>@8`
     symbol and run through the real MSVC demangler, so `.?AV?$vector@H@std@@`
     reads `std::vector<int>` instead of the verbatim decorated form — the case
     Gemini flagged as where other tools win. **Verified corpus-wide:**
     CompressToolsLib 30/30 demangled, STALKER 2 561/561, `kenshi_x64` 2989/3055
     (the 66 the MSVC demangler itself declines fall back to verbatim — sound);
     `sub_180003f70` decompiles
     `&std::basic_ifstream<unsigned char, struct std::char_traits<unsigned char> >::vtable`.
   - ✅ *(2026-08-30, verified)* **Base-class / inheritance graph.** Each COL's
     `RTTIClassHierarchyDescriptor` → base-class array → `BaseClassDescriptor`s
     → `TypeDescriptor`s is walked to reconstruct a class's bases (most-derived
     first, self excluded), added to `rtti scan`'s output as `bases`. The
     inheritance tree the binary already carries — `class Derived : Base` —
     recovered statically, the "complex C++ class tree" capability. Sound
     (out-of-`.rdata` entries skipped, bounded by `MAX_BASES`) and **verified
     against known-correct ground truth:** CompressToolsLib
     `std::bad_array_new_length : std::bad_alloc, std::exception`,
     `std::basic_ifstream<> : std::basic_istream<>, std::basic_ios<>,
     std::ios_base, std::_Iosb<int>`; STALKER 2 (UE5) 516/561 vtables carry
     bases — `GregorianCalendar : Calendar, UObject, UMemory`,
     `StringCharacterIterator`'s five-level ICU chain.
   - ⬜ Still open for this item: **virtual-call devirtualization**. Measured on
     the corpus (Kenshi `CompressToolsLib`, ~210 indirect-call sites / 200
     functions): the virtual calls dispatch through a **runtime** vtable pointer
     (`rax = *this; call [rax+k]`), not a constant — so statically resolving the
     slot would be **unsound** (a derived class overrides it), which rule #1
     forbids. The soundly-resolvable slice (`call [&Class::vtable + k]`, a
     *constant* vtable — inside a constructor after the vtable store, once
     store-to-load forwarding exposes it) does not visibly fire here (the
     compiler already de-virtualizes in-constructor calls). Sound devirt
     therefore needs precise `this`-type flow across *all* methods — call-site
     class propagation / points-to (**Rung 2**), not a local pattern — so it is
     correctly gated on that, not a quick win. Also open: feeding the recovered
     **bases into the decompiler** (type a `this` as the `Derived : Base` chain),
     and **Itanium RTTI** for ELF/GCC targets.
8. 🟡 **Library-function identification (FLIRT-class signatures) — the biggest
   time-lever.** A release build is a large fraction *known* code: the CRT, the
   STL, the runtime, statically linked in. Fingerprinting it (another tool FLIRT / another tool
   Function-ID) names `memcpy`, `std::_Tree::_Insert`, `operator new` instead of
   decompiling them by hand — the single change that most shrinks what a human must
   read. N0xis already ships the invariance primitive (`sig validate`, refusing
   <3 independent samples); this item is the *signature library* plus the auto-apply
   pass over it. High ROI and independent of the memory-SSA track, so it can land
   early and in parallel.
   - ✅ **Rung 10a — own matcher + `.npat` format + auto-apply seam.** The
     `n0xis-flirt` crate (dependency-free, crates.io-shippable) is the matcher:
     pattern+wildcard byte fingerprints, most-specific-wins, ambiguity→`None`
     (sound over complete — a wrong name is worse than none). `FlirtSymbols`
     exposes it through the existing `SymbolProvider` seam, chained *below* the
     real exports/imports/IL2CPP index so a genuine symbol always wins and FLIRT
     only fills the `sub_XXXX` gaps. Wired end to end: `decomp … --flirt <db.npat>`.
     A signature-named function renders by its **bare** name (`free`, not
     `CompressToolsLib.dll!free`) — the `module!` prefix is now imports-only, since
     a statically-linked function is *local* to the image. **Verified on a real
     target:** a `.npat` signing the free-thunk at `0x18001d84c` turns
     `sub_18001d84c(rcx, rdx.2, r8.1, r9.1)` into `free(/*ptr*/ rcx)` in
     `CompressToolsLib.dll` (bare name, correct arity), while the same decomp
     without `--flirt` still shows `sub_18001d84c` — the difference is genuinely
     the matcher.
   - ✅ **Rung 10b — `sig gen`: learn a signature library from a symbolized
     image.** The generator that turns any *symbolized* binary (an ELF with a
     `.symtab`/`.dynsym`, a PE with exports) into a `.npat` database, so the
     corpus no longer has to be hand-authored. For each named function it decodes
     the leading bytes (`--window`, default 32) and wildcards exactly the bytes a
     linker varies: a relative call/jump displacement (the trailing 1/4 bytes,
     confirmed by reconstructing the target) and a RIP-relative displacement
     (`rip_target − (va+len)`, located by its little-endian value in the
     instruction). A relocation it cannot place soundly *truncates* the pattern
     rather than leave a varying byte fixed; a trailing displacement is trimmed;
     absolute immediates stay fixed (conservative — a cross-binary miss, never a
     false name). `--min-fixed` drops signatures with too little concrete code.
     Sound over complete throughout. **Verified end to end on a stripped ELF:**
     `sig gen` on a symbolized build emits patterns for `adler_mix`/`greet`/`main`
     (wildcarding their `jcc`/`call`/RIP displacements); after `strip --strip-all`,
     `decomp … --flirt <gen.npat>` re-derives every one of those names — `greet`
     is named `greet` and its body calls `adler_mix(…)`, `main` calls `greet(…)` —
     purely from the generated signatures, while the same stripped decomp without
     `--flirt` shows only `sub_XXXX`. Three unit tests pin the wildcarding
     (relative-call, RIP-relative, trailing-trim).
   - ✅ **Rung 10c — first shipped OSS corpus + `sig gen` glue filter + the
     commercial licensing model.** `signatures/` now carries a real, verified
     starter database with the capa-style hygiene a commercial product needs.
     `sig gen` gained a default filter that drops compiler/linker scaffolding
     (`_init`, `register_tm_clones`, `frame_dummy`, PC thunks — byte-identical in
     every binary, pure noise), overridable with `--include-glue`. **Verified
     coherently (PIC↔PIC, cross-file):** a corpus generated from a from-source
     `-fPIC` build of **zlib v1.3.1**'s shared `libz.so` (118 signatures after
     glue-filtering) names `compress`/`crc32`/`uncompress`/`adler32` in a *separate*
     stripped PIE binary that statically links the same zlib — while the same
     stripped decomp without `--flirt` shows only `sub_XXXX`. Soundness re-proven:
     `uncompress` stayed anonymous when the reference did not contain it. Shipped:
     `signatures/samples/zlib-1.3.1-x86_64.npat` + `NOTICE` (zlib license) +
     `README.md` (provenance, the capa "not derived from any other reverse-engineering tool sigs"
     disclaimer, and the generate-locally model for proprietary libs) +
     `generate.sh` (reproduces the sample from the pinned upstream tag). OpenSSL
     libcrypto 3.6.4 also generates cleanly (5888 signatures) but is left
     generate-locally rather than committed as a machine-specific blob.
   - **Licensing model (researched, sourced — commercial).** What we *redistribute*
     is the constraint, not the engine. Safe to ship: OSS-generated corpora
     (zlib/OpenSSL/Qt), WARP-format reuse (Vector 35, Apache-2.0), another tool `.fidb`
     under Apache-2.0 with attribution, and readers for user-supplied sig files.
     Kept generate-locally (user runs `sig gen` on their own licensed toolchain,
     we ship nothing derived): **MSVC CRT/STL**. Never shipped: another tool's bundled
     `.sig`. FLIRT-signature copyright is genuinely unsettled (no case law); a
     lawyer should read the FLAIR toolkit license and the exact VS License Terms
     before any proprietary-derived corpus is distributed.
   - 🟡 **WARP interop (Vector 35's Apache-2.0 cross-tool format).** Where FLIRT
     matches leading *bytes*, WARP identifies a function by a **structural GUID**
     so it survives relocation/link-address changes. Being an open, Apache-2.0
     interchange format, it is the legal bridge to a whole external signature
     ecosystem (lowest-risk reuse after our own OSS corpora — see the licensing
     model above).
     - ✅ **Rung 11a — the WARP GUID primitive (clean-room, byte-compatible).**
       New `n0xis-warp` crate: `function_guid` / `basic_block_guid` as WARP
       defines them — `UUIDv5(NAMESPACE_FUNCTION, ‖ block GUIDs)` over
       `UUIDv5(NAMESPACE_BASIC_BLOCK, normalized_bytes)` — on a **dependency-free**
       SHA-1 + UUIDv5 (same zero-supply-chain discipline as `n0xis-flirt`, which a
       commercial product wants). **Verified byte-for-byte against Vector 35's own
       `warp` crate (v1.0.1):** golden GUIDs generated by their implementation
       (`bb(90 90)=9f28527a…`, `fn[bb,bb]=382ab4b9…`) are pinned as unit tests, so
       ours is genuinely *interoperable*, not merely self-consistent; the SHA-1
       and UUIDv5 layers are pinned to the RFC 3174 / RFC 4122 vectors too.
     - ✅ **Rung 11b — WARP container reader.** Reads a real `.warp` file
       (FlatBuffers `File→Chunk→SignatureChunk→Function{guid,symbol.name}`, with
       the zlib-compressed chunk payload) into its `(GUID, name)` table, via a
       hand-written, strictly bounds-checked FlatBuffers parser — so it pulls in
       only `flate2` (already in the tree), no `flatbuffers`/codegen dependency.
       **Verified byte-for-byte against Vector 35's reference:** reading their
       `random.warp` fixture reproduces its `dumper` output for all 100 functions
       exactly, and truncated inputs return `None` rather than panicking (the
       OOM/untrusted-length rule). Exposed as `n0xis warp dump --file x.warp`.
       (Writer + type chunks: later, when a producer needs them.)
     - ❌ **Rung 11c — WARP-compatible GUID computation: deliberately NOT pursued.**
       Computing a *reference-byte-identical* function GUID would mean replicating Binary
       Ninja's normalization (`binaryninja-api/plugins/warp/src/lib.rs`), which is
       defined over the reference implementation's **closed-core LLIL + its exact CFG basic-block boundaries**
       — a fragile imitation whose only purpose is to read *their* databases, that
       would couple n0xis to a foreign closed contract and leak the user's function
       GUIDs to `warp.binary.ninja`. That is an anti-pattern against this project's
       own principles (own the seams; no coupling to a foreign, closed-core-defined
       contract). Decision (2026-08-31): we take the *idea* (structural matching
       that survives relocation) but implement **our own** fingerprint on our own
       CFG + the relocation masking `sig gen` already computes — verifiable without
       any oracle (same function in two binaries → same fingerprint, proven on our
       corpus), no dependency, no egress. 11a/11b stay as cheap *passive* import
       (read a `.warp` someone hands us); we do not chase byte-compat on compute.
       The live `warp.binary.ninja` API (no-auth query-by-GUID; sources Vector 35 /
       Golang / LINUX / .NET AOT) is recorded for reference, not as a dependency.
   - ⬜ **Extend the OSS corpus** (OpenSSL/Qt/libstdc++) via `signatures/generate.sh`.
9. ⬜ **Calling-convention & argument recovery — the prototype the whole render
   hangs on.** Classify the CC (fastcall / stdcall / vectorcall / `this` / custom)
   and recover argument count, types and variadicity from entry-liveness plus
   call-site agreement, instead of assuming x64-fastcall-with-four-args. Composes
   directly with the function-summary IPA (priority 3); it is what makes an
   *un*-prototyped function render the arguments it actually takes.
10. ⬜ **Stack-frame reconstruction — the foundation readability sits on.** Track
    the stack-pointer delta across the function, handle frame-pointer-omitted (FPO)
    functions, and surface stack arrays and spilled locals as *typed* variables
    rather than raw `[rsp+N]`. Feeds type recovery and alias, and is a prerequisite
    for other tools' readable-locals output.
11. ⬜ **Output-readability structuring — the "reads like a source-level decompiler" axis.** Distinct
    from CFG *correctness* (priority 0), this is what a user sees first: aggressive
    goto elimination, recovering `&&` / `||` from short-circuit CFG diamonds,
    ternary `?:`, precise loop forms (`for` / `while` / `do-while` with
    `break` / `continue`), rendering a jump table as a `switch` rather than an
    `if`-chain, and **signedness inference** so operators and casts are correct.
    The other tools have a decade of polish here; it is a continuous dimension, not a
    single fix.
12. ⬜ **Depth-limited symbolic / concolic execution — the engine the hard cases
    need.** The passes above are all *static abstract* interpretation:
    value-set gives the *possible values* of an SSA variable, but never the
    *conditions* under which each arises. Three of the hardest problems on this
    corpus are fundamentally about *executing* a slice, not abstracting it:
    - **Control-flow deobfuscation** — a flattened/opaque-predicate dispatcher is
      cheap to defeat by concretely (or symbolically) executing the state
      variable and reading off the real successor, where a pattern matcher stalls.
    - **Virtual-call / indirect-branch resolution** — concolic-execute the
      dispatch slice (this-ptr → vtable load → slot) to recover the concrete
      target, complementing the *static* RTTI/vtable recovery (item 7) when the
      table is computed rather than a constant.
    - **State-dependent conditions** — recover *which inputs* drive a branch, not
      just that the branch exists — the missing half of `ir value-set`.
    Scope it as a **bounded** engine (depth/loop/path caps, a small SMT or an
    interval/concrete fallback — *not* a general symbolic executor), built on the
    existing SSA + `ValueSetPass`, and expose it as its own inspectable pass
    (`ir symrun` or similar) rather than hiding it inside another. Sequence it
    alongside priorities 1–2 (it wants Memory SSA underneath) — the deobfuscation
    and devirtualization items are its first two consumers. *(Raised by an
    outside RE specialist's review, 2026-08-29 — a genuine structural gap, not a
    coverage item.)*

### Decompiler analysis-depth: the staged path to source-level pseudocode

A decompiler is judged on one thing — *does the pseudocode read like source?* —
and the path there is a sequence of **representations**, each a prerequisite for
the next. This is the concrete, staged plan from where N0xis stands to
decompiler parity, with the *observable output change* each stage buys, so
progress is measurable and each stage has a real definition-of-done: verified on
a real binary, not a synthetic sample (the project's verify-before-✅ rule).

- **Rung 0 — Register/flags SSA + optimizer + structuring.** ✅ *Done.* Dominance-
  frontier phi placement, Cytron renaming, flag-precise branch conditions,
  const-fold / copy-prop / expr-prop / DCE to a fixpoint, and control structuring.
  *Output:* SSA pseudo-C, but memory still reads as raw `*(rbp - 8)` and every
  value dies at the first spill.

- **Rung 1 — Memory SSA (values flow *through* memory).** ✅ *(2026-08-30 — the
  spine is complete: 1a + 1b + 1c, standing on escape analysis 2a; verified sound
  on real Win64/MSVC and Linux/GCC code.)*
  - **1a — intra-block store-to-load forwarding.** ✅ *(2026-08-29, verified.)* A
    `Load` from a slot a dominating un-clobbered `Store` wrote becomes the stored
    value; keyed by the base's SSA name + constant offset, width-exact, pure-value
    only, cleared on any call / foreign-base / unknown-address store. *Output:* a
    spill/reload reads `return rcx`, not `return *(rbp-8)`. Verified on real x64
    (`CompressToolsLib::OpenImage`: locals forward, 8 deref-loads across 22 local
    refs; 60 functions decompiled clean).
  - **1b — cross-block forwarding.** ✅ *(2026-08-30, verified.)* A forward
    available-memory dataflow carries a slot's value along CFG edges and meets at
    joins by intersection (a fact survives only if every predecessor exports the
    identical value — a disagreement is exactly where a memory-phi would be needed,
    so it is dropped). Restricted to entry-value/constant stores, which dominate
    every block, so no per-value dominance bookkeeping is needed yet. *Output:* a
    value written to a slot in one block and read in a later block reads as the
    value, across the branch. Unit-tested both ways (forwards at a join when both
    arms agree; blocked when one arm overwrites the slot). **Verified on real x64:**
    `OIS64.dll` `sub_180005d20` forwards `[rdx.0+0x18]` across a block boundary
    (cross-checked — the surrounding function decompiles soundly, and a
    *different* slot whose value disagrees across paths is correctly *not*
    forwarded). It fires rarely on this corpus (≈2 functions per ~300) precisely
    because optimized game code is call-heavy and the sound rule clears
    availability across every call — **which is exactly what escape analysis (a
    slice of Rung 2) unlocks:** a stack slot whose address is never taken cannot be
    written by a call, so a callee-saved spill would then forward across the whole
    body. Full memory-version/phi representation (relaxing the entry-value
    restriction) is the other follow-on.
    The delta now tags each forward "within its block" vs "across a block
    boundary" — the explainability that made this real-corpus verification
    possible (surfaced via `decomp pseudo --explain`).
  - **1c — dead-store elimination.** ✅ *(2026-08-30, verified.)* A `Store` to a
    non-escaping *stack* slot (frame/stack-pointer base) that is read nowhere and
    whose value has no side effect is removed — once stage-1 forwarding has
    replaced the reloads, the callee-saved spill stores are provably dead.
    Sound: restricted to `rsp`/`rbp`-based slots (a store through an arbitrary
    pointer register `[rax]` is a write to who-knows-where and is never touched),
    gated on escape analysis (2a) and on nothing loading the slot. **Caught a
    real soundness bug in the making** — an early cut keyed *any* store base as a
    "slot", which would have dead-eliminated a pointer write; the frame-base
    restriction fixes it. **Verified on real x64:** on `CompressToolsLib.dll` it
    fired in 154/300 functions (317 stores removed), and the outputs read clean
    — the prolog's register-save housekeeping is gone, the semantic body intact.

- **Rung 2 — Alias / points-to (co-recovered with types).** 🚧 A real points-to
  oracle so "a store through a different base" stops clobbering *everything* — it
  clobbers only what it *may* actually alias (stack vs heap vs global). This is the
  chicken-and-egg with types (Rung 3): climb them together. *Output:* forwarding
  and propagation survive across real, pointer-heavy code, not just leaf slots.
  - **2a — escape analysis (the keystone slice).** ✅ *(2026-08-30, verified.)* A
    stack slot whose address is never materialized as a value — never `lea`'d and
    its base register only ever used as an address base — cannot be reached by a
    callee, a foreign-base store, or an unknown-address store, so only a store to
    that exact slot can change it. This is what lets stage-1 forwarding survive
    calls, which is where it was previously blocked on call-heavy real code.
    Sound-conservative on **both ABIs**: `AddrOf` of a clean slot is recorded
    precisely (its base does not escape), any other value-use of a base escapes
    it, and a call additionally clobbers every slot at or below the outgoing stack
    pointer — the System V **red zone** (`rsp`-relative negative offsets) and the
    Win64 **home/shadow space** (`[rsp..rsp+0x20]`) — since a callee overwrites
    that region without ever holding a pointer. **Verified on real x64 across two
    compilers:** on Windows/MSVC `CompressToolsLib.dll`, cross-block forwarding
    jumped from **0 → 28 of 400 functions**; on Linux/GCC `Factorio` (OpenSSL
    `dtls1_ctrl`) it decompiles at quality 1.0 with 10 sound forwards. **The
    Factorio run caught a real soundness bug** — the first cut cleared only the
    Win64 shadow, so it would have forwarded a System V red-zone slot across a
    call; the fix (clobber everything below the outgoing `rsp`, both ABIs) blocks
    it, and now a red-zone slot forwards only along a call-free path. The full
    points-to oracle (heap/global disambiguation, relaxing "different base
    clobbers non-safe slots") is the rest of Rung 2.
  - **2b — global (distinct-constant) disambiguation.** ✅ *(2026-08-30, sound;
    synthetic + unit-verified.)* An absolute address is keyed under a synthetic
    `__abs` base with the address as its offset, so two **different constant
    addresses are two non-overlapping slots that provably cannot alias** — a
    store to global A no longer clobbers a value available at global B, the one
    "different base" case that is always sound. Sound at every boundary (each
    pinned by a synthetic case): a store to a *different* global forwards past;
    a store through a *register* base still clobbers a global (the register may
    hold its address — `call_safe` excludes `__abs`, a fix a soundness test
    caught pre-commit); a *call* still clobbers every global. Three optimize
    unit tests; goldens and the 2a escape tests unchanged. Real-corpus firing
    is rare — it needs a global written and re-read in a call-free window — so
    this is verified by construction/soundness rather than a corpus count; the
    remaining Rung 2 is heap/allocation-site and distinct-parameter
    disambiguation (needs real points-to, the devirt prerequisite).
  - **2c — heap-allocation disambiguation.** ✅ *(2026-08-31, sound;*
    *unit-verified.)* Two distinct heap allocations never overlap, so a store
    through one no longer clobbers a value available at the other — the
    points-to slice the BN comparison names. Allocation bases are the SSA `ret`s
    of `Call` sites whose resolved callee is a **curated allocator** (malloc/
    calloc/aligned_alloc, OpenSSL `CRYPTO_*alloc`, glib, Win32 `HeapAlloc`/…, C++
    `operator new` — Itanium `_Znwm`/`_Znam`, MSVC `??2`/`??_U`); `realloc` and
    `free`/`delete` are excluded, only a direct call result is marked (never a
    phi/copy), and the callsites are carried onto `SsaArtifact` (serde-skipped)
    so the optimizer can resolve names. Sound at every boundary (unit-verified):
    a store to a *distinct* alloc does not clobber, a same-slot store does, and a
    foreign register store still clobbers an *escaped* heap object (may alias it)
    — the escape analysis already covers the non-escaped case. Real-corpus firing
    is rare: an optimizing compiler disambiguates distinct allocations itself (a
    gcc -O1 two-malloc test compiles the load away before n0xis sees it), so this
    is verified by construction and closes the case they leave; 0 regressions
    across `ls`/`openssl`/`libcrypto`/`sqlite`/`libc`. The last Rung 2 piece is
    distinct-*parameter* aliasing, which needs a `restrict`-class proof.

- **Rung 3 — Variable & type recovery (the a source-level decompiler readable-locals win).** 🚧
  Coalesce SSA versions back into named, **typed** variables; infer types from use
  (access widths, pointer arithmetic, known-API signatures), recover struct/field
  layout and enums. *Output:* `player->health -= dmg;` instead of
  `*(int*)(rbx.7 + 0x40) = *(int*)(rbx.7 + 0x40) - eax.3;`. This rung is the single
  biggest readability jump.
  - **3a — parameter typing from use.** ✅ *(2026-08-30, pointer typing verified;*
    *API-type path unit-tested, real-target hit still pending.)* A register
    parameter's signature type is inferred from how the function uses it, by
    strength of evidence: a **recovered struct pointer** (concrete field accesses
    through it) → `struct_<base> *`; a **known-API argument type** → that named
    type (`HANDLE`, `LPCWSTR`, `DWORD`, …); a bare **dereference** with no better
    evidence → `void *`; otherwise the generic `uint64_t` as before. The
    signature renderer now honors the recovered type (`void *rcx`, not
    `void * rcx`) instead of stamping every parameter `uint64_t`. **Verified on
    real MSVC x64** (`CompressToolsLib.dll`): 87 of 120 functions recover a
    pointer/struct parameter type — the C++ `this` in `rcx` now reads
    `struct_rcx_0 *rcx`. The struct/`void *` (pointer-from-dereference) paths are
    what fire on this corpus; the **known-API argument-type** path is unit-tested
    (precedence + resolution) but has not yet been observed firing on a real
    binary here (these libraries dereference their pointer params — so the struct
    rule wins by precedence — rather than forwarding a bare param straight into a
    small-set Win32 API), so it stays ⏳ real-target-unconfirmed, per the
    verify-before-✅ rule.
  - **3b — parameter naming in the body.** ✅ *(2026-08-30, verified.)* A
    recovered parameter's entry SSA version (`rcx.0`) now renders under its
    parameter name (`rcx`) everywhere in the body — bare use, struct-field base,
    store target — connecting the body to the signature. Sound by construction:
    the `.0` version of a register is uniquely its incoming value, so dropping
    the redundant subscript never conflates (`rcx.1`/`rcx.2`, genuine later
    definitions, keep their subscripts, and there is never a bare `rcx` to
    collide with). **Verified on `CompressToolsLib.dll`:** `sub_1800010d0` reads
    `*rcx = …; if ((rdx & 0x1) == 0x0) …; return rcx;` against the signature
    `(struct_rcx_0 *rcx, uint64_t rdx)` — no `.0` noise on parameters.
  - **3c — SSA-version coalescing (phi-webs → named variables).** ✅ *(2026-08-30,*
    *verified.)* A register's phi-web of versions (`rcx.1`/`rcx.2`/`rcx.3`, the
    loop-carried counter) collapses to one named variable — the a source-level decompiler
    readable-locals win: a `dec`/`jne` counter now reads
    `v1 = 3; while (v1 != 0) { v1 = v1 - 1; }` and a scan reads
    `while (*(uint8_t*)(rdx + v1) != 0x0) { v1 = v1 + 1; }`. This is SSA
    destruction, unsound if naive (the lost-copy / swap / pre-update-tested-value
    hazards), so it is **guarded by a statement-granularity liveness +
    interference analysis** and refuses to coalesce any class whose members are
    ever simultaneously live with different values (a refused class keeps its
    subscripts — sound-over-complete). Naming is collision-free by construction:
    a phi merges only versions of one register, so a class is single-root and is
    named after its parameter if it contains one, else a fresh `vN` (which
    collides with neither a register, a `root.version`, nor another `vN`). Runs
    only on the optimized `ssa` style. **Verified on `CompressToolsLib.dll`:**
    **110 of 200 functions** coalesce at least one variable; adversarial unit
    tests confirm the escaping-value, pre-update-tested, and swap hazards are
    refused while the sound loop counter and parameter-in-loop cases collapse.
  - **3d — complete SSA destruction (edge copies for un-coalesced phis).** ✅
    *(2026-08-30, verified.)* A phi that coalescing *refused* (an interference)
    previously left its destination read with no visible definition — the
    `rax.6` "undefined variable" artifact. Destruction now materializes every
    such phi by inserting copies on its incoming edges (`dst = φ(v_i)` →
    `dst = v_i` at the end of each predecessor). A **critical** edge (the
    predecessor has more than one successor) is **split** by a fresh
    fall-through block that carries the copy — in structured output that block
    becomes the matching `if`/`else` arm. Coalesced phis need nothing. **Verified
    on `CompressToolsLib.dll`:** all **200 functions decompile with zero errors
    at 0.969 average quality**, **90** use edge-split destruction (326 split
    blocks), and the showcase `sub_180002380`'s `rax.6` is now defined on both
    arms (`if (…) { rax.6 = rcx; } else { rax.5 = *rcx; rax.6 = rax.5; }`).
    Synthetic split-block addresses are non-canonical and render as
    `// block_N: (edge split)`.
  - **3e — typed-locals declaration block.** ✅ *(2026-08-30, verified.)* The
    recovered stack locals now render as a source-style typed declaration
    block at the top of the function (`uint64_t local_18; __m128 local_20; …`)
    before the body, for the `structured`/`ssa` styles (`goto` stays flat). Only
    locals that actually appear in the body are declared (an optimizer-removed
    local is not listed), and the `local_XX` name derives from the offset
    exactly as the renderer's does. **Verified** on `CompressToolsLib.dll`
    `GetBlockLODs` — declares `local_18/20/28/30/38` with inferred types (incl.
    `__m128` for a vector spill), each used below.
  - **3f — signedness inference from use.** ✅ *(2026-08-30, verified.)* A stack
    local's displayed type now takes evidence from the operators its value flows
    into, not just the `movsx`/`movzx` load encoding: a value compared with a
    signed `<`/`>` (jl/jg), divided with `idiv`, or arithmetic-shifted (`sar`) is
    signed. Readability-only (the IR ops are already correctly signed/unsigned),
    so never a soundness risk; unsigned uses never flag a slot. **Verified** on
    `CompressToolsLib.dll` `GetBottomPixels` — `local_28`/`local_30`, used in
    `(local - x) >> 1` arithmetic shifts (`sar`, a signed midpoint), declare
    `int64_t` while the canary/saved-reg locals stay `uint64_t`.
  - **3g — whole-program `this`-type propagation + C++ import naming
    (readability).** ✅ *(2026-08-31, verified.)* Two wins from the another tool
    review. **(a)** A value passed as arg 0 to a non-static C++ member
    function *is* a pointer to that method's class — `param_ctype` now types such
    a parameter as the class (`std::basic_ostream<char,…> *rcx`), other tools'
    whole-program `this`-typing, ranked just below the constructor-vtable class.
    Sound: membership is read from the demangler's access specifier (gated
    against `static`), so a free function's or static member's arg 0 is never
    mistyped. **(b)** A module-prefixed C++ import (`MSVCP140.dll!?sputc@…`) now
    reaches the demangler (it split off the `module!` prefix, which hid the
    leading `?`) and renders its qualified name only
    (`std::basic_streambuf<…>::sputc`) via an MSVC `NAME_ONLY` demangle — not the
    sanitized `MSVCP140_dll___sputc___…`. **Verified:** `sub_180002fa0` recovers
    `std::basic_ostream<char,struct std::char_traits<char> > *rcx` and names
    `flush`/`sputc`/`sputn`/`setstate` — matching another tool (in fact naming *more*
    C++ methods than another tool on that function); CompressToolsLib 17 / kenshi_x64
    19 of 200 functions get a class-typed param, 0 regressions. MSVC only for now
    (the game corpus); Itanium/ELF `this`-typing is a follow-on.
  - Still ⬜ for this rung: **width/signedness for register variables** (the
    same use-inference applied to coalesced `vN`, not only stack locals),
    **enums**, and **Itanium (ELF) member-function `this`-typing**.

- **Rung 4 — Calling convention & argument recovery.** 🚧 Classify the CC and
  recover arg count/types/variadicity by entry-liveness + call-site agreement.
  *Output:* calls render with the arguments they actually take, and prototypes are
  right — see Phase-10 item 9.
  - **4a — precise register-argument arity (Win64).** ✅ *(2026-08-30, verified.)*
    The lift emits all four Win64 argument registers (`rcx`/`rdx`/`r8`/`r9`) at
    *every* call — it can't know the callee's real arity — so counting a register
    as a parameter merely because it appears in a call's argument list pegged
    **every** calling function at arity 4. Fix: a register counts toward arity
    only when it is used in a position that is *not* a bare pass-through call
    argument (an address base, arithmetic, a branch condition, a return, a store
    value, or nested inside a computed argument) — the same trimming the renderer
    already applies to the call *display*. **Verified on real MSVC x64:** on
    `CompressToolsLib.dll` the arity-4 count collapsed from ~100% to a realistic
    spread (0:7 / 1:32 / 2:27 / 3:23 / 4:25 over 120 functions), and
    `sub_1800010d0` — which really takes 2 (`*rcx`, `rdx & 1`) — now reports 2,
    not 4; cross-checked on `OIS64.dll` (100 functions, no regression). Also
    fixed here: a **demangled C++ prototype** (which already carries its own
    return type and real parameter list) is now used verbatim as the signature
    instead of being wrapped into the garbled
    `uint32_t <full-prototype>(uint64_t rcx, …)`. Known under-count: a parameter
    forwarded straight through to an *unknown* callee has no non-argument use and
    is dropped — resolving it is the **call-site-agreement** half of this rung
    (a callee's arity, learned from all its call sites, back-propagated to each
    forwarding argument), still ⬜.
  - **4c — ABI-aware argument recovery (System V + Win64).** ✅ *(2026-08-30,*
    *verified.)* Arity and parameter recovery no longer assume Win64. The arch now
    exposes **both** x86-64 conventions (`win64` first — the lift's default — and
    `sysv`), and the **source** declares which applies via `MemorySource::abi_name`
    (`"win64"` for PE, `"sysv"` for ELF and Linux-live). Signature recovery selects
    the matching `CallConv` and reads its argument registers, so an ELF's parameters
    recover from the System V order (`rdi`/`rsi`/`rdx`/`rcx`/`r8`/`r9`) instead of the
    Win64 `rcx`/`rdx`/`r8`/`r9`. **Verified:** `Factorio` (ELF) — `sub_fe2424` now
    reads `(uint64_t rdi, uint64_t rsi, uint64_t rdx, struct_rcx_0 *rcx)` (System V,
    4th arg typed as a struct pointer), while `Kenshi` (PE) is unchanged at Win64
    (`sub_1800010d0(struct_rcx_0 *rcx, uint64_t rdx)`). Follow-on **4d** closes the
    lift half.
  - **4d — ABI-aware *call sites* in the lift.** ✅ *(2026-08-30, verified.)* 4c
    fixed each function's own signature, but the lift still emitted every `call`'s
    arguments and clobbers Win64-shaped (`calling_conventions()[0]`), so an ELF
    **call site** showed the wrong registers even where the signature was right. The
    lift now takes the source `abi` (threaded from `MemorySource::abi_name` through
    `Arch::lift`/`lift_tail_call`) and selects the matching `CallConv`. Two effects,
    one cosmetic and one **sound-critical**: (1) a System V call forwards
    `rdi, rsi, rdx, rcx, r8, r9` instead of the four Win64 registers; (2) it now
    invalidates `rsi`/`rdi` across the call — caller-saved on System V but
    callee-saved on Win64 — so a later read can no longer unsoundly reuse a pre-call
    value the callee was free to destroy. An unknown ABI falls back to the arch's
    native (first) convention. **Verified:** `Factorio` (ELF) `sub_fe2104` now emits
    `BIO_new(rax.1, rsi.1, rdx.1, rcx.1, r8.1, r9.1)` (six System V registers, arg 1
    being rdi's value from the preceding `mov rdi, rax`), while `Kenshi` (PE) call
    sites stay Win64 (`(rcx.2, rdx.2, r8, r9)`). Corpus sweep — 40 call-bearing
    functions each on `Factorio`, `Tiny Glade` (ELF) and `Kenshi` (PE): 120/120 ok,
    0 errors, 0 anomalies.
  - **4b — drop lift-padding call arguments.** ✅ *(2026-08-30, verified.)* The
    same fixed four-register call convention meant *every* call to a callee not
    in the signature library rendered four arguments (`sub_X(rdi.1, rdx, v1,
    r9.0)`). A **trailing** argument that is the bare entry value (`rN.0`) of a
    register the current function neither takes as a parameter nor writes is
    padding — the uninitialized incoming register — and is dropped, while any
    computed argument or a genuine parameter forward (including a trailing
    `rdx.0` when `rdx` *is* a parameter) is kept. Per-function and sound-
    consistent with 4a's arity model. **Verified on `CompressToolsLib.dll`:**
    `sub_18001eebd(rdi.1, rdx, v1)` (was `…, v1, r9.0)`), while a sibling call
    that really passes four (`sub_1800033e0(rcx, v1, r8.1, rdx)`) is untouched.
    The whole-program call-site-agreement recovery (4a's ⬜ half) would let this
    trim to the callee's *exact* arity instead of this local heuristic.

- **Rung 5 — Expression & idiom quality.** 🚧 Signedness inference, the compiler-
  idiom library (magic-number division, `cmov`→`min/max`, `rep`→`mem*`, canary
  recognition), and SIMD/FP lift (items 4, 6, 11). *Output:* the arithmetic reads
  as the source wrote it, and SIMD-heavy game functions stop degrading to `asm`.
  - **5a — branch conditions from arithmetic flags.** ✅ *(2026-08-30, verified.)*
    A `Jcc` after an arithmetic/logical op that keeps its result (`dec ecx; jne`,
    `sub rax,rbx; je`, `and edx,edx; jne`) previously rendered `/*cond(jne)*/`:
    the lifter modelled those flags as `OpaqueFlags`, so `branch_condition` had
    no compare to decode — most notably leaving loop latches with **no visible
    condition** (`while (/*cond(jne)*/)`). The zero flag is a pure function of the
    stored result, so a 32/64-bit **register** result now records a `Result`
    compare and the equality branch reconstructs as `result == 0` / `!= 0`. Kept
    sound-conservative: only `je`/`jne` are recovered (sign/magnitude conditions
    depend on carry/overflow the result alone doesn't carry — those stay opaque,
    never a wrong guess), and 8/16-bit or memory destinations stay opaque (the
    full register's zero-ness isn't the sub-register result's). **Verified on real
    MSVC x64** (`CompressToolsLib.dll`, 200 functions): **69 of 75 loop headers
    now carry a real condition** (was near-zero for arithmetic latches), e.g.
    `while ((*(uint8_t*)(rdx.0 + rbx.3) != 0x0))` — a real string scan.
  - **5a′ — the full jcc family after a logical op (readability finding).** ✅
    *(2026-08-31, verified.)* A review with another tool showed the biggest
    visible gap was N0xis's opaque `~/*cond(jle) after test*/` next to another tool's
    clean conditions. A **logical** op (`test`/`and`/`or`/`xor`) clears OF and CF
    to 0, so *every* signed and unsigned branch is a pure sign/zero test on the
    value — not just `je`/`jne`. `CmpKind::Test` and a new `CmpKind::LogicalResult`
    now reconstruct the whole family (`jl`/`jle`/`jg`/`jge` → `<`/`<=`/`>`/`>= 0`,
    `ja`/`jbe` → `!=`/`== 0`, `jae`/`jb` → provable true/false since CF=0); the
    arithmetic `Result` additionally recovers `js`/`jns` (SF is the stored
    result's sign bit). **Verified:** `CompressToolsLib` `sub_180002fa0` reads
    `while ((v8 > 0x0))` / `if ((rdi.1 <= 0x0) || …)` — matching another tool's
    `for (; 0 < lVar7; …)` exactly, 0 opaque conditions in that function; corpus
    opaque-cond lines collapse (kenshi_x64 200 fns to 31 — all `jo`/`jp` or
    opaque-flag-source, sound to leave), 0 regressions, 9 unit tests. Still ⬜:
    the idiom library and FP-compare conditions.
  - **5b — stack-canary recognition.** ✅ *(2026-08-30, verified.)* The compiler's
    stack protector littered every guarded MSVC function with opaque arithmetic on a
    mystery global: `rax.2 = (*(uint64_t*)(0x1421173c8) ^ rsp.1)` on entry (a load of
    `__security_cookie` XORed with `rsp`) and `(local_8 ^ rsp.1)` before the epilogue
    check. XORing a value with the **raw stack pointer** is something *only* the stack
    protector ever does — no legitimate arithmetic touches `rsp` that way — so the
    recognizer keys strictly on a stack-pointer XOR operand and is sound by
    construction: it cannot misfire on real code. Such an XOR now renders as
    `__stack_guard(<guarded value>)` (recognition + labeling; nothing is deleted, so
    the transform is information-preserving). **Verified:** `Kenshi` (PE/MSVC)
    `sub_140064abf` reads `rax.2 = __stack_guard(*(uint64_t*)(0x1421173c8))` at entry
    and `return __security_check_cookie(__stack_guard(local_8), …)` at exit — the
    whole canary dance now self-labels. Corpus sweep of 80 functions each:
    `Kenshi` fires on its real canaries (6 guards / 3 functions, a setup+check pair
    each), while `Factorio` (ELF/GCC), `Tiny Glade` (ELF/Rust) and `ChainedTogether`
    (PE/UE5) show **zero** — the Linux `%fs:0x28` canary never XORs `rsp`, proving no
    false positives; 320/320 functions decompiled with 0 errors. Follow-on: sound
    *elision* of the now-labeled setup/check (they are dead once recognized) would
    remove the noise entirely rather than only naming it.
  - **5c — SSE data-move lift.** ✅ *(2026-08-30, verified.)* A corpus census of
    every mnemonic still falling through to `// asm:` put the legacy 128-bit SSE
    **data moves** at the top by a wide margin — `movups` alone 3648 lines, plus
    `movdqu`/`movaps`/`movdqa` (~4272 together). These are pure data movement (no
    packed *arithmetic*), so modelling them as a 128-bit load/store/copy is sound.
    The lift required two fixes the generic `mov` path got wrong for vectors: (1)
    **width** — `memory_size()` reports `Packed128_*`, which `mem_bits_signed`
    deliberately doesn't special-case, so the move now takes its 128-bit width from
    the xmm register operand (and `c_type` gained `__m128`/`__m256`/`__m512` so a
    vector store can't masquerade as a 64-bit one); (2) **naming** — `reg_name` runs
    every register through `full_register()`, which widens `xmm6`→`zmm6`; a
    128-bit lane move now presents the `xmm` view the source used. Scalar `movss`/
    `movsd` are deliberately left as `asm` — `movsd` shares its mnemonic with the
    string instruction, so lifting it as a scalar move would be unsound. **Verified:**
    the census's ~4272 SSE lines drop to zero `// asm:`; `Kenshi` `sub_140064e17`
    reads its nonvolatile spill as `local_70 = xmm6.0`, and `Tiny Glade` (Rust)
    struct copies read as `xmm0.1 = *rsi` / `local_10 = xmm0.1` with correct SSA
    versioning and struct-field recovery firing through the xmm value. Sweep of 60
    functions each on `Kenshi`, `Factorio`, `Tiny Glade`: 180/180 ok, 0 errors
    (18 of Tiny Glade's 60 now render `__m128`).
  - **5d — `setcc` condition reconstruction.** ✅ *(2026-08-30, verified.)* A
    `setCC dst` writes the boolean of a condition code, and the census left every
    one as `/*sete cl*/` — a *computed value* dropped to a placeholder, worse than
    an unlifted line because a real dataflow edge goes missing. The condition codes
    are identical to the `jcc` family, so a `setcc` can reuse the exact
    `branch_condition` reconstruction 5a built — the only difference is that a
    `setcc` is mid-block, not a terminator, so the reaching `flags` aren't known
    until SSA. The lifter emits a `setcc:<jcc>` marker; the SSA renamer resolves it
    against the `flags` value on the rename stack at that point — the mid-block twin
    of how a `cjmp` resolves from `end_flags_name`, with the identical soundness
    guarantee (the reaching `Compare` captured its operands at flag-set time, so the
    recovered boolean is right even if a source register was reassigned between the
    compare and the `setcc`). When the reaching flags are opaque, it stays a
    `/*cond*/` placeholder — never a fabricated condition. **Verified:** `Kenshi`
    `sub_140064abf` now reads `rcx.43 = (v6 == 0x0); rcx->field_0xa8 = rcx.43;`
    (was `rcx.43 = /*sete cl*/`); `setne`/`setae` vanish from the `// asm:` census;
    a corpus sweep of 60 functions each on `Kenshi`, `Factorio`, `Tiny Glade` and
    `ChainedTogether` decompiled 240/240 with 0 errors and no `/*set*/` placeholders
    left in-sample. Follow-on: `cmovcc` reuses the same reaching-flags resolution but
    also needs a ternary (`cond ? a : b`) node — that overlaps Rung 6.
  - **5e — `cmovcc` → ternary select.** ✅ *(2026-08-30, verified.)* `cmovcc dst,
    src` is `dst = cond ? src : dst` — a conditional *select*, not a branch, so it
    dropped to `/*cmovb r8,rbx*/`, losing a computed value just like `setcc` did.
    Lowered now to a real ternary: a new `MicroExpr::Select { cond, a, b }` node
    (also the building block Rung 6's `?:`/`&&`/`||` recovery will reuse), with the
    condition carried as the same `setcc:<jcc>` marker the SSA builder resolves from
    the reaching flags (5d) — so `cmovb` after a `cmp` recovers its exact unsigned
    condition. The node threads through every SSA/optimizer/type/valueset walker
    (var-collection and use-counting recurse into all three children, so DCE never
    drops a def used only inside a select; value-set analysis takes the lattice
    *join* of the two branches — precise and sound). **Verified:** `Kenshi`
    `sub_140064abf` now reads `r8.30 = ((rbx.3 < /*u*/ r8.29) ? rbx.3 : r8.29)` (was
    `/*cmovb r8,rbx*/`) — which is exactly the unsigned-`min` idiom, now *visible* for
    a later idiom pass to fold. `cmovb`/`cmovbe` leave the `// asm:` census; a sweep
    of 60 functions each on `Kenshi`, `Factorio`, `Tiny Glade`, `ChainedTogether` and
    `Pit of Goblin` decompiled 300/300 with 0 errors (ternaries now render in 20, 19
    and 7 of the Kenshi / Tiny Glade / Pit-of-Goblin samples).
  - **5f — `min`/`max` idiom fold.** ✅ *(2026-08-30, verified.)* Once `cmovcc`
    lowers to a select (5e), the classic `cmov`-after-`cmp` becomes the visible shape
    `(l <cmp> r) ? x : y`. When the two branch values *are* the two compared
    operands, that select is exactly `min`/`max`; which one — and signed vs unsigned
    — is fixed by the comparison operator and by whether the true branch keeps the
    left or the right operand. A render-level recognizer folds it to
    `__min`/`__umin`/`__max`/`__umax(l, r)`. Sound: it fires only on that exact shape
    (the branches must be structurally the compared values), so it can never relabel
    an unrelated ternary — an unrelated select still renders as a plain `?:`.
    **Verified:** `Kenshi` `sub_140064abf`'s `((rbx.3 < /*u*/ r8.29) ? rbx.3 : r8.29)`
    now reads `__umin(rbx.3, r8.29)`; a sweep of 80 functions each recovered 16
    min/max on `Kenshi` and 38 on `Tiny Glade` (Rust's slice-bound and clamp code),
    0 on `Factorio` in-sample, with 240/240 ok and 0 errors.
  - **5g — immediate rotate lift (`rol`/`ror`).** ✅ *(2026-08-30, verified.)* A
    rotate by an immediate is *exactly* a shift/shift/or, and it needs no new IR node:
    `rol x, n` → `(x << n) | (x >> (w-n))`, `ror` mirrors the directions (each keeps
    its own amount — the two forms are not a reordering of the same shifts). Low by
    raw count but high-value for the `const identify` workflow: hash/PRNG code is
    built from rotates, and making them visible is what lets a rotate-heavy mix be
    recognized. Only the immediate, 32/64-bit form is lifted — a `CL`-count rotate
    would need x86 count-masking modelled to stay sound, so it falls through to the
    opaque path rather than emitting an unmasked shift. The old catch-all was
    extracted to a shared `lift_opaque` helper so both paths invalidate writes
    identically. **Verified:** `Tiny Glade` `sub_305686` now reads
    `rcx.11 = ((rcx.10 << 0xd) | (rcx.10 >> 0x33))` — a 64-bit `rol rcx, 13`
    (`0xd + 0x33 = 64`), a hash mix laid bare; `rol`/`ror` leave the census; sweep of
    80 functions each on `Kenshi`, `Factorio`, `Tiny Glade`: 240/240 ok, 0 errors.
  - **5h — the intrinsic layer (bit-scan, SSE, scalar FP).** ✅ *(2026-08-30,*
    *verified.)* A census of everything still hitting `// asm:` was dominated by
    instructions the IR had no shape for: SSE integer/string idioms
    (`pmovmskb`·152, `pcmpgtb`·57, `pxor`·70, `por`·57), bit-scan/count (`tzcnt`·95,
    `bsr`·18), and scalar FP. Added one mechanism — `CallTarget::Intrinsic(name)`,
    modelled as a call-shaped **value** so the whole expression machinery (renaming,
    propagation, rendering) handles its operands for free but it resolves to no
    symbol and reads as `name(args)`. Through it: bit-scan/count (`__tzcnt`/`__lzcnt`/
    `__popcnt`/`__bsf`/`__bsr`, flag-setting) and `__bswap`; the SSE mask/compare
    idioms (`__pmovmskb`, `__pcmpeqb`/`__pcmpgtb`…); scalar **and** packed FP
    arithmetic (`__addsd`/`__mulss`/`__addpd`…, `__sqrtsd`); int↔FP conversions
    (`__cvtsi2sd`, `__cvttsd2si`, `__cvtps2pd`…); pack/unpack/shuffle permutes; the
    1-operand `mul` (low half a real product, high half `__umulh`); and `ud2`/`int3`
    as no-result trap intrinsics (`__ud2();`). SSE *bitwise* ops need no intrinsic at
    all — bitwise doesn't cross lanes, so `pxor`/`por`/`pand`/`xorps`… lower to exact
    128-bit `^`/`|`/`&`. Scalar/vector `movss`/`movsd`/`movd`/`movq` lift as moves
    only when an xmm register is actually involved — which soundly disambiguates the
    SSE `movsd` from the *string* `movsd`. **Verified:** the `// asm:` census collapses
    from thousands to a handful — only FP *compares* (`comisd`/`ucomiss`, flag-setters
    left opaque) and `div` remain, both sound as opaque. `Tiny Glade`'s SIMD
    string-scan reads `v31 = __pmovmskb(v33)` (316 `__pmovmskb`, 198 `__tzcnt`, 87
    `__pcmpgtb`), `Kenshi` `return (__cvttsd2si(v2) + v1)`; a sweep of 100 functions
    each on `Kenshi`, `Factorio`, `Tiny Glade`, `ChainedTogether` and `Pit of Goblin`
    decompiled **500/500 with 0 errors**. Remaining ⬜ for Rung 5: mapping an FP
    compare + its `jcc` to a real ordered/unordered condition, and signedness
    inference — both separate from this lift-coverage work.
  - **5i — BMI/BMI2 + sign-extend lift (STALKER 2 finding).** ✅ *(2026-08-30,*
    *verified.)* The `STALKER 2` (UE5) verification sweep surfaced that it was built
    for a **newer ISA** than the rest of the corpus, hitting `// asm:` on instructions
    the others never used: `shlx`/`shrx`/`sarx` (BMI2 flag-less shifts, ~21),
    `cdqe`/`cwde`/`cbw` (sign-extend the accumulator, ~17), `bzhi` (BMI2 zero-high,
    ~9), `mulx` (BMI2 wide multiply, ~8), `btr`/`bts`/`btc` (bit reset/set/complement).
    Lifted, reusing existing shapes where exact: the BMI2 shifts are plain
    `Shl`/`Shr`/`Sar` with **no flag write** (their whole point vs the legacy forms);
    `cdqe` is `(int64_t)(int32_t)rax`; `mulx` is the product plus `__umulh` like the
    1-operand `mul`; immediate `btr`/`bts`/`btc` are exact `& ~(1<<n)` / `| (1<<n)` /
    `^ (1<<n)` with the CF they set left opaque; `bzhi` reads as an intrinsic.
    **Verified:** re-sweeping `STALKER 2`'s 200 functions stays 200/200, 0 errors,
    and the new lifts *compose* with the earlier idioms —
    `(int64_t)(int32_t)((rbx.1 >= /*u*/ 0x2) ? rbx.1 : 0x1)` (cdqe over a min) and
    `(rdx.18 * __umulh(rdx.18, 0x1642c8590b21642d)) >> 0x1` (mulx exposing a
    magic-number division for `const identify`). The census tail is now only `bt`
    (flag-only), `lock`-prefixed atomics, and CL-count `rol` — all sound to leave.

- **Rung 6 — Readability structuring.** 🚧 The structuring engine
  (`structure.rs`) already reconstructs `if`/`else`, `&&`/`||` short-circuit
  chains, `for`/`while`/`do-while` loops, and `switch`, falling back to a plain
  `goto block_N` only on an irreducible edge (sound over pretty). The `ternary`
  half arrived via Rungs 5e/5f (`cmovcc` → `Select`, folded to `min`/`max`).
  - **6a — `switch` dispatcher + case recovery.** ✅ *(2026-08-30, verified.)* The
    switch emitter printed `switch (/* dispatcher */)` and `case /* block N */:` —
    the shape was there but the *values* were placeholders. The jump-table pass
    already resolves a `ResolvedSwitch { index_reg, cases: Vec<Va> }` into the CFG,
    so the emitter now names the switched register (`switch (rax)`) and turns each
    successor into its real `case 0xK:` label(s) by matching the block's start VA
    against the table's case→target map — fall-through cases that share a block
    stack their labels, and a successor with no table index becomes `default:`.
    **Verified:** `Factorio` `sub_fe2424` reads `switch (rax) { case 0x0: case 0x2:
    … }` and `Tiny Glade` `sub_30b4f5` recovers a full `switch (rdi)` over cases
    `0x0`–`0x20` (fall-through cases correctly stacked); sweep of 100 functions each
    on `Kenshi`, `Factorio`, `Tiny Glade` — 300/300 ok, 0 errors, 6 switches
    recovered. Remaining ⬜: the `default`-vs-unresolved-case distinction when
    the table read is partial.
  - **6b — tail-duplicate shared return regions.** ✅ *(2026-08-31, verified.)* A
    block reached from several paths that would emit `goto block_N` is inlined
    instead when it is a small **tail region** — a `jmp`/`fall` chain, or a small
    `if`/`else` whose both arms are themselves tail regions, ending at function
    exits (`ret`/`tail-call`) with a ≤8-line body and no loop header. Sound (no
    successors past the exit, no back-edge, SSA reads stay valid inlined) — the
    other tools' tail duplication, bounded so a large shared body stays a single
    `goto` not bloat. **Verified:** `CompressToolsLib` `sub_1800021e0` 2 gotos →
    0; corpus residual-goto lines ~halved (`CompressToolsLib` 246→112, `Factorio`
    156→74, `kenshi_x64` 82→46), STALKER 2 200 fns 0 errors. The remaining gotos
    are large shared-body merges (irreducible or bloat-if-duplicated — real C
    keeps these too).
  - **6c — invert empty-then ifs, drop empty else arms.** ✅ *(2026-08-31,*
    *verified.)* `if (c) {} else { B }` reads `if (!c) { B }` and an empty else is
    dropped — both arms are emitted into buffers first so emptiness is known
    before the shape is committed (a bare `// block_N:` label is not content).
    Pure rewrite. **Verified:** `sub_1800010d0` reads `if ((rdx & 0x1) != 0x0) {…}`
    (no empty then/else); corpus empty-then ifs 398 → 15 across `CompressToolsLib`
    + STALKER 2.
  - **6d — do/while when the header is an inner branch.** ✅ *(2026-08-31,*
    *verified.)* Bottom-test detection no longer requires a non-`cjmp` header, so
    a loop whose header carries an inner `if` (both arms in-loop) and whose real
    test is the bottom latch recovers as `do { … } while (c)` instead of the
    `while (1) { … if (c) continue; break; }` fallback. **Verified:** STALKER 2
    `sub_140012757`'s inner-`if` loop reads `do { … if (…) {…} … } while ((r15.1
    != v3))`; 20 do/while loops recovered across 200 STALKER 2 functions, 0 errors.
  - **6f — collapse nested else-if into an else-if chain.** ✅ *(2026-08-31,*
    *verified.)* `else { if (c) {…} else {…} }` reads `else if (c) {…} else {…}` —
    the if-else-if ladder. `try_else_if` detects that a captured else arm is
    exactly one `if` spanning the whole block (brace-balance walk — safe since
    rendered expressions never contain `{`/`}`), dedents a level, and merges the
    `} else ` onto the inner `if`. **Verified:** a 3-way ladder reads `if (rcx==1)
    {…} else if (rcx==2) {…} else {…}`; 36 else-if chains across `CompressToolsLib`
    + STALKER 2 with **0 brace-unbalanced functions**.
  - **6e — negative struct-field offsets read signed.** ✅ *(2026-08-31,*
    *verified.)* A struct access before its base (`*(rcx.1 - 8)`) rendered as the
    two's-complement giant `field_0xfffff…f8`; it now reads `field_neg_0x8`.
    **Verified:** corpus giant-hex lines 116 → 18 (the 18 remaining are genuine
    64-bit constants — `0x7fffffffffffffff` masks, the magic-division multiplier).
  - **6g — `for`-loop recovery (step hoisting).** ✅ *(2026-08-31, verified*
    *against compiled ground truth.)* First cut emitted the `for` directly and
    mis-scoped complex loops (absorbed trailing blocks, `for` over an opaque
    condition) — reverted. The sound approach ships here: emit the loop body into
    a buffer exactly as the already-correct `while` would, then hoist its last
    *top-level* induction step into `for (; cond; step)` — a pure text reformat,
    no CFG re-scoping, so a complex loop stays a sound `while`. `split_trailing_step`
    keys on `++`/`--`/`+=`/`-=` and the self-referential `x = (x + k)` the renderer
    emits, only at the body's outermost indent, and an opaque `/*cond*/` keeps the
    `while`. **Verified against ground-truth compiled C** (gcc/clang -O1/-O2):
    `sum_array` → `for (; (rdi != rcx.1); rdi = (rdi + 0x8))`, `count_down`,
    `every_other` (step +2), `ptr_sum`, `sum_positive` (inner `if` folded to `?:`).
    Corpus: 33 for-loops (`CompressToolsLib` 10, STALKER 2 23), 0 opaque, 0
    brace-unbalanced, 0 errors; the once-mis-scoped `sub_180002fa0` is now
    brace-balanced with one clean `for`.
  - **6h — no-return paths excluded from post-dominance (readability).** ✅
    *(2026-08-31, verified.)* A another tool review found N0xis emitting a
    branch-arm + `goto` where another tool inverts the condition and flows a shared
    tail as fall-through. Root cause: `dominators_rev` connected *any*
    successor-less block to the virtual exit, so a `call-noreturn`/`int` abort
    counted as normal completion and broke the post-dominance of a shared tail
    every *returning* path converges on. It now takes `is_abort` and connects a
    dead-end to the exit only when it is not an abort — what other tools do (drop
    no-return paths for structuring). **Verified:** `CompressToolsLib`
    `sub_180002780` 2 gotos → 0, structuring the shared assignment tail once as
    fall-through with an inverted condition, *identical* to another tool; corpus
    residual gotos drop on CRT-heavy code (`CompressToolsLib` 117 → 72).
  - **6i — strip unreferenced block-label anchors from display.** ✅
    *(2026-08-31, verified.)* The `// block_N: <addr>` anchor emitted on every
    block made N0xis ~30% more verbose than another tool, which labels only jump
    targets. `DecompInput::strip_block_labels` drops the anchor from any block no
    `goto` targets on the display/agent paths, while `ProvenancePass` keeps them
    (its line→address map needs them). **Verified:** over 40 functions the line
    count fell 1779 → 1257 vs another tool's 1212 — **within 4%** (from 47% more).
  - Remaining ⬜: the residual shared-body gotos (large shared merges — real C
    keeps these) and the switch `default`/unresolved-case distinction.
  - **another tool review standing (2026-08-31, CompressToolsLib, 40 fns).** After
    this session, N0xis is at another tool's structural/readability quality on the MSVC
    C++ corpus and *ahead* on C++ class typing: total lines 1257 vs 1212 (within
    4%), gotos 17 vs 11, opaque conditions ~0 vs 0, C++ method names matched or
    better. The **one systematic remaining gap is library-function naming** —
    statically-linked CRT/STL functions (`free`, `memcpy`, `_Throw_C_error`) that
    another tool names via FunctionID/FLIRT and N0xis leaves `sub_XXXX` (108 vs 70
    unnamed). Closing it is the **FLIRT-class signature library** (Phase 10
    priority 8), which needs a reference-library corpus to bootstrap the
    signatures — the honest blocker, not a small fix.

- **Rung 7 — Structural advantages this design gets for free.** 🚧 The capabilities the
  other tools structurally lack. Two are already present by construction: every pass
  emits an **inspectable delta** (KF-5), and the **provenance ⇄ decompile** join (a
  live watchpoint → the exact decompiled statement, KF-1, shipped in Phase 4c).
  - **7a — MSVC RTTI / vtable class recovery.** ✅ *(2026-08-30, verified.)* A C++
    virtual call dispatches through a vtable slot — an edge the CFG can only mark
    "indirect". But an MSVC binary built with RTTI (`/GR`, the default) stores, right
    before each vtable, a pointer to a `CompleteObjectLocator`; the COL points by
    image-relative RVA at a `TypeDescriptor` whose tail is the decorated class name
    (`.?AVFoo@@`). `rtti::scan_msvc_rtti` walks `.rdata` for these, validated by the
    COL's **self-reference** (its `pSelf` RVA must resolve back to the COL — a far
    stronger filter than the signature word) plus a check that the vtable's first
    slot points into `.text`. `demangle_rtti_name` reverses the `@`-qualified name
    (`.?AUData@Ns@@` → `Ns::Data`) and — sound over pretty — returns a
    template/special-mangled name (`?$`) **verbatim** rather than mis-decoding it.
    Exposed as `rtti scan`. **Verified on `Kenshi` (MSVC/Ogre/Havok):** 3055 vtables
    recovered — `AnimationEvent`, `std::bad_alloc`, `AnimationSFXEvent` demangled
    cleanly, `Ogre::STLAllocator<…>` templates kept verbatim. The last-hop
    devirtualization (joining a call site's vtable slot to `Class::method`) and using
    a recovered vtable to *type* a struct's first field build on this.
  - Still ⬜: depth-limited **symbolic execution** (item 12) for the
    deobfuscation / computed-target cases a static pass cannot reach — a
    research-grade effort, deliberately not rushed.

**Sequencing:** Rungs 1→2→3 are the spine and must go in order (each is the
other's prerequisite). Rungs 4–6 are largely independent and can interleave by
corpus payoff (SIMD and RTTI rank high for games — see the framing rules). Rung 7
compounds with everything and needs Memory SSA (Rung 1) underneath.

### Two framing rules this phase encodes

- **The right priority is a function of the target corpus.** N0xis's is game
  engines on x64 Windows — which pulls **SIMD up** (a floor problem, not coverage),
  **RTTI/vtable class recovery and library-function ID up** (deep-hierarchy C++
  with heavy STL/CRT), and **PDB down** (game builds are usually stripped). A
  general-purpose x64 decompiler would order these differently. State the corpus
  *before* arguing the order.
- **Correctness before power.** The lowest foundation is a *correct* CFG, not a
  *powerful* memory model over an incorrect one. `sound over complete` makes a wrong
  graph the worst outcome — fix the graph (priority 0) before deepening the data
  flow over it.

> **Why this is the right shape of work, not a smaller feature list.** The missing
> pieces classify cleanly into a handful of *independent* projects — Memory SSA,
> interprocedural analysis, EH recovery, SIMD lift, an idiom library, RTTI/vtable
> class recovery, a FLIRT-class signature library, calling-convention recovery,
> stack-frame reconstruction, and the readability passes — rather than
> "we don't know how." That is a maturity signal: the decompiler core exists, and
> what remains is heuristics and depth. This phase also feeds CONCEPT §2's
> north-star directly — the interprocedural summary layer it builds (priority 3) is
> what materializes the persistent "program model" that turns *one pipeline* into
> *one model, many projections*.

---

## Tooling & dependencies — the build-out plan (static **and** dynamic)

N0xis is **not** a static-only tool: the live-memory engine, hardware-watchpoint
provenance, hooks and managed-runtime recovery are a first-class half, and the
seam between them (`watchpoint → decompiled statement`) is the main. So the
external tooling is planned across **three consumers** — *static*, *dynamic*, and
**both** — and the highest-value tools are the ones that serve *both*, because
they work the seam. Each entry says how it is pulled in: a **crate** (a
`Cargo.toml` dependency added when the feature is built — never pre-vendored), a
**system package**, or a **standalone** tool downloaded to the tools directory.

### Dynamic engine — deepen the existing strength

| Tool | Why | Half | Pull-in |
|---|---|---|---|
| **Unicorn Engine** | CPU emulation — execute code slices, concolic, foreign-arch dynamic; the engine Rung 7 stands on | both | crate `unicorn-engine` |
| **eBPF / uprobes** | Trace writes to an address with no byte patch (the "beyond-parity provenance" item); a Linux superpower | dynamic | crate `aya` (pure-Rust) |
| **GDB-remote client** | Attach to `qemu-user --gdb`, embedded targets, other machines → dynamic analysis of *any* arch for free | dynamic | build (protocol) |
| **HW debug registers** | Cross-platform HW watchpoints (DR0-3 / `PTRACE_POKEUSER`) — extend the current adapter | dynamic | in-tree |
| **Frida** *(optional)* | Alternative hook/stalker backend, fast prototyping | dynamic | system / bindings |
| **rr** *(optional)* | Deterministic record-replay → provenance "backwards in time" | dynamic | system pkg |

### Static breadth — the multipliers

| Tool | Why | Half | Pull-in |
|---|---|---|---|
| **SLEIGH ingest** (`.sla` → P-code → MicroIR) | One `SleighArch` backend behind `trait Arch` unlocks another tool's ~40 ISAs; the arch-breadth lever | static | crate/port + another tool specs |
| **yaxpeax-{mips,ppc,riscv}** / **Capstone** | Cheap per-ISA decoders (decode ≠ semantics); Capstone as a broad fallback | static | crates |
| **goblin/object** (Mach-O) + a **format seam** | Close Mach-O and firmware loaders (the Phase-15 format-seam debt) | static | crate (have goblin) |
| **gimli** (DWARF) + **pdb** | Type/symbol ingest — the base for whole-program types and the PDB item | static | crates |

### The shared engine — symbolic / concolic (serves both)

| **SMT solver: Z3** (or lighter **bitwuzla**) | Path constraints: deobfuscation (static) **and** runtime computed-target resolution (dynamic) — Rung 7 / priority 12, on SSA + `ValueSet` + Unicorn | **both** | crate `z3` |

This is the most important *seam* tool: one concolic engine powers both static
deobfuscation and dynamic target recovery.

### Level 1 — static-output quality (our own way, verified on real targets)

The depth where a decompiler is judged, done as our own passes (not by imitating a
third party's format). Each increment is verified on a real binary before ✅.

- ✅ **Bare local names.** A function defined in the analyzed image renders by its
  plain name (`crc32_z`, not `libz.so!crc32_z` / `image__name`); the `module!`
  prefix is imports-only. Verified: crc32's thunk → `crc32_z()`, imports keep their
  module (`VCRUNTIME140_dll__…`).
- ✅ **String-literal recovery.** A constant that addresses a printable
  NUL-terminated string in the image renders as its C literal (`"hello %s\n"`),
  escaped, instead of a bare `0x…`. Sound: the bytes are read and validated
  (printable, terminated, ≥4 chars) before an entry is trusted — a math-heavy
  function (`crc32_z`) gains *zero* spurious strings. Verified on PIE (via
  `AddrOf`) and non-PIE (bare `mov imm`) builds; both PLT-`printf` sites show the
  real format string.
- 🟡 **Whole-program type propagation (priority 1) — first interprocedural slice.**
  Type inference is no longer strictly per-function: when a function passes an
  argument to a *user* callee (a direct call, not a known API), the specific type
  that callee recovered for the matching parameter now flows to the caller's
  argument. `infer` runs interprocedurally at the top level and shallow (one level,
  cached) for each analyzed callee, so the recursion is bounded; only *named*
  callee-parameter types cross (a generic `uint64_t` carries no information), and a
  synthesized `struct_<reg>_N` — local to the callee — is carried as `void *`
  rather than leaking the callee's private struct name. **Verified end-to-end:** a
  `wrapper(void *buf, size_t)` that only null-checks `buf` and forwards it to a
  byte-summing callee recovers `buf` as `void *` purely from the callee's
  signature; regression-checked — bodies unchanged (crc32_z 0-line body diff),
  46/46 test groups green, no golden regressed, deflate (many callees) ~95 ms.
  Still ⬜ the full solver: a call-graph constraint/union-find engine that
  propagates *both* ways (caller arg → callee param) and across many hops, backed
  by the project DB below.
- ✅ **Array-access recovery.** `*(T*)(base + i*sizeof(T))` renders `base[i]`
  (both load and store) — identical C semantics, far more readable. Sound: an
  explicit `* stride` matching the element size (`stride ≥ 2`) is required; a
  stride mismatch stays a pointer deref, a byte add stays a pointer add. Verified
  on zlib's `crc32_z`: the table lookups became `v9[(uint32_t)v12]`.
- ✅ **Multi-exit loop structuring (#5) — fixed in two sound steps.**
  1. **No-code-loss sweep.** The recursive descent emitted only what it reached
     from the entry; a block reached solely by a `goto block_N` it emitted but
     never structured was silently dropped — the one failure a decompiler must
     never have. `structure()` now sweeps every unvisited block with real content
     into a top-level region after the descent. **Measured, 0 lines removed:**
     zlib's `inflate_table` had been dropping 259 body lines (522→781), `crc32_z`
     9 (its `goto block_6` target). The goto style was unaffected — proof these
     were genuine omissions.
  2. **Don't nest a loop's continuation after a `break`.** When both arms of an
     `if/else` leave (an enclosing loop's `continue`/`break`), control does not
     fall through to the merge, so emitting it there nested the loop's
     continuation *inside* the loop under a dead-looking `break`. `emit_if_else`
     now skips that merge (`both_diverge`); the exit edge reaches it and the sweep
     places it correctly. On `crc32_z` the alignment `while` now closes cleanly and
     the main CRC loop follows at the outer level. **Verified by set-diff: 0
     statements gained or lost — the code is identical, only re-placed.** Unit
     tests pin `arm_diverges`; `cargo test --workspace` + clippy green.
- ✅ **Data-symbol / global naming.** ELF `.symtab`/`.dynsym` `STT_OBJECT` symbols
  are now collected (`SymKind::Data`) and a constant equal to a global's exact
  address renders `&name` (`v9 = &crc_table;`) instead of `(void*)0x…`. Sound:
  exact-address hit only (no borrowing the symbol before an interior offset), and
  data symbols are excluded from `sig gen`'s function set. Verified on zlib: the
  CRC table base reads `&crc_table`, the lookups `crc_table[i]`.
- 🟡 **Argument-type recovery — pointer parameters.** A parameter whose value
  reaches a dereference is now typed a pointer even when it gets there through a
  copy and a loop-carried phi: `propagate_pointerness` grows the pointer-base set
  backward through `dst = Var(src)` copies and `dst = phi(…)` phis to a fixpoint
  (sound — only sources of already-known pointers are marked). Verified: zlib's
  `crc32_z(uint64_t, void *rsi, uint64_t)` recovers `buf` as `void *` (its pointer
  reaches the table loop only via `rbx = buf` + a phi), where before it was raw
  `uint64_t`. Still ⬜: the *pointee* type (`void *`→`const u8 *`), and integer
  arg widths / signedness / return-type polish.
  ✅ Switch/jump-table rendering
  (`emit_switch`: real `switch (x) { case K: }` from resolved jump tables) —
  already shipped in the structuring rung.

### Whole-program infrastructure (priority 1 — the core gap)

- **Persistent project DB** (`redb`, pure-Rust embedded — or `rusqlite`): a
  call-graph-wide type/xref/annotation store that scales past the current
  per-function + `.n0x`-journal model. This *is* the materialization of CONCEPT's
  "one model, many projections."
- **Type-constraint solver**: union-find for type unification + a constraint
  propagation engine over the call graph — the machinery of whole-program type
  propagation.

### Verification infrastructure (make verify-before-✅ mechanical)

- **Ground-truth compilers** (gcc/clang/rustc/MSVC-cross) — already used
  (for-loops); formalize as a corpus generator.
- **Differential oracles**: (a) **Unicorn** — execute a lifted function vs. the
  real bytes, diff the semantics; (b) **other tools headless**
  (`analyzeHeadless` / the reference API) — benchmark output quality against other tools on
  the same binary.
- **Fuzzing** (`cargo-fuzz`/libFuzzer) of the format/ISA parsers — mandatory,
  since they parse untrusted bytes (the OOM lesson: never `with_capacity` on a
  parsed length).
- **Cross-arch corpus** — beyond games: MIPS/PPC/RISC-V/ARM samples, malware,
  embedded firmware.

### Cross-cutting

- **Cross-compilation / remote** for ARM devices: build n0xis for armv7/aarch64
  to run *on* the device, or use the existing `remote-serve` over SSH; Unicorn +
  a gdbstub client covers the rest of the arches dynamically.
- **VM seam** (a recorded debt): engine support (IL2CPP/LuaJIT/Bitsquid) is
  per-engine and hardcoded — lift it to one plugin contract so Unity-Mono / Godot
  / Unreal / V8 register as plugins, not surgery.

### Recommended acquisition order

1. **Unicorn** — one dependency, three payoffs: the concolic engine (Rung 7), a
   differential oracle for lift verification, and non-x86 dynamic reach.
2. **Z3 + Unicorn** → the symbolic slice (deobfuscation + computed-target
   devirtualization).
3. **Persistent DB (`redb`) + union-find** → whole-program type propagation
   (priority 1, the core gap).
4. **SLEIGH ingest** → architecture breadth, strategically.
5. **eBPF/uprobes + gdbstub client** → dynamic breadth and no-patch provenance.

**`Unicorn` and `Z3` serve static *and* dynamic at once — one investment, both
halves — so they rank first.** Standalone tooling (another tool for its SLEIGH specs +
the headless oracle, and a matching JDK) is downloaded to the shared tools
directory on the Opus partition; crates are added to `Cargo.toml` at integration
time, and system packages (`unicorn`, `z3`, `qemu-user`, `rr`) via the distro.

---

## Companion tooling (not a numbered phase) — N0xHUD, game-asset & LuaJIT track

A parallel track landed outside the numbered roadmap (commits `4cc5f4e`,
`d6580f2`) and isn't otherwise represented here. These capabilities **exist and
are wired**; framed correctly they are **runtime instrumentation / live-memory
analysis + input actuation** over the very crates the CLI and MCP drive — a third
frontend plus some format adapters, not a separate product. (These four extra
crates — `n0xis-hud`, `n0xis-bitsquid`, `n0xis-lua`, `n0xis-luajit` — bring the
workspace from Phase 1's 8 crates to **12** today.)

- ✅ **N0xHUD — a third frontend** (`crates/n0xis-hud`, binary `n0xis-hud`). A
  config-driven **companion window**, *not* an in-game overlay: a plain
  always-on-top `eframe`/`egui` window that does **not** draw inside the target
  (the a separate always-on-top window model), launched from a game's `.n0x/` project and driven by
  `.n0x/hud.toml`. One shared `Engine` behind three background threads — a global
  low-level keyboard hook (hotkeys), a process watcher that auto-applies adapter
  plugins when the target appears, and a generic periodic plugin poller
  (`plugin_poll.rs`). Shipped: config-driven bindings (nothing hardcoded), write
  & freeze over the Phase 4b primitives (pointer-path locators included),
  global hotkeys with in-UI rebind + conflict detection, and (2026-07-22,
  **superseding** an earlier in-binary adapter registry) a **process-based
  plugin dispatch**: an `[[adapters]]` binding's `command` spawns a persistent
  `n0xis_sources::PluginSession`, and `on_launch`/`toggle_on`/`toggle_off`/
  `poll` become JSON ops on that session instead of a compiled-in Rust match —
  `n0xis-hud` itself carries **zero** game-specific logic; all of it lives in
  an external plugin process the user builds and points `command` at (see
  `docs/COMMUNITY_ROADMAP.md`'s "Plugin system", whose transport this reuses).
  ⚠️ Doc debt: the design docs under [`docs/n0xhud/`](docs/n0xhud/) still describe
  the *unbuilt* overlay/injection plan and use cheat-menu framing — stale, flagged
  for a rewrite; the shipped binary is the companion-window shape above.
- ✅ **Interception-driver actuation** (`interception.rs`). Dynamically loads a
  user-configured `interception.dll` (path from `hud.toml`, never hardcoded) and
  sends keystrokes through the kernel-class driver — needed because some games
  filter `LLKHF_INJECTED` and ignore the identical scancode sent via
  `SendInput` (confirmed live; `input probe` detects this directly). Two macro
  subsystems ride on top: fixed **sequences / "Combinations"** replay (via
  `SendInput`) and **stratagem macros** (via Interception) — both fully
  generic, config-driven, no game-specific code.
- ✅ **Bitsquid/Stingray + LuaJIT asset tooling** (`crates/n0xis-bitsquid`,
  `n0xis-lua`, `n0xis-luajit`; CLI `bundle {list,extract,repack}` and
  `lua {disasm,patch,strings,table,combo,seedscan}`). Offline bundle
  read/extract/repack and LuaJIT bytecode disasm/patch, plus **live GCstr/GCtab
  introspection** — decoding real LuaJIT object headers out of a running process's
  heap with pure memory reads (no debugger). None of these three crates is
  depended on by `n0xis-core` (the boundary law still holds).
- ✅ **Process-based plugin protocol** (`n0xis_sources::plugin` — `PluginCall`
  single-shot + `PluginSession` persistent, built on the same line-protocol
  plumbing `remote.rs` already proved; `.n0x/plugins.json` registry mirroring
  `selection.rs`'s storage pattern; `n0xis-pipeline::PluginHost` for
  analysis-result plugins; CLI `plugin {list,add,rm}`; MCP `plugin_list`/
  `plugin_run`) — the previously-only-*proposed* design in
  `docs/COMMUNITY_ROADMAP.md` now built and exercised by N0xHUD's own adapter
  dispatch above. Validated end-to-end (2026-07-22) by porting a real,
  previously in-binary game automation feature — an interact-combo auto-solver
  (transition-diff detection of a just-opened UI window, seed-derived exact
  solving for a high-stakes case, a safe brute fallback for the rest) — out of
  this repo entirely into an external plugin process, proving the protocol
  handles genuinely stateful, long-running automation, not just simple
  one-shot patches.

---

## Phase 11 — Agent consumability 🎯 ✅

Derived, like Phase 8, from a post-mortem rather than a wish list — this time from an
agent's session log against a Unity/IL2CPP target, with every claim re-measured against
the real binary before anything was built. The thesis of this project is *agent-native*;
these are the places the output was quietly hostile to its primary consumer.

- ✅ **Truncation is part of the contract** (`n0xis-contracts::Meta`) — `returned` /
  `total` / `truncated`, plus `note` for a *successful* result that reads as something it
  is not (`error.hint` only covers failures). Without this a reader cannot tell "40
  results" from "the first 40 of 277 199" and will conclude from a fragment. `with_page`
  derives `truncated`; `with_cap` reports it **without inventing a `total`** for producers
  that stop early on purpose.
- ✅ **`function discover --pdata` honours `--limit`** — it silently ignored it, returning
  **17.7 MB of JSON** (277 199 entries) on a 94 MB `GameAssembly.dll` when asked for 3.
  Now 459 bytes, with `meta.total` reporting the real count. `--offset` added to both
  discovery modes for paging; the prologue scan pages from the start of the range so a
  given page is the same set of addresses however it was reached.
- ✅ **The optimizer delta is opt-in** (`decomp pseudo --explain`). Measured on a real
  function: 59 518 bytes of delta against 42 306 bytes of pseudo-C — **the explanation was
  larger than the code it explained**, 59% of every payload, on the most-used command.
  It also duplicated `ir explain`, which is its dedicated home (CONCEPT §3 rule 3).
  `--explain` restores the byte-identical old payload.
- ✅ **`--addr-rva` hoisted into the shared source args** — was on three commands, absent
  from every `ir`/`decomp` command and from `provenance trace` *despite* pairing with
  `debug watch`, which had it. An RVA is the only address form that survives a restart, so
  the flag missing is exactly what pushes callers back to hand-computed absolute VAs.
- ✅ **`--addr-module` / `profile --module`** — found by running against the live game
  rather than reasoning about it. `--addr-rva` resolved against the *main* module, which
  is the wrong one for the most common real target there is: a Unity player EXE is 2
  exports and 319 functions while the 277 199 that matter are in `GameAssembly.dll`.
  `--addr 0xA54EC0 --addr-rva` landed on unmapped memory. Now selectable by
  case-insensitive substring, and a name that matches nothing fails loudly with the
  command that lists them. Verified live: `--addr-module GameAssembly.dll` produced a
  decompile byte-identical in extent to the static one at the same RVA.
  ⚠️ `debug watch` / `debug await-hit` / `provenance trace` still resolve `--addr-rva`
  against the main module only — same trap, not yet fixed there.
- ✅ **Indirect relays resolved, and detours detected** — also a live finding. Static and
  live thunk counts disagreed by one; the culprit was `il2cpp_resolve_icall`, `e9 …`
  (`jmp rel32`) on disk and `ff 25 …` (`jmp [rip+…]`) in memory. Thunk resolution now
  follows the pointer slot, with the read itself as the validation: a static image's
  unbound import slot points nowhere mapped and is correctly refused instead of yielding
  a confident wrong address. An indirect relay whose target lands *outside* the image is
  reported as `detoured_exports` + an advisory — the code running is not the code in the
  file, which silently invalidates static reasoning if nobody says so. On the live target
  it names all five MelonLoader hooks (`il2cpp_alloc`, `il2cpp_free`,
  `il2cpp_resolve_icall`, `mono_metadata_free_mh`, `mono_string_free`); the detour target
  belongs to no loaded module at all, i.e. an allocated trampoline. Computed
  unconditionally, **not** gated behind `--exports`: an advisory that only fires when the
  caller happened to ask for the full table is one that will be missed exactly when it
  matters.
- ✅ **`n0x profile`** (`n0xis-core::profile`, `n0xis.profile.v1`) — the "what am I even
  looking at" command. Image facts (sections, exports vs *distinct* addresses, branch
  stubs, `.pdata`), engine detection from export fingerprints held as **data**, IL2CPP
  metadata path + format version read from the blob header, and an `advisories` list
  naming which commands will be ineffective or degraded **on this target, with the
  reason**. Verified against the real target: reproduces in one call every fact that
  previously took a hand-written PE parser and a dozen steps — 386 exports on 279 distinct
  addresses, 39 folded groups, 49 thunks, 277 199 `.pdata` functions, metadata v31.
  Motivating failure: an agent ran `xref string` and `bindings list`, got `count: 0` from
  both, and concluded there were no references — when the format simply keeps those things
  outside the image. **A silent zero is the most misleading shape a result can take.**
- ✅ **The guide's recipes are now tested against the clap tree**
  (`guide_recipe_tests`) — the command list was generated and could not drift, but the
  hand-written `workflows` prose did: one recipe shipped `table add --name f --pid <p>
  --address <hit>` when the command takes `--addr`, has no `--pid`, and *requires*
  `--table`. The test asserts every step resolves to a real command, passes only flags
  that command accepts, and omits no required one. It caught all four defects on its
  first run; the recipe is fixed.

⬜ **Open follow-ons.** ICF folding means one address can carry many unrelated names
(measured: 23 on one address) — `profile` reports the groups, but the decompiler's
renderer does not yet know to refuse to pick one. And MCP still exposes 23 of the CLI's
85 commands, omitting the entire live-memory half that is the project's capability.

---

## Phase 12 — IL2CPP: the managed layer (Unity's hard mode) 🎯 ⏳

### Unity WebGL is the same phase, not a second one

Unity WebGL builds go through the **identical IL2CPP pipeline**: Roslyn → IL → C++ → native
code, shipped with the same `global-metadata.dat`. The managed half is therefore genuinely
portable, and the metadata parser of item 1 will serve Windows and WebGL builds alike — that
is the compatibility payoff, and it is a design decision taken at item 0 rather than a port
attempted later.

The **native** half is not portable at all, and the WebGL case is stranger than "a different
address space" — a point worth stating precisely, because the first draft of this section got
it wrong. A Windows dump's `Address` is an address: an RVA into a PE. **A WebGL dump's
`Address` is not an address at all.** It is an offset within a *signature-specific sub-table*.
Resolving it means finding the `dynCall_<signature>` function for the method's return and
parameter types, reading that function's base table index out of the module's own code, adding
the dump's offset, and using the result to index `WebAssembly.Table` — which finally yields the
wasm function index. Unity WebGL dispatches virtuals through the same machinery:
`VirtFuncInvoker` takes a slot from `klass->vtable`, adds a signature-related base, and issues
`call_indirect`.

Two consequences:

- The two are indistinguishable as integers and unrelated as meanings, and resolving the WebGL
  one requires a WASM front end this build does not have. So `AddressSpace` is carried on every
  imported index and checked before binding. A `wasm` index imports, persists and is searchable
  as a name table; it **cannot** be attached to a native target, and the refusal says why and
  what to do instead. It is deliberately not given a confidence score either — scoring a
  categorically wrong mapping would imply a better dump could fix it.
- **Item 6 (devirtualization from metadata) is not free on WebGL.** On a native target a vtable
  slot yields a function pointer; here it yields a table index that still needs the
  signature-base step. The metadata half transfers, the resolution step does not.

The practical shape of a WebGL target, for when item 1 arrives: `Build/<name>.wasm` holds the
transpiled code, and `global-metadata.dat` ships **inside `Build/<name>.data`** — the Emscripten
file-packager blob, which also carries `data.unity3d` — rather than loose on disk. Extracting it
is a packaging problem, not a metadata one, and once extracted it is the same file the Windows
parser reads. That is the compatibility payoff restated concretely: item 1 buys both platforms,
item 6 buys one and a half.

**The thesis: this is one missing layer, not five missing features.** Every IL2CPP symptom
on record — `xref string` → `count: 0`, `bindings list` → `count: 0`, **0 of 69** calls
named in `decomp pseudo`, no name→address path by any means — has a single cause: N0xis
reads the *native* half of an IL2CPP target and never the *managed* half. Build that half
once, behind seams that already exist (`SymbolProvider`, the pass `Ctx`), and the symptoms
clear together — without touching the decompiler, the xref engine, or the renderer.

### What IL2CPP is (the structural facts the phase is built on)

Unity ships two scripting backends. **Mono** emits real .NET assemblies
(`Assembly-CSharp.dll`) and JITs them — managed-assembly editors read them, edit them, write them back;
that target is solved and uninteresting. **IL2CPP** is ahead-of-time: Roslyn compiles C# to
IL, `il2cpp.exe` transpiles the IL to C++, and the platform C++ compiler emits native code.
The shipped game contains **no IL and no managed assemblies** — only machine code, exactly
like a C++ engine.

C# semantics (reflection, GC, boxing, generics, interfaces, exceptions) cannot survive that
trip inside the code alone, so IL2CPP splits the program into three parts that are only
meaningful *together*:

| Layer | Where | Holds |
|---|---|---|
| **Native code** | `GameAssembly.dll` `.text` | every transpiled C# method, plus `libil2cpp` — the C++ runtime, statically linked, exporting the `il2cpp_*` embedder API (measured: 386 exports on 279 distinct addresses, 49 thunks, 277 199 `.pdata` functions) |
| **Managed metadata** | `<Game>_Data/il2cpp_data/Metadata/global-metadata.dat` | the symbol table of the managed world: type / method / field / parameter names, tokens, generic containers, vtable slot layout, **and every string literal** (measured: 23 023 literals, ~672 KB) |
| **Registrations** | `.data` of the DLL — `Il2CppCodeRegistration`, `Il2CppMetadataRegistration` | the join key: per-module method-pointer arrays, generic instantiations, field-offset tables, metadata-usage slots |

**Neither half alone is enough, and that is the entire difficulty.** Names without addresses
(the `.dat`) plus addresses without names (the DLL); the join lives in a third structure a
naive tool never looks at. Every IL2CPP tool that exists is, at bottom, that join.

The corollary is the good news: an IL2CPP target is **native-speed code carrying a complete
symbol table**. Once the join is done it is better documented than a stripped C++ game —
every class, method, field, and offset, by name. IL2CPP is Unity's hard mode only until the
managed layer is parsed; after that it is one of the most tractable corpora in the industry.

### What is typical of the emitted code (conventions the decompiler cannot infer)

- **Hidden trailing argument.** Every method takes `const MethodInfo*` **last**; instance
  methods take `this` **first**. Recovered signatures are always one parameter "wrong".
- **16-byte object header** on x64 (`Il2CppClass* klass`, `MonitorData* monitor`), so
  `field_0x10` is the *first* managed field.
- **Null-check and bounds-check noise dominates the branch count** — `if (p == 0)
  <noreturn throw helper>()` before nearly every dereference; array accesses carry an
  index check. It is codegen, not logic.
- **Metadata-init prologue** — most methods open with a per-method `static bool inited`
  guard around a class-init call. Skip to the first statement touching an argument.
- **Generic sharing breaks 1:1 both ways.** Reference-type generics share one native body
  (disambiguated at runtime by the `MethodInfo*`/rgctx); value-type generics are duplicated
  per instantiation. One address ↔ many C# methods, one C# method ↔ many addresses. This is
  the easiest place in the whole format to state something confidently false.
- **String literals are `.data` slots**, populated at runtime from the metadata-usage table
  (in the `.dat` up to v26; moved into the binary's codegen modules at v27). Nothing to scan
  for in `.rdata` — but the *slot* is xref-able, which is the working route.
- **Virtual dispatch** through a vtable slot on `Il2CppClass`; interface dispatch through
  per-class interface-offset tables. Statically an indirect call with no resolvable edge —
  unless you have the metadata, which states the slot layout outright.
- **Internal calls (icalls)** — engine natives like `Transform::get_position_Injected` are
  *not* transpiled C#; they are resolved by name string through `il2cpp_resolve_icall`
  against registration tables of `{const char* name, void* fn}` **that do live in the
  binary** (see the hypothesis below).
- Metadata format versions 16–31 in the wild; measured target reported **31**. The 24.x
  family carries sub-versions **not** recorded in the header — inferable only from structure
  sizes, which is why every tool in this space is version-fragile.
- Typical defenses, in rough order of frequency: name obfuscation before transpilation
  (Beebyte-class — metadata intact, names garbage), and encrypted / relocated
  `global-metadata.dat` with a patched loader (file useless, memory fine).

### What fails today, and the one reason

Measured 2026-07-30, n0xis 0.1.0, Unity 2022.3 x64, `GameAssembly.dll` 94 MB.

| Command | Result | Real reason |
|---|---|---|
| `xref string` | `count: 0` | literals are in the `.dat`, materialized by index |
| `bindings list` | `count: 0` | *for managed methods* — no name strings in the image to pair (**but see the icall hypothesis**) |
| name → address | no path | needs the metadata × registration join, which nothing parses |
| `decomp pseudo` call naming | 0 / 69 named | callee names live in the metadata; export thunks recover only the runtime API |
| `xref to` / `function trace` on virtual calls | incomplete | vtable slot dispatch — the slot table is in the metadata |

`profile` already detects the target and says so in `advisories` (Phase 11). This phase is
what turns those advisories from *"this will not work here"* into *"run `il2cpp index`"*.

### Managed provenance (the item that justifies the phase)

N0xis already has the three pieces this needs: **hardware watchpoints × a real
cross-process x64 unwinder × a decompiler** (Phases 4b/4c). On an IL2CPP target that
currently answers *"`sub_18069d4d0` wrote your value, called from `sub_…`, `sub_…`"* — true
and nearly useless.

With the managed layer, the same machinery answers **"`PlayerHealth::ApplyDamage` wrote it,
called from `CombatResolver::Resolve`, called from `EnemyAI::Update`"** — a *C# stack trace
recovered from a hardware watchpoint on a memory address*, with no injection, no loader, and
no managed debugger. Generic-shared frames disambiguate through the hidden `MethodInfo*`
argument, which is *in a register at the moment the watchpoint fires* — a fact only a live
tool can use, and the exact place a static dumper cannot follow.

Nothing in the ecosystem does this. Il2CppDumper is static; a memory scanner cannot name IL2CPP
frames; a MelonLoader/HarmonyX mod can hook a method it already knows but cannot start from
an address and ask *who touched it*. **Sequence the phase so this lands as early as the
dependencies allow** — it is the point of the phase, not step 4 of a list.

A second, quieter win of the same kind: **static fields make pointer paths largely
unnecessary here.** Most game singletons are a static `Instance`; the metadata gives the
klass, the klass gives `static_fields`, and that is a stable, restart-survivable anchor
derived by name instead of by AOB/pointer scanning. On this corpus that replaces the single
most laborious classic workflow.

### Prioritized plan (leverage × cost)

0. ✅ **Import an external dump first — ~80 % of the pain gone.**
   `il2cpp import --script-json <Il2CppDumper output>` → a name index in `.n0x/il2cpp/`,
   served through the existing `SymbolProvider` seam. Named lookups *before* a single byte
   of metadata parser exists. Not scaffolding to throw away: it stays as the fallback for
   versions and obfuscations the native parser refuses, and as the interop path into an
   ecosystem that already exists (Il2CppDumper, Il2CppInspector, Cpp2IL).
   **Landed on `feat/phase13-net`** (one branch for 12 and 13 — see the sequencing note):
   `crates/n0xis-il2cpp`, 18 unit tests + an 8-test CLI exit test, clippy clean, boundary
   gate green. Three decisions carry the weight:
   - **The address convention is measured, not assumed.** Dumper versions disagree about
     whether `Address` is an RVA or an already-based VA, and the two are numerically
     indistinguishable — so both are tried against the target's own `.text` and the winner
     must clear `MIN_BIND_CONFIDENCE` (90 %). Only *method* symbols are sampled; metadata
     slots live in `.data` and would drag both counts down equally, hiding the signal.
     Verified on a real PE: an RVA dump scores 4/0, the same functions as absolute VAs score
     0/4, and each is detected correctly. **A dump from another build is refused** — with the
     measurement in the message — rather than applied, because on this corpus a confident
     wrong name poisons every downstream command at once. `--force` exists and stores the
     index without pretending the binding is sound.
   - **Address spaces are explicit, and that is the whole Unity-WebGL story** (see below).
   - **Name lookup returns a set, never one entry**, per item 2's rule — generic sharing and
     ICF both make the single-answer API a lie, and the test asserts two C# methods on one
     address.
   - ⬜ Still open here: `Il2CppSymbols` is not yet *chained* into the source seam, so
     `decomp pseudo` and `xref` do not consume it automatically. That is item 2, and it is
     now a wiring change rather than a design one.
1. ⏳ **`crates/n0xis-il2cpp` — the native parser.** Header + string table + type / method /
   field definitions + literals + generic containers from the `.dat`; `Il2CppCodeRegistration`
   / `Il2CppMetadataRegistration` located in the image (registrar export → `lea` operand,
   with a validated structural scan as fallback). **Hold per-version struct layouts as
   data**, one table, never `if version == 29` scattered through the code — the same shape
   `profile.rs` already uses for engine fingerprints and `signatures.rs` for API tables.
   **Self-validate and refuse:** string offsets in range, method RVAs inside `.text`, field
   offsets below `instance_size`. A garbage index that *looks* like symbols is the worst
   possible failure for a `sound over complete` tool (CONCEPT §3 rule 6) — it manufactures
   confident wrong names in every downstream command at once.
   `il2cpp index` builds it once and caches into the project store (Phase 6).
   - ✅ **The version-independent half reads, and is now reachable.** `metadata.rs` takes
     only what sits at byte offsets that do not move between versions — the sanity word, the
     format version, the twenty offset/size pairs through `typeDefinitions`, and the string
     literals — and refuses everything else rather than guessing a stride. `il2cpp metadata`
     is the command that reaches it (the parser landed first and sat unreachable, which is
     dead code however good it is): version, the table inventory, and a case-insensitive
     literal search with real paging.
     **Measured on a real target** (`Pit of Goblin`, Unity IL2CPP, `global-metadata.dat`
     22 984 696 bytes): version 31, **23 023 literals**, `string_literal_data` 672 564 bytes,
     and **zero** non-UTF-8 entries — the module's own tripwire for a wrong stride, clean.
     Searching returns real game text (`EnemyHealth`, `Drink_HealthPotion`,
     `ActivateDamageZoneRpc`, `Dealing Damage to: `). That is the first thing on this corpus
     that answers *"is this on-screen text in the game"* **with no external dumper at all** —
     the question `xref string` structurally cannot answer here, since the literals are not
     in the image.
   - ✅ **The Unity directory layout is knowledge held once.** `--file <image>` finds the blob
     in a sibling `*_Data/il2cpp_data/Metadata/`; `profile` and `il2cpp metadata` now share
     that rule (`n0xis-frontend::il2cpp_caps::find_metadata_near`) instead of carrying a copy
     each. It lives in the frontend rather than `n0xis-il2cpp` on purpose: that crate is
     byte-pure — bytes in, structures out, no filesystem.
   - ✅ **The answer states its own ceiling.** A literal carries a metadata *index*, not an
     address, so `meta.note` says the obvious next move does not work yet: mapping a literal
     to the `.data` slot the code loads it from is item 5, and without it these are not
     xref-able. A high non-UTF-8 ratio replaces that note with a stride warning naming the
     version.
   - ⬜ **Still the version-dependent half**: methods, types, fields, generics — and with
     them the registration join that turns a name into an address. That is the remaining bulk
     of this item, and the part that needs per-version layouts tabulated as data.
2. ⏳ **Wire the seams — where the payoff actually arrives.** The chaining is in and the
   naming is real: with an index in the project, `decomp pseudo` renders a call as
   `GameAssembly_dll__PlayerHealth__ApplyDamage` where it previously rendered
   `sub_14004d650`, and every pass going through the shared function-scoped helper gains it
   with **zero changes of its own**. Three things this actually took, and two it did not
   deliver:
   - ✅ **`ChainedSymbols` lives in the seam, not in this phase.** Two providers consulted as
     one, and **the tighter fit wins rather than the first answer**: both report the address
     they matched, so the symbol starting closest at-or-below the query is preferred. A plain
     `or_else` would let the index's function-span attribution swallow an exact export hit
     underneath it.
   - ✅ **Live targets get names too.** `LiveProcess` provides no symbols at all — the
     standing "no symbols on `--pid`" blind spot — and an imported index attaches to it
     directly. For a Unity target that blind spot is now partly closed.
   - ✅ **Attachment is never fatal and never silent.** A missing index is the ordinary case;
     a present-but-unusable one (wrong build, wasm, no `.text`) is reported in `meta.note`
     with the reason, because a user who just ran `il2cpp import` and sees unnamed output
     must be told why rather than left guessing.
   - ✅ **A function now names itself, not only its callees.** `decomp.rs` formatted the
     signature line with a hardcoded `sub_{:x}`; it consults `ctx.symbols` and falls back to
     the address, so a target with no symbols renders exactly as before (138 core tests
     unchanged — no goldens moved). **Only an exact hit on the function start counts**: the
     index attributes a whole span to its symbol, so accepting a near miss would label a
     function after whichever one precedes it. There is a test that asserts a symbol
     `0x10` below the entry does *not* name it.
   - ✅ **The range-scoped helper chains too — the claim above was half true when written.**
     "Every pass gains it with zero changes of its own" held for the *function*-scoped helper
     only; `with_src_ctx` — `xref to`/`from`, `xref string`, `ir manifest`, `function trace` —
     never attached the index at all. Now it does, on the same non-fatal terms.
   - ✅ **And discovery names what it finds.** Chaining alone changed nothing observable
     there, because `DiscoverPass` formatted `sub_{:X}` unconditionally and never consulted
     `ctx.symbols` — the same defect `decomp.rs`'s signature line had. Fixed with the same
     exact-hit rule, so `ir manifest` on an indexed target ranks *named C# methods* instead of
     a wall of `sub_`: triage is read as a list, which is where names pay off most. Two tests
     assert both halves of the rule, and the near-miss one lives at the integration level
     because `Snapshot` resolves symbols by exact address and therefore cannot express a
     covering symbol at all — a unit test there would have passed without the fix.
   - ⚠️ **Known gap, stated rather than left to be discovered:** `function discover --pdata`
     is a hand-written CLI handler, not a registry capability, and it builds a `Ctx` carrying
     no symbol provider whatsoever — so the *authoritative* discovery path on x64 PE still
     reports `sub_` even with an index loaded. `discover_pdata`'s doc comment says so at the
     source. Closing it means routing that handler through the capability seam.
   - ⬜ **The name→address direction is deliberately not on the seam yet.**
     `Index::find_by_name` exists and already returns a set (never one entry — generic
     sharing and ICF both make the single-answer API a lie), reachable through
     `il2cpp symbols`. Promoting it to `SymbolProvider` is held back until there is a second
     implementor or a real consumer: a trait method every provider must stub out is the
     speculative generality the debts section already argues against for the VM seam.
   - 🐛 **Found while wiring this: the artifact cache key ignored the symbol provider.**
     `cfg_cached` keyed on `source.label() + input + bytes`, but a CFG artifact embeds
     *resolved* call names — so a function analyzed before an index existed kept its unnamed
     artifact forever, and importing an index appeared to do nothing until `.n0x/ir-cache/`
     was deleted by hand. Measured, then fixed by adding `SymbolProvider::symbol_fingerprint`
     (default empty, so providers deriving names from the same bytes leave existing keys
     untouched) and folding it into the cache scope. Regression test asserts the whole
     sequence: analyze → import → re-analyze, with no cache clearing in between.
3. ⬜ **Managed provenance** (the item above) — `debug watch` / `provenance trace` /
   the unwinder resolve frames through the index, and disambiguate shared generic bodies via
   the live `MethodInfo*`. Depends on 1+2 and on nothing else; do not let it drift to the end.
4. ⏳ **Types, objects, and the live klass route.**
   - ✅ **`il2cpp icalls` — the engine half, and the first thing here that names anything on
     a live process.** The measurement that killed the `bindings list` hypothesis handed this
     over: there is no static `{name, fn}` table, but the *cache slot* is static, so
     name → slot recovered from the code becomes name → real address the moment a process
     runs. `IcallPass` matches the measured shape (`lea reg,<name with ::>; call <resolver>;
     mov [rip+slot],rax`) and reports the resolver targets with site counts — thousands of
     sites on one address is the evidence the shape matched, several means it matched
     something else too. Measured live: 1074 sites → 424 distinct entries, 212 with slots,
     two resolvers at 537 sites each; `Transform::get_position_Injected` → `0x7ff9d0d41a00`.
     **Those addresses land outside `GameAssembly.dll` — in `UnityPlayer.dll`** — which is
     the correctness signal: the pass never looks there, the process points there itself.
     A null slot means the game has not called that icall yet, and is reported as such
     rather than as address 0.
   - ✅ **`il2cpp obj` — the live klass route, and it needs neither a metadata parser
     nor a dumper.** `*(void**)addr` is an object's `Il2CppClass*`, and from there the type
     name and every field name and runtime offset follow. The layout problem is solved by
     **discovering and validating rather than hardcoding**: `Il2CppClass` carries `name` and
     `namespaze` in adjacent pointer slots, and `FieldInfo.parent` **points back at the class
     being examined** — an invariant a wrong guess cannot satisfy. Every result reports the
     offsets it discovered, so the inference is auditable instead of asserted.
     **The live run changed the design.** A name pair alone turned out to be too weak:
     `Il2CppImage` opens with `{ const char* name; const char* nameNoExt; }` and came back as
     a class called `mscorlib.mscorlib.dll`; stray pairs in unrelated structures did the same.
     Every *true* class hit — and no false one — also produced a back-referencing field array,
     so results now carry `confidence: validated | weak-name-pair-only`. Measured on the
     running game: `Unity.Collections.Allocator` (validated, 8 fields, `value__@0x10` after
     the 16-byte header, enum constants at 0), and a real game class
     `Entities.States.DeflectState` (validated, `BodyObjectToHide@0xb8`,
     `BodyObjectToShow@0xbc`, `UseAnimationLength@0xc0`) — beside the two coincidences,
     correctly marked weak.
     ⚠️ **Found while verifying this: `mem map` defaults to `limit` 200.** The full map of
     the target is 5292 regions / 3.5 GB; the default made it look like 256 regions and
     3.8 MB, which is what stalled the search for a managed object for several rounds. Not a
     silent cap — `limit` is a documented flag — but a default that reads as a complete answer.
   - ✅ **`il2cpp classes` — and now the pair is self-sufficient.** `il2cpp obj` needed an
     address from somewhere; this finds them, using the one property every managed object
     has: its first word is its `Il2CppClass*`. So the most-repeated pointer-like values in a
     heap sample **are** class pointers. Samples the largest writable private regions, ranks
     by repeat count, and keeps only candidates whose field array points back at them.
     Measured live: 1 MB across 8 regions → 12 474 distinct pointers, 2000 probed, 16 dropped
     as weak, **15 classes** — `System.Int32`, `System.String`, `UnityEngine.Object`, and the
     game's own `PassiveItem_Key`. Every answer states it is a *sample*, with the probe
     denominator, because a capped search must not read as an inventory.
   - 🐛 **Closing the loop found a real bug.** Feeding an enumerated class address back into
     `il2cpp obj` returned `mscorlib.mscorlib.dll`: the pass tried the object reading first
     and stopped there, and `Il2CppClass` opens with `Il2CppImage* image` whose own first two
     fields are a name pair. So the *interpretation* was being chosen without meeting the
     evidence bar the rest of the module insists on. Fixed by preferring whichever reading —
     object or class — yields a back-referencing field array, falling back to a bare name pair
     only when neither does. After the fix the same address answers
     `PassiveItem_Key` (validated, class not object) with `m_identifierToActivate@0x20`,
     `m_inventoryItem@0x28`, `m_uses@0x30`, `m_keyUnlockSound@0x38`. Regression test included.
   - ⬜ Still to come: `il2cpp type` by *name* (needs the metadata join), `scan dissect
     --as-type`, `il2cpp static <Type>::<Field>` as the anchor primitive, and object-graph
     walking with `Il2CppString`/array decoding. Also the enumerator that makes `il2cpp obj`
     self-sufficient: today you need a klass address from somewhere (a scan hit, or
     frequency analysis over a heap region — the technique the live verification used).
     Superseded framing of the original bullet: `il2cpp type` (fields, offsets, size,
     parent, statics, vtable); `scan dissect --as-type`; **address → klass → field name**, the
     reverse lookup that ends a scan session in one step instead of an afternoon;
     `il2cpp obj <addr> --depth N` walking the managed graph with `Il2CppString` (UTF-16 +
     length) and array decoding; `il2cpp static <Type>::<Field>` as the anchor primitive.
     ⚠️ **Prefer runtime offsets when a process exists** — from v24.5 field offsets live in the
     binary's registration, and generic-instance layouts are computed at runtime; the `.dat`
     alone is not authoritative for either.
5. ⬜ **Strings, properly.** Literal index → metadata-usage slot → `xref to` on the slot.
   This is what makes "find the code behind the text on screen" work here, and it is the most
   common entry point in practice. Composes directly with Phase 9's `ui locate`: on-screen
   text → managed `TMP_Text` instance → backing field → writing method.
6. ⬜ **Devirtualization from metadata.** Vtable slot + interface-offset resolution turns
   Phase 10's hardest ❌ item (*indirect / virtual call resolution*) from "needs a real
   points-to analysis" into a table lookup **on this corpus**. Cheap here, expensive there —
   take the cheap one.
7. ⬜ **Outputs for mod authors** (the data seam earning its keep):
   `il2cpp emit-hook --loader melon|bepinex` (HarmonyX skeleton with the correct signature,
   hidden `MethodInfo*` included) or a native trampoline through the existing journaled
   `patch detour`; `il2cpp emit-offsets --format cpp|rust|json`; export back to
   `dump.cs`/`script.json` shape for ecosystem interop.
8. ⬜ **`il2cpp diff --old <index> --new <index>` — the maintenance killer.** What an update
   broke: methods moved, field offsets shifted, signatures changed. Combined with `.n0xt`
   tables and `diff functions`, this is **automatic offset migration for an existing mod** —
   the one problem every mod author has forever and no RE tool addresses, because no RE tool
   holds both indices and the user's own address table.

### Cross-target verification — the answer to "does this work on IL2CPP, or on *that game*"

Everything above was measured on one target, which supports "works on this game" and not the
claim the phase actually needs. So the Steam library was inventoried and every IL2CPP build
in it run through the same battery. Three real targets, three **different metadata versions**;
the three other Unity games installed are Mono (`Managed/Assembly-CSharp.dll`, no
`il2cpp_data`) and are correctly not treated as IL2CPP.

| | Creeper World 4 | I See Red | Pit of Goblin |
|---|---|---|---|
| metadata version | **24** | **29** | **31** |
| `GameAssembly.dll` | 42.5 MB | 45.1 MB | 94.0 MB |
| exports / distinct | 240 / 216 | 388 / 285 | 386 / 279 |
| `.pdata` functions | 134 265 | 144 975 | 277 199 |
| executable sections | `.text` + `il2cpp` | `.text` + `il2cpp` | `.text` + `il2cpp` |
| `.text` share of code | 8.8 % | 10.4 % | 10.6 % |
| literals decoded / non-UTF-8 | 18 244 / **0** | 16 190 / **0** | 23 023 / **0** |
| icall names in `.rdata` | 1740 | 1911 | 2473 |
| icall resolution sites | ~~72~~ **3454** | ~~0~~ **4053** | ~~1074~~ **50 875** | ⚠️ see the correction below |
| live klass `name_offset` | **0x10** | not launched | **0x10** |
| live klass `fields_offset` | **0x80** | not launched | **0x80** |

**What this establishes.** The two-executable-section layout is a property of IL2CPP, not of
one build (3/3, with `.text` holding under 11 % of the code every time). The metadata reader's
version-independent header prefix holds across v24, v29 and v31 — 57 000 literals decoded with
**zero** non-UTF-8 entries, which is the module's own tripwire for a wrong stride, clean on all
three. The runtime klass route discovered the *same* offsets on v24 and v31 (`name` at `0x10`,
`fields` at `0x80`), and on Creeper World 4 recovered 98 classes including `TMPro.TMP_Text`
(229 fields) and `TMPro.TMP_FontAsset` (55 fields, `m_SourceFontFileGUID`,
`m_AtlasPopulationMode`, `m_GlyphLookupDictionary` — unmistakably real).

**What it disproved, and the fix.** The icall shape is **not** universal. I See Red has 1911
icall names in `.rdata` and **nothing in the image references them** — verified three ways: no
referencing `lea` (`xref string` finds the string but no xref), no absolute 8-byte pointer, no
4-byte RVA. So `il2cpp icalls` correctly returned zero, and returned it *silently*, which is
the exact failure this project exists to prevent. `names_in_data` now distinguishes the three
possible zeros:

- names present, no sites → *this build does not use the load-name/call-resolver/cache-slot
  shape; the names are real, the live-address route is not available here*
- no names, no sites → *not an IL2CPP image, or the wrong module/section was scanned*
- sites found → the ordinary case

Creeper World 4 is the intermediate case that makes the point: 1740 names, only 72 sites. The
shape is a **codegen option, not a format guarantee**, and the tool now says so per target.

#### ⚠️ Correction (2026-08-09): the icall finding above was wrong, and the cause was ours

The row reading "icall resolution sites: 72 / **0** / 1074" and the conclusion drawn from it —
*"the icall shape is a codegen option, not a format guarantee"* — are **withdrawn**. The shape
held on 3/3. What varied was how much of each binary the tool actually looked at.

`Arch::decode_stream` stops at the first instruction that does not decode. That is right for a
*function* — an undecodable byte means the function ended — and catastrophic for a *section*,
because a compiled section carries jump tables, alignment padding and data islands between
functions. Four passes swept whole sections through it: `xref`, `xref string`,
`bindings list`, `il2cpp icalls`.

Measured coverage before the fix:

| | `.text` swept | `il2cpp` swept |
|---|---|---|
| Pit of Goblin | 85.9 % | **0.45 %** |
| Creeper World 4 | 23.2 % | 0.31 % |
| I See Red | **5.1 %** | 1.47 % |

Counting only the sites inside those swept prefixes reproduces the old output exactly —
1074, 72 and 0 — which is what makes this a diagnosis rather than a theory.

`Arch::decode_range` now resynchronizes past undecodable bytes instead of stopping, and the
four section-wide passes use it. Re-measured:

| | sites before | sites after | distinct icalls | with cache slot |
|---|---|---|---|---|
| Creeper World 4 (v24) | 72 | **3454** | 1745 | 1397 |
| I See Red (v29) | **0** | **4053** | 1916 | 1893 |
| Pit of Goblin (v31) | 1074 | **50 875** | 4921 | 2448 |

Independently confirmed by a brute-force byte scan for `lea reg,[rip+disp32]` landing on a
known name address — disassembler-free, and it puts the true totals at 3447 / 4041 / 50 875.

**Three lessons worth more than the fix.**

1. **The defect was not IL2CPP-specific.** Any large binary with data between functions was
   being scanned in part and reported as if in whole. IL2CPP merely made it visible, because
   its code sits in a 61 MB section where the first jump table arrives early.
2. **"Verified three ways" was one way.** Two of the three checks — "no referencing `lea`" via
   `xref string`, and the site scan — ran through the *same* truncating sweep. The third, "no
   absolute pointer to the name", returns zero on a healthy IL2CPP build too, because the
   format never stores such pointers. Independent-looking checks that share a mechanism are
   not independent, and that is what let a wrong conclusion feel measured.
3. **The zero could not argue back.** `xref string` returned `count: 0` for both "not in this
   binary" and "here, but nothing scanned references it". It now reports
   `found_unreferenced` beside the count, so those two opposite facts stop sharing one number.

### Two routes to the same facts — keep both

| Route | Wins | Costs |
|---|---|---|
| **File** — parse `.dat` + registrations statically | deterministic, ASLR-free, reproducible, no running game | dead against on-disk encryption; version-fragile |
| **Runtime** — read `Il2CppClass` / `MethodInfo` from a live process (`klass->name` is a `const char*` into the mapped metadata blob) | survives on-disk encryption and metadata relocation; authoritative offsets; the only route to `MethodInfo*` disambiguation | needs the game running; klass layout is itself version-fragile |

And the bridge between them: **`il2cpp index --pid`** — recover the metadata blob from the
running process (it is decrypted in memory by definition) via the existing `snapshot dump`,
then index it like a file. Honest framing: memory-dumped metadata is not novel — Il2CppDumper
accepts a dump, and external dumpers exist. What is ours is that it is *one tool, one
command*, snapshot-backed and therefore replayable and checkable by someone else.

### Hypotheses to measure before building on them

- ✅ **Measured 2026-08-08 — the advisory was overstated, and the mechanism was not what the
  hypothesis said.** Half right is the honest verdict, and both halves matter:
  - **The name strings are in the image.** 2189 distinct `UnityEngine.X::Y` internal-call
    names in `.rdata` of the measured `GameAssembly.dll`, e.g.
    `UnityEngine.Transform::get_position_Injected` at `0x1842c0630`. So *"IL2CPP has no
    binding-name strings in `.rdata`"* was simply false, and it was steering callers away
    from a command that works.
  - **`xref string` finds them** — 4 referencing `lea rcx,[1842C0630h]`, in 0.37 s. It
    returned `count: 0` only because its code window defaulted to `.text`, which on this
    target is not where the code is (see the finding below).
  - **But `bindings list` still cannot work, for a different reason than stated.** There is
    no static `{name, fn}` table at all: a byte search found **zero** pointers to that string
    anywhere in the file. The emitted shape is
    `lea rcx,<name>; call <resolver>; test rax,rax; mov [<.data slot>],rax` — the name is in
    the image, the function pointer is produced at runtime and cached. A static name/pointer
    pairing does not exist to be found.
  - **And that leaves something better than the hypothesis asked for.** Each icall name is
    statically bound to *its own runtime cache slot*. Read those slots in a live process and
    you get 2189 engine functions with real addresses and real names — on a target whose
    standing description is "no symbols on `--pid`". Worth a command of its own; folded into
    item 4's live-klass work rather than left as a note.
  - Advisories corrected accordingly (`xref string` → `degraded` with both halves stated;
    `bindings list` → `ineffective` for the *right* reason), with tests pinning the wording.
- ⬜ **Cpp2IL as the obfuscation fallback** — worth evaluating as an *import* source (like
  item 0) for targets whose metadata is renamed or unreadable. Evaluate; do not reimplement.

### The finding that came out sideways: `.text` is not where the code is

Chasing the icall hypothesis turned up something larger and **not IL2CPP-specific**. On the
measured `GameAssembly.dll` the section table reads:

| Section | Characteristics | Virtual size |
|---|---|---|
| `.text` | `0x60000020` — CODE, EXECUTE, READ | 7 247 840 |
| **`il2cpp`** | `0x60000020` — **identical** | **61 303 411** |

Unity puts the transpiled C# in a section of its own and leaves `.text` holding the runtime.
Every range-scoped command defaults its code window to `.text`, so **`xref`, `xref string`,
`function discover`, `ir manifest` and `function trace` were scanning 10.6 % of the binary
and reporting the other 89.4 % as containing nothing** — not as out of range, not as
truncated. A silent zero, which Phase 11 exists to make impossible.

- ✅ **`profile` now sees it and says so.** `SectionInfo` carries `executable`
  (`IMAGE_SCN_MEM_EXECUTE`), and any executable section besides `.text` raises an advisory
  naming the affected commands **and handing over the exact window to pass**
  (`--start 0x1806eb000 --size 0x3a76a73`). Fires on any PE, not just Unity ones; two tests,
  one asserting the ordinary single-code-section image grows no warning it does not need.
- ✅ **`code_ranges()` on the seam — the real fix, landed.** A single `(start, size)` cannot
  express this target, and widening it does not help on its own: `MemorySource::read` is
  specified to truncate at the end of the region it started in, so a window spanning both
  sections would still stop at the end of `.text`. So the seam grew
  `code_ranges() -> Vec<(Va, u64)>`, defaulting to `code_range()` as a one-element list —
  a source that knows one extent behaves exactly as it did. `StaticPe` reads
  `IMAGE_SCN_MEM_EXECUTE` from the section table; `LiveProcess` parses the same bits out of
  the mapped headers.
  - `xref` and `ir manifest` scan every window and merge; the manifest's `limit` is shared
    across windows rather than applied afresh to each. `xref string` scans every code window
    against one data window and merges hits **by address** — the data side does not move, so
    concatenating would report one literal several times with its references split up.
  - 🐛 **A third consumer nobody had listed: `switch.rs`.** Its is-this-code gate took a
    single range, so every jump table in the second section was rejected and switch recovery
    quietly gave up on the bulk of the code, reporting it as unresolved. Fixing the seam
    fixed it; fixing the symptom never would have found it.
  - ✅ **`--module` on the range-scoped commands**, because a *live* Unity target needs it:
    the main module is a thin player executable and the code is in `GameAssembly.dll`, so
    `code_ranges()` alone answered about the wrong module. Both windows are module-scoped —
    fixing only the code side was measurably worse than fixing neither (61 MB scanned against
    the *player's* `.rdata`, finding nothing, slowly). An unmatched name **refuses** rather
    than falling back to the main module.
  - **Verified against the running game, and cross-checked against the file.** Live
    `xref string --pid --module GameAssembly.dll` finds the icall literal at
    `0x7ff9b6dd0630` with four referencing `lea`s; converting by the live module base gives
    rva `0x42c0630` and xref rva `0x725e83` — **identical to the static run's**
    `0x1842c0630` / `0x180725e83`. Two independent paths, same answer.

### What this phase deliberately does **not** build

Not a C# decompiler, not a mod loader, not a managed injector, not an IL reconstructor.
BepInEx/MelonLoader/Il2CppInterop own *running* mods and do it well; N0xis's contribution is
analysis, localization, provenance, and journaled patching. `emit-hook` generates a skeleton
for someone else's loader — that is a data-seam output, not an ambition to become one.

### Framing rules this phase encodes

- **Fix the layer, not the symptoms.** Five commands are broken; there is one cause. A patch
  per symptom would have produced five special cases and no name→address path at all.
- **Version-fragility is the permanent cost of this format** — pay it once, as data, with
  validation and an honest refusal. A tool that emits wrong names is worse than one that
  emits none, and on this corpus wrong names are *easy* to emit.
- **Say which layer a fact came from** — metadata, export table, live klass, or inference
  from code shape — and never collapse a generic-shared or ICF-folded set to one name.

---

## Phase 12b — .NET NativeAOT: the managed layer, other half 🎯 ✅

The sibling of Phase 12. Where IL2CPP is Unity's managed-name problem, **NativeAOT** (`ILC` /
`PublishAot`, the shape a modern Godot-C# or .NET game ships) is the CoreCLR one: the compiler
strips ordinary symbols, so `disasm`/`decomp` see only `sub_XXXX` and a config read by enum
index leaves no string to `xref`. But the managed names are still *in the image*, in the
NativeAOT reflection/stack-trace metadata — and this phase parses them, universally, with no
per-target hardcode.

- ✅ **`aot symbols --file | --pid`** (`n0xis.aot.symbols.v1`) — reconstructs a full
  `RVA ↔ Namespace.Type.Method(params)` map for any .NET 8 NativeAOT image. Same parser on a
  static PE and a live module (native or under Wine), through the `MemorySource` seam.
- ✅ **Two metadata sources, merged and tagged.** It locates the `ReadyToRunHeader`, reads the
  `EmbeddedMetadata` (NativeFormat) and both:
  - the **stack-trace `RvaToTokenMapping`** — a linear map, framework/generic-heavy; and
  - the **reflection `InvokeMap`** — a `NativeHashtable` whose entrypoint indices resolve
    through the `CommonFixupsTable` external-references table, joined to the method's declaring
    type by walking the metadata type tree. **This is the one that resolves a game's own
    gameplay methods** (the stack-trace map largely does not).
  Each symbol carries its `source` (`stacktrace` / `invoke`); the artifact reports
  `stacktrace_count` / `invoke_count`.
- ✅ **A full NativeFormat reader, ported to Rust** — the low-bit-count varints, the
  generic-vs-typed handle encodings (`type<<24|offset` vs `offset<<8|type` — the trap that ate a
  session), `ConstantStringValue`/`Method`/`TypeDefinition`/`TypeReference`/`NamespaceDefinition`
  records, and the `MethodNameFormatter` name assembly. **OOM-proof by construction:** never
  allocates on a length read from parsed bytes.
- ✅ **`profile` detects it** — `engine: nativeaot` via the `DotNetRuntimeDebugHeader` export,
  with an advisory pointing at `aot symbols`.
- ✅ **Enables the live-patch workflow** — the recovered RVAs feed `decomp pseudo --addr`
  (now with named calls) and the [Phase 14 `debug watch --exclude-rip`](#phase-14--cross-platform-the-linux-native-live-track-) setter hunt.
- **Measured:** on `UnrailedGodot.dll` (Unrailed! 2, Godot-C# NativeAOT, .NET 8, ReadyToRun 9.1)
  → **208 056** methods (91 136 stack-trace + 116 920 invoke); `common.*` fully covered, and
  gameplay targets resolve, e.g. `common.Unrailed2.UI.Drawer.GameSetupMenu.GetMaxPlayersOptions
  @ 0x122f520`.
- ⬜ *Follow-ons:* `VirtualInvokeMap` (virtual/interface method entrypoints), and feeding the
  map into `decomp`/`function discover` as a `SymbolProvider` overlay so **every** call renders
  named, the way an imported IL2CPP index does in Phase 12.

---

## Phase 14 — Cross-platform: the Linux-native live track 🎯 ⏳

Goal stated once: make the *live* half of the toolkit as portable as the analysis half
already is, and — because the machine is now Linux — **exploit what Linux exposes that
Windows gated behind a signed kernel driver or blocked outright**. This is not a 1:1 port
of the Win32 adapters. It is: keep the core untouched, write a Linux adapter behind each
existing seam, and where Linux offers a strictly stronger primitive, prefer it.

### The strategic thesis (why Linux, not just "also Linux")

On Windows, several of the capabilities this tool wants are either driver-only or actively
fought by the kernel: hardware watchpoints and stealthy cross-process reads want a driver;
**PatchGuard/KPP**, **Driver Signature Enforcement**, **HVCI/VBS**, and vendor **kernel-mode
anti-cheat** exist specifically to stop the rest. On Linux the equivalent power is in the
kernel already, reachable from an unprivileged (or `CAP_SYS_PTRACE`) userspace process
through plain syscalls — no signed driver, no code-integrity fight:

- `process_vm_readv`/`writev` + `/proc/<pid>/mem` — cross-process RW that on Windows people
  ship a driver for. **Already used** by the Linux adapter (write falls back through
  `/proc/<pid>/mem` to bypass page protection for patching).
- `ptrace` — full debug control (attach, register file, `POKEUSER` on the debug registers
  DR0–DR7 for **hardware watchpoints**, `int3` software breakpoints, single-step) in
  userspace. On Windows the DR0–DR7 path is what the Win32 debug adapter fought anti-debug
  over; here it is a syscall.
- `perf_event_open(PERF_TYPE_BREAKPOINT)` — per-thread hardware watchpoints delivered via a
  ring buffer **without stopping the thread**, and a sampling profiler that can grab a stack
  at frequency (which our unwinder then walks).
- **uprobes + eBPF** — attach a probe to *any* userspace instruction address and run a small
  kernel program: trace calls, arguments, and writes to an address **without patching a byte
  in the target**. This is the biggest "not possible on stock Windows without a driver" win,
  and it is a near-perfect fit for provenance.
- `uinput` / `evdev` — inject input as a *real kernel input device*, below any user-space
  hook an anti-cheat installs. This is the built-in-kernel replacement for the third-party
  Interception driver the Windows HUD used.
- Further out: `seccomp`-unotify (syscall interception), `LD_PRELOAD` interposition, and
  **KVM-based VM introspection** (run the target in a VM, inspect from outside, undetectable
  from within) — each a Linux-native answer to a Windows driver-or-nothing problem.

### Where we stand (this branch, `feat/linux-live-adapter`)

- ✅ Core stays OS-free — the boundary law (`cargo tree -p n0xis-core` = zero OS crates)
  still holds; nothing below was a core change.
- ✅ `StaticPe` (goblin) already analyses Windows PEs on Linux — static RE is cross-platform
  for free.
- ✅ `trait LiveTarget` seam (`sources/target.rs`) — "a running process" with no OS in the
  signature; `Src::Live` holds a `Box<dyn LiveTarget>`, frontends hold one type.
- ✅ `LinuxProcess` adapter — `/proc/<pid>/maps` for the address-space model,
  `process_vm_readv`/`writev` for bytes, ELF section re-read + load-bias rebasing; Android
  rides the same code.
- ✅ Live surface routed through the seam, not `cfg(windows)` — one dispatch point
  (`attach_live`), ~20 command sites went cfg-free.
- ✅ **Portable stack unwinder (this milestone).** `unwind.rs` is un-gated from `windows`
  and now carries **both** backends behind the same `MemReader` seam and `UnwindRegs`/`Frame`
  model: PE `.pdata`/`.xdata` (existing) and **ELF `.eh_frame` DWARF CFI** (new — CIE/FDE +
  `.eh_frame_hdr` binary search + a `DW_CFA_*` interpreter, all pure logic read straight from
  the mapped image via `PT_GNU_EH_FRAME`). Dispatch is **by module header (`MZ`→PE,
  `\x7fELF`→ELF), not host OS**, so a Wine PE target read through `/proc` unwinds correctly.
  Validated against a synthetic ELF, the real host binary's `.eh_frame` (cross-checked with
  `readelf`), and a live process.
- ✅ **Register capture seed** — `dbg_linux::StoppedThread` (ptrace `ATTACH`+`GETREGS`),
  the one genuinely OS-specific piece the unwinder needs, as an RAII stop guard.
- ✅ `LiveTarget::stack_unwind` default method — reads unwind tables *and* stack through the
  target's own `MemorySource`, so every adapter (Win32 and Linux) gets it unchanged.
- ✅ `stack backtrace --pid [--tid|--all-threads] [--max]` CLI → `n0xis.stack.backtrace.v1`.
  Emits a real cross-module stack (verified on `sleep`: nanosleep → main → `__libc_start_main`
  → `_start`, crossing `libc.so` ↔ the binary).
- ✅ **Linux debug adapter (this milestone).** `dbg_linux` now carries the full ptrace twin of
  the Win32 `debug` module: `PTRACE_SEIZE` of the whole thread-group (`O_TRACECLONE` catches
  later threads), **hardware watchpoints** via the debug registers DR0/DR7 (`PTRACE_POKEUSER`
  at `offset_of!(user, u_debugreg)`, DR6 hit detection, `EFLAGS.RF` to break the Execute-miss
  livelock), **software breakpoints** (`int3` via `/proc/<pid>/mem`), a
  `waitpid(-1,__WALL|WNOHANG)` drain loop, register capture, the conditional-hit miss budget,
  and one RAII `Session::drop` that stops-all → restores the byte → clears DR → detaches (the
  teardown order that stops a stale watchpoint from crashing the target after detach). The
  shared wire types (`BreakpointHit`/`AwaitHitOutcome`/`Registers`/`RegCond`/`WatchKind`) were
  hoisted into an OS-free `hit.rs`; both adapters emit the identical schema.
- ✅ **Provenance closed on Linux.** `debug await-hit` / `debug watch` / `debug attach` and,
  crucially, `provenance trace` (CLI *and* MCP) now route through the seam and run on Linux —
  a watchpoint hit's rip is fused with the SSA decompiler exactly as on Windows. The full
  KF-1 loop (value address → what code wrote it → recovered function → decompiled statement)
  works on a native Linux target. Verified end-to-end by 5 ptrace integration tests (hardware
  write-watchpoint, one-shot software breakpoint, timeout, miss-budget, attach) each asserting
  the target survives *and* is left untraced.
- ✅ **`debug watch --exclude-rip`** (both the ptrace and Win32 adapters) — instruction-pointer
  ranges to ignore, so a write-watchpoint on a managed field that a `memcpy`/serialization
  helper constantly rewrites can skip the copy site (resumed with the watchpoint still armed,
  *without* spending the condition budget) and surface the semantic setter instead. Emerged
  from a real .NET NativeAOT modding session where every hit landed in serialization copies.
- ⚠️ Reaching a non-descendant needs `kernel.yama.ptrace_scope=0`, `CAP_SYS_PTRACE`, or root
  — the same gate `process_vm_readv` hits; the error says so.

### Prioritized plan (leverage × cost)

1. ✅ **Linux debug adapter** — *done this milestone* (see above): DR0/DR7 hardware watchpoints,
   `int3` software breakpoints, the `waitpid` event loop, and the safe multi-thread teardown,
   producing the same `BreakpointHit`/`AwaitHitOutcome` schema and seeding the same
   `UnwindRegs` into the portable unwinder — which is what closed provenance on Linux. Went
   through an adversarial review that caught (and fixed) two real multi-thread bugs the
   single-threaded tests missed — sibling threads stranded at a breakpoint's `addr+1`, and a
   clone child spawned in the teardown window left traced+stopped — plus two robustness fixes
   (an unbounded setup `waitpid` that could hang the tracer; leader-exit mistaken for
   whole-process exit). Multi-thread ptrace tests were added.
   *Follow-ons:* a `perf_event_open(PERF_TYPE_BREAKPOINT)` non-stopping watchpoint variant;
   `PTRACE_LISTEN` for job-control group-stops; and signal-forwarding on the teardown detach —
   the low-severity residuals recorded in `dbg_linux.rs`'s header.
2. ✅ **Test hygiene** — *done*: the `pipeline` live exit tests are cross-platform and pass on
   Linux. `unwind_exit` and `phase4c_exit` (the full provenance loop) drop the hard-coded
   `.exe`/`LiveProcess` and select the adapter + `EXE_SUFFIX` per OS; `phase4b` (scan → filter
   → freeze → persist) was ported off `powershell` onto a compiled Rust target with a known
   leaked buffer, so it now gives real Linux scan/filter coverage too. `cargo test -p
   n0xis-pipeline --features live` is green on Linux (4 exit tests + lib).
3. ⬜ **Beyond the v0 port — uprobes + eBPF provenance** — trace writes to an address with no byte
   patched in the target; the natural Linux-native upgrade to the watchpoint path.
4. ⬜ **UI/automation track** (not needed for analysis): `uinput`/`evdev` input adapter
   (replaces the Windows Interception driver), then `window` capture (X11 first; Wayland only
   via portals). Abstract the HUD hotkey/window backend behind a trait.
5. ⬜ **macOS** — a `LiveTarget` that stays unimplemented (`HAS_LIVE_ADAPTER=false`) until a
   `mach_vm_read`/`thread_get_state` adapter lands; frontends already degrade, not fail.
6. ⬜ **Flexible dynamic-symbol resolution for ELF/GLIBC across distros.** The Windows path
   resolves imports through the PE IAT; the Linux live path needs the ELF equivalent —
   `.dynsym`/`.dynstr`, the GNU hash table, versioned symbols (`GLIBC_2.xx`), and the PLT/GOT
   indirection — and it must be *robust to distro variance* (glibc vs musl, stripped
   `.symtab`, prelink/relro layouts). Without it a Linux-native `--pid` renders `sub_…` where
   the Windows path renders `module!name`. *(Flagged by an outside RE specialist, 2026-08-29.)*
7. 🚧 **Verify the ARM64 track against real compiler output — resolving the standing caveat.**
   ARM64 had only ever run against synthetic samples and disassembler self-checks — the exact
   gap the verify-before-✅ rule forbids. *(2026-08-29)* **Decode and CFG are now verified on
   real Clang -O1 AArch64 output.** Method: `clang --target=aarch64-linux-gnu` on this x86-64
   box compiles a diverse C fixture (loops, recursion, a `switch` jump table, struct field
   loads, FP math), its `.text` is fed to `n0x disasm/ir build --bytes --arch arm64`, and the
   disassembly is diffed instruction-for-instruction against `llvm-objdump` from the same
   toolchain — **57/64 byte-exact, the other 7 all cosmetic** (n0xis emits the canonical form
   where LLVM prints an alias: `umull`=`umaddl …,xzr`, `mov`=`orr …,wzr`, `cmp`=`subs wzr,…`,
   `ret`=`ret x30`, `mov #-1`=`movn #0`; and stp/ldp immediates render decimal vs LLVM's hex).
   No decode errors, no width bugs (the `movn x0` at 0x84 is correctly 64-bit, `sf=1`). CFG
   forms correctly (branch targets resolve, if/else structures). **What is *not* yet done, now
   demonstrated rather than merely asserted:** the AArch64 **lift/SSA/decompile** degrades —
   `decomp pseudo` emits `// asm:` nodes and a `/*cond(b.c)*/` placeholder instead of recovered
   expressions and conditions (`flags: ["ssa","low-coverage"]`). So the optimized decompiler
   stays x64-only until an AArch64 lift lands; that is the remaining ARM64 work, not the
   decoder. *(The **x96 mini** was tried and rejected as a target: it is a 32-bit `armv7l`
   device — no AArch64 userland — so it cannot exercise the AArch64 track at all; 32-bit ARM is
   out of scope, see below.)* **Minor finding:** AArch64 `stp`/`ldp` immediates print in
   decimal while the rest of the operands (and the x64 path) use hex — a rendering-consistency
   nit worth unifying.
   - **Do we need 32-bit ARM (AArch32)?** ✅ **Yes — reversed by a real target** *(2026-08-30).*
     The earlier "no, declining niche" call assumed no concrete use. But cheap TV boxes are
     exactly the corpus: the X96 box is `armv7l` (`armeabi-v7a`), its whole userspace is 32-bit
     ARM, and our AArch64 arch (disarm64) cannot read a byte of it. So a **decode-only `Arm32`
     arch** landed: `yaxpeax-arm` (pure Rust, keeps the build C-free like disarm64), A32 +
     Thumb/Thumb-2, the `r0`-`r15` register model and AAPCS32 declared, and a best-effort
     control-flow classification for the CFG, and **resolved direct-branch targets** (A32
     from the `BranchOffset` operand; Thumb from the `$±0xN` display, base `PC=va+4`) so
     the CFG splits blocks and follows edges — verified against `llvm-objdump` (a Thumb
     `b.w` at `0x799e` resolves to `0x79a4`, its exact target; 0 mismatches where the
     linear-Thumb and mapping-symbol streams align). A target is set only when reliably
     computable, else `None` — a sound "unknown edge", never a wrong one.
     - **Semantic lift (A32 + Thumb, incl. Thumb `IT` blocks).** ✅ *(2026-08-30,*
       *verified.)* Lifts to micro-IR: data-processing (`mov`/`mvn`/`add`/`sub`/`and`/
       `orr`/`eor`/`bic`/`mul`) **including shifted second operands** (`add r0,r1,r2,lsl #3`
       → `r0 = r1 + (r2 << 3)`, for `lsl`/`lsr`/`asr` by an immediate or a register; `ror`
       stays `asm`), simple `ldr`/`str` (`[Rn,#±off]`, with write-back), `cmp` → `flags` +
       the AArch32 branch conditions (`beq`→`==`, `bhi`→`>u`, …) reconstructed the way x64
       does for `jcc`, `push`/`pop` (the `sp` move; `pop {…,pc}` is the return), `bl`/`bx
       lr` as AAPCS32 calls/returns, **and predication** — a conditional
       instruction (`addne`) becomes `dst = cond ? effect : dst` via the *same* `Select` +
       reaching-flags resolver x64 uses for `cmovcc`, reused across arches. Anything
       unmodelled (shifted-register operands, `ldm`/`stm` beyond push/pop, FP/SIMD) is
       preserved as `asm` and **soundly invalidates its writes** (`writes_of` is a sound
       over-approximation incl. the `ldm` reg-list and write-back bases — no later read
       reuses a stale value).
       - **The Thumb `IT`-block soundness fix.** yaxpeax doesn't track `IT` (if-then)
         blocks, so a post-`IT` conditional Thumb instruction decoded *standalone* reads
         `AL` (unconditional) — lifting it would silently drop its predicate (the exact
         confidently-wrong-body class the testers flagged). Fixed by threading the real
         condition through a new **stateful decode**: `decode_stream` walks the `IT`
         mnemonic's Then/Else pattern (inverting the condition for `E` slots), stamps each
         guarded instruction's `DecodedInsn.cond`, the CFG carries it on `IrInsn.cond`, and
         the `LiftPass` overlays it onto the re-decoded instruction so the lift reads the
         predicate instead of re-deriving it. (A32's condition is in every 32-bit encoding,
         so it was already right.)
       **Verified.** Synthetic A32: `add r0,r0,r1; sub r0,r0,#4; bx lr` →
       `return ((r0 + r1) - 0x4)` (folded, `r0`/`r1` recovered as AAPCS32 params);
       `cmp r0,#0; addne r0,r0,r1; bx lr` → `return ((r0 != 0x0) ? (r0 + r1) : r0)`. **Real
       Thumb `IT` block on the box's `toybox`**, checked against `llvm-objdump`: the
       `cmp r0,#0; ite ne; ldrne r0,[r0,#0x7c]; moveq r0,#0x63` sequence decompiles to
       `((r0 == 0x0) ? 0x63 : ((r0 != 0x0) ? r0->field_0x7c : r0))` — Then(`ne`)→`!=0` and
       Else(`eq`)→`==0` both exactly right. Sweep of 60 toybox functions: 60/60 ok, 0
       errors, ~54 % of lines lifted; plus instruction-level unit tests (data-proc, mem,
       shifted operand, predication→`Select`, push/pop, `bl`, `it`/`ite` then-else,
       `decode_stream` stamping). The shift lift is verified against `llvm-objdump` too:
       `add.w r0, r6, r5, lsl #3` at `0xa372` → `(… + (r5 << 0x3))`. **Shifted-index
       memory** also lifts — `ldr r0,[r0,r5,lsl #2]` → `r0 = *(r0 + (r5 << 2))`, and a plain
       register index `[r0,r5]` → `*(r0 + r5)` (unit-tested; the Thumb-2 `ldr.w` at `0xa39c`
       decodes to the same handled operand shape). ⬜ remaining: `ldm`/`stm` beyond
       push/pop, FP/SIMD, `ror`, and ARM-shaped function discovery — the last needs the
       prologue mechanism to grow **masked patterns** (Thumb `push {*,lr}` = `[reglist,
       0xb5]`, a variable first byte the exact-prefix scan can't express), a small core
       generalization. All verifiable now on the same `llvm-objdump` + `toybox`/box-binary
       loop — no external blocker. `--arch arm32` (A32) / `--arch
     thumb` (T32); mode is chosen up front (auto A32↔Thumb tracking via mapping symbols / the
     BX-to-odd-address rule is a follow-on). **Verified against `llvm-objdump --triple=thumbv7`
     on the box's own `toybox` (armv7, stripped, Thumb-2):** the decode matches instruction-for-
     instruction, including the Thumb-2 mix of 2- and 4-byte forms (`b.w`, `ldr.w` sized 4;
     `push`, `mov` sized 2). Ground-truth loop: pull the box's binaries over SSH → decode on the
     PC → diff against llvm-objdump.
8. ✅ **Static ELF loading.** *(2026-08-30, verified.)* `--file` now sniffs the leading magic
   (`MZ` → PE, `\x7fELF` → ELF) and routes to the right parser via a unified `StaticImage`
   enum; the old `load-failed: DOS header is malformed` on a Linux binary is gone. The new
   `StaticElf` source (goblin's ELF path) mirrors `StaticPe` behind the same seams: a section
   map for `read`/`code_ranges` (allocated sections, `.bss` reads short), the preferred base
   from the minimum `PT_LOAD` vaddr, and **defined function symbols from `.symtab`/`.dynsym`**
   (ELF binaries are often *not stripped* — a windfall). **Verified:** **Tiny Glade** (Bevy/Rust
   PIE, not stripped) — 38 048 functions discovered, Rust names recovered and demangled
   (`once_cell::imp::OnceCell<T>::initialize` decompiles at quality 1.0); **Factorio** (GCC/System
   V, 24 106 functions) decompiles at 1.0 with `.dynsym` naming the OpenSSL calls
   (`factorio__BIO_new_ssl_connect`, `BIO_push`). Follow-ons: **System V calling-convention
   recovery** (Rung 4 is Win64-register-specific, so ELF *signatures*/args are not yet right — the
   body is), **PLT/GOT import-slot naming** (`iat_slot` returns `None` on ELF today), and **DWARF**
   type/line recovery from `.debug_info` (Tiny Glade carries it — a ground-truth goldmine).
9. ⬜ **LuaJIT 2.1 (bytecode dump v2).** `lua disasm`/`patch` read only the LuaJIT **2.0**
   dump (version 1); modern games ship LuaJIT 2.1 (dump v2), which is rejected
   (`unsupported LuaJIT dump version 2`). Add the v2 reader.
10. ✅ **32-bit i386 (PE32) support** *(reported by external testers, 2026-08-30; fixed
    same day.)* The bug: a **32-bit PE32** decoded with the fixed-64-bit decoder shares
    only its first `rel32` call/jmp encodings with x64, then desyncs at the first
    differently-encoded opcode (`A1 mov moffs` — 4 address bytes vs 8; `0x40` = `inc eax`
    vs a REX prefix) and produced confident garbage returned as `ok:true` — the worst
    outcome for an agent-native tool. First shipped a **fail-loud** guard (never silent
    garbage), then the real fix: **i386 decode**. `X64` is now bitness-parameterized
    (`X64::x86()`), threading 32-bit through every `iced` decode site; `StaticPe` detects
    PE32 (`goblin` `is_64`), reports 4-byte pointers and the `cdecl` ABI, and the frontend
    `pick_arch` **auto-selects the i386 arch from the image** (no flag to remember), with
    `--arch x86`/`i386` as an explicit override (closing finding C). cdecl declares no
    argument *registers*, so register-based arg recovery correctly finds zero — the real
    args live in stack slots, whose recovery is the one remaining ⬜ (conservative and
    sound, never a wrong guess). Finding B dissolves too: the PE now loads and parses via
    `goblin`. **Verified against `objdump` ground truth** on real 32-bit binaries (Cheat
    Engine `allochook-i386.dll`, `cheatengine-i386.exe`): the decode matches byte-for-byte
    (`inc eax` / `push ebx` / `add dl,[eax]` — the exact bytes objdump shows), a 26-function
    sweep decompiles 26/26 with 0 errors at avg quality 0.913, and 64-bit Kenshi is
    unchanged. Follow-ons: stack-based cdecl/stdcall arg recovery, the `eax`-vs-`rax`
    display (registers normalize to the 64-bit name — sound, the low-32 *is* `eax`), live
    32-bit processes, and the bonus Authenticode-signer-CN in `profile`.

### Framing rules this phase encodes

- **A second OS is an adapter, not a rewrite.** Every item above is a new impl behind an
  existing seam; the count of core changes is zero, by design (CONCEPT §4 made structural).
- **Dispatch by format, not host OS.** The unwinder proves the pattern: a Wine PE under Linux
  takes the PE path because it *is* a PE, decided from its header — not from `cfg!`.
- **The register file is the only per-OS seam in unwinding.** `GetThreadContext` vs
  `ptrace(GETREGS)` differ; everything above `UnwindRegs` is shared, tested, and identical.
- **Prefer the kernel-native primitive when Linux has a stronger one.** Where Windows needed
  a driver (input, stealth RW, hardware watchpoints) or forbade the move outright, use the
  built-in syscall — and record it here as a deliberate "surpass", not merely "match".

### What this phase deliberately does **not** build

- **No in-process code loading.** Extension stays across the process seam (API/MCP), never a
  foreign `.so` in the analysis process — the Trust-seam law is unchanged by going portable.
- **No anti-anti-cheat / kernel-driver arms race.** The point is that Linux *doesn't need*
  the driver, not that we ship one to defeat someone else's.

---

## Engineering hardening (not a numbered phase) — CI, the frontend seam, the capability registry ✅

Not capability work: this is the project's own engineering rules, applied to itself after
an audit against the global design principles (modularity on four seams, anti-hardcode,
no privileged core). Three of the five gaps that audit found are closed; the honest state
of the rest is recorded below.

### Trust seam — the layering law is now mechanical ✅

- ✅ **CI exists** (`.github/workflows/ci.yml`, 3 jobs, each with `timeout-minutes`):
  a Linux `boundary` job, a Windows `build + test` job with `RUSTFLAGS=-D warnings`, and a
  Windows `clippy --all-targets -- -D warnings` job. Before this, "the core links zero OS
  crates" was a claim in a document, checked by hand or not at all.
- ✅ **`scripts/check_boundary.sh`** — the layering law as an executable gate. Asserts
  `n0xis-contracts` / `n0xis-arch` / `n0xis-core` pull in no OS, format, frontend or
  transport crate (and, since the frontend seam landed, no `n0xis-frontend` either — the
  arrow points down only). Uses `cargo tree --target all`, without which a
  `[target.'cfg(windows)']` dependency added to a pure crate would stay invisible on the
  very runner meant to catch it. Verified in both directions: green on the pure trio,
  red on `PURE_CRATES=n0xis-project` (which legitimately pulls `windows-sys` via `dirs`).
- ✅ **The workspace is clippy-clean at `-D warnings`** — 21 diagnostics fixed to get
  there, two of which were deny-by-default errors. `cargo fmt` is deliberately *not* a
  gate (hand-tuned register tables and single-line struct literals; adding it would be a
  repo-wide reformat, not a CI change).

**Found by turning CI on**, which is the point of turning CI on:

- 🐛 **SSA hung forever on any function with unreachable blocks** — `decomp pseudo`,
  `ir value-set`, and everything downstream spun at 100% CPU and never returned, taking
  `cargo test --workspace` with them (measured: 74 minutes before being killed;
  `phase5_exit` was the visible casualty). Root cause in `dom.rs`: `dominators_fwd` left
  unreachable blocks at their `all-blocks` initializer, `immediate_doms` then picked an
  "idom" out of that garbage, and two mutually unreachable blocks picked *each other* —
  a cycle in what must be a tree, which `dominance_frontier`'s runner walk followed
  forever. Measured on a trivial Rust `main`: 56 blocks, 7 unreachable (alignment `nop`s
  after calls), blocks 1 and 15 pointing at each other. Fixed by excluding unreachable
  blocks from the dominator lattice, plus a `seen` guard in `dominance_frontier` so a
  malformed idom degrades one function instead of wedging the process. Two regression
  tests; `phase5_exit` went from "hangs forever" to 4.7 s. **Unreachable blocks are normal
  in real binaries** (padding after `noreturn` calls, unresolved jump-table targets) — any
  dominator-based pass must handle them explicitly.
- 🐛 **`expr_prop_round`'s forward scan only ever inspects the next statement**
  (`optimize.rs`) — the trailing `break` sits inside the loop instead of after it, so
  propagation happens solely when the use is immediately adjacent. Surfaced by
  `clippy::never_loop`, documented in place with an `#[allow]` rather than silently
  changed: fixing it alters decompiler output and belongs in its own change with the
  pseudo-C goldens re-checked. ⬜ **Open.**

### Code + data seams — one frontend contract instead of a copy per frontend ✅

- ✅ **`n0xis-frontend`** (new crate, 13th member): source resolution, ISA selection and
  argument parsing, shared by every frontend. The CLI and MCP each carried their own copy
  of the source seam, and **the copies had already drifted** — the CLI never consulted the
  `.n0x/session.json` default that `attach` writes, so `attach` followed by a bare
  `decomp pseudo` worked through an agent and failed at the terminal, with the docs
  promising both. `n0xis-mcp/src/source.rs` went from 140 lines of duplicated logic to 25
  lines of shape adaptation; `n0xis-cli` lost `Src`, `build_source`, `base_for_module`,
  `scan_range`, `load_snapshot` and five parsers.
- ✅ **The ISA seam is no longer bypassed at the edge** — hardcoded `X64::new()` in the CLI
  went 18 → 9, and every one of the nine that remains is in a command that decodes no
  instructions (value scans, pointer paths, `ui locate`, `doctor`), each annotated as such.
  MCP's `with_ctx` took the ISA as a constant, which quietly made every agent-facing tool
  x64-only while the CLI had `--arch`; six tools now take `arch`, and an unknown one is a
  `bad-arch` error rather than a silent default.

### Plugin architecture — one contract for built-in and external ⏳

- ✅ **The capability registry** (`n0xis-frontend::registry`): a `Capability` is a name, a
  summary, a schema and a handler from JSON arguments to the standard envelope; a `Plugin`
  registers capabilities; `build_registry()` is the **single composition point**. Built-in
  analysis (`AnalysisPasses`) and user-registered process plugins from `.n0x/plugins.json`
  (`ProcessPlugins`) register through the *identical* trait and dispatch through the
  *identical* call — verified end-to-end: a demo plugin appears in `capability list`
  alongside `decode` with `origin: plugin`, and `capability run plugin.demo` returns the
  same envelope shape as `capability run decode`.
- ✅ **Both frontends reach it** — `capability list` / `capability run` (CLI),
  `capability_list` / `capability_run` (MCP). A new capability appears in both without
  either frontend changing.
- ✅ **Batch 1 — function-scoped analysis** — `ir.cfg`, `ir.explain`, `ir.dot`,
  `ir.value-set`, `ir.deobfuscate`, `decomp.pseudo`, plus `decode` and `function.discover`.
  The CLI/MCP handlers for them are argument mapping only, and `finish_ir` /
  `finish_decomp` were deleted outright as dead code — the compiler's own proof that the
  duplication is gone. Shared helper: `with_cfg_ctx`, the JSON twin of the CLI's `run_ir`
  (target + ISA + `addr_rva`/`addr_module` + the `cfg_cached` artifact cache).
- ✅ **Batch 2 — range-scoped analysis** — `xref`, `xref.string`, `function.trace`, via
  `with_src_ctx` (the source's own `.text`/`.rdata` windows rather than one function
  address). Both frontends dispatch; `XrefPass`/`StringXrefPass`/`TracePass` imports
  dropped from both. Behavior verified identical to the pre-migration release binary,
  including a case where both return zero hits.
- ✅ **Batch 3 — data-side scanning (a memory scanner class)** — `scan.value`, `scan.filter`,
  `scan.aob`, `scan.dissect`, `pointer.path`, via `with_scan_ctx`. Deliberately narrower
  than the other helpers: a value scan takes a `pid` (regions clipped to what is actually
  committed — a live window routinely spans unmapped gaps, and one `ReadProcessMemory`
  across a gap fails *wholesale*, silently yielding zero hits) or a `file` with an explicit
  window; a snapshot or remote agent is rejected rather than quietly scanning nothing.
  `live_scan_regions` moved into `n0xis-frontend::source`; `build_scan_criterion` /
  `build_filter_criterion` deleted from the CLI. Verified live against a spawned target:
  value scan → 1 hit, filter `unchanged` → same hit, AOB → 3 matches, dissect and a
  1-deep pointer chain — each through both `n0x scan …` and `capability run`.
  **This batch is where the parity gap starts closing in earnest**: the whole scan family
  was CLI-only, and an agent can now reach all of it through `capability_run` without a
  single new `#[tool]` method.
- ✅ **Batch 4 — raw memory + the last function-scoped analysis** — `mem.read`, `mem.write`,
  `mem.map`, `ir.slice`, `ir.manifest`, `diff.functions`. This is the batch where the CLI
  stopped having a decompilation path of its own: `run_ir`, `decompile_one` and
  `finish_slice` all became dead code and were deleted, so from flag parsing to pseudo-C
  render there is exactly one implementation. `diff.functions` keeps its two independent
  targets (`a_pid`/`a_file`/`a_bytes` vs `b_*`) — comparing two builds is the entire point.
  **`provenance.trace` was deliberately left out** despite being on the plan: it arms a
  watchpoint and blocks until a hit, which is the `debug watch` shape, not
  "arguments in, envelope out".
- ✅ **Batch 5 — the `.n0x/` database** — `annotate.set/show/list/rm`,
  `selection.save/list/show/clear`, `dump.save/list/show/rm`, `table.add/list/show/rm`
  (16 capabilities, in their own `project_caps.rs` under the `ProjectOps` plugin). These
  resolve no source and no ISA — the project *is* the target — which is exactly why they
  belong in the same registry: from a frontend's side `annotate.set` and `decomp.pseudo`
  are the same kind of call. One deliberate asymmetry: `dump.save` has no stdin arm, since
  a capability is called with arguments, not a pipe; the CLI still reads stdin and passes
  the result in as `content`.
- ✅ **Batch 6 — target inventory + evidence tooling** — `process.ps`, `module.list`,
  `sig.validate` (`method_caps.rs`, `MethodTools` plugin). These are what an agent needs
  *before* it knows what it is looking at; an agent that can decompile but cannot list
  processes is stuck at step zero. Three neighbours were deliberately left as direct
  commands rather than dragged in: `const.identify` (its Lua-chunk mode needs
  `n0xis-lua`, and widening the shared layer's dependencies for one mode is the wrong
  trade), `profile` (IL2CPP metadata detection, same reason), and `bindings.list`
  (live module-scoped `.text`/`.rdata` windows that do not fit the existing helpers
  cleanly).
- ⏳ **The rest of the surface** — 91 leaf commands exist; 45 capabilities are registered.
  (Phases 12 and 13 each added two of both, and each landed registry-first: their CLI
  handlers are argument mapping only, and MCP reached them with no new `#[tool]`.)
  Everything else still goes through the older shape (a `clap` variant plus an arm in
  `n0xis-cli`'s `match`, plus a separate `#[tool]` in `n0xis-mcp`). Migrate in batches;
  each batch also closes part of the CLI/MCP parity gap, since both frontends then ask the
  same registry rather than needing a hand-written tool per command.
  **Not everything should migrate**: roughly a third of the surface is not
  "arguments in, envelope out" — `remote-serve` is a server, `debug watch` blocks on an
  event, `table freeze` loops writes for a duration, `ui screenshot` returns a PNG,
  `project init` / `plugin add` mutate `.n0x/` rather than analyzing anything. The
  realistic ceiling is ~40-50 capabilities, not 87.

### Still open from the same audit ⬜

- ⬜ **CLI/MCP parity** — 91 CLI leaf commands vs ~20 MCP tools. Closes as a side effect of
  the registry migration above; not worth hand-writing 65 more `#[tool]` methods.
- ⬜ **Event sourcing is partial** — patch journal (`.n0x/patches/`) and per-address
  annotation history, but no shared op-log. Fine for undo; insufficient if replication or
  agent-visible history is ever wanted. Deliberate, not forgotten.
- ⬜ **Agent-feedback observability — no data on what actually gets used.** The MCP/registry
  surface is shipped, but nothing records *which* capabilities agents call, where calls error,
  or which requests repeat — so prioritization is guesswork. Add a lightweight, **opt-in,
  local-only** structured log to `.n0x/logs/` (one JSON line per capability dispatch:
  name, source kind, ok/error + error code, duration) — no network, no phone-home, open by
  construction. It is the cheapest way to let real usage drive the roadmap instead of
  intuition, and it doubles as a debugging trail for agent sessions. *(Flagged by an outside
  RE specialist, 2026-08-29.)*

### Architectural debts (recorded 2026-08-06, from a seam audit) ⬜

Not bugs — places where a seam that exists for one axis was never built for a neighbouring
one. Each is cheap to record and expensive to discover the day a second implementation is
wanted, which is the whole argument for writing them down before that day.

- ⬜ **There is no format seam.** The ISA got `trait Arch` in Phase 1 *with a single
  implementation*, precisely so x64 could never leak into the passes — see the sequencing
  note at the foot of this file. The container format never got the same treatment.
  `goblin::pe` is imported in exactly one place in the workspace
  (`n0xis-sources/src/static_pe.rs`), `StaticPe::load` is called directly from
  `n0xis-frontend::source::resolve`, and **nothing dispatches on file magic** — the format
  is decided by which flag the user typed. `Src` is a closed four-variant enum with a
  five-branch `resolve()`, plus a per-variant arm in `text_range`, `section_range`,
  `modules` and `module_base`. Consequence: a second container (an ELF for a Linux target,
  a `.wasm` module, a raw firmware image, a console executable) is **surgery spread across
  `n0xis-frontend`, not a registration call** — exactly the failure mode `trait Arch` was
  built to prevent on the other axis. The enum itself is defensible and its doc comment
  argues the case honestly (range resolution and symbol wiring genuinely do differ per
  adapter); what is missing is a `BinaryFormat` trait that takes bytes and yields the
  `MemorySource` + `SymbolProvider` + `ModuleProvider` triple, with a magic-byte dispatcher
  in front of it and `StaticPe` as its first implementation. Build it when the *second*
  format is real, not before — but build it as the second format's first commit, never
  alongside it.
- ⬜ **`trait Arch` degrades silently, and an implementation cannot declare what it
  provides.** `lift` defaults to `MicroStmt::Unlifted`, `branch_condition` to a
  placeholder, `reg_access` to empty, `prologues` and `detect_switch` to nothing. Every
  default is individually *sound* — that was the design, and it is the right one. But
  ARM64 overrides neither of the first two, so SSA optimization and flag-precise conditions
  are an x64-only capability, and the only places that say so are a doc comment at the top
  of `arm64.rs` and a ⚠️ in this file's Phase 7 heading. An agent that runs `ir value-set
  --arch arm64` receives a structurally valid, quietly degraded answer **with no
  machine-readable signal that it is degraded** — the one failure mode Phase 11 exists to
  eliminate. Global principle: modules declare what they require and provide. Fix shape: an
  `Arch::capabilities()` returning a declared set, surfaced in `doctor` and echoed in the
  `meta` of every envelope whose quality depends on it, so degradation is *data* instead of
  prose in a source file.
- ⬜ **There is no VM seam — engine support is per-engine and hardcoded.** `n0xis-lua`
  (LuaJIT 2.0 bytecode dumps), `n0xis-luajit` (live GC heap) and `n0xis-bitsquid` (bundle
  archives) are three unrelated crates sharing no abstraction; `n0xis-core` depends on none
  of them and has no notion of a bytecode VM at all — `trait Pass` is written over a native
  `Arch` plus a `MemorySource`. A second scripting runtime (stock Lua 5.1, Mono/CIL, a
  bespoke engine VM) starts from zero. **Deferred on purpose**: one engine family is
  evidence, two is the minimum from which a sound abstraction can be extracted, and
  inventing the trait now would be inventing it from a sample size of one. Recorded so that
  the second engine triggers an extraction rather than a third parallel crate.
- ⬜ **`n0xis-luajit`'s `GCstr` layout is a single-build measurement typed as a universal
  law.** The module doc says so plainly — "a validated constant for this game/build, not a
  general LuaJIT-version law", never cross-checked against upstream `lj_obj.h` — but
  **nothing in the code or in any envelope carries that caveat**, so the honesty lives only
  where a user will not look. Anti-hardcode fix: make the layout a named, overridable
  profile with the measured build as its default, and name the profile used in the output's
  `meta`. Same shape as the `lcg` constants, which were already done right (CLI flags, not
  baked in) — this is the one that was not.
- ⬜ **`PLUGIN_TIMEOUT` is one 10 s constant for every plugin** (`n0xis-frontend/src/registry.rs`).
  Named rather than inline, so anti-hardcode is satisfied to the letter — but a single
  global value cannot serve both a sub-second transform and a plugin that streams for a
  minute. It belongs in the `PluginRecord` in `.n0x/plugins.json`, with 10 s as the
  default. This is a hard blocker for any long-running or streaming plugin.

## Sequencing notes
- **Phases 1–2 are non-negotiable prerequisites** — the optimizing decompiler
  (Phase 3) has nowhere to live until the pass pipeline and adapters exist.
- **Phase 3 is the first user-visible payoff** and the original motivation; prioritize
  it immediately after parity.
- **MCP (Phase 5)** can start as soon as the core API stabilizes (after Phase 3) — it's
  a thin frontend, and it's the biggest capability, so don't defer it to the end.
- The ISA seam (`trait Arch`) is built in Phase 1 **even with one implementation**, so
  x64 knowledge never leaks back into the passes (the mistake that sank v0).
- **Phase 8 is different in kind from 0–7.** Those phases built *capabilities*
  (decompile, scan, hook, unwind). Phase 8 builds *method* — tooling derived
  from a post-mortem of using those capabilities in anger for a full campaign.
  Its items are small next to Phase 3's decompiler, but they attack the thing
  that actually dominated wall-clock time: not missing capability, but **working
  the layers in the wrong order** and **trusting under-evidenced patterns**.
  Sequence it by payoff, not by size — `game grep` (F2) and `locate
  --by-transition` (W1) are worth more than the rest combined, because one
  attacks the root cause and the other formalizes the only technique that ever
  reliably worked.
- **Phase 12 is independent of Phase 10 and partly substitutes for it on this corpus.**
  It needs nothing from the decompiler-depth work, and its devirtualization item resolves
  Phase 10's hardest ❌ (indirect/virtual calls) by table lookup for Unity targets — so on
  a game corpus, 12 outranks 10 on payoff per unit of work. Within 12, ship item 0 (import
  an external dump) immediately: it is a day's work, it is reversible, and it tells you
  what the rest of the phase is actually worth before you write a metadata parser. Then
  drive to item 3 (managed provenance) — that is the point of the phase, and it is the item a
  third party cannot copy without also owning a watchpoint engine and an unwinder.
- **The architectural debts are not a work item — they are triggers.** Do not schedule a
  "seams sprint". Each one names the change that should force it: the format seam lands as
  the *first commit of the second container format*, the VM seam as the first commit of the
  second scripting runtime, `Arch::capabilities()` when ARM64 verification starts (it is the
  thing that makes the verification legible), and the per-plugin timeout as a prerequisite
  of the first long-running or streaming plugin. Recorded now so the trigger is recognized
  when it arrives, rather than discovered as a two-week detour halfway through the work that
  tripped it.

## Phase 15 — Packed / protected binaries: the dynamic-unpack seam 🎯 ⬜

*(Raised by an external tester + user, 2026-08-30.)* A packer/protector (UPX,
ASPack, Themida, VMProtect) makes `decomp`/`ir` decode a stub, not the program —
today that returns confident-looking pseudo-C of the *packing stub*, the same
silent-blind-zone class the PE32/i386 bug was. The strategic goal: n0xis becomes
an excellent **dynamic-unpack → static-pipeline** tool (it is ~80 % there via
`debug watch`/`await-hit`/`attach`, `snapshot dump`, and live export resolution),
and keeps VM-devirtualization as a human-in-loop research mode, not a product
button. Everything here lands on the existing seams — **new `source` plugins
(Code), the OEP dump as a versioned artifact between layers (Data), an MCP
pipeline (Process), emulate-don't-run (Trust)** — no core surgery. The heavy
parts (the emulation backend) live in **their own crate**, not the core.

Tiers, ordered by ROI (not size):

- **15a — Packer detection advisory (`profile`).** ⬜ *Cheapest, first.* Pure-Rust
  heuristics into the existing `advisories`/`engine_hints`: known section names
  (`.themida`/`.vmp0`/`.boot`/`UPX!`), high section entropy, and an entry point
  outside `.text`. Emit e.g. `Themida VM detected — static decode is of the stub,
  not the program; use the unpack pipeline`. **Advisory, never a wall** — `decomp`/
  `ir` still run (you may want the stub itself); honest about the blind zone,
  exactly as the PE32 guard is. Days.
- **15b — Emulation-unpack backend (`n0xis-emu` crate + `emulated` source plugin).**
  ⬜ *The strategic direction.* Instruction-level emulation (Unicorn/Qiling-style)
  as a **new `source` backend behind the process seam**, so untrusted code is
  *emulated, never run* (Trust seam — defeats a class of anti-debug outright, since
  no real debugger exists). Because the emulator **is** the CPU, it records every
  instruction, memory write, and API/syscall into the op-log — event-sourcing the
  *execution*, which gives replay, pause-before-critical-step, and a queryable
  "every action" trace for free (this is the user's "byte-by-byte pause / log every
  action" goal, at instruction granularity — finer than CAPE/Cuckoo's VM-level API
  hooks, and integrated straight into the SSA/decompile pipeline). Pragmatic build:
  **wrap Unicorn (or Qiling) as an external plugin** rather than reimplement an OS
  emulator in Rust — Qiling already does the PE-loader/TEB-PEB/WinAPI shim; n0xis
  orchestrates `run-to-OEP → dump → IAT-rebuild` and its static pipeline consumes
  the dumped image. Weeks–months; own crate.
- **15c — Live-debugger unpack (UPX-class).** ⬜ The classic `run-to-OEP → dump →
  rebuild IAT`, on the primitives that already exist (`debug watch` for the
  write-then-execute page and the jump to OEP, `snapshot dump` for the image,
  `module list` + live export resolution for the IAT rebuild).
  Simpler than 15b and enough for benign packers, but a real debugger touches the
  host and is detectable — so 15b is strictly better for hostile samples; keep 15c
  for the easy class.
- **15d — Anti-anti-debug (per-version).** ⬜ Hide the debugger (PEB `BeingDebugged`,
  `NtGlobalFlag`, DR registers, timing — hiding the debugger). Brittle, version-locked,
  a race Themida updates to win — do only for versions actually needed. 15b sidesteps
  most of this by not being a debugger at all.
- **15e — VM devirtualization (research, human-in-loop).** ⬜ Lift a protector VM
  (find dispatcher → reverse handlers → raise bytecode into the IR, where the
  existing `ir value-set` / `ir deobfuscate` finally apply). Per-protector,
  per-version, usually partial — realistic target is an *assist* mode ("map these
  handlers") for a human, not a button. A separate research branch, not a product
  feature; chasing Themida-specific devirt is a treadmill (it updates precisely to
  break public unpackers), so the generic dynamic unpack (15b, protector-agnostic
  for the unpacking layer) is the main line.

**Priority:** 15a (now, days) → 15b (strategic, own crate) → 15c (easy class) →
15d/15e as needed. The unpacking layer of 15b/15c is protector-agnostic: you let
the sample unpack *itself* under emulation and grab the OEP image, so you never
have to understand Themida's VM to recover the ~majority of the binary that
unpacks to native — only the functions that stay virtualized need 15e.

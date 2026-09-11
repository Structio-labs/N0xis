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
  phase). All three already get exact per-branch conditions — that correctness fix
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

## Phase 4b — Dynamic memory layer 🎯 ✅
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
    `scan` reported exactly `200000` + `truncated:true`). Rebuilt so that
    the first scan **never truncates** — `exact`/`in-range`
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
  **excludes** scriptable enable/disable hooks (arbitrary code execution in
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
Goal: fuse the two worlds (CONCEPT §11).
- ✅ **Value → meaning** — `n0xis-core::ProvenancePass` (`provenance.rs`): given one or
  more `(instruction_va, access_kind)` hits (typically from Phase 4b's `debug watch`),
  resolves each to `module+rva` (`Module::rva`), then walks discovered function
  candidates backward from the hit address, building each one's CFG until one's extent
  actually covers it (bounded search, `MAX_CANDIDATES_TRIED`) — the `VA→module+RVA→
  function` chain. Runs the found function through `--style ssa` (`DecompPass`) and
  extracts exactly the rendered block containing the hit (structure.rs already tags
  every block with a `// block_N: 0xADDR` header; this greps between that marker and
  the next one) — the typed `n0xis.provenance.v1` graph. Every field is `Option`/empty
  rather than a guess when a step doesn't resolve (CONCEPT §3 rule 6). **Nothing
  joins the two sides in one step**: a "find what accesses this address" scan
  stops at a raw disassembly line, and a decompiler has no live-watchpoint input
  at all.
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
  `provenance_trace` is the explain tool (Phase 4c's fusion, now reachable over
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
  well-studied problem class of its own), not attempted here.

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
  > value (`BITSQUID` = `min.x@+0xa4 … radius@+0xbc`), not inlined — a
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

## Phase 10 — Decompiler analysis depth on x64 🎯 ⬜

The honest reframing this phase exists to encode: **a decompiler's worth is
analysis quality, not the presence of components.** N0xis already has the full
*plumbing* (decode → CFG → dominance → SSA → optimize → structure → render). But
a real decompiler is the *90%* that comes after: the long tail of interprocedural analysis, memory
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
| Switch / jump-table recovery | ✅ present — 2 x64 idioms, memory-resolved (a narrow idiom set) |
| Type recovery | ✅ **per-function *and* whole-program** — typed locals block, phi-web coalescing, struct-field/arity/return + ~30 API sigs + **C++ class from RTTI**, plus `TypePropagatePass` (a recovered type flowed along the call graph to a fixpoint) and program-wide **class layouts** unified across every method. The remaining gap is **seed density**, not plumbing: 98 of 2 485 recovered fields carry a type. Recovered *return* types are the weak half and are gated on caller-side evidence no single-function pass has — see the falsified rule below |
| Alias analysis | 🚧 **intraprocedural points-to** — escape analysis (2a), global distinct-constant (2b) and **heap-allocation** (2c) disambiguation; `Top` on loads through unknown pointers. Whole-program/distinct-parameter points-to still missing |
| Tail-call detection | ✅ 2026-08-06 — edge class **+ semantic promotion** (`jmp func` and IAT-thunk `jmp [__imp_X]` lower to `call`+`return`, render `return f(...)`); verified on real PEs |
| noreturn analysis | ✅ import calls (`ExitProcess`/`abort`/`_CxxThrowException`/…) end a block **and the function** (2026-07-22, firing on real binaries 2026-08-06 via the IAT-keying fix); ✅ whole-`.pdata`-set noreturn **detection** — `call`- *and* `jmp`(tail-call)-to-noreturn — verified on a real binary (`function noreturn`, 2026-08-29 — the compression DLL: 10 functions incl. a `jmp TerminateProcess`, cross-checked); ⏳ the call-graph **propagation** step (a `sub_XXXX` flagged via another flagged `sub_XXXX`) fired in 0/14 real DLLs, unit-tested only, pending a real-corpus positive |
| Import-name resolution | ✅ **both formats** — PE 2026-08-06 (direct, IAT-slot and thunk callees), **ELF 2026-09-05** (GOT slot via `.rela.*` `GLOB_DAT`/`JUMP_SLOT` + PLT stubs named after their import, provider library from `.gnu.version_r`); imports render by name and reach the known-API signature table |
| Compiler-idiom recovery | 🚧 growing — `const identify`, junk, opaque predicates, **stack-canary, `min`/`max`, magic-division, rotates, `cmov`→`?:`, full intrinsic layer (SSE/bit-scan/FP), BMI/BMI2** (Rung 5b–5i) |
| Memory SSA | ✅ Rung 1 — intra- and cross-block store-to-load forwarding + dead-store elimination, on escape analysis; verified on real Win64/MSVC and Linux/GCC |
| Interprocedural propagation | ✅ whole-program noreturn IPA + call-site name/ABI resolution + **whole-program type propagation** (`analyze --typeflow`, persisted) and **class-layout unification** (`--layout`). Whole-program *points-to* is now the one core item untouched |
| Exception-edge recovery | ✅ **both formats** *(ELF 2026-09-05, PE 2026-09-06)* — `.eh_frame` FDE + `.gcc_except_table` LSDA on ELF (FDE count identical to `readelf`, 14 355 on `libQt6Core.so.6`); on PE, `.pdata` `RUNTIME_FUNCTION` + `.xdata`, with `__C_specific_handler` `SCOPE_TABLE`s and MSVC C++ `FuncInfo` (`0x19930520`–`22`) reached through the handler **RVA**, funclet ranges attributed to the function whose bytes they cover. Function counts match `llvm-readobj --unwind` exactly. `__CxxFrameHandler4` is recognized as out of reach and why — see below |
| Indirect / virtual call resolution | ✅ *(2026-09-05, extended 2026-09-06)* — resolves to the method: class × RTTI vtable × slot, read out of the image and rewritten to a direct call, bounded by the next vtable and named by the class it dispatches through. The class travels along every edge that carries a value (copies, agreeing phis, spill/reload, typed field loads, direct-call returns, a stored vtable, a constructor's argument 0), and a **constant** vtable address resolves with no class at all. Yield is seed-bound: of the indirect calls left, the largest bucket dispatches on a *field of another object* and needs that field typed |
| SIMD / FP lift | ✅ Rung 5c/5h **complete** — SSE and AVX data moves as 128/256-bit ops, packed *and* scalar arithmetic in both encodings (legacy read-modify-write vs non-destructive VEX decided by `EncodingKind`, not operand count), FMA, predicate compares, conversions, blends, rounding; masked EVEX and per-lane conditional accesses refused on purpose. Over a 1 539-method sample **45** `// asm:` nodes remain, all four categories stated |
| PDB / type ingestion | ❌ missing (corpus is stripped game builds — deliberately low priority) |
| C++ RTTI / vtable / class recovery | ✅ Rung 7a **+ program-wide layouts** — MSVC and Itanium RTTI, vtable naming, `this`-typing, full template demangling, base-class inheritance graph, and one **field set per class** unified across every method that touches it (`analyze --layout`, persisted), checked against `sizeof` from the real headers (18 of 21 classes inside the true object size) |
| Library-function identification (FLIRT-class) | ✅ **matcher + generator + auto-apply** — `n0xis-flirt` matches, `sig gen` learns a corpus from any symbolized image (self-validating), `analyze --flirt` **persists** matches into `.n0x/` so the function list, xref, decompiler and GUI all render them with no flag; corpora chain. Shipped OSS corpus: zlib. Breadth of the shipped library is the remaining gap, not the mechanism |
| Calling-convention & argument recovery | 🚧 early — arity + return only; CC is *assumed* x64-fastcall, no `this`call/vectorcall/variadic detection |
| Stack-frame reconstruction (SP-delta, FPO) | 🚧 partial — locals recovered, but no explicit frame model, no frame-pointer-omission handling, no stack arrays/spills as typed variables |
| Output readability (goto-elim, `&&`/`\|\|`, `?:`, loop forms) | ✅ Rung 6 — `switch`, `&&`/`\|\|`, `?:`, `if`/`else if`, `for`/`while`/`do-while`, tail-duplication (residual gotos ~halved). Residual shared-body gotos on irreducible merges remain |
| Signedness recovery | 🚧 Rung 3f/5 — signed vs unsigned comparisons render distinctly; stack-local signedness inferred from use. Register-variable signedness still ⬜ |
| Global / data-segment typing | 🚧 early — `xref`/`xref string` exist, but globals are untyped and data-flow does not reach the decompiler |

### What this project does not have yet — the honest gap list (2026-08-31, revised 2026-09-06)

**This project does not measure itself against other tools, and does not claim a
standing relative to any.** An earlier version of this section did, on nothing
but judgement, and the claim has been removed. What is stated here is what N0xis
lacks, in its own terms; what is stated elsewhere in this phase is what it does,
with the measurement that established it. Nothing here is a comparison.

- ~~**Whole-program type propagation — the one *core-decompilation* gap.**~~
  **Closed (2026-09-05/06).** `TypePropagatePass` flows a recovered type along
  the call graph to a fixpoint and persists it; `ClassLayoutPass` unifies one
  field set per RTTI class across every method that touches it. What remains is
  not the mechanism but the **density of facts** to flow: 99 of 2 505 recovered
  fields carry a type, and recovered *return* types are the weaker half. The
  missing input is **library type information** — PDB, DWARF and shipped headers,
  which N0xis does not ingest at all — so the gap moved from "no propagation" to
  "nothing to propagate", which is priority 5, not priority 3.
- **GUI — "eyes and hands."** Graph view, click-to-rename, an interactive type
  manager, xref navigation, instant re-analysis, undo. N0xis is headless
  (CLI/MCP) by design; a GUI is deferred, not ruled out, and can be built over
  the JSON/MCP surface.
- **Architecture breadth.** N0xis: x64 (mature), i386, AArch64 (early), AArch32
  (new). MIPS, PowerPC, RISC-V, SPARC and the long tail are absent. See the
  strategy below — this is a *seam* question, not a rewrite.
- **File formats.** PE + ELF today; no Mach-O, no firmware loaders. A format
  seam (Phase 15 debt) closes this the same way `trait Arch` closed the ISA one.
- **Maturity on adversarial / varied code**, and the absence of a
  plugin/type-library ecosystem. N0xis is young; `sound over complete` keeps it
  honest, but idiom/edge-case coverage is thin and there is no shipped
  type-library yet.

Everything above is breadth/scale/surface **except** whole-program type
propagation, which is now shipped — so what ranks first is the *input* it lacks
(item 1 below), not the mechanism.

### The gap-closing plan (2026-09-07) — ranked by lever, each with a definition of done

The list above says what is missing. This says **in what order it gets built and
how each item is known to be finished.** Ranking is by measured lever, not by
size: three sessions of measurement established that the core pipeline is not
the constraint — the *facts it has to work with* are. Every number below is from
`libQt6Gui.so.6` (22 415 functions) or the neutral PE set, measured this week.

**A note on how progress here is checked.** Where a check needs a second opinion,
the project uses **independent oracles**, and adds one: an independent decompiler
run headless over the same functions, as a *differential* oracle. What gets
recorded from it is what the difference exposed about N0xis, in absolute numbers
— never a standing, never a scoreboard. That is the same discipline as the
`sizeof` oracle from real headers and the unwind-table cross-check: something
outside this codebase that can prove it wrong.

1. ⬜ **Library type information — PDB, DWARF, and header-derived types.** *The
   biggest lever, and it is not a hard problem — it is an unbuilt reader.*
   Whole-program propagation and program-wide class layouts both work; what they
   lack is input. Measured: **99 of 2 505** recovered fields carry a type (4%),
   and **343 of 22 413** functions have a recovered return type (1.5%) — and the
   return half was shown to be unrecoverable from inside a function at all
   (nothing distinguishes a returned pointer from a scratch value in the return
   register). A binary with DWARF or a PDB *states* both, and every downstream
   pass — devirtualization, field typing, readable locals — is starved without
   them.
   **Done when:** on a binary with debug info, recovered field types and return
   types are checked against the debug info itself for **agreement, not
   coverage** (a wrong type is worse than none); and on a *stripped* binary of
   the same program, the types recovered without the debug info are scored
   against it as ground truth.
2. ⬜ **Points-to / alias precision.** Ranked by a chain traced end to end this
   week: of the unresolved indirect calls, the largest bucket dispatches on a
   field of another object; 80 of those need **11 `(class, offset)` pairs**, and
   **51 need one field**, which is filled by one call whose return type cannot be
   settled because its two return paths — a freshly constructed object and the
   cached pointer read back from the cell the first path stored it into — can
   only be unified by forwarding a store to a load **through a memory cell across
   a call**. First increment already landed (the frame window a call clobbers now
   follows the ABI rather than assuming Win64).
   **Done when:** that specific field types, and the dispatch count moves with it.
3. ⬜ **Architecture breadth via SLEIGH ingest.** x64 is mature; AArch64 is
   implemented and self-tested but **not verified on a real target**; MIPS,
   PowerPC, RISC-V and SPARC are absent. Decode is cheap (a crate per ISA behind
   `trait Arch`); the lift is the real cost, and one `SleighArch` backend reading
   `.sla` specifications pays it once for ~40 ISAs.
   **Done when:** a non-x86 binary decompiles end to end and its lift is checked
   against emulation of the real bytes.
4. ⬜ **Calling conventions and an explicit stack-frame model.** Today: arity and
   return only, the convention *assumed* from the ABI. No `thiscall`,
   `vectorcall` or variadic detection; no frame model, no frame-pointer-omission
   handling, no stack arrays or spills as typed variables. Readability sits on
   this.
   **Done when:** a function with a non-default convention recovers its real
   prototype, and stack arrays render as arrays.
5. ⬜ **File-format breadth.** PE and ELF only. No Mach-O, no firmware loaders.
   A format seam closes it the way `trait Arch` closed the ISA one.
6. ⬜ **The compiler-idiom library.** Continuous, never "done" — each idiom is
   independent and individually cheap. The differential oracle is the natural
   source of candidates: an idiom this decompiler leaves as raw arithmetic and
   another recovers is a concrete, reproducible item, not a guess about what to
   build next.
7. ⬜ **Signature corpus breadth.** The mechanism ships (`sig gen`, FLIRT-class
   matching); exactly one corpus ships with it. (WARP interop no longer ships
   here at all — the layer moved to its own repository; see the WARP entry in
   the prioritized plan.) This is filling,
   not building — and it is bounded by what may be redistributed (see the
   signature licensing entry): corpora are generated locally from libraries the
   project may lawfully fingerprint, never derived from another tool's database.
8. ⬜ **Maturity on adversarial code** — packers, obfuscation, VM protectors.
   Phase 15, almost entirely unbuilt.
9. ⬜ **GUI and a plugin ecosystem.** Deliberately deferred, not ruled out; the
   JSON/MCP surface is the seam it would be built over.

**The one thing to hold on to while working through this list:** items 1, 3, 6
and 7 are *acquisition* — a reader, a specification set, a rule at a time, a
corpus. They are long, not hard. Items 2 and 4 are real analysis work. Nothing
here requires rebuilding the pipeline, which is the part that was measured and
holds.

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
2. **Ingest SLEIGH ISA specifications → P-code → MicroIR — the breadth multiplier.** SLEIGH
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

### The gap in detail (what each dimension actually requires)

| Analysis | What the dimension actually requires | N0xis today |
|---|---|---|
| Exception edges | parse `.xdata` EH handlers → try/catch/finally edges in the CFG | 🟡 *(2026-09-05)* ELF: `.eh_frame`→LSDA gives (try range → landing pad); pads become block leaders and every block overlapping a protected range gains an `eh` successor. **Where** control goes is recovered; **what** is caught (ttype tables) is a readability follow-on, as is PE `.xdata` |
| Tail-call detection | recognize `jmp func` as call+return, resolve callee, render `return f(...)` | ✅ *(2026-08-06)* both shapes — a direct `jmp` out of the function **and** an import thunk's `jmp qword ptr [__imp_X]` (previously mis-classified `ijmp`, "indirect jump (unrecovered)") — terminate as `tail-call` and lower to `call`+`return` via the new `Arch::lift_tail_call` seam, so every style renders `return f(...)`. Verified on real PEs (`version.dll` thunk → `return …GetFileVersionInfoSizeW(…)`; 15/400 notepad, 52/400 dxgi functions carry the `tail` flag) |
| noreturn analysis | detect + **interprocedurally** prune fall-through in callers | 🚧 ✅ *(2026-07-22)* a call to a well-known noreturn import (`ExitProcess`/`abort`/`TerminateProcess`/`_CxxThrowException`/`__fastfail`/…, `n0xis-core::noreturn`) now ends its block like a `ret` (`terminator: "call-noreturn"`, zero successors) — closes the CFG so `ir manifest`'s pre-existing `no-return` flag becomes accurate for free on this case. ✅ *(2026-08-06)* `truncate_to_function` (the whole-function-end heuristic) now knows about calls too, so a function no longer over-extends past a noreturn call — and the whole mechanism fires on real binaries for the first time (it needed the IAT-keying fix; `vcruntime140.dll` 0 → 33 functions flagged `calls-noreturn`). ⏳ *(2026-08-29)* **whole-program propagation** — the `NoReturnPropagatePass` call-graph fixpoint (`function noreturn`) is built and feeds `Ctx::with_noreturn` back into CFG fall-through pruning; sound-over-complete. **Detection** is verified on a real binary (the compression DLL: 9 functions, cross-checked via `ir build`); the **propagation** step itself is unit-tested only and awaits a real-corpus positive before ✅. **Still open**: a *tail-call* to a proven-noreturn function (read conservatively as returning today). |
| Indirect call resolution | devirtualize `call [reg+off]` via vtable/type analysis | ✅ *(2026-09-05)* `crate::devirt` — joins the three facts the analysis already held apart (the object's class, that class's vtable, the slot). The value-set pass could never reach this: the vtable pointer is written by a constructor that may be in another function entirely |
| Switch recovery | many idioms (dense / sparse / multi-level / bounds-checked) | ✅ 2 x64 idioms, memory-resolved, `code_range`-gated |
| Jump-table recovery | + relocation-aware | ✅ same 2 idioms; a narrow set |
| Alias analysis | a real memory-alias oracle | 🚧 light/bounded (`ValueSetPass::alias`, `Var±Const` only, `Top` on load) |
| Memory SSA | SSA over memory (versioned store/load) | ❌ SSA over registers/flags only — **why** expr-prop is conservative |
| Interprocedural propagation | types / values / CC across the call graph | ❌ intraprocedural; only the ~30-entry API table crosses a call |
| Compiler idioms | magic-division, `rep`-string→`mem*`, stack canary, strlen-inlining, cmov→min/max, SSE idioms, … | 🚧 a handful (`const identify`, junk, opaque predicates) |
| C++ RTTI / vtables | parse MSVC (`RTTICompleteObjectLocator`, `type_info`) and Itanium RTTI → class names, base-class graph, vtable→method typing; feed devirtualization | 🟡 **both ABIs recover class names** — MSVC via `.rdata` COL chains, Itanium via `_ZTV…` symbols (2026-09-04); base-class graph MSVC-only, devirtualization still ⬜ |
| Library-function ID | a signature DB (FLIRT-class) that names statically-linked CRT/STL/runtime code instead of decompiling it | ✅ end to end *(2026-09-05)* — learn (`sig gen`), match (`n0xis-flirt`), apply project-wide (`analyze --flirt` → `.n0x/flirt-symbols.json`). Verified against a linker symbol table: 639 matched, 639 correct, 0 wrong |
| Calling convention | classify the CC and recover arg count/types by entry-liveness + call-site agreement; detect variadic and `this` | 🚧 arity + return only; CC assumed, so an un-prototyped function renders guessed arguments |
| Stack frame | SP-delta tracking across the function, FPO-function handling, stack arrays/spills surfaced as typed locals | 🚧 locals only; no frame reconstruction, no FPO |
| Readability | eliminate gotos, recover `&&`/`\|\|` from short-circuit CFG diamonds, `?:`, and `for`/`while`/`do` + `break`/`continue` | 🚧 structures reducible CFGs; the readability passes that take a decade to polish anywhere are not built |
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
     a bundled PE/MSVC compression DLL it flags 9
     functions, each cross-checked
     with `ir build` to be a single `call-noreturn` block ending in
     `_invalid_parameter_noinfo_noreturn` with no reachable `ret`. But every one
     of those 9 is a *direct import caller*. A follow-up added **tail-call →
     noreturn** handling (MSVC compiles a throw/abort wrapper as `jmp <helper>`,
     not `call; ret`; the old pass read every tail-call as "may return"),
     verified on the same binary — a 10th function, `0x18001e3ac`, is now flagged
     because its sole exit is `jmp TerminateProcess` (cross-checked with
     `ir build`). But every flagged function across **14 real x64 C++ DLLs**
     (a PE/MSVC C++ game's OGRE stack, the compression DLL, …) is still a *direct* import/tail
     caller — the novel cross-function **propagation** step (a `sub_XXXX` flagged
     because it calls another flagged `sub_XXXX`) fired in **0 of 14** and is so
     far only **unit-tested on a synthetic chain** (`rounds == 2` is a
     confirmation round, *not* proof propagation fired). This is itself a real
     finding: on this corpus the noreturn wrappers are *leaves* — compilers
     rarely emit a function whose only exit is a call to another noreturn helper.
     Per the project rule — ✅ only on a real-data *positive* — the propagation
     step stays ⏳ until a genuine instance is confirmed on a real binary.
     - ✅ **CONFIRMED 2026-09-05 on `libQt6Core.so.6`.** The corpus was the
       reason, not the pass: the 14 DLLs were Windows/MSVC game code, where the
       noreturn helpers really are leaves. On Qt, `QMessageLogger::fatal` is a
       `Q_NORETURN` **wrapper** — a `sub_XXXX` to us, not a named import — and
       propagation flags its callers through it. Of the first 400 functions, the
       per-function rule proves **233** non-returning and the fixpoint **239**;
       the difference is exactly the propagation step, and every one of the six
       is traceable: `qt_assert(char const*, char const*, int)` and
       `qt_assert_x(…)` each have a **single** callee and no unknown call, so
       they are flagged *only* because `QMessageLogger::fatal` was proven first.
       Both are declared `Q_NORETURN` in Qt's own headers, so the result checks
       out against the library's source, not just against itself. Zero
       disagreements in the unsound direction (the per-function set is a strict
       subset of the fixpoint's) — the cross-check that came for free once
       [`SummaryPass`](#) started using the fixpoint's own predicate.
     **Still open in priority 0**: exception-edge recovery (`.xdata` EH handlers
     → try/catch/finally edges) — closed for ELF below, PE still open.
   - ✅ *(2026-09-05, verified)* **The whole of priority 0 was dead on ELF —
     because no ELF callee had a name.** Everything above is keyed on a resolved
     callee *name*, and `StaticElf::iat_slot` was a stub returning `None`: on
     Linux targets every import call decompiled as `(**(uint64_t*)(0x6e1a78))(…)`
     and the noreturn table, the known-API signature table and thunk recognition
     never fired at all. Measured on `libQt6Core.so.6` (150 functions sampled
     across the image): **236 unresolved import calls in 65 of 150 functions**.
     Three landings:
     1. **GOT → import name.** `StaticElf` now builds the ELF twin of the PE IAT
        map from the dynamic relocations: `R_X86_64_GLOB_DAT` (`.rela.dyn`) and
        `R_X86_64_JUMP_SLOT` (`.rela.plt`), plus the i386/AArch64/ARM numbering.
        **`GLOB_DAT` is the one that matters** — modern distro builds are
        `-fno-plt`/`-z now` and call straight through the GOT (`libQt6Core.so.6`
        has no `.plt` *at all*), so recognizing only the classic lazy `JUMP_SLOT`
        would have missed the majority of real calls. The provider library comes
        from `.gnu.version_r` (`getenv@GLIBC_2.2.5` → `libc.so.6`), which is the
        only per-symbol attribution an ELF carries; an unversioned import is
        honestly `extern`, never guessed from `DT_NEEDED`. Sound: a `GLOB_DAT`
        against a symbol *this image defines* (PIE self-interposition) is not an
        import and is skipped.
     2. **PLT stubs named after their import.** With lazy binding — the default,
        and what a stripped ELF executable almost always uses — the call is a
        *direct* `call` to a stub, which the GOT map never sees. Every x86-64 PLT
        variant contains exactly one `jmp qword ptr [rip+disp]` (`FF 25`), so the
        stub is found by that instruction rather than by assuming an entry size
        (`.plt` 16 B, `.plt.got` 8 B, `.plt.sec` prefixes `endbr64`), backing up
        over the `endbr64`/`bnd` prefixes to the address a `call` actually
        targets. Self-validating: the slot must already be a known import, which
        is what keeps PLT0 (the lazy resolver, jumping through `GOT+0x10`) out.
     3. **The noreturn table was Win32/CRT-only**, so even a *named* ELF callee
        matched nothing. Added the glibc/Itanium set — `__stack_chk_fail` (by far
        the most frequent noreturn callee in any hardened ELF), `__assert_fail`,
        `_Unwind_Resume`, `__cxa_throw`, `_ZSt9terminatev`, `pthread_exit`,
        `exit`, … — plus the `std::__throw_*` family matched **by mangled shape**
        (`_ZSt` + length + `__throw_`), since that set grows with every libstdc++
        release and an exact-name list would silently miss new members.
        `error(3)` is deliberately *excluded*: it returns when `status == 0`, so
        flagging it would prune a live path.
     **Verified against ground truth, not by eyeballing.** ELF `.symtab` carries
     each function's true `st_size`, which makes it an exact oracle for function
     boundaries. On `libQt6Core.so.6` (309 of the first 2 000 discovered
     functions have a ground-truth size):

     | | exact boundary | over-extended | total overshoot |
     |---|---|---|---|
     | before | 236 / 309 (76.4%) | 62 | 20 356 B |
     | after | **271 / 309 (87.7%)** | **9** | **1 771 B** |

     The mechanism: a function whose CFG ran on past `call __stack_chk_fail`
     swallowed its neighbours whole — `_Z9qBadAllocv` measured **1 139 B against
     a true 55 B**, absorbing ~20 following functions. 927 functions shrank, 0
     grew. Two *apparent* regressions are the same effect read backwards and are
     recorded here so they are not "fixed" later: `has-switch` 7 → 2 and `tail`
     1 262 → 715 are switches and tail-jumps that had been **misattributed to a
     swallowed neighbour** (`0xe3df0`: 2 685 B → 587 B, exactly its `st_size`),
     and the average `quality` score falls 0.609 → 0.583 because the heuristic
     scores a short, *correct* function lower than a long, wrong one.
     **The one real cost**: under-shoot 11 → 29 functions, each 12–17 B, all the
     same shape — an EH **landing pad** (`endbr64; …; jmp cleanup`) placed after
     the `call __stack_chk_fail`, reachable only through the unwinder. Our CFG is
     right (no edge reaches it); the reported `end` is short of `st_size`. That
     is precisely this priority's remaining ❌ (exception-edge recovery), now
     with a measured cost attached to it.
     Zero PE regression (both PE regression targets, 400 functions each: avg
     quality 0.9250 and 0.9159, flags identical before/after). 5 new tests, **519 → 524**, clippy clean on both
     targets. The two integration tests deliberately link **real compiler
     output** in both shapes (`-fno-plt` and lazy `-Wl,-z,lazy` + `strip`) rather
     than using a synthetic fixture, and both were mutation-checked to fail
     without the fix — this exact map was keyed wrong on the PE side for months
     while its synthetic unit tests passed.
     **Follow-on this measurement makes obvious**: ELF `.symtab` `st_size` is an
     authoritative function size for every named function, and the discovery path
     still ignores it in favour of the `truncate_to_function` heuristic. Using it
     would take the remaining 38 non-exact boundaries to 0 on any non-stripped
     ELF, for very little code.
   - ✅ *(2026-09-05, verified)* **Function extents are now facts on ELF, not
     heuristics.** `Elf64_Sym.st_size` is the linker's own statement of a
     function's length, and the analysis was re-deriving it. New
     `SymbolProvider::symbol_size` (default `None`, so PE is untouched — an export
     is an address and `.pdata` covers only functions with unwind info); `CfgPass`
     cuts exactly there when it is stated, and `DiscoverPass` reports it as `end`
     the way `.pdata` does on PE. This fixes **both** failure directions of the
     end-of-function heuristic at once — over-extending past a
     `call __stack_chk_fail` into the next function, and stopping short of a tail
     no edge reaches. Measured against `st_size` as the oracle on
     `libQt6Core.so.6` (309 functions with a stated size): exact boundaries
     **87.7% → 100.0%**, over-extended **9 → 0**, under **29 → 0**.
   - ✅ *(2026-09-05, verified)* **Exception edges — priority 0's last ❌, closed
     for ELF.** A `try`/`catch` landing pad has **no incoming branch**: the
     personality routine enters it while unwinding. To a CFG built from decoded
     instructions it is an unreachable island, and to the end-of-function
     heuristic it was invisible — the shape measured above, 29 functions whose
     extent fell 12–17 bytes short, every one ending
     `call __stack_chk_fail; endbr64; …; jmp <cleanup>`.
     New `crate::eh` walks `.eh_frame` linearly (CIE augmentation → FDE
     `pc_begin`/`pc_range`/LSDA pointer) and parses each `.gcc_except_table` LSDA's
     call-site table into `(try_start, try_end, landing_pad)` triples. Exposed as
     `function eh` (CLI + MCP + capability `n0xis.function.eh.v1`), and threaded
     onto `Ctx` so `CfgPass` makes each pad a **block leader** and gives every
     block overlapping a protected range an `eh` successor (confidence 0.8 — the
     transfer is real but conditional on a throw, which no instruction expresses).
     The renderer labels the block, so a pad reads as
     `// ^ exception landing pad — entered by the unwinder, not by a branch`
     instead of unexplained code hanging off the end.
     **Verified against an independent oracle, not self-consistency**: the FDE
     count matches `readelf --debug-dump=frames` **exactly** (14 355 on
     `libQt6Core.so.6`; 8 394 protected regions, 3 093 functions with pads), and
     the function measured by hand earlier comes back exactly right — `0xef190`,
     extent `[0xef190, 0xef234)` (= its `st_size` 164), protected range
     `[0xef1e7, 0xef1ec)` (precisely the call that can throw) → pad `0xef223`
     (precisely the `endbr64` found in the disassembly).
     **The honest cost, A/B on 199 pad-bearing functions:** gotos **1 260 →
     1 467** and `asm` nodes **2 671 → 3 236**. That is not worse lifting — it is
     *more code shown*: an unreachable pad used to be dropped by the structurer,
     so its instructions never rendered at all. Hiding real, reachable code is a
     lie by omission; the label is what keeps the extra noise legible.
     **Sound over complete throughout**: an unmodeled pointer encoding
     (`datarel`/`aligned`/`indirect`) yields *no* region rather than a plausible
     wrong address, a `cs_lp == 0` entry is not an edge to address zero, and a
     truncated table stops. **Still open in priority 0**: PE `.xdata` scope tables
     (`__C_specific_handler`) and `FuncInfo` (`__CxxFrameHandler`), and the
     `ttype` tables that would name *which* exception a pad catches.
   - ✅ *(2026-09-06, verified)* **MSVC C++ `try`/`catch` edges — `FuncInfo`.**
     For x64 C++ EH the handler-specific dword is a **pointer to a `FuncInfo`**,
     not data; reading it in place is why the entry below concluded the classic
     format was absent from binaries full of it. Dereferenced: **659** in one
     neutral C++ runtime DLL, **127** in another.
     The format identifies itself by magic, so nothing rests on guessing the
     handler. Its shape is indirect — a `TryBlockMapEntry` carries a **state
     range**, not addresses — so the protected bytes are reconstructed from the
     IP-to-state map and paired with every `catch` entry the block declares.
     **A `catch` is a funclet**, with its own `.pdata` entry pointing back at the
     parent's `FuncInfo`; without attributing a range to the function whose bytes
     it covers, the parent's ranges were reported again under each funclet.
     Caught by the containment property, not by reading: **199 of 360** ranges
     were outside the entry that named them.
     **Verified three ways on neutral targets**: function counts match
     `llvm-readobj --unwind` exactly (1 398 / 2 512 / 1 930); every range lies
     inside its own function (161/161, 224/224, 162/162); and **158 of 161,
     204 of 224, 150 of 162 landing pads are themselves the start of a
     `RUNTIME_FUNCTION`** — what an MSVC catch funclet is — cross-checked against
     `llvm-readobj`'s function list. Regions on one runtime DLL **186 → 224**.
     **`__CxxFrameHandler4` is blocked, with the evidence**: on a large modern
     C++ PE **88 555** handler RVAs point at a payload with **no magic**, header
     byte `0x28` in 81 572 of them — the compressed `FuncInfo`, undocumented and
     MSVC-version-dependent. No neutral target on hand contains it, so it could
     not be verified here even if it were parsed. Refused, not guessed.
   - ⬜ *(2026-09-06, reconnaissance done — parser deliberately **not** written)*
     **`__CxxFrameHandler4`: the corpus was found, the format was confirmed, and
     the thing the parser would recover is not in it.**
     **Corpus.** Every x64 PE on this machine was scanned by resolving each
     `UNWIND_INFO`'s handler RVA through its `jmp [IAT]` thunk to an import name
     — the precise test, not a heuristic. Three binaries use
     `__CxxFrameHandler4`: two are a Windows build of the **ICU** Unicode
     library (neutral and universally known, the same category as the Qt shared
     library used elsewhere here) at **1 080** and **355** functions, and one is
     a vendor graphics DLL at 14. Total **1 449 functions over 978 distinct
     `FuncInfo4` payloads**. So the earlier claim that no neutral target on hand
     contains FH4 is **superseded**: one does.
     **Format, confirmed by two independent descriptions plus the bytes.**
     Microsoft's own `ehdata4_export.h` and a third-party reverse-engineering
     write-up agree on the header byte — `isCatch` 0, `isSeparated` 1, `BBT` 2,
     `UnwindMap` 3, `TryBlockMap` 4, `EHs` 5, `NoExcept` 6 — and on the rule that
     `bbtFlags`, `dispUnwindMap`, `dispTryBlockMap` and `dispFrame` are omitted
     when their bit is clear while `dispIPtoStateMap` is **always** present. The
     bytes agree independently: a `0x28` payload carries exactly two RVAs and a
     `0x60` payload exactly one, and decoding the first unwind entry of one
     `0x28` payload gives type `DtorWithPtrToObj`, action RVA `0x11e0` — the
     three bytes immediately after the function that owns it, i.e. its destructor
     funclet — and frame offset `0x30`.
     **Why no parser, and it is not the format.** Across all **978** distinct
     payloads the header takes exactly three values — `0x28`, `0x60`, `0x68` —
     and the only bits ever set are `UnwindMap` (890), `EHs` (978) and
     `NoExcept` (110). **`TryBlockMap` is set in none of them**, nor is `isCatch`
     or `isSeparated`. Every FH4 payload in the entire available corpus is
     cleanup-only: destructor unwind and `noexcept`, with not one `try`/`catch`
     block. A `TryBlockMap4` reader would therefore recover **zero** regions here
     and could not be checked against either falsifiable property this phase uses
     (a range inside its own function; a landing pad that is itself a
     `RUNTIME_FUNCTION` start). The blocker moved from "no corpus" to "a corpus
     with none of the construct", which is a sharper statement and still a
     refusal to ship unverifiable code.
   - ✅ *(2026-09-06, verified)* **PE exception edges — `.pdata` + `.xdata`.**
     `crate::eh::scan_pdata`, behind the same `function eh` command and the same
     artifact shape as the ELF half. Every `RUNTIME_FUNCTION` yields an
     **authoritative `[begin, end)`** — the ground truth the end-of-function
     heuristic lacks — and a validated `__C_specific_handler` `SCOPE_TABLE`
     yields the `__try`/`__except`/`__finally` edges.
     **The handler data is accepted on evidence, not on a name**: nothing in the
     format says which handler an `UNWIND_INFO`'s private data belongs to (the
     handler field is an RVA into a statically-linked CRT with no symbol), so the
     bytes are parsed as a scope table and accepted only if *every* entry
     validates — sane count, `begin < end`, every address zero, the reserved `1`,
     or inside an executable section. One bad entry rejects the whole table.
     **Verified two ways**: function counts match `llvm-readobj --unwind`
     **exactly**, and every recovered range lies strictly inside its own
     function, with none outside. On the two PE regression targets: 467 and
     371 250 functions, 52 of 52 and 136 of 136 regions contained. Re-verified
     on **neutral, universally-known** binaries — Microsoft's own
     `msvcr120_clr0400.dll` (2 512 functions, **186** regions) and
     `ucrtbase_clr0400.dll` (1 930, **162**) as shipped in any Wine prefix —
     which carry nearly twice the scope tables and are what this work is checked
     against from here on.
     **The cost, measured**: over the 41 functions of the smaller target that
     carry a protected range, gotos **54 → 155** and pseudo lines
     **2 073 → 2 709**, `// asm:` nodes unchanged. That is +636 lines of code the
     structurer used to discard — an `__except` block has no incoming branch —
     not worse lifting. The standing PE quality gate is unchanged.
     **The claim that neither target contained a classic `FuncInfo` was wrong**
     and is corrected in the entry below: the handler dword is an *RVA* to the
     `FuncInfo`, and it was being read in place.
1. 🚧 **Memory SSA — the representation that lifts the stop-crank.** Expression
   propagation is conservative *today only because* nothing can prove a load/call
   safe to move past a store. Memory SSA is what unblocks everything downstream.
   Built incrementally — see **the analysis-depth staged plan** below; stage
   **1a (intra-block store-to-load forwarding) is landed and verified**
   *(2026-08-29)*.
2. 🚧 **Light points-to / alias, on top of Memory SSA — and the rank is now
   measured, not asserted.** *(2026-09-06)* Two things landed and one is stated
   as the blocker.
   - ✅ **The frame window a `call` clobbers follows the ABI.** Win64 reserves 32
     bytes of home/shadow space at `[rsp, rsp+0x20)` that a callee may write;
     System V has none, and instead has the 128-byte red zone **below** `rsp`.
     The optimizer applied the Win64 window unconditionally, so on every ELF
     target it discarded **every local in the low 32 bytes of the frame at every
     call** — exactly where a compiler spills the first few, and precisely the
     forwarding that carries a value across a call. Now read from
     `MemorySource::abi_name()`. Measured on a Qt shared library: fields
     **2 493 → 2 505**, methods **3 948 → 3 970**, typed fields **98 → 99**,
     typed parameters **22 823 → 23 054**, return types **315 → 343**, propagated
     parameters **105 → 149**; oracle **18 of 21**; the three neutral PE gates
     byte-identical, by construction (PE takes the same branch as before).
     **Resolved virtual calls fell 126 → 123 and that is the point.** All three
     are `QBasicDrag`, all three from one field losing a type: `QBasicDrag+0x58`
     was typed `QRasterWindow *`, the headers say the member is a
     `QShapedPixmapWindow *`, and `QShapedPixmapWindow : public QRasterWindow`.
     The recovered type was a **base class**, so each dispatch read a slot out of
     the *base's* vtable for an object whose dynamic type is derived — right only
     if the derived class overrides nothing there, which nothing here can know.
     Losing it satisfies rule #1 instead of violating it.
   - ⬜ **A latent hazard this exposed, recorded rather than patched in haste.**
     Devirtualization through a field requires only that the field's recovered
     type be a *pointer* — but a base-class type is a perfectly sound **type**
     and an unsound **vtable**. Both directions are present today:
     `QBasicDrag+0x58` carried a base claim for a derived member, and
     `QPixmap+0x10` carries a derived claim (`QBlittablePlatformPixmap *`) for a
     base-typed member. What devirtualization needs from a field is the *exact
     dynamic class*, which "the type of something stored into it once" does not
     give. Options are to require agreement across more methods, or to resolve
     only where the class has no subclasses in the recovered inheritance graph —
     both cost yield, and neither should be chosen without measuring.
   - ⬜ **Why the item still ranks where it does — now with the chain, measured
     end to end.** Of the unresolved indirect calls, the largest bucket
     dispatches on an object that is a **field of another object**. Of those the
     owner class is known for 90; 10 already have the field typed and the other
     80 need **11 distinct `(class, offset)` pairs** — **51 of them one field**,
     `QVulkanWindowPrivate+0x290`. So it is a handful of facts, not 285 problems.
     That field is filled by the return value of one named call
     (`…::deviceFunctions`), whose return type is unknown because its two return
     paths disagree: one returns a **freshly constructed object**, which the
     constructor seed already names, and the other returns the **cached pointer
     read back** from the very cell the first path stored it into. They are the
     same type and the code proves it — but proving it means forwarding a store
     to a load through a memory cell **across a call**, which is alias analysis.
     That is this item, and this is the first time its rank rests on a chain
     traced from the top metric to the missing capability rather than on
     judgement.
   Original framing: **Light points-to / alias, on top of Memory SSA.** Co-evolves with type
   recovery — chicken-and-egg: alias precision needs types, type recovery needs
   alias. Climb 1–2 together; neither is precise alone.
3. ✅ **Function-summary IPA + whole-program type propagation — was the #1 core
   gap; it is shipped, and the gap moved to seed density.** Two layers. (a) ✅ *(2026-09-05)* **Summaries**: per-function
   returns / `noreturn` / clobber set / arg & return types / side effects —
   composes with the existing `ManifestPass`, an extension not a new subsystem. (b) **Whole-program
   type propagation**: a persistent, call-graph-wide
   type store so a `struct` recovered in one function — or a class recovered from
   RTTI — is *flowed to every function that touches the same object* (callee arg
   types ⇄ caller arg values, return types ⇄ consumers, field layouts unified
   across all users). This is what turns N0xis's *per-function* type recovery
   (Rung 3, verified) into the one class model over hundreds of functions that
   a persistent type database gives. Builds on the
   RTTI class graph (Rung 7a) + the summary layer here; it is the single remaining
   *core-decompilation* gap — everything else missing is breadth, GUI or
   maturity (see the gap list above) — so it ranks first.
   - ✅ *(2026-09-05, verified)* **3a — `SummaryPass` / `function summary`.** Every
     interprocedural question was being answered by re-analyzing the callee at
     the moment it was asked, once per asker. A summary answers it once: one run
     of the existing chain (`CfgPass` → `SsaPass` → `OptimizePass` →
     `TypeInferPass`, plus the call-graph edges the CFG already carries) yields
     `returns`, recovered `params`/`ret`, the volatile registers the function
     writes, whom it calls, and whether anything about it is *unknown*.
     Sound-over-complete is explicit in the shape rather than implied:
     `clobbers_complete` is `false` for any function that calls something (a
     caller must then assume the ABI's full volatile set until the whole-program
     pass composes its callees in), `has_unknown_call` marks an indirect or
     slot-reached callee, and an address that does not decode is **absent** from
     the batch rather than a zeroed entry claiming facts.
     One design correction worth keeping: the first draft re-derived the
     "does it return" predicate, and quietly disagreed with the fixpoint — it
     scanned *every* block, while `function_returns` walks only blocks reachable
     from the entry, so an unreachable ambiguous exit made a genuinely
     non-returning function look like it returns (60 false "may return"s on
     400 real functions). It now calls the fixpoint's own predicate, so the two
     agree **by construction rather than by review** — which is what turned the
     comparison into the real-corpus proof of noreturn propagation recorded in
     priority 0. Cost: 400 functions of `libQt6Core.so.6` summarized in 1.2 s.
   - 🟡 *(2026-09-05, built and verified end to end — yield is seed-bound)*
     **3b — whole-program type propagation.** `TypePropagatePass` /
     `function typeflow`, persisted by `analyze --typeflow` into
     `.n0x/type-flow.json` and read by the decompiler with no flag, folded into
     the decompile-cache key so a view cached before the run cannot keep serving
     the untyped signature.
     Half of this already existed and is easy to miss:
     `typeinfer::user_callee_arg_types` flows a **callee's parameter types into
     its caller's arguments**, one level, lazily. Added here: **caller arguments
     back-propagated into a callee's parameters** (the direction that carries an
     RTTI-recovered class into every helper a constructor hands `this` to),
     **return types into their consumers**, and a **fixpoint** so a type crosses
     a chain of functions rather than one call. Structure is extract-once /
     iterate-cheap: each function is analyzed once into its constraint-graph
     facts (parameter names, locally-proven types, call sites as
     `(callee, argument variables, result variable)`, copy chains), and the
     rounds walk only that graph.
     **Three soundness rules, each found by measuring rather than by design:**
     1. Only a **portable** type name propagates. A recovered struct is named
        after the register its base arrived in (`struct_rdi_0`), so the name is
        per-function and arbitrary — and the ambiguity check compares *names*, so
        two unrelated callers each holding their own `struct_rdi_0` would compare
        **equal** and silently merge two different objects into one type. That is
        a wrong answer wearing the shape of agreement. `void *` is excluded for a
        different reason: it would take a slot first and then *conflict* with the
        real class arriving later, poisoning a slot about to be answered right.
     2. A **locally proven** type is never overwritten or poisoned by a caller's
        claim: a base-class pointer passed to a derived-class method is a
        hierarchy, not an ambiguity.
     3. Two *propagated* claims that disagree mark the slot ambiguous and it is
        never assigned again.
     **The bug that made the whole pass a no-op, and how it surfaced.** A first
     run propagated 749 parameters, which looked like success and was not: almost
     all of it was synthetic `struct_*` names travelling. With rule 1 in place the
     figure collapsed to **26**, and on the Qt desktop PE to **1** — so the diagnostic
     counters were added (`call_edges`, `var_arguments`, `typed_arguments`, and
     the three skip reasons) rather than the number being accepted. They said it
     immediately: of **5 722** typed arguments, **5 708** were refused as
     non-portable. The cause was an ordering mistake in `type_of` — a variable is
     very often *both* a recovered struct base and a class-typed parameter
     (`rcx.0` is `struct_rcx_0` because we saw field accesses through it, **and**
     `Ui::RpWidget *` because RTTI said so), and checking the struct first
     returned the synthetic name, which rule 1 then correctly refused. The class
     never got a chance. Consulting the program-wide sources first took that binary
     from 1 → **7** propagated parameters and 32 → **399** propagated returns.
     **Verified end to end, not just as an artifact:** on `Updater.exe`, with the
     store present `sub_140016054` renders `DWORD r9` where without it the same
     function renders `uint64_t r9` — pass → persist → load → infer → render,
     with cache invalidation.
     **The honest state.** The mechanism is correct and sound; the *yield* is
     bounded by the seeds, not by the propagation. Across 8 000 functions of the Qt desktop PE
     only 457 parameters carry a portable type at all — those are what RTTI's
     constructor idiom, member-`this` typing and the ~30-entry known-API table
     produce — so only a few dozen call sites can move one. **The next lever is
     more seeds, not more propagation**: richer RTTI `this`-typing (Itanium
     recovers only 28 of 110 method slots on Qt), a larger API signature table,
     and the FLIRT corpus naming library functions whose prototypes are known.
   - ✅ *(2026-09-05, verified)* **Field-layout unification across every user of
     a class — 3b's last ⬜.** `crate::classlayout` / `function layout` /
     `analyze --layout`, persisted to `.n0x/class-layout.json`.
     Per-function recovery describes a class by as many disjoint half-layouts as
     it has methods, each named after the register its pointer arrived in. Keyed
     on the **class** instead, every method's observations merge into one field
     set, and a field is typed from three kinds of evidence: an embedded
     sub-object (`&this->f` handed to a constructor), a pointer field (`this->f`
     handed to a member function as its `this`), and a class-typed value stored
     in. Measured on `libQt6Gui.so.6` (22 413 functions): **2 682 methods → 353
     classes, 2 036 fields, 85 typed**, in ~100 s.
     **Verified against an independent oracle, not self-consistency.** 21 public
     Qt classes were checked against `sizeof` compiled from the real headers:
     **19 layouts came out inside the true object size**, 2 exceeded it by one
     field each. `QImage+0x10 : QImageData *` (from 104 methods),
     `QFont+0x0 : QFontPrivate *`, `QWindow+0x8 : QWindowPrivate *`,
     `QTextLayout+0x0 : QTextEngine *` and the embedded
     `QFontIconEngine+0x30 : QPixmap` are all exactly what the headers say.
     **Three wrong answers found by that oracle and fixed, not argued away:**
     1. **The class must come from the function's own symbol, never from its
        first parameter's type.** A derived class's method has a `this` that
        legitimately *is* a base-class pointer, and a derived constructor
        legitimately stores the base's vtable first — so reading the parameter
        files every derived field under the base. It put a `QImage` at `+0x30` of
        a `QPlatformPixmap` the header says is `0x28` bytes, and inflated the
        `0x20`-byte `QRhiResource` to an extent of **`0x1e20` across 145
        "methods"** (the QRhi backends export no vtable of their own). Keyed on
        the symbol, `QRhiResource` is `0x30` across 7.
     2. **The hidden return slot.** Nothing in an Itanium symbol says a function
        returns a large object by value — and such a function gets the caller's
        result buffer in the first argument register, not `this`.
        `QTextDocument::toPlainText() const` filed `QString`'s three fields under
        `QTextDocument`. The ABI gives an exact marker (such a function must hand
        that buffer back in `rax`), so a function returning its own first
        argument is refused.
     3. **A field known only by its type is still a field.** `&this->f` passed to
        a constructor proves an embedded sub-object in a function that never
        loads or stores it; keying the field set on accesses alone dropped
        exactly the offsets this pass is best at.
     **What is still not caught, stated rather than hidden.** Attributed here at
     first to **static member functions** — plausible, since Itanium mangling
     does not encode staticness. The follow-on measurement (2026-09-06, below)
     says that was wrong: every over-report was a by-value return whose result
     buffer reached `rax` by a route the `sret` marker did not follow. The
     per-field `methods` count is the confidence signal and is reported for
     exactly this reason: in every false field it was `methods: 1`–`4` against
     `methods: 66` for the real ones.
     **A stale context inside `analyze` was hiding most of this, and it was
     hiding it from `--typeflow` too.** `analyze` built one `Ctx` at the start
     and kept using it, so the whole-program phases read the binary as if the
     RTTI and FLIRT phases — which had just written `Class::vfN` and library
     names into `.n0x/` — had not run. Rebuilding the context after those phases:
     layout methods **960 → 2 682**, propagated parameters **3 → 13**.
   - ✅ *(2026-09-05, verified)* **Devirtualization through a field —
     `this->impl->method()`.** The shape 33 of 199 sampled methods were left
     holding after devirtualization landed: the class of `impl` is stated nowhere
     in the calling function, so nothing local could resolve it. With the layout
     store it is one lookup. A/B over 1 156 `libQt6Gui` methods, the same binary
     and the same build, only `.n0x/class-layout.json` present or absent:
     **0 → 4 resolved virtual calls**, every one of them through a field.
     **The binary itself confirms one of them.** `QAction::~QAction` dispatches
     slot `0x20` of its `QActionPrivate *` d-pointer, and N0xis resolves it to
     `0x1e9da0`, reported as `QActionPrivate::vf4` with `implementation:
     QPlatformOpenGLContext::endFrame` (identical-code folding — both are empty
     virtuals). Two lines earlier in the same function the *compiler's own*
     devirtualization guard loads `&QPlatformOpenGLContext::endFrame` and
     compares the slot against it: the code under analysis states the same
     address we derived, independently.
     An **embedded** sub-object is deliberately refused as a dispatch base — its
     first word is its own vptr, so treating `Widget` and `Widget *` alike would
     resolve a slot of the wrong table with full confidence.
     **Honest bound.** 85 of 2 036 fields carry a type, and only 27 of those
     point at a class RTTI recovered a vtable for — which is the ceiling on this
     path, not the mechanism. More typed fields is the next lever, exactly as
     more seeds was for propagation.
   - ✅ *(2026-09-05, verified)* **Devirtualization — the last ❌ of this phase.**
     A virtual call is three facts the analysis already held in three places and
     never joined: the object's **class**, that class's **vtable address**, and
     the **slot** the site indexes. `crate::devirt` joins them, reads the slot out
     of the image, and rewrites the call target — so
     `(*rax.1->field_0x8)(rcx, …)` becomes
     `webrtc__rtcp__Tmmbn__vf1(rcx, …)` on a real binary. Reported in the
     artifact as well as rendered, because "this `call [rax+0x40]` is
     `Widget::paint`" is a finding, not only prettier text.
     **What made it work, and what it took to make it right:**
     1. **Order.** It runs on the **raw** SSA, not the optimized form:
        expression propagation rewrites the vptr's defining assignment, so in
        `opt.blocks` the dispatch is no longer the recognizable
        `*( *this + off )`. Measured mid-flight — the `goto` style resolved three
        calls in a function where the `ssa` style still rendered
        `(*rax.1->field_0x8)(…)`. Re-optimizing after the rewrite carries the
        now-direct targets through every style, and only costs a second
        optimizer run when something was actually resolved.
     2. **The `this` type had to come from somewhere.** This is the seed the
        whole class model was missing, and it is why the first attempt resolved
        **0** of 399 real functions: a `this` was typed only in a *constructor*
        (which stores a vtable into it) or where a callee's name identified it —
        never in an ordinary method, which is exactly where virtual calls are
        made. New `own_this_class`: if the function's own name is
        `Class::something` **and `Class` is one RTTI recovered a vtable for**,
        parameter 0 is `Class *`. Requiring the prefix to be a known vtable class
        is what keeps a namespace-qualified free function (`Ui::doSomething`)
        out. Effect on the Qt desktop PE's RTTI-named methods: `this` typed as a class
        **0 → 86 of 199**, and portable typed parameters across 8 000 functions
        **457 → 1 365** — so this seed also did more for priority 3b than
        propagation itself.
     3. **Two wrong answers found by looking at the output, not by reasoning.**
        A `QPlatformPixmap` dispatch at slot `0x88` resolved into an
        `rpl::details::type_erased_handlers<…>` method. Two distinct causes, both
        fixed: vtables sit end to end, so a slot past a class's last method reads
        the **next class's table** (now bounded by the next known vtable's
        start); and under **identical-code folding** one implementation is shared
        by unrelated classes and carries whichever name claimed it first, so a
        dispatch is now named by the class and slot it goes *through*
        (`QPlatformPixmap::vf17`), with the folded symbol kept alongside as
        `implementation` rather than presented as the name.
     **Honest yield.** 2 of 199 sampled RTTI-named methods resolve a virtual
     call; 33 still carry an unresolved indirect call. That is not the mechanism
     failing — those dispatch on an object *other than* `this` (a field, a
     parameter, a local), which needs field typing. **Field-layout unification
     across all users of a struct (3b's remaining ⬜) is the same missing piece,
     and it is now the single highest-leverage item left in this phase.**
   - ✅ *(2026-09-06, verified)* **The `this` seed reads the symbol table Linux
     actually has.** `typeinfer::own_this_class` read the **raw** symbol and
     understood only MSVC's mangling: `crate::demangle::member_function_class`
     bails on anything not starting with `?`, and the fallback split on `::`,
     which `_ZNK7QPixmap6isNullEv` does not contain. On ELF the seed therefore
     fired only on names N0xis's own vtable walk had synthesized — **69** of them
     on `libQt6Gui.so.6`, against **9 782** mangled method symbols unread in the
     same table. It now runs the demangle the layout pass already did, and both
     share one implementation (`classlayout::this_class_of`), so the class a
     signature claims and the class a layout files fields under cannot disagree.
     **Measured, same binary and build** (`libQt6Gui.so.6`, 22 413 functions):
     whole-program propagated parameters **13 → 100**; layout **2 682 → 3 331
     methods**, **353 → 369 classes**, **2 036 → 2 084 fields**, **85 → 88
     typed**.
     **Const-qualification is proof of non-staticness.** A static member function
     has no `this` to qualify, so an Itanium `_ZNK…`/`_ZNV…` *cannot* be one.
     That is the first positive evidence of member-ness available on ELF, and it
     is what lets a class with no vtable of its own contribute ordinary methods
     rather than only constructors. The converse is deliberately not claimed: a
     plain `_ZN…` may be a static, and stays refused unless RTTI recovered a
     vtable for the class.
     **The `sret` refusal was matching the wrong thing, and the oracle said so.**
     It compared the returned value by SSA identity, which real code defeats two
     ways. `QScreen::manufacturer() const` spills the `QString` buffer across a
     virtual call and reloads it; `QAction::toolTip() const` hands it back
     through a **phi** of `this` and a stack reload. Both filed `QString`'s
     `+0x10` under a 16-byte class. Matching the first-argument **register** and
     following phis fixes both, and the refusal moved into `typeinfer` as well —
     the signature was typing that buffer `QTextDocument *`. Against `sizeof`
     from the real Qt headers over 21 public classes: **14 → 17 layouts inside
     the true object size**. All 4 remaining over-reports are one field
     contributed by one method (`methods: 1`, against 9–70 for the real fields).
     **The earlier attribution of those over-reports to static member functions
     was wrong**, and measurement — not reasoning — is what said so.
     **Devirtualization through a field, re-measured on the same 1 460 methods**
     (only `.n0x/class-layout.json` present or absent, counting dispatches still
     rendered `(*x->field_0xNN)(…)`): **283 → 277**. The same A/B on the previous
     build moved **310 → 310**.
     **One thing tried and left out.** Raising the own-class rule *above* the
     "passed as arg 0 to `Class::method`" rule in `param_ctype`, on the
     base-vs-derived argument, changed nothing it was supposed to:
     `QRasterPlatformPixmap`'s methods already type `this` as the derived class
     either way. Not shipped.
   - ✅ *(2026-09-06, verified)* **A class travels to where the dispatch reads
     it — and the measurement says that was not the ceiling.** `devirt` bound a
     class to one *entry* SSA name (`rdi.0`); it now moves along every edge that
     carries a value — copies, agreeing phis, stack spill/reload, a **field load**
     whose type the layout proved (pointer types only), and a **direct call's
     return value** whose type propagation proved — plus a new seed that needs no
     other type to exist: **a known vtable written into an object settles that
     object's class** (the constructor idiom, generalized off the parameter list).
     Resolved virtual calls **88 → 90** in 70 → 71 functions; layouts unchanged
     (382 / 3 933 / 2 468 / 90 typed / 106 propagated) and the oracle holds at
     **18 of 21**.
     **The honest result.** Of 265 unresolved dispatches, 176 were mechanically
     in scope for the closure — 125 needing a typed field, 29 a callee return
     type, 22 only a copy. It moved 2. **The facts are not there to move**: 90 of
     2 468 fields carry a type (3.6%) and 315 of 22 413 functions have a recovered
     return type (1.4%), those 315 almost entirely by-value-return buffers. The
     ceiling is **seed density**, not propagation — the same conclusion 3b reached
     for parameters, now measured for fields and returns. More typed fields and
     more recovered return types is the next lever; the plumbing is no longer it.
     **A second hypothesis, tried and reverted rather than left implied**:
     devirtualizing *inside* the layout pass so a resolved `this->d->method()`
     would name a class and feed the field-typing rule — typed fields **90 → 90**,
     a third more wall-clock. The circularity is real; breaking it there buys
     nothing, because the dispatches that resolve are not the ones whose result is
     handed on as a `this`.
     **The metric was wrong and is corrected**: the dispatch counter matched only
     the `(*x->field_0xNN)(…)` spelling and missed `(*rax.2)(…)`, undercounting by
     2.5×. Over the same sample the honest figure is **659 → 657** unresolved
     indirect calls, not 265.
   - ✅ *(2026-09-06, verified)* **The hidden return slot survives a stack
     spill.** The ABI marker for a by-value return was matched through copies and
     phis but not through **memory**: `QFontIconEngine::scaledPixmap` parks the
     result buffer in a stack slot for the length of the function and returns the
     reload, so nothing in the copy graph joined the returned value to the
     argument register and the function read as an ordinary method whose `this`
     was the buffer. Tracking the slot closes it. Resolved virtual calls
     **83 → 88**; the `sizeof` oracle **17 → 18 of 21** (`QMovie` is one of these
     getters); typed fields **89 → 90**; propagated parameters **105 → 106**.
     **Two refusals confirmed correct while measuring:** a dispatch through a
     **function-pointer field** of an object (`(*this->d->field_0x1a8)(…)` where
     that class's whole vtable is 11 slots) is not a virtual call, and the
     vtable-bound check is right to refuse it; and the argument shift's known
     false positive, `operator=`, did not materialize — the oracle is what would
     have caught it.
   - ✅ *(2026-09-06, verified)* **A virtual call's own target was being deleted
     as dead code.** `optimize::stmt_read_exprs` yielded a `Call` statement's
     arguments but never its **indirect target**, so use-counting saw zero uses
     of the variable a virtual dispatch loads the vptr into — its only consumer
     *is* the target — and DCE deleted the load. Three things went with it: the
     argument register it came from dropped out of the recovered arity, the class
     that register identified was lost, and the dispatch could not resolve. This
     was **232 of 274** unresolved dispatches on the Qt sample, and it is the
     answer to the question the previous entry left open — the unlifted AVX was
     not the cause, this was.
     **`this` is argument *one* in a member function that returns by value.** The
     ABI puts the caller's result buffer in the first argument register and
     shifts `this` to the second. That was already detected and used only to
     *refuse* the function — throwing the class away for everything it did.
     Read as the shift it is, `QFontIconEngine::pixmap()` recovers
     `(QPixmap *ret, QFontIconEngine *this, …)`. Every by-value getter is this
     shape, so it is a population, not a handful.
     **Devirtualization sees through a phi whose inputs agree**, which is the
     shape the compiler's own devirtualization guard produces; a phi whose inputs
     disagree is left alone.
     **Measured over 1 460 methods, same binary and build:** resolved virtual
     calls **65 → 83** in **55 → 68** functions; unresolved field dispatches
     **277 → 266**; layouts **373 → 382** classes, **3 360 → 3 943** methods,
     **2 363 → 2 467** fields; propagated parameters **84 → 105**. The `sizeof`
     oracle holds at **17 of 21** — the shift's known false positive is
     `operator=`, which genuinely returns `*this`, and the oracle is the thing
     that would have caught it.
   - ✅ *(2026-09-06, verified)* **The field typer and the dispatch resolver now
     share one notion of "what class does this value hold".** The layout pass's
     third source followed plain copies back to a parameter or a call;
     `devirt::class_closure` already carried a class along strictly more edges,
     so it is reused as a fourth source rather than restated — an agreeing phi, a
     stack spill and reload, a typed field load, a direct call's return type, and
     a known vtable written into an object. Built lazily, only for a method with
     a store the older sources could not answer, so the layout phase's wall clock
     is unchanged (2:26 over 22 415 functions).
     **One genuinely new seed, and it feeds both passes: the constructor.** A
     variable handed to a constructor of `C` as argument 0 **is** a `C *` — the
     ABI settles it, and it is the only seed that reaches a *freshly allocated*
     object, which is how a d-pointer is born (`d = operator new(…); C::C(d, …);
     this->d_ptr = d`). Construction order settles base-vs-derived: a derived
     constructor runs its base's first, so the later call wins, and a stored
     vtable overrides both.
     **Measured as a clean A/B** — both arms built from the same tree, run over
     the same freshly-rebuilt `.n0x`, on the same 22 415-function image (the
     distribution's Qt package was upgraded mid-session, which shifted every
     earlier baseline; the numbers here are re-measured against a baseline built
     after it, not carried over). Typed fields **90 → 98**, every new one a
     d-pointer with 2–41 contributing methods; no field lost a type and none
     changed. Classes **383**, methods **3 943**, fields **2 485**, typed
     parameters **22 756 → 22 760** — none worse. `sizeof` oracle **18 of 21**,
     same three over-reports at the same offsets. Over a 1 539-method sample:
     resolved virtual calls **125 → 126** in 83 → 84 functions, unresolved
     indirect calls **671 → 670**.
     **The dispatch yield is one call, and that is the point worth recording.**
     Six of the eight new field types are `…Private *` — d-pointers to classes
     with no vtable of their own — so nothing can dispatch through them however
     well they are typed. Typing fields and resolving dispatches are not the same
     problem, and this measures the gap between them.
     **A return-type rule was built, measured wrong by an independent oracle, and
     removed.** `return this->f` with `f` typed, and `return v` with the closure
     naming `v`'s class, recovered **118** return types (315 → 433). Checked
     against the real Qt headers, **55 of 118 were falsified outright**: they sit
     on functions that return `void` or a struct **by value**. `QWindow::opacity`
     returns a `qreal` in `xmm0` and merely leaves `d` in `rax`; `QPixmap::rect`
     returns a `QRect` in `rax:rdx` and its early-out is a zero, which the
     "a null is compatible with a pointer" concession let through.
     **The fact this establishes: nothing inside a function distinguishes a
     returned pointer from a scratch value the ABI leaves in the return
     register.** Itanium mangling does not encode a return type, and
     `recover_return_type` only rules out an untouched `rax.0`. The one local
     proof available — some caller dereferencing the result — was implemented and
     admitted **0 of 118**, because the accessors this rule can read (`d_func`
     and its kind) are `inline` in the headers and their out-of-line copies are
     weak symbols nothing calls. Wrong where it fires, unused where it is right.
     It is recorded here instead of shipped, and **should not be retried in this
     shape**: a recovered return type needs caller-side evidence that the pass
     which produces it does not have.
     **The field↔return fixpoint that rule was to feed resolved 0 fields**, for
     the same reason.
     **What the remaining 657 unresolved indirect calls actually need**, measured
     rather than assumed: **285** dispatch on an object that is a *field of
     another object* (needs that field's type), **67** on a bare variable, **42**
     on the result of a named call, **40** on the value of one global static data
     member, **29** on the result of an unnamed `sub_…`, **41** are not a slot
     read at all, and **7** read a slot out of a vtable *constant* the compiler
     already resolved. The first bucket is the same seed-density ceiling, one
     level down: it needs field types on the specific classes those dispatches go
     through, and 98 of 2 485 fields carry one.
4. ✅ **SIMD / FP lift — a floor-fixer, and not only for *this* corpus.** For a
   *general* decompiler this looks like mere coverage (rank low). For N0xis's
   corpus (game engines) it is a floor problem: `movaps`/`mulps`/`addps`/
   `sqrtss`/`movss` appear every few lines. Measurement on ordinary C++ says the
   framing was too narrow — see below.
   - ✅ *(2026-09-06, verified)* **AVX data movement.** The legacy SSE moves had
     been lowered to load/store/copy for a while; their VEX/EVEX spellings had
     not, so on anything a modern compiler emits they came out as `// asm:`
     nodes — holes the SSA cannot see through, and a 16-byte
     `vmovdqu [rdi], xmm0` is a *field write* that no layout pass could see.
     Added `vmovdqa`/`vmovdqu` (with the AVX-512 element-size spellings),
     `vmovaps`/`vmovapd`/`vmovups`/`vmovupd`, the non-temporal `movntdq` family,
     and the cross-domain scalars `vmovq`/`vmovd`/`vmovsd`/`vmovss`; width comes
     from the register operand, so a 256-bit `vmovdqa ymm0, [rax]` is a 256-bit
     load. `endbr64` (a CET landing pad) and `vzeroupper` (it clears lanes above
     128 bits, which this model has no representation for) lower to nothing.
     A **masked** EVEX move stays opaque on purpose: with a `{k}` operand the
     move is conditional per element, and an unconditional lift would state
     which bytes changed when the mask decides that at run time.
     **Measured over 1 460 methods of a Qt shared library:** `// asm:` nodes
     **14 268 → 6 655**; functions carrying any at all **1 460 → 646**, so 814 of
     them now lift end to end. Recovered class fields **2 084 → 2 363**;
     parameters carrying a type at all **21 193 → 22 103**.
     **`typeflow_propagated_params` reads 100 → 84 and that is the metric, not a
     regression**: it is `now_typed − locally_typed`, and 910 more parameters are
     typed *locally* than before, so fewer need propagation to fill in. The
     absolute count is the one to read.
     **What it did not buy.** The unlifted AVX was the leading suspect for the
     virtual dispatches that stay unresolved *even where the class and its vtable
     are both known*. It was not the cause: over the same 1 460 methods,
     unresolved dispatches through a field are **277 before and 277 after**. The
     layout oracle is unchanged at 17 of 21 Qt classes inside the true object
     size, with one honest movement — `QTextDocument`'s extent grows `0x18` →
     `0x20` because the by-value return buffer it already mis-attributed at
     `+0x10` is now seen at its real 16-byte width.
   - ✅ *(2026-09-06, verified)* **Packed and scalar vector arithmetic — item 4
     finished.** Bitwise ops lower to exact bit-operations; arithmetic, compares,
     shuffles, permutes, blends, packs, shifts, lane-widening, insert/extract,
     conversions and square roots to one named intrinsic each; a scalar FP
     compare and `ptest` write only opaque flags, because the relation is a float
     one this integer IR cannot state. `leave` is lifted exactly.
     **One path serves both encodings**, and the difference is load-bearing:
     legacy SSE is read-modify-write, VEX is non-destructive, so counting operand
     0 as a source in the VEX form would invent a dependency on whatever the
     destination held before. `EncodingKind` decides — not the operand count,
     which legacy three-operand `pinsrq` would get wrong. Masked EVEX stays
     opaque throughout.
     **Measured over 1 460 methods:** `// asm:` nodes **6 655 → 373**, functions
     carrying any at all **646 → 113** — 92% of the sample lifts end to end,
     against 56% before this and 0% before the data-move work. Class fields
     **2 468 → 2 485**; parameters carrying a type at all **22 103 → 22 756**;
     the oracle holds at 18 of 21.
     **The remaining tail, reported rather than rounded away**: `idiv` (56 —
     integer division, a different class of change), `movbe` (40),
     `vcvtph2ps`/`vcvtps2ph` (51, half-float), `vpabsb` (29), `bt` (26), and 18
     genuinely undecodable bytes that must stay `(bad)`.
   - ✅ *(2026-09-06, verified)* **The tail is closed, and what is left is left
     for a stated reason.** Integer division reads as two intrinsics over the
     real 128-bit dividend, with the quotient parked in a temporary because both
     halves read the pre-division `rdx:rax` and writing either register first
     would feed the other its own result; `movbe` is a move through `__bswap`;
     `bt` writes **only** flags, so the lift is that write alone; `bts`/`btr`/
     `btc` with a *register* index are exact (the hardware masks the index to the
     operand width) while the memory-destination form stays opaque, because there
     the index also displaces the address; `rorx`, half-precision conversions,
     packed absolute value, lane insert/partial moves, variable blends, rounding,
     the FMA family and the predicate-carrying compares are each one named
     operation. The two families are matched **by mnemonic name** — 48 spellings
     of FMA and every `vcmp*` predicate say nothing a list of them would add.
     A `CL`-count rotate no longer goes through the opaque path: it cannot be
     written as two shifts without modelling x86's count masking, but it is a
     named operation on two values, so it reads as `__rol(x, n)` and keeps its
     dataflow instead of invalidating the register.
     **Measured over the same 1 539-method sample:** `// asm:` nodes
     **304 → 45**; functions carrying any at all **107 → 31**. As a side effect
     of code that now lifts end to end, recovered classes **383 → 384** (a
     `QVector3D` that only existed once its FP arithmetic was visible), fields
     **2 485 → 2 493**, methods **3 943 → 3 948**, parameters carrying a type
     **22 760 → 22 823**; typed fields, resolved dispatches (126) and unresolved
     indirect calls (670) all unchanged, and the `sizeof` oracle holds at 18 of
     21.
     **The 45 that remain are four honest categories, not a backlog.** 18
     genuinely undecodable bytes (`(bad)`); 10 `lock`-prefixed and 8 `xchg` —
     the *values* are expressible as a swap or a read-modify-write, but
     atomicity is the whole meaning of those instructions and rendering them as
     ordinary arithmetic would mislead a reader of a lock; 5 `rep` string ops,
     whose implicit loop over `rcx`/`rsi`/`rdi` this IR has no shape for; and 4
     `vpmaskmovd`, a **conditional** memory access per lane, which is the same
     refusal masked EVEX already gets.
     **Regression gates unchanged** on the neutral PE targets: `ir manifest
     --limit 400` averages **0.924375** and **0.969625**, same flag sets. The
     third gate reads **0.920875**, not the 0.918875 recorded earlier, because
     the distribution upgraded that package mid-session — re-measured with the
     pre-change binary it is 0.920875 too, so the change itself moves nothing.
5. ⬜ **PDB / type ingestion — corpus-dependent rank.** High value for
   system/Microsoft binaries (public symbol servers short-circuit type recovery with
   ground truth); **low for stripped game builds**. Rank it above SIMD for system-DLL
   work, below it for game work.
6. ⬜ **Compiler-idiom library — the endless backlog.** The "hundreds of idioms"
   that two decades of decompiler work accumulate. Each idiom is independent and
   individually cheap; grow the library continuously. Never "done."
7. 🚧 **C++ RTTI / vtable / class recovery — the highest-leverage addition for
   *this* corpus.** Game engines are deep-hierarchy C++ with pervasive virtual
   dispatch, and the class graph is *already in the binary*: MSVC RTTI
   (`RTTICompleteObjectLocator` → `type_info` → base-class array) and Itanium RTTI
   encode names, bases and vtable layout directly. Parsing it names classes, types
   each vtable slot to its method, and — composed with priorities 0–1 — turns
   `call qword ptr [rax+0x40]` into a *resolved* virtual call, closing the ❌
   "indirect / virtual call resolution" gap the value-set pass cannot. It is both a
   substantial feature and a
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
     an ELF/GCC title**). **Verified on three PE/MSVC binaries:** a bundled PE/MSVC
     compression DLL — 94/815 functions carry a named vtable across 27
     classes (`std::exception`@0x180021548 cross-checked vs `rtti scan`; user
     classes `FileIOStream`/`WaveletDecodeLayer`/…), `sub_1800010d0` →
     `std::exception *rcx`; a PE/MSVC C++ game executable — 24/60 with
     `AnimationEvent`/Ogre allocators; **a PE/MSVC Win64 shipping executable**
     — 561 vtables (432 cleanly demangled ICU classes), `sub_140cecb83` →
     `icu_64::GregorianCalendar *rcx` with `*rcx = &icu_64::GregorianCalendar::vtable`.
   - ✅ *(2026-08-30, verified)* **Full templated-name demangling.** A RTTI
     TypeDescriptor name for a template is wrapped back into its `??_R0<type>@8`
     symbol and run through the real MSVC demangler, so `.?AV?$vector@H@std@@`
     reads `std::vector<int>` instead of the verbatim decorated form — the case
     an external review flagged as the weakest point. **Verified corpus-wide:**
     the compression DLL 30/30 demangled, the PE/MSVC shipping build 561/561,
     the game executable 2989/3055
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
     against known-correct ground truth:** the compression DLL's
     `std::bad_array_new_length : std::bad_alloc, std::exception`,
     `std::basic_ifstream<> : std::basic_istream<>, std::basic_ios<>,
     std::ios_base, std::_Iosb<int>`; the PE/MSVC shipping build 516/561 vtables carry
     bases — `GregorianCalendar : Calendar, UObject, UMemory`,
     `StringCharacterIterator`'s five-level ICU chain.
   - ✅ *(2026-09-05, extended 2026-09-06 — this entry **supersedes and corrects**
     the "still open" note that stood here)*. **Devirtualization is done, and the
     reasoning that deferred it was half wrong.** The gating argument was right
     about the main case and wrong about the exception. Right: a dispatch through
     a **runtime** vptr does need precise `this`-type flow across all methods, and
     that is what whole-program propagation plus program-wide class layouts now
     provide — the class travels along every edge that carries a value, and the
     resolution is bounded by the next vtable so an out-of-range slot cannot read
     the neighbouring class's table.
     The constant-vtable slice — `call [&Class::vtable + k]`, where the compiler
     wrote the table's address as a **constant** — is now matched too: it needs
     no class and no type at all, because the instruction names the table, and
     multiple inheritance is no obstacle in this one case (the usual refusal
     exists to avoid guessing *which* table a class name means, and here the
     table is what is given). It is unit-tested and sound.
     **Its measured yield on this corpus is zero, and the note that stood here
     was right about that** — a first reading of the unresolved calls said 7 of
     them were this shape, and that reading was wrong. The counting script
     followed the *rendered* `x = y` chain, which has no phis in it; the IR does.
     Every one of those calls is an arm of the compiler's own devirtualization
     guard —
     `if (slot != &Known::m) { v = *obj; } else { v = &Known::vtable; }` — so the
     dispatch reads a **phi joining a loaded vptr and a constant**, which
     `fold_phis` refuses because the inputs disagree, and refuses correctly. The
     call sits *after* the join, so even path-sensitive knowledge of each arm
     would not resolve it. Unresolved is the right answer.
     That makes it the eighth time in this phase that a ceiling turned out to be
     a defect in the measurement rather than in the analysis — this time the
     defect was in a throwaway script, which is exactly where it is cheapest and
     most tempting to trust.
     Still open for this item: feeding the recovered **bases into the decompiler**
     (type a `this` as the `Derived : Base` chain).
   - ✅ *(2026-09-04)* **Itanium RTTI for ELF/GCC targets.** `scan_itanium_rtti`
     returns the same `RttiVtable` as the MSVC scan, so `Class::vfN` naming,
     `rtti_symbol_map` and the decompiler's `this`-typing all work on ELF with no
     further change. Driven by `_ZTV…` symbols, not a structural walk, and that is
     measured rather than assumed: a byte-level prototype recovered **11 of
     libstdc++'s 179** vtables, because in a shared object the type-info slot is
     empty in the file and supplied at load time by a relocation against `_ZTI…`
     (libstdc++ has zero `R_X86_64_RELATIVE` — its slots are symbolic
     `R_X86_64_64`). Verified against `nm`: libstdc++ **179/179**, libQt6Core
     **110/110**. Getting there also required fixing three breaks that stopped the
     result from reaching anything: `analyze` discovered no functions on ELF
     (`.pdata`-only, now falls back to the prologue scan — 0 → 24,922), recovered
     no classes (`.rdata`-only, now dispatches on format), and the function list
     ignored persisted names (the prologue-scan path did not chain `LocalNames`).
     **Still open:** base classes (needs `.rela` resolution to read the `_ZTI`
     object), and a structural scan for **stripped** ELFs, which today yield an
     honest `count: 0`. Only 28 of libQt6Core's method slots resolve — same
     relocation cause; the vtable entries themselves are complete.
8. ✅ **Library-function identification (FLIRT-class signatures) — the biggest
   time-lever.** *(mechanism complete 2026-09-05; corpus breadth is the open follow-on)* A release build is a large fraction *known* code: the CRT, the
   STL, the runtime, statically linked in. Fingerprinting it (FLIRT-class /
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
     `<module>!free`) — the `module!` prefix is now imports-only, since
     a statically-linked function is *local* to the image. **Verified on a real
     target:** a `.npat` signing the free-thunk at `0x18001d84c` turns
     `sub_18001d84c(rcx, rdx.2, r8.1, r9.1)` into `free(/*ptr*/ rcx)` in
     the compression DLL (bare name, correct arity), while the same decomp
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
     `README.md` (provenance, the capa "not derived from another tool's sigs"
     disclaimer, and the generate-locally model for proprietary libs) +
     `generate.sh` (reproduces the sample from the pinned upstream tag). OpenSSL
     libcrypto 3.6.4 also generates cleanly (5888 signatures) but is left
     generate-locally rather than committed as a machine-specific blob.
   - ✅ *(2026-09-05, verified)* **Rung 10d — auto-apply, corpus chaining, and the
     soundness hole the exit test found.** 10a–10c built the matcher, the generator and a
     shipped corpus, and then the lever sat unused: **`--flirt` existed only on
     `decomp pseudo`**, one function at a time, so signature names never reached the
     function list, `xref`, or the GUI. The measurement that makes the stakes concrete: a
     *five-line* C program, statically linked and stripped, discovers **1 436 functions,
     exactly one of which is the author's**. Triage is not "read the decompiler output",
     it is "find the 1 of 1 436" — and that is what this rung delivers.
     1. **`analyze --flirt <db.npat>…` persists.** A new phase matches every discovered
        function and writes `.n0x/flirt-symbols.json`, exactly as the RTTI phase writes
        `rtti-symbols.json`. `LocalNames` gained it as a **third** source, ranked
        **user rename ▸ RTTI ▸ signature** — a byte heuristic must never displace a name
        the binary carried structural evidence for — memoized on its own file so a rename
        still re-reads only the tiny annotations file, and folded into the
        `symbol_fingerprint` so a decompile cached before the run cannot serve `sub_XXXX`.
        Afterwards **every consumer renders the names with no flag of its own**.
     2. **Corpora chain.** `--flirt` is repeatable and merges (`Db::extend_npat`); order
        cannot change the answer, because `lookup` already refuses two equally-specific
        signatures that disagree. `--flirt` also reached `function discover` and
        `ir manifest` (the triage surface, and the one ctx builder FLIRT never touched) for
        one-shot use without a project.
     3. **`sig gen` now self-validates its own corpus — and it had to.** The exit test
        checks every matched name against the target's *unstripped* symbol table, and it
        caught a real false name: glibc's `__chk_fail` and `__stack_chk_fail` differ **only**
        in a RIP-relative message pointer and a relative `call __fortify_fail`, both
        correctly wildcarded as linker-varying, so their patterns are identical. The
        matcher's ambiguity rule could not save us — it refuses only when *both* are in the
        database, and `__stack_chk_fail` shares its address with the alias
        `__stack_chk_fail_local`, which the glue filter removes. `__chk_fail` was left
        holding a pattern matching both, and named every `__stack_chk_fail` in every target.
        **The first fix made it worse**, which is the instructive half: dropping merely
        *equal* patterns removed the ifunc variants `__strcasecmp_l_avx2`/`_avx2_rtm` and
        left `__strcasecmp_l_evex`, whose pattern `generate_pattern` had truncated to 23
        bytes and which is a strict *prefix* of theirs — handing the match to the
        over-broad signature. The invariant is therefore not "no two patterns are equal"
        but **"looking up any function of the reference must never return another
        function's name"**: `sig gen` builds the database it would ship, replays the real
        matcher against every reference function (including ones the filters excluded —
        their bytes are still ground truth), drops whichever signature answered wrongly,
        and iterates to a fixpoint. Cost on glibc: **1 signature of 1 070**.
     4. **PLT stubs must not be signed** — a regression from the 2026-09-05 ELF import work,
        caught by the same regeneration. Naming a stub after its import (correct for
        reading code) put it in `named_functions()`, so `sig gen` began fingerprinting
        `malloc`/`free`/`memcpy` **thunks**, whose bytes embed the PLT relocation index
        (`push <n>`) — a value specific to that binary's link order. `named_functions()`
        now returns defined functions only; the shipped zlib corpus regenerates
        **byte-identical** to the committed one, which is the proof the fix is a no-op for
        real code.
     **Verified against ground truth on a real binary.** Signatures learned from one
     statically-linked, symbolized program and applied to a *different*, stripped one:
     **639 of 1 438 functions named, all 639 correct, 0 wrong** (checked against the
     linker's own symbol table). The corpus matters more than the count suggests: the
     system's *shared* `libc.so.6` named **12.7 %**, another *static* binary of the same
     toolchain **44 %** — PIC vs non-PIC — which is exactly why chaining exists. Cost is
     negligible: `analyze --flirt` over `libQt6Core.so.6` (24 922 functions, RTTI + xref
     index included) runs in **1.0 s**. 15 new tests, **524 → 534**, clippy clean on both
     targets, PE untouched.
   - ⬜ **Extend the shipped OSS corpus** (OpenSSL/Qt/libstdc++) via `signatures/generate.sh`.
     Now the only thing between a user and a named CRT — the mechanism is done.
   - **Licensing model (researched, sourced — commercial).** What we *redistribute*
     is the constraint, not the engine. Safe to ship: OSS-generated corpora
     (zlib/OpenSSL/Qt), reuse of the Apache-2.0 WARP *format*, `.fidb`
     under Apache-2.0 with attribution, and readers for user-supplied sig files.
     **A permissive format licence is not permission to ship another project's
     files** (2026-09-11): the WARP reader's only test fixture was that project's
     own `.warp` sample, redistributed here under this repo's copyright notice
     with nothing in `NOTICE` naming it. That attribution obligation is why the
     whole WARP layer left for a separate repository rather than being patched
     over with a notice — the code was clean-room and fine, the redistributed
     bytes were not ours to carry.
     Kept generate-locally (user runs `sig gen` on their own licensed toolchain,
     we ship nothing derived): **MSVC CRT/STL**. Never shipped: any other tool's bundled
     `.sig`. FLIRT-signature copyright is genuinely unsettled (no case law); a
     lawyer should read the FLAIR toolkit license and the exact VS License Terms
     before any proprietary-derived corpus is distributed.
   - 📦 **WARP interop (an Apache-2.0 cross-tool format) — built here, then moved
     out (2026-09-11).** Where FLIRT matches leading *bytes*, WARP identifies a
     function by a **structural GUID** so it survives relocation/link-address
     changes. Being an open, Apache-2.0 interchange format, it is the legal bridge
     to a whole external signature ecosystem (lowest-risk reuse after our own OSS
     corpora — see the licensing model above).
     **Status now: `n0xis-warp` is a plugin in its own repository and is not part
     of this workspace, this binary or this build. There is no `warp` command; no
     N0xis build in this repo reads a `.warp` file.** The rungs below record what
     was built and measured while it lived here — the work happened, the
     measurements stand, and the capability is simply somewhere else now. It left
     because its test fixture was another project's own file (see the licensing
     model above), not because anything about it was wrong.
     - ✅ **Rung 11a — the WARP GUID primitive (clean-room, byte-compatible).**
       New `n0xis-warp` crate: `function_guid` / `basic_block_guid` as WARP
       defines them — `UUIDv5(NAMESPACE_FUNCTION, ‖ block GUIDs)` over
       `UUIDv5(NAMESPACE_BASIC_BLOCK, normalized_bytes)` — on a **dependency-free**
       SHA-1 + UUIDv5 (same zero-supply-chain discipline as `n0xis-flirt`, which a
       commercial product wants). **Verified byte-for-byte against the format's own
       reference implementation (the `warp` crate, v1.0.1):** golden GUIDs it generated
       (`bb(90 90)=9f28527a…`, `fn[bb,bb]=382ab4b9…`) are pinned as unit tests, so
       ours is genuinely *interoperable*, not merely self-consistent; the SHA-1
       and UUIDv5 layers are pinned to the RFC 3174 / RFC 4122 vectors too.
     - ✅ **Rung 11b — WARP container reader.** Reads a real `.warp` file
       (FlatBuffers `File→Chunk→SignatureChunk→Function{guid,symbol.name}`, with
       the zlib-compressed chunk payload) into its `(GUID, name)` table, via a
       hand-written, strictly bounds-checked FlatBuffers parser — so it pulls in
       only `flate2` (already in the tree), no `flatbuffers`/codegen dependency.
       **Verified byte-for-byte against the format's reference implementation:**
       reading its `random.warp` fixture reproduces that implementation's `dumper`
       output for all 100 functions exactly, and truncated inputs return `None`
       rather than panicking (the OOM/untrusted-length rule). It *was* exposed as
       `n0xis warp dump --file x.warp`; that command was removed from this binary
       on 2026-09-11 when the crate moved out, and that fixture — the reason for
       the move — went with it. (Writer + type chunks: later, when a producer
       needs them.)
     - ❌ **Rung 11c — WARP-compatible GUID computation: deliberately NOT pursued.**
       Computing a *reference-byte-identical* function GUID would mean replicating the
       reference implementation's normalization, which is
       defined over the reference implementation's **closed-core LLIL + its exact CFG basic-block boundaries**
       — a fragile imitation whose only purpose is to read *their* databases, that
       would couple n0xis to a foreign closed contract and leak the user's function
       GUIDs to that format's public lookup service. That is an anti-pattern against this project's
       own principles (own the seams; no coupling to a foreign, closed-core-defined
       contract). Decision (2026-08-31): we take the *idea* (structural matching
       that survives relocation) but implement **our own** fingerprint on our own
       CFG + the relocation masking `sig gen` already computes — verifiable without
       any oracle (same function in two binaries → same fingerprint, proven on our
       corpus), no dependency, no egress. 11a/11b stay as cheap *passive* import
       (read a `.warp` someone hands us); we do not chase byte-compat on compute.
       The format's live public API (no-auth query-by-GUID over Golang / Linux /
       .NET AOT sources) is recorded for reference, not as a dependency.
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
    for readable-locals output.
11. ⬜ **Output-readability structuring — the "reads like source" axis.** Distinct
    from CFG *correctness* (priority 0), this is what a user sees first: aggressive
    goto elimination, recovering `&&` / `||` from short-circuit CFG diamonds,
    ternary `?:`, precise loop forms (`for` / `while` / `do-while` with
    `break` / `continue`), rendering a jump table as a `switch` rather than an
    `if`-chain, and **signedness inference** so operators and casts are correct.
    This dimension takes a decade of polish anywhere; it is continuous, not a
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
    (the compression DLL's `OpenImage`: locals forward, 8 deref-loads across 22 local
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
    an input-library DLL's `sub_180005d20` forwards `[rdx.0+0x18]` across a block boundary
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
    restriction fixes it. **Verified on real x64:** on the compression DLL it
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
    compilers:** on Windows/MSVC (the compression DLL), cross-block forwarding
    jumped from **0 → 28 of 400 functions**; on a Linux/GCC ELF title (OpenSSL
    `dtls1_ctrl`) it decompiles at quality 1.0 with 10 sound forwards. **That
    ELF run caught a real soundness bug** — the first cut cleared only the
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
    points-to slice this needs. Allocation bases are the SSA `ret`s
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

- **Rung 3 — Variable & type recovery (readable locals).** 🚧
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
    real MSVC x64** (the compression DLL): 87 of 120 functions recover a
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
    collide with). **Verified on the compression DLL:** `sub_1800010d0` reads
    `*rcx = …; if ((rdx & 0x1) == 0x0) …; return rcx;` against the signature
    `(struct_rcx_0 *rcx, uint64_t rdx)` — no `.0` noise on parameters.
  - **3c — SSA-version coalescing (phi-webs → named variables).** ✅ *(2026-08-30,*
    *verified.)* A register's phi-web of versions (`rcx.1`/`rcx.2`/`rcx.3`, the
    loop-carried counter) collapses to one named variable — the
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
    only on the optimized `ssa` style. **Verified on the compression DLL:**
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
    on the compression DLL:** all **200 functions decompile with zero errors
    at 0.969 average quality**, **90** use edge-split destruction (326 split
    blocks), and the showcase `sub_180002380`'s `rax.6` is now defined on both
    arms (`if (…) { rax.6 = rcx; } else { rax.5 = *rcx; rax.6 = rax.5; }`).
    Synthetic split-block addresses are non-canonical and render as
    `// block_N: (edge split)`.
  - **3e — typed-locals declaration block.** ✅ *(2026-08-30, verified.)* The
    recovered stack locals now render as a typed declaration
    block at the top of the function (`uint64_t local_18; __m128 local_20; …`)
    before the body, for the `structured`/`ssa` styles (`goto` stays flat). Only
    locals that actually appear in the body are declared (an optimizer-removed
    local is not listed), and the `local_XX` name derives from the offset
    exactly as the renderer's does. **Verified** on the compression DLL
    `GetBlockLODs` — declares `local_18/20/28/30/38` with inferred types (incl.
    `__m128` for a vector spill), each used below.
  - **3f — signedness inference from use.** ✅ *(2026-08-30, verified.)* A stack
    local's displayed type now takes evidence from the operators its value flows
    into, not just the `movsx`/`movzx` load encoding: a value compared with a
    signed `<`/`>` (jl/jg), divided with `idiv`, or arithmetic-shifted (`sar`) is
    signed. Readability-only (the IR ops are already correctly signed/unsigned),
    so never a soundness risk; unsigned uses never flag a slot. **Verified** on
    the compression DLL's `GetBottomPixels` — `local_28`/`local_30`, used in
    `(local - x) >> 1` arithmetic shifts (`sar`, a signed midpoint), declare
    `int64_t` while the canary/saved-reg locals stay `uint64_t`.
  - **3g — whole-program `this`-type propagation + C++ import naming.** ✅
    *(2026-08-31, verified.)* Two changes. **(a)** A value passed as arg 0 to a non-static C++ member
    function *is* a pointer to that method's class — `param_ctype` now types such
    a parameter as the class (`std::basic_ostream<char,…> *rcx`), ranked just
    below the constructor-vtable class.
    Sound: membership is read from the demangler's access specifier (gated
    against `static`), so a free function's or static member's arg 0 is never
    mistyped. **(b)** A module-prefixed C++ import (`MSVCP140.dll!?sputc@…`) now
    reaches the demangler (it split off the `module!` prefix, which hid the
    leading `?`) and renders its qualified name only
    (`std::basic_streambuf<…>::sputc`) via an MSVC `NAME_ONLY` demangle — not the
    sanitized `MSVCP140_dll___sputc___…`. **Verified:** `sub_180002fa0` recovers
    `std::basic_ostream<char,struct std::char_traits<char> > *rcx` and names
    `flush`/`sputc`/`sputn`/`setstate`; across two real x64 PEs, 17 and 19 of
    200 functions get a class-typed param, 0 regressions. MSVC only for now;
    Itanium/ELF `this`-typing is a follow-on.
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
    the compression DLL the arity-4 count collapsed from ~100% to a realistic
    spread (0:7 / 1:32 / 2:27 / 3:23 / 4:25 over 120 functions), and
    `sub_1800010d0` — which really takes 2 (`*rcx`, `rdx & 1`) — now reports 2,
    not 4; cross-checked on an input-library DLL (100 functions, no regression). Also
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
    Win64 `rcx`/`rdx`/`r8`/`r9`. **Verified:** an ELF/GCC title — `sub_fe2424` now
    reads `(uint64_t rdi, uint64_t rsi, uint64_t rdx, struct_rcx_0 *rcx)` (System V,
    4th arg typed as a struct pointer), while a PE/MSVC C++ game binary is unchanged at Win64
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
    native (first) convention. **Verified:** an ELF/GCC title's `sub_fe2104` now emits
    `BIO_new(rax.1, rsi.1, rdx.1, rcx.1, r8.1, r9.1)` (six System V registers, arg 1
    being rdi's value from the preceding `mov rdi, rax`), while a PE/MSVC game
    binary's call sites stay Win64 (`(rcx.2, rdx.2, r8, r9)`). Corpus sweep — 40
    call-bearing functions each on an ELF/GCC title, a Bevy/Rust title (ELF) and a
    PE/MSVC C++ game binary: 120/120 ok,
    0 errors, 0 anomalies.
  - **4b — drop lift-padding call arguments.** ✅ *(2026-08-30, verified.)* The
    same fixed four-register call convention meant *every* call to a callee not
    in the signature library rendered four arguments (`sub_X(rdi.1, rdx, v1,
    r9.0)`). A **trailing** argument that is the bare entry value (`rN.0`) of a
    register the current function neither takes as a parameter nor writes is
    padding — the uninitialized incoming register — and is dropped, while any
    computed argument or a genuine parameter forward (including a trailing
    `rdx.0` when `rdx` *is* a parameter) is kept. Per-function and sound-
    consistent with 4a's arity model. **Verified on the compression DLL:**
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
    MSVC x64** (the compression DLL, 200 functions): **69 of 75 loop headers
    now carry a real condition** (was near-zero for arithmetic latches), e.g.
    `while ((*(uint8_t*)(rdx.0 + rbx.3) != 0x0))` — a real string scan.
  - **5a′ — the full jcc family after a logical op.** ✅
    *(2026-08-31, verified.)* The most visible readability defect was an opaque
    `~/*cond(jle) after test*/` where a plain comparison belongs. A **logical** op (`test`/`and`/`or`/`xor`) clears OF and CF
    to 0, so *every* signed and unsigned branch is a pure sign/zero test on the
    value — not just `je`/`jne`. `CmpKind::Test` and a new `CmpKind::LogicalResult`
    now reconstruct the whole family (`jl`/`jle`/`jg`/`jge` → `<`/`<=`/`>`/`>= 0`,
    `ja`/`jbe` → `!=`/`== 0`, `jae`/`jb` → provable true/false since CF=0); the
    arithmetic `Result` additionally recovers `js`/`jns` (SF is the stored
    result's sign bit). **Verified:** the compression DLL's `sub_180002fa0` reads
    `while ((v8 > 0x0))` / `if ((rdi.1 <= 0x0) || …)`, 0 opaque conditions in
    that function; corpus
    opaque-cond lines collapse (the PE/MSVC game executable, 200 fns to 31 — all `jo`/`jp` or
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
    the transform is information-preserving). **Verified:** a PE/MSVC C++ game
    binary's `sub_140064abf` reads `rax.2 = __stack_guard(*(uint64_t*)(0x1421173c8))` at entry
    and `return __security_check_cookie(__stack_guard(local_8), …)` at exit — the
    whole canary dance now self-labels. Corpus sweep of 80 functions each:
    the PE/MSVC binary fires on its real canaries (6 guards / 3 functions, a
    setup+check pair each), while an ELF/GCC title, a Bevy/Rust title (ELF) and a
    116 MB PE/MSVC C++ shipping binary show **zero** — the Linux `%fs:0x28` canary never
    XORs `rsp`, proving no false positives; 320/320 functions decompiled with 0
    errors. Follow-on: sound *elision* of the now-labeled setup/check (they are dead
    once recognized) would remove the noise entirely rather than only naming it.
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
    the census's ~4272 SSE lines drop to zero `// asm:`; the PE/MSVC game binary's
    `sub_140064e17` reads its nonvolatile spill as `local_70 = xmm6.0`, and a Bevy/Rust title's
    struct copies read as `xmm0.1 = *rsi` / `local_10 = xmm0.1` with correct SSA
    versioning and struct-field recovery firing through the xmm value. Sweep of 60
    functions each on a PE/MSVC C++ game binary, an ELF/GCC title and a Bevy/Rust
    title: 180/180 ok, 0 errors (18 of the Bevy/Rust title's 60 now render `__m128`).
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
    `/*cond*/` placeholder — never a fabricated condition. **Verified:** the PE/MSVC
    game binary's `sub_140064abf` now reads `rcx.43 = (v6 == 0x0); rcx->field_0xa8 = rcx.43;`
    (was `rcx.43 = /*sete cl*/`); `setne`/`setae` vanish from the `// asm:` census;
    a corpus sweep of 60 functions each on a PE/MSVC C++ game binary, an ELF/GCC
    title, a Bevy/Rust title and a 116 MB PE/MSVC C++ shipping binary decompiled
    240/240 with 0 errors and no `/*set*/` placeholders
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
    *join* of the two branches — precise and sound). **Verified:** the PE/MSVC
    game binary's `sub_140064abf` now reads `r8.30 = ((rbx.3 < /*u*/ r8.29) ? rbx.3 : r8.29)` (was
    `/*cmovb r8,rbx*/`) — which is exactly the unsigned-`min` idiom, now *visible* for
    a later idiom pass to fold. `cmovb`/`cmovbe` leave the `// asm:` census; a sweep
    of 60 functions each on a PE/MSVC C++ game binary, an ELF/GCC title, a Bevy/Rust
    title, a 116 MB PE/MSVC C++ shipping binary and an IL2CPP title decompiled
    300/300 with 0 errors (ternaries now render in 20, 19 and 7 of the PE/MSVC,
    Bevy/Rust and IL2CPP samples).
  - **5f — `min`/`max` idiom fold.** ✅ *(2026-08-30, verified.)* Once `cmovcc`
    lowers to a select (5e), the classic `cmov`-after-`cmp` becomes the visible shape
    `(l <cmp> r) ? x : y`. When the two branch values *are* the two compared
    operands, that select is exactly `min`/`max`; which one — and signed vs unsigned
    — is fixed by the comparison operator and by whether the true branch keeps the
    left or the right operand. A render-level recognizer folds it to
    `__min`/`__umin`/`__max`/`__umax(l, r)`. Sound: it fires only on that exact shape
    (the branches must be structurally the compared values), so it can never relabel
    an unrelated ternary — an unrelated select still renders as a plain `?:`.
    **Verified:** the PE/MSVC game binary's `sub_140064abf`'s `((rbx.3 < /*u*/ r8.29) ? rbx.3 : r8.29)`
    now reads `__umin(rbx.3, r8.29)`; a sweep of 80 functions each recovered 16
    min/max on it and 38 on a Bevy/Rust title (Rust's slice-bound and clamp code),
    0 on an ELF/GCC title in-sample, with 240/240 ok and 0 errors.
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
    identically. **Verified:** a Bevy/Rust title's `sub_305686` now reads
    `rcx.11 = ((rcx.10 << 0xd) | (rcx.10 >> 0x33))` — a 64-bit `rol rcx, 13`
    (`0xd + 0x33 = 64`), a hash mix laid bare; `rol`/`ror` leave the census; sweep of
    80 functions each on a PE/MSVC C++ game binary, an ELF/GCC title and a
    Bevy/Rust title: 240/240 ok, 0 errors.
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
    left opaque) and `div` remain, both sound as opaque. A Bevy/Rust title's SIMD
    string-scan reads `v31 = __pmovmskb(v33)` (316 `__pmovmskb`, 198 `__tzcnt`, 87
    `__pcmpgtb`), a PE/MSVC game binary `return (__cvttsd2si(v2) + v1)`; a sweep of
    100 functions each on a PE/MSVC C++ game binary, an ELF/GCC title, a Bevy/Rust
    title, a 116 MB PE/MSVC C++ shipping binary and an IL2CPP title decompiled
    **500/500 with 0 errors**. Remaining ⬜ for Rung 5: mapping an FP compare + its
    `jcc` to a real ordered/unordered condition, and signedness inference — both
    separate from this lift-coverage work.
  - **5i — BMI/BMI2 + sign-extend lift (a newer-ISA finding).** ✅ *(2026-08-30,*
    *verified.)* A PE/MSVC shipping build's verification sweep surfaced that it was built
    for a **newer ISA** than the rest of the corpus, hitting `// asm:` on instructions
    the others never used: `shlx`/`shrx`/`sarx` (BMI2 flag-less shifts, ~21),
    `cdqe`/`cwde`/`cbw` (sign-extend the accumulator, ~17), `bzhi` (BMI2 zero-high,
    ~9), `mulx` (BMI2 wide multiply, ~8), `btr`/`bts`/`btc` (bit reset/set/complement).
    Lifted, reusing existing shapes where exact: the BMI2 shifts are plain
    `Shl`/`Shr`/`Sar` with **no flag write** (their whole point vs the legacy forms);
    `cdqe` is `(int64_t)(int32_t)rax`; `mulx` is the product plus `__umulh` like the
    1-operand `mul`; immediate `btr`/`bts`/`btc` are exact `& ~(1<<n)` / `| (1<<n)` /
    `^ (1<<n)` with the CF they set left opaque; `bzhi` reads as an intrinsic.
    **Verified:** re-sweeping that newer-ISA build's 200 functions stays 200/200, 0 errors,
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
    **Verified:** an ELF/GCC title's `sub_fe2424` reads `switch (rax) { case 0x0: case 0x2:
    … }` and a Bevy/Rust title's `sub_30b4f5` recovers a full `switch (rdi)` over cases
    `0x0`–`0x20` (fall-through cases correctly stacked); sweep of 100 functions each
    on a PE/MSVC C++ game binary, an ELF/GCC title and a Bevy/Rust title — 300/300 ok,
    0 errors, 6 switches
    recovered. Remaining ⬜: the `default`-vs-unresolved-case distinction when
    the table read is partial.
  - **6b — tail-duplicate shared return regions.** ✅ *(2026-08-31, verified.)* A
    block reached from several paths that would emit `goto block_N` is inlined
    instead when it is a small **tail region** — a `jmp`/`fall` chain, or a small
    `if`/`else` whose both arms are themselves tail regions, ending at function
    exits (`ret`/`tail-call`) with a ≤8-line body and no loop header. Sound (no
    successors past the exit, no back-edge, SSA reads stay valid inlined) — tail
    duplication, bounded so a large shared body stays a single
    `goto` not bloat. **Verified:** the compression DLL's `sub_1800021e0` 2 gotos →
    0; corpus residual-goto lines ~halved (the compression DLL 246→112, an ELF/GCC
    title 156→74, the PE/MSVC game executable 82→46), the newer-ISA (BMI/BMI2)
    PE/MSVC shipping build 200 fns 0 errors. The remaining gotos
    are large shared-body merges (irreducible or bloat-if-duplicated — real C
    keeps these too).
  - **6c — invert empty-then ifs, drop empty else arms.** ✅ *(2026-08-31,*
    *verified.)* `if (c) {} else { B }` reads `if (!c) { B }` and an empty else is
    dropped — both arms are emitted into buffers first so emptiness is known
    before the shape is committed (a bare `// block_N:` label is not content).
    Pure rewrite. **Verified:** `sub_1800010d0` reads `if ((rdx & 0x1) != 0x0) {…}`
    (no empty then/else); corpus empty-then ifs 398 → 15 across the compression DLL
    + the newer-ISA PE/MSVC shipping build.
  - **6d — do/while when the header is an inner branch.** ✅ *(2026-08-31,*
    *verified.)* Bottom-test detection no longer requires a non-`cjmp` header, so
    a loop whose header carries an inner `if` (both arms in-loop) and whose real
    test is the bottom latch recovers as `do { … } while (c)` instead of the
    `while (1) { … if (c) continue; break; }` fallback. **Verified:** the newer-ISA
    PE/MSVC shipping build's `sub_140012757` inner-`if` loop reads `do { … if (…) {…}
    … } while ((r15.1 != v3))`; 20 do/while loops recovered across 200 of that build's
    functions, 0 errors.
  - **6f — collapse nested else-if into an else-if chain.** ✅ *(2026-08-31,*
    *verified.)* `else { if (c) {…} else {…} }` reads `else if (c) {…} else {…}` —
    the if-else-if ladder. `try_else_if` detects that a captured else arm is
    exactly one `if` spanning the whole block (brace-balance walk — safe since
    rendered expressions never contain `{`/`}`), dedents a level, and merges the
    `} else ` onto the inner `if`. **Verified:** a 3-way ladder reads `if (rcx==1)
    {…} else if (rcx==2) {…} else {…}`; 36 else-if chains across the compression DLL
    + the newer-ISA PE/MSVC shipping build with **0 brace-unbalanced functions**.
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
    Corpus: 33 for-loops (the compression DLL 10, the newer-ISA PE/MSVC shipping
    build 23), 0 opaque, 0 brace-unbalanced, 0 errors; the once-mis-scoped
    `sub_180002fa0` is now brace-balanced with one clean `for`.
  - **6h — no-return paths excluded from post-dominance.** ✅
    *(2026-08-31, verified.)* N0xis was emitting a branch-arm + `goto` where the
    shared tail should invert the condition and fall through. Root cause: `dominators_rev` connected *any*
    successor-less block to the virtual exit, so a `call-noreturn`/`int` abort
    counted as normal completion and broke the post-dominance of a shared tail
    every *returning* path converges on. It now takes `is_abort` and connects a
    dead-end to the exit only when it is not an abort — a no-return path is not
    a completion, so it must not carry post-dominance. **Verified:** on a real
    MSVC C++ PE, `sub_180002780` 2 gotos → 0, structuring the shared assignment
    tail once as fall-through with an inverted condition; residual gotos drop on
    CRT-heavy code (117 → 72).
  - **6i — strip unreferenced block-label anchors from display.** ✅
    *(2026-08-31, verified.)* The `// block_N: <addr>` anchor was emitted on
    *every* block, including the ones nothing jumps to, which is pure noise.
    `DecompInput::strip_block_labels` drops the anchor from any block no `goto`
    targets on the display/agent paths, while `ProvenancePass` keeps them (its
    line→address map needs them). **Verified:** over 40 functions the line count
    fell **1 779 → 1 257**.
  - Remaining ⬜: the residual shared-body gotos (large shared merges — real C
    keeps these) and the switch `default`/unresolved-case distinction.
  - **Where readability stood after this session (2026-08-31, a real MSVC C++
    PE, 40 functions).** Total lines **1 257**, residual gotos **17**, opaque
    conditions **~0**, C++ method names recovered from RTTI. The one systematic
    remaining gap is **library-function naming**: statically-linked CRT/STL
    functions (`free`, `memcpy`, `_Throw_C_error`) still render as `sub_XXXX`
    (108 of them unnamed). Closing it is the **FLIRT-class signature library**
    (Phase 10 priority 8), which needs a reference-library corpus to bootstrap
    the signatures — the honest blocker, not a small fix.

- **Rung 7 — Structural advantages this design gets for free.** 🚧 Capabilities
  that fall out of the architecture rather than being bolted on. Two are already
  present by construction: every pass
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
    Exposed as `rtti scan`. **Verified on a PE/MSVC C++ game binary
    (Ogre + a third-party physics stack):** 3055 vtables
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
seam between them (`watchpoint → decompiled statement`) is the point. So the
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
| **Frida** *(optional)* | Alternative hooking/tracing backend, fast prototyping | dynamic | system / bindings |
| **rr** *(optional)* | Deterministic record-replay → provenance "backwards in time" | dynamic | system pkg |

### Static breadth — the multipliers

| Tool | Why | Half | Pull-in |
|---|---|---|---|
| **SLEIGH ingest** (`.sla` → P-code → MicroIR) | One `SleighArch` backend behind `trait Arch` unlocks the ~40 ISAs those specifications cover; the arch-breadth lever | static | crate/port + SLEIGH specs |
| **yaxpeax-{mips,ppc,riscv}** / **Capstone** | Cheap per-ISA decoders (decode ≠ semantics); Capstone as a broad fallback | static | crates |
| **goblin/object** (Mach-O) + a **format seam** | Close Mach-O and firmware loaders (the Phase-15 format-seam debt) | static | crate (have goblin) |
| **gimli** (DWARF) + **pdb** | Type/symbol ingest — the base for whole-program types and the PDB item | static | crates |

### The shared engine — symbolic / concolic (serves both)

| **SMT solver: Z3** (or lighter **bitwuzla**) | Path constraints: deobfuscation (static) **and** runtime computed-target resolution (dynamic) — Rung 7 / priority 12, on SSA + `ValueSet` + Unicorn | **both** | crate `z3` |

This is the most important *seam* tool: one concolic engine powers both static
deobfuscation and dynamic target recovery.

### Level 1 — static-output quality (our own way, verified on real targets)

The depth where a decompiler is judged, done as our own passes (not by imitating a
third-party format). Each increment is verified on a real binary before ✅.

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
- **Differential oracle**: **Unicorn** — execute a lifted function against the
  real bytes and diff the semantics. The oracle is the hardware.
- **Fuzzing** (`cargo-fuzz`/libFuzzer) of the format/ISA parsers — mandatory,
  since they parse untrusted bytes (the OOM lesson: never `with_capacity` on a
  parsed length).
- **Cross-arch corpus** — beyond games: MIPS/PPC/RISC-V/ARM samples, malware,
  embedded firmware.

#### The differential verification plan (2026-09-07)

Alongside the oracles that are already mechanical (`sizeof` from real headers,
unwind-entry counts from an independent reader, the containment properties), a
second full decompiler is run **headless over the same functions of the same
binary**, and the two outputs are diffed. The harness lives outside this
repository, with the tool it drives.

**The one rule that makes this sound, and it is easy to get wrong: a second
opinion is not ground truth.** Tuning N0xis to agree with another implementation
would import its wrong answers as fast as its right ones, and the agreement would
look like progress. So a disagreement is a **question**, never an instruction,
and it is answered by a *third*, objective source wherever one exists. Nothing
changes on the strength of "the other one does it differently".

Four tiers, by how objectively a disagreement can be settled:

- **A — settled outright, no opinion involved.** Function counts against the
  symbol table and the unwind tables; `sizeof` from real headers; every recovered
  protected range inside its own function; every landing pad the start of a real
  unwind entry. These already run and the second decompiler adds nothing to them.
- **B — structural disagreement with a checkable answer.** Function boundaries,
  switch-case counts, tail calls, no-return classification, call targets. Where
  the two differ, the bytes settle it — by disassembly, or by emulating the
  function against the real hardware semantics. This is where the harness is
  most valuable and least arguable.
- **C — semantic disagreement.** Recovered types, class layouts, devirtualized
  targets, calling conventions. The third source here is **debug information**,
  which is why item 1 of the gap-closing plan pays twice: a DWARF/PDB reader is
  both the missing feature *and* the instrument that settles this tier. Until it
  exists, tier C is triaged by hand against the real headers, and disagreements
  are recorded as open questions rather than resolved by preference.
- **D — readability.** Lines, residual gotos, opaque conditions, unnamed callees.
  **Never a correctness signal**, and never a target to match. It is a work queue
  for the compiler-idiom library: an idiom left as raw arithmetic here and
  recovered elsewhere is a concrete, reproducible item instead of a guess about
  what to build next — which is exactly what the backlog has been short of.

**Mechanics, so it can actually run in parallel with development.** The analysis
pass is the expensive half and is per *binary*, not per function: analyse each
neutral target once, keep the project on disk, and drive later dumps against the
stored project rather than re-importing. Analysis runs as a background job under
a memory cap (this machine OOM-kills rather than swapping); the N0xis side of the
same function set takes seconds, so the loop is: analyse once, diff often.

**What gets recorded.** Absolute numbers for **N0xis**, keyed by commit, so a
release is comparable to its own past. The other side's numbers are context in
the working notes and do not enter this repository — see the verification
discipline above. Every change made because of a disagreement records *the
independent reason* it was made, not "to match".

#### The defect-class sweep (2026-09-07) — what it found, and what it left open

The plan above is organised by *oracle*. This one is organised by **defect
class**, because the defects this project actually ships repeat by shape, not by
feature. A class is only worth hunting when something can catch it; each entry
below names its catcher, and the ones with no catcher are stated as unverified
rather than assumed sound.

**Class 1 — silently dropped semantics. Closed, with a standing oracle.**
An instruction lifted as though a prefix were absent. `crates/n0xis-arch/examples/prefix_audit.rs`
sweeps a code blob and asks, for every flag the decoder reports, whether the
lifter modelled the instruction anyway without saying so. It found segment
overrides: `fs:[0x28]` — the stack canary — was lifted as a load of absolute
`0x28`, a read of the null page that no running program performs. 11 384 of them
in one Qt build, 455 795 in a Chromium build. Fixed (`__seg_fs`/`__seg_gs` around
the offset), and the audit now reports **zero silent drops across 74.6M
instructions** of the four verification targets. The audit's own first version
over-reported four categories — `rep` on a non-string instruction, an MPX `bnd`
hint, a branch hint, a desynchronised decode — all architecturally inert; the
metric was corrected, not caveated, and calibrated against the old lifter (11 384)
before its zero was believed.

**Class 2 — invented values. Clean on the sample.** A rendered value the source
never produced. Checked as an invariant over output: 0 across 260 constructors
and destructors in a 1 812-function Qt sample. The related `return operator
delete(...)` form is *not* a defect — the callee returns void, so the rendering
is legal and truthful.

**Class 3 — call arity. Closed.** A demangled name states its parameter list, so
a call carrying more arguments than the name allows is over-reporting. 1 191 of
1 890 such calls were over the ceiling; now 2, both the checker mis-reading a
function-pointer parameter type. A PE target states almost nothing here (7 such
calls in 600 functions — its callees are `sub_` and imports), which is reported
as no signal rather than as a pass.

**Class 5 — boundaries. Closed on PE, open on ELF without unwind info.**
A PE *does* state its function extents — in `.pdata` — and `StaticPe` was not
reporting them, so every PE ran the extent heuristic and a tail call read as an
intra-function branch. One function ran 8 685 bytes through fifteen neighbours.
Fixed, and measured by a criterion that reads neither `.pdata` nor the symbol
table: extents swallowing a padded function boundary went 22 -> 0 on one PE and
stand at 0 of 1 398 on another.

Three things this measurement taught, all worth more than the number:

- **The ELF result was circular and had to be withdrawn.** "7 105 of 7 105 exact
  against the symbol table" was the symbol table checked against itself: `ir.rs`
  already cuts at `st_size` when one exists. The non-circular reading, by the
  independent detector, splits three ways — 1.18% of functions with a stated
  size, 1.10% of those with only an `.eh_frame` FDE, and **12.23% of the 8 478
  candidates with neither**. That last group is the real open item, and it is
  where the extent heuristic is alone.
- **`.eh_frame` and `.dynsym` agree on all 7 105 functions where both speak**,
  which is what makes either usable as ground truth. An FDE also states the
  extent for 6 832 functions that have no `st_size` — but the heuristic already
  agrees with the FDE on 6 793 of them, so wiring `.eh_frame` into `symbol_size`
  is worth 39 functions, not thousands. Ranked accordingly: low.
- **What the PE fix costs, stated rather than discovered later.** `.pdata` states
  the primary extent, so separated code with no unwind entry of its own is now
  cut: 11 branches in 2 functions across one PE, each reaching 3-19 bytes past
  the stated end. The right rule is to cap tail-call detection at *the next known
  function entry* instead of cutting at the stated end, which recovers both; it
  needs the discovered-entry set in the analysis context and is a separate item.

**Class 8's first result, found while measuring Class 5 — function discovery
over-reports by a third on ELF.** The extent work kept pointing at a group of
candidates with no stated size and no `.eh_frame` FDE, and the group turned out
not to be functions. Two independent signals say so, and they agree:

- **Alignment.** Candidates confirmed by `.dynsym` or an FDE are 16-byte aligned
  99.3-99.8% of the time. The group with neither oracle: **10.5%**.
- **Entry by fallthrough.** A function is not entered by falling out of the
  preceding instruction. Confirmed functions score 10.8-13.5% by this test (the
  residue is linear-sweep desync, which is the test's own error bar); the group
  with neither scores **88.1%**.

Reading the bytes settles it outright: `0x10c313` and `0x81d46a` are both
`mov %rbx,0x28(%rsp)` in the middle of a named function, immediately after its
`mov %fs:0x28,%rbx`. The cause is in the pattern list — `mov [rsp+x], rbx` is a
Win64 *home-save* prologue, and System V has no home space, so on an ELF those
bytes are the stack-canary store that every protected function performs. Per
pattern on that build: `endbr64` 13 632 real against 8 false; the home-save
pattern **3 real against 3 993 false**; `sub rsp, imm8` 183 against 4 167.

Fixed for the home-save pattern, which is an argument about the ABI:
22 413 candidates -> 18 417, real 13 937 -> 13 934, aligned 65.9% -> 78.1%.
**`sub rsp, imm8` is left alone deliberately** — it is a genuine prologue under
both ABIs, and every rule that would filter it here was fitted to this one image
(the first attempt, "preceded by a boundary byte", discarded 9 376 real
functions because GCC pads with multi-byte `nop`s). Validating a weak candidate
by building its CFG is the principled fix and is a separate item.

**What the differential oracle added, run at last on this question.** An
independent decompiler identifies **18 833** functions in the same binary;
N0xis reported 22 413 before this change and 18 417 after. Asked at scale — 300
of the no-oracle candidates against 150 controls the symbol table confirms — it
answers:

  controls        150 asked, 150 an entry  (100.0%)
  no oracle       300 asked,   1 an entry  (0.3%, 298 called the middle of
                                            another function)

The 100% on the controls is what makes the 0.3% readable, and getting it took a
correction: the harness resolved an argument as written and only then as an
offset from the image base, which is **ambiguous** on a relocated shared object
— every address above the base is valid both ways. That silently answered about
the wrong function and scored the controls at 21.8%. The caller now states which
address space it is speaking in. The probe also does not decompile: the question
needs only the function table, which turns a ten-minute run into two seconds.

The oracle disagreed in the other direction too, on `QTextDocumentPrivate::unite`
— an 8 244-byte extent where the symbol table states 258 and N0xis matches the
symbol table exactly. That is the discipline working both ways: a disagreement
is a question, and the third source answers it, sometimes against the oracle.

**Classes still open, ranked.**

1. **Class 1's stronger oracle — emulation.** The prefix audit answers "did the
   lifter acknowledge this flag", never "is the lifted program the same program".
   Executing a lifted function against real hardware semantics answers the whole
   class at once. Unicorn is already first in the acquisition order.
2. **Class 5 on ELF without unwind info** — the 12.23% above, and the
   next-function-entry cap that also repays the PE residue.
3. **Class 4 — base versus derived in field types. Measured at last: 5 of 88.**
   A devirtualization can rest on a constant table address, on the object's own
   class, or on the *declared type of a field* — and only the last is unsound as
   a vtable, because what is stored there may be a derived class. `Devirtualized`
   now reports which (`basis`), which is what made the count possible. Over 1 812
   functions of a Qt build, against a hierarchy recovered independently from the
   image's `_ZTI` records: 88 resolutions, 79 on the object's own class and 9 on
   a field type, of which **5 name a class that has subclasses in the same
   image** — `QWindow` twice, `QWindowPrivate`, `QPaintEnginePrivate`,
   `QTextFrame`. On a project with no persisted layout the count is zero,
   because field-based dispatch needs the layout to exist at all, which is why
   the number had never appeared.

   **Closed.** The Itanium side now recovers the hierarchy too, and the pass
   refuses a field-based dispatch through any class the image shows being
   derived from: 88 resolutions -> 83, the five refused being exactly the five
   at risk, with the 79 object-based ones untouched and decompile latency
   unchanged. Two things this needed, both of which had blocked it:

   - **Base pointers do not need a relocation *parser*.** A base inside the
     same image is a relative relocation, and a relative relocation's addend is
     stored at the target location — so it reads out of the file. A base in
     another library is symbolic, reads as zero, and is correctly absent.
     Reading `.rela.dyn` alone is the trap: it does not expand `.relr.dyn`, and
     found 102 of 211 edges, understating the hazard by half.
   - **The graph must be checked against something.** The first implementation
     read from the `_ZTV` symbol rather than following its second word to the
     `type_info`, and recovered **zero** edges — invisible without a second
     extraction to compare against. On the predicate that decides the gate —
     which classes have an in-image subclass — the two now agree on all 52.

   **The original reading of this item, kept because the mistake is the lesson.** The hazard is that a field typed as a base
   class is a sound *type* and an unsound *vtable*. Trying to count how many
   resolutions rest on such a field found there are none to count on either
   verification target, for two different reasons:

   - **Devirtualization reached no ELF command — since fixed, and the first
     reading of it was wrong.** The measurement said "zero devirtualizations on
     a 22 415-function Qt build" and the conclusion drawn was that Itanium RTTI
     was missing. It is not: `scan_itanium_rtti` exists and `analyze` used it.
     What was missing is the wiring — every command that had not been through
     an `analyze` went through `rtti_vtable_map`, which read only MSVC RTTI out
     of `.rdata` and returned nothing for an ELF. The zero was real; the cause
     named for it was not, and the difference matters because it is the
     difference between a feature to build and a line to connect.

     Now wired: 20 resolutions over a 453-function sample on a fresh,
     unanalysed project. All 20 checked against the symbol table — 17 resolve
     to a method whose own symbol names that class, 2 to a method with no
     symbol, and one to an inherited base-class method the real Qt header
     confirms. None wrong.

     Chasing it also exposed a defect underneath: the Itanium demangler spells
     the ABI's *special names* in its own syntax — `{vtable(QImage)}` where the
     C++ world writes `vtable for QImage` — for **305 of 8 349** mangled
     symbols in that build. `rtti.rs` carried a local workaround, which is why
     it survived: the workaround was in one place and the defect was in all of
     them. Now normalised at the source, against `c++filt` on all eleven forms.
   - **The PE target states nothing either.** `msvcp140` has 97 vtables and 36
     classes with a subclass, but only **2** register-indirect calls in the whole
     image — everything else indirect is an import thunk. Zero devirtualizations
     over all 1 398 functions is the true answer there, not a broken metric.

   So Class 4 stays unmeasured, and that is recorded as unmeasured rather than
   assumed sound. It needs either Itanium RTTI support or a corpus with real
   virtual dispatch; the first is worth doing on its own account.
4. **Class 6 — parsers of untrusted bytes. Swept; nothing found, and one hole
   found next to it.** Four deliberately malformed PEs — an exception-table size
   declared as ~3.9 GiB, a directory pointing outside the image, a file
   truncated to a third, and header bytes followed by garbage — went through
   `profile`, both discovery modes, `function eh`, `rtti scan`, `module list`
   and `function noreturn` under a 2 GB cap. Nothing crashed, hung, or allocated
   on a parsed length: every read is bounded by bytes present, and both live
   sources clamp to the containing mapping. What it did expose is that three of
   the four **could not be opened at all** — a strict parse rejects the whole
   image over its import table, and an RE target is often exactly that image.
   Fixed with a permissive fallback that records why, so an unreadable import
   table is visibly absent instead of passing for an empty one. A property-based
   fuzzer over the same readers remains worth having; the deterministic cases
   are now the floor, not the ceiling.
5. **Class 8 — promise versus implementation. Swept; two real defects and one
   divergence.** All 114 commands the guide advertises were run against a
   neutral target: no crash, no non-JSON output, no missing schema, no hang. The
   defects were both in `serve`, the command a front-end drives — a session
   command did not use the session's image (the help text says it does), and the
   ready banner carried no `meta` at all. Comparing the CLI against the
   capability registry found five commands implemented twice; four agree
   byte-for-byte and `disasm`/`decode` did not, defaulting to 20 and 16
   instructions. All three are fixed and pinned by tests.

   **What the sweep leaves open, stated rather than assumed.** 57 of 114
   commands route through the registry; the rest are CLI-only, so an agent
   reaches them only if it shells out. That is a Process-seam gap, not a bug,
   and closing it needs an input schema on `Capability` — today a capability
   declares its output schema and its summary but not its arguments, which is
   why the MCP server hand-writes 25 typed tools instead of generating them.
   And the live-memory commands (31 of the 114) have no oracle at all without a
   target process: they are **unverified**, not passing.

**Class 9 — invented control flow. Found late, and the largest of them all.**
The classes above check what the decompiler *says*; this one checks the graph it
says it about, against the only thing a CFG can be checked against without an
oracle: **every edge must land on an instruction boundary inside the function.**
On 1 812 Qt functions that test failed 1 818 times, and behind it were three
separate defects:

- **A declared extent longer than the decode window was discarded.**
  `QPageSize::name` is 5 102 bytes by both `st_size` and its FDE, and came back
  as 99 — the heuristic cut at the first indirect jump. 334 of 15 467 declared
  functions are longer than the 4 096-byte default, and each was silently
  reshaped. A budget for guessing was overriding a fact.
- **The jump-table bound was looked for in the block that dispatches**, but
  `cmp $n,idx` / `ja default` ends its own block, so the guard is always in the
  predecessor. Unbounded, the walk read past the table's end into the
  neighbouring tables — whose entries are code addresses and pass every
  plausibility check. One function: 229 cases where the guard says 29.
- **Edges pointed at addresses with no block** — resolved cases were never made
  block leaders, and a conditional branch out of the function got an edge to a
  block that does not exist rather than being recorded as the conditional tail
  call it is.

Result: switch edges 1 527 -> 688 with none outside the function and none
mid-instruction; conditional edges leaving the function 776 -> 0; **58 149 edges
over 1 812 functions, no violations.**

Worth noting how long this hid. Two unit tests asserted the broken behaviour,
with fixtures that placed switch cases outside the decoded function — a shape
compiled code does not produce, and precisely the one that made the invented
edges look correct. **A test written from the implementation cannot falsify
it**; this one had to come from the bytes.

**Class 10 — output that is not what it claims to be.** Beyond whether the
decompiler is *right*, there is whether its output is *well-formed*, and that
needs no oracle either:

- **`goto` had no label to jump to.** The renderer emitted `goto block_2;` — a
  statement — against `// block_2: 0x10a8ce` — a comment. All 6 350 gotos over
  1 812 Qt functions pointed at something absent from the text. **Now 0**, on
  both an ELF and a PE target. Braces balance and the reported `quality` agrees
  with the emitted `// asm:` lines across all 1 812.

  It took four causes, and the order they came in is the lesson. Promoting the
  anchor to a real label fixed the bulk. Then three transforms turned out to
  discard a block's anchor for reasons that are each correct in isolation and
  wrong when something jumps there: the `else if` collapse, which drops the
  arm's leading label; the empty-arm rule, which drops an arm whose statements
  all render to nothing (a bare `cmp` is only flags, and the renderer drops
  those) — there the label *is* the content; and the short-circuit fold, which
  swallows a chain of comparison blocks and marks them visited without emitting
  them. Whether a block needs its label is not knowable until the function is
  laid out, so `structure` renders, reads the answer off its own output, and
  renders again with those blocks exempted.

  **Two hypotheses in the middle were wrong and were measured, not argued.**
  Emitting label-only blocks from the no-code-loss sweep, and iterating the
  two-pass rendering to a fixpoint, each moved the count by zero. A third fix
  was written for a mechanism that turned out not to be responsible and was
  reverted rather than kept for looking plausible. What found the real cause
  was instrumenting the pipeline — proving the anchor absent *before* the
  stripping pass, which ruled out every consumer downstream at once.
- **A whole-program pass that saw a quarter of the program.**
  `function noreturn` defaulted to 4 096 functions on a 15 470-function image
  and reported `considered: 4096` with no way to tell that from a complete run.
  It now carries `total`/`truncated`, and defaults to the whole program —
  because a default that contradicts the command's own description is the
  defect this sweep exists to find.
- **Two front doors, two answers.** `disasm` and the `decode` capability an MCP
  client reaches defaulted to 20 and 16 instructions for the same request.

**What was checked and found clean**, so the absence is on the record too: 1 248
cross-references over 400 targets (2 215 more on a PE), every one a real
instruction naming the address it is reported against; 104 proven-noreturn
functions, none containing a reachable `ret`; 7 497 call sites with a declared
arity, none over its ceiling; 260 constructors and destructors, no invented
return value.

**Two residues were claimed to be measurement noise, and are now proven so.**
The 179 extents the over-extension detector still flags are **byte-for-byte
equal to their `.eh_frame` declaration** — correct by construction, so all 179
are the detector's own floor (1.16%), not defects. The two remaining
call-arity flags were the function's own signature line and an address-of
inside a template argument list, both misread by the checker; corrected, the
count is zero. A metric that always reports the same small number trains its
reader to ignore it, which is how a real defect hides next to one.

**Where every class stands, measured on both an ELF and a PE target**

| class | ELF | PE |
| --- | --- | --- |
| 1 silently dropped prefix semantics | 0 | 0 |
| 2 invented values | 0 | 0 |
| 3 call arity | 0 | 0 (no signal: callees are `sub_`/imports) |
| 4 base-vs-derived vtable | gated | gated |
| 5 boundaries | 15 467/15 467 exact, 3 unstated | exact |
| 6 untrusted-byte parsers | no crash, hang or unbounded allocation | same |
| 8 promise vs implementation | 114 commands, no contract violation | same |
| 9 invented control flow | 0 of 58 149 edges | 0 of 27 852 |
| 10 malformed output | 0 | 0 |

**Class 7 — defects in the measurement itself — is not a queue item; it is the
tax.** This sweep produced five of them: a boundary comparison that merged
abutting `.pdata` ranges and invented 303 disagreements; an over-extension
detector that counted alignment `int3` and post-noreturn trap bytes as function
boundaries; an instruction map that captured no branch targets at all on ELF,
because objdump prints them without the `0x` the PE output carries, turning a
5.34% result into a reported 60.73%; an invariant checker that read the wrong key
out of the JSON envelope and reported "no violations" while examining nothing;
and an arity ceiling that ignored the hidden result buffer. Every one produced a
confident number first. The rule that catches them: **a metric reporting zero
must first be shown reporting non-zero on the same data.**

#### ARM64, measured (2026-09-07)

The standing caveat said "implemented and self-tested, not verified to x64's
standard", and the first attempt to lift it found why that was the honest word.
The target: a 2.9 MB AArch64 shared library, not stripped — 2 381 functions
whose `st_size` the linker states, which is the same objective boundary oracle
that put x64 at 15 467/15 467.

The first run scored **6.64% exact**. It was not the ARM64 decoder: every
analysis command was decoding the image as **x86-64**, and answering with
four-byte ARM instructions rendered as `jnp`, `sar edi,1`,
`div dword ptr [rdx+53h]` — confident, structured, entirely fictional, with no
error anywhere. Two defects, both silent:

- **The architecture was never taken from the image.** `pick_arch` asked only
  "32-bit or 64-bit", which is what keeps a PE32 from being read as x86-64, and
  nothing asked what instruction set the file declares — even though `profile`
  reads and reports it correctly (`machine: arm64`). It now comes from the
  header, through a new `Src::declared_machine`, with an explicit `--arch` still
  winning outright and an unmappable machine falling back rather than guessing.
- **The IR cache could not tell two decoders apart.** Its key was the source
  label, the input and the probed bytes. So the same image analysed as x64 and
  then, correctly, as arm64 returned the *first* answer both times: passing
  `--arch arm64` appeared to do nothing, because the wrong answer was already
  stored. `Arch::decoder_id()` is now part of the key — and it is not
  `name()`, because the 32- and 64-bit x86 decoders are one type that answers
  `"x86-64"` for both.

With both closed, on the same target and the same oracle:

| check | ARM64 | x64 for comparison |
| --- | --- | --- |
| function extents vs the symbol table | **2 381/2 381 exact** | 15 467/15 467 |
| CFG edges on an instruction boundary inside the function | **0 violations of 46 757** | 0 of 58 149 |
| `decomp pseudo` | `quality: 0.0`, `asm:` nodes, `low-coverage` | full SSA |

So the caveat splits: **the ARM64 decoder and CFG are now verified to x64's
standard on a real target**, and the decompiler is not — the AArch64 lift/SSA is
not built, and the tool says so in its own output rather than pretending.

What this cost, and the lesson: the boundary number was measured *through* the
defect and read as a weakness of the ARM64 support. It was a weakness of the
architecture seam, on every architecture — a 64-bit image whose machine the
default guessed wrong had no way to say so. "The metric is bad" and "the
subject is bad" look identical until the first disagreement is opened.

#### 32-bit PE, measured (2026-09-07)

The standing note said `profile` returned a zero section table on a PE32. It
did, and the cause reached further than `profile`: three separate places
assumed the PE32+ layout on an image that is not one.

- **`profile` walked the section table 16 bytes past its start.** The data
  directory was read at +112 (a PE32's is at +96) and the section table after a
  240-byte optional header (a PE32's is 224). The output was not empty: it was
  the right *number* of sections with empty names, zero sizes and the image base
  for every address, and zero exports. It now reads `SizeOfOptionalHeader` and
  the optional-header magic — the values the loader itself uses. On a 32-bit
  system DLL the ten sections now match an independent parse byte for byte, and
  the export count went from 0 to 363.
- **Exports by ordinal were invisible.** The PE parser yields only *named*
  exports, and on that DLL 853 of 1216 exported functions have no name at all —
  every one of them an entry point the file declares, absent from symbol
  resolution, discovery and cross-references alike. The export address table is
  now read directly (with the count bounded by the bytes present, never used to
  size an allocation), and an unnamed export is called `Ordinal<N>` — what the
  file actually says, rather than a name invented to look like a symbol.
- **`function discover` had two implementations that disagreed.** The CLI keeps
  its own handler for it instead of dispatching to the registry, and each had
  its own copy of "what does the image state about its functions". Adding
  exported entry points to one made them answer 2 394 and 2 396 for the same
  file. There is now one definition, `n0xis_frontend::stated_functions`, and a
  test that the two front doors agree.

Measured on the same 32-bit image, with the export table as the oracle:

| check | before | after |
| --- | --- | --- |
| `profile` sections | 10 entries, all empty | 10, byte-identical to an independent parse |
| exports seen | 363 of 1216 | 1216 |
| exported entry points discovered | 416/422 | **422/422** |
| CFG edges on an instruction boundary inside the function | — | **0 violations of 34 149** (1 078 of them `switch-case`) |

The declaration fix is also a reminder of the rule: the first attempt at it
changed **nothing** — 416/422 before and after — because the CLI was running its
own copy. A fix that moves the number by zero has not been understood yet.

#### The Windows half, executed (2026-09-08)

Everything under `#[cfg(windows)]` had never run anywhere. It was type-checked
with `cargo check --target x86_64-pc-windows-gnu` and nothing more — no live
adapter call, no debug register set, no detour written. That is 9 commands that
refuse outright on Linux (`patch detour`, `table freeze`, `locate
by-transition`, `input probe`, `ui locate`/`windows`/`screenshot`/`focus`,
`il2cpp classes`) plus every Win32 path underneath the rest.

It has now been run twice, on a Windows 11 machine over SSH and under Wine, with
a disposable target that is **its own oracle**: there is no `/proc/<pid>/mem`
here, so the target prints what its planted bytes hold every 100 ms and "did the
write land" is answered by the process itself.

**Result on Windows 11: 21 of 23 checks measured, 0 wrong.** The two that are
not measured say why: `stack backtrace` refuses with `live-unsupported` (it
needs the Linux ptrace register-capture path — the one place where the Linux
adapter is ahead of the Windows one), and `ui focus` correctly finds no window
for a console target.

Two defects, the second hidden by the first:

- **`patch detour` could never install.** The code cave was allocated by
  `VirtualAllocEx` with no address hint, documented as "*usually* within a `jmp
  rel32`'s reach". Measured, never: a 64-bit image at `0x7ff6_xxxx_xxxx` and an
  unhinted allocation at `0x1ce8_xxxx_xxxx` are 29 GB apart against a ±2 GB
  displacement. Every detour on an ordinary target was refused — correctly, but
  the feature did not work at all. `alloc_code_cave_near` now walks the free
  list outward from the hook site and allocates with a hint.
- **And then it killed the target.** With the hook installable, the process died
  on the next call. `build_trampoline` copied the displaced bytes verbatim —
  its own doc claimed they "still execute exactly as before" — and the ten bytes
  displaced from the real hook site were `mov rax,rcx` followed by
  `mov [rip+0xcf5ee],rcx`, a store to a global. In a cave 64 KiB away that
  instruction still decodes, still runs, and writes somewhere else.
  `Arch::relocate` now re-encodes displaced instructions for their new address.

Verified on the measure that matters — not "was the jump written" but "does the
hooked function still run": 21 lines/2 s before, 20 with the detour installed
and the process alive, 10 bytes restored by `patch undo`, 19 lines/2 s after.

**The lesson is about the order.** Fixing the allocation alone turned a safe
refusal into a crash, and the first run after that fix is what crashed. A defect
that cannot be reached is not absent; it is waiting for the thing in front of it
to be fixed.

**Wine as the cheaper loop.** The same mingw build runs under Wine, and the
static half was diffed against the Linux build on identical input: `profile`,
`function discover`, `disasm`, `ir build`, `decomp pseudo` and `guide` all
byte-identical, with `doctor` differing only in how it spells a path. Under Wine
the live half scored 27/31 with `/proc` as the oracle. That is not verification
*on Windows* — Wine is a reimplementation — but it turns a two-minute deploy
into a two-second one, and it found both detour defects before the laptop did.

#### The engine paths, measured (2026-09-08)

IL2CPP, the Bitsquid/LuaJIT reader and the WARP reader had never been run
against a real shipped asset by any oracle. Each now has one that is not n0xis:

| path | oracle | result |
| --- | --- | --- |
| `il2cpp metadata` | an independent parse of `global-metadata.dat` | file size, table offsets and sizes identical; **18 244** literals, which is exactly the 145 952-byte literal table / 8 bytes per entry |
| `il2cpp icalls` | the image's own bytes | **1 000/1 000** recovered names present verbatim in the image; 998 with a resolver site, 652 with a live slot. `function` is null on a static file by design — the binding happens at runtime |
| `bundle list` | the archive itself | **84** bundles read, **0** errors, 37 459 entries, 25 asset types; all 3 single-entry bundles named by their entry's path hash |
| `bundle extract` + `lua disasm` | the LuaJIT bytecode magic | **165/165** extracted assets carry `\x1bLJ`; **165/165** disassemble, 2 572 prototypes, 0 refusals |
| `warp dump` | the UUIDv5 shape the format specifies | **359 607** functions across four real signature files, every GUID a well-formed UUIDv5, every one named, **0** malformed |

The `warp dump` row is history as of 2026-09-11: the WARP layer moved to its own
repository and the command is no longer in this binary. The measurement was real
and is left standing as a record — do not read it as a capability this build has.

Still without an oracle here, with the reason: `il2cpp import` / `il2cpp
symbols` consume an external dumper's `script.json`, which this machine has
none of; `il2cpp obj` / `il2cpp classes` need a live managed process.

A note on the first bundle measurement, because it is the recurring shape: the
check began as "the filename must equal a recovered path hash" and reported 72
of 84 as mismatches. Only *single-entry* bundles are named that way; the rest
are named by the bundle's own hash. The reader was right and the invariant was
invented.

#### A stronger Class 1 oracle: dropped effects (2026-09-08)

`prefix_audit` answers "did the lifter acknowledge the flag this instruction
carried". The harder half of the question is whether the lifted program still
*computes* what the real one computes, and
`crates/n0xis-arch/examples/effect_audit.rs` asks it directly: for every
instruction, does the lifted form assign every register the hardware writes? A
register the instruction writes and the lift never binds is a dropped effect,
and everything downstream — SSA, value sets, the decompiler's variables —
reasons about a machine missing a write.

An `Unlifted` statement is an honest refusal and is not counted, as in the
prefix audit. What is counted is a *definite* model that is silently short.

Three writes are declared abstractions rather than drops, and are named in the
audit so a new one cannot hide behind them: `rsp` across `call`/`ret` (the pair
is stack-neutral and the micro-IR expresses the transfer as `Call`/`Return`),
and the upper vector lane on `vzeroupper` (the micro-IR models the low 128 bits,
where the instruction genuinely does nothing).

| target | definitely lifted | opaque | dropped writes |
| --- | --- | --- | --- |
| ELF x64 | 1 424 547 | 309 339 | **0** |
| PE x64 (a) | 129 720 | 32 237 | **0** |
| PE x64 (b) | 77 636 | 16 821 | **0** |
| PE32 i386 | 114 526 | 47 278 | **0** |
| ELF x64, very large | 57 322 081 | 15 326 435 | **3**, all `retf imm16` |

The three are `retf` with an immediate in a data island — `Retf` was simply not
in the declared-abstraction list beside `Ret`. **17.8% of instructions are left
opaque rather than modelled**, which is rule 6 working: an honest refusal, not a
guess.

**What this is not.** The plan asked for *emulation*: run the lifted function
against the real bytes and compare the machine states. That is still not built,
and this does not replace it. Emulation would catch a lift that assigns the
right registers with the wrong *values*; this catches only a lift that does not
assign them at all. It is a strictly weaker question — chosen because it is
exhaustive over 72 million instructions today, where an emulator is not — and
the stronger one stays open. ⬜ Emulation (Unicorn) as the Class 1 oracle.

The audit is calibrated the only way that means anything — by breaking the
lifter. Dropping the destination write from the `xor reg,reg` zeroing idiom made
it report **27 899** drops, naming the mnemonic and the register; restored, 0.

**What it found on the way.** Chasing the `retf` entries turned up something
the audit was not looking for: `ret`, `ret imm16`, `retf` and `retf imm16` all
lift to the same `Return`, so the callee-cleanup byte count is discarded. On the
32-bit PE that is **2 361 of 3 130 returns** carrying an exact argument size —
`ret 8` is two dword arguments, `ret 0xc` is three — free, exact arity for 75%
of that image's functions, thrown away. (On the 64-bit PE it is 1 of 2 386, as
expected: stdcall does not exist there.) It was worse than a gap:
with nothing else to go on, every one of those functions rendered as
`f(void)` — not "unknown", a statement that the function takes no parameters.
`AddCommasW`, an exported Windows function that plainly takes arguments, read
`void AddCommasW(void)`.

✅ Closed. `DecodedInsn`/`IrInsn` carry `stack_adjust`, and on a
stack-argument ABI — where `abi_arg_regs` is empty and the register scan can
only ever answer zero — the arity comes from the return. Every return that
states anything must state the *same* thing, and a cleanup that is not a whole
number of slots is refused rather than rounded. Measured over 400 functions of
the 32-bit DLL: **316 now carry a parameter count (79%), against 0 before**.

And one more the improved output exposed: `infer_expr_type`'s fallback width
was hardcoded to 64 bits, so **330 of those 400 signatures claimed `uint64_t`**
on a target whose return register is `eax`. The width is the architecture's
now; x64 output is unchanged, i386 reads `uint32_t`.

#### The corpus, widened (2026-09-08)

Every number above and in the sweep now rests on more than one binary. Six
targets: an ELF x64 UI library, two x64 PEs, an AArch64 ELF, a 32-bit i386 PE,
and a very large ELF x64 (72.6 M instructions).

CFG invariants — every edge on an instruction boundary inside the function —
across all six: **no violations**, after one fix the wider corpus exposed.

**The fix.** A conditional branch as the function's *last* instruction has both
sides outside it. The taken side was already recorded as a conditional tail
call; the fall-through was still emitted as a `cjmp-false` edge onto the next
function's first byte — a block that does not exist in the graph. Two on one PE
against 19 437 edges, four on a 4 000-function slice of the large ELF. That is
the size at which an invented edge is invisible, and it is why the corpus had to
widen: the same checker on the same code found nothing on the target it was
written against.

**And a defect in the sweep itself.** The first run reported 605 and 619 `eh`
violations on the two PEs. MSVC puts an exception handler in a funclet with its
own `.pdata` entry, so an `eh` edge legitimately leaves the function there — the
checker knows this, but only when handed the function-entry list, which the new
sweep script did not pass. The tool was right; the harness was not told.

#### Readiness: what is proven and what is only unbroken (2026-09-08)

Asked directly whether this is ready to ship, the honest answer is **no**, and
the reason is a number rather than a feeling.

**54 of the 114 commands have a correctness oracle** — an answer checked against
a source that is not n0xis: the kernel's view of a process, an image's own
tables, a target that reports what it holds, an independent parse. **The other
60 have only the contract check**: they return a well-formed `{ok,data,meta}`
envelope with the right schema, and nothing has looked at whether the content is
true.

A pass against purpose-built oracles has since closed all 60. **57 were
measured against a source that is not n0xis**; the other **3 are recorded with
the reason no oracle exists for them here** — `bundle repack` needs a real
engine archive to write into, and `il2cpp obj`/`classes` need a running
IL2CPP runtime.

The oracles were: a target compiled from known C source with the compiler's own
DWARF; the images' own `.pdata`, export and RTTI tables; `objdump`, `eu-stack`,
`nm` and `grep` as independent parsers; a live LuaJIT process whose heap
contents were written for the purpose; a NativeAOT binary published from known
C#; a live Windows desktop; and the OS itself (`GetForegroundWindow`,
`/proc/<pid>/mem`, `/proc/<pid>/maps`).

**The answer to the shipping question has not changed, and the reason is again
a number.** Asking those 57 found **twelve defects, all fixed**, and three
answers that are wrong or absent, recorded rather than papered over.

The three rendering fixes were then measured on four targets they were *not*
tuned against — a mingw build, two more runtime DLLs, a Qt library and a browser
engine. The empty-arm counts were already 0 everywhere. The stack-pointer count
was not: `rsp.2 = ((rsp.0 & -0x20) + -0x80)` — align, then allocate — survived
on the Qt build, because the first predicate looked one level deep. Generalised
to "built only from the stack pointer and constants, at any depth", it is 0 on
all five, and the single line left standing is `rsp.4 = (rsp.1 - rax.7)`, which
`objdump` shows is a variable-length allocation.

#### The six items this pass was set, and where each one stands

Each has a measurement against a source that is not n0xis, or a reason it has
none. There is no third option and no item without one.

| # | item | outcome |
| --- | --- | --- |
| 1 | the `float`/`double` return | **fixed and measured** — the section below |
| 2 | 23% of functions absent | **partly fixed, cause corrected** — a direct `call` target is a function (+47, all confirmed); the stated cause accounts for 53 of 478, and the real breakdown is recorded |
| 3 | 33 commands standing on an older pass | **all re-run** — two defects found and fixed (`provenance trace`, `scan dissect`); every row now names its own source |
| 4 | emulation as a Class 1 oracle | **not built** — reason below |
| 5 | the claim audit | **two classes finished**, the rest open — below |
| 6 | the JSON contract driven by someone other than its author | **not done, and cannot be done here** — below |

**4 — emulation, and why it is not a measurement.** A differential oracle
compares two static readers of the same bytes; it is blind to any case where
both are wrong in the same way, and the `float` return was exactly that (both
typed it as an 8-byte scalar). Only *running* the code settles that class.
Building that is a subsystem — a register/memory machine, a syscall boundary, a
snapshot format — not a measurement that could have been taken in this pass. It
stays open with that reason, not with a claim.

#### A sweep for "succeeded, and said nothing"

The worst shape a wrong answer can take is `ok:true` with an empty payload: the
caller has no error to branch on and no reason to doubt it. So the commands
whose answer is certainly non-empty were run against two real images and every
empty one was looked at. Two were honest (`xref string` reports
`found_unreferenced` when the literal exists and nothing points at it). The rest
of this section is what the sweep found, and what following each cause led to.

**One physical register had two names, and both seams lied about it.** `xmm0`,
`ymm0` and `zmm0` are three views of one register. The def-use records the
widest; the micro-IR and every disassembly line print `xmm0`; nothing bridged
them.

- `ir slice --reg xmm0`, on a function whose only instruction is
  `addsd xmm0,xmm1`, answered **`node_count: 0`** — the tool demanded a spelling
  it never shows.
- `function summary` reported **`clobbers: []` with `clobbers_complete: true`**
  for a pure `double add(double, double)`: a confident claim that calling it
  destroys nothing.

**`function noreturn` proved 2 functions of 1 398**, against 12 an independent
function table finds — and the ones it missed were `terminate`, `_Xbad_alloc`,
`_Xlength_error`, the most obviously non-returning functions an image has.
Three causes, each measured:

| cause | proven |
| --- | --- |
| — | 2 |
| a call to an **import stub** had no name (the stub has no symbol, and the caller's instruction has no RIP operand, so both name sources missed it) | 28 |
| the entry set was the exception table alone — 1 398 nodes where discovery now finds 2 106, and the stubs live in the difference | 30 |
| `terminate` was in the list only under its Itanium mangling, not the plain name a PE resolves | 35 |

Then the recall fix found a **precision** defect in the same list: `_cexit` runs
`exit`'s cleanup and **returns to the caller** — that is the whole difference
between them. Listing it as noreturn made every instruction after a call to it
unreachable, so the decompiler dropped live code and said nothing. Its stub only
became visible once stubs were discovered. Removed: 35 → 34.

Of the two the table has and this does not, one is a miss (`__report_gsfailure`)
and one is the table being wrong: `__CxxFrameHandler3` **returns**
`ExceptionContinueSearch` for a frame that does not handle the exception.
Following it would prune live code after every EH call site, so it is
deliberately absent and the list says so.

A structural check of five of the 104 the pass proves on a Qt build: three end
in a call to `abort` or `__glibcxx_assert_fail` with no `ret` anywhere in
range; the other two are outlined cold fragments, which do not return but are
not functions either — the same cold-partition gap recorded above.

#### Auditing the command reference found three defects in the binary

The 162 claim-shaped sentences in `docs/CLI_COMMANDS.md` were handed out in
slices to independent readers, each told to *run* the binary rather than reason
about it, and each alleged violation then handed to a second reader told to
refute it. **The pass was cut short — 13 of 24 slices finished — so this is a
partial audit and the remaining slices are open.** What the finished ones found
is not a documentation problem:

- **`bundle extract` reported files it had not written.** The output name was
  the entry's path hash alone, inside a loop over that entry's variants, so
  every variant wrote to the same path and only the last survived — while the
  count reported one extraction per variant. On a real engine archive: reported
  9, wrote 1. Now one file per variant, and `files` sits next to `count`.
- **An argument error was not an envelope.** A wrong flag printed a usage
  message to stderr, wrote nothing to stdout and exited 2 — a second failure
  format for the one thing this tool promises there is only one of.
- **Naming two targets picked one by precedence.** `--bytes … --file …`
  disassembled the file and reported success; `--file x --snapshot <missing>`
  succeeded on the file while the snapshot alone fails, which is what proved the
  second source was accepted rather than validated. Both source paths refuse now.

One sentence was genuinely over-broad and was corrected instead: the two
persistent servers are request loops and emit a banner plus one object per
command, not one object each.

**The pass then finished — all 24 slices, 162 of 162 claims — and found two
more, both claims about the binary that the binary does not keep:**

- `stack backtrace` said it reads "stack/unwind bytes via `/proc`". It reads
  them with `process_vm_readv`; `/proc/<pid>/maps` supplies only the module map.
  A syscall trace of a real walk: 487 `process_vm_readv` calls, three `ptrace`
  calls (attach, get-regs, detach), and exactly one file opened — the map.
  `/proc/<pid>/mem` appears once in the whole engine and it is in `write`. The
  same sentence was in the command's own `--help`, so the documentation and the
  binary were wrong together rather than drifting apart; both are fixed.
- `lua disasm` said it "auto-detects source text / stock bytecode / LuaJIT
  bytecode from the header". There is no auto-detection: only a LuaJIT 2.0 dump
  (version 1) is accepted, and Lua source, `luac` output and LuaJIT 2.1's
  version-2 dump are each refused by name. The command's own `--help` already
  said so — the reference contradicted it.

The complete run alleged six violations and upheld two. The other four were
**refuted**, and correctly: they described the three defects fixed above, and
the adjudicators had been handed a frozen copy of the binary from before those
fixes. That is the check working — a skeptic given the same evidence reached the
opposite conclusion because the evidence had changed.

It is also why the harness's own default had to be corrected mid-run. When a
skeptic died, the script marked its allegation *refuted*, so a finding nobody had
examined read as closed. Unexamined is not refuted, and a harness that defaults
the other way is a machine for losing findings quietly.

The reason to record this is not the three fixes. It is that the audit was of
**the author's own documentation**, and it found the binary wrong three times
out of four — the same lesson the front page's "0 wrong" produced a section
earlier.

**5 — the claim audit: two classes finished, one of them again.** There are now
2 136 claim-shaped sentences across eleven documents (up from 1 794, because
this record grew).

- **Comparative class: 17 of 17 adjudicated, 0 violations.** Every one compares
  this project against its own earlier self or against another approach inside
  it — never against another product. The class was clean before and is clean
  after two sentences were added to it.
- **Front page: 28 of 28 adjudicated, 1 wrong.** `README.md` claimed *"29 of 31
  commands measured, 0 wrong"* for the live-memory set; re-running those very
  commands this pass found one of them wrong (`scan dissect`). The claim was
  corrected on the page rather than quietly left standing — which is the point
  of auditing a claim you wrote yourself.
- **Command reference: 162 of 162 claims adjudicated**, all 24 slices, each
  alleged violation handed to a skeptic told to refute it. Five defects came out
  of it: three in the binary, two in the reference. The section above is what
  they were.
- The rest are unread. Most of them are in this file, which is a record of
  measurements rather than a promise.

**6 — the contract, and why this cannot be closed from inside.** "Someone other
than the author has driven the JSON contract" is not a measurement anyone here
can take: an agent working for the author is the author. What *can* be said
without overstating it is already on the front page — *"the versioned JSON
contract has not been road-tested by outside users — expect shapes to move."*
It stays open until an outside user moves it.

#### The pass after that: the one class where the output lied

The go/no-go answer above named one blocker that was different in kind from the
rest: a function returning `float` or `double` did not return a noisy value, it
returned **the wrong one**. This section records closing it, and the four other
defects that measuring it found.

**The defect.** The lift is handed one instruction at a time, so `ret` could
only be modelled as `return <integer return register>;`. For a function whose
result comes back in the ABI's floating-point register that is a value the
function never wrote: dead-code elimination removes it *and everything that
computed it*, and the body renders empty, returning the caller's own register.

**How it was measured.** A target compiled from C with the compiler's own DWARF,
so every return type was known before the tool was asked: twelve functions, five
kinds of shape. **Seven of twelve were wrong, and they were exactly the seven
that return `float` or `double`.** After the fix, twelve of twelve — and twelve
of twelve again on the same source built for the other x86-64 ABI, which nothing
was tuned against.

**The rule.** At a `ret`, the float return register holds a value this function
computed and nothing here reads. A value computed for no local consumer was
computed for the caller. Three qualifications, each of which exists because an
image proved it necessary:

- a block that leaves by a **tail call** is not a return site — it hands the
  register file to the callee, so what is live there is an argument;
- the test reads **through a phi** to its inputs, because a phi at a join is
  never itself read and so passes the test by construction;
- the **integer register keeps the return** when it also holds a computation of
  its own that nothing reads; it is the ABI's default and only loses when it has
  nothing to offer. (Writing the flags is not a use: `add rax, 7` sets flags
  from its own result.)

**What it costs and what it buys, on an image none of it was tuned against.**
Ground truth is the shipped headers of the same package version — the exact
return type of every exported method, from a source that is neither n0xis nor a
decompiler:

| version of the rule | right | wrong | float aggregate | missed |
| --- | --- | --- | --- | --- |
| before | 0 | 0 | 0 | every one |
| first | 125 | 99 | 62 | 25 |
| + tail call, phi, integer tie-break | 120 | 25 | 56 | 30 |
| + arithmetic flags are not a use | 119 | 14 | 55 | 31 |
| + a float **comparison** reads its operands | **117** | **3** | 54 | 33 |

The last row is one root cause, not a family. Scalar FP compares lifted to a
bare opaque-flags assignment that did not mention what they compared — so a
value whose only consumer was a float comparison had **zero uses** in the SSA
graph, and "computed here and read by nobody" was true as asked and false in the
machine. Ten of the eleven functions still answered wrongly traced to that one
shape: a `0.0` materialised by a self-xor, compared against, never stored, in a
`void` early return. Its counterpart in the rule is that writing the flags is
only a non-use when it is the *by-product* of producing the value (`add rax, 7`
sets flags from its own result); `cmp` and `ucomisd` produce nothing else, and
their operands are what they consume.

The three that survive are GCC cold-partition splits: the readers live in
`.text.unlikely`, over edges the CFG does not carry. That is a different defect
and is recorded as one.

**The 33 misses have one cause, and closing it was measured and refused.** They
are functions whose `ret` is reached by a join where one arm's value came from a
call — a stack-protected getter whose arms are "convert it here" and "ask a
helper", say. The rule requires every input of a phi to be a computation of this
function's own, so a call-clobbered arm vetoes the whole thing and the answer
falls back to the integer register (which, in a stack-protected function, holds
the canary residue — a wrong value, not merely a missing one).

Letting a call clobber count as "a value that arrived here" was implemented and
measured: **misses 33 → 15, right 117 → 135, and wrong 3 → 12.** Nine new wrong
answers to gain eighteen right ones is a bad trade under this project's own
rule that a wrong answer costs more than a missing one, so it was reverted. The
class stays open with its cause named; what it actually needs is the callee's
recovered signature, which is an interprocedural question this pass does not
ask.

"float aggregate" is a two-component struct of floats (`QPointF`, `QSizeF`)
returned in **two** vector registers. The model has no name for a multi-register
return, and inventing one would be a different wrong answer rather than a
smaller one — so the answer now says what it is: `ret_registers: ["xmm0",
"xmm1"]` next to a type that names the first half. Measured on the same image,
50 of the 54 such functions are flagged, against 1 false flag among 117 genuine
scalars.

**Four more defects, each found by measuring rather than by reading:**

1. **A call did not invalidate the vector registers.** A value in `xmm0`
   survived a call in the model that the hardware had already overwritten with
   the callee's result. Which registers is per-convention — one ABI preserves
   `xmm6`-`xmm15`, the other preserves none.
2. **A 64-bit value out of the float register was typed `uint64_t`.** Printed
   as an integer, the bit pattern of 3.5 reads as 4 615 063 718 147 915 776.
   The kind now comes from the register file the value returned in, refined by
   the `sd`/`ss` the ISA writes into every scalar-FP mnemonic — with the packed
   *integer* families that also end in `sd` excluded by name.
3. **`provenance trace` named the instruction after the one that wrote.** A data
   breakpoint is trap-class: the CPU reports it once the instruction has
   retired. On a target whose writing instruction was known from its own source,
   the command printed the *following* statement as the cause.
4. **`scan dissect` read a struct four bytes out of phase.** Width was chosen
   before alignment, so an `int` at +4 followed by a `float` at +8 read as one
   `double` covering both — a field the ABI could not have placed there. One of
   six fields right; five of six after.

**And one thing measuring refuted.** The stated cause of the 478 missing
functions — "adjustor thunks; a direct branch target lying in no known function
is a function" — is not what the image says. A direct `call` target *is* a
function (494 targets in that image, every one a function entry to an
independent function table, none interior), and adding that rule found 47 of
the 478 with nothing wrong added. The other 431 are reached otherwise: 51 by a
64-bit data pointer, 216 by beginning at the first non-padding byte after
another function's end, the rest import stubs and thunks in runs. The remaining
gap is a gap-sweep problem, and saying so is worth more than the guess it
replaces.

#### Every command, and what its answer was checked against

The claim "all sixty closed" is only checkable if the list is written down, so
here is the whole surface — all **114** commands, not only the sixty, since the
sixty are a subset and this way none of them can be missing by omission. Every
row names the source its answer was checked against, and none of those sources
is n0xis. Two rows say **not checkable here**, and each says why; three say
**Windows only**, meaning the command refuses on Linux with that reason rather
than answering, and was measured on Windows.

Thirty-three rows used to say *(earlier)* — measured in an older pass and not
re-run. They have all been re-run since, against a live process built for the
purpose (a struct whose every field value and address it prints before anything
is asked of it, plus `/proc/<pid>/mem`, `objdump` and DWARF as the independent
readers) and against real shipped archives and metadata blobs parsed here. That
re-run found two defects, both fixed: `provenance trace` named the instruction
*after* the one that wrote, and `scan dissect` read a struct four bytes out of
phase from its first mistake on.

| command | category | checked against |
| --- | --- | --- |
| `doctor` | Environment & project | the machine and the manifest |
| `profile` | Environment & project | objdump and the raw PE header |
| `guide` | Environment & project | the binary's own command tree (a test fails the build on drift) |
| `init` | Environment & project | the filesystem |
| `project info` | Environment & project | the store on disk |
| `process ps` | Environment & project | `/proc` |
| `capability list` | Environment & project | the registry, and a registered plugin appearing in it |
| `capability run` | Environment & project | the CLI's own answer, byte-identical on five capabilities |
| `remote-serve` | Environment & project | a local read of the same bytes — identical, and the bytes are an ELF magic |
| `bundle list` | Game-engine assets | the type hashes themselves — `murmur64a("timpani_bank")` computed here is the hash it reports, bit for bit |
| `bundle extract` | Game-engine assets | the extracted files, read by another program — 165 of 165 begin with the LuaJIT bytecode magic |
| `bundle repack` | Game-engine assets | **not checkable here** — needs a real engine archive to write back into |
| `lua disasm` | Game-engine assets | LuaJIT's own `-bl` listing — 4 of 4 prototypes, identical opcode sequences |
| `lua patch` | Game-engine assets | LuaJIT's own listing after the patch — exactly one byte changed, `ADDVV` became `SUBVV` |
| `lua strings` | Game-engine assets | a live LuaJIT process — all eleven planted strings, none invented |
| `lua table` | Game-engine assets | the addresses the script printed for its own tables |
| `lua combo` | Game-engine assets | the array the script built, in source order |
| `lua seedscan` | Game-engine assets | the seed planted at the address the script printed |
| `il2cpp import` | IL2CPP managed layer | a dump of known addresses — VA, RVA and neither, all three decided right |
| `il2cpp symbols` | IL2CPP managed layer | the names, addresses and signatures that went in |
| `il2cpp metadata` | IL2CPP managed layer | an independent parse of the same blob — version 24, 18 244 literals from the table's own size, first five identical |
| `il2cpp icalls` | IL2CPP managed layer | an independent PE parse — the string at each reported name address is the name reported |
| `il2cpp obj` | IL2CPP managed layer | **not checkable here** — needs a running IL2CPP runtime |
| `il2cpp classes` | IL2CPP managed layer | **not checkable here** — needs a running IL2CPP runtime |
| `mem read` | Live memory | `/proc/<pid>/mem` — byte-identical (re-checked) |
| `mem write` | Live memory | `/proc/<pid>/mem` — the four bytes it reported writing are the four bytes there |
| `mem map` | Live memory | `/proc/<pid>/maps` — every region, none missing (re-checked) |
| `patch dry-run` | Live memory | `/proc/<pid>/mem` before and after — the current bytes it reports are the ELF's, and memory is unchanged |
| `patch apply` | Live memory | the target's own execution — patched a function to `return 59` and the value it publishes froze at 59 |
| `patch list` | Live memory | the record on disk, read by another program |
| `patch show` | Live memory | the record on disk — and the status it flipped to `undone` after the undo |
| `patch undo` | Live memory | `/proc/<pid>/mem` — restored byte-for-byte to the ELF's original, and the target resumed counting by seven |
| `patch detour` | Live memory | **Windows only** — refuses on Linux saying so; measured on Windows in the earlier pass |
| `selection save` | Live memory | the store on disk, read by another program |
| `selection list` | Live memory | the store on disk, read by another program |
| `selection show` | Live memory | the store on disk, read by another program |
| `selection clear` | Live memory | the store on disk — empty after, not merely reported empty |
| `dump save` | Live memory | the file it names, read by another program |
| `dump list` | Live memory | the dump store's own directory listing |
| `dump show` | Live memory | the file on disk — same bytes |
| `dump rm` | Live memory | the directory listing after — the file is gone |
| `debug await-hit` | Live memory | DWARF for the address, and the argument register at the hit carries a value the target published |
| `debug watch` | Live memory | `objdump` + DWARF — the trap lands one instruction past the store, and a register holds the address the target printed |
| `debug attach` | Live memory | the kernel — a pid it may not trace is refused with the errno, not claimed |
| `scan value` | Live memory | the address the target printed for that variable (re-checked) |
| `scan filter` | Live memory | an independent write through `/proc/<pid>/mem` — `changed` kept exactly that address |
| `scan aob` | Live memory | the address the target printed (re-checked) |
| `scan pointer-path` | Live memory | the address the target printed for its pointer slot — the first path is that slot, dereferenced once |
| `scan dissect` | Live memory | a layout known from its own source — 1 of 6 fields right, 5 of 6 after the alignment fix |
| `scan group` | Live memory | the address the target printed — one hit, at the right two offsets |
| `table add` | Live memory | the entry store on disk, holding the address the target printed |
| `table list` | Live memory | the entry store on disk |
| `table show` | Live memory | the entry store on disk |
| `table rm` | Live memory | the table after — the entry is gone, not merely reported gone |
| `table freeze` | Live memory | **Windows only** — refuses on Linux saying so; measured on Windows in the earlier pass |
| `stack backtrace` | Other | `eu-stack` — six frames, same addresses in order |
| `aot symbols` | Other | known C# source, and 2 128 of 2 128 RVAs against an independent unwind reader |
| `serve` | Other | the CLI's own answer to the same four queries |
| `warp dump` | Other | the fixture's own bytes — 100 names, both directions *(command removed 2026-09-11 with the WARP plugin; the row records a past measurement, not a present command)* |
| `plugin add` | Provenance, annotations & snapshots | the registry, and the plugin actually spawned |
| `plugin list` | Provenance, annotations & snapshots | what was registered |
| `plugin rm` | Provenance, annotations & snapshots | the registry shrinking back |
| `provenance trace` | Provenance, annotations & snapshots | `objdump` + DWARF — it named the instruction *after* the writer; fixed and re-measured |
| `annotate name` | Provenance, annotations & snapshots | the rendered signature |
| `annotate type` | Provenance, annotations & snapshots | the stored note, read back |
| `annotate comment` | Provenance, annotations & snapshots | the rendered output |
| `annotate var` | Provenance, annotations & snapshots | the renamed local in the body |
| `annotate vartype` | Provenance, annotations & snapshots | DWARF field names in the body |
| `annotate bookmark` | Provenance, annotations & snapshots | the stored record |
| `annotate show` | Provenance, annotations & snapshots | what was written |
| `annotate list` | Provenance, annotations & snapshots | the count before and after |
| `annotate rm` | Provenance, annotations & snapshots | the store |
| `snapshot dump` | Provenance, annotations & snapshots | a live process — byte-identical over the whole capture |
| `snapshot info` | Provenance, annotations & snapshots | the modules `/proc` lists |
| `snapshot list` | Provenance, annotations & snapshots | the file on disk |
| `game grep` | Spec-first method tooling | `grep -o` — every per-term count |
| `locate by-transition` | Spec-first method tooling | the address the target printed for the value it changes |
| `input probe` | Spec-first method tooling | **Windows only** — refuses on Linux saying so; measured on Windows in the earlier pass |
| `const identify` | Spec-first method tooling | the published definition of each constant |
| `bindings list` | Spec-first method tooling | the symbol table — 4 of 4 name/address pairs |
| `sig validate` | Spec-first method tooling | a known invariant set, and both refusal reasons |
| `sig gen` | Spec-first method tooling | `nm` on the unstripped binary — 10 of 10 names correct in a stripped copy |
| `module list` | Static analysis & decompilation | the file's own header (base, size, path) |
| `disasm` | Static analysis & decompilation | objdump — 1 200 instructions, every address and length |
| `ir build` | Static analysis & decompilation | objdump's decode + the compiler's DWARF extents |
| `ir explain` | Static analysis & decompilation | the frame and callsites of a function of known source |
| `ir dot` | Static analysis & decompilation | the graph `ir build` reports — same blocks, same edges, three functions |
| `ir slice` | Static analysis & decompilation | the source: both calls and the three moves that compute the value |
| `ir manifest` | Static analysis & decompilation | per-function metrics over a known image; ranks the names an imported index supplies |
| `ir value-set` | Static analysis & decompilation | objdump — every set it states is the immediate the code loads |
| `ir deobfuscate` | Static analysis & decompilation | hand-assembled junk and an opaque predicate; both named with their reason |
| `function discover` | Static analysis & decompilation | the image's own `.pdata` read in Python, and DWARF — 61 of 61, exact extents |
| `function trace` | Static analysis & decompilation | the call graph the source declares |
| `function noreturn` | Static analysis & decompilation | objdump — 181 of 181 contain no `ret` |
| `function summary` | Static analysis & decompilation | DWARF — 10 of 14 arities, 13 of 14 return-presences |
| `function typeflow` | Static analysis & decompilation | the symbol table — 4 exact class names, 1 base class, 2 unnamed, 0 wrong |
| `function layout` | Static analysis & decompilation | DWARF — 4 field offsets of 4, 4 sizes of 4 |
| `function eh` | Static analysis & decompilation | an independent Python unwind reader — identical set on five images |
| `decomp pseudo` | Static analysis & decompilation | the source, and a second decompiler over 200 functions |
| `xref to` | Static analysis & decompilation | objdump — 1 444 of 1 444 call targets on PE, 400 of 400 on ELF |
| `xref from` | Static analysis & decompilation | objdump, at instruction level |
| `xref string` | Static analysis & decompilation | objdump — four literals at the exact `lea` sites the source predicts |
| `rtti scan` | Static analysis & decompilation | the image's own type-descriptor strings — 97 of 97, none invented |
| `analyze` | Static analysis & decompilation | the counts every other reader gives for the same image |
| `find` | Static analysis & decompilation | the byte offsets computed in Python and DWARF |
| `type struct` | Static analysis & decompilation | DWARF — seven fields round-trip and reach the rendered body |
| `type enum` | Static analysis & decompilation | the source's four members round-trip |
| `type list` | Static analysis & decompilation | what was stored |
| `type rm` | Static analysis & decompilation | the store, before and after |
| `diff functions` | Static analysis & decompilation | two builds differing in one function — exactly that one differs |
| `ui locate` | UI-layer localization | a planted element of known geometry, and a rect that must not match |
| `ui windows` | UI-layer localization | the display itself — taskbar 60px at 125% scaling |
| `ui screenshot` | UI-layer localization | the window's own client rect, and the image opened and looked at |
| `ui focus` | UI-layer localization | `GetForegroundWindow()` in the interactive session |

`aot symbols` sits under *Other* in the command catalogue and under static
analysis in the goal that drove this pass; it is one command either way.

**A command that was measured and found defective is measured.** The two kinds
below are not the same kind of row, and putting them in one table invited the
reading that they were: the first lists **commands** against this goal's
condition, the second lists **defects those measurements found**. A defect with
no fix yet does not make its command unverified — finding it is what verifying
the command did.

Commands, against the condition:

| command | measured | status |
| --- | --- | --- |
| `bundle repack` | no | **not checkable here** — needs a real engine archive to write into; writing one by hand would test the reader against the writer |
| `il2cpp obj`, `il2cpp classes` | no | **not checkable here** — need a running IL2CPP runtime; the structures they walk are the runtime's own |
| `function typeflow`, `function layout` | **yes** | measured against DWARF and the symbol table on a C++ target of known layout — see below |
| the 31 live-memory commands | **yes** | all re-run against a live process built for the purpose, with `/proc/<pid>/mem`, `objdump` and DWARF as the readers. Three of the 31 are Windows-only and refuse on Linux saying so. Two defects found — `scan dissect`'s alignment and, next to them, `provenance trace`'s off-by-one instruction — both fixed |

**`function typeflow` and `function layout`, measured.** A C++ target compiled
with known classes, DWARF for the layout and the symbol table for which method
belongs to which class:

- `function layout` reports Widget's fields at **+8, +12, +16** and Panel's at
  **+32**, with sizes 32, 32, 64 and 32 bits. DWARF says `w@8`, `h@12`, `id@16`,
  `border@32`, with exactly those widths — **4 offsets of 4 and 4 sizes of 4**.
  Signedness is 2 of 3. `scale@24` is absent because no method in the source
  reads it, and the command reports observations; the extents it gives (24, 36
  against the declared 32, 40) are the observed span, not the declared size.
- `function typeflow` names the class on 7 methods: **4 exactly, 1 with the
  correct base class** (`Panel::area` typed as `Widget *`, which it is at offset
  0), and **2 as an unnamed struct** — `Widget::grow` and `Widget::set_id`,
  which touch a field and nothing else, so no evidence ties them to a name.
  **0 wrong names.**

Defects those measurements found:

| defect | measured | status |
| --- | --- | --- |
| stack pointer rendered as a statement | 103 of 200 | **fixed** — 0 across five targets; the one line that remains is a genuine `alloca`, which `objdump` confirms and which must stay |
| branch arm with nothing in it | 20 of 200 | **fixed** — 0 across five targets; the short-circuit fold skipped the cleanup the other path had |
| branch with *both* arms empty | 4 of 200 | **fixed** — 0 across five targets; a decision with no consequence either way is dropped, and the statement count is unchanged |
| a `float`/`double` return returns the wrong value | 7 of 12 on a known target | **fixed** — 12 of 12 on that target on both ABIs; 10 of 10 confirmed and 0 contradicted on a third-party DLL; on a Qt build, against the shipped headers, **117 right and 3 wrong** of 15 472 functions. The three are GCC cold-partition splits, where the value's only readers live in `.text.unlikely` over edges the CFG does not carry — a different defect. 54 more are two-component float aggregates, now reported as such (`ret_registers`) instead of named by one half |
| `&(…)` around a `lea` result | yes | **open**: a `lea` result is a number here, not an address |
| injected argument slots at call sites | yes | **open**: Rung 4's call-site agreement, already recorded |
| 478 functions absent from the function list | yes, 77.2% coverage | **fixed — 478 → 3**, coverage 99.9%. Three rules, each measured before it was written: a direct `call` target is a function (+47); the first real instruction after a declared end is the next function (+209); then sweep the rest of the gap linearly (+230). 228 of the last 230 are confirmed and none is interior to a known function. The stated cause was wrong and measuring said so — only 53 of the 478 were branch targets at all |
| 1 794 claim-shaped sentences unread | 15 adjudicated | **open**: only the comparative class is finished (15 of 15, no violation) |

Where the 60 sat, and where they stand:

| category | unoracled before | after this pass |
| --- | --- | --- |
| Static analysis & decompilation | 21 of 28 | **0** |
| Provenance, annotations & snapshots | 15 of 16 | **0** |
| Game-engine assets | 6 of 9 | **1** — `bundle repack`, recorded with its reason |
| Spec-first method tooling (Phase 8) | 6 of 7 | **0** |
| Environment & project | 4 of 9 | **0** |
| IL2CPP managed layer | 4 of 6 | **2** — `obj` and `classes`, recorded with their reason |
| UI-layer localization | 2 of 4 | **0** |
| Other | 2 of 4 | **0** |

The second column is where this stands after the measurements recorded below.
It is a count of commands that have been *asked* a question with a checkable
answer — not a claim that each is correct. Two of the answers are recorded as
wrong (`decomp pseudo` on a float return, `function summary`'s pass-through
arity), one is absent (`function discover` could not see an imported IL2CPP
index), and twelve defects found this way are fixed:

1. a PE carrying `.eh_frame` was not read as a PE, so `.pdata` extents were lost;
2. `discover_pdata` read a PE32 at the PE32+ data-directory offset;
3. a `RUNTIME_FUNCTION` ending before it began was reported as a function;
4. `--pdata` on an image with no exception directory answered `0 functions`
   instead of saying it was the wrong question;
5. `function noreturn`'s default `--limit 0` asked for no functions at all;
6. `ir slice` did not treat a call as defining the value it returned;
7. and once it did, the slice followed the stack pointer into the prologue;
8. the LuaJIT `GCstr` offset was a per-build constant with no way to give it, so
   `lua table` returned `null` for every string and `lua combo` found no arrays;
9. `lua table` reported its payload under `lua strings`' schema;
10. `aot symbols` discarded each module's real rejection reason;
11. `locate by-transition` refused to run outside Windows for a reason that was
    not true of its own body;
12. `function discover` did not attach the IL2CPP index every other consumer of
    the same names attaches.

Two claims inside the code were corrected rather than fixed, because there was
nothing to fix: five doc comments attributed automatic plugin dispatch to a
`PluginHost` type that does not exist, and `--handles` did not say it is
declarative.

**And "unoracled" is not "probably fine".** The sixteenth provenance command —
`provenance trace`, the one the README leads with — was asked of a live target
for the first time twenty minutes after that question, and did not deliver its
front-page output: the containing function of a leaf with no prologue could not
be recovered, so the statement that moved the value was missing, with no field
saying why. Fixed above. Every category in that table is the same kind of
unexamined.

**What "ready" would require**, in order of what the evidence says costs most:

1. An oracle for the remaining 60, or an explicit "not verified" per command.
   The two that matter most are the decompiler's semantics (28 static commands
   currently checked only for well-formedness, never for meaning) and the
   annotation/snapshot round-trip.
2. Emulation as the Class 1 oracle — the only thing that catches a lift that
   assigns the right registers with the wrong values.
3. The claim audit finished. A first pass extracted 471 claim-shaped sentences
   across twelve documents and adjudicated roughly forty of them, chosen
   because they carried a number or an absolute. **That number is no longer
   reproducible**: the extractor was a scratch script and did not survive the
   session, so what counted as a claim is not recorded anywhere. A second
   extractor, written to a stated rule — a sentence carrying a number, an
   absolute, a capability verb or a comparative — finds 1 794 across eleven
   documents, 1 269 of them in this file, which is a log of past measurements
   rather than a promise to a reader. The two numbers are not a before and an
   after; they are two different questions, and only the second one has its
   question written down.

   One class is adjudicated in full: the fifteen comparative sentences. None
   compares this tool to another tool — every one of them compares a design to
   an earlier version of itself, to a gap, or to a hypothesis. The policy in
   `docs/PRODUCT_POLICY.md` holds across the documentation.
4. `ui locate` against a live target; `il2cpp import`/`symbols`/`obj`/`classes`
   against a dumped index and a live managed process.
5. Someone other than its author driving the JSON contract.

The defect rate is the argument. This pass fixed **15 defects**, and every one
of them was found by pointing an oracle at something for the first time — never
by a test that already existed, never by reading the code. The parts with no
oracle have no reason to be different in kind from the parts that had one.

#### Closing the 60: static analysis, against a compiled-from-source target (2026-09-08)

The oracle for this category is a target whose answers are known before n0xis is
asked: a C file compiled with `gcc`/`mingw` at a known optimization level, where
the independent sources are the compiler's own DWARF (extents, signatures,
struct offsets, enum values), the image's `.pdata` table read directly, and
`objdump`'s disassembly. Fourteen functions, three struct layouts and one enum,
built as PE32+, PE32 and ELF.

Pointing it at `function discover` — the front door for every later command —
found three defects in the first measurement:

| what was measured | before | after |
| --- | --- | --- |
| `function discover`, mingw PE32+, against the image's own table | 10 of 61, one of them not a function | **61 of 61, none invented** |
| the same, against the 14 functions DWARF names | 0 of 14 | **14 of 14, exact extents** |
| `function eh`, mingw-built runtime DLL | 273 of 4 270 | **4 270 of 4 270** |
| `function discover --pdata`, PE32 with no exception directory | 50 fabricated entries, the first ending before it began | **a refusal that names the reason** |

1. **A PE was not read as a PE when it also carried `.eh_frame`.** Every
   GCC-family toolchain emits both tables into a PE, so this covered Wine's
   whole DLL set, this project's own Windows build, and every mingw target
   used to test it. Asking `.eh_frame` first dropped the authoritative `.pdata`
   extents — 0 of 61 on one build, 273 of 4 270 on another, 87 of 1 750 on a
   third — and `DiscoverPass` reads its declared extents from there, which is
   why the front door's recall was 15% and why a prologue match two bytes
   inside a real function passed as a function of its own. There were two
   readers; there is now one, and `.eh_frame` still contributes the protected
   ranges `.pdata` does not describe.
2. **`discover_pdata` read a PE32 at the PE32+ data-directory offset.** The
   same defect class already fixed in `profile.rs`, missed here: 96 vs 112. The
   bytes 16 further on belong to the section table and parse as an RVA and a
   size like any others, so a 32-bit image with no exception directory at all
   answered with 50 functions instead of refusing.
3. **A `RUNTIME_FUNCTION` whose end preceded its start became a function.**
   `scan_pdata` rejected those; this second reader did not.

An empty answer here now carries its reason: `--pdata` on a PE32 says that an
x64 unwind table is a PE32+ structure, rather than reporting `0 functions` as
though that were a finding.

Each fix is calibrated: reverting it fails the exact assertion. Two of the
calibrations first caught defects in the *test* — a synthetic PE whose
`.eh_frame` name was silently truncated to eight characters, and a COFF
`PointerToSymbolTable` written into the timestamp field — both of which made
the test pass against the unfixed code.

#### What the same oracle says about the rest of the category (2026-09-08)

Five more of the twenty-one now have an answer checked against something that
is not n0xis.

**`xref to` — verified.** Every direct call target in three mingw-built system
DLLs and the ground-truth build, compared against `objdump`'s independent
decode of the same bytes: **1 444 of 1 444 call-target sets agree exactly**, 0
call sites missing, 0 extra. On an ELF (a Qt library), 400 of 400. The
comparator is calibrated: asking it about `addr + 1` drops agreement to 0 of 5.

The single disagreement was adjudicated by a third source and resolved in the
tool's favour: at one address `objdump`'s linear sweep decoded an `e8` byte as
a `call` while it is the low byte of an entry in a table of RVAs sitting inside
`.text` (the neighbouring dwords are `0x20ad0`, `0x20aec`, `0x20afc`). An
oracle's disagreement is a question, not a verdict.

**`xref string` — verified.** Four string literals whose referencing function
is known from the source: each is found at the right address, with exactly the
`lea` sites `objdump` records, inside the function that the source says loads
it.

**`xref from` is an instruction-level query, not a function-level one.** Asked
at a function's entry it answers 0 even when the function makes twelve calls,
because the entry instruction references nothing; asked at the call
instruction it answers correctly. That is what it does, but `xref to` is what
answers "who calls this".

**`function noreturn` — one defect fixed, then verified.**

Its `--limit` is documented as "`0` = every function, which is the default",
and in the `.pdata` branch that 0 was passed to `take`, which asked for none.
The whole-program analysis therefore **refused to run at all** on every x64 PE
— `no-functions` on an image whose table holds 3 988. The prologue-scan branch
below it already handled the case. Fixed and calibrated.

With it running, the answers are sound. Of 181 functions reported non-returning
in one runtime DLL, **not one contains a `ret` anywhere in its declared
extent** per `objdump`. The metric discriminates: of 300 functions *not*
reported, 87% contain one.

Its measured limit: a direct call to an **import thunk** is not seen. A thunk
(`jmp [rip+disp]`) carries no unwind info, so it is not in `.pdata`, so it is
not a node in the fixpoint — and a mingw executable reaches `abort` through
exactly such a thunk. On that build the answer is an honest but empty `[]`.
Recorded as a gap, not fixed: closing it needs call targets to become nodes of
their own, which is a change to what the pass considers, not a bug in what it
proves.

#### The decoder and the signatures, against the same oracle (2026-09-08)

**`disasm` — verified.** 1 200 instructions decoded across two images and
compared against `objdump`'s independent decode: **1 200 of 1 200 agree on the
address and on the length**, and every mnemonic difference is an AT&T spelling
of the same instruction (`movzb`/`movzx`, `xchg %ax,%ax` for the two-byte nop,
a `data16`-prefixed nop). Length is the load-bearing field — a decoder that
disagrees about where the next instruction starts desynchronises everything
after it, and these two never do.

The first run of that comparison reported six length disagreements. All six
were **the comparator's** fault: `objdump` wraps a long byte sequence onto a
second line, so an eight-byte `mov dword ptr [rsp+0x40], 0x2a` was read as
seven. `--insn-width=16` fixed the reader, not the tool. That is also the
calibration: the comparison demonstrably reports differences on this data when
there are differences to report.

**`function summary` — measured, with a known limit.** Against the compiler's
own DWARF on fourteen functions of known source: **10 of 14 arities and 13 of
14 return-presences agree**.

The four that do not are one thing, and it is already written down in the code
that produces them: a parameter forwarded straight through to a callee has no
use outside a call's argument list, and a bare argument there cannot be told
apart from the four register slots the lift injects at every call. Two of them
(`middle`, `top`) pass their only argument to two callees and touch it nowhere
else. A third (`die_hard`) does the same. The fourth is a `main` whose `argv`
the compiled code never reads — DWARF counts two parameters because the source
declares two, and one is the honest answer about the binary.

That under-count leaves a contradiction a reader can see with no oracle at all:
**8 of 61 functions render a signature saying `(void)` above a body that reads
`rcx.0`.**

**An attempt to close it was measured and reverted.** The rule tried was "a
register whose entry version reaches a call site as a live argument is an
incoming parameter". Simulated against the ground truth first, it looked
decisive — 10 of 14 to 13 of 14 with no over-count. Implemented, it made the
result *worse*: `main` went to four parameters against DWARF's two, and the two
functions it was built for stayed at zero. The simulation had been run over the
**rendered text**, which is a trimmed view, while the implementation ran over
the raw SSA — so it never measured the change that was then made. Reverted
rather than kept for plausibility. Closing this properly needs whole-program
call-site agreement, which is Rung 4 and is not built.

`report`, a `void` function, is reported as returning a value: it ends in a
call to `printf`, so `eax` is live at the `ret` and nothing in the binary says
the caller ignores it.

#### The decompiler returns the wrong value for a function that returns a float (2026-09-08)

This is the first defect found by asking the decompiler what a function
*means* rather than whether its shape is well-formed, and it is the largest one
in this pass.

**`crates/n0xis-arch/src/x64_lift.rs`, the `Ret` arm: the return value is
modelled as `rax`, unconditionally.** A function that returns a `float` or a
`double` returns it in `xmm0`. That definition is then read by nothing, so
dead-code elimination removes the instruction that produced it, and the
returned expression is whatever happened to be in `rax`.

What it does to a function whose source is known — `double
node_weight_of_next(const struct Node *n)`, which returns `n->next->weight` or
`0.0`:

```
uint64_t sub_140001600(struct_rcx_0 *rcx) {
    if ((rcx != 0x0)) {
        v1 = rcx->field_0x18;
        if ((v1 == 0x0)) {
        } else {
        }
    }
    return v1;
}
```

`field_0x18` is `next` and is correct. Everything else is gone: the `movsd
xmm0,[rax+20h]` that loads the weight, the `pxor` that produces the zero, and
both branch bodies. The value returned is the `next` pointer.

The same on a real, exported, named function — `QImage::devicePixelRatio()
const`, which returns a `qreal`:

```
QImage::devicePixelRatio() const {
    rax.1 = rdi->field_0x10;
    if ((rax.1 == 0x0)) {
        return rax.1;
    } else {
        return rax.1;
    }
}
```

Both arms of the branch return the same expression, which is the visible tell,
and what they return is the private `d` pointer rather than the ratio. Both
`vmovsd` instructions are absent.

The decode is not at fault: `ir build` shows `movsd xmm0,[rax+20h]` present,
reading `rax` and writing `zmm0`. The CFG is right, the field offsets are
right, the class name is right. Only the answer is wrong.

**Population, as a lower bound:** in one Qt library, 99 sites write `xmm0`
immediately before a `ret` (7 106 named functions). Sites that set the value
further from the return — as both examples above do on one of their paths — are
not counted, so the true number is higher.

**Not fixed here, and why.** The fix is not a patch to that line: the lift sees
one instruction and cannot know the callee's return type. A correct model
either learns the return register from a recovered signature or picks, at each
return, the candidate register whose reaching definition is *dead* — a value
computed on the way to a `ret` and read by nothing is what a return value looks
like, and that rule distinguishes both examples correctly (`rax` there is
defined *and* read, as an address base and as a null test). That is a change to
the semantics of every decompiled function and needs the whole corpus
re-measured behind it, not a one-line edit. Recorded as measured and open.

`classlayout.rs` already carries a comment about a method that "returns a
`qreal` in `xmm0` and merely leaves `d` in `rax`" — the pattern was known in one
place and never propagated to the return model.

#### `rtti scan`, `xref`, `disasm`: what the image's own tables say (2026-09-08)

**`rtti scan` — verified, and its scope measured.** On a genuine
Microsoft-built C++ runtime DLL it recovers **97 vtables, and every one of the
97 mangled names is present verbatim in the image's own bytes** — nothing
invented. The seven type-descriptor strings it does *not* pair with a vtable
are `messages_base`, `money_base`, `_Iosb<int>`, `_Crt_new_delete`,
`_Ref_count_base` and two `Concurrency` interfaces: tag structs with no virtual
functions and pure interfaces whose vtables live in another module. There is no
vtable in this image for them to find.

On a **GCC-built** PE reimplementing the same runtime it reports zero, though
the image carries 91 type-descriptor strings. The reason: those descriptors are
in `.data` there, and the scan reads `.rdata`, which is where MSVC puts them.
The command's own help says `.rdata`, so this is scope rather than a wrong
answer — but it is the same shape as the `.eh_frame`/`.pdata` defect above: an
MSVC assumption applied to a GCC-built PE, answering zero with nothing to say
why. Recorded, not fixed.

#### `ir slice` did not name the call that computed the value (2026-09-08)

Asked "what computes this value" about a function whose source is
`middle(v) + leaf_a(v)`, the backward slice answered with three register moves
and **neither call**.

The cause is one fact nobody had written down: a `call` architecturally writes
only `rsp`, and that is what `Arch::reg_access` reports, because whether `rax`
changes is an ABI property of the *callee* and not of the instruction. Def-use
analysis needs the ABI fact — without it the definition of the value a call
produced does not exist, so the chain stops at the `mov` that copied it out of
the return register.

Fixed where the ABI is known: the IR builder, which already reads
`source.abi_name()`, now records a call as defining that convention's return
register. The convention is picked by the same rule the lift uses, so the two
cannot disagree about where a return value lands.

That immediately exposed a second thing, in the way this pass keeps finding:
following the new edge pulled `push rsi`, `push rbx` and `sub rsp,0x28` into
the answer, because every call reads the stack pointer. The stack pointer is
plumbing, not data. `Arch` now names it (`stack_pointer()`, default none), and
a data slice does not follow it — while a slice *of* the stack pointer still
reaches `sub rsp,0x28`.

| slice of the result of `middle(v) + leaf_a(v)` | nodes |
| --- | --- |
| before | 3 — the register moves, neither call |
| the call fix alone | 8 — both calls, and the whole prologue |
| both | **5 — both calls and the three moves, which is the function** |

`node_sum`, whose value comes from three loads and no call, is unchanged at 3.

**Still open, and measured:** the seed is chosen by *address* — "the nearest
writer of `reg` at an address `<= at`" — not by control flow. On a `main` whose
last address-ordered writer of `rax` is a call in a `noreturn` error path that
no return can reach, that is the instruction the slice starts from. The def-use
edges are also intra-block only, so a slice never crosses a basic-block
boundary. Both need reaching definitions across the CFG, which this does not
build.

#### Types, annotations and `diff`: the round-trip, end to end (2026-09-08)

Thirteen more commands answered against something that is not n0xis — the
compiler's DWARF for the layout, and the source for what the code means.

**The type layer carries a user's assertion all the way into the output.**
`struct Node`'s seven fields, at the offsets DWARF states, were declared,
read back byte-identical, and bound to a parameter. The decompiler's answer
changed from

```
return ((rcx->field_0xc + rcx->field_0x8) + *rcx);
```

to

```
return ((rcx->pos_y + rcx->pos_x) + rcx->tag);
```

which is `n->pos.x + n->pos.y + n->tag`, the source, with every offset mapped to
the right field — including the `+0` that had rendered as a bare dereference.

Verified this way: `type struct`, `type list`, `type rm` (true when the name is
there, false when it is not), `annotate vartype`, `annotate name` and `annotate
var` (both reach the rendered signature and body), `annotate comment`,
`annotate show`, `annotate list`, `annotate rm`, and `project info`, which says
plainly that the store in use is the global one and not a local project.

`type enum` round-trips its four members, and binding it names the parameter
`Kind` — but the constants in the body stay `0x9`/`0x2a`/`0x7` rather than
becoming `KIND_BRANCH`/`KIND_ROOT`/`KIND_LEAF`. That is not an overclaim: Rung
3 already lists **enums** as not done.

**`diff functions` — verified, 13 of 13.** Two builds of the same source, one
function changed (`a * 3` → `a * 7`). Comparing every function across the pair,
exactly one body differs, and it is that one; the change is rendered through
the compiler's strength reduction (`rcx + rcx*2` becomes `rcx*8 - rcx`), which
is what those two multiplications compile to.

The first reading of that experiment said eleven of thirteen had changed. That
was the measurement's fault, not the tool's: the rendered text carries a
synthesised `sub_<address>` name and a `// 0x<address>` block comment, and
every function after the edit shifted by five bytes. The bodies were identical.
Worth knowing for anyone diffing across a rebuild — two hunks per function are
address noise — but the comparison itself is exact.

**`classify` is decompiled correctly through branchless codegen.** A five-case
switch compiled into `sete`/`movzx`/`lea` arithmetic comes back as `rcx == 9 →
2`, `rcx > 9 → (rcx == 42) * 3`, else `-1` and `(rcx == 7)` — the source's
semantics, recovered from code that contains none of its shape.

#### The rest of the static-analysis category (2026-09-08)

**`find`** — a known string is reported at `0x140004050`, the address both
`objdump` and `xref string` give for it; a six-byte pattern is reported at
`0x140001588`, which is exactly where DWARF says `add_scaled` begins. One match
each, correct section.

**`function trace`** — from `top`, the recovered call graph is `top → middle,
leaf_a` and `middle → leaf_a, leaf_b`, with the leaves calling nothing. The
source is `top(v) = middle(v) + leaf_a(v)` and `middle(v) = leaf_a(v) +
leaf_b(v)`.

**`module list`** — base, size, name and path all match the file.

**`ir dot`** — describes the same graph `ir build` reports: blocks and edges
agree exactly on three functions of 7, 5 and 3 blocks. (This one checks the
renderer against the CFG; the CFG itself is checked against `objdump` above.)

**`ir value-set` — sound.** On a function that clamps to `[10, 200]` it reports
exactly `200` and `10`, and everything downstream of the unknown argument as
`top`. On the switch it reports `-1` and `2`, the two returns loaded as
immediates. Every set it states is right; a constant that appears only as an
instruction operand is not an SSA variable and is correctly not one of its
answers.

**`ir deobfuscate` — calibrated and correct.** On compiler output it reports no
junk and no opaque branch, which is the truth there. Given a blob with `xchg
eax,eax`, `mov eax,eax` and a `jne` after `xor eax,eax; test eax,eax`, it names
both junk instructions with their reasons and lengths, and reports the branch
at `0x9` as resolving to constant false with the dead target at `0xc`.

**`function typeflow` / `function layout`** — both run whole-program and report
evidence rather than assertion: on a C image with no classes, zero; on a C++
image with RTTI, class extents and per-field observations carrying
`access_count` and `methods`. The shape is honest by construction; the field
offsets themselves are not checked against a published header here, and that
is the remaining gap for these two.

With this, the twenty-eight commands of **Static analysis & decompilation** have
been asked a question with an answer, apart from `aot symbols`, which needs a
NativeAOT binary this machine does not have.

#### Environment, engine, signatures, plugins, snapshots — and NativeAOT (2026-09-08)

**Environment & project — 9 of 9.** `doctor`'s claims check out against the
machine and the manifest; `profile`'s machine, module base, section count and
section VAs match `objdump` and the raw header on both PE32 and PE32+;
`process ps` never misses a process `/proc` has (the one extra it reported each
run was the harness's own short-lived helper, which n0xis saw and the harness
did not); `init` creates exactly what it says it created and the project then
resolves locally; `capability run` returns data byte-identical to the CLI
command on five capabilities; and `remote-serve` returns byte-identical bytes
to a local read — `7f 45 4c 46` at the mapped base, which the kernel guarantees.

`profile` reports the raw eight-byte section names, so a GCC-built PE shows
`/4` and `/14` where `objdump` shows `.eh_frame` and `.debug_info`. That is not
laziness: a long name lives in the COFF string table, which sits past every
section and is **not part of the mapped image**, so resolving it for `--file`
would make `--file` and `--pid` disagree about the same binary. Recorded rather
than changed.

**Other — 4 of 4.** `stack backtrace` agrees with `eu-stack` frame for frame:
six frames, same addresses in the same order, correct module attribution and
RVAs, and the chain `main → sleep` the source predicts. It reports
`libc.so.6+0x1026cb` where `eu-stack` says `clock_nanosleep` — it does not
resolve dynamic symbols, which is a naming gap, not a wrong answer. `serve`
answers four queries identically to the one-shot CLI after its ready banner.
`warp dump` reported 100 functions where the file holds 100 names, the two sets
equal in both directions, every GUID a valid version-5 UUID, no duplicates — a
measurement taken while the WARP layer lived in this repo; it moved out on
2026-09-11 and the command no longer exists here.

**`aot symbols` — verified, on a NativeAOT binary built for the purpose.** A
Windows PE published from known C# source: it recovers `String
N0xisOracle.Widget.Describe(N0xisOracle.Widget)`, `Int32
N0xisOracle.Program.Compute(System.Int32)` and `Int32
N0xisOracle.Program.Main(System.String[])` — namespace, class, method, return
type and signature all exactly as written. `Widget.Scaled` is absent because
the compiler inlined it; the name is not in the image at all. Of 2 128 methods
it reports, **400 of 400 sampled RVAs land exactly on a function start the
image's own `.pdata` table declares.**

Its limit, now measured rather than assumed: the reader parses PE modules. On a
Linux NativeAOT ELF whose bytes demonstrably carry the `RTR\0` header and the
managed type names, `--file` refuses ("not a PE image") and `--pid` used to say
"no NativeAOT stack-trace metadata found in any module" — which is not what was
wrong. Each module's real rejection reason is now carried into the answer.

**Signatures — `sig gen` and `sig validate` verified.** Signatures learned from
a symbolized ELF and applied to a stripped copy of it named 10 functions, and
**all 10 match the original symbol table**, with none wrong. Signatures learned
from an unrelated program named nothing. `sig validate` reports the invariant
byte set exactly on a known input, blesses only with three samples *and* a named
varied axis, and refuses with the specific reason otherwise.

**`game grep` and `const identify`.** `game grep`'s per-term counts match
`grep -o` exactly on a directory built for it, and the file with none of the
vocabulary is correctly unmatched. `const identify` is sound where it answers —
CRC-32's reversed polynomial and the golden ratio come back with the right role,
formula and note — and its table is 44 entries aimed at RNG and hashing; the
fast-inverse-sqrt magic and the MD5/SHA init words are outside it and are not
recognised.

**LuaJIT — 4 verified, 2 defects fixed.** Recorded above under the GCstr layout.

**Plugins — 3 of 3, and one claim corrected.** `plugin add` → the plugin appears
in `capability list` as `plugin.oracle` with a `plugin` origin → `capability run
plugin.oracle` spawns it, hands it exactly the artifact JSON on stdin, and
returns its findings → `plugin rm` removes it and the registry shrinks back.

What does **not** happen is automatic dispatch. `--handles` is a required
argument, is stored, and is rendered into the capability's summary — and no code
path selects a plugin by the schema it handles. Five doc comments in four crates
attributed that dispatch to `n0xis-pipeline::PluginHost`; **no such type exists
anywhere in the workspace.** The comments now describe what is there, and
`--handles` says in its own help that it is declarative.

**Snapshots — 3 of 3.** A snapshot of a live process reads back byte-identical
to the live process over the whole captured range, and its module list matches
the process. `snapshot info` and `snapshot list` report the file and the modules
that are actually there.

**One rendering defect, seen while checking `add_scaled`.** `a * 3 + b * 5`
renders as `&(rcx + (rcx * 0x2)) + &(rdx + (rdx * 0x4))`. The `&` is the `lea`
form leaking into the output: `lea` computes an address *expression*, but its
result here is an integer, and rendering it as an address-of makes ordinary
arithmetic read as pointer arithmetic. Recorded, not fixed.

#### `locate by-transition` refused to run on the wrong grounds (2026-09-08)

It answered `live-unsupported`: "requires a Windows build (needs
LiveProcess/Win32 APIs)". Its body touches neither. Every step is `ScanPass`
and `FilterPass` over a `Ctx`, both platform-neutral in the core, and
`resolve_scan_regions_live` already takes `&dyn LiveTarget`. What was
Win32-specific was one line — `LiveProcess::attach` instead of the platform
seam every other live command goes through — and the CLI's `#[cfg(windows)]`
import of the scan types, whose own comment called the list "an inventory of
what remains".

Routed through the seam, it works, and it is right. Against a target that
prints the address of the one value it changes and holds two decoys still:

```
watched=0x404030 steady_a=0x404034 steady_b=0x404038
→ 87 040 candidates, 4 survive "increased": 0x404030 = 1004, and three libc
  and stack counters that also went up
→ with --min 1000 --max 1100: exactly one survivor, 0x404030
```

Neither decoy survives. This is the command's whole purpose — localize the
value behind a change — and it had never been asked to do it.

`ui locate`, `patch detour`'s trampoline and `table freeze` are still behind
that import; the comment now says so with them named, rather than listing
commands that no longer belong to it.

#### The UI layer, on a real Windows desktop (2026-09-08)

All four, executed on Windows 11 against live windows. Reaching them needed one
thing worth writing down: **an SSH session is not on the desktop.** It runs in a
different session with its own window station, where `explorer.exe` has zero
windows and .NET reports a 1024×768 screen that does not exist. Every
measurement below ran through a `schtasks /it` task in the interactive session.

**`ui windows` — verified.** For `explorer.exe`: 44 windows, among them `Progman`
"Program Manager" at `[0,0,1920,1080]` and `Shell_TrayWnd` at `[0,1020,1920,1080]`.
Independently: the video controller reports 1920×1080, and a Windows 11 taskbar
at 125% scaling (the reported `dpi: 120`) is 48 × 1.25 = **60** physical pixels
tall, which is exactly `1080 − 1020`. For Notepad: the main window's three rects
nest as Win32 defines them — `rect_window` ⊃ `rect_frame` ⊃ `rect_client`, the
outer one wider by the DWM shadow — and the title matches the document open in it.

Asked from the SSH session about a process on the desktop, it answers `count: 0`
with an empty list. That is true of the window station it can see and useless to
the caller, and nothing in the answer says which session it looked at.

**`ui screenshot` — verified, by looking at it.** Captured Notepad's window:
1424×732, which is exactly its `rect_client` `[41,33,1465,765]`; a file whose
first bytes are `89 50 4E 47 0D 0A 1A 0A`; and, opened, a correct picture of
that window with the title bar the `ui windows` query had named. It also
measures its own capture rather than asserting success — `blank: false`,
`mean_luma: 241.6`, `frac_exact_black: 0.4%`, verdict `ok`.

**`ui focus` — verified against the OS.** Before: the interactive session's
`GetForegroundWindow()` returned 328874. n0xis focused pid 13784 and reported
`foreground: true, hwnd: 1836090`. After: `GetForegroundWindow()` returned
**1836090**.

**`ui locate` — verified, and this is its first run against a live target.**
Against a process holding one planted element in the layout the scanner reads
(seven contiguous `f32`: `min.xyz`, `max.xyz`, `radius`) plus two decoys
elsewhere:

- a query rect inside the element ranks it first — `min [300,200,0]`, `max
  [500,260,0]`, `radius 120`, the planted values exactly, at the address the
  documented `element_base = hit − 0xa4` arithmetic predicts;
- a query rect away from it does not return it;
- neither decoy appears.

The one other hit in both queries is a seven-float window straddling two of the
arrays, with 1/100th the overlap area — the ambient false positive the
`--save-as`/`--exclude-from` spatial diff exists to remove. Its `min_x_offset`
is fixed at the calibrated Bitsquid-bundle value and has no flag, the same shape
as the LuaJIT layout above.

#### The IL2CPP managed layer, and the front door that could not see it (2026-09-08)

**`il2cpp import` — verified on all three of its branches.** Against a dump
written for the purpose, whose method addresses are real function starts in a
known PE:

| the dump says | what it decided |
| --- | --- |
| absolute VAs | `absolute-va`, 5 of 5 land in `.text`, accepted, confidence 1.0 |
| the same methods as RVAs | `rva+base`, 5 of 5, accepted |
| addresses in neither space | **refused** — "only 0.0% of 5 sampled method addresses land inside `.text` (rva 0 vs va 0)" |

That is exactly what its help promises — both spaces tried against `.text`, a
mismatch refused rather than applied — and it had never been asked.

**`il2cpp symbols` — verified.** All five methods come back with the names,
addresses and signatures that went in. Asked for the symbol owning an address
two bytes *inside* one of them, it answers with the containing method.

**And the front door could not see any of it.** With an index imported,
`decomp pseudo`, `ir manifest` and `function summary` all render the C# name —
and **`function discover`, in both of its modes, rendered `sub_`** for the same
addresses. The reason is structural: `attach_for` is called from the capability
registry, and `function discover` is one of the commands still implemented
directly in the CLI, so it never asked for the index. `il2cpp_caps`'s own doc
names the failure it was built to prevent — "a user stares at unnamed pseudo-C
wondering why the import they just ran did nothing" — and this is that, in the
one command a user runs first.

Both discovery paths now attach the same index, and all four front doors agree:
5 of 61 named. With no index in the project nothing changes — 0 on that binary,
and the same 1 152 export names on a runtime DLL as before.

**`il2cpp obj` and `il2cpp classes` — not checked, and why.** Both read a live
managed heap: an `Il2CppObject`'s class pointer and the class list a running
IL2CPP runtime holds. That needs a running IL2CPP game, which this
machine does not have and which cannot be synthesized — the structures they
walk are the runtime's own, not a file format one can write by hand. They are
the two commands in this pass with no oracle available rather than none applied.

**`bundle repack` — not checked, and why.** It replaces one variant's bytes
inside an engine archive and recompresses. `bundle list` and `bundle extract`
have an oracle; `repack` needs a real archive to write back into, and there is
no fixture in the tree and no sample on this machine. Writing one by hand would
test the reader against the writer and nothing else.

#### What a second decompiler saw that the tests did not (2026-09-08)

Every check before this one compared n0xis against a source *I wrote* — a C
file with fourteen functions, a Lua script, a planted struct. That proves the
tool right about what I control. It cannot report what the tool is silent
about. So the same binaries were put through an **independent decompiler**
running headless, and the two outputs compared on facts neither has to be
trusted for.

**The oracle was calibrated first.** On the target with DWARF it agreed on 12
of 14 function extents — the two disagreements were one padding byte each — and
13 of 14 arities; the miss was a `main` where it recovered the ABI's third
argument and DWARF reports the source's two.

**Function boundaries, on a C++ runtime DLL of 2 094 functions.** 1 394 of
n0xis's 1 398 `.pdata` starts are confirmed. Where the extents differ, **n0xis
is never shorter** — 346 longer, 0 shorter — and the differences are one or two
bytes of padding, 16-byte alignment, or, in 59 cases, real code. A +37-byte
tail was put to `objdump`, which found a load, two calls and a full epilogue
ending in `ret`: an exception continuation reachable only through the unwinder,
which belongs to the function and which the other tool's CFG never reaches.
**On extents, the differential favours this tool.**

**Coverage, the other direction.** Either discovery mode finds 1 616 of the
2 094 — **77.2%**. The 478 it does not are dominated by stubs of 16 bytes or
less: `lea 0x60(%rdx),%rcx ; jmp …`, the adjustor thunks a vtable slot points
at. They carry no unwind info and open with no prologue, so neither mode can
see them. Measured, not assumed.

**Rendering, over 200 functions, counted on both sides:**

| | n0xis | the other |
| --- | --- | --- |
| a branch with **both** arms empty | 4 | 0 |
| a branch with **one** arm empty | 20 | 0 |
| the stack pointer rendered as a statement | **103** | 0 |

The last one is fixed here. `rsp.1 = (rsp.0 - 0x90)` is how a prologue is
spelled, not something the program does, and the frame is already reported on
its own line — it stood in the text of **half of all functions**. Dropped now,
and only when the displacement is constant: an `alloca` (`rsp.1 = rsp.0 -
rax.5`) is a real statement and still renders. 103 → 0, with the other two
counts unmoved.

The 20 one-armed branches are a readability defect, not a wrong answer: n0xis
emits `if (a == 0 || *a != 0) { } else { …body… }` where the other emits
`if (a != 0 && *a == 0) { …body… }` — the same logic, un-inverted. The 4 with
both arms empty are the dropped-statement defect already recorded under the
float return.

**And it sharpened that one.** Both tools decline to type a `double` return as
`double` — that limitation is shared, and the earlier record overstated it as
distinctive. What is not shared is the answer: the other returns `*(next +
0x20)`, the weight, with both arms populated; this one returns the `next`
pointer with both arms empty. The `&(…)` around a `lea` result and the injected
argument slots at call sites (`f(rcx.1, rdx.2, r8.1)` where one is real) appear
in this tool's output and not in the other's.

**Three of the measurements used to find this were wrong before they were
right** — two call counters that miscounted templated C++ names in a signature,
and an empty-arm detector that missed the very function it was written for. Each
was caught by running it against a case whose answer was known. That is the
argument for the method: a second implementation on the same bytes catches what
a self-written test does not, **including the errors in the self-written test**.

What it cannot catch is where both are wrong the same way — the `double` typing
is exactly that. Only execution decides those, which is still the unbuilt
Class 1 oracle.

#### What the differential did *not* find, which is also a result (2026-09-08)

Four further metrics were run against the same 200 functions and the same
second decompiler. Three found nothing, and saying so is part of the answer:

- **No call is lost.** Two counters said otherwise before they were fixed; both
  were miscounting templated C++ names in a signature. On 150 functions where
  `objdump` counts the calls, every one is rendered.
- **No `goto` is dangling.** A quick check reported a function jumping to a
  block it never defines; the check required a label line to end in `:` and the
  labels carry a trailing address comment. 0 dangling on both sides.
- **No memory store is dropped more often than the reference drops it.** The
  first version of that metric accused the *other* decompiler twice as often as
  this one, which is how it announced that it was the broken part: it counted
  register spills through the frame as stores. Narrowed to non-frame stores:
  7 here, 41 there — and the single most suspicious case turned out to be
  spills through a copy of `rsp`, which neither renders and both are right not
  to.

**One thing the differential shows in this tool's favour, beyond the extents.**
On a virtual-dispatch thunk ending in `jmp *%rax`, the other decompiler emits
`iVar1 = (*(code *)UNRECOVERED_JUMPTABLE)(this,param_1,param_2,param_3);`
under two warnings — inventing a call with four arguments where the code makes
a tail jump, inventing a return value, and typing the vtable slot as an
`_ExceptionHolder *` on no evidence. n0xis writes `// indirect jump
(unrecovered)` and stops. It is also less complete there: it drops the tail
call entirely rather than reporting that control leaves through the pointer it
just computed, and its signature claims one parameter where the mangled name
declares eight.

**The correction that matters most.** "Both arms of a branch empty" is a
*signature*, not a diagnosis. In the float-return case statements really are
gone. In the three others sampled here they are not: the arms are empty because
both paths continue to the same code, and the function's statements account for
its instructions. Only the first is a dropped-statement defect, and the earlier
entry should be read as covering that one case.

#### Closing the checks that were n0xis checking n0xis (2026-09-08)

Three of the checks recorded above compared one command against another
command of the same tool. A self-consistent tool cannot report what it is
silent about, so each was redone against something outside it.

**`function eh` — now verified, and it was the worst of the three.** It had
been "confirmed" against `function discover --pdata`: both are this tool
reading the same table. An independent reader of the PE unwind directory,
written in Python from the file's own bytes, gives the same answer on five
images — and not merely the same count, the **same set of (start, end) pairs**:

| image | entries | identical set |
| --- | --- | --- |
| a Microsoft C++ runtime DLL | 1 398 | yes, 0 extra, 0 missing |
| a mingw-built C runtime | 4 270 | yes |
| a mingw-built kernel shim | 1 750 | yes |
| the ground-truth build, `-O1` and `-O2` | 61 and 59 | yes |

**`aot symbols` — now verified against the same reader, on the whole set.** The
earlier check put 400 sampled RVAs against `.pdata` starts *this tool* had
read. Against the independent parser, and without sampling: **2 128 of 2 128**
method addresses land on a function start the file declares.

**Live memory, re-checked against the kernel rather than against the record.**
`mem map` reports 25 regions on a live process, all of them present in
`/proc/<pid>/maps`, none missing. `mem read` returns bytes identical to
`/proc/<pid>/mem`. `scan value --type i32 --value 4242` returns exactly one
hit, at the address the target itself printed for that variable; `scan aob`
over the bytes spanning two of its variables returns exactly one hit, at the
first of them.

**One correction to the admission itself.** `rtti scan` was listed among the
circular checks and is not: it was compared against the type-descriptor strings
present in the image's own bytes, parsed outside the tool. An attempt to
cross-check it against the independent decompiler's recovered class names
produced a meaningless zero overlap — the comparison split C++ names on `::`,
which cuts inside template arguments. Dropped rather than reported.

#### Where the eight open items stand (2026-09-08)

| # | item | state |
| --- | --- | --- |
| 1 | audit of every claim | ✅ four false numbers corrected, two overclaims reworded; `tests/docs_match_binary.rs` now fails the build when a document and the binary disagree |
| 2 | live memory, 31 commands | ✅ 29/31 measured against `/proc/<pid>/mem`, 0 wrong; the other 2 are Windows-only and say so |
| 3 | the Windows half | ✅ executed on Windows 11 — 21/23 measured, 0 wrong; 2 defects fixed |
| 4 | ARM64 | ✅ decoder and CFG verified to x64's standard; 2 defects fixed; the decompiler is still not built and says so |
| 5 | engine paths | ✅ IL2CPP, Bitsquid, LuaJIT and WARP each measured against a source that is not n0xis (WARP has since moved to its own repository, 2026-09-11); `il2cpp import`/`symbols`/`obj`/`classes` recorded as unmeasured, with the reason |
| 6 | emulation as the Class 1 oracle | ⬜ **not built.** A strictly weaker check was built instead (`effect_audit`, above) and says so |
| 7 | corpus breadth | ✅ six targets across four formats; the widening is what exposed the invented fall-through edge |
| 8 | 32-bit PE | ✅ 3 defects fixed, and 2 more the widened corpus then exposed |

Defects fixed in this pass: 12. Measurement defects of my own, each recorded
where it happened: 9.

#### A register name is a claim about the machine (2026-09-09)

The corpus had been widened to a 32-bit PE once before, for the *signature*
work. Widening it again — this time asking every command what it prints —
produced one object that states the defect on its own:

```json
{"text": "sub esp,0Ch", "reads": ["rsp"]}
```

One register, two names, adjacent fields. `function summary` answered
`clobbers: ["rax"]`, `ir value-set` reported sets for `rax`/`rcx`/`rdx`/`rsp`,
and `decomp pseudo` rendered `rax.1 = …` — for an i386 image, whose own
disassembly says `esp` on the same line.

The cause is a *deliberate* canonicalisation, which is why nothing caught it.
`normalize_reg` folds `al`/`ax`/`eax`/`rax` onto one identity so every join
sees one token; that identity is a 64-bit spelling. Right as an identity, false
as a claim.

The same shape was live on x86-64 all along, for the vector file: `ir build`
answered `"reads": ["zmm0"]` beside its own `"text": "addsd xmm0,xmm0"`, while
the ABI's volatile lists, `function summary`, `ir value-set`, the pseudocode
and every disassembly line say `xmm0`. Naming the whole physical register
rather than the width one instruction touched is the established rule here —
`mov al,1` has always recorded a write to `rax` — so this only settled *which*
of the three names that one register goes by.

Fixed as one table per target (`Arch::display_reg_map`) read at one boundary:
the response, after the analysis and before the JSON. The analyses keep the
canonical name because the backward slice matches a user's `--reg` against
exactly those strings. Doing it once for every capability is what makes the
affected set a measured property rather than a list someone maintains.

**Measured:** every one of the 114 commands run against a 32-bit PE — 0 names a
register the target has not got, against 4 commands before. On a real ELF, no
command emits `zmm` anywhere. x86-64 general-purpose output is unchanged.

#### `(void)` is a claim, and it was not true (2026-09-09)

In C, `f(void)` says the function takes no arguments; `f()` says nothing about
them. The renderer printed the first when it meant the second. On a
purpose-built 32-bit target with DWARF, **seven of ten functions were told they
take nothing while taking one to three arguments** — every caller-cleanup
(`cdecl`) function, where no argument register can be scanned and no `ret imm16`
states a size. `RecoveredSignature` now carries whether the count is a
measurement, and an unmeasured empty list renders `()`.

#### The convention knew where a float comes back, not where one goes in (2026-09-09)

`CallConv` gained `ret_float` in an earlier pass and stopped there. Parameter
recovery scans the argument registers a function reads at entry — the
**integer** ones — so a function whose parameters are floating-point read zero
of them and the signature said `(void)`. Not a 32-bit gap: measured on
purpose-built targets, `double f(double)`, `double f(double,double,double)`,
`float f(float,float)` and `double f(int,double)` — which does use `rdi` —
all reported no parameters **on both x86-64 ABIs**.

`float_args` and `float_args_share_position` are now convention data, because
the counting rule genuinely differs: Win64 assigns argument *position* to a
register in whichever file the type belongs to (`f(int,double)` → `rcx` and
`xmm1`, `xmm0` untouched), System V consumes the two files independently
(`f(int,double)` → `rdi` and `xmm0`). A parameter's width comes from the
operation that consumes it (`ss` → `float`, `sd` → `double`), and never from a
conversion, whose suffix names what the operand is *not*.

**Purpose-built oracles: 12 of 12 on both ABIs**, including both orders of a
mixed signature.

#### And then the measurement said the fix was a loss (2026-09-09)

Against 500 functions of a shared library, with arity taken from the Itanium
mangled names, the float-parameter work scored **worse**: exact 229 → 222,
over-counted 161 → 186. Diagnosing one case rather than guessing found the
real defect, which had been inflating integer arity all along:

**`collect_definite_param_regs` counted every phi input as a use.** A call
clobbers the ABI's volatile registers, so any function with a branch and a call
joins into `phi(xmm3.0, xmm3.1)` for a register nothing in it touched. Once the
floating-point argument registers were consulted at all, a destructor with no
vector instruction in its body claimed **eight `double` parameters**. A phi
input is evidence exactly when the phi's own result is used — iterated to a
fixpoint, because phis chain.

**Measured, before → after, against the mangled-name oracle:**

| image | exact | over-counted | under-counted |
| --- | --- | --- | --- |
| Qt6Gui (500) | 229 → **313** | 161 → **79** | 110 → 108 |
| Qt6Core (500, not tuned against) | 194 → **223** | 148 → **113** | 158 → 164 |
| Qt6Widgets (400, not tuned against) | 172 → **225** | 98 → **54** | 130 → 121 |

The truth column does not model a hidden `sret` pointer, so a function
returning a large object by value counts as one "over" it does not deserve;
the real agreement is higher than the table says.

**Also measured, and not a defect:** discovery on that 32-bit PE, against the
3 889 `.eh_frame` FDEs an independent parser reads out of it — **0 missed, all
3 889 extents exact, 0 entries interior to a known function.** The 254 entries
outside every FDE are functions the unwind table does not describe, not
inventions. The rule was tuned on x86-64 exception tables and holds on an
architecture with none.

#### One command, two implementations, three answers (2026-09-09)

`disasm` existed twice: the CLI carried its own source selection, architecture
choice, out-of-image check and comment attachment, while MCP and `serve` reach
the registry's `decode`. Measured on the same inputs, they disagreed three ways:

| question | CLI `disasm` | registry `decode` |
| --- | --- | --- |
| `--bytes` with an `--addr` | decodes | `decode-failed` |
| an address past the last section | `addr-out-of-image` + a hint | `decode-failed` |
| an address inside a data section | silent | flagged |
| a user's per-address comments | attached | absent |

A consumer written against one front door branches on an error code the other
never emits. Now one implementation: the CLI calls the capability, and the
capability gained the three behaviours it lacked. **48 of the CLI's 90 command
handlers still hold their own implementation, 16 of which open the source
themselves** — that is the size of the remaining surface, and every one of them
is this lottery until measured.

#### A code command now says when the bytes are not code (2026-09-09)

Asked about the middle of a PE's export directory, every code command answered
`ok: true` and none mentioned it: `decomp pseudo` returned
`void sub_100b9000()` with `quality: 0.67`, `function summary` reported a
complete clobber set, and the section table saying `READONLY, DATA` was in the
same file the whole time. An address arrives from a pointer, a vtable slot or an
arithmetic slip as often as from a function list.

A **note**, not a refusal — a packer puts real code in a data section and
unpacking is Phase 15 — and silent when the source declares no executable range
at all, because absence of knowledge is not evidence. Seven commands carry it.

#### The oracle corpus — `oracle/`, and why it is checked in (2026-09-09)

Every pass before this one built its measuring instruments in a scratch
directory and lost them; the same targets were rebuilt from nothing in three
separate sessions, which is the same work three times and a project that looks
tested while being unverified.

`oracle/` is the correction: three C sources whose function *names state their
own truth*, a hand-written `expect.json` (written from the C, never from a
tool's output — that is what makes it rung 1), and
`crates/n0xis-cli/tests/oracle_corpus.rs`, which builds what the local toolchain
allows and checks every claim. **Three shapes — ELF/SysV/x86-64, PE/Win64/
x86-64, PE32/i386 — because one shape of input buys one shape of blindness**,
and each of the three exposed something the others could not.

Two properties make it a check rather than decoration:

- **The corpus must describe itself.** A function in the `.c` with no entry in
  `expect.json` fails the build; so does the reverse.
- **A recorded gap must stay true in both directions.** A limitation listed
  under `known_open` is *expected* to disagree; if the tool starts agreeing, the
  test **fails** and says to remove the entry. A gap that quietly closes leaves
  the file lying about the tool, which is how a limitation rots into folklore.

Calibrated in both directions: lying about a truth fails on that truth's line,
and claiming a gap that is not open fails with `GAP CLOSED`.

**First run: 3 shapes, 30 functions. Both x86-64 shapes agree on every one —
arity, register file per parameter, and return class, including both orders of
a mixed integer/floating signature. The 12 disagreements are all i386, all
recorded with a reason: `cdecl` arity (the evidence is in the incoming stack
slots and is not read yet), the x87 return the lift does not model, and a
scratch write to the return register that no ABI distinguishes from a result.**

#### Two states where there are three (2026-09-09)

`RecoveredSignature::ret` was `Option<CType>`, and `None` carried both *returns
nothing* and *nothing here could tell*. The second shipped as the first: i386
hands a `double` back on the **x87 stack**, which this lift does not express at
all, so `eax` is never written and `double f(double)` was published as
returning `void` — a claim that the function produces no result, about one that
visibly computes one.

The separating rule is not an x87 special case: **when part of a function was
not modelled, an unwritten return register is not evidence of an absent return
value.** It is evidence of an incomplete model, and the answer is `Unknown`.

Making it a three-state type rather than adding a flag is the point, and the
compiler immediately named four other places that had collapsed the same two
facts. One was live: **`function summary` reported every function whose SSA or
type inference *failed* as returning nothing at all** — a pass that could not
run was publishing a measurement.

Wire-compatible: `null` still means a measured "nothing", a recovered type is
still the type, and only the new case is new (`{"unknown": true}`). The
signature line says `/*unknown*/`, the house placeholder, because C has no
notation for it and `void` is the wrong one.

**Measured:** 500 functions of an x86-64 shared library — 0 answers changed
(472 typed, 28 void, 0 unknown), so the rule does not fire where the model is
complete. 400 functions of a 32-bit PE — 0 report `void` while containing an
x87 instruction, so it does not miss the case it exists for either. In the
oracle corpus it fires on exactly the two functions that return on the x87
stack, and `i386_cdecl_v_v`, which genuinely returns nothing, still says `void`.

#### The function list had no names through the other front door (2026-09-09)

`function.discover` built its own `Ctx` instead of going through
`with_src_ctx`, which is what attaches the symbol chain — the image's exports, a
managed index, FLIRT matches, the user's own renames. Measured on a 32-bit
system DLL: **0 of 4 143 functions carried a name through the registry, against
1 152 through the CLI.** `ok: true`, and nothing to say a name was even
possible. On a shared library, 0 against 7 105 of 15 472.

Both doors now answer identically (4 143 / 1 152 and 15 472 / 7 105), and
`crates/n0xis-cli/tests/front_doors_agree.rs` is the guard: it asks the same
question through the CLI and through `capability run` and compares the payload.
Adding a pair is one row. Calibrated — reverting the fix makes it fail on the
count.

**Four capabilities still build their own `Ctx`** (`decode`, `pointer.path`,
`diff.functions`, `function.noreturn`) and **19 CLI handlers still resolve their
own source**, 13 of which have no capability at all — so they cannot be reached
through MCP or `serve` in the first place. That is the measured size of the
remaining surface, recorded rather than estimated.

#### The Process seam, made mechanical (2026-09-09)

The design says the CLI, the MCP server and `serve` are three front doors onto
one capability registry. Nothing enforced it, and two commands had drifted into
two implementations — each a question with two answers. Two guards now hold it:

- `tests/front_doors_agree.rs` — the **behavioural** half: ask the same
  question through the CLI and through `capability run`, compare the payload and
  the failure code. Four pairs; adding one is a row.
- `tests/every_command_has_one_implementation.rs` — the **structural** half: a
  CLI handler either goes through the registry or is named with the reason it
  cannot. The list may shrink and may not grow by accident, and an entry that
  goes stale fails too, so it stays a record of the codebase rather than
  folklore.

The count is printed on every run and bounded: **5 handlers cannot be
capabilities by their nature** (`serve` hosts the registry; `remote-serve` is
its far side; `snapshot dump` writes a file; the two debug waits are long-polls)
and **14 are analysis an agent still cannot reach**. The bound only moves down
without a reason.

Finding it also surfaced a detail worth keeping: a handler can be defined twice,
once per platform `cfg`, so any scan over the source must take the union of the
copies or it will read the wrong one and quietly stop looking.

#### `ok: true` with nothing in it, made a test (2026-09-09)

The twenty-line version of this sweep — run the operations whose answer is
certainly non-empty, flag every success with an empty payload — found two defect
classes in one run and was recorded as the highest defect-per-line ratio of
anything tried. It is `crates/n0xis-cli/tests/no_silent_empty_answer.rs` now:
**12 operations that cannot honestly be empty on the oracle's System V shape**,
whose contents are known, plus **4 recorded as legitimately empty with the
reason** — the honest half, without which the sweep would only cover what
happens to work.

Both detection paths are calibrated: an operation that answers `ok: true` with
an empty list fails, and so does one whose named field is missing from the
answer entirely.

**And a measurement that cleared the subject rather than accusing it:**
`function eh --addr` answering `count: 0` looked like exactly this defect. It is
not — that address has no FDE. Without `--addr`, the counts are **10 against
`objdump --dwarf=frames`' 10** on the oracle shape and **15 467 against 15 467**
on a real shared library. Exact, both times.

#### The context seam, held the same way (2026-09-09)

`with_src_ctx` / `with_cfg_ctx` are where a target becomes an analysis context —
source resolved once, architecture chosen from what the image declares, symbol
chain attached in precedence order. A capability that assembles a `Ctx` by hand
gets whichever parts its author remembered, and `function.discover` forgot the
symbols.

`crates/n0xis-frontend/tests/capabilities_share_one_context.rs` now requires a
capability to use the seam or be named with the reason it cannot. Writing it
found two things immediately:

- **Capabilities are registered from four modules, not one.** Scanning
  `registry.rs` alone saw 32 of 62 and would have quietly stopped looking at
  the rest — the same shape as the defects the guard exists for. The scan
  asserts its own yield for that reason.
- **Three more hand-built contexts**, all in the IL2CPP group. All three take
  their names from managed metadata rather than the binary's symbols, so the
  chain would likely add nothing — but for two of them **that has not been
  measured**, and the exemption says exactly that rather than claiming it.

Five guards now hold five defect classes, each calibrated in both directions —
reverting a fix fails the test on its own line, and a recorded gap that closes
fails it too:

| guard | class |
| --- | --- |
| `oracle_corpus.rs` + `oracle/` | an answer with no external source; one shape of input |
| `front_doors_agree.rs` | one command answering two ways |
| `every_command_has_one_implementation.rs` | that gap growing back |
| `capabilities_share_one_context.rs` | a capability with its own idea of the target |
| `no_silent_empty_answer.rs` | `ok: true` with nothing in it |
| `one_fact_one_place.rs` | one fact derived in more than one place |

#### The decoder itself had never been checked from outside (2026-09-09)

Every later answer stands on "these bytes are this instruction, and it is this
long". A decoder that desynchronises by one byte produces a plausible and
entirely wrong program, and **no test above it can tell** — the CFG, the SSA,
the types and the signatures all read the same wrong stream and agree with each
other. It had been verified only that way.

`crates/n0xis-cli/tests/decoder_agrees_with_objdump.rs` compares against an
independent disassembler on the one property that is syntax-free and where a
desync is immediately visible: the **instruction boundaries**. Two decoders that
agree on every `(address, length)` pair over a range are reading the same
program, whatever they call the instructions. Text is deliberately not
compared — `sub esp,0Ch` and `sub esp,0xc` are the same instruction, and
chasing formatting would turn a real check into a cosmetic one.

**Measured, all with zero disagreements and zero boundaries either side had
alone:** the three oracle shapes exact (3 037 instructions in the checked-in
test), **20 000 instructions of a shared library**, and **20 000 of a 32-bit
system DLL**.

Three parsing traps, each of which made the check silently pass on nothing
before it was caught, are documented in the test because each will recur:
`objdump`'s output is **localized** (`LC_ALL=C` is mandatory); a long
instruction's bytes **wrap onto a continuation line** with no mnemonic, so
counting the first line reports 7 bytes for a 10-byte instruction; and the
address column is **not indented** when the addresses are already 8 hex digits,
so a regex expecting whitespace parses zero instructions from a PE32.

#### ARM64 had three hand-written encodings, and now has LLVM (2026-09-09)

The AArch64 decoder's only verification was `arm64_exit.rs` — three encodings
typed in by hand. That proves the ISA seam holds (a second architecture runs
through the core unchanged) and says nothing about reading real compiler output.
The project's own notes were right to say "implemented and self-tested".

`oracle/arm64.c` compiled at `-O2` by `clang --target=aarch64-linux-gnu`, read
back by `llvm-objdump --triple=aarch64`: **147 instructions covering
floating-point and SIMD, integer division, both conversion directions, a counted
loop, a switch, bit-manipulation intrinsics, sub-word loads and stores, a
conditional select, an atomic read-modify-write and a call. 147 shared
addresses, none on either side alone, and 0 failures to decode.**

Fixed-width encodings make boundaries vacuous, so the comparison is the
mnemonic. All 28 name differences are **architecture aliases** — `mov`/`orr`,
`cmp`/`subs`, `mul`/`madd`, `b.hs`/`b.cs` — listed pair by pair in the test with
why each is the same instruction, because a check that forgave every difference
would forgive a real one.

**One real defect fell out of it.** The mnemonic came from the decoder's
*definition*, which names the encoding family (`b.c`), while the text resolved
the condition — so one decoded instruction carried `mnemonic: "b.c"` beside
`text: "b.ne 0x44"`. Two fields of one object, two answers, the same class as
the register-naming split. The mnemonic is now the first word of the text, so
they agree by construction; the instruction *class* still comes from the
definition, which is a question about the encoding and rightly asked of it.

This does not make the AArch64 decompiler exist. The lift and SSA are still not
built and still say so.

#### Function extents, checked against the image instead of against ourselves (2026-09-09)

Everything function-scoped inherits the extent: a wrong one gives the CFG extra
blocks or truncates it, and every answer built on that is confidently wrong
about a function that does not exist. It had been checked by comparing one
n0xis command with another — a contract check wearing the clothes of a
correctness check, which the notes had already flagged.

`crates/n0xis-cli/tests/function_boundaries_match_the_image.rs` uses two
independent sources answering two different questions:

- **`objdump --dwarf=frames`** — every FDE's `start..end`, compared as a *set*,
  not a count (a systematic off-by-one satisfies a count). **3 787 extents on
  this machine — the oracle shape's 10 plus libc's 3 777 — start and end
  exact.** Separately measured at 15 467 and 14 355 on two large libraries,
  also exact.
- **`nm -D`** — the linker's own export list. Every entry inside the scanned
  window must be in the function list: **10 of 10 and 2 323 of 2 323, none
  missed.**

Both arms run twice: once on the purpose-built shape, which proves the rule,
and once on a system C library, which proves it at a size where an off-by-one
has somewhere to hide. No library, no second arm, and it says so.

**And the second arm found a defect on its first run.** `sweep_declared_gaps`
computed `va - lo` on unsigned addresses before checking that `va` was inside
the scanned window — and a declared function *can* end before the window
starts, because the table describes the whole image while `bytes` is one
section. Release wraps the subtraction and the walk crawls one byte at a time
from a nonsense offset up to the window: the right answer, arrived at slowly.
**Debug panics outright**, so anyone building from source hit it on a real C
library. The gap is now clipped to what was actually read.

That is the shape worth remembering: the release build was *correct and slow*,
so nothing noticed, and only a debug build over a real image said anything.

#### And the decoder at browser scale (2026-09-09)

60 000 instructions of a 334 MB stripped browser binary against `objdump`: **2
length disagreements and 3 boundaries the reference held alone, every one of
them inside a stretch where the reference itself decodes `(bad)`** — an ASCII
string embedded in `.text`, read as `outs`/`ins`/`jo` by both. Not code, and
neither reading is the right one. No disagreement anywhere in the actual code.

#### `rtti scan` answered "no classes" for a whole dialect (2026-09-09)

Found by sweeping every runnable command in a **debug** build — where overflow
checks are on — against four real images, and then asking why one answer was
empty. `rtti scan` returned 0 for a 32-bit C++ runtime whose strings carry **95
MSVC type descriptors**. `ok: true`, an empty list, and nothing to suggest the
question had been asked in the wrong dialect.

Two independent causes, both of them "written for 64-bit, applied to both":

1. **The structures are different.** 32-bit locators use 4-byte slots and
   **absolute VAs**; 64-bit uses 8-byte slots and image-relative **RVAs**, is
   24 bytes rather than 20, carries a `pSelf` self-reference the 32-bit form
   does not have, and puts the type descriptor's name at `+16` rather than
   `+8`. The scanner stepped 8 bytes through 4-byte slots and rebased absolute
   pointers.
2. **The vtable is not always in `.rdata`.** That is an MSVC-toolchain habit,
   not a property of PE — a mingw-built image puts them in `.data`, with the
   locator a section away. The scan now takes a *list* of data ranges and
   resolves a locator through the source rather than out of the range being
   walked, because the two need not be in the same section.

**Measured: 0 → 93 vtables on that runtime, every recovered name present in the
image's own strings (no invented classes), and the 64-bit answers unchanged** —
97 and 152 on two other runtimes, 269 through the Itanium path on an ELF. The
93-against-91-distinct-names gap is multiple inheritance, where one class has
two vtables.

**No compiler on this machine emits MSVC RTTI** — mingw emits Itanium — so the
regression fixtures are *planted*: `oracle/rtti32.c` and `oracle/rtti64.S` lay
both dialects out by hand. That is the highest rung there is: the answer is
known because it was written, not inferred from a build. The 64-bit one is
assembler because C cannot express an image-relative RVA in a static
initializer; GNU as has `.rva` for exactly this.

Calibrated on both halves: forcing the scanner back to 64-bit loses the planted
32-bit class, and restricting the ranges back to `.rdata` returns the runtime to
0.

#### The sweep that found it, and what it is worth (2026-09-09)

Every command the guide lists, invoked with arguments built from the guide's own
schema, run in a **debug** build against four real images. Overflow checks are
on there, so arithmetic that silently wraps in release becomes a panic.

**59 of 114 commands ran** (the rest either mutate something — skipped on
purpose — or need a live process); **0 panics** across all four targets. The
detector is calibrated: reverting the `sweep_declared_gaps` fix makes it report
the panic again.

The first version of that sweep passed `--file` and `--addr` to everything and
would have reported "0 panics across 114 commands". **97 of them had rejected
the arguments and run nothing.** The number to state is what actually executed.

#### The panic sweep, made permanent (2026-09-09)

A debug build has overflow checks; a release build wraps. Arithmetic that wraps
is not a crash and not a visible wrong answer — it is a quiet detour, which is
exactly why `sweep_declared_gaps` went unnoticed for as long as it did.

`crates/n0xis-cli/tests/no_command_panics_on_a_real_image.rs` drives every
command the guide lists, with arguments built from the guide's own schema,
against both the purpose-built shape and a system C library. It runs in the
debug build by construction — it invokes the binary `cargo test` just built —
so the checks are on. **104 command runs across two targets, no panic**, in
about twelve seconds.

**The purpose-built shape alone is not enough, and this was measured rather than
assumed.** Reverting the fix leaves the oracle shape passing and makes the
system library panic: a fixture proves the rule, a real binary has the awkward
shape. With no system library present the test says what it could not check.

Mutating verbs are skipped **by name**, in a reviewable list, rather than by
guessing from the output — and an argument with no plausible value skips the
command instead of inventing one, because an invented argument tests the
argument parser rather than the analysis.

#### The error surface, read once (2026-09-09)

The same sweep's failures were read rather than counted. All thirteen name what
was looked for and why it was not found: `aot-failed` says "no NativeAOT
ReadyToRunHeader"; `bundle-load-failed` names the reserved field that
disqualified the layout; `no-metadata` prints the path it searched beside;
`klass-failed` says the address is neither a managed object nor a class and
gives the reason; `live-unsupported` says which build it needs. That is the
contract the tool claims, and it had never been read end to end.

#### "Who calls this?" against a disassembler that is not ours (2026-09-09)

The first question a user asks, and it had been verified only against other
n0xis commands. A cross-reference index is wrong in two directions and each
looks fine alone: a missed caller quietly narrows the answer, an invented one
sends the reader where nothing happens. Both are now asserted against `objdump`.

**4 733 references across the six busiest targets of a system C library — 139 to
601 each — none missed and none invented.**

Getting there took widening the *measurement* twice, both times because it was
narrower than the tool:

- counting only `call` flagged **37 tail-call `jmp`s as invented**; the answer
  had labelled every one `kind: "jmp"`;
- and then two `lea rdx,[rip+disp]` sites, which `objdump` prints as a trailing
  `# <hex>` comment rather than an operand. The answer labelled those
  `kind: "data"`.

Both were the tool being more complete than the check. That is the usual
direction, and it is why the first instinct on a wall of disagreement should be
to re-read the reference.

#### The call graph, against the same outside source (2026-09-09)

`xref from`, `function trace`, the noreturn fixpoint and every call the
decompiler renders read the CFG's `callsites`. A dropped call silently shortens
the graph; an invented one adds an edge to a function that never runs.

**304 call sites across 100 functions of a system C library — 0 missed and 0
invented.** It needs two independent sources, because the question has two
halves: `objdump --dwarf=frames` decides where the function *ends*, and
`objdump -d` decides which instructions in that range leave it.

The reference had to be corrected three times before it matched, each time in
the tool's favour:

- using `objdump`'s **symbol headers** as function ranges produced 89 phantom
  "extra" calls — a symbol boundary and a real extent are different things;
- counting only `call` produced 120 more, every one a real **tail call** already
  labelled `kind: "tail"` in the answer;
- and one last one, a **conditional** branch leaving the function, which is a
  tail call too.

Nothing about the tool changed across those three rounds. That is worth writing
down: on this kind of check the first suspect is the reference, and it was the
reference three times out of three.

#### And the body of a decompiled function, in the one way it can be checked

Full behavioural equivalence is not available without an emulator (ROADMAP
Phase — emulation as a Class 1 oracle, still not built). One property is:
**every call the disassembly shows must appear in the rendered body**, and the
pseudocode names them, so the check is the call-graph one above rather than a
string search. An attempt to grep the body for target *addresses* reported 48 of
60 functions "missing" calls — the body names them `fileno_unlocked`, `dup`,
`fdopen`, and the measurement had simply asked the wrong question.

### What an outside source verifies, layer by layer (2026-09-09)

The project's own note said 54 of 114 commands had an oracle and 60 had only a
contract check — and that the 54 had been taken from an earlier document **on
trust and never re-measured**. This is the re-measurement, written by layer
rather than by command, because a layer is what an external source can actually
answer about.

| layer | what settles it, from outside | state |
| --- | --- | --- |
| instruction decoding, x86 | `objdump -d` boundaries | ✅ 3 shapes + 40 000 instructions of two real images + 60 000 of a browser, 0 disagreements |
| instruction decoding, AArch64 | `llvm-objdump --triple=aarch64` mnemonics | ✅ 147 instructions, 0 failures, every name difference a documented alias |
| function extents | `objdump --dwarf=frames` FDE `start..end` | ✅ 3 787 compared as a set, exact |
| function discovery | `nm -D` exports; FDE starts | ✅ 2 333 exports, 0 missed; 3 889 FDE starts on a 32-bit PE, 0 missed |
| basic blocks | `objdump` branch targets | ✅ 464 targets, every one a block start |
| call graph | `objdump` calls + tail calls, within the FDE extent | ✅ 304 sites, 0 missed, 0 invented |
| cross-references | `objdump` branches + RIP-relative comments | ✅ 4 733, 0 missed, 0 invented |
| recovered signatures | targets compiled here, answer known first | ✅ 12/12 on both x86-64 ABIs; the 32-bit gaps recorded with reasons |
| MSVC RTTI | planted structures + the image's own strings | ✅ both dialects, 0 invented names |
| live memory, patch, undo | `/proc/<pid>/mem`, `/proc/<pid>/maps` | ✅ 29 of 31 commands, byte for byte |
| argument errors, envelope shape | the contract itself | ✅ every failure is one envelope with a code |
| **SSA and the optimizer** | the **processor**, running the same function on the same inputs | ✅ 1 920 comparisons over four optimization levels, 0 disagreements — and the SSA form and the optimized form agree with each other, which is what says the optimizer preserves meaning rather than merely being self-consistent |
| **the decompiled body's arithmetic** | the **processor** | ✅ 3 840 — 52 wrong answers on the first run, every one a dropped operand width, and one more found later by adding a **second compiler**: clang compiles `if ((int32_t)a & (int32_t)b) < 0` as `test edi, esi; … cmovns`, where gcc uses `and %esi,%edi; js`. The sign of a *computed* narrow value is bit 31 of the `and`, and the rule that reads a narrow operand as signed only looked at the root of the expression, which in gcc's shape is a cast and in clang's is the `and` itself. Four optimization levels of one compiler never showed it |
| **calls — direct, PLT, indirect, recursive, stack arguments** | the **processor**, running the callee too | ✅ 1 280 comparisons over two compilers and four optimization levels, 1 616 callee frames executed, 0 disagreements. Three optimizer defects found doing it: DCE and expr-prop each removed the frame allocation (`sub rsp, N` reads as dead when locals are addressed off the frame pointer, and its single "use" is the flags the `sub` also writes), and expr-prop inlined the call-clobber marker into a use, throwing away the register's name |
| **scalar floating point** | the **processor** | ✅ 4 096 comparisons over two compilers and four optimization levels, 0 disagreements — arithmetic, the NaN and signed-zero rules of `minsd`/`maxsd`, conversions, and eleven branch shapes. `cvtsi2sd` had been reading its integer source zero-extended; a `jcc` after `ucomisd` had **no condition at all**; and constant folding took the operation's width from its left operand, so `mov eax, 0x1ff; shl rax, 53` folded to **zero** |
| **Wine as a stand-in for Windows** | **real Windows**, on a different CPU | ✅ 3 968 of 3 968 byte-identical. The Win64 numbers below were all taken under Wine, which is an implementation and not a processor, and nobody had checked. Same binaries (SHA-256 verified on both sides), same inputs, run natively on Windows 11 / Ryzen 5 3500U over ssh and under Wine on Ryzen 5 1600: zero differences, including all 2 048 floating-point cases. The comparator was calibrated by mutating one line and confirming it reported exactly that line. **Not** verified, and stated as such: MXCSR and the x87 control word were never read on either side |
| **PE / Win64, end to end** | the **processor**, under Wine | ✅ 3 968 comparisons: the same two corpora built by mingw as DLLs, run as a Windows `.exe`, compared against what n0xis recovers from the PE. Everything measured before this was an ELF. It found a refusal that had outlived its reason — an 8- or 16-bit register destination left a condition unreconstructed, on the grounds that a byte read used to widen to the whole register, which it has not done since the operand-width work |
| **switch / jump-table dispatch** | the **processor** | ✅ 768 comparisons over two compilers and four optimization levels, 0 disagreements — and the check is two-sided: every case returns a distinct constant, *and* every indirect jump the emulator follows must land on an address the CFG already recorded as an edge. Until now the resolver's only tests compared it against itself. Three defects, two of them silently missing control flow — see below |
| **packed SIMD** | the **processor** | ✅ 2 560 comparisons over two compilers and four optimization levels, 0 disagreements. The emulator's word is 128 bits now; scalar arithmetic still narrows to 64 at every `Binary` but the bitwise ones, so seventeen thousand existing comparisons are the control group for the widening. Every corpus function folds **both halves** of its result into one integer, so a defect in the upper lane is as visible as one in the lower. It found a memory-operand default that read every unnamed size as eight bytes — see below |
| **calls on Win64** | — | ⬜ **not measured, and why.** `oracle/emu_calls.c` reaches a callee defined in the driver executable, which on Windows needs an import library the corpus does not have. The leaf and floating-point corpora do run there; the call corpus does not |
| **32-bit code (i386 and PE32)** | the **processor** | ✅ 3 888 comparisons over three targets — ELF32 by gcc, ELF32 by clang, **PE32 by mingw under Wine** — and four optimization levels, 0 disagreements — and it started at **zero**, because the IR carried no widths at all on a 32-bit target. `reg_read`/`reg_write` decided whether to state an operand's width by asking whether it filled its *container*, which is the same question as "is it 64 bits" only in 64-bit mode: there `eax` **is** the container, so `add eax, ebx` lifted to `rax = rax + rbx`. Eleven defects, four of which are 64-bit defects that a 32-bit corpus happened to reach first — see below |
| **a carry after an addition** | — | ⬜ **refused, and named.** The IR records an arithmetic op's flags as `Compare { Result, sum, 0 }` — two slots — from which the zero and sign conditions reconstruct exactly and the carry ones cannot: `CF` after `add a, b` is `sum <u a`, and `a` is no longer in the record. So `jb`/`jae`/`sbb` after an `add` come back as *no condition*: a refusal, not a wrong answer. `oracle/emu32.c`'s `emu32_carry` — the standard unsigned-overflow idiom — keeps it measured at 96 of 2 688. Closing it needs a flags model with room for both operands, which is an IR change |
| **AArch64 register identity** | `ir slice` against the machine's own code | ✅ fixed 2026-09-10, and it was the project's *own* canonical defect one architecture over. `w0` and `x0` are one register; the def-use records named them by the `sf` bit, so `ir slice --reg x0` answered `node_count: 0` on `emu_add32`, whose entire body is `add w0, w0, w1` — a statement that nothing computes the function's return value, on the register that is both the first argument and the result. C's `int` is 32 bits, so that is most of what any compiler emits. Records are canonical now (64-bit spelling, as x86 has always done), `Arch::normalize_reg` folds `w`→`x`, the SIMD views `b/h/s/d/q`→`v`, and `lr`/`fp`. Three existing tests asserted the 32-bit spelling and so held the defect in place; the guard that was missing — *the same operation at two widths names one register* — is now there |
| **ARM64 semantics** | — | ⬜ **there is no lift to verify.** `Arch::lift` is not overridden for AArch64: every instruction becomes `MicroStmt::Unlifted`, which the source says plainly ("a documented follow-on, not a silent gap"). So this is a *build*, not a verification — and as of 2026-09-10 it can be built against a processor from the first instruction: `qemu-user-static` and the `aarch64-linux-gnu` cross toolchain are installed, and an aarch64 binary compiled here runs here. The earlier entry called this "refused for want of a processor"; the want was one `pacman -S` | The decoder is checked against LLVM on 147 instructions; the *lift* is checked by nothing, because rung 1 here means executing the code and this machine cannot. `clang --target=aarch64-linux-gnu` produces the objects; `qemu-user-static` is in the distribution's repository and is **not installed**, and the ARM device on this network is a 32-bit Android userspace. One `pacman -S qemu-user-static` closes it, and until someone runs it the honest entry is this sentence |
| recovered struct fields | `gcc -g` / DWARF member offsets | ✅ 15 across 10 functions, 0 invented |
| recovered **locals** | DWARF `DW_OP_fbreg` against `DW_OP_call_frame_cfa`, compared as **addresses** | ✅ 65 of 65 declared stack objects touched at exactly the stated address, across `-O0`/`-O1`/`-O2`. The earlier refusal stands as written — it was the *displacement* comparison that was unsound, and this one has no displacements in it |
| **`function typeflow`'s call graph** | `objdump`'s direct calls, `nm`'s symbols | ✅ every edge the disassembly shows is walked. It saw **1 of 3** before: a call whose result the optimizer folds into its consumer stops being a `Call` statement and becomes a `Call` expression, and the pass read only the first shape |
| **what `typeflow` then propagates** | — | ⬜ measured as **zero** on four purpose-built targets, and *not explained*. See below |
| **IL2CPP** | `global-metadata.dat`'s own header and tables | ✅ three builds, format versions **24, 29 and 31**: version, table layout, literal count and 1 000 literal **values** byte for byte, plus a query's match count. The earlier entry said "no target on this machine"; there were three |
| **the JSON contract, by anyone else** | — | ⬜ **recorded as unmeasurable here, not skipped.** Every call of every command in this project has been made by its author or by an agent the author is driving; there is no second party on this machine to be surprised by a field name, a missing envelope or an answer that reads as success. That is a property of the setting, not a gap a test can close, and the honest entry is this sentence rather than a number |

#### The processor as the oracle (2026-09-09)

Three of those layers had no outside source and could not get one by the method
the other eleven used. A second disassembler does not settle SSA, an optimizer or
recovered arithmetic — it guesses too. The question is not what another tool
thinks, it is what the machine does.

`oracle/emu.c` holds leaf functions; `oracle/emu_run.c` dlopens the compiled
library and calls each on planted inputs, printing what came back. That is rung
1, produced by hardware with no tool in the path. `n0xis-core::emulate` executes
the same function's recovered micro-IR on the same inputs, and the numbers are
compared.

The emulator is deliberately **naive**: it implements what the IR says and never
re-derives what the IR failed to record. A helpful emulator hides the defects it
exists to find. Where the IR is silent it reports *which* construct is missing,
and that is a result — a gap, countable, and distinct from a wrong number.

| run | agree | disagree | not modelled |
| --- | --- | --- | --- |
| first, `-O2` only | 108 | **52** | 40 |
| after the width seam | 240 | 0 | 0 |
| four optimization levels | **1 920** | **0** | **0** |

The 52 were one root cause: every register operand was widened to its container,
so the IR said `rax` where the instruction said `eax`. `mov eax,ecx` claimed to
copy 64 bits; `mov %sil,%al` — a one-byte merge — decompiled as `return rsi`,
wrong by a factor of sixteen million on the first input the CPU was asked about.
All at `quality: 1.0`. Five more classes followed from the same instrument:
unmasked shift counts, signed predicates reading zero-extended operands, `adc`/
`sbb` dropping the carry, a flag-marker resolver that matched only at an
expression's root, and `push`/`pop` moving nothing at all.

**The reference was wrong three times here too**, and each is recorded in the
commit that fixed it: two emulator defects and one in the test's own DWARF
parser, each of which first looked like a defect in the IR.

**The pattern worth keeping:** every layer above was verified by finding a
source that answers *one* question that layer claims to answer, not by finding
a tool that does the same job. `objdump` cannot recover a signature and `nm`
cannot build a CFG — but each answers exactly one thing exactly, and a stack of
narrow exact answers is worth more than one broad approximate one.

**And on this pass the reference was wrong more often than the tool.** Three
times in the call-graph check alone, six times in parsing, and three times a
*calibration* silently failed to apply — which would have reported a test as
calibrated when nothing had been mutated. Every mutation now asserts that it
happened and lands on what the test actually reads.

#### A check that was refused, and why (2026-09-09)

Recovered **locals** looked easy to verify the same way the fields were: every
`local_XX` should correspond to a stack access the disassembly shows. The
measurement ran clean — **782 locals across 80 functions, 781 matched** — and it
was thrown away, because the one that did not match explained why the other 781
were meaningless.

The tool normalizes every stack slot to **one frame base**, the entry `rsp`.
`objdump` prints the displacement **from `rsp` at that instruction**, which
moves with every `push` and every `sub rsp`. The same slot is `[rsp+0x8]` in one
place and `rsp+0x18` from the entry frame, and those are the two numbers the
comparison was equating. They agreed 781 times because the frames were small
enough for the offsets to collide, not because the answer was checked.

The function that exposed it also had `rbp` holding a **data** pointer
(`mov rbp,[rdi+0x20]`), not a frame pointer — so `[rbp+0x20]` there is a struct
field, and reading it as a stack slot would have been a second error on top of
the first.

The sound source is DWARF's `DW_AT_location` resolved through the frame base
(`DW_OP_call_frame_cfa`), which is the mapping the shortcut was trying to avoid.
Recorded as **not verified** rather than shipped: a check that passes for the
wrong reason is worse than no check, because it is then quoted as one.

#### Type propagation: the graph is fixed, the yield is not explained (2026-09-09)

`function typeflow` claims that a type recovered in one function reaches every
function that touches the same object. Two separate things were measured.

**The graph was wrong, and is fixed.** On `oracle/typeflow.c` — three calls,
built with `-fno-inline` so the chain survives — the pass walked **one** edge.
A call reaches it in two shapes: as a `Call` statement, and, once the optimizer
folds a single-use result into its only consumer, as a `Call` expression inside
that consumer. Reading only statements lost most of the graph, and propagation
along a graph that is not the program's is indistinguishable from having nothing
to propagate. Now 4 edges where `objdump` shows 3 in the corpus (the rest of the
program has its own), guarded by a test calibrated to fail at 1.

**The yield is still zero, and that is recorded rather than explained.** With the
graph correct, `propagated_params` is 0 on every shape built for it: a leaf that
types itself from field accesses with blind callers, a caller that types itself
with a blind leaf, and both again in C++ where the type is a real class name
(`Widget *`) rather than a per-function synthetic (`struct_rdi_0 *`, correctly
refused as unportable). `typed_arguments` is 0 — no call argument ever resolved
to a type at all.

Whether that is a defect or a chain of correct refusals **has not been
established**, so it is not claimed either way. What is claimed: the pass runs,
its call graph is now the program's, and on these four targets it propagates
nothing. The next session has a measurement to start from instead of a metric.

#### The seed, measured against the compiler (2026-09-09, later the same day)

The pass is not the bottleneck; the supply of **program-wide names** is. A type
called `struct_rdi_0 *`, recovered inside one function from how that function
uses a register, means nothing in any other — and `is_portable_type` refuses it,
correctly. A `this` pointer is the opposite: `Widget *` means the same thing
everywhere, so every `this` recovered is a seed that can travel and every one
**invented** is a program-wide type carried to a fixpoint from a false start.

So the rule that produces them was measured directly, against
`DW_AT_object_pointer` — the compiler stating, for each function it emitted,
which formal parameter is `this`. `oracle/cxx_this.cpp` is built for it:
instance methods const and non-const, static member functions, constructors,
an operator, a nested class, two template instantiations, and a namespace
whose free functions mangle exactly like methods.

**One of the three grounds was unsound, and the corpus caught it.** *The
qualified name is `Class::method` and RTTI recovered a vtable for `Class`* was
there to keep a namespaced free function out, and did — while letting through
the case it could not see. A **static member function of a polymorphic class**
has precisely that shape: `Virt::no_this(int)` mangles as `_ZN4Virt7no_thisEi`,
`Virt` has a vtable, and the first argument is an `int`. The Itanium ABI
mangles a static member exactly like an instance method, which is why only the
cv-qualifier and the constructor/destructor grounds are proofs.

| | |
| --- | --- |
| `this` pointers the compiler recorded | 59, over `-O0`/`-O1`/`-O2` |
| recovered, after the removal | **41** |
| **invented** | **0** (1 before it) |
| cost on a real library | `analyze --typeflow --limit 1500` on Qt6Gui: 84 → **75** propagated parameters |

Nine propagations traded for zero invented types. What would restore them
soundly is **membership in the vtable** rather than a name that matches its
class — a virtual method is necessarily an instance method. On a PE the slots
are in the image. On an ELF shared object they are relocations (`R_X86_64_64`
in `.rela.dyn` naming the method, zeroes in the file), so it needs the
relocation table read into the vtable region: the same work ELF
devirtualization needs, and not this change.

**A number in the earlier note does not survive contact.** A session summary
recorded "3 parameters propagated" for this library. Re-run today at the
commit that session ended on, before any change here, the same command reports
**74**. The two are not the same measurement and the earlier one was not
reconstructed; the figures above are all from `analyze --typeflow --limit 1500`
on `/usr/lib/libQt6Gui.so.6`, taken today. The four-target zero above is a
different corpus and stands as written.

#### A switch case outside its own function (2026-09-10)

With packed SIMD modelled, enough of a real library executes for the *accusing*
class to appear for the first time: a dispatch the CFG resolved, to a case it
did not record. One function in 400, and the cause is worth writing down.

`QImageData::checkForAlphaPixels` dispatches a 33-case table. The resolver reads
all 33 — the guard bounds them, so this is a read and not a probe — and 32 land
inside the function. The 33rd is `0xe5244`, some 300 KB earlier, and it is
**real code**: a proper instruction boundary after alignment padding, the start
of a basic block. GCC splits cold blocks out of a function, so part of a
function legitimately lives outside its contiguous extent, and the CFG's rule
that "a case must land on an instruction boundary of *this* function" drops it.

The rule is not wrong — without it an unbounded probe walks into a neighbouring
table and invents control flow, which is far worse. What is missing is the
notion that a function can be **more than one range**. Keeping the edge without
that would only move the error: there is no block at `0xe5244` to jump to.
Recorded here rather than patched, because the patch is a change to what a
function *is*.

#### Packed SIMD, and a default that answered instead of refusing (2026-09-10)

The largest block the census named. Nothing in it could be *represented* until
the emulator's word grew from 64 bits to 128 — a change whose control group is
every other corpus here continuing to agree, since scalar arithmetic still
narrows to 64 bits at every `Binary` but the bitwise ones. Bitwise operations
run at the full width because the lift models a vector `pxor`/`andps` as an
exact bit operation rather than an intrinsic; the scalar `not`/`neg` now state
their own width so that stays sound in both directions.

Then the lanes: interleaves, packed add/subtract/compare at four lane widths,
per-lane and whole-register shifts, `pshufd`, `pmovmskb`, packed single and
double arithmetic, and the packed compare predicates in the same `fcmp`
vocabulary the scalar ones use.

**One defect, and it was not a SIMD defect.** `mem_bits_signed` mapped a memory
operand's size through a table of the sizes someone had listed, ending in
`_ => (64, false)`. So *every operand the table did not name read as eight
bytes*: a 128-bit `movdqa xmm0, [mem]` loaded half a register and the upper lane
was silently zero, and a packed add against a memory operand added zeros to it.
The width comes from the decoder's own operand size now. A default that answers
rather than refuses is the worst shape a fallback can take — nothing downstream
can tell it from a measurement.

The census moves 37% → **41%**, and `__vpcmpeqd`, which led it at 39
functions, is gone.

**The 19 "unresolved indirect jumps" were the harness, for the fourth time.**
Every one of them jumped to `0x0` — a GOT slot the loader fills — and they were
not dispatches at all but *tail calls to imports*. The pipeline classifies those
correctly and even renders `return QMetaObject::activate(...)`; the census could
not, because it built its `Ctx` **without a symbol table**, and a tail call
through a slot is recognized *by its callee's name*. With symbols attached the
class disappears and those functions join the call count. A starved pass
measures the harness — the same mistake as the `this`-pointer rule scoring 0 of
22, and the emulator census's own largest class once being planted integers
instead of pointers.

What is left at the top is calls (111, imports deliberately not stubbed) and
unmapped memory (89), both harness-shaped, then 13 branches with no synthesized
condition.

#### Computed control flow, checked for the first time (2026-09-10)

A jump table resolved wrongly is the worst answer a decompiler can give: not a
number that is off, but *control flow that never happened*, and everything
derived downstream inherits it. It had no outside source at all — the switch
resolver's tests compared it against itself, which is a contract check wearing
the clothes of a correctness one.

Two things had to be built before it could be measured. The IR did not carry an
**indirect jump's destination**: a direct jump is structural, the CFG holds the
edge, and the same reasoning was applied to `jmp *(%rdx,%rax,8)`, whose computed
address then existed nowhere. It is now recorded in a reserved variable, the way
the flags are. And the emulator follows it — *and checks it*: the destination
must be one of the edges the CFG claims, so a case the resolver missed comes out
as an error naming the address rather than as a silently different program.

Three defects, on the first run:

- **the function ended before one of its own cases.** The end-of-function
  heuristic raises the function's end for every *direct* forward branch. A jump
  table's case target is not a direct branch, so a case body emitted after the
  default's `ret` — where gcc routinely puts one — fell outside the function,
  and the resolver then dropped that case for not landing on an instruction of
  this function. A switch one case short, silently. The extent now takes a
  floor from the resolved cases of any switch whose count a guard bounds: the
  same evidence the CFG already trusts for the edges, only ever extending, and
  bounded to three rounds.
- **a table base hoisted out of a loop was never found.** The detector
  back-scans the dispatching block for `lea table(%rip), %reg`, and a compiler
  puts that `lea` in the preheader whenever the dispatch is inside a loop —
  which is most of the time. Those dispatches resolved *no cases at all*. The
  dispatch now names the register its table base lives in, and the search
  continues backwards to that register's most recent definition and no further:
  if the last writer is the `lea`, that is the table; anything else, and there
  is no answer. Widening the scan instead would eventually find some
  `lea [rip+…]` and call it a table, which is invented control flow.
- **`sub` recorded its flags as a result, not as the comparison it is.**
  `sub dst, src` sets flags identically to `cmp dst, src`; recording only the
  stored result kept the zero and sign conditions and lost carry and overflow,
  because those are not functions of the result alone. clang writes a switch's
  bounds check as `sub $0xe, %eax; ja default`, so **every clang dispatch came
  out with no condition at all**. Recording the comparison recovers the whole
  `jcc` family. The flags statement had to move *before* the store: SSA renames
  by position, and a compare emitted after it re-read the destination and
  resolved to the value the subtraction had just written.

On a shipped library the instrument now reports **19 of 400** functions
stopping at an indirect jump — and every one of them is a dispatch the CFG
resolved *no* edges for, not a resolved one that went somewhere unrecorded.
Those two are counted separately on purpose: only the second accuses an answer.

#### One bitness down, nothing had ever been executed (2026-09-10)

Two platforms, two compilers, four optimization levels, thirteen thousand
comparisons — and every one of them a **64-bit** target. The first run of a
32-bit corpus scored **51 of 168** at `-O0`, and the causes were not small:

| | what it did |
| --- | --- |
| widths absent entirely | `reg_read`/`reg_write` stated a width when the operand was narrower than its **container**; on i386 `eax` *is* the container, so nothing was ever stated and a 32-bit sum that overflowed stayed 33 bits wide |
| the stack pointer had **two names** | `push` wrote `esp` (spelled by mode) while every other read and write used `rsp` (spelled by `reg_name`, which canonicalizes to the full register). One register, two variables — so every stack access after a push read a pointer four bytes stale, which on i386 is every local in every function |
| effective addresses did not wrap | `[ebp-0x10]` is computed modulo 2^32; the IR built it with a 64-bit add that carries. A `lea`-produced pointer *was* truncated, because a register write states its width — so one stack slot had two addresses and a byte written through the pointer was invisible to the next read of the same local |
| `sar` read its operand unsigned | a narrow operand arrives zero-extended, so `sar eax, cl` on `0xffffffff` shifted a positive 64-bit number. **A 64-bit defect too** — the only `sar` in the older corpus was on a 64-bit value, where there is no cast to re-read |
| the divide did not state its width | `idivl` reads `edx:eax`, not `rdx:rax`. Reading both whole registers made the dividend astronomically larger, so every signed division of a negative number reported a quotient that does not fit |
| `__umulh` did not state its width | `mul %edx` leaves `(a*b) >> 32` in `edx`, not `>> 64` |
| the one-operand multiply **clobbered its own input** | both halves read the pre-multiply `rax` *and* the source, and the source is frequently `rdx` — writing the high half first left the low half reading what it had just written. The divide beside it has a temporary and a comment explaining exactly this hazard; the multiply had neither. **A 64-bit defect**, found because clang builds the closed form of a summation loop as `mul %edx` |
| a constant ignored its stated width | `cmpl $0xffffffff, mem` encodes a sign-extended byte, so the IR holds `-1` at 32 bits; the emulator took `value as u64` and compared `0xffffffffffffffff` against a zero-extended memory read. Never equal — so a guard against dividing by −1 fell through into the divide. The constant folder had always masked to `bits`; this was the second reader disagreeing with the first |
| a variable-count rotate was refused | on the stated grounds that it "needs x86 count-masking to be sound". The masking is the whole of it, and `shift_rmw` had been masking counts for some time: the refusal had outlived its reason |
| the emulator fabricated the return address | deliberately, on the reasoning that it could not know an instruction's length. It does not need to — the IR says where execution continues. It matters because **there are no leaf functions in position-independent 32-bit code**: every one begins by calling a thunk whose whole body is `mov (%esp), %eax`, so a fabricated return address is the first thing such a program reads |

Two of those (`sar`, the multiply) are wrong answers on x86-64 that thirteen
thousand 64-bit comparisons never produced, because neither compiler chose
those shapes for that corpus at that width. A new **axis** — a bitness, a
platform, a compiler — had by then found a defect on its first run three times
in a row, and a deeper sample of an existing axis had not found one since.

**And then a fourth axis found nothing, which is worth recording too.** PE32
(mingw, under Wine) was added as a third 32-bit target on the reasoning above:
a different container, a different image base, a different
position-independence idiom, a different stack-protector convention. It passed
on the first run, 1 296 comparisons, 0 disagreements. The width work done for
ELF32 covered it, because the axis that mattered was the *bitness* and not the
container. The one thing it did surface is a naming fact rather than a defect:
i386 Windows decorates a cdecl symbol with a leading underscore, so the symbol
table says `_emu32_add` where the export says `emu32_add` — two names for one
function, and a harness that matched on the symbol saw no corpus at all.

#### The AArch64 decoder judged over the encoding space, not compiler output (2026-09-09)

147 compiler-emitted instructions all agreed with LLVM. That says nothing about
the far larger space a decoder meets when it walks data, padding, or a section
it should not be in — and that is where a decoder does its quiet damage.

600 deterministic words, each judged by `llvm-mc --mattr=+all` and by n0xis, on
**validity** alone:

| | count |
| --- | --- |
| both reject | 304 |
| both accept | 241 |
| **n0xis accepts, LLVM rejects** | **48 (8.0%)** |
| **LLVM accepts, n0xis rejects** | **7 (1.2%)** |

**Deliberately not attempted on 2026-09-09, and here is the reason.** Closing
this needs the architecture manual open, one encoding at a time: a rule written
from the shape of the failures would reject *valid* instructions, which is
strictly worse than accepting invalid ones — a decoder that refuses real code
stops the analysis, while one that over-accepts produces a line a reader can
see is wrong. The ratchet in `tests/arm64_encoding_space.rs` holds the gap at
these numbers and fails if it grows. Three cases are already worked out by hand
(the 32-bit logical form with `imm6 >= 32`, returned as `and`/`orr`); the rest
is manual work, not a session's leftover time.

A second sample drawn a different way gave 31 and 12 (5.2% and 2.0%) — the two
disagree on the figure and agree on the scale.

**Three of the accepted-but-reserved words were decoded by hand against the
architecture's rules and are genuinely UNALLOCATED.** `0x0a559521` and
`0x2a9da3bc` are 32-bit logical shifted-register forms whose `imm6` is 37 and
40, where the architecture requires it below 32; n0xis calls them `and` and
`orr`. The consequence is not cosmetic: a reserved word read as an instruction
turns bytes that are not code into a plausible program, which is precisely what
the discovery sweep and every "is this code" test rest on.

**Not patched, on purpose.** The classes are identifiable — 11 of 31 in one
sample fell into three well-defined reserved-field rules — but a rule written
in a hurry rejects *valid* instructions, which is strictly worse than accepting
invalid ones. The gap is held by a bound that fails if it grows, with the
numbers in the test, and closing it belongs in its own pass with the
architecture manual open.

The same walk also found three aliases no compiler had emitted (`sbfiz`/`sbfm`,
`bfxil`/`bfm`, `tst`/`ands`), now in the alias table.

### Cross-cutting

- **Cross-compilation / remote** for ARM devices: build n0xis for armv7/aarch64
  to run *on* the device, or use the existing `remote-serve` over SSH; Unicorn +
  a gdbstub client covers the rest of the arches dynamically.
- **VM seam** (a recorded debt): engine support (IL2CPP/LuaJIT/Bitsquid) is
  per-engine and hardcoded — lift it to one plugin contract so Mono / Godot
  / V8 register as plugins, not surgery.

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
halves — so they rank first.** The SLEIGH ISA specifications are downloaded
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
  (a separate always-on-top window beside the game), launched from a game's `.n0x/` project and driven by
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
- ✅ **Bitsquid-bundle + LuaJIT asset tooling** (`crates/n0xis-bitsquid`,
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
agent's session log against an IL2CPP target, with every claim re-measured against
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
  is the wrong one for the most common real target there is: an IL2CPP player EXE is 2
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
85 commands, omitting the entire live-memory half.

---

## Phase 12 — IL2CPP: the managed layer (the runtime's hard mode) 🎯 ⏳

### IL2CPP WebGL is the same phase, not a second one

IL2CPP WebGL builds go through the **identical IL2CPP pipeline**: Roslyn → IL → C++ → native
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
wasm function index. IL2CPP WebGL dispatches virtuals through the same machinery:
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
file-packager blob, which also carries the engine's asset data — rather than loose on disk.
Extracting it is a packaging problem, not a metadata one, and once extracted it is the same
file the Windows parser reads. That is the compatibility payoff restated concretely: item 1
buys both platforms, item 6 buys one and a half.

**The thesis: this is one missing layer, not five missing features.** Every IL2CPP symptom
on record — `xref string` → `count: 0`, `bindings list` → `count: 0`, **0 of 69** calls
named in `decomp pseudo`, no name→address path by any means — has a single cause: N0xis
reads the *native* half of an IL2CPP target and never the *managed* half. Build that half
once, behind seams that already exist (`SymbolProvider`, the pass `Ctx`), and the symptoms
clear together — without touching the decompiler, the xref engine, or the renderer.

### What IL2CPP is (the structural facts the phase is built on)

The runtime ships two scripting backends. **Mono** emits real .NET assemblies
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
every class, method, field, and offset, by name. IL2CPP is the runtime's hard mode only until the
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

Measured 2026-07-30, n0xis 0.1.0, an IL2CPP build (runtime 2022.3, x64), `GameAssembly.dll` 94 MB.

| Command | Result | Real reason |
|---|---|---|
| `xref string` | `count: 0` | literals are in the `.dat`, materialized by index |
| `bindings list` | `count: 0` | *for managed methods* — no name strings in the image to pair (**but see the icall hypothesis**) |
| name → address | no path | needs the metadata × registration join, which nothing parses |
| `decomp pseudo` call naming | 0 / 69 named | callee names live in the metadata; export thunks recover only the runtime API |
| `xref to` / `function trace` on virtual calls | incomplete | vtable slot dispatch — the slot table is in the metadata |

`profile` already detects the target and says so in `advisories` (Phase 11). This phase is
what turns those advisories from *"this will not work here"* into *"run `il2cpp index`"*.

### Managed provenance — the item that justifies the phase

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

Nothing in the ecosystem does this. Static dumpers do not see the running process; a memory scanner cannot name IL2CPP
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
   **Landed:** `crates/n0xis-il2cpp`, 18 unit tests + an 8-test CLI exit test, clippy clean, boundary
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
   - **Address spaces are explicit, and that is the whole IL2CPP-WebGL story** (see below).
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
     **Measured on a real target** (an IL2CPP title's `global-metadata.dat`,
     22 984 696 bytes): version 31, **23 023 literals**, `string_literal_data` 672 564 bytes,
     and **zero** non-UTF-8 entries — the module's own tripwire for a wrong stride, clean.
     Searching returns real game text (`EnemyHealth`, `Drink_HealthPotion`,
     `ActivateDamageZoneRpc`, `Dealing Damage to: `). That is the first thing on this corpus
     that answers *"is this on-screen text in the game"* **with no external dumper at all** —
     the question `xref string` structurally cannot answer here, since the literals are not
     in the image.
   - ✅ **The IL2CPP directory layout is knowledge held once.** `--file <image>` finds the blob
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
     directly. For an IL2CPP target that blind spot is now partly closed.
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
     **Those addresses land outside `GameAssembly.dll` — in the player module** — which is
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
claim the phase actually needs. So the local game library was inventoried and every IL2CPP build
in it run through the same battery. Three real targets, three **different metadata versions**;
the three other managed titles installed are Mono (`Managed/Assembly-CSharp.dll`, no
`il2cpp_data`) and are correctly not treated as IL2CPP.

| | the IL2CPP title (v24) | the IL2CPP title (v29) | the IL2CPP title (v31) |
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
`fields` at `0x80`), and on the IL2CPP title (v24) recovered 98 classes including
`TMPro.TMP_Text` (229 fields) and `TMPro.TMP_FontAsset` (55 fields, `m_SourceFontFileGUID`,
`m_AtlasPopulationMode`, `m_GlyphLookupDictionary` — unmistakably real).

**What it disproved, and the fix.** The icall shape is **not** universal. The IL2CPP
title (v29) has 1911 icall names in `.rdata` and **nothing in the image references them** —
verified three ways: no referencing `lea` (`xref string` finds the string but no xref), no
absolute 8-byte pointer, no 4-byte RVA. So `il2cpp icalls` correctly returned zero, and returned it *silently*, which is
the exact failure this project exists to prevent. `names_in_data` now distinguishes the three
possible zeros:

- names present, no sites → *this build does not use the load-name/call-resolver/cache-slot
  shape; the names are real, the live-address route is not available here*
- no names, no sites → *not an IL2CPP image, or the wrong module/section was scanned*
- sites found → the ordinary case

The IL2CPP title (v24) is the intermediate case that makes the point: 1740 names, only
72 sites. The shape is a **codegen option, not a format guarantee**, and the tool now says so
per target.

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
| the IL2CPP title (v31) | 85.9 % | **0.45 %** |
| the IL2CPP title (v24) | 23.2 % | 0.31 % |
| the IL2CPP title (v29) | **5.1 %** | 1.47 % |

Counting only the sites inside those swept prefixes reproduces the old output exactly —
1074, 72 and 0 — which is what makes this a diagnosis rather than a theory.

`Arch::decode_range` now resynchronizes past undecodable bytes instead of stopping, and the
four section-wide passes use it. Re-measured:

| | sites before | sites after | distinct icalls | with cache slot |
|---|---|---|---|---|
| the IL2CPP title (v24) | 72 | **3454** | 1745 | 1397 |
| the IL2CPP title (v29) | **0** | **4053** | 1916 | 1893 |
| the IL2CPP title (v31) | 1074 | **50 875** | 4921 | 2448 |

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
  - **The name strings are in the image.** 2189 distinct `Namespace.Type::Method` internal-call
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

IL2CPP puts the transpiled C# in a section of its own and leaves `.text` holding the runtime.
Every range-scoped command defaults its code window to `.text`, so **`xref`, `xref string`,
`function discover`, `ir manifest` and `function trace` were scanning 10.6 % of the binary
and reporting the other 89.4 % as containing nothing** — not as out of range, not as
truncated. A silent zero, which Phase 11 exists to make impossible.

- ✅ **`profile` now sees it and says so.** `SectionInfo` carries `executable`
  (`IMAGE_SCN_MEM_EXECUTE`), and any executable section besides `.text` raises an advisory
  naming the affected commands **and handing over the exact window to pass**
  (`--start 0x1806eb000 --size 0x3a76a73`). Fires on any PE, not just IL2CPP ones; two tests,
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
  - ✅ **`--module` on the range-scoped commands**, because a *live* IL2CPP target needs it:
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

The sibling of Phase 12. Where IL2CPP is the managed-name problem of one runtime, **NativeAOT**
(`ILC` / `PublishAot`, the shape a modern Godot-C# or .NET game ships) is the CoreCLR one: the
compiler strips ordinary symbols, so `disasm`/`decomp` see only `sub_XXXX` and a config read by
enum index leaves no string to `xref`. But the managed names are still *in the image*, in the
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
- **Measured:** on a Godot Windows x86-64 module (Godot-C# NativeAOT, .NET 8, ReadyToRun 9.1)
  → **208 056** methods (91 136 stack-trace + 116 920 invoke); `common.*` fully covered, and
  gameplay targets resolve, e.g. `common.<title>.UI.Drawer.GameSetupMenu.GetMaxPlayersOptions
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
   (ELF binaries are often *not stripped* — a windfall). **Verified:** a **Bevy/Rust** title
   (PIE, not stripped) — 38 048 functions discovered, Rust names recovered and demangled
   (`once_cell::imp::OnceCell<T>::initialize` decompiles at quality 1.0); an **ELF/GCC** title
   (System V, 24 106 functions) decompiles at 1.0 with `.dynsym` naming the OpenSSL calls
   (`BIO_push`, and its statically-linked `…__BIO_new_ssl_connect`).
   Follow-ons: **System V calling-convention
   recovery** (Rung 4 is Win64-register-specific, so ELF *signatures*/args are not yet right — the
   body is), **PLT/GOT import-slot naming** (`iat_slot` returns `None` on ELF today), and **DWARF**
   type/line recovery from `.debug_info` (the Bevy/Rust title carries it — a ground-truth goldmine).
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
    `goblin`. **Verified against `objdump` ground truth** on real 32-bit binaries (a
    32-bit PE tool binary and its i386 hook DLL): the decode matches byte-for-byte
    (`inc eax` / `push ebx` / `add dl,[eax]` — the exact bytes objdump shows), a 26-function
    sweep decompiles 26/26 with 0 errors at avg quality 0.913, and the 64-bit PE/MSVC
    game binary is unchanged. Follow-ons: stack-based cdecl/stdcall arg recovery, the `eax`-vs-`rax`
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
  a thin frontend, and it is the capability the phase exists for, so don't defer it to the end.
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
  Phase 10's hardest ❌ (indirect/virtual calls) by table lookup for IL2CPP targets — so on
  a game corpus, 12 outranks 10 on payoff per unit of work. Within 12, ship item 0 (import
  an external dump) immediately: it is a day's work, it is reversible, and it tells you
  what the rest of the phase is actually worth before you write a metadata parser. Then
  drive to item 3 (managed provenance) — it is the item the phase exists for, and
  it needs both a watchpoint engine and an unwinder to work at all.
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
  `NtGlobalFlag`, DR registers, timing). Brittle, version-locked,
  a race the packer updates to win — do only for versions actually needed. 15b sidesteps
  most of this by not being a debugger at all.
- **15e — VM devirtualization (research, human-in-loop).** ⬜ Lift a protector VM
  (find dispatcher → reverse handlers → raise bytecode into the IR, where the
  existing `ir value-set` / `ir deobfuscate` finally apply). Per-protector,
  per-version, usually partial — realistic target is an *assist* mode ("map these
  handlers") for a human, not a button. A separate research branch, not a product
  feature; chasing packer-specific devirt is a treadmill (it updates precisely to
  break public unpackers), so the generic dynamic unpack (15b, protector-agnostic
  for the unpacking layer) is the main line.

**Priority:** 15a (now, days) → 15b (strategic, own crate) → 15c (easy class) →
15d/15e as needed. The unpacking layer of 15b/15c is protector-agnostic: you let
the sample unpack *itself* under emulation and grab the OEP image, so you never
have to understand the packer's VM to recover the ~majority of the binary that
unpacks to native — only the functions that stay virtualized need 15e.

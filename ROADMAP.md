# N0xis — Roadmap (v1 rewrite)

> Companion to [`CONCEPT.md`](CONCEPT.md). Strategy: **full rewrite** into a Cargo
> workspace, porting the sound parts of v0 ([`archive/`](archive/)) rather than
> re-deriving them from a blank page. Each phase ends with the tool **buildable and
> usable** — no phase leaves `main`/CLI broken.

Legend: 🎯 milestone · ✅ done · ⏳ in progress · ⬜ todo · ⚠️ caveat.

---

## Phase 0 — Reset & docs ✅
- ✅ Archive v0 to `archive/` (code + docs).
- ✅ Delete the web/Tauri frontend prototype entirely.
- ✅ Preserve the CLI surface → [`docs/CLI_COMMANDS.md`](docs/CLI_COMMANDS.md) (originally captured as `CLI_COMMANDS_v0.md`; since **renamed** and now the current command reference, not a frozen snapshot).
- ✅ Concept + roadmap.

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
- ✅ **Tools mirror CLI verbs + return the same schemas**: 14 tools in `crates/n0xis-mcp/
  src/tools.rs` at this phase's exit — `doctor`, `process_ps`, `attach`, `module_list`,
  `disasm`, `function_discover`, `function_trace`, `decomp_pseudo` (goto/structured/ssa),
  `xref`, `xref_string`, `mem_read`, `mem_write`, `provenance_trace`, and the
  `explain_opt_delta` tool below (`provenance_trace`, the other "explain" tool, is
  already named above). (Later phases add `annotate_set`/`annotate_get`/`annotate_list`
  in Phase 6 and `ui_locate` in Phase 9, for **18** exposed tools in the working tree.)
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
Goal: turn [`docs/RE_METHOD.md`](docs/RE_METHOD.md) into tools. That doc is the
post-mortem of one complete campaign (auto-solving a game's directional
interact-combo mini-game). It succeeded — and **~90% of the effort went into
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
> reads first. (Phase 9's working-tree `ui locate` brings a rebuild to 78 leaf
> commands.)

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

> **Status (2026-07-22) — working tree, uncommitted.** Nothing in this phase is on
> `main` yet. Every ⚠️ item below is **implemented and self-tested** (unit tests
> over synthetic snapshots — the AABB predicate, the overlap maths, the
> mirrored-dword relation, the real 348k-noise sample), but the decisive
> **live-target validation** — the §9.3 appearance-correlation test on a running
> game — **has not been run**. Read the ⚠️ markers as *implemented, pending live
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
  > value (`HELLDIVERS` = `min.x@+0xa4 … radius@+0xbc`), not inlined — a
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
  > internal engine (and the guide's `guide_category` has no `ui` arm yet, so the
  > auto-catalog currently buckets `ui locate` under "Other").

- ⏳ **Agent target-selection tooling — `ui windows` / `ui screenshot` /
  `ui focus`** *(the operator's proposal: an agent driving `ui locate` needs to
  see the target and name a window before it can choose a rect)*. The `ui
  locate` brief's no-pixels rule governs how widgets are *found* (by their data,
  not their appearance); it does not forbid *showing the operator/agent the
  window so they can pick a rectangle* — a distinct, read-only concern.
  - **`ui windows --pid <p>`** — enumerate a process's top-level windows
    (title, class, on-screen rect), so an agent can name the game window rather
    than guess an HWND. Read-only.
  - **`ui screenshot --pid <p> [--out <png>]`** — capture the target window to
    a PNG (or base64 in the envelope) via external Win32 only (no injection, no
    D3D hook). **The load-bearing risk**, being researched before implementation:
    GDI `BitBlt`/`PrintWindow` return an all-black frame for many
    DirectX-accelerated windows, and an agent must never mistake a black capture
    for "the UI is empty" — so the command must *detect and report* a blank
    capture rather than hand back a misleading image.
  - **`ui focus --pid <p> --hwnd <h>`** — bring a window forward (window
    selector). Unlike the rest of Phase 9 this is **not** purely read-only (it
    activates a window on the target); it will be labeled as such in the
    command contract. Marked "if needed" by the operator.
  **Status**: in progress this session — `ui locate`/structural-scan landed
  first; these build on the same `n0xis-sources` (Win32, `live` feature) seam.
  Not yet implemented.

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
| Type recovery | 🚧 early — locals / struct-field / arity / return + ~30 API sigs |
| Alias analysis | 🚧 basic — bounded value-set, intraprocedural, `Top` on loads |
| Tail-call detection | 🚧 partial — edge class only, no semantic promotion |
| noreturn analysis | 🚧 partial — triage flag, not interprocedural |
| Compiler-idiom recovery | 🚧 early — `const identify`, junk, opaque predicates only |
| Memory SSA | ❌ missing |
| Interprocedural propagation | ❌ missing (bar the known-API table) |
| Exception-edge recovery | ❌ missing — `.xdata` parsed for unwinding only |
| Indirect / virtual call resolution | ❌ missing — IAT/direct only |
| SIMD / FP lift | ❌ missing — integer set only; degrades to `asm` nodes |
| PDB / type ingestion | ❌ missing |

### The gap in detail (what parity actually requires)

| Analysis | What real parity needs | N0xis today |
|---|---|---|
| Exception edges | parse `.xdata` EH handlers → try/catch/finally edges in the CFG | ❌ `.pdata`/`.xdata` read for **unwinding only**; no EH edges in the graph |
| Tail-call detection | recognize `jmp func` as call+return, resolve callee, render `return f(...)` | 🚧 `tail` exists as an **edge class**; no semantic promotion |
| noreturn analysis | detect + **interprocedurally** prune fall-through in callers | 🚧 `no-return` is a **triage flag**; not propagated into caller CFGs |
| Indirect call resolution | devirtualize `call [reg+off]` via vtable/type analysis | ❌ only IAT/direct resolved; value-set gives `Top` on loads |
| Switch recovery | many idioms (dense / sparse / multi-level / bounds-checked) | ✅ 2 x64 idioms, memory-resolved, `code_range`-gated |
| Jump-table recovery | + relocation-aware | ✅ same 2 idioms; narrower than other tools |
| Alias analysis | a real memory-alias oracle | 🚧 light/bounded (`ValueSetPass::alias`, `Var±Const` only, `Top` on load) |
| Memory SSA | SSA over memory (versioned store/load) | ❌ SSA over registers/flags only — **why** expr-prop is conservative |
| Interprocedural propagation | types / values / CC across the call graph | ❌ intraprocedural; only the ~30-entry API table crosses a call |
| Compiler idioms | magic-division, `rep`-string→`mem*`, stack canary, strlen-inlining, cmov→min/max, SSE idioms, … | 🚧 a handful (`const identify`, junk, opaque predicates) |

### Prioritized plan (ordered by leverage × cost, not size)

0. ⬜ **CFG fidelity — the correctness debt. Do this first.** Interprocedural
   `noreturn` propagation, tail-call promotion, exception edges. It is *cheap* —
   the data already exists (`.xdata` is already parsed for the unwinder; `no-return`
   and `tail` are already computed) — and it is **correctness, not prettiness**.
   Memory SSA over a wrong CFG is precise nonsense: for a *sound-over-complete* tool
   (CONCEPT §3 rule 6), a wrong control graph yields *confidently-wrong* C, which is
   worse than an honest `asm` node.
1. ⬜ **Memory SSA — the representation that lifts the stop-crank.** Expression
   propagation is conservative *today only because* nothing can prove a load/call
   safe to move past a store. Memory SSA is what unblocks everything downstream.
2. ⬜ **Light points-to / alias, on top of Memory SSA.** Co-evolves with type
   recovery — chicken-and-egg: alias precision needs types, type recovery needs
   alias. Climb 1–2 together; neither is precise alone.
3. ⬜ **Function-summary IPA — the high-ROI slice.** Per-function summaries
   (returns / `noreturn` / clobber set / arg & return types / side effects), **not**
   full context-sensitive interprocedural analysis. Composes directly with the
   existing `ManifestPass`, which already computes per-function flags — so this is
   an extension, not a new subsystem.
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

### Two framing rules this phase encodes

- **The right priority is a function of the target corpus.** N0xis's is game
  engines on x64 Windows — which pulls **SIMD up** (a floor problem, not coverage)
  and **PDB down** (game builds are usually stripped). A general-purpose x64
  decompiler would order these differently. State the corpus *before* arguing the
  order.
- **Correctness before power.** The lowest foundation is a *correct* CFG, not a
  *powerful* memory model over an incorrect one. `sound over complete` makes a wrong
  graph the worst outcome — fix the graph (priority 0) before deepening the data
  flow over it.

> **Why this is the right shape of work, not a smaller feature list.** The missing
> pieces classify cleanly into a handful of *independent* projects — Memory SSA,
> interprocedural analysis, EH recovery, SIMD lift, an idiom library — rather than
> "we don't know how." That is a maturity signal: the decompiler core exists, and
> what remains is heuristics and depth. This phase also feeds CONCEPT §2's
> north-star directly — the interprocedural summary layer it builds (priority 3) is
> what materializes the persistent "program model" that turns *one pipeline* into
> *one model, many projections*.

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
  low-level keyboard hook (hotkeys), a process watcher that auto-applies adapters
  when the target appears, and the combo watcher. Shipped: config-driven bindings
  (nothing hardcoded), write & freeze over the Phase 4b primitives (pointer-path
  locators included), global hotkeys with in-UI rebind + conflict detection, and
  an in-binary adapter registry (today only `helldivers-infinite-mags`, an
  AOB-anchored live LuaJIT-bytecode patch journaled so toggle-off restores the
  original bytes).
  ⚠️ Doc debt: the design docs under [`docs/n0xhud/`](docs/n0xhud/) still describe
  the *unbuilt* overlay/injection plan and use cheat-menu framing — stale, flagged
  for a rewrite; the shipped binary is the companion-window shape above.
- ✅ **Interception-driver actuation** (`interception.rs`). Dynamically loads a
  user-configured `interception.dll` (path from `hud.toml`, never hardcoded) and
  sends keystrokes through the kernel-class driver — needed because Helldivers
  filters `LLKHF_INJECTED` and ignores the identical scancode sent via
  `SendInput` (confirmed live). Two macro subsystems ride on top: fixed
  **sequences / "Combinations"** replay (via `SendInput`) and **stratagem
  macros** (via Interception).
- ✅ **Bitsquid/Stingray + LuaJIT asset tooling** (`crates/n0xis-bitsquid`,
  `n0xis-lua`, `n0xis-luajit`; CLI `bundle {list,extract,repack}` and
  `lua {disasm,patch,strings,table,combo,seedscan}`). Offline bundle
  read/extract/repack and LuaJIT bytecode disasm/patch, plus **live GCstr/GCtab
  introspection** — decoding real LuaJIT object headers out of a running process's
  heap with pure memory reads (no debugger). None of these three crates is
  depended on by `n0xis-core` (the boundary law still holds).
- ⚠️ **Helldivers interact-combo auto-solver** (`combo_watcher.rs` +
  `adapters/helldivers_combo.rs` + `interception.rs`) — the main HUD
  capability, framed as *dynamic analysis in a loop*: detect an active
  interact-combo component in live memory, recover its small-integer seed, and
  recompute the deterministic sequence from the game's own LCG
  (`s' = s*1664525 + 1013904223`, reverse-engineered from the native
  `Math.next_random` binding and validated live against two independent
  activations), actuate through Interception, and re-read live `progress` before
  each tap — stopping the instant the window closes.
  - **Mines/UXO (default)**: solved **exactly** from the seed, **never**
    brute-forced (a wrong tap detonates) — the validated, always-safe path.
  - **Universal (opt-in)**: detects any interact object by diffing
    `interacting_unit` between polls, solving seed-first with a per-position
    brute fallback (safe because a wrong *non-mine* input only resets progress;
    **mines are never brute-forced regardless**). Explicitly **gated behind its
    own live-validation checkpoint** — implemented, not verified.
  ⚠️ Doc debt: the solver code cites planning docs (`AUTO_COMBO_PLAN.md`,
  `cheats_research.md`) that don't exist in this repo, and it has **zero**
  coverage under `docs/n0xhud/` — to reconcile in the HUD doc rewrite.

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

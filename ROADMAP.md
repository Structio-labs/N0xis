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
| Type recovery | 🚧 early — locals / struct-field / arity / return + ~30 API sigs |
| Alias analysis | 🚧 basic — bounded value-set, intraprocedural, `Top` on loads |
| Tail-call detection | ✅ 2026-08-06 — edge class **+ semantic promotion** (`jmp func` and IAT-thunk `jmp [__imp_X]` lower to `call`+`return`, render `return f(...)`); verified on real PEs |
| noreturn analysis | 🚧 partial — known-import calls (`ExitProcess`/`abort`/`_CxxThrowException`/…) correctly end a block **and the function** ✅ 2026-07-22, first actually firing on real binaries 2026-08-06 (the IAT-keying fix); self-discovered-function propagation still not attempted |
| Import-name resolution | ✅ 2026-08-06 — direct, IAT-slot and thunk callees resolve to `module!name`; imports render by name and reach the known-API signature table |
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
| Tail-call detection | recognize `jmp func` as call+return, resolve callee, render `return f(...)` | ✅ *(2026-08-06)* both shapes — a direct `jmp` out of the function **and** an import thunk's `jmp qword ptr [__imp_X]` (previously mis-classified `ijmp`, "indirect jump (unrecovered)") — terminate as `tail-call` and lower to `call`+`return` via the new `Arch::lift_tail_call` seam, so every style renders `return f(...)`. Verified on real PEs (`version.dll` thunk → `return …GetFileVersionInfoSizeW(…)`; 15/400 notepad, 52/400 dxgi functions carry the `tail` flag) |
| noreturn analysis | detect + **interprocedurally** prune fall-through in callers | 🚧 ✅ *(2026-07-22)* a call to a well-known noreturn import (`ExitProcess`/`abort`/`TerminateProcess`/`_CxxThrowException`/`__fastfail`/…, `n0xis-core::noreturn`) now ends its block like a `ret` (`terminator: "call-noreturn"`, zero successors) — closes the CFG so `ir manifest`'s pre-existing `no-return` flag becomes accurate for free on this case. ✅ *(2026-08-06)* `truncate_to_function` (the whole-function-end heuristic) now knows about calls too, so a function no longer over-extends past a noreturn call — and the whole mechanism fires on real binaries for the first time (it needed the IAT-keying fix; `vcruntime140.dll` 0 → 33 functions flagged `calls-noreturn`). **Still open**: propagating noreturn-ness across N0xis's *own discovered* functions (a whole-program call-graph fixpoint) is not attempted — a documented follow-on, not a silent gap. |
| Indirect call resolution | devirtualize `call [reg+off]` via vtable/type analysis | ❌ only IAT/direct resolved; value-set gives `Top` on loads |
| Switch recovery | many idioms (dense / sparse / multi-level / bounds-checked) | ✅ 2 x64 idioms, memory-resolved, `code_range`-gated |
| Jump-table recovery | + relocation-aware | ✅ same 2 idioms; narrower than other tools |
| Alias analysis | a real memory-alias oracle | 🚧 light/bounded (`ValueSetPass::alias`, `Var±Const` only, `Top` on load) |
| Memory SSA | SSA over memory (versioned store/load) | ❌ SSA over registers/flags only — **why** expr-prop is conservative |
| Interprocedural propagation | types / values / CC across the call graph | ❌ intraprocedural; only the ~30-entry API table crosses a call |
| Compiler idioms | magic-division, `rep`-string→`mem*`, stack canary, strlen-inlining, cmov→min/max, SSE idioms, … | 🚧 a handful (`const identify`, junk, opaque predicates) |

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

## Phase 11 — Agent consumability 🎯 ✅ (working tree)

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

## Phase 12 — IL2CPP: the managed layer (Unity's hard mode) 🎯 ⬜

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

0. ⬜ **Import an external dump first — one day, ~80 % of the pain gone.**
   `il2cpp import --script-json <Il2CppDumper output>` → an RVA→name table in `.n0x/`,
   chained in as a `SymbolProvider` over the PE exports. Named decompilation *before* a
   single byte of metadata parser exists. Not scaffolding to throw away: it stays as the
   fallback for versions and obfuscations the native parser refuses, and as the interop
   path into an ecosystem that already exists (Il2CppDumper, Il2CppInspector, Cpp2IL).
1. ⬜ **`crates/n0xis-il2cpp` — the native parser.** Header + string table + type / method /
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
2. ⬜ **Wire the seams — where the payoff actually arrives.** `Il2CppSymbols:
   SymbolProvider`, chained over the PE provider. `decomp pseudo`, `ir explain`,
   `function discover`, `xref to`, `function trace` all start naming with **zero changes of
   their own**. Extend the seam with a name→address direction (`symbol_by_name`) that
   **returns a set, never one entry** — generic sharing and ICF both make the single-answer
   API a lie (the same discipline Phase 11 established for folded exports).
3. ⬜ **Managed provenance** (the item above) — `debug watch` / `provenance trace` /
   the unwinder resolve frames through the index, and disambiguate shared generic bodies via
   the live `MethodInfo*`. Depends on 1+2 and on nothing else; do not let it drift to the end.
4. ⬜ **Types, objects, and the live klass route.** `il2cpp type` (fields, offsets, size,
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

- ⬜ **The icall table may make `bindings list` work after all.** IL2CPP registers engine
  internal calls through tables of `{const char* name, Il2CppMethodPointer fn}` — which is
  *exactly* the name-string × function-pointer pairing `bindings list` was built for, and
  those strings should be in `.rdata`. If it holds, the current advisory ("IL2CPP has no
  binding-name strings in `.rdata`") is **overstated** and must be narrowed to *managed*
  methods, with icalls called out as the working case. Measure first:
  `n0x xref string --file GameAssembly.dll --query "get_position_Injected"`, then
  `bindings list` over the hit's data window. This is precisely the class of overstated claim
  Phase 11 exists to hunt — check it before the phase, not after.
- ⬜ **Cpp2IL as the obfuscation fallback** — worth evaluating as an *import* source (like
  item 0) for targets whose metadata is renamed or unreadable. Evaluate; do not reimplement.

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

## Phase 13 — The wire: network & protocol layer (netcode QA and server-authority testing) 🎯 ⬜

**The thesis: N0xis can say what is in memory and which code touched it, and has no idea what
left the machine.** For any title with a server, half the truth lives on the wire — and the
questions a studio actually cannot answer today are wire questions: *does the client send
what the design says it sends?*, *what is in this 340-byte frame we ship 30 times a second?*,
*if a client lies about this field, does the server catch it?* None of those are reachable
from a memory scanner and a decompiler alone.

### What this phase is for, stated once and plainly

This is **netcode QA and server-authority testing on builds you own or are authorized to
test** — a studio's own game, a client's game under a testing agreement, a server you
operate. Three concrete jobs:

1. **Protocol truth.** What the shipped client actually puts on the wire, versus the protocol
   document, which is wrong roughly as often as documents are. Field layout, cadence,
   bandwidth per subsystem, and what leaks into a packet that should never have been in one.
2. **Desync and regression analysis.** Two captures of the same scripted scenario across two
   builds, differenced. This is the netcode analogue of `diff functions`, and it is how you
   find the change that broke replication without reading the diff.
3. **Server-authority verification — the security job.** A server is authoritative only if a
   *lying* client gets refused. Testing that claim requires producing the lying client's
   traffic and recording the server's answer; there is no other way to test it. That is why
   `net replay` exists, and it is why its output is shaped as a **test result** — accepted or
   rejected, per mutated field — rather than as a working exploit.

The standing project line holds without amendment here: every command in this phase describes
what *your* client sends and whether *your* server checks it.

### Why this belongs in N0xis rather than in Wireshark

Wireshark sees bytes with no code context. A debugger sees code with no protocol view. The
gap between them is where every real netcode investigation stalls, and N0xis already owns the
one combination that closes it: **hardware watchpoints × a cross-process x64 unwinder × a
decompiler** (Phases 4b/4c). Pointed at a send buffer, that stack answers:

> the 4 bytes at frame offset `0x1C` were serialized from `+0x40` of the object at
> `…`, which `Inventory::CommitSlot` wrote 12 ms earlier, called from `PickupItem`

A wire field bound to a memory address bound to a named function, in one artifact. **Nothing
else joins those three views**, and it is the answer QA actually wants — not a hexdump, but
*which of your code put this on the wire*. On an IL2CPP target with Phase 12 landed, those
frame names come out as C# methods, which is the point at which this stops being a hex tool.

Everything else in this phase is table stakes that exists to make that one join possible.

### Where frames can be captured (ordered by cost, and by how much they are worth)

| Route | Mechanism | Yields | Costs |
|---|---|---|---|
| **Offline** | read a pcap / JSONL someone else recorded | schema, dissection, diffing, CI replay — with no target at all | no process context, so no provenance join |
| **API detour** | inline hook on `ws2_32` `send`/`recv`/`WSASend`/`WSARecv` — **the machinery already exists** (`patch detour`, `trampoline.rs`, undo journal) | per-process, driver-free, exact buffers as the app hands them over | post-encryption if the title encrypts above the socket; hooking is a mutation |
| **App detour** | hook the title's own serialize/deserialize routine, found with the existing static pipeline | plaintext structures *before* any encryption, and the natural provenance anchor | needs that function found first — i.e. the normal RE loop, which is the part N0xis is already good at |
| **ETW** | `Microsoft-Windows-Winsock-AFD` / `-TCPIP` providers | per-PID socket events with **no injection whatsoever** | metadata-rich, payload-poor; needs a session and elevation |

Note the ordering is not the obvious one: the highest-value route is the *app-level* detour,
and it is the one that depends on work N0xis already does well. Encryption is not an obstacle
to be defeated — in a build you own you hook above it, where the plaintext already is.

### The seam (crate layout, and the boundary law)

- `crates/n0xis-net` — a **new crate outside the pure trio**. `scripts/check_boundary.sh`
  must gain the transport crates to its `FORBIDDEN` regex **in the same change**, or the
  boundary law silently weakens on the day this lands. Treat that line of the script as part
  of the phase's definition of done, not as cleanup.
- The abstraction mirrors `MemorySource`: a **`FrameSource`** trait — implementations for a
  live capture, a pcap file, and a `.n0x/` replay journal. Every analysis pass is written
  against the trait, so all of them are testable offline against a recorded capture exactly
  as the core is testable against `Snapshot` today. This is the item that decides whether the
  phase is maintainable; get it right before writing a single capture backend.
- **Capture runs as a separate process** — the existing `RemoteAgent` / `PluginSession` shape
  (spawn an argv, newline-JSON over stdio). It is the part that needs privileges and the part
  most likely to die on a driver; it must not share an address space with the analyzer. This
  also keeps the ETW-vs-WinDivert-vs-pcap choice an implementation detail behind an argv
  instead of a compile-time dependency of N0xis. **Depends on the per-plugin timeout debt**
  recorded above — a capture plugin is long-running by definition, and the global 10 s
  constant forecloses it.
- Schemas follow the standing policy: `n0xis.net.*.v1`.

### Prioritized plan (leverage × cost)

0. ⬜ **Offline first — `net import <pcap|jsonl>` + `net frames`.** No capture, no hooks, no
   driver, no target, nothing privileged: a `FrameSource` over a file and the envelope shape.
   Same trick as Phase 12's item 0 — it fixes the schema before anything that can crash a
   game exists, and from here on every later item is testable against a checked-in capture.
1. ⬜ **`net dissect` / `net diff` — field inference by differential capture.** This is
   `scan filter`'s narrowing algorithm applied to frames instead of an address space: record
   two sessions differing by one deliberate action, keep the bytes that changed, repeat.
   Field offsets, widths and candidate types fall out of it. Conceptually the same engine as
   the value scanner — **do not write a second one.**
2. ⬜ **`net capture --pid`, API detour then app detour.** Ship the `ws2_32` variant first: it
   works with zero prior RE and proves the live path end to end. Then the "hook this
   function" variant, which is where the plaintext and the provenance anchor both live. Both
   land in the existing undo journal like every other mutation — a capture hook is a patch,
   and it must be removable by `patch undo` on the same terms.
3. ⬜ **`net provenance` — the point of the phase, and the reason to do the phase at all.** Frame
   field → the memory address it was serialized from → the function that wrote that address,
   through the watchpoint + unwinder + decompiler stack that already exists. Sequence this as
   early as its dependencies allow, exactly as Phase 12's managed provenance is sequenced —
   it is the item a third party cannot copy without also owning a watchpoint engine and an
   unwinder, and without it this phase is a worse Wireshark.
4. ⬜ **`net replay` — deterministic re-send of a recorded session against a server you
   operate.** Replay with one field mutated; record whether the server accepted it. Output is
   a pass/fail matrix over mutated fields — the server-authority test from the framing above.
   This is the single most valuable thing a studio can run against its own build before ship,
   and the artifact is a report, never a payload.

### What this phase deliberately does **not** build

- **No MITM proxy against third-party servers**, no TLS interception, no certificate
  injection. In a build you own you hook above the crypto, which is both easier and the only
  framing this project accepts.
- **No anti-cheat evasion, no traffic obfuscation, and no injection into titles you do not
  operate.** Out of scope permanently — not "later", not behind a flag.
- **No protocol emulation or server reimplementation.** Replay goes against a real server you
  run. Rewriting someone's server is a different project with a different license question.
- **No general network-security tooling.** Not a port scanner, not a fuzzer-for-hire, not a
  traffic generator. The scope is one process's own traffic and its join back to that
  process's code; anything that does not need the join belongs in Wireshark, and should be
  sent there.

### Framing rules this phase encodes

- **Capture is a source, not a feature.** Frames enter through a trait the same way bytes
  enter through `MemorySource`, so the analysis half never learns whether it is looking at a
  live socket, a pcap, or a journal — and stays testable without a network.
- **The join is the product.** Bytes on the wire are a commodity that four free tools already
  print. The map from a wire field back to a named function is not, and every design choice
  here should be settled by asking which option preserves that map.
- **A test result is not an exploit.** Anything this phase emits about a server answers
  "did the check hold", and is shaped so that the answer is the deliverable.

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
- ⏳ **The rest of the surface** — 87 leaf commands exist; 41 capabilities are registered.
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

- ⬜ **CLI/MCP parity** — 87 CLI leaf commands vs ~20 MCP tools. Closes as a side effect of
  the registry migration above; not worth hand-writing 65 more `#[tool]` methods.
- ⬜ **Event sourcing is partial** — patch journal (`.n0x/patches/`) and per-address
  annotation history, but no shared op-log. Fine for undo; insufficient if replication or
  agent-visible history is ever wanted. Deliberate, not forgotten.

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
  default. This is a hard blocker for any long-running plugin, and Phase 13's capture
  process is exactly that shape.

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
- **Phase 13 is independent of 10 and 12, and compounds with both.** It needs nothing from
  the decompiler-depth work and nothing from IL2CPP — item 0 is a file parser and a schema.
  But its payoff *multiplies* with 12: `net provenance` on a Unity target reports native
  `sub_…` frames without the managed layer and C# method names with it, which is the same
  artifact at two wildly different levels of usefulness. If both are on the table, 12 first.
  Within 13, ship item 0 before anything that can touch a running game, and drive to item 3
  (`net provenance`) as early as its dependencies allow — items 0-2 are table stakes that
  several free tools already cover, and item 3 is the only one that is N0xis-shaped.
- **The architectural debts are not a work item — they are triggers.** Do not schedule a
  "seams sprint". Each one names the change that should force it: the format seam lands as
  the *first commit of the second container format*, the VM seam as the first commit of the
  second scripting runtime, `Arch::capabilities()` when ARM64 verification starts (it is the
  thing that makes the verification legible), and the per-plugin timeout as a prerequisite
  of Phase 13's capture process. Recorded now so the trigger is recognized when it arrives,
  rather than discovered as a two-week detour halfway through the work that tripped it.

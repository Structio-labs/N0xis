# N0xis — Capability registry (living)

A registry of the capabilities that sit on the static⇄dynamic seam, each entry
with its scope analysis and an honest status. Kept current rather than written
once: an entry is downgraded when its capability stops being distinctive to this
design, and each one carries its own caveats.

**This project does not compare itself to other tools.** An entry states what a
capability *is*, what problem it solves, what evidence backs it, and what is
still unverified — nothing about anyone else's product.

See [`../CONCEPT.md`](../CONCEPT.md) §11 for the summary; this file holds the detail.
The runnable command surface for everything referenced here is
[`CLI_COMMANDS.md`](CLI_COMMANDS.md); the method-first thinking behind the Phase 8
tooling comes from a real RE campaign's post-mortem, written up in
[`../ROADMAP.md`](../ROADMAP.md)'s Phase 8 section.

---

## The review loop (how entries are produced)

Run this per capability area, repeatedly, as N0xis grows:

1. **Map the state of practice** — what do established static-analysis,
   debugging and live-memory workflows already cover here, and how well?
2. **Map us** — what does N0xis do (or plan to)?
3. **Find the gap** — which capability is not well covered anywhere the project
   has looked? The richest seam is
   **static⇄dynamic fusion** and **scriptable inspectability**, because that is
   out of reach for a GUI-first or single-world design without restructuring.
4. **Decide whether to fill it** — and whether the gap follows from an
   architectural choice or is simply unbuilt.
5. **Record it** here with rationale + status; link it to a ROADMAP phase.

**Entry statuses:** `idea` → `proposed` → `planned` (in ROADMAP) → `building` →
`shipped`. Also `parked` / `dropped` with a reason.

**Verification discipline (binding).** A `shipped` status says the code exists
and passes *its own* tests. It does **not** by itself say the feature was
verified against a live target. Where those differ, the entry says so explicitly: **`self-tested`** (unit
tests, no live target), **`live-verified`** (run against a real process/binary), and
distinct from "verified".

---

## Capability-area coverage matrix (top level)

| Area | What N0xis provides |
| --- | --- |
| Static analysis / decompiler | ✅ + inspectable passes |
| Types / structs / signatures | ✅ fused with scanning |
| Value scanning / filtering | ✅ peer of static |
| Pointer-path / AOB | ✅ **typed** paths (planned) |
| Find-what-writes | ✅ **+ auto-decompile** that code |
| Cross-process caller chain on a HW hit | ✅ **.pdata/.xdata unwind from outside** |
| Persistent table | `.n0xt` + code/type/provenance links |
| Survive game updates | ~ **anchors + `sig validate`** (self-heal planned) |
| Localize an unknown value | ✅ **"the change is the signal"** as a primitive |
| Localize an on-screen UI element in memory | ✅ **hit-test the target's own scene graph** (WT) |
| Game-engine assets (Bitsquid) + LuaJIT | ✅ **static bundles + live VM introspection** |
| Scriptability | ✅ CLI+MCP, deterministic JSON |
| Live⇄static reconciliation | ✅ **automatic** |
| Windows **and** Linux, PE **and** ELF in one pipeline | ✅ same passes, same JSON, both formats |

---

## Registry

### KF-1 — Provenance-Driven Memory Intelligence  ·  status: `shipped` (Phase 4c, live-verified for value→meaning)
- **What it solves:** closing the value⇄code⇄meaning loop automatically, in one command.
- **Feature:** (a) *value → meaning*: scan → find-what-accesses (HW watchpoint) →
  `VA→module+RVA→function` → SSA decompile → **the exact decompiled statement
  responsible**. Shipped as [`provenance trace`](CLI_COMMANDS.md) (schema
  `n0xis.provenance.v1`), exposed over both CLI and MCP (`provenance_trace`); the
  watchpoint × decompiler fusion is verified live. (b) *intent →
  verified change*: NL intent → locate → synthesize patch/table entry → apply →
  **verify live** → record in `.n0xt`. Part (b) is **composable today** from shipped
  pieces (`locate by-transition` → `patch apply` → `provenance trace
  --save-to-table`), but is **not yet a single command** — a documented follow-on, not
  a silent gap.
- **Why it matters:** requires spanning both worlds over one core — hard for single-world
  tools to copy. **Roadmap:** Phase 4c (done).

### KF-2 — Version-Resilient Anchors  ·  status: `building` (building blocks shipped; self-heal is `idea`)
- **What it solves:** no persistent, self-healing anchor that survives updates.
- **Feature:** each `.n0xt` entry stores not just an address/offset but an **AOB
  signature + an IR/pseudo-C fingerprint** of the surrounding function; on a new
  binary version, N0xis re-locates the anchor by matching the fingerprint and
  auto-repairs the entry (reporting confidence + diff).
- **What exists now:** the *ingredients* are shipped but not yet wired into
  auto-repair — `.n0xt` fixed-address **and** pointer-path locators (`table add`,
  freeze resolves both), `scan aob` for byte anchors, and
  [`sig validate`](CLI_COMMANDS.md) (Phase 8), which refuses to bless a signature from
  fewer than 3 deliberately-varied samples (so an anchor's invariance is *evidenced*,
  not assumed). The self-healing "re-locate by fingerprint on a new version" step is
  still `idea`.
- **Why it matters:** turns cheat tables from fragile to durable; only possible because
  we have both the byte-level and the semantic (IR) view. **Roadmap:** Phase 4b/4c
  (anchors) → ties into KF-6 (diff-driven repair).

### KF-3 — Typed Pointer-Path Fusion  ·  status: `idea` (untyped pieces shipped)
- **What it solves:** the two are never merged.
- **Feature:** annotate each hop of a discovered pointer path with the **recovered
  struct + field**, rendering `Player->stats->hp` instead of raw offsets; validate
  the typed path against the running process.
- **What exists now:** [`scan pointer-path`](CLI_COMMANDS.md) finds stable multi-level
  chains and [`scan dissect`](CLI_COMMANDS.md) heuristically types a region's fields;
  **fusing** the two (typed hops) is the unbuilt part.
- **Why it matters:** readable, self-documenting, and robust to struct-layout changes.
  **Roadmap:** Phase 4b (with Phase 4 types).

### KF-4 — Snapshot-Diff Causal Attribution  ·  status: `building` (localization half shipped)
- **What it solves:** no "what changed when I did X, and which function did it" in one step.
- **Feature:** snapshot memory before/after an in-game action, diff, then correlate
  each changed region with the writing function (via find-what-writes + decompile),
  producing an agent-readable causal report.
- **What exists now:** the *diff* half is shipped and live-verified as
  [`locate by-transition`](CLI_COMMANDS.md) (snapshot → operator toggles one thing →
  rescan → keep only what changed; see KF-7), and `snapshot dump` captures reloadable
  regions. The *causal* half — auto-correlating each survivor with its writing
  function — is done manually today by handing a survivor address to `provenance
  trace`; folding both into one report is the remaining work.
- **Why it matters:** fuses dynamic diffing with static explanation. **Roadmap:** Phase 4c+.

### KF-5 — Explainable Decompilation  ·  status: `shipped` (Phase 3)
- **What it solves:** you can't ask "why is this condition `x>4`?" / "what did DCE remove?".
- **Feature:** every pass (SSA, propagate/fold, DCE, structuring) emits an
  **inspectable JSON delta** (`n0xis.opt.delta.v1`, `n0xis.ir.ssa.v1`); agent-facing
  "explain" tools surface the reasoning.
- **What exists now:** `decomp pseudo --style ssa` (the default) runs the optimizing
  SSA pipeline and embeds the per-pass delta; the MCP `explain_opt_delta` tool returns
  *only* that delta. Additional inspection via `ir value-set` / `ir deobfuscate`
  (value-set-provable opaque predicates + junk).
- **Why it matters:** you can interrogate the decompiler's reasoning instead of
  only reading its answer.
  **Roadmap:** Phase 3 (done) (+ MCP explain tools in Phase 5, done).
- **⚠️ caveat:** the SSA optimizer + flag-precise conditions are **x64-only**; ARM64 is
  implemented and self-tested for CFG/discover/xref/goto+structured decompile, **not
  verified to x64's standard** — say "implemented and self-tested", never "verified".

#### What the output actually reads like

A raw string-scan loop from a **real MSVC binary** (Kenshi's `CompressToolsLib.dll`),
`decomp pseudo --style ssa`:

```c
uint64_t sub_180002380(struct_rcx_0 *rcx, uint64_t rdx) {   // recovered pointer parameter type
    v1 = -0x1;
    while ((*(uint8_t*)(rdx + v1) != 0x0)) {   // a strlen scan — ONE named counter,
        v1 = (v1 + 0x1);                       // not rax.1 / rax.2 / rax.3 SSA noise
    }
    r8.1 = rcx->field_0x18;                    // struct fields, not *(rcx+0x18)
    rcx.1 = rcx->field_0x10;
    if ((v1 > /*u*/ (r8.1 - rcx.1))) {
        return sub_1800033e0(rcx, v1, r8.1, rdx);
    } else { /* … */ }
}
```

That readability is the product of the whole SSA pipeline — Memory-SSA, variable coalescing
into named locals, complete SSA destruction (no undefined temporaries), branch conditions
rebuilt from `dec`/`sub`/`and` flags, and pointer/struct parameter typing — and **every one of
those passes emits a checkable delta** (`--explain`), so a claim is auditable, not taken on
faith. Verified on real AAA binaries across compilers and engines: **Kenshi** (MSVC), an
**Unreal Engine 5** shipping build, **Factorio** (GCC/System V), and a **Bevy/Rust** title —
PE and ELF alike.

**This is a real optimizing decompiler, not an automation wrapper.** The honest remaining
ladder — full type recovery, compiler-idiom lifting, more architectures — is written down rung
by rung in [ROADMAP.md](../ROADMAP.md). Layered on top of it: the live⇄static seam, cross-platform
reach, the inspectable per-pass delta, and a scriptable JSON surface a human pipes through `jq`
or an agent drives over MCP — equally.

### KF-6 — Cross-Version Binary Diffing (semantic)  ·  status: `building` (function diff shipped)
- **What it solves:** no agent-friendly "what changed between game v1.2 and v1.3, semantically,
  and what does it mean for my anchors/cheats".
- **Feature:** diff two binaries at the IR/pseudo-C level, emit a structured change
  report, and auto-flag which `.n0xt` anchors are affected (ties into KF-2).
- **What exists now:** [`diff functions`](CLI_COMMANDS.md) (Phase 7, schema
  `n0xis.diff.v1`) decompiles two functions from two sources/addresses and diffs their
  pseudo-C line-by-line (default `--style goto` for stable/deterministic diffing). The
  **auto-flag-affected-anchors** step (the KF-2 tie-in) is not built yet.
- **Why it matters:** closes the loop between "game updated" and "my tools still work".
  **Roadmap:** Phase 7+ (function diff done; anchor-impact reporting open).

### KF-7 — Spec-First Method Tooling ("the change is the signal")  ·  status: `shipped` (Phase 8, live-verified; 6/7 landed, merged to main)
- **What it solves:** the reliable RE *techniques* live in tutorials and muscle memory, not in the
  tool surface. An agent can't invoke "the technique that reliably returns exactly one
  result".
- **Feature:** a category of commands that encode named RE methods (post-mortem
  written up in [`../ROADMAP.md`](../ROADMAP.md)'s Phase 8 section), each with a
  deterministic JSON schema:
  - [`locate by-transition`](CLI_COMMANDS.md) — snapshot → operator toggles one thing →
    rescan → keep only what changed; **the only localization technique that reliably
    returns exactly one result** (RE_METHOD W1). Supports structural predicates over
    survivors (`--expect`/`--min`/`--max`) and a scripted `--wait-ms`. *Live-verified*
    (13.6M → 19k survivors on a real narrow).
  - [`game grep`](CLI_COMMANDS.md) — rank scripts/data/strings by how densely they
    cluster a concept's vocabulary (LuaJIT bytecode auto-decoded to text) — start from
    *meaning* instead of an address.
  - [`input probe`](CLI_COMMANDS.md) — try each actuation method, report which the OS
    input stack registers and whether each carries the `LLKHF_INJECTED` flag a target
    may filter (RE_METHOD F4). *Live-verified* (the injected-flag finding).
  - [`const identify`](CLI_COMMANDS.md) — recognize canonical magic constants (LCG
    multipliers, hash seeds, CRC polys, float normalizers) from a value, a function's
    literals, or a Lua chunk (RE_METHOD W3). *Live-verified* (`0x5bd1e995` → Murmur2).
  - [`bindings list`](CLI_COMMANDS.md) — pair name strings with function pointers to
    list a script VM's native bindings (RE_METHOD W2). *Live-verified* on `n0xis.exe`.
  - [`sig validate`](CLI_COMMANDS.md) — report invariant bytes across samples; **refuse
    to bless a signature from fewer than 3 deliberately-varied samples** (RE_METHOD F3).
    *Live-verified* (N=2 refused, N=3 blessed).
- **Why it matters:** these are **method-as-tooling** — the difference between a human
  knowing the trick and an *agent* being able to call it deterministically. "The change
  is the signal" (`locate by-transition`) in particular is a one-command primitive no
  manual procedure rather than a single command.
- **Status detail:** 6/7 named commands **DONE and merged to `main`** (commit
  `a0a9168`); the one **open** Phase-8 item is **region caching as a built-in scan
  option** (⬜).  "not exposed as a command elsewhere" statement is a design judgement, not a
  measured survey. **Roadmap:** Phase 8.

### KF-8 — Position-by-Region UI Localization  ·  status: `building` (working-tree; implemented + self-tested, **pending live validation**)
- **What it solves:** nothing maps a **screen rectangle → the addresses of the scene-graph nodes
  that draw there** without touching the render pipeline.
- **Feature:** [`ui locate --rect`](CLI_COMMANDS.md) enumerates live UI elements whose
  bounding box intersects a screen rect by **hit-testing a live target's own retained
  scene-graph AABBs from outside** — no graphics-API hooking, no frame capture, no
  pixels. Built on the internal **structural-predicate scanning** primitive
  (`n0xis-core::structural`, schema `n0xis.scan.structural.v1`) — a scan that matches on
  *relations between fields* (e.g. an AABB whose min ≤ max in each axis, finite,
  plausibly-scaled) rather than a single value. `--space auto` probes screen-pixel vs
  NDC coordinates and reports the observed range; a `--save-as`/`--exclude-from`
  spatial-diff workflow isolates what's specific to a rect vs. ambient AABB-shaped
  structures. Exposed over both CLI (`cmd_ui_locate`, schema `n0xis.ui.locate.v1`) and
  MCP (`ui_locate`).
- **Why it matters:** position-by-region hit-testing of a program's *own* scene graph, from
  a separate process, with no render-path instrumentation.
- **⚠️ status detail (be precise):** **working-tree / uncommitted** — not on `main`, not
  in the installed binary (installed `n0x guide` = 77 commands; a rebuild = 78). The
  predicate and the overlap maths have **real unit tests** (`structural.rs` 3 tests,
  `ui_locate.rs` 8 tests over synthetic `Snapshot`s — known AABB found at overlap 0.25
  exactly, `FLT_MAX` sentinels rejected, per-space size floors). The size-floor was also
  tuned against **one live scan of an *empty* process** (predicate false-positive
  tuning). But the **decisive live appearance-correlation test** (query a rect while an
  element is visible vs. hidden, intersect two snapshots, cross-check a second element)
  has **not** run. Say **"implemented, pending live-target validation"** — never
  "verified". *Scope claim unaudited.* **Roadmap:** Phase 9 (⏳).
- **Note:** `scan structural` is **not** a runnable CLI subcommand — it is the
  core-internal primitive `ui locate` configures. Do not document it as a command.

### KF-9 — Game-Engine Asset & Live-Script Layer (Bitsquid/Stingray + LuaJIT)  ·  status: `shipped` (offline tooling self-tested; live GCstr/GCtab introspection implemented and self-tested, not yet live-verified)
- **What it solves:** no single toolkit does **static engine-asset extraction + offline bytecode
  editing + live in-VM introspection** alongside native RE, over one JSON envelope.
- **Feature:** a two-sided engine layer, all `n0xis.*.v1`-tagged:
  - **Static / offline:** [`bundle list/extract/repack`](CLI_COMMANDS.md) for
    Bitsquid/Stingray bundles (type/path-hash, variants, `.stream` pairing, same-length
    repack), and [`lua disasm`/`lua patch`](CLI_COMMANDS.md) — a LuaJIT 2.0 bytecode
    disassembler that auto-detects source/stock/LuaJIT bytecode and patches one
    instruction's raw word in place.
  - **Live / in-VM:** [`lua strings`](CLI_COMMANDS.md) finds live `GCstr` objects by
    decoding the real object header (no per-string byte pattern);
    [`lua table`](CLI_COMMANDS.md) decodes a live `GCtab` (array + hash parts, string
    values resolved) by walking the object graph with **pure memory reads, no
    debugger**; [`lua combo`](CLI_COMMANDS.md) reads an array of known strings out of
    the heap layout-independently; [`lua seedscan`](CLI_COMMANDS.md) recovers an LCG
    seed from an observed sequence, locating the seed field and validating the RNG model
    at once.
- **Why it matters:** static asset RE and *live* script-VM introspection under the same
  scriptable surface, with the live side needing no debugger attach — a combination no
  one place. The live GCstr/GCtab introspection (`lua strings`/`lua table`) is
  implemented and self-tested against synthetic buffers — **not yet run against a live
  game**. What *is* exercised in the field is the HUD's live LuaJIT-*bytecode* path: the
  AOB-anchored infinite-mags patch and the seed-driven combo solver, which reads the seed
  via a direct offset memory read and borrows only `n0xis_luajit::Lcg` (the LCG math), not
  the object-introspection decoders. **Roadmap:** landed with the Bitsquid/LuaJIT adapters
  (commits `4cc5f4e`, `d6580f2`).- **Boundary note:** `n0xis-bitsquid`, `n0xis-lua`, and `n0xis-luajit` are **not**
  depended on by `n0xis-core` (the core stays engine-agnostic and OS-free) — the engine
  layer is a pluggable seam, which is *why* it can grow without touching the analysis
  core.

### KF-10 — Cross-Process Stack Unwinding on a Watchpoint Hit  ·  status: `shipped` (live-verified)
- **What it solves:** on a find-what-writes hit you get an instruction address, not "who called the
  function that did this".
- **Feature:** a **pure cross-process x64 stack unwinder** driven by the target's PE
  exception tables (`.pdata` → `.xdata` unwind codes). On a `debug watch` /
  `provenance trace` hit it reconstructs the **true caller chain** (each frame resolved
  to module + function), rather than a naive stack-scan guess. Pairs with **authoritative
  `.pdata` function discovery** (`function discover --pdata`: every function with unwind
  info, exact start+end, no heuristic and no cap) so the frames land on real function
  boundaries.
- **Why it matters:** it turns the KF-1 provenance hit from "an address" into "a
  named call stack", cross-process, with no in-process agent and no symbols required —
  which a raw scanner hit does not carry.
- **Status detail:** **shipped and live-verified** (commit `d1231be`; `.pdata` discovery
  `52bb491`). Also underpins the conditional watchpoint (`debug watch --when
  <reg>=<value>`, `MAX_CONDITION_MISSES=300` guard) — though that `--when` path is
  **working-tree/uncommitted** and the guarded conditional route has **not** been
  re-run against a live target post-guard, so treat `--when` as *implemented, not
  live-verified*. **Roadmap:** Phase 4b/4c (unwind) + Phase 9 (conditional `--when`, WT).

---

## Adjacent surface worth naming (not yet its own KF)

- **N0xHUD — a companion window over the same engine.** A third frontend
  (`n0xis-hud`) that is a plain always-on-top `eframe`/`egui` window sitting beside the game rather than inside it, **not** an in-game overlay and **not** framed as a trainer: it drives the same
  crates for **runtime instrumentation** — process-watcher auto-apply, write-and-freeze
  (incl. pointer-path locators), an AOB-anchored live LuaJIT-bytecode patch adapter,
  Interception kernel-driver key actuation (for titles that filter `LLKHF_INJECTED`
  `SendInput`), and a **seed-recovered interact-combo auto-solver** (read a generator
  seed from live memory → recompute the deterministic sequence → actuate + verify each
  step; mines solved *exactly* from the seed, never brute-forced — the universal
  any-object mode is a separate opt-in, **implemented, pending live validation**). It
  exists precisely to show that a GUI, if it lands, is a *thin visualization layer over
  the ok/data/meta artifacts* — not a rewrite of the CLI/MCP core. Not promoted to a KF
  because its edge is "the CLI's power, live and on-screen" rather than a distinct
  capability of its own; the interact-combo solver is the part most worth eventually
  writing up on its own.

---

## How to add / update an entry

Append a new `### KF-N — <name> · status: <status>` block with the five loop fields
(Context / Gap / Feature / Why it matters / Roadmap), plus a **What exists now** line
when the shipped subset differs from the full vision, and an explicit **verification
state** (`self-tested` / `live-verified`, and
working-tree vs merged). Keep the top matrix in sync. Promote status as work progresses.
When an entry ships, keep it here (mark `shipped`) — the registry is also the record of
*why* each capability exists. Never let a `shipped` flag silently imply the
capability was verified live or that the feature was validated live; if it wasn't, say so.

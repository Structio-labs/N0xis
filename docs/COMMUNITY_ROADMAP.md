# Community Roadmap — claimable work

This is the task list for anyone besides the core maintainer(s). It's separate
from [ROADMAP.md](../ROADMAP.md) (the phased build history — what already
shipped and why) on purpose: that document is a record; this one is a queue.

**Read [CONTRIBUTING.md](../CONTRIBUTING.md) first** — it explains how claiming
actually works (short version, pre-launch: open a PR flipping `Status` below to
`Claimed — @you`; post-launch: this list becomes GitHub Issues with labels, and
claiming works the normal GitHub way).

Every entry below traces back to a spot in `ROADMAP.md` or the code where the
gap is explicitly documented — none of this is guesswork about what might be
missing; it's the project's own honest "not attempted, here's why" notes,
collected into one place.

The Phase 8 spec-first method commands (`game grep`, `locate by-transition`,
`input probe`, `const identify`, `bindings list`, `sig validate`) have **landed**
and are documented in [CLI_COMMANDS.md](CLI_COMMANDS.md) — they are no longer
claimable. Phase 9's `ui locate`, the structural-predicate scan primitive it's
built on (`n0xis-core::structural`, an internal engine — **not** a runnable
`scan structural` command), and the conditional hardware watchpoint
(`debug watch --when`) are **implemented in the working tree** (unit-tested
against synthetic snapshots, pending live-target validation — not yet on `main`)
and likewise off this list. What's below is what's still genuinely open.

Labels follow [Bevy](https://github.com/bevyengine/bevy)'s shape, scaled down:
**A-** (area), **D-** (difficulty: `Trivial` → `Complex`), **S-** (status).

---

## Architecture ports

The `trait Arch` seam ([`n0xis-arch/src/lib.rs`](../crates/n0xis-arch/src/lib.rs))
exists precisely so a new architecture is "implement one trait," not "touch
`n0xis-core`." `n0xis-arch::Arm64` ([`arm64.rs`](../crates/n0xis-arch/src/arm64.rs))
is the reference implementation and the template for *scope*: it deliberately
implements `decode`/`decode_stream`/`reg_access` for the base integer ISA and
leaves `lift`/`branch_condition`/`detect_switch` at the trait's sound defaults
rather than half-modeling flag semantics for a second ISA in one pass — a new
port doesn't need to do more than that to be a real, mergeable contribution.
**It is not yet the template for "verified enough"** — its own `reg_access`
had a real bug that only real compiler output caught (see `ROADMAP.md` Phase
7); test any new port against genuine cross-compiled code, not just
hand-picked instruction words, before calling it done.

Before starting: find a decoder crate that matches `disarm64`'s bar — pure
Rust, no `unsafe`, no C dependency, no `windows-sys`-style OS linkage (the
`n0xis-arch` boundary test requires `n0xis-core` to stay OS-free; the decoder
itself living in `n0xis-arch` is fine either way). If none exists for your
target ISA, that's worth flagging before investing implementation time.

| Target | Area | Difficulty | Status |
|---|---|---|---|
| ARM32 / Thumb-2 | `A-Arch` | `D-Complex` (two encoding modes) | Open |
| MIPS (32/64) | `A-Arch` | `D-Modest` | Open |
| PowerPC | `A-Arch` | `D-Modest` | Open |
| RISC-V (32/64) | `A-Arch` | `D-Modest` (very regular encoding, likely the easiest real-world target after ARM64) | Open |
| AVR (8-bit micro) | `A-Arch` | `D-Straightforward` | Open |
| 6502 / Z80 (retro) | `A-Arch` | `D-Straightforward` (small ISAs, good first port) | Open |

### ARM64 depth (extending what's already there)

**Before adding depth, the existing base coverage needs more real-world
verification — it's implemented and self-tested, not battle-tested.** One
ad-hoc test against genuine LLVM-compiled AArch64 code (not the hand-picked
bytes the unit tests use) already found and fixed a real `reg_access` bug
(the `sp`-vs-`xzr` aliasing of register 31; see `ROADMAP.md`'s Phase 7
write-up) that the passing unit tests + a passing exit test had missed.
**A genuinely valuable, claimable task on its own**: run
`n0xis function discover`/`ir build`/`decomp pseudo --arch arm64` against
larger real ARM64 binaries (more cross-compiled Rust/C programs, a real
ARM64 Windows PE if you have access to one) and file/fix whatever else turns
up — this doesn't need new features, just more real bytes thrown at what
already exists. This is the top-priority open item for the ARM64 track: until
it's done, the whole ARM64 path stays "implemented and self-tested," never
"verified." `A-Arch` / `D-Straightforward` / `S-Ready-For-Implementation`.
Status: Open.

- **`Arch::lift`/SSA optimization parity with x64** — `n0xis-arch/src/x64_lift.rs`
  is the template (typed micro-IR + flags-as-a-real-dataflow-value). Comparable
  effort to the original Phase 3 work. `A-Arch` / `D-Complex`. Status: Open.
- **`Arch::branch_condition` for ARM64** — flag-precise conditions are x64-only;
  ARM64's `NZCV` condition model needs its own lifter before conditional-edge
  labelling and structured decompilation match x64's fidelity. Naturally paired
  with the `lift` work above. `A-Arch` / `D-Complex`. Status: Open.
- **`Arch::detect_switch` for ARM64** — ARM64 jump-table idioms differ from
  x64's two (`switch.rs`'s `SwitchKind::MemIndexed`/`RegRel32`); needs its own
  idiom recognition. `A-Arch` / `D-Modest`. Status: Open.
- **SIMD/FP/crypto/SVE `reg_access` coverage** — currently reports empty
  reads/writes for these classes (sound, just incomplete). `A-Arch` /
  `D-Modest`. Status: Open.
- **More `prologues()` patterns / structural (not just exact-byte) discovery**
  for functions that don't start with the four `stp x29,x30,[sp,#-N]!` sizes
  currently listed. `A-Arch` / `D-Trivial`. Status: Open.

---

## Plugin system (design + implementation)

**The biggest item on this list.** No implementation exists yet — this is a
proposed design, open for discussion before (or during) implementation.

**Why process-based, not dynamic libraries.** Rust has no stable ABI, so a
`cdylib`-loaded plugin locks a third party to the exact compiler version and
crate layout the host was built with — fragile in practice, and it would
reintroduce `unsafe` at the plugin boundary this project has otherwise avoided.
This project already has a working precedent for a better shape:
`n0xis-sources::remote`'s newline-JSON-over-stdio protocol
([`remote.rs`](../crates/n0xis-sources/src/remote.rs)) and the MCP frontend
itself are both "a separate process speaks a small JSON protocol over stdio" —
the same idea a plugin needs, already proven out twice in this codebase.

**Proposed first extension point: analysis-result plugins.** A plugin is an
executable registered in `.n0x/plugins.json` (name → command/argv, mirroring
how `--remote-cmd` is just an argv). Given an artifact (a `CfgArtifact`,
`PseudoFunction`, or `DiscoverArtifact` — whichever the plugin declares it
handles) as JSON on stdin, it returns additional findings as JSON on stdout:
extra annotations, vendor-specific signature matches, game-specific heuristics
— without needing a Rust PR against `n0xis-core` at all. `n0xis-pipeline`
would gain a `PluginHost` that shells out to registered plugins after a pass
runs and merges their findings into the response under a `plugins` key,
additive to the existing schema (never replacing core fields — CONCEPT §3
rule 6 again: a plugin's opinion is additional information, not authoritative
over the core analysis).

**Deliberately not proposed yet: architecture-via-plugin** (a decoder plugin
receiving raw bytes over stdio instead of a native `impl Arch`). Feasible in
principle with the same protocol shape, but a process round-trip per
instruction is a real performance concern for anything beyond prototyping —
worth a separate design discussion once the analysis-plugin shape is proven,
not bundled into the first cut.

**Concretely open for whoever picks this up:**
1. The wire protocol shape (request/response JSON schema, one artifact kind to
   start with).
2. `.n0x/plugins.json` registration format + a `plugin list`/`plugin add` CLI
   surface (mirroring `table`/`selection`'s existing storage pattern).
3. `n0xis-pipeline::PluginHost` — spawn, send, merge, with the same
   fail-open-but-visible posture the rest of this project uses (a plugin
   crashing or timing out degrades to "no plugin findings," never breaks the
   underlying analysis).
4. MCP exposure: a `plugin_list`/`plugin_run` tool pair, per Product Policy
   §3 (every capability, both frontends).

`A-Plugins` / `D-Complex` / `S-Needs-Design`. Status: Open.

---

## MCP parity gaps

The MCP server ([`n0xis-mcp`](../crates/n0xis-mcp/src/tools.rs)) exposes 18
tools today — the read-oriented static/dynamic workflow plus the working-tree
`ui_locate`. The stateful, cross-invocation verbs are the gap.

- **Mirror `scan`/`table`/`patch`/`debug watch` as MCP tools** — these CLI
  verbs bridge state across independent process invocations via `.n0x/dumps/`;
  the long-lived MCP server should use real in-memory session state instead of
  a straight port of that file-bridging (see `n0xis-mcp`'s module doc for the
  reasoning already written down). `A-MCP` / `D-Modest`. Status: Open.
- **Port the remaining single-shot verbs to MCP** — beyond the stateful set
  above, the broader static/dynamic surface isn't exposed yet either
  (`ir build/explain/dot/slice/manifest/value-set/deobfuscate`,
  `scan aob/pointer-path/dissect`, `selection`, `dump`, `snapshot`, `diff`,
  `bundle`, `lua *`, `game grep`, `locate by-transition`, `input probe`,
  `const identify`, `bindings list`, `sig validate`, `mem map`). Each is a
  near-mechanical wrapper around a verb the CLI already drives — good, low-risk
  first contributions. `A-MCP` / `D-Straightforward`. Status: Open.

## Binary diffing

- **Auto-match every function across two whole binaries** — `diff functions`
  today compares one already-identified pair; automatically matching by name
  (where symbols exist) and by structural similarity (where they don't — a
  well-studied problem class of its own) is a substantially larger,
  separate problem. `A-Diffing` / `D-Complex`. Status: Open.

## Deobfuscation extensions

- **Control-flow flattening detection/simplification** — `DeobfuscatePass`
  currently catches junk instructions and value-set-provable opaque
  predicates; flattening (a dispatcher loop + state variable replacing normal
  control flow) is a different, harder pattern, not attempted.
  `A-Decompiler` / `D-Complex`. Status: Open.
- **VM-protector/packer pattern recognition** — out of scope for the same
  reason. `A-Decompiler` / `D-Complex`. Status: Open.

## Static analysis follow-ons (from early phases, still open)

- **`function list`/`function info` + export/IAT enumeration verbs** —
  `function discover`/`trace` exist; a plain listing + export table view
  doesn't yet. `A-Analysis` / `D-Trivial`. Status: Open.
- **Relocation-aware / recursive `xref string` scan** — currently a single
  linear window. `A-Analysis` / `D-Modest`. Status: Open.
- **Stack-passed argument (5+) type recovery** — `TypeInferPass` recovers
  arity/types for register-passed args (Win64 args 1-4); stack args need
  precise `rsp`-delta tracking through prologues that Phase 3's `lift`
  deliberately doesn't model yet. `A-Types` / `D-Modest`. Status: Open.

## Dynamic memory

- **Region caching as a built-in scan option** — the one remaining Phase 8
  ergonomics item (`ROADMAP.md`), and the last open piece of Phase 8. A scan
  against a live process with no `--start` re-enumerates every committed
  writable region on every call, so a `scan value` → `scan filter` →
  `scan filter` loop pays that enumeration cost each pass. Caching the
  discovered region set as an opt-in scan flag — invalidated on module
  load/unload so it can never narrow onto a stale map — would cut the
  steady-state cost without changing results. N0xHUD's interact-combo solver
  already does exactly this ad-hoc for its own pool region
  (see [`n0xis-hud`](../crates/n0xis-hud/)); this task
  promotes it to a first-class `scan` option. `A-DynamicMemory` / `D-Modest`.
  Status: Open.
- **Smarter `alloc_code_cave` placement** — currently a plain `VirtualAllocEx`
  with no "near this address" search, so `patch detour`'s rel32-range check
  correctly *refuses* rather than corrupts a jump when the cave lands too far
  from the hook site (the safety property works), but a smarter allocator
  would refuse less often. `A-DynamicMemory` / `D-Modest`. Status: Open.
- **Capture a `snapshot dump` directly from a `--remote-cmd` target** —
  `snapshot dump` currently accepts `--pid`/`--file` only, not
  `--remote-cmd`. `A-DynamicMemory` / `D-Trivial`. Status: Open.
- **Feed the unwound caller chain into `provenance trace`** — `BreakpointHit`
  now carries real unwound `frames` (`n0xis-sources::unwind`), but
  `provenance trace` still explains only the hit instruction itself. Walking one
  frame up to decompile the *caller* of a writing instruction (e.g. a generic
  clamping setter's specific caller) through the SSA pipeline is the natural next
  step. `A-DynamicMemory` / `D-Modest`. Status: Open.
- **Root-cause the provenance detach/re-attach hang** — repeated
  `provenance trace` / `debug watch` cycles can hang around the debugger
  `DebugActiveProcessStop` → re-`DebugActiveProcess` path (or a lingering
  suspended thread / DR state). Not yet diagnosed. `A-DynamicMemory` /
  `D-Modest`. Status: Open.
- **ARM64/AArch64 stack unwinding** — the x64 unwinder
  (`n0xis-sources::unwind`) is `.pdata`/`.xdata`-specific; AArch64 Windows uses a
  different unwind-code encoding. A sibling implementation would extend the true
  caller chain to ARM64 targets. `A-DynamicMemory` / `A-Arch` / `D-Complex`.
  Status: Open.

## Infrastructure

- **CI** (GitHub Actions: build + test matrix on every push/PR). No workflow
  exists yet. `A-Infra` / `D-Trivial`. Status: Open.
- **A decompilation-quality benchmark harness** — run the pipeline over a fixed
  public-binary corpus and publish *absolute* per-function metrics (coverage,
  error rate, quality score) so releases are comparable **to each other** over
  time. This project does not publish comparisons against other tools.
  `A-Infra` / `D-Modest`. Status: Open.

## GUI

Explicitly deferred, not ruled out (see [README.md](../README.md)). Needs a
design discussion before implementation work starts — likely a thin
visualization layer over existing `ok/data/meta` artifacts (CFG/DOT rendering,
decompiled output, the analysis DB), not a rewrite of the CLI/MCP-drivable
core. N0xHUD already exists as a third frontend of exactly that shape (a window
over the same crates), so any GUI would be sibling to it, not a replacement.
`A-GUI` / `D-Complex` / `S-Needs-Design`. Status: Open, not yet scoped.

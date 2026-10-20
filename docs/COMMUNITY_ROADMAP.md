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

The Phase 8 spec-first method commands (`concept grep`, `locate by-transition`,
`input probe`, `const identify`, `bindings list`, `sig validate`) have **landed**
and are documented in [CLI_COMMANDS.md](CLI_COMMANDS.md) — they are no longer
claimable. Phase 9 (`ui locate`, screen region → memory) is **marked invalid**:
the capability is not implemented on real targets, so that work is open again.
What's below is what's still genuinely open.

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

**Half built.** A plugin can be registered, listed and removed from the CLI,
listed from MCP, and run by name from both; nothing runs one after a pass yet,
so no command's answer carries plugin findings.

**Why process-based, not dynamic libraries.** Rust has no stable ABI, so a
`cdylib`-loaded plugin locks a third party to the exact compiler version and
crate layout the host was built with — fragile in practice, and it would
reintroduce `unsafe` at the plugin boundary this project has otherwise avoided.
This project already has a working precedent for a better shape:
`n0xis-sources::remote`'s newline-JSON-over-stdio protocol
([`remote.rs`](../crates/n0xis-sources/src/remote.rs)) and the MCP frontend
itself are both "a separate process speaks a small JSON protocol over stdio" —
the same idea a plugin needs, already proven out twice in this codebase. The
plugin transport is built on the same line framing and process spawning as
`remote` ([`linewire.rs`](../crates/n0xis-sources/src/linewire.rs)).

**The first extension point: analysis-result plugins.** A plugin is an
executable registered under a name in `.n0x/plugins.json`, with its command
line (split the same way as `--remote-cmd`) and the artifact kinds it declares
it handles: `cfg`, `pseudo`, `discover` (`CfgArtifact`, `PseudoFunction`,
`DiscoverArtifact`; [`plugins.rs:19-32`](../crates/n0xis-project/src/plugins.rs)).
Given an artifact as JSON on stdin, it returns additional findings as JSON on
stdout: extra annotations, vendor-specific signature matches, target-specific
heuristics — without needing a Rust PR against `n0xis-core` at all. The design
merges those findings into a pass's response under a `plugins` key, additive to
the existing schema (never replacing core fields — CONCEPT §3 rule 6: a
plugin's opinion is additional information, not authoritative over the core
analysis); that merge is the part not built (item 3 below).

**Deliberately not proposed yet: architecture-via-plugin** (a decoder plugin
receiving raw bytes over stdio instead of a native `impl Arch`). Feasible in
principle with the same protocol shape, but a process round-trip per
instruction is a real performance concern for anything beyond prototyping —
worth a separate design discussion once the analysis-plugin shape is proven,
not bundled into the first cut.

**What exists:**
- **The stdio transport**
  ([`n0xis-sources/src/plugin.rs`](../crates/n0xis-sources/src/plugin.rs)):
  `call_once` spawns the command, writes one JSON line, reads one JSON line
  back and waits for the process to exit, all inside one deadline that starts
  at spawn (`:224`; the 10 s `DEADLINE` every door passes, `:49`). A plugin
  that does not answer, or does not read its input, is killed and reaped at
  the deadline and reported as a timeout; one that answers and does not exit
  is killed at the deadline and its answer kept. The reply is one line of at
  most `MAX_REPLY_BYTES`, 4 MiB (`:83`), refused past it, never truncated; a
  reply of `null` is refused too (`NullReply`, `:106`), since handed on it
  was `{"ok":true,"data":null}`. The plugin's stderr is a pipe of its own,
  copied to the host's stderr by a thread nothing waits for
  (`forward_stderr`, `:324`): inherited, it was the host's own stderr, a
  plugin's child inherited it in turn, and a caller capturing the host's
  stderr got control back only when that child exited (measured through the
  CLI: an answer at 10 s, `subprocess.run(capture_output=True)` back at
  40 s; with the copier, on Linux, the capture is back at 10.02 s with a
  `sleep 40` grandchild still holding the plugin's stderr).
  `crates/n0xis-sources/tests/plugin_deadline.rs` runs each of these
  against a misbehaving plugin that is the test binary itself, on every
  platform the suite runs on — the two stderr cases on Unix only (see the
  open list below). A persistent `PluginSession`, for many requests to one
  process, sat beside it with no caller, no deadline and no bound on its
  reply; it was removed.
- **Registration**
  ([`n0xis-project/src/plugins.rs`](../crates/n0xis-project/src/plugins.rs)):
  add (overwriting by name), list, get, remove and select by kind, over
  `plugins.json` in the project's `.n0x/` (`:191-259`); outside a project the
  file is the global directory's (`n0xis-project/src/lib.rs:167-176`). A
  registry that does not exist is no plugins; one that exists and cannot be
  read or parsed is its own error, `RegistryUnreadable` (`:43-77`, read at
  `:79-182`), answered as `plugin-registry-unreadable` with the OS's or the
  parser's reason. That includes three states that answered "no plugins" or
  hung: an empty file (a registry with none is `[]`), a symbolic link to
  nothing, and anything that is not a regular file once links are followed —
  a FIFO there made every registry read block, so `capability list` and every
  MCP tool call hung. A save replaces the file whole — written beside it,
  flushed, renamed over it (`n0xis-project/src/store.rs:45`) — so an
  interrupted save leaves the old registry, not an empty one; a link is
  written through, the permissions are kept and a read-only file is refused,
  as the in-place write did.
- **The CLI** ([`n0xis-cli/src/main.rs`](../crates/n0xis-cli/src/main.rs)):
  `plugin add --name … --command … --handles …`, `plugin list` and
  `plugin rm --name …` (`:1523-1558`, run at `:4809-4837`).
- **The registry**
  ([`n0xis-frontend/src/registry.rs`](../crates/n0xis-frontend/src/registry.rs)):
  each registered plugin is a capability named `plugin.<name>`, registered
  through the same `Plugin` trait as the built-in capabilities (`:2596-2650`,
  composed with them at `:2664`). `capability list` shows it with its command
  and its declared kinds, and `capability run plugin.<name> --args '{…}'` sends
  those arguments as the request and returns the plugin's answer as `data`,
  under `n0xis.plugin.v1`. When the registry cannot be read, `capability list`
  carries it in `diagnostics` (`Diagnostic`, `:84-109`; listed by `describe`,
  `:196`) and `capability run plugin.<name>` answers that error instead of
  `unknown-capability` (`dispatch`, `:172`).
- **MCP** ([`n0xis-mcp/src/tools.rs`](../crates/n0xis-mcp/src/tools.rs)):
  `plugin_list`, the same payload as the CLI's `plugin list` (`:1044-1055`;
  `n0xis-mcp/tests/cross_door_parity.rs:408` compares the two doors), and
  `plugin_run`, which sends one registered plugin `{kind, artifact}`
  (`:1057-1077`); `capability_run` reaches `plugin.<name>` as it reaches a
  built-in. `cross_door_parity.rs:477` and `:518` hold the unreadable and the
  readable-but-absent registry on both doors.

**Concretely open for whoever picks this up:**
1. **The wire protocol shape — half done.** One JSON line each way is built;
   no schema states either side. `plugin_run` and `run_plugins_for` send
   `{kind, artifact}` (`tools.rs:1072`, `n0xis-pipeline/src/lib.rs:497`),
   `capability run plugin.<name>` sends its arguments as they are
   (`registry.rs:2640`), and whatever line comes back is the answer. The two
   ways to run a plugin also answer in two shapes under one schema:
   `plugin_run` as `{plugin, findings}` (`tools.rs:1074`), the capability as
   the plugin's line itself (`registry.rs:2641`).

   **What a reply is, as built:** data — the plugin's findings, any JSON
   value but `null` — and not an n0xis envelope. A reply of
   `{"ok":false,"error":{…}}` is findings that happen to carry those keys:
   every door answers it as a success with that object as its payload
   (`plugin_deadline.rs` pins this). A plugin reports a failure by exiting
   without writing a reply line, with a non-zero status: the host answers
   that as an error naming the plugin and its exit status (`plugin-failed` on
   `capability run`, `plugin-run-failed` on MCP `plugin_run`, the entry's
   `error` in `run_plugins_for`). What it writes to its stderr reaches the
   host's stderr, not the answer. Reading an `ok:false` reply as a failure
   would be a protocol change; no schema says either way yet.
2. **`.n0x/plugins.json` registration and a CLI surface — done**, as listed
   above. Registering and removing a plugin have no MCP tool.
3. **The plugin host in `n0xis-pipeline` — half done.** `run_plugins_for`
   (`n0xis-pipeline/src/lib.rs:466-509`) runs every plugin registered for a
   kind against an artifact and returns one entry per plugin, its findings or
   its error, or `PluginHostError` (`:442-464`) when no plugin could be
   chosen: a registry that exists and cannot be read or parsed is that error,
   not an empty answer (it returned no entry at all, the same answer as no
   registry). Only its own tests call it (`:544, 556, 576, 599, 621, 627,
   641`), so no pass merges plugin findings into a response, and `--handles`
   is declarative only: recorded and shown in `capability list`, dispatched on
   by nothing (`n0xis-cli/src/main.rs:1545-1551`). The fail-open-but-visible
   posture now holds for every way a plugin itself can fail that the tests
   above plant — no answer, no exit, not reading its input, no reply, not
   JSON, `null`, too long: each is reported as an error within the deadline,
   never a panic and never a hang (a plugin that read its request and slept used to
   hang the host: still no answer after 30 s, measured through
   `capability run`). Still open:
   - **A plugin's grandchildren outlive it.** Only the direct child is killed
     at the deadline. Measured 2026-10-20 through `call_once` with a 2 s
     deadline: `sh -c 'cat >/dev/null; sleep 17; true'` timed out at 2 s and
     `sleep 17` was still running afterwards; with `echo "{}"` before the
     `sleep` the reply came back at 2 s, `sleep 17` again still running.
     The threads that talk to the plugin, the stderr copier among them, live
     until the grandchild closes the pipes. A grandchild no longer holds the
     host's own stderr on Unix; on Windows it is expected to still: `std`
     starts a process with handle inheritance on, so it receives every
     inheritable handle its parent holds (Rust's `CommandExt::inherit_handles`
     documentation, default `true`), and the host's stderr arrived as one.
     Under Wine it does: the two stderr cases, built for Windows with their
     gate lifted, fail on their capture assertion (Wine is a second
     implementation of Windows, not Windows). Not run on Windows itself; the
     stderr cases are Unix only for this reason. Closing it there needs the
     host's own handles kept out of the plugin's inheritance (a handle list
     at spawn, or the host's standard handles made non-inheritable), which
     needs `windows-sys`. On Windows a virtual environment's `python.exe` is a launcher
     that runs the interpreter as its child, so an ordinary Python plugin is
     expected to have this shape there (not run on Windows). Killing the tree
     needs a process group (Unix) or a Job Object (Windows); a plugin in its
     own process group no longer receives the terminal's Ctrl-C with the
     host, and both need `libc`/`windows-sys`, which `n0xis-sources` links
     only under its `live` feature (`n0xis-sources/src/plugin.rs:198-223`).
   - **A reply's memory is bounded, not small.** At the 4 MiB bound the
     worst reply measured costs the host about 0.54 GB once parsed (120
     nested single-key objects per element, 128.6 times its length), and
     `run_plugins_for` holds every plugin's reply at once
     (`n0xis-sources/src/plugin.rs:51-83`).
4. **MCP exposure — done**: the `plugin_list`/`plugin_run` pair, as listed
   above.

`A-Plugins` / `D-Modest` / `S-Needs-Design`. Status: Open — items 2 and 4
done, 1 and 3 half done.

---

## MCP parity gaps

The MCP server ([`n0xis-mcp`](../crates/n0xis-mcp/src/tools.rs)) exposes 27
tools today — the read-oriented static/dynamic workflow (its `ui_locate` is not
validated; Phase 9 is marked invalid). The stateful, cross-invocation verbs are the gap.

- **Mirror `scan`/`table`/`patch`/`debug watch` as MCP tools** — these CLI
  verbs bridge state across independent process invocations via `.n0x/dumps/`;
  the long-lived MCP server should use real in-memory session state instead of
  a straight port of that file-bridging (see `n0xis-mcp`'s module doc for the
  reasoning already written down). `A-MCP` / `D-Modest`. Status: Open.
- **Port the remaining single-shot verbs to MCP** — beyond the stateful set
  above, the broader static/dynamic surface isn't exposed yet either
  (`ir build/explain/dot/slice/manifest/value-set/deobfuscate`,
  `scan aob/pointer-path/dissect`, `selection`, `dump`, `snapshot`, `diff`,
  `bundle`, `lua *`, `concept grep`, `locate by-transition`, `input probe`,
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
  steady-state cost without changing results. This task makes it a
  first-class `scan` option. `A-DynamicMemory` / `D-Modest`.
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
core.
`A-GUI` / `D-Complex` / `S-Needs-Design`. Status: Open, not yet scoped.

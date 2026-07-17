# N0xis

**Agent-native reverse-engineering *and* live-memory toolkit for x64 Windows,
with early ARM64 support** — a synthesis of other tools (another tool /
another tool-a source-level decompiler / another tool) and first-class live dynamic memory analysis, driven
entirely through a stable CLI + MCP contract, analyzing both static PE files
and live processes through one and the same analysis pipeline.

> **Status: alpha.** ROADMAP Phases 1–7 are complete (see [ROADMAP.md](ROADMAP.md)
> for the full history) — **except ARM64, which is implemented and passes its
> own test suite but needs substantially more real-world verification before
> it should be trusted the way x64 is** (a real register-naming bug was found
> and fixed only once tested against genuine compiler output — see ROADMAP.md's
> Phase 7 for the full account; it's an argument for more testing, not a
> reason to distrust everything, but "implemented" and "verified" aren't the
> same claim). The JSON contract is versioned (`n0xis.*.v1`, breaking shape
> changes bump the version) but hasn't been exercised by outside users yet —
> expect some shapes to still move. The archived v0 implementation lives in
> [`archive/`](archive/) and was the reference for this rewrite.

## What makes it different

another tool / another tool / another tool are GUI-first with black-box decompilers; Cheat
Engine finds runtime values but can't explain the code. N0xis **fuses both
worlds** and is **contract-first**: every capability is a CLI verb *and* an MCP
tool returning the identical versioned JSON artifact, every analysis pass (SSA,
propagation, DCE, type inference, control structuring) emits an *inspectable*
result an agent can query instead of a black-box final answer, and dynamic memory
work (scanning, pointer paths, AOB, freeze, hooks) is a first-class peer of static
analysis, not a separate tool. Live-process and on-disk analysis run through the
identical pipeline — the only difference is which input adapter supplies bytes.

An **RE workbench GUI** (graph views, a disassembly/decompiler workspace) is
**deferred, not ruled out** — the original design bias was "contract-first,
GUI-never" (see [CONCEPT.md](CONCEPT.md)); the current position is "not now, but
not never," and if/when it lands it'll be a thin visualization layer over the
existing `ok/data/meta` artifacts, not a rewrite of the CLI/MCP-drivable
analysis core. [N0xHUD](docs/n0xhud/CONCEPT.md) — a companion window for driving
runtime instrumentation against a live target — already exists as a third
frontend and is exactly that shape: a window over the engine, sharing the same
crates the CLI and MCP frontends use.

### The principal: Provenance-Driven Memory Intelligence

Arm a hardware watchpoint on a live value, catch one real memory access, and get
back not just an address but the **exact decompiled source-level statement**
responsible for it — the containing function auto-resolved, decompiled through
the SSA pipeline, with the precise block extracted:

```
$ n0xis provenance trace --pid 4821 --addr 0x1a2b3c40 --kind write
{"ok":true,"data":{"entries":[{"function_va":"0x140012a00",
  "decompiled_context":["*rax.2 = (*rax.2 + 0x1);"], ...}]}, ...}
```

Nothing else here fuses a live watchpoint hit with an optimizing decompiler like
this — a memory scanner's "find what accesses this address" stops at a raw
disassembly line; other tools' decompilers have no live-watchpoint integration
at all. (Independently fact-checked against current any other reverse-engineering tool/Cheat
Engine capabilities before making this claim.)

### Everything else

- **Static + live, one pipeline**: `--pid <live process>`, `--file <PE>`,
  `--snapshot <captured dump>`, or `--remote-cmd "<ssh ...>"` — same commands,
  same JSON shapes, regardless of where the bytes come from.
- **Optimizing SSA decompiler**: dominance-frontier phi insertion, copy/const/
  expression propagation, dead-code elimination, control structuring
  (if/while/switch) — `decomp pseudo --style goto|structured|ssa`.
- **Types & signatures**: stack-slot coalescing, struct/field recovery, real
  arity/return-type recovery from register usage, a Win32/CRT signature table,
  Rust/MSVC/Itanium demangling.
- **Live dynamic memory analysis**: typed value scan + iterative rescan
  (**snapshot-backed narrowing, no truncated result cap** — an `unknown` first
  scan stores region snapshots and narrows by what changed/stayed, so a common
  value like `4` with millions of hits works the way it does in a memory scanner),
  AOB signature scan (`?`/`??` wildcards), multi-hop pointer-path finding, struct
  dissection, freeze loops, code-cave detour hooks, and **hardware watchpoints
  with a real unwound call stack** (a from-scratch cross-process x64 unwinder
  reads the target's own `.pdata`/`.xdata`, so a mid-function watchpoint hit
  reports the true caller chain, not a raw `[rsp]` guess) — all against a *live*
  process, verified against real spawned targets.
- **`.n0xt` tables + analysis DB**: persistent analysis tables (findings,
  evidence, verification state), and an
  `annotate` command that keeps names/types/comments at an address as
  **versioned truth** — every change appended to history, nothing silently
  overwritten.
- **Multi-arch**: x64 (via `iced-x86`, full pipeline, battle-tested) and
  **ARM64** (via `disarm64`, a pure-Rust decoder — CFG/discovery/xrefs and
  `goto`/`structured` decompilation; the optimized SSA pass and flag-precise
  conditions are x64-only for now, a documented gap, not a silent one).
  **ARM64 is early**: implemented and self-tested, but not yet verified to
  the standard x64 is — see the status note above.
- **Value-set / light alias analysis**: bounded dataflow over SSA answering
  "what values can this variable actually hold" and "can these two pointers
  touch the same memory."
- **Deobfuscation**: junk-instruction detection (self-moves, cancelling
  push/pop, identity arithmetic) and value-set-provable opaque-predicate
  detection.
- **Binary/version diffing**: decompile two functions, diff the pseudo-C,
  get an agent-friendly change report with a similarity score.
- **Content-addressed artifact caching**: repeated analysis of unchanged code
  is a cache hit, not a re-decode — safe against self-modifying code and
  hot-patched functions by construction (the cache key hashes the actual bytes,
  not just the address).
- **MCP server** (`n0xis-mcp`): the same pipeline, exposed as MCP tools over
  stdio, for agent tool-calling — see [Using it from an agent](#using-it-from-an-agent-mcp) below.

## Building

Requires a recent stable Rust toolchain (pinned via `rust-toolchain.toml` — this
repo builds with `stable-x86_64-pc-windows-gnu`, since it needs no MSVC Build
Tools). From the repo root:

```
cargo build --workspace --release
```

This produces three binaries in `target/release/`:

- **`n0xis`** (also invocable as `n0x`) — the CLI.
- **`n0xis-mcp`** — the MCP server.
- **`n0xis-hud`** — N0xHUD, the companion window (see
  [docs/n0xhud/CONCEPT.md](docs/n0xhud/CONCEPT.md)).

Run the test suite (some tests spawn real disposable processes and need the
`live` feature):

```
cargo test --workspace --features n0xis-pipeline/live
```

## Using it from the command line

Every command prints one JSON object: `{"ok":true,"data":{...},"meta":{...}}` on
success, `{"ok":false,"error":{...}}` on failure. Add `--pretty` for indented
output; the exit code is non-zero on `ok:false`, so scripts can branch on it.

```sh
# Environment check
n0xis doctor --pretty

# Discover functions in a static PE and decompile one
n0xis function discover --file game.exe --limit 50
n0xis decomp pseudo --file game.exe --addr 0x140012a00 --style ssa --pretty

# Same analysis, live process instead of a file
n0xis process ps --filter game
n0xis decomp pseudo --pid 4821 --addr 0x140012a00 --style ssa

# Value scanning against a live process (snapshot-backed narrowing)
n0xis scan value --pid 4821 --type i32 --criterion unknown --save-as hp
n0xis scan filter --pid 4821 --from hp --criterion increased --save-as hp

# Capture a reproducible offline snapshot and analyze it later, no process needed
n0xis snapshot dump --pid 4821 --start 0x140001000 --size 4096 --name boss_fight
n0xis ir build --snapshot boss_fight --addr 0x140001000

# Analyze a remote machine's process over SSH, transparently
n0xis mem read --remote-cmd "ssh user@host n0xis remote-serve --pid 4821" \
  --addr 0x140001000 --size 32

# Diff a function across two builds
n0xis diff functions --a-file old.exe --a-addr 0x140012a00 \
                      --b-file new.exe --b-addr 0x140013100
```

Run `n0xis guide` for the full, current command reference (kept in sync with the
binary, not a doc that drifts) or `n0xis <command> --help` for any subcommand's
flags.

## Using it from an agent (MCP)

`n0xis-mcp` exposes the same pipeline as MCP tools returning the identical
`{ok,data,meta}` envelope the CLI prints — an agent's parsing code is the same
either way. Point an MCP-capable client at the binary, e.g. in Claude
Desktop's `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "n0xis": {
      "command": "/path/to/target/release/n0xis-mcp.exe"
    }
  }
}
```

Typical flow: `attach` (pid or file) to set the session default, `function_discover`
to find candidates, `decomp_pseudo` to decompile one, `explain_opt_delta` or
`provenance_trace` to see *why* the decompiler produced what it did.

## Layout

```
n0xis-contracts/   all wire schemas + shared types (single source of truth)
n0xis-arch/        ISA abstraction (trait Arch) + X64 (iced-x86) / Arm64 (disarm64)
n0xis-sources/     input adapters: LiveProcess, StaticPe, Snapshot, RemoteAgent
n0xis-core/        pure analysis passes (CFG/SSA/types/scan/diff/...) — no I/O, no OS
n0xis-project/     .n0x/ analysis database (names, types, notes, patches, tables)
n0xis-pipeline/    wires source + arch into the core; artifact caching
n0xis-cli/         thin clap frontend (binary: n0xis, alias n0x)
n0xis-mcp/         MCP server frontend (binary: n0xis-mcp)
n0xis-hud/         N0xHUD companion-window frontend (binary: n0xis-hud)
n0xis-bitsquid/    Bitsquid/Stingray bundle format adapter (not depended on by core)
n0xis-lua/         offline LuaJIT bytecode disassembler/patcher (not depended on by core)
n0xis-luajit/      live LuaJIT VM introspection — GCstr discovery in a running process
archive/           v0 reference implementation
```

## Docs

- **[CONCEPT.md](CONCEPT.md)** — the architecture: modular/adapter/pass design,
  the seams, the dynamic-memory layer, the `.n0xt` table format.
- **[ROADMAP.md](ROADMAP.md)** — the full phased build history, Phase 1 through
  Phase 7, with what's verified and what's explicitly scoped out at each step.
- **[docs/PRODUCT_POLICY.md](docs/PRODUCT_POLICY.md)** — the non-negotiable
  design rules every change is held to (modularity, anti-hardcode, CLI+MCP
  parity, sound-over-complete).
- **[docs/COMMUNITY_ROADMAP.md](docs/COMMUNITY_ROADMAP.md)** — claimable work:
  new architecture ports, the plugin-system proposal, and every gap the
  project's own docs already flag as a "documented follow-on."
- **[docs/n0xhud/CONCEPT.md](docs/n0xhud/CONCEPT.md)** — **N0xHUD**: a
  config-driven companion window that drives the engine's runtime
  instrumentation (write & freeze, watchers, global hotkeys) against a live
  target, built as a third frontend over the same crates the CLI and MCP use.
  A working binary exists; note that it deliberately renders as its own window
  rather than drawing inside the target — see its
  [ROADMAP.md](docs/n0xhud/ROADMAP.md) for what that does and doesn't cover.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — how to build, test, and claim work
  from the community roadmap above.
- **[docs/CLI_COMMANDS_v0.md](docs/CLI_COMMANDS_v0.md)** — the v0 CLI surface
  this rewrite preserved as a compatibility contract.
- **[docs/KILLER_FEATURES.md](docs/KILLER_FEATURES.md)** — the scope
  capability registry (what's actually unique vs. any other reverse-engineering tool/
  a memory scanner, kept honest against re-checks, not just asserted once).

## License

[GNU Affero General Public License v3.0](LICENSE) — matching `Cargo.toml`'s
`license = "AGPL-3.0-only"`.

**Using** N0xis is unrestricted: run it on whatever you like, including at work
and for commercial reverse-engineering, with no obligation to share anything.
The copyleft only binds *distribution* — ship a modified build, or offer one to
users over a network, and that build's source has to be available under the AGPL
too. Fork it, hack it, learn from it; just don't make it proprietary.

Copyright is held solely by the author, so a commercial license for anyone who
needs terms other than the AGPL is available on request — open an issue or reach
out.

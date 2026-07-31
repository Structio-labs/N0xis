# N0xis

**Deterministic reverse engineering — one analysis pipeline for static binaries *and* live processes.**
Every capability is a stable CLI verb *and* an MCP tool returning versioned JSON: drive it from a terminal or an autonomous agent. No GUI to click, no ML nondeterminism in the core.

> **One command. One JSON schema. One analysis pipeline** — whether the bytes come from a PE file, a live process, a snapshot, or a remote machine.

---

### From a hardware watchpoint to the line of code that moved your value

a memory scanner finds the *address*. other tools decompile the *code*. **N0xis connects them.** Arm a hardware watchpoint on a live value, catch one write, and get back the exact **decompiled statement** responsible — the containing function auto-resolved and run through the SSA decompiler:

```console
$ n0x provenance trace --pid 4821 --addr 0x1a2b3c40 --kind write
```
```jsonc
"decompiled_context": ["*rax.2 = (*rax.2 + 0x1);"]
//                      ^ the instruction that touched your value — as source
```

No other does this: a memory scanner's "find what accesses this" stops at a raw disassembly line; other tools' decompilers have no live-watchpoint integration at all. *(Fact-checked against current another tool / another tool / another tool / a memory scanner before making the claim.)*

<!-- ▶ HERO GIF GOES HERE — record `provenance trace` running live and drop it at docs/assets/provenance.gif, then:  ![demo](docs/assets/provenance.gif) -->

- ✔ **x64 Windows** — full pipeline (early ARM64)
- ✔ **Optimizing SSA decompiler** — and every pass emits an *inspectable* artifact, not a black-box answer
- ✔ **Live memory analysis** — value/pointer/AOB scanning, freeze, hooks (a memory scanner class)
- ✔ **Provenance** — hardware watchpoint → decompiled statement
- ✔ **Stable CLI + MCP** — the same versioned JSON from a terminal or an agent

---

## How it compares

|  | N0xis | a memory scanner | another tool / another tool / another tool |
|---|:---:|:---:|:---:|
| **Watchpoint → decompiled statement** | ✅ | ❌ | ❌ |
| Live value / pointer / AOB scanning | ✅ | ✅ | ❌ |
| Static *and* live in one pipeline | ✅ | ❌ | ~ |
| Agent-native automation (CLI + MCP, JSON) | ✅ | ❌ | ~ |

N0xis does **not** try to out-decompile other tools — theirs are mature and multi-arch, and the honest gap is written down ([ROADMAP Phase 10](ROADMAP.md)). It wins where they're structurally weak: **the live⇄static seam, and being drivable by an agent.**

---

## What it does

- **Decompile** — an optimizing SSA decompiler (`decomp pseudo --style ssa`) where every pass emits an *inspectable* artifact, not a black-box answer. Same pipeline on `--file`, `--pid`, `--snapshot`, or a remote process.
- **Scan live memory** — value scan with snapshot-backed narrowing (no result cap), AOB wildcards, pointer paths, struct dissection, freeze, code-cave hooks — a memory scanner class.
- **Watch & explain** — software / hardware / *conditional* breakpoints and a real cross-process **unwound call stack** from `.pdata`/`.xdata` — the raw material provenance is built on.
- **Method tooling** — `game grep`, `locate by-transition`, `const identify`, `sig validate`, …: the *"how do I actually find X"* methods, as commands instead of folklore.
- **Game engines** — Bitsquid/Stingray bundles + a LuaJIT stack (offline bytecode **and** live in-VM introspection).
- **Persist & diff** — `.n0xt` tables, versioned `annotate` truth, content-addressed caching, function/version diffing.

→ **Full command reference: [docs/CLI_COMMANDS.md](docs/CLI_COMMANDS.md)** — or `n0x guide`, auto-generated from the binary so it never drifts.

---

## Quickstart

Every command prints **one** JSON object: `{"ok":true,"data":…,"meta":…}` or `{"ok":false,"error":…}`. Add `--pretty` to read it; the exit code is non-zero on failure.

```sh
n0x doctor                                                      # environment check
n0x function discover --file game.exe --pdata                   # authoritative .pdata discovery
n0x decomp pseudo --file game.exe --addr 0x140012a00 --style ssa --pretty
n0x scan value --pid 4821 --type i32 --criterion unknown --save-as hp
n0x provenance trace --pid 4821 --addr 0x1a2b3c40 --kind write --pretty   # ← the principal
```

The same commands run on a live `--pid`, a static `--file`, a captured `--snapshot`, or a remote process over SSH (`--remote-cmd "ssh user@host n0x remote-serve --pid …"`).

**From an agent:** point any MCP client at `n0xis-mcp` — [details below](#mcp).

---

## Build

```sh
cargo build --workspace --release      # → n0x (n0xis), n0xis-mcp, n0xis-hud
```

Rust toolchain pinned in `rust-toolchain.toml` (builds with `stable-x86_64-pc-windows-gnu` — no MSVC Build Tools needed). Tests: `cargo test --workspace --features n0xis-pipeline/live` (some spawn real disposable processes). The analysis core is OS-free by construction — `cargo test -p n0xis-core` links zero Windows crates.

<details>
<summary><b>Workspace layout — 12 crates</b></summary>

```
n0xis-contracts/   all wire schemas (n0xis.*.vN) + shared value types — single source of truth
n0xis-arch/        ISA abstraction (trait Arch) + X64 (iced-x86, full pipeline) / Arm64 (disarm64)
n0xis-sources/     input adapters: LiveProcess, StaticPe, Snapshot, RemoteAgent, debug, input
n0xis-core/        pure analysis passes (CFG/SSA/types/scan/diff/structural/ui_locate/…) — no I/O, no OS
n0xis-project/     .n0x/ analysis DB (names, types, notes, patches, selections, .n0xt tables)
n0xis-pipeline/    wires source + arch into the core; content-addressed artifact caching
n0xis-cli/         thin clap frontend (binary: n0xis, alias n0x)
n0xis-mcp/         MCP server frontend (binary: n0xis-mcp)
n0xis-hud/         N0xHUD companion-window frontend (binary: n0xis-hud)
n0xis-bitsquid/    Bitsquid/Stingray bundle format adapter (not depended on by core)
n0xis-lua/         offline LuaJIT 2.0 bytecode disassembler/patcher (not depended on by core)
n0xis-luajit/      live LuaJIT VM introspection — GCstr discovery in a running process
```
</details>

---

## MCP

`n0xis-mcp` exposes the pipeline as **18 MCP tools** returning the identical `{ok,data,meta}` envelope the CLI prints — an agent's parsing code is the same either way. It speaks JSON-RPC over pure stdio (no port, no flags). Point a client at it:

```json
{ "mcpServers": { "n0xis": { "command": "/path/to/target/release/n0xis-mcp.exe" } } }
```

Run it with the working directory set to your `.n0x/` project so `attach` state is shared with the CLI. Typical flow: `attach` → `function_discover` → `decomp_pseudo` → `explain_opt_delta` / `provenance_trace` to see *why* the decompiler produced what it did.

<details>
<summary><b>The 18 tools</b></summary>

Session/environment (`attach`, `doctor`, `process_ps`, `module_list`), static analysis (`disasm`, `function_discover`/`function_trace`, `decomp_pseudo`, `explain_opt_delta`, `xref`/`xref_string`), live memory (`mem_read`/`mem_write`), the provenance principal (`provenance_trace`), annotations (`annotate_set`/`annotate_get`/`annotate_list`), and `ui_locate`. Source args mirror the CLI: `pid` XOR `file` XOR `snapshot` XOR `remote_cmd`, falling back to the session default.

Stateful cross-call workflows that want in-memory session state (`scan`/`filter`, `.n0xt` tables, `patch`/`debug watch`) are a **documented follow-on, not a silent gap** — driven from the CLI today.
</details>

---

## Status

**Alpha.** The static + live pipeline, the SSA decompiler, and provenance are built and exercised against real spawned targets. Honest caveats, because *"implemented"* and *"verified"* are not the same claim:

- **ARM64 is early** — implemented and self-tested, not yet verified to x64's standard (a real `sp`-vs-`xzr` bug surfaced only against genuine LLVM output); the optimized SSA pass and flag-precise conditions are **x64-only** for now.
- **Phase 9** (`ui locate`, conditional watchpoints) is implemented and unit-tested but **pending live validation**, and lives uncommitted in the working tree.
- The versioned JSON contract (`n0xis.*.vN`) hasn't been road-tested by outside users yet — expect some shapes to move.

Full phase-by-phase history (Phase 1 → 9) and the decompiler-depth plan (Phase 10): **[ROADMAP.md](ROADMAP.md)**.

---

## Docs

- **[docs/CLI_COMMANDS.md](docs/CLI_COMMANDS.md)** — current, code-verified command reference (every command, args, sources, schema id).
- **[CONCEPT.md](CONCEPT.md)** — the architecture: adapters, passes, seams, the dynamic-memory layer, and the *"one model, many projections"* north-star.
- **[ROADMAP.md](ROADMAP.md)** — phased build history + the honest decompiler-parity gap (Phase 10).
- **[docs/KILLER_FEATURES.md](docs/KILLER_FEATURES.md)** — what's actually unique vs. other tools, kept honest against re-checks.
- **[docs/n0xhud/CONCEPT.md](docs/n0xhud/CONCEPT.md)** — **N0xHUD**, the companion-window frontend (a window over the engine, not a GUI rewrite of it).
- **[docs/COMMUNITY_ROADMAP.md](docs/COMMUNITY_ROADMAP.md)** · **[docs/PRODUCT_POLICY.md](docs/PRODUCT_POLICY.md)** · **[CONTRIBUTING.md](CONTRIBUTING.md)**

## License

[**AGPL-3.0-only**](LICENSE). *Using* it is unrestricted — including commercial RE, with no obligation to share anything; the copyleft only binds *distribution* of a modified build. Copyright is held solely by the author, so a commercial license is available on request.

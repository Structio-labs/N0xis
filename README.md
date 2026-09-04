# N0xis

**Deterministic reverse engineering — an optimizing SSA decompiler and a live-memory engine in one analysis pipeline, for static binaries *and* live processes.**
Every capability is a stable CLI verb — and the same verb again as an MCP tool — returning versioned JSON: read it, pipe it through `jq`, script it, or drive it from an agent. No GUI **yet** — deferred, not ruled out; no ML nondeterminism in the core, ever.

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

- ✔ **Windows + Linux, PE + ELF** — the full static pipeline on both formats; live memory & hardware-watchpoint debugging on each through a native adapter (x64; early ARM64)
- ✔ **Optimizing SSA decompiler** — Memory-SSA, phi-web variable coalescing, complete SSA destruction, exact branch conditions; source-level readability on x64, and every pass an *inspectable* artifact
- ✔ **Live memory analysis** — value/pointer/AOB scanning, freeze, hooks (a memory scanner class)
- ✔ **Provenance** — hardware watchpoint → decompiled statement
- ✔ **Managed-runtime name recovery** — .NET NativeAOT `RVA ↔ Namespace.Type.Method`, LuaJIT, Bitsquid; turns stripped `sub_XXXX` back into real names
- ✔ **Stable CLI + MCP** — the same versioned JSON whether you type it, script it, or drive it from an agent

---

## How it compares

|  | N0xis | a memory scanner | another tool / another tool / another tool |
|---|:---:|:---:|:---:|
| **Watchpoint → decompiled statement** | ✅ | ❌ | ❌ |
| Optimizing **SSA decompiler** (Memory-SSA, variable coalescing) | ✅ | ❌ | ✅ |
| Every pass an **inspectable artifact** (not a black box) | ✅ | ❌ | ~ |
| Live value / pointer / AOB scanning | ✅ | ✅ | ❌ |
| Static *and* live in one pipeline | ✅ | ❌ | ~ |
| Windows **and** Linux, PE **and** ELF, one pipeline | ✅ | ~ | ~ |
| Structured-JSON automation (CLI + MCP) | ✅ | ❌ | ~ |

**This is a real optimizing decompiler, not an automation wrapper.** Its SSA pipeline
reconstructs source-level pseudocode — Memory-SSA (values flow *through* memory), phi-web
**variable coalescing**, complete SSA destruction, and exact branch conditions recovered
from arithmetic flags — reaching source-level readability on x64, verified on real AAA
binaries (see below). The honest remaining ladder — full type recovery, compiler-idiom
lifting, more architectures — is written down rung by rung ([ROADMAP](ROADMAP.md)); the
other tools are still broader and more mature there. What they *structurally* can't match is
layered on top: the live⇄static seam, cross-platform reach, the inspectable per-pass delta,
and a scriptable JSON surface a human pipes through `jq` or an agent drives over MCP —
equally.

---

## Reads like C — see for yourself

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
rebuilt from `dec`/`sub`/`and` flags, and pointer/struct parameter typing — and **every one
of those passes emits a checkable delta** (`--explain`), so a claim is auditable, not taken
on faith. Verified on real AAA binaries across compilers and engines: **Kenshi** (MSVC),
an **Unreal Engine 5** shipping build, **Factorio** (GCC/System V), and a **Bevy/Rust**
title — PE and ELF alike.

---

## What it does

- **Decompile** — an optimizing SSA decompiler (`decomp pseudo --style ssa`) where every pass emits an *inspectable* artifact, not a black-box answer. Same pipeline on `--file`, `--pid`, `--snapshot`, or a remote process.
- **Scan live memory** — value scan with snapshot-backed narrowing (no result cap), AOB wildcards, pointer paths, struct dissection, freeze, code-cave hooks — a memory scanner class.
- **Watch & explain** — software / hardware / *conditional* breakpoints and a real cross-process **unwound call stack** from `.pdata`/`.xdata` — the raw material provenance is built on.
- **Method tooling** — `game grep`, `locate by-transition`, `const identify`, `sig validate`, …: the *"how do I actually find X"* methods, as commands instead of folklore.
- **Game engines & managed runtimes** — Bitsquid/Stingray bundles, a LuaJIT stack (offline bytecode **and** live in-VM introspection), and **.NET NativeAOT** managed-name recovery: `aot symbols` reconstructs `RVA ↔ Namespace.Type.Method` from stack-trace metadata *and* the reflection InvokeMap, so a stripped AOT image reads as source, not `sub_XXXX` (native or under Wine).
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
n0x provenance trace --pid 4821 --addr 0x1a2b3c40 --kind write --pretty   # ← watchpoint → statement
```

The same commands run on a live `--pid`, a static `--file`, a captured `--snapshot`, or a remote process over SSH (`--remote-cmd "ssh user@host n0x remote-serve --pid …"`).

**From a program or an agent:** point any MCP client at `n0xis-mcp` — [details below](#mcp). The CLI is the reference frontend; MCP mirrors it.

**From a shell:** it's ordinary Unix plumbing — `n0x function discover --file game.exe --pdata | jq -r '.data.functions[].va'` feeds straight into the next command.

---

## Build

```sh
cargo build --workspace --release      # → n0x (n0xis), n0xis-mcp
```

Builds on **Windows and Linux**. `rust-toolchain.toml` pins the Windows gnu host (`stable-x86_64-pc-windows-gnu` — no MSVC Build Tools needed); on Linux, build with your host `stable` toolchain (override the pin with `RUSTUP_TOOLCHAIN`/`+stable` if needed). Tests: `cargo test --workspace --features n0xis-pipeline/live` (some spawn real disposable processes; live debugging on Linux uses `ptrace`, so run them able to trace descendants). The analysis core is OS-free by construction — `cargo test -p n0xis-core` links zero OS crates.

<details>
<summary><b>Workspace layout — 14 crates</b></summary>

```
n0xis-contracts/   all wire schemas (n0xis.*.vN) + shared value types — single source of truth
n0xis-arch/        ISA abstraction (trait Arch) + X64 (iced-x86, full pipeline) / Arm64 (disarm64)
n0xis-sources/     input adapters: LiveProcess, StaticPe, Snapshot, RemoteAgent, debug, input
n0xis-core/        pure analysis passes (CFG/SSA/types/scan/diff/structural/ui_locate/…) — no I/O, no OS
n0xis-project/     .n0x/ analysis DB (names, types, notes, patches, selections, .n0xt tables)
n0xis-pipeline/    wires source + arch into the core; content-addressed artifact caching
n0xis-frontend/    shared frontend seam: source/ISA resolution, argument parsing, capability registry
n0xis-cli/         thin clap frontend (binary: n0xis, alias n0x)
n0xis-mcp/         MCP server frontend (binary: n0xis-mcp)
n0xis-il2cpp/     IL2CPP managed layer — symbol index pairing a Unity target's addresses with C# names
n0xis-bitsquid/    Bitsquid/Stingray bundle format adapter (not depended on by core)
n0xis-lua/         offline LuaJIT 2.0 bytecode disassembler/patcher (not depended on by core)
n0xis-luajit/      live LuaJIT VM introspection — GCstr discovery in a running process
```
</details>

---

## MCP

`n0xis-mcp` exposes the pipeline as **25 MCP tools** returning the identical `{ok,data,meta}` envelope the CLI prints — an agent's parsing code is the same either way. It speaks JSON-RPC over pure stdio (no port, no flags). Point a client at it:

```json
{ "mcpServers": { "n0xis": { "command": "/path/to/target/release/n0xis-mcp.exe" } } }
```

Run it with the working directory set to your `.n0x/` project so `attach` state is shared with the CLI. Typical flow: `attach` → `function_discover` → `decomp_pseudo` → `explain_opt_delta` / `provenance_trace` to see *why* the decompiler produced what it did.

<details>
<summary><b>The 25 tools</b></summary>

Session/environment (`attach`, `doctor`, `process_ps`, `module_list`), static analysis (`disasm`, `function_discover`/`function_trace`, `decomp_pseudo`, `explain_opt_delta`, `xref`/`xref_string`), live memory (`mem_read`/`mem_write`), provenance (`provenance_trace`), annotations (`annotate_set`/`annotate_get`/`annotate_list`), on-screen UI location (`ui_locate`, `ui_windows`, `ui_focus`, `ui_screenshot`), the capability registry (`capability_list`/`capability_run`), and external plugins (`plugin_list`/`plugin_run`). Source args mirror the CLI: `pid` XOR `file` XOR `snapshot` XOR `remote_cmd`, falling back to the session default.

Stateful cross-call workflows that want in-memory session state (`scan`/`filter`, `.n0xt` tables, `patch`/`debug watch`) are a **documented follow-on, not a silent gap** — driven from the CLI today.
</details>

---

## Status

**Alpha.** The static + live pipeline, the SSA decompiler, and provenance are built and exercised against real spawned targets on Windows and Linux. Honest caveats, because *"implemented"* and *"verified"* are not the same claim:

- **ARM64 — decoder & CFG verified, decompiler not.** The AArch64 *decoder* and *CFG* are verified against real Clang `-O1` output (57/64 instructions byte-exact vs `llvm-objdump`, the rest canonical-vs-alias equivalences — no decode or register-width errors); branch resolution and if/else structuring hold. But the AArch64 **lift/SSA/decompile is not built** — `decomp pseudo` degrades to `asm` nodes and unrecovered conditions — so the optimizing decompiler and flag-precise conditions are **x64-only** for now. That lift is the remaining ARM64 work, not the decoder.
- **The Linux-native live track is new** — `ptrace` hardware watchpoints (DR0–DR7), the portable ELF/DWARF unwinder, and `stack backtrace` are implemented and tested against spawned targets; still hardening against the more mature Windows path.
- The versioned JSON contract (`n0xis.*.vN`) hasn't been road-tested by outside users yet — expect some shapes to move.

Full phase-by-phase history and the decompiler-depth plan (Phase 10): **[ROADMAP.md](ROADMAP.md)**.

---

## Docs

- **[docs/CLI_COMMANDS.md](docs/CLI_COMMANDS.md)** — current, code-verified command reference (every command, args, sources, schema id).
- **[CONCEPT.md](CONCEPT.md)** — the architecture: adapters, passes, seams, the dynamic-memory layer, and the *"one model, many projections"* north-star.
- **[ROADMAP.md](ROADMAP.md)** — phased build history + the honest decompiler-parity gap (Phase 10).
- **[docs/CAPABILITIES.md](docs/CAPABILITIES.md)** — what N0xis does that other tools don't, with the third party analysis and caveats behind each claim.
- **[docs/COMMUNITY_ROADMAP.md](docs/COMMUNITY_ROADMAP.md)** · **[docs/PRODUCT_POLICY.md](docs/PRODUCT_POLICY.md)** · **[CONTRIBUTING.md](CONTRIBUTING.md)**

## License

N0xis is **source-available** software, developed under the Structio name.

- **Free for noncommercial use** — personal projects, research, education,
  CTFs, hobby reverse engineering, and use by noncommercial organizations,
  under the [PolyForm Noncommercial License 1.0.0](LICENSE).
- **Commercial use requires a paid license.** If you use N0xis in a company,
  as part of paid work, or in any activity intended for commercial advantage,
  see [COMMERCIAL.md](COMMERCIAL.md).

Versions up to and including 0.2.1 were released under AGPL-3.0 and remain
available under those terms. This license applies to 0.3.0 and later.

Not sure whether your use case is commercial? Open an issue or email
<structio.dev@gmail.com> — I'd rather answer a question than chase a violation.

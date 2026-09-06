# N0xis

**From a hardware watchpoint in a live process to the exact decompiled statement that changed the value.**

Memory scanners find the *address*. Decompilers explain the *code*. **N0xis connects them.**

<!-- ▶ HERO GIF GOES HERE — record `provenance trace` running live and drop it at docs/assets/provenance.gif, then:  ![demo](docs/assets/provenance.gif) -->

```console
$ n0x provenance trace --pid 9348 --addr 0x7ff68bef3010 --kind write
```
```jsonc
"function_va": "0x7ff68bef1580",          // containing function, auto-resolved
"decompiled_context": [
  "rax.2 = (*(uint32_t*)(0x7ff68bef3010) - 0x1);",
  "*(uint32_t*)(0x7ff68bef3010) = rax.2;"  // ← the statement that moved your value
]
```

That is the source's `hp -= 1;`, recovered from a running process — the watched address
appears in the statement. Verified on Windows **and** Linux.

A "find what accesses this" scan normally stops at a raw disassembly line, and a
decompiler normally has no live-watchpoint input at all. This is the two halves
joined: the watchpoint hit is resolved through the same SSA pipeline that
decompiles the file.

## Install

Prebuilt binaries for Linux and Windows — **[latest release](https://github.com/Structio-labs/N0xis/releases/latest)**.

```sh
curl -LO https://github.com/Structio-labs/N0xis/releases/latest/download/n0xis-linux-x86_64
chmod +x n0xis-linux-x86_64 && ./n0xis-linux-x86_64 --version
```

Or build it: `cargo build --workspace --release` (Windows and Linux; no MSVC Build Tools
needed — `rust-toolchain.toml` pins the gnu host).

## Quickstart

Every command prints **one** JSON object: `{"ok":true,"data":…,"meta":…}` or
`{"ok":false,"error":…}`. Add `--pretty` to read it; the exit code is non-zero on failure.

```sh
n0x doctor                                                    # environment check
n0x profile --file game.exe                                   # triage: sections, exports, engine hints
n0x function discover --file game.exe --pdata                 # exact .pdata discovery
n0x decomp pseudo --file game.exe --addr 0x140012a00 --style ssa --pretty
n0x provenance trace --pid 4821 --addr 0x1a2b3c40 --kind write --pretty
```

The same commands run on a live `--pid`, a static `--file`, a captured `--snapshot`, or a
remote process over SSH. It is ordinary Unix plumbing —
`n0x function discover --file game.exe --pdata | jq -r '.data.functions[].va'` feeds the next
command. `n0x guide` lists all 110 commands, generated from the binary so it never drifts.

**From an agent:** point any MCP client at `n0xis-mcp` — 25 tools returning the identical
`{ok,data,meta}` envelope, JSON-RPC over stdio.

```json
{ "mcpServers": { "n0xis": { "command": "/path/to/n0xis-mcp" } } }
```

## What it does

- **Decompile** — an optimizing SSA decompiler (Memory-SSA, phi-web variable coalescing,
  complete SSA destruction, exact branch conditions) where **every pass emits an inspectable
  delta** (`--explain`), not a black-box answer.
- **Scan live memory** — value/pointer/AOB scanning with snapshot-backed narrowing, freeze,
  code-cave hooks. the full scan → narrow → freeze → patch loop.
- **Watch & explain** — software / hardware / conditional breakpoints and a real cross-process
  unwound call stack; the raw material provenance is built on.
- **Recover names** — C++ classes from RTTI on both ABIs (MSVC `.rdata` chains and Itanium
  `_ZTV` symbols), .NET NativeAOT `RVA ↔ Namespace.Type.Method`, LuaJIT, Bitsquid, IL2CPP —
  so a stripped image reads as source, not `sub_XXXX`.
- **Persist & diff** — `.n0xt` tables, versioned annotations, content-addressed caching,
  function/version diffing.

Windows **and** Linux, PE **and** ELF, one pipeline — static files, live processes, snapshots
and remote targets all flow through the same passes and the same versioned JSON.

There is no ML nondeterminism in the core, ever. A desktop GUI lives in a separate repo:
**[n0xis-gui](https://github.com/Structio-labs/n0xis-gui)**.

## Status

**Alpha.** The static + live pipeline, the SSA decompiler and provenance are exercised against
real spawned targets on both platforms. Honest caveats, because *implemented* and *verified*
are not the same claim:

- **ARM64 — decoder and CFG verified, decompiler not.** The AArch64 lift/SSA is not built, so
  `decomp pseudo` degrades to `asm` nodes there. The optimizing decompiler is **x64-only**.
- **The Linux-native live track is newer** than the Windows one and still hardening.
- The versioned JSON contract has not been road-tested by outside users — expect shapes to move.

## Docs

- **[docs/CLI_COMMANDS.md](docs/CLI_COMMANDS.md)** — every command, args, sources, schema id.
  decompiler output samples, and the caveats behind each claim.
- **[CONCEPT.md](CONCEPT.md)** — architecture: adapters, passes, seams.
- **[ROADMAP.md](ROADMAP.md)** — build history and the analysis capabilities still missing.
- **[MAP.md](MAP.md)** — the 16-crate workspace layout.
- **[docs/COMMUNITY_ROADMAP.md](docs/COMMUNITY_ROADMAP.md)** ·
  **[docs/PRODUCT_POLICY.md](docs/PRODUCT_POLICY.md)** · **[CONTRIBUTING.md](CONTRIBUTING.md)**

## License

N0xis is **source-available** software, developed under the Structio name.

- **Free for noncommercial use** — personal projects, research, education, CTFs, hobby reverse
  engineering, and use by noncommercial organizations, under the
  [PolyForm Noncommercial License 1.0.0](LICENSE).
- **Commercial use requires a paid license** — see [COMMERCIAL.md](COMMERCIAL.md).

Versions up to and including 0.2.1 were released under AGPL-3.0 and remain available under
those terms. This license applies to 0.3.0 and later.

Not sure whether your use case is commercial? Open an issue or email <structio.dev@gmail.com> —
I'd rather answer a question than chase a violation.

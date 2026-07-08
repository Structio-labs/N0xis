# N0xis

**reverse-engineering and live-memory toolkit for x64
Windows** — a synthesis of other tools (another tool / another tool-a source-level decompiler / another tool)
and a memory scanner-class dynamic memory work, driven entirely through a stable CLI +
MCP contract, analyzing both static PE files and live processes through one and the
same analysis pipeline.

> Status: **v1 rewrite in progress.** The working v0 implementation is archived in
> [`archive/`](archive/) and used as a reference for the port.
>
> Name: **N0xis** (pronounced "Noxis"). The CLI binary stays invocable as `n0x`
> (and `n0xis`) so the installed global shim keeps working.

## Start here

- **[CONCEPT.md](CONCEPT.md)** — what N0xis is, the architecture (modular / adapter
  / passes), the seams, the dynamic-memory layer, the `.n0xt` table format, and the
  killer feature.
- **[ROADMAP.md](ROADMAP.md)** — phased plan from workspace skeleton to the
  optimizing decompiler, type recovery, dynamic memory, MCP, and beyond.
- **[docs/CLI_COMMANDS_v0.md](docs/CLI_COMMANDS_v0.md)** — the CLI surface the
  rewrite must preserve (compatibility contract).

## What makes it different

another tool / another tool / another tool are GUI-first with black-box decompilers; a memory scanner
finds runtime values but can't explain the code. N0xis is **contract-first and
GUI-never**, and it **fuses both worlds**: every capability is a CLI verb + MCP tool
returning a versioned JSON artifact, every analysis pass (SSA, propagation, DCE,
type inference, control structuring) emits an *inspectable* result an agent can
query, and dynamic memory work (scanning, pointer paths, AOB, freeze, hooks) is a
first-class peer of static analysis. Live-process and on-disk analysis run through
the identical pipeline — the only difference is which input adapter supplies bytes.

## Layout (target)

```
n0xis-contracts/   all wire schemas + shared types (single source of truth)
n0xis-arch/        ISA abstraction (trait Arch) + X64 impl (iced-x86)
n0xis-sources/     input adapters: LiveProcess, StaticPe, Snapshot, ...
n0xis-core/        pure analysis passes + memory scan/diff (no I/O, no OS)
n0xis-project/     .n0x/ analysis database (names, types, notes, patches, tables)
n0xis-pipeline/    PassManager wiring source + arch + project into core
n0xis-cli/         thin clap frontend (binary: n0xis, alias n0x)
n0xis-mcp/         MCP server frontend
archive/           v0 reference implementation
```

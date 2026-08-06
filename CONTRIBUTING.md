# Contributing to N0xis

N0xis is public but early (see [README.md](README.md) for current status), and
its issue tracker isn't populated yet — the process below was decided before
launch so it didn't need inventing under pressure. This document explains how
work gets found, claimed, and reviewed.

## Where the rules come from

- **[docs/PRODUCT_POLICY.md](docs/PRODUCT_POLICY.md)** — the non-negotiable
  design rules (modularity, anti-hardcode, CLI+MCP parity, sound-over-complete).
  Read this before writing code; PRs that violate it get sent back regardless of
  how well they otherwise work.
- **[CONCEPT.md](CONCEPT.md)** — why the architecture is shaped the way it is
  (the crate boundaries, the pass model, the contract-first design).
- **[ROADMAP.md](ROADMAP.md)** — what's built and how, phase by phase. Every
  phase's write-up says what was verified and what was deliberately left out —
  read the relevant phase before touching adjacent code.

## How to build and test it

See [README.md#building](README.md#building). Before opening a PR:

```
cargo build --workspace          # must be warning-free
cargo test --workspace --features n0xis-pipeline/live
cargo clippy --workspace --all-targets -- -D warnings
sh scripts/check_boundary.sh     # the layering law, mechanically
```

Zero warnings is enforced, not a suggestion — every phase in this project's
history shipped with a clean build, and that's not going to change now.

**CI runs exactly these four** ([.github/workflows/ci.yml](.github/workflows/ci.yml)),
so a green local run is a green PR:

- **`boundary` (Linux)** — `scripts/check_boundary.sh` asserts `n0xis-contracts`,
  `n0xis-arch` and `n0xis-core` pull in no OS, file-format or frontend crate,
  then builds and tests them, and checks that `n0xis-cli` / `n0xis-mcp` still
  compile where the `live` adapter does not exist. This is CONCEPT §4's layering
  law; it used to be a claim in a doc, and now it fails the build instead.
- **`windows`** — the full workspace (including `cfg(windows)` code: live
  process, debugger, N0xHUD) built with `RUSTFLAGS=-D warnings` and tested.
- **`clippy`** — the whole workspace, all targets, `-D warnings`.

`cargo fmt` is deliberately *not* a gate: parts of this codebase use hand-tuned
layout (register tables, single-line struct literals) that rustfmt would reflow.

## How work gets claimed

**[docs/COMMUNITY_ROADMAP.md](docs/COMMUNITY_ROADMAP.md)** is the task list:
new architecture ports, plugin-system design, deobfuscation extensions, MCP
parity gaps, and everything else marked as a "documented follow-on" somewhere
in `ROADMAP.md`. Each entry has a `Status` field.

**Right now** (no Issues opened yet): open a PR against
`docs/COMMUNITY_ROADMAP.md` changing an entry's `Status` from `Open` to
`Claimed — @yourhandle`, in the same PR as your first commit, or as a
standalone PR if you want to reserve it before writing code. This is a stopgap,
not the intended long-term mechanism — editing a shared markdown file to claim
work doesn't scale and doesn't notify anyone, which is exactly the failure mode
GitHub Issues exist to solve.

**Once the tracker is populated**, every `COMMUNITY_ROADMAP.md` entry becomes a
GitHub Issue, and claiming works the way it does on any project of this shape —
closest model is [Bevy](https://github.com/bevyengine/bevy), which runs
contribution at real scale (hundreds of contributors) on exactly this system:

- **Labels, not a shared checklist.** Issues get an area label (`A-*`, e.g.
  `A-Arch`, `A-Decompiler`, `A-MCP`), a difficulty label (`D-Trivial` through
  `D-Complex`), and a status label (`S-Ready-For-Implementation`,
  `S-Needs-Design`, `S-Blocked`). You pick by area/difficulty, not by asking
  permission first.
- **Claim by comment or assignment**, not by editing a file. Comment "I'll take
  this" (or self-assign, if you have that permission) before starting non-trivial
  work, so two people don't build the same thing in parallel. Trivial fixes
  don't need a claim — just open the PR.
- **`S-Adopt-Me`** marks work whose original author stalled or stepped away —
  explicitly available for someone else to pick up, no awkwardness about
  "taking" someone's issue.
- **Tracking issues** for large multi-part efforts (this project's own
  `ROADMAP.md` phases are the analogue) — a checklist issue linking each
  sub-task's own issue, so a big effort like "port to a new architecture" is
  visible as one place to watch even though ten people might work on pieces
  of it independently.

This project will adopt the same shape at launch (a lightweight `A-`/`D-`/`S-`
label set, not Bevy's full taxonomy — no point pre-building infrastructure for
a scale we're not at yet).

## Adding a capability

Two seams matter here, and both are in `n0xis-frontend`:

- **Target arguments** (`--pid`, `--file`, `--snapshot`, `--remote-cmd`,
  `--bytes`, `--arch`) resolve through `n0xis_frontend::source` /
  `::resolve_arch`. Never re-implement that in a frontend and never write
  `X64::new()` inline in one — the CLI and MCP each used to keep their own copy
  of the source seam, and they had already drifted apart (the CLI silently
  ignored the `.n0x/` session default that `attach` writes).
- **New functionality** registers into the capability registry
  (`n0xis_frontend::registry`). Implement `Plugin`, add your `Capability` in
  its `register`, and add one line to `build_registry()` — the single
  composition point. It then shows up in `capability list`, in the
  `capability_list` MCP tool, and is runnable through `capability run`, without
  either frontend changing. An external process plugin registered in
  `.n0x/plugins.json` arrives through the *same* trait and dispatches through
  the same call; there is no privileged built-in path.

The older shape — a `clap` variant plus an arm in `n0xis-cli`'s `match`, plus a
separate `#[tool]` method in `n0xis-mcp` — still carries most of the command
surface and is fine to extend when a command needs bespoke flags. Prefer the
registry for anything that is "arguments in, envelope out".

## What a good PR looks like here

- **One module, one PR.** Don't bundle an architecture port with a decompiler
  change — reviewers can't reason about coupled changes, and it makes bisecting
  a regression harder later.
- **Tests against real behavior, not just mocks.** Every phase in this
  project's history that touched a live-process or on-disk-format capability
  was verified against a real spawned process or a real system binary, not just
  synthetic bytes. New capabilities should meet the same bar — see any
  `tests/*_exit.rs` file for the pattern.
- **Honest incompleteness over a silent gap.** If a capability doesn't cover
  every case (a new architecture that doesn't yet implement `lift`, a pattern
  matcher that only catches the common form), say so in a doc comment and
  return the trait's sound default for the rest — never guess. This is
  `docs/PRODUCT_POLICY.md`'s single most important rule and the one most PRs
  get wrong on a first pass.
- **No unrelated cleanup.** A feature PR that also reformats three unrelated
  files makes review slower, not faster.

## Design discussions

For anything that changes a *contract* (a JSON schema shape, the `Arch` trait,
the wire protocol a frontend depends on) — open a discussion before a PR.
Once Discussions and the label set are set up this becomes a GitHub Discussion
or an `S-Needs-Design` issue; for now, it's a conversation with the maintainer
before you invest the implementation time.

## Licensing of contributions

N0xis is [AGPL-3.0](LICENSE), and contributions are accepted under that same
license — by opening a PR you're licensing your work to the project under it.

Copyright is currently held entirely by the author, which keeps a commercial
license possible for users who can't take AGPL terms. To preserve that, a
contributor licence agreement may be required before a non-trivial PR is
merged. There's no CLA to sign yet — if that changes it'll be stated here and
on the PR, never applied retroactively to work already merged.

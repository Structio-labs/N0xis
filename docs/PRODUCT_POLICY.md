# N0xis Product Policy

These are the rules the project is actually held to — not aspirations. Every
phase in [ROADMAP.md](../ROADMAP.md) was built against them, and every review
(human or agent) checks new work against them. If a change violates one of
these, it goes back regardless of how well it otherwise works, and regardless
of who's asking — they apply to every contributor, maintainer included.

## 1. Modularity in the spirit of Bevy, within this project's context

Every module — every crate, every `Arch` implementation, every `Pass`, every
`MemorySource` adapter — should be one you can take on its own, use, and later
swap for another without rewriting the rest. Modules talk through **stable
contracts** (a trait, a JSON schema, a wire protocol), never through hidden
internal coupling.

Concretely, in this codebase:

- `n0xis-core`'s passes depend only on `trait Arch` and `trait MemorySource` —
  never on `iced-x86`, `disarm64`, Win32, or any concrete adapter. Adding
  ARM64 (`n0xis-arch::Arm64`) required zero changes to any pass in
  `n0xis-core` — that's the seam working as designed, not an accident.
- The CLI and MCP frontends are **equal peers** over the same
  `n0xis-pipeline`/`n0xis-core` API, both driven only through
  `n0xis-contracts`'s versioned schemas. Neither is "the real one" with the
  other bolted on.
- A duplicated schema or constant across two sides (e.g. a wire message
  shape defined twice) is a signal to extract it into
  `n0xis-contracts` — the single source of truth — not a style nitpick.

## 2. Think ahead so you don't dead-end the project

Before adding a module, ask how it would live on its own: does it leak a
hidden dependency into something that's supposed to be independent of it? Is
an external system (an OS API, a file format, a network protocol) isolated
behind an adapter, or has it leaked into analysis logic? Is a wire contract
versioned so a breaking change doesn't silently corrupt an old client's
assumptions?

This is why `trait Arch` was built in Phase 1 with exactly **one**
implementation (`X64`) — the seam exists before it's needed twice, so ISA
knowledge never leaks into the passes (the mistake that sank the archived v0
implementation, see `archive/`). It's also why `n0xis-contracts::schema`
reserves both a `v0` namespace (the archived tool's wire shapes, kept
byte-compatible) and a `v1` namespace (new shapes) with an explicit rule:
**a breaking shape change bumps the version, it never mutates a shipped one.**

## 3. Powerful CLI and MCP — every capability, both frontends

Every capability that's user/agent-facing gets both a CLI verb and an MCP
tool, returning the **identical** JSON shape either way. An agent's parsing
code should never need to know which frontend answered it. When a capability
lands in only one frontend, that's a tracked gap (see
[docs/COMMUNITY_ROADMAP.md](COMMUNITY_ROADMAP.md)), not a permanent split.

Both frontends are driven from the outside through a stable interface — never
only from inside the code. A human and an agent get the same power.

## 4. Anti-hardcode policy

No literals, magic numbers, URLs, ports, credentials, or fixed business rules
embedded directly in analysis logic. Any value that can change independently
of the logic around it — a calling convention's argument registers, a
prologue byte pattern, a schema id, a default port — belongs in a named
constant, a config value, or a data table (`n0xis-arch`'s `RegisterFile`/
`CallConv`, `n0xis-contracts::schema`, `signatures.rs`'s known-API table), not
inline in a pass.

**Common-sense exception**: throwaway test fixtures and genuinely immutable
constants (the size of a `u32`, an architecturally-reserved opcode) don't need
extraction — that would just be noise. The test is "could this reasonably
change without the surrounding logic changing," not "is this a literal."

## 5. Sound over complete — never silently give wrong data

An incomplete answer is fine. A wrong answer presented as if it were complete
is not. Every pass in this codebase follows the same discipline:

- `Arch::reg_access`, `Arch::lift`, `Arch::branch_condition`,
  `Arch::detect_switch` all have **sound empty/placeholder defaults** — an ISA
  backend that doesn't override one reports "unknown," never a guess.
  `n0xis-arch::Arm64` uses this precisely: it implements `reg_access` for the
  base integer ISA and reports empty reads/writes for SIMD/FP/crypto/SVE
  rather than misreading bits it doesn't understand.
- `ValueSetPass` reports `Top` (unknown) the instant anything is
  unmodeled — a memory load, a call result — never a guessed constant.
- `ProvenancePass`'s fields are `Option`/empty rather than a guess when a step
  doesn't resolve.
- A cache (`n0xis-pipeline::cfg_cached`) is keyed on the **actual bytes**, not
  just an address, specifically so it can never hand back a stale artifact for
  code that changed underneath it.

When you're tempted to make an assumption to fill a gap, don't — return
`None`/empty/a placeholder and document the gap instead. This is the rule
`CONTRIBUTING.md` calls out as the one most first-pass PRs get wrong.

A concrete violation this project shipped and had to fix: `ScanPass`'s first
cut capped a value scan at 200 000 matches and `break`-ed out of the region
loop — so a common value silently stopped being scanned in every higher-address
region, and the returned working set was partial and order-dependent while
*looking* complete. It even set a `truncated` flag, which is not enough: a
wrong-but-flagged answer that breaks the next step (no rescan could recover a
target that was never scanned) is still the failure this rule is about. The fix
was to make the scan genuinely complete — snapshot-backed narrowing that never
truncates, materializing addresses only on demand (see ROADMAP Phase 4b). "We
capped it and set a flag" is not "sound"; covering the whole input, or refusing
with the true total, is.

## 6. No half-finished implementations, no scope creep

A bug fix doesn't need surrounding cleanup. A one-shot capability doesn't need
a speculative abstraction for a use case nobody asked for. Three similar lines
of code is better than a premature abstraction built for a hypothetical future
requirement.

The flip side: when a capability is *deliberately* scoped down (an
architecture port that skips SSA lifting for now, a diff pass that compares
one function pair instead of auto-matching a whole binary), that scope cut
must be **documented in the code and in ROADMAP.md**, not silently absent.
"Not attempted, here's why, here's the follow-on" is the standing pattern —
search ROADMAP.md for "documented follow-on" to see it applied throughout the
project's history.

## 7. Test against real behavior

Mocks and synthetic byte sequences are fine for unit tests of a single pass in
isolation. Anything that touches a live process, a real file format, or an OS
API gets verified against the real thing before it's called done — spawn a
real disposable process, decode real system DLL bytes, drive the actual
compiled binary as a subprocess. Every `tests/*_exit.rs` file in this repo is
built to this standard; new capabilities of similar shape should be too.

**Hand-picked test cases don't catch a systemic misunderstanding, only real
generated data does.** The ARM64 port's first pass shipped 19 unit tests, each
built from an instruction encoding cross-checked against the decoder library's
own regression suite — every individual test was correct, and the whole set
still missed a real bug (a backwards `sp`-vs-`xzr` register selection) because
a human choosing which instructions to hand-test doesn't reproduce the actual
*distribution* of operand patterns a real compiler emits. It was caught by
cross-compiling a real program (`rustc --target aarch64-linux-android --emit=obj`,
no linker even needed) and running the genuine LLVM-generated bytes through
the same passes. **"Passes its own test suite" and "verified" are not the same
claim** — say which one you mean, and if it's the former, say so explicitly
rather than letting it read as the latter.

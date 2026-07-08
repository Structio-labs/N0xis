# N0xis — Killer Features (living registry)

This is the **single source of truth** for N0xis's scope edge: a *growing
portfolio* of features that surpass other tools, plus the standing process that
produces them. It is meant to be **continuously updated** by the agent as the
project matures — not written once.

See [`../CONCEPT.md`](../CONCEPT.md) §11 for the summary; this file holds the detail.

---

## The synthesis loop (how entries are produced)

Run this per capability area, repeatedly, as N0xis grows:

1. **Map other tools** — what do another tool / another tool-a source-level decompiler / another tool / a memory scanner /
   other tools actually do here, and how well?
2. **Map us** — what does N0xis do (or plan to)?
3. **Find the gap** — where does *no* other do well? The richest seam is
   **static⇄dynamic fusion** and **agent-native inspectability**, because that is
   structurally hard for GUI-first, single-world tools.
4. **Propose a feature that surpasses** — not parity; a capability they can't easily
   copy given their architecture.
5. **Record it** here with rationale + status; link it to a ROADMAP phase.

**Entry statuses:** `idea` → `proposed` → `planned` (in ROADMAP) → `building` →
`shipped`. Also `parked` / `dropped` with a reason.

---

## Capability-area third party matrix (top level)

| Area | other tools (other tools/another tool) | a memory scanner & kin | N0xis edge |
|---|---|---|---|
| Static analysis / decompiler | ✅ mature, **black-box** | ❌ | ✅ + inspectable passes |
| Types / structs / signatures | ✅ | ~ (dissect) | ✅ fused with scanning |
| Value scanning / filtering | ~ (debugger) | ✅ core | ✅ peer of static |
| Pointer-path / AOB | ✗ / basic | ✅ | ✅ **typed** paths |
| Find-what-writes | ✅ (debugger) | ✅ | ✅ **+ auto-decompile** that code |
| Persistent table | project DB | `.CT` | `.n0xt` + code/type/provenance links |
| Survive game updates | manual re-RE | ❌ tables break | ✅ **version-resilient anchors** |
| Agent-nativeness | plugin-in-GUI | Lua-in-GUI | ✅ CLI+MCP, deterministic JSON |
| Live⇄static reconciliation | manual | no static | ✅ **automatic** |

---

## Registry

### KF-1 — Provenance-Driven Memory Intelligence  ·  *principal*  ·  status: `proposed`
- **What exists elsewhere:** CE finds an *address*; RE tools show *code*; bridging them (ASLR
  addr → module+RVA → function → meaning) is manual.
- **Gap:** nobody auto-closes the value⇄code⇄meaning loop.
- **Feature:** (a) *value → meaning*: scan → find-what-accesses (HW bp) →
  `VA→module+RVA→function` → SSA decompile → **typed provenance graph**; (b) *intent
  → verified change*: NL intent → locate → synthesize patch/table entry → apply →
  **verify live** → record in `.n0xt`.
- **Why it wins:** requires spanning both worlds over one core — hard for single-world
  tools to copy. **Roadmap:** Phase 4c.

### KF-2 — Version-Resilient Anchors  ·  status: `idea`
- **What exists elsewhere:** CE cheat tables **break on every game patch** (addresses/offsets
  shift); the #1 user pain. RE tools re-analyze by hand.
- **Gap:** no persistent, self-healing anchor that survives updates.
- **Feature:** each `.n0xt` entry stores not just an address/offset but an **AOB
  signature + an IR/pseudo-C fingerprint** of the surrounding function; on a new
  binary version, N0xis re-locates the anchor by matching the fingerprint and
  auto-repairs the entry (reporting confidence + diff).
- **Why it wins:** turns cheat tables from fragile to durable; only possible because
  we have both the byte-level and the semantic (IR) view. **Roadmap:** Phase 4b/4c.

### KF-3 — Typed Pointer-Path Fusion  ·  status: `idea`
- **What exists elsewhere:** CE pointer-scan yields raw hops `[[base+0x10]+0x8]+0x68`; RE tools
  have struct types but don't apply them to live pointer chains.
- **Gap:** the two are never merged.
- **Feature:** annotate each hop of a discovered pointer path with the **recovered
  struct + field**, rendering `Player->stats->hp` instead of raw offsets; validate
  the typed path against the running process.
- **Why it wins:** readable, self-documenting, and robust to struct-layout changes.
  **Roadmap:** Phase 4b (with Phase 4 types).

### KF-4 — Snapshot-Diff Causal Attribution  ·  status: `idea`
- **What exists elsewhere:** CE can compare scans; nobody attributes *why* a region changed to
  the *code* that changed it.
- **Gap:** no "what changed when I did X, and which function did it" in one step.
- **Feature:** snapshot memory before/after an in-game action, diff, then correlate
  each changed region with the writing function (via find-what-writes + decompile),
  producing an agent-readable causal report.
- **Why it wins:** fuses dynamic diffing with static explanation. **Roadmap:** Phase 4c+.

### KF-5 — Explainable Decompilation  ·  status: `planned`
- **What exists elsewhere:** a source-level decompiler/BN microcode optimization is a **black box**; you see final
  C, not the reasoning.
- **Gap:** you can't ask "why is this condition `x>4`?" / "what did DCE remove?".
- **Feature:** every pass (SSA, propagate/fold, DCE, structuring) emits an
  **inspectable JSON delta** (`n0xis.opt.delta.v1`, `n0xis.ir.ssa.v1`); agent-facing
  "explain" tools surface the reasoning.
- **Why it wins:** uniquely valuable to an LLM agent; impossible to ask a GUI IDE.
  **Roadmap:** Phase 3 (+ MCP explain tools in Phase 5).

### KF-6 — Cross-Version Binary Diffing (semantic)  ·  status: `idea`
- **What exists elsewhere:** structural diff tools diff functions structurally; output is GUI-oriented,
  not agent-oriented, and not fused with live memory.
- **Gap:** no agent-friendly "what changed between game v1.2 and v1.3, semantically,
  and what does it mean for my anchors/cheats".
- **Feature:** diff two binaries at the IR/pseudo-C level, emit a structured change
  report, and auto-flag which `.n0xt` anchors are affected (ties into KF-2).
- **Why it wins:** closes the loop between "game updated" and "my tools still work".
  **Roadmap:** Phase 7+.

---

## How to add / update an entry

Append a new `### KF-N — <name> · status: <status>` block with the five loop fields
(What exists elsewhere / Gap / Feature / Why it wins / Roadmap). Keep the top matrix in sync.
Promote status as work progresses. When an entry ships, keep it here (mark `shipped`)
— the registry is also the record of *why* each edge exists.

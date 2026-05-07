---
tags: [moc, index, project/n0x]
aliases: [Index, Project Map, Hub]
---

# N0x — Project Map

Central navigation hub for the N0x reverse engineering toolkit. Open this folder (`D:\Projects\N0x\`) as an **Obsidian vault** to get bidirectional navigation, backlinks, and the graph view across all documents.

> Navigation: [[MAP|Map]] · [[CLI_FEATURES_SPEC|CLI Spec]] · [[BACKEND_SPEC|Backend Spec]] · [[README|Frontend README]] · [[n0x-cli-rs/README|CLI README]] · [[n0x-cli-rs/DEVLOG|CLI DevLog]]

---

## High-level architecture

- **Frontend** — React 19 + TypeScript + Tailwind. Runs in the browser today, designed for Tauri later.
  See [[BACKEND_SPEC]] for the contract the frontend expects from the native side.
- **Backend CLI** — Rust crate `n0x-cli-rs`. CLI-first, JSON-on-stdout. Ground truth for every analysis capability.
  See [[CLI_FEATURES_SPEC]] for the complete command surface and roadmap.
- **Single source of data** — both AI agents and (future) UI talk to the same CLI in JSON. No duplicate code paths.

---

## Document index

| Document | Role | Audience |
|---|---|---|
| [[MAP]] | Navigation hub (this file) | everyone |
| [[CLI_FEATURES_SPEC]] | CLI command surface, IR plan, output contract, live progress | AI agent, dev, reviewer |
| [[BACKEND_SPEC]] | What the React frontend expects from native backend (Tauri model) | frontend dev, backend dev |
| [[README]] | Frontend project root README (npm scripts, dev workflow) | frontend dev |
| [[n0x-cli-rs/README]] | CLI build instructions and quick-start examples | CLI user, AI agent |
| [[n0x-cli-rs/DEVLOG]] | Chronological log of every backend change | dev, future-you |

---

## By topic

### Reverse engineering capabilities
- Process / module / memory primitives — see [[CLI_FEATURES_SPEC#3) CLI Command Surface]] and the Quick Start in [[n0x-cli-rs/README]].
- Cross-references — [[CLI_FEATURES_SPEC#3.5 Cross References (Critical)]].
- Selections (named code regions for AI focus) — `selection save|list|show|xref|ir`.

### Decompilation / IR layer
- Plan and schema overview — [[CLI_FEATURES_SPEC#Decompilation / IR Layer Plan]] and [[CLI_FEATURES_SPEC#IR Schema v1 (`n0x.ir.v1`)]].
- Implementation history — [[n0x-cli-rs/DEVLOG#Decompilation / IR Layer v1 (`src/ir.rs`)]] · [[n0x-cli-rs/DEVLOG#Decompilation / IR Layer v1.1]] · [[n0x-cli-rs/DEVLOG#Decompilation / IR Layer v1.2 — slicing / view levels]] · [[n0x-cli-rs/DEVLOG#Decompilation / IR Layer v1.3 — cross-module symbols, IAT, switch hints, constant tracking]] · [[n0x-cli-rs/DEVLOG#Decompilation / IR Layer v1.4 — memory-side switch resolution]] · [[n0x-cli-rs/DEVLOG#Decompilation / IR Layer v1.5 — `ir manifest`]] · [[n0x-cli-rs/DEVLOG#Decompilation / IR Layer v1.6 — `decomp pseudo` (template-based v0)]] · [[n0x-cli-rs/DEVLOG#Added — Decompilation / IR Layer v1.7 — structured control reconstruction|v1.7 structured control reconstruction]] · [[n0x-cli-rs/DEVLOG#Added — IR Layer v1.8 — backward register slicing (`ir slice`)|v1.8 backward register slicing]] · [[n0x-cli-rs/DEVLOG#Added — IR Layer v1.9 — DOT CFG export (`ir dot`)|v1.9 DOT export]] · [[n0x-cli-rs/DEVLOG#Added — IR Layer v1.10 — edge confidence on CFG successors|v1.10 edge confidence]] · [[n0x-cli-rs/DEVLOG#Added — Decomp Structured v2 (`decomp pseudo --style structured`)|decomp structured v2]].
- Live commands — `ir build` / `ir explain` / `ir cfg` / `ir dot` / `ir slice` / `selection ir`. Examples in [[n0x-cli-rs/README]].

### AI agent contract
- View levels for IR (`full | minimal | cfg | block`) and slicing (`--block`, `--range`) — [[n0x-cli-rs/DEVLOG#Decompilation / IR Layer v1.2 — slicing / view levels]].
- Safe write workflow (`patch dry-run|apply|undo`, `.n0x/patches` journal, rollback guard) — [[n0x-cli-rs/DEVLOG#Added — Patch pipeline v1 (`patch dry-run|apply|undo`)]].

### Frontend expectations
- Required services (Process Manager / Memory Engine / Debugger / Pattern Engine) — [[BACKEND_SPEC#Core Services Needed]].
- Tauri `invoke` / `listen` model — [[BACKEND_SPEC#Communication Pattern]].

---

## Working modes

| Goal | Read first | Then |
|---|---|---|
| Run the CLI for the first time | [[n0x-cli-rs/README]] | [[CLI_FEATURES_SPEC]] |
| Wire the React UI to a real backend | [[BACKEND_SPEC]] | [[CLI_FEATURES_SPEC]] (use the CLI as the backend) |

---

## Documentation rules

- Roadmap progress (checkboxes) lives in [[CLI_FEATURES_SPEC#Implementation Progress (Live)]].
- This hub ([[MAP]]) only references — never duplicates content.

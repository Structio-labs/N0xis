# N0xis GUI — Frontend Strategy

> Status: design doc, `feat/frontend` branch. The GUI is developed in isolation
> here until it is stable enough to merge. Nothing in the engine depends on it.

## 0. First principles (non-negotiable)

1. **Thin client over the capability surface.** The GUI holds **no analysis
   logic**. Every panel is a projection of one `n0x` command's `data`
   (`ok/data/meta`). If the GUI ever needs "smartness", it belongs in the engine —
   then the CLI, MCP, and every future frontend get it for free. This is the
   project's process seam ([`n0xis-frontend`](../crates/n0xis-frontend)) and the
   `one model, many projections` rule.
2. **Beginner-friendly is a design requirement, not a coat of paint.** RE
   tooling has a steep entry curve, and lowering it is part of why this project
   exists. Every decision is judged against: *would a motivated beginner get
   unstuck here?*
   Power stays available; it never blocks the newcomer.
3. **Static and dynamic are one session, not two apps.** Rather than being a
   pure decompiler or a pure live-memory tool, N0xis binds a
   **static image** and an **optional live process** into a single target. The UI
   never makes the user "switch modes"; the dynamic panels light up when a
   process is attached, joined to the static analysis (KF-1: watchpoint →
   decompiled statement).
4. **Flexible engine, opinionated defaults.** Full Blender-style docking
   underneath (pros rearrange, add widgets, save workspaces); curated preset
   workspaces on top (beginners never face a blank canvas). Blender's own answer
   to "too much flexibility": workspaces.
5. **Modern, keyboard-first, and easy on the eyes for long sessions.**

## 1. Tech stack

| Layer | Choice | Why |
| --- | --- | --- |
| Shell | **Tauri v2** | Rust backend links the engine directly (in-process, no IPC serialization on the hot path); MIT/Apache; WebView2 on Windows (90% of users) is rock-solid. |
| UI | Web (framework TBD — Solid/Svelte/React) | Richest ecosystem for the two hardest RE widgets. |
| Code view | **Monaco** (or CodeMirror 6) | Syntax highlight, folding, minimap, find — free. The decompilation/disasm/hex star. |
| Graph | **ELK / dagre + a canvas renderer** (or Cytoscape) | CFG / call-graph layout + pan/zoom. |
| Docking | **Dockview** (or FlexLayout) | Split/join/tab/float, **serializable layouts** = workspaces as JSON. |
| Theme | CSS design tokens (variables) | Live palette swap; Monaco themes for syntax. |
| Transport | In-process Rust commands + **Tauri channels** for streams | Heavy/live data (memory, disasm) streams as binary, not JSON. |

**Linux distribution** (the one real Tauri risk): ship a **Flatpak** with a
bundled recent WebKitGTK + a launcher that sets the known NVIDIA/DMABUF
workarounds, so Linux is consistent regardless of the user's distro. `.deb`/`.rpm`/
AppImage secondary, declaring the `webkit2gtk-4.1` dependency. The multi-frontend
seam keeps an Iced frontend as a fallback if Linux ever becomes untenable.

## 2. Window shell — frameless, custom title bar

Default OS title bar is **off** (`decorations: false`). A custom title bar gives a
consistent, brandable, denser shell:

- **Custom controls**: min / max-restore / close, placed per-OS convention
  (macOS left, Windows/Linux right). `tauri-plugin-decorum` or hand-rolled.
- **Integrated menu bar** in the title bar (File / Edit / View / Analyze / Debug /
  Window / Help) — no separate strip.
- **Draggable region** across the empty title-bar area; double-click to
  maximize; snap/aero-snap preserved.
- **Resize handles** on all edges/corners (Tauri gives OS resize; verify on
  frameless).
- **Left of the menu**: target indicator (module name + `static` / `● live`
  badge). **Right**: global search, command-palette button, settings gear.

## 3. Zoom & scaling (out of the box)

Two independent levels, both first-class:

1. **Global UI scale** — one control scales *everything* (accessibility, HiDPI,
   projector). Implement with a root `rem` scale + Tauri `scaleFactor` awareness.
   `Ctrl` `+` / `-` / `0`, a View-menu slider, and a status-bar % indicator.
   Persisted per user.
2. **Per-view zoom** — code font size (`Ctrl`+wheel over a code panel); **graph
   pan/zoom** (wheel = zoom, drag = pan, `F` = fit, `1:1` reset); hex column
   density. Independent of global scale.

Rule: **nothing is a fixed pixel size that should scale** — use tokens/rem so a
zoom change never breaks a layout.

## 4. Layout system — Dockview + workspaces

- **Docking engine**: split horizontally/vertically, tab-group any panels, float a
  panel into its own window, drag to rearrange. Every panel is closeable and
  re-addable from **View → Add panel**.
- **Workspaces (presets)** — the beginner/pro reconciliation:
  - **`Decompile`** *(default, beginner)* — Functions list ▸ Decompilation ▸ AI
    Copilot ▸ Output. Minimal, guided.
  - **`Static`** — Functions/Imports/Strings ▸ Decomp + Disasm split ▸ Xrefs +
    Details ▸ Output.
  - **`Graph`** — CFG/Call-graph center ▸ Decomp side ▸ Details.
  - **`Dynamic / Debug`** — Process/Modules ▸ Registers + Stack ▸ Memory Scanner +
    Watchlist ▸ Live Memory/Hex ▸ Decomp (joined). Scanner-shaped.
  - **`Reverse` (everything)** — the dense pro layout.
  - **`Minimal`** — just Decomp + Copilot.
- **Custom workspaces**: user rearranges → **Save workspace as…** (named, JSON on
  disk). Switcher = tabs across the top (Blender-style) or a View submenu.
- **Guardrails**: always a **Reset to default layout**; a beginner who closes
  everything gets a one-click way back; first launch loads `Decompile`, never a
  blank canvas.
- **Beginner vs Pro toggle**: Beginner = curated workspace, extra tooltips/hints,
  Copilot prominent, destructive actions confirmed. Pro = full docking, add
  arbitrary widgets, dense, fewer confirmations.

## 5. The target session — what's on the first screen

The hardest question, because N0xis is **both** static and dynamic. Answer: a
**Welcome / Launcher screen** that frames the *three ways to bind a target*, then
drops into the `Decompile` workspace.

```
┌──────────────── N0xis ────────────────┐
│  Open a target:                        │
│   ▸ Analyze a file        (static)     │  → pick .exe/.dll/.so/.elf
│   ▸ Attach to a process   (dynamic)    │  → process picker (list, search)
│   ▸ Launch & attach       (both)       │  → pick .exe, spawn, attach
│                                        │
│  Recent targets:  [ … ]                │
│  Learn:  Getting started · Glossary    │
└────────────────────────────────────────┘
```

**Session model** — one `Target` binds:
- a **static image** (file) — always present for `Analyze` / `Launch & attach`;
  optional for a bare `Attach` (we may only have a live process, no file).
- an **optional live process** (pid) — ASLR-mapped to the static image so the
  same function has one identity across the static listing and the live memory.

So the three entry points are just *which halves are bound*:

| Entry | Static image | Live process | Use |
| --- | --- | --- | --- |
| Analyze a file | ✓ | — | pure decompilation / RE |
| Attach to a process | (optional, auto-resolve) | ✓ | inspect a running game |
| Launch & attach | ✓ | ✓ (spawned) | full static⇄dynamic |

The UI **never says "static mode / dynamic mode."** Dynamic panels are simply
enabled once a process is bound; the target badge shows `static` or `● live`. A
user analyzing a file can **Attach** later from the toolbar; a user attached to a
process can **Load the file** for full static analysis — both halves converge on
the same session.

## 6. Panel catalog (every panel = one capability)

### Navigation (left rail)
| Panel | Backing capability |
| --- | --- |
| Functions | function list / `profile`, symbol sources |
| Imports / Exports | `profile` (IAT/EAT) |
| Strings | string scan |
| Types / Structures | recovered structs, RTTI (`rtti scan`) |
| Sections / Segments | `profile` sections |
| Symbols / Signatures | FLIRT (`sig gen`/`--flirt`), WARP (`warp dump`) |
| Bookmarks / Annotations | project annotations |

### Code & graph (center)
| Panel | Capability |
| --- | --- |
| **Decompilation** (pseudo-C) | `decomp pseudo` — style toggle goto/structured/ssa, clickable symbols, inline provenance |
| Disassembly / Listing | `disasm` — synced to decomp |
| Hex | raw bytes — synced selection |
| **CFG graph** | `ir dot` / `ir build` |
| Call graph | xref graph |

### Context (right rail)
| Panel | Capability |
| --- | --- |
| **AI Copilot** | MCP/engine — context-aware chat, "explain / guide me / do it" |
| Xrefs (to / from) | static xrefs **+ live hit counts** |
| Details / Inspector | recovered signature, types, comments, **provenance for the selected line** |

### Dynamic (enabled when live)
| Panel | Capability |
| --- | --- |
| Process / Modules | `process ps`, `module list` |
| Registers | live register file |
| Stack / Threads | thread list, stack walk |
| **Memory Scanner** | value scan / refine (`scan`) → watchlist |
| **Watchlist / Watchpoints** | HW watchpoints, **"find what accesses" hit counter**, freeze value |
| Breakpoints | execute/read/write BPs, on-hit → caller |
| Live Memory / Hex | live read, edit |
| Patch journal | journaled patches, undo |

### Bottom
| Panel | Capability |
| --- | --- |
| Output / Console | the `ok/data/meta` stream, raw command results |
| Command history | re-runnable |
| Net / Traffic (Phase 13) | `net frames` (WebSocket capture) |

## 7. Context menus (right-click, object-specific)

Deliberately overlaps toolbar/menu actions — some users prefer buttons, some
prefer right-click. Every context action also lives in a menu or the palette.

**On a function** (list or code): Decompile · Disassemble · Show CFG · Show call
graph · Rename (F2) · Add comment · Find xrefs to / from · Copy name / address ·
Set execute breakpoint · Apply / generate signature · Bookmark · Ask Copilot
about this.

**On a code line / instruction**: Copy address · Show in disasm / hex · Follow
jump/call · Set watchpoint (R/W/X) · **Find what accesses this** ·
Provenance — what wrote this · Patch instruction (NOP / edit) · Add comment · Ask
Copilot to explain this line.

**On a data address / global**: Rename · Set type · Watch (R/W) · **Find what
accesses / writes** (hit counter) · Show xrefs · Show in hex · Copy address.

**On a memory-scan result**: Add to watchlist · Freeze value · Watch (R/W) · Find
what accesses · Set access breakpoint · Show in hex · Show in decomp (if mapped).

**On a process / module**: Attach · Detach · Dump module · Refresh · Open file for
static analysis.

**On selected bytes (hex)**: Copy hex · Copy as AOB pattern · Scan for this
pattern · Patch · Set watchpoint on range.

**On empty layout / tab bar**: Split right / down · Add panel ▸ · Float panel ·
Close · Reset layout · Save workspace.

## 8. Settings window

Categorized (left nav), searchable:

- **Appearance** — theme (palette presets + custom editor), UI scale, UI font,
  code font + size, density (compact/comfortable), accent color, syntax color
  scheme, animations on/off.
- **Layout** — default workspace, restore last layout on open, beginner/pro mode,
  tab vs split defaults, Copilot docked vs overlay.
- **Editor / Code** — decomp default style (goto/structured/ssa), tab width, word
  wrap, minimap, line numbers, inline provenance, hex bytes-per-row & grouping.
- **Analysis** — auto-analysis depth, signature databases (FLIRT `.npat` / WARP
  paths), demangler options, arch override, symbol sources order.
- **Dynamic / Debug** — default watchpoint kind, hit-counter cap, scan defaults
  (type/alignment), ASLR handling, **safety: confirm before patch/write/attach**,
  undo-journal retention.
- **AI Copilot** — model/endpoint, context level (selection / function /
  program), auto-explain on select, **privacy: what is sent** (explicit).
- **Keybindings** — fully rebindable, with importable keymap presets for users
  migrating from other tools; the N0xis default ships out of the box.
- **Onboarding / Guides** — tooltips on/off, beginner hints, glossary,
  link-outs to the web docs.
- **Advanced** — MCP/command-server port, logging level, **telemetry off by
  default**, plugin management, reset all settings.

## 9. Themes & customization

Long sessions need palette variety — a first-class feature, not an afterthought.

- **Ship several palettes**: `Midnight` (default dark), `Deep` (darker/OLED),
  `Light`, `High-contrast` (accessibility), `Warm/Sepia` (eye comfort), plus a
  couple of loved-classic-inspired dark schemes.
- **Custom palette editor** — the theme is a set of **design tokens** (bg
  surfaces, text, accent, semantic colors, syntax roles). Edit live, save, export/
  import (JSON) and share.
- **Syntax themes** for Monaco selectable independently of the app chrome theme.
- **Accent color** pickable separately (one knob most users want).

## 10. Command palette & discoverability

- **`Ctrl`+`P` command palette** — fuzzy over **every** capability, generated from
  the `n0x guide` catalog (so it never drifts from the backend). This is the
  beginner's "how do I…" and the pro's fast path in one.
- **`Ctrl`+`K`** — go-to symbol / address / string.
- Every command shows its shortcut + a one-line description (from the guide),
  which doubles as onboarding.

## 11. AI Copilot integration

- **Context-aware**: knows the current target, function, selection, and last
  command results.
- **Three verbs**: *Explain* (this function / line / abbreviation / concept),
  *Guide me* (walk me through a task, e.g. "find the health value"), *Do it*
  (drive the actual commands with the user watching).
- Docked right by default (beginner), collapsible/overlay for pros.
- Grounded in the same JSON surface the GUI uses — it can point at panels
  ("open the Xrefs panel, top-right") and execute real capabilities.

## 12. Onboarding & guides (beginner layer)

- **Welcome screen** → getting-started + glossary links.
- **Contextual tooltips** from the guide catalog (auto-generated, don't rot).
- **Glossary** of abbreviations/concepts (HLIL, SSA, xref, void\*, RVA, …) — in-app
  panel + a web docs site as the source of truth; tooltips deep-link to it.
- **Beginner hints**: dismissible "what am I looking at" call-outs per panel.
- Theory lives primarily **on the web** (discoverable, updatable without a
  release); the app links into it. Pros just turn all of this off.

## 13. Architecture & data flow

- **Selection/context bus** — one shared `current = { target, function, address,
  line, selection }`. Panels read from it; any click updates it; every panel
  re-projects. This is the "everything is spliced together" behavior.
- **Backing calls** — Tauri commands wrapping the engine in-process for
  request/response; **channels** for streams (live memory, disasm paging, scan
  progress) as binary payloads.
- **Persistence** — layouts, workspaces, settings, themes, keybindings, recent
  targets, per-target annotations → JSON on disk (same structured ethos as the
  rest of N0xis).
- **Every panel maps to a capability**; adding an engine command ≈ adding a
  panel/menu entry with near-zero glue.

## 14. Build order (incremental, always usable)

1. **Shell + session**: frameless window, welcome/launcher, target binding,
   Output panel, command palette (guide-driven), global zoom, one theme.
2. **MVP workspace** (`Decompile`): Functions list + Decompilation (Monaco) + AI
   Copilot + selection bus. Usable end-to-end for a first decompile.
3. **Static depth**: Disassembly (synced) + Xrefs + Details/provenance + Hex.
4. **Docking + workspaces**: Dockview, presets, save/reset, beginner/pro.
5. **Themes**: palette presets + custom editor + syntax themes.
6. **Graph**: CFG + call graph (pan/zoom).
7. **Dynamic**: Process/Modules → attach → Registers/Stack → Memory Scanner +
   Watchlist (access hit counter) → Live Memory → Patch journal.
8. **Settings** grows alongside each area; keybinding presets last.

## 15. Workflow note

All frontend work stays on **`feat/frontend`** until it is stable and the engine
contract it needs is frozen. The engine (`main`) never depends on the GUI. Merge
when the MVP workspace (step 2–3) is solid.

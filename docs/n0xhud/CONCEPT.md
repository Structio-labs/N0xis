# N0xHUD — the concept

**A universal, config-driven cheat-menu overlay for any window, built on the
n0xis engine.** Press a key (default **F2**), a menu appears *over* the target
window, input to the game is frozen while it's open, and every entry — toggle,
value, hotkey — is defined in that game's `.n0x/` config folder, not compiled
in. The cheats themselves execute through n0xis's existing value-scanning
memory work (scan / freeze / pointer-path / patch / `.n0xt` tables).

> **Status: design only.** Nothing here is built yet. This document and
> [ROADMAP.md](ROADMAP.md) are the plan; they follow the same phased,
> exit-test-gated, honest-about-limits discipline as n0xis's own
> [CONCEPT.md](../../CONCEPT.md)/[ROADMAP.md](../../ROADMAP.md).

## Where it sits

N0xHUD is **part of n0xis, not a separate project** — a third frontend
alongside the CLI (`n0xis`) and MCP server (`n0xis-mcp`), shipped as its own
binary `n0xis-hud`. It is a *frontend over the same core*: it renders a menu and
routes user intent, but every actual memory operation goes through the existing
n0xis crates. It adds **zero** analysis logic of its own.

```
n0xis-core / n0xis-sources / n0xis-project   ← the engine (scan, freeze, patch,
                                                pointer-path, .n0xt tables) — unchanged
        ▲
        │  (linked as a library, exactly like the CLI/MCP frontends)
        │
   n0xis-hud (+ n0xis-overlay, n0xis-input)  ← THIS: overlay window + input
                                                isolation + declarative menu
```

Because the memory engine already exists, N0xHUD is "the interactive, on-screen,
runtime face of a `.n0xt` table" — the piece n0xis was missing between a table
file and a player holding a controller.

## The five layers

Each is a seam (a trait / a wire contract), so any one can be swapped without
touching the others — the same modularity rule n0xis holds for its `Arch` and
source seams.

1. **Overlay** (`n0xis-overlay`) — puts a UI surface *on top of* a target
   window. Default backend: an external, transparent, always-on-top,
   click-through window (no injection, can't crash the game, works for any
   *borderless/windowed* game). The backend is a trait so an **injected**
   backend (hook the game's `Present`/swapchain, draw in-process) can slot in
   later for *exclusive-fullscreen* games — the menu/model layers above never
   change.

2. **Input** (`n0xis-input`) — a global low-level keyboard/mouse hook. Owns the
   **menu-toggle key** (F2 by default, configurable), **swallows input so it
   never reaches the game while the menu is open** (true input isolation, not
   just "steal focus"), and runs the **hotkey engine** that fires cheat binds
   even when the menu is closed (like a memory scanner / `.n0xt` hotkeys).

3. **Menu** (`n0xis-hud::menu`) — a **declarative, data-driven** model:
   sections, toggles, sliders, value fields, buttons, keybind widgets. It
   renders a `.n0xt` table directly and is **hot-reloadable**. Adding a new game
   is *data*, not a recompile.

4. **Adapter** — how a specific game plugs in. The simplest adapter is *pure
   config* (a `.n0xt` table + a `hud.toml`); for cheats that need real logic
   (a live pointer-path resolve, an offline asset patch, a game-specific
   sequence) an adapter is a **n0xis plugin** (the process-based JSON-over-stdio
   plugin protocol already proposed in n0xis's
   [COMMUNITY_ROADMAP](../COMMUNITY_ROADMAP.md)). "The per-game patch that talks
   to the cheat-menu API" *is* this adapter.

5. **Engine** — n0xis. A menu toggle maps onto an existing n0xis operation:
   `freeze` a `.n0xt` entry, apply a `patch`, resolve+freeze a `pointer-path`,
   run a `scan`. N0xHUD never re-implements any of it.

## Everything runs through `.n0x/` (the config folder)

Every game is a **n0xis project** — a folder with a `.n0x/` directory, exactly
as n0xis already uses today. N0xHUD adds two config surfaces inside it; there is
**no hard-coded key or cheat anywhere in the binary**:

- **`.n0x/hud.toml`** — global HUD config for this game: the menu-toggle key,
  whether input-isolation is on, overlay opacity/theme, and which `.n0xt`
  tables to load into the menu.
  ```toml
  [menu]
  toggle_key   = "F2"        # any key, rebindable here
  isolate_input = true       # freeze game input while the menu is open

  [overlay]
  opacity = 0.92
  theme   = "dark"

  tables = ["helldivers.n0xt"]   # which .n0xt files become menu sections
  ```
- **`.n0xt` tables** — the cheats themselves. Each entry already carries
  `name`, `value_type`, `frozen`, `freeze_value`, `groups`, and a **`hotkey`**
  field — so a per-cheat bind is *already* a config value in the table n0xis
  writes. N0xHUD renders each entry as a menu row and honors its `hotkey`.

Result: a player (or a shared community profile) tweaks one folder; the binary
is fixed. "Any button bindable in config" is satisfied by `hud.toml.toggle_key`
plus each `.n0xt` entry's `hotkey`.

## Overlay: how, and the honest limits

The default external-overlay backend, on Windows:

- A `WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TOOLWINDOW` window, its rect tracked
  to the target window (via `SetWinEventHook` on move/resize, not a busy poll).
- Rendered with **egui** on a transparent surface (DirectComposition /
  `windows` crate for the compositing layer).
- **Click-through when idle**: `WS_EX_TRANSPARENT` is set while the menu is
  closed, so the overlay is invisible-to-input and the player plays normally.
  Opening the menu clears `WS_EX_TRANSPARENT` and focuses the overlay.

**Limits, stated up front (not discovered later):**

- Works cleanly for **borderless-windowed** games — the common case, and what
  we target first. For **exclusive-fullscreen**, an external window cannot draw
  on top; the answer is either "run the game borderless" or the injected
  backend (a later phase). This is a documented seam, not a dead end.
- Input isolation via low-level hooks reliably swallows keyboard and mouse
  *buttons*; games reading devices through **RawInput/DirectInput** are still
  covered because the hook drops the event before any process sees it, but this
  is the area to verify hardest against real games (per n0xis Product Policy §7,
  "test against real behavior").

## Adapter model — a game is a profile

To support a game you create a **profile** (a `.n0x/` project). For most cheats
that's *only data*: a `.n0xt` table of addresses/pointer-paths + a `hud.toml`.
For anything needing logic, the profile also declares a **n0xis plugin** (the
existing process/stdio protocol) that N0xHUD calls when a menu action fires.

**Worked example — Helldivers 1** (the game that motivated this): the profile's
"Infinite magazines" toggle can be wired to any of three adapter action types,
all of which n0xis already supports the pieces for:
- a **live pointer-path freeze** on the reserve-mag field (runtime, toggleable
  instantly — the natural fit for a menu), or
- an **offline asset patch** action (the `n0xis lua patch` + `bundle repack`
  path already built — flips the game's own `infinite_mags` bytecode flag;
  requires a game restart, so it reads as a "one-shot apply" button, not a
  live toggle), or
- an **AOB-anchored code patch** via `n0xis patch detour`.

The menu doesn't know or care which — it shows a toggle and calls the adapter.

## Proposed crate layout

Consistent with n0xis's fine-grained, single-responsibility crate style:

```
n0xis-overlay/   the render-surface seam + external transparent-window backend
n0xis-input/     low-level hooks: toggle key, input isolation, hotkey engine
n0xis-hud/       menu model + hud.toml config + the n0xis-hud binary; wires
                 overlay + input + engine (n0xis-core/sources/project)
```

`n0xis-overlay`/`n0xis-input` are OS-facing (behind the `live`-style feature
gate, like `n0xis-sources`); `n0xis-core` stays OS-free and untouched.

## Design rules (inherited from n0xis)

N0xHUD is held to n0xis's [Product Policy](../PRODUCT_POLICY.md) verbatim —
modularity via seams, anti-hardcode (**no key, cheat, or game constant baked
into the binary — it all lives in `.n0x/`**), sound-over-complete (a cheat that
can't be applied safely refuses and says so, never half-applies), and
"test against real behavior" (every overlay/input capability is verified against
a real window and a real spawned process, not a mock).

## Non-goals

- **Not** an anti-cheat-evasion tool. External overlay + LL hooks are for
  single-player / offline use; no stealth, no signature-dodging.
- **Not** a new memory engine — it is strictly a frontend over n0xis.
- **Not** a per-game recompile — games are `.n0x/` profiles (data + optional
  plugin), never hard-coded into `n0xis-hud`.

# N0xHUD — roadmap

The phased build plan, in the same shape as n0xis's own
[ROADMAP.md](../../ROADMAP.md): every phase has a **goal**, concrete
**deliverables**, and an **exit test** that must pass against *real* software
(a real window, a real spawned process) before the phase counts as done —
n0xis Product Policy §7. Scope deliberately cut from a phase is written down as
a "documented follow-on", never silently dropped.

**This plan has been overtaken by what shipped.** A working `n0xis-hud` binary
exists (config-driven companion window, global hotkeys, write & freeze,
watchers), but it got there by a different route than the phases below assume:
it renders as its **own window** instead of drawing inside the target, so the
in-target overlay work (an injected surface + a graphics-API present hook) is
still unbuilt and the phase list still describes it as the starting point. Read
the phases below as the overlay design that hasn't landed, not as the status of
the shipped binary; they need re-cutting against what the companion-window model
actually made unnecessary. See [CONCEPT.md](CONCEPT.md) for the architecture,
and `crates/n0xis-hud/src/main.rs` for the shipped model's own rationale.

---

## Phase 0 — Skeleton & seams 🎯

Goal: the workspace shape and the two hardware-facing seams, with a trivial
implementation behind each, so later phases are "fill in a trait", not
"re-architect".

- Add crates `n0xis-overlay`, `n0xis-input`, `n0xis-hud` to the workspace
  (feature-gated OS deps, `n0xis-core` stays OS-free).
- `trait OverlaySurface` (create/resize/present a UI surface bound to a target
  window) and `trait InputBackend` (install/remove hooks, deliver events) —
  the seams the CONCEPT names, each with one stub impl.
- `n0xis-hud` binary that parses args (`--pid` / `--window` target) and loads a
  `.n0x/` project via the existing `n0xis-project` resolver.

**Exit test**: `n0xis-hud --pid <n>` attaches to a real running process's
main window, resolves its `.n0x/` project, and prints the resolved config paths
+ target window rect — no UI yet, but the whole skeleton links and runs.

## Phase 1 — The overlay draws 🎯

Goal: a transparent, always-on-top surface that visibly renders *over* a real
target window and tracks it as it moves/resizes.

- External-window `OverlaySurface` backend: layered + topmost + tool-window,
  transparent, composited (DirectComposition via the `windows` crate).
- egui render loop drawing a placeholder panel; window rect tracked to the
  target via `SetWinEventHook` (event-driven, not polled).
- Click-through while idle (`WS_EX_TRANSPARENT`), so the target is fully usable
  underneath.

**Exit test**: launch a real windowed app (e.g. Notepad or a spawned game),
run `n0xis-hud`, and confirm an egui panel is drawn on top, stays anchored when
the target window is dragged/resized, and that clicking through the idle
overlay reaches the app underneath.

## Phase 2 — F2, and true input isolation 🎯

Goal: the menu toggles on a configurable key, and while it's open the game
receives *no* input.

- `n0xis-input`: global `WH_KEYBOARD_LL` / `WH_MOUSE_LL` hooks. Toggle key
  read from `.n0x/hud.toml` (`[menu] toggle_key`, default F2).
- While the menu is open: swallow keyboard + mouse events so no other process
  sees them; overlay clears `WS_EX_TRANSPARENT` and takes focus/input. While
  closed: pass everything through.
- Documented follow-on: RawInput/DirectInput edge cases catalogued per game as
  they're found (LL hooks drop events pre-delivery, which should cover these,
  but this is the area to keep testing).

**Exit test**: with a real app focused, open the N0xHUD menu and confirm typing
and mouse clicks do **not** reach the app (verified by the app showing no
input), then close the menu and confirm input flows again. Toggle key changed
in `hud.toml` takes effect on reload.

## Phase 3 — The menu is a `.n0xt` table 🎯

Goal: the menu is fully declarative and config-driven — a `.n0xt` table renders
as menu sections/rows, and each entry's `hotkey` binds.

- `n0xis-hud::menu`: render `n0xis-project`'s `.n0xt` `TableEntry` set as
  rows (name, editable value, freeze toggle, group → section), driven by
  `hud.toml`'s `tables = [...]`.
- The hotkey engine wires each entry's `hotkey` field to its toggle, live even
  when the menu is closed.
- Hot-reload: editing `.n0xt` / `hud.toml` on disk refreshes the menu.

**Exit test**: hand-write a `.n0xt` table with two grouped entries and hotkeys;
N0xHUD renders them as a two-section menu, and pressing an entry's hotkey (menu
closed) flips its frozen state — confirmed by reading the table state back.

## Phase 4 — Cheats actually fire (engine wiring) 🎯

Goal: a menu toggle performs a real n0xis memory operation against a live
process.

- Wire menu actions to `n0xis-core`/`n0xis-sources`: freeze/unfreeze a
  `.n0xt` entry (the existing freeze loop), edit a value, resolve+freeze a
  pointer-path entry.
- Value edits and freezes run against the attached `--pid` target through the
  same code the CLI's `table freeze` / `scan` use.

**Exit test**: against a **real spawned process** with a known writable value
(the pattern from n0xis's `phase4b_exit.rs`), toggle a freeze from the menu and
confirm the value is held; untoggle and confirm it moves again.

## Phase 5 — Per-game adapters & the Helldivers profile 🎯

Goal: a game with real cheat logic plugs in as a profile + optional plugin, and
the principal Helldivers "infinite magazines" toggle works end to end.

- Adapter contract: menu actions can call a **n0xis plugin** (the process/stdio
  protocol from n0xis's COMMUNITY_ROADMAP) for game-specific logic, in addition
  to pure-data `.n0xt` cheats.
- Helldivers `.n0x/` profile: `hud.toml` + a `.n0xt` table + an adapter action
  for infinite mags (live pointer-path freeze as the toggle; the offline
  `lua patch`/`bundle repack` path exposed as a separate "apply (needs
  restart)" button).

**Exit test**: with Helldivers running, the N0xHUD menu shows an "Infinite
magazines" toggle that, enabled, stops reserve magazines from decreasing —
verified in-game.

## Phase 6 — Injected backend for exclusive-fullscreen 🎯

Goal: cover games the external overlay can't draw over, without changing any
layer above the surface seam.

- A second `OverlaySurface` impl that injects and hooks the game's
  `Present`/swapchain (D3D11/D3D12/Vulkan/GL), rendering egui in-process; input
  via a WndProc hook.
- Selected per-profile (`[overlay] backend = "injected"`); the menu/model/engine
  layers are untouched.
- Documented follow-on: per-graphics-API hooks land incrementally (D3D11 first);
  anti-cheat interaction is explicitly out of scope (single-player only).

**Exit test**: an exclusive-fullscreen D3D11 game shows the same menu, driven by
the same `.n0x/` profile, as the external backend does for a borderless one.

## Phase 7 — Polish & sharing 🎯

Goal: it feels like a finished trainer UI, and profiles are shareable.

- In-menu keybind capture ("press a key to bind", written back to config),
  theming, layout/persistence, a value-scanner panel (drive `scan value`/
  `filter` from the overlay).
- Import/export a `.n0x/` profile as a shareable bundle (the `.CT`-analog
  distribution story from the CONCEPT).

**Exit test**: bind a key through the menu (not by editing files), confirm it
persists to `.n0x/hud.toml`; export a profile, re-import it into a clean
project, and confirm the menu is identical.

---

## Community / follow-on backlog

- **Linux/X11/Wayland overlay backend** behind the same `OverlaySurface` seam.
- **Controller (gamepad) binds** alongside keyboard, in the same config model.
- **Drive the menu over n0xis MCP** — let an agent flip cheats/inspect state
  through the same actions a human uses (ties N0xHUD back into the agent-native
  story n0xis is built around).
- **Profile repository** — a shared index of community `.n0x/` game profiles.

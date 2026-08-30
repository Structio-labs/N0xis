# N0xHUD — roadmap

The phased build plan, in the same shape as n0xis's own
[ROADMAP.md](../../ROADMAP.md): every phase has a **goal**, concrete
**deliverables**, and an **exit test** that must pass against *real* software
(a real window, a real spawned process) before the phase counts as done —
n0xis Product Policy §7. Scope deliberately cut from a phase is written down as
a "documented follow-on", never silently dropped.

Legend: 🎯 milestone · ✅ done · ⏳ in progress · ⬜ todo · ⚠️ caveat.

N0xHUD (binary `n0xis-hud`) is the **interactive, on-screen face of the same
engine** the CLI (`n0xis`) and MCP server (`n0xis-mcp`) drive — runtime
instrumentation and live-memory analysis plus input actuation, not a separate
tool. It is held to the same [Product Policy](../PRODUCT_POLICY.md) and to the
same positioning as the rest of n0xis: an RE / dynamic-analysis frontend, single
-player / offline use only. The command surface it drives is the same one the
CLI documents in [docs/CLI_COMMANDS.md](../CLI_COMMANDS.md).

---

## Reality check — this plan was overtaken by what shipped

**A working `n0xis-hud` binary exists and it took a different route than the
phases below assume.** The original plan below was written around an *in-game
overlay* (an injected surface + a graphics-API present-hook, tracking the target
window's rect). That is **not** what shipped. The shipped binary is a plain,
always-on-top **companion window** (`eframe`/`egui`, titled "N0xHUD",
360×520) — the a separate always-on-top window model — that deliberately does **not** draw inside
the target. Its own module doc (`crates/n0xis-hud/src/main.rs`) states this
outright and claims it works reliably today including for fullscreen games; that
last claim is the binary's own and is flagged below as claim-to-verify (§Phase 6).

Because it renders its own window, an entire cluster of the planned overlay
machinery turned out to be **unnecessary**, and a cluster of capabilities the
plan never anticipated **shipped instead**. Read the phases below as re-cut
status, not as the original overlay design:

**Shipped, working today** (`crates/n0xis-hud/src/`):

- ✅ **Companion window** — always-on-top `eframe`/`egui` native window; header
  (target status), central menu panel, resizable scrollable footer log
  (500-line buffer, copy/clear). `main.rs`.
- ✅ **Config-driven, nothing hardcoded** — every key, process name, adapter, DLL
  path comes from `.n0x/hud.toml`; runtime edits persist to separate JSON so the
  shipped toml stays untouched. `config.rs`, `engine.rs`.
- ✅ **Process watcher + auto-apply** — polls for `watch.process_name`, sets the
  pid on match, drives every adapter binding's `run_on_launch` action (there is
  no per-adapter opt-out — every binding is run), retrying every 3 s until it
  lands; clears live state on exit. `watcher.rs`.
- ✅ **Write & freeze** — a `FreezeWorker` thread rewrites a `.n0xt` entry's
  `freeze_value` every 50 ms (pointer-path locators included). `freeze.rs`,
  `engine.rs`.
- ✅ **Global hotkeys** — `WH_KEYBOARD_LL` hook on its own thread; down-transition
  only, injected keystrokes ignored, HUD-bound keys swallowed so the game never
  double-sees them; F2 shows/hides the window even when egui isn't ticking.
  In-UI keybind capture with conflict detection across all four binding
  namespaces. `input.rs`, `engine.rs`, `menu.rs`.
- ✅ **Interception driver input** — dynamically loads a user-configured
  `interception.dll` (path from `hud.toml`, no build-time link) and sends
  keyboard strokes through the kernel-class driver, indistinguishable from
  hardware. Exists for the class of games that accept a real keypress but
  ignore the identical scancode via `SendInput` (they filter
  `LLKHF_INJECTED`). `interception.rs`.
- ✅ **Declarative menu from `.n0xt` tables** — grouped `TableEntry` rows honoring
  each entry's `hotkey`; rebind popups; solver/stratagem/sequences panels. `menu.rs`.
- ✅ **Stratagem macros** — hold Ctrl + tap a direction code, sent via Interception,
  with independent hold/gap speed knobs and a bindable hotkey. `engine.rs`, `menu.rs`.
- ✅ **Sequences / "Combinations" replay** — replay a fixed direction combo via
  `SendInput`, configurable per-step delay + hold; run button or bindable hotkey.
  `sequence.rs`.
- ✅ **Process-based plugin protocol** — `adapters/mod.rs` dispatches every
  binding's `on_launch`/`toggle_on`/`toggle_off`/`poll` to a spawned,
  long-lived plugin process over newline-delimited JSON on stdio
  (`n0xis_sources::PluginSession`), instead of an in-binary Rust match. Any
  per-game logic — AOB patches, live-memory automation, whatever a specific
  title needs — lives entirely in an external plugin executable named in
  `hud.toml`, never compiled into `n0xis-hud` itself. `adapters/mod.rs`,
  `plugin_poll.rs`, `engine.rs`.

**Unbuilt** (the original overlay design; still a legitimate follow-on):

- ⬜ In-target overlay drawing (injected surface + present-hook + rect tracking).
- ⬜ True input isolation ("freeze game input while the menu is open"):
  `isolate_input` is parsed in `config.rs` but **never read anywhere** — there is
  no "menu open" concept; the hook only ever swallows the *specific* HUD-bound keys.
- ⬜ The separate crates `n0xis-overlay` and `n0xis-input` were **never created** —
  everything lives inside `n0xis-hud/src/` (single crate).
- ⬜ Hot-reload of `.n0xt` / `hud.toml` (tables load once at startup).
- ⬜ In-menu value editing (rows are on/off freeze checkboxes only), value-scanner
  panel, profile import/export bundle.

See [CONCEPT.md](CONCEPT.md) for the architecture (also re-cut against this
reality) and `crates/n0xis-hud/src/main.rs` for the shipped model's own rationale.

---

## Phase 0 — Skeleton & seams 🎯 — ✅ done, ⚠️ different shape

Goal: the workspace shape and the two hardware-facing seams, with a trivial
implementation behind each.

- ⬜ **`n0xis-overlay` / `n0xis-input` crates** — *not created*. The intended
  seam split never happened; all HUD code lives in the single `n0xis-hud` crate
  (`engine / input / interception / menu / config / watcher / combo_watcher /
  freeze / sequence / sound / adapters`). `n0xis-core` did stay OS-free.
- ⬜ **`trait OverlaySurface` / `trait InputBackend`** — *not created* as traits;
  input is a concrete `WH_KEYBOARD_LL` hook, there is no overlay-surface abstraction.
- ✅ **`n0xis-hud` binary loading a `.n0x/` project** — done, but it takes **no
  `--pid` / `--window` args**. It resolves the `.n0x/` project from cwd
  (`n0xis_project::resolve()`), loads `.n0x/hud.toml`, and finds the target
  **itself** by `watch.process_name`.

**Exit test (re-cut)**: launched from a game's `.n0x/` directory, `n0xis-hud`
resolves the project, loads `hud.toml`, and — via the watcher — attaches to the
target process by name and reports its pid in the header. ✅ met by the shipped
watcher path, *not* by the original `--pid`/`--window` + window-rect skeleton.

## Phase 1 — The overlay draws 🎯 — ⬜ unbuilt (superseded)

Goal: a transparent, always-on-top surface that renders *over* a real target
window and tracks it as it moves/resizes.

- ⬜ External-window `OverlaySurface` (layered + topmost + tool-window,
  transparent, DirectComposition) — **not built**.
- ⬜ egui panel tracked to the target via `SetWinEventHook` — **not built**.
- ⬜ Click-through while idle (`WS_EX_TRANSPARENT`) — **not built**.

⚠️ **Superseded, not merely skipped.** The shipped binary is a plain always-on-top
top-level egui window with no transparency, no click-through, no compositing, and
no target-rect tracking. This whole phase is the unbuilt overlay design; it
remains a legitimate follow-on for the injected-overlay story (§Phase 6), not a
prerequisite for anything that shipped.

## Phase 2 — F2, and true input isolation 🎯 — ⏳ half done

Goal: the menu toggles on a configurable key, and while it's open the game
receives *no* input.

- ✅ **Configurable toggle key** — `[menu] toggle_key` (default F2), read from
  `hud.toml`; F2 shows/hides the window via `ShowWindow` even when egui isn't
  ticking, sidestepping Windows' foreground lock. `input.rs`.
- ✅ **Per-key swallow** — HUD-bound keys are dispatched to `engine.handle_hotkey`
  and swallowed (`return 1`) so the game never also sees them; injected keys
  (`LLKHF_INJECTED`) are ignored so the HUD's own `SendInput`/Interception combos
  don't feed back. This is a *narrower, better* mechanism than the plan's
  "swallow everything while the menu is open".
- ⬜ **True input isolation** ("game receives no input while the menu is open") —
  **not built**. `isolate_input` exists in `config.rs` but is *never read*; there
  is no "menu open" concept at all (the window is shown or hidden, independent of
  input flow). ⚠️ Documented follow-on, not a silent gap.
- ⬜ Mouse hook (`WH_MOUSE_LL`) — not built; the shipped hook is keyboard-only.

**Exit test**: partially met — the toggle key and per-key swallow work; the
"typing/clicks do not reach the app while the menu is open" half does not exist.

## Phase 3 — The menu is a `.n0xt` table 🎯 — ✅ done (⬜ hot-reload)

Goal: the menu is fully declarative and config-driven.

- ✅ **`.n0xt` table → menu rows** — `menu.rs` renders grouped `TableEntry` rows,
  driven by `hud.toml`'s `tables = [...]` (loaded via `n0xis_project::table::load_at`).
- ✅ **Per-entry hotkey binding** — each entry's `hotkey` fires its toggle live,
  even when the window is hidden (the hook thread mutates `Engine` directly).
- ⬜ **Hot-reload** — **not built**. Tables load once in `Engine::new`; there is no
  on-disk file-watch/refresh. ⚠️ Documented follow-on.

**Exit test**: met for render + hotkey-flips-frozen-state; not met for the
"edit `.n0xt`/`hud.toml` on disk and see the menu refresh" clause.

## Phase 4 — Toggles actually fire (engine wiring) 🎯 — ✅ done for freeze (⬜ value-edit)

Goal: a menu toggle performs a real n0xis memory operation against a live process.

- ✅ **Freeze / unfreeze** — `apply_toggle` is the single funnel for the checkbox,
  an in-game hotkey, and the watcher; plain entries route to a `FreezeWorker`
  (50 ms rewrite loop), pointer-path locators resolved via `resolve_table_locator`.
  `engine.rs`, `freeze.rs`.
- ⬜ **Edit a value from the menu** — **not built**. Rows are on/off checkboxes
  freezing `entry.freeze_value`; there is no value-edit widget. ⚠️ Documented
  follow-on.

**Exit test**: met for freeze (toggle holds a value, untoggle releases it) against
a real live process; the value-edit path is not present.

## Phase 5 — Per-game adapters via the plugin protocol 🎯 — ✅ done

Goal: a game with real logic plugs in as an external process, with no
game-specific Rust compiled into `n0xis-hud` itself.

- ✅ **Process-based plugin dispatch** — `adapters/mod.rs` resolves a
  `PluginSession` per `[[adapters]]` binding (spawned from the `command` in
  `hud.toml`) and sends `on_launch`/`toggle_on`/`toggle_off`/`poll` requests
  over stdio JSON. There is no in-binary game match anymore; a binding is just
  config plus a spawned executable.
- ✅ **Generic periodic polling** — `plugin_poll.rs` drives each binding's
  `poll_ms` cadence and forwards a `"poll"` op to its session, so a stateful
  external adapter (one that caches a scanned region, tracks progress, etc.)
  can run its own loop against live memory without `n0xis-hud` knowing
  anything about what it's polling for.
- ✅ **`n0xis-hud` is game-agnostic** — no title-specific AOB signatures,
  component layouts, or automation logic remain in this crate; that logic now
  lives entirely in whichever external plugin project a `hud.toml` points at.

**Exit test**: met — a stub plugin executable registered in `hud.toml`
receives `on_launch`/`toggle_on`/`toggle_off`/`poll` over stdio and the menu's
toggle rows drive it exactly like they drove the old in-binary adapters, with
zero change in UX.

### Phase 5+ — Stateful automation lives in the plugin, not here 🎯 — ✅ protocol done, per-plugin logic external

**The plugin protocol's `poll` op is designed for exactly this class of
feature**: a background loop that reads live process state (a generator seed,
a progress counter, an object handle), recomputes a deterministic result, and
actuates it — "dynamic analysis in a loop." `n0xis-hud` provides the polling
cadence (`plugin_poll.rs`), the session transport, and Interception-based
actuation as a *library* (`n0xis_sources`, `n0xis_core`, `interception.rs`
patterns) that an external plugin can reuse; it does not implement any
specific game's detect/compute/solve logic itself.

What used to be an in-binary "interact-combo auto-solver" for one specific
title has been relocated in full to that title's own external plugin project,
which independently depends on `n0xis-core`/`n0xis-sources` (including the
LuaJIT LCG helper in `n0xis-luajit::lcg`) as ordinary libraries. Its
detect/compute/solve pipeline, safety gating (step caps, stall limits, abort
on progress reset), and universal-vs-narrow solving modes are that project's
own concern and its own documentation, not n0xis's — this repo carries no
description of any single game's automation logic.

**Exit test**: met for the protocol (`poll` round-trips a stateful external
adapter correctly against a live process); any specific game's solver logic is
verified inside that game's own plugin project, out of scope for this repo.

## Phase 6 — Injected backend for exclusive-fullscreen 🎯 — ⬜ unbuilt, ⚠️ premise reframed

Goal: cover games the external surface can't draw over, via injection + a
present-hook, without changing layers above the surface seam.

- ⬜ Injected `OverlaySurface` (hook `Present`/swapchain, in-process egui, WndProc
  input) — **not built**.
- ⚠️ **The premise shifted.** The shipped companion-window model's own module doc
  claims it already handles fullscreen *without* injection (an always-on-top
  top-level window covers borderless/windowed reliably). That is a **claim to
  verify**: it holds for borderless/windowed and typically fails for true
  *exclusive*-fullscreen, which remains the honest caveat and the real reason an
  injected backend would still be wanted.

**Exit test**: not met — no injected backend exists.

## Phase 7 — Polish & sharing 🎯 — ⏳ keybind capture done; scanner/export ⬜

Goal: it feels finished, and profiles are shareable.

- ✅ **In-menu keybind capture** — "press a key to bind" with live conflict
  detection across all four binding namespaces (`.n0xt` entries, sequences, the
  combo-solver toggle, stratagem macros); rebind popups in `menu.rs`; bindings
  persist. `hotkey_owner` in `engine.rs`.
- ⏳ **Theming** — only dark/light via `hud.toml` `[overlay] theme` (dark unless
  `"light"`); no layout persistence beyond that.
- ⬜ **Value-scanner panel** (drive `scan value`/`filter` from the window) — **not built**.
- ⬜ **Profile import/export bundle** (the `.CT`-analog distribution story) — **not built**.

**Exit test**: partially met — binding a key through the menu persists; profile
export/re-import does not exist.

---

## Community / follow-on backlog

- **In-target overlay** — the injected surface + present-hook + rect tracking from
  Phases 1/6, behind a real `OverlaySurface` seam (would also revive the
  `n0xis-overlay`/`n0xis-input` crate split if it's worth it).
- **True input isolation** — wire up the parsed-but-unused `isolate_input`, add a
  "menu open" concept and mouse hook.
- **Hot-reload** `.n0xt` / `hud.toml`, and an **in-menu value-edit widget**.
- **Value-scanner panel** + **profile import/export bundle** (Phase 7 leftovers).
- **Linux/X11/Wayland** surface backend behind the same seam (once the seam exists).
- **Controller (gamepad) binds** alongside keyboard, in the same config model.
- **Drive the menu over n0xis MCP** — let an agent flip instrumentation / inspect
  state through the same actions a human uses (the same contract every n0xis
  frontend goes through).
- **Profile repository** — a shared index of community `.n0x/` game profiles.

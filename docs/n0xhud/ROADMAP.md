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
  hardware. Exists because Helldivers 1 accepts a real keypress but ignores the
  identical scancode via `SendInput` (it filters `LLKHF_INJECTED`). `interception.rs`.
- ✅ **Declarative menu from `.n0xt` tables** — grouped `TableEntry` rows honoring
  each entry's `hotkey`; rebind popups; solver/stratagem/sequences panels. `menu.rs`.
- ✅ **Stratagem macros** — hold Ctrl + tap a direction code, sent via Interception,
  with independent hold/gap speed knobs and a bindable hotkey. `engine.rs`, `menu.rs`.
- ✅ **Sequences / "Combinations" replay** — replay a fixed direction combo via
  `SendInput`, configurable per-step delay + hold; run button or bindable hotkey.
  `sequence.rs`.
- ✅ **Helldivers interact-combo auto-solver** — the main shipped capability
  (§Phase 5+). `combo_watcher.rs`, `adapters/helldivers_combo.rs`, `interception.rs`.

**Unbuilt** (the original overlay design; still a legitimate follow-on):

- ⬜ In-target overlay drawing (injected surface + present-hook + rect tracking).
- ⬜ True input isolation ("freeze game input while the menu is open"):
  `isolate_input` is parsed in `config.rs` but **never read anywhere** — there is
  no "menu open" concept; the hook only ever swallows the *specific* HUD-bound keys.
- ⬜ The separate crates `n0xis-overlay` and `n0xis-input` were **never created** —
  everything lives inside `n0xis-hud/src/` (single crate).
- ⬜ The stdio plugin adapter protocol — `adapters/mod.rs` is a plain **in-binary
  Rust function registry**, not the JSON-over-stdio plugin the plan describes.
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

## Phase 5 — Per-game adapters & the Helldivers profile 🎯 — ✅ result works, ⚠️ via in-binary adapter

Goal: a game with real logic plugs in as a profile, and the principal Helldivers
"infinite magazines" toggle works end to end.

- ✅ **Infinite magazines works** — but via the **in-binary adapter**
  `"helldivers-infinite-mags"` (`adapters/helldivers.rs`), the **only** registered
  adapter today. It AOB-scans the LuaJIT bytecode of the firearm-ammo component in
  live memory and patches one instruction (`TGETS r9 → KPRI r9,true`) so the
  reload path treats `infinite_mags` as always true. It is idempotent (matches both
  original and already-patched patterns), disambiguates the live GC copy from stale
  buffers by smallest containing region, and journals a `PatchRecord` so toggle-off
  restores the original bytes. The patch dies with the *game* process, so it
  outlives a HUD restart. ⚠️ Note: this is an **AOB-anchored live LuaJIT-bytecode
  patch**, not the "live pointer-path freeze" the plan named as the natural fit.
- ⬜ **Stdio plugin adapter protocol** — **not built**. `adapters/mod.rs` is a plain
  in-binary function registry (its own doc: *"a plain function registry today, not
  the (unbuilt) stdio plugin protocol"*). The `COMMUNITY_ROADMAP` protocol it
  points to just isn't implemented. ⚠️ Documented follow-on.

**Exit test**: met — with Helldivers running, the menu's infinite-mags toggle stops
reserve magazines from decreasing, verified in-game — but through the in-binary
adapter path, not the plugin path.

### Phase 5+ — Helldivers interact-combo auto-solver 🎯 — ✅ mines validated, ⚠️ universal opt-in gated

**The biggest shipped feature, anticipated by no original phase.** Frame it as
*dynamic analysis in a loop*: read a generator seed out of the live process,
recompute the deterministic sequence, actuate it, and verify against live state at
each step. `combo_watcher.rs` (background loop) + `adapters/helldivers_combo.rs`
(detect/compute/solve) + `interception.rs` (actuation).

Pipeline:

1. **Detect** an active interact-combo component in the running game's memory. The
   default (mine/UXO) path AOB-scans the mine/UXO type signature, then reads three
   component fields — `progress`, `interacting_unit`, `seed` — filtering
   coincidental hits by 4-byte alignment, a uint31 seed floor, and a
   plausible-progress cap. (The type `marker` is matched via the AOB *signature*,
   not read as a field; the extra `state` dword is read only in universal mode —
   see below.)
2. **Compute** the combo from the integer `seed` — no screen-reading, no hardcoded
   combo. The game generates it via a Numerical-Recipes LCG
   (`s' = s*1664525 + 1013904223 mod 2^32`, draw = `floor(u*4)`,
   `0=left 1=up 2=right 3=down`), **reverse-engineered from the native
   `Math.next_random` binding** and validated live against two independent activations.
3. **Actuate + verify** — each iteration re-reads live `interacting_unit` before
   tapping, reads live `progress` as the source of truth for the next direction,
   taps it through Interception, and confirms `progress` advanced. It stops the
   instant the window closes. Safety: `max_steps` cap, `MAX_STALLS = 3`, aborts on
   a progress reset (wrong input) — all surfaced to the footer log.

The **background loop** (`combo_watcher.rs`) caches the mine-pool region so
steady-state scans read kilobytes not gigabytes (with a periodic full rescan to
survive relocation), and keys `attempted` on the `(anchor, seed)` pair because the
component is a persistent slot reused across activations.

Two modes:

- ✅ **Default = mines/UXO only** — solved **exactly** from the seed and **never
  brute-forced** (a wrong tap detonates). This is the validated, always-safe path.
- ⚠️ **Universal (opt-in checkbox)** — detects *any* interact object with no
  per-type marker, by diffing `interacting_unit` `0xFFFF → handle` between polls
  (it reads `marker`/`state` here to enumerate slots); solves seed-first with a
  per-position brute fallback (safe only because a wrong non-mine input merely
  *resets* progress — **mines are never brute-forced regardless**), backed by an
  offline combo-template catalogue and a `learned_solutions` cache that carries
  confirmed sequences across an objective's stages. **Explicitly gated behind a
  separate live-validation checkpoint** — treat as *implemented, pending live
  validation*, not verified.

UX: solver is **off by default** and its whole panel is **hidden unless an
Interception DLL path is set** in `hud.toml`. Every detection and every pressed key
is logged to the footer.

⚠️ **Doc-reconciliation follow-on**: the solver code cites planning docs
`AUTO_COMBO_PLAN.md` and `cheats_research.md` in many places — **neither file
exists in the repo**. Either add the doc(s) or drop/redirect the citations. Until
then, [CONCEPT.md](CONCEPT.md) is the solver's primary doc coverage.

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
- **Stdio plugin adapters** — replace the in-binary registry with the
  JSON-over-stdio plugin protocol from n0xis's
  [COMMUNITY_ROADMAP](../COMMUNITY_ROADMAP.md), so games plug in as data + a plugin
  rather than a recompile.
- **Hot-reload** `.n0xt` / `hud.toml`, and an **in-menu value-edit widget**.
- **Value-scanner panel** + **profile import/export bundle** (Phase 7 leftovers).
- **Universal combo solver — finish live validation** past the gated checkpoint.
- **Linux/X11/Wayland** surface backend behind the same seam (once the seam exists).
- **Controller (gamepad) binds** alongside keyboard, in the same config model.
- **Drive the menu over n0xis MCP** — let an agent flip instrumentation / inspect
  state through the same actions a human uses (ties N0xHUD back into the
  agent-native story n0xis is built around).
- **Profile repository** — a shared index of community `.n0x/` game profiles.

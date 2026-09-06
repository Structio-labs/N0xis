# N0xHUD — the concept

**A universal, config-driven companion *window* that drives the n0xis engine's
runtime instrumentation against a live target.** Launch it from inside a game's
`.n0x/` project; it finds the target by process name, and presents an on-screen
menu whose every entry — a `.n0xt` write-&-freeze, an adapter action, an input
macro — is defined in that game's `.n0x/` config, not compiled in. Every
memory operation it performs goes through n0xis's existing dynamic-analysis
machinery (scan / freeze / pointer-path / patch / `.n0xt` tables), plus a live
input-actuation path for games that gate on where keystrokes come from.

> **Status: implemented and shipping (alpha).** A substantial `n0xis-hud`
> binary exists and runs — this document describes what it *is*, not a plan.
> (The earlier "design only, nothing built yet" banner and the *overlay* premise
> below it are obsolete; see [ROADMAP.md](ROADMAP.md) for the phase-by-phase
> plan-vs-reality reconciliation.) It follows the same honest-about-limits
> discipline as n0xis's own [CONCEPT.md](../../CONCEPT.md) /
> [ROADMAP.md](../../ROADMAP.md): "implemented and self-tested" is kept strictly
> distinct from "verified live," and the caveats are stated up front.

## It is a window, not an overlay

The single most important correction to the original concept: **N0xHUD is a
normal, separate, always-on-top OS window — it deliberately does *not* draw
inside the game.** A separate always-on-top window, not an overlay.

- A plain `eframe` / `egui` native window titled **"N0xHUD"**, `always_on_top`,
  360×520 (min 300×300). There is **no** transparency, no click-through, no
  DirectComposition, no `WS_EX_LAYERED`, and **no tracking of the target
  window's rect**. None of the compositing/overlay machinery the old concept
  described exists — and it isn't needed for this model.
- A true in-game overlay would require process injection + a graphics-API
  present-hook. That is a documented follow-on (ROADMAP Phase 6), **not** what
  ships. The binary's own rationale: an always-on-top top-level window covers
  borderless / windowed games reliably, *including fullscreen*, with no
  injection and no risk of crashing the target.
- Honest limit on the fullscreen claim: an always-on-top window sits over
  borderless-fullscreen and windowed modes reliably; **true exclusive-fullscreen
  is the usual caveat** — the window may be occluded, and the answer there is
  "run the game borderless" or the (unbuilt) injected backend. Treat "handles
  fullscreen" as the binary's own claim, verified for borderless, still to be
  hardened against exclusive-fullscreen.

## Where it sits

N0xHUD is **part of n0xis, not a separate project** — a third frontend
alongside the CLI (`n0xis`) and the MCP server (`n0xis-mcp`), shipped as its own
binary `n0xis-hud`. It is a *frontend over the same core*: it renders a menu and
routes user intent, but every actual memory / input operation goes through the
existing n0xis crates. It adds **zero** analysis logic of its own.

```
n0xis-core / n0xis-sources / n0xis-project   ← the engine (scan, freeze, patch,
                                                pointer-path, .n0xt tables) — unchanged
        ▲
        │  (linked as a library, exactly like the CLI/MCP frontends)
        │
   n0xis-hud/src/*                            ← THIS: window + menu + hotkeys +
                                                watcher + input actuation + adapters
```

> **Crate reality:** everything is inside the single crate `n0xis-hud/src/`
> (`main`, `engine`, `menu`, `config`, `input`, `interception`, `watcher`,
> `plugin_poll`, `freeze`, `sequence`, `sound`, `adapters/`). `adapters/` is
> now pure generic dispatch (see "Adapter model" below) — **zero game-specific
> Rust code lives in this crate**. The separate `n0xis-overlay` / `n0xis-input`
> crates the original concept proposed **were never created** — the
> overlay/input-isolation model they existed to hold isn't the model that
> shipped. `n0xis-core` stays OS-free and untouched.

Because the memory engine already exists, N0xHUD is "the interactive, on-screen,
runtime face of a `.n0xt` table" — the piece n0xis was missing between an
analysis table on disk and a live target reacting to it in real time.

## Architecture — one shared `Engine`, three background threads

`main.rs` builds one `Arc<Mutex<Engine>>` and hands clones to three threads it
spawns alongside the UI:

1. **`input::spawn`** — a global low-level keyboard hook (hotkeys),
2. **`watcher::spawn`** — the process watcher + adapter plugin auto-apply,
3. **`plugin_poll::spawn`** — a generic periodic poller: for any binding that
   declares `poll_ms`, calls that plugin's `"poll"` op on the host's clock. The
   host never interprets what a plugin does with a poll tick — see "Adapter
   model" below.

The design rule that makes this work: **all logic lives in `Engine`, not in the
egui `App`.** The hook thread mutates `Engine` directly, so an in-game hotkey can
toggle something *even while the HUD window is hidden* — no UI tick required.

The window itself is a header (target status: *running / pid N* or *waiting for
`<process_name>`*), a central panel (`menu::render`), and a resizable, scrollable
footer **log** (500-line ring buffer with copy / clear). Every detection and
every actuated keystroke is logged there, so a live event can later be inspected
offline with `n0xis mem read` / `scan dissect` at the exact anchor it reports.

It is launched **from inside a game's `.n0x/` project directory** — it calls
`n0xis_project::resolve()`, loads `.n0x/hud.toml`, and pins the project dir
before GL init can change cwd. It takes **no `--pid` / `--window` arguments**: it
finds the target itself by the configured process name.

## Everything runs through `.n0x/` (the config folder)

Every game is a **n0xis project** — a folder with a `.n0x/` directory, exactly
as n0xis already uses. There is **no hard-coded key, cheat, process name, or DLL
path anywhere in the binary**; it all comes from config. `.n0x/hud.toml` is the
shipped, hand-authored surface, and the sections actually parsed are:

```toml
[menu]
toggle_key    = "F2"            # window show/hide key (default F2), rebindable
# isolate_input = true          # PARSED BUT UNUSED — see note below

[overlay]
# opacity = 0.92                # PARSED BUT UNUSED (no transparent surface exists)
theme   = "dark"               # honored: dark unless "light"

[watch]
process_name = "mygame.exe"      # REQUIRED, no default — how the target is found

tables = ["mygame"]               # .n0xt tables loaded via n0xis_project::table

[interception]                    # driver settings shared by stratagems + any
dll = "C:/path/to/interception.dll"  # plugin that needs a KeySender
# device = 1

[[adapters]]                      # plugin bindings: name/table/entry + command/poll_ms
name    = "mygame-plugin"
table   = "mygame"
entry   = "some_entry"
command = "C:/path/to/mygame-plugin.exe"  # spawned once, held open — see "Adapter model"
poll_ms = 700                             # omit to disable this binding's periodic poll

[sequences]                       # + [sequences.keys] + [[sequences.combo]]
[[stratagem]]                     # stratagem macros + [stratagem_speed]
```

- **`.n0xt` tables** — the analysis entries themselves. Each already carries
  `name`, `value_type`, `frozen`, `freeze_value`, `groups`, and a **`hotkey`**
  field, so a per-entry bind is already a config value in the table n0xis writes.
  N0xHUD renders each entry as a menu row and honors its `hotkey`.
- **Honest note — three config keys are parsed but never read**: `menu.isolate_input`,
  `overlay.opacity`, and `stratagem[].modifier`. The first two are vestiges of the
  old overlay/input-isolation model — there is no "menu open" concept at all (the
  window is simply shown or hidden), and there is no transparent surface to apply
  opacity to. `stratagem[].modifier` is self-documented in the config as *"only
  `ctrl` supported today,"* but `run_stratagem_macro` hardcodes `LEFT_CTRL` and
  never reads the field — so stratagem macros are Ctrl-only because the knob is
  ignored, not because Ctrl is the sole supported value. Documented here so nobody
  wires a feature to a dead knob. (There is likewise **no** `run_on_launch` field
  on an `[[adapters]]` binding — see the watcher section; serde silently drops any
  such stray key.)
- **Runtime edits are persisted *separately*** so the shipped `hud.toml` stays
  pristine: in-UI changes go to `.n0x/sequences.json`, `.n0x/stratagem_speed.json`,
  and `.n0x/stratagem_hotkeys.json`.

## What it actually does

### Process watcher + auto-apply

Polls `n0xis_sources::list_processes()` for `watch.process_name`
(case-insensitive) once a second. On a match it records the pid and drives
**every** `[[adapters]]` binding's `on_launch` op (`Engine::run_adapter_on_launch`
— spawns/reuses that binding's plugin session and sends `{"op":"on_launch",...}`;
there is no per-binding opt-out, so every configured binding runs), **retrying
every 3 s until it lands** — a plugin's target signature often isn't resident
in memory until real gameplay loads it. When the target exits, all live state is
cleared. This is the "it just turns on once I'm in" behavior, with no manual
attach step.

### Write & freeze

`Engine::apply_toggle` is the single funnel for the three ways a toggle can
fire — the on-screen checkbox, an in-game hotkey, and the watcher — with two
back-ends:

- **Plain `.n0xt` entry → `FreezeWorker`**: a background thread resolves the
  entry's `TableLocator` once, then rewrites the encoded `freeze_value` every
  50 ms until unchecked (Drop stops the thread). **Pointer-path locators** work
  here, via `resolve_table_locator`.
- **Adapter-bound entry → a plugin process** (see "Adapter model" below).

Two-tone `Beep` feedback marks activate (880 Hz) / deactivate (440 Hz).

### Global hotkeys + in-UI rebinding

A `WH_KEYBOARD_LL` hook on its own thread, acting on the key **down-transition
only** (auto-repeat deduped via a `HELD` set):

- The **window toggle key** (default F2) shows / hides the HUD via `ShowWindow` —
  this works even when egui isn't ticking, and sidesteps Windows' foreground
  lock.
- Any other **HUD-bound** key is dispatched to `Engine::handle_hotkey` **and
  swallowed** (`return 1`) so the game never also sees it (a bind on `G` won't
  also throw a grenade). Dispatch order: stratagem macro → sequence combo →
  `.n0xt` entry toggle.
- **Injected keystrokes are ignored** (`LLKHF_INJECTED`), so the HUD's own
  actuated combos don't feed back into its hook.
- **In-UI keybind capture** ("press a key to bind") with live **conflict
  detection** across all three binding namespaces (`.n0xt` entries, sequences,
  stratagem macros); bindings persist.

### Interception input path — why a kernel driver

Some titles accept a real hardware keypress but **ignore the identical scancode
sent via `SendInput`** (they filter `LLKHF_INJECTED`) — confirmed live against a
real target (`input probe` detects this directly). So N0xHUD can dynamically
load a **user-configured `interception.dll`** via `libloading` (path from
`hud.toml`'s `[interception]` section, never build-time linked —
anti-hardcode) and send strokes through the **Interception kernel-class
driver**, indistinguishable from hardware. `KeySender` exposes `open`,
`tap(direction)` (WASD scancodes: up `0x11` / down `0x1F` / left `0x1E` / right
`0x20`), and `run_stratagem(modifier, dirs)`. It is deliberately **not**
`Send`/`Sync` — one driver context per thread.

### Input macros — sequences and stratagems

Two distinct, fully generic macro subsystems — both config-driven, no
game-specific code either way:

- **Sequences / "Combinations"** — replay a *fixed* direction combo via
  **`SendInput`**, with configurable per-step delay and hold. Run button or
  bindable hotkey. Honest limit: `SendInput` may not register in a strict
  DirectInput title (which is exactly why Interception exists).
- **Stratagem macros** — hold Ctrl and tap a direction code, sent via
  **Interception** (because the target ignores `SendInput`). Own hold/gap speed
  knobs (`[stratagem_speed]`). (The modifier is hardcoded to Ctrl:
  `run_stratagem_macro` passes `LEFT_CTRL`; the config `stratagem[].modifier`
  field is parsed but never read — see the honest note above.)

### Adapter model — how a game plugs in logic

For most entries a game is *pure config*: a `.n0xt` table + a `hud.toml`. For
anything that needs real logic, an entry binds to a **process-based plugin**
(2026-07-22, **superseding** an earlier in-binary adapter registry): an
`[[adapters]]` binding's `command` is spawned once and held open as a
`n0xis_sources::PluginSession` (`crate::adapters` — no per-binding namespace,
just a small dispatch layer over the shared plugin transport), and
`on_launch`/`toggle_on`/`toggle_off`/`poll` become JSON requests on that
session's stdio instead of a compiled-in Rust match. **`n0xis-hud` itself
carries zero game-specific logic** — every byte of it lives in the plugin
executable the user points `command` at.

> This is now the shipping shape. It's the same process-based, JSON-over-stdio
> **plugin protocol** proposed in n0xis's
> [COMMUNITY_ROADMAP](../COMMUNITY_ROADMAP.md) — built out as part of making
> `n0xis-hud` itself fully generic, and reused by `n0xis-pipeline::PluginHost`
> for the analysis-side (artifact-in, findings-out) plugin shape described
> there. The two share the same low-level transport
> (`n0xis_sources::plugin`/`linewire`) but differ in lifecycle: an
> `on_launch`/`toggle_on`/`toggle_off`/`poll` session is **persistent** (held
> open for the HUD's lifetime, since `toggle_on`/`toggle_off` fire
> synchronously on the UI thread on every click — spawning a fresh process per
> click would be a real latency risk), while an analysis plugin is
> **single-shot** (one artifact in, one findings response, exit).

A plugin's `on_launch`/`toggle_on`/`toggle_off` ops return the standard
`n0xis_project::patch::PatchRecord` shape (`{"ok":true,"record":{...}}` /
`{"ok":false,"error":"..."}`), so a plugin that (say) AOB-scans a target
process and patches a single instruction can reuse the exact same
apply/journal/undo contract `n0xis`'s own `patch` command uses — idempotency
(matching both original and already-patched byte patterns so a HUD restart
against an already-patched game doesn't spin retrying forever) and
disambiguating a live copy from a stale cached buffer are the plugin's own
responsibility, not the host's.

For a binding that also declares `poll_ms`, the host calls that same session's
`"poll"` op on a timer (`crate::plugin_poll`) and just logs whatever
human-readable note the plugin returns — the host never inspects or
interprets what the plugin does with a poll tick, or what state it keeps
between calls (a plugin is a normal long-running process; it can hold
arbitrarily complex state across polls). This was validated end-to-end
(2026-07-22) by porting a real, previously in-binary feature — an
interact-combo auto-solver reading a live generator seed, recomputing the
game's own deterministic sequence, and actuating + verifying it against live
state every step, entirely via memory reads/a kernel-driver key sender, no
screen-reading — out of this repo into an external plugin process, proving
the protocol handles genuinely stateful automation, not just simple one-shot
patches. That solver's own implementation details are documented in its own
project, outside this repo — not duplicated here, since `n0xis-hud` no longer
has any stake in them.

## Design rules (inherited from n0xis)

N0xHUD is held to n0xis's [Product Policy](../PRODUCT_POLICY.md) verbatim:

- **Modularity via seams** — a frontend over the core, swappable without touching
  the engine, exactly like the CLI/MCP frontends.
- **Anti-hardcode** — **no key, adapter, process name, or DLL path baked into the
  binary; it all lives in `.n0x/`.** Runtime edits are persisted to their own
  JSON files so the shipped `hud.toml` is never mutated.
- **Sound over complete** — a plugin's `on_launch`/`toggle_on` is expected to
  refuse (and say so) rather than half-apply; the host degrades to a clean
  error rather than pretending success when a plugin isn't reachable.
- **Test against real behavior** — the `SendInput`-vs-Interception finding was
  confirmed against a real target, not a mock (`input probe` is built
  specifically to catch this on day one of a new target). Where a capability
  is *not* yet confirmed live (exclusive-fullscreen coverage) this doc says so
  plainly.

## Non-goals

- **Not** an anti-cheat-evasion tool. An always-on-top window plus low-level
  hooks are for single-player / offline analysis and instrumentation; no stealth,
  no signature-dodging.
- **Not** a new memory engine — it is strictly a frontend over n0xis's existing
  dynamic-analysis crates.
- **Not** an in-game overlay (today) — it is a companion window. An injected,
  present-hooked overlay is a documented follow-on, not a shipped feature.
- **Not** a per-game recompile of behavior — games are `.n0x/` profiles (data +
  an optional plugin process), configured, never hand-wired into a build.
  `n0xis-hud` itself never needs a code change or a rebuild to support a new
  game.

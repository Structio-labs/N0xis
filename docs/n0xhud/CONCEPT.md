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
inside the game.** This is the a separate always-on-top window model.

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
> `combo_watcher`, `freeze`, `sequence`, `sound`, `adapters/`). The
> separate `n0xis-overlay` / `n0xis-input` crates the original concept proposed
> **were never created** — the overlay/input-isolation model they existed to
> hold isn't the model that shipped. `n0xis-core` stays OS-free and untouched.

Because the memory engine already exists, N0xHUD is "the interactive, on-screen,
runtime face of a `.n0xt` table" — the piece n0xis was missing between an
analysis table on disk and a live target reacting to it in real time.

## Architecture — one shared `Engine`, three background threads

`main.rs` builds one `Arc<Mutex<Engine>>` and hands clones to three threads it
spawns alongside the UI:

1. **`input::spawn`** — a global low-level keyboard hook (hotkeys),
2. **`watcher::spawn`** — the process watcher + adapter auto-apply,
3. **`combo_watcher::spawn`** — the Helldivers interact-combo solver.

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
process_name = "helldivers.exe"  # REQUIRED, no default — how the target is found

tables = ["helldivers"]          # .n0xt tables loaded via n0xis_project::table

[[adapters]]                     # native-adapter bindings (fields: name/table/entry only)
name  = "helldivers-infinite-mags"
table = "helldivers"
entry = "infinite_mags"

[sequences]                      # + [sequences.keys] + [[sequences.combo]]
[combo_solver]                   # interact-combo auto-solver knobs
[[stratagem]]                    # stratagem macros + [stratagem_speed]
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
  pristine: in-UI changes go to `.n0x/sequences.json`, `.n0x/combo_solver.json`,
  `.n0x/stratagem_speed.json`, and `.n0x/stratagem_hotkeys.json`.

## What it actually does

### Process watcher + auto-apply

Polls `n0xis_sources::list_processes()` for `watch.process_name`
(case-insensitive) once a second. On a match it records the pid and drives
**every** `[[adapters]]` binding's on-launch action (the adapter registry's
`run_on_launch` entry point — *this is a function name in the code, not a config
field*; there is no per-binding opt-out, so every configured binding runs),
**retrying every 3 s until it lands** — an AOB anchor often isn't in memory until
a mission loads the relevant Lua chunk. When the target exits, all live state is
cleared. This is the "it just turns on once I'm in a mission" behavior, with no
manual attach step.

### Write & freeze

`Engine::apply_toggle` is the single funnel for the three ways a toggle can
fire — the on-screen checkbox, an in-game hotkey, and the watcher — with two
back-ends:

- **Plain `.n0xt` entry → `FreezeWorker`**: a background thread resolves the
  entry's `TableLocator` once, then rewrites the encoded `freeze_value` every
  50 ms until unchecked (Drop stops the thread). **Pointer-path locators** work
  here, via `resolve_table_locator`.
- **Adapter-bound entry → a native adapter** (see below).

Two-tone `Beep` feedback marks activate (880 Hz) / deactivate (440 Hz).

### Global hotkeys + in-UI rebinding

A `WH_KEYBOARD_LL` hook on its own thread, acting on the key **down-transition
only** (auto-repeat deduped via a `HELD` set):

- The **window toggle key** (default F2) shows / hides the HUD via `ShowWindow` —
  this works even when egui isn't ticking, and sidesteps Windows' foreground
  lock.
- Any other **HUD-bound** key is dispatched to `Engine::handle_hotkey` **and
  swallowed** (`return 1`) so the game never also sees it (a bind on `G` won't
  also throw a grenade). Dispatch order: combo-solver toggle → stratagem macro →
  sequence combo → `.n0xt` entry toggle.
- **Injected keystrokes are ignored** (`LLKHF_INJECTED`), so the HUD's own
  actuated combos don't feed back into its hook.
- **In-UI keybind capture** ("press a key to bind") with live **conflict
  detection** across all four binding namespaces (`.n0xt` entries, sequences, the
  combo-solver toggle, stratagem macros); bindings persist.

### Interception input path — why a kernel driver

Some titles accept a real hardware keypress but **ignore the identical scancode
sent via `SendInput`** (they filter `LLKHF_INJECTED`). This was *confirmed live*
on Helldivers 1. So N0xHUD can dynamically load a **user-configured
`interception.dll`** via `libloading` (path from `hud.toml`, never build-time
linked — anti-hardcode) and send strokes through the **Interception kernel-class
driver**, indistinguishable from hardware. `KeySender` exposes `open`,
`tap(direction)` (WASD scancodes: up `0x11` / down `0x1F` / left `0x1E` / right
`0x20`), and `run_stratagem(modifier, dirs)`. It is deliberately **not**
`Send`/`Sync` — one driver context per thread.

### Input macros — sequences and stratagems

Two distinct macro subsystems, separate from the solver:

- **Sequences / "Combinations"** — replay a *fixed* direction combo via
  **`SendInput`**, with configurable per-step delay and hold. Run button or
  bindable hotkey. Honest limit: `SendInput` may not register in a strict
  DirectInput title (which is exactly why Interception exists).
- **Stratagem macros** — hold Ctrl and tap a direction code, sent via
  **Interception** (because the target ignores `SendInput`). Own hold/gap speed
  knobs, independent of the solver's timing. (The modifier is hardcoded to Ctrl:
  `run_stratagem_macro` passes `LEFT_CTRL`; the config `stratagem[].modifier`
  field is parsed but never read — see the honest note above.)

### Adapter model — how a game plugs in logic

For most entries a game is *pure config*: a `.n0xt` table + a `hud.toml`. For
anything that needs real logic, an entry binds to a **native adapter** — a plain
in-binary Rust function registry (`adapters/mod.rs`) whose `run_on_launch` /
`toggle_on` / `toggle_off` match on the adapter name.

> This is the honest current shape. The process-based, JSON-over-stdio **plugin
> protocol** proposed in n0xis's
> [COMMUNITY_ROADMAP](../COMMUNITY_ROADMAP.md) is a documented follow-on, **not**
> what ships — today an adapter is compiled in, not a separate process.

The one registered adapter today, **`helldivers-infinite-mags`**, is a good
worked example of what an adapter *is*: it AOB-scans the LuaJIT bytecode of the
firearm-ammo component in live memory and patches a single instruction
(`TGETS r9` → `KPRI r9, true`) so the reload path reads `infinite_mags` as always
true. It is **idempotent** (matches both the original and the already-patched
byte patterns), disambiguates the live GC copy from a stale buffer by smallest
containing region, and **journals a `PatchRecord`** so toggle-off restores the
original bytes. The patch outlives a HUD restart (it dies with the *game*
process). Note it is an AOB-anchored live-bytecode patch — *not* the "pointer-path
freeze" the old concept guessed at.

### Example adapter — the Helldivers interact-combo auto-solver

The largest capability, and the clearest illustration of the HUD as *dynamic
analysis in a loop*: read a generator seed out of the live process, recompute the
deterministic sequence it produces, actuate it, and verify against live state at
every step. No screen-reading, no hardcoded combo.

1. **Detect** an active interact-combo component in the running game's memory.
   The default path AOB-scans the mine/UXO type signature (the `marker` dword is
   matched *inside the signature*, not read back as a field), then reads the
   component's `interacting_unit` / `progress` / `seed` fields, rejecting
   coincidental hits by 4-byte alignment, a uint31 seed floor, and a
   plausible-progress cap. (The `state` and `marker` dwords are read as separate
   fields only in *universal* mode, below.)
2. **Compute** the sequence from the small integer `seed`. The game draws it from
   a Numerical-Recipes LCG (`s' = s·1664525 + 1013904223 mod 2³²`,
   `draw = floor(u·4)`, `0=left 1=up 2=right 3=down`) — **reverse-engineered from
   the native `Math.next_random` binding** and validated live against two
   independent activations. `direction_at(seed, progress)` regenerates the draw
   for the current position.
3. **Actuate + verify**: each iteration re-reads live `interacting_unit` *before*
   tapping (so the final, window-closing tap is never followed by a stray one),
   reads live `progress` as the source of truth for the next direction, taps it
   through Interception, and confirms `progress` advanced. Safety rails:
   `max_steps` cap, `MAX_STALLS`, and an abort on a progress reset (a wrong
   input) — all surfaced to the footer log.

The `combo_watcher.rs` background loop drives this on a timer (`poll_ms`, default
700 ms): it **caches the mine-pool region** so steady-state scans touch kilobytes
not gigabytes (with a periodic full rescan to survive relocation), and keys its
`attempted` set on the `(anchor, seed)` pair — the component is a persistent slot
the game reuses across activations, so the pair is what distinguishes a fresh
combo from one already solved.

Two modes, with honesty about how far each is validated:

- **Default = mines / UXO only** — solved **exactly** from the seed and **never
  brute-forced** (a wrong tap detonates). This is the validated, always-safe
  path.
- **Universal (opt-in)** — detects *any* interact object (SAM, terminal, drill…)
  with no per-type marker, by diffing `interacting_unit` `0xFFFF → handle`
  between polls (a genuine open transition). It solves seed-first with a
  per-position brute fallback — safe there because a wrong *non-mine* input only
  *resets* progress; **mines are never brute-forced regardless** — backed by an
  offline combo-template catalogue (`TEMPLATES`) and a `learned_solutions` cache
  that carries a confirmed sequence across an objective's successive stages. This
  mode is explicitly **gated behind a separate live-validation checkpoint** —
  treat it as *implemented, pending live validation*, not verified.

UX: the solver is **off by default**, and its whole panel is **hidden unless an
Interception DLL path is set** in `hud.toml`. In-UI: on/off checkbox, "Universal
(all types)" checkbox, hold/gap speed knobs, and a bindable in-game on/off
hotkey.

> Doc-debt note for maintainers: the solver's source cites a planning file
> `AUTO_COMBO_PLAN.md` (and `cheats_research.md`) in many places; **neither file
> exists in the repo** (`git ls-files` finds nothing). This concept section is
> currently the solver's primary doc coverage — either restore those planning
> docs or drop/redirect the in-code citations.

## Design rules (inherited from n0xis)

N0xHUD is held to n0xis's [Product Policy](../PRODUCT_POLICY.md) verbatim:

- **Modularity via seams** — a frontend over the core, swappable without touching
  the engine, exactly like the CLI/MCP frontends.
- **Anti-hardcode** — **no key, adapter, process name, or DLL path baked into the
  binary; it all lives in `.n0x/`.** Runtime edits are persisted to their own
  JSON files so the shipped `hud.toml` is never mutated.
- **Sound over complete** — the infinite-mags adapter refuses (and says so)
  rather than half-apply; the mine solver aborts on the first sign of a wrong
  input rather than press on.
- **Test against real behavior** — the `SendInput`-vs-Interception finding and
  the LCG model were both confirmed against the real game, not a mock. Where a
  capability is *not* yet confirmed live (universal-solver mode,
  exclusive-fullscreen coverage) this doc says so plainly.

## Non-goals

- **Not** an anti-cheat-evasion tool. An always-on-top window plus low-level
  hooks are for single-player / offline analysis and instrumentation; no stealth,
  no signature-dodging.
- **Not** a new memory engine — it is strictly a frontend over n0xis's existing
  dynamic-analysis crates.
- **Not** an in-game overlay (today) — it is a companion window. An injected,
  present-hooked overlay is a documented follow-on, not a shipped feature.
- **Not** a per-game recompile of behavior — games are `.n0x/` profiles (data +
  optional in-binary adapter), configured, never hand-wired into a build. (The
  one exception, honestly stated: a native adapter that needs real logic is
  compiled in today, until the stdio plugin protocol lands.)

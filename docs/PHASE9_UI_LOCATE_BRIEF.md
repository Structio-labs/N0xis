# Brief: `ui locate` — screen region → memory addresses (Phase 9)

**Audience**: the engineer/agent implementing this. Self-contained: you do not
need the conversation this came from.

**Status**: ⏳ **implemented, pending live validation** (working tree; not yet
committed to `main`). `ui locate` is wired into the CLI (`cmd_ui_locate`, schema
`n0xis.ui.locate.v1`) and exposed over MCP (`ui_locate`), built on the
structural-predicate scan primitive (`n0xis-core::structural` +
`ui_locate`). Its unit tests pass — predicate and overlap maths on synthetic
buffers (§9.1, §11). The decisive **§9.3 live appearance-correlation test has
NOT been run** on a real target, so this is "implemented and self-tested", **not
"verified"**; live correlation validation is still pending. Conditional
watchpoints (the sibling item) also landed in the working tree — see "What
already exists".

> Command-reference for `ui locate` (args, flags, envelope): see
> [docs/CLI_COMMANDS.md](CLI_COMMANDS.md). This file remains the historical
> implementation brief (spec, verified offsets, rejected alternatives).

---

## 1. The mission in one sentence

Given a rectangle in the target's window, report the **memory addresses of the
UI objects drawing inside it**, by hit-testing the target's own retained scene
graph from outside the process.

No graphics-API hooking. No frame capture. No reading pixels. See §6 for why
those are rejected rather than merely unnecessary.

---

## 2. Why this exists — the failure that motivated it

This is not speculative tooling. It comes from a completed campaign
(2026-07-20) against a Bitsquid/Stingray-engine game, whose full post-mortem
lives in that project's own planning docs (external to this repo). Short version:

The target had an interact mini-game: a terminal shows a row of **direction
arrows** (`up, down, down, up`), the player types them, a progress counter
advances. The goal was a solver that reads the required combination and
inputs it.

That goal **was achieved**, but by *computing* the combination (a template from
the game's own script bundles + a per-object `seed` read from memory), not by
reading it. The operator then asked the better question: why not just read the
arrows the game is already drawing? That would work for object types no
catalogue knows, and for both random and fixed combinations.

**Every attempt to find that data failed, and the failures are informative:**

| Attempt | Result |
|---|---|
| Contiguous array of direction enums — `u8`/`u32` `1,3,3,1`, `0,2,2,0`, LuaJIT doubles `1,3,3,1`/`2,4,4,2`, rotation as float radians and degrees | **0 hits**, all six encodings |
| Same, but differentially: two independent snapshots taken while the window was open, intersected, minus a closed-window snapshot | **0 hits** (this method is rigorous — it survives heap churn, which a single before/after diff does not) |
| Lua string array (`lua combo`, purpose-built for exactly this) | **0 runs**, even with the window open |
| Execute breakpoint on the arrow draw function | **crashed the game** — see §7 |
| Widget AABB init sentinel (`FLT_MAX` ×3) as a byte signature | **0 hits** — the sentinel is transient (§5) |

**The diagnosis that makes the tool obvious**: the arrows are **separate widget
objects**. Their directions are *not adjacent in memory*, so no
contiguous-array search can ever find them, in any encoding. Searching by
*structure* is the wrong question. The right question is **"what is drawn
here?"** — and the target already answers it, because every UI element stores
its own bounding box.

---

## 3. What the target already gives us (verified, from decompilation)

All offsets confirmed by decompiling the target game's main executable (image
base `0x140000000`; use `n0x decomp pseudo --file … --addr …`).

`sub_1400ce800` (the arrow/UI vertex-buffer builder) and `sub_1400cc860` (the
per-frame reset) both write the same element layout:

| Offset | Meaning |
|---|---|
| `+0xa0` | dirty flag (set to `1` on rebuild) |
| `+0xa4`, `+0xa8`, `+0xac` | bounding-box **min** x, y, z (`f32`) |
| `+0xb0`, `+0xb4`, `+0xb8` | bounding-box **max** x, y, z (`f32`) |
| `+0xbc` | radius (`sqrtf` of the max squared extent) |

The AABB is computed by `comiss` min/max reduction over the element's
vertices, so by the time the frame is presented it holds **real bounds**.

Supporting layout on the same objects (useful for validation, not required):

| Offset | Meaning |
|---|---|
| `+0x78` | vertex/segment count |
| `+0x7c` | capacity |
| `+0x80` | data pointer |
| `+0x88` | allocator/vtable-ish pointer |

Geometry stride is **`0x24` bytes per segment**; in `sub_1400ce800` the
register `r9` holds the segment count (the code computes `r9 * 9 * 4`).

Objects are reached by the draw-command interpreter `sub_1400670c0` through a
retained scene graph: `object = field_0xa8[ field_0xd8[id] ]` (id → index →
pointer). That is the structure this tool is querying, just from outside.

---

## 4. What to build

### Command shape

```
n0x ui locate --pid <PID> --rect <x0,y0,x1,y1> [--space screen|ndc|auto] [--limit N]
```

Output must follow the project envelope (`{ok,data,meta}`, `meta.schema =
"n0xis.ui.locate.v1"`), like every other command. Suggested payload:

```jsonc
{
  "rect": [x0, y0, x1, y1],
  "space": "ndc",
  "count": 3,
  "elements": [
    {
      "address": "0x245…",        // element base (the object, not the AABB field)
      "min": [x, y, z],
      "max": [x, y, z],
      "radius": 1.0,
      "area_overlap": 0.87,        // fraction of the element inside the rect
      "vertex_count": 36           // from +0x78, when it reads plausibly
    }
  ]
}
```

Rank by overlap descending; `--limit` caps output.

### Algorithm

1. Enumerate committed writable regions (`LiveProcess::default_writable_regions`
   — the same scan set `scan value`/`scan aob` use).
2. Read each region once and walk it on 4-byte steps (fields are dword-aligned).
3. At each offset treat the next 6 floats as a candidate AABB and apply a
   **structural predicate**, not a byte pattern:
   - all six are finite (not NaN/Inf/denormal),
   - `min.x <= max.x`, `min.y <= max.y`, `min.z <= max.z`,
   - the extents are plausible for a UI element (non-zero, and within the
     coordinate space bound — see `--space`),
   - `radius` at `+0xbc` is finite and roughly consistent with the extents
     (a cheap, strong filter: it should be near `‖max−min‖/2`, order-of-magnitude).
4. Keep candidates whose box intersects `rect`; compute overlap.
5. Report `address = candidate_offset − 0xa4` (the element base), so the caller
   can immediately dump the object.

### `--space`

Coordinate space is the one genuine unknown: the AABBs may be in pixels, in
normalized device coordinates, or in a UI-layout space. Do **not** guess
silently.

- `--space auto` (default): run the predicate with a permissive bound, then
  report the observed value ranges in `meta` so the operator can see which
  space the numbers are in.
- `screen` / `ndc`: apply the corresponding bound and interpret `--rect`
  accordingly.

Getting this wrong is the most likely reason a first implementation returns
nothing useful, so make the space **observable** rather than assumed.

---

## 5. Traps that already cost time — do not repeat

- **`FLT_MAX` is not a signature.** `sub_1400cc860` initializes the AABB
  accumulator to `0x7f7fffff`, which is tempting to scan for. It is overwritten
  with real bounds inside the same frame rebuild. Scanning for
  `ff ff 7f 7f ff ff 7f 7f ff ff 7f 7f 00 00 00 00` on a live target with the UI
  visible returned **zero hits**. Use the structural predicate (§4), not a byte
  pattern.
- **A single before/after diff is not evidence.** The heap churns constantly;
  a one-shot "open vs closed" diff produced 2 candidates that both turned out
  to be noise. The reliable protocol is: **two independent snapshots in the same
  state, intersected**, then differenced against the other state. Use it when
  validating.
- **Do not assume the interesting data is contiguous.** That assumption is what
  wasted the campaign's scanning effort. Separate widgets ⇒ separate
  allocations.

---

## 6. Why not hook the graphics API / read pixels

Both were considered and rejected on merit:

- **Pixel reading** was already ruled out for this class of problem by the
  operator: the arrows' on-screen positions shift in multiplayer, so anything
  keyed to screen appearance is fragile. Reading widget *data* is immune —
  position is exactly what we query by, not what we depend on.
- **API hooking** (D3D/present interception) adds a rendering dependency, a
  code-injection surface, and per-frame overhead to what is otherwise a
  read-only memory tool. The AABBs make it unnecessary: the target has already
  computed the answer and left it in memory.

---

## 7. Safety rules for live targets (learned the hard way)

**A conditional breakpoint on a per-frame function will kill the target.** This
happened: an execute breakpoint on `sub_1400ce800` with `--when r9=4` turned
every non-matching hit into a full stop/inspect/resume round-trip. On a function
called many times per frame that is thousands of round-trips — the game runs
effectively single-stepped, and it crashed.

Consequences for this tool:

- `ui locate` must be **read-only**. No breakpoints, no patching, no thread
  suspension. `ReadProcessMemory` over enumerated regions only.
- Scanning cost is real: the target's writable set was ~1.2 GB. Read each region
  once into a buffer and walk it in one pass; skip regions above a sane cap.
  Do not re-read per candidate.
- Prefer returning slightly stale results over stopping the target to get exact
  ones.

---

## 8. What already exists (reuse, don't rebuild)

- `LiveProcess` + `MemorySource::read` — attach and read (`crates/n0xis-sources`).
- `LiveProcess::default_writable_regions()` — the standard scan set.
- `AobScanPass` and the `Ctx`/`Pass` plumbing (`crates/n0xis-core`) — model the
  new scan on this, but note it matches **constants**; this tool needs
  **relations between fields**, which is precisely the gap Phase 9's third item
  ("structural-predicate scanning") calls out. If you generalize the primitive
  instead of writing a one-off, do that — `ui locate` then becomes its first
  consumer.
- CLI command registration and the `{ok,data,meta}` envelope:
  `crates/n0xis-cli/src/main.rs` (see `cmd_debug_watch` for the shape:
  parse args → attach → run → `emit(&Response::success(schema::v1::X, payload))`).
- `debug watch --when <reg>=<value>` (`await_watchpoint_hit_where`, `RegCond`)
  — conditional hardware breakpoints, landed 2026-07-20, with a
  `MAX_CONDITION_MISSES = 300` guard so a hot trap site aborts loudly instead of
  killing the target. Useful for *rare* events; not for render functions.

Also expose the command through the MCP server (`crates/n0xis-mcp/src/tools.rs`)
— same pipeline, same shapes, per project policy.

---

## 9. How to validate it actually works

The bar is not "it compiles" — it is "it finds a thing we can independently
confirm."

1. **Static self-test first.** Synthesize a buffer with a known AABB at a known
   offset and assert the scanner finds it, with correct overlap maths. No game
   required; this belongs in unit tests. **Done** — synthetic-buffer unit tests
   for the predicate and overlap maths pass in the working tree.
2. **Live confirmation, non-destructive.** With the target running and a UI
   element clearly visible in a known part of the window, query that rect. Then
   dump the returned addresses (`n0x mem read`) and check the object looks like
   the layout in §3 (`+0xa0` dirty flag, plausible `+0x78` count, an allocator
   pointer at `+0x88`).
3. **The decisive test — appearance correlation.** Query the same rect while the
   element is on screen and again while it is not. The addresses that are
   present only when it is visible are the real ones. Use the two-snapshot
   intersection protocol from §5, not a single diff. **Still pending** — this
   has NOT been run against a live target; until it passes, `ui locate` is
   "implemented and self-tested", not "verified".
4. **Cross-check against a second element** with different on-screen geometry,
   to prove the tool discriminates by position rather than returning the same
   set for any rect.

---

## 10. Build

The workspace pins its toolchain in `rust-toolchain.toml`. On the machine this
brief was written on, building also requires a MinGW-w64 (`w64devkit`) on
`PATH` for `dlltool` (used by `windows-sys`/`parking_lot_core`), plus an empty
`libgcc_eh.a` stub in its GCC lib directory — GCC 16 no longer ships one, but
`x86_64-pc-windows-gnu` still links `-lgcc_eh`.

```
cargo build --release -p n0xis-cli
cargo check -p n0xis-cli        # type-check only; needs no linker
```

---

## 11. Definition of done

- `n0x ui locate --pid <p> --rect …` returns ranked candidate elements with
  addresses, bounds and overlap, in the standard envelope. **Done.**
- Unit tests cover the predicate and the overlap maths on synthetic buffers.
  **Done.**
- Read-only: no breakpoints, no writes, no thread suspension. **Done.**
- Coordinate space is **reported**, not assumed. **Done.**
- Exposed via MCP as well as the CLI. **Done.**
- The live correlation test in §9.3 passes on a real target. **Outstanding** —
  this is the one remaining gate before `ui locate` may be called "verified".

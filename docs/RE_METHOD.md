# RE method — field notes from the Helldivers combo campaign

Written after one complete reverse-engineering campaign: making a game's
directional interact-combo mini-game (mines, terminals, SAM sites) solve itself
hands-free. It succeeded. It also took *weeks* longer than it needed to, and
almost all of that overrun traces to a handful of repeatable mistakes.

This is the honest post-mortem, distilled into a method. It's written to become
a skill, so it's organised as: what went wrong → what worked → the re-framing →
tools worth building → a checklist.

---

## The campaign in one paragraph

Goal: read the combo the game demands and input it automatically. We hunted the
combo through native memory for weeks (found `interact_progress`, found a
"combo array" of int32 handles, chased the handles), decompiled the C++ display
path into a MurmurHash2 widget-lookup swamp, and got nowhere. Then we
decompiled the game's **Lua** — and the entire system fell out in about thirty
minutes: the combo is generated from a `seed` by a Numerical-Recipes LCG, from
a per-objective template of fixed and `"random"` slots. The final working
solver reads **4 bytes** from memory (the seed) and computes everything else.
Separately: the game ignores synthetic `SendInput` entirely, so input required
the Interception kernel driver — a fact we discovered *after* building and
shipping an input feature that had never once worked.

---

## The one lesson, if you read nothing else

> **We spent ~90% of the effort reverse-engineering runtime *state* to recover
> information that was declaratively *specified* in the game's own data and
> scripts.**

The combo system's complete specification — the generation algorithm, the
direction encoding, the per-building templates, the validation rule — was
sitting in `lua_scripts/raw/*.luac`, already extracted from a previous session.
One `grep` for the feature's vocabulary found all of it. Everything we did
before that grep was avoidable.

**Memory is for the irreducible runtime inputs only.** Ours ended up being: a
seed (4 bytes), an `interacting_unit` handle (4 bytes), a `progress` counter (4
bytes). Everything else is computation over the spec.

---

## Failure taxonomy

### F1 — View/Model confusion *(largest single cost)*

We found `component+0x20`: an array of int32s, exactly `#combo` long, appearing
when a combo activated. Obviously the combo. It was the **display layer** —
those int32s were widget/element handles, and the direction lived somewhere
behind them. We chased that indirection for weeks. The C++ we decompiled
(`sub_1400ce800`) turned out to be a MurmurHash2 hashmap lookup — the engine
resolving the texture `"icon_dpad_01"` to draw an arrow sprite.

**Root cause:** we found *a* structure holding plausibly-shaped data and assumed
it was authoritative.

**The signal we missed:** *when recovering a value requires chasing three or
more levels of handle indirection, you are in a view or a cache, not the model.*
Models store values. Views store references to things that render values. Our
own notes recorded the symptom ("напрямок лежить УСЕРЕДИНІ об'єкта елемента")
and we read it as "keep digging" instead of "wrong layer".

**Lesson:** deepening indirection is a signal to *stop and go find the
declarative source*, not to dig harder.

### F2 — Skipped the script layer *(root cause of F1)*

The game is Bitsquid/Stingray — a **Lua-scripted engine**. Its game logic is not
in the C++ at all. We had 890 extracted `.luac` files on disk the whole time.

The moment we grepped them for the feature's vocabulary
(`combo|interact|stratagem`), we found: the component (`4313cac5…`), the
algorithm module (`d30f9dc2…`), the RNG class (`55d3e751…`), and every combo
template. Thirty minutes, versus weeks of native work.

**Lesson:** **identify the engine first.** If it's scripted (Bitsquid, Unity/IL2CPP,
Unreal Blueprints, Godot, any embedded Lua/Python), the script layer *is* the
spec. Go native only for what the scripts explicitly call out to — for us that
was exactly **one** function.

### F3 — N=2 pattern-matching / confirmation bias *(cost: 3 debugging rounds, one shipped bug)*

Three times I promoted a coincidence to an invariant:

| Claim | Evidence | Reality |
|---|---|---|
| "`0xCF` at `+0x18` is a class-type marker" | matched 2 live instances | The 2 were repeated test missions with the same generated-level seed. A third mine on a new map had different bytes. **Shipped before the third test.** |
| "`state == 0` = window is open" | matched 1 instance | Refuted in one minute by the operator closing the window: `state` stayed 0. |
| "The structural scan is astronomically specific" | my probability math | Math assumed *random* memory. Real memory is full of zeros. **1844 false positives** in 4 MB. |

**Lesson:** an invariant claimed from fewer than **3 deliberately-varied,
independent** instances is a guess. And vary *the axis you're claiming
invariance over*: different map, different mission, different object type,
different session. Two samples from the same test loop prove nothing — they may
share a seed.

**Corollary:** when computing a false-positive rate, never model memory as
uniform random. Zero, small ints, `0xFFFF` and pointers are wildly over-represented.

### F4 — Never verified the actuation path *(cost: an entire feature, built dead)*

The HUD shipped an input-macro runner built on `SendInput`. It "worked" — keys
were sent, no errors. It **never once registered in the game**. We found out at
the very end, when the auto-solver read a combo perfectly and then failed to
input it.

The game filters injected input (the standard `LLKHF_INJECTED` check). The fix
was the Interception kernel driver. The old code's own doc comment even
*documented the risk* ("a title reading the keyboard through DirectInput might
not [see it]") — and we never tested it.

**Lesson:** a cheat has two halves — **read** and **write**. Prove each one
independently, *before* integrating. A single-key probe on day one would have
saved the whole dead branch.

### F5 — Blamed the target instead of the tool

The debugger crashed the game on attach. We concluded "anti-debug" and avoided
debugging. The real cause: our debugger returned `DBG_EXCEPTION_NOT_HANDLED` for
the initial attach breakpoint, which the OS then delivered to the target. **Our
bug.**

**Lesson:** suspect your own tool first. Anti-tamper is rarer than your own bugs,
and "the target is defending itself" is an unfalsifiable story that stops
investigation.

### F6 — Silent failure in live scanning

`combo-solver scan failed: address 0x… is not mapped` — one transiently-freed
region aborted the entire scan, so the background solver silently found nothing
while looking perfectly healthy.

Region lists are **inherently racy**: a region you enumerated is not a region you
can read. The game allocates and frees constantly.

**Lesson:** live scans must *skip and continue*, never abort. And "0 results"
must be distinguishable from "the scan died".

### F7 — Ergonomics tax

- Hand-converting hex→decimal for `--min`/`--max`: got it wrong **twice**,
  burning two scan rounds on ranges that pointed at the wrong address entirely.
- Hand-rolled the same snapshot/diff Python **three times**.
- Full 1.3 GB scans on every poll until region caching was added late.

---

## What actually worked *(keep these)*

**W1 — The transition diff.** Every single successful localization used it, and
nothing else ever worked: snapshot → operator toggles exactly one thing → rescan
→ diff. It gave **exactly one** result every time, where static value-matching
gave 651, 1025, 1844. *The change is the signal; the value is not.*

**W2 — Native bindings via their registration string.** To find `Math.next_random`'s
C implementation: find the `"next_random"` string → scan `.text` for a
RIP-relative reference → land in the registration function → the pattern is
`register(L, ns, "name", cfunc)` and the **C function pointer is right there as
an argument**. Question to answer: ~20 minutes.

**W3 — Recognizing canonical constants.** `0x5bd1e995` → MurmurHash2.
`1664525` / `1013904223` → Numerical Recipes LCG. `1/2^32` → normalization.
Seeing a known constant identifies an algorithm *instantly*, with no reversing.

**W4 — Deriving instead of reading.** Once the LCG was known, the combo became
`f(seed)`. That collapsed the problem from "traverse a transient object graph"
to "read 4 bytes".

**W5 — Ground truth on screen.** Every claim was checkable against the arrows the
operator could see. `seed 468487285 → right,down,up,up,left,right,up,up` matching
the screen exactly is what turned a hypothesis into a fact.

**W6 — The operator's domain knowledge.** Twice, one sentence from the user beat
hours of my memory analysis:
- *"activation only starts when I press E"* → explained why scans found nothing.
- *"for mines it's random, for other buildings it's almost certainly static"* →
  collapsed the entire remaining search and led straight to the template model.

**Ask the human what they know about the system.** They're playing it.

---

## The re-framing: spec-first RE

Climb this ladder **top-down**. Each rung is cheaper, more stable, and more
general than the one below it.

| # | Layer | What it gives you | Cost |
|---|---|---|---|
| 1 | **Data / config** | Templates, tables, tuning. Declarative truth. | trivial |
| 2 | **Script layer** | The algorithm, in readable form. | low |
| 3 | **Native bindings** | Only what scripts call into — findable *by name*. | low |
| 4 | **Native code** | One specific function. | medium |
| 5 | **Runtime memory** | Only the irreducible inputs (seeds, handles). | high, brittle |

We climbed it **backwards** (5 → 4 → 3 → 2 → 1). Done in the right order this
campaign is roughly a day's work.

**Two corollaries:**

1. **Minimize the memory surface.** Every byte you read from a live process is a
   liability: transient, ASLR'd, version-fragile, race-prone. Our final read
   surface is 12 bytes. The first design tried to traverse an object graph.
2. **Prefer computed over observed.** If the game derives it, you can derive it.
   Observation is only for what the game *didn't* derive (its random seed).

---

## Tools worth building

Ranked by (pain avoided × generality). Each traces to a specific failure above.

### T1 — `n0x game grep <concept>` *(fixes F2)*
Search a game's extracted scripts + data + binary strings for a concept, rank
files by vocabulary-cluster density, print the hits with context.

This is literally the thing that cracked the campaign — and I hand-rolled it in
throwaway Python. It should be a first-class command. **Highest payoff on this
list: it turns weeks into thirty minutes.**

### T2 — `n0x locate --by-transition` *(fixes F7, formalizes W1)*
The diff-locator as a real workflow: snapshot → wait for the operator to toggle
the state → rescan → diff → filter survivors by a structural predicate → report.

I hand-rolled this three times. It is the **only** localization technique that
ever worked. It deserves to be a command, not a habit.

### T3 — `n0x input probe --pid <p>` *(fixes F4)*
Try each actuation method (SendInput / keybd_event / Interception / raw HID) and
report which ones the target actually registers. Run it *before* building
anything on top of input.

Would have prevented an entire feature being built dead.

### T4 — `n0x const identify` *(automates W3)*
Recognize canonical magic constants in decompiled output and data: LCG
multipliers, hash seeds (Murmur/FNV/xxhash/CRC polys), float normalizers.
Turns "reverse this arithmetic" into "this is Numerical Recipes, here's the
formula".

### T5 — `n0x bindings list --module <m>` *(generalizes W2)*
Enumerate a script VM's native bindings by finding registration calls and
pairing each name string with its C function pointer. Turns "where is the native
implementation of `X`" into a lookup.

### T6 — `n0x sig validate` *(fixes F3)*
Given a candidate signature and ≥2 instances, report which bytes are *actually*
invariant, and **refuse to bless a signature derived from fewer than 3
independent samples**. Ask which axis was varied.

This is a guardrail against the exact bias that shipped a broken marker.

### T7 — Ergonomics *(fixes F6, F7)*
- Accept hex for `--min`/`--max` (and everywhere else taking an address/value).
- Scans skip unreadable regions and continue; distinguish "0 results" from
  "scan aborted".
- Region caching as a built-in scan option, not per-caller hand-rolling.

---

## Doctrine — the checklist

**Before touching memory at all:**

- [ ] What engine is this? Is there a script layer? (Bitsquid/Stingray, Unity,
      Unreal, Godot, embedded Lua/Python…)
- [ ] Extract the scripts and **grep them for the feature's vocabulary**.
- [ ] Find the data/templates that parameterize the feature — they're the spec.
- [ ] Read the algorithm out of the script. Note precisely what it calls into
      natively.
- [ ] Reverse **only** those native calls — find them by their binding
      registration name, not by wandering.
- [ ] Identify the **minimal runtime input set**. Usually a seed or a handle.
      If your answer is "an object graph", you're on the wrong rung.

**Then, and only then:**

- [ ] Prove the **read** half: derive the value; cross-check against ground
      truth the operator can see.
- [ ] Prove the **write** half **independently**, before integrating. Probe the
      actuation path with one key.
- [ ] Locate by **transition diff**, not by static value matching.
- [ ] Validate every claimed invariant against **≥3 deliberately-varied**
      instances. Say out loud which axis you varied.
- [ ] When something fails, **suspect your own tool first**.
- [ ] **Ask the operator what they know.** They play the game; you don't.

**Smells that mean "stop, you're on the wrong rung":**

- Indirection is getting deeper, not shallower.
- You're reverse-engineering drawing/animation code.
- Your signature works on two instances from the same test loop.
- Your false-positive estimate assumed uniformly random memory.
- You're about to build on an actuation path you've never verified.

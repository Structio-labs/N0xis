# `why`: where each fact about an address came from

Status: accepted 2026-10-23 (the owner approved the form: a category of source, shown on
request, no confidence numbers). Step 1 built (969bcc6); the owner asked to deepen the
direction, so §5 is its plan.

## 1. What it is

`n0x why --addr <va> <target>` answers, for one address, what the engine states about it and
**where each statement came from**, as a category from a closed list. It does not grade the
statements: a confidence number is itself a claim that needs a measurement per rule, and a rule
measured right on two binaries has been wrong 99 times on a third. Every other answer stays as
it is; this is a door of its own, not a field added everywhere.

What a category is: the input or the rule that produced the fact, checkable by someone else —
"the unwind table declares this start" can be checked against `llvm-readobj`; "a prologue
matched" says the start is a heuristic's.

## 2. The facts and their categories (step 1)

- **The function the address is in, and whether it starts there.** Every source that found the
  start, all of them, not the first:
  - declared by the image: `export`, `symbol` (with its table: `.symtab`, `.dynsym`, a name
    section), `unwind` (`.pdata`; an `.eh_frame` FDE), `pdb`, `body` (a WebAssembly function),
    `stub` (a PLT entry);
  - found by a rule: `after-declared-end`, `gap-sweep`, `call-target` (with the calling
    instruction), `prologue`;
  - `user` when an annotation states it.
- **Its end**, with the one source the answer used: `symbol-size` (and whose: PDB, `st_size`),
  `unwind` (`.pdata` end, FDE range), `body`, or `not-stated` (the CFG's own end, what
  `truncate_to_function` decides, named as such).
- **Its name**, with the layer that answered: `user`, `rtti`, `flirt`, `pdb`, `managed`,
  `image` (with the table), `stub` (named after its import), or `fallback` (`sub_…`,
  `func_N`). A name that several layers give is reported from the one that won, with the
  others listed as `also`.

Categories are enums in the code (no free strings), so a new rule cannot reach an answer
without naming its category: the compiler makes every rule answer.

## 3. One source of truth

A fact's source is recorded **where the rule fires**, never recomputed for `why`: re-running the
rules for one address would be a second copy of discovery, and copies drift. So:

- discovery keeps a set of sources per start (today each rule writes `or_insert` and the second
  source of a start is dropped); `Discovered` carries it, and the discover cache's format
  changes with it (keyed so an old cache misses, never misreads);
- the stated functions handed to discovery carry the image's `StartReason` (and the PDB/FDE
  cases) instead of bare pairs;
- the composed symbol layers answer which layer gave a name (a lookup on the composition, not a
  change to `SymbolProvider`);
- the end records which source it came from.

`why` is a reader of those; `function discover` and every other answer keep their JSON.

## 4. Verification (what makes the answer true)

- Rung 1: planted images in which exactly one rule can produce a given start (a start only the
  unwind table declares; one only a call reaches; one only a prologue matches; a gap-sweep one),
  each asserted exactly, and a start several sources find, asserting all of them.
- Rung 3: on real images, every `unwind`/`symbol`/`export` claim against `llvm-readobj`/`nm`
  (an `unwind` claim with no table entry there is a wrong answer), names against `nm`/PDB.
- The empty-success sweep: every function `function discover` lists must have a non-empty
  start source; an empty one fails.

## 5. Built, and what is not (step 1)

Built: starts with every source, the end with its one source, the name with its layer.
Never fires yet: a `symbol` start (discovery takes no start from an ELF symbol, only its size)
and a `user` start (an annotation names an address, never creates a start); making either fire
changes `function discover`, so each is its own decision. Checked: 228 506 table claims on 80
images against objdump/llvm-readobj/llvm-nm/wasm-objdump, 0 wrong; the rule sources (call
target, prologue, gap sweep, after a declared end) on planted images only.

## 6. The direction, in order (each step measurable)

1. **Contradictions as facts.** A command listing every place in an image where sources
   disagree (an unwind end against a symbol size, two declared starts with different extents,
   two layers naming one address differently): the map of where to doubt. Cheap now that every
   source of a start is kept.
2. **Measured accuracy per rule.** On a corpus with known truth (builds here with DWARF/PDB),
   each start, end and name rule measured on its own ("prologue: X of Y right, corpus C,
   version V"); the instrument checked in and re-run per release; `why` may cite a rule's
   measured rate together with its corpus and version, and the README's numbers are pinned the
   same way.
3. **Test the direction itself.** Of the facts wrong against the truth, how many carry only a
   heuristic source? If the category does not predict the error, say so and stop building on it.
4. **Types and decompiler lines.** Which rung of the parameter-type ladder fired, user
   overrides marked; each pseudo-C line mapped to its instructions; on request only.
5. **A fact log as the store.** Every fact with its source, author and history; its own design
   discussion with the owner before anything is built.

Never: a confidence number nobody measured; a field added to every answer; a source computed
apart from the rule that produced the fact.

# Rust binaries: what the engine does today, and the steps

Status: accepted 2026-11-05. Nothing below is built yet. The engine reads compiled images only: it
reads no source code, in any language.

## 1. Measured

A planted program built here (`rustc -O`, debug level 1, x86-64; each answer known before the
question), on the build of main `a85a927`:

| Question | Answer | Verdict |
|---|---|---|
| Names, legacy and v0 mangling | `p::pick`, `<p::Sq as p::Shape>::area`, no raw `_R` left | right |
| `str_len_sum(a: &str, b: &[u8])` | `return (rsi + rcx);`, which is `a.len() + b.len()` | right |
| Two `&str` literals side by side | `strings` gives one string, `PLANTED_ALPHAPLANTED_BETA` | **wrong** |
| `rtti scan`, two `dyn Shape` vtables | `ok`, 0 vtables | true of C++ RTTI, silent on what is there |
| `panic!("...")` in pseudo-C | an unnamed call through a relocated slot; the message a raw address with its length beside it | lost |
| The signature of `str_len_sum` | four 64-bit words | lost: the pointer and length pairs |

The string answer is the worst of them: a `&str` has no terminator, so `strings` is confidently wrong
on any Rust binary, in the shape `ok: true`.

## 2. Steps, wrong answers first

Each with a planted truth first, then programs held out from tuning (rules in `WHY.md` §6).

1. **Length-delimited literals.** A reference with its length beside it gives the literal's bounds, in
   `strings` and in pseudo-C. Where nothing states a length, the answer stays what it is today.
2. **Calls through relocated slots** named as the slot's target, not only through PLT relocations; the
   panic family as functions that do not return, so no false path continues past them.
3. **The compiler and library version,** from what the image itself records, so that signatures of
   exactly that standard library can name a stripped image's library functions.
4. **Panic locations** as `file:line:column` at each site: source positions that survive stripping.
   Their layout is no stable contract, so it is checked per compiler version and refused when unsure.
5. **`dyn` vtables** by their shape (drop, size, alignment, methods), and `rtti scan` says which kinds
   it looked for.
6. **Fat pointers and enum layouts** in signatures, last: each needs evidence at its own site.

## 3. DWARF: the link to source, for C++ and Rust alike

The engine reads PDB and has no DWARF reader. With one: names, types, ranges and address to
`file:line`, so with the source on disk a line can be shown beside the pseudo-C. That is not
understanding source (no compiler front end); it is a new fact source for `why`, and a truth the
decompiler can be compared with directly.

## 4. Inputs are claims

Everything here reads what the image says, and the code may be obfuscated (`OBFUSCATED.md`): a planted
false location, length or DWARF entry must produce a stated doubt, not a confident wrong answer.

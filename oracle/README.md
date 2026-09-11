# The oracle corpus — targets whose answer is known before the question

**This directory exists because the tool has no way to be wrong.**

In most programs, wrong means a crash, an exception, a red test. Here, wrong
means a *plausible string*. The compiler cannot tell `rax` from `esp`. A test
cannot tell `(void)` from `()` unless someone wrote that exact expectation. The
feedback channel that normally catches defects does not exist for this kind of
program — so it has to be built, and this is it.

Every verification pass on this project found the same thing: **confident wrong
answers, never errors.** 674 tests found none of them. One new *shape* of input
found four classes in an hour. That is the lesson this directory encodes.

## The rule

A claim is true when a source that is **not n0xis** says so. Rank the source
and know which rung you are on:

1. **An answer built to be known before the question is asked** — this
   directory. A function called `sysv_f_d3` *is* three doubles; `expect.json`
   says so, and it was written from the C, not from any tool's output.
2. The producer's own artifact — shipped headers, the format's own tables.
3. An independent parser — `objdump`, `nm`, `readelf`, a Python reader.
4. A second implementation of the same thing. **It guesses too.** Use it to
   raise suspicion, never to settle a question.
5. n0xis compared with n0xis. Not evidence — a contract check wearing the
   clothes of a correctness check.

## Why the corpus is multi-shape, not bigger

Every defect found on 2026-09-09 was invisible on the shape the tool had been
developed against, and visible on the first line of a shape it had not:

| shape | what it exposed |
| --- | --- |
| i386 / cdecl | four commands naming registers the target does not have; `(void)` claimed for functions with three arguments |
| SysV / floating-point arguments | `double f(double)` reported as taking nothing — on the *main* path, not a 32-bit corner |
| Win64 / mixed int+float | the two register files share a positional slot, and counting them independently is wrong |

One shape of input buys one shape of blindness. The corpus is therefore
organised by **ABI × architecture × format**, and a new one is a new file here,
not a new argument in a test.

## What is here

| file | shape | built with |
| --- | --- | --- |
| `sysv.c` | ELF, x86-64, System V | `gcc -shared` |
| `win64.c` | PE, x86-64, Microsoft x64 | `x86_64-w64-mingw32-gcc -shared` |
| `i386.c` | PE32, i386, cdecl + stdcall | `i686-w64-mingw32-gcc -shared` |
| `expect.json` | **the truth**, one entry per exported function | written by hand from the C |

`expect.json` is the artifact that matters. It is not generated from a tool's
output — that would make it a record of what n0xis says, which is worth
nothing. It is written from the source, which is what makes it rung 1.

## Running it

`cargo test -p n0xis-cli --test oracle_corpus` builds whatever the local
toolchain allows and checks every claim in `expect.json`. A missing compiler
**skips that shape and says so on stderr**; it never passes silently, because a
check that quietly does nothing is worse than no check.

`oracle/build.sh` builds the same targets by hand, for measuring outside the
test harness.

## Adding to it

1. Write the function in the `.c` for its shape. **Name it after its own
   truth** (`sysv_f_di` = System V, returns floating, takes double then int) so
   a mismatch is readable without opening this file.
2. Add its entry to `expect.json`, **from the C source**, never from a tool.
3. Run the test. If it passes on the first run, ask whether it is checking
   anything: a new case should fail against the version of n0xis that predates
   the fix it exists for.

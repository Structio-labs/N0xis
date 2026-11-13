#!/bin/sh
# Rebuilds the planted image of `chained_unwind_is_one_function.rs` and records
# what an independent reader says it holds. Run from this directory; the
# recordings are what the test cites.
#
# `split.s` uses the assembler's own `.seh_splitchained`, so LLVM's unwind
# emitter writes `f`'s entries. It only ever chains to the first entry and
# only contiguously, so `tables.s` writes `g`'s and `h`'s entries by hand: one
# continuation contiguous, one past `h` and chained through the first (nested
# once). `llvm-readobj --unwind` reads both back.
set -eu
llvm-mc -triple=x86_64-pc-windows-msvc -filetype=obj -o split.obj split.s
llvm-mc -triple=x86_64-pc-windows-msvc -filetype=obj -o tables.obj tables.s
lld-link /dll /noentry /export:f /export:g /export:h /out:chained.dll split.obj tables.obj
rm -f split.obj tables.obj chained.lib chained.exp
LC_ALL=C llvm-readobj --unwind chained.dll > chained.dll.unwind.txt
LC_ALL=C llvm-objdump -d --no-show-raw-insn chained.dll > chained.dll.disassembly.txt

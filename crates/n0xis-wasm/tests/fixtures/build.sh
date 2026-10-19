#!/bin/sh
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Build every fixture from its source and record what the independent tools
# say about it, into the directory given (this one by default):
#
#   ctarget-O0.wasm, ctarget-O2.wasm   clang --target=wasm32, from ctarget.c
#   core.wasm, simd.wasm, shapes.wasm  wasm-tools parse, from the .wat files
#
# and for each <name>.wasm:
#
#   <name>.headers.txt      wasm-objdump -h   (sections, ranges, counts)
#   <name>.details.txt      wasm-objdump -x   (every entry, the name section)
#   <name>.disassembly.txt  wasm-objdump -d   (every body, every instruction)
#   <name>.print.txt        wasm-tools print -p of a copy without custom
#                           sections, so every index prints as a number
#
# The default tests compare the reader with these recordings; the `oracle`
# feature's test runs this script again and fails if anything recorded here no
# longer matches what the tools say. A missing tool is a failure, never a skip.
#
# Measured with clang 23.1.1, wasm-tools 1.262.0, wabt 1.0.42.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-$here}
mkdir -p "$out"
out=$(cd "$out" && pwd)
for tool in clang wasm-ld wasm-tools wasm-objdump; do
    command -v "$tool" >/dev/null 2>&1 || { echo "build.sh: $tool is not on PATH" >&2; exit 1; }
done
export LC_ALL=C

# Run from the output directory with bare file names: the module name clang
# writes and the file name wasm-objdump prints are then the same everywhere.
cd "$out"
for level in 0 2; do
    clang --target=wasm32 -O"$level" -nostdlib -Wl,--no-entry -Wl,--export-all \
        -o "ctarget-O$level.wasm" "$here/ctarget.c"
done
for name in core simd shapes; do
    wasm-tools parse "$here/$name.wat" -o "$name.wasm"
done

for name in ctarget-O0 ctarget-O2 core simd shapes; do
    wasm-tools validate --features all "$name.wasm"
    wasm-objdump -h "$name.wasm" > "$name.headers.txt"
    wasm-objdump -x "$name.wasm" > "$name.details.txt"
    wasm-objdump -d "$name.wasm" > "$name.disassembly.txt"
    wasm-tools strip --all "$name.wasm" -o "$name.stripped.tmp"
    wasm-tools print -p "$name.stripped.tmp" > "$name.print.txt"
    rm "$name.stripped.tmp"
done
echo "built and recorded 5 fixtures into $out"

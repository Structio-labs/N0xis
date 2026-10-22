#!/bin/sh
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Build the modules of this directory from their source, require that two
# validators accept each (`wasm-tools validate` and wabt's `wasm-validate`),
# and record what wabt's `wasm-objdump` says about the ones the engine's
# answers are compared with (tests/wasm_facts_are_what_wasm_objdump_lists.rs):
#
#   placed-by-import.wasm   wasm-tools parse, from its .wat
#   indexed.wasm            wasm-tools parse, from its .wat     (recorded)
#   names-cpp.wasm          clang++ --target=wasm32 -O1, from names.cpp
#                                                               (recorded)
#   wide-even.wasm,         clang --target=wasm32 -O2, from wide.c, with
#   wide-odd.wasm           -DNAME=wide_a and -DNAME=wide_ab
#
# For each recorded <name>.wasm: <name>.headers.txt (wasm-objdump -h),
# <name>.details.txt (-x) and <name>.disassembly.txt (-d).
#
# The two wide builds must place their data at module offsets of different
# parity, which is what the pair is for; this script fails if they do not.
#
# Measured with clang 23.1.1, wasm-tools 1.262.0 and wabt 1.0.42.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
for tool in clang clang++ wasm-ld wasm-tools wasm-objdump wasm-validate; do
    command -v "$tool" >/dev/null 2>&1 || { echo "build.sh: $tool is not on PATH" >&2; exit 1; }
done
export LC_ALL=C
# Bare file names from here: the name wasm-objdump prints is then the same
# wherever the script runs.
cd "$here"

for name in placed-by-import indexed; do
    wasm-tools parse "$name.wat" -o "$name.wasm"
done
clang++ --target=wasm32 -O1 -fno-inline -fno-exceptions -nostdlib -Wl,--no-entry \
    -Wl,--export=entry -Wl,--allow-undefined -o names-cpp.wasm names.cpp
clang --target=wasm32 -O2 -nostdlib -Wl,--no-entry -Wl,--export-dynamic \
    -DNAME=wide_a -o wide-even.wasm wide.c
clang --target=wasm32 -O2 -nostdlib -Wl,--no-entry -Wl,--export-dynamic \
    -DNAME=wide_ab -o wide-odd.wasm wide.c

for name in placed-by-import indexed names-cpp wide-even wide-odd; do
    wasm-tools validate "$name.wasm"
    wasm-validate "$name.wasm"
done
for name in indexed names-cpp; do
    wasm-objdump -h "$name.wasm" > "$name.headers.txt"
    wasm-objdump -x "$name.wasm" > "$name.details.txt"
    wasm-objdump -d "$name.wasm" > "$name.disassembly.txt"
done

# The data section's start, which the two wide builds place at module offsets
# of different parity: their sections are the same bytes (the same size and
# placement), so the one segment's bytes inside differ in parity with them.
data_at() {
    wasm-objdump -h "$1" | sed -n 's/^ *Data start=0x\([0-9a-f]*\) .*/\1/p'
}
even=$(data_at wide-even.wasm)
odd=$(data_at wide-odd.wasm)
[ -n "$even" ] && [ -n "$odd" ] || { echo "build.sh: a wide build has no data section" >&2; exit 1; }
if [ $((0x$even % 2)) -eq $((0x$odd % 2)) ]; then
    echo "build.sh: the wide builds' data sections start at 0x$even and 0x$odd, the same parity" >&2
    exit 1
fi
echo "built: the wide data sections at 0x$even and 0x$odd"

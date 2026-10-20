#!/bin/sh
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Build every fixture from its source and record what the independent tools
# say about it, into the directory given (this one by default):
#
#   ctarget-O0.wasm, ctarget-O2.wasm   clang --target=wasm32, from ctarget.c
#   cthreads-O2.wasm                   clang -pthread with a shared memory,
#                                      from cthreads.c
#   ceh-legacy-O2.wasm                 clang++ -fwasm-exceptions, from ceh.cpp,
#   ceh-exnref-O2.wasm                 with the legacy exception instructions
#                                      and with the exnref ones
#   core.wasm, simd.wasm, shapes.wasm, wasm-tools parse, from the .wat files
#   threads.wasm, refs.wasm, gc.wasm,
#   eh.wasm, eh-legacy.wasm,
#   relaxed.wasm
#
# Every module must be accepted by three validators: `wasm-tools validate
# --features all`, V8 (`node v8dis.mjs --validate`, which compiles it with
# `new WebAssembly.Module`) and wabt's `wasm-validate --enable-all`, wabt for
# the modules it reads at all, which is every one but gc.wasm, and V8 for those
# it compiles, which today is every one. Then, for each <name>.wasm:
#
#   <name>.headers.txt      wasm-objdump -h   (sections, ranges, counts)
#   <name>.details.txt      wasm-objdump -x   (every entry, the name section)
#   <name>.disassembly.txt  wasm-objdump -d   (every body, every instruction)
#   <name>.wabt-refuses.txt instead of those three, for a module wabt cannot
#                           read: what wasm-objdump -h prints on stderr and its
#                           exit status, so that the absence of wabt's answer is
#                           recorded too (a wabt that reads it fails here)
#   <name>.print.txt        wasm-tools print -p of a copy without custom
#                           sections, so every index prints as a number
#   <name>.v8.txt           V8's own disassembly of that copy (v8dis.mjs),
#                           made twice and required to come out the same
#   <name>.v8-refuses.txt   instead of it, for a module V8 refuses (none
#                           today): what v8dis.mjs prints on stderr when it
#                           disassembles that copy, then its exit status,
#                           made twice and required to come out the same; the
#                           status must be 1, V8's refusal (2 is v8dis.mjs
#                           failing, no verdict), and V8 compiling the module
#                           fails here, as wabt reading its refused one does
#
# Both refusals are written by one function, record_refusal, in the one shape
# tests/v8.rs reads. `sh build.sh --v8-refusal MODULE.wasm RECORD` writes the
# record of V8 refusing MODULE.wasm, and nothing else, so that the tests can
# check that shape on a module V8 refuses without a fixture that is one.
#
# The default tests compare the reader with these recordings; the `oracle`
# feature's test runs this script again and fails if anything recorded here no
# longer matches what the tools say. A missing tool is a failure, never a skip.
#
# Measured with clang 23.1.1, wasm-tools 1.262.0, wabt 1.0.42 and node 26.10.0
# (V8 14.6.202.34). No module needs a V8 flag: V8 14.6 compiles all of them
# with its defaults.
set -eu
here=$(cd "$(dirname "$0")" && pwd)

# Run "$@" with its stdout discarded, its stderr into the file $record, and
# its exit status appended to that file as a last line `exit status N`; the
# status is left in $status. The shape of every refusal recorded here.
record_refusal() {
    record=$1
    shift
    status=0
    "$@" > /dev/null 2> "$record" || status=$?
    echo "exit status $status" >> "$record"
}

# Record V8 refusing the module $1 into $2, or fail and leave no $2 behind:
# V8 compiling it, or v8dis.mjs failing (any status but 1, as 2 for a module
# it cannot read), is no refusal to record.
record_v8_refusal() {
    record_refusal "$2" node "$here/v8dis.mjs" "$1"
    case $status in
        1) ;;
        0) echo "build.sh: V8 compiles $1 now; record its disassembly like the others" >&2; rm -f "$2"; exit 1 ;;
        *) echo "build.sh: v8dis.mjs failed on $1 (exit status $status), which is no verdict:" >&2; cat "$2" >&2; rm -f "$2"; exit 1 ;;
    esac
}

if [ "${1:-}" = "--v8-refusal" ]; then
    [ $# -eq 3 ] || { echo "usage: sh build.sh --v8-refusal MODULE.wasm RECORD" >&2; exit 1; }
    command -v node >/dev/null 2>&1 || { echo "build.sh: node is not on PATH" >&2; exit 1; }
    record_v8_refusal "$2" "$3"
    exit 0
fi

out=${1:-$here}
mkdir -p "$out"
out=$(cd "$out" && pwd)
for tool in clang clang++ wasm-ld wasm-tools wasm-objdump wasm-validate node; do
    command -v "$tool" >/dev/null 2>&1 || { echo "build.sh: $tool is not on PATH" >&2; exit 1; }
done
export LC_ALL=C

# The modules wabt reads, and the one it cannot: gc.wasm, whose type section
# it refuses at the first recursion group (byte 0x4e).
wabt_reads="ctarget-O0 ctarget-O2 cthreads-O2 ceh-legacy-O2 ceh-exnref-O2 core simd shapes threads refs eh eh-legacy relaxed"
wabt_refuses="gc"
# The modules V8 refuses: none. V8 14.6 compiles every fixture with its
# defaults.
v8_refuses=""

# Run from the output directory with bare file names: the module name clang
# writes and the file name wasm-objdump prints are then the same everywhere.
cd "$out"
for level in 0 2; do
    clang --target=wasm32 -O"$level" -nostdlib -Wl,--no-entry -Wl,--export-all \
        -o "ctarget-O$level.wasm" "$here/ctarget.c"
done
clang --target=wasm32 -O2 -pthread -nostdlib -Wl,--no-entry -Wl,--export-all \
    -Wl,--shared-memory -Wl,--import-memory -Wl,--max-memory=262144 \
    -o cthreads-O2.wasm "$here/cthreads.c"
clang++ --target=wasm32 -O2 -fwasm-exceptions -fno-rtti -nostdlib -Wl,--no-entry \
    -Wl,--export-all -Wl,--allow-undefined \
    -o ceh-legacy-O2.wasm "$here/ceh.cpp"
clang++ --target=wasm32 -O2 -fwasm-exceptions -fno-rtti -nostdlib -Wl,--no-entry \
    -Wl,--export-all -Wl,--allow-undefined -mllvm -wasm-use-legacy-eh=false \
    -o ceh-exnref-O2.wasm "$here/ceh.cpp"
for name in core simd shapes threads refs gc eh eh-legacy relaxed; do
    wasm-tools parse "$here/$name.wat" -o "$name.wasm"
done

count=0
for name in $wabt_reads $wabt_refuses; do
    wasm-tools validate --features all "$name.wasm"
    case " $v8_refuses " in
        *" $name "*) v8_reads=no ;;
        *) v8_reads=yes ;;
    esac
    if [ "$v8_reads" = yes ]; then
        node "$here/v8dis.mjs" --validate "$name.wasm"
    fi
    wasm-tools strip --all "$name.wasm" -o "$name.stripped.tmp"
    wasm-tools print -p "$name.stripped.tmp" > "$name.print.txt"
    if [ "$v8_reads" = yes ]; then
        node "$here/v8dis.mjs" "$name.stripped.tmp" > "$name.v8.txt"
        node "$here/v8dis.mjs" "$name.stripped.tmp" > "$name.v8.tmp"
        cmp -s "$name.v8.txt" "$name.v8.tmp" || { echo "build.sh: V8's disassembly of $name differs between two runs" >&2; exit 1; }
    else
        record_v8_refusal "$name.stripped.tmp" "$name.v8-refuses.txt"
        record_v8_refusal "$name.stripped.tmp" "$name.v8.tmp"
        cmp -s "$name.v8-refuses.txt" "$name.v8.tmp" || { echo "build.sh: V8's refusal of $name differs between two runs" >&2; exit 1; }
    fi
    rm "$name.stripped.tmp" "$name.v8.tmp"
    count=$((count + 1))
done
for name in $wabt_reads; do
    wasm-validate --enable-all "$name.wasm"
    wasm-objdump -h "$name.wasm" > "$name.headers.txt"
    wasm-objdump -x "$name.wasm" > "$name.details.txt"
    wasm-objdump -d "$name.wasm" > "$name.disassembly.txt"
done
for name in $wabt_refuses; do
    record_refusal "$name.wabt-refuses.txt" wasm-objdump -h "$name.wasm"
    if [ "$status" -eq 0 ]; then
        echo "build.sh: wasm-objdump reads $name.wasm now; record it like the others" >&2
        exit 1
    fi
done
echo "built and recorded $count fixtures into $out"

#!/bin/bash
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Build `processor_run.cpp` for the two x86 widths, run each on this machine's
# processor, and record what it printed (`processor_run.txt`). The run is the
# evidence for refusing a dispatch through a parameter's declared type when the
# class has a subclass. Then `flow_run.cpp` for x86-64: the evidence for where a
# construction gives an object its class. Then `vbnortti_run.cpp` for both x86
# widths, built without RTTI as the `vn-*` fixtures are: the evidence for where
# the vptr of a class whose virtual base shares it points in its `_ZTV`. Then
# `plugin_run.cpp`, linked against the committed `vp-x86_64-linux-gnu.so`
# itself: the evidence for taking a library's classes as derived from in the
# program that loads it. Nothing in a test reads any of them.
set -eu
cd "$(dirname "$0")"
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
{
    for t in x86_64-linux-gnu i686-linux-gnu; do
        clang++ --target=$t -O1 -o "$out/run-$t" processor_run.cpp
        # The call in main goes to Base::h itself, not an inlined copy.
        if ! LC_ALL=C llvm-objdump -d --no-show-raw-insn "$out/run-$t" | grep -A40 '<main>:' | grep -q 'call.*<_ZNK4Base1hEv>'; then
            echo "$t: main does not call Base::h" >&2
            exit 1
        fi
        echo "== $t, clang++ --target=$t -O1: main calls _ZNK4Base1hEv"
        "$out/run-$t"
    done
    # `flow.cpp`: which f each call runs, for the x86-64 fixture built from it.
    clang++ --target=x86_64-linux-gnu -O1 -o "$out/flow" flow_run.cpp
    for f in _Z1gPvi _Z5builtPv _Z7rebuiltPvi; do
        if ! LC_ALL=C llvm-objdump -d --no-show-raw-insn "$out/flow" | grep -A40 '<main>:' | grep -q "call.*<$f>"; then
            echo "flow: main does not call $f" >&2
            exit 1
        fi
    done
    echo "== flow, clang++ --target=x86_64-linux-gnu -O1: main calls g, built and rebuilt"
    "$out/flow"
    # `vbnortti.cpp`: where each object's vptr points in its table.
    for t in x86_64-linux-gnu i686-linux-gnu; do
        clang++ --target=$t -O2 -fno-rtti -o "$out/vbnortti-$t" vbnortti_run.cpp
        echo "== vbnortti, clang++ --target=$t -O2 -fno-rtti"
        "$out/vbnortti-$t"
    done
    # `plugin.cpp`: which run `Plugin::drive` calls, in the committed shared
    # object, for a `My` the program defines.
    clang++ --target=x86_64-linux-gnu -O1 -o "$out/plugin" plugin_run.cpp "$PWD/vp-x86_64-linux-gnu.so"
    echo "== plugin, clang++ --target=x86_64-linux-gnu -O1 against vp-x86_64-linux-gnu.so"
    "$out/plugin"
} > processor_run.txt
cat processor_run.txt

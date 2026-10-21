#!/bin/bash
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Record what the LLVM tools say each fixture of this directory needs, so
# `imports_say_when_they_were_not_read.rs` can show each needs something
# without the tools installed; with `--features oracle` it re-runs these
# commands and fails when a recording no longer says what the tool says.
#
#   recorded/<name>.readobj.txt  a PE: llvm-readobj --coff-imports, which
#                                lists the delay-load table as `DelayImport`
#   recorded/<name>.nm.txt       an object: llvm-nm --undefined-only
#   recorded/unplaced-name-i686.exe.objdump.txt  llvm-objdump -p, which
#                                reads the import address table and lists
#                                both of planted.dll's entries
#   recorded/unplaced-name-i686.exe.readobj.txt and .readobj.err.txt
#                                llvm-readobj --coff-imports, which reads the
#                                lookup table and stops (exit 1) at the entry
#                                whose name it cannot place
set -eu
cd "$(dirname "$0")"
export LC_ALL=C
for f in delay-x86_64.dll delay-only-x86_64.dll; do
    llvm-readobj --coff-imports "$f" > "recorded/$f.readobj.txt"
done
llvm-readobj --file-headers relocatable-x86_64.o > recorded/relocatable-x86_64.o.readobj.txt
llvm-nm --undefined-only relocatable-x86_64.o > recorded/relocatable-x86_64.o.nm.txt
f=unplaced-name-i686.exe
llvm-objdump -p "$f" > "recorded/$f.objdump.txt"
if llvm-readobj --coff-imports "$f" > "recorded/$f.readobj.txt" 2> "recorded/$f.readobj.err.txt"; then
    echo "llvm-readobj read $f whole; the fixture no longer plants what it says" >&2
    exit 1
fi

#!/bin/bash
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Record what two LLVM tools say about each fixture, so a test can compare the
# engine with them without either tool installed. `--features oracle` re-runs
# this and fails when a recording no longer says what the tool says.
#
#   <fixture>.nm.txt       llvm-nm: where each _ZTV and _ZTI object is
#   <fixture>.readobj.txt  llvm-readobj: the ELF class, the relocations (which
#                          one fills each slot of a shared object), and for an
#                          executable the bytes of .rodata, where its vtables are;
#                          for `vp-*`, also the program headers and the dynamic
#                          table, which say whether an `ET_DYN` is a program
set -eu
cd "$(dirname "$0")"
export LC_ALL=C
for f in vt-* vb-* vbi-* vo-* vd-* vx-* vf-* vn-* vy-* vr-* vp-*; do
    case "$f" in *.txt) continue ;; esac
    llvm-nm "$f" > "$f.nm.txt"
    case "$f" in
        vp-*.so) llvm-readobj --file-headers --program-headers --dynamic-table --relocations "$f" > "$f.readobj.txt" ;;
        vp-*) llvm-readobj --file-headers --program-headers --dynamic-table --relocations --hex-dump=.rodata "$f" > "$f.readobj.txt" ;;
        *.so) llvm-readobj --file-headers --relocations "$f" > "$f.readobj.txt" ;;
        *) llvm-readobj --file-headers --relocations --hex-dump=.rodata "$f" > "$f.readobj.txt" ;;
    esac
done

#!/bin/bash
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Build the fixtures planted for an `imports` answer that must say "not read":
# each needs something from another image (or another object) that the
# engine's import reader does not read, so an empty or partial `read` list
# would be a wrong answer. Built 2026-10-21 with clang, lld-link and
# llvm-dlltool 23.1.1, and gcc 16.2.1; the committed binaries are what the
# recordings describe, so a rebuild is followed by `record.sh`.
#
#   delay-x86_64.dll       imports n0x_now from n0xnow.dll through the
#                          ordinary import table, and n0x_later_a and
#                          n0x_later_b from n0xlater.dll through the
#                          delay-load table (/delayload)
#   delay-only-x86_64.dll  imports only n0x_later_a, delay-loaded
#   relocatable-x86_64.o   compiled, not linked: needs n0x_ext_fn and
#                          n0x_ext_data, and has no dynamic section
#   unplaced-name-i686.exe ../ordinals-i686.exe with the first entry of
#                          planted.dll's import lookup table (by_name) pointed
#                          at RVA 0x7fff0000, in no section (plant.py): the
#                          table holds two entries and goblin returns one
set -eu
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
llvm-dlltool -m i386:x86-64 -d n0xnow.def -l "$work/n0xnow.lib"
llvm-dlltool -m i386:x86-64 -d n0xlater.def -l "$work/n0xlater.lib"
clang --target=x86_64-pc-windows-msvc -O1 -c delay.c -o "$work/delay.obj"
clang --target=x86_64-pc-windows-msvc -O1 -c delay_only.c -o "$work/delay_only.obj"
lld-link /dll /noentry /nodefaultlib /Brepro /implib:"$work/a.lib" /out:delay-x86_64.dll /delayload:n0xlater.dll \
    "$work/delay.obj" "$work/n0xnow.lib" "$work/n0xlater.lib"
lld-link /dll /noentry /nodefaultlib /Brepro /implib:"$work/b.lib" /out:delay-only-x86_64.dll /delayload:n0xlater.dll \
    "$work/delay_only.obj" "$work/n0xlater.lib"
gcc -O1 -c -o relocatable-x86_64.o relocatable.c
python3 -I plant.py ../ordinals-i686.exe unplaced-name-i686.exe planted.dll by_name 0x7fff0000

#!/bin/bash
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Build the two fixtures planted for `imports`, from the sources beside this
# script. Built 2026-10-21 with gcc 16.2.1 (GNU ld 2.47) and the mingw-w64
# i686 cross gcc and dlltool; the committed binaries are what the recordings
# describe, so a rebuild is followed by `record.sh`.
#
#   ordinals-i686.exe  a PE32 importing `by_name` by name and ordinal 7 by
#                      ordinal only from planted.dll (an import library made
#                      from planted.def; no such DLL needs to exist), and
#                      ExitProcess from kernel32.dll
#   planted-i686.dll   the library it names, exporting one function by name,
#                      one by ordinal only, a variable, and a forwarder to
#                      kernel32.dll (planted_dll.def)
#   imports-x86_64.so  needs libm.so.6 then libc.so.6, imports from each by a
#                      versioned name, and calls its own `n0x_self` through its
#                      PLT (a jump slot bound to its own definition)
set -eu
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
i686-w64-mingw32-dlltool -d planted.def -l "$work/libplanted.a"
i686-w64-mingw32-gcc -O1 -s -nostdlib -Wl,-e,_start -Wl,--no-insert-timestamp -o ordinals-i686.exe ordinals.c -L"$work" -lplanted -lkernel32
i686-w64-mingw32-gcc -O1 -s -shared -nostdlib -Wl,-e,__DllMainCRTStartup -Wl,--no-insert-timestamp -o planted-i686.dll planted_dll.c planted_dll.def
gcc -O1 -fPIC -fno-builtin -shared -Wl,--no-as-needed -o imports-x86_64.so imports.c -lm

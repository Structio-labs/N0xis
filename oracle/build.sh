#!/bin/bash
# Build the oracle corpus into `out/`. Each shape is independent: a missing
# toolchain skips that shape loudly and never fails the others, because a check
# that quietly does nothing is worse than no check.
#
# The test harness (`cargo test -p n0xis-cli --test oracle_corpus`) does the
# same thing into a temporary directory; this script is for measuring by hand.
set -u
cd "$(dirname "$0")"
mkdir -p out
built=0
try() { # try <label> <compiler> <output> <source> [extra…]
    local label="$1" cc="$2" out="$3" src="$4"; shift 4
    if ! command -v "$cc" >/dev/null 2>&1; then
        echo "skip  $label — no $cc" >&2
        return
    fi
    if "$cc" -shared -O1 -o "out/$out" "$src" "$@" 2>/dev/null; then
        echo "built $label -> out/$out"
        built=$((built+1))
    else
        echo "FAIL  $label — $cc could not build $src" >&2
    fi
}
try "sysv  (ELF x86-64)"  gcc                     sysv.so  sysv.c  -fPIC
try "win64 (PE  x86-64)"  x86_64-w64-mingw32-gcc  win64.dll win64.c
try "i386  (PE32 i386)"   i686-w64-mingw32-gcc    i386.dll  i386.c
echo "$built shape(s) built"

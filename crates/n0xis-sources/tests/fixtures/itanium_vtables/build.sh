#!/bin/bash
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Rebuild the fixtures from `vtables.cpp`, then record what llvm-nm and
# llvm-readobj say about each. The committed binaries were built with clang and
# ld.lld 23.1.1; another version lays the sections out differently, which is
# why the binaries are committed rather than built by the tests.
#
#   vt-<name>.so    a shared object, as measured when the defect was found:
#                   method slots are symbolic relocations, zero in the file.
#   vt-<name>       a static non-PIE executable: every slot and every type_info
#                   pointer holds its address in the file, and a vtable address
#                   is an immediate in the code.
#   stripped/vt-<name>
#                   that executable with only its _ZT* symbols left, so no
#                   function symbol names a method the slots point at.
set -eu
cd "$(dirname "$0")"
mkdir -p stripped
# <name> <clang target> <extra flags>
while read -r name target extra; do
    clang++ --target=$target $extra -O1 -fPIC -shared -nostdlib -fuse-ld=lld -o vt-$name.so vtables.cpp
    # `opaque` and the runtime's type_info vtables are defined nowhere; they
    # resolve to 0, which is what a slot the loader fills reads as anyway.
    clang++ --target=$target $extra -O1 -fno-pic -static -nostdlib -fuse-ld=lld \
        -Wl,--unresolved-symbols=ignore-all -Wl,--entry=0 -o vt-$name vtables.cpp
    # The executable with every symbol but the `_ZT*` (vtable, type_info) ones
    # removed, so a tool has to name the methods from the slots. `--strip-all`
    # drops non-allocated sections only: every byte the loader maps is the
    # unstripped file's, so that file's recordings say where everything is.
    llvm-objcopy --strip-all --keep-symbol='_ZT*' --wildcard vt-$name stripped/vt-$name
done <<'EOF'
i686-linux-gnu i686-linux-gnu
armv7-linux-gnueabihf armv7-linux-gnueabihf -marm
armv7-thumb-linux-gnueabihf armv7-linux-gnueabihf -mthumb
x86_64-linux-gnu x86_64-linux-gnu
aarch64-linux-gnu aarch64-linux-gnu
EOF
# `-marm` is A32: its slots hold even addresses, and that fixture is about
# pointer width. `-mthumb` is the same source as Thumb-2: every method is a
# Thumb function, so every slot that holds one holds its address with bit 0
# set — the case `analyze` must not name.
#
# Classes with virtual bases (`vbases.cpp`), at both widths: their vtables
# begin with virtual-base offsets, so `_ZTV` + two pointers is not their vptr.
for target in i686-linux-gnu x86_64-linux-gnu; do
    clang++ --target=$target -O1 -fPIC -shared -nostdlib -fuse-ld=lld -o vb-$target.so vbases.cpp
done
#
# Classes with virtual bases and no key function (`vbinline.cpp`), at -O2 as
# clang builds a header-only class: no VTT is emitted for any of them, so the
# refusal has to read the tables. A shared object and an executable each, at
# both widths.
for target in i686-linux-gnu x86_64-linux-gnu; do
    clang++ --target=$target -O2 -fPIC -shared -nostdlib -fuse-ld=lld -o vbi-$target.so vbinline.cpp
    clang++ --target=$target -O2 -fno-pic -static -nostdlib -fuse-ld=lld \
        -Wl,--unresolved-symbols=ignore-all -Wl,--entry=0 -o vbi-$target vbinline.cpp
done
#
# A subclass whose first method is outside `.text`, in an executable section
# of its own (`outside.cpp`): an executable, so its slots hold their addresses.
clang++ --target=x86_64-linux-gnu -O1 -fno-pic -static -nostdlib -fuse-ld=lld \
    -Wl,--unresolved-symbols=ignore-all -Wl,--entry=0 -o vo-x86_64-linux-gnu outside.cpp
#
# A subclass whose first method is outside every executable section
# (`notcode.cpp`, the method written in assembly into a writable `.data`).
clang++ --target=x86_64-linux-gnu -O1 -fno-pic -static -nostdlib -fuse-ld=lld \
    -Wl,--unresolved-symbols=ignore-all -Wl,--entry=0 -o vd-x86_64-linux-gnu notcode.cpp
#
# A class whose base is in another image (`external.cpp`), at both widths.
for target in i686-linux-gnu x86_64-linux-gnu; do
    clang++ --target=$target -O1 -fno-pic -static -nostdlib -fuse-ld=lld \
        -Wl,--unresolved-symbols=ignore-all -Wl,--entry=0 -o vx-$target external.cpp
done
#
# Where a construction gives an object its class (`flow.cpp`): an executable,
# so the vtable a placement new stores is an immediate in the code.
clang++ --target=x86_64-linux-gnu -O1 -fno-pic -static -nostdlib -fuse-ld=lld \
    -Wl,--unresolved-symbols=ignore-all -Wl,--entry=0 -o vf-x86_64-linux-gnu flow.cpp
#
# Classes with a virtual base built without RTTI (`vbnortti.cpp`), at -O2 as
# clang builds a header-only class: no type_info and no VTT, so only the
# relocations say that `_ZTV` + two pointers is not their first method. A
# shared object and a static executable at both x86 widths, and an ARMv7 (A32)
# executable.
for target in i686-linux-gnu x86_64-linux-gnu; do
    clang++ --target=$target -O2 -fno-rtti -fPIC -shared -nostdlib -fuse-ld=lld -o vn-$target.so vbnortti.cpp
    clang++ --target=$target -O2 -fno-rtti -fno-pic -static -nostdlib -fuse-ld=lld \
        -Wl,--unresolved-symbols=ignore-all -Wl,--entry=0 -o vn-$target vbnortti.cpp
done
clang++ --target=armv7-linux-gnueabihf -marm -O2 -fno-rtti -fno-pic -static -nostdlib -fuse-ld=lld \
    -Wl,--unresolved-symbols=ignore-all -Wl,--entry=0 -o vn-armv7-linux-gnueabihf vbnortti.cpp
#
# Classes whose virtual base is indirect and shares their vptr
# (`vbindirect.cpp`), as shared objects: their type_info pointers are symbolic
# relocations, so only the relocations say where their vptr is.
for target in i686-linux-gnu x86_64-linux-gnu; do
    clang++ --target=$target -O1 -fPIC -shared -nostdlib -fuse-ld=lld -o vy-$target.so vbindirect.cpp
done
#
# `vtables.cpp` as shared objects whose relative relocations are packed
# (`-z pack-relative-relocs`, with `-Bsymbolic` so the method slots are
# relative): the `RELR` table the reader of relocated words decodes.
for target in i686-linux-gnu x86_64-linux-gnu; do
    clang++ --target=$target -O1 -fPIC -shared -nostdlib -fuse-ld=lld -Wl,-Bsymbolic -Wl,-z,pack-relative-relocs \
        -o vr-$target.so vtables.cpp
done
#
# A class nothing in the image derives from (`plugin.cpp`), whose `drive`
# calls `run` through `this`, for x86-64: as a shared object, which a program
# that loads it may derive from (`plugin_run.cpp` does); as a static
# executable; and as a position-independent executable, an `ET_DYN` that is a
# program. The two `ET_DYN`s are linked `-Bsymbolic --apply-dynamic-relocs`, so
# their slots are relative relocations whose values are in the file too, as
# GNU ld writes them: lld otherwise leaves them zero, and a zero slot resolves
# nothing whatever the rule.
clang++ --target=x86_64-linux-gnu -O1 -fPIC -shared -nostdlib -fuse-ld=lld -Wl,-Bsymbolic -Wl,--apply-dynamic-relocs \
    -o vp-x86_64-linux-gnu.so plugin.cpp
clang++ --target=x86_64-linux-gnu -O1 -fno-pic -static -nostdlib -fuse-ld=lld \
    -Wl,--unresolved-symbols=ignore-all -Wl,--entry=0 -o vp-x86_64-linux-gnu plugin.cpp
clang++ --target=x86_64-linux-gnu -O1 -fPIE -pie -nostdlib -fuse-ld=lld -Wl,--apply-dynamic-relocs \
    -Wl,--unresolved-symbols=ignore-all -Wl,--entry=0 -o vp-pie-x86_64-linux-gnu plugin.cpp
#
# A big-endian shared object (`EI_DATA` = 2), for the refusal of the RTTI
# paths to read one. Only the shared object: nothing here reads its code.
clang++ --target=aarch64_be-linux-gnu -O1 -fPIC -shared -nostdlib -fuse-ld=lld -o vt-aarch64_be-linux-gnu.so vtables.cpp
./record.sh

#!/bin/sh
# Rebuilds the planted images of `strings_cut_where_a_length_says.rs` and records
# what `readelf` says they hold. Run from this directory.
set -eu
as --64 -o x86_64.o x86_64.s
as --64 --defsym PATH_ONLY=1 -o path_only.o x86_64.s
as --64 --defsym NOT_RUST=1 -o not_rust.o x86_64.s
# The one source in every shape a word of data can be written in. GNU ld keeps
# the address in the table and the word; lld leaves the word zero.
FIXED=--section-start=.fixed=0x9000
ld -shared $FIXED -o rela.so x86_64.o
ld.lld -shared --section-start=.fixed=0x9000 -o rela_zero.so x86_64.o
ld -shared -z pack-relative-relocs $FIXED -o relr.so x86_64.o
ld $FIXED -o exec x86_64.o
# What opens the gate, and what does not. `path_only_stripped.so` is what `strip`
# leaves of `path_only.so`: labels are read from the unstripped one's recording.
ld -shared $FIXED -o path_only.so path_only.o
strip --strip-all -o path_only_stripped.so path_only.so
ld -shared $FIXED -o not_rust.so not_rust.o
# Android's packed relocations, which this reader does not read.
ld.lld -shared --pack-dyn-relocs=android --section-start=.fixed=0x9000 -o android.so x86_64.o
rm -f x86_64.o path_only.o not_rust.o
as --32 -o i386.o i386.s
ld -m elf_i386 -shared -o i386.so i386.o
ld -m elf_i386 -o i386_exec i386.o
rm -f i386.o
aarch64-linux-gnu-as -EB -o aarch64_be.o aarch64_be.s
aarch64-linux-gnu-ld -EB -z max-page-size=0x1000 -shared -o aarch64_be.so aarch64_be.o
aarch64-linux-gnu-ld -EB -z max-page-size=0x1000 -o aarch64_be_exec aarch64_be.o
rm -f aarch64_be.o
x86_64-w64-mingw32-as -o win64.o win64.s
x86_64-w64-mingw32-ld --entry=_start -o win64.exe win64.o
rm -f win64.o
# readelf does not read a PE: `nm`, in the columns the test reads of readelf's.
LC_ALL=C x86_64-w64-mingw32-nm win64.exe | awk '{ print NR": "$1" 0 NOTYPE LOCAL DEFAULT 1 "$3 }' > win64.exe.symbols.txt
for f in rela.so rela_zero.so relr.so exec path_only.so not_rust.so android.so i386.so i386_exec aarch64_be.so aarch64_be_exec; do
    LC_ALL=C readelf -sW "$f" > "$f.symbols.txt"
    LC_ALL=C readelf -hW "$f" | grep -E 'Class|Data|Type' > "$f.header.txt"
    LC_ALL=C readelf -rW "$f" > "$f.relocs.txt"
done

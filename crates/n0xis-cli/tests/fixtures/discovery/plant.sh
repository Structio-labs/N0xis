#!/bin/sh
# Rebuilds the planted images of `discovery_on_planted_images.rs` from their
# sources and records what independent tools say they hold. Run from this
# directory; the recordings are what the test cites.
set -eu
as --64 -o x86_64.o x86_64.s
# `ext` stays undefined, so the call to it goes through a PLT the linker writes,
# with an FDE of the linker's own over it (`--ld-generated-unwind-info`, on by
# default).
ld -shared --ld-generated-unwind-info -o x86_64.so x86_64.o
rm -f x86_64.o
as --32 -o i386.o i386.s
ld -m elf_i386 -shared -o i386.so i386.o
rm -f i386.o
# LLVM's linker: GNU ld for arm-none-eabi moves a Thumb symbol onto an
# interworking stub, and the Thumb bit has to stay on the function's own.
llvm-mc -triple=armv7-linux-gnueabihf -filetype=obj -o arm32.o arm32.s
ld.lld -shared -o arm32.so arm32.o
rm -f arm32.o
as --64 -o rules.o rules.s
ld -shared -o rules.so rules.o
rm -f rules.o
LC_ALL=C objdump -d rules.so > rules.so.disassembly.txt
LC_ALL=C objdump --dwarf=frames rules.so | grep FDE > rules.so.frames.txt
as --64 -o lying.o lying.s
# No `--eh-frame-hdr`: nothing here should tidy the table up.
ld -shared -o lying.so lying.o
rm -f lying.o
LC_ALL=C objdump -d lying.so > lying.so.disassembly.txt
LC_ALL=C objdump --dwarf=frames lying.so | grep FDE > lying.so.frames.txt
as --64 -o noreturn.o noreturn.s
# `.data.rel.ro` is under PT_GNU_RELRO only with this.
ld -shared -z relro -o noreturn.so noreturn.o
rm -f noreturn.o
LC_ALL=C objdump -d noreturn.so > noreturn.so.disassembly.txt
LC_ALL=C readelf -rW noreturn.so > noreturn.so.relocations.txt
LC_ALL=C readelf -lW noreturn.so > noreturn.so.segments.txt
strip -o noreturn.stripped.so noreturn.so
aarch64-linux-gnu-as -o noreturn_a64.o noreturn_a64.s
aarch64-linux-gnu-ld -shared -o noreturn_a64.so noreturn_a64.o
rm -f noreturn_a64.o
LC_ALL=C aarch64-linux-gnu-objdump -d noreturn_a64.so > noreturn_a64.so.disassembly.txt
aarch64-linux-gnu-as -march=armv8.3-a -o aarch64.o aarch64.s
aarch64-linux-gnu-ld -shared -o aarch64.so aarch64.o
rm -f aarch64.o
LC_ALL=C aarch64-linux-gnu-objdump -d aarch64.so > aarch64.so.disassembly.txt
for f in x86_64.so i386.so arm32.so aarch64.so lying.so rules.so; do
    LC_ALL=C readelf -SW "$f" > "$f.sections.txt"
    LC_ALL=C readelf -sW "$f" > "$f.symbols.txt"
done
for f in x86_64.so i386.so; do
    LC_ALL=C objdump --dwarf=frames "$f" | grep FDE > "$f.frames.txt"
done
LC_ALL=C objdump -d i386.so > i386.so.disassembly.txt
# `big`'s 1 700 `add $0x1,%eax` are left out of the recording and counted.
LC_ALL=C objdump -d x86_64.so | grep -v 'add    $0x1,%eax' > x86_64.so.disassembly.txt
printf 'add $0x1,%%eax lines left out above: %s\n' "$(LC_ALL=C objdump -d x86_64.so | grep -c 'add    $0x1,%eax')" >> x86_64.so.disassembly.txt

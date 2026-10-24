#!/bin/sh
# Rebuilds the planted images from their sources and records what independent
# tools say they hold. Run from this directory; the recordings are what the
# test `contradictions_on_planted_images.rs` cites.
set -eu
as --64 -o planted.o planted.s
# No `--eh-frame-hdr`: the header refuses overlapping FDEs, and they are planted.
ld -shared -o planted.full.so planted.o
# `.dynsym` keeps `exported_name`; `.symtab` is left with `symtab_name` alone.
objcopy --strip-symbol=exported_name planted.full.so planted.so
rm -f planted.o planted.full.so
as --64 -o same_table.o same_table.s
ld -shared -o same_table.so same_table.o
rm -f same_table.o
wat2wasm --debug-names planted.wat -o planted.wasm
LC_ALL=C objdump --dwarf=frames planted.so | grep FDE > planted.so.frames.txt
LC_ALL=C readelf -sW planted.so > planted.so.symbols.txt
wasm-objdump -x planted.wasm > planted.wasm.details.txt
LC_ALL=C objdump --dwarf=frames same_table.so | grep FDE > same_table.so.frames.txt
LC_ALL=C readelf -sW same_table.so > same_table.so.symbols.txt

#!/bin/sh
# Rebuilds the planted images from be_eh.s and records what independent tools
# say they hold. Run from this directory; the recordings are what the test
# `big_endian_eh_frame_is_read.rs` cites. Needs clang and ld.lld (no sysroot:
# nothing is linked but the one object).
set -eu
for t in aarch64_be aarch64; do
    clang --target=$t-linux-gnu -c be_eh.s -o be_eh-$t.o
    ld.lld -shared --eh-frame-hdr -o be_eh-$t.so be_eh-$t.o
    rm -f be_eh-$t.o
    LC_ALL=C readelf --debug-dump=frames be_eh-$t.so | grep FDE > be_eh-$t.so.frames.txt
    LC_ALL=C readelf -sW be_eh-$t.so > be_eh-$t.so.symbols.txt
    LC_ALL=C readelf -h be_eh-$t.so | grep 'Data:' > be_eh-$t.so.data.txt
done

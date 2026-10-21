#!/bin/bash
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Build contested-x86_64.so: contested.c linked by gcc 16.2.1 (GNU ld 2.47)
# on 2026-10-21, then patched by plant.py so that two JUMP_SLOT relocations,
# one against the undefined n0x_ext_fn and one against the defined
# n0x_local_fn, name one slot. A rebuild is followed by `record.sh`.
set -eu
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
gcc -O1 -fPIC -fno-inline -shared -o "$work/contested.so" contested.c
python3 -I plant.py "$work/contested.so" contested-x86_64.so n0x_ext_fn n0x_local_fn

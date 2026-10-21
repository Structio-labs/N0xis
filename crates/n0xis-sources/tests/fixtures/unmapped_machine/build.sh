#!/bin/bash
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Build unmapped-riscv64.so from unmapped.c with clang and ld.lld 23.1.1 on
# 2026-10-21. No C library is needed: -nostdlib, and the one undefined
# function is left for the loader, as a shared object may. A rebuild is
# followed by `record.sh`.
set -eu
cd "$(dirname "$0")"
clang --target=riscv64-linux-gnu -O1 -fPIC -shared -nostdlib -fuse-ld=lld -o unmapped-riscv64.so unmapped.c

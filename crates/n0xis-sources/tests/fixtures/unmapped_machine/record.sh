#!/bin/bash
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Record what llvm-readobj says about unmapped-riscv64.so, so
# `a_slot_not_read_is_not_unbound.rs` reads the machine and the bound slot
# without the tool installed (`--features oracle` re-runs this):
#
#   unmapped-riscv64.so.readobj.txt  llvm-readobj --file-headers
#                                    --relocations: EM_RISCV, and the
#                                    R_RISCV_JUMP_SLOT against n0x_ext_fn
set -eu
cd "$(dirname "$0")"
export LC_ALL=C
llvm-readobj --file-headers --relocations unmapped-riscv64.so > unmapped-riscv64.so.readobj.txt

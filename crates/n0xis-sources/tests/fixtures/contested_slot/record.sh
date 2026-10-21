#!/bin/bash
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Record what the LLVM tools say about the planted slot, so
# `a_contested_slot_keeps_both_bindings.rs` compares the engine with them
# without the tools installed (`--features oracle` re-runs these):
#
#   contested-x86_64.so.readobj.txt  llvm-readobj --relocations: both
#                                    JUMP_SLOT entries at one offset
#   contested-x86_64.so.nm.txt       llvm-nm --defined-only: where
#                                    n0x_local_fn is
#   contested-x86_64.so.plt.txt      llvm-objdump -d of .plt: which entry
#                                    jumps through the slot
set -eu
cd "$(dirname "$0")"
export LC_ALL=C
llvm-readobj --relocations contested-x86_64.so > contested-x86_64.so.readobj.txt
llvm-nm --defined-only contested-x86_64.so > contested-x86_64.so.nm.txt
llvm-objdump -d --no-show-raw-insn -j .plt contested-x86_64.so > contested-x86_64.so.plt.txt

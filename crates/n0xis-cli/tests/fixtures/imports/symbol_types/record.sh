#!/bin/bash
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Record both symbol tables of types-x86_64.so as llvm-readobj lists them, so
# `image_layout_is_what_llvm_readobj_lists.rs` can count the symbols of each
# type without the tool installed; with `--features oracle` it re-runs this
# and fails when the recording no longer says what the tool says.
set -eu
cd "$(dirname "$0")"
export LC_ALL=C
llvm-readobj --symbols --dyn-syms types-x86_64.so > recorded/types-x86_64.so.readobj.txt

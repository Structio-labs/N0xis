#!/bin/bash
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Build types-x86_64.so from types.c: defined, named symbols of the types the
# ELF reader does not read as names (STT_GNU_IFUNC, STT_TLS, STT_NOTYPE), in
# both .symtab and .dynsym. Built 2026-10-21 with gcc 16.2.1 (GNU ld 2.47);
# a rebuild is followed by `record.sh`.
set -eu
cd "$(dirname "$0")"
gcc -O1 -fPIC -shared -o types-x86_64.so types.c

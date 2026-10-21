#!/bin/bash
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Record what the LLVM tools say each fixture imports, so
# `imports_are_what_llvm_readobj_lists.rs` compares the engine with them
# without either tool installed; with `--features oracle` it re-runs these
# commands and fails when a recording no longer says what the tool says.
# Run from anywhere; paths are given to the tools relative to the repository.
#
#   recorded/<name>.readobj.txt  llvm-readobj. A PE: its file headers (the
#                                image base) and import table. An ELF: its
#                                file headers, dynamic table (DT_NEEDED in
#                                order), needed libraries, dynamic symbols,
#                                version information and relocations.
#   recorded/<name>.plt.txt      an ELF's PLT entries as llvm-objdump names
#                                them (`<puts@plt>:`), from its .plt, .plt.sec
#                                and .plt.got sections.
#   recorded/<name>.layout.txt   llvm-readobj on how the image is loaded. A PE:
#                                its file headers, section table and export
#                                table. An ELF: its file and program headers.
set -eu
cd "$(dirname "$0")/../../../../.."
export LC_ALL=C
out=crates/n0xis-cli/tests/fixtures/imports/recorded
while read -r f; do
    name=$(basename "$f")
    case "$name" in
        *.exe | *.dll)
            llvm-readobj --file-headers --coff-imports "$f" > "$out/$name.readobj.txt"
            llvm-readobj --file-headers --sections --coff-exports "$f" > "$out/$name.layout.txt"
            ;;
        *)
            llvm-readobj --file-headers --dynamic-table --needed-libs --dyn-syms --version-info --relocations "$f" > "$out/$name.readobj.txt"
            llvm-readobj --file-headers --program-headers "$f" > "$out/$name.layout.txt"
            llvm-objdump -d --no-show-raw-insn -j .plt -j .plt.sec -j .plt.got "$f" 2>/dev/null | grep '@plt>:' > "$out/$name.plt.txt" || true
            ;;
    esac
done < crates/n0xis-cli/tests/fixtures/imports/fixtures.txt

// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// A PE whose .text holds 0x20 bytes in a 512-byte raw section: the rest is the
// file's padding to FileAlignment, which no section holds.
// (crates/n0xis-cli/tests/a_pe_section_is_its_virtual_size.rs)
int f(int x){return x*3+1;}
int start(void){return f(2);}

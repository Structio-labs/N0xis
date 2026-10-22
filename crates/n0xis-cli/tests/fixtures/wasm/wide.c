/* Copyright (c) 2026 Tymofii Kosovskyi
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 *
 * One wide string and one narrow one, built twice by build.sh: as
 * wide-even.wasm with -DNAME=wide_a and as wide-odd.wasm with -DNAME=wide_ab.
 * The longer name moves the data segment one byte further into the module,
 * and nothing about the strings: the compiler places char16_t text at an even
 * address of linear memory, whatever the module offset its bytes sit at.
 * build.sh requires that the two segments' module offsets differ in parity,
 * so the pair tests what it is for. */
typedef unsigned short char16_t;
__attribute__((visibility("default"))) const char16_t *NAME(void) { return u"Hello wide string here"; }
__attribute__((visibility("default"))) const char *narrow(void) { return "narrow text one"; }

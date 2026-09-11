/* Copyright (c) 2026 Tymofii Kosovskyi
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 *
 * Shape: PE32 carrying **hand-built MSVC RTTI**.
 *
 * A compiler will not produce this. mingw emits Itanium RTTI (`_ZTV`), and no
 * MSVC targets i386 on this machine — but real 32-bit PEs do carry MSVC RTTI,
 * because a runtime that has to be ABI-compatible with MSVC constructs those
 * structures by hand in its own source. Wine's C++ runtime does exactly that,
 * and reading it is how the defect below was found.
 *
 * So the structures are written here by hand too, which makes this the highest
 * rung of all: the answer is known *because it was planted*, and the layout
 * under test is stated in the file rather than inferred from a build.
 *
 * The 32-bit MSVC dialect, which is NOT the 64-bit one:
 *   TypeDescriptor { void *vftable; void *spare; char name[]; }   name at +8
 *   CompleteObjectLocator { u32 signature=0; u32 offset; u32 cdOffset;
 *                           TypeDescriptor *pTD;   <- an ABSOLUTE VA, not an RVA
 *                           void *pClassDescriptor; }             20 bytes, no pSelf
 *   ...COL pointer... | vtable[0] | vtable[1] | ...   <- the COL sits *before* the vtable
 *
 * Two things were wrong before this file existed. The scanner stepped 8 bytes
 * at a time through 4-byte slots and resolved absolute pointers as RVAs; and it
 * looked only in `.rdata`, while the vtable can sit in `.data` with its COL a
 * section away. It reported **0 classes for a 32-bit C++ runtime carrying 95
 * type descriptors**, with `ok: true` and an empty list.
 */

struct TypeDescriptor {
    const void *vftable;
    const void *spare;
    char name[24];
};

struct CompleteObjectLocator {
    unsigned signature; /* 0 marks the 32-bit dialect */
    unsigned offset;
    unsigned cd_offset;
    const struct TypeDescriptor *type_descriptor; /* absolute VA */
    const void *class_descriptor;
};

/* The first vtable slot has to land in `.text`, or the scanner rightly refuses
 * the candidate — a run of pointers into data is not a vtable. */
int planted_method(void);
int planted_method(void) { return 42; }

static const struct TypeDescriptor planted_td = { 0, 0, ".?AVPlantedClass@@" };
static const struct CompleteObjectLocator planted_col = { 0, 0, 0, &planted_td, 0 };

/* `[0]` is the COL pointer; the vtable proper starts at `[1]`. The trailing
 * null terminates the slot walk. */
__attribute__((used)) const void *planted_vtable[] = { &planted_col, (const void *)&planted_method, 0 };

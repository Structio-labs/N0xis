// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Fixture source for the phase12_il2cpp binding tests.
//
// Why this exists: those tests need a *real* PE — a genuine `.text` range, a
// genuine image base, and at least one function that calls another — so that
// `find_call_pair` can DISCOVER a real inter-function call and the IL2CPP
// name-binding measurement is made against an honest image. Previously the
// tests used n0xis's own compiled binary as that image, which made their ground
// truth a build artifact of whichever compiler the CI runner shipped: the same
// function moved between build configurations and one test failed on the MSVC
// runner while passing on the GNU/ELF build.
//
// This fixture removes that dependence. It is compiled ONCE with mingw at a
// pinned image base (0x140000000, matching the tests' IMAGE_BASE) and the
// resulting `native_pe.dll` is committed frozen. CI never rebuilds it — the
// tests only READ it — so the committed `.dll` is the sole ground truth and the
// tests are deterministic on any host.
//
// Shape required by the tests:
//   * base 0x140000000 (forced with -Wl,--image-base at link time);
//   * at least one function that CALLS another, where both the caller and the
//     callee are *unnamed* in the image — `find_call_pair` looks for a decompiled
//     `sub_140...` call to a different function, and the IL2CPP tests then bind a
//     managed name onto that `sub_`. So the interesting functions must NOT be
//     exported (an export name would make the decompiler print `combine` where
//     the test expects `sub_...`, and the index would have nothing to override).
//
// `mid` calls `leaf`; both are `static` (no export) so both render as `sub_140...`.
// `entry` is the single export, present only to give the image a legitimate
// export table; it is laid out at a HIGHER address than the internal pair, so
// `find_call_pair` (which walks candidates in address order) returns the
// internal `mid` -> `leaf` pair and never selects the named `entry`.
//
// Every function is `noinline` so the calls survive optimization and the call
// pair is real machine code, not an inlined constant. No libc beyond trivial
// arithmetic.
//
// Build (run once, then commit the .dll — do NOT rebuild in CI):
//   x86_64-w64-mingw32-gcc -O1 -shared -nostdlib -Wl,--image-base,0x140000000 \
//       -Wl,--entry,0 -o native_pe.dll native_pe.c
//
// The caller `mid` must sit at least 0x20 bytes into `.text`, because the
// near-miss tests plant an index entry at `caller_rva - 0x10` and
// `caller_rva - 0x20` and require those to land inside the PRECEDING function
// (so a covering symbol has something to attribute to, but not `mid`). `leaf`
// is therefore deliberately large enough to push `mid` past RVA 0x1020.
//
// Recorded addresses at the committed build (sanity only; the tests still
// DISCOVER the pair dynamically via find_call_pair):
//   leaf  RVA 0x1000 (VA 0x140001000, end 0x14000102a) -- callee, sub_140001000
//   mid   RVA 0x102a (VA 0x14000102a)                  -- caller, sub_14000102a
//   entry RVA 0x1051 (VA 0x140001051)                  -- the only export

// callee: unnamed leaf, rendered sub_140001000; padded with real arithmetic so
// it spans well over 0x20 bytes and `mid` starts above RVA 0x1020.
__attribute__((noinline)) static int leaf(int a, int b) {
    int r = a + b;
    r ^= a << 3;
    r += b * 7;
    r ^= r >> 2;
    r += (a ^ b) * 5;
    r -= b << 1;
    return r;
}

// caller: unnamed, calls the unnamed leaf so a decompiled listing shows a
// `sub_140...` target that is not the caller itself.
__attribute__((noinline)) static int mid(int a, int b) {
    return leaf(a, b) + leaf(b, a);
}

// The single export: only anchors a real export table; deliberately last so it
// sits above the internal pair in address order.
__declspec(dllexport) __attribute__((noinline)) int entry(int a, int b) {
    return mid(a, b) + leaf(a, 1);
}

// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Second fixture PE for the phase12_il2cpp provenance test — "binary B".
//
// Why this exists: the provenance regression test needs TWO distinct native
// images. An IL2CPP index is imported and validated against binary A
// (`native_pe.dll`), and then a DIFFERENT binary B (this file) is analysed. The
// bug the test pins is that the index used to AUTO-attach to B and fabricate a
// managed name at a coincidental address; with provenance recorded, the index
// only attaches to the binary it was validated against, so B shows its own
// symbols and no il2cpp note.
//
// Requirements it satisfies:
//   * same image base 0x140000000 as `native_pe.dll`, so the index's measured
//     RVA+base convention lands inside THIS image's `.text` too — otherwise the
//     "before" state (a fabricated name on B) would not reproduce and the test
//     would pass for the wrong reason;
//   * a function at RVA 0x1000, i.e. the same address the index's single method
//     is planted at, so the index would name THIS function were it to attach;
//   * BYTE-DIFFERENT code from `native_pe.dll` (different arithmetic), so its
//     `.text` fingerprint — and therefore its provenance identity — differs from
//     binary A. That difference is exactly what the fix keys on.
//
// Compiled ONCE with mingw and committed frozen; CI never rebuilds it.
//
// Build (run once, then commit the .dll — do NOT rebuild in CI):
//   x86_64-w64-mingw32-gcc -O1 -shared -nostdlib -Wl,--image-base,0x140000000 \
//       -Wl,--entry,0 -o native_pe_b.dll native_pe_b.c

// First function in `.text`, at RVA 0x1000 — the address the imported index's
// lone method is planted at. Unnamed (static) so it renders `sub_140001000`;
// its arithmetic is deliberately unlike `native_pe.dll`'s `leaf` so the image
// fingerprint differs.
__attribute__((noinline)) static int bleaf(int a, int b) {
    int r = a * b;
    r += a << 2;
    r ^= b + 9;
    r -= (a | b) * 3;
    r ^= r << 1;
    r += a - b;
    return r;
}

__attribute__((noinline)) static int bmid(int a, int b) {
    return bleaf(a, b) - bleaf(b, a);
}

__declspec(dllexport) __attribute__((noinline)) int bentry(int a, int b) {
    return bmid(a, b) + bleaf(a, 2);
}

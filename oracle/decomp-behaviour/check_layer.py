#!/usr/bin/env python3
"""The layer's rules and the prelude's operations, each against an answer worked out by hand or by the processor. A rule that
misreads a body is a wrong count for every body it touches, and these were found wrong by a set of functions nobody had read."""
import os, subprocess, sys, tempfile

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import behave

rules = set()
for raw, want in [
    # Nested in another's left operand, and in its right one.
    ("if ((((a > b) ? c : d) > e)) {", "if (((int64_t)((((int64_t)(a) > (int64_t)(b)) ? c : d)) > (int64_t)(e))) {"),
    ("x = (a > ((b < c) + 1));", "x = ((int64_t)(a) > (int64_t)((((int64_t)(b) < (int64_t)(c)) + 1)));"),
    ("x = ((uint8_t)a < /*u*/ b);", "x = ((uint8_t)((uint8_t)a) < (uint8_t)(b));"),
    ("x = ((int32_t)a >= 0);", "x = ((int32_t)((int32_t)a) >= (int32_t)(0));"),
    # 32 bits compared at 32 bits: the literal does not widen past them.
    ("if (((uint32_t)x != (-(long long)0x1))) {", "if (((uint32_t)((uint32_t)x) != (uint32_t)((-(long long)0x1)))) {"),
    ("if ((y == 0x1)) {", "if ((y == 0x1)) {"),
    # A string's text is not an expression.
    ('p = "a > (b";', 'p = "a > (b";'),
    ("x = (a->b >> 3);", "x = (a->b >> 3);"),
]:
    got = behave.signed_rel(raw, rules)
    assert got == want, (raw, got, want)

for raw, want in [
    ("(*r12_1)(a);", "((bh_fn)r12_1)(a);"),
    ("(**r12_1)(a);", "((bh_fn)*(uint64_t*)r12_1)(a);"),
    ("(*(*(bh_star_t*)(r12_1 + 0x8)))(a);", "((bh_fn)*(uint64_t*)(r12_1 + 0x8))(a);"),
    ("r12_1(a);", "((bh_fn)r12_1)(a);"),
]:
    got = behave.call_fix(raw)
    assert got == want, (raw, got, want)

assert behave.declare("rdi_0") == "uint64_t rdi_0 = G_RDI;"
assert behave.declare("r9_0") == "uint64_t r9_0 = G_R9;"
assert "BH_UNDEF" in behave.declare("rax_0")
assert "BH_UNDEF" in behave.declare("rdi_2")

with tempfile.TemporaryDirectory() as d:
    subprocess.run([sys.executable, str(behave.HERE) + "/gen_prelude.py", d + "/prelude.h"], check=True)
    src = d + "/t.c"
    # Each line: the prelude's operation, what the instruction leaves, from the Intel manual's definition.
    checks = [
        ("__cdq(0xfffffffbull)", "0xffffffffull"),
        ("__cdq(5)", "0ull"),
        ("(uint32_t)__idiv(0xffffffffull, 0xfffffffbull, 2, 32)", "0xfffffffeull"),
        ("(uint32_t)__irem(0xffffffffull, 0xfffffffbull, 2, 32)", "0xffffffffull"),
        ("(uint32_t)__idiv(0, 7, 0xfffffffeull, 32)", "0xfffffffdull"),
        ("(uint32_t)__udiv(1, 0, 2, 32)", "0x80000000ull"),
        ("__idiv(0xffffffffffffffffull, 0xfffffffffffffffbull, 2, 64)", "0xfffffffffffffffeull"),
        ("__rol((uint8_t)0x81, 1)", "0x03ull"),
        ("__ror((uint16_t)0x0001, 1)", "0x8000ull"),
        ("__rol((uint32_t)0x80000000u, 33)", "0x1ull"),
        ("__ror((uint64_t)1, 1)", "0x8000000000000000ull"),
        ("__bswap((uint32_t)0x11223344u)", "0x44332211ull"),
        ("__bswap((uint64_t)0x1122334455667788ull)", "0x8877665544332211ull"),
        ("__bsr((uint32_t)0x10u)", "4ull"),
        ("__bsf((uint32_t)0x10u)", "4ull"),
        ("__tzcnt((uint32_t)0)", "32ull"),
        ("__lzcnt((uint32_t)1)", "31ull"),
        ("__popcnt((uint32_t)0xf0f0u)", "8ull"),
    ]
    body = "\n".join(f'    if ((uint64_t)({a}) != {b}) {{ puts("{a.replace(chr(34), "")}"); bad++; }}' for a, b in checks)
    open(src, "w").write('#include <stdio.h>\n#include "prelude.h"\nuint64_t G_BASE, G_RDI, G_RSI, G_RDX, G_RCX, G_R8, G_R9;\nint main(void) {\n    int bad = 0;\n' + body + "\n    return bad;\n}\n")
    subprocess.run(["gcc", "-std=gnu11", "-w", "-I", d, src, "-o", d + "/t", "-lm"], check=True)
    r = subprocess.run([d + "/t"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout
print(f"layer and prelude: {len(checks)} operations, all as the manual says")

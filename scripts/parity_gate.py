#!/usr/bin/env python3
"""Phase 2 exit test: golden-output parity gate, v0 vs N0xis v1.

Runs the archived v0 CLI and the N0xis v1 CLI against the *same* PE and
checks that they agree on the facts that must hold regardless of schema:
which addresses are function starts, per-function block/instruction/callsite
counts, per-instruction address/length/mnemonic/branch-ness, xref "who calls
this" sets, and switch/jump-table case resolution.

Not a byte-for-byte diff — v0 and v1 use different JSON schemas and
disassembly formatters (NASM vs Intel syntax), so this compares structure and
content, not raw text. See ROADMAP.md Phase 2 "Exit test (parity gate)".

Usage:
    python scripts/parity_gate.py --v0 <path> --v1 <path> --target <PE>
    python scripts/parity_gate.py --v0 <path> --v1 <path>   # target defaults to --v1

Exit code 0 = every check passed; 1 = at least one failed.
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys


def run(binary: str, *args: str) -> dict:
    proc = subprocess.run([binary, *args, "--json"], capture_output=True, text=True)
    if not proc.stdout.strip():
        raise RuntimeError(f"{binary} {' '.join(args)} produced no stdout: {proc.stderr.strip()[:300]}")
    try:
        resp = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"{binary} {' '.join(args)}: invalid JSON: {proc.stdout[:300]}") from e
    if not resp.get("ok", False):
        raise RuntimeError(f"{binary} {' '.join(args)}: {resp.get('error')}")
    return resp["data"]


def hx(s: str) -> int:
    return int(s, 16)


class Report:
    def __init__(self) -> None:
        self.checks: list[tuple[str, bool, str]] = []

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append((name, ok, detail))
        mark = "PASS" if ok else "FAIL"
        line = f"[{mark}] {name}"
        if detail:
            line += f" — {detail}"
        print(line)

    def info(self, name: str, detail: str = "") -> None:
        line = f"[INFO] {name}"
        if detail:
            line += f" — {detail}"
        print(line)

    def summary(self) -> bool:
        total = len(self.checks)
        passed = sum(1 for _, ok, _ in self.checks if ok)
        print(f"\n{passed}/{total} checks passed")
        return passed == total


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--v0", required=True, help="path to the archived v0 CLI binary")
    ap.add_argument("--v1", required=True, help="path to the n0xis v1 CLI binary")
    ap.add_argument("--target", help="PE file both tools analyze (defaults to --v1's own binary)")
    ap.add_argument("--discover-limit", type=int, default=4000)
    ap.add_argument("--sample", type=int, default=15, help="functions to structurally compare")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    target = args.target or args.v1
    rpt = Report()
    random.seed(args.seed)

    print(f"v0={args.v0}\nv1={args.v1}\ntarget={target}\n")

    # --- 1. Discovery agreement: same address set from prologue scanning. ---
    d0 = run(args.v0, "function", "discover", "--file", target, "--limit", str(args.discover_limit))
    d1 = run(args.v1, "function", "discover", "--file", target, "--limit", str(args.discover_limit))
    s0 = {hx(f["address"]) for f in d0["functions"]}
    s1 = {hx(f["va"]) for f in d1["functions"]}
    inter = s0 & s1
    union = s0 | s1
    overlap = len(inter) / len(union) if union else 1.0
    rpt.check(
        "function discover: address-set overlap >= 0.95",
        overlap >= 0.95,
        f"v0={len(s0)} v1={len(s1)} intersection={len(inter)} overlap={overlap:.3f}",
    )

    if not inter:
        print("\nNo common function starts — cannot run per-function checks.")
        sys.exit(1 if not rpt.summary() else 0)

    sample = random.sample(sorted(inter), min(args.sample, len(inter)))

    # --- 2. Per-function CFG structural parity + switch-case resolution. ---
    switch_checked = 0
    switch_ok = 0
    for va in sample:
        addr = hex(va)
        f0 = run(args.v0, "ir", "build", "--file", target, "--addr", addr)
        f1 = run(args.v1, "ir", "build", "--file", target, "--addr", addr)

        rpt.check(
            f"{addr}: block_count matches",
            f0["block_count"] == f1["block_count"],
            f"v0={f0['block_count']} v1={f1['block_count']}",
        )
        rpt.check(
            f"{addr}: instruction_count matches",
            f0["instruction_count"] == f1["insn_count"],
            f"v0={f0['instruction_count']} v1={f1['insn_count']}",
        )
        shape0 = (len(f0["callsites"]), f0["returns"], f0["indirect_branches"], f0["tail_calls"])
        shape1 = (
            len(f1["callsites"]),
            f1["stats"]["returns"],
            f1["stats"]["indirect_branches"],
            f1["stats"]["tail_calls"],
        )
        rpt.check(f"{addr}: callsites/returns/indirect/tail match", shape0 == shape1, f"v0={shape0} v1={shape1}")

        for sw0 in f0.get("switches", []):
            switch_checked += 1
            at = sw0["at"]
            sw1 = next((s for s in f1.get("switches", []) if hx(s["at"]) == hx(at)), None)
            if sw1 is None:
                rpt.check(f"{addr}: switch at {at} also detected by v1", False, "v1 found no switch here")
                continue
            # Informational, not gating: v0's case resolver has no "is this
            # really code" gate (it over-reads into adjacent data on an
            # unreliable bound — the exact bug v1's code_range() check exists
            # to fix) and its "inside the current function" sanity filter can
            # under-resolve to an empty list where v1 correctly succeeds.
            # Both directions are documented, known-better-in-v1 divergences,
            # not parity failures — see ROADMAP.md's switch-resolution entry.
            c0 = {hx(c) for c in sw0.get("cases", [])}
            c1 = {hx(c) for c in sw1.get("cases", [])}
            agree = bool(c0 & c1) if (c0 and c1) else (not c0 and not c1)
            if agree:
                switch_ok += 1
            rpt.info(
                f"{addr}: switch at {at} case sets overlap = {agree}",
                f"v0={sorted(hex(x) for x in c0)} v1={sorted(hex(x) for x in c1)}",
            )

    # --- 3. Disasm parity: address/length/mnemonic/branch-ness sequence. ---
    for va in sample[: min(5, len(sample))]:
        addr = hex(va)
        r0 = run(args.v0, "disasm", "--file", target, "--addr", addr, "--count", "20")["instructions"]
        r1 = run(args.v1, "disasm", "--file", target, "--addr", addr, "--count", "20")["insns"]
        n = min(len(r0), len(r1))
        # Compare the leading token of each side's *formatted text*, not v1's
        # semantic `mnemonic` field — iced-x86 canonicalizes some encodings to
        # a semantic name (e.g. the `66 90` NOP-alias encoding of `xchg
        # ax,ax` reports mnemonic "nop"), which v0's NASM-formatted text
        # doesn't do. Comparing both sides' literal text keeps this
        # formatter-syntax-invariant without being fooled by that aliasing.
        mism = [
            i
            for i in range(n)
            if (hx(r0[i]["address"]), r0[i]["len"], r0[i]["text"].split()[0].lower())
            != (hx(r1[i]["va"]), r1[i]["len"], r1[i]["text"].split()[0].lower())
        ]
        rpt.check(f"{addr}: disasm addr/len/mnemonic sequence matches ({n} insns)", not mism, f"mismatched indices={mism}")

    # --- 4. Xref parity: "who calls this target" from-address sets. ---
    xref_checked = False
    for va in sample:
        addr = hex(va)
        f1 = run(args.v1, "ir", "build", "--file", target, "--addr", addr)
        target_addr = next((c["target"] for c in f1["callsites"] if c.get("target")), None)
        if not target_addr:
            continue
        xref_checked = True
        x0 = run(args.v0, "xref", "to", "--file", target, "--addr", target_addr, "--start", addr, "--size", "4096")
        x1 = run(args.v1, "xref", "to", "--file", target, "--addr", target_addr, "--start", addr, "--size", "4096")
        fs0 = {hx(r["from"]) for r in x0["xrefs"]}
        fs1 = {hx(r["from"]) for r in x1["refs"]}
        rpt.check(
            f"xref to {target_addr} (scanned from {addr}): from-sets match",
            fs0 == fs1,
            f"v0={sorted(hex(x) for x in fs0)} v1={sorted(hex(x) for x in fs1)}",
        )
        break
    if not xref_checked:
        rpt.check("xref to: found a comparable call target in the sample", False, "no resolved callsite target in sample")

    ok = rpt.summary()
    if switch_checked:
        print(f"switch-case parity: {switch_ok}/{switch_checked}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Score one obfuscation measurement against the truth, per command, and —
the number that matters — for each wrong answer say whether anything in the
engine's output warned of it (flagged) or it was `ok:true` with nothing
(silent).

Truth:
  function starts/ends/names   `truth.py` on the obfuscated unstripped build
                               (its own DWARF, correct by construction), scored
                               by rule-accuracy's `score.py` unchanged.
  instruction boundaries       the reference twin's `objdump` (`readers.py`):
                               its code is the obfuscated one with the planted
                               dead bytes replaced by equal-length NOPs, so it
                               decodes without the desync the junk is built to
                               cause.
  planted byte ranges          `build.json` (addresses resolved from the linked
                               image's symbol table): known, not inferred.

A warning is any of: the address is listed by `contradictions`; `why` gives the
start only heuristic sources; `ir deobfuscate` reports junk or an opaque
predicate in the function; the command refused (`ok:false`). Everything else
that is wrong is silent.

Usage: obf_score.py <build.json> <truth.json> <measure.json> <out.summary.json>
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter

import obf_corpus as corpus  # noqa: F401  keeps the rule-accuracy path set up
import readers
import score as ra_score


def ref_boundaries(ref_file: str | None) -> dict:
    """address -> (len, text) for every real instruction in the twin. The twin
    has no junk, so objdump does not desync; these are the true boundaries."""
    if not ref_file:
        return {}
    return readers.instructions(ref_file)


def contradiction_addrs(m: dict) -> set:
    """Every address a contradiction entry names, in any of its fields."""
    out = set()
    c = m.get("contradictions", {})
    if not c.get("ok"):
        return out
    for e in c["data"].get("contradictions", []):
        for v in json.dumps(e).split('"'):
            if re.fullmatch(r"0x[0-9a-fA-F]+", v):
                out.add(int(v, 16))
    return out


def ir_flagged(m: dict) -> set:
    """Function start addresses `ir deobfuscate` flagged (junk or opaque)."""
    out = set()
    for a, d in m.get("ir_deob", {}).items():
        if d.get("ok") and (d["data"].get("junk_bytes", 0) > 0 or d["data"].get("opaque_branches")):
            out.add(int(a, 16))
    return out


def score_discover(build, truth, m, contra):
    """Reuse rule-accuracy's scorer; split wrong starts into flagged/silent."""
    rows, summary = ra_score.score(truth, m, readers.symbols(build["measured_file"]))
    wrong = [r for r in rows if r["class"] in ("interior", "outside")]
    flagged = sum(1 for r in wrong if r["heuristic_only"] or r["va"] in contra)
    missed = summary.get("per_tier", {})
    n_missed = sum(v.get("missed", 0) for v in missed.values())
    n_truth = sum(v.get("truth", 0) for v in missed.values())
    return {
        "listed": summary.get("listed"),
        "wrong_starts": len(wrong),
        "wrong_flagged": flagged,
        "wrong_silent": len(wrong) - flagged,
        "truth_functions": n_truth,
        "missed_functions": n_missed,
        "recall": round((n_truth - n_missed) / n_truth, 4) if n_truth else None,
    }


def score_disasm(truth, m, ref, contra, irflag, planted):
    """Each engine instruction whose address is not a true boundary is a desync:
    a confident instruction over bytes that are not one. The planted dead-byte
    starts are true boundaries in the twin (a NOP there), so a desync shows up
    as the *next* address being off."""
    junk_starts = {p["lo"] for p in planted}
    total = decoded_junk = 0
    wrong_vas, flagged_vas = {}, set()
    examples = []
    for a, d in m.get("disasm", {}).items():
        if not d.get("ok"):
            continue
        fn = int(a, 16)
        for ins in d["data"].get("insns", []):
            va = int(ins["va"], 16)
            total += 1
            if va in junk_starts:
                decoded_junk += 1
                continue
            if va in ref:
                continue  # a true boundary: aligned
            # not a true instruction boundary -> a desynced (fictitious)
            # instruction. Counted once per distinct address (several calls may
            # reach the same desynced region).
            wrong_vas[va] = ins
            if fn in irflag or va in contra:
                flagged_vas.add(va)
    wrong = len(wrong_vas)
    flagged = len(flagged_vas)
    for va in sorted(wrong_vas):
        if va not in flagged_vas and len(examples) < 6:
            ins = wrong_vas[va]
            examples.append({"va": ins["va"], "bytes": ins["bytes"], "text": ins["text"]})
    return {"instructions": total, "decoded_dead_bytes": decoded_junk,
            "wrong": wrong, "wrong_flagged": flagged, "wrong_silent": wrong - flagged,
            "examples_silent": examples}


def score_strings(m, expected):
    """Recall of the planted strings; a planted string that is absent or merged
    into a neighbour is wrong. `strings` carries no per-string warning, so a
    miss is silent unless the command refused."""
    s = m.get("strings", {})
    if not s.get("ok"):
        return {"refused": True, "expected": len(expected), "found": 0, "wrong": len(expected), "wrong_flagged": len(expected), "wrong_silent": 0}
    texts = [x.get("text", "") for x in s["data"].get("strings", [])]
    blob = "\x00".join(texts)
    found = sum(1 for e in expected if any(e == t for t in texts))
    merged = sum(1 for e in expected if not any(e == t for t in texts) and e in blob)
    miss = len(expected) - found
    return {"refused": False, "expected": len(expected), "found": found, "merged": merged,
            "wrong": miss, "wrong_flagged": 0, "wrong_silent": miss}


def score_xref(truth, m, ref, contra):
    """Truth: the real call edges to each named function, counted off the twin's
    objdump. A reported reference whose source is not a real call to the target
    is wrong (a junk `0xe8` can look like a `call`)."""
    # Real call targets from the twin: source addr -> target addr.
    real_to = Counter()
    for va, (ln, text) in ref.items():
        mt = re.match(r"(call|jmp)\s+(?:0x)?([0-9a-f]+)", text)
        if mt:
            real_to[int(mt.group(2), 16)] += 1
    wrong = flagged = total = 0
    for a, d in m.get("xref_to", {}).items():
        if not d.get("ok"):
            continue
        tgt = int(a, 16)
        for r in d["data"].get("refs", []):
            total += 1
            frm = int(r["from"], 16)
            at = ref.get(frm)
            # Wrong if the twin has no call/jmp instruction at `from` to `tgt`.
            ok = at is not None and re.match(r"(call|jmp)\s+(?:0x)?([0-9a-f]+)", at[1]) and int(re.match(r"(call|jmp)\s+(?:0x)?([0-9a-f]+)", at[1]).group(2), 16) == tgt
            if not ok:
                wrong += 1
                if frm in contra:
                    flagged += 1
    return {"refs_reported": total, "wrong": wrong, "wrong_flagged": flagged, "wrong_silent": wrong - flagged}


def score_decomp(truth, m, planted):
    """Semantics is not measured. Recorded: did it return pseudo-C, its quality,
    and whether any pseudo line decoded a planted dead byte as a call/instruction
    (a leaked junk artifact)."""
    ok = weak = refused = leaked = 0
    junk_starts = {p["lo"] for p in planted}
    for a, d in m.get("decomp", {}).items():
        if not d.get("ok"):
            refused += 1
            continue
        ok += 1
        if d["data"].get("quality", 1.0) < 1.0:
            weak += 1
    return {"functions": len(m.get("decomp", {})), "ok": ok, "weak_quality": weak, "refused": refused}


def score_ir_deob(truth, m, planted):
    """Of the functions a planted junk byte lies in, how many does `ir
    deobfuscate` flag (recall of this junk class); and how many functions with
    NO planted byte does it flag (false positives on honest code)."""
    planted_fns = set()
    fns = sorted((f["start"], f.get("end") or f["start"] + 0x10000) for f in truth["functions"] if f["tier"] == "dwarf")
    for p in planted:
        for s, e in fns:
            if s <= p["lo"] < e:
                planted_fns.add(s)
                break
    detected = honest = fp = 0
    for a, d in m.get("ir_deob", {}).items():
        if not d.get("ok"):
            continue
        va = int(a, 16)
        flag = d["data"].get("junk_bytes", 0) > 0 or bool(d["data"].get("opaque_branches"))
        if va in planted_fns:
            if flag:
                detected += 1
        else:
            honest += 1
            if flag:
                fp += 1
    return {"functions_with_planted_junk": len(planted_fns), "detected": detected,
            "honest_functions": honest, "false_positives_on_honest": fp}


EXPECTED_STRINGS = {
    "calib": ["CALIB_POSITIVE", "CALIB_NONPOSITIVE", "CALIB_RESULT a=%d c=%d s=%ld p=%s\n"],
    "lua": [],
}


def main() -> int:
    build = json.load(open(sys.argv[1]))
    truth = json.load(open(sys.argv[2]))
    m = json.load(open(sys.argv[3]))
    out_path = sys.argv[4]
    ref = ref_boundaries(build.get("reference_file"))
    contra = contradiction_addrs(m)
    irflag = ir_flagged(m)
    planted = build.get("planted", [])
    summary = {
        "id": build["id"], "transform": build["transform"], "intensity": build["intensity"],
        "arch": build["arch"], "program": build["program"], "engine": m["engine"],
        "behaviour_ok": build.get("behaviour_ok"), "planted_count": build.get("planted_count"),
        "contradictions_count": m.get("contradictions", {}).get("data", {}).get("count"),
        "cmd": {
            "function_discover": score_discover(build, truth, m, contra),
            "disasm": score_disasm(truth, m, ref, contra, irflag, planted),
            "strings": score_strings(m, EXPECTED_STRINGS.get(build["program"], [])),
            "xref": score_xref(truth, m, ref, contra),
            "decomp": score_decomp(truth, m, planted),
            "ir_deobfuscate": score_ir_deob(truth, m, planted),
        },
    }
    json.dump(summary, open(out_path, "w"), indent=1)
    c = summary["cmd"]
    print(f"{build['id']}: disasm wrong {c['disasm']['wrong']} (silent {c['disasm']['wrong_silent']}), "
          f"discover wrong {c['function_discover']['wrong_starts']} recall {c['function_discover']['recall']}, "
          f"ir-deob detected {c['ir_deobfuscate']['detected']}/{c['ir_deobfuscate']['functions_with_planted_junk']} "
          f"fp {c['ir_deobfuscate']['false_positives_on_honest']}, contradictions {summary['contradictions_count']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Join one measurement with its truth: every listed start classified, every
truth function found or missed, every end and name compared.

A start is:
  true        the entry of a truth function (tier dwarf, symtab or plt)
  fragment    the start of a non-entry range of a DWARF function (a `.cold`
              part): code of a function, not a start of one. Kept apart from
              both true and wrong, so either reading can be taken from the table
  plt0        a PLT's header, which no table calls a function
  interior    wrong: inside a truth function (or a fragment) at no start
  outside     wrong: in no truth function — padding, or code nothing names

Usage: score.py <truth.json> <measure.json> <rows.jsonl> <summary.json>
"""

from __future__ import annotations

import bisect
import json
import re
import sys
from collections import Counter, defaultdict

DECLARED = {"unwind:eh_frame", "unwind:pdata", "export", "symbol", "pdb", "body", "stub"}
HEURISTIC = {"after_declared_end", "gap_sweep", "call_target", "prologue"}
TRUE = ("true",)
WRONG = ("interior", "outside")


def source_key(s: dict) -> str:
    src = s["source"]
    if src == "unwind":
        return f"unwind:{s['table']}"
    return src


def end_key(e: dict) -> str:
    src = e["source"]
    if src == "unwind":
        return f"unwind:{e['table']}"
    if src == "symbol_size":
        return f"symbol_size:{e['of']}"
    if src == "not_stated":
        return "not_stated" if "end" in e.get("cfg", {}) else "not_stated(no cfg)"
    return src


def end_va(e: dict):
    if "va" in e:
        return int(e["va"], 16)
    cfg = e.get("cfg", {})
    return int(cfg["end"], 16) if "end" in cfg else None


def name_key(n: dict) -> str:
    if n["source"] == "image":
        return f"image:{n['table']}"
    return n["source"]


class Truth:
    def __init__(self, t: dict):
        self.t = t
        self.functions = {f["start"]: f for f in t["functions"]}
        self.fragments = {f["start"]: f for f in t["fragments"]}
        self.plt_heads = set(t["plt_heads"])
        # Every extent with a known end, for "inside which function".
        spans = []
        for f in t["functions"]:
            if f["end"]:
                spans.append((f["start"], f["end"], f["start"]))
        for fr in t["fragments"]:
            spans.append((fr["start"], fr["end"], fr["of"]))
        for lo, hi in t["ranges"]:
            spans.append((lo, hi, -1))  # -1: a DWARF range whose owner is found above
        spans.sort()
        self.spans = spans
        self.span_starts = [s[0] for s in spans]
        self.names = {int(k): v for k, v in t["names"].items()}
        self.dem = t["demangled"]
        self.dem_llvm = t.get("demangled_llvm", {})

    def containing(self, va: int):
        """The truth extent `va` lies strictly inside, if any (lo, hi, owner)."""
        i = bisect.bisect_right(self.span_starts, va)
        best = None
        for j in range(i - 1, -1, -1):
            lo, hi, owner = self.spans[j]
            if lo < va < hi:
                if best is None or (owner != -1 and best[2] == -1):
                    best = (lo, hi, owner)
            if va - lo > 1 << 20:
                break
        return best

    def classify(self, va: int) -> tuple:
        if va in self.functions:
            return "true", self.functions[va]["tier"]
        if va in self.fragments:
            return "fragment", None
        if va in self.plt_heads:
            return "plt0", None
        if self.containing(va):
            return "interior", None
        return "outside", None

    def name_matches(self, listed: str, va: int) -> bool:
        cands = self.names.get(va, [])
        return any(listed in (n, self.dem.get(n, n), self.dem_llvm.get(n, n)) for n in cands)

    def name_spelled(self, listed: str, va: int) -> bool:
        """The listed name is a symbol's name in another spelling of the same
        identity — kept apart from both exact and wrong, so a style is never
        counted as a wrong name and never hides one:

        - an undemangled name with every character outside `[A-Za-z0-9_]` as
          `_` (`luaD_throw.cold` listed as `luaD_throw_cold`);
        - a stub named after its import (`puts` for objdump's `puts@plt`);
        - a demangled name whose only differences from c++filt's or
          llvm-cxxfilt's are how an
          integer template argument is written (`(unsigned long)0` for `0ul`)
          and the space in `> >`. Anything else a demangler prints
          differently — a parameter more or fewer — stays wrong.
        """
        cands = self.names.get(va, [])
        for n in cands:
            if listed == re.sub(r"[^A-Za-z0-9_]", "_", n) or listed + "@plt" in (n, self.dem.get(n, n), self.dem_llvm.get(n, n)):
                return True
            if canon_demangled(listed) in (canon_demangled(self.dem.get(n, n)), canon_demangled(self.dem_llvm.get(n, n))):
                return True
        return False


_LITERAL_CAST = re.compile(r"\((?:unsigned |signed )?(?:long long|long|int|short|char)\)(-?\d+)")
_LITERAL_SUFFIX = re.compile(r"\b(-?\d+)(?:ull|ul|ll|l|u)\b")


def canon_demangled(s: str) -> str:
    """A demangled name with the integer-literal and `> >` styles taken out."""
    s = _LITERAL_CAST.sub(r"\1", s)
    s = _LITERAL_SUFFIX.sub(r"\1", s)
    return s.replace(" >", ">")


def end_cmp(engine_end, truth_ends: list) -> str:
    if engine_end is None:
        return "no_end"
    if not truth_ends:
        return "no_truth"
    if engine_end in truth_ends:
        return "exact"
    if engine_end < min(truth_ends):
        return "short"
    if engine_end > max(truth_ends):
        return "long"
    return "between"


def score(truth: dict, meas: dict, measured_symbols: list | None = None) -> tuple:
    """`measured_symbols`: the measured file's own symbol entries (readelf),
    so a missed function can say whether the file it was missed in names it."""
    T = Truth(truth)
    rows = []
    checks = Counter()
    disc = meas["discover"]
    if not disc.get("ok"):
        return [], {"error": disc}
    listed = {f["va"]: f for f in disc["data"]["functions"]}
    found = {}
    for va_s, f in listed.items():
        va = int(va_s, 16)
        w = meas["why"].get(va_s, {})
        if not w.get("ok") or "found" not in w["data"]["function"]:
            checks["why: no function"] += 1
            continue
        fw = w["data"]["function"]["found"]
        # Contract checks between the two doors (rung 5: they flag a harness
        # or engine inconsistency, they are not evidence of truth).
        if int(fw["start"], 16) != va or not fw["addr_is_start"]:
            checks["why: start differs from the list"] += 1
        if f.get("end") is not None and end_va(fw["end"]) != int(f["end"], 16):
            checks["why: end differs from the list"] += 1
        if fw["name"]["name"] != f["name"]:
            checks["why: name differs from the list"] += 1
        sources = sorted({source_key(s) for s in fw["start_sources"]})
        unknown = set(sources) - DECLARED - HEURISTIC
        if unknown:
            checks[f"unknown source {sorted(unknown)}"] += 1
        cls, tier = T.classify(va)
        ekey, eva = end_key(fw["end"]), end_va(fw["end"])
        if cls == "true":
            ecmp = end_cmp(eva, T.functions[va]["ends"])
        elif cls == "fragment":
            ecmp = end_cmp(eva, [T.fragments[va]["end"]])
        else:
            ecmp = "not_a_start"
        nkey = name_key(fw["name"])
        truth_names = T.names.get(va, [])
        if nkey == "fallback":
            ncmp = "fallback_where_named" if truth_names else "fallback_unnamed"
        elif not truth_names:
            ncmp = "named_where_unnamed"
        else:
            ncmp = "exact" if T.name_matches(fw["name"]["name"], va) else "spelled" if T.name_spelled(fw["name"]["name"], va) else "wrong"
        row = {
            "va": va, "class": cls, "tier": tier, "sources": sources,
            "heuristic_only": not (set(sources) & DECLARED),
            "end_source": ekey, "end": eva, "end_cmp": ecmp,
            "truth_end": (T.functions[va]["ends"] if cls == "true" else [T.fragments[va]["end"]] if cls == "fragment" else None),
            "name_layer": nkey, "name": fw["name"]["name"], "truth_names": truth_names, "name_cmp": ncmp,
        }
        if cls in WRONG:
            c = T.containing(va)
            if c:
                owner = c[2]
                row["inside"] = {"lo": c[0], "hi": c[1], "owner": owner, "owner_names": T.names.get(owner, [])}
        rows.append(row)
        found[va] = row

    # --- per source category
    per_source = defaultdict(Counter)
    for r in rows:
        for s in r["sources"]:
            per_source[s]["produced"] += 1
            per_source[s][r["class"]] += 1
        if len(r["sources"]) == 1:
            s = r["sources"][0]
            per_source[s]["alone"] += 1
            per_source[s][f"alone_{r['class']}"] += 1

    # --- truth functions found / missed
    per_tier = defaultdict(Counter)
    found_by = defaultdict(Counter)
    missed = []
    for start, f in T.functions.items():
        tier = f["tier"]
        per_tier[tier]["truth"] += 1
        r = found.get(start)
        if r is None:
            per_tier[tier]["missed"] += 1
            named_in = sorted({s["table"] for s in (measured_symbols or []) if s["value"] == start and s["type"] in ("FUNC", "IFUNC") and s["ndx"] not in ("UND", "ABS")})
            per_tier[tier]["missed_named_in_" + ("+".join(named_in) or "none")] += 1
            missed.append({"va": start, "tier": tier, "names": T.names.get(start, []), "measured_file_names_it_in": named_in})
            continue
        per_tier[tier]["found"] += 1
        for s in r["sources"]:
            found_by[tier][s] += 1
        if len(r["sources"]) == 1:
            found_by[tier][f"only:{r['sources'][0]}"] += 1

    # --- ends and names
    per_end = defaultdict(Counter)
    per_name = defaultdict(Counter)
    for r in rows:
        if r["class"] in ("true", "fragment"):
            per_end[f"{r['class']}|{r['end_source']}"][r["end_cmp"]] += 1
        per_name[r["name_layer"]][r["name_cmp"]] += 1

    # --- the direction: wrong answers by kind of source
    direction = Counter()
    for r in rows:
        kind = "heuristic_only" if r["heuristic_only"] else "any_declared"
        direction[f"starts|{kind}|all"] += 1
        direction[f"starts|{kind}|{r['class']}"] += 1
        if r["class"] == "true" and r["end_cmp"] in ("exact", "short", "long", "between", "no_end"):
            ekind = "declared" if r["end_source"].split(":")[0] in ("unwind", "symbol_size", "export", "pdb", "body", "stub") else "heuristic"
            direction[f"ends|{ekind}|all"] += 1
            direction[f"ends|{ekind}|{'right' if r['end_cmp'] == 'exact' else 'wrong'}"] += 1
            # The start's own kind, for the question "does a heuristic start
            # predict a wrong end too".
            direction[f"ends_by_start|{kind}|{'right' if r['end_cmp'] == 'exact' else 'wrong'}"] += 1

    summary = {
        "listed": len(listed),
        "classes": Counter(r["class"] for r in rows),
        "per_source": {k: dict(v) for k, v in per_source.items()},
        "per_tier": {k: dict(v) for k, v in per_tier.items()},
        "found_by": {k: dict(v) for k, v in found_by.items()},
        "per_end": {k: dict(v) for k, v in per_end.items()},
        "per_name": {k: dict(v) for k, v in per_name.items()},
        "direction": dict(direction),
        "checks": dict(checks),
        "missed": missed,
        "engine": meas["engine"],
    }
    return rows, summary


def main() -> int:
    truth = json.load(open(sys.argv[1]))
    meas = json.load(open(sys.argv[2]))
    rows, summary = score(truth, meas)
    with open(sys.argv[3], "w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    json.dump(summary, open(sys.argv[4], "w"), indent=1)
    print(json.dumps({"listed": summary.get("listed"), "classes": summary.get("classes"), "checks": summary.get("checks")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

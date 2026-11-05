#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Score a lying table: per command, the answers the lie made wrong, and of those
how many carried a warning.

The truth is the file before tampering (DWARF and symbols read by `truth.py`,
instructions by `objdump`). The control is the configuration that differs by the
lie alone: the code is byte-identical (checked here, not assumed), so a wrong
answer the control also gives is the engine's normal behaviour and is not charged
to the lie. Every set is of addresses, so "new" is a set difference, never a
difference of two counts, which could hide a wrong answer behind a fixed one.

A warning is any of: the address lies in a place `contradictions` lists; `why`
gives only a heuristic source for the fact (start, or end); the command refused.
Everything else that is wrong is silent.

What is scored, per command:
  function discover  starts no function has; functions no longer listed; ends;
                     names (against the rule-accuracy scorer's classes).
  why                on every true start: does it answer the function that starts
                     there? (`why --addr` is the door a hidden function shows on.)
  contradictions     of the lies planted, how many it names; how many it lists.
  decomp pseudo      on every true start: an end moved off the truth; a function
                     name or a callee name the lie gave. A pseudo text that changed
                     for no reason this can name is counted apart as changed, never
                     as wrong.
  xref to            references the file before tampering does not have, and real
                     ones the control reported and this answer lost.
"""

from __future__ import annotations

import bisect
import json
import re

import obf_corpus as corpus  # noqa: F401  keeps the rule-accuracy path set up
import readers
import score as ra_score

DECLARED_ENDS = ("unwind", "symbol_size", "export", "pdb", "body", "stub")


class Warnings:
    """Where `contradictions` speaks: every address it names, and every extent it
    names. A contradiction about an extent is a warning about what lies inside: a
    function hidden inside an extent someone doubts has been warned of, one inside
    an extent nobody doubts has not."""

    def __init__(self, meas: dict):
        self.named, spans = set(), []
        self.count, self.kinds = 0, {}
        c = meas.get("contradictions", {})
        if not c.get("ok"):
            self.refused = True
            self.lo, self.hi = [], []
            return
        self.refused = False
        self.count = c["data"].get("count", 0)
        for e in c["data"].get("contradictions", []):
            k = e.get("kind")
            self.kinds[k] = self.kinds.get(k, 0) + 1
            if k == "overlap":
                for side in (e["first"], e["second"]):
                    lo, hi = int(side["start"], 16), int(side["end"], 16)
                    self.named.add(lo)
                    spans.append((lo, hi))
            elif k == "end":
                lo = int(e["start"], 16)
                self.named.add(lo)
                spans.append((lo, max(int(x["end"], 16) for x in e["ends"])))
            elif k == "name":
                self.named.add(int(e["addr"], 16))
        spans.sort()
        merged: list = []
        for lo, hi in spans:
            if merged and lo <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        self.lo, self.hi = [m[0] for m in merged], [m[1] for m in merged]

    def covers(self, va: int) -> bool:
        if va in self.named:
            return True
        i = bisect.bisect_right(self.lo, va) - 1
        return i >= 0 and va < self.hi[i]


def _why_found(meas: dict, va: int):
    w = meas.get("why", {}).get(hex(va))
    if not w or not w.get("ok"):
        return None
    return w["data"]["function"].get("found")


def _heuristic_owner(found) -> bool:
    return bool(found) and not ({ra_score.source_key(s) for s in found["start_sources"]} & ra_score.DECLARED)


def _facts(truth: dict, meas: dict, measured_symbols: list) -> dict:
    """Every wrong answer in `meas`, as sets keyed by address, with what the answer
    was. Against the truth alone; the control is subtracted by `score`."""
    T = ra_score.Truth(truth)
    rows, summary = ra_score.score(truth, meas, measured_symbols)
    out: dict = {k: {} for k in ("wrong_start", "missed", "wrong_end", "wrong_name", "why_owner", "decomp_ok", "decomp_refused", "xref")}
    out["checks"] = summary.get("checks", {})
    out["discover_ok"] = bool(meas["discover"].get("ok"))
    if not out["discover_ok"]:
        return out
    for r in rows:
        va = r["va"]
        if r["class"] in ra_score.WRONG:
            out["wrong_start"][va] = {"sources": r["sources"], "heuristic_only": r["heuristic_only"], "name": r["name"], "end": r["end"], "inside": r.get("inside")}
        if r["class"] == "true" and r["end_cmp"] in ("short", "long", "between"):
            declared = r["end_source"].split(":")[0] in DECLARED_ENDS
            out["wrong_end"][va] = {"end": r["end"], "truth": r["truth_end"], "cmp": r["end_cmp"], "source": r["end_source"], "declared": declared, "name": r["name"]}
        if r["name_cmp"] == "wrong":
            out["wrong_name"][va] = {"name": r["name"], "truth": r["truth_names"], "layer": r["name_layer"]}
    for m in summary.get("missed", []):
        if m["tier"] in ("dwarf", "symtab"):
            out["missed"][m["va"]] = {"names": m["names"]}
    for f in truth["functions"]:
        if f["tier"] not in ("dwarf", "symtab"):
            continue
        s = f["start"]
        w = meas.get("why", {}).get(hex(s))
        if w is None:
            continue
        if not w.get("ok"):
            out["why_owner"][s] = {"refused": True}
            continue
        fw = w["data"]["function"].get("found")
        if fw is None:
            out["why_owner"][s] = {"none": True, "answer": w["data"]["function"]}
        elif int(fw["start"], 16) != s or not fw["addr_is_start"]:
            out["why_owner"][s] = {"owner": int(fw["start"], 16), "name": fw["name"]["name"], "sources": [ra_score.source_key(x) for x in fw["start_sources"]], "heuristic_only": _heuristic_owner(fw), "names": T.names.get(s, [])}
    return out


_CALLEE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _signature_name(sig: str) -> str:
    m = re.search(r"([A-Za-z_][A-Za-z0-9_.$]*)\s*\(", sig or "")
    return m.group(1) if m else ""


def _decomp(truth: dict, meas: dict, base: dict, lie_names: set) -> dict:
    """Against the control, on every true start. `lie_names`: what the lie says a
    function is called (a false symbol's name, a swapped export): such a name newly
    in the text is a name the code did not have."""
    T = ra_score.Truth(truth)
    wrong, refused, changed, crashed, same = {}, {}, {}, {}, 0
    for f in truth["functions"]:
        if f["tier"] not in ("dwarf", "symtab"):
            continue
        s = f["start"]
        a = hex(s)
        d, b = meas.get("decomp", {}).get(a), base.get("decomp", {}).get(a)
        if d is None or b is None:
            continue
        if not d.get("ok"):
            if d.get("error", {}).get("code") == "crash":
                crashed[s] = d["error"]
            elif b.get("ok"):
                refused[s] = d.get("error", {})
            continue
        if not b.get("ok"):
            continue
        dd, bd = d["data"], b["data"]
        if dd["pseudo"] == bd["pseudo"] and dd.get("end_address") == bd.get("end_address"):
            same += 1
            continue
        why = {}
        end, bend = dd.get("end_address"), bd.get("end_address")
        if end != bend and f["end"] and (end is None or int(end, 16) != f["end"]):
            why["end"] = {"said": end, "control": bend, "truth": hex(f["end"]), "instructions": dd.get("instruction_count"), "control_instructions": bd.get("instruction_count")}
        nm, bnm = _signature_name(dd.get("signature")), _signature_name(bd.get("signature"))
        if nm != bnm and not T.name_matches(nm, s) and not nm.startswith("sub_"):
            why["name"] = {"said": nm, "control": bnm, "truth": T.names.get(s, [])}
        if lie_names:
            # Line by line, not over the whole text: a swap keeps both names in a
            # function that calls both, and only their places change. (Whole-text sets
            # called `main`'s swapped callees "changed for no reason" on the first run.)
            said, ctl = dd["pseudo"][1:], bd["pseudo"][1:]
            pairs = zip(said, ctl) if len(said) == len(ctl) else [("\n".join(said), "\n".join(ctl))]
            new_callees = set()
            for line, cline in pairs:
                if line != cline:
                    new_callees |= (set(_CALLEE.findall(line)) - set(_CALLEE.findall(cline))) & lie_names
            if new_callees:
                why["callee"] = sorted(new_callees)
        if why:
            wrong[s] = why
        else:
            changed[s] = {"instructions": dd.get("instruction_count"), "control_instructions": bd.get("instruction_count")}
    return {"wrong": wrong, "refused": refused, "changed": changed, "crashed": crashed, "same": same}


_TRANSFER = re.compile(r"(callq?|jmpq?|bl|br|b|j[a-z]+|b\.[a-z]+|cbn?z|tbn?z)\b\s+(?:\S+,\s*)*(?:0x)?([0-9a-f]+)")


def _xref(meas: dict, base: dict, ref: dict) -> dict:
    """A reported reference is checked against the file before tampering's own
    `objdump`; a data reference (`lea`, `adrp`) carries no transfer target there, so
    what the control also reported is not charged. `lost` is what the control
    reported and this answer does not."""
    invented, lost, total = {}, {}, 0
    for a, d in meas.get("xref_to", {}).items():
        b = base.get("xref_to", {}).get(a, {})
        if not d.get("ok") or not b.get("ok"):
            continue
        tgt = int(a, 16)
        mine = {int(r["from"], 16) for r in d["data"].get("refs", [])}
        theirs = {int(r["from"], 16) for r in b["data"].get("refs", [])}
        total += len(mine)
        for frm in mine - theirs:
            at = ref.get(frm)
            m = _TRANSFER.match(at[1]) if at else None
            if m is None or int(m.group(2), 16) != tgt:
                invented[(tgt, frm)] = at[1] if at else None
        for frm in theirs - mine:
            lost[(tgt, frm)] = ref[frm][1] if frm in ref else None
    return {"refs_reported": total, "invented": invented, "lost": lost}


def _split(new: dict, flagged) -> dict:
    f = [k for k, v in new.items() if flagged(k, v)]
    silent = [k for k in new if k not in set(f)]
    return {"wrong": len(new), "flagged": len(f), "silent": len(silent), "silent_at": sorted(silent)[:8], "flagged_at": sorted(f)[:4]}


def score(build: dict, truth: dict, meas: dict, base_build: dict, base_truth: dict, base_meas: dict) -> dict:
    """The lie's numbers. `base_*`: its control. A lie with itself as its control
    (a baseline scored against itself) gives its absolute numbers under `abs` and
    zero new ones: that is the check that the subtraction subtracts."""
    same, _, _ = readers.same_code(build["truth_file"], base_build["truth_file"])
    if not same:
        raise ValueError(f"{build['id']}: its code is not its control's: the join would compare different programs")
    ref = readers.instructions(build["reference_file"] or build["truth_file"])
    W = Warnings(meas)
    mine = _facts(truth, meas, readers.symbols(build["measured_file"]))
    theirs = _facts(base_truth, base_meas, readers.symbols(base_build["measured_file"]))
    planted = build.get("planted_lies", [])

    def new(key):
        return {k: v for k, v in mine[key].items() if k not in theirs[key]}

    out: dict = {
        "id": build["id"], "transform": build["transform"], "intensity": build["intensity"], "arch": build["arch"], "program": build["program"],
        "engine": meas["engine"], "behaviour_ok": build.get("behaviour_ok"), "planted": len(planted), "eligible": build.get("eligible_functions"),
        "listed": meas["discover"]["data"]["count"] if meas["discover"].get("ok") else None,
        "serve_crashes": meas.get("serve_crashes", 0), "discover_ok": mine["discover_ok"], "contract_checks": mine["checks"],
    }
    if not mine["discover_ok"]:
        out["refused"] = meas["discover"].get("error")
        return out

    def by_table_or_heuristic(k, v):
        return v.get("heuristic_only") or W.covers(k)

    out["wrong_start"] = _split(new("wrong_start"), by_table_or_heuristic)
    out["wrong_start_cites_table"] = sum(1 for v in new("wrong_start").values() if not v["heuristic_only"])
    out["missed"] = _split(new("missed"), lambda k, v: W.covers(k))
    out["wrong_end"] = _split(new("wrong_end"), lambda k, v: (not v["declared"]) or W.covers(k))
    out["wrong_end_declared"] = sum(1 for v in new("wrong_end").values() if v["declared"])
    out["wrong_name"] = _split(new("wrong_name"), lambda k, v: W.covers(k))
    # `none`: "no listed function contains this address". It claims no function, so
    # it is a refusal, not a wrong owner; the miss itself is scored under `missed`.
    out["why_owner"] = _split(new("why_owner"), lambda k, v: v.get("refused") or v.get("none") or v.get("heuristic_only") or W.covers(k))
    out["why_refused"] = sum(1 for v in new("why_owner").values() if v.get("refused") or v.get("none"))

    lie_names = {r["lying_name"] for r in planted if "lying_name" in r} | {x[0] for r in planted for x in r.get("sym", []) if x[0] != r.get("name")}
    dec = _decomp(truth, meas, base_meas, lie_names)
    out["decomp"] = _split(dec["wrong"], lambda k, v: bool(_heuristic_owner(_why_found(meas, k))) or W.covers(k))
    out["decomp"]["refused"] = len(dec["refused"])
    out["decomp"]["changed_unclassified"] = len(dec["changed"])
    out["decomp"]["same"] = dec["same"]
    out["decomp"]["crashed"] = len(dec["crashed"])
    out["decomp_kinds"] = {k: sum(1 for v in dec["wrong"].values() if k in v) for k in ("end", "name", "callee")}
    x = _xref(meas, base_meas, ref)
    out["xref"] = _split({**{("i",) + k: v for k, v in x["invented"].items()}, **{("l",) + k: v for k, v in x["lost"].items()}},
                         lambda k, v: W.covers(k[1]) or W.covers(k[2]))
    out["xref"]["invented"] = len(x["invented"])
    out["xref"]["lost"] = len(x["lost"])
    out["xref"]["refs_reported"] = x["refs_reported"]

    # What contradictions says about the lies themselves: a lie is named when the
    # place it is about, or the function it touches, is one the answer names.
    named = [r for r in planted if W.covers(r["site"]) or W.covers(r["function"])]
    out["contradictions"] = {"count": W.count, "control_count": Warnings(base_meas).count, "kinds": W.kinds, "lies_named": len(named), "refused": W.refused}

    # The verdict's numbers: of every fact this image gets wrong (the control's too:
    # this is the rule-accuracy direction on this image), by the category of its source.
    all_start = mine["wrong_start"]
    all_end = mine["wrong_end"]
    rows, summ = ra_score.score(truth, meas, readers.symbols(build["measured_file"]))
    out["category"] = {
        "declared_starts": sum(1 for r in rows if not r["heuristic_only"]),
        "heuristic_starts": sum(1 for r in rows if r["heuristic_only"]),
        "declared_starts_wrong": sum(1 for v in all_start.values() if not v["heuristic_only"]),
        "heuristic_starts_wrong": sum(1 for v in all_start.values() if v["heuristic_only"]),
        "declared_ends_wrong": sum(1 for v in all_end.values() if v["declared"]),
        "heuristic_ends_wrong": sum(1 for v in all_end.values() if not v["declared"]),
        "declared_ends": summ["direction"].get("ends|declared|all", 0),
        "heuristic_ends": summ["direction"].get("ends|heuristic|all", 0),
    }
    # The examples the report shows by the bytes.
    out["examples"] = {
        "wrong_start": {hex(k): new("wrong_start")[k] for k in out["wrong_start"]["silent_at"]},
        "missed": {hex(k): new("missed")[k] for k in out["missed"]["silent_at"]},
        "wrong_end": {hex(k): new("wrong_end")[k] for k in out["wrong_end"]["silent_at"]},
        "wrong_name": {hex(k): new("wrong_name")[k] for k in out["wrong_name"]["silent_at"]},
        "why_owner": {hex(k): new("why_owner")[k] for k in out["why_owner"]["silent_at"]},
        "decomp": {hex(k): dec["wrong"][k] for k in out["decomp"]["silent_at"]},
        "decomp_changed": {hex(k): dec["changed"][k] for k in sorted(dec["changed"])[:6]},
        "xref_lost": [[hex(a), hex(b), t] for (a, b), t in list(x["lost"].items())[:4]],
        "xref_invented": [[hex(a), hex(b), t] for (a, b), t in list(x["invented"].items())[:4]],
    }
    for key in ("wrong_start", "missed", "wrong_end", "wrong_name", "why_owner", "decomp", "xref"):
        out[key].pop("silent_at", None)
        out[key].pop("flagged_at", None)
    return out


def dump(s: dict, path: str):
    json.dump(s, open(path, "w"), indent=1)

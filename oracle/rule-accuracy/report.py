#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Sum every `<v>.summary.json` under RESULTS into the tables: per variant x
arch x compiler x -O level, per start source, per end source, per name layer,
and the direction's test. Writes RESULTS/report.md and RESULTS/totals.json.

Usage: report.py
"""

from __future__ import annotations

import glob
import json
import os
import sys
from collections import Counter, defaultdict

import corpus

WRONG = ("interior", "outside")
SOURCES = ["unwind:eh_frame", "unwind:pdata", "export", "symbol", "pdb", "body", "stub", "after_declared_end", "gap_sweep", "call_target", "prologue"]


def pct(a: int, b: int) -> str:
    return "-" if b == 0 else f"{100.0 * a / b:.1f}%"


def load() -> list:
    out = []
    for p in sorted(glob.glob(os.path.join(corpus.RESULTS, "*", "*", "*", "?.summary.json"))):
        s = json.load(open(p))
        if "config" in s:
            out.append(s)
    return out


def add(into: dict, s: dict):
    c = s.get("classes", {})
    into["runs"] += 1
    into["listed"] += s.get("listed", 0)
    for k in ("true", "fragment", "plt0", "interior", "outside"):
        into[k] += c.get(k, 0)
    for tier, v in s.get("per_tier", {}).items():
        into[f"{tier}_truth"] += v.get("truth", 0)
        into[f"{tier}_found"] += v.get("found", 0)
        for k, n in v.items():
            if k.startswith("missed_named_in_"):
                into[f"{tier}_{k}"] += n
    for src, v in s.get("per_source", {}).items():
        for k, n in v.items():
            into[f"src|{src}|{k}"] += n
    for tier, v in s.get("found_by", {}).items():
        for k, n in v.items():
            into[f"foundby|{tier}|{k}"] += n
    for e, v in s.get("per_end", {}).items():
        for k, n in v.items():
            into[f"end|{e}|{k}"] += n
    for nl, v in s.get("per_name", {}).items():
        for k, n in v.items():
            into[f"name|{nl}|{k}"] += n
    for k, n in s.get("direction", {}).items():
        into[f"dir|{k}"] += n
    for k, n in s.get("checks", {}).items():
        into[f"check|{k}"] += n
    into["fdes"] += s.get("fdes_in_measured", 0)


def group(summaries: list, keyf) -> dict:
    g = defaultdict(Counter)
    for s in summaries:
        add(g[keyf(s["config"])], s)
    return g


def starts_table(g: dict, title: str, keyname: str) -> list:
    out = [f"### {title}", "", f"| {keyname} | runs | listed | true | wrong (interior / outside) | fragment | plt0 | precision | DWARF fns found | CRT fns found | PLT entries found |", "|---|---|---|---|---|---|---|---|---|---|---|"]
    for k in sorted(g):
        c = g[k]
        wrong = c["interior"] + c["outside"]
        out.append(
            f"| {k} | {c['runs']} | {c['listed']} | {c['true']} | {wrong} ({c['interior']} / {c['outside']}) | {c['fragment']} | {c['plt0']} | "
            f"{pct(c['true'], c['true'] + wrong)} | {c['dwarf_found']} / {c['dwarf_truth']} | {c['symtab_found']} / {c['symtab_truth']} | {c['plt_found']} / {c['plt_truth']} |"
        )
    return out + [""]


def sources_table(g: dict, title: str, keyname: str) -> list:
    out = [f"### {title}", "", "Precision = true / (true + wrong); a fragment or a PLT header is neither. `alone`: the starts this source alone produced.", ""]
    out.append(f"| {keyname} | source | produced | true | wrong | fragment | plt0 | precision | alone produced | alone true | alone wrong |")
    out.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for k in sorted(g):
        c = g[k]
        for src in SOURCES:
            p = c[f"src|{src}|produced"]
            if not p:
                continue
            t = c[f"src|{src}|true"]
            w = c[f"src|{src}|interior"] + c[f"src|{src}|outside"]
            fr, p0 = c[f"src|{src}|fragment"], c[f"src|{src}|plt0"]
            a = c[f"src|{src}|alone"]
            at = c[f"src|{src}|alone_true"]
            aw = c[f"src|{src}|alone_interior"] + c[f"src|{src}|alone_outside"]
            out.append(f"| {k} | {src} | {p} | {t} | {w} | {fr} | {p0} | {pct(t, t + w)} | {a} | {at} | {aw} |")
    return out + [""]


def ends_table(g: dict, title: str, keyname: str) -> list:
    out = [f"### {title}", "", f"| {keyname} | start class / end source | exact | short | long | between | no end | no truth end |", "|---|---|---|---|---|---|---|---|"]
    for k in sorted(g):
        c = g[k]
        kinds = sorted({key.split("|")[1] + "|" + key.split("|")[2] for key in c if key.startswith("end|")})
        for kind in kinds:
            v = {x: c[f"end|{kind}|{x}"] for x in ("exact", "short", "long", "between", "no_end", "no_truth")}
            cls, src = kind.split("|", 1)  # a `|` inside a cell would split the table
            out.append(f"| {k} | {cls}: {src} | {v['exact']} | {v['short']} | {v['long']} | {v['between']} | {v['no_end']} | {v['no_truth']} |")
    return out + [""]


def names_table(g: dict, title: str, keyname: str) -> list:
    cols = ("exact", "spelled", "wrong", "named_where_unnamed", "fallback_where_named", "fallback_unnamed")
    out = [f"### {title}", "", f"| {keyname} | layer | " + " | ".join(cols) + " |", "|---|---|" + "---|" * len(cols)]
    for k in sorted(g):
        c = g[k]
        layers = sorted({key.split("|")[1] for key in c if key.startswith("name|")})
        for layer in layers:
            out.append(f"| {k} | {layer} | " + " | ".join(str(c[f"name|{layer}|{x}"]) for x in cols) + " |")
    return out + [""]


def direction_rows(c: Counter) -> dict:
    d = {}
    for kind in ("heuristic_only", "any_declared"):
        allc = c[f"dir|starts|{kind}|all"]
        wrong = c[f"dir|starts|{kind}|interior"] + c[f"dir|starts|{kind}|outside"]
        d[kind] = {"all": allc, "true": c[f"dir|starts|{kind}|true"], "wrong": wrong, "fragment": c[f"dir|starts|{kind}|fragment"], "plt0": c[f"dir|starts|{kind}|plt0"]}
    for kind in ("declared", "heuristic"):
        d[f"end_{kind}"] = {"all": c[f"dir|ends|{kind}|all"], "right": c[f"dir|ends|{kind}|right"], "wrong": c[f"dir|ends|{kind}|wrong"]}
    for kind in ("heuristic_only", "any_declared"):
        d[f"end_by_start_{kind}"] = {"right": c[f"dir|ends_by_start|{kind}|right"], "wrong": c[f"dir|ends_by_start|{kind}|wrong"]}
    return d


def direction_table(g: dict, title: str, keyname: str) -> list:
    out = [f"### {title}", "",
           f"| {keyname} | wrong starts: heuristic only | wrong starts: any declared | heuristic-only starts wrong | declared starts wrong | wrong ends: heuristic (`not_stated`) | wrong ends: declared | heuristic ends wrong | declared ends wrong |",
           "|---|---|---|---|---|---|---|---|---|"]
    for k in sorted(g):
        d = direction_rows(g[k])
        h, a = d["heuristic_only"], d["any_declared"]
        eh, ed = d["end_heuristic"], d["end_declared"]
        out.append(
            f"| {k} | {h['wrong']} | {a['wrong']} | {h['wrong']} / {h['all']} ({pct(h['wrong'], h['all'])}) | {a['wrong']} / {a['all']} ({pct(a['wrong'], a['all'])}) | "
            f"{eh['wrong']} | {ed['wrong']} | {eh['wrong']} / {eh['all']} ({pct(eh['wrong'], eh['all'])}) | {ed['wrong']} / {ed['all']} ({pct(ed['wrong'], ed['all'])}) |"
        )
    return out + [""]


def vkey(c: dict) -> str:
    """The variant as the ledger groups it: (c) apart for C and C++, since the
    flags of (c) leave C++'s FDEs in place (corpus.py, variant d)."""
    lang = corpus.PROGRAMS[c["program"]].lang
    if c["variant"] == "c":
        return "c (C)" if lang == "c" else "c (C++)"
    return c["variant"]


def doc_tables(ss: list) -> list:
    """The tables docs/VERIFICATION.md carries, generated so no number in it
    is copied by hand."""
    out = []
    # Corpus.
    corpus_rows = defaultdict(Counter)
    for s in ss:
        c = s["config"]
        if c["variant"] != "a":
            continue
        k = (c["arch"], c["program"])
        corpus_rows[k]["configs"] += 1
        for tier, v in s["per_tier"].items():
            corpus_rows[k][tier] += v.get("truth", 0)
    out += ["#### Corpus (truth functions summed over the compiler x level builds of each)", "",
            "| arch | program | builds | DWARF functions | CRT functions | PLT entries |", "|---|---|---|---|---|---|"]
    tot = Counter()
    for (arch, prog), c in sorted(corpus_rows.items()):
        out.append(f"| {arch} | {prog} | {c['configs']} | {c['dwarf']} | {c['symtab']} | {c['plt']} |")
        tot.update(c)
    out += [f"| all | | {tot['configs']} | {tot['dwarf']} | {tot['symtab']} | {tot['plt']} |", ""]
    g = group(ss, vkey)
    out += starts_table(g, "Starts, per variant", "variant")
    out += sources_table({k: v for k, v in g.items() if k != "b"}, "Start sources, per variant ((b) is (a): stripping changes no start)", "variant")
    # Per variant x compiler x level, one row each, a cell per source.
    gv = group(ss, lambda c: (vkey(c), c["compiler"], c["opt"]))
    srcs = ["unwind:eh_frame", "after_declared_end", "gap_sweep", "call_target", "prologue"]
    out += ["### Per variant x compiler x level: true / produced per start source", "",
            "| variant | cc | -O | " + " | ".join(srcs) + " | wrong starts | DWARF functions found |", "|---|---|---|" + "---|" * (len(srcs) + 2)]
    for k in sorted(gv, key=lambda k: (k[0], k[1], k[2])):
        if k[0] == "b":
            continue
        c = gv[k]
        cells = [f"{c[f'src|{s}|true']} / {c[f'src|{s}|produced']}" if c[f"src|{s}|produced"] else "-" for s in srcs]
        out.append(f"| {k[0]} | {k[1]} | {k[2]} | " + " | ".join(cells) + f" | {c['interior'] + c['outside']} | {c['dwarf_found']} / {c['dwarf_truth']} |")
    out.append("")
    ga = group(ss, lambda c: f"{vkey(c)} {c['arch']}")
    out += starts_table({k: v for k, v in ga.items() if not k.startswith("b ")}, "Starts, per variant x arch", "variant arch")
    out += ends_table({k: v for k, v in g.items()}, "Ends, per variant", "variant")
    out += names_table({k: v for k, v in g.items()}, "Names, per variant", "variant")
    out += direction_table(g, "The direction, per variant (strict: a wrong start is interior or outside)", "variant")
    out += direction_table({k: v for k, v in ga.items() if not k.startswith("b ")}, "The direction, per variant x arch", "variant arch")
    # The broad reading: fragments and PLT headers counted wrong too.
    out += ["### The direction, broad reading (a `.cold` fragment and a PLT header counted as wrong starts too)", "",
            "| variant | heuristic-only starts wrong | declared starts wrong |", "|---|---|---|"]
    for k in sorted(g):
        d = direction_rows(g[k])
        h, a = d["heuristic_only"], d["any_declared"]
        hw = h["wrong"] + h["fragment"] + h["plt0"]
        aw = a["wrong"] + a["fragment"] + a["plt0"]
        out.append(f"| {k} | {hw} / {h['all']} ({pct(hw, h['all'])}) | {aw} / {a['all']} ({pct(aw, a['all'])}) |")
    out.append("")
    out += ["### Missed truth functions", "", "| variant | DWARF missed | of them in the measured file's `.dynsym` | CRT missed | PLT entries missed |", "|---|---|---|---|---|"]
    for k in sorted(g):
        c = g[k]
        out.append(f"| {k} | {c['dwarf_truth'] - c['dwarf_found']} | {c['dwarf_missed_named_in_.dynsym']} | {c['symtab_truth'] - c['symtab_found']} | {c['plt_truth'] - c['plt_found']} |")
    out.append("")
    return out


def main() -> int:
    ss = load()
    if not ss:
        print("report: no summaries", file=sys.stderr)
        return 1
    engines = Counter((s["engine"]["sha256"], s["engine"]["version"]) for s in ss)
    lines = ["# Rule accuracy: raw report", "", f"Summaries: {len(ss)}. Engine(s): {dict((f'{k[0]} ({k[1]})', v) for k, v in engines.items())}", ""]
    by_v = group(ss, lambda c: c["variant"])
    by_vacco = group(ss, lambda c: f"{c['variant']} {c['arch']} {c['compiler']} -{c['opt']}")
    by_vco = group(ss, lambda c: f"{c['variant']} {c['compiler']} -{c['opt']}")
    by_va = group(ss, lambda c: f"{c['variant']} {c['arch']}")
    by_vp = group(ss, lambda c: f"{c['variant']} {c['program']}")
    lines += starts_table(by_v, "Starts, per variant", "variant")
    lines += starts_table(by_vacco, "Starts, per variant x arch x compiler x level", "variant arch cc opt")
    lines += starts_table(by_vp, "Starts, per variant x program", "variant program")
    lines += sources_table(by_v, "Start sources, per variant", "variant")
    lines += sources_table(by_vco, "Start sources, per variant x compiler x level", "variant cc opt")
    lines += sources_table(by_va, "Start sources, per variant x arch", "variant arch")
    lines += ends_table(by_v, "Ends, per variant", "variant")
    lines += ends_table(by_vco, "Ends, per variant x compiler x level", "variant cc opt")
    lines += names_table(by_v, "Names, per variant", "variant")
    lines += direction_table(by_v, "The direction, per variant", "variant")
    lines += direction_table(by_vco, "The direction, per variant x compiler x level", "variant cc opt")
    lines += direction_table(by_va, "The direction, per variant x arch", "variant arch")
    # Found-by and missed-but-named, per variant.
    lines += ["### Truth functions found, by source (a function found by several counts under each)", "", "| variant | tier | source | found by it | found by it alone |", "|---|---|---|---|---|"]
    for v in sorted(by_v):
        c = by_v[v]
        for tier in ("dwarf", "symtab", "plt"):
            for src in SOURCES:
                n = c[f"foundby|{tier}|{src}"]
                if n:
                    lines.append(f"| {v} | {tier} | {src} | {n} | {c[f'foundby|{tier}|only:{src}']} |")
    lines += ["", "### Missed truth functions, by whether the measured file names them", "", "| variant | tier | missed | of them named in the measured file's tables |", "|---|---|---|---|"]
    for v in sorted(by_v):
        c = by_v[v]
        for tier in ("dwarf", "symtab", "plt"):
            missed = c[f"{tier}_truth"] - c[f"{tier}_found"]
            named = {k.split("missed_named_in_")[1]: n for k, n in c.items() if k.startswith(f"{tier}_missed_named_in_") and not k.endswith("_none")}
            lines.append(f"| {v} | {tier} | {missed} | {named or 0} |")
    lines += ["", "### Contract checks (`why` against `function discover`; rung 5, they flag inconsistency, not truth)", ""]
    checks = {k[6:]: n for k, n in by_v.get("a", Counter()).items() if k.startswith("check|")}
    for v in sorted(by_v):
        checks = {k[6:]: n for k, n in by_v[v].items() if k.startswith("check|")}
        lines.append(f"- variant {v}: {checks or 'none'}")
    lines.append("")
    lines += ["### FDEs in the measured files, per variant", ""]
    for v in sorted(by_v):
        lines.append(f"- {v}: {by_v[v]['fdes']} `.eh_frame` FDEs over {by_v[v]['runs']} files")
    open(os.path.join(corpus.RESULTS, "report.md"), "w").write("\n".join(lines) + "\n")
    open(os.path.join(corpus.RESULTS, "doc-tables.md"), "w").write("\n".join(doc_tables(ss)) + "\n")
    totals = {"engines": [list(k) + [n] for k, n in engines.items()], "by_variant": {k: dict(v) for k, v in by_v.items()}, "direction": {k: direction_rows(v) for k, v in by_v.items()}}
    json.dump(totals, open(os.path.join(corpus.RESULTS, "totals.json"), "w"), indent=1)
    print(f"report: {len(ss)} summaries -> {os.path.join(corpus.RESULTS, 'report.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

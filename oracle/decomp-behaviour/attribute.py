#!/usr/bin/env python3
"""Each failing body on the behaviour corpus: which shapes it holds. Text detectors, first match named; every class read by hand first. Usage: attribute.py <run-dir>"""
import collections, json, os, re, subprocess, sys

run = sys.argv[1]
res = json.load(open(run + "/results.json"))
cache = {}


def body(lib, fn):
    if lib not in cache:
        syms = {}
        for l in subprocess.run(["readelf", "-Ws", "--dyn-syms", f"{run}/lib/{lib}.g.so"], capture_output=True, text=True, env=dict(os.environ, LC_ALL="C")).stdout.splitlines():
            f = l.split()
            if len(f) >= 8 and f[3] == "FUNC":
                syms[f[7].split("@")[0]] = int(f[1], 16)
        rows = [json.loads(l) for l in open(f"{run}/bodies/{lib}.jsonl")]
        cache[lib] = (syms, {int(r["entry"], 16): r for r in rows})
    syms, byaddr = cache[lib]
    return byaddr[syms[fn]].get("c", "")


def classify(r):
    c = body(r["lib"], r["fn"])
    code = re.sub(r"//[^\n]*", "", c)
    out = []
    ls = code.split("\n")
    for i, l in enumerate(ls):
        m = re.match(r"\s*while\s*\((.*)\)\s*\{\s*$", l)
        if m and m[1].strip() != "1":
            names = set(re.findall(r"(?<![\w.])([a-z][a-z0-9]*\.\d+|v\d+)\b", m[1]))
            before = "\n".join(ls[:i])
            if any(not re.search(rf"(?<![\w.]){re.escape(n)}\s*=[^=]", before) and not n.endswith(".0") for n in names):
                out.append("while_unset")
                break
    if re.search(r"switch\s*\(\s*(r[a-z0-9]+)\s*\)", code) and re.search(r"\b(r[a-z0-9]+)\.\d+\s*=", code):
        out.append("stale_switch")
    if re.search(r"\(u?int32_t\)[^;\n]*\*[^;\n]*>>\s*0x[2-9a-f][0-9a-f]", code):
        out.append("narrow_mul")
    if r["fn"] in ("emu_sar",):
        out.append("sar_as_shift")
    if re.search(r"\*\s*[a-z]\w*\.?\d*\s*=|->field_\w+\s*=", code) or re.search(r"(?<![\w)])\*[a-z]", code) or "->field_" in code:
        out.append("no_width")
    assigned = set(re.findall(r"^\s*([a-z][\w.]*)\s*=[^=]", code, re.M))
    names = set(re.findall(r"(?<![\w.])([a-z][a-z0-9]*\.\d+|v\d+)\b", code))
    if {n for n in names if n not in assigned and not n.endswith(".0") and not n.startswith(("rsp", "xmm"))}:
        out.append("unset_name")
    if re.search(r"\b(?:rcx|rdx|rsi|rdi|r8|r9|rax)\.0\b", code):
        out.append("entry_reg")
    if "rsp." in code:
        out.append("rsp_arith")
    if "(*" in code:
        out.append("indirect")
    if re.search(r"=\s*/\*|\(\s*/\*", c):
        out.append("hole")
    if re.search(r"__p|__fcmpmask|__add[ps]|__mul[ps]", code):
        out.append("simd")
    return out or ["other"]


cnt = collections.Counter()
lines = []
for r in res:
    if r["tool"] != "n0xis" or r["outcome"] in ("same", "same_ext", "no_answer"):
        continue
    k = classify(r)
    cnt[k[0]] += 1
    run_ = r.get("run") or {}
    lines.append((r["lib"].replace("heldout", "H").replace("gcc", "g").replace("clang", "c"), r["fn"].replace("emu_", ""), r["outcome"][:9], ",".join(k)[:42], ("r:" + str(r["rescued_by"][0][4:6]) + str(r["rescued_by"][1])) if r.get("rescued_by") else "", r.get("level1_why", "")[:24]))
print(cnt.most_common())
for l in lines:
    print(" ".join(l))

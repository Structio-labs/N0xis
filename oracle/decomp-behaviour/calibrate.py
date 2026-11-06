#!/usr/bin/env python3
"""Plant a mistake in bodies that scored same; the score must fall. Usage: calibrate.py <run-dir> ; writes <run-dir>/calibrate.json"""
import json, os, random, re, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import behave as b
run = sys.argv[1]
res = json.load(open(run + "/results.json"))
rng = random.Random(20261106)
out = {}


def mutate_const(t):
    head, sep, rest = t.partition("bh_stack[65536];")
    i = rest.find("{")
    end = rest.find("#undef")
    body = rest[i:end]
    ms = [m for m in re.finditer(r"(?<![\w.])(0x[0-9a-fA-F]+|[1-9]\d*)\b", body)]
    if not ms:
        return None
    m = ms[0]
    v = int(m[1], 0) + 1
    return head + sep + rest[:i] + body[:m.start()] + hex(v) + body[m.end():] + rest[end:]


def mutate_branch(t):
    if "if (" not in t:
        return None
    return t.replace("if (", "if (0 && ", 1)


def mutate_loop(t):
    for k in ("while (", "for ("):
        if k in t:
            return t.replace("while (", "while (0 && ", 1)
    return None


def one(r, name, fn):
    tu = r.get("tu") or None
    if not tu or not os.path.exists(tu):
        return None
    t = open(tu).read()
    m = fn(t)
    if m is None:
        return None
    wd = os.path.dirname(tu)
    p = f"{wd}/m_{name}.c"
    open(p, "w").write(m)
    so = f"{run}/lib/{r['lib']}.g.so"
    c = b.gcc([*b.CFLAGS, "-c", p, "-o", p + ".o"])
    if c.returncode:
        return "no_compile"
    return b.outcome(b.run_body(p, so, wd, "m"))


b.CFLAGS.extend(["-I", os.path.abspath(run)])
same = [r for r in res if r["tool"] == "n0xis" and r["outcome"] in ("same", "same_ext") and r.get("tu")]
rng.shuffle(same)
for name, fn in (("const", mutate_const), ("branch", mutate_branch), ("loop", mutate_loop)):
    got = {"tried": 0, "fell": 0, "stayed": []}
    for r in same:
        if got["tried"] >= 30:
            break
        o = one(r, name, fn)
        if o is None:
            continue
        got["tried"] += 1
        if o in ("same", "same_ext"):
            got["stayed"].append(r["lib"] + ":" + r["fn"])
        else:
            got["fell"] += 1
    out[name] = got
    print(name, got["tried"], got["fell"], got["stayed"][:5])
json.dump(out, open(run + "/calibrate.json", "w"), indent=1)

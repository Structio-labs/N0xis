#!/usr/bin/env python3
"""The width and extension a body prints for a memory access, against objdump's for the same instruction.

Usage: check_widths.py ENGINE [--mutate] LABEL=IMAGE=ADDRS...
For each function, `decomp pseudo --style goto`, which keeps one statement per instruction in address order, and objdump of the
same bytes. A block counts when it prints as many sized accesses as it holds memory instructions that print one (a `cmp` or `test`
reads memory into the flags and prints nothing here); each pair is compared in order. Says how many it skipped, and how many printed
an access with no width at all. `--mutate` turns every printed uint8_t into uint32_t: a check that then finds nothing has checked nothing.
"""
import json, os, random, re, resource, sys, tempfile
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bodylib as bl

ACCESS = re.compile(r"\*\((u?int(?:8|16|32|64)_t|__m128)\*\)|\(\((u?int(?:8|16|32|64)_t)\*\)")
BARE = re.compile(r"(?<![\w)\]])\*[a-z][\w.]*|\w->field_")
BLOCK = re.compile(r"^block_\d+:\s*// (0x[0-9a-f]+)")
REG8 = re.compile(r"^%(?:[a-d]l|[a-d]h|sil|dil|bpl|spl|r\d+b)$")
REG16 = re.compile(r"^%(?:ax|bx|cx|dx|si|di|bp|sp|r\d+w)$")
REG32 = re.compile(r"^%(?:e[a-ds][xpi]|e[sd]i|ebp|esp|r\d+d)$")
SUFFIX = {"b": 8, "w": 16, "l": 32, "q": 64}
SKIP = re.compile(r"^(?:lea|nop|cmp|test|push|pop|call|jmp|ret|j[a-z]+|set|cmov|bt|ucomis|comis|prefetch|endbr|xchg|cmpxchg|lock|rep|vm|sfence|lfence|mfence)")


def reg_bits(op):
    if REG8.match(op):
        return 8
    if REG16.match(op):
        return 16
    if REG32.match(op):
        return 32
    if op.startswith("%r") or op.startswith("%rip"):
        return 64
    return None


def bytes_width(mn, ops):
    """(bits, signed or None) of an integer memory access by objdump's AT&T text; None when this is not one."""
    if "(" not in ops or SKIP.match(mn) or "%xmm" in ops or "%ymm" in ops or "%st" in ops or "%fs:" in ops or "%gs:" in ops:
        return None
    m = re.fullmatch(r"mov([sz])([bwl])([wlq])", mn)
    if m:
        return SUFFIX[m[2]], m[1] == "s"
    if mn == "movabs":
        return None
    # objdump adds `# <target>` after a rip-relative operand.
    parts = re.split(r",(?![^(]*\))", ops.split("#")[0].strip())
    if not mn.startswith("mov"):
        return None
    if mn == "mov":
        for p in parts:
            b = reg_bits(p.strip())
            if b:
                return b, False
        return None
    if mn[3:] in SUFFIX:
        return SUFFIX[mn[3:]], False
    return None


def spelled(ty):
    return (int(re.search(r"\d+", ty)[0]), not ty.startswith("u"))


def ask(engine, image, cwd, a):
    lim = lambda: resource.setrlimit(resource.RLIMIT_AS, (4194304 * 1024, 4194304 * 1024))
    p = subprocess.run(["nice", "-n", "19", engine, "decomp", "pseudo", "--style", "goto", "--file", image, "--addr", "0x" + a, "--quiet"], cwd=cwd, capture_output=True, preexec_fn=lim, timeout=120, env=bl.ENV)
    try:
        d = json.loads(p.stdout)
    except ValueError:
        return None
    return d["data"] if d.get("ok") else None


def blocks_of(lines):
    out, cur = [], None
    for l in lines:
        m = BLOCK.match(l)
        if m:
            cur = [int(m[1], 16), []]
            out.append(cur)
        elif cur is not None:
            cur[1].append(l)
    return out


def measure(engine, label, image, addrs, mutate, pairs, cwd):
    im = bl.Image(image)
    res = {"functions": 0, "blocks": 0, "accesses": 0, "blocks_skipped": 0, "bare_lines": 0, "wrong": 0, "wrong_sign": 0}
    wrong = []
    for a in [l.strip() for l in open(addrs) if l.strip()]:
        d = ask(engine, image, cwd, a)
        if not d:
            continue
        res["functions"] += 1
        blocks = blocks_of(d["pseudo"])
        end = int(str(d["end_address"]), 0)
        for i, (start, lines) in enumerate(blocks):
            stop = blocks[i + 1][0] if i + 1 < len(blocks) else end
            real = []
            for va, t in im.in_range(start, stop):
                w = bytes_width(*im.parse(t))
                if w:
                    real.append((va, t, w))
            text = "\n".join(lines)
            if mutate:
                text = text.replace("uint8_t*", "uint32_t*")
            # A comment or a string is not an access.
            bare = bl.strip_strings(bl.strip_comments(text))
            res["bare_lines"] += sum(1 for l in bare.split("\n") if BARE.search(re.sub(r"\(\*+[\w.]+(?:->field_\w+)?\)\(|&[\w.]+->field_\w+", "", l)))
            printed = [m[1] or m[2] for m in ACCESS.finditer(bare)]
            printed = [p for p in printed if p != "__m128"]
            if not real and not printed:
                continue
            if len(real) != len(printed):
                res["blocks_skipped"] += 1
                continue
            res["blocks"] += 1
            for (va, t, (bits, signed)), ty in zip(real, printed):
                res["accesses"] += 1
                got_bits, got_signed = spelled(ty)
                pairs.append((label, va, t, ty, got_bits == bits and (got_signed == signed or not re.match(r"movs", im.parse(t)[0]))))
                if got_bits != bits:
                    res["wrong"] += 1
                    wrong.append((hex(va), t, ty))
                elif re.match(r"mov[sz][bwl]", im.parse(t)[0]) and got_signed != signed:
                    res["wrong_sign"] += 1
                    wrong.append((hex(va), t, ty))
    return res, wrong


def main():
    argv = sys.argv[1:]
    mutate = "--mutate" in argv
    if mutate:
        argv.remove("--mutate")
    engine = os.path.abspath(argv[0])
    pairs = []
    with tempfile.TemporaryDirectory() as cwd:
        os.makedirs(cwd + "/.n0x")
        for spec in argv[1:]:
            label, image, addrs = spec.split("=")
            res, wrong = measure(engine, label, os.path.abspath(image), addrs, mutate, pairs, cwd)
            print(label, res, "first wrong:", wrong[:3])
    rng = random.Random(20261106)
    print("twenty, by seed: image, address, objdump, printed, agree")
    for p in rng.sample(pairs, min(20, len(pairs))):
        print(" ", p[0], hex(p[1]), p[2][:44], p[3], p[4])
    print("compared", len(pairs), "disagree", sum(1 for p in pairs if not p[4]))


main()

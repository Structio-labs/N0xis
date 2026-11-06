#!/usr/bin/env python3
"""Mechanical counts of shapes seen when bodies were opened: how often each class occurs per image. Text only; each class was first opened against the bytes.

Usage: lint_bodies.py RAW.jsonl...  (files written by bodies.py); prints a table, one column per file; `--json OUT` writes the counts.
"""
import collections, json, re, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bodylib as bl

def count(c, ARGS, SAVED):
    out = collections.Counter()
    ex = {}
    sig = c.split("\n", 1)[0]
    body = bl.strip_comments(bl.strip_strings(c.split("\n", 1)[1] if "\n" in c else ""))
    raw_body = c.split("\n", 1)[1] if "\n" in c else ""
    # A parameter the body reads but the signature leaves out.
    if any(re.search(rf"\b{r}\.0\b", body) and not re.search(rf"\b{r}\b", sig) for r in ARGS):
        out["sig_omits_read_param"] = 1
    # Callee-saved registers' entry values: a push shown as an assignment.
    saves = re.findall(rf"^\s*local_\w+\s*=\s*(?:{SAVED})\.0\s*;", body, re.M)
    out["save_lines"] = len(saves)
    if saves:
        out["fn_with_saves"] = 1
    # Several writes of entry values / pushes to one slot name: slots not told apart.
    slots = collections.Counter(re.findall(rf"^\s*(local_\w+)\s*=\s*(?:{SAVED})\.0\s*;", body, re.M))
    if any(v > 1 for v in slots.values()):
        out["fn_slot_merged"] = 1
    # Names read and never assigned, not parameters, not entry values: a value with no definition.
    params = set(re.findall(r"\b(rdi|rsi|rdx|rcx|r8|r9|xmm\d+)\b", sig))
    names = set(re.findall(r"(?<![\w.])([a-z][a-z0-9]*\.\d+|v\d+|local_\w+)\b", body))
    assigned = set(re.findall(r"^\s*([a-z][\w.]*)\s*=[^=]", body, re.M)) | set(re.findall(r"(?:\*|&)?\b(local_\w+)\b\s*=[^=]", body))
    declared = set(re.findall(r"^\s*[A-Za-z_][\w ]*\*?\s+\*?([\w.]+)(?:\[\w*\])?\s*;", body, re.M))
    unset = {n for n in names if n not in assigned and n not in declared and not n.endswith(".0") and not n.startswith("rsp") and not n.startswith("xmm")}
    if unset:
        out["fn_unset_value"] = 1
        out["unset_names"] = len(unset)
    # Entry value of a caller-saved register that is not a parameter, shown as a call argument.
    if re.search(r"\b(?:rax|r10|r11)\.0\b|" + "|".join(rf"\b{r}\.0\b" for r in ARGS if not re.search(rf"\b{r}\b", sig)), body):
        out["fn_reads_entry_reg"] = 1
    # Rendered `while` reading a name set only inside the loop.
    lines = body.split("\n")
    for i, l in enumerate(lines):
        m = re.match(r"\s*while\s*\((.*)\)\s*\{\s*$", l)
        if not m or m[1].strip() == "1":
            continue
        cond_names = set(re.findall(r"(?<![\w.])([a-z][a-z0-9]*\.\d+|v\d+)\b", m[1]))
        before = "\n".join(lines[:i])
        if any(not re.search(rf"(?<![\w.]){re.escape(n)}\s*=[^=]", before) and not n.endswith(".0") for n in cond_names):
            out["while_reads_unset"] += 1
            out["fn_while_unset"] = 1
    # Memory accesses that state no width.
    # `*(T*)&x->field_0x8` is the field with its width stated; `&x->field_0x8` reads nothing; `(*x->field_0x8)(...)` and `(**x)(...)` read a
    # pointer through which a call goes, as wide as a pointer whatever is printed.
    typed = len(re.findall(r"\*\s*\(\s*[\w ]+\*\s*\)", body))
    call_slots = re.findall(r"\(\*+[\w.]+(?:->field_\w+)?\)\(", body)
    out["call_slot"] = len(call_slots)
    addr_of = re.findall(r"&[\w.]+->field_", re.sub(r"\*\s*\(\s*[\w ]+\*\s*\)\s*&", "", body))
    out["address_of_field"] = len(addr_of)
    plain = re.sub(r"\*\s*\(\s*[\w ]+\*\s*\)\s*&[\w.]+->field_\w+", "stated", body)
    plain = re.sub(r"&[\w.]+->field_\w+", "stated", plain)
    plain = re.sub(r"\(\*+[\w.]+(?:->field_\w+)?\)\(", "(", plain)
    field = len(re.findall(r"\w->field_", plain))
    star = 0
    for m in re.finditer(r"\*\s*([A-Za-z_][\w.]*)", plain):
        before = plain[:m.start()].rstrip()
        if before and (before[-1].isalnum() or before[-1] in "_)]") and not re.search(r"\([\w ]*(?:_t|void|int|long|char)\s*\*?\s*\)$", before):
            continue
        star += 1
    out["access_typed"] = typed
    out["access_untyped"] = field + star
    if field + star:
        out["fn_untyped_access"] = 1
    # A switch on a register that has a later version already.
    for m in re.finditer(r"switch\s*\(\s*([a-z][a-z0-9]*)\s*\)", body):
        if re.search(rf"\b{m[1]}\.\d+\s*=", body[:m.start()]):
            out["switch_stale"] = 1
    # A statement the tool could not lift, printed as a comment in place of an expression.
    holes = re.findall(r"=\s*/\*[^*]*\*/\s*;", raw_body)
    conds = re.findall(r"\(\s*[~!]?\s*/\*\s*(?:cond\(|\?)[^*]*\*/", raw_body)
    if holes:
        out["fn_unlifted_insn"] = 1
    out["unlifted_insn"] = len(holes)
    if conds:
        out["fn_cond_lost"] = 1
    out["cond_lost"] = len(conds)
    out["if_total"] = len(re.findall(r"\bif\s*\(", raw_body))
    if re.search(r"\b(?:operator [\w ]+|[\w:]+::[\w~]+)(?:<[^()]*>)?\([^()]*\)\(", raw_body):
        out["fn_demangled_args"] = 1
    return out


# The rows of the table, in order: (printed name, counter, what it counts).
TABLE = [("answered", "answered"), ("a parameter read and absent from the signature", "sig_omits_read_param"), ("a name read that nothing assigns", "fn_unset_value"),
         ("a `while` reading a name set only inside it", "fn_while_unset"), ("`switch` on a register with a later version", "switch_stale"),
         ("a branch condition printed as a comment", "fn_cond_lost"), ("  such conditions", "cond_lost"), ("  all ifs", "if_total"),
         ("an instruction printed as a comment for a value", "fn_unlifted_insn"), ("memory access that states no width", "fn_untyped_access"),
         ("  untyped accesses", "access_untyped"), ("  typed accesses", "access_typed"), ("  calls through a slot (not counted)", "call_slot"), ("  & of a field (not counted)", "address_of_field"), ("register saves printed as assignments", "fn_with_saves"), ("several saves into one slot name", "fn_slot_merged"),
         ("`quality` 1.0", "quality_1"), ("a condition or a value left as a comment", "fn_hole"), ("  and `quality` 1.0", "hole_at_quality_1"), ("  a name read with no definition, and `quality` 1.0", "unset_at_quality_1")]


def abi(image):
    # The ABI's argument and callee-saved registers differ by image kind.
    if bl.is_pe(image):
        return ("rcx", "rdx", "r8", "r9"), "rbx|rbp|rdi|rsi|r12|r13|r14|r15"
    return ("rdi", "rsi", "rdx", "rcx", "r8", "r9"), "rbx|rbp|r12|r13|r14|r15"


def lint(path):
    meta, bodies = bl.rows(path)
    args, saved = abi(meta["image"])
    res = collections.Counter()
    examples = {}
    for r in bodies:
        res["answered"] += 1
        c = count(r["c"], args, saved)
        res.update(c)
        # What the body itself shows against what `quality` says of it. A hole is a condition or a value left as a comment.
        hole = c["cond_lost"] or c["unlifted_insn"] or "/*index in " in r["c"]
        if hole:
            res["fn_hole"] += 1
        if c["fn_unset_value"]:
            res["fn_unset"] += 1
        if r.get("quality") == 1.0:
            res["quality_1"] += 1
            if hole:
                res["hole_at_quality_1"] += 1
            if c["fn_unset_value"]:
                res["unset_at_quality_1"] += 1
        for k in c:
            if c[k] and k.startswith(("fn_", "sig_", "switch")):
                examples.setdefault(k, r["entry"])
    return res, examples


def table(columns):
    """columns: {label: Counter}. Prints one line per row of TABLE."""
    labels = list(columns)
    print(f"{'':52}" + "".join(f"{l[:12]:>13}" for l in labels))
    for name, key in TABLE:
        print(f"{name:52}" + "".join(f"{columns[l][key]:>13}" for l in labels))


if __name__ == "__main__":
    argv = sys.argv[1:]
    out = None
    if "--json" in argv:
        i = argv.index("--json")
        out = argv[i + 1]
        del argv[i:i + 2]
    res = {}
    for p in argv:
        res[Path(p).name.replace(".jsonl", "")] = lint(p)
    table({k: v[0] for k, v in res.items()})
    if out:
        json.dump({k: {"counts": v[0], "examples": v[1]} for k, v in res.items()}, open(out, "w"), indent=1)

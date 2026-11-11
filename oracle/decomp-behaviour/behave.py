#!/usr/bin/env python3
"""Behaviour: each body the engine prints, compiled with one prelude, run against the original on generated inputs.

Usage: behave.py ENGINE OUTDIR
Builds the libraries, asks ENGINE for every function of each (`function discover`, then one `decomp pseudo` per start,
each under `ulimit -v 4194304` in a project of its own), and prints the counts per set. Everything goes under OUTDIR:
results.json, functions.tsv (one line per function per build, what `report.py` reads), lib/, bodies/, runs/.

Level 0: the body exactly as printed, prelude only (does it compile).
Level 1: the same text through one mechanical layer, each rule counted per body:
  ssa      x.N -> x_N (no C identifier holds a dot)
  undecl   an identifier used and never declared gets a declaration: 128-bit for xmmN, the entry value for rdi..r9
           and their .0, a scratch frame for rsp/rbp, else uint64_t = 0
  star     unary * on an integer: reads as *(uint64_t*)
  bits     double/float in a signature mean the register bits the intrinsics return
           and /*unknown*/ in one is a word
  neg_hex  -0xN is a negative number (in C a hex literal may be unsigned first)
  rel      a relational is signed unless marked /*u*/: spelled in C at the first operand's width, however deep it is
           nested; == and != against an operand cast narrow compare at that width too
  callee   a callee is bound by address in the image; imports by name
  untyped_ptr `void *x`/`struct_x_0 *x` with no printed definition: x is an integer; x->field_0xN reads 64 bits at x+N
  subscript x[i] on an integer: elements of the width of the cast in front, else 64 bits
  call_slot (*x)(...) on an integer: a call to the value x holds, as the engine prints it; (**x)(...) and
           (*x->field_0xN)(...): a call to what is read there; x_N(...) a call to the value
Nothing else touches a body. A wrong answer here is the body's; a would-not-compile is reported with the compiler's reason.
The layer is a generous reader, so "same" is an upper bound on what a reader of the printed body gets: see README.md.
"""
import concurrent.futures as cf, json, os, re, resource, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ORACLE = os.path.dirname(HERE)
BASE = 0x40000000
INPUTS = 500
CFLAGS = ["-std=gnu11", "-O0", "-w", "-fwrapv", "-fno-strict-aliasing", "-fpermissive", "-fno-builtin"]  # + -I OUTDIR, set by main
ENV = dict(os.environ, LC_ALL="C", LANG="C")
KEYWORDS = {"if", "while", "for", "switch", "return", "sizeof", "do", "else", "case", "default", "goto", "break", "continue"}
INTS = {"bool": (8, 0), "uint8_t": (8, 0), "int8_t": (8, 1), "char": (8, 1),
        "uint16_t": (16, 0), "int16_t": (16, 1), "short": (16, 1),
        "uint32_t": (32, 0), "int32_t": (32, 1), "int": (32, 1), "unsigned int": (32, 0), "float": (32, 0),
        "uint64_t": (64, 0), "size_t": (64, 0), "long": (64, 1), "int64_t": (64, 1), "double": (64, 0)}
HELD = {  # kinds, source return bits (0 void), returns a string
    "h_strlen": ("s", 64), "h_strchr": ("sn", 64), "h_strcmp": ("ss", 32), "h_memcmp": ("BBn", 32), "h_memrev": ("bn", 0), "h_crc32": ("bn", 32), "h_fnv1a": ("s", 32), "h_popcount": ("v", 32), "h_gcd": ("vv", 64),
    "h_isqrt": ("v", 32), "h_clamp": ("vvv", 32), "h_bsearch": ("Snn", 64), "h_isort": ("bn", 0), "h_bitrev": ("v", 32), "h_atol": ("s", 64), "h_hexval": ("v", 32), "h_utf8len": ("c", 32), "h_sum32": ("bn", 64), "h_max32": ("bn", 32),
    "h_struct": ("b", 64), "h_struct_set": ("bv", 0), "h_day": ("n", 32), "h_fall": ("vv", 32), "h_trace": ("bm", 64), "h_div10": ("v", 32), "h_mod7": ("v", 32), "h_udiv1000": ("v", 32), "h_rotl": ("vv", 32), "h_cmp3": ("vv", 32), "h_abs": ("v", 32),
    "h_satadd": ("vv", 32), "h_toupper": ("c", 8), "h_ispow2": ("v", 32), "h_bswap": ("v", 64), "h_count_eq": ("Bnc", 32), "h_fill16": ("bnc", 0), "h_collatz": ("v", 64), "h_call3": ("vv", 32), "h_call_loop": ("v", 32), "h_table": ("v", 32), "h_name": ("n", 64)}
SRC = {"emu": ORACLE + "/emu.c", "emu_fp": ORACLE + "/emu_fp.c", "emu_calls": ORACLE + "/emu_calls.c", "emu_switch": ORACLE + "/emu_switch.c", "emu_simd": ORACLE + "/emu_simd.c", "heldout": HERE + "/heldout.c"}
LIBS = [("emu", "gcc", "-O1"), ("emu_fp", "gcc", "-O1"), ("emu_calls", "gcc", "-O1"), ("emu_switch", "gcc", "-O1"), ("emu_simd", "gcc", "-O1"),
        ("emu", "gcc", "-O2"), ("emu_fp", "gcc", "-O2"), ("emu_calls", "gcc", "-O2"), ("emu_switch", "gcc", "-O2"), ("emu_simd", "gcc", "-O2"),
        ("heldout", "gcc", "-O1"), ("heldout", "gcc", "-O2"), ("heldout", "clang", "-O2"), ("emu", "clang", "-O2"), ("emu_switch", "clang", "-O2"), ("emu_calls", "clang", "-O2")]


def libname(s, c, o):
    return f"{s}.{c}{o}"


def strip_comments(t):
    return re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", "", t, flags=re.S))


def parse_sig(text, head_only=None):
    """(return type text, name, [(type, pname)], variadic). One parser for the engine's signature and the source's."""
    t = strip_comments(text)
    m = re.search(r"\(", t)
    if not m:
        return None
    depth, i = 0, m.start()
    while i < len(t):
        depth += t[i] == "("
        depth -= t[i] == ")"
        if depth == 0:
            break
        i += 1
    head, inner = t[:m.start()].strip(), t[m.start() + 1:i]
    nm = re.search(r"([A-Za-z_~][\w:~]*)\s*$", head)
    if not nm:
        return None
    ret = head[:nm.start()].strip()
    ret = re.sub(r"\b(EXPORT|E|static|inline|const|__attribute__\(\(\w+\)\))\b", "", ret).strip()
    ps, d, cur = [], 0, ""
    for c in inner:
        if c == "," and d == 0:
            ps.append(cur); cur = ""
            continue
        # A template argument list is one parameter's type: `std::tuple<void (*)(T*, unsigned long), T*,
        # unsigned long>` is one `this`, which counting its commas made three (four libFuzzer
        # destructors once their class was named, read as a fall in exact parameter counts).
        d += c in "([<"
        d -= c in ")]>"
        cur += c
    if cur.strip():
        ps.append(cur)
    params, variadic = [], False
    for p in ps:
        p = p.strip()
        if p == "..." or p.endswith("..."):
            variadic = True
            continue
        if p == "void":
            continue
        q = re.match(r"(.*?)([A-Za-z_]\w*)\s*(\[[^\]]*\])?$", p, re.S)
        params.append((q[1].strip() or "?", q[2]) if q else (p, ""))
    return ret, nm[1], params, variadic


def retinfo(ret):
    r = re.sub(r"\bconst\b", "", ret).strip()
    if r == "void":
        return (0, 0, True)
    if r.endswith("*"):
        return (64, 0, False)
    return (*INTS.get(r, (64, 0)), False)


SLOTS = {"rdi": 0, "rsi": 1, "rdx": 2, "rcx": 3, "r8": 4, "r9": 5}


def slot_of(pname, pos):
    if pname in SLOTS:
        return SLOTS[pname]
    return pos


def wrapper(sig, kinds, src_bits):
    ret, name, params, _ = sig
    args = []
    for pos, (ty, pn) in enumerate(params):
        s = slot_of(pn, pos)
        v = f"a[{s}]" if s < 6 else "0x5a5a5a5a"
        t = re.sub(r"\bconst\b", "", ty).strip()
        if pn.startswith("xmm"):
            v = "0"
        if t == "double":
            args.append(f"bh_b2d({v})")
        elif t == "float":
            args.append(f"bh_b2f((uint32_t){v})")
        else:
            args.append(f"({ty}){v}")
    w, sg, void = retinfo(ret)
    call = f"{name}({', '.join(args)})"
    r = re.sub(r"\bconst\b", "", ret).strip()
    if void:
        ret_stmt = f"{call}; return 0;"
    elif r == "double":
        ret_stmt = f"return bh_d2b({call});"
    elif r == "float":
        ret_stmt = f"return bh_f2b({call});"
    else:
        ret_stmt = f"return (uint64_t){call};"
    return f'''
#undef {name}
uint64_t bh_call(uint64_t *a) {{ {ret_stmt} }}
const char *BH_NAME = "{name}", *BH_KINDS = "{kinds}";
int BH_RET_BITS = {w}, BH_RET_SIGNED = {sg}, BH_VOID = {int(void)}, BH_SRC_BITS = {src_bits}, BH_RET_STR = {int(name == "h_name")}, BH_FP = {int(name.startswith(("emu_fp", "emu_simd")))};
'''


def bindings(text, own, table, rules):
    """#defines binding callees by address. table: the engine's own name -> address in the image."""
    out = []
    for n in sorted(set(re.findall(r"\b([A-Za-z_][\w]*)\s*\(", strip_comments(text)))):
        if n == own or n in KEYWORDS or n.startswith("bh_"):
            continue
        a = table.get(n)
        m = re.fullmatch(r"sub_([0-9a-fA-F]+)", n)
        if a is None and m:
            a = int(m[1], 16)
        if a is not None:
            out.append(f"#undef {n}\n#define {n} ((bh_fn)(G_BASE+{a:#x}ull))")
            rules.add("callee")
            continue
        m = re.fullmatch(r"(?:lib\w*_so(?:_\d+)*|extern)__(\w+)", n)
        if m:
            out.append(f'extern uint64_t bh_imp_{m[1]}() __asm__("{m[1]}");\n#define {n} ((bh_fn)&bh_imp_{m[1]})')
            rules.add("callee")
    return "\n".join(out)


CAST_END = re.compile(r"\(\s*[\w ]*(?:_t|int|long|char|short|double|float)\s*\*?\s*\)$")


def binary_before(before):
    return bool(before) and (before[-1].isalnum() or before[-1] in "_)]") and not CAST_END.search(before) and not before.endswith("return")


def unary_star(line):
    """Rewrite unary * on an integer on this line: `*x` and `*(x + 8)` with no pointer cast read 64 bits."""
    def fix(m):
        before = line[:m.start()].rstrip()
        if binary_before(before):
            return m[0]
        return "*(bh_star_t*)" + m[1]
    line2 = re.sub(r"\*\s*([A-Za-z_]\w*)", fix, line)
    out, i = "", 0
    while True:
        m = re.compile(r"\*\s*\(").search(line2, i)
        if not m:
            out += line2[i:]
            break
        before = line2[:m.start()].rstrip()
        d, j = 0, m.end() - 1
        while j < len(line2):
            d += line2[j] == "("
            d -= line2[j] == ")"
            if d == 0:
                break
            j += 1
        inner = line2[m.end():j]
        out += line2[i:m.start()]
        if binary_before(before) or inner.rstrip().endswith("*"):
            out += m[0]
        else:
            out += "*(bh_star_t*)("
        i = m.end()
    return out


def subscript_fix(line):
    """x[i] on an integer: elements of the width of the cast in front of it, else 64 bits."""
    def f(m):
        return f"(({m[1] or 'bh_star_t'}*){m[2]})["
    return re.sub(r"(?:\((u?int(?:8|16|32|64)_t)\)\s*)?\b([A-Za-z_]\w*)\[", lambda m: (f"({m[1]})" if m[1] else "") + f(m), line)


def call_fix(line):
    """A call on an integer. The engine prints `(*x)(...)` for a call to the value x holds, whether x is a register or a
    local: it reads no memory. `(**x)(...)` reads a slot, and so does `(*(*(T*)(x + 8)))(...)`, what a field becomes here."""
    line = re.sub(r"\(\s*\*\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\(", r"((bh_fn)*(uint64_t*)\1)(", line)
    line = re.sub(r"\(\s*\*\s*\(\s*\*\s*\(bh_star_t\*\)\s*(\([^()]*\))\s*\)\s*\)\s*\(", r"((bh_fn)*(uint64_t*)\1)(", line)
    line = re.sub(r"\(\s*\*\s*\(?(?:uint64_t|bh_star_t)\*\)\s*([A-Za-z_]\w*)\s*\)\s*\(", r"((bh_fn)*(uint64_t*)\1)(", line)
    line = re.sub(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\(", r"((bh_fn)\1)(", line)
    return re.sub(r"(?<![\w)])([a-z][a-z0-9]*_\d+)\s*\(", r"((bh_fn)\1)(", line)


def declare(name):
    if name in SLOTS:
        return f"uint64_t {name} = G_{name.upper()};"
    # What a register held on arrival is that, parameter or not: read as 0 it hid every forwarded argument.
    if name.endswith("_0") and name[:-2] in SLOTS:
        return f"uint64_t {name} = G_{name[:-2].upper()};"
    if re.match(r"xmm\d+", name):
        return f"bh_u128 {name} = 0;"
    if re.match(r"(rsp|rbp|esp)\b|(rsp|rbp)_\d+", name):
        return f"uint64_t {name} = (uint64_t)bh_stack + 32768;"
    return f"uint64_t {name} = BH_UNDEF;"


REL = re.compile(r"(<=|>=|(?<![<\-])<(?!<)|(?<![>\-])>(?!>))")
EQ = re.compile(r"(==|!=)")
NARROW = re.compile(r"\(\s*u?int(8|16|32)_t\s*\)")


def depth0(pattern, text):
    """The first match of `pattern` in `text` outside any parenthesis."""
    d = 0
    for m in pattern.finditer(text):
        d = text.count("(", 0, m.start()) - text.count(")", 0, m.start())
        if d == 0:
            return m
    return None


def spell_group(inner, rules):
    """One parenthesised group whose own groups are done: a relational at its top spelled in C."""
    m = depth0(REL, inner)
    if m:
        a, b = inner[:m.start()].strip(), inner[m.end():].strip()
        unsigned = "/*u*/" in b
        b = b.replace("/*u*/", "").strip()
        n = NARROW.match(a)
        bits = n[1] if n else "64"
        ty = f"{'u' if unsigned else ''}int{bits}_t"
        rules.add("rel")
        return f"({ty})({a}) {m[1]} ({ty})({b})"
    m = depth0(EQ, inner)
    if m:
        a, b = inner[:m.start()].strip(), inner[m.end():].strip()
        n = NARROW.match(a)
        if n and not NARROW.match(b):
            # `(uint32_t)x != -0x1`: the machine compared 32 bits, and C would widen the literal and never find them equal.
            ty = f"uint{n[1]}_t"
            rules.add("rel")
            return f"({ty})({a}) {m[1]} ({ty})({b})"
    return inner


def signed_rel(text, rules):
    """The engine marks an unsigned relational with /*u*/ and leaves a signed one unmarked (its binary expressions are always parenthesised).
    Spell that in C, at the width of the first operand's cast, else 64; a literal takes the same cast. Innermost first, so that a
    relational inside another's operand is reached too."""
    out = []
    for line in text.split("\n"):
        # A string's text is not an expression.
        strings = []
        def hide(m):
            strings.append(m[0])
            return f"@S{len(strings) - 1}@"
        masked = re.sub(r'"(?:[^"\\\n]|\\.)*"', hide, line)
        stack = [""]
        for ch in masked:
            if ch == "(":
                stack.append("")
            elif ch == ")" and len(stack) > 1:
                done = spell_group(stack.pop(), rules)
                stack[-1] += "(" + done + ")"
            else:
                stack[-1] += ch
        # A parenthesis never closed: the line is not an expression this reads.
        res = stack[0] if len(stack) == 1 else masked
        res = re.sub(r"@S(\d+)@", lambda m: strings[int(m[1])], res)
        out.append(res)
    return "\n".join(out)


def layer(text, sig, rules):
    t = text
    # -0x80000001 means a negative number; in C the hex literal is unsigned first.
    def neg(m):
        before = t[:m.start()].rstrip()
        if before and (before[-1].isalnum() or before[-1] in "_)]"):
            return m[0]
        return f"(-(long long)0x{m[1]})"
    new = re.sub(r"-\s*0x([0-9a-fA-F]+)\b", neg, t)
    if new != t:
        rules.add("neg_hex")
    t = new
    new = re.sub(r"(?<![\w.])([A-Za-z_]\w*)\.(\d+)\b", r"\1_\2", t)
    if new != t:
        rules.add("ssa")
    t = new
    head, sep, rest = t.partition("{")
    h2 = re.sub(r"^\s*double\b", "uint64_t", re.sub(r"^\s*float\b", "uint32_t", head))
    # A return the engine says it could not determine: as C it would be int, and cut a result in half.
    h2 = re.sub(r"^\s*/\*unknown\*/\s*", "uint64_t ", h2)
    if h2 != head:
        rules.add("bits")
    rest = signed_rel(rest, rules)
    h3 = re.sub(r"\b(?:struct_\w+|void)\s*\*\s*(\w+)", r"uint64_t \1", h2)
    if h3 != h2:
        rules.add("untyped_ptr")
    r2 = re.sub(r"\b([A-Za-z_]\w*)->field_neg_(0x[0-9a-f]+)", r"(*(bh_star_t*)(\1 - \2))", rest)
    r2 = re.sub(r"\b([A-Za-z_]\w*)->field_(0x[0-9a-f]+)", r"(*(bh_star_t*)(\1 + \2))", r2)
    if r2 != rest:
        rules.add("untyped_ptr")
    t = h3 + sep + r2
    return t


def spell_calls(t, rules):
    """`(*x)(...)` is well-formed C on a function pointer and an error on an integer, and an error is what used to send it to a fix
    that read through x. Spell them all before the compiler sees one."""
    head, sep, rest = t.partition("{")
    new = "\n".join(call_fix(l) if "(*" in l else l for l in rest.split("\n"))
    if new != rest:
        rules.add("call_slot")
    return head + sep + new


def gcc(args, timeout=60):
    return subprocess.run(["nice", "-n", "19", "gcc", *args], capture_output=True, text=True, env=ENV, timeout=timeout, errors="replace")


def first_error(err):
    for l in err.splitlines():
        if "error:" in l:
            m = l.split("error:", 1)[1].strip()
            return re.sub(r"[‘’'`][^‘’'`]*[‘’'`]", "X", m)[:90]
    return err.strip()[:90] or "unknown"


def compile_body(raw, own_table, kinds, src_bits, workdir, stem="b"):
    """Returns dict: level0 ok/reason, level1 ok/reason, rules, path of TU."""
    os.makedirs(workdir, exist_ok=True)
    res = {"rules": []}
    sig0 = parse_sig(raw)
    if not sig0:
        return {"level0": False, "level0_why": "no signature", "level1": False, "level1_why": "no signature", "rules": []}
    # Level 0: exactly as printed. Only the prelude; callees may be implicit, as C would have it under -fpermissive.
    p0 = f"{workdir}/{stem}.l0.c"
    open(p0, "w").write('#include "prelude.h"\n' + raw + "\n")
    r = gcc([*CFLAGS, "-fsyntax-only", p0])
    res["level0"] = r.returncode == 0
    if r.returncode:
        res["level0_why"] = first_error(r.stderr)
    # Level 1.
    rules = set()
    t = spell_calls(layer(raw, sig0, rules), rules)
    sig = parse_sig(t)
    binds = bindings(t, sig[1], own_table, rules)
    decls = []
    p1 = f"{workdir}/{stem}.l1.c"
    why = ""
    for _ in range(40):
        head, sep, rest = t.partition("{")
        tu = '#include "prelude.h"\nstatic uint8_t bh_stack[65536];\n' + binds + "\n" + head + sep + "\n" + "\n".join(decls) + "\n" + rest + "\n" + wrapper(sig, kinds, src_bits)
        open(p1, "w").write(tu)
        r = gcc([*CFLAGS, "-c", p1, "-o", p1 + ".o"])
        if r.returncode == 0:
            why = ""
            break
        changed = False
        for name in sorted(set(re.findall(r"error: [‘']([\w]+)[’'] undeclared", r.stderr))):
            d = declare(name)
            if d not in decls:
                decls.append(d)
                rules.add("undecl")
                changed = True
        if "invalid type argument of unary" in r.stderr or "invalid operands" in r.stderr and False:
            lines = tu.split("\n")
            prefix = '#include "prelude.h"\nstatic uint8_t bh_stack[65536];\n' + binds + "\n" + head + sep + "\n" + "\n".join(decls) + "\n"
            off = prefix.count("\n")
            body_lines = rest.split("\n")
            for m in re.finditer(r"\.c:(\d+):\d+: error: invalid type argument of unary", r.stderr):
                k = int(m[1]) - 1 - off
                if 0 <= k < len(body_lines):
                    nl = unary_star(body_lines[k])
                    if nl != body_lines[k]:
                        body_lines[k] = nl
                        changed = True
                        rules.add("star")
            t = head + sep + "\n".join(body_lines)
        for rx, fix, rule in ((r"\.c:(\d+):\d+: error: subscripted value", subscript_fix, "subscript"), (r"\.c:(\d+):\d+: error: called object", call_fix, "call_slot")):
            hits = list(re.finditer(rx, r.stderr))
            if hits:
                head, sep, rest = t.partition("{")
                prefix = '#include "prelude.h"\nstatic uint8_t bh_stack[65536];\n' + binds + "\n" + head + sep + "\n" + "\n".join(decls) + "\n"
                off = prefix.count("\n")
                body_lines = rest.split("\n")
                for m in hits:
                    k = int(m[1]) - 1 - off
                    if 0 <= k < len(body_lines):
                        nl = fix(body_lines[k])
                        if nl != body_lines[k]:
                            body_lines[k] = nl
                            changed = True
                            rules.add(rule)
                t = head + sep + "\n".join(body_lines)
        if not changed:
            why = first_error(r.stderr)
            break
    res["rules"] = sorted(rules)
    res["level1"] = not why
    if why:
        res["level1_why"] = why
    res["tu"] = p1
    res["sig"] = sig[0] + " " + sig[1] + "(" + ", ".join(p[0] + " " + p[1] for p in sig[2]) + ")"
    return res


def run_body(tu, orig_so, workdir, stem="b", defs=()):
    exe = f"{workdir}/{stem}.exe"
    h = HERE + "/harness.c"
    obj = tu + ".o"
    if defs:
        obj = f"{workdir}/{stem}.v.o"
        r = gcc([*CFLAGS, *defs, "-c", tu, "-o", obj])
        if r.returncode:
            return {"link_error": first_error(r.stderr)}
    r = gcc([*CFLAGS, obj, h, "-o", exe, "-ldl", "-lm", "-rdynamic"])
    if r.returncode:
        return {"link_error": first_error(r.stderr) if "error" in r.stderr else r.stderr.strip().splitlines()[-1][:120] if r.stderr.strip() else "?"}
    try:
        p = subprocess.run(["nice", "-n", "19", exe, orig_so, str(INPUTS)], capture_output=True, text=True, timeout=120, errors="replace")
    except subprocess.TimeoutExpired:
        return {"run_timeout": True}
    try:
        return json.loads(p.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"run_died": p.returncode, "stderr": p.stderr[-200:]}


def outcome(o):
    if not o:
        return "not_run"
    if "link_error" in o:
        return "no_link"
    if "run_timeout" in o or "run_died" in o or "harness_error" in o:
        return "died"
    if o["crash"]:
        return "crash"
    if o["differ"]:
        return "differ"
    if o.get("differ_nan"):
        return "differ_nan_only"
    if o["same_low"]:
        return "same_ext" if o["ext_only"] else "narrow"
    return "same"


def dynsyms(path):
    out = {}
    for l in subprocess.run(["readelf", "-Ws", "--dyn-syms", path], capture_output=True, text=True, env=ENV).stdout.splitlines():
        f = l.split()
        if len(f) >= 8 and f[3] == "FUNC" and f[6] != "UND":
            out[f[7].split("@")[0]] = int(f[1], 16)
    return out


def source_fns(src):
    out = {}
    t = open(src).read()
    for m in re.finditer(r"^(?:EXPORT|E)\s+[^\n{;]*\([^\n{;]*\)\s*\{", t, re.M):
        s = parse_sig(m[0].rstrip("{ "))
        out[s[1]] = s
    return out


def one(job):
    lib, fn, raw, table, kinds, src_bits, orig, wd = job
    r = compile_body(raw, table, kinds, src_bits, wd)
    if r.get("level1"):
        r["run"] = run_body(r["tu"], orig, wd)
    r["outcome"] = "no_compile" if not r.get("level1") else outcome(r.get("run"))
    r.update(lib=lib, fn=fn, tool="n0xis")
    # A body that fails may fail on what it did not say: the width of an untyped access, the value of a name read before it is set.
    # Each other reading; a body rescued this way did not state what it needs, and is counted apart.
    if r["outcome"] in ("differ", "crash", "died", "differ_nan_only") and set(r["rules"]) & {"star", "untyped_ptr", "subscript", "undecl"}:
        for w in ("uint64_t", "uint8_t", "uint16_t", "uint32_t"):
            for u in ("0", "1"):
                if w == "uint64_t" and u == "0":
                    continue
                v = run_body(r["tu"], orig, wd, "v", (f"-DBH_STAR={w}", f"-DBH_UNDEF={u}"))
                if outcome(v) in ("same", "same_ext"):
                    r["rescued_by"] = (w, u)
                    break
            if "rescued_by" in r:
                break
    return r


def one_source(job):
    """The source itself through the same harness: must score full marks."""
    lib, fn, sig, srcpath, kinds, bits, orig, wd = job
    os.makedirs(wd, exist_ok=True)
    p = f"{wd}/b.c"
    src = open(srcpath).read()
    open(p, "w").write(f'#include "{srcpath}"\nextern uint64_t G_BASE;\n' + wrapper(sig, kinds, bits))
    r = gcc(["-std=gnu11", "-O0", "-w", "-fwrapv", "-fno-strict-aliasing", "-fpermissive", "-c", p, "-o", p + ".o"])
    res = {"lib": lib, "fn": fn, "tool": "source", "rules": [], "level0": r.returncode == 0, "level1": r.returncode == 0, "sig": ""}
    if r.returncode:
        res["level1_why"] = first_error(r.stderr)
        res["outcome"] = "no_compile"
        return res
    res["run"] = run_body(p, orig, wd)
    res["outcome"] = outcome(res["run"])
    return res


def build_libs(outdir):
    """Every library at a fixed base, so that a literal address in a body is valid; the engine reads the stripped copy."""
    os.makedirs(f"{outdir}/lib", exist_ok=True)
    for s, c, o in LIBS:
        lib = libname(s, c, o)
        g = f"{outdir}/lib/{lib}.g.so"
        if not os.path.exists(g):
            subprocess.run(["nice", "-n", "19", c, "-g", o, "-fPIC", "-shared", "-Wl,-Ttext-segment=0x40000000", SRC[s], "-lm", "-o", g], check=True, env=ENV, capture_output=True)
            subprocess.run(["strip", "-o", f"{outdir}/lib/{lib}.so", g], check=True, env=ENV)


def ask_engine(engine, outdir, lib):
    """One `function discover`, then one `decomp pseudo` per start, as a user runs them: a project of its own, 4 GiB of address space."""
    img = f"{outdir}/lib/{lib}.so"
    cwd = f"{outdir}/bodies/{lib}.run"
    shutil.rmtree(cwd, ignore_errors=True)
    os.makedirs(cwd + "/.n0x")
    lim = lambda: resource.setrlimit(resource.RLIMIT_AS, (4194304 * 1024, 4194304 * 1024))
    run = lambda *a: subprocess.run([engine, *a, "--file", img, "--quiet"], cwd=cwd, capture_output=True, preexec_fn=lim, timeout=120, env=ENV)
    fns = json.loads(run("function", "discover").stdout)["data"]["functions"]
    with open(f"{outdir}/bodies/{lib}.jsonl", "w") as w:
        for f in fns:
            r = run("decomp", "pseudo", "--addr", f["va"])
            try:
                x = json.loads(r.stdout)
            except ValueError:
                x = {"ok": False, "error": {"code": "died", "rc": r.returncode}}
            rec = {"entry": f["va"][2:], "name": f["name"]}
            if x.get("ok"):
                rec.update(completed=True, c="\n".join(x["data"]["pseudo"]), signature=x["data"]["signature"], quality=x["data"].get("quality"))
            else:
                rec.update(completed=False, error=str(x.get("error"))[:200])
            w.write(json.dumps(rec) + "\n")
    return fns


def load_bodies(outdir, lib, fns):
    rows = [json.loads(l) for l in open(f"{outdir}/bodies/{lib}.jsonl")]
    by, table = {}, {}
    for r in rows:
        a = int(r["entry"], 16)
        by[a] = r
        table.setdefault(r["name"].split("::")[-1], a)
    for f in fns:
        table.setdefault(f["name"], int(f["va"], 16))
    return by, table


def jobs(outdir, discovered):
    js = []
    for s, c, o in LIBS:
        lib = libname(s, c, o)
        so = f"{outdir}/lib/{lib}.g.so"
        syms = dynsyms(so)
        by, table = load_bodies(outdir, lib, discovered[lib])
        for fn, sig in source_fns(SRC[s]).items():
            kinds, bits = HELD.get(fn, ("v" * 4, 64))
            js.append(("SRC", lib, fn, sig, SRC[s], kinds, bits, so, f"{outdir}/runs/source/{lib}/{fn}"))
            row = by.get(syms.get(fn))
            wd = f"{outdir}/runs/n0xis/{lib}/{fn}"
            if not row or not row.get("completed"):
                js.append((lib, fn, None, None, kinds, bits, so, wd))
            else:
                js.append((lib, fn, row["c"], table, kinds, bits, so, wd))
    return js


def main():
    engine, outdir = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    CFLAGS.extend(["-I", outdir])
    os.makedirs(f"{outdir}/bodies", exist_ok=True)
    subprocess.run([sys.executable, HERE + "/gen_prelude.py", outdir + "/prelude.h"], check=True)
    build_libs(outdir)
    libs = [libname(*l) for l in LIBS]
    with cf.ThreadPoolExecutor(4) as ex:
        discovered = dict(zip(libs, ex.map(lambda l: ask_engine(engine, outdir, l), libs)))
    js = jobs(outdir, discovered)

    def go(j):
        if j[0] == "SRC":
            return one_source(j[1:])
        if j[2] is None:
            return {"lib": j[0], "fn": j[1], "tool": "n0xis", "outcome": "no_answer", "rules": []}
        return one(j)

    with cf.ThreadPoolExecutor(4) as ex:
        res = list(ex.map(go, js))
    json.dump(res, open(outdir + "/results.json", "w"), indent=0)
    subprocess.run([sys.executable, HERE + "/report.py", outdir], check=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Prototypes from DWARF (llvm-dwarfdump): per code-holding subprogram: entry, name, parameter count, void or not.

Usage: dwarfprotos.py <unstripped> <out.json>
A concrete out-of-line copy takes its name and return type through abstract_origin/specification.
Parameters: the DIE's own direct DW_TAG_formal_parameter children, else its origin's. `this` (artificial) is counted, as the ABI passes it.
variadic: DW_TAG_unspecified_parameters among them. by_value_aggregate is not known here (needs the type): see scorer.
"""
import json, re, subprocess, sys

ATTR = re.compile(r"^\s+(DW_AT_\w+)\s+\((.*)\)\s*$")
DIE = re.compile(r"^0x([0-9a-f]+):(\s+)(DW_TAG_\w+|NULL)")
REF = re.compile(r"0x([0-9a-f]+)")


def parse(path):
    subs, stack = {}, []
    cur = None
    p = subprocess.Popen(["llvm-dwarfdump", "--debug-info", path], stdout=subprocess.PIPE, text=True, errors="replace", bufsize=1 << 20)
    for line in p.stdout:
        m = DIE.match(line)
        if m:
            off, depth, tag = int(m[1], 16), len(m[2]), m[3]
            while stack and stack[-1][0] >= depth:
                stack.pop()
            if tag == "NULL":
                cur = None
                continue
            parent = stack[-1][1] if stack else None
            cur = None
            if tag == "DW_TAG_subprogram":
                cur = {"off": off, "params": 0, "variadic": False, "artificial": 0, "param_types": [], "kind": "sub"}
                subs[off] = cur
            elif tag == "DW_TAG_formal_parameter" and parent is not None and parent.get("kind") == "sub":
                parent["params"] += 1
                cur = {"kind": "param", "owner": parent}
            elif tag == "DW_TAG_unspecified_parameters" and parent is not None and parent.get("kind") == "sub":
                parent["variadic"] = True
            stack.append((depth, cur if cur is not None else {"kind": "other"}))
            continue
        if cur is None:
            continue
        a = ATTR.match(line)
        if not a:
            continue
        k, v = a[1], a[2]
        if cur["kind"] == "param":
            if k == "DW_AT_artificial":
                cur["owner"]["artificial"] += 1
            elif k == "DW_AT_type":
                q = re.search(r'"(.*)"', v)
                cur["owner"]["param_types"].append(q[1] if q else "?")
            continue
        if k == "DW_AT_name":
            cur["name"] = v.strip('"')
        elif k == "DW_AT_linkage_name":
            cur["linkage"] = v.strip('"')
        elif k == "DW_AT_low_pc":
            cur["low"] = int(v, 16)
        elif k == "DW_AT_ranges":
            cur["has_ranges"] = True
        elif k == "DW_AT_type":
            q = re.search(r'"(.*)"', v)
            cur["type"] = q[1] if q else "?"
        elif k in ("DW_AT_abstract_origin", "DW_AT_specification"):
            cur["origin"] = int(REF.search(v)[1], 16)
        elif k == "DW_AT_entry_pc":
            cur["entry_pc"] = int(v, 16)
        elif k == "DW_AT_decl_line":
            cur["line"] = int(v)
        elif k == "DW_AT_decl_file":
            cur["file"] = v.strip('"')
        elif k == "DW_AT_noreturn":
            cur["noreturn"] = True
    p.wait()
    return subs


def chain(subs, s, key):
    seen = 0
    while s is not None and seen < 8:
        if key in s:
            return s[key]
        s = subs.get(s.get("origin"))
        seen += 1
    return None


def main():
    subs = parse(sys.argv[1])
    out = {}
    for s in subs.values():
        if "low" not in s and "has_ranges" not in s:
            continue
        o, params, variadic, art, ptypes = s, s["params"], s["variadic"], s["artificial"], s["param_types"]
        seen = 0
        while params == 0 and not variadic and o.get("origin") in subs and seen < 8:
            o = subs[o["origin"]]
            params, variadic, art, ptypes = o["params"], o["variadic"], o["artificial"], o["param_types"]
            seen += 1
        # A multi-range function's own low_pc is 0 or absent; truth.py's entry comes first, so entries are matched by name there.
        out[s["off"]] = {"low": s.get("low"), "entry_pc": s.get("entry_pc"), "has_ranges": s.get("has_ranges", False), "name": chain(subs, s, "name"), "linkage": chain(subs, s, "linkage"),
                         "ret": chain(subs, s, "type"), "params": params, "variadic": variadic, "artificial": art, "param_types": ptypes[:12],
                         "file": chain(subs, s, "file"), "line": chain(subs, s, "line"), "noreturn": bool(chain(subs, s, "noreturn"))}
    json.dump(list(out.values()), open(sys.argv[2], "w"))
    print(len(out), "code subprograms;", sum(1 for v in out.values() if v["low"] is None), "without a low_pc")


main()

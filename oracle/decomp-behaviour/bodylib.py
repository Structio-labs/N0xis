#!/usr/bin/env python3
"""Shared readers for the counters over big images: the rows `bodies.py` wrote, what a body shows, and an image's instructions by objdump."""
import bisect, json, os, re, subprocess

ENV = dict(os.environ, LC_ALL="C", LANG="C")
INSN = re.compile(r"^\s*([0-9a-f]+):\s+(.*)$")
PREFIX = re.compile(r"^(?:notrack|bnd|rex\.\w+|repz|repnz|rep|lock|data16|cs|ds|nopw?\s)\s+")


def rows(path):
    """(the meta line, the rows that hold a body) of a file written by bodies.py."""
    all_rows = [json.loads(l) for l in open(path)]
    return all_rows[0], [r for r in all_rows[1:] if r.get("completed")]


def is_pe(path):
    return open(path, "rb").read(2) == b"MZ"


class Image:
    """Instructions of an image, by address. `objdump -w`, since it otherwise wraps a long instruction; LC_ALL=C, since its output is localized."""

    def __init__(self, path):
        self.addrs, self.insn = [], {}
        tool = "x86_64-w64-mingw32-objdump" if is_pe(path) else "objdump"
        p = subprocess.Popen([tool, "-d", "--no-show-raw-insn", "-w", path], stdout=subprocess.PIPE, text=True, errors="replace", env=ENV)
        for line in p.stdout:
            m = INSN.match(line)
            if m:
                a = int(m[1], 16)
                self.addrs.append(a)
                self.insn[a] = m[2].strip()
        p.wait()
        self.addrs.sort()

    def in_range(self, lo, hi):
        i = bisect.bisect_left(self.addrs, lo)
        while i < len(self.addrs) and self.addrs[i] < hi:
            yield self.addrs[i], self.insn[self.addrs[i]]
            i += 1

    def parse(self, text):
        t = text
        while True:
            n = PREFIX.sub("", t)
            if n == t:
                break
            t = n
        f = t.split(None, 1)
        return f[0], (f[1] if len(f) > 1 else "")


def strip_comments(t):
    return re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", "", t, flags=re.S))


def strip_strings(t):
    return re.sub(r'"(?:[^"\\\n]|\\.)*"', '""', t)

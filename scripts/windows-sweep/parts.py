"""The parts of the sweep that are more than a list: a real console, path spellings, a live target and the defects found on it,
the MCP parent, the update client, real programs, Defender. Each part ends in rows, and a row is decided here, not by a reader."""

import base64
import hashlib
import json
import os
import queue
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

M = None  # the main script, for what it owns: LaptopGone, the ssh options, first_diff


def bind(main_module):
    global M
    M = main_module


class Target:
    """A target this run started and holds, over a connection of its own: closing that connection is what would end a process
    started any other way. Everything it says about itself is on its standard output: `T` lines, ten a second."""

    def __init__(self, s, exe="wtarget.exe"):
        self.s = s
        self.addr, self.lua, self.tick = {}, {}, {}
        self.ticks, self.dead, self.lines = 0, False, []
        self.pid = self.base = self.combo = self.tid = None
        self.ready = threading.Event()
        self.p = subprocess.Popen([*M.SSH, s.laptop.host, f"cmd /c {s.wroot}\\runt.bat {s.W('in/' + exe)}"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        threading.Thread(target=self._read, daemon=True).start()
        if not self.ready.wait(40):
            s.laptop.gone_unless_up("a target was starting")
            raise RuntimeError(f"the target did not come up: {self.lines[:4]}")

    def _read(self):
        for raw in self.p.stdout:
            l = raw.decode("utf-8", "replace").strip()
            if l.startswith("T "):
                self.tick = dict(kv.split("=", 1) for kv in l[2:].split())
                self.ticks = int(self.tick["n"])
            elif l.startswith(("ADDR ", "LUA ")):
                kind, n, v = l.split()
                (self.addr if kind == "ADDR" else self.lua)[n] = v
            elif l.startswith("PID "):
                self.pid = l.split()[1]
            elif l.startswith("TID "):
                self.tid = l.split()[1]
            elif l.startswith("BASE "):
                self.base = l.split()[1]
            elif l.startswith("COMBO "):
                self.combo = l.split()[1]
            elif l == "READY":
                self.ready.set()
            self.lines = self.lines[-40:] + [l]
        self.dead = True

    def alive(self, need=2, wait=8):
        """Ticks counted after this was asked, which is the only meaning survival can have."""
        t0, end = self.ticks, time.time() + wait
        while time.time() < end:
            if self.ticks >= t0 + need:
                return True
            time.sleep(0.05)
        return False

    def exit_code(self):
        end = time.time() + 3
        while time.time() < end:
            found = [x for x in self.lines if x.startswith("EXITCODE")]
            if found:
                return hex(int(found[-1].split()[1]) & 0xffffffff)
            time.sleep(0.1)
        return "still running" if not self.dead else "unknown"

    def stop(self):
        if self.pid and not self.dead:
            self.s.laptop.run(r"C:\Windows\System32\taskkill.exe", ["/F", "/PID", self.pid], bound=15)
        self.p.kill()


class Live:
    """Runs a command against a target and decides the row: the answer as stated, then that the target still ticks, and that
    what the command had no business changing has not changed. A target that died is replaced, so one death fails one row."""

    SILENT = ("i32", "rc", "hb", "write", "pin", "patch")

    def __init__(self, s, exe="wtarget.exe", prefix=""):
        self.s, self.exe, self.prefix = s, exe, prefix
        self.T = Target(s, exe)

    def __getitem__(self, name):
        return self.T.addr[name]

    def FP(self):
        return ["--pid", self.T.pid]

    def replace_target(self):
        try:
            self.T.stop()
        except OSError:
            pass
        self.T = Target(self.s, self.exe)

    def finish(self):
        self.T.stop()

    def run(self, args, stdin=None, bound=60, exe=None, cwd="{W}live", kill_after=None):
        return self.s.win(args, cwd=cwd, stdin=stdin, bound=bound, exe=exe, kill_after=kill_after)

    def survived(self, need=3, wait=8):
        """None, or how it died, the replacement already started."""
        if not self.T.dead and self.T.alive(need, wait):
            return None
        self.s.laptop.gone_unless_up("a target stopped")
        code = self.T.exit_code()
        self.replace_target()
        return f"the target stopped ticking, exit {code}"

    def t(self, id, *args, must=(), mustnot=(), check=None, stdin=None, bound=60, changes=(), refuse=None, exe=None):
        s = self.s
        id = self.prefix + id
        if s.skipped(id):
            return None, ""
        command = s.leaf_of(args)
        before = dict(self.T.tick)
        r = self.run(args, stdin=stdin, bound=bound, exe=exe)
        env = s.parsed(r["o"])
        text = r["o"].decode("utf-8", "replace").lower()
        why = s.contract(r) or s.expectation(r, refuse)
        if not why and not refuse:
            gone = [m for m in must if str(m).lower() not in text]
            there = [m for m in mustnot if str(m).lower() in text]
            why = f"missing {gone}" if gone else f"present {there}" if there else None
            if not why and check:
                try:
                    why = check(env, text)
                except Exception as e:  # noqa: BLE001 - an answer of the wrong shape is a wrong answer
                    why = f"the answer does not read as expected: {e!r}"
        died = self.survived()
        if died:
            why = f"{died}{'; ' + why if why else ''}"
        else:
            moved = [f"{k} {before.get(k)} -> {self.T.tick.get(k)}" for k in self.SILENT if k not in changes and self.T.tick.get(k) != before.get(k)]
            if moved and not why:
                why = "the target's own printout moved: " + ", ".join(moved)
        s.row(id, command, "failed" if why else "passed", why or "")
        return env, text

    def prints(self, key, value, wait=2):
        """Whether the target says so itself."""
        end = time.time() + wait
        while time.time() < end:
            if self.T.tick.get(key) == value:
                return None
            time.sleep(0.05)
        return f"the target prints {key}={self.T.tick.get(key)}, not {value}"

    def wait_past_site(self):
        """Just after the rare branch ran, so that a breakpoint there is reached well after the command's start."""
        self.T.alive(need=1)
        end = time.time() + 8
        while time.time() < end and int(self.T.tick.get("cnt", 0)) % 40 not in (2, 3):
            time.sleep(0.02)


def hooked_listing(s):
    """hooked, by objdump: a line per instruction, offsets from its first."""
    dis = M.run_local("x86_64-w64-mingw32-objdump", "-d", "--disassemble=hooked", str(s.lroot / "in/wtarget.exe"))
    lines = [l for l in dis.splitlines() if re.match(r"\s+[0-9a-f]+:", l)]
    first = int(lines[0].split(":")[0], 16)
    return [(int(l.split(":")[0], 16) - first, l) for l in lines]


def rare_site(s, L):
    """The first instruction after `jne`, `toggled = toggled + 1`, reached once in forty ticks."""
    listing = hooked_listing(s)
    at = next(i for i, (_, l) in enumerate(listing) if re.search(r"\bjne\b", l))
    return int(L["hooked"], 16) + listing[at + 1][0]


def new_value_site(s, L):
    """`mov %eax,counter`: rax holds the counter's new value there, the same on every pass."""
    off = next(o for o, l in hooked_listing(s) if re.search(r"mov\s+%eax,.*<counter>", l))
    return int(L["hooked"], 16) + off


def in_range(text, base, size):
    lo = int(base, 16)
    if any(lo <= int(m, 16) < lo + size for m in re.findall(r"0x[0-9a-f]+", text)):
        return None
    return f"no address within {base}+{size:#x}"


def tobytes(v, n):
    return " ".join(f"{b:02x}" for b in v.to_bytes(n, "little"))


# -- the live part ----------------------------------------------------------------------------------------------------

def live_part(s):
    L = Live(s)
    try:
        read_group(s, L)
        scan_group(s, L)
        debug_group(s, L)
        mutate_group(s, L)
        rest_group(s, L)
        same_session_rows(s)
        not_run_rows(s)
    finally:
        L.finish()
    L32 = Live(s, "wtarget32.exe", "32bit.")
    try:
        a, FP = L32, L32.FP
        L32.t("module.list", "module", "list", *FP(), must=["wtarget32.exe"])
        L32.t("mem.read", "mem", "read", "--addr", a["p_i32"], "--size", "4", *FP(), must=[tobytes(0x1CEB00DA, 4)])
        L32.t("scan.value", "scan", "value", "--type", "i32", "--value", str(0x1CEB00DA), *FP(), "--save-as", "w32", "--force", must=[a["p_i32"]])
        L32.t("disasm", "disasm", "--addr", a["hooked"], "--count", "3", *FP(), "--arch", "x86", must=["push", "ebp"])
        L32.t("mem.write", "mem", "write", "--addr", a["writeme"], "--bytes", "EF CD AB 89 67 45 23 01", *FP(), changes=("write",), check=lambda e, x: L32.prints("write", "0123456789abcdef"))
        L32.t("mem.write+back", "mem", "write", "--addr", a["writeme"], "--bytes", "11 11 11 11 11 11 11 11", *FP(), changes=("write",), check=lambda e, x: L32.prints("write", "1111111111111111"))
        L32.t("debug.attach", "debug", "attach", *FP(), "--timeout-ms", "800")
        c0 = int(L32.T.tick["cnt"])
        hb = L32.T.tick["hb"]
        L32.t("patch.detour", "patch", "detour", *FP(), "--hook-at", a["hooked"], "--arch", "x86", changes=("hb",), check=lambda e, x: detour_runs(L32, hb, c0))
        L32.t("patch.undo", "patch", "undo", changes=("hb",), check=lambda e, x: L32.prints("hb", hb))
    finally:
        L32.finish()


def detour_runs(L, original_bytes, c0):
    end = time.time() + 2.5
    while time.time() < end and L.T.tick.get("hb") == original_bytes:
        time.sleep(0.05)
    if L.T.tick.get("hb") == original_bytes:
        return "the target's function bytes did not change"
    c1 = int(L.T.tick["cnt"])
    time.sleep(1.0)
    c2 = int(L.T.tick["cnt"])
    return None if c2 > c1 > c0 else f"the hooked function stopped counting: {c0} {c1} {c2}"


def read_group(s, L):
    t, a, FP = L.t, L, L.FP
    T = lambda: L.T  # noqa: E731
    t("process.ps+filter", "process", "ps", "--filter", "wtarget", must=[f'"pid":{T().pid}', "wtarget.exe"])
    t("process.ps", "process", "ps", must=[f'"pid":{T().pid}'])
    t("module.list+pid", "module", "list", *FP(), must=["wtarget.exe", "ntdll", "kernel32", T().base])
    t("profile+pid", "profile", *FP(), must=["wtarget"])
    t("mem.read+pid", "mem", "read", "--addr", a["p_i32"], "--size", "4", *FP(), must=[tobytes(0x1CEB00DA, 4)])
    t("mem.read+i64", "mem", "read", "--addr", a["p_i64"], "--size", "8", *FP(), must=[tobytes(0x0DEADBEEFCAFEF00D, 8)])
    t("mem.read+unmapped", "mem", "read", "--addr", "0x10", "--size", "4", *FP(), refuse="read-failed")
    t("mem.span+pid", "mem", "span", "--addr", a["p_aob"], "--size", "16", *FP(), must=["b1 6b 00 b5 ac dc 77 31"])
    t("mem.span+edge", "mem", "span", "--addr", hex(int(a["page"], 16) + 0x8000 - 8), "--size", "64", *FP())
    t("mem.map", "mem", "map", *FP(), "--limit", "4000", must=[])
    t("find+pid", "find", "--string", "N0XIS_LIVE_ASCII_MARKER_77", *FP(), must=[a["p_str"]])
    t("find+utf16", "find", "--string", "N0XIS_LIVE_WIDE_MARKER_79", "--utf16", *FP(), must=[a["p_wide"]])
    t("find+bytes", "find", "--bytes", "B1 6B 00 B5 AC DC 77 31", *FP(), must=[a["p_aob"]])
    t("strings+pid", "strings", *FP(), "--contains", "MARKER_77", "--limit", "20", must=["n0xis_live_ascii_marker_77"])
    t("strings+utf16pid", "strings", *FP(), "--contains", "WIDE_MARKER", "--encoding", "utf16le", "--limit", "20", must=["n0xis_live_wide_marker_79"])
    t("strings+utf8pid", "strings", *FP(), "--contains", "MARKER_78", "--limit", "20", must=["n0xis_живий_marker_78"])
    t("disasm+pid", "disasm", "--addr", a["hooked"], "--count", "3", *FP(), must=["push", "rbp", "mov"])
    t("why+pid", "why", "--addr", a["hooked"], *FP())
    t("contradictions+pid", "contradictions", *FP(), "--limit", "40")
    for leaf in ("ir build", "ir explain", "ir dot", "ir value-set", "ir deobfuscate"):
        t(leaf.replace(" ", ".") + "+pid", *leaf.split(), "--addr", a["hooked"], *FP())
    t("ir.slice+pid", "ir", "slice", "--addr", a["hooked"], "--reg", "rax", *FP())
    t("ir.manifest+pid", "ir", "manifest", *FP(), "--limit", "20")
    t("function.discover+pid", "function", "discover", *FP(), "--limit", "4000", must=[a["hooked"], a["magic_mix"]])
    t("function.discover+pdata", "function", "discover", *FP(), "--pdata", "--limit", "4000", must=[a["hooked"]])
    t("function.trace+pid", "function", "trace", "--addr", a["step"], *FP(), "--depth", "2", must=[a["hooked"], a["magic_mix"]])
    t("function.noreturn+pid", "function", "noreturn", *FP(), "--limit", "20")
    t("function.summary+pid", "function", "summary", *FP(), "--limit", "10")
    t("function.typeflow+pid", "function", "typeflow", *FP(), "--limit", "10")
    t("function.layout+pid", "function", "layout", *FP(), "--limit", "10")
    t("decomp+pid", "decomp", "pseudo", "--addr", a["magic_mix"], *FP(), must=["5bd1e995"])
    t("decomp+rva", "decomp", "pseudo", "--addr", hex(int(a["magic_mix"], 16) - int(T().base, 16)), "--addr-rva", *FP(), must=["5bd1e995"])
    t("xref.to+pid", "xref", "to", "--addr", a["counter"], *FP(), check=lambda e, x: in_range(x, a["hooked"], 0x70))
    t("xref.from+pid", "xref", "from", "--addr", a["step"], *FP(), must=[a["hooked"]])
    t("xref.string+pid", "xref", "string", "--query", "MARKER_77", *FP(), "--limit", "10")
    t("rtti.scan+pid", "rtti", "scan", *FP())
    t("bindings.list+pid", "bindings", "list", *FP(), "--limit", "20")
    t("const.identify+pid", "const", "identify", "--addr", a["magic_mix"], *FP(), must=["5bd1e995"])
    t("sig.validate+pid", "sig", "validate", "--at", a["hooked"], "--len", "8", *FP())
    t("analyze+pid", "analyze", *FP(), "--limit", "10", refuse="needs-file")


def scan_group(s, L):
    t, a, FP = L.t, L, L.FP
    t("scan.value+i32", "scan", "value", "--type", "i32", "--value", str(0x1CEB00DA), *FP(), "--save-as", "s1", "--force", must=[a["p_i32"]])
    t("scan.value+hex", "scan", "value", "--type", "u32", "--value", "0x1CEB00DA", *FP(), "--save-as", "s1h", "--force", must=[a["p_i32"]])
    t("scan.value+i16", "scan", "value", "--type", "i16", "--value", "0x7A5B", *FP(), "--save-as", "s2", "--force", must=[a["p_i16"]])
    t("scan.value+f32", "scan", "value", "--type", "f32", "--value", "32125.625", *FP(), "--save-as", "s4", "--force", must=[a["p_f32"]])
    t("scan.value+f64", "scan", "value", "--type", "f64", "--value", "1234.56789125", *FP(), "--save-as", "s5", "--force", must=[a["p_f64"]])
    t("scan.value+range", "scan", "value", "--type", "i32", "--criterion", "in-range", "--min", str(0x1CEB00D0), "--max", str(0x1CEB00E0), *FP(), "--save-as", "s6", "--force", must=[a["p_i32"]])
    t("scan.value+window", "scan", "value", "--type", "i32", "--value", str(0x1CEB00DA), *FP(), "--start", a["p_i32"], "--size", "16", "--save-as", "s7", "--force", must=[a["p_i32"]])
    t("scan.value+unknown", "scan", "value", "--type", "i32", "--criterion", "unknown", *FP(), "--start", a["counter"], "--size", "4", "--save-as", "c1", "--force", must=[a["counter"]])
    time.sleep(0.5)
    t("scan.filter+increased", "scan", "filter", "--from", "c1", "--criterion", "increased", *FP(), "--save-as", "c2", "--force", must=[a["counter"]])
    t("scan.filter+exact", "scan", "filter", "--from", "s1", "--criterion", "exact", "--value", str(0x1CEB00DA), *FP(), "--save-as", "s1b", "--force", must=[a["p_i32"]])
    t("scan.filter+unchanged", "scan", "filter", "--from", "s1", "--criterion", "unchanged", *FP(), "--save-as", "s1c", "--force", must=[a["p_i32"]])
    t("scan.filter+decreased", "scan", "filter", "--from", "c2", "--criterion", "decreased", *FP(), "--save-as", "c3", "--force", mustnot=[a["counter"]])
    t("scan.aob+default", "scan", "aob", "--pattern", "B1 6B ?? B5 AC ?? 77 31", *FP(), must=[a["p_aob"]])
    t("scan.aob+window", "scan", "aob", "--pattern", "B1 6B ?? B5", *FP(), "--start", a["p_aob"], "--size", "16", must=[a["p_aob"]])
    t("scan.aob+code", "scan", "aob", "--pattern", "95 E9 D1 5B", *FP(), "--start", a["magic_mix"], "--size", "64", check=lambda e, x: in_range(x, a["magic_mix"], 64))
    t("scan.dissect", "scan", "dissect", "--start", a["p_grp"], "--size", "32", *FP())
    t("scan.group", "scan", "group", "--field", "i32=1364349780", "--field", "f32=6.5", *FP(), "--limit", "10", must=[a["p_grp"]])
    t("scan.pointer-path", "scan", "pointer-path", *FP(), "--target", a["leaf_value"], "--module", "wtarget.exe", check=lambda e, x: None if hex(int(a["root_ptr"], 16) - int(L.T.base, 16)) in x or a["root_ptr"].lower() in x else f"no chain from root_ptr: {x[:120]}")
    t("locate.by-transition", "locate", "by-transition", *FP(), "--type", "i32", "--start", a["counter"], "--size", "4", "--wait-ms", "600", "--transition", "increased", "--save-as", "tr1", "--force", must=[a["counter"]])
    t("locate.by-transition+stdin", "locate", "by-transition", *FP(), "--type", "i32", "--start", a["counter"], "--size", "4", "--transition", "changed", "--save-as", "tr3", "--force", stdin="\n", must=[a["counter"]])


def debug_group(s, L):
    t, a, FP = L.t, L, L.FP
    h = lambda: int(a["hooked"], 16)  # noqa: E731
    t("debug.attach", "debug", "attach", *FP(), "--timeout-ms", "800", check=lambda e, x: None if e["data"].get("detached") is True else "did not detach")
    t("debug.await-hit", "debug", "await-hit", *FP(), "--addr", a["hooked"], "--timeout-ms", "6000", must=[a["hooked"]])
    t("debug.await-hit+rva", "debug", "await-hit", *FP(), "--addr", hex(h() - int(L.T.base, 16)), "--addr-rva", "--timeout-ms", "6000", must=[a["hooked"]])
    t("debug.await-hit+timeout", "debug", "await-hit", *FP(), "--addr", a["main"], "--timeout-ms", "1200", check=lambda e, x: None if e["data"].get("timed_out") is True else "should have timed out: main does not run again")
    t("debug.watch+write", "debug", "watch", *FP(), "--addr", a["counter"], "--kind", "write", "--timeout-ms", "6000", check=lambda e, x: in_range(e["data"]["hit"]["rip"], a["hooked"], 0x70))
    t("debug.watch+execute", "debug", "watch", *FP(), "--addr", a["hooked"], "--kind", "execute", "--len", "1", "--timeout-ms", "6000", must=[a["hooked"]])
    t("debug.watch+read-or-write", "debug", "watch", *FP(), "--addr", a["counter"], "--kind", "read-or-write", "--timeout-ms", "6000", check=lambda e, x: in_range(e["data"]["hit"]["rip"], a["hooked"], 0x70))
    t("debug.watch+when", "debug", "watch", *FP(), "--addr", a["hooked"], "--kind", "execute", "--len", "1", "--when", "rcx=1", "--timeout-ms", "6000", check=lambda e, x: None if e["data"]["hit"]["registers"]["rcx"] == 1 else "rcx is not what was asked")
    t("debug.watch+when-never", "debug", "watch", *FP(), "--addr", a["hooked"], "--kind", "execute", "--len", "1", "--when", "rcx=99", "--timeout-ms", "1500", check=lambda e, x: None if e["data"].get("timed_out") is True else "a condition never true hit")
    t("debug.watch+exclude", "debug", "watch", *FP(), "--addr", a["counter"], "--kind", "write", "--exclude-rip", f"{h():x}-{h() + 0x70:x}", "--timeout-ms", "1500", check=lambda e, x: None if e["data"].get("timed_out") is True else "an excluded site hit")
    want = int(L.T.tick["cnt"]) + 20
    t("debug.watch+write-when-later", "debug", "watch", *FP(), "--addr", a["counter"], "--kind", "write", "--when", f"rax={want}", "--timeout-ms", "12000", check=lambda e, x: None if e["data"]["hit"]["registers"]["rax"] == want else f"rax {e['data']['hit']['registers']['rax']}, asked {want}")
    t("debug.watch+bad-align", "debug", "watch", *FP(), "--addr", hex(int(a["counter"], 16) + 1), "--len", "4", "--timeout-ms", "500", refuse="bad-arguments")
    t("provenance.trace", "provenance", "trace", *FP(), "--addr", a["counter"], "--timeout-ms", "6000", "--save-to-table", "pt", check=lambda e, x: in_range(x, a["hooked"], 0x70))
    t("stack.backtrace", "stack", "backtrace", *FP(), refuse="live-unsupported")
    t("stack.backtrace+tid", "stack", "backtrace", *FP(), "--tid", L.T.tid, refuse="live-unsupported")
    t("stack.backtrace+all", "stack", "backtrace", *FP(), "--all-threads", refuse="live-unsupported")


def mutate_group(s, L):
    t, a, FP = L.t, L, L.FP
    t("mem.write", "mem", "write", "--addr", a["writeme"], "--bytes", "EF CD AB 89 67 45 23 01", *FP(), changes=("write",), check=lambda e, x: L.prints("write", "0123456789abcdef"))
    t("mem.write+back", "mem", "write", "--addr", a["writeme"], "--bytes", "11 11 11 11 11 11 11 11", *FP(), changes=("write",), check=lambda e, x: L.prints("write", "1111111111111111"))
    t("mem.write+unmapped", "mem", "write", "--addr", "0x10", "--bytes", "00", *FP(), refuse="write-failed")
    t("patch.dry-run", "patch", "dry-run", "--addr", a["patchme"], "--bytes", "01 02 03 04", *FP())
    env, _ = t("patch.apply", "patch", "apply", "--addr", a["patchme"], "--bytes", "01 02 03 04", *FP(), changes=("patch",), check=lambda e, x: L.prints("patch", "01020304"))
    pid = patch_id(env)
    t("patch.list", "patch", "list", must=[pid])
    t("patch.show", "patch", "show", "--id", pid, must=[pid])
    t("patch.undo", "patch", "undo", "--id", pid, *FP(), changes=("patch",), check=lambda e, x: L.prints("patch", "a0a1a2a3"))
    t("patch.undo+again", "patch", "undo", "--id", pid, *FP(), refuse="patch-undo-failed")
    t("patch.apply+code", "patch", "apply", "--addr", a["rc_imm"], "--bytes", "88 77 66 55", *FP(), changes=("rc",), check=lambda e, x: L.prints("rc", "55667788"))
    t("patch.undo+code", "patch", "undo", *FP(), changes=("rc",), check=lambda e, x: L.prints("rc", "11223344"))
    hb, c0 = L.T.tick["hb"], int(L.T.tick["cnt"])
    env, _ = t("patch.detour", "patch", "detour", *FP(), "--hook-at", a["hooked"], changes=("hb",), check=lambda e, x: detour_runs(L, hb, c0))
    t("patch.undo+detour", "patch", "undo", *FP(), changes=("hb",), check=lambda e, x: L.prints("hb", hb))
    t("table.add+pin", "table", "add", "--table", "live", "--name", "pinme", "--addr", a["pinme"], "--type", "u32")
    t("table.pin", "table", "pin", "--table", "live", "--name", "pinme", *FP(), "--value", "0x33333333", "--interval-ms", "50", "--duration-ms", "1200", changes=("pin",), check=lambda e, x: L.prints("pin", "33333333"))
    t("mem.write+unpin", "mem", "write", "--addr", a["pinme"], "--bytes", "22 22 22 22", *FP(), changes=("pin",), check=lambda e, x: L.prints("pin", "22222222"))


def patch_id(env):
    d = (env or {}).get("data") or {}
    for k in ("id", "patch_id"):
        if k in d:
            return str(d[k])
    for v in d.values():
        if isinstance(v, dict) and "id" in v:
            return str(v["id"])
    return "no-id-in-the-answer"


def rest_group(s, L):
    t, a, FP = L.t, L, L.FP
    T = lambda: L.T  # noqa: E731
    t("snapshot.dump+pid", "snapshot", "dump", "--name", "ls1", *FP(), "--start", a["p_i32"], "--size", "0x400", "--force")
    t("snapshot.info+pid", "snapshot", "info", "ls1")
    t("mem.read+snapshot", "mem", "read", "--addr", a["p_i32"], "--size", "4", "--snapshot", "ls1", must=[tobytes(0x1CEB00DA, 4)])
    t("snapshot.dump+full", "snapshot", "dump", "--name", "lsfull", *FP(), "--force", bound=120)
    t("find+snapfull", "find", "--string", "N0XIS_LIVE_ASCII_MARKER_77", "--snapshot", "lsfull", must=[a["p_str"]])
    t("decomp+snapfull", "decomp", "pseudo", "--addr", a["magic_mix"], "--snapshot", "lsfull", must=["5bd1e995"])
    t("annotate.name+pid", "annotate", "name", "--addr", a["hooked"], "--value", "мій_хук", *FP())
    t("annotate.show+pid", "annotate", "show", "--addr", a["hooked"], *FP(), must=["мій_хук"])
    t("annotate.list+pid", "annotate", "list", *FP(), must=["мій_хук"])
    t("annotate.rm+pid", "annotate", "rm", "--addr", a["hooked"], *FP())
    t("lua.strings", "lua", "strings", *FP(), "--contains", "zzsweep", check=lambda e, x: None if str(e["data"]["matches"][0].get("object_base")).lower() == T().lua["zzsweepmarker"].lower() else "wrong object base")
    t("lua.strings+window", "lua", "strings", *FP(), "--start", a["page"], "--size", "0x1000", "--contains", "zzsweep", must=["zzsweepmarker"])
    t("lua.table", "lua", "table", *FP(), "--addr", a["tab"], must=["up", "down", "left", "right"])
    t("lua.combo", "lua", "combo", *FP(), "--start", a["page"], "--size", "0x2000", check=lambda e, x: None if e["data"].get("count") else "count 0")
    t("lua.seedscan", "lua", "seedscan", *FP(), "--combo", T().combo, must=[a["lcg_seed"]])
    t("ui.locate", "ui", "locate", *FP(), "--rect", "150,150,160,160", "--start", a["page"], "--size", "0x8000", must=[a["ui"]])
    t("ui.locate+default", "ui", "locate", *FP(), "--rect", "150,150,160,160", "--save-as", "u1", "--force", must=[a["ui"]])
    t("ui.locate+exclude", "ui", "locate", *FP(), "--rect", "150,150,160,160", "--exclude-from", "u1", mustnot=[a["ui"]])
    t("il2cpp.import+pid", "il2cpp", "import", "--script-json", "{IN}script.json", "--name", "lidx", *FP(), "--force")
    t("il2cpp.symbols+pid", "il2cpp", "symbols", "--name", "lidx", *FP(), "--limit", "5")
    t("il2cpp.classes+pid", "il2cpp", "classes", *FP(), "--limit", "5", check=lambda e, x: None if not e["data"].get("classes") else "classes in a target that has none")
    # Remote: the same binary behind the command that a real remote session would run.
    rc = lambda: ["--remote-cmd", f"{s.wbin} remote-serve --pid {T().pid}"]  # noqa: E731
    t("remote.mem.read", "mem", "read", "--addr", a["p_i32"], "--size", "4", *rc(), must=[tobytes(0x1CEB00DA, 4)])
    t("remote.decomp", "decomp", "pseudo", "--addr", a["magic_mix"], *rc(), must=["5bd1e995"])
    t("remote.function.discover", "function", "discover", *rc(), "--limit", "4000", must=[a["hooked"]])
    t("remote.find", "find", "--string", "N0XIS_LIVE_ASCII_MARKER_77", *rc(), must=[a["p_str"]])
    t("remote.xref.from", "xref", "from", "--addr", a["step"], *rc(), must=[a["hooked"]])
    t("remote.bad-path", "mem", "read", "--addr", a["p_i32"], "--size", "4", "--remote-cmd", "C:\\no\\such.exe remote-serve --pid " + T().pid, refuse="remote-spawn-failed")
    t("remote-serve+eof", "remote-serve", *FP(), stdin="")
    for leaf, *rest in (("mem read", "--addr", "0x1000", "--size", "4"), ("mem map",), ("debug attach", "--timeout-ms", "300"), ("debug await-hit", "--addr", "0x1000", "--timeout-ms", "300"), ("debug watch", "--addr", "0x1000", "--timeout-ms", "300"),
                        ("scan aob", "--pattern", "90"), ("lua strings",), ("module list",), ("patch apply", "--addr", "0x1000", "--bytes", "90"), ("profile",), ("decomp pseudo", "--addr", "0x1000"), ("function discover",)):
        t("dead." + leaf.replace(" ", "."), *leaf.split(), "--pid", "999999", *rest, refuse="attach-failed")


def same_session_rows(s):
    """A window is seen only from its own session, so `ui windows` is asked from the batch file that started the target."""
    lap = s.laptop
    if s.skipped("ui.windows+same-session"):
        return
    bat = s.lroot / "uiw.bat"
    bat.write_bytes(f'@echo off\r\nset N0X_CONFIG_DIR={s.W("config")}\r\ncd /d {s.W("live")}\r\nstart /b "" {s.W("in/wtarget.exe")} >NUL\r\nping -n 3 127.0.0.1 >NUL\r\n{s.wbin} ui windows\r\ntaskkill /F /IM wtarget.exe >NUL\r\n'.encode())
    lap.put(bat, s.wroot + r"\uiw.bat")
    r = subprocess.run([*M.SSH, lap.host, f"cmd /c {s.wroot}\\uiw.bat"], capture_output=True, timeout=60)
    text = r.stdout.decode("utf-8", "replace").lower()
    s.row("ui.windows+same-session", "ui windows", "passed" if "n0xis target" in text and "живий" in text else "failed", "" if "n0xis target" in text else f"the target's window is not listed: {text[:150]}")


NOT_RUN = [
    ("ui.screenshot", "ui screenshot", "a positive answer needs an interactive desktop, and a run over ssh has none"),
    ("ui.focus", "ui focus", "a positive answer needs an interactive desktop, and a run over ssh has none"),
    ("input.probe", "input probe", "delivering input needs an interactive desktop, and a run over ssh has none"),
    ("aot.symbols", "aot symbols", "only its refusal ran: no NativeAOT program is built for this run"),
    ("il2cpp.icalls+image", "il2cpp icalls", "only the static answer on other images ran: no IL2CPP program is built for this run"),
    ("il2cpp.obj+image", "il2cpp obj", "only the static answer on other images ran: no IL2CPP program is built for this run"),
]


def not_run_rows(s):
    for case, command, why in NOT_RUN:
        if not s.skipped(case):
            s.row(case, command, "not-run", why)


# -- the defects found by the first sweep, each a case for good ----------------------------------------------------------

REPEAT_TIMEOUT = 60  # seen 4 times in 40: at 10% a run, 60 runs miss it 0.2% of the time


def defects_part(s):
    L = Live(s, prefix="defect.")
    try:
        t, a, FP = L.t, L, L.FP
        # 1. past 2^53, exact, or the value went through a float on its way to the target.
        big = 0x0DEADBEEFCAFEF00D
        t("1.scan-i64-past-2^53", "scan", "value", "--type", "i64", "--value", str(big - 2**64), *FP(), "--save-as", "big1", "--force", must=[a["p_i64"]])
        t("1.scan-u64-past-2^53", "scan", "value", "--type", "u64", "--value", str(big), *FP(), "--save-as", "big2", "--force", must=[a["p_i64"]])
        t("1.scan-u64-planted", "scan", "value", "--type", "u64", "--value", str(0x1111111111111111), *FP(), "--save-as", "big3", "--force", must=[a["writeme"]])
        t("1.mem-write-u64-top", "mem", "write", "--addr", a["writeme"], "--bytes", "fd ff ff ff ff ff ff ff", *FP(), changes=("write",), check=lambda e, x: L.prints("write", "fffffffffffffffd"))
        t("1.scan-u64-past-2^63", "scan", "value", "--type", "u64", "--value", str(2**64 - 3), *FP(), "--save-as", "big4", "--force", must=[a["writeme"]])
        t("1.scan-does-not-fit-i32", "scan", "value", "--type", "i32", "--value", str(2**40), *FP(), "--save-as", "big5", "--force", refuse="bad-value")
        t("1.scan-filter-past-2^53", "scan", "filter", "--from", "big1", "--criterion", "exact", "--value", str(big - 2**64), *FP(), "--save-as", "big6", "--force", must=[a["p_i64"]])
        L.run(["mem", "write", "--addr", a["writeme"], "--bytes", "11 11 11 11 11 11 11 11", *FP()])
        # 2. A breakpoint left behind by an interrupt or a kill: the target dies at the next pass, which is the measure.
        site = lambda: hex(rare_site(s, L))  # noqa: E731
        for how in ("c", "break"):
            interrupted(s, L, f"2.await-hit-ctrl-{how}", "debug await-hit", how, lambda: ["debug", "await-hit", *FP(), "--addr", site(), "--timeout-ms", "30000"])
            interrupted(s, L, f"2.watch-ctrl-{how}", "debug watch", how, lambda: ["debug", "watch", *FP(), "--addr", a["toggled"], "--kind", "write", "--timeout-ms", "30000"])
        for n in range(3):
            killed(s, L, f"2.await-hit-killed-then-undo#{n}", "patch undo", lambda: ["debug", "await-hit", *FP(), "--addr", site(), "--timeout-ms", "30000"], undo=True)
        # The same for a watch. A debug register is in the thread, not the journal.
        for n in range(3):
            killed(s, L, f"killed-watch-target-lives#{n}", "debug watch", lambda: ["debug", "watch", *FP(), "--addr", a["toggled"], "--kind", "write", "--timeout-ms", "30000"], undo=False)
        # 4. A filtered watch that times out with hits passing: intermittent, so many runs of one row.
        deaths, h = [], int(a["hooked"], 16)
        for i in range(REPEAT_TIMEOUT):
            filt = ["--exclude-rip", f"{int(a['hooked'], 16):#x}-{int(a['hooked'], 16) + 0x70:#x}"] if i % 2 == 0 else ["--when", "rax=0x7fffffff0"]
            L.run(["debug", "watch", *FP(), "--addr", a["counter"], "--kind", "write", *filt, "--timeout-ms", "1000"], bound=20)
            died = L.survived()
            if died:
                deaths.append(died)
        s.row("defect.4.filtered-watch-times-out", "debug watch", "failed" if deaths else "passed", f"{len(deaths)} of {REPEAT_TIMEOUT} targets died: {deaths[0]}" if deaths else f"0 of {REPEAT_TIMEOUT} died")
        # 5. A miss at an execute watch must step off, not refire.
        want = int(L.T.tick["cnt"]) + 30
        t("5.execute-when-later", "debug", "watch", *FP(), "--addr", hex(new_value_site(s, L)), "--kind", "execute", "--len", "1", "--when", f"rax={want}", "--timeout-ms", "15000", bound=30, check=lambda e, x: None if e["data"]["hit"]["registers"]["rax"] == want else f"rax {e['data']['hit']['registers']['rax']}, asked {want}")
        # 6. The exception directory of a live image, against a reader of the file written here.
        d = (s.lroot / "in/wtarget.exe").read_bytes()
        t("6.function-eh-pid", "function", "eh", *FP(), check=lambda e, x: eh_check(e, d, int(L.T.base, 16)))
        # 7. A verbatim output path: a file named by a literal slash is no file.
        t("7.bundle-extract-verbatim", "bundle", "extract", "--file", "{IN}test.bundle", "--type", "lua", "--out", "\\\\?\\" + s.W("out_verbatim"), check=lambda e, x: on_disk(s, "out_verbatim"))
        t("7.bundle-extract-forward-slash", "bundle", "extract", "--file", "{IN}test.bundle", "--type", "lua", "--out", s.W("out_slash").replace("\\", "/"), check=lambda e, x: on_disk(s, "out_slash"))
    finally:
        L.finish()
    # 3. A 32-bit target from the 64-bit debugger: a refusal before touching it is the right answer; the target lives.
    L32 = Live(s, "wtarget32.exe", "defect.3.32bit-")
    try:
        t, a, FP = L32.t, L32, L32.FP
        for n in range(2):
            t(f"await-hit#{n}", "debug", "await-hit", *FP(), "--addr", a["hooked"], "--timeout-ms", "4000", bound=25, refuse="target-unsupported")
            t(f"watch-write#{n}", "debug", "watch", *FP(), "--addr", a["counter"], "--kind", "write", "--timeout-ms", "4000", bound=25, refuse="target-unsupported")
            t(f"watch-execute#{n}", "debug", "watch", *FP(), "--addr", a["hooked"], "--kind", "execute", "--len", "1", "--timeout-ms", "4000", bound=25, refuse="target-unsupported")
            t(f"provenance#{n}", "provenance", "trace", *FP(), "--addr", a["counter"], "--timeout-ms", "4000", bound=25, refuse="target-unsupported")
    finally:
        L32.finish()
    # 8. A reader that goes away: quiet, exit 0, on both builds. `guide` is larger than any pipe's buffer.
    for args in (["guide"], ["guide", "--pretty"], ["doctor"], ["doctor", "--pretty"]):
        name = "+".join(args)
        for side, r in (("windows", s.win(args, close_after=1, bound=30)), ("twin", s.lin(args, close_after=1, bound=30))):
            why = None if r["rc"] == 0 and not r["e"] else f"exit {r['rc']}, stderr {r['e'][:100]!r}"
            s.row(f"defect.8.closed-pipe.{side}.{name}", args[0], "failed" if why else "passed", why or "")


def interrupted(s, L, case, command, how, build):
    """What a person at a console does, by a helper that holds one: the event reaches the tool while it waits."""
    case = "defect." + case
    if s.skipped(case):
        return
    L.wait_past_site()
    r = s.win([how, "1500", s.wbin, *build()], cwd="{W}live", exe=s.W("in/ctrlsend.exe"), bound=30)
    lived = L.T.alive(need=60, wait=9)
    why = None if lived and b"TOOL_EXIT wait=0" in r["o"] else f"the tool's end: {r['o'][-60:]!r}" if lived else f"the target died at the next pass, exit {L.T.exit_code()}"
    if not lived:
        L.replace_target()
    s.row(case, command, "failed" if why else "passed", why or "")


def killed(s, L, case, command, build, undo):
    """A kill cannot be handled, so it must leave something to recover from, or nothing to recover."""
    case = "defect." + case if not case.startswith("killed-watch") else case
    if s.skipped(case):
        return
    L.wait_past_site()
    r = s.win(build(), cwd="{W}live", kill_after=800, bound=30)
    why = None if r["killed"] else "the command ended before the kill"
    if undo:
        u = s.win(["patch", "undo"], cwd="{W}live")
        why = why or s.contract(u) or s.expectation(u, None)
    lived = L.T.alive(need=60, wait=9)
    if not lived:
        why = f"the target died at the next pass, exit {L.T.exit_code()}"
        L.replace_target()
    s.row(case, command, "failed" if why else "passed", why or "")


def eh_check(env, image, base):
    pe = struct.unpack_from("<I", image, 0x3c)[0]
    nsec, opt = struct.unpack_from("<H", image, pe + 6)[0], struct.unpack_from("<H", image, pe + 20)[0]
    want = []
    for i in range(nsec):
        sec = pe + 24 + opt + 40 * i
        if image[sec:sec + 8].rstrip(b"\0") == b".pdata":
            vsize, raw = struct.unpack_from("<I", image, sec + 8)[0], struct.unpack_from("<I", image, sec + 20)[0]
            want = sorted((e[0], e[1]) for e in (struct.unpack_from("<III", image, raw + 12 * k) for k in range(vsize // 12)) if e[0])
    live = sorted((int(f["va"], 16) - base, int(f["end"], 16) - base) for f in env["data"]["functions"])
    return None if want and live == want else f".pdata has {len(want)} entries, the answer {len(live)}"


def on_disk(s, sub):
    r = s.laptop.run(r"C:\Windows\System32\cmd.exe", ["/c", "dir", "/b", s.W(sub)])
    names = r["o"].decode("utf-8", "replace").split()
    return None if "1111222233334444.luac" in names else f"on disk: {names[:4]}"


# -- a real console -----------------------------------------------------------------------------------------------------

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\r")


def console(s, lines, inputs=(), bound=40, config=None):
    """A batch file on a real console, a pty over ssh. Standard input stays open: at its end the console on the far side closes
    before the batch has run. inputs: (seconds after start, bytes typed)."""
    bat = s.lroot / "con.bat"
    cfg = config or s.W("console-config")
    bat.write_bytes(("@echo off\r\nchcp 65001 >NUL\r\n" + f"set N0X_CONFIG_DIR={cfg}\r\nset N={s.wbin}\r\ncd /d {s.W('console')}\r\n" + "\r\n".join(lines) + "\r\necho ALL^DONE\r\n").encode())
    s.laptop.put(bat, s.wroot + r"\con.bat")
    p = subprocess.Popen([*M.SSH, "-tt", s.laptop.host, f"cmd /c {s.wroot}\\con.bat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    buf, finished = bytearray(), threading.Event()
    def read():
        while True:
            b = p.stdout.read1(65536)
            if not b:
                break
            buf.extend(b)
            if b"ALLDONE" in buf:
                break
        finished.set()
    threading.Thread(target=read, daemon=True).start()
    t0 = time.time()
    for at, data in inputs:
        time.sleep(max(0, at - (time.time() - t0)))
        try:
            p.stdin.write(data)
            p.stdin.flush()
        except OSError:
            pass
    done = finished.wait(max(0.1, bound - (time.time() - t0)))
    p.kill()
    return ANSI.sub("", bytes(buf).decode("utf-8", "replace")), done and b"ALLDONE" in buf


def console_part(s):
    s.laptop.run(r"C:\Windows\System32\cmd.exe", ["/c", "mkdir", s.W("console/.n0x"), s.W("console-config")])
    # The daily check must not ask the network from a console in this part: the update part is where that is asked.
    s.laptop.run(s.wbin, ["config", "set", "update.check", "false"], env={"N0X_CONFIG_DIR": s.W("console-config")})
    def case(id, command, lines, wants, inputs=(), bound=40):
        if s.skipped("console." + id):
            return
        text, done = console(s, lines, inputs, bound)
        lost = [w for w in wants if w not in text]
        s.row("console." + id, command, "passed" if done and not lost else "failed", ("" if done else f"did not finish in {bound} s; ") + (f"missing {lost}; shown {text[-120:]!r}" if lost else ""))
    case("doctor", "doctor", ["%N% doctor", "echo RC=%ERRORLEVEL%"], ['"status":"ready"', "RC=0"])
    case("pretty", "project info", ["%N% --pretty project info", "echo RC=%ERRORLEVEL%"], ['"ok": true', "RC=0"])
    case("help", "", ["%N% --help", "echo RC=%ERRORLEVEL%"], ["Usage:", "doctor", "RC=0"])
    case("error", "", ["%N% nonsense", "echo RC=%ERRORLEVEL%"], ["bad-arguments", "RC=2"])
    case("unicode-output", "strings", [f"%N% strings --file {s.W('in/app.exe')} --contains MARKER --limit 10", "echo RC=%ERRORLEVEL%"], ["N0XIS_ЮНІКОД_MARKER_92", "RC=0"])
    case("unicode-arg", "annotate comment", ["%N% annotate comment --addr 0x1000 --value коментар --bytes \"48 89 c8 c3\"", "echo RC=%ERRORLEVEL%"], ["коментар", "RC=0"])
    case("redirect", "doctor", ["%N% doctor > out.txt", "echo RC=%ERRORLEVEL%", "type out.txt"], ['"status":"ready"', "RC=0"])
    case("typed-stdin", "dump save", ["%N% dump save --name typed --kind ir", "echo RC=%ERRORLEVEL%", "%N% dump show --name typed --kind ir"], ["друкую", "RC=0"], inputs=[(5, "друкую\r\n".encode()), (6, b"\x1a\r\n")])
    case("typed-serve", "serve", [f"%N% serve --file {s.W('in/app.exe')}", "echo RC=%ERRORLEVEL%"], ["4e 30 58 49", "RC=0"], inputs=[(5, f"mem read --addr {nm_data(s)} --size 4\r\n".encode()), (7, b"\x1a\r\n")])
    # A real Ctrl-C from a real console, at a command holding a target.
    T = Target(s)
    try:
        for id, command, line, need in (("ctrl-c-await-hit", "debug await-hit", f"%N% debug await-hit --pid {T.pid} --addr {T.addr['main']} --timeout-ms 30000", None), ("ctrl-c-table-pin", "table pin", f"%N% table add --table cc --name pin --addr {T.addr['pinme']} --type u32 >NUL\r\n%N% table pin --table cc --name pin --pid {T.pid} --value 0x44444444 --interval-ms 50 --duration-ms 30000", "44444444")):
            if s.skipped("console." + id):
                continue
            _, done = console(s, [line], inputs=[(6, b"\x03")], bound=25)
            lived, why = T.alive(), None
            if not lived:
                why = f"the target died, exit {T.exit_code()}"
                T.stop()
                T = Target(s)
            elif need and T.tick.get("pin") != need:
                why = f"the target prints pin={T.tick.get('pin')}"
            s.row("console." + id, command, "failed" if why else "passed", why or "")
    finally:
        T.stop()


def nm_data(s):
    return hex(M.nm_of("x86_64-w64-mingw32-nm", s.lroot / "in/app.exe")["planted_ascii"])


# -- spellings of a path, on the machine whose spellings they are --------------------------------------------------------

def paths_part(s, table):
    """The same command with its file spelled differently, each from a project of its own, against the plain spelling."""
    base = s.W("in") + "\\"
    # Past MAX_PATH, in characters that are not one code page's: the first spelling a narrow API would break.
    space = s.W("sp ü/ім'я папки")
    long_dir = s.W("long/" + "/".join(["каталог_" + "a" * 40] * 7))
    q = lambda p: p.replace("'", "''")  # noqa: E731
    made = s.laptop.ps(f"$n = @('{q(space)}','\\\\?\\{q(long_dir)}'); foreach ($d in $n) {{ New-Item -ItemType Directory -Force -Path $d | Out-Null; foreach ($f in 'app.exe','test.bundle','lj20.ljbc','payload.txt') {{ Copy-Item -Force -LiteralPath '{base}'$f -Destination ($d + '\\' + $f) }} }}; 'made'")
    if "made" not in made:
        made = made or "no answer"
    spellings = dict(space=space + "\\", long=long_dir + "\\", forward=base.replace("\\", "/"), relative="..\\in\\", verbatim="\\\\?\\" + base)
    code = hex(table["app"]["code"])
    commands = [
        ("profile", ["profile", "--file", "{P}app.exe"]),
        ("decomp", ["decomp", "pseudo", "--addr", code, "--file", "{P}app.exe"]),
        ("strings", ["strings", "--file", "{P}app.exe", "--contains", "MARKER", "--limit", "5"]),
        ("lua.disasm", ["lua", "disasm", "--file", "{P}lj20.ljbc"]),
        ("bundle.list", ["bundle", "list", "--file", "{P}test.bundle"]),
        ("dump.save", ["dump", "save", "--name", "dp", "--kind", "ir", "--file", "{P}payload.txt", "--force"]),
    ]
    def fresh(name):
        s.laptop.run(r"C:\Windows\System32\cmd.exe", ["/c", "mkdir", s.W(f"p_{name}/.n0x")])
        return "{W}" + f"p_{name}"
    plain = {}
    cwd = fresh("plain")
    for id, args in commands:
        plain[id] = s.win([a.replace("{P}", base) for a in args], cwd=cwd)
    for name, prefix in spellings.items():
        cwd = fresh(name)
        for id, args in commands:
            case = f"path.{name}.{id}"
            if s.skipped(case):
                continue
            # The spelling the answer states of the path is the spelling it was given, so it is taken out before comparing.
            r = s.win([a.replace("{P}", prefix) for a in args], cwd=cwd)
            why = s.contract(r) or s.expectation(r, None)
            if not why:
                sub = lambda v: json.loads(json.dumps(v, ensure_ascii=False).replace(json.dumps(prefix, ensure_ascii=False)[1:-1], "<P>").replace(json.dumps(base, ensure_ascii=False)[1:-1], "<P>").replace(prefix.replace("\\", "\\\\"), "<P>"))  # noqa: E731
                a, b = sub(s.norm(s.parsed(r["o"]))), sub(s.norm(s.parsed(plain[id]["o"])))
                why = M.first_diff(path_free(a), path_free(b))
            s.row(case, s.leaf_of(args), "failed" if why else "passed", why or "")


def path_free(v):
    """A count of the bytes a stored path took is the path's length, not an answer."""
    if isinstance(v, dict):
        return {k: path_free(x) for k, x in v.items() if k not in ("bytes_written", "already_existed", "file", "path", "image", "source")}
    if isinstance(v, list):
        return [path_free(x) for x in v]
    return v


# -- the MCP server and its parent ----------------------------------------------------------------------------------------

class Mcp:
    def __init__(self, s, side, env=None):
        self.n = 0
        self.lines = queue.Queue()
        if side == "lin":
            self.p = subprocess.Popen([s.lmcp], cwd=s.L("mcp"), env=s.lin_env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        else:
            bat = s.lroot / "mcp.bat"
            bat.write_bytes(f"@echo off\r\ncd /d {s.W('mcp')}\r\nset N0X_CONFIG_DIR={s.W('config')}\r\n{s.wmcp}\r\n".encode())
            s.laptop.put(bat, s.wroot + r"\mcp.bat")
            self.p = subprocess.Popen([*M.SSH, s.laptop.host, f"cmd /c {s.wroot}\\mcp.bat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for l in self.p.stdout:
            self.lines.put(l)
        self.lines.put(None)

    def send(self, obj):
        self.p.stdin.write((json.dumps(obj, ensure_ascii=False) + "\n").encode())
        self.p.stdin.flush()

    def req(self, method, params=None, wait=60):
        self.n += 1
        mid = self.n
        self.send(dict(jsonrpc="2.0", id=mid, method=method, **({"params": params} if params is not None else {})))
        end = time.time() + wait
        while time.time() < end:
            try:
                l = self.lines.get(timeout=max(0.1, end - time.time()))
            except queue.Empty:
                continue
            if l is None:
                return "ended"
            try:
                m = json.loads(l.decode("utf-8"))
            except ValueError:
                continue
            if m.get("id") == mid:
                return m
        return "no answer"

    def open(self):
        r = self.req("initialize", dict(protocolVersion="2024-11-05", capabilities={}, clientInfo=dict(name="sweep", version="1")))
        self.send(dict(jsonrpc="2.0", method="notifications/initialized"))
        return r

    def call(self, tool, args, wait=70):
        return self.req("tools/call", dict(name=tool, arguments=args), wait)

    def close(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            self.p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.p.kill()


def envelope(r):
    try:
        return json.loads(r["result"]["content"][0]["text"])
    except (TypeError, KeyError, IndexError, ValueError):
        return r


def mcp_procs(s):
    out = s.laptop.ps(f"Get-CimInstance Win32_Process | Where-Object {{ $_.ExecutablePath -eq '{s.wmcp}' }} | ForEach-Object {{ '{{0}} {{1}}' -f $_.ProcessId,$_.ParentProcessId }}")
    return [l.split() for l in out.splitlines() if l.strip()]


def mcp_part(s, table):
    app, F = table["app"], lambda side, n="app.exe": s.expand("{IN}" + n, side)  # noqa: E731
    A, D = hex(app["magic"]), hex(app["data"])
    calls = lambda side: [  # noqa: E731
        ("doctor", {}), ("capability_list", {}), ("plugin_list", {}),
        ("disasm", dict(addr=A, count=4, file=F(side))), ("decomp_pseudo", dict(addr=A, file=F(side))),
        ("function_discover", dict(file=F(side), limit=20)), ("function_trace", dict(addr=A, file=F(side))), ("explain_opt_delta", dict(addr=A, file=F(side))),
        ("mem_read", dict(addr=D, size=16, file=F(side))), ("mem_span", dict(addr=D, size=16, file=F(side))), ("module_list", dict(file=F(side))),
        ("strings", dict(file=F(side), contains="MARKER", limit=10)), ("xref", dict(addr=A, file=F(side))), ("xref_string", dict(query="MARKER", file=F(side), limit=5)),
        ("annotate_set", dict(addr=A, field="name", value="мій", file=F(side))), ("annotate_get", dict(addr=A, file=F(side))), ("annotate_list", dict(file=F(side))),
        ("capability_run", dict(name="decode", args=dict(bytes="48 89 c8 c3", addr="0x1000"))),
        ("plugin_run", dict(name="noplugin", kind="pseudo", artifact=dict(a=1))), ("disasm", dict(addr=A, file=F(side, "no_such.exe"))),
    ]
    w, l = Mcp(s, "win"), Mcp(s, "lin")
    try:
        same = lambda a, b: M.first_diff(s.norm(a), s.norm(b))  # noqa: E731
        init = (w.open(), l.open())
        s.row("mcp.initialize", "", "failed" if same(*init) else "passed", same(*init) or "")
        tools = (w.req("tools/list"), l.req("tools/list"))
        s.row("mcp.tools-list", "", "failed" if same(*tools) else "passed", same(*tools) or f"{len(tools[0]['result']['tools'])} tools, the same schemas" if isinstance(tools[0], dict) else str(tools[0]))
        cw, cl = calls("win"), calls("lin")
        for i, (tool, _) in enumerate(cw):
            why = same(envelope(w.call(tool, cw[i][1])), envelope(l.call(tool, cl[i][1])))
            s.row(f"mcp.{tool}#{i}", "", "failed" if why else "passed", why or "")
        unknown = w.req("no/such", {}, 15)
        s.row("mcp.unknown-method", "", "passed" if isinstance(unknown, dict) and "error" in unknown else "failed", str(unknown)[:120])
    finally:
        w.close()
        l.close()
    # Live tools, against a target that says what it holds.
    plugin_rows(s)
    L = Live(s, prefix="mcp.")
    m = Mcp(s, "win")
    try:
        m.open()
        P, a = int(L.T.pid), L
        def v(id, tool, args, must=(), check=None):
            r = envelope(m.call(tool, args))
            text = json.dumps(r, ensure_ascii=False).lower()
            gone = [x for x in must if str(x).lower() not in text]
            why = (r.get("error") if isinstance(r, dict) and r.get("ok") is False else None) or (f"missing {gone}" if gone else None) or (check() if check else None)
            died = L.survived()
            why = died or why
            s.row("mcp.live." + id, "", "failed" if why else "passed", str(why or "")[:300])
        v("process_ps", "process_ps", dict(filter="wtarget"), [str(P)])
        v("module_list", "module_list", dict(pid=P), ["wtarget.exe", L.T.base])
        v("mem_read", "mem_read", dict(pid=P, addr=a["p_i32"], size=4), ["da 00 eb 1c"])
        v("mem_span", "mem_span", dict(pid=P, addr=a["p_i32"], size=4), ["da 00 eb 1c"])
        v("disasm", "disasm", dict(pid=P, addr=a["hooked"], count=3), ["push"])
        v("decomp", "decomp_pseudo", dict(pid=P, addr=a["magic_mix"]), ["5bd1e995"])
        v("discover", "function_discover", dict(pid=P, limit=4000), [a["hooked"]])
        v("mem_write", "mem_write", dict(pid=P, addr=a["writeme"], bytes="EF CD AB 89 67 45 23 01"), check=lambda: L.prints("write", "0123456789abcdef"))
        v("mem_write.back", "mem_write", dict(pid=P, addr=a["writeme"], bytes="11 11 11 11 11 11 11 11"), check=lambda: L.prints("write", "1111111111111111"))
        v("provenance", "provenance_trace", dict(pid=P, addr=a["counter"], timeout_ms=6000))
        v("ui_locate", "ui_locate", dict(pid=P, rect="150,150,160,160"), [a["ui"]])
        v("attach", "attach", dict(pid=P))
        v("after-attach.mem_read", "mem_read", dict(addr=a["p_i32"], size=4), ["da 00 eb 1c"])
    finally:
        m.close()
        L.finish()
    parent_rows(s, F("win"))


def plugin_rows(s):
    """A plugin is run by the MCP door, the only one that runs them. Its stored command with a space in it is quoted, as the docs say."""
    s.laptop.run(r"C:\Windows\System32\cmd.exe", ["/c", "mkdir", s.W("mcp/.n0x")])
    plug = s.W("in/plug.exe")
    a = s.win(["plugin", "add", "--name", "pexe", "--command", plug, "--handles", "pseudo"], cwd="{W}mcp")
    s.row("plugin.add", "plugin add", "failed" if s.contract(a) or s.expectation(a, None) else "passed", s.contract(a) or s.expectation(a, None) or "")
    l = s.win(["plugin", "list"], cwd="{W}mcp")
    s.row("plugin.list", "plugin list", "passed" if b"pexe" in l["o"] else "failed", "" if b"pexe" in l["o"] else str(l["o"][:100]))
    m = Mcp(s, "win")
    try:
        m.open()
        r = envelope(m.call("plugin_run", dict(name="pexe", kind="pseudo", artifact={"text": "абв"})))
        s.row("plugin.run", "", "passed" if "plugin_saw_bytes" in json.dumps(r) else "failed", str(r)[:200])
    finally:
        m.close()
    d = s.win(["plugin", "rm", "--name", "pexe"], cwd="{W}mcp")
    l = s.win(["plugin", "list"], cwd="{W}mcp")
    s.row("plugin.rm", "plugin rm", "passed" if d["rc"] == 0 and b"pexe" not in l["o"] else "failed", "" if d["rc"] == 0 else str(d["o"][:120]))


def parent_rows(s, app_file):
    """The parent and the worker of the release's own file. The overflow is real, and in the very worker that goes out: the worker's
    NtReadFile is written over, through the tool's own `patch apply`, with a loop that walks down the stack until the guard page
    says 0xC00000FD. A debug build's planted worker would be a different program, and 0.3.8 would pass the row without having a parent."""
    m = Mcp(s, "win")
    try:
        r = m.open()
        listed = m.req("tools/list")
        procs = mcp_procs(s)
        pids = [p[0] for p in procs]
        worker = [p for p in procs if p[1] in pids]
        have = isinstance(listed, dict) and "result" in listed and bool(worker)
        if not have:
            for case in ("no-console-window", "overflow-is-a-crash", "restart", "no-orphan"):
                s.row("mcp.parent." + case, "", "failed", f"there is no worker under a parent: {procs}")
            return
        listing = ",".join(pids)
        windows = s.laptop.ps(f"$w = @({listing}); Get-CimInstance Win32_Process -Filter \"Name='conhost.exe'\" | Where-Object {{ $w -contains $_.ParentProcessId }} | ForEach-Object {{ '{{0}} {{1}}' -f $_.ParentProcessId,(Get-Process -Id $_.ProcessId).MainWindowHandle }}; Get-Process -Id $w | ForEach-Object {{ 'P {{0}}' -f $_.MainWindowHandle }}").split("\n")
        hosts = [l.split() for l in windows if l and not l.startswith("P")]
        own = [h for h in hosts if h[0] == worker[0][0]]
        visible = [l for l in windows if l.strip() and not l.strip().endswith(" 0")]
        s.row("mcp.parent.no-console-window", "", "passed" if own and not visible else "failed", f"the worker's console has no window, on a session with no desktop: {hosts}" if own and not visible else f"worker {worker}; conhost {hosts}; handles {visible}")
        s.row("mcp.parent.no-console-window-on-a-desktop", "", "not-run", "that a person's desktop stays clean needs a run from one, and a run over ssh has none")
        # A real restart: the worker killed from outside.
        s.laptop.run(r"C:\Windows\System32\taskkill.exe", ["/F", "/PID", worker[0][0]], bound=15)
        m.call("process_ps", {}, 40)
        again = m.call("process_ps", {}, 40)
        fine = isinstance(again, dict) and "result" in again
        s.row("mcp.parent.restart", "", "passed" if fine else "failed", "" if fine else str(again)[:200])
        # A real stack overflow in the new worker.
        procs = mcp_procs(s)
        pids = [p[0] for p in procs]
        worker = [p for p in procs if p[1] in pids]
        T = Target(s)
        where = T.addr["ntreadfile"]
        T.stop()
        walk_down = "48 81 EC 00 10 00 00 48 89 04 24 EB F3"  # sub rsp,0x1000; mov [rsp],rax; jmp back
        planted = s.win(["patch", "apply", "--pid", worker[0][0], "--addr", where, "--bytes", walk_down], cwd="{W}live")
        answer = m.call("mem_read", dict(addr=hex(0x1000), size=4, file=app_file), 40)
        err = (answer or {}).get("error", {}) if isinstance(answer, dict) else {}
        said = json.dumps(err).lower()
        overflow = err.get("code") == -32002 and "c00000fd" in said
        s.row("mcp.parent.overflow-is-a-crash", "", "passed" if overflow else "failed", f"{said[:180]}" if overflow else f"patch: {planted['o'][:80]!r}; answer {str(answer)[:220]}")
        after = m.call("process_ps", {}, 40)
        next_ok = isinstance(m.call("process_ps", {}, 40), dict)
        s.row("mcp.parent.session-goes-on-after-the-crash", "", "passed" if next_ok else "failed", str(after)[:120] if not next_ok else "")
        # No orphan: the parent killed, the worker goes by itself.
        procs = mcp_procs(s)
        pids = [p[0] for p in procs]
        parents = [p for p in procs if p[1] not in pids]
        for p in parents:
            s.laptop.run(r"C:\Windows\System32\taskkill.exe", ["/F", "/PID", p[0]], bound=15)
        time.sleep(8)
        left = mcp_procs(s)
        s.row("mcp.parent.no-orphan", "", "passed" if parents and not left else "failed", f"killed {parents}; left {left}")
    finally:
        m.p.kill()


# -- the update client, before there is a release to update to --------------------------------------------------------------

MANIFEST = "https://github.com/Structio-labs/N0xis/releases/latest/download/manifest.json"
BEFORE_PUBLISHING = "needs a release newer than this binary, signed by the release key, which exists only after this one is published; scripts/update_e2e.py runs it with a test key and that is not this file's trust"


def version_key(v):
    return tuple(int(x) for x in re.match(r"(\d+)\.(\d+)\.(\d+)", v).groups())


def update_part(s):
    """A copy of its own, beside a configuration of its own, so that nothing here can touch the files the rest of the run answers for."""
    place, config = s.W("upd"), s.W("upd-config")
    s.laptop.run(r"C:\Windows\System32\cmd.exe", ["/c", "mkdir", place, config])
    exe = place + r"\n0xis.exe"
    s.laptop.run(r"C:\Windows\System32\cmd.exe", ["/c", "copy", "/y", s.wbin, exe])
    def ask(*args, **kw):
        return s.laptop.run(exe, list(args), cwd=s.W("proj"), env={"N0X_CONFIG_DIR": config}, **kw)
    def digest():
        r = s.laptop.run(r"C:\Windows\System32\certutil.exe", ["-hashfile", exe, "SHA256"])
        found = re.search(r"\b[0-9a-f]{64}\b", r["o"].decode("utf-8", "replace").replace(" ", ""))
        return found.group(0) if found else None
    original = digest()
    # In a pipe nothing starts, and standard error stays empty.
    r = ask("doctor")
    stamp = s.laptop.run(r"C:\Windows\System32\cmd.exe", ["/c", "dir", "/b", config])["o"]
    why = None if b"update-check.stamp" not in stamp and not r["e"] else f"config holds {stamp[:60]!r}, stderr {r['e'][:80]!r}"
    s.row("update.a-pipe-starts-no-check", "update", "failed" if why else "passed", why or "")
    # `--check`, by the real addresses, against what GitHub says when asked from here.
    try:
        with urllib.request.urlopen(MANIFEST, timeout=60) as answer:
            latest = json.load(answer)["version"]
    except (OSError, ValueError) as e:
        latest = None
        s.row("update.check", "update", "not-run", f"GitHub did not answer the machine driving this run: {e}")
    version = s.win(["--version"])["o"].decode("utf-8", "replace").split()[-1]
    available = False
    if latest:
        r = ask("update", "--check", bound=90)
        env = s.parsed(r["o"]) or {}
        d = env.get("data") or {}
        available = version_key(latest) > version_key(version)
        why = s.contract(r) or s.expectation(r, None)
        if not why and (d.get("latest") != latest or d.get("available") is not available):
            why = f"said latest {d.get('latest')} available {d.get('available')}; GitHub {latest}, this is {version}"
        s.row("update.check", "update", "failed" if why else "passed", why or f"latest {latest}, verified against the key this binary holds")
    # A real console: the first run says nothing, the check goes on behind it.
    con = s.W("upd-con-config")
    text, done = console(s, [f'"{exe}" doctor >NUL', "echo FIRST-DONE"], bound=30, config=con)
    first = text.partition("FIRST-DONE")[0]
    why = None if done and "[n0x]" not in first else f"on a console, first run: {first[-120:]!r}"
    s.row("update.console-first-run-says-nothing", "update", "failed" if why else "passed", why or "")
    # Nothing newer: nothing moves. An older file than what is published would install it, and this copy must not change under the run.
    if latest and not available:
        r = ask("update", bound=90)
        why = s.contract(r) or s.expectation(r, None) or (None if digest() == original else "the file changed")
        s.row("update.nothing-newer", "update", "failed" if why else "passed", why or "")
    else:
        s.row("update.nothing-newer", "update", "not-run", f"a newer release is published ({latest}) or GitHub did not answer")
    r = ask("update", "--rollback")
    why = s.contract(r) or s.expectation(r, "no-previous") or (None if digest() == original else "the file changed")
    s.row("update.rollback-with-nothing-to-go-back-to", "update", "failed" if why else "passed", why or "")
    for case in ("update.install", "update.rollback", "update.auto", "update.with-the-mcp-server-running", "update.a-directory-this-user-may-not-write", "update.console-says-a-newer-one-is-there"):
        s.row(case, "update", "not-run", BEFORE_PUBLISHING)


# -- real programs -------------------------------------------------------------------------------------------------------

def real_part(s):
    import cases
    images = []
    if s.args.images:
        for im in cases.IMAGES:
            path = s.args.images / im["file"]
            if path.is_file():
                images.append(dict(im, path=path, truth=(s.args.images / im["truth"]) if im.get("truth") else None))
            else:
                s.row(f"real.{im['tag']}", "", "not-run", f"{im['file']} is not under --images")
    else:
        s.row("real-programs", "", "not-run", "no directory of real programs was given to this run")
    # The tool looking at itself, always at hand.
    images.append(dict(tag="n0xis-itself", path=s.args.dir / M.ASSETS["n0xis.exe"], heavy=True, truth=None))
    if s.args.extra_images:
        for im in json.loads(s.args.extra_images.read_text()):
            images.append(dict(im, path=Path(im["file"]), truth=Path(im["truth"]) if im.get("truth") else None))
    for im in images:
        real_image(s, cases, im)


def real_cases(tag, top, mid, arm):
    """Whole-image commands, cheapest first; then the rest once each, on the image's largest function."""
    a, file = top[0], ["--file", "@F"]
    c = []
    def add(id, *args):
        c.append((id, list(args)))
    add("profile", "profile", *file)
    add("imports", "imports", *file)
    add("module.list", "module", "list", *file)
    add("function.discover", "function", "discover", *file)
    add("function.discover+pdata", "function", "discover", *file, "--pdata")
    add("strings", "strings", *file)
    add("strings+utf16", "strings", *file, "--encoding", "utf16le")
    add("strings+contains", "strings", *file, "--contains", "error", "--limit", "200")
    add("find", "find", "--string", "panicked", *file, "--limit", "100")
    add("rtti.scan", "rtti", "scan", *file)
    add("xref.string", "xref", "string", "--query", "panicked", *file, "--limit", "50")
    add("xref.to", "xref", "to", "--addr", a, *file)
    add("xref.from", "xref", "from", "--addr", mid, *file)
    add("ir.manifest", "ir", "manifest", *file)
    add("function.noreturn", "function", "noreturn", *file)
    add("function.summary", "function", "summary", *file, "--limit", "0")
    add("function.typeflow", "function", "typeflow", *file, "--limit", "0")
    add("function.layout", "function", "layout", *file, "--limit", "0")
    add("analyze", "analyze", *file)
    add("contradictions", "contradictions", *file, "--limit", "0")
    add("bindings.list", "bindings", "list", *file)
    add("sig.gen", "sig", "gen", *file)
    for i, f in enumerate(top[:3]):
        add(f"decomp.top{i}", "decomp", "pseudo", "--addr", f, *file)
        add(f"ir.build.top{i}", "ir", "build", "--addr", f, *file)
    add("decomp.top0+goto", "decomp", "pseudo", "--addr", a, *file, "--style", "goto")
    add("why", "why", "--addr", a, *file)
    add("disasm", "disasm", "--addr", a, "--count", "32", *file)
    add("ir.explain", "ir", "explain", "--addr", a, *file)
    add("ir.dot", "ir", "dot", "--addr", a, *file)
    add("ir.slice", "ir", "slice", "--addr", a, "--reg", "x0" if arm else "rax", *file)
    add("ir.value-set", "ir", "value-set", "--addr", a, *file)
    add("ir.deobfuscate", "ir", "deobfuscate", "--addr", a, *file)
    add("function.trace", "function", "trace", "--addr", mid, *file, "--depth", "3")
    add("function.eh", "function", "eh", "--addr", a, *file)
    add("mem.read", "mem", "read", "--addr", a, "--size", "256", *file)
    add("mem.span", "mem", "span", "--addr", a, "--size", "256", *file)
    add("scan.aob", "scan", "aob", "--pattern", "48 8B ?? 48", *file, "--start", a, "--size", hex(0x100000))
    add("scan.value", "scan", "value", "--type", "u32", "--value", "0", *file, "--start", a, "--size", hex(0x100000), "--save-as", "sv", "--force")
    add("scan.filter", "scan", "filter", "--from", "sv", "--criterion", "exact", "--value", "0", *file, "--save-as", "sf", "--force")
    add("scan.dissect", "scan", "dissect", "--start", a, "--size", "256", *file)
    add("scan.group", "scan", "group", "--field", "u8=72", "--field", "u8=139", *file, "--start", a, "--size", hex(0x10000), "--limit", "100")
    add("const.identify", "const", "identify", "--addr", a, *file)
    add("sig.validate", "sig", "validate", "--at", a, "--len", "32", *file)
    add("aot.symbols", "aot", "symbols", *file, "--limit", "10")
    add("il2cpp.icalls", "il2cpp", "icalls", *file, "--limit", "10")
    add("il2cpp.obj", "il2cpp", "obj", "--addr", a, *file)
    add("il2cpp.metadata", "il2cpp", "metadata", *file, "--limit", "10")
    add("annotate.name", "annotate", "name", "--addr", a, "--value", "ім'я", *file)
    add("decomp.after-name", "decomp", "pseudo", "--addr", a, *file)
    add("annotate.show", "annotate", "show", "--addr", a, *file)
    add("annotate.list", "annotate", "list", *file)
    add("annotate.rm", "annotate", "rm", "--addr", a, *file)
    add("snapshot.dump", "snapshot", "dump", "--name", "s", *file, "--start", a, "--size", hex(0x10000), "--force")
    add("snapshot.info", "snapshot", "info", "s")
    add("mem.read+snap", "mem", "read", "--addr", a, "--size", "16", "--snapshot", "s")
    add("decomp+snap", "decomp", "pseudo", "--addr", mid, "--snapshot", "s")
    add("project.cache", "project", "cache")
    return c


def real_image(s, cases, im):
    tag, path = im["tag"], Path(im["path"])
    size = path.stat().st_size >> 20
    wdir, ldir = f"img/{tag}", f"img/{tag}"
    wfile = s.W(f"{wdir}/{path.name}")
    lfile = s.L(f"{ldir}/{path.name}")
    Path(s.L(ldir)).mkdir(parents=True, exist_ok=True)
    Path(s.L(f"{ldir}/p/.n0x")).mkdir(parents=True, exist_ok=True)
    shutil.copy(path, lfile)
    s.laptop.run(r"C:\Windows\System32\cmd.exe", ["/c", "mkdir", s.W(f"{wdir}/p/.n0x")])
    s.laptop.put(path, wfile)
    cwd = "{W}" + f"{ldir}/p"
    # Which functions to ask about; the tool's own list, and the only use of it: an answer about the wrong one is still compared.
    first = s.lin(["function", "discover", "--file", lfile, "--quiet"], cwd=cwd, bound=600)
    listed = (s.parsed(first["o"]) or {}).get("data", {}).get("functions", [])
    sized = sorted(((int(f["end"], 16) - int(f["va"], 16), f["va"]) for f in listed if f.get("end")), reverse=True)
    if not sized:
        s.row(f"real.{tag}", "", "failed", f"the twin lists no function in {path.name}: {first['o'][:120]!r}")
        return
    top, mid = [x[1] for x in sized[:3]], sized[len(sized) // 2][1]
    arm = "a64" in tag or "arm" in tag
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=1) as pool:
        wanted = [(id, a) for id, a in real_cases(tag, top, mid, arm) if id not in cases.HEAVY or im.get("heavy")]
        twins = {id: pool.submit(s.lin, [x.replace("@F", lfile) for x in a], cwd, None, 600) for id, a in wanted}
        for id, a in wanted:
            case = f"real.{tag}.{id}"
            if s.skipped(case):
                continue
            w = s.win([x.replace("@F", wfile) for x in a], cwd=cwd, bound=600)
            l = twins[id].result()
            # The directories an image and its project sit in are taken out by file name: they are paths.
            why = s.contract(w) or (f"on the twin: {s.contract(l)}" if s.contract(l) else None) or s.difference(w, l)
            s.row(case, s.leaf_of(a), "failed" if why else "passed", why or "")
            del w, l
            twins[id] = None
    if im.get("truth"):
        scored_row(s, im, listed, wfile, lfile, cwd)
    s.laptop.run(r"C:\Windows\System32\cmd.exe", ["/c", "rmdir", "/s", "/q", s.W(wdir)], bound=120)
    shutil.rmtree(s.L(ldir), ignore_errors=True)
    print(f"  {tag} ({size} MB): {int(time.time() - t0)} s", flush=True)


def scored_row(s, im, listed, wfile, lfile, cwd):
    """The instrument's two questions, the list and `why` at every start in one session, on both machines; both scored by its own
    scorer against the same truth. Numbers the same is the row: a start the Windows build adds would be in `wrong`."""
    sys.path.insert(0, str(M.ROOT / "oracle" / "rule-accuracy"))
    import readers
    import score
    import truth as truth_reader
    tag = im["tag"]
    addresses = [f["va"] for f in listed]
    questions = "".join(json.dumps(["why", "--addr", x]) + "\n" for x in addresses)
    bound = max(500, len(addresses) // 4)
    answers = {}
    def measure(side, file, run):
        disc = run(["function", "discover", "--file", file], cwd=cwd, bound=600)
        session = run(["serve", "--file", file], cwd=cwd, stdin=questions, bound=bound)
        lines = [json.loads(l) for l in session["o"].decode("utf-8").splitlines() if l.strip()]
        d = s.parsed(disc["o"])
        return dict(image=str(im["path"]), engine=dict(path=side, sha256=side), discover=d, why=dict(zip([f["va"] for f in d["data"]["functions"]], lines[1:])))
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            twin = pool.submit(measure, "twin", lfile, s.lin)
            answers["win"] = measure("windows", wfile, s.win)
            answers["lin"] = twin.result()
        truth = truth_reader.truth(str(im["truth"]))
        symbols = readers.symbols(str(im["path"]))
        _, sw = score.score(truth, answers["win"], symbols)
        _, sl = score.score(truth, answers["lin"], symbols)
    except M.LaptopGone:
        raise
    except Exception as e:  # noqa: BLE001 - a scorer that did not run must read as a failure of this row, not as numbers
        s.row(f"real.{tag}.score", "function discover", "failed", f"the scorer did not run: {e!r}")
        return
    keys = ("classes", "per_end", "per_name", "per_source")
    same = all(sw.get(k) == sl.get(k) for k in keys)
    s.row(f"real.{tag}.score", "function discover", "passed" if same else "failed", f"Windows {sw['classes']} missed {len(sw.get('missed') or [])}; twin {sl['classes']} missed {len(sl.get('missed') or [])}")


# -- Defender, and the laptop ---------------------------------------------------------------------------------------------

def defender_mark(s):
    """The laptop's own clock, so that this run's new entries are the ones after it. Nothing is cleared: what was there stays."""
    return s.laptop.ps("(Get-Date).ToUniversalTime().ToString('o')").strip()


def defender_check(s, mark):
    out = s.laptop.ps(f"try {{ $since = [datetime]::Parse('{mark}').ToUniversalTime(); @(Get-MpThreatDetection | Where-Object {{ $_.InitialDetectionTime.ToUniversalTime() -ge $since }}) | ForEach-Object {{ ($_.Resources -join ';') + ' ID' + $_.ThreatID }}; 'READ' }} catch {{ 'REFUSED ' + $_.Exception.Message }}")
    if "READ" not in out:
        s.row("defender", "", "not-run", f"this user cannot read Defender's detections: {out.strip()[:120]}")
        return
    entries = [l for l in out.splitlines() if l.strip() and l.strip() != "READ"]
    ours = [e for e in entries if re.search(r"n0xis|n0xtest|sweep-", e, re.I) and not re.search(r"powershell|amsi", e, re.I)]
    harness = [e for e in entries if re.search(r"powershell|amsi|wrun|wtarget|ctrlsend", e, re.I)]
    s.row("defender.our-binaries", "", "failed" if ours else "passed", "; ".join(ours)[:300] or f"{len(entries)} new detections in the run, none naming them")
    # Not a verdict on the release, and not a thing to pass over: the harness's own text set it off, and the harness is to be fixed.
    s.row("defender.the-harness", "", "failed" if harness else "passed", ("the harness itself was detected, fix it: " + "; ".join(harness))[:300] if harness else "")
    others = [e for e in entries if e not in ours and e not in harness]
    if others:
        print(f"  Defender, not of this run's making: {others[:3]}", flush=True)


def outside_listing(s):
    """Anything of the tool's name in the user's application data: a fallback to a global place would show here."""
    return sorted(s.laptop.ps("Get-ChildItem $env:LOCALAPPDATA,$env:APPDATA -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^n0x' } | ForEach-Object { $_.FullName }").split("\n"))

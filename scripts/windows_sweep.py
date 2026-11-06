#!/usr/bin/env python3
"""Every command of an assembled release on a real Windows, on the very files that go out. A person's verdict is not in it.

    python3 scripts/windows_sweep.py --dir target/release-vX.Y.Z [--host winlaptop] [--images DIR] [--extra-images FILE]

Writes target/windows-sweep/<version>.json, which scripts/release.py reads back. Each case states what it expects and ends
`passed` or `failed`; a case that cannot run says why, as `not-run`, and that reason goes in the public release notes.

  Static     the Windows build against its Linux twin on the same bytes, the same after paths and the OS's own error text
             are taken out, and nothing more. A case expected to refuse names the refusal's kind.
  Real       whole programs from --images: the same comparison; where there is truth, the numbers of oracle/rule-accuracy's
             own scorer on the Windows answers must be the Linux twin's.
  Live       a target that plants known values, prints them, and keeps ticking after every debugger command returned, which
             is what survival means. x64 and 32-bit.
  MCP        the parent and its worker: no console window, a real 0xC00000FD, no orphan, a session across a restart.
  Update     what can be done before a release exists; the rest is `not-run`, and says what is not proved.
  Defender   new detections since the start of the run, read-only.

Nothing outside a scratch directory on the laptop is touched and no Windows setting changes; the directory goes at the end,
also after a failure. A laptop that drops off ends the run with no record, because a part of a sweep must not read as one.
--only and --without exist for working on the sweep and for calibrating it: --only writes no record.
"""

import argparse
import base64
import hashlib
import json
import os
import queue
import re
import resource
import shlex
import shutil
import struct
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "scripts" / "windows-sweep"
sys.path.insert(0, str(SOURCES))
RECORDS = ROOT / "target" / "windows-sweep"
ASSETS = {"n0xis.exe": "n0xis-windows-x86_64.exe", "n0xis-mcp.exe": "n0xis-mcp-windows-x86_64.exe", "n0xis": "n0xis-linux-x86_64", "n0xis-mcp": "n0xis-mcp-linux-x86_64"}
TOOLS = ("x86_64-w64-mingw32-gcc", "x86_64-w64-mingw32-g++", "x86_64-w64-mingw32-objdump", "x86_64-w64-mingw32-nm", "i686-w64-mingw32-gcc", "i686-w64-mingw32-g++", "i686-w64-mingw32-nm",
         "i686-w64-mingw32-objdump", "g++", "gcc", "nm", "objdump", "aarch64-linux-gnu-g++", "aarch64-linux-gnu-nm", "aarch64-linux-gnu-objdump", "wat2wasm", "wasm-objdump", "luajit", "ssh", "scp")
SSH = ["ssh", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=15", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4"]
AS_LIMIT = 4194304 * 1024
PARTS = ("static", "console", "paths", "live", "fixes", "mcp", "update", "real")


class LaptopGone(Exception):
    """Not a result of any case. It ends the run, with no record."""


def die(message):
    print(f"windows_sweep: {message}", file=sys.stderr)
    sys.exit(2)


def run_local(*cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", env=dict(os.environ, LC_ALL="C"), **kw).stdout


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def win_argv(args):
    """One command line by the rules CommandLineToArgvW reads back, as Rust's std builds them for the same list."""
    out = []
    for a in args:
        if a and not re.search(r'[\s"]', a):
            out.append(a)
            continue
        q, slashes = '"', 0
        for ch in a:
            if ch == "\\":
                slashes += 1
                continue
            q += "\\" * (slashes * 2 + 1 if ch == '"' else slashes) + ch
            slashes = 0
        out.append(q + "\\" * (slashes * 2) + '"')
    return " ".join(out)


def b64(text):
    data = text if isinstance(text, bytes) else (text or "").encode()
    return base64.b64encode(data).decode() or "-"


class Laptop:
    """The far side: ssh, scp, one-shot PowerShell for what only it can answer, and the long-lived case runner."""

    def __init__(self, host, root):
        self.host, self.root = host, root
        self.proc = None
        self.lines = queue.Queue()
        self.count = 0

    def reachable(self):
        try:
            r = subprocess.run([*SSH, self.host, "cmd /c echo up"], capture_output=True, timeout=45)
            return b"up" in r.stdout
        except (subprocess.TimeoutExpired, OSError):
            return False

    def gone_unless_up(self, doing):
        if not self.reachable():
            raise LaptopGone(f"the laptop stopped answering while {doing}")

    def ps(self, script, timeout=120):
        """Base64 so that `$` survives the far shell. Harness queries only: a console case goes by a batch file, because a
        PowerShell command line with that text in it once tripped the script scanner."""
        enc = base64.b64encode(("$ProgressPreference='SilentlyContinue'\n" + script).encode("utf-16le")).decode()
        try:
            r = subprocess.run([*SSH, self.host, f"powershell -NoProfile -NonInteractive -EncodedCommand {enc}"], capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            self.gone_unless_up("a query was running")
            return ""
        if r.returncode == 255:
            self.gone_unless_up("a query was running")
        out = r.stdout.decode("utf-8", "replace").replace("\r", "")
        return "\n".join(l for l in out.splitlines() if not l.startswith(("#< CLIXML", "<Objs ")))

    def scp(self, src, dst):
        r = subprocess.run(["scp", "-q", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=15", "-r", str(src), str(dst)], capture_output=True)
        if r.returncode:
            self.gone_unless_up("a file was being copied")
            raise RuntimeError(f"scp {src} {dst}: {r.stderr.decode('utf-8', 'replace')[:200]}")

    def put(self, local, remote):
        self.scp(local, f"{self.host}:{remote.replace(chr(92), '/')}")

    def get(self, remote, local):
        self.scp(f"{self.host}:{remote.replace(chr(92), '/')}", local)

    def start_runner(self):
        self.proc = subprocess.Popen([*SSH, self.host, self.root + r"\wrun.exe"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.lines = queue.Queue()
        threading.Thread(target=self._read, args=(self.proc, self.lines), daemon=True).start()
        try:
            if self.lines.get(timeout=40) != b"HELLO\n":
                raise queue.Empty
        except queue.Empty:
            self.gone_unless_up("the case runner was starting")
            raise RuntimeError("the case runner did not start") from None

    @staticmethod
    def _read(proc, lines):
        for raw in proc.stdout:
            lines.put(raw)
        lines.put(None)

    def run(self, exe, args, cwd="", env=None, stdin=None, bound=60, kill_after=None, close_after=None):
        """One process on the laptop, bounded there. A case that outlives its bound comes back with timed_out; a runner that
        does not come back is either a laptop gone or a harness to restart, and the difference is asked for, not assumed."""
        self.count += 1
        id = str(self.count)
        env_text = "".join(f"{k}={v}\n" for k, v in (env or {}).items())
        line = " ".join([id, b64(exe), b64(win_argv([exe, *args])), b64(cwd), b64(env_text), b64(stdin), str(int(bound * 1000)), str(-1 if kill_after is None else kill_after), str(-1 if close_after is None else close_after)])
        answer = dict(rc=None, o=b"", e=b"", ms=0, timed_out=False, killed=False, low_memory=False, peak=0, start_error=0)
        try:
            self.proc.stdin.write((line + "\n").encode())
            self.proc.stdin.flush()
            head = self.lines.get(timeout=bound + 40)
            if head is None:
                raise queue.Empty
            out = self.lines.get(timeout=120)
            err = self.lines.get(timeout=120)
            if out is None or err is None:
                raise queue.Empty
        except (queue.Empty, OSError):
            self.gone_unless_up("a case was running")
            self.proc.kill()
            self.start_runner()
            answer["timed_out"] = True
            answer["start_error"] = "the case runner stopped answering"
            return answer
        f = head.decode().split()
        answer.update(rc=None if f[2] == "none" else int(f[2]), ms=int(f[3]), timed_out=f[4] == "1", killed=f[5] == "1", low_memory=f[6] == "1", peak=int(f[7]), start_error=int(f[8]), o=base64.b64decode(out), e=base64.b64decode(err))
        return answer

    def stop_runner(self):
        if self.proc:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
            self.proc.kill()


class Sweep:
    """What every part shares: both machines' layout, the rows, the help tree."""

    def __init__(self, args):
        self.args = args
        self.rows = []
        self.pid = os.getpid()
        self.wroot = rf"C:\n0xtest\sweep-{self.pid}"
        self.lroot = RECORDS / f"work-{self.pid}"
        self.laptop = Laptop(args.host, self.wroot)
        self.tree = {}
        self.without = re.compile(args.without) if args.without else None
        self.lmcp = str(self.lroot / "bin" / "n0xis-mcp")
        self.lbin = str(self.lroot / "bin" / "n0xis")
        self.wbin = self.wroot + r"\bin\n0xis.exe"
        self.wmcp = self.wroot + r"\bin\n0xis-mcp.exe"
        self.sweep_started = time.time()
        self.lin_env = dict(os.environ, N0X_CONFIG_DIR=self.L("config"))

    def W(self, p=""):
        return self.wroot + "\\w" + ("\\" + p.replace("/", "\\") if p else "")

    def L(self, p=""):
        return str(self.lroot / "w") + ("/" + p if p else "")

    def expand(self, s, side):
        """{IN}x is the input x, {W}x a path under the work directory; the slash is the machine's own."""
        def repl(m):
            rest = ("in/" if m.group(1) == "IN" else "") + m.group(2)
            return self.W(rest) if side == "win" else self.L(rest)
        return re.sub(r"\{(IN|W)\}([^{}\x00]*)", repl, s)

    def row(self, case, command, result, why=""):
        assert result in ("passed", "failed", "not-run")
        self.rows.append(dict(case=case, command=command, result=result, why=why[:400]))
        if result == "failed":
            print(f"  failed {case}: {why[:170]}", flush=True)

    def skipped(self, case):
        """--without: the calibration's way of taking a case away, to see the command land in `uncovered`."""
        return bool(self.without and self.without.search(case))

    def leaf_of(self, args):
        """The command a list of arguments is, by the help tree: a row names what it ran, not what its author meant."""
        words = [a for a in args if a not in ("--pretty", "--json", "--quiet")]
        path = ""
        for w in words:
            longer = f"{path} {w}".strip()
            if longer not in self.tree:
                break
            path = longer
        return path

    def win(self, args, cwd=None, stdin=None, bound=60, exe=None, env=None, **kw):
        env = dict({"N0X_CONFIG_DIR": self.W("config")}, **(env or {}))
        return self.laptop.run(exe or self.wbin, [self.expand(a, "win") for a in args], cwd=self.expand(cwd or "{W}proj", "win"), env=env, stdin=self.expand(stdin, "win") if stdin else None, bound=bound, **kw)

    def lin(self, args, cwd=None, stdin=None, bound=60, close_after=None, env=None):
        """The twin, under the same bound, at the lowest priority and the address-space limit every engine run here has."""
        def limit():
            resource.setrlimit(resource.RLIMIT_AS, (AS_LIMIT, AS_LIMIT))
            os.nice(19)
        t0 = time.time()
        answer = dict(rc=None, o=b"", e=b"", ms=0, timed_out=False, peak=0, start_error=0, low_memory=False, killed=False)
        argv = [self.lbin, *[self.expand(a, "lin") for a in args]]
        full_env = dict(self.lin_env, **(env or {}))
        try:
            if close_after is not None:
                p = subprocess.Popen(argv, cwd=self.expand(cwd or "{W}proj", "lin"), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=full_env, preexec_fn=limit)
                answer["o"] = p.stdout.read(close_after)
                p.stdout.close()
                answer["e"] = p.stderr.read()
                answer["rc"] = p.wait(timeout=bound)
            else:
                p = subprocess.run(argv, cwd=self.expand(cwd or "{W}proj", "lin"), input=(self.expand(stdin, "lin") if stdin else "").encode(), capture_output=True, env=full_env, timeout=bound, preexec_fn=limit)
                answer.update(rc=p.returncode, o=p.stdout, e=p.stderr)
        except subprocess.TimeoutExpired:
            answer["timed_out"] = True
        answer["ms"] = int((time.time() - t0) * 1000)
        return answer

    # -- what is the same, what is not ------------------------------------------------------------------------------

    DROP_KEYS = re.compile(r"(^|_)(elapsed|ms|duration|time|timestamp|took|mtime|created|modified|created_at|updated_at|at_unix|saved_at|unix)(_|$)|^(captured_at|added_at|ts)$", re.I)
    OS_ERROR = re.compile(r"[^:;\"\n]*\(os error \d+\)")

    def norm_text(self, s):
        for root in (self.wroot + "\\w", self.wroot.replace("\\", "/") + "/w", self.L()):
            if root in s:
                s = s.replace(root, "<W>")
                s = re.sub(r"<W>[^\s\"',;:()]*", lambda m: m.group(0).replace("\\", "/"), s)
        s = s.replace(self.wroot + "\\bin\\", "<BIN>/").replace(str(self.lroot / "bin") + "/", "<BIN>/")
        s = s.replace("n0xis.exe", "n0xis").replace("n0xis-mcp.exe", "n0xis-mcp")
        return self.OS_ERROR.sub("<os error>", s)

    def norm(self, v):
        if isinstance(v, dict):
            return {k: self.norm(x) for k, x in v.items() if not self.DROP_KEYS.search(k)}
        if isinstance(v, list):
            return [self.norm(x) for x in v]
        return self.norm_text(v) if isinstance(v, str) else v

    @staticmethod
    def parsed(out):
        try:
            return json.loads(out.decode("utf-8"))
        except ValueError:
            return None

    @staticmethod
    def contract(r):
        """What the documentation promises of any command on any machine, as a reason or None. A timeout says its bound."""
        if r["timed_out"]:
            return f"stopped at its bound after {r['ms'] // 1000} s{': ' + r['start_error'] if isinstance(r['start_error'], str) else ''}"
        if r.get("low_memory"):
            return "stopped because the laptop was running out of memory"
        if r["start_error"]:
            return f"could not start: error {r['start_error']}"
        if b"panicked" in r["e"] or b"stack backtrace" in r["e"]:
            return f"panic text on stderr: {r['e'][:120]!r}"
        if r["rc"] not in (0, 2):
            return f"exit code {r['rc'] if r['rc'] is None else hex(r['rc'] & 0xffffffff)}"
        return None

    def expectation(self, r, refuses):
        """A reason, or None. An envelope that says ok:true must have exit 0, ok:false exit 2, and only the named kind of refusal is the expected one."""
        env = self.parsed(r["o"])
        if isinstance(env, dict) and "ok" in env:
            if env["ok"] is True and r["rc"] != 0:
                return f"ok:true with exit {r['rc']}"
            if env["ok"] is False and r["rc"] != 2:
                return f"ok:false with exit {r['rc']}"
            code = None if env["ok"] else (env.get("error") or {}).get("code")
            if code != refuses:
                message = (env.get("error") or {}).get("message", "")
                return f"expected {'refusal ' + refuses if refuses else 'an answer'}, got {'refusal ' + str(code) + ': ' + message[:120] if code else 'an answer'}"
        elif refuses:
            return f"expected refusal {refuses}, got exit {r['rc']}, not an envelope"
        return None

    @staticmethod
    def parsed_lines(out):
        """`serve` answers a line of JSON each: as many values, or None."""
        try:
            return [json.loads(line) for line in out.decode("utf-8").splitlines() if line.strip()]
        except ValueError:
            return None

    def difference(self, w, l, ignore=()):
        """The first difference between the two answers after normalising, or None."""
        ew, el = self.parsed(w["o"]), self.parsed(l["o"])
        if ew is None and el is None:
            ew, el = self.parsed_lines(w["o"]), self.parsed_lines(l["o"])
        if w["rc"] != l["rc"]:
            return f"exit {w['rc']} here, {l['rc']} on the twin"
        if ew is None or el is None:
            a = self.norm_text(w["o"].decode("utf-8", "replace").replace("\r\n", "\n"))
            b = self.norm_text(l["o"].decode("utf-8", "replace"))
            if a == b:
                return None
            at = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
            return f"text differs at {at}: {a[max(0, at - 30):at + 50]!r} / {b[max(0, at - 30):at + 50]!r}"
        return first_diff(without_keys(self.norm(ew), ignore), without_keys(self.norm(el), ignore))


def without_keys(v, keys):
    if not keys:
        return v
    if isinstance(v, dict):
        return {k: without_keys(x, keys) for k, x in v.items() if k not in keys}
    return [without_keys(x, keys) for x in v] if isinstance(v, list) else v


def first_diff(a, b, path=""):
    if type(a) is not type(b):
        return f"{path}: {str(a)[:90]} / {str(b)[:90]}"
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                return f"{path}.{k}: only on {'the twin' if k not in a else 'Windows'}"
            d = first_diff(a[k], b[k], f"{path}.{k}")
            if d:
                return d
    elif isinstance(a, list):
        if len(a) != len(b):
            return f"{path}: {len(a)} items / {len(b)} on the twin"
        for i, (x, y) in enumerate(zip(a, b)):
            d = first_diff(x, y, f"{path}[{i}]")
            if d:
                return d
    elif a != b:
        return f"{path}: {str(a)[:90]} / {str(b)[:90]}"
    return None


# -- inputs -----------------------------------------------------------------------------------------------------------

def build_inputs(s):
    """Every input from source, at the start of each run. Addresses are nm's and objdump's, never the tool's."""
    missing = [t for t in TOOLS if not shutil.which(t)]
    if missing:
        die(f"missing from the path: {', '.join(missing)}. Nothing was run.")
    o = s.lroot / "in"
    (o / "scripts").mkdir(parents=True)
    def sh(*a):
        r = subprocess.run(a, capture_output=True, text=True, errors="replace")
        if r.returncode:
            die(f"building an input failed: {' '.join(map(str, a))}\n{r.stderr[:400]}")
    app, plug = SOURCES / "app.cpp", SOURCES / "plug.c"
    sh("x86_64-w64-mingw32-g++", "-O1", "-g", "-static", app, "-o", o / "app.exe")
    sh("x86_64-w64-mingw32-g++", "-O1", "-s", "-static", app, "-o", o / "app_stripped.exe")
    sh("x86_64-w64-mingw32-g++", "-O1", "-shared", "-static", app, "-o", o / "app.dll")
    sh("i686-w64-mingw32-g++", "-O1", "-g", "-static", app, "-o", o / "app32.exe")
    sh("g++", "-O1", "-g", app, "-o", o / "app.elf")
    sh("g++", "-O1", "-g", "-shared", "-fPIC", app, "-o", o / "app.so")
    sh("aarch64-linux-gnu-g++", "-O1", "-g", "-static", app, "-o", o / "app_arm64.elf")
    sh("wat2wasm", SOURCES / "mod.wat", "-o", o / "mod.wasm")
    sh("x86_64-w64-mingw32-gcc", "-O1", "-static", plug, "-o", o / "plug.exe")
    sh("gcc", "-O1", plug, "-o", o / "plug.bin")
    for name, cc in (("wtarget.exe", "x86_64-w64-mingw32-gcc"), ("wtarget32.exe", "i686-w64-mingw32-gcc")):
        sh(cc, "-O0", "-g", "-static", SOURCES / "wtarget.c", "-o", o / name, "-lgdi32", "-luser32")
    sh("x86_64-w64-mingw32-gcc", "-O1", "-static", SOURCES / "ctrlsend.c", "-o", o / "ctrlsend.exe")
    sh("x86_64-w64-mingw32-gcc", "-O1", "-static", SOURCES / "wrun.c", "-o", s.lroot / "wrun.exe")
    for f in ("pdbtarget.exe", "pdbtarget.pdb"):
        shutil.copy(ROOT / "crates/n0xis-pdb/tests/fixtures" / f, o / f)
    # A LuaJIT 2.0 dump (version 1) built by hand: one prototype, a KSTR and a number constant the catalogue knows.
    def uleb(v):
        r = bytearray()
        while True:
            b, v = v & 0x7f, v >> 7
            r.append(b | 0x80 if v else b)
            if not v:
                return bytes(r)
    body = bytes([0, 0, 2, 0]) + uleb(1) + uleb(1) + uleb(1) + struct.pack("<I", 37) + bytes([5 + 2]) + b"hi" + uleb(1664525 << 1)
    chunk = bytes([0x1b]) + b"LJ\x01\x02" + uleb(len(body)) + body + b"\0"
    (o / "lj20.ljbc").write_bytes(chunk)
    (o / "src.lua").write_text("local function f(a) return a * 1664525 end\nprint(f(2), 'retry backoff timeout')\n")
    sh("luajit", "-b", o / "src.lua", o / "lj21.ljbc")
    # A bundle with one inline variant of the Lua type, by the crate's own type hash, and one streamed.
    type_hash = int(re.search(r"TYPE_HASH_LUA:\s*u64\s*=\s*(0x[0-9a-fA-F_]+)", (ROOT / "crates/n0xis-bitsquid/src/types.rs").read_text()).group(1).replace("_", ""), 16)
    inline = struct.pack("<II", len(chunk), 1) + chunk
    streamed = b"STREAMED-BYTES-95"
    hash1, hash2 = 0x1111222233334444, 0x5555666677778888
    body = struct.pack("<I", 2) + bytes(256)
    for h in (hash1, hash2):
        body += struct.pack("<QQ", type_hash, h)
    body += struct.pack("<QQII", type_hash, hash1, 1, 0) + struct.pack("<III", 0, len(inline), 0) + inline
    body += struct.pack("<QQII", type_hash, hash2, 1, 0) + struct.pack("<III", 0, 0, len(streamed))
    archive = bytes([4, 0, 0, 0xF0]) + struct.pack("<II", len(body), 0)
    for i in range(0, len(body), 0x10000):
        z = zlib.compress(body[i:i + 0x10000])
        archive += struct.pack("<I", len(z)) + z
    (o / "test.bundle").write_bytes(archive)
    (o / "test.bundle.stream").write_bytes(streamed)
    (o / "repl.bin").write_bytes(bytes(len(inline)))
    # A dump of method names, and a metadata blob with the documented header.
    (o / "script.json").write_text(json.dumps({"ScriptMethod": [{"Address": 0x1000, "Name": "App$$Tick", "Signature": "void f(void *, const MethodInfo *)", "TypeSignature": "vi"}], "ScriptString": [{"Address": 65536, "Value": "planted"}]}))
    literals = [b"Alpha", "Ютф8".encode(), b"Gamma"]
    blob, pairs, off = b"".join(literals), b"", 0
    for l in literals:
        pairs += struct.pack("<II", len(l), off)
        off += len(l)
    header = 8 + 8 * 40
    meta = struct.pack("<Ii", 0xFAB11BAF, 24)
    for a, b in [(header, len(pairs)), (header + len(pairs), len(blob))] + [(header + len(pairs) + len(blob), 0)] * 38:
        meta += struct.pack("<ii", a, b)
    (o / "global-metadata.dat").write_bytes(meta + pairs + blob)
    (o / "sample1.bin").write_bytes(bytes.fromhex("488b05aabbccdd4889c3"))
    (o / "sample2.bin").write_bytes(bytes.fromhex("488b05112233444889c3"))
    (o / "sample3.bin").write_bytes(bytes.fromhex("488b05a1b2c3d44889c3"))
    (o / "scripts" / "net.lua").write_text("-- retry and backoff with a timeout\nlocal retry, backoff, timeout = 1, 2, 3\n")
    (o / "scripts" / "other.txt").write_text("nothing to see\n")
    shutil.copy(o / "lj20.ljbc", o / "scripts" / "bc.ljbc")
    (o / "payload.txt").write_text("dump payload ю\n")
    (o / "empty.bin").write_bytes(b"")
    (o / "truncated.exe").write_bytes((o / "app.exe").read_bytes()[:1024])


def nm_of(tool, path):
    out = {}
    for line in run_local(tool, "--defined-only", str(path)).splitlines():
        f = line.split()
        if len(f) == 3:
            out.setdefault(f[2].lstrip("_"), int(f[0], 16))
    return out


def entry_of(tool, path):
    found = re.search(r"start address (0x[0-9a-f]+)", run_local(tool, "-f", str(path)))
    return int(found.group(1), 16)


def address_table(s):
    """Each static input's known addresses, for the case list. The system files come from the laptop, whose exact bytes the twin reads too."""
    i = s.lroot / "in"
    table = {}
    def native(tag, name, nm, od):
        syms = nm_of(nm, i / name)
        code = syms.get("branchy")
        return dict(f=name, code=code or entry_of(od, i / name), magic=syms.get("magic_mix"), data=syms.get("planted_ascii"), aob=syms.get("planted_aob"), wide=syms.get("planted_wide"), reg="eax" if tag == "pe32" else "x0" if tag == "arm64" else "rax")
    table["where"] = native("where", "where.exe", "x86_64-w64-mingw32-nm", "x86_64-w64-mingw32-objdump")
    table["version"] = native("version", "version.dll", "x86_64-w64-mingw32-nm", "x86_64-w64-mingw32-objdump")
    table["app"] = native("app", "app.exe", "x86_64-w64-mingw32-nm", "x86_64-w64-mingw32-objdump")
    table["strip"] = native("strip", "app_stripped.exe", "x86_64-w64-mingw32-nm", "x86_64-w64-mingw32-objdump")
    table["dll"] = native("dll", "app.dll", "x86_64-w64-mingw32-nm", "x86_64-w64-mingw32-objdump")
    table["pe32"] = native("pe32", "app32.exe", "i686-w64-mingw32-nm", "i686-w64-mingw32-objdump")
    table["elf"] = native("elf", "app.elf", "nm", "objdump")
    table["so"] = native("so", "app.so", "nm", "objdump")
    table["arm64"] = native("arm64", "app_arm64.elf", "aarch64-linux-gnu-nm", "aarch64-linux-gnu-objdump")
    funcs = dict((m[1], int(m[0], 16)) for m in re.findall(r"^([0-9a-f]+) func\[\d+\] <(\w+)>:", run_local("wasm-objdump", "-d", str(i / "mod.wasm")), re.M))
    table["wasm"] = dict(f="mod.wasm", code=funcs["add"], magic=funcs["mix"], data=None, aob=None, wide=None, reg="stack")
    return table


# -- the laptop's scratch -----------------------------------------------------------------------------------------------

def lay_out(s, release):
    lap = s.laptop
    # What an earlier run could not take away because the laptop dropped off. Only this script makes sweep-<number>.
    lap.ps(r"Get-ChildItem 'C:\n0xtest' -Directory -Filter 'sweep-*' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^sweep-\d+$' } | ForEach-Object { $d = $_.FullName; Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -like ($d + '\*') } | Stop-Process -Force -ErrorAction SilentlyContinue; Remove-Item -Recurse -Force $d -ErrorAction SilentlyContinue }")
    r = subprocess.run([*SSH, lap.host, f"cmd /c mkdir {s.wroot}\\bin {s.wroot}\\w\\in {s.wroot}\\w\\proj\\.n0x {s.wroot}\\w\\live\\.n0x {s.wroot}\\w\\mcp\\.n0x {s.wroot}\\w\\config"], capture_output=True)
    if r.returncode:
        die(f"could not reach {lap.host} to make {s.wroot}: {r.stderr.decode('utf-8', 'replace')[:200]}")
    (s.lroot / "w" / "proj" / ".n0x").mkdir(parents=True)
    (s.lroot / "w" / "mcp" / ".n0x").mkdir(parents=True)
    (s.lroot / "w" / "config").mkdir(parents=True)
    (s.lroot / "bin").mkdir(parents=True)
    for name in ("n0xis", "n0xis-mcp"):
        shutil.copy(release / ASSETS[name], s.lroot / "bin" / name)
        os.chmod(s.lroot / "bin" / name, 0o755)
    i = s.lroot / "in"
    lap.get(r"C:\Windows\System32\where.exe", i / "where.exe")
    lap.get(r"C:\Windows\System32\version.dll", i / "version.dll")
    lap.put(s.lroot / "wrun.exe", s.wroot + r"\wrun.exe")
    for name in ("n0xis.exe", "n0xis-mcp.exe"):
        lap.put(release / ASSETS[name], s.wroot + "\\bin\\" + name)
    with tarfile.open(s.lroot / "in.tar", "w") as tar:
        tar.add(i, arcname=".")
    lap.put(s.lroot / "in.tar", s.W("in.tar"))
    lap.start_runner()
    r = lap.run(r"C:\Windows\System32\tar.exe", ["-xf", s.W("in.tar")], cwd=s.W("in"))
    if r["rc"] != 0:
        raise RuntimeError(f"the inputs did not unpack: {r['e'][:200]!r}")
    shutil.copytree(i, s.L("in"))
    (s.lroot / "runt.bat").write_bytes(b'@echo off\r\n"%~1"\r\necho EXITCODE %ERRORLEVEL%\r\n')
    lap.put(s.lroot / "runt.bat", s.wroot + r"\runt.bat")


def take_away(s):
    """Everything this run left on the laptop, also when it failed. True when the directory is gone."""
    lap = s.laptop
    lap.stop_runner()
    out = lap.ps(f"Get-Process -ErrorAction SilentlyContinue | Where-Object {{ $_.Path -like '{s.wroot}\\*' }} | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 500; Remove-Item -Recurse -Force -LiteralPath '{s.wroot}' -ErrorAction SilentlyContinue; Test-Path -LiteralPath '{s.wroot}'")
    return out.strip().endswith("False")


# -- the help tree --------------------------------------------------------------------------------------------------------

def help_nodes(text):
    subs, section = [], None
    for line in text.splitlines():
        if re.match(r"^[A-Z][a-z]+( [a-z]+)*:$", line):
            section = line.rstrip(":")
        elif section == "Commands":
            m = re.match(r"^  ([a-z0-9][\w-]*)\s", line + " ")
            if m and m.group(1) != "help":
                subs.append(m.group(1))
    return subs


def enumerate_commands(s):
    """The tree the Windows binary states of itself, walked on the laptop, and the twin's beside it: the one a case list answers to."""
    tree, texts = {}, {}
    def walk(path):
        w = s.win([*path, "--help"], bound=30)
        if w["timed_out"] or w["rc"] is None:
            raise RuntimeError(f"--help of {' '.join(path)!r} did not answer")
        text = (w["o"] + w["e"]).decode("utf-8", "replace").replace("\r\n", "\n")
        subs = help_nodes(text)
        name = " ".join(path)
        tree[name] = subs
        texts[name] = text
        for sub in subs:
            walk(path + [sub])
    walk([])
    s.tree = tree
    twin_differs = []
    for name, text in texts.items():
        l = s.lin([*name.split(), "--help"], bound=30)
        if s.norm_text(text) != s.norm_text((l["o"] + l["e"]).decode("utf-8", "replace")):
            twin_differs.append(name or "(top)")
    s.row("help-tree", "", "failed" if twin_differs else "passed", f"--help differs from the twin's at: {', '.join(twin_differs[:6])}" if twin_differs else f"{len(tree)} nodes the same")
    return [k for k, v in tree.items() if k and not v]


# -- the parts --------------------------------------------------------------------------------------------------------

def static_part(s, table):
    import cases
    for c in cases.all_static(table):
        if s.skipped(c["id"]):
            continue
        command = s.leaf_of(c["args"])
        w = s.win(c["args"], stdin=c.get("stdin"), bound=c.get("bound", 60))
        l = s.lin(c["args"], stdin=c.get("stdin"), bound=c.get("bound", 60))
        why = s.contract(w) or (f"on the twin: {s.contract(l)}" if s.contract(l) else None) or s.expectation(w, c.get("refuses")) or (None if c.get("kind_only") and s.expectation(l, c.get("refuses")) is None else s.difference(w, l, c.get("ignore", ())))
        if not why and c.get("must"):
            text = w["o"].decode("utf-8", "replace").lower()
            gone = [m for m in c["must"] if str(m).lower() not in text]
            why = f"not in the answer, though the source says it must be: {gone}" if gone else None
        s.row(c["id"], command, "failed" if why else "passed", why or "")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", required=True, type=Path, help="an assembled release: the four binaries by their asset names")
    ap.add_argument("--host", default="winlaptop", help="the ssh name of the Windows machine")
    ap.add_argument("--images", type=Path, help="a directory of real programs; without it those cases are not-run, and the release notes say so")
    ap.add_argument("--extra-images", type=Path, help="a JSON list of further images, {tag, file, truth?, heavy?}")
    ap.add_argument("--only", help=f"comma-separated parts of {','.join(PARTS)}, for work on the sweep. Writes no record")
    ap.add_argument("--without", help="a regular expression of case names to leave out, for calibrating `uncovered`")
    args = ap.parse_args()
    for name, asset in ASSETS.items():
        if not (args.dir / asset).is_file():
            die(f"{args.dir / asset} is not there: --dir takes an assembled release")
    only = set(args.only.split(",")) if args.only else set(PARTS)
    unknown = only - set(PARTS)
    if unknown:
        die(f"no such part: {', '.join(sorted(unknown))}")
    RECORDS.mkdir(parents=True, exist_ok=True)
    s = Sweep(args)
    t0 = time.time()
    done = False
    import parts
    parts.bind(sys.modules[__name__])
    try:
        build_inputs(s)
        lay_out(s, args.dir)
        table = address_table(s)
        build = re.search(r"\[Version ([\d.]+)\]", s.laptop.run(r"C:\Windows\System32\cmd.exe", ["/c", "ver"])["o"].decode("utf-8", "replace"))
        windows = build.group(1) if build else None
        stated = s.win(["--version"])["o"].decode("utf-8", "replace").split()
        version = stated[-1] if stated else None
        if not windows or not version:
            raise LaptopGone(f"the laptop did not state its build ({windows}) or the binary its version ({version})")
        twin = s.lin(["--version"])["o"].decode("utf-8", "replace").split()
        s.row("twin-states-the-same-version", "", "passed" if twin and twin[-1] == version else "failed", f"Windows {version}, twin {twin[-1] if twin else None}")
        print(f"sweep of {version} on Windows {windows}, {s.wroot}", flush=True)
        mark = parts.defender_mark(s)
        before = parts.outside_listing(s)
        leaves = enumerate_commands(s)
        print(f"{len(leaves)} commands; inputs on both machines at {int(time.time() - t0)} s", flush=True)
        runs = dict(static=lambda: static_part(s, table), console=lambda: parts.console_part(s), paths=lambda: parts.paths_part(s, table), live=lambda: parts.live_part(s), fixes=lambda: parts.defects_part(s), mcp=lambda: parts.mcp_part(s, table), update=lambda: parts.update_part(s), real=lambda: parts.real_part(s))
        for part in PARTS:
            if part not in only:
                continue
            t1, n = time.time(), len(s.rows)
            try:
                runs[part]()
            except LaptopGone:
                raise
            except Exception as e:  # noqa: BLE001 - a broken part is a failed row, never a part quietly missing
                s.row(f"{part}.harness", "", "failed", f"the part stopped: {e!r}")
            new = s.rows[n:]
            print(f"{part}: {sum(r['result'] == 'passed' for r in new)} passed, {sum(r['result'] == 'failed' for r in new)} failed, {sum(r['result'] == 'not-run' for r in new)} not-run, {int(time.time() - t1)} s", flush=True)
        parts.defender_check(s, mark)
        s.row("laptop.nothing-outside-the-scratch", "", "passed" if parts.outside_listing(s) == before else "failed", "no n0x* appeared in the user's application data" if parts.outside_listing(s) == before else "something named n0x* appeared in the user's application data")
        # The digests of what actually ran: read back after the last case, not what was meant to be sent.
        back = s.lroot / "back"
        back.mkdir()
        binaries = {}
        for name in ("n0xis.exe", "n0xis-mcp.exe"):
            s.laptop.get(s.wroot + "\\bin\\" + name, back / name)
            binaries[name] = sha256(back / name)
            if binaries[name] != sha256(args.dir / ASSETS[name]):
                s.row(f"binaries.{name}", "", "failed", "the file on the laptop is not the file in --dir")
        done = True
    except LaptopGone as e:
        print(f"windows_sweep: {e}. The run is over and no record was written: a part of a sweep must not read as one.", file=sys.stderr)
        sys.exit(3)
    finally:
        try:
            gone = take_away(s)
        except LaptopGone:
            gone = False
        if not gone:
            print(f"windows_sweep: {s.wroot} could not be removed; the next run takes it away", file=sys.stderr)
        shutil.rmtree(s.lroot, ignore_errors=True)
        if not done:
            print("no record written", file=sys.stderr)
    covered = {r["command"] for r in s.rows}
    uncovered = sorted(set(leaves) - covered)
    passed = sum(r["result"] == "passed" for r in s.rows)
    failed = [r for r in s.rows if r["result"] == "failed"]
    not_run = sum(r["result"] == "not-run" for r in s.rows)
    took = int(time.time() - t0)
    summary = f"{passed} passed, {len(failed)} failed, {not_run} not-run, {len(leaves)} commands, in {took} s"
    if args.only:
        path = RECORDS / f"{version}.partial.json"
        path.write_text(json.dumps(dict(only=sorted(only), rows=s.rows), indent=0, ensure_ascii=False))
        print(f"partial run, no record: {summary}; rows in {path}")
    else:
        record = dict(windows=windows, commands=len(leaves), binaries=binaries, uncovered=uncovered, rows=s.rows, seconds=took)
        path = RECORDS / f"{version}.json"
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(record, indent=0, ensure_ascii=False))
        temp.replace(path)
        print(f"{summary}; {len(uncovered)} commands with no case: {', '.join(uncovered[:12])}; written {path}")
    for r in failed[:12]:
        print(f"  failed {r['case']}: {r['why'][:150]}")
    if len(failed) > 12:
        print(f"  and {len(failed) - 12} more, in {path}")
    sys.exit(1 if failed or (uncovered and not args.only) else 0)


if __name__ == "__main__":
    main()

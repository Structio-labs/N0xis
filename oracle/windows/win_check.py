"""win_check.py: does the Windows build of n0xis work on real Windows?

Runs ON the Windows machine (Python 3.8+, standard library only), so the live
target lives in the same session as the checks. Windows has no /proc, so every
live answer is checked against what the target itself reports (wtarget.c), and
the static answers against the PE's own exception table, parsed here without
n0xis.

    python win_check.py [--dir C:\\n0xtest] [--pe <a 64-bit system DLL>]

Exit status is the number of failed checks. A JSON report is written next to the
binaries (win_check_report.json).
"""
import argparse
import hashlib
import json
import os
import platform
import queue
import struct
import subprocess
import tempfile
import threading
import time


class Checks:
    def __init__(self):
        self.rows = []

    def add(self, name, ok, evidence):
        self.rows.append({"check": name, "ok": bool(ok), "evidence": evidence})
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {evidence}", flush=True)


def run(exe, args, cwd, timeout=180):
    p = subprocess.run([exe, *args], capture_output=True, timeout=timeout, cwd=cwd)
    out = p.stdout.decode("utf-8", "replace")
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"ok": False, "error": {"raw": (out + p.stderr.decode("utf-8", "replace"))[:400]}}


def pdata_entries(path):
    """The PE's own .pdata table, read straight from the file bytes."""
    b = open(path, "rb").read()
    pe = struct.unpack_from("<I", b, 0x3C)[0]
    if b[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE")
    nsec = struct.unpack_from("<H", b, pe + 6)[0]
    optsz = struct.unpack_from("<H", b, pe + 20)[0]
    opt = pe + 24
    if struct.unpack_from("<H", b, opt)[0] != 0x20B:
        raise ValueError("PE32+ expected")
    image_base = struct.unpack_from("<Q", b, opt + 24)[0]
    exc_rva, exc_size = struct.unpack_from("<II", b, opt + 112 + 3 * 8)
    secs = []
    for i in range(nsec):
        vsize, va, rawsz, rawptr = struct.unpack_from("<IIII", b, opt + optsz + i * 40 + 8)
        secs.append((va, max(vsize, rawsz), rawptr))

    def off(rva):
        for va, size, raw in secs:
            if va <= rva < va + size:
                return raw + (rva - va)
        raise ValueError(hex(rva))

    entries = []
    base = off(exc_rva)
    for i in range(exc_size // 12):
        begin, end, unwind = struct.unpack_from("<III", b, base + i * 12)
        # A set low bit makes the entry an indirect pointer to another
        # RUNTIME_FUNCTION; otherwise UNW_FLAG_CHAININFO (0x4) marks a fragment
        # that continues an earlier function rather than starting one.
        chained = bool(unwind & 1) or bool((b[off(unwind)] >> 3) & 0x4)
        entries.append((begin, end, chained))
    return image_base, entries


def as_rva(va_hex, image_base):
    v = int(va_hex, 16)
    return v - image_base if v >= image_base else v


def mcp_check(mcp_exe, cwd, checks):
    p = subprocess.Popen([mcp_exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, cwd=cwd)
    lines = queue.Queue()
    threading.Thread(target=lambda: [lines.put(l) for l in p.stdout], daemon=True).start()

    def send(o):
        p.stdin.write((json.dumps(o) + "\n").encode())
        p.stdin.flush()

    def recv(want_id, deadline=30):
        end = time.time() + deadline
        while time.time() < end:
            try:
                msg = json.loads(lines.get(timeout=max(0.1, end - time.time())))
            except (queue.Empty, json.JSONDecodeError):
                continue
            if msg.get("id") == want_id:
                return msg
        return None

    try:
        send({"jsonrpc": "2.0", "id": 0, "method": "initialize",
              "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                         "clientInfo": {"name": "win_check", "version": "0"}}})
        init = recv(0)
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        tl = recv(1)
        tools = [t["name"] for t in (tl or {}).get("result", {}).get("tools", [])]
        checks.add("mcp: initialize + tools/list", init is not None and len(tools) > 0,
                   f"{len(tools)} tools")
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": "doctor", "arguments": {}}})
        call = recv(2)
        text = ((call or {}).get("result", {}).get("content") or [{}])[0].get("text", "{}")
        env = json.loads(text)
        checks.add("mcp: doctor tool answers", env.get("ok") is True,
                   f"status={env.get('data', {}).get('status')}")
    finally:
        p.kill()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=r"C:\n0xtest")
    ap.add_argument("--pe", default=os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                                  "System32", "kernel32.dll"))
    a = ap.parse_args()
    n0x = os.path.join(a.dir, "n0xis.exe")
    mcp = os.path.join(a.dir, "n0xis-mcp.exe")
    tgt = os.path.join(a.dir, "wtarget.exe")
    # Scan dumps go to a throwaway local project, not the user's own.
    cwd = tempfile.mkdtemp(prefix="n0x_wincheck_")
    os.makedirs(os.path.join(cwd, ".n0x"), exist_ok=True)
    checks = Checks()
    print(f"host: {platform.platform()}  python {platform.python_version()}", flush=True)

    ver = subprocess.run([n0x, "--version"], capture_output=True).stdout.decode().strip()
    checks.add("binary runs", ver.startswith("n0xis"), ver)
    doc = run(n0x, ["doctor"], cwd)
    checks.add("doctor", doc.get("ok") is True, f"status={doc.get('data', {}).get('status')}")

    # ---- live: the target is the oracle ----
    t = subprocess.Popen([tgt], stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=cwd)
    try:
        hdr = json.loads(t.stdout.readline())
        pid = hdr["pid"]
        hp, mk, td = (int(hdr[k], 16) for k in ("hp_addr", "marker_addr", "take_damage"))

        def hit():
            t.stdin.write(b"hit\n")
            t.stdin.flush()
            return json.loads(t.stdout.readline())["hp"]

        r = run(n0x, ["mem", "read", "--pid", str(pid), "--addr", hex(mk), "--size", "8", "--quiet"], cwd)
        got = bytes.fromhex((r.get("data") or {}).get("hex", "").replace(" ", ""))
        want = struct.pack("<Q", 0x0123456789ABCDEF)
        checks.add("live: mem read returns the planted marker", got == want, f"{got.hex()} vs {want.hex()}")

        r = run(n0x, ["scan", "value", "--pid", str(pid), "--type", "i32", "--value", "1000",
                      "--save-as", "wc1", "--force", "--quiet"], cwd)
        total = (r.get("data") or {}).get("total_matches")
        checks.add("live: scan value finds candidates", r.get("ok") and (total or 0) >= 1, f"total_matches={total}")

        now = hit()
        r = run(n0x, ["scan", "filter", "--pid", str(pid), "--from", "wc1", "--criterion", "exact",
                      "--value", str(now), "--save-as", "wc2", "--force", "--quiet"], cwd)
        addrs = [int(m["addr"], 16) for m in (r.get("data") or {}).get("matches", [])]
        checks.add("live: scan filter narrows to the target's hp", hp in addrs,
                   f"{len(addrs)} match(es); target says hp at {hex(hp)}")

        box = {}
        th = threading.Thread(target=lambda: box.update(r=run(
            n0x, ["provenance", "trace", "--pid", str(pid), "--addr", hex(hp),
                  "--timeout-ms", "20000", "--quiet"], cwd)))
        th.start()
        time.sleep(2.5)
        after = hit()
        th.join(40)
        pr = box.get("r") or {}
        e = ((pr.get("data") or {}).get("entries") or [{}])[0]
        fva = int(e.get("function_va", "0x0"), 16)
        ctx = "\n".join(e.get("decompiled_context", []))
        stmt_ok = hex(hp) in ctx and "- 0x1" in ctx
        checks.add("live: provenance names the writing function", pr.get("ok") and fva == td,
                   f"function_va={hex(fva)}, target says take_damage at {hex(td)} (hp now {after})")
        checks.add("live: provenance gives the writing statement", stmt_ok,
                   next((l.strip() for l in e.get("decompiled_context", []) if hex(hp) in l), "no statement"))
    finally:
        try:
            t.stdin.write(b"quit\n")
            t.stdin.flush()
        except OSError:
            pass
        t.kill()

    # ---- static: the PE's own table is the oracle ----
    image_base, entries = pdata_entries(a.pe)
    starts_true = {b for b, _, ch in entries if not ch}
    begins_all = {b for b, _, _ in entries}
    r = run(n0x, ["profile", "--file", a.pe, "--quiet"], cwd)
    checks.add("static: profile", r.get("ok") is True, os.path.basename(a.pe))
    r = run(n0x, ["function", "discover", "--file", a.pe, "--pdata", "--limit", "0", "--quiet"], cwd)
    found = {as_rva(f["va"], image_base) for f in (r.get("data") or {}).get("functions", [])}
    missing = starts_true - found
    invented = found - begins_all
    checks.add("static: discover --pdata matches the PE's own table",
               r.get("ok") and not missing and not invented,
               f"table {len(entries)} entries ({len(starts_true)} function starts), "
               f"found {len(found)}, missing {len(missing)}, outside table {len(invented)}")
    starts_sha = hashlib.sha256(",".join(f"{x:x}" for x in sorted(found)).encode()).hexdigest()

    first = min(starts_true) if starts_true else None
    if first is not None:
        r = run(n0x, ["decomp", "pseudo", "--file", a.pe, "--addr", hex(image_base + first), "--quiet"], cwd)
        lines = (r.get("data") or {}).get("pseudo") or []
        checks.add("static: decomp pseudo returns code", r.get("ok") is True and len(lines) > 2,
                   f"{len(lines)} lines at rva {hex(first)}")

    mcp_check(mcp, cwd, checks)

    fails = [c for c in checks.rows if not c["ok"]]
    report = {"host": platform.platform(), "n0xis": ver, "pe": a.pe,
              "discover_starts_sha256": starts_sha, "discover_count": len(found),
              "checks": checks.rows, "failed": len(fails)}
    with open(os.path.join(a.dir, "win_check_report.json"), "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n{len(checks.rows) - len(fails)}/{len(checks.rows)} checks passed", flush=True)
    raise SystemExit(len(fails))


if __name__ == "__main__":
    main()

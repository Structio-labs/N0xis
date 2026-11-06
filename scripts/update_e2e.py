#!/usr/bin/env python3
"""The real binaries, an old build updating to a newer one and rolling back, on Linux and under Wine.

    python3 scripts/update_e2e.py --linux --wine
    python3 scripts/update_e2e.py --linux --old-dir DIR     an old client kept as a fixture

docs/design/UPDATE.md §5. Everything is built from a clean export of HEAD, with two changes made to that
copy and nowhere else: the release key is a key made for this run, and the workspace version is the
old or the new one. So the binaries differ from a release in those two constants and no more, and there
is no switch in the source that lets a test in.

No request leaves the machine, though the binaries ask the addresses they ship with. They go through a
proxy (HTTPS_PROXY, as any user's) in this script, which refuses `updates.structio.dev`, as the
unconfigured domain does today, and tunnels `github.com` to a local server. That server answers with a
certificate for that name from an authority the binary is told to trust by SSL_CERT_FILE, and follows
the shape of `latest/download`: a redirect to the tagged release. The manifest comes from
`scripts/release.py` of the same copy, signed by openssl.

Each step's truth is the file on disk: `--version` of it, and its sha256.
"""

import argparse
import contextlib
import hashlib
import http.server
import json
import os
import pty
import select
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "n0xis-update-e2e"
OLD, NEW = "9.0.0", "9.0.1"
WINDOWS = "x86_64-pc-windows-gnu"
RELEASE_PATH = "/Structio-labs/N0xis/releases/download/v" + NEW + "/"
LATEST_PATH = "/Structio-labs/N0xis/releases/latest/download/"

failures = []


def step(ok, what):
    print(f"{'ok    ' if ok else 'FAILED'} {what}", flush=True)
    if not ok:
        failures.append(what)


def sha(path):
    """None for a file that is not there, which then fails the step that compares it."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest() if Path(path).is_file() else None


def sh(*cmd, **kw):
    return subprocess.run([str(c) for c in cmd], check=True, **kw)


def build_tree(src, public_key, version):
    """A clean export of HEAD with this run's key and this version in it."""
    if src.exists():
        shutil.rmtree(src)
    src.mkdir(parents=True)
    archive = subprocess.run(["git", "archive", "HEAD"], cwd=ROOT, check=True, stdout=subprocess.PIPE).stdout
    subprocess.run(["tar", "-x", "-C", str(src)], input=archive, check=True)
    trust = src / "crates/n0xis-update/src/trust.rs"
    text = trust.read_text()
    line = next(l for l in text.splitlines() if l.startswith("pub const RELEASE_PUBLIC_KEY"))
    trust.write_text(text.replace(line, f'pub const RELEASE_PUBLIC_KEY: &str = "{public_key}";'))
    manifest = src / "Cargo.toml"
    text = manifest.read_text()
    anchor = f'version = "{current_version()}"\nedition'
    assert text.count(anchor) == 1, "the version line of the workspace was not found"
    manifest.write_text(text.replace(anchor, f'version = "{version}"\nedition'))


def current_version():
    import tomllib
    with open(ROOT / "Cargo.toml", "rb") as f:
        return tomllib.load(f)["workspace"]["package"]["version"]


def build(src, target, out):
    """n0xis and n0xis-mcp for `target`, copied to `out` under their installed names."""
    out.mkdir(parents=True, exist_ok=True)
    cmd = ["systemd-run", "--user", "--scope", "-q", "--nice=19", "-p", "MemoryMax=6G", "--"] if shutil.which("systemd-run") else []
    cmd += ["cargo", "build", "-p", "n0xis-cli", "-p", "n0xis-mcp", "-j", "8"] + (["--target", target] if target else [])
    env = {**os.environ, "CARGO_TARGET_DIR": str(CACHE / "target"), "CARGO_PROFILE_DEV_DEBUG": "0"}
    log = open(CACHE / "build.log", "ab")
    subprocess.run(cmd, cwd=src, env=env, check=True, stdout=log, stderr=log)
    built = CACHE / "target" / (Path(target) / "debug" if target else "debug")
    suffix = ".exe" if target else ""
    for name in ("n0xis", "n0xis-mcp"):
        shutil.copyfile(built / f"{name}{suffix}", out / f"{name}{suffix}")
        os.chmod(out / f"{name}{suffix}", 0o755)


def make_key_and_certificates():
    """A signing key and a certificate authority kept between runs, so a kept fixture still verifies."""
    CACHE.mkdir(parents=True, exist_ok=True)
    key = CACHE / "release.pem"
    if not key.exists():
        sh("openssl", "genpkey", "-algorithm", "ed25519", "-out", key)
    der = subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"], check=True, stdout=subprocess.PIPE).stdout
    certs = CACHE / "tls"
    if not (certs / "leaf.pem").exists():
        certs.mkdir(exist_ok=True)
        quiet = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
        sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", certs / "ca.key", "-out", certs / "ca.pem", "-days", "3650", "-subj", "/CN=update-e2e authority", "-addext", "basicConstraints=critical,CA:TRUE", **quiet)
        sh("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", certs / "leaf.key", "-out", certs / "leaf.csr", "-subj", "/CN=github.com", **quiet)
        (certs / "ext").write_text("subjectAltName=DNS:github.com\nbasicConstraints=CA:FALSE\n")
        sh("openssl", "x509", "-req", "-in", certs / "leaf.csr", "-CA", certs / "ca.pem", "-CAkey", certs / "ca.key", "-CAcreateserial", "-out", certs / "leaf.pem", "-days", "3650", "-extfile", certs / "ext", **quiet)
    return key, der[-32:].hex(), certs


class Release:
    """The planted release: what the local server serves, and how it misbehaves on request."""

    def __init__(self, dist, key=None):
        self.dist = dist
        self.key = key
        self.tamper = None  # the name of a file to serve with a byte flipped
        self.bad_signature = False
        self.asked = []

    def sign(self):
        raw = CACHE / "manifest.raw"
        sh("openssl", "pkeyutl", "-sign", "-rawin", "-inkey", self.key, "-in", self.dist / "manifest.json", "-out", raw)
        (self.dist / "manifest.json.sig").write_text(raw.read_bytes().hex() + "\n")

    @contextlib.contextmanager
    def substituting(self, suffix, data):
        """The running component's file replaced by `data`, with a manifest that truly signs it."""
        name = "n0xis-windows-x86_64.exe" if suffix else "n0xis-linux-x86_64"
        platform = "windows-x86_64" if suffix else "linux-x86_64"
        kept = {f: (self.dist / f).read_bytes() for f in (name, "manifest.json", "manifest.json.sig")}
        manifest = json.loads(kept["manifest.json"])
        entry = manifest["components"]["n0xis"][platform]
        entry["size"], entry["sha256"] = len(data), hashlib.sha256(data).hexdigest()
        (self.dist / name).write_bytes(data)
        (self.dist / "manifest.json").write_text(json.dumps(manifest, indent=2))
        self.sign()
        try:
            yield
        finally:
            for f, bytes_ in kept.items():
                (self.dist / f).write_bytes(bytes_)


def serve(release, certs):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            release.asked.append(self.path)
            if self.path.startswith(LATEST_PATH):
                self.send_response(302)
                self.send_header("Location", "https://github.com" + RELEASE_PATH + self.path[len(LATEST_PATH):])
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            name = self.path[len(RELEASE_PATH):] if self.path.startswith(RELEASE_PATH) else ""
            path = release.dist / name
            if not name or not path.is_file():
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = bytearray(path.read_bytes())
            if release.tamper == name:
                body[len(body) // 2] ^= 1
            if release.bad_signature and name == "manifest.json.sig":
                body = b"00" * 64 + b"\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    server = Server(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certs / "leaf.pem", certs / "leaf.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]


def proxy(tls_port, seen):
    """The one way out of the binary: github.com reaches the local server, and nothing else reaches anything."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(32)

    def pump(a, b):
        try:
            while data := a.recv(65536):
                b.sendall(data)
        except OSError:
            pass
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def one(client):
        head = b""
        while b"\r\n\r\n" not in head:
            data = client.recv(4096)
            if not data:
                return
            head += data
        target = head.split()[1].decode()
        seen.append(target)
        if target != "github.com:443":
            client.sendall(b"HTTP/1.1 502 No such host today\r\nContent-Length: 0\r\n\r\n")
            client.close()
            return
        up = socket.create_connection(("127.0.0.1", tls_port))
        client.sendall(b"HTTP/1.1 200 Connected\r\n\r\n")
        threading.Thread(target=pump, args=(up, client), daemon=True).start()
        pump(client, up)

    def loop():
        while True:
            client, _ = listener.accept()
            threading.Thread(target=one, args=(client,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return listener.getsockname()[1]


class Platform:
    def __init__(self, name, suffix, runner, env, to_native):
        self.name, self.suffix, self.runner, self.env, self.to_native = name, suffix, runner, env, to_native

    def run(self, exe, *args, env=None):
        """Output to files, not pipes: a wineserver started by the run can hold a pipe open for ever."""
        logs = CACHE / "last"
        with open(logs.with_suffix(".out"), "wb") as out, open(logs.with_suffix(".err"), "wb") as err:
            code = subprocess.run([*self.runner, str(exe), *args], env={**os.environ, **self.env, **(env or {})}, stdin=subprocess.DEVNULL, stdout=out, stderr=err).returncode
        return code, logs.with_suffix(".out").read_text(errors="replace"), logs.with_suffix(".err").read_text(errors="replace")

    def version(self, exe):
        return self.run(exe, "--version")[1].strip().split()[-1]

    def answer(self, exe, *args):
        code, out, _ = self.run(exe, *args)
        try:
            return code, json.loads(out)
        except ValueError:
            return code, {"unparsed": out[:300]}


def journey(p, release, olds, seen):
    """An old build updating to a newer one and back, each step confirmed by the file on disk."""
    new_exe_sha = sha(release.dist / {"": "n0xis-linux-x86_64", ".exe": "n0xis-windows-x86_64.exe"}[p.suffix])
    new_mcp_sha = sha(release.dist / {"": "n0xis-mcp-linux-x86_64", ".exe": "n0xis-mcp-windows-x86_64.exe"}[p.suffix])
    work = CACHE / f"run-{p.name}"
    if work.exists():
        shutil.rmtree(work)
    bin_dir = work / "bin"
    bin_dir.mkdir(parents=True)
    config = work / "config"
    config.mkdir()
    p.env["N0X_CONFIG_DIR"] = p.to_native(config)
    exe = bin_dir / f"n0xis{p.suffix}"
    mcp = bin_dir / f"n0xis-mcp{p.suffix}"
    shutil.copyfile(olds / exe.name, exe)
    shutil.copyfile(olds / mcp.name, mcp)
    os.chmod(exe, 0o755)
    os.chmod(mcp, 0o755)
    old_version = p.version(exe)
    old_sha, old_mcp_sha = sha(exe), sha(mcp)
    previous = bin_dir / f"{exe.name}.previous"
    say = lambda ok, what: step(ok, f"{p.name}: {what}")  # noqa: E731

    say(old_version != NEW, f"the old build says {old_version}")
    seen.clear()
    code, a = p.answer(exe, "update", "--check")
    data = a.get("data", {})
    say(code == 0 and data.get("available") is True and data.get("latest") == NEW, f"--check offers {NEW}: {json.dumps(a)[:160] if code else 'yes'}")
    say(seen[:2] == ["updates.structio.dev:443", "github.com:443"], f"asked the shipped addresses in order, the first dead: {seen[:2]}")
    say([t["code"] for t in data.get("tried", [])] == ["manifest-unavailable"], "the dead first address is recorded and is no failure")

    for name, arrange, code_expected in [("tampered file", ("tamper", {"": "n0xis-linux-x86_64", ".exe": "n0xis-windows-x86_64.exe"}[p.suffix]), "digest-mismatch"), ("bad signature", ("bad_signature", True), "bad-signature")]:
        setattr(release, *arrange)
        code, a = p.answer(exe, "update")
        setattr(release, arrange[0], None if arrange[0] == "tamper" else False)
        # The lock stays, by design, and holds nothing.
        untouched = sha(exe) == old_sha and sha(mcp) == old_mcp_sha and sorted(f.name for f in bin_dir.iterdir() if not f.name.endswith(".update-lock")) == sorted([exe.name, mcp.name])
        say(code != 0 and a.get("error", {}).get("code") == code_expected and untouched, f"{name}: refused as {a.get('error', {}).get('code')}, the files byte for byte unchanged")

    code, a = p.answer(exe, "update")
    say(code == 0 and a.get("data", {}).get("to") == NEW, f"update: {json.dumps(a)[:200] if code else 'ok'}")
    say(p.version(exe) == NEW and sha(exe) == new_exe_sha, f"--version of the file on disk says {p.version(exe)}, and its sha256 is the release's")
    say(sha(mcp) == new_mcp_sha, "the MCP server beside it was replaced with it")
    say(previous.is_file() and sha(previous) == old_sha, "the old binary is kept beside it")
    code, a = p.answer(exe, "update", "--check")
    say(code == 0 and a["data"]["available"] is False, "the new build is up to date")

    code, a = p.answer(exe, "update", "--rollback")
    say(code == 0 and p.version(exe) == old_version and sha(exe) == old_sha, f"--rollback: the file on disk says {p.version(exe)}")
    say(sha(mcp) == old_mcp_sha, "the MCP server went back with it")
    say(not previous.exists(), "the kept file is what came back, so nothing is left to go forward to")
    code, a = p.answer(exe, "update", "--rollback")
    say(code != 0 and a.get("error", {}).get("code") == "no-previous" and p.version(exe) == old_version, f"a second --rollback goes nowhere: {a.get('error', {}).get('code')}, {p.version(exe)}")

    # A file every check passes and that cannot start: refused by running it, under each platform's
    # own loader. The manifest is re-signed here and put back after, so the release stays the release.
    with release.substituting(p.suffix, b"signed, checked, and not a program\n"):
        code, a = p.answer(exe, "update")
    untouched = sha(exe) == old_sha and sha(mcp) == old_mcp_sha and sorted(f.name for f in bin_dir.iterdir() if not f.name.endswith(".update-lock")) == sorted([exe.name, mcp.name])
    say(code != 0 and a.get("error", {}).get("code") == "does-not-run" and untouched, f"a garbage signed file: refused as {a.get('error', {}).get('code')}, the files byte for byte unchanged")

    # A kept file that is not what its record says, by the real binary, on each platform.
    p.answer(exe, "update")
    say(p.version(exe) == NEW, f"installed again: {p.version(exe)}")
    kept = previous.read_bytes()
    previous.write_bytes(kept[:-1] + bytes([kept[-1] ^ 1]))
    code, a = p.answer(exe, "update", "--rollback")
    say(code != 0 and a.get("error", {}).get("code") == "previous-does-not-match" and p.version(exe) == NEW, f"an altered kept file: refused as {a.get('error', {}).get('code')}, still {p.version(exe)}")
    previous.write_bytes(kept)
    code, a = p.answer(exe, "update", "--rollback")
    say(code == 0 and p.version(exe) == old_version and a.get("data", {}).get("from") == NEW, f"with it restored, --rollback goes back: {p.version(exe)}")

    # update.auto, by the detached copy's own entry: the running file replaces itself, between runs.
    # From a clean state, because the rollbacks above have rightly put a hold on the new version.
    (config / "update-state.json").unlink()
    p.answer(exe, "config", "set", "update.auto", "true")
    p.run(exe, "__update-check")
    say(p.version(exe) == NEW and sha(previous) == old_sha, f"update.auto: the check installed it: {p.version(exe)}")
    state = json.loads((config / "update-state.json").read_text())
    say((state.get("installed") or {}).get("to") == NEW, "the state says what was installed")
    p.answer(exe, "update", "--rollback")
    p.run(exe, "__update-check")
    say(p.version(exe) == old_version, f"a rollback holds: the next check leaves it at {p.version(exe)}")
    state = json.loads((config / "update-state.json").read_text())
    say(state.get("held") == NEW, "the state says which version is held")
    p.answer(exe, "config", "set", "update.auto", "false")


def on_a_terminal(p, release):
    """The whole notice for real, on Linux: a run starts the check, a later run prints the line."""
    exe = CACHE / f"run-{p.name}" / "bin" / "n0xis"
    config = CACHE / f"run-{p.name}" / "config"
    for name in ("update-state.json", "update-check.stamp", "update-notice.stamp"):
        (config / name).unlink(missing_ok=True)

    def run():
        master, slave = pty.openpty()
        child = subprocess.Popen([str(exe), "guide", "update"], env={**os.environ, **p.env}, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=slave)
        os.close(slave)
        text = b""
        while True:
            ready, _, _ = select.select([master], [], [], 5)
            if not ready:
                break
            try:
                data = os.read(master, 4096)
            except OSError:
                break
            if not data:
                break
            text += data
        child.wait()
        os.close(master)
        return text.decode().strip()

    first = run()
    deadline = time.time() + 10
    while not (config / "update-state.json").exists() and time.time() < deadline:
        time.sleep(0.05)
    second = run()
    step(first == "", f"{p.name} terminal: the first run says nothing and starts the check: {first!r}")
    step(second == f"[n0x] {NEW} is available: n0x update", f"{p.name} terminal: a later run prints the line: {second!r}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--linux", action="store_true")
    ap.add_argument("--wine", action="store_true")
    ap.add_argument("--old-dir", help="an old client kept as a fixture, instead of building one; its files carry their installed names")
    args = ap.parse_args()
    key, public_key, certs = make_key_and_certificates()
    (CACHE / "build.log").write_bytes(b"")
    src = CACHE / "src"
    targets = ([("linux", "")] if args.linux else []) + ([("wine", ".exe")] if args.wine else [])
    fixtures = CACHE / "fixtures"

    # The old build, kept as a fixture for later clients to be tested the same way.
    if not args.old_dir:
        build_tree(src, public_key, OLD)
        for name, suffix in targets:
            build(src, WINDOWS if suffix else None, fixtures)
            print(f"built the old client for {name}", flush=True)

    # The new one, released by the script a release is made with.
    build_tree(src, public_key, NEW)
    built_new = CACHE / "new"
    if built_new.exists():
        shutil.rmtree(built_new)
    prebuilt = CACHE / "prebuilt"
    if prebuilt.exists():
        shutil.rmtree(prebuilt)
    prebuilt.mkdir()
    made = set()
    for _, suffix in [("linux", ""), ("wine", ".exe")]:
        wanted = suffix in {s for _, s in targets}
        if wanted:
            build(src, WINDOWS if suffix else None, built_new)
        os_name = "windows" if suffix else "linux"
        for tool in ("n0xis", "n0xis-mcp"):
            source = built_new / f"{tool}{suffix}"
            asset = prebuilt / f"{tool}-{os_name}-x86_64{suffix}"
            if wanted:
                shutil.copyfile(source, asset)
                made.add(asset)
            else:
                asset.write_bytes(b"this platform was not built by this run")
    dist = CACHE / "dist"
    sh(sys.executable, src / "scripts/release.py", "--tag", f"v{NEW}", "--prebuilt", prebuilt, "--key", key, "--out", dist, stdout=subprocess.DEVNULL)

    # An old client must read a manifest that has grown since it shipped, so this one has.
    manifest = json.loads((dist / "manifest.json").read_text())
    manifest["a_field_of_a_later_release"] = {"anything": [1, 2]}
    manifest["components"]["a-signature-pack"] = {"linux-x86_64": {"layout": "no one has thought of it yet"}}
    for platforms in manifest["components"]["n0xis"].values():
        platforms["delta"] = {"from": OLD, "url": "https://github.com/none", "size": 1}
    (dist / "manifest.json").write_text(json.dumps(manifest, indent=2))
    release = Release(dist, key)
    release.sign()
    tls_port = serve(release, certs)
    seen = []
    proxy_port = proxy(tls_port, seen)
    # Removed rather than set empty: a Windows environment does not tell `https_proxy` from `HTTPS_PROXY`,
    # so under Wine an empty lower-case one took the place of the real one and the binary went direct.
    for name in ("ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "no_proxy", "all_proxy", "http_proxy", "https_proxy"):
        os.environ.pop(name, None)
    base = {"HTTPS_PROXY": f"http://127.0.0.1:{proxy_port}"}
    olds = Path(args.old_dir) if args.old_dir else fixtures

    if args.linux:
        p = Platform("linux", "", [], {**base, "SSL_CERT_FILE": str(certs / "ca.pem")}, str)
        journey(p, release, olds, seen)
        on_a_terminal(p, release)
    if args.wine:
        native = lambda path: "Z:" + str(path).replace("/", "\\")  # noqa: E731
        p = Platform("wine", ".exe", ["wine"], {**base, "SSL_CERT_FILE": native(certs / "ca.pem"), "WINEDEBUG": "-all"}, native)
        journey(p, release, olds, seen)

    print(f"{'ALL OK' if not failures else str(len(failures)) + ' FAILED'}; the old client is kept in {olds}, the key in {key}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""The local gate in one command: everything CI checks that can be checked here, and the oracle tests.

    python3 scripts/gate.py            boundary law, tests, clippy for Linux and for Windows
    python3 scripts/gate.py --wine     also the Windows test suite under Wine (slower)
    python3 scripts/gate.py --no-oracle   without the tests behind the `oracle` features (below)
    python3 scripts/gate.py --no-clippy
    python3 scripts/gate.py -p n0xis-core -p n0xis-arch      tests of these crates only

It prints one line per step and, on a failure, the failing tests with their panics. Full output
goes to the log directory it names, so a run costs a screen, not a scrollback.

Why it is not `cargo test`:

- `cargo test` runs test binaries one after another. Here each runs in a worker of its own, so
  the suite takes about as long as its slowest few binaries.
- Clippy keeps its own target directory, so it runs beside the test build instead of waiting on
  a lock.
- Tests run with the stack a Windows main thread has (`TEST_STACK_KIB`). Rust gives no warning
  of a stack overflow and a process that hits one dies with no answer, so a binary that fits in
  Linux's 8 MiB and not in Windows's 1 MiB used to be found by CI only, after the push.

The `oracle` tests build their targets with a compiler, an assembler or a processor emulator
at run time and check against what that build holds, so their answer depends on the toolchain's
version. CI does not run them, so this does, in a target directory of its own so the plain build
keeps its cache, and only the binaries the features change. They are the checks against a source
that is not the tool, and for a while nothing ran them: they stopped compiling and nobody saw.
One needs a module list in N0XIS_WASM_CORPUS and takes over ten minutes; without it, it is named
as not run.

Memory: it runs in a capped scope when systemd is there (`MEMORY_HIGH`, `MEMORY_MAX`).
"""

import argparse
import json
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WINDOWS = "x86_64-pc-windows-gnu"
# What a Windows main thread has unless the linker is told otherwise.
TEST_STACK_KIB = 1024
TEST_TIMEOUT_S = 900
MEMORY_HIGH, MEMORY_MAX = "5G", "6G"
# These compile a target with `rustc`, and under Wine here the only `rustc` is a Linux program.
WINE_ONLY_FAILURES = {"phase6_remote_exit", "phase5_exit"}
# Measures wall-clock deadlines of its own child processes, so it runs alone, after the others.
RUNS_ALONE = {"plugin_deadline"}
ORACLE_FEATURES = "n0xis-core/oracle,n0xis-cli/oracle,n0xis-sources/oracle,n0xis-wasm/oracle"
ORACLE_CFG = 'feature = "oracle"'
# Oracle tests that cannot run without an input named in the environment: not run, and said so.
ORACLE_NEEDS = {"wasm_facts_are_what_wasm_objdump_lists": "N0XIS_WASM_CORPUS"}
LOG_ROOT = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "n0xis-gate"

# No debug info: the single biggest saving of memory and time. Incremental stays on: after a change to
# a core crate it took the rebuild from 91 s to 49 s, for 1.5 GB of disk.
BUILD_ENV = {"CARGO_PROFILE_TEST_DEBUG": "0"}


def in_capped_scope():
    """True when a finite memory cap already applies to this process."""
    try:
        line = Path("/proc/self/cgroup").read_text().strip().split(":")[-1]
    except OSError:
        return False
    cg = Path("/sys/fs/cgroup" + line)
    while cg != Path("/sys/fs/cgroup") and "user@" not in cg.name:
        try:
            if (cg / "memory.max").read_text().strip() != "max":
                return True
        except OSError:
            pass
        cg = cg.parent
    return False


def reexec_capped():
    if in_capped_scope() or not shutil.which("systemd-run") or os.environ.get("N0XIS_GATE_SCOPED"):
        return
    os.environ["N0XIS_GATE_SCOPED"] = "1"
    os.execvp(
        "systemd-run",
        [
            "systemd-run", "--user", "--scope", "-q", "--collect", "--expand-environment=no",
            f"--unit=n0xis-gate-{os.getpid()}-{time.time_ns()}", "--nice=19",
            "-p", f"MemoryHigh={MEMORY_HIGH}", "-p", f"MemoryMax={MEMORY_MAX}",
            "--", sys.executable, *sys.argv,
        ],
    )


class Log:
    """Where each step's full output goes."""

    def __init__(self):
        sha = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip() or "nohead"
        self.dir = LOG_ROOT / f"{time.strftime('%Y%m%d-%H%M%S')}-{sha}"
        self.dir.mkdir(parents=True)
        self.lock = threading.Lock()

    def path(self, step):
        return self.dir / f"{step}.log"

    def line(self, text):
        with self.lock:
            print(text, flush=True)


def run_step(log, step, cmd, env=None, cwd=ROOT):
    start = time.time()
    with open(log.path(step), "wb") as out:
        rc = subprocess.run(cmd, cwd=cwd, env={**os.environ, **BUILD_ENV, **(env or {})}, stdout=out, stderr=subprocess.STDOUT).returncode
    return rc, time.time() - start


def report(log, step, ok, seconds, note=""):
    log.line(f"{step:<12} {'ok' if ok else 'FAILED':<7} {seconds:6.0f}s  {note}".rstrip())


def compile_tests(log, packages, target=None, target_dir=None, env=None, features=None, step=None):
    """Build the test binaries; returns (name, manifest directory, executable) of each."""
    cmd = ["cargo", "test", "--no-run", "--message-format=json", "-j", str(os.cpu_count() or 4)]
    cmd += [a for p in packages for a in ("-p", p)] or ["--workspace"]
    if target:
        cmd += ["--target", target]
    if features:
        cmd += ["--features", features]
    full_env = {**os.environ, **BUILD_ENV, **(env or {})}
    if target_dir:
        full_env["CARGO_TARGET_DIR"] = str(target_dir)
    step = step or (f"build-{target}" if target else "build")
    start = time.time()
    with open(log.path(step), "wb") as err:
        p = subprocess.run(cmd, cwd=ROOT, env=full_env, stdout=subprocess.PIPE, stderr=err)
    binaries = []
    # With this message format the compiler's diagnostics arrive here and not on stderr.
    with open(log.path(step), "a") as diagnostics:
        for line in p.stdout.splitlines():
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if m.get("reason") == "compiler-artifact" and m.get("executable") and m.get("profile", {}).get("test"):
                binaries.append((m["target"]["name"], str(Path(m["manifest_path"]).parent), m["executable"]))
            elif m.get("reason") == "compiler-message":
                diagnostics.write(m["message"].get("rendered") or "")
    return p.returncode, binaries, time.time() - start


def run_binary(entry, log_dir, runner, env):
    name, manifest_dir, exe = entry
    start = time.time()

    def small_stack():
        resource.setrlimit(resource.RLIMIT_STACK, (TEST_STACK_KIB * 1024, resource.getrlimit(resource.RLIMIT_STACK)[1]))
        os.setsid()

    p = subprocess.Popen([*runner, exe], cwd=manifest_dir, env={**os.environ, "CARGO_MANIFEST_DIR": manifest_dir, **env}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, preexec_fn=small_stack)
    try:
        out, _ = p.communicate(timeout=TEST_TIMEOUT_S)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, _ = p.communicate()
        rc = "timeout"
    text = out.decode(errors="replace")
    (log_dir / f"{Path(exe).name}.log").write_text(text)
    passed = sum(int(n) for n in re.findall(r"^test result: \w+\. (\d+) passed", text, re.M))
    return name, rc, time.time() - start, passed, text


def failure_digest(text):
    """The names of the failed tests and their panics, without the passing noise."""
    keep = []
    in_failure = False
    for line in text.splitlines():
        if re.match(r"---- .* (stdout|stderr) ----", line):
            in_failure = True
        elif line.startswith("failures:") or line.startswith("test result:"):
            in_failure = False
        if in_failure or "overflowed its stack" in line or "SIG" in line:
            keep.append(line[:400])
    return "\n".join(keep[:60]) or "\n".join(text.splitlines()[-20:])


def run_suite(log, step, binaries, runner=(), env=None, allowed=frozenset()):
    """Each binary in a worker of its own. Returns True when nothing but `allowed` failed."""
    start = time.time()
    log_dir = log.dir / step
    log_dir.mkdir()
    workers = max(2, (os.cpu_count() or 4) - 2)
    run = lambda b: run_binary(b, log_dir, list(runner), env or {})  # noqa: E731
    with ThreadPoolExecutor(workers) as pool:
        results = list(pool.map(run, [b for b in binaries if b[0] not in RUNS_ALONE]))
    results += [run(b) for b in binaries if b[0] in RUNS_ALONE]
    failed = [r for r in results if r[1] != 0 and r[0] not in allowed]
    tolerated = [r[0] for r in results if r[1] != 0 and r[0] in allowed]
    slowest = sorted(results, key=lambda r: -r[2])[:3]
    note = f"{sum(r[3] for r in results)} passed in {len(results)} binaries; slowest " + ", ".join(f"{r[0]} {r[2]:.0f}s" for r in slowest)
    if tolerated:
        note += f"; known here only: {', '.join(tolerated)}"
    report(log, step, not failed, time.time() - start, note)
    for name, rc, _, _, text in failed:
        log.line(f"--- {name} rc={rc}\n{failure_digest(text)}")
    return not failed


def tests(log, packages):
    rc, binaries, built = compile_tests(log, packages)
    report(log, "build", rc == 0, built, f"{len(binaries)} test binaries")
    if rc != 0:
        tail_errors(log, "build")
        return False
    return run_suite(log, "tests", binaries)


def tail_errors(log, step):
    text = log.path(step).read_text(errors="replace")
    errors = [m.group(0)[:1500] for m in re.finditer(r"^error.*?(?=^error|\Z)", text, re.M | re.S)]
    log.line("\n".join(errors[:6]) or "\n".join(text.splitlines()[-20:]))


def clippy(log, step, target=None):
    cmd = ["cargo", "clippy", "--workspace", "--all-targets", "-j", str(os.cpu_count() or 4)]
    env = {"CARGO_TARGET_DIR": str(ROOT / "target" / "gate-clippy")}
    if target:
        cmd += ["--target", target]
        env["CARGO_TARGET_DIR"] = str(ROOT / "target" / "gate-clippy-windows")
    rc, seconds = run_step(log, step, [*cmd, "--", "-D", "warnings"], env=env)
    report(log, step, rc == 0, seconds)
    if rc != 0:
        tail_errors(log, step)
    return rc == 0


def wine(log):
    target_dir = ROOT / "target" / "gate-wine"
    rc, binaries, built = compile_tests(log, [], target=WINDOWS, target_dir=target_dir)
    report(log, "build-win", rc == 0, built, f"{len(binaries)} test binaries")
    if rc != 0:
        tail_errors(log, f"build-{WINDOWS}")
        return False
    return run_suite(log, "tests-wine", binaries, runner=("wine",), env={"WINEDEBUG": "-all"}, allowed=WINE_ONLY_FAILURES)


def switched_by_oracle(name, manifest_dir):
    """True when the feature changes what this binary runs; a binary whose source is not found runs."""
    crate = Path(manifest_dir)
    test = crate / "tests" / f"{name}.rs"
    if test.exists():
        return ORACLE_CFG in test.read_text(errors="replace")
    if name == crate.name.replace("-", "_"):
        return any(ORACLE_CFG in f.read_text(errors="replace") for f in (crate / "src").rglob("*.rs"))
    return True


def oracle(log):
    """The test binaries the `oracle` features switch on, built in a directory of their own."""
    rc, binaries, built = compile_tests(log, [], target_dir=ROOT / "target" / "gate-oracle", features=ORACLE_FEATURES, step="build-oracle")
    report(log, "build-oracle", rc == 0, built, f"{len(binaries)} test binaries")
    if rc != 0:
        tail_errors(log, "build-oracle")
        return False
    switched = [b for b in binaries if switched_by_oracle(b[0], b[1])]
    unmet = {b[0]: ORACLE_NEEDS[b[0]] for b in switched if b[0] in ORACLE_NEEDS and not os.environ.get(ORACLE_NEEDS[b[0]])}
    for name, var in sorted(unmet.items()):
        log.line(f"not run      {name}: it needs {var}, which is not set")
    return run_suite(log, "tests-oracle", [b for b in switched if b[0] not in unmet])


def memory_peak():
    """This scope's peak, page cache included, so an upper bound on what the gate needed."""
    try:
        line = Path("/proc/self/cgroup").read_text().strip().split(":")[-1]
        return f"; peak {int(Path('/sys/fs/cgroup' + line, 'memory.peak').read_text()) / 2**30:.1f} GiB"
    except (OSError, ValueError):
        return ""


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--wine", action="store_true", help="also run the Windows test suite under Wine")
    ap.add_argument("--no-oracle", action="store_true", help="skip the tests behind the `oracle` features")
    ap.add_argument("--no-clippy", action="store_true", help="tests only")
    ap.add_argument("-p", dest="packages", action="append", default=[], help="tests of this crate only")
    args = ap.parse_args()
    reexec_capped()
    log = Log()
    start = time.time()

    t = time.time()
    rc = subprocess.run(["sh", "scripts/check_boundary.sh"], cwd=ROOT, stdout=open(log.path("boundary"), "wb"), stderr=subprocess.STDOUT).returncode
    report(log, "boundary", rc == 0, time.time() - t)
    if rc != 0:
        tail_errors(log, "boundary")
        log.line(f"GATE FAILED; logs in {log.dir}")
        sys.exit(1)

    jobs = [lambda: tests(log, args.packages)]
    if not args.no_clippy:
        jobs += [lambda: clippy(log, "clippy"), lambda: clippy(log, "clippy-win", WINDOWS)]
    with ThreadPoolExecutor(len(jobs)) as pool:
        ok = all([f.result() for f in [pool.submit(j) for j in jobs]])
    if ok and args.wine:
        ok = wine(log)
    if ok and not args.no_oracle:
        ok = oracle(log)

    scope = "" if not (args.packages or args.no_clippy or args.no_oracle) else " (partial)"
    log.line(f"GATE {'OK' if ok else 'FAILED'}{scope} in {time.time() - start:.0f}s{memory_peak()}; logs in {log.dir}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

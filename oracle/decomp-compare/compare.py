#!/usr/bin/env python3
"""Did a change alter what `decomp pseudo` answers? Old build against new, on real functions.

    compare.py OLD_BINARY NEW_BINARY OUT.json IMAGE...

The biggest functions of each image (by distance to the next start) plus a seeded random sample.
It prints, per image, how many answers are the same, how many differ and who died, and writes the
addresses to OUT.json. The old build's answers are kept under ~/.cache by the two files' digests, so
asking again about the same build and image runs only the new one.

The old build runs with 8 MiB of stack and the new one with 1 MiB, what a Windows main thread has.

This says what changed, not whether it is right: an unchanged answer may be wrong, and a changed one
needs reading. Calibrate it when it reports nothing: build the new side with a change that must show,
such as a very low `MAX_PROPAGATED_DEPTH` in `optimize.rs`, and see that it does (a bound of 4 reported
77 of 104 functions on the first library tried).
"""

import hashlib
import json
import os
import random
import resource
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

BIGGEST, SAMPLED, JOBS, TIMEOUT_S = 60, 60, 6, 90
OLD_STACK_KIB, NEW_STACK_KIB = 8192, 1024
ADDRESS_SPACE_LIMIT = 6 << 30
SEED = 0x4E30
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "n0xis-decomp-compare"


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


class Runner:
    def __init__(self, root):
        self.root = root

    def project(self, tag):
        d = Path(self.root, f"{tag}-{threading.get_ident()}")
        (d / ".n0x").mkdir(parents=True, exist_ok=True)
        return d

    def ask(self, binary, tag, stack_kib, image, va):
        def limits():
            resource.setrlimit(resource.RLIMIT_STACK, (stack_kib * 1024, stack_kib * 1024))
            resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_LIMIT, ADDRESS_SPACE_LIMIT))

        start = time.time()
        try:
            r = subprocess.run(
                [binary, "decomp", "pseudo", "--file", image, "--addr", va, "--quiet"],
                cwd=self.project(tag), capture_output=True, timeout=TIMEOUT_S, preexec_fn=limits,
            )
        except subprocess.TimeoutExpired:
            return {"died": "timeout", "t": TIMEOUT_S}
        seconds = time.time() - start
        err = r.stderr.decode(errors="replace")
        if not r.stdout or r.returncode < 0 or "overflowed" in err:
            return {"died": "overflow" if "overflowed" in err else f"rc={r.returncode}", "t": seconds}
        try:
            answer = json.loads(r.stdout)
        except ValueError:
            return {"died": "not-json", "t": seconds}
        if answer.get("ok"):
            return {"pseudo": answer["data"].get("pseudo"), "t": seconds, "n": answer["data"].get("instruction_count")}
        return {"refused": answer.get("error", {}).get("code"), "t": seconds}


def starts(binary, image, root):
    d = tempfile.mkdtemp(dir=root)
    os.makedirs(d + "/.n0x")
    r = subprocess.run([binary, "function", "discover", "--file", image, "--quiet"], cwd=d, capture_output=True)
    return sorted(int(f["va"], 16) for f in json.loads(r.stdout)["data"]["functions"])


def compare_image(runner, old, new, old_digest, image):
    vas = starts(new, image, runner.root)
    by_size = sorted(zip(vas, vas[1:]), key=lambda pair: pair[0] - pair[1])
    picked = {a for a, _ in by_size[:BIGGEST]} | set(random.Random(SEED).sample(vas, min(SAMPLED, len(vas))))
    picked = [hex(a) for a in sorted(picked)]

    CACHE.mkdir(parents=True, exist_ok=True)
    kept_path = CACHE / f"{old_digest}-{digest(image)}.json"
    kept = json.loads(kept_path.read_text()) if kept_path.exists() else {}
    missing = [va for va in picked if va not in kept]
    with ThreadPoolExecutor(JOBS) as pool:
        for va, got in zip(missing, pool.map(lambda v: runner.ask(old, "old", OLD_STACK_KIB, image, v), missing)):
            kept[va] = got
    kept_path.write_text(json.dumps(kept))
    with ThreadPoolExecutor(JOBS) as pool:
        fresh = dict(zip(picked, pool.map(lambda v: runner.ask(new, "new", NEW_STACK_KIB, image, v), picked)))

    rows = [(va, kept[va], fresh[va]) for va in picked]
    return {
        "functions": len(vas),
        "asked": len(rows),
        "from_kept": len(picked) - len(missing),
        "same": sum(1 for _, o, n in rows if o.get("pseudo") is not None and o.get("pseudo") == n.get("pseudo")),
        "both_refused": sum(1 for _, o, n in rows if o.get("refused") and n.get("refused")),
        "differ": [(v, o.get("n")) for v, o, n in rows if o.get("pseudo") is not None and n.get("pseudo") is not None and o["pseudo"] != n["pseudo"]],
        "old_dead": [(v, o["died"]) for v, o, _ in rows if o.get("died")],
        "new_dead": [(v, n["died"]) for v, _, n in rows if n.get("died")],
        "seconds_old": round(sum(o["t"] for _, o, _ in rows), 1),
        "seconds_new": round(sum(n["t"] for _, _, n in rows), 1),
    }


def main():
    old, new, out = sys.argv[1:4]
    images = sys.argv[4:]
    root = tempfile.mkdtemp(prefix="decomp-compare-")
    runner = Runner(root)
    old_digest = digest(old)
    results = {}
    try:
        for image in images:
            r = compare_image(runner, old, new, old_digest, image)
            results[image] = r
            print(os.path.basename(image), {k: (len(v) if isinstance(v, list) else v) for k, v in r.items()}, flush=True)
            for kind in ("differ", "new_dead", "old_dead"):
                for va, detail in r[kind][:10]:
                    print(f"   {kind} {va} {detail}", flush=True)
            Path(out).write_text(json.dumps(results, indent=1))
    finally:
        shutil.rmtree(root, ignore_errors=True)
    sys.exit(1 if any(r["differ"] or r["new_dead"] for r in results.values()) else 0)


if __name__ == "__main__":
    main()

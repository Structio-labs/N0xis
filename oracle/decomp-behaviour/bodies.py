#!/usr/bin/env python3
"""The bodies of one image: one `decomp pseudo --file --addr` per address, as a user runs it.

Usage: bodies.py ENGINE IMAGE ADDRS OUT.jsonl
ADDRS: hex addresses, one a line. A directory with its own .n0x/, `ulimit -v 4194304`, a runner's timeout of TIMEOUT_S
(the engine has none of its own). One JSON line per function, the first the meta: the engine's sha256 and the image.
"""
import concurrent.futures as cf, hashlib, json, os, resource, shutil, subprocess, sys

TIMEOUT_S = 120
JOBS = 4


def limits():
    resource.setrlimit(resource.RLIMIT_AS, (4194304 * 1024, 4194304 * 1024))


def ask(engine, image, cwd, a):
    env = dict(os.environ, LC_ALL="C", LANG="C")
    rec = {"entry": a}
    try:
        p = subprocess.run(["nice", "-n", "19", engine, "decomp", "pseudo", "--file", image, "--addr", "0x" + a, "--quiet"], cwd=cwd, capture_output=True, env=env, preexec_fn=limits, timeout=TIMEOUT_S)
    except subprocess.TimeoutExpired:
        rec["timed_out"] = True
        return rec
    try:
        d = json.loads(p.stdout)
    except ValueError:
        rec.update(completed=False, died=True, rc=p.returncode, stderr=p.stderr.decode(errors="replace")[-300:])
        return rec
    if d.get("ok"):
        x = d["data"]
        rec.update(completed=True, c="\n".join(x["pseudo"]) if isinstance(x["pseudo"], list) else x["pseudo"], signature=x.get("signature"), quality=x.get("quality"), flags=x.get("flags"), n=x.get("instruction_count"), end=x.get("end_address"))
    else:
        rec.update(completed=False, refused=d.get("error", {}).get("code"), error=str(d.get("error"))[:300])
    return rec


def run(engine, image, addrs, out):
    asked = [l.strip() for l in open(addrs) if l.strip()]
    cwd = out + ".run"
    shutil.rmtree(cwd, ignore_errors=True)
    os.makedirs(cwd + "/.n0x")
    with cf.ThreadPoolExecutor(JOBS) as ex:
        got = list(ex.map(lambda a: ask(engine, image, cwd, a), asked))
    with open(out, "w") as w:
        w.write(json.dumps({"meta": True, "engine": engine, "sha256": hashlib.sha256(open(engine, "rb").read()).hexdigest(), "image": image, "asked": len(asked), "timeout_s": TIMEOUT_S}) + "\n")
        for r in got:
            w.write(json.dumps(r) + "\n")
    return len(asked), sum(1 for r in got if r.get("completed"))


if __name__ == "__main__":
    print(run(*sys.argv[1:5]))

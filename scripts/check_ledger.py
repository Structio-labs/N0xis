#!/usr/bin/env python3
"""Check docs/verification/ledger.toml against the documents that cite it and the gate run that tests it.

    python3 scripts/check_ledger.py LOG_DIR [--partial]

A claim is `verified` only while the test it names ran and passed in this gate (LOG_DIR holds the
gate's per-binary logs under tests/, tests-wine/ and tests-oracle/). A test that was removed, renamed,
skipped or failed turns the gate red: a mark cannot outlive its check. With --partial (a gate run
that skipped suites) a verified claim whose test did not run is reported, not failed.

Also checked: every `[ledger: <id>]` in ROADMAP.md, README.md and docs/ names a claim; every claim
has the fields its status needs. Exit 0 when all hold.
"""
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "docs" / "verification" / "ledger.toml"
STATUSES = {
    "verified": "a test in this repository checks it against an independent source, and it passed in this run",
    "measured-private": "measured against an independent source with an instrument or input that cannot be public",
    "built": "built and tested against itself only: not verified",
    "false": "known to give a wrong answer: a recorded defect",
}
NEEDS = {"verified": ("test",), "measured-private": ("measured",), "false": ("measured",), "built": ()}
REF = re.compile(r"\[ledger: ([a-z0-9_.-]+)\]")
PASSED = re.compile(r"^test (\S+) \.\.\. ok\s*$")


def passed_tests(log_dir):
    """Names of the tests that passed in this gate run, as `module::name` and as the bare name."""
    out = set()
    for suite in ("tests", "tests-wine", "tests-oracle"):
        for f in (log_dir / suite).glob("*.log"):
            for line in f.read_text(errors="replace").splitlines():
                m = PASSED.match(line)
                if m:
                    out.add(m[1])
                    out.add(m[1].rsplit("::", 1)[-1])
    return out


def citing_documents():
    docs = [ROOT / "ROADMAP.md", ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
    return [d for d in docs if d.is_file()]


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    partial = "--partial" in sys.argv
    if len(args) != 1:
        sys.exit(__doc__)
    log_dir = Path(args[0])
    claims = tomllib.loads(LEDGER.read_text())["claim"]
    errors, notes = [], []
    ids = {}
    for c in claims:
        cid = c.get("id", "?")
        if cid in ids:
            errors.append(f"{cid}: listed twice")
        ids[cid] = c
        for k in ("id", "layer", "says", "oracle", "status"):
            if not c.get(k):
                errors.append(f"{cid}: no `{k}`")
        st = c.get("status")
        if st not in STATUSES:
            errors.append(f"{cid}: status `{st}` is none of {sorted(STATUSES)}")
            continue
        for k in NEEDS[st]:
            if not c.get(k):
                errors.append(f"{cid}: a `{st}` claim needs `{k}`")
    ran = passed_tests(log_dir)
    if not ran:
        errors.append(f"no passed test found under {log_dir}: not a gate log directory")
    for cid, c in ids.items():
        if c.get("status") != "verified":
            continue
        tests = c["test"] if isinstance(c["test"], list) else [c["test"]]
        missing = [t for t in tests if t not in ran]
        if missing:
            (notes if partial else errors).append(f"{cid}: verified by {missing}, which did not pass in this run")
    for doc in citing_documents():
        for n, line in enumerate(doc.read_text(errors="replace").splitlines(), 1):
            for m in REF.finditer(line):
                if m[1] not in ids:
                    errors.append(f"{doc.relative_to(ROOT)}:{n}: [ledger: {m[1]}] names no claim")
    counts = {s: sum(1 for c in claims if c.get("status") == s) for s in STATUSES}
    print("ledger: " + ", ".join(f"{n} {s}" for s, n in counts.items() if n))
    for n in notes:
        print(f"  not run here: {n}")
    for e in errors:
        print(f"  ERROR {e}")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()

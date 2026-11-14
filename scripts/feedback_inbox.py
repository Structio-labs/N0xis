#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Read the local folder of pulled feedback reports: what is new since the last run, grouped by version and error code.

    python3 -I scripts/feedback_inbox.py FOLDER          # list, and remember what was listed
    python3 -I scripts/feedback_inbox.py FOLDER --peek   # list, remember nothing

FOLDER holds what the receiver's `export` names, as pulled: `YYYY-MM/ID/{report.json, sha256, attachment-N.png|jpg}`.
Each report's files are checked against its own `sha256` listing, and one that does not match is said, not hidden.
Attachments are never opened: their names are listed beside the report, for a person to look at.

What was listed is remembered in FOLDER/.inbox-seen, one id a line, so the next run lists only what came after.
"""

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

SEEN = ".inbox-seen"


def reports(folder):
    """Every report under FOLDER, oldest first, as (id, directory)."""
    for month in sorted(p for p in folder.iterdir() if p.is_dir() and len(p.name) == 7 and p.name[4] == "-"):
        for rid in sorted(p for p in month.iterdir() if p.is_dir()):
            yield rid.name, rid


def digests_hold(directory):
    """Whether every file the `sha256` listing names is there with that digest, and nothing else is: None, or why not."""
    listing = directory / "sha256"
    if not listing.is_file():
        return "no sha256 listing"
    named = {}
    for line in listing.read_text(encoding="utf-8", errors="replace").splitlines():
        digest, _, name = line.partition("  ")
        if not name or "/" in name or "\\" in name:
            return f"a listing line that names no file: {line[:60]!r}"
        named[name] = digest
    for name, digest in named.items():
        path = directory / name
        if not path.is_file():
            return f"{name} is missing"
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            return f"{name} is not the bytes its digest states"
    extra = sorted(p.name for p in directory.iterdir() if p.name != "sha256" and p.name not in named)
    return f"files the listing does not name: {', '.join(extra)}" if extra else None


def read(directory):
    """The report's JSON, or why it does not read."""
    try:
        return json.loads((directory / "report.json").read_text(encoding="utf-8")), None
    except (OSError, ValueError) as e:
        return None, f"report.json does not read: {e}"


def error_code(report):
    # `error` is there only when the user handed one over with --with-error.
    last = report.get("error") if isinstance(report, dict) else None
    return last.get("code", "none") if isinstance(last, dict) else "none"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("folder", type=Path)
    ap.add_argument("--peek", action="store_true", help="list without remembering what was listed")
    args = ap.parse_args()
    if not args.folder.is_dir():
        sys.exit(f"feedback_inbox: {args.folder} is not a folder")

    seen_file = args.folder / SEEN
    seen = set(seen_file.read_text(encoding="utf-8").split()) if seen_file.is_file() else set()
    everything = list(reports(args.folder))
    new = [(rid, d) for rid, d in everything if rid not in seen]

    groups_all, groups_new, problems, rows = Counter(), Counter(), [], []
    for rid, directory in everything:
        report, why = read(directory)
        key = (report.get("version", "?"), error_code(report)) if isinstance(report, dict) else ("?", "unreadable")
        groups_all[key] += 1
        if rid in seen:
            continue
        groups_new[key] += 1
        problem = why or digests_hold(directory)
        if problem:
            problems.append(f"{directory.parent.name}/{rid}: {problem}")
        text = (report or {}).get("text", "") if isinstance(report, dict) else ""
        first = next((line.strip() for line in str(text).splitlines() if line.strip()), "")
        attachments = sorted(p.name for p in directory.glob("attachment-*"))
        rows.append(f"  {directory.parent.name}/{rid}  {key[0]}  {(report or {}).get('os', '?')}/{(report or {}).get('arch', '?')}"
                    f"  {first[:90]!r}{'  + ' + ', '.join(attachments) if attachments else ''}")

    print(f"{len(everything)} reports in {args.folder}, {len(new)} new since the last run")
    if groups_all:
        print("by version and error code (new / all):")
        for (version, code), n in sorted(groups_all.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"  {version:<12} {code:<24} {groups_new.get((version, code), 0)} / {n}")
    if rows:
        print("new:")
        print("\n".join(rows))
    if problems:
        print(f"{len(problems)} reports that do not hold together:")
        print("\n".join(f"  {p}" for p in problems))
    if not args.peek and new:
        with open(seen_file, "a", encoding="utf-8") as f:
            f.write("".join(f"{rid}\n" for rid, _ in new))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

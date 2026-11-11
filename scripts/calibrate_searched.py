#!/usr/bin/env python3
"""Calibrate the tests of a scan that says what it searched: remove what each guards, and the named test must fail.

    python3 scripts/calibrate_searched.py            all of them
    python3 scripts/calibrate_searched.py -k window  those whose source file or test name match

The rules are `scripts/calibrate_update.py`'s, and so is the runner: each mutation asserts its anchor is there
exactly once, files are restored from the bytes read, and the run is judged by the named test failing. It edits
the work tree while it runs, so nothing else should build from this tree meanwhile; a run killed part way leaves
its mutation there, so read `git status` after one. `CALIBRATE_JOBS` sets cargo's `-j` (8 by default).
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from calibrate_update import ROOT, run_test  # noqa: E402

REGIONS = "crates/n0xis-sources/src/regions.rs"
SCAN = "crates/n0xis-core/src/scan.rs"
SEARCHED = "crates/n0xis-contracts/src/searched.rs"
REGISTRY = "crates/n0xis-frontend/src/registry.rs"
NEW = ("n0xis-cli", "a_scan_says_what_it_searched")
OLD = ("n0xis-cli", "scan_states_what_it_did_not_read")

JOIN = "Some((at, run)) if at.0.checked_add(run.len() as u64) == Some(start.0)"
GO_ON = "while !bytes.is_empty() && bytes.len() < size {"
WINDOW = "Some((start, size)) => match n0xis_sources::window_regions(pe.as_ref(), start, size) {"

# (file, anchor, replacement, package, test binary or None for the library's own, test name)
MUTATIONS = [
    # Two regions that touch are searched apart again: the seam hides the value.
    (REGIONS, JOIN, "Some((at, run)) if false && at.0.checked_add(run.len() as u64) == Some(start.0)", *NEW, "a_value_across_two_mappings_is_found_by_every_scan"),
    # A read stops at the first section's end, as it did.
    (REGIONS, GO_ON, "while false && !bytes.is_empty() && bytes.len() < size {", *NEW, "a_window_of_an_image_is_read_past_its_first_section"),
    # A file window is one region read from its start, as it was.
    (REGISTRY, WINDOW, "Some((start, size)) => match Ok::<_, n0xis_sources::SourceError>(vec![(start, size)]) {", *NEW, "a_window_of_an_image_is_read_past_its_first_section"),
    # `exhaustive` without what was searched: the default set and the stride are forgotten.
    (SCAN, "read.read_whole() && searched.whole()", "read.read_whole()", *NEW, "an_answer_of_nothing_names_what_it_left_out"),
    (SCAN, "read.read_whole() && searched.whole()", "read.read_whole()", *OLD, "every_other_scan_states_the_same"),
    # A stride past one byte counted as whole.
    (SEARCHED, "self.stride == 1 && self.not_searched.is_empty()", "self.not_searched.is_empty()", *OLD, "every_other_scan_states_the_same"),
    # A file window states nothing of what it searched, as it did.
    (REGISTRY, "Ok(stated) => ok_json(schema, stated, label),", "Ok(stated) => ok_json(schema, stated.answer, label),", *OLD, "a_file_window_says_what_it_searched"),
]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-k", help="only mutations whose file or test name contains this")
    args = ap.parse_args()
    chosen = [m for m in MUTATIONS if (not args.k or args.k in m[0] or args.k in m[5])]
    bad = []
    for path, anchor, replacement, package, binary, test in chosen:
        file = ROOT / path
        original = file.read_bytes()
        text = original.decode()
        assert text.count(anchor) == 1, f"{path}: the anchor is there {text.count(anchor)} times: {anchor}"
        try:
            file.write_text(text.replace(anchor, replacement))
            verdict, log = run_test(package, binary, test)
        finally:
            file.write_bytes(original)
        ok = verdict == "failed"
        print(f"{'ok    ' if ok else 'MISSED'} {verdict:<17} {test}  <-  {anchor[:50]!r}", flush=True)
        if not ok:
            bad.append((test, anchor, verdict))
            if verdict == "does-not-compile":
                errors = [line for line in log.splitlines() if line.startswith("error")]
                print("       " + " | ".join(errors[:3])[:300], flush=True)
    print(f"{len(chosen) - len(bad)} of {len(chosen)} calibrated")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

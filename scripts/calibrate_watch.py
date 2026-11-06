#!/usr/bin/env python3
"""Calibrate the tests of a watchpoint that outlives no run unaccounted for: remove what each guards, and the
named test must fail.

    python3 scripts/calibrate_watch.py            all of them
    python3 scripts/calibrate_watch.py -k signal  those whose source file or test name match

The rules are `scripts/calibrate_update.py`'s, and so is the runner: each mutation asserts its anchor is
there exactly once, files are restored from the bytes read, and the run is judged by the named test failing.
It edits the work tree while it runs, so nothing else should build from this tree meanwhile; a run killed part way
leaves its mutation there, so read `git status` after one.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from calibrate_update import ROOT, run_test  # noqa: E402

JOURNAL = "crates/n0xis-project/src/patch.rs"
SLOT = "crates/n0xis-sources/src/watch_slot.rs"
LINUX = "crates/n0xis-sources/src/dbg_linux.rs"
DOOR = "crates/n0xis-frontend/src/watch.rs"
CLI = "crates/n0xis-cli/src/main.rs"
MCP = "crates/n0xis-mcp/src/tools.rs"
KILL = ("n0xis-cli", "a_watchpoint_outlives_no_run_unaccounted")
HERE_TOO = ("n0xis-mcp", "a_watchpoint_is_on_the_record_here_too")
READ = ("n0xis-sources", "debug_linux")

WRITE_RECORD = "    write_record(&rec.id, &rec)?;\n    Ok(rec)\n}\n\n/// The record goes if"
SETTLE = "    let clear = found.clear();\n    if clear {\n        remove(&rec.id)?;\n    }\n    Ok(clear)"
POKE_DR7 = "            pokeuser(tid, dr_off(7), WatchSlot::cleared_from(dr7));\n"
POKE_BOTH = POKE_DR7 + "            pokeuser(tid, dr_off(0), 0);\n"

# (file, anchor, replacement, package, test binary or None for the library's own, test name)
MUTATIONS = [
    # The record: the journal has it before the target does.
    (JOURNAL, WRITE_RECORD, "    Ok(rec)\n}\n\n/// The record goes if", *KILL, "a_killed_watch_leaves_a_record_and_patch_undo_clears_it"),
    (DOOR, 'pj::record_before_arming(w.pid, slot, w.planted_by)\n            .map_err(|e| format!("nothing was armed, because no record of it could be kept: {e}"))?;', 'pj::record_before_arming(w.pid, slot, w.planted_by)\n            .map_err(|e| format!("{e}"))?;', *KILL, "a_journal_that_cannot_be_written_means_nothing_is_armed"),
    (LINUX, "    before_arming(&slot).map_err(os)?;\n", "    let _ = before_arming(&slot);\n", *KILL, "a_journal_that_cannot_be_written_means_nothing_is_armed"),
    (CLI, 'planted_by: "debug watch",', 'planted_by: "debug",', *KILL, "a_killed_watch_leaves_a_record_and_patch_undo_clears_it"),
    (CLI, 'planted_by: "provenance trace",', 'planted_by: "debug watch",', *KILL, "a_killed_provenance_trace_is_on_the_record_too"),
    (MCP, 'planted_by: "provenance_trace",', 'planted_by: "debug watch",', *HERE_TOO, "provenance_trace_is_on_the_record_while_it_waits_and_not_after"),
    (DOOR, 'eprintln!("[n0x] watchpoint at {} recorded as patch {}: if this run is killed, `n0xis patch undo --id {}` clears the debug register", w.addr, rec.id, rec.id);', "let _ = rec.id.len();", *KILL, "a_killed_watch_leaves_a_record_and_patch_undo_clears_it"),
    # The clearing: `patch undo` takes it out of the threads, and says what it found.
    (CLI, "pj::Record::DebugRegister(rec) => return patch_undo_watch(&rec, a.pid, pretty),", 'pj::Record::DebugRegister(rec) => { let _ = pj::settle_armed(&rec, &n0xis_sources::TargetSlots::Gone); return emit(&Response::success(schema::v1::PATCH, json!({"op": "undo", "threads_cleared": 2, "slots_cleared": 2, "threads_seen": 3})), pretty); }', *KILL, "a_killed_watch_leaves_a_record_and_patch_undo_clears_it"),
    (LINUX, POKE_BOTH, "", *KILL, "a_killed_watch_leaves_a_record_and_patch_undo_clears_it"),
    # Every other slot stays.
    (SLOT, "dr7 & !(DR7_ENABLE | DR7_RW_LEN)", "dr7 & 0", *KILL, "every_other_slot_stays_as_it_was"),
    (SLOT, "dr0 == self.addr.0 && ", "", *KILL, "every_other_slot_stays_as_it_was"),
    (SLOT, " && dr7 & DR7_RW_LEN == bits & DR7_RW_LEN", " && bits != 0", *READ, "reading_and_clearing_a_slot_is_what_the_kernel_says_is_there"),
    # A target that is gone, or holds nothing, and the mistyped `--pid`.
    (LINUX, '    if has_no_living_thread(pid) {\n        return Ok(TargetSlots::Gone);\n    }\n', "", *KILL, "a_target_that_is_gone_clears_nothing_and_says_so"),
    (LINUX, '    matches!(state, Some("Z" | "X" | "x"))', "    let _ = state;\n    false", *KILL, "a_target_that_is_gone_clears_nothing_and_says_so"),
    (CLI, "    if cleared == 0 {\n        data[\"note\"]", "    if false {\n        data[\"note\"]", *KILL, "a_reused_pid_holding_nothing_of_ours_clears_nothing_and_says_so"),
    (CLI, "let elsewhere = pid != rec.pid && cleared == 0;", "let elsewhere = false;", *KILL, "patch_undo_with_another_pid_that_holds_nothing_keeps_the_record"),
    # The record goes when, and only when, the target is read back as clear.
    (JOURNAL, SETTLE, "    let _ = (rec, found);\n    Ok(true)", *KILL, "a_watch_that_ends_by_itself_leaves_no_record"),
    (SLOT, "            TargetSlots::Present(c) => c.holding == 0 && c.unread == 0,", "            TargetSlots::Present(_) => true,", "n0xis-sources", None, "watch_slot::tests::only_a_thread_read_as_clear_is_clear"),
    # A failed clear in the run itself: the read-back says so and the record stays. Without the read-back, this passes.
    (LINUX, "            pokeuser(tid, dr_off(7), o7);\n", "", *KILL, "a_watch_that_ends_by_itself_leaves_no_record"),
    # A signal is handled while it waits, which on Linux it was not.
    (LINUX, "    let _interruptible = Interruptible::install();\n    let mut s = seize_group(pid)?;\n    before_arming(&slot)", "    let mut s = seize_group(pid)?;\n    before_arming(&slot)", *KILL, "sigterm_clears_the_register_and_detaches"),
    # An old journal, and a record that is never bytes.
    (JOURNAL, "#[serde(untagged)]\npub enum Record {", "pub enum Record {", *KILL, "an_old_journal_still_reads_and_undoes_as_bytes"),
    (JOURNAL, '#[serde(rename = "applied")]', '#[serde(rename = "applied", alias = "undone")]', "n0xis-project", None, "patch::tests::a_debug_register_cannot_be_on_record_as_undone"),
]

# A crate alone is built with its default features, and these tests are behind one.
CARGO_ARGS = {"n0xis-sources": ("--features", "static-pe,static-wasm,live")}


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
            verdict, log = run_test(package, binary, test, CARGO_ARGS.get(package, ()))
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

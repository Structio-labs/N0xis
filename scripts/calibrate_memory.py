#!/usr/bin/env python3
"""Calibrate the tests of an answer that fits and a session that survives one: remove what each guards,
and the named test must fail.

    python3 scripts/calibrate_memory.py            all of them
    python3 scripts/calibrate_memory.py -k orphan  those whose source file or test name match

The rules are `scripts/calibrate_update.py`'s, and so is the runner: each mutation asserts its anchor is
there exactly once, files are restored from the bytes read, and the run is judged by the named test failing.
It edits the work tree while it runs, so nothing else should build from this tree meanwhile; a run killed part way
leaves its mutation there, so read `git status` after one. `--skip FILE` skips the tests named in FILE's lines of an earlier
run that passed the calibration.
"""

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from calibrate_update import ROOT, run_test  # noqa: E402

# `cargo test --test X` does not build examples, so a test that runs one would run the unmutated
# one and pass, which reads as a guard that guards nothing. This is how that was found.
EXAMPLES = {"a_refusal_never_follows_part_of_an_answer": ("n0xis-cli", "an_answer_past_the_ceiling")}
# A crate alone is built with its default features, and these tests are behind one.
CARGO_ARGS = {"n0xis-sources": ("--features", "static-pe")}

SUP = "crates/n0xis-mcp/src/supervisor.rs"
MAIN = "crates/n0xis-mcp/src/main.rs"
EMIT = "crates/n0xis-cli/src/emit.rs"
CEILING = "crates/n0xis-core/src/ceiling.rs"
ELF = "crates/n0xis-sources/src/static_elf.rs"
STRINGS = "crates/n0xis-frontend/src/strings_caps.rs"
SESSION = ("n0xis-mcp", "a_session_survives_the_engine")
WRITE = ("n0xis-cli", "a_refusal_never_follows_part_of_an_answer")

# (file, anchor, replacement, package, test binary or None for the library's own, test name)
MUTATIONS = [
    # An answer has no second copy, and no refusal follows part of one.
    (EMIT, "    let _writing = n0xis_core::lift_while_writing();\n    write_out(resp, pretty) && resp.is_ok()", "    write_out(resp, pretty) && resp.is_ok()", *WRITE, "past_the_ceiling_while_writing_the_answer_is_written_whole"),
    (EMIT, "    let _writing = n0xis_core::lift_while_writing();\n    write_out(resp, pretty) && resp.is_ok()", "    write_out(resp, pretty) && resp.is_ok()", *WRITE, "the_same_when_pretty"),
    (CEILING, "        CEILING.store(self.ceiling, Ordering::Relaxed);\n", "", *WRITE, "the_ceiling_is_back_once_the_answer_is_written"),
    (EMIT, "            if out.get_ref().any {", "            if false {", *WRITE, "a_failure_to_serialize_past_the_first_write_adds_no_second_envelope"),
    (EMIT, "            if out.get_ref().any {", "            if true {", *WRITE, "a_failure_to_serialize_with_nothing_written_is_the_whole_answer"),
    (EMIT, 'Err(e) if e.is_io() => panic!("failed printing to stdout: {e}"),', "Err(e) if e.is_io() => false,", *WRITE, "a_closed_pipe_is_what_it_was"),
    # The value form's bytes.
    (STRINGS, "struct CutByRow {\n    at: Va,\n    kind: n0xis_core::CutKind,\n}", "struct CutByRow {\n    kind: n0xis_core::CutKind,\n    at: Va,\n}", "n0xis-frontend", None, "strings_caps::tests::rows_write_what_the_value_form_wrote"),
    (STRINGS, "    section: &'a str,\n    size: usize,\n    text: &'a str,\n}", "    size: usize,\n    section: &'a str,\n    text: &'a str,\n}", "n0xis-frontend", None, "strings_caps::tests::rows_write_what_the_value_form_wrote"),
    (STRINGS, 'next_if(|(key, _)| key.as_str() < "ranges")', 'next_if(|(key, _)| key.as_str() < "a")', "n0xis-frontend", None, "strings_caps::tests::rows_write_what_the_value_form_wrote"),
    # A table of relocated words is counted before one is kept.
    (ELF, "    if decoded > bytes.len() / usize::from(crate::PointerWidth::of_64_bit(elf.is_64).bytes()) {\n", "    if false {\n", "n0xis-sources", None, "static_elf::relr_tests::a_table_naming_more_words_than_the_file_has_keeps_none"),
    (ELF, "    if decoded > bytes.len() / usize::from(crate::PointerWidth::of_64_bit(elf.is_64).bytes()) {\n", "    if decoded > bytes.len() / 512 {\n", "n0xis-sources", None, "static_elf::relr_tests::a_table_that_fits_is_read"),
    (ELF, "    if decoded > bytes.len() / usize::from(crate::PointerWidth::of_64_bit(elf.is_64).bytes()) {\n", "    if decoded > bytes.len() / 64 {\n", "n0xis-sources", None, "static_elf::relr_tests::a_dense_table_in_a_file_with_room_is_read"),
    # What the worker's exit says.
    (MAIN, "std::process::exit(supervisor::EXIT_PAST_THE_CEILING);", "std::process::exit(1);", *SESSION, "a_query_past_the_ceiling_gets_its_error_and_the_next_answers"),
    (SUP, "status.code() == Some(EXIT_PAST_THE_CEILING)", "status.code() != Some(0)", *SESSION, "the_exit_code_tells_the_ceiling_from_a_crash"),
    # Each request in flight gets its error.
    (SUP, "    if let Some(status) = status {\n        for id in &pending {", "    if let Some(status) = status {\n        for id in pending.iter().take(1) {", *SESSION, "every_request_in_flight_gets_the_error"),
    (SUP, "    if let Some(status) = status {\n        for id in &pending {", "    if let Some(status) = status {\n        for id in pending.iter().take(1) {", *SESSION, "a_request_in_flight_when_another_dies_gets_the_error_too"),
    (SUP, "FromClient::Cancelled(id) => session.pending.retain(|p| *p != id),", "FromClient::Cancelled(_) => {}", *SESSION, "a_cancelled_request_is_owed_nothing"),
    # A new worker gets the opening, and the response to it goes nowhere.
    (SUP, "        if let Some(line) = initialized {\n            let _ = stdin.write_all(&line).and_then(|()| stdin.flush());\n        }\n", "        let _ = initialized;\n", *SESSION, "a_new_worker_gets_the_opening_and_not_the_request"),
    (SUP, "            if swallow.is_none() {\n                // A client that has gone", "            if true {\n                // A client that has gone", *SESSION, "a_new_worker_gets_the_opening_and_not_the_request"),
    # The next query in the session answers: without the replay the real server refuses it.
    (SUP, "        match session.hello.as_ref().filter(|h| h.answered) {", "        match session.hello.as_ref().filter(|_| false) {", *SESSION, "a_query_past_the_ceiling_gets_its_error_and_the_next_answers"),
    # A worker dead mid-line.
    (SUP, '    if mid_line.swap(false, Ordering::SeqCst) {\n        let _ = out.write_all(b"\\n");\n    }\n', "", *SESSION, "a_worker_dead_mid_line_leaves_one_line_that_does_not_parse"),
    # A response counts once its line has ended, and not when its id has gone by.
    (SUP, "            if ends_line {\n                let line = scan.finish();", "            if let Some(id) = (scan.at == At::Settled).then(|| serde_json::from_slice::<Value>(&scan.id).ok()).flatten() {\n                shared.session().answered(&id);\n            }\n            if ends_line {\n                let line = scan.finish();", *SESSION, "a_worker_dead_mid_line_leaves_one_line_that_does_not_parse"),
    # A death is read from the worker, not only from its output.
    (SUP, "        if let Ok(Some(status)) = child.try_wait() {\n            break status;\n        }\n", "", *SESSION, "a_worker_dead_with_its_output_held_open_is_still_noticed"),
    # A crash loop ends.
    (SUP, "        if deaths.len() > MOST_DEATHS {", "        if false {", *SESSION, "a_worker_that_dies_at_once_ends_the_parent_with_its_reason"),
    (SUP, "        if deaths.len() > MOST_DEATHS {", "        if false {", *SESSION, "deaths_with_no_answer_between_them_end_the_parent"),
    (SUP, "        if answered {\n            deaths.clear();\n        }\n", "        let _ = answered;\n", *SESSION, "deaths_with_answers_between_them_go_on_for_ever"),
    (SUP, "        if !answered {\n            let _ = child.kill();", "        if false {\n            let _ = child.kill();", *SESSION, "a_worker_that_dies_on_the_replayed_initialize_ends_the_parent"),
    # No orphan.
    (SUP, "    let status = wait_bounded(&mut child, SHUTDOWN_DEADLINE).or_else(|| {\n        let _ = child.kill();\n        let _ = child.wait();\n        None\n    });", "    let status = wait_bounded(&mut child, SHUTDOWN_DEADLINE);\n    std::mem::forget(child);", *SESSION, "a_worker_that_stays_after_the_client_closes_is_killed"),
    (MAIN, "            Ok(()) => std::process::exit(0),\n", "            Ok(()) => {\n                drop(runtime);\n                std::process::exit(0)\n            }\n", *SESSION, "the_parent_killed_ends_a_busy_real_worker_with_no_orphan"),
    (SUP, "    session.client_gone = true;\n    session.worker = None;\n", "    session.client_gone = true;\n", *SESSION, "the_client_closing_ends_the_real_worker_with_no_orphan"),
    (MAIN, "            Ok(()) => std::process::exit(0),\n", "            Ok(()) => loop {\n                std::thread::park();\n            },\n", *SESSION, "the_parent_killed_ends_the_real_worker_with_no_orphan"),
    # The parent holds no whole response.
    (SUP, "        for piece in chunk[..n].split_inclusive(|&b| b == b'\\n') {", "        std::mem::forget(chunk[..n].to_vec());\n        for piece in chunk[..n].split_inclusive(|&b| b == b'\\n') {", *SESSION, "the_parent_holds_no_whole_response"),
]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-k", help="only mutations whose file or test name contains this")
    ap.add_argument("--skip", help="an earlier run's output: its calibrated lines are not run again")
    args = ap.parse_args()
    chosen = [m for m in MUTATIONS if (not args.k or args.k in m[0] or args.k in m[5])]
    if args.skip:
        done = [line.split() for line in Path(args.skip).read_text().splitlines() if line.startswith("ok ")]
        marks = {(d[2], line_anchor) for d, line_anchor in ((d, " ".join(d[4:])) for d in done)}
        chosen = [m for m in chosen if (m[5], " ".join(repr(m[1][:50]).split())) not in marks]
    bad = []
    for path, anchor, replacement, package, binary, test in chosen:
        file = ROOT / path
        original = file.read_bytes()
        text = original.decode()
        assert text.count(anchor) == 1, f"{path}: the anchor is there {text.count(anchor)} times: {anchor}"
        try:
            file.write_text(text.replace(anchor, replacement))
            if binary in EXAMPLES:
                example = EXAMPLES[binary]
                subprocess.run(["systemd-run", "--user", "--scope", "-q", "--nice=19", "-p", "MemoryMax=6G", "--", "cargo", "build", "-p", example[0], "--example", example[1], "-j", "8"], cwd=ROOT, capture_output=True)
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

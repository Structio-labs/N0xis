#!/usr/bin/env python3
"""Calibrate the tests of an answer that says what it looked through (a scan's `searched`, a list's `total`): remove what each guards, and the named test must fail.

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
CUT = ("n0xis-cli", "a_cut_list_says_its_total")
WAIT = ("n0xis-cli", "a_wait_says_why_it_ended")
LANDED = ("n0xis-cli", "a_failed_write_says_what_landed")
WALK = ("n0xis-cli", "a_backtrace_after_a_call_that_does_not_return")
UNWIND_LIB = ("n0xis-sources", None)
HIT = "crates/n0xis-sources/src/hit.rs"
DBG_LINUX = "crates/n0xis-sources/src/dbg_linux.rs"
WATCH = "crates/n0xis-frontend/src/watch.rs"
PATCH = "crates/n0xis-project/src/patch.rs"
MAIN = "crates/n0xis-cli/src/main.rs"
UNWIND = "crates/n0xis-sources/src/unwind.rs"
LIVE = ("--features", "live")
PROVENANCE = ("n0xis-cli", "a_provenance_names_the_writer")
CORE_LIB = ("n0xis-core", None)

JOIN = "Some((at, run)) if at.0.checked_add(run.len() as u64) == Some(start.0)"
GO_ON = "while !bytes.is_empty() && bytes.len() < size {"
WINDOW = "Some((start, size)) => match n0xis_sources::window_regions(pe.as_ref(), start, size) {"

# (file, anchor, replacement, package, test binary or None for the library's own, test name[, cargo args])
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
    # A cut list's total is the cut's length again.
    (SEARCHED, "Shown { total, truncated: all.len() < total }", "Shown { total: all.len(), truncated: false }", *CUT, "a_function_list_cut_at_a_limit_says_its_total"),
    (SEARCHED, "Shown { total, truncated: all.len() < total }", "Shown { total: all.len(), truncated: false }", *CUT, "a_memory_map_cut_at_a_limit_says_its_total"),
    # The map listed only up to the limit, as it was.
    (REGISTRY, "let mut regions = live.regions(n0xis_sources::ALL_REGIONS);", "let mut regions = live.regions(limit.max(1));", *CUT, "a_memory_map_cut_at_a_limit_says_its_total"),
    # Discovery stops at the limit again, so the total is the cut.
    (REGISTRY, "n0xis_core::DiscoverInput { start, size, limit: 0, offset: 0 },\n                        ) {\n                            Ok(d) => d,\n                            Err(e) => return Response::error(\"discover-failed\"", "n0xis_core::DiscoverInput { start, size, limit, offset: 0 },\n                        ) {\n                            Ok(d) => d,\n                            Err(e) => return Response::error(\"discover-failed\"", *CUT, "a_function_list_cut_at_a_limit_says_its_total"),
    # A wait with no hit is a timeout again, whatever ended it.
    (HIT, "matches!(self.ended, Ended::TimedOut)", "self.hit().is_none()", *WAIT, "a_target_killed_during_await_hit_is_gone_not_timed_out"),
    (HIT, "matches!(self.ended, Ended::TimedOut)", "self.hit().is_none()", *WAIT, "a_target_killed_during_a_watch_is_gone_not_timed_out"),
    # An unmapped address is armed and waited on, as it was.
    (WATCH, "matches!(live.read(w.addr, 1), Err(SourceError::Unmapped(_)))", "false", *WAIT, "a_watch_on_an_address_no_mapping_holds_is_refused"),
    # Hits set aside go uncounted.
    (DBG_LINUX, "excluded_hits: (!exclude_rip.is_empty()).then_some(excluded),", "excluded_hits: None,", *WAIT, "hits_set_aside_by_exclude_rip_are_counted"),
    # Old bytes read up to the mapping's end, as they were: the patch is written, and recorded short.
    (PATCH, "    if bytes.len() < len {\n        return Err(anyhow!(", "    if false && bytes.len() < len {\n        return Err(anyhow!(", *LANDED, "a_patch_across_a_mappings_end_is_refused_and_writes_nothing"),
    # The dry run reads up to the end again and says `wouldChange`.
    (MAIN, "n0xis_project::patch::read_exact(live.as_ref(), addr, desired.len())", "n0xis_project::patch::read_exact(live.as_ref(), addr, 0).map(|_| live.read(addr, desired.len()).unwrap_or_default())", *LANDED, "a_patch_across_a_mappings_end_is_refused_and_writes_nothing"),
    # A failed write takes its record back whatever it changed.
    (PATCH, "if landed.changed == 0 && landed.read_back == landed.of {", "if true {", *LANDED, "a_patch_that_fails_part_way_keeps_its_record_and_says_what_changed"),
    # Old bytes are read one mapping at a time again: 4 of 8 across two readable mappings.
    (REGIONS, "    let mut bytes = src.read(start, size)?;\n    read_on(src, start, size, &mut bytes)?;", "    let bytes = src.read(start, size)?;", *LANDED, "a_patch_that_fails_part_way_keeps_its_record_and_says_what_changed"),
    # `mem write` says only that it failed.
    (REGISTRY, 'format!("{e}: {}", n0xis_project::patch::Landed::read(live.as_ref(), addr, &before, bytes.len()))', "e.to_string()", *LANDED, "mem_write_across_a_mappings_end_says_how_many_bytes_changed"),
    # A caller's unwind rule is looked up at its return address again.
    (UNWIND, "let at = if caller { regs.rip.wrapping_sub(1) } else { regs.rip };", "let at = regs.rip;", *WALK, "the_walk_goes_on_past_a_call_that_ends_its_function"),
    (UNWIND, "let at = if caller { regs.rip.wrapping_sub(1) } else { regs.rip };", "let at = regs.rip;", *UNWIND_LIB, "unwind::dwarf::tests::a_return_address_past_its_functions_end_unwinds_by_the_call", LIVE),
    # A return address in no mapping is printed as a frame again.
    (UNWIND, "if caller && owner.is_none() && reader.read(regs.rip, 1).is_none() {", "if false {", *UNWIND_LIB, "unwind::dwarf::tests::a_return_address_in_no_mapping_is_not_a_frame", LIVE),
    # The backtrace says only how many threads it walked.
    (MAIN, "let threads_in_process = in_process.len();", "let threads_in_process = 1usize;", *WALK, "a_backtrace_of_one_thread_says_how_many_the_process_has"),
    # Provenance searches with an empty context again: none of the functions the image states.
    ("crates/n0xis-frontend/src/provenance.rs", "\n        .with_stated_functions(&stated, crate::registry::stated_coverage(&src));", ";", *PROVENANCE, "the_writer_an_unaligned_function_after_a_jmp_is_named_with_its_instruction"),
    # An unresolved indirect jump is not counted as an unknown call, nor kept from `leaf`.
    ("crates/n0xis-core/src/summary.rs", "if cfg.leaves_by_an_unresolved_jump() {", "if false {", *CORE_LIB, "summary::tests::an_unresolved_indirect_jump_is_an_unknown_call"),
    ("crates/n0xis-core/src/manifest.rs", "if art.callsites.is_empty() && !cut && !art.leaves_by_an_unresolved_jump() {", "if art.callsites.is_empty() && !cut {", *CORE_LIB, "manifest::tests::an_unresolved_indirect_jump_is_not_a_leaf"),
    # `no-return` of a graph that leaves by a jump nothing resolved, again.
    ("crates/n0xis-core/src/manifest.rs", "if art.stats.returns == 0 && art.stats.tail_calls == 0 && !cut && !art.leaves_by_an_unresolved_jump() {", "if art.stats.returns == 0 && art.stats.tail_calls == 0 && !cut {", *CORE_LIB, "manifest::tests::an_unresolved_indirect_jump_is_not_said_not_to_return"),
    # `writes_memory`: every store counts, the frame's too.
    ("crates/n0xis-core/src/summary.rs", "MicroStmt::Store { addr, .. } => frame.offset(addr).is_none(),", "MicroStmt::Store { .. } => true,", *CORE_LIB, "summary::tests::a_store_into_its_own_frame_is_not_a_write"),
    ("crates/n0xis-core/src/summary.rs", "MicroStmt::Store { addr, .. } => frame.offset(addr).is_none(),", "MicroStmt::Store { .. } => true,", "n0xis-cli", "writes_memory_is_outside_the_frame", "every_function_says_whether_it_stores_outside_its_frame", ("--features", "oracle")),
    # An instruction the lift kept verbatim writes nothing.
    ("crates/n0xis-core/src/summary.rs", "MicroStmt::Unlifted { mem, .. } => mem.may_write(),", "MicroStmt::Unlifted { .. } => false,", *CORE_LIB, "summary::tests::a_store_outside_the_frame_is_a_write_and_a_load_is_not"),
    # The address of a frame expression is not placed: a pointer into the frame is not the frame.
    ("crates/n0xis-core/src/ssa.rs", "MicroExpr::AddrOf(inner) => of(inner),", "MicroExpr::AddrOf(inner) if false => of(inner),", *CORE_LIB, "summary::tests::a_store_into_its_own_frame_is_not_a_write"),
    # A cut to the width of an address is not seen through: nothing on i386 is placed.
    ("crates/n0xis-core/src/ssa.rs", "MicroExpr::Cast { bits, expr, .. } if Some(*bits) == address_bits => {", "MicroExpr::Cast { bits, expr, .. } if false && Some(*bits) == address_bits => {", *CORE_LIB, "summary::tests::an_i386_local_is_in_the_frame_and_a_store_through_an_argument_is_not"),
    # Seen through without wrapping: a 32-bit displacement stays an unsigned word.
    ("crates/n0xis-core/src/ssa.rs", "(*bits > 0 && *bits < 128).then(|| (off << shift) >> shift)", "(*bits > 0 && *bits < 128 && shift > 0).then_some(off)", *CORE_LIB, "ssa::tests::an_i386_slot_is_placed_at_its_signed_offset"),
]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-k", help="only mutations whose file or test name contains this")
    args = ap.parse_args()
    chosen = [m for m in MUTATIONS if (not args.k or args.k in m[0] or args.k in m[5])]
    bad = []
    for path, anchor, replacement, package, binary, test, *cargo_args in chosen:
        file = ROOT / path
        original = file.read_bytes()
        text = original.decode()
        assert text.count(anchor) == 1, f"{path}: the anchor is there {text.count(anchor)} times: {anchor}"
        try:
            file.write_text(text.replace(anchor, replacement))
            verdict, log = run_test(package, binary, test, *cargo_args)
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

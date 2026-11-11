#!/usr/bin/env python3
"""Calibrate the tests of what a decompiled body says a function takes, gives back and calls: remove what each guards,
and the named test must fail.

    python3 scripts/calibrate_bodies.py            all of them
    python3 scripts/calibrate_bodies.py -k void    those whose source file or test name match

The rules and the runner are `scripts/calibrate_update.py`'s: each mutation asserts its anchor is there exactly once,
files are restored from the bytes read, and the run is judged by the named test failing. It edits the work tree while it
runs, so nothing else should build from this tree meanwhile.
"""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from calibrate_update import ROOT  # noqa: E402
import calibrate_update  # noqa: E402

CORE = "crates/n0xis-core/src/"
LIB = ("n0xis-core", None)
# A test that spawns a compiler is a local instrument, built only with the `oracle` feature.
ORACLE = ("--features", "oracle")

# (file, anchor, replacement, package, test binary or None for the library's own, test name[, cargo arguments])
MUTATIONS = [
    # What an earlier process found about the image is read, and only for that image.
    (CORE + "callee.rs", "        let kept = store.load(&id).unwrap_or_default();", "        let kept = KeptAnswers::default();", "n0xis-cli", "kept_answers_are_the_images", "a_kept_answer_is_read_and_only_for_its_image", ORACLE),
    ("crates/n0xis-pipeline/src/lib.rs", "        identity.hash(&mut h);\n        format!(\"{}{:016x}\", answers_cache_generation(), h.finish())", "        format!(\"{}{:016x}\", answers_cache_generation(), h.finish())", "n0xis-cli", "kept_answers_are_the_images", "a_kept_answer_is_read_and_only_for_its_image", ORACLE),
    # What a function takes.
    (CORE + "ssa.rs", "if seen.iter().any(|(n, left)| *left && passed.contains(n)) {", "if false {", *LIB, "callee::tests::a_value_moved_to_a_call_is_a_parameter"),
    (CORE + "callee.rs", "        if takes_of(ctx, id.as_deref(), callee, depth).floor() > pos {", "        if false {", *LIB, "callee::tests::a_register_passed_on_as_it_came_is_a_parameter_when_the_callee_reads_it"),
    (CORE + "callee.rs", "        if takes_of(ctx, id.as_deref(), callee, depth).floor() > pos {", "        if false {", *LIB, "callee::tests::the_question_goes_down_through_a_function_that_only_passes_it_on"),
    (CORE + "typeinfer.rs", "MicroStmt::Store { addr, value: MicroExpr::Var(v), .. } if flow.saved.contains(v) => walk(addr, &mut out),", "", *LIB, "callee::tests::a_register_merely_saved_and_restored_is_not_a_parameter"),
    (CORE + "callee.rs", "    used.extend(flow.stored_at.keys().filter(|e| !flow.saved.contains(*e)).cloned());", "", *LIB, "callee::tests::a_store_nothing_loads_is_not_a_save"),
    (CORE + "callee.rs", "    if let Some(from) = unnamed_from {", "    if let Some(from) = unnamed_from.filter(|_| false) {", *LIB, "callee::tests::a_register_save_area_is_no_read_for_who_calls_it"),
    (CORE + "decomp.rs", "        let names = names.with_from_caller(from_caller);", "        let names = names.with_from_caller(Default::default());", *LIB, "callee::tests::a_register_read_that_is_no_parameter_is_marked"),
    # What a call is given.
    (CORE + "callee.rs", "            Some(Def::Clobber) => {}", "            Some(Def::Clobber) => return true,", *LIB, "callee::tests::what_a_call_left_behind_is_no_argument"),
    (CORE + "callee.rs", "        Takes::Exactly(n) => n.min(args.len()),", "        Takes::Exactly(_) => args.len(),", *LIB, "callee::tests::a_call_is_cut_to_what_the_callee_in_this_image_takes"),
    # What it gives back.
    (CORE + "decomp.rs", "                crate::callee::settle_void_returns(blocks);", "", *LIB, "callee::tests::a_value_out_of_a_call_asks_the_callee"),
    (CORE + "callee.rs", "        Gives::Nothing if value => Gives::Unknown,", "        Gives::Nothing if value => Gives::Value,", *LIB, "callee::tests::a_value_also_read_on_its_way_cannot_be_told_from_a_leftover"),
    (CORE + "typeinfer.rs", "    if gives == crate::callee::Gives::Unknown {\n        return ReturnType::Unknown;\n    }", "", *LIB, "callee::tests::a_callee_that_cannot_be_asked_leaves_the_return_unknown"),
    (CORE + "ssa.rs", "            if !matches!(s.stmt, MicroStmt::Return(_)) && !flags_by_product(&s.stmt) {", "            if !matches!(s.stmt, MicroStmt::Return(_)) {", *LIB, "typeinfer::tests::a_function_that_computes_rax_has_a_typed_return"),
    # Whether a call comes back.
    (CORE + "ir.rs", "    if ctx.noreturn_on_demand && ins.target", "    if false && ctx.noreturn_on_demand && ins.target", *LIB, "callee::tests::a_body_stops_at_a_call_that_does_not_come_back"),
    (CORE + "callee.rs", "                        .filter(|c| b.insns.iter().any(|i| i.va == c.from && i.flow == n0xis_arch::InsnKind::Call))\n", "", *LIB, "callee::tests::a_conditional_jump_out_is_no_call_on_the_path"),
    # A switch, a name through the PLT, a format. Two fixes have a test that removing them does not fail, and so are not
    # here: the case behind a block of copies (the fixture builds no such block; on one C image's interpreter it moved
    # 166 `default:` labels to 166 cases), and a stack argument's store no longer printed (the fixture's store is also
    # cleared as dead; a push is not).
    (CORE + "ir.rs", "        .or_else(|| ins.target.and_then(|t| ctx.symbols.and_then(|s| s.thunk_to(t))).and_then(|def| symbol_on_entry(ctx, def)))\n", "", *LIB, "callee::tests::a_call_through_the_plt_to_the_images_own_export_has_its_name_and_count"),
    (CORE + "render.rs", "let rest = args[n..].iter().filter(|_| sig.variadic)", "let rest = args[n..].iter().filter(|_| false)", *LIB, "callee::tests::a_format_shows_its_text_and_takes_what_it_asks_for"),
    (CORE + "callee.rs", '                    used.insert(format!("{reg}.0"));\n', "", *LIB, "callee::tests::a_double_the_format_asks_for_comes_from_its_register"),
]


def run_test(package, binary, test, cargo_args=()):
    """`calibrate_update.run_test`, at the jobs this machine allows when others build too (`CARGO_BUILD_JOBS`, else 4)."""
    jobs = os.environ.get("CARGO_BUILD_JOBS", "4")
    real = calibrate_update.subprocess.run

    def capped(cmd, *a, **k):
        return real([jobs if c == "8" and cmd[i - 1] == "-j" else c for i, c in enumerate(cmd)], *a, **k)

    calibrate_update.subprocess.run = capped
    try:
        return calibrate_update.run_test(package, binary, test, cargo_args)
    finally:
        calibrate_update.subprocess.run = real


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
        print(f"{'ok    ' if ok else 'MISSED'} {verdict:<17} {test}  <-  {anchor.strip()[:50]!r}", flush=True)
        if not ok:
            bad.append((test, anchor, verdict))
            if verdict == "does-not-compile":
                errors = [line for line in log.splitlines() if line.startswith("error")]
                print("       " + " | ".join(errors[:3])[:300], flush=True)
    print(f"{len(chosen) - len(bad)} of {len(chosen)} calibrated")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

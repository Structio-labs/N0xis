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
    # Where a graph ends, and a body cut where reading stopped. (`a_kept_graph_without_its_end_is_not_read` is not here:
    # what it guards is a field with no default, and a mutation that gives one does not compile.)
    (CORE + "ir.rs", "        let limit = if stated_len.is_some() { bytes.len().max(DEFAULT_MAX_INSNS) } else { DEFAULT_MAX_INSNS };", "        let limit = DEFAULT_MAX_INSNS;", *LIB, "ir::tests::a_stated_extent_is_read_to_its_end"),
    (CORE + "ir.rs", "None if ran_out && !limited =>", "None if false && ran_out && !limited =>", *LIB, "decomp::tests::a_body_cut_by_the_window_says_so"),
    (CORE + "ir.rs", "                    None if limited => GraphEnd::InstructionCap { read, stated: beyond },\n", "", *LIB, "ir::tests::the_instruction_limit_is_said_where_it_binds"),
    (CORE + "decomp.rs", "        let quality = cfg.end_by.quality_cap().map_or(quality, |cap| quality.min(cap));\n", "", *LIB, "decomp::tests::a_body_cut_by_the_window_says_so"),
    (CORE + "decomp.rs", "            .chain(cut.as_ref().map(|c| format!(\"    /* {} */\", c.words)))\n", "", *LIB, "decomp::tests::a_body_cut_by_the_window_says_so"),
    (CORE + "manifest.rs", "    if art.callsites.is_empty() && !cut && !art.leaves_by_an_unresolved_jump() {", "    if art.callsites.is_empty() && !art.leaves_by_an_unresolved_jump() {", *LIB, "manifest::tests::a_cut_graph_says_so_and_claims_nothing_of_the_rest"),
    (CORE + "manifest.rs", "    if !cut && !crate::noreturn_ipa::function_returns(", "    if !crate::noreturn_ipa::function_returns(", *LIB, "manifest::tests::a_cut_graph_whose_read_part_loops_is_not_said_not_to_return"),
    (CORE + "trace.rs", "            not_followed.cut_bodies += usize::from(cut.is_some());\n", "", *LIB, "trace::tests::a_cut_body_truncates_the_walk"),
    (CORE + "summary.rs", "    cfg.callsites.is_empty() && !cfg.leaves_by_an_unresolved_jump() && !cfg.end_by.is_cut()", "    cfg.callsites.is_empty() && !cfg.leaves_by_an_unresolved_jump()", *LIB, "summary::tests::a_cut_function_has_no_complete_clobbers"),
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
    # The stack convention (i386): a slot read is a parameter, a tail jump passes the caller's on, a push is an argument.
    (CORE + "typeinfer.rs", "callee_cleanup_arity(ctx, cfg).or_else(|| crate::callee::stack_params(ctx, cfg, blocks, flow).map(|t| t.floor()).filter(|n| *n > 0))", "callee_cleanup_arity(ctx, cfg)", *LIB, "stack_args::tests::a_stack_slot_read_is_a_parameter"),
    (CORE + "ssa.rs", "MicroExpr::Cast { bits, expr, .. } if self.word_bits.is_some_and(|w| *bits >= w) => e = expr,", "MicroExpr::Cast { bits, expr, .. } if false => e = expr,", *LIB, "stack_args::tests::a_stack_slot_read_is_a_parameter"),
    (CORE + "ssa.rs", "                MicroExpr::AddrOf(inner) => e = inner,\n", "", *LIB, "stack_args::tests::a_displacement_wraps_at_the_word"),
    (CORE + "ssa.rs", "        Some(self.wrap(self.at.get(base)? + c))", "        Some(self.at.get(base)? + c)", *LIB, "stack_args::tests::a_displacement_wraps_at_the_word"),
    ("crates/n0xis-arch/src/x64_lift.rs", "                && instr.near_branch_target() == instr.next_ip() =>", "                && false =>", *LIB, "stack_args::tests::a_call_to_the_next_instruction_is_a_push"),
    (CORE + "decomp.rs", "            crate::stack_args::name_params(ctx, blocks, stack_params);\n", "", *LIB, "stack_args::tests::a_stack_slot_read_is_a_parameter"),
    (CORE + "typeinfer.rs", "                (crate::stack_args::arg_entry(stack - 1), p)", "                (format!(\"{}.0\", p.reg), p)", *LIB, "stack_args::tests::a_stack_slot_read_is_a_parameter"),
    (CORE + "callee.rs", "own.tails.iter().flat_map(", "own.tails.iter().take(0).flat_map(", *LIB, "stack_args::tests::a_tail_jump_passes_its_own_arguments_on"),
    (CORE + "callee.rs", "            let (frame, loaded, entry) = if frame.get(&version).is_some() {", "            let (frame, loaded, entry) = if true {", *LIB, "stack_args::tests::a_realigned_stack_still_passes_what_was_stored"),
    (CORE + "callee.rs", "    settle_stack_args(ctx, cfg, blocks, raw);\n", "", *LIB, "stack_args::tests::what_is_pushed_before_a_call_is_its_arguments"),
    # An indirect jump nothing was read for: said, counted, and what it may reach set apart (round 3, item 3).
    (CORE + "structure.rs", "    !t.is_empty() && (!t.starts_with(\"//\") || t == UNRECOVERED_JUMP)", "    !t.is_empty() && !t.starts_with(\"//\")", *LIB, "decomp::tests::an_unread_jump_is_said_and_what_it_may_reach_is_set_apart"),
    (CORE + "structure.rs", "                ctx.out.push(format!(\"{}{UNREACHED_PREFIX}{}\", pad(ctx.indent), ctx.blocks[b].start));\n", "", *LIB, "decomp::tests::an_unread_jump_is_said_and_what_it_may_reach_is_set_apart"),
    (CORE + "decomp.rs", "\"/* dispatcher */\", crate::structure::UNRECOVERED_JUMP, crate::switch::UNGUARDED_TABLE]", "\"/* dispatcher */\", crate::switch::UNGUARDED_TABLE]", *LIB, "decomp::tests::a_jump_with_the_frame_still_up_is_not_a_tail_call"),
    # A jump with the frame given back is a tail call through a pointer, and only that (item 3b).
    (CORE + "decomp.rs", "        let cfg = crate::pointer_tail::with_tail_calls_through_pointers(ctx, input.cfg)?;", "        let cfg = input.cfg;", *LIB, "decomp::tests::a_jump_through_a_slot_with_the_frame_given_back_is_a_tail_call"),
    (CORE + "tail_jump.rs", "                at == Some(0) && !is_constant", "                !is_constant", *LIB, "decomp::tests::a_jump_with_the_frame_still_up_is_not_a_tail_call"),
    (CORE + "tail_jump.rs", " && !read_through_an_index(target, &defs, 0)", "", *LIB, "decomp::tests::a_jump_through_a_table_with_no_frame_is_not_a_tail_call"),
    (CORE + "tail_jump.rs", "        if v.split('.').next() == Some(self.sp) {\n            return None;\n        }\n", "", *LIB, "decomp::tests::an_i386_jump_through_a_slot_is_given_the_slots_it_rewrites"),
    (CORE + "callee.rs", "                (None, Takes::AtLeast(n)) if tail =>", "                (None, Takes::AtLeast(n)) if false =>", *LIB, "decomp::tests::an_i386_jump_through_a_slot_is_given_the_slots_it_rewrites"),
    # What the bytes settle, said (round 3, item 4).
    ("crates/n0xis-arch/src/x64_lift.rs", "            if sources_are_one_register(&instr) {", "            if false {", "n0xis-arch", None, "x64_lift::tests::a_vector_xor_of_one_register_with_itself_is_zero"),
    ("crates/n0xis-arch/src/x64_lift.rs", "            let name = if op_bits(&instr, 0) == 32 { format!(\"{name}32\") } else { name };\n", "", "n0xis-arch", None, "x64_lift::tests::a_float_to_int_conversion_is_named_at_its_width"),
    (CORE + "emulate.rs", "        \"__cvttsd2si32\" => to_int(d(a)?.trunc(), 32),", "        \"__cvttsd2si32\" => to_int(d(a)?.trunc(), 64),", *LIB, "emulate::tests::a_float_to_int_conversion_answers_at_its_width"),
    (CORE + "emulate.rs", "        \"__cvtsd2si\" => to_int(d(a)?.round_ties_even(), 64),", "        \"__cvtsd2si\" => to_int(d(a)?.trunc(), 64),", *LIB, "emulate::tests::a_float_to_int_conversion_answers_at_its_width"),
    ("crates/n0xis-arch/src/x64_lift.rs", "        Mnemonic::Mul | Mnemonic::Imul if instr.op_count() == 1 && op_bits(&instr, 0) >= 32 => {", "        Mnemonic::Mul if instr.op_count() == 1 && op_bits(&instr, 0) >= 32 => {", "n0xis-arch", None, "x64_lift::tests::a_one_operand_imul_has_a_signed_high_half"),
    (CORE + "emulate.rs", "            let p = sign_extend_128(arg(0)?, bits) * sign_extend_128(arg(1)?, bits);", "            let p = (mask(arg(0)?, bits) * mask(arg(1)?, bits)) as i128;", *LIB, "emulate::tests::the_signed_high_half_of_a_product"),
    (CORE + "render.rs", "        MicroExpr::Binary(BinOp::Shl, l, r) if word.is_some_and(|w| w > 32) && matches!(l.as_ref(), MicroExpr::Const { .. }) => {", "        MicroExpr::Binary(BinOp::Shl, l, r) if false && word.is_some_and(|w| w > 32) && matches!(l.as_ref(), MicroExpr::Const { .. }) => {", *LIB, "render::tests::a_shifted_64_bit_constant_says_its_width"),
    # A signed order or the carry after a register inc, dec or neg reads the operation; the zero and the sign, the result.
    ("crates/n0xis-arch/src/flags.rs", "        \"inc\" => (INC_FLAGS,", "        \"inc_\" => (INC_FLAGS,", "n0xis-core", "flags_after_arithmetic_agree_with_the_processor", "every_condition_after_arithmetic_answers_as_the_processor_does"),
    ("crates/n0xis-arch/src/flags.rs", "        \"dec\" => (DEC_FLAGS,", "        \"dec_\" => (DEC_FLAGS,", "n0xis-core", "flags_after_arithmetic_agree_with_the_processor", "every_condition_after_arithmetic_answers_as_the_processor_does"),
    ("crates/n0xis-arch/src/flags.rs", "        \"neg\" => (NEG_FLAGS,", "        \"neg_\" => (NEG_FLAGS,", "n0xis-core", "flags_after_arithmetic_agree_with_the_processor", "every_condition_after_arithmetic_answers_as_the_processor_does"),
    ("crates/n0xis-arch/src/flags.rs", "        (DEC_FLAGS, [a, _]) => Some(branch_condition(jcc, &MicroExpr::compare(CmpKind::Cmp, a.clone(), one()))),", "        (DEC_FLAGS, [_, r]) => Some(branch_condition(jcc, &MicroExpr::compare(CmpKind::Cmp, r.clone(), MicroExpr::constant(0, 64)))),", "n0xis-core", "flags_after_arithmetic_agree_with_the_processor", "every_condition_after_arithmetic_answers_as_the_processor_does"),
    (CORE + "render.rs", "        MicroExpr::Binary(op @ (BinOp::Slt | BinOp::Sle | BinOp::Sgt | BinOp::Sge), l, r) if word.is_some() => {", "        MicroExpr::Binary(op @ (BinOp::Slt | BinOp::Sle | BinOp::Sgt | BinOp::Sge), l, r) if false && word.is_some() => {", *LIB, "render::tests::a_signed_order_at_the_word_says_it_is_signed"),
    # A jump back to a loop's header is that loop's `continue` only where it is the innermost (round 3, item 4).
    (CORE + "structure.rs", "    if ctx.loop_stack.last() == Some(&n) {", "    if ctx.loop_stack.contains(&n) {", *LIB, "structure::tests::a_jump_to_an_outer_loop_header_is_not_the_inner_loops_continue"),
    (CORE + "structure.rs", "                    ctx.out.extend(header_lines.iter().map(|l| format!(\"{pad0}{}\", l.trim_start())));\n                    ctx.out.push(format!(\"{pad0}while ({cond_for_loop}) {{\"));\n                    ctx.out.extend(inside_lines);", "                    ctx.out.push(format!(\"{pad0}while ({cond_for_loop}) {{\"));\n                    ctx.out.extend(body);", *LIB, "structure::tests::a_goto_to_a_loop_that_tests_first_lands_on_its_test"),
    # One name for one frame slot: an index steps from the slot's own name, which is declared (round 3, item 4).
    (CORE + "render.rs", "    if names.is_frame_address(base)\n", "    if false && names.is_frame_address(base)\n", *LIB, "decomp::tests::an_indexed_frame_slot_is_named_by_the_slot_it_steps_from"),
    (CORE + "typeinfer.rs", "indexed_base(addr, *bits) {\n                out.push(MemAccess { base, offset, bits: *bits, signed: *signed, indexed: true });", "indexed_base(addr, *bits).filter(|_| false) {\n                out.push(MemAccess { base, offset, bits: *bits, signed: *signed, indexed: true });", *LIB, "decomp::tests::an_indexed_frame_slot_is_named_by_the_slot_it_steps_from"),
    # A multiply and shift that divides for every operand is a division, and only that (round 3, item 5).
    (CORE + "optimize.rs", "                changed |= division_round(&mut blocks, &mut delta);\n", "", *LIB, "divide::tests::a_multiply_and_shift_that_divides_for_every_operand_is_a_division"),
    (CORE + "divide.rs", "        e.checked_mul((1u128 << xbits) - 1).is_some_and(|b| b < p)", "        true", *LIB, "divide::tests::a_multiply_and_shift_that_does_not_divide_stays_as_it_is"),
    (CORE + "divide.rs", "        e > 0 && e.checked_mul(1u128 << (xbits - 1)).is_some_and(|b| b <= p)", "        true", *LIB, "divide::tests::the_bound_is_exactly_what_every_operand_agrees_with"),
    (CORE + "divide.rs", "    canonical(v) == canonical(x) && constant(k)", "    v.as_ref() == x && constant(k)", *LIB, "divide::tests::a_multiply_and_shift_that_divides_for_every_operand_is_a_division"),
    (CORE + "divide.rs", "        MicroExpr::Binary(BinOp::Shr, t, k) if cut && constant(k).is_some_and(|k| k <= 32)", "        MicroExpr::Binary(BinOp::Shr, t, k) if cut && constant(k).is_some_and(|k| k <= 64)", *LIB, "divide::tests::a_logical_floor_is_read_only_where_the_low_half_is_the_same"),
    (CORE + "render.rs", "        MicroExpr::Binary(op @ (BinOp::SDiv | BinOp::SMod), l, r) if word.is_some() => {", "        MicroExpr::Binary(op @ (BinOp::SDiv | BinOp::SMod), l, r) if false && word.is_some() => {", *LIB, "divide::tests::a_multiply_and_shift_that_divides_for_every_operand_is_a_division"),
    (CORE + "optimize.rs", "        BinOp::SDiv => sl.wrapping_div(sign_extend(r, bits)),", "        BinOp::SDiv => l.wrapping_div(r),", *LIB, "optimize::shift_agreement::a_signed_divide_folds_signed"),
    # A register a local callee's own instructions do not write keeps its value across the call (round 3, item 5).
    (CORE + "ssa.rs", "        crate::callee::keep_what_callees_leave(ctx, &cfg, &mut lifted);\n", "", *LIB, "callee::tests::a_register_a_leaf_callee_does_not_write_keeps_its_value"),
    (CORE + "callee.rs", " && crate::summary::writes_are_all_of_it(cfg))", ")", *LIB, "callee::tests::a_register_a_callee_writes_or_may_write_is_not_kept"),
    (CORE + "callee.rs", "                keep[k] = changes.as_ref().is_none_or(|w| w.contains(&reg));", "                keep[k] = changes.as_ref().is_none_or(|_| false);", *LIB, "callee::tests::a_register_a_callee_writes_or_may_write_is_not_kept"),
    # A marker is asked about only where something after the call reads it, and a later call's argument list is no read.
    (CORE + "callee.rs", "        MicroStmt::Call { .. } => Vec::new(),\n", "", *LIB, "callee::tests::a_marker_nothing_after_the_call_reads_is_not_asked_about"),
    (CORE + "callee.rs", "                && read.remove(&reg)\n", "                && (read.remove(&reg) || true)\n", *LIB, "callee::tests::a_marker_nothing_after_the_call_reads_is_not_asked_about"),
    # One switch bound, the guard's, for every consumer (round 3, item 6); and the test takes it from the bytes.
    (CORE + "switch.rs", "    let index = ctx.arch.index_guard(insns, disp);", "    let index = disp.bound.map(n0xis_arch::IndexBound::Guard);", "n0xis-cli", "xref_reads_jump_tables", "gcc_position_independent", ORACLE),
    ("crates/n0xis-cli/tests/xref_reads_jump_tables.rs", "        let guarded = guards.iter().find(|(at, _)| *at == jump).is_some_and(|(_, g)| g.is_some());", "        let guarded = false;", "n0xis-cli", "xref_reads_jump_tables", "gcc14_position_independent", ORACLE),
    # A table no guard bounds is read to the first of its index's width, the function's stated end, the next table's
    # base and an entry that is not code, and the body says which (round 3, item 6b).
    ("crates/n0xis-arch/src/x64.rs", "        guard.map(IndexBound::Guard).or(width.map(IndexBound::Width))", "        width.map(IndexBound::Width)", *LIB, "switch::tests::a_guarded_table_is_read_to_its_guard"),
    ("crates/n0xis-arch/src/x64.rs", "                                if let Some(w) = zero_extended_from(&ins) {", "                                if let Some(w) = None::<u64> {", *LIB, "switch::tests::an_index_widened_from_a_byte_holds_the_read_to_256"),
    (CORE + "switch.rs", "        if function.is_some_and(|f| !f.holds(target)) {", "        if false {", *LIB, "switch::tests::an_unguarded_read_stops_at_the_functions_stated_end"),
    (CORE + "switch.rs", "        if function.is_some_and(|f| !f.holds(target)) {", "        if function.is_some_and(|f| !(target >= f.start && target < f.end)) {", *LIB, "switch::tests::a_part_of_the_function_apart_is_inside_it"),
    (CORE + "switch.rs", "        Some(before_next) if before_next < held => (before_next, TableEnd::NextTable),", "        Some(before_next) if false && before_next < held => (before_next, TableEnd::NextTable),", *LIB, "switch::tests::an_unguarded_read_stops_at_the_next_table"),
    (CORE + "ir.rs", "        let bases = TableBases::of_code(ctx, instrs, dispatches.iter().map(|(_, d)| d));", "        let bases = TableBases::new([0u64; 0], [0u64; 0]);", *LIB, "switch::tests::the_graph_stops_a_table_where_its_function_takes_the_next"),
    (CORE + "switch.rs", "        let target = decode_entry(kind, table, chunk).filter(|&t| is_code(ctx, &code, t));", "        let target = decode_entry(kind, table, chunk);", *LIB, "switch::tests::an_unguarded_read_stops_at_an_entry_that_is_not_code"),
    (CORE + "switch.rs", "        end = TableEnd::Unreadable;\n", "", *LIB, "switch::tests::a_read_past_the_words_the_image_holds_says_so"),
    (CORE + "switch.rs", "Err(serde::de::Error::custom(\"a switch with both a guard's bound and a width\"))", "Ok(None)", *LIB, "switch::tests::a_switch_says_its_guard_and_its_width_under_their_own_keys"),
    # The function's end stops only a read no guard holds; the guard of the register the index was copied from is its
    # guard; the image's table bases, where attached, are the graph's (round 3, item 6c).
    ("crates/n0xis-arch/src/x64.rs", "                                if let Some((_, limit)) = pending.iter().find(|(cmp, _)| earlier.is_compared_by(cmp)) {", "                                if let Some((_, limit)) = pending.iter().find(|_| false) {", *LIB, "switch::tests::a_guard_of_the_register_the_index_was_copied_from_is_the_index_guard"),
    ("crates/n0xis-arch/src/x64.rs", "                    pending.retain(|(cmp, _)| !writes(cmp.op0_register().full_register()));\n", "", *LIB, "switch::tests::a_guard_of_the_register_the_index_was_copied_from_is_the_index_guard"),
    (CORE + "switch.rs", ".filter(|_| !matches!(bound, Some(IndexBound::Guard(_))));", ";", *LIB, "switch::tests::a_guarded_read_goes_past_the_functions_stated_end"),
    (CORE + "switch.rs", "(end != TableEnd::Guard && end != TableEnd::Limit && (self.cases.len() as u64) <= guard)", "false", *LIB, "switch::tests::a_guarded_read_stopped_early_says_it_is_short_of_its_guard"),
    (CORE + "switch.rs", "ctx.table_bases.and_then(|t| t.bases()).unwrap_or_else(", "None::<std::sync::Arc<Self>>.unwrap_or_else(", *LIB, "switch::tests::the_images_table_bases_end_a_table_its_own_code_does_not_name"),
    (CORE + "structure.rs", "    if let Some(note) = sw.and_then(crate::switch::ResolvedSwitch::unguarded_note) {", "    if let Some(note) = None::<String> {", *LIB, "switch::tests::a_body_says_no_guard_held_its_switch"),
    (CORE + "decomp.rs", "                    if let Some(note) = sw.and_then(crate::switch::ResolvedSwitch::unguarded_note) {", "                    if let Some(note) = None::<String> {", *LIB, "switch::tests::a_body_says_no_guard_held_its_switch"),
    (CORE + "decomp.rs", "crate::structure::UNRECOVERED_JUMP, crate::switch::UNGUARDED_TABLE]", "crate::structure::UNRECOVERED_JUMP]", *LIB, "switch::tests::a_body_says_no_guard_held_its_switch"),
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

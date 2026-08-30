//! Control structuring — dominators + natural-loop detection +
//! `if`/`else`/`&&`/`||`/`for`/`while`/`do-while` reconstruction, ported from
//! the archived v0 template renderer
//! (v0's `pseudo.rs::render_structured`) onto our typed
//! IR. The algorithm itself is unchanged (dominators/post-dominators →
//! natural loops → recursive descent with an `until` stop-point and a
//! `loop_stack` for `continue`/`break`); what's different is *what* it
//! structures: v0 walked raw re-lifted instruction text with a mutable
//! "last compare" for conditions, this walks [`SsaBlock`]s whose
//! `condition` is already the exact expression [`crate::SsaPass`]
//! synthesized — so structuring never has to guess.
//!
//! Anything this pass can't classify (irreducible CFG, missing ipdom, …)
//! falls back to a plain `goto block_N;`, same as v0 — sound over pretty.

use std::collections::{BTreeSet, HashMap};

use n0xis_arch::MicroExpr;

use crate::dom::{block_graph, dominators_fwd, dominators_rev, immediate_doms};
use crate::ir::CfgArtifact;
use crate::render::{negate_condition, render_condition, render_stmt, RenderNames};
use crate::ssa::SsaBlock;

/// Result of structuring: the rendered lines plus telemetry mirroring v0's
/// flags (`has-loop`, `structured-partial`, …).
pub struct StructuredOutput {
    pub lines: Vec<String>,
    pub has_loop: bool,
    /// How many places the structurer gave up and fell back to a bare
    /// `goto` — 0 means a fully clean structuring.
    pub fallback_count: usize,
}

fn cjmp_arms(cfg: &CfgArtifact, succ: &[Vec<usize>], n: usize) -> (Option<usize>, Option<usize>) {
    let mut t_idx = None;
    let mut f_idx = None;
    for &s in &succ[n] {
        if let Some(edge) = cfg.blocks[n].successors.iter().find(|e| e.to == cfg.blocks[s].start) {
            match edge.kind.as_str() {
                "cjmp-true" => t_idx = Some(s),
                "cjmp-false" => f_idx = Some(s),
                _ => {}
            }
        }
    }
    (t_idx, f_idx)
}

fn collect_loop_body(header: usize, tail: usize, pred: &[Vec<usize>]) -> BTreeSet<usize> {
    let mut body = BTreeSet::new();
    body.insert(header);
    if header == tail {
        return body;
    }
    let mut stack = vec![tail];
    body.insert(tail);
    while let Some(u) = stack.pop() {
        for &p in &pred[u] {
            if body.insert(p) && p != header {
                stack.push(p);
            }
        }
    }
    body
}

/// If a rendered loop body's **last top-level statement** is an induction step,
/// return the body with that line removed plus the step text (no indent, no
/// trailing `;`) — for hoisting into a `for (; cond; step)` header. Recognizes
/// `++`/`--`/`+=`/`-=` and a self-referential `x = (x + k)` / `x = x - k` (the
/// shape our renderer emits — the step variable recurs on the right with a
/// `+`/`-`); self-reference excludes a call assignment `x = f(…)`. The step must
/// sit at the body's **outermost** indent (not nested inside an `if`), so a
/// counter update tucked in a branch is never mistaken for the loop step.
/// `None` leaves the loop as a `while` — sound over pretty.
fn split_trailing_step(body: &[String]) -> Option<(Vec<String>, String)> {
    let indent_of = |l: &str| l.len() - l.trim_start().len();
    let min_indent = body.iter().filter(|l| is_code_line(l)).map(|l| indent_of(l)).min()?;
    let last_idx = body.iter().rposition(|l| is_code_line(l))?;
    if indent_of(&body[last_idx]) != min_indent {
        return None;
    }
    let last = body[last_idx].trim().trim_end_matches(';').trim();
    if last.len() >= 96 {
        return None;
    }
    let is_step = last.ends_with("++")
        || last.ends_with("--")
        || last.contains(" += ")
        || last.contains(" -= ")
        || last.split_once(" = ").is_some_and(|(l, r)| {
            let l = l.trim();
            !l.is_empty() && r.contains(l) && (r.contains(" + ") || r.contains(" - "))
        });
    if !is_step {
        return None;
    }
    let mut rest = body.to_vec();
    rest.remove(last_idx);
    Some((rest, last.to_string()))
}

struct Ctx<'a> {
    cfg: &'a CfgArtifact,
    names: &'a RenderNames,
    succ: &'a [Vec<usize>],
    pred: &'a [Vec<usize>],
    ipdom: &'a [Option<usize>],
    is_header: &'a [bool],
    loop_body: &'a HashMap<usize, BTreeSet<usize>>,
    loop_back_edges: &'a HashMap<usize, Vec<usize>>,
    loop_exit: &'a HashMap<usize, Option<usize>>,
    body_lines: &'a [Vec<String>],
    conds: &'a [Option<MicroExpr>],
    visited: Vec<bool>,
    loop_stack: Vec<usize>,
    out: Vec<String>,
    indent: usize,
    fallback_count: usize,
    budget: usize,
}

fn pad(indent: usize) -> String {
    "    ".repeat(indent)
}

fn cond_text(ctx: &Ctx, n: usize) -> String {
    match &ctx.conds[n] {
        Some(e) => render_condition(e, ctx.names),
        None => "/*?*/".to_string(),
    }
}

fn negated_cond_text(ctx: &Ctx, n: usize) -> String {
    match &ctx.conds[n] {
        Some(e) => render_condition(&negate_condition(e), ctx.names),
        None => "/*?*/".to_string(),
    }
}

fn emit_node(ctx: &mut Ctx, n: usize, until: Option<usize>) {
    if ctx.budget == 0 {
        ctx.out.push(format!("{}// (structural budget exhausted)", pad(ctx.indent)));
        ctx.fallback_count += 1;
        return;
    }
    ctx.budget -= 1;

    if Some(n) == until {
        return;
    }
    if ctx.loop_stack.contains(&n) {
        ctx.out.push(format!("{}continue;", pad(ctx.indent)));
        return;
    }
    if let Some(&active) = ctx.loop_stack.last()
        && ctx.loop_exit.get(&active).copied().flatten() == Some(n)
    {
        ctx.out.push(format!("{}break;", pad(ctx.indent)));
        return;
    }
    if ctx.visited[n] {
        // A small, successor-free tail block (a shared `return`/epilogue reached
        // from several paths) is **tail-duplicated** inline instead of jumped to
        // — the transform other tools use to erase the most common residual goto.
        // Sound: the block has no successors (nothing downstream to re-run or
        // re-enter), its body is straight-line, and every SSA value it reads was
        // valid at the original join, so it is equally valid inlined at this
        // predecessor. Not a fallback, so `fallback_count` is untouched.
        if is_duplicable_tail(ctx, n) {
            emit_block_body_and_terminator(ctx, n, until);
            return;
        }
        ctx.out.push(format!("{}goto block_{n};", pad(ctx.indent)));
        ctx.fallback_count += 1;
        return;
    }
    ctx.visited[n] = true;

    if ctx.is_header[n] && !ctx.loop_stack.contains(&n) {
        emit_loop(ctx, n, until);
        return;
    }
    emit_block_body_and_terminator(ctx, n, until);
}

/// The most real (non-comment, non-blank) lines a shared tail *region* may hold
/// and still be duplicated inline — a shared epilogue is a handful of lines; a
/// larger shared region stays a `goto` rather than bloating every predecessor.
const MAX_DUP_LINES: usize = 8;
/// Depth cap on the linear tail chain, a belt-and-braces guard against a
/// pathological CFG (real epilogue chains are 1–3 blocks).
const MAX_DUP_DEPTH: usize = 6;

/// Real (non-comment, non-blank) rendered lines in block `n`.
fn real_line_count(ctx: &Ctx, n: usize) -> usize {
    ctx.body_lines[n].iter().filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with("//")).count()
}

/// May block `n` be tail-duplicated inline where it would otherwise be reached by
/// a `goto`? True for a small **linear tail region** — a straight `jmp`/`fall`
/// chain that ends at a function exit (`ret`/`tail-call`, no successors) — with
/// no loop header on the way and a small total line count. These are exactly the
/// shared `return`/epilogue sequences that produce the bulk of residual gotos;
/// duplicating them is sound (no successors past the exit to re-run, no
/// back-edge, and every SSA value stays valid inlined at the predecessor).
/// Branch (`cjmp`/`switch`) regions are deliberately left as `goto` — simpler
/// and never a bloat risk.
fn is_duplicable_tail(ctx: &Ctx, n: usize) -> bool {
    region_lines(ctx, n, MAX_DUP_DEPTH).is_some()
}

/// The total rendered-line count of the acyclic tail region rooted at `n`, or
/// `None` if it is not duplicable — it hits a loop header/back-edge, a
/// non-terminating terminator, or exceeds [`MAX_DUP_LINES`]/[`MAX_DUP_DEPTH`].
/// A region is a straight `jmp`/`fall` chain **or a small `if`/`else` whose both
/// arms are themselves tail regions**, always ending at function exits
/// (`ret`/`tail-call`). Summing across a branch's two arms bounds the real bloat
/// (a diamond's shared merge is counted in both, conservatively).
fn region_lines(ctx: &Ctx, n: usize, depth: usize) -> Option<usize> {
    if depth == 0 || ctx.is_header[n] || ctx.loop_stack.contains(&n) {
        return None;
    }
    let mut total = real_line_count(ctx, n);
    match ctx.cfg.blocks[n].terminator.as_str() {
        "ret" | "tail-call" if ctx.succ[n].is_empty() => {}
        "jmp" | "fall" => total += region_lines(ctx, *ctx.succ[n].first()?, depth - 1)?,
        "cjmp" if ctx.succ[n].len() == 2 => {
            total += region_lines(ctx, ctx.succ[n][0], depth - 1)?;
            total += region_lines(ctx, ctx.succ[n][1], depth - 1)?;
        }
        _ => return None,
    }
    (total <= MAX_DUP_LINES).then_some(total)
}

fn emit_block_body_and_terminator(ctx: &mut Ctx, n: usize, until: Option<usize>) {
    for line in &ctx.body_lines[n] {
        ctx.out.push(format!("{}{}", pad(ctx.indent), line));
    }
    let is_switch = ctx.cfg.blocks[n].successors.iter().any(|s| s.kind == "switch-case");
    match ctx.cfg.blocks[n].terminator.as_str() {
        "ret" | "tail-call" => {
            // Body lift already pushed `return ...;`.
        }
        "int" => ctx.out.push(format!("{}// int / abort", pad(ctx.indent))),
        "call-noreturn" => ctx.out.push(format!("{}// unreachable: call does not return", pad(ctx.indent))),
        "ijmp" if !is_switch => {
            ctx.out.push(format!("{}// indirect jump (unrecovered)", pad(ctx.indent)));
        }
        "jmp" | "fall" => {
            if let Some(&j) = ctx.succ[n].first() {
                emit_node(ctx, j, until);
            }
        }
        "cjmp" => emit_if_else(ctx, n, until),
        _ if is_switch => emit_switch(ctx, n, until),
        _ => {
            ctx.out.push(format!("{}// (unknown terminator)", pad(ctx.indent)));
            ctx.fallback_count += 1;
        }
    }
}

fn emit_if_else(ctx: &mut Ctx, n: usize, until: Option<usize>) {
    let cond = cond_text(ctx, n);
    let (t_idx, f_idx) = cjmp_arms(ctx.cfg, ctx.succ, n);
    let merge = ctx.ipdom[n];

    let (Some(t), Some(f)) = (t_idx, f_idx) else {
        ctx.out.push(format!("{}// (cjmp without resolved successors)", pad(ctx.indent)));
        ctx.fallback_count += 1;
        return;
    };

    if let Some((folded_cond, body_arm, else_arm, eaten)) = try_short_circuit(ctx, n, &cond, t, f) {
        for b in &eaten {
            ctx.visited[*b] = true;
        }
        ctx.out.push(format!("{}if ({folded_cond}) {{", pad(ctx.indent)));
        ctx.indent += 1;
        emit_node(ctx, body_arm, merge);
        ctx.indent -= 1;
        if Some(else_arm) != merge {
            ctx.out.push(format!("{}}} else {{", pad(ctx.indent)));
            ctx.indent += 1;
            emit_node(ctx, else_arm, merge);
            ctx.indent -= 1;
        }
        ctx.out.push(format!("{}}}", pad(ctx.indent)));
        if let Some(m) = merge {
            emit_node(ctx, m, until);
        }
        return;
    }

    // Emit both arms into buffers first, so an *empty* arm can be cleaned up the
    // way other tools do: an empty then-arm inverts the condition
    // (`if (c) {} else { B }` → `if (!c) { B }`), and an empty else-arm is simply
    // dropped. Both are pure readability rewrites — the guarded body and the
    // condition's truth value are unchanged.
    ctx.indent += 1;
    let then_lines = capture_arm(ctx, t, merge);
    let else_lines = capture_arm(ctx, f, merge);
    ctx.indent -= 1;

    let has_code = |ls: &[String]| ls.iter().any(|l| is_code_line(l));
    let pad0 = pad(ctx.indent);
    if !has_code(&then_lines) && has_code(&else_lines) {
        ctx.out.push(format!("{pad0}if ({}) {{", negated_cond_text(ctx, n)));
        ctx.out.extend(else_lines);
        ctx.out.push(format!("{pad0}}}"));
    } else if has_code(&then_lines) && !has_code(&else_lines) {
        ctx.out.push(format!("{pad0}if ({cond}) {{"));
        ctx.out.extend(then_lines);
        ctx.out.push(format!("{pad0}}}"));
    } else {
        ctx.out.push(format!("{pad0}if ({cond}) {{"));
        ctx.out.extend(then_lines);
        // `else { if (…) … }` collapses to `else if (…)` when the else arm is
        // exactly one `if` spanning the whole block — other tools' else-if chain.
        if let Some(collapsed) = try_else_if(&else_lines, ctx.indent) {
            ctx.out.extend(collapsed);
        } else {
            ctx.out.push(format!("{pad0}}} else {{"));
            ctx.out.extend(else_lines);
            ctx.out.push(format!("{pad0}}}"));
        }
    }
    if let Some(m) = merge {
        emit_node(ctx, m, until);
    }
}

/// Emit one `if` arm (the subtree rooted at `arm`, stopping at `until`) into a
/// detached buffer, returning its lines. `visited`/`fallback_count` and all
/// other structuring state stay shared — only the output is captured — so the
/// caller can inspect the arm (e.g. is it empty?) before committing it.
fn capture_arm(ctx: &mut Ctx, arm: usize, until: Option<usize>) -> Vec<String> {
    let saved = std::mem::take(&mut ctx.out);
    emit_node(ctx, arm, until);
    std::mem::replace(&mut ctx.out, saved)
}

/// A rendered line that is real code — not blank and not a `//` comment (a bare
/// `// block_N:` label does not make an arm non-empty).
fn is_code_line(l: &str) -> bool {
    let t = l.trim();
    !t.is_empty() && !t.starts_with("//")
}

/// Net brace nesting a rendered pseudo-C line changes: `if (…) {` → +1, `}` →
/// −1, `} else {` → 0, `} while (…);` → −1. Safe to count literal braces since
/// our rendered expressions never contain `{`/`}` (calls use `()`, fields `->`).
fn brace_delta(l: &str) -> i32 {
    l.matches('{').count() as i32 - l.matches('}').count() as i32
}

/// If a captured else-arm is **exactly one `if` statement** spanning the whole
/// block (`else { if (c) {…} else {…} }`), return the lines that collapse it into
/// an `else if (c) …` chain — dedented one level, the leading `} else ` merged
/// onto the inner `if`, and the arm's own closing brace reused as the chain's.
/// `None` when the else arm is anything else (statements around the `if`, or not
/// an `if` at all), leaving the plain `else { … }` form. Pure text rewrite over
/// lines the renderer produced, so indentation and brace structure stay exact.
fn try_else_if(else_lines: &[String], indent: usize) -> Option<Vec<String>> {
    let first_code = else_lines.iter().position(|l| is_code_line(l))?;
    if !else_lines[first_code].trim_start().starts_with("if (") {
        return None;
    }
    // The `if` must balance back to depth 0 exactly at the last code line — i.e.
    // it is the entire else body, with nothing (bar comments) after its close.
    let mut depth = 0i32;
    let mut closed_at = None;
    for (i, l) in else_lines.iter().enumerate() {
        depth += brace_delta(l);
        if i >= first_code && depth == 0 {
            closed_at = Some(i);
            break;
        }
    }
    let closed_at = closed_at?;
    if else_lines[closed_at + 1..].iter().any(|l| is_code_line(l)) {
        return None;
    }
    // Dedent one level (each line was rendered at `indent + 1`).
    let dedent = |l: &str| l.strip_prefix("    ").unwrap_or(l).to_string();
    let pad0 = pad(indent);
    // Drop the else-if condition block's own leading `// block_N:` label (it is
    // redundant once the block is the `else if` itself), keep the body's lines.
    let mut out = vec![format!("{pad0}}} else {}", else_lines[first_code].trim_start())];
    for l in &else_lines[first_code + 1..] {
        out.push(dedent(l));
    }
    Some(out)
}

/// Fold a 2-block short-circuit chain rooted at `n` into `&&`/`||`, mirroring
/// v0's pattern: `B` must be a "pure guard" (a lone `cjmp` with no rendered
/// body lines — i.e. nothing but the comparison that became its condition)
/// reached only from `A`.
fn try_short_circuit(ctx: &Ctx, n: usize, cond_a: &str, t: usize, f: usize) -> Option<(String, usize, usize, Vec<usize>)> {
    let is_pure_guard = |b: usize| -> bool {
        if b == n || ctx.is_header[b] || ctx.cfg.blocks[b].terminator != "cjmp" {
            return false;
        }
        if ctx.pred[b].len() != 1 || ctx.pred[b][0] != n {
            return false;
        }
        ctx.body_lines[b].iter().all(|l| l.trim_start().starts_with("//") || l.trim().is_empty())
    };

    if is_pure_guard(t) {
        let (bt, bf) = cjmp_arms(ctx.cfg, ctx.succ, t);
        if let (Some(bt), Some(bf)) = (bt, bf) {
            let cond_b = cond_text(ctx, t);
            if bf == f {
                return Some((format!("({cond_a}) && ({cond_b})"), bt, f, vec![t]));
            }
            if bt == f {
                let neg_b = negated_cond_text(ctx, t);
                return Some((format!("({cond_a}) && ({neg_b})"), bf, f, vec![t]));
            }
        }
    }
    if is_pure_guard(f) {
        let (bt, bf) = cjmp_arms(ctx.cfg, ctx.succ, f);
        if let (Some(bt), Some(bf)) = (bt, bf) {
            let cond_b = cond_text(ctx, f);
            if bt == t {
                return Some((format!("({cond_a}) || ({cond_b})"), t, bf, vec![f]));
            }
            if bf == t {
                let neg_b = negated_cond_text(ctx, f);
                return Some((format!("({cond_a}) || ({neg_b})"), t, bt, vec![f]));
            }
        }
    }
    None
}

fn emit_switch(ctx: &mut Ctx, n: usize, until: Option<usize>) {
    let merge = ctx.ipdom[n];
    // The resolved jump-table dispatch for this block's indirect jump (its `at`
    // is the `ijmp`, which sits inside `[block.start, block.end)`), when the
    // switch pass recovered one. It gives the switched register and the table's
    // case→target map, turning the old `/* dispatcher */` / `/* block N */`
    // placeholders into real `switch (idx)` / `case K:` labels.
    let (bstart, bend) = {
        let b = &ctx.cfg.blocks[n];
        (b.start.get(), b.end.get())
    };
    let sw = ctx.cfg.switches.iter().find(|s| s.at.get() >= bstart && s.at.get() < bend);
    let disp = sw.and_then(|s| s.index_reg.clone()).unwrap_or_else(|| "/* dispatcher */".to_string());
    ctx.out.push(format!("{}switch ({disp}) {{", pad(ctx.indent)));
    let mut emitted: BTreeSet<usize> = BTreeSet::new();
    for &s in &ctx.succ[n].to_vec() {
        if !emitted.insert(s) {
            continue;
        }
        // Every table index whose target is this successor becomes a `case`
        // (fall-through cases share a block, so a block can carry several); a
        // successor with no matching index is the out-of-range `default`.
        let target = ctx.cfg.blocks[s].start.get();
        let cases: Vec<usize> = sw
            .map(|w| w.cases.iter().enumerate().filter(|(_, va)| va.get() == target).map(|(i, _)| i).collect())
            .unwrap_or_default();
        if sw.is_none() {
            ctx.out.push(format!("{}    case /* block {s} */:", pad(ctx.indent)));
        } else if cases.is_empty() {
            ctx.out.push(format!("{}    default:", pad(ctx.indent)));
        } else {
            for i in cases {
                ctx.out.push(format!("{}    case 0x{i:x}:", pad(ctx.indent)));
            }
        }
        ctx.indent += 2;
        emit_node(ctx, s, merge);
        ctx.out.push(format!("{}break;", pad(ctx.indent)));
        ctx.indent -= 2;
    }
    ctx.out.push(format!("{}}}", pad(ctx.indent)));
    if let Some(m) = merge {
        emit_node(ctx, m, until);
    }
}

fn emit_loop(ctx: &mut Ctx, h: usize, until: Option<usize>) {
    ctx.loop_stack.push(h);
    let exit = ctx.loop_exit.get(&h).copied().flatten();
    let term = ctx.cfg.blocks[h].terminator.clone();
    let body_set = ctx.loop_body.get(&h).cloned().unwrap_or_default();
    let back_edges = ctx.loop_back_edges.get(&h).cloned().unwrap_or_default();

    if term == "cjmp" {
        let (t_idx, f_idx) = cjmp_arms(ctx.cfg, ctx.succ, h);
        if let (Some(t), Some(f)) = (t_idx, f_idx) {
            let t_in = body_set.contains(&t);
            let f_in = body_set.contains(&f);
            if t_in ^ f_in {
                let cond_for_loop = if t_in { cond_text(ctx, h) } else { negated_cond_text(ctx, h) };
                let inside = if t_in { t } else { f };
                let outside = if t_in { f } else { t };

                // Emit the loop body (header block + the in-loop arm) into a
                // buffer, then reformat: if its last top-level statement is an
                // induction step and the condition is clean, hoist that step
                // into a `for (; cond; step)`. This is a pure text reformat of an
                // already-correct `while` body — no CFG re-scoping — so unlike a
                // direct for-emission it cannot mis-structure a complex loop
                // (absorb trailing blocks, emit a `for` over an opaque cond).
                ctx.indent += 1;
                let mut body: Vec<String> = ctx.body_lines[h].iter().map(|l| format!("{}{}", pad(ctx.indent), l)).collect();
                let saved = std::mem::take(&mut ctx.out);
                emit_node(ctx, inside, Some(h));
                let inside_lines = std::mem::replace(&mut ctx.out, saved);
                body.extend(inside_lines);
                ctx.indent -= 1;

                let pad0 = pad(ctx.indent);
                let for_form = if cond_for_loop.contains("/*") { None } else { split_trailing_step(&body) };
                if let Some((body_wo_step, step)) = for_form {
                    ctx.out.push(format!("{pad0}for (; {cond_for_loop}; {step}) {{"));
                    ctx.out.extend(body_wo_step);
                    ctx.out.push(format!("{pad0}}}"));
                } else {
                    ctx.out.push(format!("{pad0}while ({cond_for_loop}) {{"));
                    ctx.out.extend(body);
                    ctx.out.push(format!("{pad0}}}"));
                }
                ctx.loop_stack.pop();
                emit_node(ctx, outside, until);
                return;
            }
        }
    }

    // Bottom-test (`do`/`while`) detection: a single back-edge from a `cjmp`
    // latch that tests at the *bottom*. Reached either when the header is not a
    // cjmp, or when the header *is* a cjmp but an inner branch (both arms stay in
    // the loop) — the `term == "cjmp"` path above already returned if the header
    // itself was the loop's exit test, so getting here means the real test is the
    // latch below, which is exactly a `do`/`while`.
    if back_edges.len() == 1 {
        let t = back_edges[0];
        if t != h && ctx.cfg.blocks[t].terminator == "cjmp" {
            let (tt, tf) = cjmp_arms(ctx.cfg, ctx.succ, t);
            if let (Some(tt), Some(tf)) = (tt, tf) {
                let tt_back = tt == h;
                let tf_back = tf == h;
                let tt_out = !body_set.contains(&tt);
                let tf_out = !body_set.contains(&tf);
                let do_while_cond: Option<String> = if tt_back && tf_out {
                    Some(cond_text(ctx, t))
                } else if tf_back && tt_out {
                    Some(negated_cond_text(ctx, t))
                } else {
                    None
                };
                if let Some(cond_for_loop) = do_while_cond {
                    let outside = if tt_back && tf_out { tf } else { tt };
                    ctx.out.push(format!("{}do {{", pad(ctx.indent)));
                    ctx.indent += 1;
                    ctx.visited[t] = true;
                    emit_block_body_and_terminator(ctx, h, Some(t));
                    for line in &ctx.body_lines[t] {
                        ctx.out.push(format!("{}{}", pad(ctx.indent), line));
                    }
                    ctx.indent -= 1;
                    ctx.out.push(format!("{}}} while ({cond_for_loop});", pad(ctx.indent)));
                    ctx.loop_stack.pop();
                    emit_node(ctx, outside, until);
                    return;
                }
            }
        }
    }

    // Generic infinite-loop-with-break fallback.
    ctx.out.push(format!("{}while (1) {{", pad(ctx.indent)));
    ctx.indent += 1;
    emit_block_body_and_terminator(ctx, h, Some(h));
    ctx.indent -= 1;
    ctx.out.push(format!("{}}}", pad(ctx.indent)));
    ctx.loop_stack.pop();
    if let Some(e) = exit {
        emit_node(ctx, e, until);
    }
}

/// Structure `blocks` (aligned by index with `cfg.blocks`) into pseudo-C.
pub fn structure(cfg: &CfgArtifact, blocks: &[SsaBlock], names: &RenderNames) -> StructuredOutput {
    let n = cfg.blocks.len();
    if n == 0 {
        return StructuredOutput { lines: Vec::new(), has_loop: false, fallback_count: 0 };
    }

    let (succ, pred) = block_graph(cfg);
    let dom = dominators_fwd(n, &pred);
    let idom = immediate_doms(&dom);
    let is_exit: Vec<bool> = cfg.blocks.iter().map(|b| matches!(b.terminator.as_str(), "ret" | "tail-call" | "int" | "call-noreturn")).collect();
    let pdom = dominators_rev(n, &succ, &is_exit);
    let ipdom = immediate_doms(&pdom);
    let _ = &idom; // idom itself isn't needed beyond computing dom sets for back-edge detection

    let mut loop_body: HashMap<usize, BTreeSet<usize>> = HashMap::new();
    let mut loop_back_edges: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut is_header = vec![false; n];
    for u in 0..n {
        for &h in &succ[u] {
            if dom[u].contains(&h) {
                is_header[h] = true;
                loop_back_edges.entry(h).or_default().push(u);
                let body = collect_loop_body(h, u, &pred);
                loop_body.entry(h).or_default().extend(body);
            }
        }
    }
    let mut loop_exit: HashMap<usize, Option<usize>> = HashMap::new();
    for (&h, body) in &loop_body {
        let mut candidates: BTreeSet<usize> = BTreeSet::new();
        for &b in body {
            for &s in &succ[b] {
                if !body.contains(&s) {
                    candidates.insert(s);
                }
            }
        }
        let chosen = match ipdom[h] {
            Some(p) if candidates.contains(&p) => Some(p),
            _ => candidates.iter().next().copied(),
        };
        loop_exit.insert(h, chosen);
    }

    let body_lines: Vec<Vec<String>> = blocks
        .iter()
        .map(|b| {
            let header = if crate::coalesce::is_synthetic_va(b.start) {
                format!("// block_{}: (edge split)", b.id)
            } else {
                format!("// block_{}: {}", b.id, b.start)
            };
            let mut lines = vec![header];
            lines.extend(b.stmts.iter().filter_map(|s| render_stmt(&s.stmt, names)));
            lines
        })
        .collect();
    let conds: Vec<Option<MicroExpr>> = blocks.iter().map(|b| b.condition.clone()).collect();

    let mut ctx = Ctx {
        cfg,
        names,
        succ: &succ,
        pred: &pred,
        ipdom: &ipdom,
        is_header: &is_header,
        loop_body: &loop_body,
        loop_back_edges: &loop_back_edges,
        loop_exit: &loop_exit,
        body_lines: &body_lines,
        conds: &conds,
        visited: vec![false; n],
        loop_stack: Vec::new(),
        out: Vec::new(),
        indent: 1,
        fallback_count: 0,
        budget: n.saturating_mul(8) + 64,
    };
    emit_node(&mut ctx, 0, None);

    StructuredOutput { lines: ctx.out, has_loop: !loop_body.is_empty(), fallback_count: ctx.fallback_count }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CfgInput, CfgPass, Ctx as PassCtx, Pass, SsaPass};
    use n0xis_arch::X64;
    use n0xis_contracts::Va;
    use n0xis_sources::Snapshot;

    fn structure_code(code: Vec<u8>) -> StructuredOutput {
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = PassCtx::new(&snap, &arch);
        let cfg = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), 128)).unwrap();
        let ssa = SsaPass.run(&ctx, cfg.clone()).unwrap();
        let names = RenderNames::new(&cfg.callsites);
        structure(&cfg, &ssa.blocks, &names)
    }

    #[test]
    fn if_else_reconstructs_with_the_exact_condition() {
        // cmp rcx,0 ; je 0x100f ; mov rax,1 ; jmp 0x1016 ; mov rax,2 ; ret
        let code = vec![
            0x48, 0x83, 0xf9, 0x00, // 0x1000 cmp rcx, 0
            0x74, 0x09, // 0x1004 je 0x100f
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // 0x1006 mov rax, 1
            0xeb, 0x07, // 0x100d jmp 0x1016
            0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00, // 0x100f mov rax, 2
            0xc3, // 0x1016 ret
        ];
        let out = structure_code(code);
        let text = out.lines.join("\n");
        assert!(text.contains("if ((rcx.0 == 0x0)) {"), "{text}");
        assert!(text.contains("rax.1 = 0x1;"), "{text}");
        assert!(text.contains("} else {"), "{text}");
        assert!(text.contains("rax.2 = 0x2;"), "{text}");
        assert_eq!(out.fallback_count, 0, "should structure cleanly: {text}");
    }

    #[test]
    fn an_empty_then_arm_inverts_the_condition() {
        // test rcx,rcx ; je 0x1008 ; mov rax,rdx ; ret — the true edge goes
        // straight to the return (empty then), the work is on the false edge.
        // Structuring inverts to `if (rcx != 0) { … }` with no empty arm/else.
        let code = vec![0x48, 0x85, 0xc9, 0x74, 0x03, 0x48, 0x89, 0xd0, 0xc3];
        let out = structure_code(code);
        let text = out.lines.join("\n");
        assert!(text.contains("if ((rcx.0 != 0x0))"), "condition should invert: {text}");
        assert!(!text.contains("} else {"), "no else arm expected: {text}");
        // No empty braced block (`{` immediately followed by `}`).
        for w in out.lines.windows(2) {
            assert!(!(w[0].trim_end().ends_with('{') && w[1].trim() == "}"), "no empty block: {text}");
        }
        assert_eq!(out.fallback_count, 0, "{text}");
    }

    #[test]
    fn split_trailing_step_hoists_only_a_top_level_induction_step() {
        // The `for`-header step is the last top-level statement, self-referential.
        let body = vec!["    v1 = (v1 + *rdi);".to_string(), "    rdi = (rdi + 0x8);".to_string()];
        let (rest, step) = split_trailing_step(&body).expect("should find the step");
        assert_eq!(step, "rdi = (rdi + 0x8)");
        assert_eq!(rest, vec!["    v1 = (v1 + *rdi);".to_string()]);
        // `++`/`+=` forms.
        assert_eq!(split_trailing_step(&["    i += 0x2;".to_string()]).unwrap().1, "i += 0x2");
        // A non-step last line (a plain store / call) is not a step.
        assert!(split_trailing_step(&["    rdi = (rdi + 0x8);".to_string(), "    *rcx = v1;".to_string()]).is_none());
        // A step nested one level deeper (inside an inner `if`, not the loop's own
        // step) must be refused — it is not at the body's outermost indent.
        let nested = vec!["    v1 = (v1 + *rdi);".to_string(), "    if ((x != 0x0)) {".to_string(), "        i = (i + 0x1);".to_string(), "    }".to_string()];
        assert!(split_trailing_step(&nested).is_none());
    }

    #[test]
    fn a_real_compiled_counting_for_loop_recovers_as_for() {
        // Ground-truth guard using a compiled pointer-walk shape the corpus test
        // covers end-to-end: a `while` whose body's last top-level line is the
        // induction step reformats to `for (; cond; step)`. Exercised here at the
        // helper level (the CFG-level recovery is verified on real binaries —
        // gcc/clang -O1/-O2 sum_array/count_down/every_other/ptr_sum).
        let body = vec!["    v2 = (v2 + *(uint64_t*)((rdi + (v1 * 0x8))));".to_string(), "    v1 = (v1 + 0x2);".to_string()];
        let (rest, step) = split_trailing_step(&body).unwrap();
        assert_eq!(step, "v1 = (v1 + 0x2)");
        assert_eq!(rest.len(), 1);
    }

    #[test]
    fn a_nested_else_if_collapses_into_an_else_if_chain() {
        // cmp rcx,1; je A ; cmp rcx,2; je B ; C: ret 30 ; A: ret 10 ; B: ret 20
        // The else arm is exactly one `if`, so it reads `else if`, not `else { if }`.
        let code = vec![
            0x48, 0x83, 0xf9, 0x01, // cmp rcx, 1
            0x74, 0x09, // je A (0x100f)
            0x48, 0x83, 0xf9, 0x02, // cmp rcx, 2
            0x74, 0x06, // je B (0x1012)
            0xb0, 0x1e, 0xc3, // C: mov al,30 ; ret
            0xb0, 0x0a, 0xc3, // A: mov al,10 ; ret
            0xb0, 0x14, 0xc3, // B: mov al,20 ; ret
        ];
        let out = structure_code(code);
        let text = out.lines.join("\n");
        assert!(text.contains("} else if ((rcx.0 == 0x2))"), "expected an else-if chain: {text}");
        // Braces stay balanced after the collapse.
        let balance: i32 = out.lines.iter().map(|l| l.matches('{').count() as i32 - l.matches('}').count() as i32).sum();
        assert_eq!(balance, 0, "braces must balance: {text}");
        assert_eq!(out.fallback_count, 0, "{text}");
    }

    #[test]
    fn a_bottom_test_loop_with_an_inner_if_becomes_a_do_while() {
        // do { if (rdx) rax++; rcx-- } while (rcx != 0). The loop header is
        // itself a `cjmp` (the inner `if`), and the real test is the bottom
        // latch — the case the `term != "cjmp"` gate used to miss, leaving a
        // `while (1)` + continue/break instead of this `do`/`while`.
        // test rdx,rdx ; je 0x1008 ; inc rax ; dec rcx ; jne 0x1000 ; ret
        let code = vec![
            0x48, 0x85, 0xd2, // 0x1000 test rdx, rdx  (header / inner if)
            0x74, 0x03, // 0x1003 je 0x1008
            0x48, 0xff, 0xc0, // 0x1005 inc rax
            0x48, 0xff, 0xc9, // 0x1008 dec rcx        (latch)
            0x75, 0xf3, // 0x100b jne 0x1000
            0xc3, // 0x100d ret
        ];
        let out = structure_code(code);
        let text = out.lines.join("\n");
        assert!(out.has_loop, "{text}");
        assert!(text.contains("do {"), "expected a do/while: {text}");
        assert!(text.contains("} while ((rcx.1 != 0x0));"), "expected the bottom test: {text}");
        assert!(text.contains("if ("), "the inner branch must survive inside the loop: {text}");
        assert!(!text.contains("while (1)"), "should not fall back to while(1): {text}");
        assert_eq!(out.fallback_count, 0, "{text}");
    }

    #[test]
    fn a_cross_edge_diamond_structures_without_a_goto() {
        // Two conditional edges converge on a shared block that returns — the
        // shape that used to leave a `goto`. Structuring now resolves it fully
        // (here the second guard folds into `||`, and the shared return is
        // reached cleanly), with no residual `goto` and no fallback.
        // test rcx,rcx ; je 0x100c ; test rdx,rdx ; je 0x100c ; jmp 0x100e ;
        // mov al,7 ; ret
        let code = vec![0x48, 0x85, 0xc9, 0x74, 0x07, 0x48, 0x85, 0xd2, 0x74, 0x02, 0xeb, 0x02, 0xb0, 0x07, 0xc3];
        let out = structure_code(code);
        let text = out.lines.join("\n");
        assert!(!text.contains("goto"), "no residual goto expected: {text}");
        assert_eq!(out.fallback_count, 0, "should structure cleanly: {text}");
    }

    #[test]
    fn a_top_test_loop_becomes_a_while() {
        // entry: cmp rcx,0 ; jle 0x100b (exit)      -- header
        // body:  dec rcx ; jmp back to header
        // exit:  ret
        //
        // 0x1000: cmp rcx, 0        48 83 f9 00
        // 0x1004: jle 0x100b        7e 05
        // 0x1006: dec rcx           48 ff c9
        // 0x1009: jmp 0x1000        eb f5
        // 0x100b: ret               c3
        let code = vec![
            0x48, 0x83, 0xf9, 0x00, // 0x1000 cmp rcx, 0
            0x7e, 0x05, // 0x1004 jle 0x100b
            0x48, 0xff, 0xc9, // 0x1006 dec rcx
            0xeb, 0xf5, // 0x1009 jmp 0x1000
            0xc3, // 0x100b ret
        ];
        let out = structure_code(code);
        let text = out.lines.join("\n");
        assert!(out.has_loop, "{text}");
        assert!(text.contains("while ("), "expected a while loop: {text}");
        assert_eq!(out.fallback_count, 0, "should structure cleanly: {text}");
    }
}

//! Turns one decoded instruction (opcode definition + raw field values) into
//! a human-readable text line, resolving constant-pool references where the
//! prototype's own pools make that possible. Never panics on an out-of-range
//! reference — an unresolvable operand renders as an explicit `<bad ref>`
//! rather than a guess.

use crate::opcodes::{Mode, OpDef};
use crate::proto::{GcConst, NumConst, TableValue};

/// GC constants are backward-indexed: operand value `d` refers to
/// `gc[gc.len() - 1 - d]` (see [`Mode::Str`]'s doc comment for why).
fn gc_ref(gc: &[GcConst], d: u16) -> Option<&GcConst> {
    gc.len().checked_sub(1)?.checked_sub(d as usize).map(|i| &gc[i])
}

fn num_ref(num: &[NumConst], d: u16) -> Option<&NumConst> {
    num.get(d as usize)
}

fn quote(s: &str) -> String {
    format!("{:?}", s) // Rust's Debug escaping is a fine stand-in for Lua string-literal quoting
}

fn render_table_value(v: &TableValue) -> String {
    match v {
        TableValue::Nil => "nil".to_string(),
        TableValue::False => "false".to_string(),
        TableValue::True => "true".to_string(),
        TableValue::Int(i) => i.to_string(),
        TableValue::Num(n) => n.to_string(),
        TableValue::Str(s) => quote(s),
    }
}

fn render_gc(gc: &GcConst) -> String {
    match gc {
        GcConst::Child(idx) => format!("proto#{idx}"),
        GcConst::Str(s) => quote(s),
        GcConst::Table(t) => {
            let preview: Vec<String> = t.array.iter().take(4).map(render_table_value).collect();
            let suffix = if t.array.len() > 4 || !t.hash.is_empty() { ", ..." } else { "" };
            format!("{{{}{}}}", preview.join(", "), suffix)
        }
        GcConst::I64 { lo, hi } => format!("{}i64", (*lo as u64) | ((*hi as u64) << 32)),
        GcConst::U64 { lo, hi } => format!("{}u64", (*lo as u64) | ((*hi as u64) << 32)),
        GcConst::Complex { .. } => "<complex>".to_string(),
    }
}

fn render_num(n: &NumConst) -> String {
    match n {
        NumConst::Int(i) => i.to_string(),
        NumConst::Num(f) => f.to_string(),
    }
}

fn render_pri(v: u16) -> String {
    match v {
        0 => "nil".to_string(),
        1 => "false".to_string(),
        2 => "true".to_string(),
        other => format!("pri<{other}>"),
    }
}

/// Render one operand field per its [`Mode`]. `idx` is the current
/// instruction's own index, needed for jump-target arithmetic.
fn render_operand(mode: Mode, value: u16, idx: u32, gc: &[GcConst], num: &[NumConst]) -> Option<String> {
    match mode {
        Mode::None => None,
        Mode::Dst | Mode::Base | Mode::Var | Mode::RBase => Some(format!("r{value}")),
        Mode::Uv => Some(format!("u{value}")),
        Mode::Lit => Some(value.to_string()),
        Mode::Lits => Some((value as i16).to_string()),
        Mode::Pri => Some(render_pri(value)),
        Mode::Num => Some(num_ref(num, value).map(render_num).unwrap_or_else(|| "<bad knum ref>".to_string())),
        Mode::Str | Mode::Tab | Mode::Func | Mode::Cdata => {
            Some(gc_ref(gc, value).map(render_gc).unwrap_or_else(|| "<bad kgc ref>".to_string()))
        }
        Mode::Jump => {
            let delta = value as i64 - 0x8000;
            let target = idx as i64 + 1 + delta;
            Some(format!("=>{target}"))
        }
    }
}

/// Render a full instruction line, e.g. `GGET r0, "reserve_ammo"` or
/// `ADDVN r1, r1, 1`.
pub fn render(def: &OpDef, idx: u32, a: u16, b: Option<u16>, d: u16, gc: &[GcConst], num: &[NumConst]) -> String {
    let mut parts = Vec::with_capacity(3);
    if let Some(s) = render_operand(def.a, a, idx, gc, num) {
        parts.push(s);
    }
    if let Some(bval) = b
        && let Some(s) = render_operand(def.b, bval, idx, gc, num)
    {
        parts.push(s);
    }
    if let Some(s) = render_operand(def.d, d, idx, gc, num) {
        parts.push(s);
    }
    if parts.is_empty() {
        def.name.to_string()
    } else {
        format!("{} {}", def.name, parts.join(", "))
    }
}

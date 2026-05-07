//! Template-based pseudo-C renderer (v0). Lifts the linear instruction
//! stream of an already-built `IrFunction` into a goto-style C-like view that
//! preserves block structure, call targets (with resolved names where
//! available), arg hints, stack locals, and constant tracking.
//!
//! Scope intentionally limited:
//!   * No structured-control reconstruction (no `if/else/while`).
//!     Block transitions are emitted as labels + `goto`.
//!   * No SSA / type recovery.
//!   * Best-effort instruction lifting; anything unrecognised is rendered as
//!     `// asm: <original>` so the output never silently drops semantics.
//!
//! Output schema: `n0x.decomp.pseudo.v1`.

use crate::ir::{IrCallsite, IrFunction, SymbolMap};
use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const SCHEMA: &str = "n0x.decomp.pseudo.v1";

#[derive(Serialize)]
pub struct PseudoFunction {
    pub schema: &'static str,
    pub address: String,
    pub end_address: String,
    pub signature: String,
    pub pseudo: Vec<String>,
    pub locals: Vec<PseudoLocal>,
    pub quality: f32,
    pub flags: Vec<&'static str>,
    pub instruction_count: usize,
    pub converted_count: usize,
}

#[derive(Serialize)]
pub struct PseudoLocal {
    /// Stack offset from `rsp` at function entry (always non-negative for
    /// callee-allocated locals: `rsp` was already decremented in the prolog).
    pub offset: u64,
    pub access_count: usize,
    pub size_hint: usize,
}

#[derive(Clone, Copy, Debug)]
pub enum Style {
    /// Goto-style block labels. Always succeeds.
    Goto,
    /// Structured (`if/else/while/do-while`) recovery via dominators +
    /// natural-loop detection. Falls back to goto for regions that are
    /// irreducible or that the v0 reducer can't classify.
    Structured,
}

#[allow(dead_code)]
pub fn render(
    start_ip: u64,
    bytes: &[u8],
    func: &IrFunction,
    symbols: Option<&SymbolMap>,
    iat: Option<&SymbolMap>,
) -> PseudoFunction {
    render_with(start_ip, bytes, func, symbols, iat, Style::Goto)
}

pub fn render_with(
    start_ip: u64,
    bytes: &[u8],
    func: &IrFunction,
    symbols: Option<&SymbolMap>,
    iat: Option<&SymbolMap>,
    style: Style,
) -> PseudoFunction {
    match style {
        Style::Goto => render_goto(start_ip, bytes, func, symbols, iat),
        Style::Structured => render_structured(start_ip, bytes, func, symbols, iat),
    }
}

fn render_goto(
    start_ip: u64,
    bytes: &[u8],
    func: &IrFunction,
    symbols: Option<&SymbolMap>,
    iat: Option<&SymbolMap>,
) -> PseudoFunction {
    let mut decoder = Decoder::with_ip(64, bytes, start_ip, DecoderOptions::NONE);
    let end_ip = parse_hex(&func.end_address);

    // Pre-index blocks by start address so we can map branch targets to
    // labels, and callsites by `from` address for argument-hint lookup.
    let mut block_id_by_ip: BTreeMap<u64, usize> = BTreeMap::new();
    for b in &func.blocks {
        block_id_by_ip.insert(parse_hex(&b.address), b.id);
    }
    let mut callsite_by_ip: BTreeMap<u64, &IrCallsite> = BTreeMap::new();
    for cs in &func.callsites {
        callsite_by_ip.insert(parse_hex(&cs.from), cs);
    }

    let mut lines: Vec<String> = Vec::new();
    let mut locals: BTreeMap<u64, PseudoLocal> = BTreeMap::new();
    let mut total = 0usize;
    let mut converted = 0usize;
    let mut current_block: Option<usize> = None;

    // Track the most recent `cmp`/`test` so a following Jcc can reference it.
    let mut last_compare: Option<Compare> = None;

    while decoder.can_decode() && decoder.ip() < end_ip {
        let ins = decoder.decode();
        if ins.is_invalid() {
            break;
        }
        total += 1;

        // Emit a block label when we cross a block boundary.
        if let Some(&id) = block_id_by_ip.get(&ins.ip()) {
            if current_block != Some(id) {
                if !lines.is_empty() {
                    lines.push(String::new());
                }
                lines.push(format!("block_{id}:    // 0x{:X}", ins.ip()));
                current_block = Some(id);
            }
        }

        let lifted = lift_instruction(
            &ins,
            &block_id_by_ip,
            &callsite_by_ip,
            symbols,
            iat,
            &mut last_compare,
            &mut locals,
        );
        if !lifted.unhandled {
            converted += 1;
        }
        for line in lifted.lines {
            lines.push(format!("    {line}"));
        }
    }

    let signature = render_signature(start_ip, func);
    let mut flags: Vec<&'static str> = Vec::new();
    if !func.switches.is_empty() {
        flags.push("has-switch");
    }
    if func.indirect_branches > 0 {
        flags.push("has-indirect");
    }
    if func.tail_calls > 0 {
        flags.push("has-tail");
    }
    if total > 0 && converted * 5 < total * 4 {
        flags.push("low-coverage");
    }

    let quality = if total == 0 {
        0.0
    } else {
        (converted as f32 / total as f32).min(1.0)
    };

    let mut pseudo: Vec<String> = Vec::new();
    pseudo.push(format!(
        "// {} .. {} ({} instructions, {} blocks)",
        func.address, func.end_address, func.instruction_count, func.block_count
    ));
    pseudo.push(format!(
        "// frame_size=0x{:X}, callsites={}, returns={}",
        func.frame.frame_size,
        func.callsites.len(),
        func.returns
    ));
    pseudo.push(format!("{signature} {{"));
    for line in lines {
        pseudo.push(line);
    }
    pseudo.push("}".to_string());

    let locals_vec: Vec<PseudoLocal> = locals.into_values().collect();

    PseudoFunction {
        schema: SCHEMA,
        address: func.address.clone(),
        end_address: func.end_address.clone(),
        signature,
        pseudo,
        locals: locals_vec,
        quality,
        flags,
        instruction_count: total,
        converted_count: converted,
    }
}

fn render_signature(start_ip: u64, func: &IrFunction) -> String {
    // Win64 ABI: first 4 integer args in rcx, rdx, r8, r9.
    // We don't know real arity, so the v0 signature is fixed.
    let _ = func;
    format!(
        "void sub_{:X}(uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9)",
        start_ip
    )
}

struct Lifted {
    lines: Vec<String>,
    unhandled: bool,
}

#[derive(Clone)]
struct Compare {
    lhs: String,
    rhs: String,
    is_test: bool,
}

fn lift_instruction(
    ins: &Instruction,
    blocks: &BTreeMap<u64, usize>,
    callsites: &BTreeMap<u64, &IrCallsite>,
    symbols: Option<&SymbolMap>,
    iat: Option<&SymbolMap>,
    last_compare: &mut Option<Compare>,
    locals: &mut BTreeMap<u64, PseudoLocal>,
) -> Lifted {
    let mn = ins.mnemonic();
    let mut lines: Vec<String> = Vec::new();

    let goto_for = |target: u64| -> String {
        match blocks.get(&target) {
            Some(id) => format!("goto block_{id};"),
            None => format!("goto 0x{target:X};"),
        }
    };

    match mn {
        Mnemonic::Mov => {
            let dst = format_operand(ins, 0, symbols, locals, true);
            let src = format_operand(ins, 1, symbols, locals, false);
            lines.push(format!("{dst} = {src};"));
        }
        Mnemonic::Movzx => {
            let dst = format_operand(ins, 0, symbols, locals, true);
            let src = format_operand(ins, 1, symbols, locals, false);
            lines.push(format!("{dst} = (uint64_t){src};"));
        }
        Mnemonic::Movsx | Mnemonic::Movsxd => {
            let dst = format_operand(ins, 0, symbols, locals, true);
            let src = format_operand(ins, 1, symbols, locals, false);
            lines.push(format!("{dst} = (int64_t){src};"));
        }
        Mnemonic::Lea => {
            let dst = format_operand(ins, 0, symbols, locals, true);
            let mem = format_lea_target(ins, symbols);
            lines.push(format!("{dst} = {mem};"));
        }
        Mnemonic::Add => binary_op(ins, "+=", &mut lines, symbols, locals),
        Mnemonic::Sub => binary_op(ins, "-=", &mut lines, symbols, locals),
        Mnemonic::Adc => binary_op(ins, "+= /*+CF*/", &mut lines, symbols, locals),
        Mnemonic::Sbb => binary_op(ins, "-= /*-CF*/", &mut lines, symbols, locals),
        Mnemonic::And => binary_op(ins, "&=", &mut lines, symbols, locals),
        Mnemonic::Or => binary_op(ins, "|=", &mut lines, symbols, locals),
        Mnemonic::Xor => {
            // `xor reg, reg` zeroing idiom.
            if ins.op0_kind() == OpKind::Register
                && ins.op1_kind() == OpKind::Register
                && ins.op0_register().full_register() == ins.op1_register().full_register()
            {
                let dst = format_operand(ins, 0, symbols, locals, true);
                lines.push(format!("{dst} = 0;"));
            } else {
                binary_op(ins, "^=", &mut lines, symbols, locals);
            }
        }
        Mnemonic::Shl | Mnemonic::Sal => binary_op(ins, "<<=", &mut lines, symbols, locals),
        Mnemonic::Shr => binary_op(ins, ">>= /*u*/", &mut lines, symbols, locals),
        Mnemonic::Sar => binary_op(ins, ">>= /*s*/", &mut lines, symbols, locals),
        Mnemonic::Rol => binary_op(ins, "= __rotl(...);", &mut lines, symbols, locals),
        Mnemonic::Ror => binary_op(ins, "= __rotr(...);", &mut lines, symbols, locals),
        Mnemonic::Inc => {
            let dst = format_operand(ins, 0, symbols, locals, true);
            lines.push(format!("{dst}++;"));
        }
        Mnemonic::Dec => {
            let dst = format_operand(ins, 0, symbols, locals, true);
            lines.push(format!("{dst}--;"));
        }
        Mnemonic::Neg => {
            let dst = format_operand(ins, 0, symbols, locals, true);
            lines.push(format!("{dst} = -{dst};"));
        }
        Mnemonic::Not => {
            let dst = format_operand(ins, 0, symbols, locals, true);
            lines.push(format!("{dst} = ~{dst};"));
        }
        Mnemonic::Imul | Mnemonic::Mul => binary_op(ins, "*=", &mut lines, symbols, locals),
        Mnemonic::Test => {
            let lhs = format_operand(ins, 0, symbols, locals, false);
            let rhs = format_operand(ins, 1, symbols, locals, false);
            *last_compare = Some(Compare {
                lhs: lhs.clone(),
                rhs: rhs.clone(),
                is_test: true,
            });
            lines.push(format!("// flags = test({lhs}, {rhs});"));
        }
        Mnemonic::Cmp => {
            let lhs = format_operand(ins, 0, symbols, locals, false);
            let rhs = format_operand(ins, 1, symbols, locals, false);
            *last_compare = Some(Compare {
                lhs: lhs.clone(),
                rhs: rhs.clone(),
                is_test: false,
            });
            lines.push(format!("// flags = cmp({lhs}, {rhs});"));
        }
        Mnemonic::Push => {
            let src = format_operand(ins, 0, symbols, locals, false);
            lines.push(format!("// push {src};"));
        }
        Mnemonic::Pop => {
            let dst = format_operand(ins, 0, symbols, locals, true);
            lines.push(format!("// pop -> {dst};"));
        }
        Mnemonic::Nop => {
            lines.push("// nop".to_string());
        }
        Mnemonic::Ret => {
            lines.push("return rax;".to_string());
        }
        Mnemonic::Call => {
            let cs = callsites.get(&ins.ip()).copied();
            let target_name = cs
                .and_then(|c| c.target_name.clone())
                .or_else(|| {
                    if ins.near_branch_target() != 0 {
                        symbols
                            .and_then(|m| m.get(&ins.near_branch_target()).cloned())
                    } else {
                        None
                    }
                })
                .or_else(|| {
                    if ins.is_ip_rel_memory_operand() {
                        iat.and_then(|m| m.get(&ins.ip_rel_memory_address()).cloned())
                    } else {
                        None
                    }
                });
            let callee = match target_name {
                Some(n) => mangle_call_name(&n),
                None => match ins.near_branch_target() {
                    0 => format_operand(ins, 0, symbols, locals, false),
                    t => format!("sub_{t:X}"),
                },
            };
            let args = render_args(cs);
            lines.push(format!("rax = {callee}({args});"));
        }
        Mnemonic::Jmp => {
            let cs = callsites.get(&ins.ip()).copied();
            let tgt = ins.near_branch_target();
            if let Some(cs) = cs {
                if cs.kind == "tail" || cs.kind == "tail-import" {
                    let name = cs
                        .target_name
                        .clone()
                        .unwrap_or_else(|| match cs.target.clone() {
                            Some(t) => format!("sub_{}", t.trim_start_matches("0x")),
                            None => "(*indirect)".to_string(),
                        });
                    let callee = mangle_call_name(&name);
                    let args = render_args(Some(cs));
                    lines.push(format!("return {callee}({args});  // tail-call"));
                    return Lifted {
                        lines,
                        unhandled: false,
                    };
                }
            }
            if tgt != 0 {
                lines.push(goto_for(tgt));
            } else if ins.is_ip_rel_memory_operand() {
                let slot = ins.ip_rel_memory_address();
                let name = iat.and_then(|m| m.get(&slot).cloned());
                match name {
                    Some(n) => lines.push(format!("return {}();  // tail-import", mangle_call_name(&n))),
                    None => lines.push(format!("goto *(*(void**)0x{slot:X});")),
                }
            } else {
                let dst = format_operand(ins, 0, symbols, locals, false);
                lines.push(format!("goto *{dst};"));
            }
        }
        m if is_jcc(m) => {
            let cond = condition_for(m, last_compare.as_ref());
            let tgt = ins.near_branch_target();
            let goto = if tgt != 0 {
                goto_for(tgt)
            } else {
                "/* indirect */".to_string()
            };
            lines.push(format!("if ({cond}) {goto}"));
        }
        _ => {
            // Fallback: emit the original asm as a comment so semantics
            // aren't silently lost. Uses iced's intel form.
            let mut buf = String::new();
            use iced_x86::{Formatter, NasmFormatter};
            let mut fmt = NasmFormatter::new();
            fmt.format(ins, &mut buf);
            lines.push(format!("// asm: {buf}"));
            return Lifted {
                lines,
                unhandled: true,
            };
        }
    }

    Lifted {
        lines,
        unhandled: false,
    }
}

fn binary_op(
    ins: &Instruction,
    op: &str,
    lines: &mut Vec<String>,
    symbols: Option<&SymbolMap>,
    locals: &mut BTreeMap<u64, PseudoLocal>,
) {
    let dst = format_operand(ins, 0, symbols, locals, true);
    let src = if ins.op_count() >= 2 {
        format_operand(ins, 1, symbols, locals, false)
    } else {
        String::new()
    };
    if src.is_empty() {
        lines.push(format!("{dst} {op};"));
    } else {
        lines.push(format!("{dst} {op} {src};"));
    }
}

fn render_args(cs: Option<&IrCallsite>) -> String {
    match cs {
        None => "rcx, rdx, r8, r9".to_string(),
        Some(c) => {
            // Prefer the tracked constant (e.g. "0x0", "&str_foo"); otherwise
            // just emit the register name. The prior pseudo lines already show
            // where the register's value came from, so re-pasting the asm
            // text would only add noise.
            let mut out = Vec::new();
            for reg in ["rcx", "rdx", "r8", "r9"] {
                let h = c.arg_hints.iter().find(|h| h.reg == reg);
                let val = h
                    .and_then(|h| h.const_val.clone())
                    .unwrap_or_else(|| reg.to_string());
                out.push(val);
            }
            out.join(", ")
        }
    }
}

fn format_operand(
    ins: &Instruction,
    idx: u32,
    symbols: Option<&SymbolMap>,
    locals: &mut BTreeMap<u64, PseudoLocal>,
    is_dst: bool,
) -> String {
    match ins.op_kind(idx) {
        OpKind::Register => reg_name(ins.op_register(idx)),
        OpKind::Immediate8 => format!("0x{:X}", ins.immediate8()),
        OpKind::Immediate16 => format!("0x{:X}", ins.immediate16()),
        OpKind::Immediate32 => format!("0x{:X}", ins.immediate32()),
        OpKind::Immediate64 => format!("0x{:X}", ins.immediate64()),
        OpKind::Immediate8to16 => format!("0x{:X}", ins.immediate8to16() as u64),
        OpKind::Immediate8to32 => format!("0x{:X}", ins.immediate8to32() as u64),
        OpKind::Immediate8to64 => format!("0x{:X}", ins.immediate8to64() as u64),
        OpKind::Immediate32to64 => format!("0x{:X}", ins.immediate32to64() as u64),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            format!("0x{:X}", ins.near_branch_target())
        }
        OpKind::Memory => format_memory(ins, symbols, locals, is_dst),
        _ => "/*op?*/".to_string(),
    }
}

fn format_memory(
    ins: &Instruction,
    symbols: Option<&SymbolMap>,
    locals: &mut BTreeMap<u64, PseudoLocal>,
    is_dst: bool,
) -> String {
    let base = ins.memory_base();
    let index = ins.memory_index();
    let scale = ins.memory_index_scale();
    let disp = ins.memory_displacement64();
    let size = c_type_for_memsize(ins.memory_size());

    // RIP-relative: prefer symbol name when known.
    if ins.is_ip_rel_memory_operand() {
        let addr = ins.ip_rel_memory_address();
        if let Some(name) = symbols.and_then(|m| m.get(&addr).cloned()) {
            return format!("{name}");
        }
        return format!("*({size}*)0x{addr:X}");
    }

    // Stack local: track and name it.
    if base == Register::RSP && index == Register::None {
        let entry = locals.entry(disp).or_insert_with(|| PseudoLocal {
            offset: disp,
            access_count: 0,
            size_hint: type_byte_size(ins.memory_size()),
        });
        entry.access_count += 1;
        entry.size_hint = entry.size_hint.max(type_byte_size(ins.memory_size()));
        let _ = is_dst;
        return format!("local_{disp:X}");
    }

    // Pure absolute (no base, no index): treat as MMIO/global pointer.
    if base == Register::None && index == Register::None {
        return format!("*({size}*)0x{disp:X}");
    }

    // General: *(typed*)(base + index*scale + disp).
    let mut parts: Vec<String> = Vec::new();
    if base != Register::None {
        parts.push(reg_name(base));
    }
    if index != Register::None {
        if scale > 1 {
            parts.push(format!("{}*{}", reg_name(index), scale));
        } else {
            parts.push(reg_name(index));
        }
    }
    if disp != 0 {
        parts.push(format!("0x{disp:X}"));
    }
    let inner = parts.join(" + ");
    format!("*({size}*)({inner})")
}

fn format_lea_target(ins: &Instruction, symbols: Option<&SymbolMap>) -> String {
    if ins.is_ip_rel_memory_operand() {
        let addr = ins.ip_rel_memory_address();
        if let Some(name) = symbols.and_then(|m| m.get(&addr).cloned()) {
            return format!("&{name}");
        }
        return format!("(void*)0x{addr:X}");
    }
    let base = ins.memory_base();
    let index = ins.memory_index();
    let scale = ins.memory_index_scale();
    let disp = ins.memory_displacement64();
    let mut parts: Vec<String> = Vec::new();
    if base != Register::None {
        parts.push(reg_name(base));
    }
    if index != Register::None {
        if scale > 1 {
            parts.push(format!("{}*{}", reg_name(index), scale));
        } else {
            parts.push(reg_name(index));
        }
    }
    if disp != 0 {
        parts.push(format!("0x{disp:X}"));
    }
    if parts.is_empty() {
        "0".to_string()
    } else if parts.len() == 1 {
        parts.into_iter().next().unwrap()
    } else {
        parts.join(" + ")
    }
}

fn c_type_for_memsize(s: MemorySize) -> &'static str {
    use iced_x86::MemorySize as MS;
    match s {
        MS::UInt8 | MS::Int8 => "uint8_t",
        MS::UInt16 | MS::Int16 => "uint16_t",
        MS::UInt32 | MS::Int32 => "uint32_t",
        MS::UInt64 | MS::Int64 => "uint64_t",
        MS::Float32 => "float",
        MS::Float64 => "double",
        MS::Packed128_Float32 | MS::Packed128_Float64 => "__m128",
        MS::Packed256_Float32 | MS::Packed256_Float64 => "__m256",
        _ => "uint64_t",
    }
}

fn type_byte_size(s: MemorySize) -> usize {
    use iced_x86::MemorySize as MS;
    match s {
        MS::UInt8 | MS::Int8 => 1,
        MS::UInt16 | MS::Int16 => 2,
        MS::UInt32 | MS::Int32 | MS::Float32 => 4,
        MS::UInt64 | MS::Int64 | MS::Float64 => 8,
        MS::Packed128_Float32 | MS::Packed128_Float64 => 16,
        MS::Packed256_Float32 | MS::Packed256_Float64 => 32,
        _ => 8,
    }
}

fn reg_name(r: Register) -> String {
    if r == Register::None {
        return "0".to_string();
    }
    format!("{:?}", r.full_register()).to_lowercase()
}

fn is_jcc(m: Mnemonic) -> bool {
    use Mnemonic as M;
    matches!(
        m,
        M::Ja | M::Jae
            | M::Jb
            | M::Jbe
            | M::Je
            | M::Jne
            | M::Jg
            | M::Jge
            | M::Jl
            | M::Jle
            | M::Js
            | M::Jns
            | M::Jo
            | M::Jno
            | M::Jp
            | M::Jnp
            | M::Jcxz
            | M::Jecxz
            | M::Jrcxz
    )
}

fn condition_for(m: Mnemonic, last: Option<&Compare>) -> String {
    let (lhs, rhs) = match last {
        Some(c) if !c.is_test => (c.lhs.clone(), c.rhs.clone()),
        Some(c) if c.is_test => {
            // After test reg,reg: jne == "(reg != 0)", je == "(reg == 0)".
            let same = c.lhs == c.rhs;
            let a = c.lhs.clone();
            let b = c.rhs.clone();
            return match m {
                Mnemonic::Je => {
                    if same {
                        format!("{a} == 0")
                    } else {
                        format!("({a} & {b}) == 0")
                    }
                }
                Mnemonic::Jne => {
                    if same {
                        format!("{a} != 0")
                    } else {
                        format!("({a} & {b}) != 0")
                    }
                }
                Mnemonic::Js => format!("(int64_t){a} < 0"),
                Mnemonic::Jns => format!("(int64_t){a} >= 0"),
                _ => format!("/*flags from test {a},{b}*/ {m:?}"),
            };
        }
        _ => ("/*lhs*/".to_string(), "/*rhs*/".to_string()),
    };
    use Mnemonic as M;
    match m {
        M::Je => format!("{lhs} == {rhs}"),
        M::Jne => format!("{lhs} != {rhs}"),
        M::Ja => format!("{lhs} > {rhs} /*u*/"),
        M::Jae => format!("{lhs} >= {rhs} /*u*/"),
        M::Jb => format!("{lhs} < {rhs} /*u*/"),
        M::Jbe => format!("{lhs} <= {rhs} /*u*/"),
        M::Jg => format!("(int64_t){lhs} > (int64_t){rhs}"),
        M::Jge => format!("(int64_t){lhs} >= (int64_t){rhs}"),
        M::Jl => format!("(int64_t){lhs} < (int64_t){rhs}"),
        M::Jle => format!("(int64_t){lhs} <= (int64_t){rhs}"),
        M::Js => format!("(int64_t)({lhs} - {rhs}) < 0"),
        M::Jns => format!("(int64_t)({lhs} - {rhs}) >= 0"),
        _ => format!("/*{m:?}*/"),
    }
}

fn mangle_call_name(name: &str) -> String {
    // Replace '!' with '__' so it can be read as a C identifier without
    // dropping the module prefix. `kernel32!CreateFileW` -> `kernel32__CreateFileW`.
    name.replace('!', "__")
}

fn parse_hex(s: &str) -> u64 {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).unwrap_or(0)
}

/// Flatten the structured `pseudo` Vec into a single source-like string.
#[allow(dead_code)]
pub fn flatten(p: &PseudoFunction) -> String {
    p.pseudo.join("\n")
}

// ============================================================================
// Structured control reconstruction (v0)
//
// Pipeline:
//   1. Build CFG (succ/pred adjacency keyed by block index).
//   2. Compute dominators (iterative fixed point).
//   3. Compute post-dominators on a reversed CFG with a synthetic exit node
//      collecting every `ret`/`tail-*`/`int`/no-successor block.
//   4. Derive immediate dominators / immediate post-dominators.
//   5. Detect natural loops: back-edges (u,h) where h ∈ dom[u]; the body is
//      every node that can reach u without going through h.
//   6. Per block: re-lift its instructions, dropping the trailing branch
//      and capturing the cjmp condition.
//   7. Recursive descent emitter with `until` (stop point — usually the
//      ipdom of the enclosing `if`) and a `loop_stack` so back-edges become
//      `continue;` and edges to the loop exit become `break;`.
//
// Anything we can't classify cleanly (irreducible CFG, missing ipdom, etc.)
// falls back to a plain `goto block_N;` so the output stays sound.
// ============================================================================

fn render_structured(
    start_ip: u64,
    bytes: &[u8],
    func: &IrFunction,
    symbols: Option<&SymbolMap>,
    iat: Option<&SymbolMap>,
) -> PseudoFunction {
    // 1. CFG ------------------------------------------------------------------
    let n = func.blocks.len();
    if n == 0 {
        return render_goto(start_ip, bytes, func, symbols, iat);
    }
    let mut addr_to_idx: HashMap<u64, usize> = HashMap::new();
    for (i, b) in func.blocks.iter().enumerate() {
        addr_to_idx.insert(parse_hex(&b.address), i);
    }
    let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut succ_kind: Vec<Vec<&'static str>> = vec![Vec::new(); n];
    let mut pred: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, b) in func.blocks.iter().enumerate() {
        for s in &b.successors {
            let to_addr = parse_hex(&s.to);
            if let Some(&j) = addr_to_idx.get(&to_addr) {
                succ[i].push(j);
                succ_kind[i].push(s.kind);
                pred[j].push(i);
            }
        }
    }

    // 2 + 3. Dominators / post-dominators -------------------------------------
    let dom = dominators_fwd(n, &pred);
    let pdom = dominators_rev(n, &succ, func);
    let _idom = immediate_doms(&dom);
    let ipdom = immediate_doms(&pdom);

    // 4. Loops ----------------------------------------------------------------
    let mut loop_body: HashMap<usize, BTreeSet<usize>> = HashMap::new();
    let mut loop_back_edges: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut is_header = vec![false; n];
    for u in 0..n {
        for &h in &succ[u] {
            if dom[u].contains(&h) {
                // (u → h) is a back-edge.
                is_header[h] = true;
                loop_back_edges.entry(h).or_default().push(u);
                let body = collect_loop_body(h, u, &pred);
                loop_body.entry(h).or_default().extend(body);
            }
        }
    }
    // Loop exit per header: the most-frequent successor that lies outside the
    // body. If the header's terminator is `cjmp`, this is just the off-body
    // arm of the conditional jump.
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
        // Prefer ipdom[h] if it's in candidates.
        let chosen = if let Some(p) = ipdom[h] {
            if candidates.contains(&p) {
                Some(p)
            } else {
                candidates.iter().next().copied()
            }
        } else {
            candidates.iter().next().copied()
        };
        loop_exit.insert(h, chosen);
    }

    // 5. Lift each block (strip trailing branch).------------------------------
    let (body_lines, conds, locals_map, total, converted) =
        lift_blocks_for_structured(start_ip, bytes, func, symbols, iat);

    // 6. Recursive emit -------------------------------------------------------
    let mut ctx = Ctx {
        blocks: &func.blocks,
        succ: &succ,
        succ_kind: &succ_kind,
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

    // 7. Assemble PseudoFunction ---------------------------------------------
    let signature = render_signature(start_ip, func);
    let mut flags: Vec<&'static str> = vec!["structured"];
    if !func.switches.is_empty() {
        flags.push("has-switch");
    }
    if func.indirect_branches > 0 {
        flags.push("has-indirect");
    }
    if func.tail_calls > 0 {
        flags.push("has-tail");
    }
    if !loop_body.is_empty() {
        flags.push("has-loop");
    }
    if ctx.fallback_count > 0 {
        flags.push("structured-partial");
    }
    if total > 0 && converted * 5 < total * 4 {
        flags.push("low-coverage");
    }
    let quality = if total == 0 {
        0.0
    } else {
        (converted as f32 / total as f32).min(1.0)
    };

    let mut pseudo: Vec<String> = Vec::new();
    pseudo.push(format!(
        "// {} .. {} ({} instructions, {} blocks, {} loops)",
        func.address,
        func.end_address,
        func.instruction_count,
        func.block_count,
        loop_body.len()
    ));
    pseudo.push(format!(
        "// frame_size=0x{:X}, callsites={}, returns={}, structured-fallbacks={}",
        func.frame.frame_size,
        func.callsites.len(),
        func.returns,
        ctx.fallback_count,
    ));
    pseudo.push(format!("{signature} {{"));
    pseudo.extend(ctx.out);
    pseudo.push("}".to_string());

    let locals_vec: Vec<PseudoLocal> = locals_map.into_values().collect();

    PseudoFunction {
        schema: SCHEMA,
        address: func.address.clone(),
        end_address: func.end_address.clone(),
        signature,
        pseudo,
        locals: locals_vec,
        quality,
        flags,
        instruction_count: total,
        converted_count: converted,
    }
}

struct Ctx<'a> {
    blocks: &'a [crate::ir::IrBlock],
    succ: &'a [Vec<usize>],
    succ_kind: &'a [Vec<&'static str>],
    pred: &'a [Vec<usize>],
    ipdom: &'a [Option<usize>],
    is_header: &'a [bool],
    loop_body: &'a HashMap<usize, BTreeSet<usize>>,
    loop_back_edges: &'a HashMap<usize, Vec<usize>>,
    loop_exit: &'a HashMap<usize, Option<usize>>,
    body_lines: &'a [Vec<String>],
    conds: &'a [Option<String>],
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

fn emit_node(ctx: &mut Ctx, n: usize, until: Option<usize>) {
    if ctx.budget == 0 {
        ctx.out
            .push(format!("{}// (structural budget exhausted)", pad(ctx.indent)));
        ctx.fallback_count += 1;
        return;
    }
    ctx.budget -= 1;

    if Some(n) == until {
        return;
    }
    // Back-edge to an enclosing loop header → continue;
    if ctx.loop_stack.contains(&n) {
        ctx.out.push(format!("{}continue;", pad(ctx.indent)));
        return;
    }
    // Edge to a known enclosing loop's exit → break;
    if let Some(&active) = ctx.loop_stack.last() {
        if ctx.loop_exit.get(&active).copied().flatten() == Some(n) {
            ctx.out.push(format!("{}break;", pad(ctx.indent)));
            return;
        }
    }
    if ctx.visited[n] {
        ctx.out
            .push(format!("{}goto block_{};", pad(ctx.indent), n));
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

fn emit_block_body_and_terminator(ctx: &mut Ctx, n: usize, until: Option<usize>) {
    // Body lines (terminator branch already stripped).
    for line in &ctx.body_lines[n] {
        ctx.out.push(format!("{}{}", pad(ctx.indent), line));
    }
    let block = &ctx.blocks[n];
    match block.terminator {
        "ret" => {
            // body lift already pushed `return rax;`
        }
        "tail-call" | "tail-import" => {
            // body lift already pushed `return name(...);  // tail-*`
        }
        "int" => {
            ctx.out.push(format!("{}// int / abort", pad(ctx.indent)));
        }
        "ijmp" => {
            ctx.out
                .push(format!("{}// indirect jump (unrecovered)", pad(ctx.indent)));
        }
        "jmp" | "fall" => {
            if let Some(&j) = ctx.succ[n].first() {
                emit_node(ctx, j, until);
            }
        }
        "cjmp" => emit_if_else(ctx, n, until),
        "switch" => emit_switch(ctx, n, until),
        _ => {
            ctx.out
                .push(format!("{}// (unknown terminator)", pad(ctx.indent)));
            ctx.fallback_count += 1;
        }
    }
}

fn emit_if_else(ctx: &mut Ctx, n: usize, until: Option<usize>) {
    let cond = ctx.conds[n].clone().unwrap_or_else(|| "/*?*/".to_string());
    let (t_idx, f_idx) = cjmp_arms(ctx, n);
    let merge = ctx.ipdom[n];

    match (t_idx, f_idx) {
        (Some(t), Some(f)) => {
            // Try to fold short-circuit (a && b) / (a || b) before emission.
            if let Some((folded_cond, body_arm, else_arm, eaten)) =
                try_short_circuit(ctx, n, &cond, t, f)
            {
                for &b in &eaten {
                    ctx.visited[b] = true;
                }
                ctx.out
                    .push(format!("{}if ({}) {{", pad(ctx.indent), folded_cond));
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

            ctx.out.push(format!("{}if ({}) {{", pad(ctx.indent), cond));
            ctx.indent += 1;
            emit_node(ctx, t, merge);
            ctx.indent -= 1;
            ctx.out.push(format!("{}}} else {{", pad(ctx.indent)));
            ctx.indent += 1;
            emit_node(ctx, f, merge);
            ctx.indent -= 1;
            ctx.out.push(format!("{}}}", pad(ctx.indent)));
            if let Some(m) = merge {
                emit_node(ctx, m, until);
            }
        }
        _ => {
            ctx.out.push(format!(
                "{}// (cjmp without resolved successors)",
                pad(ctx.indent)
            ));
            ctx.fallback_count += 1;
        }
    }
}

fn cjmp_arms(ctx: &Ctx, n: usize) -> (Option<usize>, Option<usize>) {
    let mut t_idx: Option<usize> = None;
    let mut f_idx: Option<usize> = None;
    for (k, &s) in ctx.succ[n].iter().enumerate() {
        match ctx.succ_kind[n][k] {
            "cjmp-true" => t_idx = Some(s),
            "cjmp-false" => f_idx = Some(s),
            _ => {}
        }
    }
    (t_idx, f_idx)
}

/// Try to fold a 2-block short-circuit chain rooted at `n`.
///
/// Patterns recognised (M = outer merge, B = inner cjmp block, only A→B edge into B):
///   AND-true:  A(t=B, f=M),  B(t=Body, f=M)              → (cond_A && cond_B), body=Body, else=M
///   AND-false: A(t=B, f=M),  B(t=M,    f=Body)           → (cond_A && !cond_B), body=Body, else=M
///   OR-true:   A(t=Body, f=B), B(t=Body, f=M)            → (cond_A || cond_B), body=Body, else=M
///   OR-false:  A(t=M,    f=B), B(t=Body, f=M)            → (!cond_A || cond_B) = unhandled (we keep simple)
///
/// We require: B has cjmp terminator, B has exactly one predecessor (= A), B is not a loop header,
/// B's body has no side-effecting lines (only the comparison/test the cond was lifted from).
fn try_short_circuit(
    ctx: &Ctx,
    n: usize,
    cond_a: &str,
    t: usize,
    f: usize,
) -> Option<(String, usize, usize, Vec<usize>)> {
    // Helper: validate that B is a simple guard block we can fold away.
    let is_pure_guard = |b: usize| -> bool {
        if b == n {
            return false;
        }
        if ctx.is_header[b] {
            return false;
        }
        if ctx.blocks[b].terminator != "cjmp" {
            return false;
        }
        if ctx.pred[b].len() != 1 || ctx.pred[b][0] != n {
            return false;
        }
        // Allow only side-effect-free body lines (heuristic: no assignment with `(`,
        // no `return`, no `goto`, no semicolon-bearing call). Comparisons are lifted
        // into `cond` and don't appear here.
        for line in &ctx.body_lines[b] {
            let l = line.trim();
            if l.is_empty() || l.starts_with("//") {
                continue;
            }
            // Reject if line contains a call or store-like assignment.
            if l.contains('(') || l.contains('=') || l.starts_with("return") {
                return false;
            }
        }
        true
    };

    // AND: A(t=B, f=M)
    if is_pure_guard(t) {
        let (bt, bf) = cjmp_arms(ctx, t);
        if let (Some(bt), Some(bf)) = (bt, bf) {
            let cond_b = ctx.conds[t].clone().unwrap_or_else(|| "/*?*/".into());
            // AND-true:  A(t=B, f=M),  B(t=Body, f=M==f_outer)
            if bf == f {
                let folded = format!("({}) && ({})", cond_a, cond_b);
                return Some((folded, bt, f, vec![t]));
            }
            // AND-false: A(t=B, f=M), B(t=M==f_outer, f=Body)
            if bt == f {
                let folded = format!("({}) && ({})", cond_a, negate_cond(&cond_b));
                return Some((folded, bf, f, vec![t]));
            }
        }
    }

    // OR: A(t=Body, f=B), B(t=Body, f=M)  → (cond_A || cond_B), body=Body=t, else=M=B's f
    if is_pure_guard(f) {
        let (bt, bf) = cjmp_arms(ctx, f);
        if let (Some(bt), Some(bf)) = (bt, bf) {
            let cond_b = ctx.conds[f].clone().unwrap_or_else(|| "/*?*/".into());
            if bt == t {
                let folded = format!("({}) || ({})", cond_a, cond_b);
                return Some((folded, t, bf, vec![f]));
            }
            // OR-mirror: A(t=Body, f=B), B(t=M, f=Body) → (cond_A || !cond_B)
            if bf == t {
                let folded = format!("({}) || ({})", cond_a, negate_cond(&cond_b));
                return Some((folded, t, bt, vec![f]));
            }
        }
    }

    None
}

fn emit_switch(ctx: &mut Ctx, n: usize, until: Option<usize>) {
    let merge = ctx.ipdom[n];
    ctx.out
        .push(format!("{}switch (/* dispatcher */) {{", pad(ctx.indent)));
    let mut emitted_targets: BTreeSet<usize> = BTreeSet::new();
    for (k, &s) in ctx.succ[n].iter().enumerate() {
        if !emitted_targets.insert(s) {
            continue;
        }
        let kind = ctx.succ_kind[n][k];
        let label = if kind == "switch" {
            format!("case {}:", k)
        } else {
            format!("/* {kind} */")
        };
        ctx.out.push(format!("{}    {}", pad(ctx.indent), label));
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
    let block_term = ctx.blocks[h].terminator;
    let body_set = ctx.loop_body.get(&h).cloned().unwrap_or_default();
    let back_edges = ctx
        .loop_back_edges
        .get(&h)
        .cloned()
        .unwrap_or_default();

    // ----- Top-test loop: header is a cjmp with exactly one arm leaving body. ---
    if block_term == "cjmp" {
        let (t_idx, f_idx) = cjmp_arms(ctx, h);
        if let (Some(t), Some(f)) = (t_idx, f_idx) {
            let t_in = body_set.contains(&t);
            let f_in = body_set.contains(&f);
            if t_in ^ f_in {
                let raw_cond = ctx.conds[h].clone().unwrap_or_else(|| "/*?*/".into());
                let cond_for_loop = if t_in {
                    raw_cond
                } else {
                    negate_cond(&raw_cond)
                };
                let inside = if t_in { t } else { f };
                let outside = if t_in { f } else { t };

                // Try to detect a `for` shape: a single latch L (back-edge
                // source), terminator fall/jmp, with a step pattern at the tail
                // of its body lines.
                let mut for_step: Option<String> = None;
                let mut latch_for_skip: Option<usize> = None;
                if back_edges.len() == 1 {
                    let l = back_edges[0];
                    if l != h
                        && matches!(ctx.blocks[l].terminator, "fall" | "jmp")
                        && ctx.succ[l].first().copied() == Some(h)
                    {
                        if let Some(step) = detect_step_text(&ctx.body_lines[l]) {
                            for_step = Some(step);
                            latch_for_skip = Some(l);
                        }
                    }
                }

                if let (Some(step), Some(latch)) = (for_step, latch_for_skip) {
                    ctx.out.push(format!(
                        "{}for (; {}; {}) {{",
                        pad(ctx.indent),
                        cond_for_loop,
                        step
                    ));
                    ctx.indent += 1;
                    for line in &ctx.body_lines[h] {
                        ctx.out.push(format!("{}{}", pad(ctx.indent), line));
                    }
                    // Emit body up to (but not including) the latch — we
                    // pre-mark latch as visited so the walker stops there
                    // and falls back to the loop header via continue.
                    ctx.visited[latch] = true;
                    emit_node(ctx, inside, Some(h));
                    ctx.indent -= 1;
                    ctx.out.push(format!("{}}}", pad(ctx.indent)));
                    ctx.loop_stack.pop();
                    emit_node(ctx, outside, until);
                    return;
                }

                ctx.out
                    .push(format!("{}while ({}) {{", pad(ctx.indent), cond_for_loop));
                ctx.indent += 1;
                for line in &ctx.body_lines[h] {
                    ctx.out.push(format!("{}{}", pad(ctx.indent), line));
                }
                emit_node(ctx, inside, Some(h));
                ctx.indent -= 1;
                ctx.out.push(format!("{}}}", pad(ctx.indent)));
                ctx.loop_stack.pop();
                emit_node(ctx, outside, until);
                let _ = exit;
                return;
            }
        }
    }

    // ----- Bottom-test loop (do-while): header is not the cjmp, but the
    // unique back-edge source `T` is a cjmp inside the body whose two arms
    // split into "back to header" (continue) and "outside body" (exit).
    if block_term != "cjmp" && back_edges.len() == 1 {
        let t = back_edges[0];
        if t != h && ctx.blocks[t].terminator == "cjmp" {
            let (tt, tf) = cjmp_arms(ctx, t);
            if let (Some(tt), Some(tf)) = (tt, tf) {
                let tt_back = tt == h;
                let tf_back = tf == h;
                let tt_out = !body_set.contains(&tt);
                let tf_out = !body_set.contains(&tf);
                // Exactly one arm goes back to header, the other leaves body.
                let do_while_cond: Option<String> = if tt_back && tf_out {
                    Some(ctx.conds[t].clone().unwrap_or_else(|| "/*?*/".into()))
                } else if tf_back && tt_out {
                    let c = ctx.conds[t].clone().unwrap_or_else(|| "/*?*/".into());
                    Some(negate_cond(&c))
                } else {
                    None
                };
                if let Some(cond_for_loop) = do_while_cond {
                    let outside = if tt_back && tf_out { tf } else { tt };
                    ctx.out.push(format!("{}do {{", pad(ctx.indent)));
                    ctx.indent += 1;
                    // Emit the header's body & terminator; the cjmp at T will
                    // be encountered as the loop's natural tail. We stop walking
                    // at T by pre-emitting its body lines and pretending its
                    // terminator was consumed by the do-while condition.
                    // Mark T as visited *after* we manually flush its body.
                    // To keep emission flow simple, we walk normally up to T
                    // and replace T with a sentinel: we mark T visited and
                    // emit T's body lines + a `continue;`/break-equivalent.
                    // Strategy: walk h normally; when emit_node hits T, we
                    // intercept by pre-marking T.visited=true and emitting
                    // T's body lines manually here.
                    //
                    // Implementation: we emit header normally (it's not cjmp),
                    // then let emit_node walk down. When it reaches T, since
                    // visited[T]=false initially, we can't intercept easily.
                    // Cleaner: we manually drive emission until T.
                    emit_do_while_body(ctx, h, t);
                    // Append T's lifted (non-terminator) body lines.
                    for line in &ctx.body_lines[t] {
                        ctx.out.push(format!("{}{}", pad(ctx.indent), line));
                    }
                    ctx.indent -= 1;
                    ctx.out
                        .push(format!("{}}} while ({});", pad(ctx.indent), cond_for_loop));
                    ctx.loop_stack.pop();
                    // The arm leaving body is the natural successor.
                    emit_node(ctx, outside, until);
                    return;
                }
            }
        }
    }

    // ----- Generic infinite loop with break; fallback ------------------------
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

/// Drive emission for a do-while body: walk from `h` toward `tail`, treating
/// `tail` as a sentinel (we mark it visited so emit_node will not re-enter,
/// and any path landing on it short-circuits to `goto block_tail` which the
/// caller suppresses by following up with the do-while condition.)
///
/// In practice, the natural CFG for a single-tail bottom-test loop is a chain
/// h → ... → tail with no other entries to tail except through that chain,
/// so we emit normally with `until = Some(tail)` to terminate cleanly there.
fn emit_do_while_body(ctx: &mut Ctx, h: usize, tail: usize) {
    // Mark tail as visited so any straggling edge degrades to `goto block_tail`
    // (very rare for clean do-while shapes). Then drive emission up to tail.
    ctx.visited[tail] = true;
    emit_block_body_and_terminator(ctx, h, Some(tail));
    // Unmark so subsequent passes (none, in practice) can still refer to it.
    // Leaving it marked is also fine because we've already laid down its body.
}

/// Detect a counter step (`x++`, `x--`, `x += k`, `x -= k`, `x = x + k`, etc.)
/// at the tail of a block's lifted body. Returns the loop-step expression
/// (without trailing `;`) or `None`.
fn detect_step_text(body_lines: &[String]) -> Option<String> {
    // Walk backwards over the last few non-empty, non-comment lines.
    for line in body_lines.iter().rev().take(3) {
        let trimmed = line.trim().trim_end_matches(';').trim().to_string();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        // Patterns: `x++`, `x--`, `++x`, `--x`, `x += N`, `x -= N`,
        // `x = x + N`, `x = x - N` (integer step on a single LHS variable).
        let bytes = trimmed.as_bytes();
        let looks_like_step = trimmed.ends_with("++")
            || trimmed.ends_with("--")
            || trimmed.starts_with("++")
            || trimmed.starts_with("--")
            || trimmed.contains(" += ")
            || trimmed.contains(" -= ")
            || (trimmed.contains(" = ") && (trimmed.contains(" + ") || trimmed.contains(" - ")));
        if looks_like_step && !trimmed.contains('(') && bytes.len() < 96 {
            return Some(trimmed);
        }
        // First non-empty line that didn't match → bail; we don't search past it.
        return None;
    }
    None
}

fn negate_cond(c: &str) -> String {
    let trimmed = c.trim();
    // Cheap structural negation for patterns produced by `condition_for`.
    for (op, neg) in [
        (" == ", " != "),
        (" != ", " == "),
        (" >= ", " < "),
        (" <= ", " > "),
        (" > ", " <= "),
        (" < ", " >= "),
    ] {
        if trimmed.contains(op) {
            return trimmed.replacen(op, neg, 1);
        }
    }
    format!("!({trimmed})")
}

// ---------- dominators ------------------------------------------------------

fn dominators_fwd(n: usize, pred: &[Vec<usize>]) -> Vec<BTreeSet<usize>> {
    let all: BTreeSet<usize> = (0..n).collect();
    let mut dom = vec![all.clone(); n];
    dom[0] = BTreeSet::from([0]);
    let mut changed = true;
    while changed {
        changed = false;
        for i in 1..n {
            if pred[i].is_empty() {
                continue;
            }
            let mut acc: Option<BTreeSet<usize>> = None;
            for &p in &pred[i] {
                acc = Some(match acc {
                    None => dom[p].clone(),
                    Some(s) => s.intersection(&dom[p]).copied().collect(),
                });
            }
            let mut new = acc.unwrap_or_default();
            new.insert(i);
            if new != dom[i] {
                dom[i] = new;
                changed = true;
            }
        }
    }
    dom
}

fn dominators_rev(n: usize, succ: &[Vec<usize>], func: &IrFunction) -> Vec<BTreeSet<usize>> {
    // Reverse CFG with synthetic exit at index n.
    let exit = n;
    let total = n + 1;
    let mut rsucc: Vec<Vec<usize>> = vec![Vec::new(); total];
    let mut rpred: Vec<Vec<usize>> = vec![Vec::new(); total];
    for i in 0..n {
        let term = func.blocks[i].terminator;
        let is_exit = succ[i].is_empty()
            || term == "ret"
            || term == "tail-call"
            || term == "tail-import"
            || term == "int";
        if is_exit {
            rsucc[exit].push(i);
            rpred[i].push(exit);
        }
        for &s in &succ[i] {
            rsucc[s].push(i);
            rpred[i].push(s);
        }
    }
    let all: BTreeSet<usize> = (0..total).collect();
    let mut dom = vec![all.clone(); total];
    dom[exit] = BTreeSet::from([exit]);
    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..n {
            if rpred[i].is_empty() {
                continue;
            }
            let mut acc: Option<BTreeSet<usize>> = None;
            for &p in &rpred[i] {
                acc = Some(match acc {
                    None => dom[p].clone(),
                    Some(s) => s.intersection(&dom[p]).copied().collect(),
                });
            }
            let mut new = acc.unwrap_or_default();
            new.insert(i);
            if new != dom[i] {
                dom[i] = new;
                changed = true;
            }
        }
    }
    dom.into_iter()
        .take(n)
        .map(|mut s| {
            s.remove(&exit);
            s
        })
        .collect()
}

fn immediate_doms(dom: &[BTreeSet<usize>]) -> Vec<Option<usize>> {
    let n = dom.len();
    let mut out = vec![None; n];
    for i in 0..n {
        let candidates: Vec<usize> = dom[i].iter().copied().filter(|&j| j != i).collect();
        // idom = the unique candidate that is dominated by every other candidate.
        for &c in &candidates {
            let is_idom = candidates
                .iter()
                .all(|&d| d == c || dom[c].contains(&d));
            if is_idom {
                out[i] = Some(c);
                break;
            }
        }
    }
    out
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
            if !body.contains(&p) {
                body.insert(p);
                if p != header {
                    stack.push(p);
                }
            }
        }
    }
    body
}

// ---------- per-block instruction lifting (no goto on terminator branch) ----

fn lift_blocks_for_structured(
    start_ip: u64,
    bytes: &[u8],
    func: &IrFunction,
    symbols: Option<&SymbolMap>,
    iat: Option<&SymbolMap>,
) -> (
    Vec<Vec<String>>,
    Vec<Option<String>>,
    BTreeMap<u64, PseudoLocal>,
    usize,
    usize,
) {
    let n = func.blocks.len();
    let mut body_lines: Vec<Vec<String>> = vec![Vec::new(); n];
    let mut conds: Vec<Option<String>> = vec![None; n];
    let mut locals: BTreeMap<u64, PseudoLocal> = BTreeMap::new();

    // Map each address → block index.
    let mut block_idx_by_addr: HashMap<u64, usize> = HashMap::new();
    for (i, b) in func.blocks.iter().enumerate() {
        block_idx_by_addr.insert(parse_hex(&b.address), i);
    }
    // For lift_instruction's target lookup we need block.id by ip.
    let mut block_id_by_ip: BTreeMap<u64, usize> = BTreeMap::new();
    for b in &func.blocks {
        block_id_by_ip.insert(parse_hex(&b.address), b.id);
    }
    let mut callsite_by_ip: BTreeMap<u64, &IrCallsite> = BTreeMap::new();
    for cs in &func.callsites {
        callsite_by_ip.insert(parse_hex(&cs.from), cs);
    }

    let mut decoder = Decoder::with_ip(64, bytes, start_ip, DecoderOptions::NONE);
    let end_ip = parse_hex(&func.end_address);

    let mut last_compare: Option<Compare> = None;
    let mut current: usize = 0;
    let mut total = 0usize;
    let mut converted = 0usize;

    while decoder.can_decode() && decoder.ip() < end_ip {
        let ins = decoder.decode();
        if ins.is_invalid() {
            break;
        }
        // Update current block.
        if let Some(&idx) = block_idx_by_addr.get(&ins.ip()) {
            current = idx;
        }
        total += 1;

        // Is this the terminating branch instruction of `current`?
        let block_end = parse_hex(&func.blocks[current].end_address);
        let is_terminator = ins.next_ip() == block_end;
        let mn = ins.mnemonic();
        let term = func.blocks[current].terminator;

        if is_terminator {
            // For cjmp blocks: capture condition, do NOT emit a goto line.
            if term == "cjmp" && is_jcc(mn) {
                let cond = condition_for(mn, last_compare.as_ref());
                conds[current] = Some(cond);
                converted += 1;
                continue;
            }
            // Plain `jmp` and `fall`: skip — structured emitter follows the edge.
            if term == "jmp" && mn == Mnemonic::Jmp && ins.near_branch_target() != 0 {
                converted += 1;
                continue;
            }
            // Tail variants and ret are emitted via lift_instruction (it
            // already produces `return name(...);` / `return rax;`), so let
            // them pass through.
        }

        let lifted = lift_instruction(
            &ins,
            &block_id_by_ip,
            &callsite_by_ip,
            symbols,
            iat,
            &mut last_compare,
            &mut locals,
        );
        if !lifted.unhandled {
            converted += 1;
        }
        body_lines[current].extend(lifted.lines);
    }

    // Decorate each block's body with a leading comment that anchors it back
    // to the original IR address for grep-ability.
    for (i, b) in func.blocks.iter().enumerate() {
        let header = format!("// block_{}: {}", b.id, b.address);
        let mut new_body = vec![header];
        new_body.append(&mut body_lines[i]);
        body_lines[i] = new_body;
    }

    (body_lines, conds, locals, total, converted)
}

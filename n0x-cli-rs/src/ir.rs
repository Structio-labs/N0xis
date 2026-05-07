use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, InstructionInfoFactory,
    Mnemonic, NasmFormatter, OpAccess, OpKind, Register,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const SCHEMA: &str = "n0x.ir.v1";
pub const SCHEMA_CFG: &str = "n0x.ir.cfg.v1";
pub const SCHEMA_MANIFEST: &str = "n0x.ir.manifest.v1";
pub const SCHEMA_SLICE: &str = "n0x.ir.slice.v1";
pub const SCHEMA_DOT: &str = "n0x.ir.dot.v1";
#[allow(dead_code)]
pub const SCHEMA_EXPLAIN: &str = "n0x.ir.explain.v1";

pub type SymbolMap = BTreeMap<u64, String>;

const ARG_REGS: [&str; 4] = ["rcx", "rdx", "r8", "r9"];
const VOLATILE_REGS: [&str; 7] = ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"];

#[derive(Serialize)]
pub struct IrFunction {
    pub schema: &'static str,
    pub address: String,
    pub end_address: String,
    pub instruction_count: usize,
    pub block_count: usize,
    pub blocks: Vec<IrBlock>,
    pub callsites: Vec<IrCallsite>,
    pub returns: usize,
    pub indirect_branches: usize,
    pub tail_calls: usize,
    pub frame: IrFrameSummary,
    /// Detected switch / jump-table dispatches. Best-effort: contains the
    /// pieces we can recover from the instruction stream (table base, index
    /// register, scale, bound from a preceding `cmp idx, imm`). Resolution
    /// of actual case targets requires reading the table from process memory
    /// and is performed by a higher layer.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub switches: Vec<IrSwitch>,
}

#[derive(Serialize)]
pub struct IrSwitch {
    /// Address of the dispatching `jmp` instruction.
    pub at: String,
    /// "mem-indexed" — `jmp [rip+disp+idx*scale]` (table holds absolute pointers).
    /// "reg-rel32"  — MSVC `lea base,[rip+disp]; movsxd r,[base+idx*4]; add r,base; jmp r`.
    pub kind: &'static str,
    /// Resolved table base address when computable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    /// Index register feeding the table.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_reg: Option<String>,
    /// Scale of the index (1 / 4 / 8).
    pub scale: u32,
    /// Upper bound (exclusive) recovered from a nearby `cmp idx, imm` /
    /// `sub idx, imm` bound check, when found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound: Option<u64>,
    /// Resolved case-target absolute addresses, in the order they appear in
    /// the dispatch table. Populated by a memory-side resolver layer that
    /// reads the table from process memory; empty when unresolved.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cases: Vec<String>,
}

#[derive(Serialize, Default)]
pub struct IrFrameSummary {
    pub frame_size: u64,
    pub uses_rbp: bool,
    pub spilled_regs: Vec<String>,
    pub prolog: Vec<String>,
}

#[derive(Serialize)]
pub struct IrBlock {
    pub id: usize,
    pub address: String,
    pub end_address: String,
    pub terminator: &'static str,
    pub successors: Vec<IrSuccessor>,
    pub instructions: Vec<IrInstr>,
}

#[derive(Serialize)]
pub struct IrSuccessor {
    pub to: String,
    pub kind: &'static str,
    /// 0.0..=1.0 confidence that this edge is semantically correct.
    /// Heuristic only; intended for triage/ranking by agents.
    pub confidence: f32,
    /// Index within an enclosing switch dispatch table, when `kind == "switch"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_index: Option<usize>,
}

#[derive(Serialize)]
pub struct IrInstr {
    pub address: String,
    pub len: usize,
    pub text: String,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_name: Option<String>,
    pub reads_regs: Vec<String>,
    pub writes_regs: Vec<String>,
    pub reads_mem: Vec<IrMemAccess>,
    pub writes_mem: Vec<IrMemAccess>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub def_use: Vec<DefUseEntry>,
}

#[derive(Serialize, Clone)]
pub struct DefUseEntry {
    pub reg: String,
    pub def_index: usize,
    pub def_addr: String,
    /// Last known immediate constant assigned to `reg` at the def site,
    /// when discoverable by the lite tracker (`mov reg, imm`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub const_val: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct IrMemAccess {
    pub base: Option<String>,
    pub index: Option<String>,
    pub scale: u32,
    pub displacement: String,
}

#[derive(Serialize)]
pub struct IrCallsite {
    pub from: String,
    pub kind: &'static str,
    pub target: Option<String>,
    pub target_name: Option<String>,
    pub instruction: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub arg_hints: Vec<ArgHint>,
}

#[derive(Serialize)]
pub struct ArgHint {
    pub reg: String,
    pub def_addr: Option<String>,
    pub def_text: Option<String>,
    /// Best-effort immediate constant currently held in `reg` at this
    /// callsite (resolved by the per-block constant tracker).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub const_val: Option<String>,
}

#[derive(Default, Clone, Copy)]
pub struct BuildOptions<'a> {
    pub auto_end: bool,
    /// Absolute address -> "module!symbol" for direct call/jmp resolution.
    /// Should span all loaded modules so cross-module direct calls resolve.
    pub symbols: Option<&'a SymbolMap>,
    /// Owner-module IAT slot address -> "DLL!Name" for resolving
    /// `call [rip+disp]` / `jmp [rip+disp]` through the import table.
    pub iat: Option<&'a SymbolMap>,
}

pub fn build_function_ir(start_ip: u64, bytes: &[u8], opts: BuildOptions) -> IrFunction {
    let (instrs, texts) = decode_linear(start_ip, bytes, opts.auto_end);
    let end_ip = instrs.last().map(|i| i.next_ip()).unwrap_or(start_ip);

    let valid_ips: BTreeSet<u64> = instrs.iter().map(|i| i.ip()).collect();
    let leaders = compute_leaders(&instrs, &valid_ips);

    let mut block_id_by_ip: BTreeMap<u64, usize> = BTreeMap::new();
    for (i, ip) in leaders.iter().enumerate() {
        block_id_by_ip.insert(*ip, i);
    }

    let mut info_factory = InstructionInfoFactory::new();
    let mut blocks: Vec<IrBlock> = Vec::new();
    let mut callsites: Vec<IrCallsite> = Vec::new();
    let mut switches: Vec<IrSwitch> = Vec::new();
    let mut returns = 0usize;
    let mut indirect_branches = 0usize;
    let mut tail_calls = 0usize;

    let mut i = 0usize;
    while i < instrs.len() {
        let block_start_index = i;
        let block_start_ip = instrs[i].ip();
        let block_id = *block_id_by_ip.get(&block_start_ip).unwrap_or(&blocks.len());
        let mut ir_instrs: Vec<IrInstr> = Vec::new();
        let mut terminator: &'static str = "fall";
        let mut successors: Vec<IrSuccessor> = Vec::new();
        let mut block_end_ip;
        let mut last_def: HashMap<String, (usize, u64)> = HashMap::new();
        let mut consts: HashMap<String, String> = HashMap::new();

        loop {
            let ins = &instrs[i];
            block_end_ip = ins.next_ip();
            let info = info_factory.info(ins);

            let (reads_regs, writes_regs) = collect_reg_access(info);
            let (reads_mem, writes_mem) = collect_mem_access(info);

            let mut def_use_entries: Vec<DefUseEntry> = Vec::new();
            for r in &reads_regs {
                if let Some((idx, addr)) = last_def.get(r) {
                    def_use_entries.push(DefUseEntry {
                        reg: r.clone(),
                        def_index: *idx,
                        def_addr: format!("0x{:X}", addr),
                        const_val: consts.get(r).cloned(),
                    });
                }
            }

            let target_addr = ins.near_branch_target();
            let mut target_str = if target_addr != 0 {
                Some(format!("0x{target_addr:X}"))
            } else {
                None
            };

            let mut kind = ins_kind(ins.flow_control());
            let mut target_name: Option<String> = None;
            if matches!(ins.flow_control(), FlowControl::Call) {
                target_name = opts.symbols.and_then(|m| m.get(&target_addr).cloned());
            }

            let is_tail_call = matches!(ins.flow_control(), FlowControl::UnconditionalBranch)
                && (target_addr == 0 || target_addr < start_ip || target_addr >= end_ip);
            if is_tail_call {
                kind = "tail-call";
                target_name = opts.symbols.and_then(|m| m.get(&target_addr).cloned());
            }

            // IAT resolution for `call [rip+disp]` / `jmp [rip+disp]` (and
            // memory-operand variants of indirect branches). Computes the IAT
            // slot address and looks it up in the per-owner-module IAT map.
            let mut iat_slot: Option<u64> = None;
            if matches!(
                ins.flow_control(),
                FlowControl::IndirectCall | FlowControl::IndirectBranch
            ) && ins.is_ip_rel_memory_operand()
            {
                let slot = ins.ip_rel_memory_address();
                iat_slot = Some(slot);
                if target_name.is_none() {
                    if let Some(name) = opts.iat.and_then(|m| m.get(&slot).cloned()) {
                        target_name = Some(name);
                        target_str = Some(format!("0x{slot:X}"));
                        if matches!(ins.flow_control(), FlowControl::IndirectBranch) {
                            kind = "tail-import";
                        }
                    }
                }
            }

            let cur_index_in_block = ir_instrs.len();
            ir_instrs.push(IrInstr {
                address: format!("0x{:X}", ins.ip()),
                len: ins.len(),
                text: texts[i].clone(),
                kind,
                target: target_str.clone(),
                target_name: target_name.clone(),
                reads_regs: reads_regs.clone(),
                writes_regs: writes_regs.clone(),
                reads_mem,
                writes_mem,
                def_use: def_use_entries,
            });

            for w in &writes_regs {
                last_def.insert(w.clone(), (cur_index_in_block, ins.ip()));
            }

            // Maintain per-block immediate-constant tracker: any write
            // invalidates a prior known constant; an immediate-defining
            // instruction reseeds it.
            let new_const = const_def(ins);
            for w in &writes_regs {
                consts.remove(w);
            }
            if let Some((reg, val)) = new_const {
                consts.insert(reg, val);
            }

            match ins.flow_control() {
                FlowControl::Return => {
                    returns += 1;
                    terminator = "ret";
                    i += 1;
                    break;
                }
                FlowControl::Interrupt => {
                    terminator = "int";
                    i += 1;
                    break;
                }
                FlowControl::UnconditionalBranch => {
                    if is_tail_call {
                        tail_calls += 1;
                        terminator = "tail-call";
                        callsites.push(IrCallsite {
                            from: format!("0x{:X}", ins.ip()),
                            kind: "tail",
                            target: target_str.clone(),
                            target_name,
                            instruction: texts[i].clone(),
                            arg_hints: snapshot_args(&last_def, &consts, &ir_instrs),
                        });
                    } else {
                        terminator = "jmp";
                        if let Some(t) = target_str.clone() {
                            successors.push(IrSuccessor {
                                to: t,
                                kind: "jmp",
                                confidence: edge_confidence("jmp", None),
                                case_index: None,
                            });
                        }
                    }
                    i += 1;
                    break;
                }
                FlowControl::IndirectBranch => {
                    indirect_branches += 1;
                    terminator = "ijmp";
                    if target_name.is_some() {
                        // Tail jump through IAT (PLT-style import thunk).
                        terminator = "tail-import";
                        tail_calls += 1;
                        callsites.push(IrCallsite {
                            from: format!("0x{:X}", ins.ip()),
                            kind: "tail-import",
                            target: target_str.clone(),
                            target_name: target_name.clone(),
                            instruction: texts[i].clone(),
                            arg_hints: snapshot_args(&last_def, &consts, &ir_instrs),
                        });
                    } else if let Some(sw) = detect_switch(&instrs, block_start_index, i) {
                        switches.push(sw);
                    }
                    let _ = iat_slot;
                    i += 1;
                    break;
                }
                FlowControl::ConditionalBranch => {
                    terminator = "cjmp";
                    if let Some(t) = target_str.clone() {
                        successors.push(IrSuccessor {
                            to: t,
                            kind: "cjmp-true",
                            confidence: edge_confidence("cjmp-true", None),
                            case_index: None,
                        });
                    }
                    let next = ins.next_ip();
                    successors.push(IrSuccessor {
                        to: format!("0x{next:X}"),
                        kind: "cjmp-false",
                        confidence: edge_confidence("cjmp-false", None),
                        case_index: None,
                    });
                    i += 1;
                    break;
                }
                FlowControl::Call => {
                    let arg_hints = snapshot_args(&last_def, &consts, &ir_instrs);
                    callsites.push(IrCallsite {
                        from: format!("0x{:X}", ins.ip()),
                        kind: "direct",
                        target: target_str.clone(),
                        target_name,
                        instruction: texts[i].clone(),
                        arg_hints,
                    });
                    invalidate_volatile(&mut last_def);
                    invalidate_volatile_consts(&mut consts);
                }
                FlowControl::IndirectCall => {
                    let arg_hints = snapshot_args(&last_def, &consts, &ir_instrs);
                    let cs_kind: &'static str = if target_name.is_some() {
                        "import"
                    } else {
                        "indirect"
                    };
                    callsites.push(IrCallsite {
                        from: format!("0x{:X}", ins.ip()),
                        kind: cs_kind,
                        target: target_str.clone(),
                        target_name: target_name.clone(),
                        instruction: texts[i].clone(),
                        arg_hints,
                    });
                    invalidate_volatile(&mut last_def);
                    invalidate_volatile_consts(&mut consts);
                }
                _ => {}
            }

            i += 1;
            if i >= instrs.len() {
                break;
            }
            let next_ip = instrs[i].ip();
            if leaders.contains(&next_ip) {
                terminator = "fall";
                successors.push(IrSuccessor {
                    to: format!("0x{next_ip:X}"),
                    kind: "fall",
                    confidence: edge_confidence("fall", None),
                    case_index: None,
                });
                break;
            }
        }

        blocks.push(IrBlock {
            id: block_id,
            address: format!("0x{block_start_ip:X}"),
            end_address: format!("0x{block_end_ip:X}"),
            terminator,
            successors,
            instructions: ir_instrs,
        });
    }

    let frame = analyze_frame(&instrs, &texts);

    IrFunction {
        schema: SCHEMA,
        address: format!("0x{start_ip:X}"),
        end_address: format!("0x{end_ip:X}"),
        instruction_count: instrs.len(),
        block_count: blocks.len(),
        blocks,
        callsites,
        returns,
        indirect_branches,
        tail_calls,
        frame,
        switches,
    }
}

pub fn explain(func: &IrFunction) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "Function {} .. {} ({} instructions in {} blocks)",
        func.address, func.end_address, func.instruction_count, func.block_count
    ));
    lines.push(format!(
        "Returns: {}, IndirectBranches: {}, TailCalls: {}, Callsites: {}",
        func.returns,
        func.indirect_branches,
        func.tail_calls,
        func.callsites.len()
    ));
    lines.push(format!(
        "Frame: size=0x{:X}, uses_rbp={}, spilled={}",
        func.frame.frame_size,
        func.frame.uses_rbp,
        func.frame.spilled_regs.join(",")
    ));

    let block_ips: BTreeSet<u64> = func.blocks.iter().map(|b| parse_hex(&b.address)).collect();
    let mut back_edges = 0usize;
    for b in &func.blocks {
        let from_ip = parse_hex(&b.address);
        for s in &b.successors {
            let to_ip = parse_hex(&s.to);
            if to_ip <= from_ip && block_ips.contains(&to_ip) {
                back_edges += 1;
            }
        }
    }
    lines.push(format!("Back-edges (loops): {back_edges}"));

    if !func.callsites.is_empty() {
        lines.push("Calls:".to_string());
        for cs in func.callsites.iter().take(20) {
            let name = cs
                .target_name
                .clone()
                .or_else(|| cs.target.clone())
                .unwrap_or_else(|| "(indirect)".to_string());
            let mut argstr = String::new();
            for h in &cs.arg_hints {
                let val = h
                    .const_val
                    .as_deref()
                    .or(h.def_text.as_deref())
                    .unwrap_or("?");
                argstr.push_str(&format!(" {}={}", h.reg, val));
            }
            lines.push(format!("  {} {} -> {}{}", cs.from, cs.kind, name, argstr));
        }
    }

    if !func.switches.is_empty() {
        lines.push(format!("Switches: {}", func.switches.len()));
        for sw in func.switches.iter().take(8) {
            let table = sw.table.as_deref().unwrap_or("?");
            let idx = sw.index_reg.as_deref().unwrap_or("?");
            let bound = sw
                .bound
                .map(|b| format!("0x{b:X}"))
                .unwrap_or_else(|| "?".to_string());
            lines.push(format!(
                "  {} {} table={} idx={} scale={} bound={}",
                sw.at, sw.kind, table, idx, sw.scale, bound
            ));
        }
    }
    lines
}

#[derive(Serialize)]
pub struct IrCfg {
    pub schema: &'static str,
    pub address: String,
    pub end_address: String,
    pub block_count: usize,
    pub blocks: Vec<IrCfgBlock>,
}

#[derive(Serialize)]
pub struct IrCfgBlock {
    pub id: usize,
    pub address: String,
    pub end_address: String,
    pub terminator: String,
    pub successors: Vec<IrSuccessor>,
    pub instruction_count: usize,
}

pub fn cfg(func: &IrFunction) -> IrCfg {
    IrCfg {
        schema: SCHEMA_CFG,
        address: func.address.clone(),
        end_address: func.end_address.clone(),
        block_count: func.block_count,
        blocks: func
            .blocks
            .iter()
            .map(|b| IrCfgBlock {
                id: b.id,
                address: b.address.clone(),
                end_address: b.end_address.clone(),
                terminator: b.terminator.to_string(),
                successors: b
                    .successors
                    .iter()
                    .map(|s| IrSuccessor {
                        to: s.to.clone(),
                        kind: s.kind,
                        confidence: s.confidence,
                        case_index: s.case_index,
                    })
                    .collect(),
                instruction_count: b.instructions.len(),
            })
            .collect(),
    }
}

#[derive(Serialize)]
pub struct IrDot {
    pub schema: &'static str,
    pub address: String,
    pub end_address: String,
    pub block_count: usize,
    pub edge_count: usize,
    pub dot: String,
}

pub fn dot(func: &IrFunction) -> IrDot {
    let mut out = String::new();
    out.push_str("digraph n0x_cfg {\n");
    out.push_str("  rankdir=TB;\n");
    out.push_str("  node [shape=box, fontname=\"Consolas\", fontsize=10];\n");
    out.push_str("  edge [fontname=\"Consolas\", fontsize=9];\n");

    for b in &func.blocks {
        let label = format!(
            "B{}\\n{}\\n{}\\nins={}",
            b.id,
            b.address,
            b.terminator,
            b.instructions.len()
        );
        out.push_str(&format!("  b{} [label=\"{}\"];\n", b.id, escape_dot(&label)));
    }

    let mut edge_count = 0usize;
    for b in &func.blocks {
        for s in &b.successors {
            if let Some(to_id) = func
                .blocks
                .iter()
                .find(|bb| bb.address.eq_ignore_ascii_case(&s.to))
                .map(|bb| bb.id)
            {
                let mut edge_label = s.kind.to_string();
                if let Some(ci) = s.case_index {
                    edge_label.push_str(&format!(" #{}", ci));
                }
                edge_label.push_str(&format!(" (q={:.2})", s.confidence));
                out.push_str(&format!(
                    "  b{} -> b{} [label=\"{}\"];\n",
                    b.id,
                    to_id,
                    escape_dot(&edge_label)
                ));
                edge_count += 1;
            }
        }
    }

    out.push_str("}\n");
    IrDot {
        schema: SCHEMA_DOT,
        address: func.address.clone(),
        end_address: func.end_address.clone(),
        block_count: func.block_count,
        edge_count,
        dot: out,
    }
}

fn escape_dot(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\"', "\\\"")
}

fn edge_confidence(kind: &str, case_index: Option<usize>) -> f32 {
    match kind {
        "fall" => 0.99,
        "jmp" => 0.98,
        "cjmp-true" | "cjmp-false" => 0.95,
        "switch" => {
            if case_index.is_some() {
                0.85
            } else {
                0.75
            }
        }
        _ => 0.80,
    }
}

#[derive(Serialize)]
pub struct IrSlice {
    pub schema: &'static str,
    pub address: String,
    pub reg: String,
    pub seed: Option<String>,
    pub node_count: usize,
    pub edge_count: usize,
    pub roots: Vec<String>,
    pub nodes: Vec<IrSliceNode>,
}

#[derive(Serialize)]
pub struct IrSliceNode {
    pub address: String,
    pub text: String,
    pub reads_regs: Vec<String>,
    pub writes_regs: Vec<String>,
    pub deps: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub const_inputs: Vec<String>,
}

/// Backward register slice over a single recovered function.
///
/// The seed selection is practical, not perfect SSA:
/// - Prefer the instruction at `addr` if it writes `reg`.
/// - Otherwise, walk backward to find the closest writer of `reg`.
/// Dependencies are taken from each instruction's `def_use` entries.
pub fn slice(func: &IrFunction, addr: u64, reg: &str) -> IrSlice {
    let reg = normalize_reg(reg);
    let mut flat: Vec<&IrInstr> = Vec::new();
    for b in &func.blocks {
        for i in &b.instructions {
            flat.push(i);
        }
    }
    let mut idx_by_addr: HashMap<u64, usize> = HashMap::new();
    for (idx, ins) in flat.iter().enumerate() {
        idx_by_addr.insert(parse_hex(&ins.address), idx);
    }

    let seed = find_seed(&flat, &idx_by_addr, addr, &reg);
    let mut used: BTreeSet<usize> = BTreeSet::new();
    let mut stack: Vec<usize> = Vec::new();
    if let Some(s) = seed {
        stack.push(s);
    }

    while let Some(cur) = stack.pop() {
        if !used.insert(cur) {
            continue;
        }
        let ins = flat[cur];
        for d in &ins.def_use {
            let a = parse_hex(&d.def_addr);
            if let Some(dep_idx) = idx_by_addr.get(&a).copied() {
                stack.push(dep_idx);
            }
        }
    }

    let mut nodes: Vec<IrSliceNode> = Vec::new();
    let mut roots: Vec<String> = Vec::new();
    let mut edge_count = 0usize;

    for idx in &used {
        let ins = flat[*idx];
        let mut deps: Vec<String> = Vec::new();
        let mut const_inputs: Vec<String> = Vec::new();
        for d in &ins.def_use {
            let a = parse_hex(&d.def_addr);
            if let Some(dep_idx) = idx_by_addr.get(&a).copied() {
                if used.contains(&dep_idx) {
                    deps.push(format!("0x{:X}", a));
                } else if let Some(c) = &d.const_val {
                    const_inputs.push(format!("{}={}", d.reg, c));
                }
            } else if let Some(c) = &d.const_val {
                const_inputs.push(format!("{}={}", d.reg, c));
            }
        }
        deps.sort();
        deps.dedup();
        edge_count += deps.len();
        if deps.is_empty() {
            roots.push(ins.address.clone());
        }
        nodes.push(IrSliceNode {
            address: ins.address.clone(),
            text: ins.text.clone(),
            reads_regs: ins.reads_regs.clone(),
            writes_regs: ins.writes_regs.clone(),
            deps,
            const_inputs,
        });
    }

    nodes.sort_by_key(|n| parse_hex(&n.address));
    roots.sort();
    roots.dedup();

    IrSlice {
        schema: SCHEMA_SLICE,
        address: format!("0x{:X}", addr),
        reg,
        seed: seed.map(|i| flat[i].address.clone()),
        node_count: nodes.len(),
        edge_count,
        roots,
        nodes,
    }
}

fn find_seed(flat: &[&IrInstr], idx_by_addr: &HashMap<u64, usize>, addr: u64, reg: &str) -> Option<usize> {
    if let Some(&idx) = idx_by_addr.get(&addr) {
        if flat[idx]
            .writes_regs
            .iter()
            .any(|r| reg_eq(r, reg))
        {
            return Some(idx);
        }
    }
    // Nearest previous writer.
    let mut best: Option<(u64, usize)> = None;
    for (idx, ins) in flat.iter().enumerate() {
        let a = parse_hex(&ins.address);
        if a > addr {
            continue;
        }
        if ins.writes_regs.iter().any(|r| reg_eq(r, reg)) {
            match best {
                None => best = Some((a, idx)),
                Some((cur, _)) if a > cur => best = Some((a, idx)),
                _ => {}
            }
        }
    }
    best.map(|(_, idx)| idx)
}

fn reg_eq(a: &str, b: &str) -> bool {
    normalize_reg(a) == normalize_reg(b)
}

fn normalize_reg(reg: &str) -> String {
    let r = reg.trim().to_ascii_lowercase();
    match r.as_str() {
        "rax" | "eax" | "ax" | "al" | "ah" => "rax".to_string(),
        "rbx" | "ebx" | "bx" | "bl" | "bh" => "rbx".to_string(),
        "rcx" | "ecx" | "cx" | "cl" | "ch" => "rcx".to_string(),
        "rdx" | "edx" | "dx" | "dl" | "dh" => "rdx".to_string(),
        "rsi" | "esi" | "si" | "sil" => "rsi".to_string(),
        "rdi" | "edi" | "di" | "dil" => "rdi".to_string(),
        "rbp" | "ebp" | "bp" | "bpl" => "rbp".to_string(),
        "rsp" | "esp" | "sp" | "spl" => "rsp".to_string(),
        "rip" | "eip" | "ip" => "rip".to_string(),
        _ => {
            if let Some(n) = r.strip_prefix('r') {
                if n.chars().all(|c| c.is_ascii_digit()) {
                    return format!("r{}", n);
                }
                if n.ends_with('d') || n.ends_with('w') || n.ends_with('b') {
                    let stem = &n[..n.len().saturating_sub(1)];
                    if stem.chars().all(|c| c.is_ascii_digit()) {
                        return format!("r{}", stem);
                    }
                }
            }
            r
        }
    }
}

// ---------------------------------------------------------------------------
// Manifest API: lightweight per-function index with quality scoring.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct IrManifestEntry {
    pub address: String,
    pub name: String,
    /// Where the entry came from: `"export"` (PE export table) or `"discover"`
    /// (heuristic prolog scan).
    pub source: &'static str,
    pub instruction_count: usize,
    pub block_count: usize,
    pub returns: usize,
    pub indirect_branches: usize,
    pub tail_calls: usize,
    pub callsites: usize,
    pub frame_size: u64,
    pub end_address: String,
    /// 0.0..=1.0 confidence that the entry is a real, well-formed function.
    pub quality: f32,
    /// Short categorical flags, e.g. `leaf`, `has-switch`, `stub`, `runaway`.
    pub flags: Vec<&'static str>,
}

/// Score how "real" this recovered function looks. Combines structural
/// signals (prolog, return, multi-block CFG, plausible size) into a rough
/// 0.0..=1.0 confidence.
pub fn quality_score(func: &IrFunction) -> f32 {
    let mut s = 0.0_f32;
    let frame_ok = func.frame.frame_size > 0
        || func.frame.uses_rbp
        || !func.frame.spilled_regs.is_empty();
    if frame_ok {
        s += 0.25;
    }
    if func.returns >= 1 {
        s += 0.25;
    }
    if func.block_count >= 2 {
        s += 0.10;
    }
    if (5..=2000).contains(&func.instruction_count) {
        s += 0.15;
    }
    if !func.callsites.is_empty() {
        s += 0.05;
    }
    let max_indirect = func.block_count.max(1);
    if (func.indirect_branches as usize) <= max_indirect {
        s += 0.10;
    }
    if func.instruction_count > 0 {
        s += 0.05;
    }
    if func.tail_calls > 0 || func.returns > 0 {
        s += 0.05;
    }
    if s > 1.0 { 1.0 } else { s }
}

/// Categorical flags for fast filtering / display in a manifest.
pub fn flags(func: &IrFunction) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    if func.callsites.is_empty() {
        out.push("leaf");
    }
    if !func.switches.is_empty() {
        out.push("has-switch");
    }
    if func
        .callsites
        .iter()
        .any(|c| c.kind == "import" || c.kind == "tail-import")
    {
        out.push("has-import");
    }
    if func.tail_calls > 0 {
        out.push("tail");
    }
    if func.instruction_count < 5 {
        out.push("stub");
    }
    if func.instruction_count > 2000 {
        out.push("runaway");
    }
    let no_frame = func.frame.frame_size == 0
        && !func.frame.uses_rbp
        && func.frame.spilled_regs.is_empty();
    if no_frame {
        out.push("no-frame");
    }
    if func.returns == 0 && func.tail_calls == 0 {
        out.push("no-return");
    }
    out
}

pub fn manifest_entry(
    name: String,
    source: &'static str,
    func: &IrFunction,
) -> IrManifestEntry {
    IrManifestEntry {
        address: func.address.clone(),
        name,
        source,
        instruction_count: func.instruction_count,
        block_count: func.block_count,
        returns: func.returns,
        indirect_branches: func.indirect_branches,
        tail_calls: func.tail_calls,
        callsites: func.callsites.len(),
        frame_size: func.frame.frame_size,
        end_address: func.end_address.clone(),
        quality: quality_score(func),
        flags: flags(func),
    }
}

fn decode_linear(start_ip: u64, bytes: &[u8], auto_end: bool) -> (Vec<Instruction>, Vec<String>) {
    let mut decoder = Decoder::with_ip(64, bytes, start_ip, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut text_buf = String::new();
    let mut instrs: Vec<Instruction> = Vec::new();
    let mut texts: Vec<String> = Vec::new();
    let end_cap = start_ip.saturating_add(bytes.len() as u64);
    let mut max_forward_leader: u64 = start_ip;

    while decoder.can_decode() {
        let ins = decoder.decode();
        if ins.is_invalid() {
            break;
        }
        text_buf.clear();
        formatter.format(&ins, &mut text_buf);
        let next = ins.next_ip();
        let fc = ins.flow_control();
        let tgt = ins.near_branch_target();
        let in_range = tgt != 0 && tgt >= start_ip && tgt < end_cap;
        instrs.push(ins);
        texts.push(text_buf.clone());

        if !auto_end {
            continue;
        }
        match fc {
            FlowControl::ConditionalBranch => {
                if in_range && tgt > max_forward_leader {
                    max_forward_leader = tgt;
                }
            }
            FlowControl::UnconditionalBranch => {
                let tail = !in_range;
                if !tail && tgt > max_forward_leader {
                    max_forward_leader = tgt;
                }
                if tail && next > max_forward_leader {
                    break;
                }
                if !tail && tgt < next && next > max_forward_leader {
                    break;
                }
            }
            FlowControl::IndirectBranch | FlowControl::Return | FlowControl::Interrupt => {
                if next > max_forward_leader {
                    break;
                }
            }
            _ => {}
        }
    }

    (instrs, texts)
}

fn compute_leaders(instrs: &[Instruction], valid_ips: &BTreeSet<u64>) -> BTreeSet<u64> {
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    if let Some(first) = instrs.first() {
        leaders.insert(first.ip());
    }
    for ins in instrs {
        match ins.flow_control() {
            FlowControl::ConditionalBranch
            | FlowControl::UnconditionalBranch
            | FlowControl::IndirectBranch
            | FlowControl::Return
            | FlowControl::Interrupt => {
                let next = ins.next_ip();
                if valid_ips.contains(&next) {
                    leaders.insert(next);
                }
                let tgt = ins.near_branch_target();
                if tgt != 0 && valid_ips.contains(&tgt) {
                    leaders.insert(tgt);
                }
            }
            _ => {}
        }
    }
    leaders
}

fn collect_reg_access(info: &iced_x86::InstructionInfo) -> (Vec<String>, Vec<String>) {
    let mut reads: Vec<String> = Vec::new();
    let mut writes: Vec<String> = Vec::new();
    for u in info.used_registers() {
        let name = reg_name(u.register());
        match u.access() {
            OpAccess::Read | OpAccess::CondRead => push_unique(&mut reads, name),
            OpAccess::Write | OpAccess::CondWrite => push_unique(&mut writes, name),
            OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                push_unique(&mut reads, name.clone());
                push_unique(&mut writes, name);
            }
            _ => {}
        }
    }
    (reads, writes)
}

fn collect_mem_access(info: &iced_x86::InstructionInfo) -> (Vec<IrMemAccess>, Vec<IrMemAccess>) {
    let mut reads = Vec::new();
    let mut writes = Vec::new();
    for m in info.used_memory() {
        let mem = IrMemAccess {
            base: opt_reg(m.base()),
            index: opt_reg(m.index()),
            scale: m.scale(),
            displacement: format!("0x{:X}", m.displacement()),
        };
        match m.access() {
            OpAccess::Read | OpAccess::CondRead => reads.push(mem),
            OpAccess::Write | OpAccess::CondWrite => writes.push(mem),
            OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                reads.push(mem.clone());
                writes.push(mem);
            }
            _ => {}
        }
    }
    (reads, writes)
}

fn snapshot_args(
    last_def: &HashMap<String, (usize, u64)>,
    consts: &HashMap<String, String>,
    ir_instrs: &[IrInstr],
) -> Vec<ArgHint> {
    let mut hints = Vec::new();
    for &reg in &ARG_REGS {
        let def = last_def.get(reg);
        let const_val = consts.get(reg).cloned();
        if def.is_none() && const_val.is_none() {
            continue;
        }
        let (def_addr, def_text) = match def {
            Some((idx, addr)) => (
                Some(format!("0x{:X}", addr)),
                ir_instrs.get(*idx).map(|i| i.text.clone()),
            ),
            None => (None, None),
        };
        hints.push(ArgHint {
            reg: reg.to_string(),
            def_addr,
            def_text,
            const_val,
        });
    }
    hints
}

fn invalidate_volatile(last_def: &mut HashMap<String, (usize, u64)>) {
    for v in &VOLATILE_REGS {
        last_def.remove(*v);
    }
}

fn invalidate_volatile_consts(consts: &mut HashMap<String, String>) {
    for v in &VOLATILE_REGS {
        consts.remove(*v);
    }
}

/// Detects the immediate-constant value produced by a single instruction,
/// when recoverable. Covers `mov reg, imm`, `xor reg, reg` (zeroing) and
/// `lea reg, [rip+disp]` (rip-relative pointer constant — heavily used as
/// a switch-table base / string pointer / vtable pointer).
fn const_def(ins: &Instruction) -> Option<(String, String)> {
    if ins.op_count() < 2 || ins.op0_kind() != OpKind::Register {
        return None;
    }
    let reg = reg_name(ins.op0_register());
    match ins.mnemonic() {
        Mnemonic::Mov => {
            if matches!(
                ins.op1_kind(),
                OpKind::Immediate8
                    | OpKind::Immediate16
                    | OpKind::Immediate32
                    | OpKind::Immediate64
                    | OpKind::Immediate8to16
                    | OpKind::Immediate8to32
                    | OpKind::Immediate8to64
                    | OpKind::Immediate32to64
            ) {
                Some((reg, format!("0x{:X}", ins.immediate(1))))
            } else {
                None
            }
        }
        Mnemonic::Xor => {
            if ins.op1_kind() == OpKind::Register
                && ins.op0_register() == ins.op1_register()
            {
                Some((reg, "0x0".to_string()))
            } else {
                None
            }
        }
        Mnemonic::Lea => {
            if ins.is_ip_rel_memory_operand() {
                Some((reg, format!("0x{:X}", ins.ip_rel_memory_address())))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Best-effort switch / jump-table dispatch detection on a block-terminating
/// indirect branch. Looks at the dispatching instruction itself first
/// (memory-operand form), and otherwise back-scans the block for the MSVC
/// `lea base; movsxd r,[base+idx*4]; add r,base; jmp r` pattern.
fn detect_switch(
    instrs: &[Instruction],
    block_start: usize,
    term_idx: usize,
) -> Option<IrSwitch> {
    let term = &instrs[term_idx];
    if term.flow_control() != FlowControl::IndirectBranch {
        return None;
    }

    // Form 1: `jmp [rip+disp + idx*scale]` — table holds absolute pointers.
    if term.is_ip_rel_memory_operand() && term.memory_index() != Register::None {
        return Some(IrSwitch {
            at: format!("0x{:X}", term.ip()),
            kind: "mem-indexed",
            table: Some(format!("0x{:X}", term.ip_rel_memory_address())),
            index_reg: Some(reg_name(term.memory_index())),
            scale: term.memory_index_scale(),
            bound: scan_bound(instrs, block_start, term_idx),
            cases: Vec::new(),
        });
    }

    // Form 2: `jmp <reg>` — back-scan for MSVC rel32 table pattern.
    if term.op0_kind() == OpKind::Register {
        let mut table: Option<u64> = None;
        let mut index_reg: Option<String> = None;
        let mut scale: u32 = 0;

        let mut i = term_idx;
        while i > block_start {
            i -= 1;
            let ins = &instrs[i];
            // movsxd / mov from memory with [base + idx*scale] discloses
            // the index register and scale.
            if index_reg.is_none() && ins.memory_index() != Register::None {
                index_reg = Some(reg_name(ins.memory_index()));
                scale = ins.memory_index_scale();
            }
            // lea reg, [rip+disp] sets the table base.
            if table.is_none()
                && ins.mnemonic() == Mnemonic::Lea
                && ins.is_ip_rel_memory_operand()
            {
                table = Some(ins.ip_rel_memory_address());
            }
            if table.is_some() && index_reg.is_some() {
                break;
            }
        }

        if table.is_some() || index_reg.is_some() {
            return Some(IrSwitch {
                at: format!("0x{:X}", term.ip()),
                kind: "reg-rel32",
                table: table.map(|t| format!("0x{t:X}")),
                index_reg,
                scale,
                bound: scan_bound(instrs, block_start, term_idx),
                cases: Vec::new(),
            });
        }
    }

    None
}

/// Recover the bound of a switch from the most recent `cmp idx, imm` or
/// `sub idx, imm` within the dispatching block.
fn scan_bound(instrs: &[Instruction], block_start: usize, term_idx: usize) -> Option<u64> {
    let mut i = term_idx;
    while i > block_start {
        i -= 1;
        let ins = &instrs[i];
        if matches!(ins.mnemonic(), Mnemonic::Cmp | Mnemonic::Sub)
            && ins.op_count() >= 2
            && ins.op0_kind() == OpKind::Register
        {
            if matches!(
                ins.op1_kind(),
                OpKind::Immediate8
                    | OpKind::Immediate16
                    | OpKind::Immediate32
                    | OpKind::Immediate64
                    | OpKind::Immediate8to16
                    | OpKind::Immediate8to32
                    | OpKind::Immediate8to64
                    | OpKind::Immediate32to64
            ) {
                return Some(ins.immediate(1));
            }
        }
    }
    None
}

fn analyze_frame(instrs: &[Instruction], texts: &[String]) -> IrFrameSummary {
    let mut summary = IrFrameSummary::default();
    let mut prolog: Vec<String> = Vec::new();
    let scan_count = instrs.len().min(16);

    for i in 0..scan_count {
        let t = texts[i].to_lowercase();
        if t.starts_with("push ") {
            let rest = t.trim_start_matches("push ").trim();
            if rest.starts_with('r') || rest.starts_with("rbx") || rest.starts_with("rsi") {
                push_unique(&mut summary.spilled_regs, rest.to_string());
                prolog.push(texts[i].clone());
                continue;
            }
        }
        if t.starts_with("sub rsp,") {
            if let Some(num) = t.split(',').nth(1) {
                let num = num.trim().trim_end_matches('h');
                if let Ok(v) = u64::from_str_radix(num, 16) {
                    summary.frame_size = v;
                }
            }
            prolog.push(texts[i].clone());
            continue;
        }
        if t.starts_with("mov rbp,rsp") || t == "mov rbp,rsp" {
            summary.uses_rbp = true;
            prolog.push(texts[i].clone());
            continue;
        }
        if t.starts_with("mov [rsp") || t.starts_with("mov ") && t.contains("[rsp+") {
            prolog.push(texts[i].clone());
            continue;
        }
        if !prolog.is_empty() {
            break;
        }
    }
    summary.prolog = prolog;
    summary
}

fn ins_kind(fc: FlowControl) -> &'static str {
    match fc {
        FlowControl::Call => "call",
        FlowControl::IndirectCall => "icall",
        FlowControl::UnconditionalBranch => "jmp",
        FlowControl::IndirectBranch => "ijmp",
        FlowControl::ConditionalBranch => "cjmp",
        FlowControl::Return => "ret",
        FlowControl::Interrupt => "int",
        FlowControl::Next => "other",
        _ => "other",
    }
}

fn reg_name(r: Register) -> String {
    if r == Register::None {
        return "none".to_string();
    }
    let full = r.full_register();
    format!("{full:?}").to_lowercase()
}

fn opt_reg(r: Register) -> Option<String> {
    if r == Register::None {
        None
    } else {
        Some(reg_name(r))
    }
}

fn push_unique(v: &mut Vec<String>, s: String) {
    if !v.iter().any(|x| x == &s) {
        v.push(s);
    }
}

fn parse_hex(s: &str) -> u64 {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(stripped, 16).unwrap_or(0)
}

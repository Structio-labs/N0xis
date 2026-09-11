//! Dev-only sweep, a level below [`prefix_audit`]: for every instruction, does
//! the lifted form **assign every register the instruction writes**?
//!
//! The prefix audit asks whether the lifter acknowledged a *flag* it was
//! carrying. This asks the harder half of the same question — whether the
//! lifted program still computes what the real one computes. A register the
//! hardware writes and the lift never assigns is a dropped effect: everything
//! downstream (SSA, value sets, the decompiler's variables) reasons about a
//! machine that is missing a write.
//!
//! An `Unlifted` statement is an honest refusal and is not counted, exactly as
//! in the prefix audit. What is counted is a *definite* model that is silently
//! short.
//!
//! Usage: effect_audit <file> <file-offset-hex> <len-hex> <va-hex> [abi]
use iced_x86::{Decoder, DecoderOptions, Instruction, InstructionInfoFactory, OpAccess, Register};
use n0xis_arch::{Arch, MicroStmt, X64};
use n0xis_contracts::Va;
use std::collections::{BTreeMap, BTreeSet};

fn hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex")
}

/// The names the lifter uses are full 64-bit registers, so `eax` and `al` both
/// have to be asked about as `rax`.
fn canonical(r: Register) -> Option<String> {
    if r == Register::None {
        return None;
    }
    let full = r.full_register();
    // Segment and instruction-pointer writes are control-flow bookkeeping the
    // micro-IR expresses as statements, not as register assignments.
    if full.is_segment_register() || full == Register::RIP {
        return None;
    }
    let name = format!("{full:?}").to_ascii_lowercase();
    // `full_register()` widens a vector register to its AVX-512 name, so
    // `xmm0` comes back as `zmm0` and every SIMD instruction looked like a
    // dropped write against a lifter that models 128-bit lanes. The comparison
    // has to happen at one granularity, and the micro-IR's is `xmmN`.
    if let Some(n) = name.strip_prefix("zmm").or_else(|| name.strip_prefix("ymm")) {
        return Some(format!("xmm{n}"));
    }
    Some(name)
}

/// Every register name a statement binds.
fn assigned(stmts: &[MicroStmt], out: &mut BTreeSet<String>) {
    for s in stmts {
        match s {
            MicroStmt::Assign { dst, .. } => {
                out.insert(dst.split('.').next().unwrap_or(dst).to_ascii_lowercase());
            }
            MicroStmt::Call { ret: Some(r), .. } => {
                out.insert(r.to_ascii_lowercase());
            }
            _ => {}
        }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        eprintln!("usage: effect_audit <file> <off> <len> <va> [abi]");
        std::process::exit(2);
    }
    let bytes = std::fs::read(&a[1]).expect("read");
    let (off, len, va) = (hex(&a[2]) as usize, hex(&a[3]) as usize, hex(&a[4]));
    let abi = a.get(5).map(String::as_str).unwrap_or("sysv");
    let code = &bytes[off..off + len];

    let arch = X64::new();
    let mut dec = Decoder::with_ip(64, code, va, DecoderOptions::NONE);
    let mut insn = Instruction::default();
    let mut info = InstructionInfoFactory::new();

    let mut total = 0u64;
    let mut definite = 0u64;
    let mut opaque = 0u64;
    // mnemonic -> (instructions with a dropped write, one example)
    let mut dropped: BTreeMap<String, (u64, String)> = BTreeMap::new();
    let mut dropped_total = 0u64;

    while dec.can_decode() {
        dec.decode_out(&mut insn);
        total += 1;
        if insn.is_invalid() {
            continue;
        }
        let start = (insn.ip() - va) as usize;
        let end = start + insn.len();
        let decoded = arch.decode_stream(&code[start..end], Va(insn.ip()), 1);
        if decoded.is_empty() {
            continue;
        }
        let stmts = arch.lift(&decoded[0], abi);
        if stmts.is_empty() || stmts.iter().any(|s| matches!(s, MicroStmt::Unlifted { .. })) {
            opaque += 1;
            continue;
        }
        definite += 1;

        let mut bound = BTreeSet::new();
        assigned(&stmts, &mut bound);

        let inf = info.info(&insn);
        let mut missing: Vec<String> = Vec::new();
        for u in inf.used_registers() {
            if !matches!(u.access(), OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite) {
                continue;
            }
            let Some(name) = canonical(u.register()) else { continue };
            if !bound.contains(&name) {
                missing.push(name);
            }
        }
        // Three writes the micro-IR deliberately does not model. Each is an
        // abstraction, not an oversight — and an abstraction nobody wrote down
        // is indistinguishable from an oversight, which is why they are named
        // here rather than left to be rediscovered.
        let declared_abstraction = match insn.mnemonic() {
            // A call pushes a return address and the matching `ret` pops it:
            // the stack pointer is unchanged across the pair, and the micro-IR
            // expresses the transfer as `Call`/`Return` rather than as
            // arithmetic on `rsp`.
            iced_x86::Mnemonic::Call | iced_x86::Mnemonic::Ret => {
                missing.iter().all(|m| m == "rsp")
            }
            // `vzeroupper` clears bits 128..255 of every vector register and
            // leaves the low 128 alone. The micro-IR models the low lane only —
            // a 256-bit `vmovdqu ymm0` lift binds `xmm0` — so at that width the
            // instruction really is a no-op.
            iced_x86::Mnemonic::Vzeroupper | iced_x86::Mnemonic::Vzeroall => {
                missing.iter().all(|m| m.starts_with("xmm"))
            }
            _ => false,
        };
        if !missing.is_empty() && !declared_abstraction {
            dropped_total += 1;
            let key = format!("{:?}", insn.mnemonic()).to_ascii_lowercase();
            let e = dropped.entry(key).or_insert_with(|| (0, String::new()));
            e.0 += 1;
            if e.1.is_empty() {
                e.1 = format!("{insn}  -> lift binds {bound:?}, misses {missing:?}");
            }
        }
    }

    println!("decoded {total} instructions: {definite} lifted definitely, {opaque} left opaque");
    println!(
        "{dropped_total} definite lifts drop a write the instruction makes \
         (excluding the declared abstractions: rsp across call/ret, the upper vector lane)"
    );
    println!("\n{:<12} {:>10}  example", "mnemonic", "count");
    let mut rows: Vec<_> = dropped.iter().collect();
    rows.sort_by_key(|(_, (n, _))| std::cmp::Reverse(*n));
    for (m, (n, ex)) in rows.iter().take(25) {
        println!("{m:<12} {n:>10}  {ex}");
    }
}

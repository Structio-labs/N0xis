// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The i386 PIC base register must have a defining statement.**
//!
//! GCC's position-independent 32-bit code begins every function that touches a
//! global with the pair `call __x86.get_pc_thunk.<reg>; add e<reg>, <GOT-off>`.
//! The thunk's whole body is `mov e<reg>, [esp]; ret`: it loads the **return
//! address** — the VA of the instruction after the `call` — into the
//! *suffix-named* register, and the following `add` turns that into the PIC
//! base the whole function indexes globals through.
//!
//! The generic call lift binds a call's result to the ABI return register
//! (`eax`). Applied here it produced a dead `eax = __x86_get_pc_thunk_bx()` and
//! left `ebx` — the PIC base — with **no defining statement**, so every
//! GOT-relative access dangled off the function-entry value of `ebx`. This
//! reproduced (confirmed against `readelf`: the recovered base did not equal
//! `_GLOBAL_OFFSET_TABLE_`).
//!
//! `Arch::lift_named_call` (i386 `x64_lift`) is the fix: the core resolves the
//! callee name once and hands it to the arch, which recognizes the thunk and
//! emits `<suffix reg> = <next-insn VA>` and no `eax` def. This test drives the
//! whole seam — CFG name resolution, the `LiftPass` wiring, the x64 override —
//! on a synthetic i386 image with a planted thunk symbol, so it needs no gcc and
//! runs in the plain gate. Reverting the x64 match to `None` fails it on its own
//! line (the pre-SSA statement is a `Call` binding `rax`, not the `rbx` assign).
//!
//! A compiled-object end-to-end reproduction lives in the developer notes; a
//! synthetic image is used here because it exercises the identical seam without
//! depending on a 32-bit multilib toolchain being present when the test runs.

use n0xis_arch::{MicroExpr, MicroStmt, X64};
use n0xis_contracts::{SymKind, Symbol, Va};
use n0xis_core::{CfgInput, CfgPass, Ctx, LiftPass, Pass, SsaPass, SsaStmt};
use n0xis_sources::{Snapshot, SymbolProvider};

/// The address of the thunk the caller calls into, and the name it resolves to.
const THUNK_VA: u64 = 0x1040;
const THUNK_NAME: &str = "__x86.get_pc_thunk.bx";

/// A symbol table with exactly the two symbols the real pipeline would carry
/// here: the function under analysis and the PC-thunk it calls. Attaching this
/// is what makes `resolved_target_name` (in the core) name the call target — the
/// same fact `.with_symbols(&image)` supplies from an ELF `.symtab` in the real
/// `decomp` pipeline. Without it the call is anonymous and the idiom is invisible.
struct ThunkSymbols;

impl SymbolProvider for ThunkSymbols {
    fn symbol_at(&self, va: Va) -> Option<Symbol> {
        match va.0 {
            0x1000 => Some(Symbol {
                va: Va(0x1000),
                module: String::new(),
                name: "use_base".into(),
                kind: SymKind::Function,
            }),
            THUNK_VA => Some(Symbol {
                va: Va(THUNK_VA),
                module: String::new(),
                name: THUNK_NAME.into(),
                kind: SymKind::Function,
            }),
            _ => None,
        }
    }
}

/// The function under analysis, hand-assembled i386 (verified with `objdump -m
/// i386`):
///
/// ```text
/// 0x1000  e8 3b 00 00 00     call  0x1040   ; __x86.get_pc_thunk.bx
/// 0x1005  81 c3 ae 2e 00 00  add   ebx, 0x2eae
/// 0x100b  89 d8              mov   eax, ebx
/// 0x100d  c3                 ret
/// ```
///
/// The return address the thunk reads is the VA after the `call`: **0x1005**.
const FN_BYTES: [u8; 14] =
    [0xe8, 0x3b, 0x00, 0x00, 0x00, 0x81, 0xc3, 0xae, 0x2e, 0x00, 0x00, 0x89, 0xd8, 0xc3];

/// The thunk body itself (`mov ebx, [esp]; ret`) — never entered by the CFG of
/// the caller, but present so the image has readable bytes at the call target.
const THUNK_BYTES: [u8; 4] = [0x8b, 0x1c, 0x24, 0xc3];

/// The VA immediately after the `call` — what `[esp]` holds inside the thunk.
const RETURN_ADDR: i128 = 0x1005;
/// The `add ebx, <imm>` displacement the next instruction applies to the base.
const GOT_OFFSET: i128 = 0x2eae;

fn image() -> Snapshot {
    Snapshot::builder()
        .region(Va(0x1000), FN_BYTES.to_vec())
        .region(Va(THUNK_VA), THUNK_BYTES.to_vec())
        .build()
}

/// Tier 1 — the pre-SSA lowering. The `call` instruction must lower to exactly
/// one assignment of the return address to `rbx` (the canonical full-width name
/// def-use records `ebx` under), and to **no** `rax` def and no `Call` stmt.
#[test]
fn the_thunk_call_lowers_to_a_single_base_register_assignment() {
    let img = image();
    let arch = X64::x86();
    let syms = ThunkSymbols;
    let ctx = Ctx::new(&img, &arch).with_symbols(&syms);

    let cfg = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), 64)).expect("CFG builds");
    // The name the whole fix keys on has to have been resolved by the core.
    let call = cfg
        .blocks
        .iter()
        .flat_map(|b| &b.insns)
        .find(|i| i.va == Va(0x1000))
        .expect("the call instruction is in the CFG");
    assert_eq!(
        call.target_name.as_deref(),
        Some(THUNK_NAME),
        "the core must resolve the thunk's name before the arch can recognize it"
    );

    let lifted = LiftPass.run(&ctx, cfg).expect("lift succeeds");
    let stmts: Vec<&MicroStmt> = lifted
        .blocks
        .iter()
        .flat_map(|b| &b.stmts)
        .filter(|s| s.va == Va(0x1000))
        .map(|s| &s.stmt)
        .collect();

    assert_eq!(
        stmts,
        vec![&MicroStmt::Assign { dst: "rbx".into(), value: MicroExpr::constant(RETURN_ADDR, 32) }],
        "the thunk call must lower to `rbx = next-insn VA` alone"
    );
    // The fabricated dead def the bug produced: a `Call` binding `rax`.
    assert!(
        !stmts.iter().any(|s| matches!(s, MicroStmt::Call { .. })),
        "no call statement — the thunk is not an ordinary call"
    );
    assert!(
        !stmts.iter().any(|s| matches!(s, MicroStmt::Assign { dst, .. } if dst == "rax")),
        "the thunk call must not define rax/eax"
    );
}

/// Tier 2 — the def connects. After SSA, the `add`'s read of the base must name
/// the very version the thunk assignment defined (its reaching definition), and
/// that assignment's value is the return-address constant. This is the behaviour
/// the bug broke: the `add` used to read the function-entry version of `ebx`.
#[test]
fn the_base_register_def_reaches_the_got_relative_add() {
    let img = image();
    let arch = X64::x86();
    let syms = ThunkSymbols;
    let ctx = Ctx::new(&img, &arch).with_symbols(&syms);

    let cfg = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), 64)).expect("CFG builds");
    let ssa = SsaPass.run(&ctx, cfg).expect("SSA builds");
    let stmts: Vec<&SsaStmt> = ssa.blocks.iter().flat_map(|b| &b.stmts).collect();

    // The thunk assignment: a versioned `rbx` set to the return-address constant.
    let thunk_def = stmts
        .iter()
        .find(|s| {
            s.va == Va(0x1000)
                && matches!(
                    &s.stmt,
                    MicroStmt::Assign { dst, value: MicroExpr::Const { value, bits: 32 } }
                        if dst.starts_with("rbx") && *value == RETURN_ADDR
                )
        })
        .expect("the thunk defines a versioned rbx with the return address");
    let MicroStmt::Assign { dst: base_version, .. } = &thunk_def.stmt else { unreachable!() };

    // The GOT-relative `add`: `rbx.m = (uint32)((uint32)rbx.<base_version> +
    // GOT_OFFSET)` — the width casts the 32-bit lift wraps operands in are not
    // load-bearing here; what is, is that the add **reads exactly the version
    // the thunk defined** (its reaching def) and applies the GOT offset.
    let add = stmts
        .iter()
        .find(|s| s.va == Va(0x1005))
        .expect("the add instruction has a lifted statement");
    let MicroStmt::Assign { value, .. } = &add.stmt else {
        panic!("the add must lower to an assignment, got {:?}", add.stmt)
    };
    assert!(
        reads_var(value, base_version),
        "the add must read the exact rbx version the thunk defined (its reaching def), got {value:?}"
    );
    assert!(
        contains_const(value, GOT_OFFSET),
        "the add must apply the GOT offset {GOT_OFFSET:#x}, got {value:?}"
    );

    // And `rax` is never defined at the call site — the fabricated def is gone.
    assert!(
        !stmts.iter().any(|s| s.va == Va(0x1000)
            && matches!(&s.stmt, MicroStmt::Assign { dst, .. } if dst.starts_with("rax"))),
        "the thunk call defines no rax version"
    );
}

/// Does `expr` read the SSA variable `name` anywhere in its tree? The 32-bit
/// lift wraps operands in width `Cast`s, so a structural equality check would be
/// brittle; a reachability check over the tree is what "the def reaches the read"
/// actually means.
fn reads_var(expr: &MicroExpr, name: &str) -> bool {
    match expr {
        MicroExpr::Var(v) => v == name,
        MicroExpr::Load { addr, .. } => reads_var(addr, name),
        MicroExpr::Unary(_, e) | MicroExpr::Cast { expr: e, .. } | MicroExpr::AddrOf(e) => {
            reads_var(e, name)
        }
        MicroExpr::Binary(_, a, b) | MicroExpr::Compare { lhs: a, rhs: b, .. } => {
            reads_var(a, name) || reads_var(b, name)
        }
        MicroExpr::Select { cond, a, b } => {
            reads_var(cond, name) || reads_var(a, name) || reads_var(b, name)
        }
        MicroExpr::Call { args, .. } => args.iter().any(|a| reads_var(a, name)),
        MicroExpr::Const { .. } | MicroExpr::OpaqueFlags { .. } | MicroExpr::Unknown(_) => false,
    }
}

/// Does `expr` contain the constant `val` anywhere in its tree?
fn contains_const(expr: &MicroExpr, val: i128) -> bool {
    match expr {
        MicroExpr::Const { value, .. } => *value == val,
        MicroExpr::Load { addr, .. } => contains_const(addr, val),
        MicroExpr::Unary(_, e) | MicroExpr::Cast { expr: e, .. } | MicroExpr::AddrOf(e) => {
            contains_const(e, val)
        }
        MicroExpr::Binary(_, a, b) | MicroExpr::Compare { lhs: a, rhs: b, .. } => {
            contains_const(a, val) || contains_const(b, val)
        }
        MicroExpr::Select { cond, a, b } => {
            contains_const(cond, val) || contains_const(a, val) || contains_const(b, val)
        }
        MicroExpr::Call { args, .. } => args.iter().any(|a| contains_const(a, val)),
        MicroExpr::Var(_) | MicroExpr::OpaqueFlags { .. } | MicroExpr::Unknown(_) => false,
    }
}

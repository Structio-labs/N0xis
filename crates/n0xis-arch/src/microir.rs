//! The micro-IR — [`Arch::lift`](crate::Arch::lift)'s typed output.
//!
//! Replaces the Phase 1 placeholder (`MicroStmt::Unlifted` only) with a real
//! expression/statement tree. Two design choices carry the correctness goal
//! of ROADMAP Phase 3 ("conditions correct under intervening flag writes"):
//!
//! - **One variable namespace.** Registers and the CPU flags share the same
//!   `Var(String)` space (flags live under the reserved name `"flags"`, which
//!   can never collide with a register name). This lets SSA construction
//!   treat both uniformly — no special-casing a "flag def" vs a "register
//!   def".
//! - **Flags are a real dataflow value, not a mutable "last compare".** Every
//!   instruction that touches the flags — not just `cmp`/`test` — writes the
//!   `"flags"` variable. `cmp`/`test` write a precise [`MicroExpr::Compare`];
//!   anything else writes [`MicroExpr::OpaqueFlags`]. A later `Jcc` reads
//!   whatever SSA value of `"flags"` reaches it: if that's a stale
//!   `OpaqueFlags` (some flag-setting instruction ran in between with no
//!   intervening `cmp`/`test`), [`Arch::branch_condition`](crate::Arch::branch_condition)
//!   can only render a placeholder — it is structurally impossible to reuse a
//!   stale compare the way a mutable "last compare" variable (v0's approach)
//!   could.

use n0xis_contracts::Va;
use serde::Serialize;

/// Bit width of a value the micro-IR operates on.
pub type Bits = u32;

/// The reserved variable name the CPU flags live under. Never a valid
/// register name, so it shares the `Var` namespace safely.
pub const FLAGS_VAR: &str = "flags";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnOp {
    Neg,
    Not,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    UDiv,
    SDiv,
    UMod,
    SMod,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
    // Comparisons — produced by `Arch::branch_condition`, not by `lift`
    // directly, but shared here since they're ordinary binary expressions.
    Eq,
    Ne,
    Ult,
    Ule,
    Ugt,
    Uge,
    Slt,
    Sle,
    Sgt,
    Sge,
}

/// Which compare-family instruction defined a `"flags"` value. Distinguishes
/// `cmp` (result discarded, flags from `lhs - rhs`) from `test` (flags from
/// `lhs & rhs`) since they render different conditions for the same mnemonic
/// (e.g. `je` after `test reg,reg` is `reg == 0`, not `reg == reg`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CmpKind {
    Cmp,
    Test,
    /// Flags left by an arithmetic/logical op that *keeps* its result in `lhs`
    /// (e.g. `dec ecx`, `sub rax,rbx`, `and edx,edx`). Only the zero flag —
    /// `je`/`jne`, reconstructed as `lhs == 0` / `lhs != 0` — is a pure
    /// function of the stored result and therefore sound to recover; the
    /// magnitude/sign conditions depend on carry/overflow, which the result
    /// alone does not carry, so `branch_condition` leaves those opaque. `rhs`
    /// is the constant `0`.
    Result,
}

/// A typed expression — the arch-neutral lowering of an operand or a flags
/// computation. Every variant is sound to render even half-optimized: nothing
/// here depends on a pass having already run.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "node", content = "data", rename_all = "snake_case")]
pub enum MicroExpr {
    Const {
        value: i128,
        bits: Bits,
    },
    /// A register or the `"flags"` pseudo-variable, pre-SSA. SSA construction
    /// rewrites these into versioned names (`rax.2`) in `n0xis.ir.ssa.v1`.
    Var(String),
    Load {
        addr: Box<MicroExpr>,
        bits: Bits,
        signed: bool,
    },
    Unary(UnOp, Box<MicroExpr>),
    Binary(BinOp, Box<MicroExpr>, Box<MicroExpr>),
    Cast {
        signed: bool,
        bits: Bits,
        expr: Box<MicroExpr>,
    },
    /// An absolute address (from a `lea`/RIP-relative target) used as a value
    /// rather than dereferenced.
    AddrOf(Box<MicroExpr>),
    /// Flags after `cmp lhs,rhs` or `test lhs,rhs` — precise enough for
    /// `Arch::branch_condition` to synthesize an exact condition.
    Compare {
        kind: CmpKind,
        lhs: Box<MicroExpr>,
        rhs: Box<MicroExpr>,
    },
    /// Flags changed by `mnemonic` in a way this lifter does not model
    /// precisely. A `Jcc` reading this (instead of a `Compare`) renders a
    /// placeholder — sound-but-vague beats silently wrong (CONCEPT §3 rule 6).
    OpaqueFlags {
        mnemonic: String,
    },
    /// A call used as a value — never produced by `lift` (a call is always a
    /// [`MicroStmt::Call`] statement there); this is what the optimizer's
    /// expression-propagation pass builds when it inlines a single-use call
    /// result into its sole consumer (the `rax=f(); x=*(rax+8)` →
    /// `x=*(f()+8)` collapse CONCEPT §6 calls out). The original `Call`
    /// statement is removed when this happens, so the call still executes
    /// exactly once — just at this expression's position instead.
    Call {
        target: CallTarget,
        args: Vec<MicroExpr>,
    },
    /// A ternary select — `cond ? a : b`. The lowering of `cmovcc` (`dst =
    /// cond ? src : dst`), and the node Rung 6's `?:`/`&&`/`||` recovery builds
    /// on. `cond` is a boolean expression; for a freshly-lifted `cmovcc` it is a
    /// `setcc:<jcc>` flag marker the SSA builder resolves against the reaching
    /// flags, exactly as it does for a bare `setcc`.
    Select {
        cond: Box<MicroExpr>,
        a: Box<MicroExpr>,
        b: Box<MicroExpr>,
    },
    /// Preserves an unlifted operand/expression verbatim so no semantics are
    /// silently dropped.
    Unknown(String),
}

impl MicroExpr {
    pub const fn constant(value: i128, bits: Bits) -> Self {
        MicroExpr::Const { value, bits }
    }
    pub fn var(name: impl Into<String>) -> Self {
        MicroExpr::Var(name.into())
    }
    pub fn flags() -> Self {
        MicroExpr::Var(FLAGS_VAR.to_string())
    }
    pub fn load(addr: MicroExpr, bits: Bits, signed: bool) -> Self {
        MicroExpr::Load { addr: Box::new(addr), bits, signed }
    }
    pub fn binary(op: BinOp, lhs: MicroExpr, rhs: MicroExpr) -> Self {
        MicroExpr::Binary(op, Box::new(lhs), Box::new(rhs))
    }
    pub fn unary(op: UnOp, v: MicroExpr) -> Self {
        MicroExpr::Unary(op, Box::new(v))
    }
    pub fn compare(kind: CmpKind, lhs: MicroExpr, rhs: MicroExpr) -> Self {
        MicroExpr::Compare { kind, lhs: Box::new(lhs), rhs: Box::new(rhs) }
    }
    pub fn select(cond: MicroExpr, a: MicroExpr, b: MicroExpr) -> Self {
        MicroExpr::Select { cond: Box::new(cond), a: Box::new(a), b: Box::new(b) }
    }
    /// A pure intrinsic call value, e.g. `__tzcnt(src)`. See
    /// [`CallTarget::Intrinsic`].
    pub fn intrinsic(name: impl Into<String>, args: Vec<MicroExpr>) -> Self {
        MicroExpr::Call { target: CallTarget::Intrinsic(name.into()), args }
    }
}

/// A direct or indirect call target. Direct calls carry only the address —
/// name resolution goes through the symbol seam, which `lift` (no `Ctx`
/// access) cannot reach; the core lift pass / renderer resolves it against
/// `n0xis-core`'s `CfgArtifact::callsites`, which already carries the name.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum CallTarget {
    Direct { va: Va },
    // Boxed: `MicroExpr::Call` embeds a `CallTarget`, so an unboxed
    // `MicroExpr` here would make the type infinitely recursive.
    Indirect(Box<MicroExpr>),
    /// A compiler *intrinsic* — a named pure operation the ISA exposes as one
    /// instruction with no callable address (`__tzcnt`, `__popcnt`, `__pmovmskb`,
    /// `__addsd`, …). Modelled as a call-shaped value so the whole expression
    /// machinery (renaming, propagation, rendering) handles its operands for
    /// free, but it resolves to no symbol and reads as `name(args)`.
    Intrinsic(String),
}

/// One micro-IR statement — the arch-neutral lowering of one machine
/// instruction (an instruction may lower to zero, one, or several statements,
/// e.g. `cmp` lowers to one `"flags"` assign; a plain `jmp` lowers to none —
/// the branch itself is structural, carried by the CFG, not a statement).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "op", content = "data", rename_all = "snake_case")]
pub enum MicroStmt {
    Assign {
        dst: String,
        value: MicroExpr,
    },
    Store {
        addr: MicroExpr,
        value: MicroExpr,
        bits: Bits,
    },
    Call {
        target: CallTarget,
        args: Vec<MicroExpr>,
        /// The variable the call's result is bound to (`"rax"` by Win64
        /// convention), if the caller is expected to consume it.
        ret: Option<String>,
    },
    Return(Option<MicroExpr>),
    Nop,
    /// Explicit "not yet lowered" — preserves the instruction verbatim so no
    /// semantics are silently lost (CONCEPT §3 rule 6).
    Unlifted { va: Va, text: String },
}

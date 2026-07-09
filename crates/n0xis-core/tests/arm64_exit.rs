//! **The Phase 7 exit test (multi-arch slice)**: ROADMAP Phase 7's "Multi-arch
//! via `trait Arch` (ARM64 first candidate)" — proves the ISA seam built in
//! Phase 1 for exactly this purpose actually holds: a second, real
//! architecture (`n0xis_arch::Arm64`, backed by the `disarm64` decoder) runs
//! through `n0xis-core`'s CFG/def-use pass **with zero changes to
//! `n0xis-core` itself**. Every byte below is a real, verified AArch64
//! encoding (cross-checked against `disarm64`'s own regression suite where
//! available), not a guess.

use n0xis_arch::Arm64;
use n0xis_contracts::Va;
use n0xis_core::{CfgInput, CfgPass, Ctx, Pass};
use n0xis_sources::Snapshot;

/// A tiny real function:
/// ```text
/// 0x1000: cbz  w0, 0x1008   ; branch over the next instruction if w0 == 0
/// 0x1004: add  w0, w0, w0   ; w0 *= 2 (only on the fall-through path)
/// 0x1008: ret
/// ```
fn tiny_function_bytes() -> Vec<u8> {
    let cbz_w0_plus8: u32 = 0x34000000 | (2 << 5); // imm19=2 words = +8 bytes, Rt=w0
    let add_w0_w0_w0: u32 = 0x0b000000; // verified: disarm64 regression "add\t\tw0, w0, w0"
    let ret: u32 = 0xd65f03c0; // verified: RET (implicit x30)

    [cbz_w0_plus8, add_w0_w0_w0, ret]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect()
}

#[test]
fn cfg_pass_builds_a_correct_graph_over_real_arm64_bytes() {
    let code = tiny_function_bytes();
    let snap = Snapshot::builder().region(Va(0x1000), code).label("arm64-exit").build();
    let arch = Arm64::new();
    let ctx = Ctx::new(&snap, &arch);

    let art = CfgPass
        .run(&ctx, CfgInput::new(Va(0x1000), 64))
        .expect("CfgPass must run over Arm64 exactly like X64 — n0xis-core never touches the decoder");

    // Three instructions, and the branch target (0x1008) plus the
    // fall-through (0x1004) both start new blocks, so three blocks.
    assert_eq!(art.insn_count, 3);
    assert_eq!(art.block_count, 3, "cbz's two successors must each start a block: {art:#?}");

    let cbz_block = art.blocks.iter().find(|b| b.start == Va(0x1000)).expect("cbz block");
    assert_eq!(cbz_block.terminator, "cjmp");
    assert_eq!(cbz_block.successors.len(), 2, "cbz falls through *and* branches");
    let targets: Vec<u64> = cbz_block.successors.iter().map(|s| s.to.0).collect();
    assert!(targets.contains(&0x1004), "fall-through to the add: {targets:?}");
    assert!(targets.contains(&0x1008), "taken branch to the ret: {targets:?}");

    // reg_access must have resolved through the whole pipeline: the cbz's
    // decoded instruction reports reading w0 (the tested register), proving
    // Arm64::reg_access is wired into the same def-use path X64 uses.
    let cbz_insn = &cbz_block.insns[0];
    assert_eq!(cbz_insn.reads, vec!["w0".to_string()]);

    let add_block = art.blocks.iter().find(|b| b.start == Va(0x1004)).expect("add block");
    assert_eq!(add_block.terminator, "fall");
    let add_insn = &add_block.insns[0];
    assert_eq!(add_insn.writes, vec!["w0".to_string()]);
    assert_eq!(add_insn.reads, vec!["w0".to_string(), "w0".to_string()]);

    let ret_block = art.blocks.iter().find(|b| b.start == Va(0x1008)).expect("ret block");
    assert_eq!(ret_block.terminator, "ret");
    assert_eq!(art.stats.returns, 1);
}

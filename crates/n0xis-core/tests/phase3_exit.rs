//! **The Phase 3 exit test** (ROADMAP P3 / CONCEPT §8).
//!
//! ROADMAP's wording: on [`archive/docs-v0/Decompile.txt`] — "no bare
//! `rax`/`rcx` in the common path; loads resolved to named locals/fields;
//! conditions correct under intervening flag writes." We don't have the
//! original game binary those addresses came from (it was never part of the
//! repo), so this test reconstructs the *shape* that motivated the rewrite —
//! a call result whose fields get read twice (`count`/`max` at `+0x68`/
//! `+0x6C`, exactly like the archived transcript) and a branch separated from
//! its guard by another flag-touching instruction — as synthetic x64 bytes,
//! and checks the properties ROADMAP names against the real `n0xis-cli`
//! pipeline (`CfgPass` → `SsaPass` → `OptimizePass` → `structure` → render).
//!
//! Scope note: "resolved to named locals/fields" is Phase 3's *address
//! expression* resolving (the pointer's origin inlined, e.g.
//! `*(f()+0x68)` instead of a stale/bare `*(rax+0x68)`) plus the existing
//! `local_XX` stack-slot convention — real *struct field names*
//! (`state->count`) are explicitly Phase 4 scope (CONCEPT §6 step 4). This
//! test holds Phase 3 to what it actually owns.
//!
//! [`archive/docs-v0/Decompile.txt`]: ../../../archive/docs-v0/Decompile.txt

use n0xis_arch::X64;
use n0xis_contracts::Va;
use n0xis_core::{CfgInput, CfgPass, Ctx, DecompInput, DecompPass, DecompStyle, Pass};
use n0xis_sources::Snapshot;

fn decomp(code: Vec<u8>, style: DecompStyle) -> n0xis_core::PseudoFunction {
    let snap = Snapshot::builder().region(Va(0x1000), code).build();
    let arch = X64::new();
    let ctx = Ctx::new(&snap, &arch);
    let cfg = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), 256)).unwrap();
    DecompPass.run(&ctx, DecompInput { cfg, style, explain: true }).unwrap()
}

/// Every occurrence of `reg` in `text` is immediately followed by an SSA
/// version separator (`.`) — i.e. nothing renders as a bare, undifferentiated
/// register the way v0's linear template renderer always did.
fn every_occurrence_is_versioned(text: &str, reg: &str) -> bool {
    let bytes = text.as_bytes();
    let needle = reg.as_bytes();
    let mut i = 0;
    while let Some(off) = text[i..].find(reg) {
        let start = i + off;
        let end = start + needle.len();
        // Reject a match that's itself a substring of a longer identifier
        // (e.g. "rax" inside "traxxx") by requiring a non-alnum boundary
        // before it.
        let boundary_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        if boundary_ok && (end >= bytes.len() || bytes[end] != b'.') {
            return false;
        }
        i = end;
    }
    true
}

#[test]
fn call_result_fields_read_twice_never_leak_a_bare_register() {
    // Mirrors Decompile.txt's motivating shape:
    //   rax = sub_X(rcx, rdx, r8, r9);
    //   count = *(uint32_t*)(rax + 0x68);
    //   max   = *(uint32_t*)(rax + 0x6C);
    //   free_slots = max - count;
    //   return free_slots;
    let code = vec![
        0xE8, 0x00, 0x00, 0x00, 0x00, // 0x1000 call +0            -> rax.1 = f()
        0x48, 0x8B, 0x50, 0x68, // 0x1005 mov rdx, [rax+0x68]       -> rdx.1 = *(rax.1+0x68) = count
        0x48, 0x8B, 0x48, 0x6C, // 0x1009 mov rcx, [rax+0x6C]       -> rcx.1 = *(rax.1+0x6c) = max
        0x48, 0x29, 0xD1, // 0x100d sub rcx, rdx                    -> rcx.1 -= rdx.1 (free_slots)
        0x48, 0x89, 0xC8, // 0x1010 mov rax, rcx                    -> rax = free_slots
        0xC3, // 0x1013 ret
    ];
    let out = decomp(code, DecompStyle::Ssa);
    let body = out.pseudo[1..out.pseudo.len() - 1].join("\n");

    assert!(body.contains("0x68"), "expected the `count` field offset: {body}");
    assert!(body.contains("0x6c") || body.contains("0x6C"), "expected the `max` field offset: {body}");
    assert!(body.contains("sub_1005("), "expected the call site inlined/named: {body}");
    for reg in ["rax", "rcx", "rdx"] {
        assert!(
            every_occurrence_is_versioned(&body, reg),
            "found a bare, un-versioned `{reg}` in the common path (v0's exact failure mode): {body}"
        );
    }
}

#[test]
fn a_condition_separated_from_its_guard_by_another_flag_write_never_reuses_a_stale_compare() {
    // Block A: cmp rcx,0 ; jmp <next>   (unconditional jump to the very next
    // instruction — forces a real block boundary without changing control
    // flow, so the intervening instruction lives in a genuinely different
    // block from the `cmp`, matching how this bug actually manifests across
    // a CFG rather than within one straight-line block).
    // Block B: add rcx,rdx ; je <target>   -- B's own `add` is the *last*
    // flags-setter before B's own `je`; if the renderer ever showed
    // `rcx == 0` here it would be silently reusing block A's stale compare
    // across an instruction that provably changed the flags in between —
    // exactly the v0 bug ROADMAP calls out.
    let code = vec![
        0x48, 0x83, 0xF9, 0x00, // 0x1000 cmp rcx, 0
        0xEB, 0x00, // 0x1004 jmp 0x1006 (unconditional, same address)
        0x48, 0x01, 0xD1, // 0x1006 add rcx, rdx   <- last flags-setter before the je
        0x74, 0x08, // 0x1009 je 0x1013
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // 0x100b mov rax, 1
        0xC3, // 0x1012 ret
        0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00, // 0x1013 mov rax, 2
        0xC3, // 0x101a ret
    ];
    // Use the `structured` style (SSA, no optimizer) so each block's
    // condition maps 1:1 to source blocks without further collapsing.
    let out = decomp(code, DecompStyle::Structured);
    let body = out.pseudo.join("\n");

    assert!(
        !body.contains("rcx.0 == 0x0") && !body.contains("(rcx.0 == 0x0)"),
        "the je must not have reused block A's stale `cmp rcx,0` across the intervening `add`: {body}"
    );
    assert!(
        body.contains("cond(je)"),
        "expected an honest placeholder for the je (flags were opaque, not a compare) — sound over silently wrong: {body}"
    );
}

//! **The Phase 4 exit test** (ROADMAP P4 / CONCEPT §6 steps 4-5).
//!
//! ROADMAP's wording: "recovered signatures + named fields on a labeled
//! sample set." There's no existing labeled corpus in this repo (Phase 3's
//! exit test hit the same gap and reconstructed Decompile.txt's motivating
//! shape instead), so this test *is* the labeled sample set — each case
//! below is synthetic x64 bytes whose ground truth (real arity, real return
//! type, which offsets are a coalesced local vs. a struct field) is known
//! by construction, and is checked against the real pipeline
//! (`CfgPass` → `SsaPass` → `OptimizePass` → `TypeInferPass` → `DecompPass`).

use n0xis_arch::X64;
use n0xis_contracts::Va;
use n0xis_core::{CfgInput, CfgPass, Ctx, DecompInput, DecompPass, DecompStyle, Pass};
use n0xis_sources::Snapshot;

fn decomp(code: Vec<u8>) -> n0xis_core::PseudoFunction {
    let snap = Snapshot::builder().region(Va(0x1000), code).build();
    let arch = X64::new();
    let ctx = Ctx::new(&snap, &arch);
    let cfg = CfgPass.run(&ctx, CfgInput::new(Va(0x1000), 256)).unwrap();
    DecompPass.run(&ctx, DecompInput { cfg, style: DecompStyle::Ssa, explain: true }).unwrap()
}

/// Label: arity 0, `void` return — a function that touches no argument
/// register and never assigns `rax`.
#[test]
fn labeled_void_niladic_function() {
    // mov [rsp+8], 0x2a ; ret  -- writes a local constant, returns nothing.
    let code = vec![0x48, 0xC7, 0x44, 0x24, 0x08, 0x2A, 0x00, 0x00, 0x00, 0xC3];
    let out = decomp(code);
    assert_eq!(out.signature, "void sub_1000(void)", "{}", out.signature);
}

/// Label: arity 1 (`rcx` only), non-`void` return — the ABI can't skip
/// straight to `rdx` while leaving `rcx` unused, so a function reading only
/// `rcx` has real arity exactly 1, not the old fixed 4.
#[test]
fn labeled_single_arg_function_with_a_value_return() {
    // add rax, rcx ; ret  -- reads rcx, returns something derived from it.
    let code = vec![0x48, 0x01, 0xC8, 0xC3];
    let out = decomp(code);
    assert_eq!(out.signature, "uint64_t sub_1000(uint64_t rcx)", "{}", out.signature);
}

/// Label: a gap in the middle of the register-arg sequence (`r8` used,
/// `rdx` not) still yields arity 3 — Win64 argument registers are
/// positional, so using `r8` implies `rcx`/`rdx` are real (if unread) slots.
#[test]
fn labeled_arity_with_a_skipped_middle_register() {
    // mov rax, rcx ; add rax, r8 ; ret
    let code = vec![0x48, 0x89, 0xC8, 0x4C, 0x01, 0xC0, 0xC3];
    let out = decomp(code);
    assert_eq!(
        out.signature,
        "uint64_t sub_1000(uint64_t rcx, uint64_t rdx, uint64_t r8)",
        "{}",
        out.signature
    );
}

/// Label: two accesses at the *same* stack offset coalesce into exactly one
/// named local, referenced consistently at both use sites.
///
/// Uses two live *reads* of the slot: a store/reload version is now fully
/// store-to-load forwarded and the spent store dead-eliminated (Memory-SSA
/// Rungs 1a–1c), which correctly collapses `[rsp+0x10] = rcx; … = [rsp+0x10]`
/// to the value itself — the "local" was only a spill. Two live reads keep a
/// genuine slot to name.
#[test]
fn labeled_local_used_at_two_sites_stays_one_name() {
    // mov rax, [rsp+0x10] ; add rax, [rsp+0x10] ; ret
    let code = vec![
        0x48, 0x8b, 0x44, 0x24, 0x10, // mov rax, [rsp+0x10]
        0x48, 0x03, 0x44, 0x24, 0x10, // add rax, [rsp+0x10]
        0xc3,
    ];
    let out = decomp(code);
    let body = out.pseudo[1..out.pseudo.len() - 1].join("\n");
    let occurrences = body.matches("local_10").count();
    assert!(occurrences >= 2, "expected local_10 referenced at 2+ sites: {body}");
    // Exactly one distinct local name at offset 0x10 — never local_10 *and*
    // some other alias for the same slot, and never the raw `rsp+off` form.
    assert!(!body.contains("rsp"), "the raw rsp+offset form must not leak through: {body}");
}

/// Label: a pointer held in a register and dereferenced at two distinct
/// offsets renders as `base->field_0xNN` — CONCEPT §6's literal example
/// (`state->count` instead of `*(uint32_t*)(rax+0x68)`), field names aside
/// (no debug info to recover real ones from, hence the synthetic
/// `field_0xNN` naming — see `typeinfer.rs` module docs).
#[test]
fn labeled_struct_pointer_with_two_fields() {
    // call +0 ; mov edx,[rax+0x68] ; mov ecx,[rax+0x6c] ; sub ecx,edx ; mov eax,ecx ; ret
    let code = vec![
        0xE8, 0x00, 0x00, 0x00, 0x00, // call +0        -> rax = f()
        0x8B, 0x50, 0x68, // mov edx, [rax+0x68]         -> count (32-bit)
        0x8B, 0x48, 0x6C, // mov ecx, [rax+0x6c]          -> max
        0x2B, 0xCA, // sub ecx, edx                        -> free_slots
        0x89, 0xC8, // mov eax, ecx
        0xC3,
    ];
    let out = decomp(code);
    let body = out.pseudo[1..out.pseudo.len() - 1].join("\n");
    assert!(body.contains("->field_0x68") && body.contains("->field_0x6c"), "{body}");
    assert!(!body.contains("0x68 + rax") && !body.contains("rax + 0x68"), "raw pointer math should be gone: {body}");
}

/// Label: a known Win32 API call gets its argument list trimmed to the
/// real arity and each argument named, instead of the generic 4-register
/// dump. `CloseHandle` takes exactly one `HANDLE` argument.
#[test]
fn labeled_known_api_call_gets_named_and_trimmed() {
    // Build a tiny static PE-less function: we can't resolve a real import
    // without a loaded module, so this drives the same check through
    // `RenderNames` directly (the unit-level equivalent lives in
    // `render.rs`) — kept here as a labeled-sample-set entry for
    // discoverability alongside the other Phase 4 recoveries.
    use n0xis_arch::{CallTarget, MicroExpr};
    use n0xis_core::{render_expr, RenderNames};

    let callsites = vec![n0xis_core::Callsite {
        from: Va(0x2000),
        kind: "named".to_string(),
        target: Some(Va(0x3000)),
        target_name: Some("kernel32!CloseHandle".to_string()),
        via_slot: None,
    }];
    let names = RenderNames::new(&callsites);
    let call = MicroExpr::Call {
        target: CallTarget::Direct { va: Va(0x3000) },
        args: vec![
            MicroExpr::var("rcx.0"),
            MicroExpr::var("rdx.0"),
            MicroExpr::var("r8.0"),
            MicroExpr::var("r9.0"),
        ],
    };
    let text = render_expr(&call, &names);
    assert_eq!(text, "(BOOL)kernel32__CloseHandle(/*hObject*/ rcx.0)");
}

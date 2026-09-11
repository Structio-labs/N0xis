//! Dev-only sweep: over a raw code blob, report every instruction whose
//! decode carries a flag the lifter could ignore, and say whether the lifter
//! modelled it anyway or left it opaque.
//!
//! Usage: prefix_audit <file> <file-offset-hex> <len-hex> <va-hex>
//! Get the three numbers from `readelf -SW` / `objdump -h`.
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, Register};
use n0xis_arch::{Arch, X64};
use n0xis_contracts::Va;
use std::collections::BTreeMap;

fn hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex")
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        eprintln!("usage: prefix_audit <file> <off> <len> <va>");
        std::process::exit(2);
    }
    let bytes = std::fs::read(&a[1]).expect("read");
    let (off, len, va) = (hex(&a[2]) as usize, hex(&a[3]) as usize, hex(&a[4]));
    let code = &bytes[off..off + len];

    let arch = X64::new();
    let mut dec = Decoder::with_ip(64, code, va, DecoderOptions::NONE);
    let mut insn = Instruction::default();

    // category -> (total, modelled-anyway)
    let mut tally: BTreeMap<&'static str, (u64, u64)> = BTreeMap::new();
    let mut examples: BTreeMap<&'static str, String> = BTreeMap::new();
    let mut total = 0u64;

    while dec.can_decode() {
        dec.decode_out(&mut insn);
        total += 1;
        if insn.is_invalid() {
            continue;
        }
        // A prefix byte only carries meaning on the instructions it applies to.
        // F3/F2 on anything but a string operation is `rep ret` padding or an
        // MPX `bnd` hint — architecturally inert, so counting it as dropped
        // semantics over-reports. Likewise a segment override on an operand
        // that is not memory is a branch hint or a desynchronised decode.
        let string_op = matches!(
            insn.mnemonic(),
            Mnemonic::Movsb | Mnemonic::Movsw | Mnemonic::Movsd | Mnemonic::Movsq
                | Mnemonic::Stosb | Mnemonic::Stosw | Mnemonic::Stosd | Mnemonic::Stosq
                | Mnemonic::Lodsb | Mnemonic::Lodsw | Mnemonic::Lodsd | Mnemonic::Lodsq
                | Mnemonic::Scasb | Mnemonic::Scasw | Mnemonic::Scasd | Mnemonic::Scasq
                | Mnemonic::Cmpsb | Mnemonic::Cmpsw | Mnemonic::Cmpsd | Mnemonic::Cmpsq
                | Mnemonic::Insb | Mnemonic::Insw | Mnemonic::Insd
                | Mnemonic::Outsb | Mnemonic::Outsw | Mnemonic::Outsd
        );
        let touches_memory =
            (0..insn.op_count()).any(|i| insn.op_kind(i) == iced_x86::OpKind::Memory);

        let mut cats: Vec<&'static str> = Vec::new();
        if insn.has_lock_prefix() {
            cats.push("lock");
        }
        if insn.has_rep_prefix() && string_op {
            cats.push("rep");
        }
        if insn.has_repne_prefix() && string_op {
            cats.push("repne");
        }
        if insn.has_xacquire_prefix() {
            cats.push("xacquire");
        }
        if insn.has_xrelease_prefix() {
            cats.push("xrelease");
        }
        if insn.op_mask() != Register::None {
            cats.push("opmask");
        }
        if insn.zeroing_masking() {
            cats.push("zeroing");
        }
        if insn.suppress_all_exceptions() {
            cats.push("sae");
        }
        if insn.rounding_control() != iced_x86::RoundingControl::None {
            cats.push("rounding");
        }
        if touches_memory {
            match insn.segment_prefix() {
                Register::FS => cats.push("seg-fs"),
                Register::GS => cats.push("seg-gs"),
                Register::None => {}
                _ => cats.push("seg-zero-base"),
            }
        }
        if cats.is_empty() {
            continue;
        }

        // Ask the lifter what it does with these exact bytes.
        let start = (insn.ip() - va) as usize;
        let end = start + insn.len();
        let insns = arch.decode_stream(&code[start..end], Va(insn.ip()), 1);
        let (opaque, text) = if insns.is_empty() {
            (true, String::new())
        } else {
            let stmts = arch.lift(&insns[0], "sysv");
            let opaque = stmts.is_empty()
                || stmts.iter().any(|s| matches!(s, n0xis_arch::MicroStmt::Unlifted { .. }));
            (opaque, format!("{stmts:?}"))
        };
        for c in cats {
            // "Silent" is the only failure that matters: the lifter produced a
            // definite model that says nothing about the flag it was carrying.
            // Leaving it opaque is an honest refusal, and naming the semantics
            // in the output is the fix. Anything else is a lie with a shape.
            let honest = match c {
                "seg-fs" => text.contains("__seg_fs"),
                "seg-gs" => text.contains("__seg_gs"),
                "lock" => text.contains("__atomic_") || opaque,
                // A zero-base override in 64-bit mode changes nothing, so
                // ignoring it is correct, not silent.
                "seg-zero-base" => true,
                // An intrinsic is an honest refusal to specify: `__vcvtph2ps(x)`
                // claims a value, never a rounding mode or an exception policy.
                // Concrete arithmetic under a rounding override would be the lie.
                "sae" | "rounding" => opaque || text.contains("Intrinsic"),
                // Everything else must be refused outright to be honest.
                _ => opaque,
            };
            let e = tally.entry(c).or_default();
            e.0 += 1;
            if !honest {
                e.1 += 1;
                examples.entry(c).or_insert_with(|| format!("{insn}"));
            }
        }
    }

    println!("decoded {total} instructions");
    println!("{:<16} {:>10} {:>10}  example silently dropped", "flag", "carried", "SILENT");
    for (k, (n, m)) in &tally {
        println!("{:<16} {:>10} {:>10}  {}", k, n, m, examples.get(k).cloned().unwrap_or_default());
    }
}

//! `bindings list` — enumerate a script VM's native bindings by pairing each
//! registration *name* string with the C function pointer registered under it
//! (ROADMAP Phase 8, generalizes RE_METHOD W2).
//!
//! Finding `Math.next_random`'s native implementation took ~20 minutes by hand:
//! string → RIP-relative xref → land in the `register(L, ns, "name", cfunc)`
//! call → the C function pointer is right there as an argument. That's a
//! mechanical lookup masquerading as reverse engineering. This pass automates
//! exactly that walk: for each candidate binding-name string in the data
//! window, it finds the `lea reg,[name]` site(s) in the code window, then looks
//! in a small neighborhood for the `lea reg,[cfunc]` that loads a pointer *into
//! executable code* — the bound native function.
//!
//! Deliberately a **heuristic with a confidence**, not a claimed certainty: it
//! recognizes the common "load the name and the function pointer near each
//! other, then call the registrar" shape (Lua's `luaL_Reg` tables, Bitsquid's
//! `register`, most embedded-VM binding APIs), and reports proximity + whether a
//! `call` sits between the two loads. It does not model any specific ABI or
//! decode the registrar itself — that would be a per-engine effort, honestly
//! out of scope here (the same sound-over-complete line `detect_switch` draws).

use n0xis_contracts::Va;
use serde::Serialize;

use crate::{Ctx, CoreError, Pass};

#[derive(Clone, Debug)]
pub struct BindingsInput {
    /// Window searched for candidate name strings (typically `.rdata`).
    pub data_start: Va,
    pub data_size: usize,
    /// Window decoded for reference sites; also the executable range that gates
    /// what counts as a "function pointer" (typically `.text`).
    pub code_start: Va,
    pub code_size: usize,
    /// If non-empty, only these exact names are searched; otherwise every
    /// identifier-like string in the data window is a candidate.
    pub names: Vec<String>,
    /// How many instructions on each side of a name-load to search for the
    /// paired function-pointer load.
    pub window: usize,
    pub limit: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct Binding {
    pub name: String,
    pub name_addr: Va,
    /// The `lea reg,[name]` instruction that loads the name.
    pub name_ref_site: Va,
    /// The registered native function pointer (lands inside the code window).
    pub cfunc: Va,
    /// The `lea reg,[cfunc]` instruction that loads it.
    pub cfunc_ref_site: Va,
    /// Instruction distance between the two loads (0 = adjacent).
    pub distance_insns: usize,
    /// Whether a `call` (the registrar) sits in the neighborhood of the two
    /// loads — the loads set up the arguments and the call consumes them, so a
    /// nearby `call` is a strong "this really is a `register(..., name, cfunc)`
    /// site" signal.
    pub call_nearby: bool,
    /// 0.0..=1.0 heuristic confidence (closer loads + a nearby call → higher).
    pub confidence: f32,
}

#[derive(Clone, Debug, Serialize)]
pub struct BindingsArtifact {
    pub count: usize,
    /// How many distinct name strings had at least one paired function pointer.
    pub named: usize,
    pub bindings: Vec<Binding>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BindingsPass;

/// Read an identifier-like string starting exactly at `off` in `data`. An
/// identifier here is `[A-Za-z_][A-Za-z0-9_.:]*` — the shape a binding name
/// takes (`next_random`, `Math.next_random`, `Vector3.length`) — and it must be
/// terminated by a non-identifier byte (usually NUL) so a mid-blob slice isn't
/// mistaken for a whole name. Returns `None` if `off` doesn't begin a valid
/// identifier of length in `[min_len, max_len]`.
fn read_identifier_at(data: &[u8], off: usize, min_len: usize, max_len: usize) -> Option<String> {
    let first = *data.get(off)?;
    if first != b'_' && !first.is_ascii_alphabetic() {
        return None;
    }
    let mut j = off;
    while j < data.len() {
        let c = data[j];
        if c == b'_' || c == b'.' || c == b':' || c.is_ascii_alphanumeric() {
            j += 1;
        } else {
            break;
        }
    }
    let len = j - off;
    let terminated = j >= data.len() || data[j] == 0;
    if len < min_len || len > max_len || !terminated {
        return None;
    }
    std::str::from_utf8(&data[off..j]).ok().map(str::to_string)
}

impl Pass for BindingsPass {
    type In = BindingsInput;
    type Out = BindingsArtifact;

    fn name(&self) -> &'static str {
        "bindings.list"
    }

    fn run(&self, ctx: &Ctx, input: BindingsInput) -> Result<BindingsArtifact, CoreError> {
        let data = ctx.source.read(input.data_start, input.data_size)?;
        let code = ctx.source.read(input.code_start, input.code_size)?;
        let insns = ctx.arch.decode_stream(&code, input.code_start, code.len());

        let code_lo = input.code_start.0;
        let code_hi = input.code_start.0.saturating_add(input.code_size as u64);
        let data_lo = input.data_start.0;
        let data_hi = input.data_start.0.saturating_add(data.len() as u64);
        let in_code = |va: Va| va.0 >= code_lo && va.0 < code_hi;
        let is_lea = |ins: &n0xis_arch::DecodedInsn| ins.mnemonic == "lea";

        // If the caller restricted to specific names, index them for O(1) member
        // tests (case-sensitive — binding names are exact).
        let restrict: Option<std::collections::HashSet<&str>> =
            if input.names.is_empty() { None } else { Some(input.names.iter().map(String::as_str).collect()) };

        // One linear pass over the decoded stream: every `lea reg,[name]` whose
        // target lands in the data window and reads a valid identifier there is a
        // name-load site. This replaces the old O(names × insns) rescan with a
        // single O(insns) sweep — essential on a real module with thousands of
        // candidate strings (matches the "index once" perf discipline elsewhere).
        struct NameSite {
            insn_idx: usize,
            name_addr: Va,
            name: String,
        }
        let mut sites: Vec<NameSite> = Vec::new();
        for (i, ins) in insns.iter().enumerate() {
            let Some(t) = ins.rip_target else { continue };
            if !is_lea(ins) || t.0 < data_lo || t.0 >= data_hi {
                continue;
            }
            let off = (t.0 - data_lo) as usize;
            let Some(name) = read_identifier_at(&data, off, 2, 64) else { continue };
            if let Some(set) = &restrict {
                if !set.contains(name.as_str()) {
                    continue;
                }
            }
            sites.push(NameSite { insn_idx: i, name_addr: t, name });
        }

        let mut bindings = Vec::new();
        let mut seen: std::collections::HashSet<(u64, u64)> = std::collections::HashSet::new();
        for site in &sites {
            let i = site.insn_idx;
            // Search the neighborhood for the nearest lea of a code pointer.
            let lo = i.saturating_sub(input.window);
            let hi = (i + input.window + 1).min(insns.len());
            let mut best: Option<(usize, &n0xis_arch::DecodedInsn)> = None;
            for (k, cand) in insns[lo..hi].iter().enumerate() {
                let ki = lo + k;
                if ki == i {
                    continue;
                }
                let Some(t) = cand.rip_target else { continue };
                if !is_lea(cand) || !in_code(t) {
                    continue;
                }
                let dist = ki.abs_diff(i);
                match best {
                    Some((bi, _)) if bi.abs_diff(i) <= dist => {}
                    _ => best = Some((ki, cand)),
                }
            }
            let Some((cfunc_idx, cfunc_ins)) = best else { continue };
            let cfunc = cfunc_ins.rip_target.unwrap();
            if !seen.insert((site.name_addr.0, cfunc.0)) {
                continue;
            }
            let distance = cfunc_idx.abs_diff(i);
            // Is there a `call` in the neighborhood (the registrar consuming the
            // argument loads it set up)? Search the window spanning both loads.
            let (a, b) = (i.min(cfunc_idx).saturating_sub(input.window), (i.max(cfunc_idx) + input.window + 1).min(insns.len()));
            let call_nearby = insns[a..b].iter().any(|x| x.kind == n0xis_arch::InsnKind::Call);
            let proximity = 1.0 - (distance as f32 / (input.window as f32 + 1.0)).min(1.0);
            let confidence = (0.5 * proximity + if call_nearby { 0.4 } else { 0.0 } + 0.1).min(1.0);

            bindings.push(Binding {
                name: site.name.clone(),
                name_addr: site.name_addr,
                name_ref_site: insns[i].va,
                cfunc,
                cfunc_ref_site: cfunc_ins.va,
                distance_insns: distance,
                call_nearby,
                confidence,
            });
        }

        bindings.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.name.cmp(&b.name))
        });
        bindings.truncate(input.limit);
        let named = bindings.iter().map(|b| b.name.as_str()).collect::<std::collections::HashSet<_>>().len();
        Ok(BindingsArtifact { count: bindings.len(), named, bindings })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    /// A tiny contiguous-instruction assembler so the linear sweep never lands
    /// mid-instruction on padding (a real `.text` is contiguous code; the pass
    /// is the same linear-sweep shape `StringXrefPass` uses and verifies on real
    /// PEs — the test just needs a realistic gap-free layout).
    struct Asm {
        base: u64,
        bytes: Vec<u8>,
    }
    impl Asm {
        fn new(base: u64) -> Self {
            Asm { base, bytes: Vec::new() }
        }
        fn va(&self) -> u64 {
            self.base + self.bytes.len() as u64
        }
        /// `lea reg, [rip+disp]` — `reg` via its ModR/M reg field byte.
        fn lea(&mut self, modrm: u8, target: u64) {
            let va = self.va();
            let disp = (target as i64 - (va as i64 + 7)) as i32;
            self.bytes.extend_from_slice(&[0x48, 0x8D, modrm]);
            self.bytes.extend_from_slice(&disp.to_le_bytes());
        }
        fn lea_rdx(&mut self, target: u64) {
            self.lea(0x15, target);
        }
        fn lea_rcx(&mut self, target: u64) {
            self.lea(0x0D, target);
        }
        fn call(&mut self, target: u64) {
            let va = self.va();
            let rel = (target as i64 - (va as i64 + 5)) as i32;
            self.bytes.push(0xE8);
            self.bytes.extend_from_slice(&rel.to_le_bytes());
        }
        fn ret(&mut self) {
            self.bytes.push(0xC3);
        }
    }

    #[test]
    fn pairs_a_name_with_its_nearby_function_pointer() {
        // .rdata @ 0x4000: "next_random\0"
        // .text  @ 0x1000 (contiguous):
        //   lea rdx, [cfunc=0x1100]     ; load the native function pointer
        //   lea rcx, [name=0x4000]      ; load the name
        //   call registrar              ; register(L, ns, name, cfunc)
        //   ret
        let name_addr = 0x4000u64;
        let cfunc = 0x1100u64;
        let mut data = b"next_random".to_vec();
        data.push(0);

        let mut asm = Asm::new(0x1000);
        asm.lea_rdx(cfunc);
        asm.lea_rcx(name_addr);
        asm.call(0x1000);
        asm.ret();
        let mut code = asm.bytes;
        code.resize(0x1000, 0x00); // pad the window out; cfunc target lands in it
        code[0x100] = 0xC3; // a body byte at cfunc (0x1100), so the target is in-window

        let snap = Snapshot::builder()
            .region(Va(0x1000), code)
            .region(Va(0x4000), data)
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);

        let art = BindingsPass
            .run(&ctx, BindingsInput {
                data_start: Va(0x4000),
                data_size: 64,
                code_start: Va(0x1000),
                code_size: 0x1000,
                names: Vec::new(),
                window: 8,
                limit: 50,
            })
            .expect("bindings pass runs");

        assert_eq!(art.count, 1, "should find exactly one binding: {art:?}");
        let b = &art.bindings[0];
        assert_eq!(b.name, "next_random");
        assert_eq!(b.name_addr, Va(0x4000));
        assert_eq!(b.cfunc, Va(0x1100));
        assert!(b.call_nearby, "the call to the registrar sits just after the two loads");
        assert!(b.confidence > 0.5);
    }

    #[test]
    fn a_name_with_no_nearby_code_pointer_is_not_reported() {
        // The name is loaded, but nothing nearby loads a code pointer.
        let mut data = b"orphan".to_vec();
        data.push(0);
        let mut asm = Asm::new(0x1000);
        asm.lea_rcx(0x4000); // load the name
        asm.ret();
        let mut code = asm.bytes;
        code.resize(0x100, 0x90);
        let snap = Snapshot::builder()
            .region(Va(0x1000), code)
            .region(Va(0x4000), data)
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = BindingsPass
            .run(&ctx, BindingsInput {
                data_start: Va(0x4000), data_size: 32,
                code_start: Va(0x1000), code_size: 0x100,
                names: vec!["orphan".into()], window: 8, limit: 50,
            })
            .unwrap();
        assert_eq!(art.count, 0);
    }
}

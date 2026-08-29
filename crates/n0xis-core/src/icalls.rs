//! `il2cpp icalls` — recover Unity's engine internal-call table from the code
//! that resolves it (ROADMAP Phase 12, item 4).
//!
//! ## Why this is not `bindings list`
//!
//! `bindings list` pairs a name string with a **function pointer loaded nearby**
//! — the shape of `luaL_Reg` and most embedded-VM registrars. IL2CPP does not
//! have that shape, and measuring it is what settled the question: a byte search
//! for pointers to a known icall name string found **zero** anywhere in the
//! image. There is no static `{name, fn}` table to read.
//!
//! What the emitted code does instead, measured on a real Unity build:
//!
//! ```text
//! lea  rcx, "UnityEngine.Transform::get_position_Injected(UnityEngine.Vector3&)"
//! call <resolver>              ; il2cpp::vm::InternalCalls::Resolve
//! test rax, rax
//! je   <fallback>
//! mov  [<slot in .data>], rax  ; cache the resolved pointer
//! ```
//!
//! So the name is static, the pointer is not — it exists only once the process
//! has resolved it. That makes this pass do something more useful than a table
//! read: it recovers **name → cache-slot**, statically, and the slot is a stable
//! module-relative address. Read those slots in a running game and you have the
//! engine's native functions with their real addresses *and* their real names —
//! on a target whose standing description is "no symbols on `--pid`".
//!
//! Measured across three Unity builds (metadata v24, v29, v31): the shape holds
//! on all three — 3447, 4041 and 50 875 resolution sites respectively. An
//! earlier measurement said 72, 0 and 1074 and was wrong in the same way three
//! times: the code sweep stopped at the first byte that did not decode, which on
//! a 61 MB section is the first jump table (see [`Arch::decode_range`]).
//!
//! ## Portability, stated plainly
//!
//! The name test (`Namespace.Type::Method`) is a Unity fact and holds anywhere.
//! The *store* test is not: it matches `mov [rip+disp], rax` by the formatted
//! instruction text, so it is **x64-specific** and will match nothing on an
//! ARM64 Unity build (Android, iOS). Such a target still gets its icall names
//! and resolver calls — every entry simply comes back slotless, which is
//! reported rather than hidden, but the live half is unavailable until an
//! ARM64 store pattern is added.
//!
//! ## What it does not claim
//!
//! Like [`BindingsPass`](crate::bindings::BindingsPass) this is a **shape
//! matcher with a stated confidence**, not a model of libil2cpp. It recognizes
//! "load a `Namespace.Type::Method` string, then store `rax` to a data slot
//! within a few instructions". A name found without a store is still reported —
//! knowing the game references `Transform::get_position_Injected` is worth
//! something even when the caching shape differs — but it is reported *as*
//! slotless rather than paired with a guess.

use n0xis_contracts::Va;
use serde::Serialize;

use crate::{CoreError, Ctx, Pass};

/// Instructions to look ahead from a name load for the caching store. The
/// measured shape puts it 4 instructions out; the allowance covers a resolver
/// call with a different guard sequence without wandering into the next site.
pub const DEFAULT_WINDOW: usize = 12;

/// Shortest and longest plausible icall name. The lower bound rejects stray
/// two-character strings that happen to contain `::`; the upper one is generous
/// next to real signatures, which carry their parameter list.
const MIN_NAME: usize = 8;
const MAX_NAME: usize = 512;

#[derive(Clone, Debug)]
pub struct IcallInput {
    /// Window searched for candidate name strings (typically `.rdata`).
    pub data_start: Va,
    pub data_size: usize,
    /// Window decoded for resolution sites (a code section).
    pub code_start: Va,
    pub code_size: usize,
    /// Window a caching store must land in to count (typically `.data`). A zero
    /// size means "accept any RIP-relative store target outside the code
    /// window", for callers that cannot resolve the section.
    pub slot_start: Va,
    pub slot_size: usize,
    /// Instructions to look ahead from the name load for the store.
    pub window: usize,
    pub limit: usize,
}

/// One recovered internal call.
#[derive(Clone, Debug, Serialize)]
pub struct Icall {
    /// The registration name, e.g. `UnityEngine.Transform::get_position_Injected`.
    /// Kept verbatim, signature and all — it is the key the runtime resolves on.
    pub name: String,
    /// Where the name string lives.
    pub name_addr: Va,
    /// The `lea reg,[name]` that loads it.
    pub site: Va,
    /// The resolver the site calls, when the call is direct. Several thousand
    /// sites calling **one** address is the strongest evidence that the shape
    /// was matched correctly, so it is reported rather than assumed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolver: Option<Va>,
    /// The `.data` slot the resolved pointer is cached into — the address to
    /// read in a live process to turn this name into a real function address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<Va>,
    /// Instruction distance from the name load to the store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distance_insns: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct IcallArtifact {
    /// How many icall-shaped names the *data* window holds, independent of
    /// whether any code was found loading them.
    ///
    /// It exists because of a wrong conclusion it would have prevented. A build
    /// reported 1911 names and **zero** sites, and that was taken as evidence
    /// that it resolved icalls by some other mechanism. It did not: the code
    /// sweep was dying at the first jump table and never reached the 4041 sites
    /// that were there (see [`n0xis_arch::Arch::decode_range`]). A bare
    /// `count: 0` cannot be argued with; `names_in_data` beside it turns the
    /// zero into a question — the names are here, so where did the sweep go?
    pub names_in_data: usize,
    pub count: usize,
    /// How many of `icalls` carry a cache slot — the ones a live read can turn
    /// into addresses. Stated separately because the difference is the whole
    /// usefulness of the result.
    pub with_slot: usize,
    /// Distinct direct call targets across all sites, most-used first. One
    /// dominant address is the resolver; more than a couple means the shape
    /// matched something else too, and the caller should look before trusting.
    pub resolvers: Vec<ResolverCount>,
    pub icalls: Vec<Icall>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResolverCount {
    pub va: Va,
    pub sites: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct IcallPass;

/// Read a NUL-terminated icall registration name at `off`.
///
/// The distinguishing mark is `::` — a managed `Namespace.Type::Method`. Plain
/// identifiers are deliberately rejected: `.rdata` is full of them and this pass
/// is not a string dump.
fn read_icall_name(data: &[u8], off: usize) -> Option<String> {
    let first = *data.get(off)?;
    if first != b'_' && !first.is_ascii_alphabetic() {
        return None;
    }
    let end = data[off..].iter().position(|&c| c == 0)? + off;
    let len = end - off;
    if !(MIN_NAME..=MAX_NAME).contains(&len) {
        return None;
    }
    let s = std::str::from_utf8(&data[off..end]).ok()?;
    if !s.contains("::") || !s.is_ascii() {
        return None;
    }
    // A real name is printable throughout; a random `::` inside binary data is
    // not.
    if s.bytes().any(|b| !(0x20..0x7f).contains(&b)) {
        return None;
    }
    Some(s.to_string())
}

impl Pass for IcallPass {
    type In = IcallInput;
    type Out = IcallArtifact;

    fn name(&self) -> &'static str {
        "il2cpp.icalls"
    }

    fn run(&self, ctx: &Ctx, input: IcallInput) -> Result<IcallArtifact, CoreError> {
        let data = ctx.source.read(input.data_start, input.data_size)?;
        let code = ctx.source.read(input.code_start, input.code_size)?;
        let insns = ctx.arch.decode_range(&code, input.code_start, code.len());

        let data_lo = input.data_start.0;
        let data_hi = data_lo.saturating_add(data.len() as u64);
        let code_lo = input.code_start.0;
        let code_hi = code_lo.saturating_add(input.code_size as u64);
        let slot_lo = input.slot_start.0;
        let slot_hi = slot_lo.saturating_add(input.slot_size as u64);
        let in_slot_window = |va: Va| {
            if input.slot_size == 0 {
                // No section resolved: accept anything that is not code, which
                // is weaker but still rejects the obvious wrong answer.
                va.0 < code_lo || va.0 >= code_hi
            } else {
                va.0 >= slot_lo && va.0 < slot_hi
            }
        };

        let window = if input.window == 0 { DEFAULT_WINDOW } else { input.window };
        let mut icalls: Vec<Icall> = Vec::new();
        let mut resolver_counts: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();

        for (i, ins) in insns.iter().enumerate() {
            if ins.mnemonic != "lea" {
                continue;
            }
            let Some(t) = ins.rip_target else { continue };
            if t.0 < data_lo || t.0 >= data_hi {
                continue;
            }
            let Some(name) = read_icall_name(&data, (t.0 - data_lo) as usize) else { continue };

            // Walk forward for the resolver call and the caching store. Stop at
            // the next name load: that is the next site, and crossing into it
            // would attribute one call's slot to another's name.
            let mut resolver = None;
            let mut slot = None;
            let mut distance = None;
            for (d, next) in insns.iter().enumerate().skip(i + 1).take(window) {
                let (d, next) = (d - i, next);
                if next.mnemonic == "lea"
                    && next.rip_target.map(|r| r.0 >= data_lo && r.0 < data_hi).unwrap_or(false)
                    && read_icall_name(&data, (next.rip_target.expect("checked").0 - data_lo) as usize).is_some()
                {
                    break;
                }
                if resolver.is_none()
                    && next.kind == n0xis_arch::InsnKind::Call
                    && let Some(target) = next.target
                {
                    resolver = Some(target);
                }
                // The caching store: `mov [rip+disp], rax`. Matched on the
                // formatted text because the decoder's structured form does not
                // distinguish load from store — narrow and documented rather
                // than a silent assumption.
                if next.mnemonic == "mov"
                    && let Some(dest) = next.rip_target
                    && in_slot_window(dest)
                    && next.text.replace(' ', "").ends_with(",rax")
                {
                    slot = Some(dest);
                    distance = Some(d);
                    break;
                }
            }

            if let Some(r) = resolver {
                *resolver_counts.entry(r.0).or_default() += 1;
            }
            icalls.push(Icall { name, name_addr: t, site: ins.va, resolver, slot, distance_insns: distance });
            if input.limit != 0 && icalls.len() >= input.limit {
                break;
            }
        }

        // Count the names the data window holds, so a zero-site result can say
        // which kind of zero it is. One linear walk of NUL-terminated runs.
        let mut names_in_data = 0usize;
        let mut at = 0usize;
        while at < data.len() {
            if read_icall_name(&data, at).is_some() {
                names_in_data += 1;
            }
            match data[at..].iter().position(|&b| b == 0) {
                Some(rel) => at += rel + 1,
                None => break,
            }
        }

        let with_slot = icalls.iter().filter(|c| c.slot.is_some()).count();
        let mut resolvers: Vec<ResolverCount> = resolver_counts.into_iter().map(|(va, sites)| ResolverCount { va: Va(va), sites }).collect();
        resolvers.sort_by(|a, b| b.sites.cmp(&a.sites).then(a.va.0.cmp(&b.va.0)));
        resolvers.truncate(8);

        Ok(IcallArtifact { names_in_data, count: icalls.len(), with_slot, resolvers, icalls })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    /// `lea rcx,[rip+d]` / `call rel32` / `test rax,rax` / `mov [rip+d],rax` —
    /// the measured shape, assembled by hand so the test pins the pattern rather
    /// than a fixture's accident.
    fn image() -> Snapshot {
        // code at 0x1000
        let mut code: Vec<u8> = Vec::new();
        // lea rcx,[rip+0x1000] → target 0x2007 (name string)
        code.extend_from_slice(&[0x48, 0x8D, 0x0D, 0x00, 0x10, 0x00, 0x00]);
        // call rel32 → 0x1100
        code.extend_from_slice(&[0xE8, 0xF4, 0x00, 0x00, 0x00]);
        // test rax,rax
        code.extend_from_slice(&[0x48, 0x85, 0xC0]);
        // mov [rip+0x1fea],rax → target 0x3000 (slot); the instruction ends at
        // 0x1016, and RIP-relative displacements count from there.
        code.extend_from_slice(&[0x48, 0x89, 0x05, 0xEA, 0x1F, 0x00, 0x00]);
        code.push(0xC3);

        let mut data = vec![0u8; 0x100];
        let name = b"UnityEngine.Transform::get_position_Injected\0";
        data[7..7 + name.len()].copy_from_slice(name);

        Snapshot::builder().region(Va(0x1000), code).region(Va(0x2000), data).region(Va(0x3000), vec![0u8; 8]).build()
    }

    #[test]
    fn the_measured_shape_yields_a_name_a_resolver_and_a_slot() {
        let snap = image();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = IcallPass
            .run(
                &ctx,
                IcallInput {
                    data_start: Va(0x2000),
                    data_size: 0x100,
                    code_start: Va(0x1000),
                    code_size: 0x40,
                    slot_start: Va(0x3000),
                    slot_size: 8,
                    window: DEFAULT_WINDOW,
                    limit: 0,
                },
            )
            .unwrap();
        assert_eq!(art.count, 1, "{art:?}");
        let c = &art.icalls[0];
        assert_eq!(c.name, "UnityEngine.Transform::get_position_Injected");
        assert_eq!(c.name_addr, Va(0x2007));
        assert_eq!(c.slot, Some(Va(0x3000)), "the cache slot is the address a live read turns into a function pointer");
        assert_eq!(c.resolver, Some(Va(0x1100)));
        assert_eq!(art.with_slot, 1);
        assert_eq!(art.resolvers[0].sites, 1);
    }

    #[test]
    fn a_plain_identifier_is_not_an_icall_name() {
        // `.rdata` is full of identifiers; only `Namespace.Type::Method` counts.
        // Without this the pass degenerates into a string dump with extra steps.
        let mut data = vec![0u8; 0x100];
        data[7..7 + 12].copy_from_slice(b"just_a_name\0");
        assert!(read_icall_name(&data, 7).is_none());
        assert!(read_icall_name(b"A::b\0", 0).is_none(), "too short to be a real registration name");
        let long = b"UnityEngine.Object::Internal_CloneSingle\0";
        assert_eq!(read_icall_name(long, 0).as_deref(), Some("UnityEngine.Object::Internal_CloneSingle"));
    }

    #[test]
    fn a_name_with_no_caching_store_is_reported_as_slotless_not_dropped() {
        // Knowing the game references an engine call is worth reporting even
        // when the caching shape differs — but it must not be paired with a
        // guessed slot.
        let mut code: Vec<u8> = Vec::new();
        code.extend_from_slice(&[0x48, 0x8D, 0x0D, 0x00, 0x10, 0x00, 0x00]); // lea rcx,[0x2007]
        code.push(0xC3);
        let mut data = vec![0u8; 0x100];
        let name = b"UnityEngine.Transform::get_position_Injected\0";
        data[7..7 + name.len()].copy_from_slice(name);
        let snap = Snapshot::builder().region(Va(0x1000), code).region(Va(0x2000), data).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = IcallPass
            .run(
                &ctx,
                IcallInput {
                    data_start: Va(0x2000),
                    data_size: 0x100,
                    code_start: Va(0x1000),
                    code_size: 0x20,
                    slot_start: Va(0x3000),
                    slot_size: 8,
                    window: DEFAULT_WINDOW,
                    limit: 0,
                },
            )
            .unwrap();
        assert_eq!(art.count, 1);
        assert_eq!(art.icalls[0].slot, None);
        assert_eq!(art.with_slot, 0, "the count that matters is stated separately, so a slotless result cannot look like a usable one");
    }
}

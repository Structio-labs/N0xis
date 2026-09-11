// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `il2cpp klass` / `il2cpp obj` — read the **runtime** type system of a running
//! IL2CPP game, with no metadata parser and no external dumper
//! (ROADMAP Phase 12, item 4 — the live klass route).
//!
//! ## Why the runtime, when there is a metadata file right there
//!
//! Three reasons, in order of how often they bite:
//!
//! 1. **It survives on-disk encryption.** A packed `global-metadata.dat` is one of
//!    the two common defenses; the process decrypts it to run at all.
//! 2. **Its field offsets are the authoritative ones.** From metadata v24.5 the
//!    offsets live in the binary's registration, and generic-instance layouts are
//!    computed at run time — the `.dat` alone is not the answer for either.
//! 3. **It answers the question a scan actually leaves you with.** A scan gives an
//!    address. `*(void**)addr` is the object's `Il2CppClass*`, and from there the
//!    class name and every field name and offset follow. Address → `PlayerHealth`
//!    → `currentHp` at `+0x38`, in one step instead of an afternoon.
//!
//! ## The layout problem, and how this avoids hardcoding it
//!
//! `Il2CppClass` and `FieldInfo` shift between Unity versions, and the sub-version
//! is not recorded anywhere. Hardcoding offsets is what makes every tool in this
//! space fragile, and the failure is silent: a wrong offset yields a plausible
//! wrong name.
//!
//! So the *class* layout is **discovered and then validated against invariants
//! that a wrong guess cannot satisfy**:
//!
//! - `Il2CppClass` carries `const char* name` and `const char* namespaze` in
//!   **adjacent** pointer slots. Two consecutive slots that both dereference to
//!   NUL-terminated printable identifiers is a shape random data does not take.
//! - `FieldInfo` is `{ const char* name; Il2CppType* type; Il2CppClass* parent;
//!   int32_t offset; int32_t token; }`, and **`parent` points back at the class
//!   being examined**. That back-reference is the strong invariant: a candidate
//!   array either satisfies it or the guess was wrong, with no middle ground.
//!
//! Every result reports the offsets it discovered, so the reader can see *why*
//! the tool believes it, and a target whose layout does not validate is
//! **refused** rather than decoded into confident nonsense (CONCEPT §3 rule 6).
//!
//! ## What *is* assumed here, stated plainly
//!
//! Two things, and pretending otherwise would be the same overstatement this
//! module exists to avoid:
//!
//! - **`FieldInfo`'s internal offsets** — `parent` at `+0x10`, `offset` at
//!   `+0x18` — are fixed, and Unity's headers say they have been in every
//!   version from v16 to v110. The *stride* is **not** assumed: it is 0x28 on
//!   pre-Unity-2018.3 builds and 0x20 since, so it is measured per class (see
//!   [`FIELD_ENTRY_STRIDES`]) and reported.
//! - **64-bit, little-endian.** Pointers are read as 8 bytes throughout. A
//!   32-bit IL2CPP build (Android `armeabi-v7a`, WebGL `wasm32`) halves every
//!   offset here — `name` at `0x08`, `fields` at `0x40`, `FieldInfo` stride
//!   `0x14` — and that path does not exist yet; such a target finds nothing
//!   rather than mis-decoding, but "found nothing" is the wrong answer there.

use n0xis_contracts::Va;
use serde::Serialize;

use crate::{CoreError, Ctx, Pass};

/// How far into `Il2CppClass` to look for the name pair and the field array.
/// Generous next to every published layout; small enough to stay cheap.
const DEFAULT_PROBE: usize = 0x120;
/// `FieldInfo` strides to try, on x64, in preference order.
///
/// **Not one number, because it is not one struct.** Unity's own headers give
/// three historical shapes, and the middle one is 8 bytes wider:
///
/// - metadata v16 — `{name,type,parent,offset,customAttributeIndex}` = `0x20`
/// - metadata v19..v24 up to Unity 2018.2 — the same plus `token` = **`0x28`**
/// - metadata v24.1+ (Unity 2018.3 →) — `customAttributeIndex` dropped = `0x20`
///
/// `parent` and `offset` sit at the same place in all three, so a single entry
/// decodes correctly under any stride; it is the *walk* that desynchronizes.
/// So the stride is **measured** — the one under which the second entry also
/// back-references the class — and reported, never assumed.
const FIELD_ENTRY_STRIDES: [usize; 2] = [0x20, 0x28];
/// The stride used when a class has too few fields to distinguish them.
const FIELD_ENTRY: usize = 0x20;
/// Offset of `parent` within a `FieldInfo` — the back-reference that validates
/// the whole guess.
const FIELD_PARENT: usize = 0x10;
/// Offset of the `int32_t offset` within a `FieldInfo`.
const FIELD_OFFSET: usize = 0x18;
/// A managed field cannot sit further than this into an object. Bounds the
/// validator without pretending to know the real instance size.
const MAX_FIELD_OFFSET: i64 = 0x10_000;
/// Refuse to walk a field array longer than this — a mis-validated array would
/// otherwise walk forever.
const MAX_FIELDS: usize = 512;
/// Longest name accepted from the target.
const MAX_NAME: usize = 128;

#[derive(Clone, Debug)]
pub struct KlassInput {
    /// An object address (its `Il2CppClass*` is read from offset 0) or a class
    /// address directly — both are tried, and which one answered is reported.
    pub addr: Va,
    /// Read this many bytes at `object` for field values. 0 = no value read.
    pub read_values: usize,
    pub probe: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct KlassField {
    pub name: String,
    /// Byte offset from the start of the object, as the runtime states it.
    pub offset: i64,
    /// The field's bytes, when an object address was resolved and the read
    /// reached that far. Absent means "not read", never "zero".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// Where the layout was found. Reported so a reader can audit the inference
/// instead of taking the names on faith.
#[derive(Clone, Debug, Serialize)]
pub struct LayoutEvidence {
    /// Offset within `Il2CppClass` of the `name` pointer (`namespaze` follows it).
    pub name_offset: usize,
    /// Offset within `Il2CppClass` of the `fields` pointer, when found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields_offset: Option<usize>,
    /// How many field entries satisfied the `parent == klass` back-reference.
    pub fields_validated: usize,
    /// Offset of the class's pointer to **itself** — Unity's `klass` field,
    /// "points to ourself". Its presence is near-conclusive; its absence means
    /// a pre-Unity-2018.1 layout, not a refutation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_pointer_offset: Option<usize>,
    /// The `FieldInfo` stride that was **measured**, not assumed: `0x28` on
    /// pre-Unity-2018.3 builds, `0x20` since.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_stride: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct KlassArtifact {
    /// The address the caller passed.
    pub queried: Va,
    /// The object, when `queried` turned out to be one (its klass pointer
    /// validated). Absent when the caller passed a class directly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<Va>,
    pub klass: Va,
    pub namespace: String,
    pub name: String,
    pub field_count: usize,
    pub fields: Vec<KlassField>,
    pub layout: LayoutEvidence,
    /// `"validated"` when a `FieldInfo[]` pointed back at this class, otherwise
    /// `"weak-name-pair-only"` — the name shape alone matches non-class
    /// structures too, so the distinction is load-bearing, not decoration.
    pub confidence: &'static str,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct KlassPass;

/// One way of reading the queried address: `(the object if it was one, the
/// class, its discovered name triple)`.
type Reading = (Option<Va>, Va, (usize, String, String));

fn read_u64(ctx: &Ctx, at: Va) -> Option<u64> {
    let b = ctx.source.read(at, 8).ok()?;
    (b.len() == 8).then(|| u64::from_le_bytes(b[..8].try_into().expect("8 bytes")))
}

/// Read a NUL-terminated identifier at `at`, or `None` if it is not one.
///
/// "Identifier" is deliberately narrow — a managed type or field name — because
/// the whole layout discovery rests on random data *not* looking like this.
fn read_name(ctx: &Ctx, at: Va) -> Option<String> {
    if at.0 == 0 {
        return None;
    }
    let bytes = ctx.source.read(at, MAX_NAME).ok()?;
    let end = bytes.iter().position(|&b| b == 0)?;
    if end == 0 {
        return None;
    }
    let s = std::str::from_utf8(&bytes[..end]).ok()?;
    let ok_first = s.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_' || c == '<');
    let ok_rest = s.chars().all(|c| c.is_ascii_alphanumeric() || "_<>`.[]".contains(c));
    (ok_first && ok_rest).then(|| s.to_string())
}

/// Verdict on how much the layout discovery actually proved.
///
/// Measured against a running game, and it changed the design: an adjacent
/// string-pointer pair is **not** enough on its own. `Il2CppImage` opens with
/// `{ const char* name; const char* nameNoExt; }`, so an image matched the name
/// shape and came back as a class called `mscorlib.mscorlib.dll`; unrelated
/// structures produced stray pairs too. Every *true* class hit — and no false
/// one — also yielded a `FieldInfo[]` whose entries point back at it.
///
/// So the back-reference is the evidence, and a result without it has to say so
/// rather than read like a fact.
pub const VALIDATED: &str = "validated";
pub const WEAK: &str = "weak-name-pair-only";

/// The candidate structure's own bytes, read **once**.
///
/// The probe walks up to `probe/8` slots and the field walk another
/// `MAX_FIELDS`, so reading eight bytes at a time meant ~70 `ReadProcessMemory`
/// calls per candidate. At the enumerator's default probe budget that is most
/// of a million syscalls, which does not look like slow — it looks like a hang.
/// One read up front, then slot access is arithmetic.
fn slots_of(ctx: &Ctx, base: Va, probe: usize) -> Vec<u64> {
    let Ok(bytes) = ctx.source.read(base, probe) else { return Vec::new() };
    bytes.as_chunks::<8>().0.iter().map(|c| u64::from_le_bytes(*c)).collect()
}

/// The slot holding the class's pointer **to itself**, if there is one.
///
/// Unity's own comment on the field, verbatim in the runtime headers:
/// `Il2CppClass* klass; // hack to pretend we are a MonoVTable. Points to
/// ourself`. Present since Unity 2018.1.0, at `+0x78` on x64.
///
/// This is the strongest discriminator available and it costs **nothing**: the
/// candidate's bytes are already in hand, so it is a comparison, not a read.
/// Both facts matter.
///
/// - *Correctness*: `Il2CppImage` also opens with two adjacent `const char*`
///   (`name`, `nameNoExt`, since the same Unity 2018.1.0), which is why a
///   name-pair-only scan reported an image as a class called
///   `mscorlib.mscorlib.dll`. An image has no pointer to itself in its header.
/// - *Cost*: rejecting on arithmetic means the overwhelming majority of
///   candidates never trigger a single string read. That is the difference
///   between a scan that finishes and one that looks like a hang.
///
/// Returns `None` on pre-2018.1 layouts, which simply have no such field — so
/// callers treat its absence as "no evidence", never as "not a class".
fn self_pointer_index(slots: &[u64], base: Va) -> Option<usize> {
    slots.iter().position(|&v| v == base.0)
}

/// Distance from `name` to the self-pointer, in slots.
///
/// `name` is at `0x10` and `klass` at `0x78` on x64 in **every** layout from
/// Unity 2018.1.0 through 6000.7 — the two most stable landmarks in the struct.
/// So the self-pointer is not merely a filter, it is an **anchor**: find it, and
/// the name pair's position follows by arithmetic.
///
/// That matters for cost, not elegance. A self-pointer alone has false
/// positives — an empty intrusive list head points at itself too — and each one
/// used to pay for a full 36-slot sweep of string reads. Anchoring turns the
/// common case into two reads.
const SELF_PTR_SLOTS_AFTER_NAME: usize = (0x78 - 0x10) / 8;

/// The name pair implied by a self-pointer at `idx`, if the anchor holds.
fn name_pair_from_anchor(ctx: &Ctx, slots: &[u64], idx: usize) -> Option<(usize, String, String)> {
    name_pair_at(ctx, slots, idx.checked_sub(SELF_PTR_SLOTS_AFTER_NAME)?)
}

/// The `name` / `namespaze` pair at one candidate slot index, if it is one.
fn name_pair_at(ctx: &Ctx, slots: &[u64], idx: usize) -> Option<(usize, String, String)> {
    let name_ptr = *slots.get(idx)?;
    let name = read_name(ctx, Va(name_ptr))?;
    // `namespaze` sits immediately after `name`. An empty namespace is legal
    // and common (the global namespace), and IL2CPP stores it as a pointer to
    // an empty string rather than NULL — so the slot must be *readable*, not
    // necessarily non-empty.
    let ns_ptr = *slots.get(idx + 1)?;
    let ns = match read_name(ctx, Va(ns_ptr)) {
        Some(s) => s,
        None => match ctx.source.read(Va(ns_ptr), 1) {
            Ok(b) if b.first() == Some(&0) => String::new(),
            _ => return None,
        },
    };
    Some((idx * 8, ns, name))
}

/// The first adjacent `name` / `namespaze` pair inside a candidate class.
fn discover_names(ctx: &Ctx, klass: Va, probe: usize) -> Option<(usize, String, String)> {
    let slots = slots_of(ctx, klass, probe);
    (0..slots.len()).find_map(|i| name_pair_at(ctx, &slots, i))
}

/// A decoded field array: `(offset of the `fields` pointer, measured stride,
/// the fields themselves)`.
type FieldTable = (usize, usize, Vec<(String, i64)>);

/// Find the `FieldInfo[]` pointer by the `parent == klass` back-reference.
fn discover_fields(ctx: &Ctx, klass: Va, probe: usize) -> Option<FieldTable> {
    let slots = slots_of(ctx, klass, probe);
    for (idx, arr) in slots.iter().copied().enumerate() {
        let off = idx * 8;
        if arr == 0 {
            continue;
        }
        // One read for the first entry decides whether this slot is the field
        // array at all — the overwhelmingly common answer is "no", so paying
        // for a bulk read of the whole array before that check would be worse,
        // not better. `parent` sits at the same place under every stride, so
        // this check does not depend on knowing it yet.
        let Ok(head) = ctx.source.read(Va(arr), FIELD_ENTRY) else { continue };
        if head.len() < FIELD_ENTRY || u64::from_le_bytes(head[FIELD_PARENT..FIELD_PARENT + 8].try_into().expect("8 bytes")) != klass.0 {
            continue;
        }
        // It is. Now the bulk read pays for itself — and the stride gets
        // *measured*: whichever candidate makes the second entry back-reference
        // the class too is the real one. A class with a single field cannot
        // distinguish them, and then the modern stride stands in.
        let Ok(table) = ctx.source.read(Va(arr), MAX_FIELDS * FIELD_ENTRY_STRIDES[1]) else { continue };
        let back_refs = |stride: usize| {
            table
                .get(stride + FIELD_PARENT..stride + FIELD_PARENT + 8)
                .map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")) == klass.0)
                .unwrap_or(false)
        };
        let stride = FIELD_ENTRY_STRIDES.into_iter().find(|s| back_refs(*s)).unwrap_or(FIELD_ENTRY);

        let mut out: Vec<(String, i64)> = Vec::new();
        for entry in table.chunks_exact(stride) {
            let name_ptr = u64::from_le_bytes(entry[..8].try_into().expect("8 bytes"));
            let Some(name) = read_name(ctx, Va(name_ptr)) else { break };
            // The invariant the whole guess rests on.
            if u64::from_le_bytes(entry[FIELD_PARENT..FIELD_PARENT + 8].try_into().expect("8 bytes")) != klass.0 {
                break;
            }
            let field_off = i32::from_le_bytes(entry[FIELD_OFFSET..FIELD_OFFSET + 4].try_into().expect("4 bytes")) as i64;
            if !(0..MAX_FIELD_OFFSET).contains(&field_off) {
                break;
            }
            out.push((name, field_off));
        }
        if !out.is_empty() {
            return Some((off, stride, out));
        }
    }
    None
}

impl Pass for KlassPass {
    type In = KlassInput;
    type Out = KlassArtifact;

    fn name(&self) -> &'static str {
        "il2cpp.klass"
    }

    fn run(&self, ctx: &Ctx, input: KlassInput) -> Result<KlassArtifact, CoreError> {
        let probe = if input.probe == 0 { DEFAULT_PROBE } else { input.probe };

        // Two readings of the same address: it is an object (its first word is
        // the class) or it is the class. Both are legitimate, and "this address
        // is an object of type X" and "this address is X" are different facts,
        // so which one answered is part of the result.
        //
        // **Trying the object reading first and stopping there is wrong**, and
        // the live run proved it: `Il2CppClass` opens with `Il2CppImage* image`,
        // and an image's own first two fields are a name pair — so a *class*
        // address read as an object produced a class called
        // `mscorlib.mscorlib.dll`. The interpretation therefore has to meet the
        // same evidence bar as everything else here: prefer whichever reading
        // yields a back-referencing field array, and only fall back to a bare
        // name pair when neither does.
        let as_object = read_u64(ctx, input.addr).map(Va).and_then(|k| discover_names(ctx, k, probe).map(|n| (Some(input.addr), k, n)));
        let as_class = discover_names(ctx, input.addr, probe).map(|n| (None, input.addr, n));
        let validates = |candidate: &Option<Reading>| candidate.as_ref().is_some_and(|(_, k, _)| discover_fields(ctx, *k, probe).is_some());

        let chosen = if validates(&as_object) {
            as_object
        } else if validates(&as_class) {
            as_class
        } else {
            as_object.or(as_class)
        };
        let (object, klass, (name_offset, namespace, name)) = chosen.ok_or_else(|| {
            CoreError::Other(format!(
                "{} is neither a managed object nor an Il2CppClass: no adjacent name/namespace pointer pair validated within {probe:#x} bytes. \
                 Reading a live IL2CPP process is required — a static image has no runtime type structures at all",
                input.addr
            ))
        })?;

        let discovered = discover_fields(ctx, klass, probe);
        let fields_offset = discovered.as_ref().map(|(o, _, _)| *o);
        let field_stride = discovered.as_ref().map(|(_, st, _)| *st);
        let self_pointer_offset = self_pointer_index(&slots_of(ctx, klass, probe), klass).map(|i| i * 8);
        let raw_fields = discovered.map(|(_, _, f)| f).unwrap_or_default();
        let confidence = if raw_fields.is_empty() && self_pointer_offset.is_none() { WEAK } else { VALIDATED };

        // Field values only mean anything when the address really was an object.
        let obj_bytes = match (object, input.read_values) {
            (Some(o), n) if n > 0 => ctx.source.read(o, n).ok(),
            _ => None,
        };
        let fields: Vec<KlassField> = raw_fields
            .into_iter()
            .map(|(fname, offset)| {
                let value = obj_bytes.as_ref().and_then(|b| {
                    let at = offset as usize;
                    b.get(at..at + 8).map(|w| format!("0x{:016x}", u64::from_le_bytes(w.try_into().expect("8 bytes"))))
                });
                KlassField { name: fname, offset, value }
            })
            .collect();

        Ok(KlassArtifact {
            queried: input.addr,
            object,
            klass,
            namespace,
            name,
            field_count: fields.len(),
            layout: LayoutEvidence { name_offset, fields_offset, fields_validated: fields.len(), self_pointer_offset, field_stride },
            fields,
            confidence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    /// A synthetic runtime: an object at 0x1000 pointing at a class at 0x2000,
    /// whose name pair sits at +0x10 and whose `FieldInfo[]` sits at +0x30 —
    /// none of which the pass is told.
    fn runtime() -> Snapshot {
        let mut obj = vec![0u8; 0x40];
        obj[0..8].copy_from_slice(&0x2000u64.to_le_bytes()); // klass
        obj[0x18..0x20].copy_from_slice(&99u64.to_le_bytes()); // currentHp at +0x18

        let mut klass = vec![0u8; 0x100];
        klass[0x10..0x18].copy_from_slice(&0x3000u64.to_le_bytes()); // name
        klass[0x18..0x20].copy_from_slice(&0x3020u64.to_le_bytes()); // namespaze
        klass[0x30..0x38].copy_from_slice(&0x4000u64.to_le_bytes()); // fields

        let mut strs = vec![0u8; 0x60];
        strs[0..12].copy_from_slice(b"PlayerHealth");
        strs[0x20..0x25].copy_from_slice(b"Game\0");

        // Two FieldInfo entries, then a terminator whose parent is wrong.
        let mut fields = vec![0u8; 3 * FIELD_ENTRY];
        let mk = |buf: &mut [u8], i: usize, name_va: u64, parent: u64, off: i32| {
            let b = i * FIELD_ENTRY;
            buf[b..b + 8].copy_from_slice(&name_va.to_le_bytes());
            buf[b + FIELD_PARENT..b + FIELD_PARENT + 8].copy_from_slice(&parent.to_le_bytes());
            buf[b + FIELD_OFFSET..b + FIELD_OFFSET + 4].copy_from_slice(&off.to_le_bytes());
        };
        mk(&mut fields, 0, 0x5000, 0x2000, 0x18);
        mk(&mut fields, 1, 0x5010, 0x2000, 0x20);
        mk(&mut fields, 2, 0x5020, 0xDEAD, 0x28); // wrong parent → stop here

        let mut fnames = vec![0u8; 0x40];
        fnames[0..11].copy_from_slice(b"currentHp\0\0");
        fnames[0x10..0x18].copy_from_slice(b"maxHp\0\0\0");
        fnames[0x20..0x28].copy_from_slice(b"ghost\0\0\0");

        Snapshot::builder()
            .region(Va(0x1000), obj)
            .region(Va(0x2000), klass)
            .region(Va(0x3000), strs)
            .region(Va(0x4000), fields)
            .region(Va(0x5000), fnames)
            .build()
    }

    fn run(addr: Va, read_values: usize) -> Result<KlassArtifact, CoreError> {
        let snap = runtime();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        KlassPass.run(&ctx, KlassInput { addr, read_values, probe: 0 })
    }

    #[test]
    fn an_object_address_yields_its_class_and_field_names() {
        let art = run(Va(0x1000), 0x40).unwrap();
        assert_eq!(art.object, Some(Va(0x1000)), "a scan hands you an object, and that is the default reading");
        assert_eq!(art.klass, Va(0x2000));
        assert_eq!(art.name, "PlayerHealth");
        assert_eq!(art.namespace, "Game");
        assert_eq!(art.fields.len(), 2);
        assert_eq!(art.fields[0].name, "currentHp");
        assert_eq!(art.fields[0].offset, 0x18);
        assert_eq!(art.fields[0].value.as_deref(), Some("0x0000000000000063"), "the field's live bytes, read at the offset the runtime states");
    }

    #[test]
    fn the_discovered_layout_is_reported_as_evidence_not_assumed() {
        // Nothing above told the pass where `name` or `fields` sit; a reader has
        // to be able to audit the inference rather than trust the names.
        let art = run(Va(0x1000), 0).unwrap();
        assert_eq!(art.layout.name_offset, 0x10);
        assert_eq!(art.layout.fields_offset, Some(0x30));
        assert_eq!(art.layout.fields_validated, 2);
        assert_eq!(art.confidence, VALIDATED, "the back-reference held, so the result is evidence rather than a shape match");
    }

    #[test]
    fn the_field_walk_stops_at_the_first_broken_back_reference() {
        // `parent == klass` is the invariant the whole guess rests on. The third
        // entry names a real string but belongs to another class, and must not
        // be reported — that is exactly the shape of a mis-read array.
        let art = run(Va(0x1000), 0).unwrap();
        assert!(!art.fields.iter().any(|f| f.name == "ghost"), "a field whose parent is not this class is not this class's field: {art:?}");
    }

    #[test]
    fn a_class_address_is_accepted_directly_and_says_so() {
        let art = run(Va(0x2000), 0).unwrap();
        assert_eq!(art.object, None, "'this address is an object of type X' and 'this address is X' are different facts");
        assert_eq!(art.klass, Va(0x2000));
        assert_eq!(art.name, "PlayerHealth");
    }


    #[test]
    fn a_structure_that_only_matches_the_name_shape_is_marked_weak() {
        // Measured on a running game, and it is why the verdict field exists:
        // an Il2CppImage opens with two adjacent string pointers, so it matched
        // the name shape and came back as a class named "mscorlib.mscorlib.dll".
        // It has no FieldInfo array pointing back at it, and that difference is
        // the whole distinction between a fact and a coincidence.
        let image = Snapshot::builder()
            .region(Va(0x8000), {
                let mut b = vec![0u8; 0x40];
                b[0..8].copy_from_slice(&0x9000u64.to_le_bytes());
                b[8..16].copy_from_slice(&0x9010u64.to_le_bytes());
                b
            })
            .region(Va(0x9000), {
                let mut b = vec![0u8; 0x40];
                b[0..12].copy_from_slice(b"mscorlib.dll");
                b[0x10..0x18].copy_from_slice(b"mscorlib");
                b
            })
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&image, &arch);
        let art = KlassPass.run(&ctx, KlassInput { addr: Va(0x8000), read_values: 0, probe: 0 }).unwrap();
        assert_eq!(art.confidence, WEAK, "a name pair with no back-referencing field array is not proof of a class");
        assert_eq!(art.layout.fields_validated, 0);
    }


    #[test]
    fn a_class_address_is_not_mistaken_for_an_object_because_its_image_has_a_name_pair() {
        // The live regression. `Il2CppClass` opens with `Il2CppImage* image`,
        // and an image's own first two fields are a name pair — so reading a
        // *class* address as an object found the image and reported the class
        // as `mscorlib.mscorlib.dll`. Both readings are plausible; only one
        // produces a back-referencing field array, and that is the tiebreak.
        let mut klass = vec![0u8; 0x100];
        klass[0x00..0x08].copy_from_slice(&0x108000u64.to_le_bytes()); // image
        klass[0x10..0x18].copy_from_slice(&0x103000u64.to_le_bytes()); // name
        klass[0x18..0x20].copy_from_slice(&0x103020u64.to_le_bytes()); // namespaze
        klass[0x30..0x38].copy_from_slice(&0x104000u64.to_le_bytes()); // fields

        let mut strs = vec![0u8; 0x60];
        strs[0..15].copy_from_slice(b"PassiveItem_Key");
        strs[0x20] = 0;

        let mut fields = vec![0u8; 2 * FIELD_ENTRY];
        fields[0..8].copy_from_slice(&0x105000u64.to_le_bytes());
        fields[FIELD_PARENT..FIELD_PARENT + 8].copy_from_slice(&0x102000u64.to_le_bytes());
        fields[FIELD_OFFSET..FIELD_OFFSET + 4].copy_from_slice(&0x18i32.to_le_bytes());
        fields[FIELD_ENTRY + FIELD_PARENT..FIELD_ENTRY + FIELD_PARENT + 8].copy_from_slice(&0xDEADu64.to_le_bytes());

        let mut fnames = vec![0u8; 0x20];
        fnames[0..7].copy_from_slice(b"chargeS");

        // The image the class points at: a name pair and nothing more.
        let mut image = vec![0u8; 0x40];
        image[0..8].copy_from_slice(&0x109000u64.to_le_bytes());
        image[8..16].copy_from_slice(&0x109010u64.to_le_bytes());
        let mut inames = vec![0u8; 0x40];
        inames[0..12].copy_from_slice(b"mscorlib.dll");
        inames[0x10..0x18].copy_from_slice(b"mscorlib");

        let snap = Snapshot::builder()
            .region(Va(0x102000), klass)
            .region(Va(0x103000), strs)
            .region(Va(0x104000), fields)
            .region(Va(0x105000), fnames)
            .region(Va(0x108000), image)
            .region(Va(0x109000), inames)
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = KlassPass.run(&ctx, KlassInput { addr: Va(0x102000), read_values: 0, probe: 0 }).unwrap();

        assert_eq!(art.name, "PassiveItem_Key", "the validated reading must win over the plausible one: {art:?}");
        assert_eq!(art.object, None, "this address is the class, not an object of it");
        assert_eq!(art.confidence, VALIDATED);
    }

    #[test]
    fn an_address_that_is_neither_is_refused_with_the_reason() {
        let err = run(Va(0x5000), 0).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("neither a managed object nor an Il2CppClass"), "{msg}");
        assert!(msg.contains("live IL2CPP process"), "the refusal should say what would work: {msg}");
    }
}

// ---------------------------------------------------------------------------
// Finding classes without being handed an address
// ---------------------------------------------------------------------------

/// A pointer must repeat at least this often in the sampled windows before it
/// is worth probing. Every managed object starts with its class pointer, so a
/// real class recurs once per live instance; a one-off value is almost always
/// something else.
const DEFAULT_MIN_HITS: usize = 2;
/// Candidates probed before giving up, unless the caller says otherwise.
const DEFAULT_MAX_PROBE: usize = 2_000;

#[derive(Clone, Debug)]
pub struct ClassScanInput {
    /// Memory windows to sample — typically committed private read-write
    /// regions, i.e. the GC heap.
    pub windows: Vec<(Va, usize)>,
    pub probe: usize,
    pub max_probe: usize,
    pub limit: usize,
    pub min_hits: usize,
    /// Reject candidates with no pointer to themselves before doing any string
    /// work. Correct **and** fast on Unity 2018.1+, which is every metadata
    /// version from 24@2018.1 onward. Turn it off for an older target, where
    /// the field does not exist and its absence proves nothing.
    pub require_self_pointer: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClassSummary {
    pub klass: Va,
    pub namespace: String,
    pub name: String,
    pub field_count: usize,
    /// How many times this pointer appeared in the sampled windows — a rough
    /// popularity signal, **not** an instance count: one object can hold several
    /// references to the same class, and the sample is partial either way.
    pub hits: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClassScanArtifact {
    pub windows_read: usize,
    pub bytes_read: usize,
    /// Distinct pointer-like values seen.
    pub candidates: usize,
    /// How many of them were actually probed — the honest denominator, because
    /// the probe is capped and a capped search must not read as an exhaustive
    /// one.
    pub probed: usize,
    /// Candidates that matched the name shape but produced no back-referencing
    /// field array, and were therefore dropped. Counted rather than hidden: a
    /// large number here means the sample was mostly `Il2CppImage`s and stray
    /// pairs, which is worth knowing.
    pub weak_rejected: usize,
    /// Candidates skipped for having no self-pointer. A scan where this is the
    /// whole probe count and nothing was found is the signature of a
    /// pre-Unity-2018.1 target — re-run without the requirement.
    pub no_self_pointer: usize,
    pub count: usize,
    pub classes: Vec<ClassSummary>,
}

/// Discover live classes by the one property every managed object has: its
/// first word is its `Il2CppClass*`.
///
/// So the most-repeated pointer-like values in a heap sample *are* class
/// pointers, and ranking by frequency puts them first. This is the technique
/// that worked by hand during Phase 12's live verification; building it in is
/// what makes [`KlassPass`] self-sufficient — before it, you had to already
/// possess an address to ask about.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClassScanPass;

impl Pass for ClassScanPass {
    type In = ClassScanInput;
    type Out = ClassScanArtifact;

    fn name(&self) -> &'static str {
        "il2cpp.classes"
    }

    fn run(&self, ctx: &Ctx, input: ClassScanInput) -> Result<ClassScanArtifact, CoreError> {
        let probe = if input.probe == 0 { DEFAULT_PROBE } else { input.probe };
        let max_probe = if input.max_probe == 0 { DEFAULT_MAX_PROBE } else { input.max_probe };
        let min_hits = if input.min_hits == 0 { DEFAULT_MIN_HITS } else { input.min_hits };

        let mut freq: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
        let mut windows_read = 0usize;
        let mut bytes_read = 0usize;
        for (base, size) in &input.windows {
            // A refused or short read is ordinary here — regions come and go in
            // a running process — so it skips rather than failing the scan.
            let Ok(bytes) = ctx.source.read(*base, *size) else { continue };
            windows_read += 1;
            bytes_read += bytes.len();
            for chunk in bytes.as_chunks::<8>().0 {
                let v = u64::from_le_bytes(*chunk);
                // Canonical user-space, pointer-aligned, past the null page.
                if v > 0x1_0000 && v < 0x7fff_ffff_ffff && v.is_multiple_of(8) {
                    *freq.entry(v).or_default() += 1;
                }
            }
        }

        let candidates = freq.len();
        let mut ranked: Vec<(u64, usize)> = freq.into_iter().filter(|(_, n)| *n >= min_hits).collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

        let mut classes: Vec<ClassSummary> = Vec::new();
        let mut probed = 0usize;
        let mut weak_rejected = 0usize;
        let mut no_self_pointer = 0usize;
        for (va, hits) in ranked {
            if probed >= max_probe || (input.limit != 0 && classes.len() >= input.limit) {
                break;
            }
            probed += 1;
            let klass = Va(va);

            // **One read, then arithmetic.** The candidate's own bytes decide
            // whether it is worth any further work: a class points to itself,
            // and that comparison costs nothing. Before this the scan chased
            // every plausible-looking slot with a separate string read — tens
            // of reads per candidate, which at the default probe budget is
            // hundreds of thousands of syscalls and reads as a hang rather than
            // as slowness.
            let slots = slots_of(ctx, klass, probe);
            if slots.is_empty() {
                continue;
            }
            let anchor = self_pointer_index(&slots, klass);
            if input.require_self_pointer && anchor.is_none() {
                no_self_pointer += 1;
                continue;
            }
            // Anchored first: a self-pointer fixes where the name pair must be,
            // so the common case costs two string reads instead of sweeping all
            // 36 slots. The sweep stays as the fallback, because a self-pointer
            // can also be an empty intrusive list head pointing at itself — a
            // real false positive, and the reason the gate alone did not make
            // the scan fast.
            //
            // ⚠️ The anchor is a **fast path, not an authority**, and that was
            // measured the hard way: making a failed anchor end the candidate
            // cut the scan from 15.6 s to 6.3 s and dropped the class count on
            // one v29 build from 35 to **zero**. Whatever those classes are,
            // their name pair is not `0x68` below the first slot that equals the
            // base — most likely because `position` finds the *first* such slot
            // and it is not always the `klass` field. So the sweep stays as the
            // fallback, and the speed-up is only the part that was free.
            let found = anchor
                .and_then(|i| name_pair_from_anchor(ctx, &slots, i))
                .or_else(|| (0..slots.len()).find_map(|i| name_pair_at(ctx, &slots, i)));
            let Some((_, namespace, name)) = found else { continue };
            // The back-reference is the whole test. A name pair alone matches
            // `Il2CppImage` and stray data, so an unvalidated candidate is
            // counted and dropped rather than reported as a class.
            let Some((_, _, fields)) = discover_fields(ctx, klass, probe) else {
                weak_rejected += 1;
                continue;
            };
            classes.push(ClassSummary { klass, namespace, name, field_count: fields.len(), hits });
        }

        Ok(ClassScanArtifact { windows_read, bytes_read, candidates, probed, weak_rejected, no_self_pointer, count: classes.len(), classes })
    }
}

#[cfg(test)]
mod scan_tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    /// A heap window holding three references to a real class and three to an
    /// image-shaped decoy — the exact pair of shapes the live run produced.
    ///
    /// Addresses sit above `0x10000` on purpose: the scanner ignores anything in
    /// the null page region, which is a real-world guard and would otherwise
    /// make this fixture silently untestable.
    fn heap() -> Snapshot {
        let mut heap = vec![0u8; 0x80];
        for (i, va) in [0x102000u64, 0x108000, 0x102000, 0x108000, 0x102000, 0x108000].iter().enumerate() {
            heap[i * 8..i * 8 + 8].copy_from_slice(&va.to_le_bytes());
        }

        let mut klass = vec![0u8; 0x100];
        klass[0x10..0x18].copy_from_slice(&0x103000u64.to_le_bytes());
        klass[0x18..0x20].copy_from_slice(&0x103020u64.to_le_bytes());
        klass[0x30..0x38].copy_from_slice(&0x104000u64.to_le_bytes());

        let mut strs = vec![0u8; 0x60];
        strs[0..12].copy_from_slice(b"PlayerHealth");
        strs[0x20..0x24].copy_from_slice(b"Game");

        let mut fields = vec![0u8; 2 * FIELD_ENTRY];
        fields[0..8].copy_from_slice(&0x105000u64.to_le_bytes());
        fields[FIELD_PARENT..FIELD_PARENT + 8].copy_from_slice(&0x102000u64.to_le_bytes());
        fields[FIELD_OFFSET..FIELD_OFFSET + 4].copy_from_slice(&0x18i32.to_le_bytes());
        fields[FIELD_ENTRY + FIELD_PARENT..FIELD_ENTRY + FIELD_PARENT + 8].copy_from_slice(&0xDEADu64.to_le_bytes());

        let mut fnames = vec![0u8; 0x20];
        fnames[0..9].copy_from_slice(b"currentHp");

        // The decoy: two adjacent string pointers, no field array.
        let mut image = vec![0u8; 0x40];
        image[0..8].copy_from_slice(&0x109000u64.to_le_bytes());
        image[8..16].copy_from_slice(&0x109010u64.to_le_bytes());
        let mut inames = vec![0u8; 0x40];
        inames[0..12].copy_from_slice(b"mscorlib.dll");
        inames[0x10..0x18].copy_from_slice(b"mscorlib");

        Snapshot::builder()
            .region(Va(0x101000), heap)
            .region(Va(0x102000), klass)
            .region(Va(0x103000), strs)
            .region(Va(0x104000), fields)
            .region(Va(0x105000), fnames)
            .region(Va(0x108000), image)
            .region(Va(0x109000), inames)
            .build()
    }

    fn scan() -> ClassScanArtifact {
        let snap = heap();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        ClassScanPass
            .run(&ctx, ClassScanInput { windows: vec![(Va(0x101000), 0x80)], probe: 0, max_probe: 0, limit: 0, min_hits: 0, require_self_pointer: false })
            .unwrap()
    }

    #[test]
    fn repeated_object_headers_surface_their_class() {
        // Every managed object begins with its class pointer, so frequency is
        // the signal — that is the whole idea, and it is what removes the need
        // to already have an address.
        let art = scan();
        assert_eq!(art.count, 1, "{art:?}");
        assert_eq!(art.classes[0].name, "PlayerHealth");
        assert_eq!(art.classes[0].namespace, "Game");
        assert_eq!(art.classes[0].field_count, 1);
        assert_eq!(art.classes[0].hits, 3, "seen once per referencing object");
    }

    #[test]
    fn an_image_shaped_decoy_is_counted_and_dropped_not_reported() {
        // The measured false positive: an `Il2CppImage` matches the name shape.
        // It must not appear as a class, and it must not vanish silently either
        // — a large `weak_rejected` says the sample was mostly not classes.
        let art = scan();
        assert!(!art.classes.iter().any(|c| c.name.contains("mscorlib")), "{art:?}");
        assert_eq!(art.weak_rejected, 1);
        assert_eq!(art.probed, 2, "both candidates were probed; the denominator is reported honestly");
    }

    #[test]
    fn a_one_off_pointer_is_not_a_candidate() {
        let snap = heap();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let art = ClassScanPass
            .run(&ctx, ClassScanInput { windows: vec![(Va(0x101000), 0x80)], probe: 0, max_probe: 0, limit: 0, min_hits: 4, require_self_pointer: false })
            .unwrap();
        assert_eq!(art.count, 0, "min_hits raised above the real repeat count filters it out, as asked");
        assert_eq!(art.probed, 0);
    }
}

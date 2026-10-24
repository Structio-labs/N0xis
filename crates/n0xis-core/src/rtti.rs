// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MSVC RTTI / vtable class recovery — Rung 7's devirtualization down-payment.
//!
//! A C++ virtual call dispatches through a vtable slot, an edge the CFG can only
//! mark "indirect". But an MSVC binary built with RTTI (`/GR`, the default)
//! carries, right before each vtable, a pointer to a
//! `RTTICompleteObjectLocator` (COL); the COL points (by image-relative RVA) at
//! a `TypeDescriptor` whose tail is the class's decorated name (`.?AVFoo@@`).
//! Walking that chain turns an anonymous vtable address into a concrete class
//! name — the fact that makes a `(*vtable[k])()` call readable and a struct's
//! first field typeable.
//!
//! This is inherently a PE/MSVC concept: the caller supplies the image base
//! (to resolve the RVAs) and the `.rdata` range (where COLs and vtables live).
//! The scan is validated by the COL's **self-reference** — its `pSelf` RVA must
//! resolve back to the COL's own address — which is a far stronger filter than
//! the signature word alone and keeps false positives out.

use n0xis_contracts::Va;
use serde::{Deserialize, Serialize};

use crate::MemorySource;
use n0xis_sources::{DataSymbol, RelocatedWords};

/// One recovered vtable and the class it belongs to.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RttiVtable {
    /// Address of the vtable's first method slot.
    pub vtable: Va,
    /// Address of the `TypeDescriptor` the COL points at.
    pub type_descriptor: Va,
    /// The decorated name as stored (`.?AVFoo@@`).
    pub mangled: String,
    /// The readable class name (`Foo`, `Ns::Bar`); equals `mangled` when the
    /// name uses template/special mangling this does not safely reverse.
    pub name: String,
    /// The COL's `offset` field — this base's offset within the complete
    /// object, non-zero for a secondary base under multiple inheritance.
    pub offset: u32,
    /// The class's **base classes** — or that the image does not say. See
    /// [`Bases`] for the JSON shape: `bases` (an array, `[]` for none) where the
    /// bases were read, `bases_unknown` (the reason) where they could not be.
    #[serde(flatten)]
    pub bases: Bases,
}

/// What an image says about a class's bases.
///
/// Two states, because "read, and there are none" and "could not be read" are
/// different answers and one of them was printed as the other: the field was a
/// `Vec` that was empty both for a class with no bases and for one whose
/// `type_info` the file does not hold — which is **every** class of a shared
/// object whose `type_info` pointers are symbolic relocations (all 179 of
/// `libstdc++.so.6`'s). The subclass guard of devirtualization read that empty
/// list as "nothing here derives from anything" and so never refused a
/// dispatch there.
///
/// Serialized flat into the [`RttiVtable`] (this is the `rtti scan` schema,
/// `n0xis.rtti.scan.v1`): `"bases": ["A", "B"]` or `"bases": []` when read —
/// readable names, most-derived base first, self excluded — and, when not, no
/// `bases` key and `"bases_unknown": "<reason>"` (a [`BasesUnknown`] code). A
/// consumer that reads `bases` keeps working where it is known; before this a
/// class with no bases had no `bases` key either, so absent now means only
/// unknown.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Bases {
    /// Read from the image. Empty: the image says the class has none — of the
    /// bases this image can name; one defined in another image is a symbolic
    /// relocation that reads as zero and is not listed (see
    /// [`itanium_bases`]).
    Known {
        /// Base class names, most-derived first, self excluded.
        bases: Vec<String>,
    },
    /// The image does not say, and why.
    Unknown {
        /// The reason, as a stable code.
        bases_unknown: BasesUnknown,
    },
}

impl Bases {
    /// A class with no bases, as read.
    pub fn none() -> Self {
        Bases::Known { bases: Vec::new() }
    }
    /// The bases, where they were read.
    pub fn known(&self) -> Option<&[String]> {
        match self {
            Bases::Known { bases } => Some(bases),
            Bases::Unknown { .. } => None,
        }
    }
}

/// Why a class's bases are not known.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BasesUnknown {
    /// Itanium: the image has no `_ZTI` symbol of the class's own, and the
    /// vtable's `type_info` pointer reads zero. A relocation the file does not
    /// hold fills it — a symbolic one against a `_ZTI` defined elsewhere — or
    /// the class was compiled without RTTI and the slot is zero for good.
    /// Either way nothing in the image leads to the `type_info`, so its bases
    /// cannot be read. (Where the class's own `_ZTI` is in the image its bases
    /// are read from it, whatever the pointer reads: [`itanium_bases`].)
    TypeInfoNotInFile,
    /// Itanium: the vtable's `type_info` pointer holds an address, and it is
    /// not the address of the class's own `_ZTI` symbol. The two say different
    /// things about which `type_info` is the class's, and neither is taken.
    TypeInfoDisagrees,
    /// Itanium: the class's `type_info` says it has a base (its symbol's size
    /// is that of a one-base or a several-base `type_info`), and the pointer to
    /// that base's `type_info` names no `_ZTI` object of this image — it reads
    /// zero, a relocation the file does not hold (a base defined in another
    /// image, or one this image reaches by symbol), or points where no `_ZTI`
    /// symbol is. The class has a base this image cannot name, which is not
    /// the same answer as having fewer bases: on one Qt build 105 classes were
    /// listed with no bases, or some, this way.
    BaseNotNamed,
    /// The `type_info` object (Itanium) or the class hierarchy descriptor
    /// (MSVC) the class points at is not in what could be read — for Itanium,
    /// also a `type_info` whose symbol states no size, or one that is none of
    /// the ABI's three layouts.
    HierarchyUnreadable,
}

/// The classes of an image that may have a **subclass in it** — what the
/// subclass guard of devirtualization asks.
///
/// A set of names is only an answer to "is this class derived from here?" when
/// every class's bases were read: one class whose bases are unknown may derive
/// from any of the others. So the rule, in one place ([`Self::of`]): when the
/// bases of **any** class in the image are unknown, **every** class may have a
/// subclass, and a dispatch the guard protects is refused for all of them.
/// Narrower rules were possible and none is sound — the unknown class could
/// derive from any class at all, and nothing in the image says which.
///
/// **It stays this wide until the format seam can name a base in another
/// image** (the relocation that fills a base pointer — `binding_at`,
/// docs/design/IMAGE_FORMATS.md §5 step 2). Its price, measured on
/// `libQt6Gui.so.6.11.2`, where 105 of 269 classes have a base in another
/// library (`QObject` and its kin, in `libQt6Core`) and so are
/// `base-not-named`: over the 4 280 functions with an indirect call through a
/// register, devirtualization resolves 3 calls with the rule and 51 without
/// it, every one of the 48 through the `object` basis. (Counts of this kind
/// depend on the candidate set: over every function `llvm-objdump` shows with
/// a `call *`, a review counted 99 at the build before the rule and the same
/// 3 after; the 51 was not re-measured there.)
///
/// **A library's set is open** ([`Subclasses::Open`]). A class a shared object
/// holds can be derived from in the program that loads it, which the image
/// cannot see: in a shared object with no internal inheritance,
/// `Plugin::drive`'s call through `this` was named `Plugin::run`, and the
/// processor ran the client's `My::run` (8 of 12 builds: g++ and clang++,
/// `-O1`/`-O2`, linked `-Bsymbolic` or `-Bsymbolic-functions`; linked without,
/// the slots are symbolic relocations and nothing resolved). Since each
/// class's bases are read from its own `_ZTI`, a library's hierarchy is
/// usually all known (`libx265`, 50 of 50 classes; `libicutest`, 10 of 10), so
/// what the image says of itself could not stand in for the rule. A
/// program's set is taken as closed: a class an executable linked with
/// `-rdynamic` exports can be derived from in a plugin it loads, which this
/// cannot see either — not measured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Subclasses {
    /// Every class's bases were read; these are the classes some class here
    /// derives from.
    Known(std::collections::HashSet<String>),
    /// The bases of `classes` classes could not be read, so any class may have
    /// a subclass here.
    Unknown {
        /// How many classes' bases are unknown.
        classes: usize,
    },
    /// The image is a library ([`n0xis_sources::Linkage::SharedLibrary`]), so
    /// any class may have a subclass in an image that loads it.
    Open,
}

impl Subclasses {
    /// The guard's answer for the image these vtables were recovered from.
    ///
    /// `unread` counts the image's classes that are not in `vtables` at all —
    /// the ones the scan refused ([`ItaniumScan::refused`]). Their bases were
    /// not read either, and a class left out of the hierarchy is as unknown as
    /// one whose bases could not be read: `basic_iostream` refused for its
    /// virtual bases is still a subclass of `basic_istream`.
    ///
    /// `linkage` is what the image's headers say it is: a library's set is
    /// [`Subclasses::Open`] whatever its hierarchy holds.
    pub fn of(vtables: &[RttiVtable], unread: usize, linkage: n0xis_sources::Linkage) -> Self {
        if linkage == n0xis_sources::Linkage::SharedLibrary {
            return Subclasses::Open;
        }
        let unknown = vtables.iter().filter(|v| v.bases.known().is_none()).count() + unread;
        if unknown > 0 {
            return Subclasses::Unknown { classes: unknown };
        }
        Subclasses::Known(vtables.iter().filter_map(|v| v.bases.known()).flatten().cloned().collect())
    }
    /// May `class` have a subclass? `false` only in a program whose every
    /// class's bases were read and none of them is `class`.
    pub fn may_have_subclass(&self, class: &str) -> bool {
        match self {
            Subclasses::Known(set) => set.contains(class),
            Subclasses::Unknown { .. } | Subclasses::Open => true,
        }
    }
}

/// Why an image's RTTI is not read at all — a typed refusal where the answer
/// would otherwise be an empty or a wrong success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RttiRefusal {
    /// A big-endian ELF (`e_ident[EI_DATA]` = 2, `ELFDATA2MSB`). Every reader
    /// here reads little-endian pointers, so the vtables, `type_info` objects
    /// and slots of such an image would be read byte-swapped: `rtti scan` on an
    /// `aarch64_be` shared object answered `ok: true` with seven classes whose
    /// bases and slots were read as nonsense.
    ///
    /// Its reach is wider than RTTI: `decomp pseudo` asks for the vtable map
    /// and so refuses **every** big-endian image, one with no C++ in it too,
    /// with this message about RTTI. A right answer was traded for it: on an
    /// `aarch64_be` shared object of `int add(int a, int b) { return a + b; }`
    /// the build before this refusal answered `return (uint32_t)((uint32_t)x1 +
    /// (uint32_t)x0);` — correct, AArch64 instructions being little-endian in
    /// either byte order — and this one refuses. Narrowing it to images that
    /// have Itanium vtables to read is an open item.
    BigEndian,
    /// An image with no one address space for an object to point into: a
    /// WebAssembly module, whose positions are module offsets and whose data
    /// lives in linear memories (docs/design/WASM.md §5 decision 2). Every
    /// RTTI reader here reads vtables and type descriptors as pointers into the
    /// image's own space at its pointer width, and a module has neither.
    NoNativePointers,
}

impl RttiRefusal {
    /// The error code a command answers with.
    pub fn code(self) -> &'static str {
        match self {
            RttiRefusal::BigEndian => "big-endian-image",
            RttiRefusal::NoNativePointers => "no-native-pointers",
        }
    }
    /// The message a command answers with, naming the byte order.
    pub fn message(self) -> String {
        match self {
            RttiRefusal::BigEndian => "the image is big-endian (ELF EI_DATA = 2, ELFDATA2MSB); C++ RTTI is read only from \
                                      little-endian images, and reading this one would byte-swap every pointer"
                .to_string(),
            RttiRefusal::NoNativePointers => "the image has no one address space for an object to point into (a WebAssembly \
                                              module: its positions are module offsets and its data is in linear memories); \
                                              C++ RTTI is read as pointers into a native image's own space"
                .to_string(),
        }
    }
}

/// How a vtable slot holds a method: the slot's width, and what its low bit
/// means. Built from the image (`Src::vtable_slots` in the frontend) and handed
/// to everything that reads a method out of a slot, so the two facts are
/// stated together and nothing reads a slot without both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VtableSlots {
    /// Bytes per slot, 4 or 8: the image's data pointer size (its PE
    /// optional-header magic or ELF class), never the decoder's register
    /// width — the x32 ABI runs x86-64 code with 4-byte pointers.
    pub pointer_size: u8,
    /// What a code pointer's bits mean in this image.
    pub code_pointers: CodePointers,
}

/// What a code pointer's low bit means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodePointers {
    /// The value is the address of the code.
    Address,
    /// 32-bit ARM (`EM_ARM`): bit 0 of a code pointer is the Thumb indication
    /// of interworking, not part of the address — a Thumb method at `0x2029c`
    /// is stored in its slot as `0x2029d`.
    ArmInterworking,
}

/// A slot whose value the reader refuses to take as a method address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ThumbSlot;

impl VtableSlots {
    /// The method a slot's value names, or the refusal.
    ///
    /// **An interim rule.** On `EM_ARM` a value with bit 0 set is a Thumb
    /// method at `value & !1`; reading it as the address named an odd address,
    /// mid-instruction, `Class::vfN` — and `analyze` persisted those names once
    /// slots were read at the right width. Until the one rule exists — clear bit
    /// 0 for symbols and code pointers alike, in one place, with the mode kept
    /// as a fact of the address — such a slot is neither named nor
    /// devirtualized. That rule belongs to the format seam's step 2
    /// (docs/design/IMAGE_FORMATS.md §5 step 2; docs/design/ISA_AND_LIFT.md §8
    /// decision 4), because a symbol's Thumb bit and a slot's are the same
    /// fact and must be cleared by the same code.
    pub(crate) fn method(self, value: u64) -> Result<u64, ThumbSlot> {
        match self.code_pointers {
            CodePointers::ArmInterworking if value & 1 != 0 => Err(ThumbSlot),
            _ => Ok(value),
        }
    }
}

/// What the Itanium scan found: the classes it reports and the ones it
/// refused.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ItaniumScan {
    /// Each class at its vptr — `_ZTV` + two pointers.
    pub vtables: Vec<RttiVtable>,
    /// Classes with a `_ZTV` symbol that are not reported, and why.
    pub refused: Vec<RefusedVtable>,
}

impl ItaniumScan {
    /// How many classes were refused for `reason`.
    pub fn count_refused(&self, reason: VtableRefusal) -> usize {
        self.refused.iter().filter(|r| r.reason == reason).count()
    }
}

/// A class the Itanium scan does not report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefusedVtable {
    /// The `_ZTV` symbol, version suffix removed.
    pub mangled: String,
    /// The readable class name.
    pub name: String,
    /// Why.
    pub reason: VtableRefusal,
}

/// Why a class's vtable is not reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VtableRefusal {
    /// The class has virtual bases. Such a vtable begins with its virtual-base
    /// offsets (and vcall offsets) before `offset_to_top`, so the address point
    /// is not `_ZTV` + two pointers: that address is the `type_info` slot, or
    /// an offset before it. Measured on `libstdc++.so.6.0.36` (both widths):
    /// `basic_stringstream<char>` was reported with its vptr on the relocation
    /// that names `_ZTI…basic_stringstream…`, one pointer before the first
    /// method. Where the address point really is takes the number of those
    /// offsets, which only the class hierarchy says; until that is read, the
    /// class is refused rather than placed.
    ///
    /// Shown by any of four facts of the image (`vtable_shows_virtual_bases`
    /// has the three that are read from its bytes): a VTT (`_ZTT` with the same
    /// suffix), which a compiler emits only where a constructor needs one —
    /// clang at `-O1`/`-O2` emits none for a class without a key function, so a
    /// VTT alone missed every such class, and `analyze` persisted their
    /// vftables at the wrong address.
    VirtualBases,
    /// The word at `_ZTV` + two pointers holds an address outside every
    /// executable section of the image, so it is no method and the table is
    /// not where the scan reads it. Such a
    /// class was dropped without a word; it is counted now, because a class
    /// left out of the scan is one whose bases were not read either, and the
    /// subclass guard must know it is there ([`Subclasses::of`]).
    FirstSlotNotCode,
    /// The word at `_ZTV` + two pointers reads zero, **no relocation writes
    /// it** ([`n0xis_sources::RelocatedWords`]), and the word before it is no
    /// pointer — neither the address of the class's own `type_info` nor a word
    /// a relocation writes — so nothing places the address point there. The
    /// `type_info` pointer is the one word before the address point that can be
    /// either: no virtual-base, vcall or `offset_to_top` offset is relocated.
    ///
    /// The case it closes: a class built without RTTI (`-fno-rtti`) whose
    /// virtual base has no data and shares its vptr, and for which clang emits
    /// no VTT — `HM : virtual P` and `HL : HM`. Its table begins with vcall and
    /// virtual-base offsets that are all zero, then an `offset_to_top` of zero
    /// and a `type_info` slot of zero, so none of the virtual-base facts sees
    /// it, and the zero at `_ZTV` + two pointers was taken for a slot the
    /// loader fills: `rtti scan` listed both at `_ZTV` + 8 where the processor
    /// puts the vptr at `_ZTV` + 20 (i686, executable and shared object, and
    /// ARMv7), and `analyze` persisted `HM::vftable` there; on x86-64 at + 16
    /// for + 40.
    ///
    /// A zero first slot is not by itself a sign of anything: GCC writes a
    /// literal zero, with no relocation, into the destructor slots of an
    /// abstract class (`std::error_category`, `std::pmr::memory_resource`).
    /// Refusing every unrelocated zero refused 8 classes of `libstdc++.so.6`, 5
    /// of `libzmq.so.5` and 19 of `libprotobuf.so.36.1.0` whose vptrs are
    /// `_ZTV` + two pointers; their `type_info` pointer is a relocation, which
    /// is what keeps them listed. **The price**: such an abstract class compiled
    /// by GCC *without* RTTI has no `type_info` pointer to place it, and is
    /// refused here too. Where the relocations were not read the zero is
    /// accepted as before.
    FirstSlotEmpty,
}

/// Turn an MSVC RTTI decorated type name into a readable, **bounded** one.
///
/// `.?AVFoo@@` → `Foo`, `.?AUData@Ns@@` → `Ns::Data`. The full readable form
/// ([`demangle_rtti_name_full`]) is then folded to a compact label
/// ([`shorten_type_name`]): heavily-templated code (reactive-stream template libraries, the STL
/// type-erasure helpers) demangles to multi-KiB type strings — correct but
/// useless as a list/decompiler label — and the `<lambda>`-in-a-local-scope
/// names the `msvc_demangler` cannot parse would otherwise render as the raw
/// `.?A…` decorated string. Both are bounded here so nothing ever renders a
/// 9 KiB identifier or a raw mangled blob.
pub fn demangle_rtti_name(mangled: &str) -> String {
    shorten_type_name(demangle_rtti_name_full(mangled), mangled)
}

/// The best readable form of an RTTI decorated name, **unbounded**.
///
/// The real MSVC demangler first — it reads the templated names
/// (`.?AV?$vector@H@std@@` → `std::vector<int>`) the hand-rolled `@`-splitter
/// below deliberately refuses. The splitter stays as a fallback for a name the
/// demangler declines, and the decorated string verbatim is the final,
/// always-sound floor. A name carrying template or other special mangling
/// (`?$`, a bare `?`) the splitter cannot safely decode is returned verbatim
/// rather than mis-decoded — sound over pretty.
fn demangle_rtti_name_full(mangled: &str) -> String {
    if let Some(full) = crate::demangle::demangle_rtti_type_descriptor(mangled) {
        return full;
    }
    let Some(rest) = mangled.strip_prefix(".?A") else {
        return mangled.to_string();
    };
    // The kind letter: V class, U struct, W enum, T union, …
    let mut chars = rest.chars();
    let _kind = chars.next();
    let body_full = chars.as_str();
    let body = body_full.strip_suffix("@@").unwrap_or(body_full);
    if body.contains('?') || body.contains('$') {
        return mangled.to_string();
    }
    let parts: Vec<&str> = body.split('@').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return mangled.to_string();
    }
    parts.into_iter().rev().collect::<Vec<_>>().join("::")
}

/// Ceiling on a rendered class name. Past it a name is truncated on a `char`
/// boundary with a stable hash suffix that keeps distinct types distinct — a
/// bare prefix cut would collide the thousands of template types that share a long
/// opening (`rpl::details::consumer_handlers<struct rpl::no_value, …`).
const RENDER_NAME_MAX: usize = 160;

/// A short, stable disambiguator derived from the full decorated name.
fn type_name_hash(decorated: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    decorated.hash(&mut h);
    format!("{:08x}", h.finish() as u32)
}

/// Fold a possibly-huge or still-decorated type name into a compact, bounded,
/// collision-resistant label. `decorated` is the original `.?A…` form, used for
/// the stable hash. A name the demanglers both declined (still `.?A…`) is
/// reduced to its leading template/class identifier (`consumer_handlers<…>`)
/// rather than shown as a raw mangled blob.
fn shorten_type_name(name: String, decorated: &str) -> String {
    let name = if let Some(rest) = name.strip_prefix(".?A") {
        let body = rest.get(1..).unwrap_or(""); // drop the kind letter (V/U/W/…)
        let (is_tmpl, base_src) = match body.strip_prefix("?$") {
            Some(t) => (true, t),
            None => (false, body),
        };
        let base = base_src.split('@').next().unwrap_or("");
        if base.is_empty() || base.contains(['?', '$']) {
            format!("type_{}", type_name_hash(decorated))
        } else if is_tmpl {
            format!("{base}<…>")
        } else {
            base.to_string()
        }
    } else {
        name
    };
    if name.len() <= RENDER_NAME_MAX {
        return name;
    }
    let mut cut = RENDER_NAME_MAX;
    while cut > 0 && !name.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…#{}", &name[..cut], type_name_hash(decorated))
}

/// The three layouts an Itanium `type_info` for a class has (ABI §2.9.5), as
/// its **symbol's size** states them.
///
/// The size is the one thing in the image that says which it is. The bytes do
/// not: the `type_info` vptr that tells `__si_class_type_info` from
/// `__vmi_class_type_info` is a symbolic relocation into the runtime, and what
/// follows a `__class_type_info`'s name is the next object. Reading the
/// structure instead took a one-base `type_info` whose base pointer is a
/// symbolic relocation (zero in the file) for one with no bases — 105 classes
/// of one Qt build were listed with no bases, or some, this way — and read
/// past a `__class_type_info` at the end of a segment into nothing, which made
/// a class without bases unreadable.
///
/// In the image's pointers (`p`): `{ vptr, __type_name }` is `2p`; a single
/// base adds its pointer (`3p`); several add `__flags:u32, __base_count:u32`
/// and `n` `__base_info { __base_type, __offset_flags }` of `2p` each, the
/// `long` being pointer-sized on ILP32 and LP64 alike. A class with no bases
/// has no `__vmi_class_type_info`, so `n` is at least 1, and the three sizes
/// never coincide at either width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TypeInfoShape {
    /// `__class_type_info`.
    NoBases,
    /// `__si_class_type_info`.
    OneBase,
    /// `__vmi_class_type_info`, with this many `__base_info` entries.
    Several(u64),
}

impl TypeInfoShape {
    fn of(size: u64, ptr: u64) -> Option<Self> {
        let several = size.checked_sub(2 * ptr + 8).filter(|rest| rest % (2 * ptr) == 0).map(|rest| rest / (2 * ptr));
        match size {
            s if s == 2 * ptr => Some(TypeInfoShape::NoBases),
            s if s == 3 * ptr => Some(TypeInfoShape::OneBase),
            _ => several.filter(|n| (1..=u64::from(MAX_ITANIUM_BASES)).contains(n)).map(TypeInfoShape::Several),
        }
    }
}

/// Bounds the `__base_info` walk so a mis-read size can never drive an
/// unbounded loop.
const MAX_ITANIUM_BASES: u32 = 64;

/// `__offset_flags & __virtual_mask`: the base is virtual.
const ITANIUM_VIRTUAL_BASE: u64 = 0x1;

/// What one `type_info` object says about its class.
#[derive(Clone, Debug, PartialEq)]
struct TypeInfoRead {
    bases: Bases,
    /// A `__base_info` of it has the virtual bit: the class has a virtual base.
    /// Read from `__offset_flags`, an integer the file holds even where every
    /// pointer around it is a relocation.
    virtual_base: bool,
}

/// The `_ZTI` objects of an image, by address: the class each names and the
/// size its symbol states.
type TypeInfos = std::collections::HashMap<u64, (String, Option<u64>)>;

/// Read the `type_info` object at `zti`.
///
/// The comment this replaces said base classes "need relocation resolution to
/// read". They do not, for the ones that matter: a base pointer inside the same
/// image is supplied by a *relative* relocation — `R_X86_64_RELATIVE` or a
/// `.relr.dyn` entry — and a relative relocation's addend is stored **at the
/// target location**, so reading the pointer there yields the address.
/// (Measured: `readelf -r` alone, which does not expand `.relr.dyn`, found 102
/// of 211 edges on one Qt build. Reading the file found 194 of 195
/// single-inheritance classes.) A base in *another* library is a symbolic
/// relocation and reads as zero: the class has a base this image cannot name,
/// and the answer says so ([`BasesUnknown::BaseNotNamed`]) instead of leaving
/// the base out.
///
/// The layout is the one the `_ZTI` symbol's size states ([`TypeInfoShape`]).
/// An object no `_ZTI` symbol starts, or whose symbol states no size, or none of
/// the three, is not read: its bases are unknown, never guessed.
fn read_type_info(src: &dyn MemorySource, zti: u64, infos: &TypeInfos, ptr_size: u8) -> TypeInfoRead {
    let unknown = |why| TypeInfoRead { bases: Bases::Unknown { bases_unknown: why }, virtual_base: false };
    let ptr = u64::from(ptr_size);
    let Some(shape) = infos.get(&zti).and_then(|(_, size)| *size).and_then(|size| TypeInfoShape::of(size, ptr)) else {
        return unknown(BasesUnknown::HierarchyUnreadable);
    };
    let after_name = zti.saturating_add(2 * ptr);
    let named = |at: u64| -> Result<String, BasesUnknown> {
        let word = read_pointer(src, Va(at), ptr_size).ok_or(BasesUnknown::HierarchyUnreadable)?;
        infos.get(&word).map(|(name, _)| name.clone()).ok_or(BasesUnknown::BaseNotNamed)
    };
    match shape {
        TypeInfoShape::NoBases => TypeInfoRead { bases: Bases::none(), virtual_base: false },
        TypeInfoShape::OneBase => match named(after_name) {
            Ok(base) => TypeInfoRead { bases: Bases::Known { bases: vec![base] }, virtual_base: false },
            Err(why) => unknown(why),
        },
        TypeInfoShape::Several(n) => {
            // `__base_count` must be the count the size states, or this is not
            // the object the symbol says it is.
            let count = src.read(Va(after_name.saturating_add(4)), 4).ok().and_then(|b| u32_le(&b, 0));
            if count.map(u64::from) != Some(n) {
                return unknown(BasesUnknown::HierarchyUnreadable);
            }
            let entry = |i: u64| after_name.saturating_add(8).saturating_add(2 * ptr * i);
            // The virtual bit is read for every entry first: it is an integer in
            // the file, and it stands even where a base's pointer does not.
            let mut virtual_base = false;
            for i in 0..n {
                match read_pointer(src, Va(entry(i).saturating_add(ptr)), ptr_size) {
                    Some(flags) => virtual_base |= flags & ITANIUM_VIRTUAL_BASE != 0,
                    None => return unknown(BasesUnknown::HierarchyUnreadable),
                }
            }
            let bases: Result<Vec<String>, BasesUnknown> = (0..n).map(|i| named(entry(i))).collect();
            match bases {
                Ok(bases) => TypeInfoRead { bases: Bases::Known { bases }, virtual_base },
                Err(why) => TypeInfoRead { bases: Bases::Unknown { bases_unknown: why }, virtual_base },
            }
        }
    }
}

/// A class's bases, read from its **own** `type_info` — the `_ZTI` symbol with
/// its suffix, at `own` — where the image defines one.
///
/// It was read through the vtable's `type_info` pointer, and in a shared
/// object built with default visibility that pointer is a symbolic relocation
/// against the class's own `_ZTI`, zero in the file: all 179 classes of
/// `libstdc++.so.6` were `type-info-not-in-file`, though each `_ZTI` was right
/// there, and its symbol's size says whether the class has a base at all. The
/// pointer, `word`, is kept as a cross-check where it reads an address: it must
/// be the own `_ZTI`'s, or the bases are not read
/// ([`BasesUnknown::TypeInfoDisagrees`]).
///
/// Without an own `_ZTI` the pointer is all there is, as before. Several own
/// `_ZTI` symbols at different addresses (none in the twelve system libraries
/// measured) leave the bases unknown rather than pick one.
fn itanium_bases(src: &dyn MemorySource, own: &[u64], word: Option<u64>, infos: &TypeInfos, ptr_size: u8) -> Bases {
    let unknown = |why| Bases::Unknown { bases_unknown: why };
    let mut at: Vec<u64> = own.to_vec();
    at.sort_unstable();
    at.dedup();
    match (at.as_slice(), word) {
        ([], None) => unknown(BasesUnknown::HierarchyUnreadable),
        ([], Some(0)) => unknown(BasesUnknown::TypeInfoNotInFile),
        ([], Some(zti)) => read_type_info(src, zti, infos, ptr_size).bases,
        ([zti], Some(w)) if w != 0 && w != *zti => unknown(BasesUnknown::TypeInfoDisagrees),
        ([zti], _) => read_type_info(src, *zti, infos, ptr_size).bases,
        (_, _) => unknown(BasesUnknown::HierarchyUnreadable),
    }
}

/// A little-endian pointer of the image's width, `ptr_size` bytes (4 or 8), at
/// `va`. `None` when the bytes are not all there.
///
/// The one reader of a pointer-sized word for everything that walks a vtable —
/// the Itanium scan, the slot naming and devirtualization — so the width is
/// asked in one place. Each of them used to read eight bytes whatever the image
/// was, which on a 32-bit image joins two slots into one value that is no
/// address at all.
///
/// # Panics
/// On a width other than 4 or 8. No image this build loads has one, and
/// reading at a wrong width anyway would be a wrong answer, not an error.
pub(crate) fn read_pointer(src: &dyn MemorySource, va: Va, ptr_size: u8) -> Option<u64> {
    assert!(matches!(ptr_size, 4 | 8), "a data pointer is 4 or 8 bytes, not {ptr_size}");
    let b = src.read(va, usize::from(ptr_size)).ok()?;
    if ptr_size == 8 { u64_le(&b, 0) } else { u32_le(&b, 0).map(u64::from) }
}

/// The class named by a `_ZTV…` symbol, as a readable, bounded name.
///
/// Demanglers do not agree on how to render a vtable symbol: `cpp_demangle`
/// produces `{vtable(std::lock_error)}` while others emit `vtable for
/// std::lock_error`. Both wrappers are peeled here; if neither matches, the
/// mangled type is demangled on its own by re-forming it as a `_ZTS` (type
/// string) symbol, which every demangler renders as a plain type name.
fn itanium_class_name(ztv_symbol: &str) -> String {
    let demangled = crate::demangle::demangle(ztv_symbol);
    let peeled = demangled
        .strip_prefix("vtable for ")
        .map(str::to_string)
        .or_else(|| {
            demangled.strip_prefix("{vtable(").and_then(|r| r.strip_suffix(")}")).map(str::to_string)
        })
        .or_else(|| {
            // Fall back to demangling the bare type: `_ZTVFoo` -> `_ZTSFoo`.
            let ty = ztv_symbol.strip_prefix("_ZTV")?;
            let as_type = crate::demangle::demangle(&format!("_ZTS{ty}"));
            let cleaned = as_type
                .strip_prefix("typeinfo name for ")
                .map(str::to_string)
                .or_else(|| as_type.strip_prefix("{typeinfo name(").and_then(|r| r.strip_suffix(")}")).map(str::to_string));
            cleaned.filter(|c| c != ty)
        })
        .unwrap_or(demangled);
    shorten_type_name(peeled, ztv_symbol)
}

/// Does the `_ZTV` object at `ztv` show, in its own bytes or its class's
/// `type_info`, that the class has virtual bases?
///
/// Four facts, each a property of every vtable without virtual bases whose
/// class has a `type_info`, so none can refuse such a class:
///
/// 1. **The first word is not zero.** A vtable group begins with the primary
///    vtable, whose `offset_to_top` is 0 — a constant the file holds even in a
///    shared object, where every pointer around it is a relocation. Anything
///    else there is a virtual-base or vcall offset, which only a class with
///    virtual bases has.
/// 2. **The class's own `type_info` address is in the table, and not in its
///    second word.** In an executable, or a shared object whose pointers are
///    relative relocations, the `type_info` pointer holds `_ZTI` + the same
///    suffix; the word that holds it is one pointer before the address point.
///    A primary virtual base that shares the vptr has a virtual-base offset of
///    0 and vcall offsets of 0, so (1) cannot see it, and this does.
/// 3. **The class's `type_info` says a base is virtual** (`__offset_flags`,
///    an integer the file holds where the pointers are relocations). This is
///    the one that reaches a shared object whose vtable reads as zeros from
///    `offset_to_top` on — but only for a *direct* virtual base, as only a
///    `__vmi_class_type_info` carries the bit.
/// 4. **The class has its own `type_info`, and its second word reads zero with
///    no relocation writing it** ([`RelocatedWords`]). The second word of a
///    table without virtual bases is its `type_info` pointer, which holds the
///    address in the file or is written by a relocation (relative, or symbolic
///    against the `_ZTI`); a zero nothing writes is an offset. This is the one
///    that reaches a class whose virtual base is *indirect* and shares its
///    vptr, in a shared object whose `type_info` pointers are symbolic
///    relocations, with no VTT, which (1)–(3) all miss: `Leaf : Mid`, `Mid :
///    virtual P` with `P` without data (listed at `_ZTV` + two pointers, an
///    offset, where its vptr is three pointers further on), and `Leaf : Mid`,
///    `Mid : virtual E` with `E` empty, whose one zero offset put the listing
///    on the relocation that names `_ZTI4Leaf`, one pointer before its vptr.
///    It needs the relocations read; where they were not, it says nothing.
///
/// A class compiled without RTTI has no `type_info`, so (2)–(4) do not apply
/// to it; its zero offsets are refused at the first-slot gate instead
/// ([`VtableRefusal::FirstSlotEmpty`]). A class built without RTTI in a
/// translation unit whose vtable leaves the `type_info` slot zero while
/// another unit emits its `_ZTI` would be refused here as having virtual
/// bases; none was seen.
fn vtable_shows_virtual_bases(
    src: &dyn MemorySource,
    ztv: &DataSymbol,
    own: &[u64],
    infos: &TypeInfos,
    ptr_size: u8,
    relocated: &RelocatedWords,
) -> bool {
    let ptr = u64::from(ptr_size);
    let word = |at: u64| read_pointer(src, Va(ztv.va.get().saturating_add(at)), ptr_size);
    if word(0).is_some_and(|w| w != 0) {
        return true;
    }
    // Where the class's own `type_info` address first appears in its table.
    // Bounded by the `_ZTV` symbol's size; where it states none, the first two
    // words.
    let words = ztv.size.map_or(2, |size| (size / ptr).min(MAX_SLOTS as u64));
    if !own.is_empty()
        && let Some(at) = (0..words).find(|&i| word(i * ptr).is_some_and(|w| own.contains(&w)))
        && at != 1
    {
        return true;
    }
    let second = Va(ztv.va.get().saturating_add(ptr));
    if !own.is_empty() && word(ptr) == Some(0) && !relocated.may_write(second, ptr) {
        return true;
    }
    own.iter().any(|&zti| read_type_info(src, zti, infos, ptr_size).virtual_base)
}

/// Recover C++ classes from **Itanium ABI** RTTI (GCC/Clang, i.e. ELF), the
/// counterpart to [`scan_msvc_rtti`]. Returns the same [`RttiVtable`] shape, so
/// everything downstream — `rtti_symbol_map`, `Class::vfN` naming, the
/// decompiler's `this`-typing — works unchanged across both formats.
///
/// **Driven by symbols, not by a structural scan, and that is deliberate.** In an
/// ELF shared object the vtable's type-info slot is *empty in the file*: it is
/// supplied at load time by a relocation against the `_ZTI…` symbol (measured on
/// `libstdc++.so.6` — the slot reads as zeroes and carries an `R_X86_64_64`
/// against `_ZTISt10lock_error`). A byte-level walk therefore recovers almost
/// nothing without also resolving relocations: a prototype of that approach found
/// 11 of 179 vtables. The `_ZTV…` symbol names the class outright, which is both
/// exact and the cheapest source to consult first.
///
/// A fully stripped ELF has no such symbols and yields nothing here — honest, and
/// the documented follow-on (structural scan + `.rela` resolution).
///
/// **The known limit**: where the image's relocations were not read
/// (`relocated` is [`RelocatedWords::NotRead`] — an object file, a machine
/// other than the four measured, a packed format not decoded), a zero word is
/// taken for one the loader may fill, as it always was, and two cases are
/// listed at `_ZTV` + two pointers though their vptr is further on, because
/// only the relocations tell them apart: a class whose virtual base, direct
/// or indirect, has no data and shares its vptr, with no VTT, either built
/// without RTTI (then any image) or with its `type_info` pointers as symbolic
/// relocations (an indirect virtual base). Where they were read, both are
/// refused (`vtable_shows_virtual_bases` fact 4, and
/// [`VtableRefusal::FirstSlotEmpty`]). The two were measured as wrong answers
/// before that rule: clang `-fno-rtti` `HM : virtual P` listed at `_ZTV` + 8
/// with its vptr at + 20 on i686 and ARMv7 (and + 16 for + 40 on x86-64 and
/// AArch64), and an `-O1` shared object's `Leaf : Mid : virtual P` at
/// `_ZTV4Leaf` `0x27f0` listed at `0x2800`, where `llvm-readobj -r` shows
/// `0x2808` filled by `_ZTI4Leaf` and the address point at `0x2810`.
///
/// What remains open with the relocations read is one shape, not measured
/// anywhere: a class with virtual bases whose word at `_ZTV` + two pointers is
/// a **non-zero** virtual-base or vcall offset whose value happens to lie inside
/// an executable range (an offset of `0x1010` in a shared object whose code
/// starts at `0x1000`), and whose earlier words none of the four facts reads as
/// an offset. Every other word that can sit there — a zero offset, a zero
/// `offset_to_top`, a zero `type_info` slot of a class without RTTI — is a
/// zero nothing writes, or a value outside the code. Telling every case apart
/// takes what a relocation names, the format seam's `binding_at`
/// (docs/design/IMAGE_FORMATS.md §5, step 2 part 3).
///
/// `vtable` is the address an object actually stores: the `_ZTV` object begins
/// with `offset_to_top` and the type-info pointer, so the first method slot — and
/// thus the stored vptr — sits **two pointers** in: 16 bytes on a 64-bit image,
/// 8 on a 32-bit one.
///
/// `ptr_size` is the **image's** data pointer size (4 or 8), never the
/// decoder's register width — the x32 ABI runs x86-64 code with 4-byte
/// pointers. This was a constant 16-byte header and 8-byte slots, so on a
/// 32-bit shared object the scan took two slots — or, past a short table, the
/// next object — as its "first slot", eight bytes wide. That joined value is
/// rarely a code address, so most classes were skipped (`ok: true`, no
/// vtables); where it read zero, which is accepted below as a slot the loader
/// fills, the class was reported at an address 8 bytes past its real vptr.
///
/// A class with **virtual bases** is refused, not reported
/// ([`VtableRefusal::VirtualBases`]): "symbol + two pointers" is not where its
/// vptr is. So is one whose word there is no code
/// ([`VtableRefusal::FirstSlotNotCode`]), and one whose word there is a zero
/// nothing fills ([`VtableRefusal::FirstSlotEmpty`]). Every `_ZTV` the scan
/// sees is either reported or refused, never dropped.
///
/// `relocated` is the set of words the image's loader writes
/// ([`RelocatedWords`], `ImageSource::relocated_words`): what tells a zero the
/// loader fills from a zero that stays.
///
/// `code` is every executable range of the image (`MemorySource::code_ranges`,
/// the same ranges devirtualization takes a slot's value to be code by).
pub fn scan_itanium_rtti(
    src: &dyn MemorySource,
    data_symbols: &[DataSymbol],
    code: &[(Va, u64)],
    ptr_size: u8,
    relocated: &RelocatedWords,
) -> ItaniumScan {
    let ptr = u64::from(ptr_size);
    // `offset_to_top` + the `type_info` pointer, one pointer each.
    let vtable_header = 2 * ptr;
    // Every executable range, not `.text` alone: a method the compiler or the
    // source put in a section of its own (`__attribute__((section))`,
    // `.text.hot` kept apart by a linker script, an IL2CPP-style code section)
    // is code all the same. Gated on `.text` only, `Sub : Base` with `Sub::f`
    // in an executable `hot_code` section was refused as having no code
    // there. No range stated (an image without section headers) is no gate,
    // as no `.text` was before.
    let in_code = |va: u64| code.is_empty() || code.iter().any(|(t, n)| va >= t.get() && va < t.get() + n);
    // Strip an ELF symbol-version suffix (`_ZTVFoo@@GLIBCXX_3.4`) before a name
    // reaches the demangler, which would otherwise decline the whole name.
    let bare = |s: &DataSymbol| crate::demangle::elf_unversioned(&s.name).to_string();

    // `_ZTI` address → class name and size, so a base pointer read out of a
    // type_info can be named and the type_info's layout known. Built first
    // because a base may be declared after its derived class in symbol order.
    let mut infos: TypeInfos = std::collections::HashMap::new();
    // Suffix → the addresses of its `_ZTI` (versioned aliases are separate
    // symbols of one class).
    let mut own_zti: std::collections::HashMap<String, Vec<u64>> = std::collections::HashMap::new();
    // The suffixes that have a VTT (`_ZTT`): classes with virtual bases.
    let mut has_vtt: std::collections::HashSet<String> = std::collections::HashSet::new();
    for s in data_symbols {
        let name = bare(s);
        if let Some(rest) = name.strip_prefix("_ZTI")
            && !rest.is_empty()
        {
            infos.insert(s.va.get(), (itanium_class_name(&format!("_ZTV{rest}")), s.size));
            own_zti.entry(rest.to_string()).or_default().push(s.va.get());
        }
        if let Some(rest) = name.strip_prefix("_ZTT")
            && !rest.is_empty()
        {
            has_vtt.insert(rest.to_string());
        }
    }

    let mut out = Vec::new();
    let mut refused = Vec::new();
    for s in data_symbols {
        let mangled = bare(s);
        let Some(rest) = mangled.strip_prefix("_ZTV") else { continue };
        if rest.is_empty() {
            continue;
        }
        let refuse = |reason| RefusedVtable { mangled: mangled.clone(), name: itanium_class_name(&mangled), reason };
        let own = own_zti.get(rest).map(Vec::as_slice).unwrap_or_default();
        // Before the first-slot gate below, which reads `_ZTV` + two pointers:
        // for such a class that word is the `type_info` pointer or an offset,
        // so in an executable, where it holds the address, the gate dropped the
        // class without a word, and where it reads zero, the gate passed it at
        // the wrong address.
        if has_vtt.contains(rest) || vtable_shows_virtual_bases(src, s, own, &infos, ptr_size, relocated) {
            refused.push(refuse(VtableRefusal::VirtualBases));
            continue;
        }
        let vtable = s.va.get().saturating_add(vtable_header);
        // Soundness gate on the first method slot. A **zero** slot a relocation
        // writes is accepted: in a shared object the method pointers are
        // supplied by relocations and read as zeroes from the file
        // (`libstdc++.so.6` uses symbolic `R_X86_64_64` and has no
        // `R_X86_64_RELATIVE` at all), so requiring a resolved code pointer
        // here rejected 178 of its 179 vtables. A zero **no** relocation writes
        // is zero at run time, and is accepted only where the word before it
        // names the class's own `type_info` ([`VtableRefusal::FirstSlotEmpty`]).
        let type_info_word = read_pointer(src, Va(s.va.get().saturating_add(ptr)), ptr_size);
        // The word before the first slot is a pointer — the address of the
        // class's own `type_info`, or a word a relocation writes — so it is the
        // `type_info` pointer, and the first slot is right after it. No offset
        // before `offset_to_top` is ever relocated.
        let type_info_placed = type_info_word.is_some_and(|w| w != 0 && own.contains(&w))
            || relocated.may_write(Va(s.va.get().saturating_add(ptr)), ptr);
        match read_pointer(src, Va(vtable), ptr_size) {
            None => {}                                                         // unreadable
            Some(0) if relocated.may_write(Va(vtable), ptr) => {}              // relocation-supplied
            Some(0) if type_info_placed => {}                                  // placed by its type_info pointer
            Some(0) => {
                refused.push(refuse(VtableRefusal::FirstSlotEmpty));
                continue;
            }
            Some(target) if in_code(target) => {} // resolved and points at code
            Some(_) => {
                refused.push(refuse(VtableRefusal::FirstSlotNotCode));
                continue;
            }
        }
        out.push(RttiVtable {
            vtable: Va(vtable),
            type_descriptor: Va(s.va.get().saturating_add(ptr)),
            name: itanium_class_name(&mangled),
            mangled,
            offset: 0,
            // From the class's own `_ZTI` where the image has one, with the
            // vtable's `type_info` pointer (its second word) as the
            // cross-check; from that pointer alone where it has none.
            bases: itanium_bases(src, own, type_info_word, &infos, ptr_size),
        });
    }
    out.sort_by_key(|v| v.vtable.get());
    refused.sort_by(|a: &RefusedVtable, b| a.mangled.cmp(&b.mangled));
    ItaniumScan { vtables: out, refused }
}

const COL_SIZE: usize = 24; // sig,u32 | offset,u32 | cdOffset,u32 | pTD,rva | pClass,rva | pSelf,rva
/// The 32-bit COL: the same five words **without** `pSelf`, and its pointer
/// fields are absolute VAs rather than image-relative RVAs.
const COL_SIZE_32: usize = 20;
const COL_PCLASS: usize = 16; // RVA of the RTTIClassHierarchyDescriptor
// RTTIClassHierarchyDescriptor: signature,u32 | attributes,u32 | numBaseClasses,u32 | pBaseClassArray,rva
const CHD_NUM_BASES: usize = 8;
const CHD_BASE_ARRAY: usize = 12;
/// Base-class count ceiling — bounds the walk so a mis-read descriptor can
/// never drive an unbounded loop/allocation (the OOM lesson, again).
const MAX_BASES: usize = 256;
/// Hard ceiling on a decorated type name — a mis-read pointer can never drive an
/// unbounded read (the OOM lesson). Real MSVC names, even deeply nested
/// template types, stay well under this; 512 was far too small and
/// truncated ~half of the Qt desktop PE's names mid-symbol, which then could not demangle.
const MAX_NAME: usize = 64 * 1024;
/// First read size for [`read_cstr`], doubled on each miss. Most names are short
/// and terminate inside this one small read; the long template names double their
/// way out in a few steps. A large fixed chunk would copy (and allocate) kilobytes
/// per name across tens of thousands of descriptors for no gain.
const NAME_CHUNK: usize = 256;
/// Ceiling on a single [`read_cstr`] read, so the doubling cannot request a huge
/// buffer for one pathological name.
const NAME_CHUNK_MAX: usize = 8192;
/// A hard ceiling so a mis-identified `.rdata` size can never drive an
/// unbounded allocation (the machine's OOM lesson, applied to a parsed length).
const MAX_RDATA: usize = 64 * 1024 * 1024;

fn u32_le(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64_le(b: &[u8], at: usize) -> Option<u64> {
    b.get(at..at + 8).map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

/// Scan `.rdata` for MSVC RTTI vtables.
///
/// **`ptr_size` is not a formality — the two MSVC RTTI dialects are different
/// structures**, and reading one as the other finds nothing rather than finding
/// something wrong:
///
/// | | 32-bit (signature 0) | 64-bit (signature 1) |
/// | --- | --- | --- |
/// | vtable/COL slots | 4 bytes | 8 bytes |
/// | COL's `pTypeDescriptor` etc. | **absolute VAs** | image-relative **RVAs** |
/// | COL size | 20 bytes | 24 bytes |
/// | `pSelf` | **absent** | present, and the strongest validity check there is |
/// | name inside the TypeDescriptor | at `+8` (two 4-byte slots) | at `+16` |
///
/// This scanner was written for 64-bit and applied to both, so on a 32-bit PE
/// it stepped 8 bytes at a time through 4-byte slots and resolved absolute
/// pointers as RVAs. It returned **0 classes for a 32-bit C++ runtime carrying
/// 95 MSVC type descriptors** — `ok: true`, an empty list, and nothing to
/// suggest the question had been asked in the wrong dialect.
///
/// **`data_ranges` is a list because the vtable is not always in `.rdata`.**
/// That is an MSVC-toolchain habit, not a property of PE: a mingw-built PE puts
/// its vtables in `.data`, and scanning only `.rdata` reported **0 classes for
/// a 32-bit C++ runtime whose COLs are laid out exactly as expected** — they
/// were simply in the section next door. Pass every initialized data range the
/// image has; a candidate still has to survive the signature, the `.?A` name
/// and the first-slot-in-code checks, so a wider search costs a scan and not
/// accuracy.
///
/// `image_base` resolves the 64-bit RVAs and is unused on 32-bit. `text` (when
/// known) gates a candidate on its first vtable slot pointing into code.
pub fn scan_msvc_rtti(
    src: &dyn MemorySource,
    image_base: Va,
    data_ranges: &[(Va, u64)],
    text: Option<(Va, u64)>,
    ptr_size: u8,
) -> Vec<RttiVtable> {
    let mut out = Vec::new();
    for &range in data_ranges {
        out.extend(scan_one_range(src, image_base, range, data_ranges, text, ptr_size));
    }
    out.sort_by_key(|v| v.vtable.get());
    out.dedup_by_key(|v| v.vtable.get());
    out
}

/// One data range's worth of the scan above. `all` is every range, because
/// **the vtable and the COL it points at need not be in the same section** — in
/// a mingw-built PE the vtable is in `.data` and its COL in `.rdata`, so a
/// membership test against the range being walked rejects every real hit.
fn scan_one_range(
    src: &dyn MemorySource,
    image_base: Va,
    rdata: (Va, u64),
    all: &[(Va, u64)],
    text: Option<(Va, u64)>,
    ptr_size: u8,
) -> Vec<RttiVtable> {
    let (rd_base, rd_len) = (rdata.0.get(), (rdata.1 as usize).min(MAX_RDATA));
    let Ok(buf) = src.read(Va(rd_base), rd_len) else {
        return Vec::new();
    };
    let wide = ptr_size >= 8;
    let step = if wide { 8usize } else { 4 };
    let col_size = if wide { COL_SIZE } else { COL_SIZE_32 };
    let td_name_at = 2 * step as u64;
    // A COL can live in any of the image's data ranges, not only this one.
    let in_data = |va: u64| all.iter().any(|(b, n)| va >= b.get() && va < b.get() + n);
    let in_text = |va: u64| text.is_none_or(|(t, n)| va >= t.get() && va < t.get() + n);
    // A pointer-sized slot, at the target's width.
    let slot = |at: usize| -> Option<u64> {
        if wide { u64_le(&buf, at) } else { u32_le(&buf, at).map(u64::from) }
    };
    // A COL field: an RVA to be rebased on 64-bit, already a VA on 32-bit.
    let field_va = |raw: u32| -> u64 {
        if wide { image_base.get().wrapping_add(raw as u64) } else { raw as u64 }
    };

    let mut out = Vec::new();
    // Every aligned slot is a candidate "pointer to a COL". A vtable is the slot
    // *after* such a pointer.
    let mut off = 0usize;
    while off + step <= buf.len() {
        let Some(col_ptr) = slot(off) else { break };
        if in_data(col_ptr) {
            // Read the COL through the source rather than out of this buffer:
            // it may be in a different section entirely.
            let col = src.read(Va(col_ptr), col_size).unwrap_or_default();
            // 64-bit's `pSelf` is the strongest check available: the COL points
            // at itself. 32-bit has no such field, so the signature word (which
            // is 0 there, by definition of the dialect) stands in — the real
            // filter for both is the type descriptor's `.?A` name below.
            let structurally_sound = if wide {
                u32_le(&col, 20).is_some_and(|p_self| field_va(p_self) == col_ptr)
            } else {
                u32_le(&col, 0).is_some_and(|sig| sig == 0)
            };
            if let (Some(offset), Some(p_td)) = (u32_le(&col, 4), u32_le(&col, 12))
                && col.len() >= col_size
                && structurally_sound
            {
                let vtable = rd_base + off as u64 + step as u64;
                if slot(off + step).is_some_and(in_text) {
                    let td_name_va = field_va(p_td) + td_name_at;
                    if let Some(mangled) = read_cstr(src, Va(td_name_va))
                        && mangled.starts_with(".?A")
                    {
                        let name = demangle_rtti_name(&mangled);
                        let pclass = u32_le(&col, COL_PCLASS).unwrap_or(0);
                        let bases = read_base_classes(&buf, rd_base, image_base.get(), src, pclass, ptr_size);
                        out.push(RttiVtable {
                            vtable: Va(vtable),
                            type_descriptor: Va(td_name_va - td_name_at),
                            mangled,
                            name,
                            offset,
                            bases,
                        });
                    }
                }
            }
        }
        off += step;
    }
    out
}

/// Ceiling on vtable slots walked per class — a mis-read vtable can never drive
/// an unbounded loop (the OOM lesson), and a real class rarely exceeds it.
const MAX_SLOTS: usize = 4096;

/// Turn recovered [`RttiVtable`]s into address→name maps for the symbol layer:
///
/// - **data**: each vtable address → `Class::vftable` (a secondary base under
///   multiple inheritance gets `Class::vftable_offN`). This is **sound** — that
///   address *is* that class's vtable — so it names every vtable constant the
///   decompiler prints and every vtable address the listing/xref shows.
/// - **functions**: each in-`.text` method slot → `Class::vfN`. A method inherited
///   by several classes points to one function from many vtables; the first class
///   to reach it keeps the name (iteration is `.rdata` order). This is a
///   decompiler **aid, not ground truth** — a user rename overrides it — so it is
///   deliberately first-writer-wins rather than guessing the defining class.
///
/// The walk of a vtable stops at the first slot that does not point into `.text`
/// (past the last virtual method) or that coincides with another known vtable's
/// start (the adjacent class), so one class never claims another's slots.
///
/// Slots are `ptr_size` bytes, the image's pointer size — the width the scan
/// that produced `vtables` read them at. At a fixed eight bytes, a 32-bit
/// image's first two slots read as one value, which is no code address, so on
/// a PE32 or a 32-bit ELF the walk ended before the first method — unless the
/// word after it was zero, which made a one-method table come out right by
/// coincidence — and every later slot was skipped.
///
/// A slot [`VtableSlots::method`] refuses — a Thumb method on `EM_ARM` — is
/// walked past, not named, and counted in [`RttiSymbols::thumb_slots_refused`].
pub fn rtti_symbol_map(src: &dyn MemorySource, vtables: &[RttiVtable], text: Option<(Va, u64)>, slots: VtableSlots) -> RttiSymbols {
    use std::collections::{BTreeMap, BTreeSet};
    let ptr_size = slots.pointer_size;
    let in_text = |va: u64| text.is_none_or(|(t, n)| va >= t.get() && va < t.get() + n);
    let starts: BTreeSet<u64> = vtables.iter().map(|v| v.vtable.get()).collect();

    let mut functions: BTreeMap<u64, String> = BTreeMap::new();
    let mut data: BTreeMap<u64, String> = BTreeMap::new();
    let mut thumb_slots_refused = 0usize;
    for v in vtables {
        let vtable = v.vtable.get();
        let label = if v.offset != 0 {
            format!("{}::vftable_off{}", v.name, v.offset)
        } else {
            format!("{}::vftable", v.name)
        };
        data.entry(vtable).or_insert(label);

        let mut i = 0usize;
        while i < MAX_SLOTS {
            let slot_addr = vtable + (i as u64) * u64::from(ptr_size);
            // Don't run into the next class's vtable.
            if i > 0 && starts.contains(&slot_addr) {
                break;
            }
            let Some(target) = read_pointer(src, Va(slot_addr), ptr_size) else { break };
            if !in_text(target) {
                break; // past the last virtual method
            }
            // Still a method of this table, so the walk goes on and the next
            // slot keeps its index; only the name is withheld.
            match slots.method(target) {
                Ok(method) => {
                    functions.entry(method).or_insert_with(|| format!("{}::vf{}", v.name, i));
                }
                Err(ThumbSlot) => thumb_slots_refused += 1,
            }
            i += 1;
        }
    }
    RttiSymbols { functions, data, thumb_slots_refused }
}

/// What [`rtti_symbol_map`] names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RttiSymbols {
    /// Method address → `Class::vfN`.
    pub functions: std::collections::BTreeMap<u64, String>,
    /// Vtable address → `Class::vftable`.
    pub data: std::collections::BTreeMap<u64, String>,
    /// Slots walked and not named because their value is a Thumb code pointer
    /// on `EM_ARM` (see [`VtableSlots::method`]) — one per slot, so a method
    /// two tables hold counts twice.
    pub thumb_slots_refused: usize,
}

/// Walk an MSVC RTTI class-hierarchy descriptor to the class's base-class
/// names. `pclass_rva` is the COL's `pClassDescriptor` RVA; the descriptor's
/// base-class array holds, most-derived first, an entry per class in the
/// hierarchy — index 0 is the class itself, so 1.. are its bases. Every
/// structure here lives in `.rdata`, so reads index the already-loaded buffer.
/// Bounded by [`MAX_BASES`].
///
/// Anything that cannot be read makes the bases **unknown**, never shorter: a
/// base dropped from the list read as "not derived from that", and an
/// unreadable descriptor read as "no bases", which the subclass guard of
/// devirtualization took for a fact.
///
/// Measured where it says so: on two i386 PE32 DLLs (Wine's mingw-built
/// `msvcp140` and `ucrtbase`) **every** class is `hierarchy-unreadable`, the
/// hierarchy descriptor not being in the ranges read; the build before omitted
/// the key, which read as "no bases". The 64-bit MSVC side is **not measured**:
/// no MSVC-built PE32+ was at hand, and Wine's x86-64 DLLs give no class at all
/// before or after.
fn read_base_classes(
    buf: &[u8],
    rd_base: u64,
    image_base: u64,
    src: &dyn MemorySource,
    pclass_rva: u32,
    ptr_size: u8,
) -> Bases {
    let unreadable = Bases::Unknown { bases_unknown: BasesUnknown::HierarchyUnreadable };
    let mut bases = Vec::new();
    if pclass_rva == 0 {
        return unreadable;
    }
    // Same dialect split as the COL above: a 64-bit descriptor holds RVAs, a
    // 32-bit one holds absolute VAs.
    let wide = ptr_size >= 8;
    let to_va = |raw: u32| -> u64 { if wide { image_base.wrapping_add(raw as u64) } else { raw as u64 } };
    let at = |rva: u32| -> Option<usize> {
        let va = to_va(rva);
        (va >= rd_base && va < rd_base + buf.len() as u64).then_some((va - rd_base) as usize)
    };
    let Some(chd) = at(pclass_rva) else { return unreadable };
    let (Some(num), Some(bca_rva)) = (u32_le(buf, chd + CHD_NUM_BASES), u32_le(buf, chd + CHD_BASE_ARRAY)) else {
        return unreadable;
    };
    let Some(bca) = at(bca_rva) else { return unreadable };
    let num = (num as usize).min(MAX_BASES);
    // Skip index 0 (the class itself); collect the remaining bases in order.
    for i in 1..num {
        let Some(bcd_rva) = u32_le(buf, bca + i * 4) else { return unreadable };
        let Some(bcd) = at(bcd_rva) else { return unreadable };
        // BaseClassDescriptor's first field is its TypeDescriptor RVA; the
        // decorated name sits 16 bytes into the TypeDescriptor (past its two
        // leading pointer slots), exactly as for the primary type above.
        let Some(td_rva) = u32_le(buf, bcd) else { return unreadable };
        let td_name_va = to_va(td_rva) + if wide { 16 } else { 8 };
        match read_cstr(src, Va(td_name_va)) {
            Some(m) if m.starts_with(".?A") => bases.push(demangle_rtti_name(&m)),
            _ => return unreadable,
        }
    }
    Bases::Known { bases }
}

/// Read a NUL-terminated ASCII string, the shape a `TypeDescriptor` name has.
///
/// Grows a chunk at a time until the terminator, capped by [`MAX_NAME`]. A single
/// large read would truncate long names on a source that clamps to what a section
/// physically holds ([`MemorySource::read`] returns a short/empty `Vec` at a
/// boundary, never an error), and reading `MAX_NAME` up front for every descriptor
/// would churn 64 KiB per name; growing keeps the common short name to one read
/// while still reaching the multi-KiB template names heavy C++ template code produces.
fn read_cstr(src: &dyn MemorySource, at: Va) -> Option<String> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut step = NAME_CHUNK;
    while bytes.len() < MAX_NAME {
        let want = step.min(MAX_NAME - bytes.len());
        let chunk = src.read(Va(at.get() + bytes.len() as u64), want).ok()?;
        if let Some(pos) = chunk.iter().position(|&b| b == 0) {
            bytes.extend_from_slice(&chunk[..pos]);
            break;
        }
        let short = chunk.len() < want; // clamped at the section boundary — no more to read
        bytes.extend_from_slice(&chunk);
        if short {
            break;
        }
        step = (step * 2).min(NAME_CHUNK_MAX);
    }
    (!bytes.is_empty()).then(|| String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A data symbol as a static ELF reports it.
    fn ds(va: u64, name: &str, size: Option<u64>) -> DataSymbol {
        DataSymbol { va: Va(va), name: name.to_string(), size }
    }

    /// The relocations of a planted image that does not say: a zero is taken
    /// for a word the loader may fill, as every test here before the
    /// relocations were read planted it.
    const UNREAD: RelocatedWords = RelocatedWords::NotRead(n0xis_sources::RelocationsNotRead::NoImage);

    const SLOTS_64: VtableSlots = VtableSlots { pointer_size: 8, code_pointers: CodePointers::Address };
    const SLOTS_32: VtableSlots = VtableSlots { pointer_size: 4, code_pointers: CodePointers::Address };

    /// Lay out an Itanium `type_info` graph the way a linked shared object
    /// does: the pointers inside it are supplied by *relative* relocations,
    /// whose addend sits at the target location — so they read straight out of
    /// the image. Anything a relocation cannot supply locally (a base in
    /// another library) reads as zero.
    fn itanium_image() -> n0xis_sources::Snapshot {
        use n0xis_contracts::{SymKind, Symbol};
        const BASE: u64 = 0x10000;
        let put = |buf: &mut Vec<u8>, at: usize, v: u64| buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
        let mut data = vec![0u8; 0x200];
        // 0x10000 _ZTI4Base : { vptr, name } and no bases
        // 0x10040 _ZTI7Derived (single base) : { vptr, name, Base }
        put(&mut data, 0x50, BASE); // +0x40 +0x10 -> &_ZTI4Base
        // 0x10080 _ZTI4Both (two bases) : { vptr, name, flags|count=2, {Base,f}, {Derived,f} }
        put(&mut data, 0x90, 2u64 << 32); // flags=0, base_count=2
        put(&mut data, 0x98, BASE); //        base 0 -> Base
        put(&mut data, 0xa8, BASE + 0x40); // base 1 -> Derived
        // the three vtables, each with `type_info` in its second word
        put(&mut data, 0x108, BASE); //        _ZTV4Base    + 8
        put(&mut data, 0x128, BASE + 0x40); // _ZTV7Derived + 8
        put(&mut data, 0x148, BASE + 0x80); // _ZTV4Both    + 8
        let sym = |va: u64, n: &str| Symbol { va: Va(va), name: n.into(), kind: SymKind::Data, module: String::new() };
        n0xis_sources::Snapshot::builder()
            .region(Va(BASE), data)
            .symbol(sym(BASE, "_ZTI4Base"))
            .symbol(sym(BASE + 0x40, "_ZTI7Derived"))
            .symbol(sym(BASE + 0x80, "_ZTI4Both"))
            .symbol(sym(BASE + 0x100, "_ZTV4Base"))
            .symbol(sym(BASE + 0x120, "_ZTV7Derived"))
            .symbol(sym(BASE + 0x140, "_ZTV4Both"))
            .build()
    }

    #[test]
    fn itanium_base_classes_are_read_from_the_image() {
        // The comment this replaced said base classes "need relocation
        // resolution to read", so `bases` came back empty on every ELF and the
        // hierarchy — which is what tells a *sound* devirtualization from an
        // unsound one — did not exist.
        let snap = itanium_image();
        // With the sizes a linker records for them: `type_info`s of two, three
        // and 2 + 1 + 2·2 pointers (no base, one, two), and vtables of two
        // pointers of header and none, one or one method.
        let syms: Vec<DataSymbol> = [
            (0x10000u64, "_ZTI4Base", 16), (0x10040, "_ZTI7Derived", 24), (0x10080, "_ZTI4Both", 56),
            (0x10100, "_ZTV4Base", 16), (0x10120, "_ZTV7Derived", 16), (0x10140, "_ZTV4Both", 16),
        ]
        .iter()
        .map(|&(v, n, size)| ds(v, n, Some(size)))
        .collect();
        let out = scan_itanium_rtti(&snap, &syms, &[], 8, &UNREAD).vtables;
        let by: std::collections::HashMap<&str, &[String]> =
            out.iter().map(|v| (v.name.as_str(), v.bases.known().expect("every type_info here reads out of the image"))).collect();
        assert_eq!(by.get("Base").map(|b| b.len()), Some(0), "a class with no bases states none");
        assert_eq!(by.get("Derived").copied(), Some(["Base".to_string()].as_slice()));
        let both = by.get("Both").expect("Both").to_vec();
        assert_eq!(both.len(), 2, "multiple inheritance walks the base_info array: {both:?}");
        assert!(both.contains(&"Base".to_string()) && both.contains(&"Derived".to_string()), "{both:?}");
    }

    /// The same graph as [`itanium_image`] at **4-byte** pointers, as an
    /// `ELFCLASS32` image lays it out: a `type_info` is `{ vptr, name }` in 8
    /// bytes, a single base follows at `+8`, `__vmi_class_type_info` keeps its
    /// two `unsigned int`s at `+8` and `+12` and its 8-byte `__base_info`s from
    /// `+16`, and a vtable's first slot is 8 bytes past its symbol. Code sits at
    /// `0x1000`, and every table's first slot points into it.
    fn itanium_image_32() -> (n0xis_sources::Snapshot, Vec<DataSymbol>) {
        const BASE: u64 = 0x10000;
        let put = |buf: &mut Vec<u8>, at: usize, v: u32| buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
        let b = BASE as u32;
        let mut data = vec![0u8; 0x200];
        // 0x10000 _ZTI4Base : { vptr, name }, no bases
        // 0x10020 _ZTI7Derived : { vptr, name, &_ZTI4Base }
        put(&mut data, 0x28, b);
        // 0x10040 _ZTI4Both : { vptr, name, flags, count=2, {Base, off}, {Derived, off} }
        put(&mut data, 0x4c, 2);
        put(&mut data, 0x50, b);
        put(&mut data, 0x58, b + 0x20);
        // _ZTV4Base at 0x10100: offset_to_top, &_ZTI4Base, then two methods.
        put(&mut data, 0x104, b);
        put(&mut data, 0x108, 0x1000);
        put(&mut data, 0x10c, 0x1008);
        // _ZTV7Derived at 0x10120, _ZTV4Both at 0x10140: one method each.
        put(&mut data, 0x124, b + 0x20);
        put(&mut data, 0x128, 0x1010);
        put(&mut data, 0x144, b + 0x40);
        put(&mut data, 0x148, 0x1018);
        let snap = n0xis_sources::Snapshot::builder().region(Va(0x1000), vec![0xC3; 0x100]).region(Va(BASE), data).build();
        // The sizes a linker records at 4-byte pointers: 8, 12 and 8 + 8 + 2·8.
        let syms = [
            (BASE, "_ZTI4Base", 8), (BASE + 0x20, "_ZTI7Derived", 12), (BASE + 0x40, "_ZTI4Both", 32),
            (BASE + 0x100, "_ZTV4Base", 16), (BASE + 0x120, "_ZTV7Derived", 12), (BASE + 0x140, "_ZTV4Both", 12),
        ]
        .iter()
        .map(|&(v, n, size)| ds(v, n, Some(size)))
        .collect();
        (snap, syms)
    }

    /// At 4-byte pointers the stored vptr is two pointers — 8 bytes — into the
    /// `_ZTV` object. Read with a 16-byte header and 8-byte slots, as it was,
    /// the scan put `Base` at `0x10110` (zeros there pass as a slot the loader
    /// fills) and skipped `Derived` and `Both`, whose "first slot" joined two
    /// words into a value that is no code address.
    #[test]
    fn a_32_bit_itanium_vtable_is_two_4_byte_pointers_past_its_symbol() {
        let (snap, syms) = itanium_image_32();
        let out = scan_itanium_rtti(&snap, &syms, &[(Va(0x1000), 0x100)], 4, &UNREAD).vtables;
        let at: Vec<(&str, u64, u64)> = out.iter().map(|v| (v.name.as_str(), v.vtable.get(), v.type_descriptor.get())).collect();
        assert_eq!(at, vec![("Base", 0x10108, 0x10104), ("Derived", 0x10128, 0x10124), ("Both", 0x10148, 0x10144)]);
        let by: std::collections::HashMap<&str, &[String]> = out.iter().map(|v| (v.name.as_str(), v.bases.known().expect("read"))).collect();
        assert_eq!(by["Base"].len(), 0);
        assert_eq!(by["Derived"], ["Base".to_string()].as_slice(), "the single base sits one pointer after the name");
        assert_eq!(by["Both"], ["Base".to_string(), "Derived".to_string()].as_slice(), "8-byte __base_info entries from +16");
    }

    /// The slot walk at the image's width names each method once. At eight
    /// bytes it read `Base`'s two slots as one value and named nothing.
    #[test]
    fn a_32_bit_vtable_walk_names_each_4_byte_slot() {
        let (snap, syms) = itanium_image_32();
        let text = Some((Va(0x1000), 0x100));
        let vts = scan_itanium_rtti(&snap, &syms, &[(Va(0x1000), 0x100)], 4, &UNREAD).vtables;
        let RttiSymbols { functions, data, .. } = rtti_symbol_map(&snap, &vts, text, SLOTS_32);
        assert_eq!(data.get(&0x10108).map(String::as_str), Some("Base::vftable"));
        let named: Vec<(u64, &str)> = functions.iter().map(|(va, n)| (*va, n.as_str())).collect();
        assert_eq!(named, vec![(0x1000, "Base::vf0"), (0x1008, "Base::vf1"), (0x1010, "Derived::vf0"), (0x1018, "Both::vf0")]);
    }

    #[test]
    fn demangles_a_plain_and_a_namespaced_class() {
        assert_eq!(demangle_rtti_name(".?AVFoo@@"), "Foo");
        assert_eq!(demangle_rtti_name(".?AUData@Ns@@"), "Ns::Data");
        // a real third-party physics-engine class name from the corpus
        assert_eq!(
            demangle_rtti_name(".?AUAccelerationData@hkaiGeometrySegmentCaster@@"),
            "hkaiGeometrySegmentCaster::AccelerationData",
        );
    }

    #[test]
    fn a_template_name_is_fully_demangled_via_the_msvc_demangler() {
        // `?$` is a template; the hand-rolled `@`-splitter refuses it, but the
        // real MSVC demangler (wrapping it as an `??_R0…@8` type descriptor)
        // reads it — a readable class name, never mis-decoded nonsense.
        assert_eq!(demangle_rtti_name(".?AV?$vector@H@std@@"), "std::vector<int>");
        // A real third-party physics-engine template name from the corpus
        // demangles rather than falling through to verbatim.
        assert_eq!(
            demangle_rtti_name(".?AV?$basic_ios@EU?$char_traits@E@std@@@std@@"),
            "std::basic_ios<unsigned char, struct std::char_traits<unsigned char> >",
        );
    }

    #[test]
    fn itanium_vtable_symbol_names_its_class() {
        use n0xis_sources::Snapshot;
        // A `_ZTV` object is [offset_to_top][typeinfo][fn0…]; the pointer an
        // object stores is +16, and the ELF symbol-version suffix must not reach
        // the demangler.
        let mut vt = vec![0u8; 32];
        vt[16..24].copy_from_slice(&0x1000u64.to_le_bytes());
        let snap = Snapshot::builder().region(Va(0x1000), vec![0xC3]).region(Va(0x2000), vt).build();
        let syms = [ds(0x2000, "_ZTVSt10lock_error@@GLIBCXX_3.4.11", None)];
        let vts = scan_itanium_rtti(&snap, &syms, &[(Va(0x1000), 0x100)], 8, &UNREAD).vtables;
        assert_eq!(vts.len(), 1);
        assert_eq!(vts[0].vtable, Va(0x2010), "the stored vptr is 16 bytes into the _ZTV object");
        assert_eq!(vts[0].name, "std::lock_error");
    }

    #[test]
    fn a_relocation_supplied_slot_does_not_disqualify_a_vtable() {
        use n0xis_sources::Snapshot;
        // In a shared object the method slots are filled by the loader and read
        // as zero from the file. Requiring a resolved code pointer here rejected
        // 178 of libstdc++'s 179 vtables; the `_ZTV` symbol is authoritative.
        let snap = Snapshot::builder().region(Va(0x2000), vec![0u8; 32]).build();
        let syms = [ds(0x2000, "_ZTV3Foo", None)];
        assert_eq!(scan_itanium_rtti(&snap, &syms, &[(Va(0x1000), 0x100)], 8, &UNREAD).vtables.len(), 1);
    }

    #[test]
    fn a_slot_resolving_outside_code_is_rejected() {
        use n0xis_sources::Snapshot;
        let mut vt = vec![0u8; 32];
        vt[16..24].copy_from_slice(&0xDEAD_0000u64.to_le_bytes()); // not in .text
        let snap = Snapshot::builder().region(Va(0x2000), vt).build();
        let syms = [ds(0x2000, "_ZTV3Foo", None)];
        assert!(scan_itanium_rtti(&snap, &syms, &[(Va(0x1000), 0x100)], 8, &UNREAD).vtables.is_empty());
    }

    #[test]
    fn a_non_rtti_string_passes_through() {
        assert_eq!(demangle_rtti_name("not a name"), "not a name");
    }

    #[test]
    fn a_declined_name_is_reduced_to_a_readable_label_never_a_raw_blob() {
        // Both demanglers declined → the input is still the raw decorated string
        // (the `<lambda>`-in-a-local-scope names `msvc_demangler` 0.11 cannot
        // parse). It must not render as a `.?A…` blob: reduce to the leading
        // template identifier so the listing stays readable.
        let raw = ".?AV?$consumer_handlers@VQString@@Uno_error@rpl@@V<lambda_1>@?1??".to_string();
        assert_eq!(shorten_type_name(raw.clone(), &raw), "consumer_handlers<…>");
        // A plain (non-template) decorated name keeps its identifier, no `<…>`.
        let plain = ".?AVWeird@@".to_string();
        assert_eq!(shorten_type_name(plain.clone(), &plain), "Weird");
    }

    #[test]
    fn a_giant_demangled_name_is_truncated_with_a_stable_disambiguator() {
        // A demangled STL type-erasure name runs to multiple KiB — bound it.
        let huge = format!("std::_Func_impl_no_alloc<{}>", "class rpl::details::x, ".repeat(200));
        let a = shorten_type_name(huge.clone(), ".?AVdecorated_a@@");
        assert!(a.len() <= RENDER_NAME_MAX + 12, "must be bounded, got {} bytes", a.len());
        assert!(a.starts_with("std::_Func_impl_no_alloc<") && a.contains('…'));
        // Two distinct types sharing that long opening must not collide.
        let b = shorten_type_name(huge, ".?AVdecorated_b@@");
        assert_ne!(a, b);
    }

    #[test]
    fn a_short_name_is_untouched_by_the_bound() {
        assert_eq!(shorten_type_name("Ns::Foo".to_string(), ".?AVFoo@Ns@@"), "Ns::Foo");
    }

    #[test]
    fn scans_a_synthetic_vtable_and_recovers_its_base_classes() {
        use n0xis_sources::Snapshot;
        let image_base = 0x140000000u64;
        let rd_base = 0x140010000u64;
        let mut buf = vec![0u8; 0x800];
        let put_u32 = |b: &mut [u8], off: usize, v: u32| b[off..off + 4].copy_from_slice(&v.to_le_bytes());
        let put_u64 = |b: &mut [u8], off: usize, v: u64| b[off..off + 8].copy_from_slice(&v.to_le_bytes());
        let put_str = |b: &mut [u8], off: usize, s: &str| b[off..off + s.len()].copy_from_slice(s.as_bytes());
        let rva = |off: usize| ((rd_base + off as u64) - image_base) as u32;
        // TypeDescriptors: name sits 16 bytes in (past two pointer slots).
        put_str(&mut buf, 0x110, ".?AVDerived@@\0");
        put_str(&mut buf, 0x150, ".?AVBase1@@\0");
        put_str(&mut buf, 0x190, ".?AVBase2@@\0");
        // BaseClassDescriptors: first field is the TypeDescriptor RVA. Index 0 is
        // the class itself, 1 and 2 its bases.
        put_u32(&mut buf, 0x1e0, rva(0x100)); // BCD0 -> self TD
        put_u32(&mut buf, 0x200, rva(0x140)); // BCD1 -> Base1 TD
        put_u32(&mut buf, 0x220, rva(0x180)); // BCD2 -> Base2 TD
        // Base-class array: three BCD RVAs.
        put_u32(&mut buf, 0x260, rva(0x1e0));
        put_u32(&mut buf, 0x264, rva(0x200));
        put_u32(&mut buf, 0x268, rva(0x220));
        // ClassHierarchyDescriptor: numBaseClasses=3, pBaseClassArray.
        put_u32(&mut buf, 0x288, 3);
        put_u32(&mut buf, 0x28c, rva(0x260));
        // CompleteObjectLocator: pTD, pClassDescriptor, and the self-reference.
        put_u32(&mut buf, 0x2a0 + 12, rva(0x100)); // pTypeDescriptor
        put_u32(&mut buf, 0x2a0 + 16, rva(0x280)); // pClassHierarchyDescriptor
        put_u32(&mut buf, 0x2a0 + 20, rva(0x2a0)); // pSelf (validates the COL)
        // The vtable: a COL pointer, then a first slot pointing into "code".
        put_u64(&mut buf, 0x300, rd_base + 0x2a0); // -> COL
        put_u64(&mut buf, 0x308, 0x140001000); // first method slot

        let snap = Snapshot::builder().region(Va(rd_base), buf).build();
        let vts = scan_msvc_rtti(&snap, Va(image_base), &[(Va(rd_base), 0x800)], None, 8);
        assert_eq!(vts.len(), 1, "{vts:#?}");
        assert_eq!(vts[0].name, "Derived");
        assert_eq!(vts[0].vtable, Va(rd_base + 0x308));
        assert_eq!(vts[0].bases, Bases::Known { bases: vec!["Base1".to_string(), "Base2".to_string()] });
    }

    #[test]
    fn symbol_map_names_the_vtable_and_walks_method_slots() {
        use n0xis_sources::Snapshot;
        let text = (Va(0x140001000), 0x1000u64);
        let vt = Va(0x140010000);
        // Two in-`.text` method pointers, then a null (stops the walk).
        let mut buf = vec![0u8; 0x20];
        buf[0..8].copy_from_slice(&0x140001000u64.to_le_bytes()); // vf0
        buf[8..16].copy_from_slice(&0x140001100u64.to_le_bytes()); // vf1
        // buf[16..24] stays 0 → not in .text → walk stops after vf1.
        let snap = Snapshot::builder().region(vt, buf).build();

        let vts = vec![RttiVtable {
            vtable: vt,
            type_descriptor: Va(0),
            mangled: ".?AVFoo@@".into(),
            name: "Foo".into(),
            offset: 0,
            bases: Bases::none(),
        }];
        let RttiSymbols { functions, data, .. } = rtti_symbol_map(&snap, &vts, Some(text), SLOTS_64);

        assert_eq!(data.get(&vt.get()).map(String::as_str), Some("Foo::vftable"));
        assert_eq!(functions.get(&0x140001000).map(String::as_str), Some("Foo::vf0"));
        assert_eq!(functions.get(&0x140001100).map(String::as_str), Some("Foo::vf1"));
        assert_eq!(functions.len(), 2, "the null slot must end the walk");
    }

    /// A class whose vtable group has a VTT has virtual bases, and its vtable
    /// starts with virtual-base offsets: `_ZTV` + two pointers is its
    /// `type_info` slot, not its first method. Planted the way
    /// `libstdc++.so.6`'s `basic_stringstream<char>` is laid out (one
    /// virtual-base offset, `offset_to_top`, the `type_info` pointer, then the
    /// methods); reported at `_ZTV` + 16 before, which is where the relocation
    /// naming its `_ZTI` sits.
    #[test]
    fn a_class_with_a_vtt_is_refused_not_placed() {
        use n0xis_sources::Snapshot;
        let mut vt = vec![0u8; 0x40];
        vt[0..8].copy_from_slice(&0x48u64.to_le_bytes()); // virtual-base offset
        // offset_to_top 0, type_info 0 (a relocation), then two methods
        vt[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
        vt[32..40].copy_from_slice(&0x1008u64.to_le_bytes());
        let snap = Snapshot::builder().region(Va(0x1000), vec![0xC3; 0x100]).region(Va(0x2000), vt).build();
        let syms = [
            ds(0x2000, "_ZTV3Vir@@V_1", None),
            ds(0x2100, "_ZTT3Vir@@V_1", None),
            ds(0x2200, "_ZTV5Plain", None),
        ];
        let scan = scan_itanium_rtti(&snap, &syms, &[(Va(0x1000), 0x100)], 8, &UNREAD);
        let listed: Vec<&str> = scan.vtables.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(listed, vec!["Plain"], "a class with virtual bases has no vptr to report");
        assert_eq!(scan.refused, vec![RefusedVtable { mangled: "_ZTV3Vir".into(), name: "Vir".into(), reason: VtableRefusal::VirtualBases }]);
        assert_eq!(scan.count_refused(VtableRefusal::VirtualBases), 1);
    }

    /// A `type_info` pointer that reads zero is a relocation the file does not
    /// hold: the bases are unknown, which is not "none". All 179 classes of
    /// `libstdc++.so.6` were reported with no bases this way.
    #[test]
    fn a_zero_type_info_pointer_leaves_the_bases_unknown() {
        use n0xis_sources::Snapshot;
        let snap = Snapshot::builder().region(Va(0x2000), vec![0u8; 32]).build();
        let syms = [ds(0x2000, "_ZTV3Foo", None)];
        let scan = scan_itanium_rtti(&snap, &syms, &[(Va(0x1000), 0x100)], 8, &UNREAD);
        assert_eq!(scan.vtables[0].bases, Bases::Unknown { bases_unknown: BasesUnknown::TypeInfoNotInFile });
    }

    /// The JSON keeps `bases` an array wherever the bases are known — `[]` for
    /// none — and says why where they are not, with no `bases` key at all.
    #[test]
    fn bases_serialize_as_an_array_or_a_reason() {
        let v = |bases| RttiVtable { vtable: Va(0x10), type_descriptor: Va(0x8), mangled: "_ZTV1A".into(), name: "A".into(), offset: 0, bases };
        let none = serde_json::to_value(v(Bases::none())).unwrap();
        assert_eq!(none["bases"], serde_json::json!([]));
        assert!(none.get("bases_unknown").is_none());
        let two = serde_json::to_value(v(Bases::Known { bases: vec!["B".into(), "C".into()] })).unwrap();
        assert_eq!(two["bases"], serde_json::json!(["B", "C"]));
        let unknown = serde_json::to_value(v(Bases::Unknown { bases_unknown: BasesUnknown::TypeInfoNotInFile })).unwrap();
        assert!(unknown.get("bases").is_none(), "{unknown}");
        assert_eq!(unknown["bases_unknown"], "type-info-not-in-file");
        // And back, so a stored scan reads as it was written.
        for json in [none, two, unknown] {
            let back: RttiVtable = serde_json::from_value(json.clone()).unwrap();
            assert_eq!(serde_json::to_value(back).unwrap(), json);
        }
    }

    /// The subclass guard's rule: a class is known not to be derived from only
    /// when every class's bases were read — a class whose bases are unknown,
    /// or one the scan refused, may derive from any of them.
    #[test]
    fn one_unknown_class_makes_every_class_possibly_subclassed() {
        let v = |name: &str, bases| RttiVtable { vtable: Va(0), type_descriptor: Va(0), mangled: String::new(), name: name.into(), offset: 0, bases };
        let read = [v("Base", Bases::none()), v("Derived", Bases::Known { bases: vec!["Base".into()] })];
        let known = Subclasses::of(&read, 0, PROGRAM);
        assert!(known.may_have_subclass("Base") && !known.may_have_subclass("Derived"), "{known:?}");
        let refused_one = Subclasses::of(&read, 1, PROGRAM);
        assert_eq!(refused_one, Subclasses::Unknown { classes: 1 });
        assert!(refused_one.may_have_subclass("Derived"));
        let mut unread = read.to_vec();
        unread.push(v("Other", Bases::Unknown { bases_unknown: BasesUnknown::TypeInfoNotInFile }));
        assert!(Subclasses::of(&unread, 0, PROGRAM).may_have_subclass("Derived"));
    }

    /// The hierarchies the guard's tests read are a program's: in a library
    /// every class may have a subclass ([`a_librarys_classes_may_each_have_a_subclass`]).
    const PROGRAM: n0xis_sources::Linkage = n0xis_sources::Linkage::Executable;

    /// A library's classes may each be derived from in the program that loads
    /// it, so its set is open even where every base was read and nothing in
    /// it derives from `Derived`.
    #[test]
    fn a_librarys_classes_may_each_have_a_subclass() {
        let v = |name: &str, bases| RttiVtable { vtable: Va(0), type_descriptor: Va(0), mangled: String::new(), name: name.into(), offset: 0, bases };
        let read = [v("Base", Bases::none()), v("Derived", Bases::Known { bases: vec!["Base".into()] })];
        assert!(!Subclasses::of(&read, 0, PROGRAM).may_have_subclass("Derived"), "in a program nothing derives from Derived");
        let library = Subclasses::of(&read, 0, n0xis_sources::Linkage::SharedLibrary);
        assert_eq!(library, Subclasses::Open);
        assert!(library.may_have_subclass("Derived"), "a client may derive from Derived");
    }

    /// On `EM_ARM` a slot whose value has bit 0 set is a Thumb method; the walk
    /// goes past it, names nothing there, and counts it. Read as an address it
    /// was named at the odd value — what `analyze` persisted on a Thumb build.
    #[test]
    fn a_thumb_slot_is_walked_counted_and_not_named() {
        use n0xis_sources::Snapshot;
        let text = (Va(0x1000), 0x100u64);
        let vt = Va(0x2000);
        let mut buf = vec![0u8; 0x10];
        buf[0..4].copy_from_slice(&0x1001u32.to_le_bytes()); // Thumb
        buf[4..8].copy_from_slice(&0x1010u32.to_le_bytes()); // A32
        let snap = Snapshot::builder().region(vt, buf).build();
        let vts = vec![RttiVtable { vtable: vt, type_descriptor: Va(0), mangled: "_ZTV3Foo".into(), name: "Foo".into(), offset: 0, bases: Bases::none() }];
        let arm = VtableSlots { pointer_size: 4, code_pointers: CodePointers::ArmInterworking };
        let named = rtti_symbol_map(&snap, &vts, Some(text), arm);
        assert_eq!(named.functions.into_iter().collect::<Vec<_>>(), vec![(0x1010, "Foo::vf1".to_string())], "the A32 slot keeps its index");
        assert_eq!(named.thumb_slots_refused, 1);
        let plain = rtti_symbol_map(&snap, &vts, Some(text), SLOTS_32);
        assert_eq!(plain.functions.get(&0x1001).map(String::as_str), Some("Foo::vf0"), "elsewhere the value is the address");
        assert_eq!(plain.thumb_slots_refused, 0);
    }

    /// A planted image for the virtual-base facts: one `_ZTV3Vir` of `words`
    /// at `0x2000`, code at `0x1000`, and, where given, a `_ZTI3Vir` at
    /// `0x2100` of `zti_size` bytes holding `zti`.
    fn vir_image(words: &[u64], zti: &[u64], zti_size: Option<u64>) -> (n0xis_sources::Snapshot, Vec<DataSymbol>) {
        let bytes = |ws: &[u64]| ws.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
        let mut syms = vec![ds(0x2000, "_ZTV3Vir", Some(8 * words.len() as u64))];
        let mut b = n0xis_sources::Snapshot::builder().region(Va(0x1000), vec![0xC3; 0x100]).region(Va(0x2000), bytes(words));
        if let Some(size) = zti_size {
            syms.push(ds(0x2100, "_ZTI3Vir", Some(size)));
            b = b.region(Va(0x2100), bytes(zti));
        }
        (b.build(), syms)
    }

    fn refused_for_virtual_bases(words: &[u64], zti: &[u64], zti_size: Option<u64>) -> bool {
        let (snap, syms) = vir_image(words, zti, zti_size);
        let scan = scan_itanium_rtti(&snap, &syms, &[(Va(0x1000), 0x100)], 8, &UNREAD);
        let refused = scan.count_refused(VtableRefusal::VirtualBases) == 1;
        assert_eq!(refused, scan.vtables.is_empty(), "a class is either listed or refused: {scan:?}");
        refused
    }

    /// No VTT, and the first word of the table is not `offset_to_top` = 0: a
    /// virtual-base offset, as in a class with two virtual bases that have
    /// data. Laid out as clang -O2 lays out `M : virtual A, virtual B` with no
    /// key function (`vbinline.cpp`), whose table it emits without a VTT; the
    /// `type_info` slot reads zero, as in a shared object.
    #[test]
    fn a_vtable_that_begins_with_an_offset_is_refused_without_a_vtt() {
        assert!(refused_for_virtual_bases(&[0x20, 0x10, 0, 0, 0x1000], &[], None), "a virtual-base offset where offset_to_top is");
        // The same table without the offsets is placed.
        assert!(!refused_for_virtual_bases(&[0, 0, 0x1000], &[], None));
    }

    /// A virtual base that shares the vptr (a nearly-empty primary base) has a
    /// virtual-base offset of 0, so the first word is 0 too; but the class's
    /// own `type_info` address is in the table three words in, so the address
    /// point is four words in, not two.
    #[test]
    fn a_vtable_whose_own_type_info_is_not_in_its_second_word_is_refused() {
        assert!(refused_for_virtual_bases(&[0, 0, 0, 0x2100, 0x1000], &[0, 0], Some(16)), "_ZTI3Vir three words in");
        assert!(!refused_for_virtual_bases(&[0, 0x2100, 0x1000], &[0, 0], Some(16)), "_ZTI3Vir in the second word");
    }

    /// Where every pointer reads zero, the class's `type_info` still says it:
    /// its `__offset_flags` has the virtual bit, an integer the file holds.
    /// `{ vptr, name, flags, count = 1, { base, offset_flags } }`, 40 bytes.
    #[test]
    fn a_type_info_with_a_virtual_base_refuses_its_class() {
        let vmi = |flags: u64| [0, 0, 1 << 32, 0, flags];
        assert!(refused_for_virtual_bases(&[0, 0, 0, 0, 0], &vmi(0x3), Some(40)), "virtual and public");
        assert!(!refused_for_virtual_bases(&[0, 0, 0, 0, 0], &vmi(0x2), Some(40)), "public, not virtual");
    }

    /// A table whose first slot holds an address outside the code is not
    /// listed, and it is counted: dropped without a word, the class was absent
    /// from the hierarchy, and the subclass guard read the image's hierarchy as
    /// known.
    #[test]
    fn a_first_slot_outside_the_code_is_refused_and_counted() {
        let mut vt = vec![0u8; 32];
        vt[16..24].copy_from_slice(&0xDEAD_0000u64.to_le_bytes());
        let snap = n0xis_sources::Snapshot::builder().region(Va(0x2000), vt).build();
        let scan = scan_itanium_rtti(&snap, &[ds(0x2000, "_ZTV3Foo", None)], &[(Va(0x1000), 0x100)], 8, &UNREAD);
        assert!(scan.vtables.is_empty());
        assert_eq!(scan.count_refused(VtableRefusal::FirstSlotNotCode), 1, "{scan:?}");
        assert_eq!(Subclasses::of(&scan.vtables, scan.refused.len(), PROGRAM), Subclasses::Unknown { classes: 1 });
    }

    /// The layout of a `type_info` is its symbol's size. Planted as a shared
    /// object leaves them: the vtable's `type_info` pointer is a relative
    /// relocation and reads as the address, and a base in another library is a
    /// symbolic one and reads zero.
    fn bases_of(zti: &[u64], size: Option<u64>, extra: &[DataSymbol]) -> Bases {
        bases_through(0x2100, zti, size, extra)
    }

    /// [`bases_of`] with the vtable's `type_info` pointer holding `word`
    /// (`_ZTI3Foo` is at `0x2100`).
    fn bases_through(word: u64, zti: &[u64], size: Option<u64>, extra: &[DataSymbol]) -> Bases {
        let bytes = |ws: &[u64]| ws.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
        let snap = n0xis_sources::Snapshot::builder()
            .region(Va(0x1000), vec![0xC3; 0x100])
            .region(Va(0x2000), bytes(&[0, word, 0x1000]))
            .region(Va(0x2100), bytes(zti))
            .build();
        let mut syms = vec![ds(0x2000, "_ZTV3Foo", Some(24)), ds(0x2100, "_ZTI3Foo", size)];
        syms.extend_from_slice(extra);
        let scan = scan_itanium_rtti(&snap, &syms, &[(Va(0x1000), 0x100)], 8, &UNREAD);
        assert_eq!(scan.vtables.len(), 1, "{scan:?}");
        scan.vtables[0].bases.clone()
    }

    /// A one-base `type_info` (three pointers) whose base pointer reads zero
    /// has a base this image cannot name. Read by structure, it was "no bases".
    #[test]
    fn a_one_base_type_info_with_an_unnamed_base_is_not_none() {
        let unnamed = Bases::Unknown { bases_unknown: BasesUnknown::BaseNotNamed };
        assert_eq!(bases_of(&[0, 0, 0], Some(24), &[]), unnamed, "the base is a symbolic relocation");
        assert_eq!(bases_of(&[0, 0, 0x3000], Some(24), &[]), unnamed, "the base pointer names no _ZTI");
        let named = bases_of(&[0, 0, 0x3000], Some(24), &[ds(0x3000, "_ZTI4Base", Some(16))]);
        assert_eq!(named, Bases::Known { bases: vec!["Base".into()] });
    }

    /// A several-base `type_info` with one base it cannot name is unknown, not
    /// the list of the others.
    #[test]
    fn a_several_base_type_info_with_an_unnamed_base_is_not_a_shorter_list() {
        let two = [0, 0, 2 << 32, 0x3000, 0x2, 0, 0x802];
        let base = [ds(0x3000, "_ZTI4Base", Some(16))];
        assert_eq!(bases_of(&two, Some(56), &base), Bases::Unknown { bases_unknown: BasesUnknown::BaseNotNamed });
        // A count that is not the one the size states is not this layout.
        let three = [0, 0, 3 << 32, 0x3000, 0x2, 0x3000, 0x802];
        assert_eq!(bases_of(&three, Some(56), &base), Bases::Unknown { bases_unknown: BasesUnknown::HierarchyUnreadable });
    }

    /// A `type_info` of two pointers has no bases, and nothing past it is read:
    /// at the end of a segment, reading on ran into nothing and the class was
    /// reported unreadable (a Thumb build's last `type_info`).
    #[test]
    fn a_two_pointer_type_info_has_no_bases_and_nothing_past_it_is_read() {
        assert_eq!(bases_of(&[0, 0], Some(16), &[]), Bases::none(), "the region ends with the object");
        // Without a stated size there is no layout to read.
        assert_eq!(bases_of(&[0, 0], None, &[]), Bases::Unknown { bases_unknown: BasesUnknown::HierarchyUnreadable });
    }

    /// A class's bases are read from its **own** `_ZTI` where the image has
    /// one, though the vtable's `type_info` pointer reads zero, as it does in a
    /// shared object, where it is a symbolic relocation. Read through the
    /// pointer, every such class was `type-info-not-in-file`.
    #[test]
    fn the_bases_are_read_from_the_class_s_own_type_info() {
        assert_eq!(bases_through(0, &[0, 0], Some(16), &[]), Bases::none(), "two pointers: no base");
        let base = [ds(0x3000, "_ZTI4Base", Some(16))];
        assert_eq!(bases_through(0, &[0, 0, 0x3000], Some(24), &base), Bases::Known { bases: vec!["Base".into()] }, "one base, named");
        assert_eq!(bases_through(0, &[0, 0, 0], Some(24), &[]), Bases::Unknown { bases_unknown: BasesUnknown::BaseNotNamed }, "one base, a relocation");
        // Without an own `_ZTI`, a zero pointer is still all the image says.
        let snap = n0xis_sources::Snapshot::builder().region(Va(0x2000), vec![0u8; 24]).build();
        let scan = scan_itanium_rtti(&snap, &[ds(0x2000, "_ZTV3Foo", Some(24))], &[], 8, &UNREAD);
        assert_eq!(scan.vtables[0].bases, Bases::Unknown { bases_unknown: BasesUnknown::TypeInfoNotInFile });
    }

    /// The vtable's `type_info` pointer is the cross-check: where it holds an
    /// address that is not the own `_ZTI`'s, the two disagree and the bases
    /// are not read from either.
    #[test]
    fn a_type_info_pointer_that_is_not_the_own_type_info_refuses_the_bases() {
        let other = [ds(0x3000, "_ZTI4Base", Some(16))];
        assert_eq!(bases_through(0x3000, &[0, 0], Some(16), &other), Bases::Unknown { bases_unknown: BasesUnknown::TypeInfoDisagrees });
        assert_eq!(bases_through(0x2100, &[0, 0], Some(16), &other), Bases::none(), "the pointer names the own _ZTI");
    }

    /// The first-slot gate takes a slot into any executable range for code,
    /// not only `.text`'s; outside every one it still refuses.
    #[test]
    fn a_first_slot_in_any_code_range_is_code() {
        let table = |first: u64| {
            let mut vt = vec![0u8; 24];
            vt[16..24].copy_from_slice(&first.to_le_bytes());
            n0xis_sources::Snapshot::builder().region(Va(0x2000), vt).build()
        };
        let code = [(Va(0x1000), 0x100), (Va(0x5000), 0x100)];
        let scan = |first| scan_itanium_rtti(&table(first), &[ds(0x2000, "_ZTV3Foo", None)], &code, 8, &UNREAD);
        let hot = scan(0x5010);
        assert_eq!(hot.vtables.len(), 1, "a method in the second code range: {hot:?}");
        assert_eq!(hot.count_refused(VtableRefusal::FirstSlotNotCode), 0);
        assert_eq!(scan(0x9000).count_refused(VtableRefusal::FirstSlotNotCode), 1, "outside every code range");
    }

    /// Relocations read, at these words.
    fn written(words: &[u64]) -> RelocatedWords {
        RelocatedWords::Read { words: words.to_vec(), copies: Vec::new() }
    }

    /// What the scan does with one 64-bit `_ZTV2HM` at `0x2000` of `words`,
    /// code at `0x1000`, given the relocations, and with `own` the class's own
    /// `_ZTI2HM` at `0x2100` (two pointers, no base) where given.
    fn scan_hm(words: &[u64], own: bool, relocated: &RelocatedWords) -> ItaniumScan {
        let bytes = |ws: &[u64]| ws.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
        let mut b = n0xis_sources::Snapshot::builder().region(Va(0x1000), vec![0xC3; 0x100]).region(Va(0x2000), bytes(words));
        let mut syms = vec![ds(0x2000, "_ZTV2HM", Some(8 * words.len() as u64))];
        if own {
            b = b.region(Va(0x2100), bytes(&[0, 0]));
            syms.push(ds(0x2100, "_ZTI2HM", Some(16)));
        }
        let scan = scan_itanium_rtti(&b.build(), &syms, &[(Va(0x1000), 0x100)], 8, relocated);
        assert_eq!(scan.vtables.len() + scan.refused.len(), 1, "a class is either listed or refused: {scan:?}");
        scan
    }

    /// A class built without RTTI whose virtual base shares its vptr: `HM :
    /// virtual P`, laid out as clang lays it out on x86-64 — two vcall offsets,
    /// a virtual-base offset, `offset_to_top` and the `type_info` slot, all
    /// zero, then the methods at `_ZTV` + 40. Only the methods are written by a
    /// relocation, so the zero at `_ZTV` + 16 is no slot the loader fills, and
    /// the class is refused, not listed there. Where the relocations were not
    /// read, it is listed there as before; where one writes `_ZTV` + 16, the
    /// zero is a method the loader fills.
    #[test]
    fn a_zero_first_slot_nothing_writes_is_refused() {
        let hm = [0, 0, 0, 0, 0, 0, 0];
        let methods = written(&[0x2028, 0x2030]);
        let scan = scan_hm(&hm, false, &methods);
        assert_eq!(scan.count_refused(VtableRefusal::FirstSlotEmpty), 1, "{scan:?}");
        assert_eq!(Subclasses::of(&scan.vtables, scan.refused.len(), PROGRAM), Subclasses::Unknown { classes: 1 });
        assert_eq!(scan_hm(&hm, false, &UNREAD).vtables.len(), 1, "unread relocations: a zero may be filled");
        assert_eq!(scan_hm(&hm, false, &written(&[0x2010])).vtables[0].vtable, Va(0x2010), "a zero a relocation writes");
        // A relocation that starts a few bytes before the word still writes it.
        assert_eq!(scan_hm(&hm, false, &written(&[0x200c])).vtables.len(), 1);
        assert_eq!(scan_hm(&hm, false, &written(&[0x2000])).count_refused(VtableRefusal::FirstSlotEmpty), 1, "ends before it");
    }

    /// A zero first slot nothing writes, after a `type_info` word a relocation
    /// writes, is listed: that word is a pointer, so it is the `type_info`
    /// pointer, and the address point is right after it. GCC leaves the
    /// destructor slots of an abstract class zero with no relocation —
    /// `std::error_category` in `libstdc++.so.6` — and refusing those refused
    /// 32 right answers on three system libraries.
    #[test]
    fn a_zero_first_slot_after_a_relocated_type_info_word_is_listed() {
        let abstract_class = [0, 0, 0, 0, 0];
        let type_info_relocated = written(&[0x2008, 0x2020]);
        assert_eq!(scan_hm(&abstract_class, true, &type_info_relocated).vtables[0].vtable, Va(0x2010));
        // The same zeros with no relocation before the slot: no pointer places it.
        assert_eq!(scan_hm(&abstract_class, false, &written(&[0x2020])).count_refused(VtableRefusal::FirstSlotEmpty), 1);
    }

    /// A zero first slot nothing writes, in a table whose second word holds the
    /// address of the class's own `type_info`, is listed: the `type_info`
    /// pointer places the address point right after it, and the slot is a
    /// method no image defines (`__cxa_pure_virtual` in the fixtures, linked
    /// with unresolved symbols ignored).
    #[test]
    fn a_zero_first_slot_its_type_info_places_is_listed() {
        let scan = scan_hm(&[0, 0x2100, 0, 0x1000], true, &written(&[]));
        assert_eq!(scan.vtables.iter().map(|v| v.vtable).collect::<Vec<_>>(), vec![Va(0x2010)], "{scan:?}");
        // Without its own `type_info` nothing places it.
        assert_eq!(scan_hm(&[0, 0x2100, 0, 0x1000], false, &written(&[])).count_refused(VtableRefusal::FirstSlotEmpty), 1);
    }

    /// Fact 4: a class with its own `type_info` whose second word reads zero
    /// with no relocation writing it has an offset there, not its `type_info`
    /// pointer — `Leaf2 : Mid2 : virtual E` with `E` empty in a shared object,
    /// whose one zero offset put `_ZTV` + 16 on the relocation naming its own
    /// `_ZTI` (written, so the first-slot gate passed it).
    #[test]
    fn a_type_info_slot_nothing_writes_shows_virtual_bases() {
        let leaf2 = [0, 0, 0, 0];
        let scan = scan_hm(&leaf2, true, &written(&[0x2010, 0x2018]));
        assert_eq!(scan.count_refused(VtableRefusal::VirtualBases), 1, "{scan:?}");
        // The same table with its second word written is a table without
        // virtual bases: its `type_info` pointer is a relocation.
        assert_eq!(scan_hm(&leaf2, true, &written(&[0x2008, 0x2010])).vtables.len(), 1);
        // Unread relocations say nothing.
        assert_eq!(scan_hm(&leaf2, true, &UNREAD).vtables.len(), 1);
    }
}

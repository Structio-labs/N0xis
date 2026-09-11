// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Exception edges** — recovering the control flow an unwinder takes, which no
//! instruction in the function encodes (ROADMAP Phase 10, priority 0: the last
//! open item of the CFG-fidelity debt).
//!
//! A `try`/`catch` produces code with **no incoming branch**: the landing pad is
//! entered by the personality routine during unwinding, never by a `jmp` or a
//! fall-through. To a CFG built purely from decoded instructions such a block is
//! unreachable, and to the end-of-function heuristic it is invisible — which is
//! exactly the shape measured on `libQt6Core.so.6`: 29 functions whose reported
//! extent fell 12–17 bytes short, every one of them ending in
//! `call __stack_chk_fail; endbr64; …; jmp <cleanup>`.
//!
//! This module reads the tables that *do* encode it. On ELF that is DWARF CFI:
//! `.eh_frame` holds one **FDE** per function, whose augmentation may carry a
//! pointer to an **LSDA** (`.gcc_except_table`) — a call-site table mapping each
//! protected byte range to the landing pad an exception in it transfers to.
//!
//! Scope, deliberately: this recovers **where** control can go, not **what** is
//! caught. Type tables (`ttype`) and action records are located and skipped —
//! naming the caught C++ types is a readability follow-on, while the edges are
//! the correctness item. Sound over complete throughout: anything unparsable
//! yields no region rather than a guessed one, and the CFG is then exactly what
//! it was before.
//!
//! PE/MSVC (`.xdata` scope tables for `__C_specific_handler`, `FuncInfo` for
//! `__CxxFrameHandler`) is the sibling follow-on; the artifact shape here is
//! format-neutral so it can carry both.

use n0xis_contracts::Va;
use n0xis_sources::MemorySource;

/// One protected range and the landing pad it unwinds to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EhRegion {
    /// First byte covered by this call-site entry.
    pub try_start: Va,
    /// Exclusive end of the covered range.
    pub try_end: Va,
    /// Where the personality routine transfers control. Never 0 — an entry with
    /// no landing pad ("this range cannot be caught here") is dropped rather
    /// than reported as an edge to address zero.
    pub landing_pad: Va,
}

/// One function's exception information, as recovered from its FDE + LSDA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EhFunction {
    pub start: Va,
    /// Exclusive end, from the FDE's `pc_range` — an authoritative extent, like
    /// ELF `st_size` and unlike the end-of-function heuristic.
    pub end: Va,
    pub regions: Vec<EhRegion>,
}

/// `DW_EH_PE_omit` — the field is absent.
const DW_EH_PE_OMIT: u8 = 0xff;

/// The largest `.eh_frame` this will read in one go. A parsed length is never
/// used to size an allocation (see the machine's OOM rule); this bounds the one
/// deliberate whole-section read.
const MAX_EH_FRAME: usize = 64 * 1024 * 1024;
/// Bound on records walked, so a corrupt or adversarial section cannot spin.
const MAX_RECORDS: usize = 2_000_000;
/// Bound on call-site entries per function — a real one has a handful.
const MAX_CALLSITES: usize = 100_000;

/// A bounds-checked little-endian cursor over a byte slice. Every read returns
/// `None` past the end, so a truncated table stops rather than panics.
struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cur { b, p: 0 }
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.p)?;
        self.p += 1;
        Some(v)
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.p..self.p.checked_add(n)?)?;
        self.p += n;
        Some(s)
    }
    fn u16(&mut self) -> Option<u64> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?) as u64)
    }
    fn u32(&mut self) -> Option<u64> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?) as u64)
    }
    fn u64v(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn uleb(&mut self) -> Option<u64> {
        let (mut out, mut shift) = (0u64, 0u32);
        loop {
            let b = self.u8()?;
            if shift < 64 {
                out |= ((b & 0x7f) as u64) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                return Some(out);
            }
            if shift > 70 {
                return None; // malformed
            }
        }
    }
    fn sleb(&mut self) -> Option<i64> {
        let (mut out, mut shift) = (0i64, 0u32);
        loop {
            let b = self.u8()?;
            if shift < 64 {
                out |= ((b & 0x7f) as i64) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    out |= -1i64 << shift;
                }
                return Some(out);
            }
            if shift > 70 {
                return None;
            }
        }
    }

    /// Read a DWARF-encoded pointer. `here` is the runtime address of the field
    /// being read, which is what `DW_EH_PE_pcrel` is relative to.
    ///
    /// Returns `None` for an encoding this does not model rather than guessing a
    /// value — an unknown application (`datarel`, `aligned`, `indirect`) would
    /// otherwise produce a plausible-looking wrong address.
    fn encoded(&mut self, enc: u8, here: u64) -> Option<u64> {
        if enc == DW_EH_PE_OMIT {
            return None;
        }
        let raw: i64 = match enc & 0x0f {
            0x00 => self.u64v()? as i64, // absptr (64-bit)
            0x01 => self.uleb()? as i64,
            0x02 => self.u16()? as i64,
            0x03 => self.u32()? as i64,
            0x04 => self.u64v()? as i64,
            0x09 => self.sleb()?,
            0x0a => self.u16()? as i16 as i64,
            0x0b => self.u32()? as i32 as i64,
            0x0c => self.u64v()? as i64,
            _ => return None,
        };
        match enc & 0x70 {
            0x00 => Some(raw as u64),                    // absolute
            0x10 => Some(here.wrapping_add(raw as u64)), // pcrel
            _ => None,                                   // datarel/textrel/funcrel/aligned: not modeled
        }
    }
}

/// What a CIE tells its FDEs: how their `pc_begin` and LSDA pointers are encoded.
#[derive(Clone, Copy)]
struct Cie {
    fde_enc: u8,
    lsda_enc: u8,
    has_z: bool,
}

/// Parse a CIE's augmentation. Only the three fields that matter here are kept;
/// alignment factors and the initial CFI program are the unwinder's business.
fn parse_cie(content: &[u8]) -> Option<Cie> {
    let mut c = Cur::new(content);
    if c.u32()? != 0 {
        return None; // CIE id must be 0
    }
    let version = c.u8()?;
    if version != 1 && version != 3 && version != 4 {
        return None;
    }
    let mut aug = Vec::new();
    loop {
        let ch = c.u8()?;
        if ch == 0 {
            break;
        }
        aug.push(ch);
    }
    if version == 4 {
        let _address_size = c.u8()?;
        let _segment_size = c.u8()?;
    }
    let _code_align = c.uleb()?;
    let _data_align = c.sleb()?;
    let _ra_reg = if version == 1 { c.u8()? as u64 } else { c.uleb()? };

    let has_z = aug.first() == Some(&b'z');
    let (mut fde_enc, mut lsda_enc) = (0x00u8, DW_EH_PE_OMIT);
    if has_z {
        let aug_len = c.uleb()? as usize;
        let aug_start = c.p;
        for &ch in &aug[1..] {
            match ch {
                b'R' => fde_enc = c.u8()?,
                b'L' => lsda_enc = c.u8()?,
                b'P' => {
                    let enc = c.u8()?;
                    // The personality pointer's value is irrelevant here, but it
                    // must be *consumed* or every following field misparses.
                    c.encoded(enc, 0)?;
                }
                b'S' => {}
                _ => {}
            }
        }
        // Validate that the augmentation block is well-formed and inside the
        // record; nothing after it is read, so the cursor itself is done.
        aug_start.checked_add(aug_len).filter(|e| *e <= content.len())?;
    }
    Some(Cie { fde_enc, lsda_enc, has_z })
}

/// Parse the GCC LSDA (`.gcc_except_table`) at `lsda_addr` for a function
/// starting at `func_start`, returning its landing-pad regions.
fn parse_lsda(src: &dyn MemorySource, lsda_addr: u64, func_start: u64) -> Vec<EhRegion> {
    // A generous fixed read: the call-site table of a real function is small,
    // and the size is NOT taken from the parsed header (OOM rule).
    let Ok(buf) = src.read(Va(lsda_addr), 64 * 1024) else { return Vec::new() };
    let mut c = Cur::new(&buf);
    let mut out = Vec::new();

    let Some(lp_enc) = c.u8() else { return out };
    // `DW_EH_PE_omit` means "landing pads are relative to the function start",
    // which is the overwhelmingly common case gcc/clang emit.
    let lp_start = if lp_enc == DW_EH_PE_OMIT {
        func_start
    } else {
        match c.encoded(lp_enc, lsda_addr + c.p as u64) {
            Some(v) => v,
            None => return out,
        }
    };
    let Some(ttype_enc) = c.u8() else { return out };
    if ttype_enc != DW_EH_PE_OMIT && c.uleb().is_none() {
        return out; // ttype table offset — located and skipped, see the module doc
    }
    let Some(cs_enc) = c.u8() else { return out };
    let Some(cs_len) = c.uleb() else { return out };

    let table_start = c.p;
    let Some(table_end) = table_start.checked_add(cs_len as usize) else { return out };
    if table_end > buf.len() {
        return out; // truncated read: report nothing rather than half a table
    }
    let mut seen = 0usize;
    while c.p < table_end && seen < MAX_CALLSITES {
        seen += 1;
        let here = lsda_addr + c.p as u64;
        let Some(cs_start) = c.encoded(cs_enc, here) else { break };
        let Some(cs_range) = c.encoded(cs_enc, lsda_addr + c.p as u64) else { break };
        let Some(cs_lp) = c.encoded(cs_enc, lsda_addr + c.p as u64) else { break };
        let Some(_action) = c.uleb() else { break };
        // A zero landing pad means "no handler here" — not an edge to address 0.
        if cs_lp == 0 {
            continue;
        }
        let (Some(ts), Some(te), Some(pad)) = (
            func_start.checked_add(cs_start),
            func_start.checked_add(cs_start).and_then(|s| s.checked_add(cs_range)),
            lp_start.checked_add(cs_lp),
        ) else {
            break;
        };
        out.push(EhRegion { try_start: Va(ts), try_end: Va(te), landing_pad: Va(pad) });
    }
    out
}

/// Walk `.eh_frame` linearly and return every function that carries exception
/// information, with its protected ranges and landing pads.
///
/// `eh_frame` is `(section start VA, size)`. Linear rather than a binary search
/// through `.eh_frame_hdr` on purpose: one pass builds the whole-image map that
/// `analyze` wants, and it does not depend on `.eh_frame_hdr` being present.
///
/// Functions with an FDE but no LSDA are still returned (with no regions),
/// because the FDE's `pc_range` is itself an authoritative function extent —
/// useful on a stripped binary, where `st_size` is gone but `.eh_frame` remains.
pub fn scan_eh_frame(src: &dyn MemorySource, eh_frame: (Va, u64)) -> Vec<EhFunction> {
    let (base, size) = (eh_frame.0.get(), eh_frame.1.min(MAX_EH_FRAME as u64) as usize);
    let Ok(sec) = src.read(Va(base), size) else { return Vec::new() };
    let mut out: Vec<EhFunction> = Vec::new();
    // CIEs are shared by many FDEs and are re-read by section offset.
    let mut cies: std::collections::HashMap<usize, Cie> = std::collections::HashMap::new();

    let mut off = 0usize;
    let mut records = 0usize;
    while off + 4 <= sec.len() && records < MAX_RECORDS {
        records += 1;
        let len32 = u32::from_le_bytes(sec[off..off + 4].try_into().unwrap());
        if len32 == 0 {
            break; // terminator
        }
        // 64-bit DWARF length is not emitted by any toolchain we target; stop
        // rather than misparse the rest of the section as records.
        if len32 == 0xffff_ffff {
            break;
        }
        let content_start = off + 4;
        let Some(content_end) = content_start.checked_add(len32 as usize) else { break };
        if content_end > sec.len() {
            break;
        }
        let content = &sec[content_start..content_end];
        if content.len() < 4 {
            off = content_end;
            continue;
        }
        let id = u32::from_le_bytes(content[0..4].try_into().unwrap());
        if id == 0 {
            if let Some(cie) = parse_cie(content) {
                cies.insert(off, cie);
            }
        } else if let Some(cie) = (content_start).checked_sub(id as usize).and_then(|o| cies.get(&o).copied()) {
            let mut c = Cur::new(content);
            let _ = c.u32();
            let pc_begin_field = base + (content_start + c.p) as u64;
            if let Some(pc_begin) = c.encoded(cie.fde_enc, pc_begin_field) {
                // `pc_range` is a length: the pcrel base never applies to it, so
                // read it with the encoding's *format* and an absolute base.
                if let Some(pc_range) = c.encoded(cie.fde_enc & 0x0f, 0) {
                    let mut lsda = None;
                    if cie.has_z && let Some(aug_len) = c.uleb() {
                        let aug_start = c.p;
                        if cie.lsda_enc != DW_EH_PE_OMIT {
                            lsda = c.encoded(cie.lsda_enc, base + (content_start + c.p) as u64);
                        }
                        c.p = aug_start.saturating_add(aug_len as usize);
                    }
                    let regions = lsda.map(|l| parse_lsda(src, l, pc_begin)).unwrap_or_default();
                    out.push(EhFunction {
                        start: Va(pc_begin),
                        end: Va(pc_begin.saturating_add(pc_range)),
                        regions,
                    });
                }
            }
        }
        off = content_end;
    }
    out.sort_by_key(|f| f.start.get());
    out
}

/// Every landing-pad address in `functions`, as a flat sorted set — the shape
/// the CFG builder wants when it needs to know "is this block an EH entry?".
/// `UNW_FLAG_EHANDLER` — the unwind info is followed by an exception handler.
const UNW_FLAG_EHANDLER: u8 = 0x1;
/// `UNW_FLAG_UHANDLER` — …a termination handler. Either one means handler data
/// follows the unwind codes.
const UNW_FLAG_UHANDLER: u8 = 0x2;
/// `UNW_FLAG_CHAININFO` — the "handler" slot is another `RUNTIME_FUNCTION`
/// instead, so this entry carries no handler data of its own.
const UNW_FLAG_CHAININFO: u8 = 0x4;
/// Bound on `SCOPE_TABLE.Count`. A real `__try` nest is a handful; anything
/// larger is the surest sign this handler's data is not a scope table at all.
const MAX_SCOPES: u64 = 512;

/// **PE exception edges** — `.pdata` (`RUNTIME_FUNCTION`) + `.xdata`
/// (`UNWIND_INFO`), the Windows sibling of [`scan_eh_frame`].
///
/// Two things come out of it, and the first is worth having on its own: every
/// entry gives an **authoritative `[begin, end)`** for a function, the same kind
/// of ground truth ELF `st_size` and a DWARF FDE's `pc_range` give and the
/// end-of-function heuristic does not.
///
/// The second is the `__try`/`__except`/`__finally` edges. When `UNWIND_INFO`
/// carries a handler, the bytes after the unwind codes are handler-specific, and
/// **nothing in the format says which handler they belong to** — the handler
/// field is an RVA into a statically-linked CRT with no symbol on it. So the
/// data is not trusted on the strength of a name; it is *parsed as* a
/// `__C_specific_handler` `SCOPE_TABLE` and accepted only if **every** entry
/// validates: a sane count, `begin < end`, and each of the addresses either
/// zero, the reserved `1`, or inside an executable section. One bad entry
/// rejects the whole table. That is the same sound-over-complete rule the DWARF
/// side follows, applied where the format itself gives no discriminator.
///
/// SEH semantics decide which address is the edge: a `__try`/`__except` records
/// its filter in `HandlerAddress` and the `__except` body in `JumpTarget`, while
/// a `__finally` has no jump target and its routine *is* `HandlerAddress`.
///
/// **Not covered, and it is the larger half of a modern C++ image.** MSVC's
/// `__CxxFrameHandler4` stores a *compressed*, undocumented blob rather than the
/// classic `FuncInfo`; on a 371 250-function C++ target 89 790 handler payloads
/// are that format and are refused here rather than guessed at. The classic
/// `FuncInfo` (magic `0x19930520`–`0x19930522`) is recognized so it is never
/// mistaken for a scope table — its try-block map is a follow-on.
pub fn scan_pdata(src: &dyn MemorySource, image_base: Va, pdata: (Va, u64)) -> Vec<EhFunction> {
    let (base, size) = (pdata.0.get(), pdata.1.min(MAX_EH_FRAME as u64) as usize);
    let Ok(table) = src.read(Va(base), size) else { return Vec::new() };
    let code = src.code_ranges();
    let is_code = |va: u64| code.iter().any(|(s, n)| va >= s.get() && va < s.get().saturating_add(*n));
    let va = |rva: u64| image_base.get().saturating_add(rva);

    let mut out = Vec::new();
    let mut cur = Cur::new(&table);
    let mut records = 0usize;
    while records < MAX_RECORDS {
        records += 1;
        let (Some(begin), Some(end), Some(unwind)) = (cur.u32(), cur.u32(), cur.u32()) else { break };
        if begin == 0 && end == 0 && unwind == 0 {
            break;
        }
        if end <= begin {
            continue;
        }
        let mut regions = pe_regions(src, image_base, unwind, &is_code);
        // Attribute a protected range to the function whose bytes it covers.
        // MSVC compiles each `catch` into a **funclet** with its own `.pdata`
        // entry, and every one of them points at the *parent's* `FuncInfo` — so
        // without this filter the parent's try ranges are reported again under
        // each funclet, where they do not lie. Measured on a neutral C++ runtime
        // DLL: 199 of 360 ranges were outside the entry that named them.
        regions.retain(|r| r.try_start.get() >= va(begin) && r.try_end.get() <= va(end));
        out.push(EhFunction { start: Va(va(begin)), end: Va(va(end)), regions });
    }
    out
}

/// The protected ranges one `UNWIND_INFO` describes, or none.
fn pe_regions(src: &dyn MemorySource, image_base: Va, unwind_rva: u64, is_code: &impl Fn(u64) -> bool) -> Vec<EhRegion> {
    let va = |rva: u64| image_base.get().saturating_add(rva);
    let Ok(head) = src.read(Va(va(unwind_rva)), 4) else { return Vec::new() };
    let mut h = Cur::new(&head);
    let (Some(ver_flags), Some(_prolog), Some(count), Some(_frame)) = (h.u8(), h.u8(), h.u8(), h.u8()) else {
        return Vec::new();
    };
    // Version 1 and 2 share this layout; anything else is not a shape we know.
    if !matches!(ver_flags & 7, 1 | 2) {
        return Vec::new();
    }
    let flags = ver_flags >> 3;
    if flags & UNW_FLAG_CHAININFO != 0 || flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) == 0 {
        return Vec::new();
    }
    // Unwind codes are 2 bytes each and padded to an even count; the handler
    // RVA and then its private data follow.
    let codes = 2 * ((count as u64 + 1) & !1);
    let data_rva = unwind_rva.saturating_add(4).saturating_add(codes);
    let Ok(head2) = src.read(Va(va(data_rva)), 8) else { return Vec::new() };
    let mut d = Cur::new(&head2);
    let (Some(_handler), Some(first)) = (d.u32(), d.u32()) else { return Vec::new() };
    // For MSVC C++ EH the dword is not data — it is an **RVA to a `FuncInfo`**,
    // and reading it in place is how this first concluded the format was absent
    // from binaries full of it. Dereference before deciding.
    if let Ok(head) = src.read(Va(va(first)), 4)
        && head.len() == 4
        && matches!(u32::from_le_bytes(head[..4].try_into().unwrap()), 0x1993_0520..=0x1993_0522)
    {
        return cxx_regions(src, image_base, first, is_code);
    }
    if first == 0 || first > MAX_SCOPES {
        return Vec::new();
    }
    let n = first as usize;
    let Ok(body) = src.read(Va(va(data_rva.saturating_add(8))), n * 16) else { return Vec::new() };
    if body.len() < n * 16 {
        return Vec::new();
    }
    let mut c = Cur::new(&body);
    let mut regions = Vec::with_capacity(n.min(MAX_CALLSITES));
    for _ in 0..n {
        let (Some(b), Some(e), Some(handler), Some(jump)) = (c.u32(), c.u32(), c.u32(), c.u32()) else {
            return Vec::new();
        };
        if b >= e || !is_code(va(b)) || !is_code(va(e).saturating_sub(1)) {
            return Vec::new();
        }
        // `HandlerAddress` is a filter RVA, or the reserved 0/1 (`__finally`
        // and "continue search"); `JumpTarget` is 0 for a `__finally`.
        if handler > 1 && !is_code(va(handler)) {
            return Vec::new();
        }
        if jump != 0 && !is_code(va(jump)) {
            return Vec::new();
        }
        // The edge: the `__except` body, or the `__finally` routine.
        let pad = if jump != 0 {
            jump
        } else if handler > 1 {
            handler
        } else {
            continue;
        };
        regions.push(EhRegion { try_start: Va(va(b)), try_end: Va(va(e)), landing_pad: Va(va(pad)) });
    }
    regions
}

/// Bounds on a `FuncInfo`'s tables. A real function has a handful of try
/// blocks; the IP-to-state map is one entry per state transition.
const MAX_TRY_BLOCKS: u64 = 4096;
const MAX_CATCHES: u64 = 1024;
const MAX_IP_STATES: u64 = 200_000;

/// The `try` ranges and `catch` entry points of an MSVC **C++** frame, from the
/// classic `FuncInfo` (magic `0x19930520`–`0x19930522`).
///
/// Unlike the SEH scope table, this format identifies itself: the magic is the
/// discriminator, so nothing here rests on guessing which handler the data
/// belongs to.
///
/// The shape is indirect in a way the SEH one is not. A `TryBlockMapEntry` does
/// not carry addresses — it carries a **state range** (`tryLow..=tryHigh`), and
/// the bytes those states cover are in a separate IP-to-state map. So the
/// protected range is reconstructed: walk the map in address order, keep the
/// runs whose state falls inside the try block, and pair each run with every
/// catch handler that block declares. Every address is required to be inside an
/// executable section, and any table that does not validate yields nothing.
fn cxx_regions(src: &dyn MemorySource, image_base: Va, info_rva: u64, is_code: &impl Fn(u64) -> bool) -> Vec<EhRegion> {
    let va = |rva: u64| image_base.get().saturating_add(rva);
    let Ok(head) = src.read(Va(va(info_rva)), 28) else { return Vec::new() };
    if head.len() < 28 {
        return Vec::new();
    }
    let mut h = Cur::new(&head);
    // magic, maxState, pUnwindMap, nTryBlocks, pTryBlockMap, nIPMapEntries,
    // pIPtoStateMap — the prefix is the same for all three magics; the fields
    // that differ between them come after and are not read.
    let (Some(_magic), Some(_max_state), Some(_unwind), Some(n_try), Some(try_map), Some(n_ip), Some(ip_map)) =
        (h.u32(), h.u32(), h.u32(), h.u32(), h.u32(), h.u32(), h.u32())
    else {
        return Vec::new();
    };
    if n_try == 0 || n_try > MAX_TRY_BLOCKS || n_ip == 0 || n_ip > MAX_IP_STATES {
        return Vec::new();
    }

    // The IP-to-state map, in address order: entry `i` covers `[ip_i, ip_i+1)`.
    let Ok(ips) = src.read(Va(va(ip_map)), (n_ip as usize) * 8) else { return Vec::new() };
    if ips.len() < (n_ip as usize) * 8 {
        return Vec::new();
    }
    let mut c = Cur::new(&ips);
    let mut states: Vec<(u64, i32)> = Vec::with_capacity(n_ip as usize);
    for _ in 0..n_ip {
        let (Some(ip), Some(st)) = (c.u32(), c.u32()) else { return Vec::new() };
        if !is_code(va(ip)) {
            return Vec::new();
        }
        states.push((ip, st as i32));
    }
    states.sort_by_key(|(ip, _)| *ip);

    let Ok(blocks) = src.read(Va(va(try_map)), (n_try as usize) * 20) else { return Vec::new() };
    if blocks.len() < (n_try as usize) * 20 {
        return Vec::new();
    }
    let mut t = Cur::new(&blocks);
    let mut out = Vec::new();
    for _ in 0..n_try {
        let (Some(low), Some(high), Some(_catch_high), Some(n_catch), Some(handlers)) =
            (t.u32(), t.u32(), t.u32(), t.u32(), t.u32())
        else {
            return Vec::new();
        };
        let (low, high) = (low as i32, high as i32);
        if low > high || n_catch == 0 || n_catch > MAX_CATCHES {
            return Vec::new();
        }
        // The catch entry points this block declares.
        let Ok(hs) = src.read(Va(va(handlers)), (n_catch as usize) * 20) else { return Vec::new() };
        if hs.len() < (n_catch as usize) * 20 {
            return Vec::new();
        }
        let mut hc = Cur::new(&hs);
        let mut pads = Vec::new();
        for _ in 0..n_catch {
            let (Some(_adj), Some(_ty), Some(_disp), Some(addr), Some(_frame)) = (hc.u32(), hc.u32(), hc.u32(), hc.u32(), hc.u32())
            else {
                return Vec::new();
            };
            if addr == 0 || !is_code(va(addr)) {
                return Vec::new();
            }
            pads.push(addr);
        }
        // The bytes those states cover, merged into contiguous runs.
        for (start, end) in state_runs(&states, low, high) {
            for &pad in &pads {
                out.push(EhRegion { try_start: Va(va(start)), try_end: Va(va(end)), landing_pad: Va(va(pad)) });
            }
        }
    }
    out
}

/// The contiguous address runs whose IP-to-state entry falls inside
/// `low..=high`. `states` is sorted by address; entry `i` covers up to entry
/// `i+1`, and the last one is dropped rather than extended to a guessed end.
fn state_runs(states: &[(u64, i32)], low: i32, high: i32) -> Vec<(u64, u64)> {
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for w in states.windows(2) {
        let ((ip, st), (next, _)) = (w[0], w[1]);
        if st < low || st > high || next <= ip {
            continue;
        }
        match runs.last_mut() {
            Some(last) if last.1 == ip => last.1 = next,
            _ => runs.push((ip, next)),
        }
    }
    runs
}

pub fn landing_pads(functions: &[EhFunction]) -> std::collections::BTreeSet<u64> {
    functions.iter().flat_map(|f| f.regions.iter()).map(|r| r.landing_pad.get()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `MemorySource` over one flat buffer mapped at a base address.
    struct Flat {
        base: u64,
        bytes: Vec<u8>,
    }
    impl MemorySource for Flat {
        fn read(&self, va: Va, len: usize) -> Result<Vec<u8>, n0xis_sources::SourceError> {
            let off = va.get().checked_sub(self.base).ok_or(n0xis_sources::SourceError::Unmapped(va))? as usize;
            if off > self.bytes.len() {
                return Err(n0xis_sources::SourceError::Unmapped(va));
            }
            Ok(self.bytes[off..(off + len).min(self.bytes.len())].to_vec())
        }
        fn contains(&self, va: Va) -> bool {
            va.get() >= self.base && va.get() < self.base + self.bytes.len() as u64
        }
        fn label(&self) -> String {
            "flat".into()
        }
    }

    /// A `Flat` that also answers `code_ranges`, which the PE scan needs: every
    /// address a scope table names must land in executable memory, and that test
    /// is the only thing standing between a scope table and a lookalike.
    struct FlatCode {
        base: u64,
        bytes: Vec<u8>,
        code: (u64, u64),
    }
    impl MemorySource for FlatCode {
        fn read(&self, va: Va, len: usize) -> Result<Vec<u8>, n0xis_sources::SourceError> {
            let off = va.get().checked_sub(self.base).ok_or(n0xis_sources::SourceError::Unmapped(va))? as usize;
            if off > self.bytes.len() {
                return Err(n0xis_sources::SourceError::Unmapped(va));
            }
            Ok(self.bytes[off..(off + len).min(self.bytes.len())].to_vec())
        }
        fn contains(&self, va: Va) -> bool {
            va.get() >= self.base && va.get() < self.base + self.bytes.len() as u64
        }
        fn code_ranges(&self) -> Vec<(Va, u64)> {
            vec![(Va(self.code.0), self.code.1)]
        }
        fn label(&self) -> String {
            "flat-code".into()
        }
    }

    /// Lay out a PE-shaped image at base `0x1000`: `.text` at +0x100, a
    /// `.pdata` entry at +0x00 and an `UNWIND_INFO` at +0x40.
    ///
    /// `handler_first` is the first `u32` of the handler's private data — a
    /// scope count for `__C_specific_handler`, or a `FuncInfo` magic.
    fn pe_image(handler_first: u32, scopes: &[(u32, u32, u32, u32)]) -> FlatCode {
        const BASE: u64 = 0x1000;
        let mut b = vec![0u8; 0x400];
        let put = |b: &mut Vec<u8>, at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        // RUNTIME_FUNCTION { begin, end, unwind } — all RVAs.
        put(&mut b, 0x00, 0x100);
        put(&mut b, 0x04, 0x180);
        put(&mut b, 0x08, 0x40);
        // UNWIND_INFO: version 1, UNW_FLAG_EHANDLER, 2 unwind codes.
        b[0x40] = 1 | (UNW_FLAG_EHANDLER << 3);
        b[0x41] = 0x08;
        b[0x42] = 2;
        b[0x43] = 0;
        // …4 bytes of codes, then the handler RVA and its private data.
        put(&mut b, 0x48, 0x300);
        put(&mut b, 0x4c, handler_first);
        for (i, (sb, se, h, j)) in scopes.iter().enumerate() {
            let o = 0x50 + 16 * i;
            put(&mut b, o, *sb);
            put(&mut b, o + 4, *se);
            put(&mut b, o + 8, *h);
            put(&mut b, o + 12, *j);
        }
        FlatCode { base: BASE, bytes: b, code: (BASE + 0x100, 0x300) }
    }

    #[test]
    fn a_pe_scope_table_becomes_protected_ranges_and_their_pads() {
        // One `__try`/`__except` (a filter plus a jump target) and one
        // `__finally` (no jump target — the routine itself is the pad).
        let img = pe_image(2, &[(0x110, 0x140, 0x200, 0x150), (0x150, 0x160, 0x220, 0)]);
        let fns = scan_pdata(&img, Va(0x1000), (Va(0x1000), 12));
        assert_eq!(fns.len(), 1);
        assert_eq!((fns[0].start, fns[0].end), (Va(0x1100), Va(0x1180)), "`.pdata` gives an authoritative extent");
        assert_eq!(
            fns[0].regions,
            vec![
                EhRegion { try_start: Va(0x1110), try_end: Va(0x1140), landing_pad: Va(0x1150) },
                EhRegion { try_start: Va(0x1150), try_end: Va(0x1160), landing_pad: Va(0x1220) },
            ]
        );
    }

    /// A PE-shaped image whose one function carries an MSVC C++ `FuncInfo`:
    /// handler data at +0x4c is an **RVA** to the `FuncInfo` at +0x100, one try
    /// block over states 0..=1 with one catch handler.
    fn pe_cxx_image() -> FlatCode {
        const BASE: u64 = 0x1000;
        let mut b = vec![0u8; 0x400];
        let put = |b: &mut Vec<u8>, at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        put(&mut b, 0x00, 0x200); // RUNTIME_FUNCTION.begin
        put(&mut b, 0x04, 0x280); // .end
        put(&mut b, 0x08, 0x40); // .unwind
        b[0x40] = 1 | (UNW_FLAG_EHANDLER << 3);
        b[0x42] = 2; // two unwind codes
        put(&mut b, 0x48, 0x300); // handler RVA
        put(&mut b, 0x4c, 0x100); // handler data: an RVA to the FuncInfo
        // FuncInfo @0x100: magic, maxState, pUnwindMap, nTryBlocks,
        // pTryBlockMap, nIPMapEntries, pIPtoStateMap.
        put(&mut b, 0x100, 0x1993_0522);
        put(&mut b, 0x104, 2);
        put(&mut b, 0x108, 0);
        put(&mut b, 0x10c, 1);
        put(&mut b, 0x110, 0x140); // pTryBlockMap
        put(&mut b, 0x114, 3);
        put(&mut b, 0x118, 0x180); // pIPtoStateMap
        // TryBlockMapEntry @0x140: tryLow 0, tryHigh 1, catchHigh 2, 1 catch.
        put(&mut b, 0x140, 0);
        put(&mut b, 0x144, 1);
        put(&mut b, 0x148, 2);
        put(&mut b, 0x14c, 1);
        put(&mut b, 0x150, 0x160); // pHandlerArray
        // HandlerType @0x160: adjectives, pType, dispCatchObj, handler, dispFrame.
        put(&mut b, 0x160, 0);
        put(&mut b, 0x164, 0);
        put(&mut b, 0x168, 0);
        put(&mut b, 0x16c, 0x260); // the catch entry point
        put(&mut b, 0x170, 0);
        // IPtoStateMap @0x180: 0x210→state 0, 0x230→state 1, 0x250→state -1.
        put(&mut b, 0x180, 0x210);
        put(&mut b, 0x184, 0);
        put(&mut b, 0x188, 0x230);
        put(&mut b, 0x18c, 1);
        put(&mut b, 0x190, 0x250);
        put(&mut b, 0x194, u32::MAX); // state -1 — outside the try block
        FlatCode { base: BASE, bytes: b, code: (BASE + 0x200, 0x100) }
    }

    #[test]
    fn an_msvc_cxx_funcinfo_yields_the_try_range_and_its_catch_entry() {
        let fns = scan_pdata(&pe_cxx_image(), Va(0x1000), (Va(0x1000), 12));
        assert_eq!(fns.len(), 1);
        // States 0 and 1 are adjacent and both inside the block, so they merge
        // into one run [0x210, 0x250); state -1 ends it.
        assert_eq!(
            fns[0].regions,
            vec![EhRegion { try_start: Va(0x1210), try_end: Va(0x1250), landing_pad: Va(0x1260) }],
            "the protected bytes come from the IP-to-state map, not from the try block itself"
        );
    }

    #[test]
    fn handler_data_that_is_not_a_scope_table_yields_nothing() {
        // The classic C++ `FuncInfo` magic sits exactly where a scope count
        // would: reading it as one would invent 0x19930520 regions.
        let img = pe_image(0x1993_0520, &[]);
        assert!(scan_pdata(&img, Va(0x1000), (Va(0x1000), 12))[0].regions.is_empty());

        // One entry pointing outside executable memory rejects the whole table,
        // rather than reporting the entries that happened to look right.
        let img = pe_image(2, &[(0x110, 0x140, 0x200, 0x150), (0x150, 0x160, 0x220, 0xdead)]);
        assert!(scan_pdata(&img, Va(0x1000), (Va(0x1000), 12))[0].regions.is_empty());

        // A count no real `__try` nest reaches is refused before it is walked.
        let img = pe_image(9999, &[]);
        assert!(scan_pdata(&img, Va(0x1000), (Va(0x1000), 12))[0].regions.is_empty());
    }

    fn uleb(v: u64) -> Vec<u8> {
        let (mut v, mut out) = (v, Vec::new());
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return out;
            }
            out.push(b | 0x80);
        }
    }

    /// Build a minimal but *real-shaped* `.eh_frame`: one CIE with the `zLR`
    /// augmentation gcc emits, one FDE pointing at an LSDA with two call-site
    /// entries — one with a landing pad, one without.
    fn fixture() -> (Flat, u64) {
        const BASE: u64 = 0x1000;
        const FUNC: u64 = 0x4000;
        let mut b: Vec<u8> = Vec::new();

        // --- CIE at offset 0 ---
        let mut cie = Vec::new();
        cie.extend_from_slice(&0u32.to_le_bytes()); // CIE id
        cie.push(1); // version
        cie.extend_from_slice(b"zLR\0"); // augmentation
        cie.extend(uleb(1)); // code align
        cie.push(0x78); // data align (sleb -8)
        cie.push(16); // ra reg
        // augmentation data: L enc, R enc
        let aug = vec![0x00u8 /* lsda: absptr */, 0x00u8 /* fde: absptr */];
        cie.extend(uleb(aug.len() as u64));
        cie.extend_from_slice(&aug);
        while cie.len() % 8 != 0 {
            cie.push(0); // DW_CFA_nop padding
        }
        b.extend_from_slice(&(cie.len() as u32).to_le_bytes());
        b.extend_from_slice(&cie);

        // --- FDE at offset `fde_off` ---
        let fde_off = b.len();
        let lsda_addr = 0x8000u64;
        let mut fde = Vec::new();
        fde.extend_from_slice(&((fde_off + 4) as u32).to_le_bytes()); // CIE ptr (backward distance)
        fde.extend_from_slice(&FUNC.to_le_bytes()); // pc_begin (absptr)
        fde.extend_from_slice(&0x100u64.to_le_bytes()); // pc_range
        let aug = lsda_addr.to_le_bytes();
        fde.extend(uleb(aug.len() as u64));
        fde.extend_from_slice(&aug);
        while fde.len() % 8 != 0 {
            fde.push(0);
        }
        b.extend_from_slice(&(fde.len() as u32).to_le_bytes());
        b.extend_from_slice(&fde);
        b.extend_from_slice(&0u32.to_le_bytes()); // terminator
        let eh_len = b.len() as u64;

        // --- LSDA at 0x8000 (pad the buffer out to it) ---
        b.resize((lsda_addr - BASE) as usize, 0);
        let mut cs = Vec::new();
        // entry 1: [0x10, 0x20) -> pad at func+0xd0
        cs.extend(uleb(0x10));
        cs.extend(uleb(0x20));
        cs.extend(uleb(0xd0));
        cs.extend(uleb(0));
        // entry 2: [0x40, 0x10) -> NO landing pad
        cs.extend(uleb(0x40));
        cs.extend(uleb(0x10));
        cs.extend(uleb(0));
        cs.extend(uleb(0));
        let mut lsda = Vec::new();
        lsda.push(DW_EH_PE_OMIT); // lpstart omitted -> relative to func start
        lsda.push(DW_EH_PE_OMIT); // ttype omitted
        lsda.push(0x01); // call-site encoding: uleb128
        lsda.extend(uleb(cs.len() as u64));
        lsda.extend_from_slice(&cs);
        b.extend_from_slice(&lsda);

        (Flat { base: BASE, bytes: b }, eh_len)
    }

    #[test]
    fn recovers_the_landing_pad_and_skips_the_entry_without_one() {
        let (mem, eh_len) = fixture();
        let fns = scan_eh_frame(&mem, (Va(0x1000), eh_len));
        assert_eq!(fns.len(), 1, "one FDE, one function: {fns:?}");
        let f = &fns[0];
        assert_eq!(f.start, Va(0x4000));
        assert_eq!(f.end, Va(0x4100), "pc_range is an authoritative extent");
        assert_eq!(
            f.regions,
            vec![EhRegion { try_start: Va(0x4010), try_end: Va(0x4030), landing_pad: Va(0x40d0) }],
            "the cs_lp == 0 entry is not an edge to address zero"
        );
        assert_eq!(landing_pads(&fns).into_iter().collect::<Vec<_>>(), vec![0x40d0]);
    }

    /// A truncated section must stop, not panic and not invent records.
    #[test]
    fn a_truncated_section_yields_what_it_can() {
        let (mem, eh_len) = fixture();
        for cut in [1u64, 4, 7, 12, 20, eh_len / 2] {
            let _ = scan_eh_frame(&mem, (Va(0x1000), cut));
        }
        // And a section that is entirely absent is simply no information.
        assert!(scan_eh_frame(&mem, (Va(0x1000), 0)).is_empty());
    }

    /// An unmodeled pointer application (`datarel`) must yield nothing rather
    /// than a plausible-looking wrong address.
    #[test]
    fn an_unmodeled_encoding_is_refused_not_guessed() {
        let mut c = Cur::new(&[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(c.encoded(0x30 | 0x03, 0x1000), None, "datarel is not modeled");
        let mut c = Cur::new(&[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(c.encoded(0x10 | 0x0b, 0x1000), Some(0x1000 + 0x4433_2211));
    }
}

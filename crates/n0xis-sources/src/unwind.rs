//! Pure x64 (AMD64) stack unwinder — a from-scratch reimplementation of what
//! `RtlVirtualUnwind` does, but **cross-process and dependency-free**.
//!
//! ## Why not just call `RtlVirtualUnwind` / `dbghelp`
//!
//! `RtlVirtualUnwind` unwinds using the *current* process's function tables; it
//! can't walk a foreign target's stack. `dbghelp!StackWalkEx` can, but drags in
//! a stateful C symbol API. A watchpoint hit lands mid-function, where the true
//! caller is **not** simply `[rsp]` (the compiler may have pushed nonvolatiles
//! and allocated a frame), so a raw stack read gives the wrong answer — exactly
//! the limitation this module removes. Instead we read the target's own
//! `.pdata` (the `RUNTIME_FUNCTION` table) and `.xdata` (`UNWIND_INFO`) and
//! replay the unwind codes ourselves, one frame at a time.
//!
//! ## Boundary
//!
//! This is pure logic over a [`MemReader`] seam — it names no OS API. The live
//! debugger ([`crate::debug`]) supplies a `ReadProcessMemory`-backed reader and
//! a module map; the algorithm here is unit-tested against a synthetic in-memory
//! PE with zero Windows calls, the same discipline the rest of `n0xis-core`
//! holds. Scope: the integer unwind needed to recover the return-address chain
//! (RSP + nonvolatile GPRs). XMM saves don't move RSP, so they're skipped (their
//! slots are still counted); anything genuinely unrecognized stops the walk
//! rather than emitting a guessed frame (sound-over-complete).

use serde::Serialize;

/// Byte-level reader over the target's address space. `read` returns exactly
/// `len` bytes or `None` (unmapped / short read) — the unwinder treats any
/// `None` as "stop here", never a guess.
pub trait MemReader {
    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>>;

    fn u16(&self, addr: u64) -> Option<u16> {
        let b = self.read(addr, 2)?;
        Some(u16::from_le_bytes(b.try_into().ok()?))
    }
    fn u32(&self, addr: u64) -> Option<u32> {
        let b = self.read(addr, 4)?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    }
    fn u64(&self, addr: u64) -> Option<u64> {
        let b = self.read(addr, 8)?;
        Some(u64::from_le_bytes(b.try_into().ok()?))
    }
}

/// Bridges the crate's [`MemorySource`](crate::MemorySource) seam to
/// [`MemReader`]. `MemorySource::read` returns *up to* `len` bytes (truncated at
/// the mapping end); the unwinder needs an *exact* count or a hard stop, so a
/// short read is turned into `None` — the same discipline the Win32
/// `ProcMemReader` applies. Generic (and `?Sized`) so a `LiveTarget` default
/// method can wrap `self` without a `dyn` upcast.
pub(crate) struct SourceReader<'a, R: crate::MemorySource + ?Sized>(pub &'a R);

impl<R: crate::MemorySource + ?Sized> MemReader for SourceReader<'_, R> {
    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let bytes = self.0.read(n0xis_contracts::Va(addr), len).ok()?;
        (bytes.len() == len).then_some(bytes)
    }
}

/// A loaded module's span and name, for locating the `.pdata` that covers a
/// given RIP and for labelling frames.
#[derive(Clone, Debug)]
pub struct ModuleRange {
    pub base: u64,
    pub size: u64,
    pub name: String,
}

/// One recovered call-stack frame.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Frame {
    pub rip: u64,
    /// Owning module name, when RIP falls inside a known module.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// RVA within that module.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rva: Option<u32>,
    /// `"<module>+0x<rva>"` convenience label, mirroring `BreakpointHit`'s
    /// `relative_rip`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}

/// The minimal x64 machine state the unwinder threads from frame to frame.
/// `gpr` is indexed by the architectural integer-register number the unwind
/// codes use (see [`reg`]).
#[derive(Clone, Copy, Debug)]
pub struct UnwindRegs {
    pub rip: u64,
    pub gpr: [u64; 16],
}

/// x64 integer register numbers, as used by `UNWIND_CODE` `OpInfo`. The full
/// set is spelled out to document the ABI numbering even where a given name
/// isn't referenced directly.
#[allow(dead_code)]
pub mod reg {
    pub const RAX: usize = 0;
    pub const RCX: usize = 1;
    pub const RDX: usize = 2;
    pub const RBX: usize = 3;
    pub const RSP: usize = 4;
    pub const RBP: usize = 5;
    pub const RSI: usize = 6;
    pub const RDI: usize = 7;
    // 8..=15 are R8..=R15.
}

impl UnwindRegs {
    fn rsp(&self) -> u64 {
        self.gpr[reg::RSP]
    }
    fn set_rsp(&mut self, v: u64) {
        self.gpr[reg::RSP] = v;
    }
}

// UNWIND_INFO flags.
const UNW_FLAG_CHAININFO: u8 = 0x4;

// UWOP unwind operation codes.
const UWOP_PUSH_NONVOL: u8 = 0;
const UWOP_ALLOC_LARGE: u8 = 1;
const UWOP_ALLOC_SMALL: u8 = 2;
const UWOP_SET_FPREG: u8 = 3;
const UWOP_SAVE_NONVOL: u8 = 4;
const UWOP_SAVE_NONVOL_FAR: u8 = 5;
const UWOP_SAVE_XMM128: u8 = 8;
const UWOP_SAVE_XMM128_FAR: u8 = 9;
const UWOP_PUSH_MACHFRAME: u8 = 10;

/// A `.pdata` `RUNTIME_FUNCTION` (all fields are module RVAs).
#[derive(Clone, Copy, Debug)]
struct RuntimeFunction {
    begin: u32,
    end: u32,
    unwind: u32,
}

/// The executable format of a module, decided by the first bytes at its base.
/// Dispatch is by *format*, not host OS: a Windows binary running under Wine on
/// Linux is still a PE with `.pdata`, so it takes the PE path even though the
/// process is read through `/proc`. That is what lets one unwinder serve native
/// Linux, native Windows, and Wine targets alike.
enum Format {
    Pe,
    Elf,
    Unknown,
}

fn module_format(reader: &dyn MemReader, base: u64) -> Format {
    // PE needs only its 2-byte 'MZ'; ELF its 4-byte magic. Checking MZ first
    // (and with the smaller read) keeps the dispatch working even for a source
    // that can serve just the signature bytes.
    if reader.read(base, 2).as_deref() == Some(b"MZ") {
        return Format::Pe;
    }
    match reader.read(base, 4) {
        Some(h) if h == *b"\x7fELF" => Format::Elf,
        _ => Format::Unknown,
    }
}

/// One walk-step's outcome, uniform across formats: `Some(true)` stepped to a
/// caller, `Some(false)` reached a clean end of stack, `None` hit something
/// unmodeled and the walk must stop without fabricating a frame.
type Step = Option<bool>;

/// Walk the call stack from `start`, up to `max_frames` deep. The first frame
/// is `start.rip` itself (the hit site); each subsequent frame is a real caller
/// recovered through that module's unwind data — PE `.pdata`/`.xdata` or ELF
/// `.eh_frame` DWARF CFI, chosen per module by [`module_format`]. Stops cleanly
/// at the first thing it can't resolve (unknown module or format, missing or
/// unreadable unwind data, a zero or non-increasing frame) — a short honest
/// stack, never a fabricated one.
pub fn unwind(reader: &dyn MemReader, modules: &[ModuleRange], start: UnwindRegs, max_frames: usize) -> Vec<Frame> {
    let mut frames = Vec::new();
    let mut regs = start;
    // Per-module unwind tables, parsed lazily and reused across frames.
    let mut pdata_cache: Vec<(u64, Option<Vec<RuntimeFunction>>)> = Vec::new();
    let mut eh_cache: Vec<(u64, Option<u64>)> = Vec::new();

    for _ in 0..max_frames {
        let owner = module_containing(modules, regs.rip);
        frames.push(make_frame(regs.rip, owner));

        let Some(m) = owner else { break };
        let prev_rsp = regs.rsp();

        let step = match module_format(reader, m.base) {
            Format::Pe => pe_step(reader, m, &mut regs, &mut pdata_cache),
            Format::Elf => dwarf::elf_step(reader, m, &mut regs, &mut eh_cache),
            Format::Unknown => break,
        };
        match step {
            Some(true) => {}
            Some(false) => break,
            None => break, // hit something we don't model — stop, don't guess.
        }

        // Termination guards: a real call stack's RSP strictly increases toward
        // higher addresses. Anything else is corruption or a loop — stop.
        if regs.rsp() <= prev_rsp {
            break;
        }
    }
    frames
}

/// Advance one PE frame using the module's `.pdata`/`.xdata`. Returns the
/// uniform [`Step`] outcome (see [`unwind`]).
fn pe_step(reader: &dyn MemReader, m: &ModuleRange, regs: &mut UnwindRegs, pdata_cache: &mut Vec<(u64, Option<Vec<RuntimeFunction>>)>) -> Step {
    let rva = (regs.rip - m.base) as u32;
    let funcs = cached_pdata(pdata_cache, reader, m.base)?;
    match find_function(funcs, rva) {
        None => {
            // Leaf function: no unwind data, RSP untouched beyond the call — the
            // return address sits right at the top of the stack.
            let ret = reader.u64(regs.rsp())?;
            regs.set_rsp(regs.rsp().wrapping_add(8));
            if ret == 0 {
                return Some(false);
            }
            regs.rip = ret;
            Some(true)
        }
        Some(rf) => match apply_chain(reader, m.base, rf, regs, rva - rf.begin)? {
            StepKind::Normal => {
                let ret = reader.u64(regs.rsp())?;
                regs.set_rsp(regs.rsp().wrapping_add(8));
                if ret == 0 {
                    return Some(false);
                }
                regs.rip = ret;
                Some(true)
            }
            StepKind::MachineFrame => {
                // rip/rsp already set from the hardware trap frame.
                if regs.rip == 0 {
                    Some(false)
                } else {
                    Some(true)
                }
            }
        },
    }
}

enum StepKind {
    Normal,
    MachineFrame,
}

fn make_frame(rip: u64, owner: Option<&ModuleRange>) -> Frame {
    match owner {
        Some(m) => {
            let rva = (rip - m.base) as u32;
            Frame {
                rip,
                module: Some(m.name.clone()),
                rva: Some(rva),
                symbol: Some(format!("{}+0x{rva:x}", m.name)),
            }
        }
        None => Frame { rip, module: None, rva: None, symbol: None },
    }
}

fn module_containing(modules: &[ModuleRange], rip: u64) -> Option<&ModuleRange> {
    modules.iter().find(|m| rip >= m.base && rip < m.base.saturating_add(m.size))
}

fn cached_pdata<'a>(
    cache: &'a mut Vec<(u64, Option<Vec<RuntimeFunction>>)>,
    reader: &dyn MemReader,
    base: u64,
) -> Option<&'a [RuntimeFunction]> {
    if let Some(idx) = cache.iter().position(|(b, _)| *b == base) {
        return cache[idx].1.as_deref();
    }
    let parsed = exception_functions(reader, base);
    cache.push((base, parsed));
    cache.last().unwrap().1.as_deref()
}

/// Parse a module's PE headers (from the target's memory at `base`) down to the
/// exception data directory, then read the whole `RUNTIME_FUNCTION` array.
fn exception_functions(reader: &dyn MemReader, base: u64) -> Option<Vec<RuntimeFunction>> {
    // DOS header: 'MZ', e_lfanew at 0x3C.
    let mz = reader.read(base, 2)?;
    if mz != *b"MZ" {
        return None;
    }
    let e_lfanew = reader.u32(base + 0x3C)? as u64;
    let nt = base + e_lfanew;
    // "PE\0\0"
    if reader.read(nt, 4)? != [b'P', b'E', 0, 0] {
        return None;
    }
    // Optional header begins after the 4-byte signature + 20-byte file header.
    let opt = nt + 4 + 20;
    // PE32+ magic 0x20B (we only unwind 64-bit).
    if reader.u32(opt)? & 0xFFFF != 0x020B {
        return None;
    }
    // Data directories start at optional-header offset 112 for PE32+.
    // Index 3 = IMAGE_DIRECTORY_ENTRY_EXCEPTION.
    let dir = opt + 112 + 3 * 8;
    let ex_rva = reader.u32(dir)? as u64;
    let ex_size = reader.u32(dir + 4)? as usize;
    if ex_rva == 0 || ex_size == 0 {
        return None;
    }
    let raw = reader.read(base + ex_rva, ex_size)?;
    let mut funcs = Vec::with_capacity(ex_size / 12);
    for c in raw.chunks_exact(12) {
        funcs.push(RuntimeFunction {
            begin: u32::from_le_bytes(c[0..4].try_into().unwrap()),
            end: u32::from_le_bytes(c[4..8].try_into().unwrap()),
            unwind: u32::from_le_bytes(c[8..12].try_into().unwrap()),
        });
    }
    Some(funcs)
}

/// Binary-search the (begin-sorted) `RUNTIME_FUNCTION` table for the entry whose
/// `[begin, end)` covers `rva`.
fn find_function(funcs: &[RuntimeFunction], rva: u32) -> Option<&RuntimeFunction> {
    let mut lo = 0usize;
    let mut hi = funcs.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        let f = &funcs[mid];
        if rva < f.begin {
            hi = mid;
        } else if rva >= f.end {
            lo = mid + 1;
        } else {
            return Some(f);
        }
    }
    None
}

/// Apply an `UNWIND_INFO`'s codes to `regs`, following `UNW_FLAG_CHAININFO` to
/// any parent. `offset_in_func` is RIP's offset from the function start; codes
/// for prologue instructions that haven't executed yet at that offset are
/// skipped (the `RtlVirtualUnwind` prologue-position rule). Returns how the
/// caller should recover the return address, or `None` if an unmodeled code was
/// hit (caller stops the walk).
fn apply_chain(reader: &dyn MemReader, base: u64, rf: &RuntimeFunction, regs: &mut UnwindRegs, offset_in_func: u32) -> Option<StepKind> {
    let mut unwind_rva = rf.unwind;
    let mut first = true;
    // Bound the chain depth defensively (real chains are 1–2 deep).
    for _ in 0..16 {
        let info_addr = base + unwind_rva as u64;
        let header = reader.read(info_addr, 4)?;
        let flags = header[0] >> 3;
        let count = header[2] as usize;
        let frame_reg = (header[3] & 0x0F) as usize;
        let frame_off = (header[3] >> 4) as u64;

        // Only the primary function's codes are prologue-position sensitive; a
        // chained parent describes a shared region and applies in full.
        let limit = if first { Some(offset_in_func) } else { None };
        let kind = apply_codes(reader, info_addr + 4, count, frame_reg, frame_off, limit, regs)?;
        if matches!(kind, StepKind::MachineFrame) {
            return Some(StepKind::MachineFrame);
        }

        if flags & UNW_FLAG_CHAININFO != 0 {
            // A RUNTIME_FUNCTION follows the (even-padded) code array.
            let padded = count.div_ceil(2) * 2;
            let chain_at = info_addr + 4 + (padded as u64) * 2;
            let chain = reader.read(chain_at, 12)?;
            unwind_rva = u32::from_le_bytes(chain[8..12].try_into().unwrap());
            first = false;
            continue;
        }
        return Some(StepKind::Normal);
    }
    None
}

/// Replay `count` unwind codes (2 bytes each) at `codes_addr`, mutating `regs`.
/// A code is applied only if its prologue offset is `<= offset_limit` (when
/// `Some`) — i.e. that prologue instruction has already executed at the hit RIP.
/// `None` means "apply all" (chained parent / caller wants the full set).
/// Returns `None` on any code we don't model, so the walk stops cleanly rather
/// than desyncing the code stream. Only RSP-moving ops matter for the return
/// chain; `SAVE_*` (including XMM) record a save location without touching RSP,
/// so they're counted but skipped.
fn apply_codes(
    reader: &dyn MemReader,
    codes_addr: u64,
    count: usize,
    frame_reg: usize,
    frame_off: u64,
    offset_limit: Option<u32>,
    regs: &mut UnwindRegs,
) -> Option<StepKind> {
    let raw = reader.read(codes_addr, count * 2)?;
    let slot = |k: usize| -> u64 { u16::from_le_bytes([raw[k * 2], raw[k * 2 + 1]]) as u64 };

    let mut i = 0usize;
    while i < count {
        let code_offset = raw[i * 2] as u32;
        let op = raw[i * 2 + 1] & 0x0F;
        let info = raw[i * 2 + 1] >> 4;

        // Total nodes this op occupies (self + operand slots). Unknown op →
        // stop, since we can no longer trust the slot alignment.
        let nodes = match op {
            UWOP_PUSH_NONVOL | UWOP_ALLOC_SMALL | UWOP_SET_FPREG | UWOP_PUSH_MACHFRAME => 1,
            UWOP_ALLOC_LARGE => {
                if info == 0 {
                    2
                } else {
                    3
                }
            }
            UWOP_SAVE_NONVOL | UWOP_SAVE_XMM128 => 2,
            UWOP_SAVE_NONVOL_FAR | UWOP_SAVE_XMM128_FAR => 3,
            _ => return None,
        };
        if i + nodes > count {
            return None; // malformed: operand slots run past the array
        }

        if offset_limit.is_none_or(|lim| code_offset <= lim) {
            match op {
                UWOP_PUSH_NONVOL => {
                    let v = reader.u64(regs.rsp())?;
                    regs.gpr[info as usize] = v;
                    regs.set_rsp(regs.rsp().wrapping_add(8));
                }
                UWOP_ALLOC_LARGE => {
                    let size = if info == 0 { slot(i + 1) * 8 } else { slot(i + 1) | (slot(i + 2) << 16) };
                    regs.set_rsp(regs.rsp().wrapping_add(size));
                }
                UWOP_ALLOC_SMALL => {
                    regs.set_rsp(regs.rsp().wrapping_add(info as u64 * 8 + 8));
                }
                UWOP_SET_FPREG => {
                    // RSP := frame_register - FrameRegisterOffset*16. The frame
                    // register still holds its live value here (its pop appears
                    // later in the code stream), so this recovers the RSP the
                    // prologue lea'd the frame pointer from.
                    regs.set_rsp(regs.gpr[frame_reg].wrapping_sub(frame_off * 16));
                }
                UWOP_SAVE_NONVOL | UWOP_SAVE_NONVOL_FAR | UWOP_SAVE_XMM128 | UWOP_SAVE_XMM128_FAR => {
                    // Records where a register was saved; RSP unchanged.
                }
                UWOP_PUSH_MACHFRAME => {
                    // Hardware trap frame: [ (err?) RIP CS EFLAGS oldRSP SS ].
                    let extra = if info == 1 { 8 } else { 0 };
                    let rip = reader.u64(regs.rsp() + extra)?;
                    let old_rsp = reader.u64(regs.rsp() + extra + 24)?;
                    regs.rip = rip;
                    regs.set_rsp(old_rsp);
                    return Some(StepKind::MachineFrame);
                }
                _ => return None,
            }
        }
        i += nodes;
    }
    Some(StepKind::Normal)
}

/// The ELF/DWARF `.eh_frame` backend — the second unwind format behind the same
/// [`MemReader`] seam and the same [`UnwindRegs`]/[`Frame`] model as the PE
/// path. It is pure logic: `.eh_frame_hdr`/`.eh_frame` are `SHF_ALLOC` (mapped
/// via `PT_GNU_EH_FRAME`), so everything is read straight from the target image
/// — no filesystem, no OS API — and unit-tested against a synthetic in-memory
/// ELF and the real host binary. Sound-over-complete: a DWARF expression rule,
/// a missing table, or an `undefined` RA stops the walk rather than guessing.
mod dwarf {
    use super::{reg, MemReader, ModuleRange, UnwindRegs};
    use std::collections::HashMap;

    // DWARF x86-64 register column → architectural gpr index used by
    // `UnwindRegs::gpr`. The `.eh_frame` numbering is NOT the Win32 UNWIND_CODE
    // numbering, so this table bridges them. Column 16 is the return address.
    const DWARF_TO_GPR: [usize; 16] = [
        reg::RAX, reg::RDX, reg::RCX, reg::RBX, reg::RSI, reg::RDI, reg::RBP, reg::RSP,
        8, 9, 10, 11, 12, 13, 14, 15,
    ];
    fn dwarf_to_gpr(dw: u64) -> Option<usize> {
        (dw < 16).then(|| DWARF_TO_GPR[dw as usize])
    }

    // DW_EH_PE pointer encodings (low nibble = format, high nibble = base).
    const DW_EH_PE_OMIT: u8 = 0xff;
    const DW_EH_PE_ABSPTR: u8 = 0x00;
    const DW_EH_PE_ULEB128: u8 = 0x01;
    const DW_EH_PE_UDATA2: u8 = 0x02;
    const DW_EH_PE_UDATA4: u8 = 0x03;
    const DW_EH_PE_UDATA8: u8 = 0x04;
    const DW_EH_PE_SLEB128: u8 = 0x09;
    const DW_EH_PE_SDATA2: u8 = 0x0a;
    const DW_EH_PE_SDATA4: u8 = 0x0b;
    const DW_EH_PE_SDATA8: u8 = 0x0c;
    const DW_EH_PE_INDIRECT: u8 = 0x80;

    // CFI opcodes. The three "packed" ops carry an operand in their low 6 bits.
    const DW_CFA_ADVANCE_LOC: u8 = 0x40;
    const DW_CFA_OFFSET: u8 = 0x80;
    const DW_CFA_RESTORE: u8 = 0xc0;
    const DW_CFA_NOP: u8 = 0x00;
    const DW_CFA_SET_LOC: u8 = 0x01;
    const DW_CFA_ADVANCE_LOC1: u8 = 0x02;
    const DW_CFA_ADVANCE_LOC2: u8 = 0x03;
    const DW_CFA_ADVANCE_LOC4: u8 = 0x04;
    const DW_CFA_OFFSET_EXTENDED: u8 = 0x05;
    const DW_CFA_RESTORE_EXTENDED: u8 = 0x06;
    const DW_CFA_UNDEFINED: u8 = 0x07;
    const DW_CFA_SAME_VALUE: u8 = 0x08;
    const DW_CFA_REGISTER: u8 = 0x09;
    const DW_CFA_REMEMBER_STATE: u8 = 0x0a;
    const DW_CFA_RESTORE_STATE: u8 = 0x0b;
    const DW_CFA_DEF_CFA: u8 = 0x0c;
    const DW_CFA_DEF_CFA_REGISTER: u8 = 0x0d;
    const DW_CFA_DEF_CFA_OFFSET: u8 = 0x0e;
    const DW_CFA_DEF_CFA_EXPRESSION: u8 = 0x0f;
    const DW_CFA_EXPRESSION: u8 = 0x10;
    const DW_CFA_OFFSET_EXTENDED_SF: u8 = 0x11;
    const DW_CFA_DEF_CFA_SF: u8 = 0x12;
    const DW_CFA_DEF_CFA_OFFSET_SF: u8 = 0x13;
    const DW_CFA_VAL_OFFSET: u8 = 0x14;
    const DW_CFA_VAL_OFFSET_SF: u8 = 0x15;
    const DW_CFA_VAL_EXPRESSION: u8 = 0x16;
    const DW_CFA_GNU_ARGS_SIZE: u8 = 0x2e;
    const DW_CFA_GNU_NEGATIVE_OFFSET_EXTENDED: u8 = 0x2f;

    /// A byte cursor over a `&[u8]` slice with LEB128 + DW_EH_PE decoding.
    struct Cur<'a> {
        b: &'a [u8],
        p: usize,
    }
    impl<'a> Cur<'a> {
        fn new(b: &'a [u8]) -> Self {
            Cur { b, p: 0 }
        }
        fn done(&self) -> bool {
            self.p >= self.b.len()
        }
        fn u8(&mut self) -> Option<u8> {
            let v = *self.b.get(self.p)?;
            self.p += 1;
            Some(v)
        }
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            let s = self.b.get(self.p..self.p + n)?;
            self.p += n;
            Some(s)
        }
        fn u16(&mut self) -> Option<u16> {
            Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
        }
        fn u32(&mut self) -> Option<u32> {
            Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
        }
        fn u64(&mut self) -> Option<u64> {
            Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
        }
        fn uleb(&mut self) -> Option<u64> {
            let mut result = 0u64;
            let mut shift = 0u32;
            loop {
                let byte = self.u8()?;
                if shift < 64 {
                    result |= ((byte & 0x7f) as u64) << shift;
                }
                shift += 7;
                if byte & 0x80 == 0 {
                    return Some(result);
                }
                if shift >= 128 {
                    return None;
                }
            }
        }
        fn sleb(&mut self) -> Option<i64> {
            let mut result = 0i64;
            let mut shift = 0u32;
            loop {
                let byte = self.u8()?;
                if shift < 64 {
                    result |= ((byte & 0x7f) as i64) << shift;
                }
                shift += 7;
                if byte & 0x80 == 0 {
                    if shift < 64 && (byte & 0x40) != 0 {
                        result |= -1i64 << shift;
                    }
                    return Some(result);
                }
                if shift >= 128 {
                    return None;
                }
            }
        }
        /// Decode one DW_EH_PE value, resolving `pcrel`/`datarel` against the
        /// given bases. Indirect/unsupported applications yield `None`.
        fn encoded(&mut self, enc: u8, field_addr: u64, datarel_base: u64) -> Option<u64> {
            if enc == DW_EH_PE_OMIT || enc & DW_EH_PE_INDIRECT != 0 {
                return None;
            }
            let raw = self.encoded_raw(enc)?;
            apply_encoding_base(enc, raw, field_addr, datarel_base)
        }
        /// Read only the value bytes (ignoring the application base) — used for
        /// the FDE `pc_range` length and the personality pointer we discard.
        fn encoded_raw(&mut self, enc: u8) -> Option<i128> {
            Some(match enc & 0x0f {
                DW_EH_PE_ABSPTR => self.u64()? as i128,
                DW_EH_PE_ULEB128 => self.uleb()? as i128,
                DW_EH_PE_UDATA2 => self.u16()? as i128,
                DW_EH_PE_UDATA4 => self.u32()? as i128,
                DW_EH_PE_UDATA8 => self.u64()? as i128,
                DW_EH_PE_SLEB128 => self.sleb()? as i128,
                DW_EH_PE_SDATA2 => (self.u16()? as i16) as i128,
                DW_EH_PE_SDATA4 => (self.u32()? as i32) as i128,
                DW_EH_PE_SDATA8 => (self.u64()? as i64) as i128,
                _ => return None,
            })
        }
    }

    fn apply_encoding_base(enc: u8, raw: i128, field_addr: u64, datarel_base: u64) -> Option<u64> {
        let applied: i128 = match enc & 0x70 {
            0x00 => raw,                        // absolute
            0x10 => raw + field_addr as i128,   // pcrel
            0x30 => raw + datarel_base as i128, // datarel
            _ => return None,                   // textrel/funcrel/aligned unsupported
        };
        Some(applied as u64)
    }

    /// Locate a module's `.eh_frame_hdr` by parsing the ELF header + program
    /// headers straight from mapped memory at `base` (the ELF analogue of the
    /// PE `exception_functions` header walk). Returns its runtime address.
    fn eh_frame_hdr_addr(reader: &dyn MemReader, base: u64) -> Option<u64> {
        let ident = reader.read(base, 20)?;
        // 0x7f 'E' 'L' 'F', class(4)=2 (64-bit), data(5)=1 (little-endian).
        if &ident[0..4] != b"\x7fELF" || ident[4] != 2 || ident[5] != 1 {
            return None;
        }
        let e_phoff = reader.u64(base + 0x20)?;
        let e_phentsize = reader.u16(base + 0x36)? as u64;
        let e_phnum = reader.u16(base + 0x38)?;
        if e_phentsize < 56 {
            return None;
        }
        let mut first_load_vaddr: Option<u64> = None;
        let mut gnu_eh_vaddr: Option<u64> = None;
        for i in 0..e_phnum as u64 {
            let ph = base + e_phoff + i * e_phentsize;
            let p_type = reader.u32(ph)?;
            let p_vaddr = reader.u64(ph + 0x10)?;
            match p_type {
                1 => first_load_vaddr = first_load_vaddr.or(Some(p_vaddr)), // PT_LOAD
                0x6474_e550 => gnu_eh_vaddr = Some(p_vaddr),                // PT_GNU_EH_FRAME
                _ => {}
            }
        }
        // Load bias: the first PT_LOAD is mapped at `base`, so a link-time vaddr
        // `x` lives at `x + (base - first_load_vaddr)` at runtime.
        let bias = base.wrapping_sub(first_load_vaddr?);
        Some(gnu_eh_vaddr?.wrapping_add(bias))
    }

    /// Binary-search `.eh_frame_hdr`'s sorted table for the FDE covering `pc`.
    fn find_fde(reader: &dyn MemReader, hdr_addr: u64, pc: u64) -> Option<u64> {
        let head = reader.read(hdr_addr, 4)?;
        if head[0] != 1 {
            return None; // unknown version
        }
        let (eh_ptr_enc, count_enc, table_enc) = (head[1], head[2], head[3]);
        let mut off = 4u64;
        // Decode a leading scalar (eh_frame_ptr / fde_count), advancing `off`.
        let mut lead = |enc: u8| -> Option<u64> {
            let field_addr = hdr_addr + off;
            let win = reader.read(field_addr, 16)?;
            let mut c = Cur::new(&win);
            let raw = c.encoded_raw(enc)?;
            off += c.p as u64;
            apply_encoding_base(enc, raw, field_addr, hdr_addr)
        };
        let _eh_frame_ptr = lead(eh_ptr_enc)?;
        let fde_count = lead(count_enc)?;
        if fde_count == 0 {
            return None;
        }
        let entry_size = match table_enc & 0x0f {
            DW_EH_PE_SDATA4 | DW_EH_PE_UDATA4 => 8u64,
            DW_EH_PE_SDATA8 | DW_EH_PE_UDATA8 => 16u64,
            _ => return None,
        };
        let table_start = hdr_addr + off;
        let decode = |idx: u64| -> Option<(u64, u64)> {
            let ent = table_start + idx * entry_size;
            let win = reader.read(ent, entry_size as usize)?;
            let mut c = Cur::new(&win);
            let loc_raw = c.encoded_raw(table_enc)?;
            let fde_raw = c.encoded_raw(table_enc)?;
            let loc = apply_encoding_base(table_enc, loc_raw, ent, hdr_addr)?;
            let fde = apply_encoding_base(table_enc, fde_raw, ent + entry_size / 2, hdr_addr)?;
            Some((loc, fde))
        };
        // Greatest initial_location <= pc.
        let (mut lo, mut hi, mut chosen) = (0u64, fde_count, None);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let (loc, fde) = decode(mid)?;
            if loc <= pc {
                chosen = Some(fde);
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        chosen
    }

    struct Cie {
        code_align: u64,
        data_align: i64,
        ra_reg: u64,
        fde_enc: u8,
        has_aug: bool,
        initial: Vec<u8>,
    }

    struct Fde {
        pc_begin: u64,
        pc_range: u64,
        instructions: Vec<u8>,
        cie: Cie,
    }

    /// Read one `.eh_frame` record at `addr`: `(total_size, content, len_field)`
    /// where `len_field` is 4 (normal) or 12 (0xffffffff extended length).
    fn read_entry(reader: &dyn MemReader, addr: u64) -> Option<(u64, Vec<u8>, u64)> {
        let len32 = reader.u32(addr)?;
        let (len, len_field) = if len32 == 0xffff_ffff {
            (reader.u64(addr + 4)?, 12u64)
        } else {
            (len32 as u64, 4u64)
        };
        if len == 0 {
            return None; // terminator
        }
        let content = reader.read(addr + len_field, len as usize)?;
        Some((len_field + len, content, len_field))
    }

    fn parse_cie(reader: &dyn MemReader, cie_addr: u64) -> Option<Cie> {
        let (_total, content, len_field) = read_entry(reader, cie_addr)?;
        let mut c = Cur::new(&content);
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
        let code_align = c.uleb()?;
        let data_align = c.sleb()?;
        let ra_reg = if version == 1 { c.u8()? as u64 } else { c.uleb()? };
        let has_aug = aug.first() == Some(&b'z');
        let mut fde_enc = DW_EH_PE_ABSPTR;
        if has_aug {
            let aug_len = c.uleb()? as usize;
            let aug_start = c.p;
            for &ch in &aug[1..] {
                match ch {
                    b'R' => fde_enc = c.u8()?,
                    b'P' => {
                        let enc = c.u8()?;
                        let _ = c.encoded_raw(enc)?; // personality ptr, discarded
                    }
                    b'L' => {
                        let _lsda_enc = c.u8()?;
                    }
                    _ => {}
                }
            }
            c.p = aug_start + aug_len; // skip any augmentation remainder
        }
        let initial = content.get(c.p..)?.to_vec();
        let _ = len_field;
        Some(Cie { code_align, data_align, ra_reg, fde_enc, has_aug, initial })
    }

    fn parse_fde(reader: &dyn MemReader, fde_addr: u64) -> Option<Fde> {
        let (_total, content, len_field) = read_entry(reader, fde_addr)?;
        let mut c = Cur::new(&content);
        let cie_ptr = c.u32()?;
        if cie_ptr == 0 {
            return None; // a CIE, not an FDE
        }
        // The CIE pointer is the byte distance backward from this field.
        let cie_ptr_field = fde_addr + len_field;
        let cie_addr = cie_ptr_field.checked_sub(cie_ptr as u64)?;
        let cie = parse_cie(reader, cie_addr)?;
        let pc_begin_field = fde_addr + len_field + c.p as u64;
        let pc_begin = c.encoded(cie.fde_enc, pc_begin_field, 0)?;
        // pc_range uses the same value width, but the pcrel/datarel base does
        // not apply to a length — take the raw magnitude.
        let pc_range = c.encoded_raw(cie.fde_enc)? as u64;
        if cie.has_aug {
            let aug_len = c.uleb()? as usize;
            c.p += aug_len; // FDE augmentation data (LSDA ptr) — unused
        }
        let instructions = content.get(c.p..)?.to_vec();
        Some(Fde { pc_begin, pc_range, instructions, cie })
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum RegRule {
        Undefined,
        SameValue,
        Offset(i64),    // saved at *(CFA + off)
        ValOffset(i64), // value IS CFA + off
        Register(u64),  // value is in another dwarf register
    }

    #[derive(Clone)]
    struct Row {
        cfa_reg: u64,
        cfa_offset: i64,
        regs: HashMap<u64, RegRule>,
    }
    impl Row {
        fn new() -> Self {
            Row { cfa_reg: 0, cfa_offset: 0, regs: HashMap::new() }
        }
    }

    /// Run the CIE initial instructions, then the FDE instructions up to (not
    /// past) `pc`, producing the unwind row in effect at `pc`. `None` on any
    /// unmodeled opcode (DWARF expressions) — sound over complete.
    fn run_cfi(cie: &Cie, fde: &Fde, pc: u64) -> Option<Row> {
        let mut row = Row::new();
        let mut loc = fde.pc_begin;
        run_instrs(&cie.initial, cie, &mut row, &mut loc, u64::MAX, &mut Vec::new(), true)?;
        let mut stack = Vec::new();
        run_instrs(&fde.instructions, cie, &mut row, &mut loc, pc, &mut stack, false)?;
        Some(row)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_instrs(instrs: &[u8], cie: &Cie, row: &mut Row, loc: &mut u64, pc_limit: u64, state_stack: &mut Vec<Row>, is_initial: bool) -> Option<()> {
        let mut c = Cur::new(instrs);
        // DW_CFA_restore restores to the CIE's initial rule for a register — the
        // row as it stands when the FDE pass begins (i.e. after the CIE pass).
        let initial_rules = row.clone();
        while !c.done() {
            if !is_initial && *loc > pc_limit {
                break;
            }
            let op = c.u8()?;
            let (hi, lo) = (op & 0xc0, op & 0x3f);
            if hi == DW_CFA_ADVANCE_LOC {
                *loc = loc.wrapping_add(lo as u64 * cie.code_align);
                continue;
            }
            if hi == DW_CFA_OFFSET {
                let n = c.uleb()?;
                row.regs.insert(lo as u64, RegRule::Offset(n as i64 * cie.data_align));
                continue;
            }
            if hi == DW_CFA_RESTORE {
                let r = initial_rules.regs.get(&(lo as u64)).copied().unwrap_or(RegRule::SameValue);
                row.regs.insert(lo as u64, r);
                continue;
            }
            match op {
                DW_CFA_NOP => {}
                DW_CFA_SET_LOC => *loc = c.encoded_raw(cie.fde_enc)? as u64,
                DW_CFA_ADVANCE_LOC1 => *loc = loc.wrapping_add(c.u8()? as u64 * cie.code_align),
                DW_CFA_ADVANCE_LOC2 => *loc = loc.wrapping_add(c.u16()? as u64 * cie.code_align),
                DW_CFA_ADVANCE_LOC4 => *loc = loc.wrapping_add(c.u32()? as u64 * cie.code_align),
                DW_CFA_OFFSET_EXTENDED => {
                    let (r, n) = (c.uleb()?, c.uleb()?);
                    row.regs.insert(r, RegRule::Offset(n as i64 * cie.data_align));
                }
                DW_CFA_OFFSET_EXTENDED_SF => {
                    let (r, n) = (c.uleb()?, c.sleb()?);
                    row.regs.insert(r, RegRule::Offset(n * cie.data_align));
                }
                DW_CFA_RESTORE_EXTENDED => {
                    let r = c.uleb()?;
                    let rule = initial_rules.regs.get(&r).copied().unwrap_or(RegRule::SameValue);
                    row.regs.insert(r, rule);
                }
                DW_CFA_UNDEFINED => {
                    let r = c.uleb()?;
                    row.regs.insert(r, RegRule::Undefined);
                }
                DW_CFA_SAME_VALUE => {
                    let r = c.uleb()?;
                    row.regs.insert(r, RegRule::SameValue);
                }
                DW_CFA_REGISTER => {
                    let (r, r2) = (c.uleb()?, c.uleb()?);
                    row.regs.insert(r, RegRule::Register(r2));
                }
                DW_CFA_REMEMBER_STATE => state_stack.push(row.clone()),
                DW_CFA_RESTORE_STATE => *row = state_stack.pop()?,
                DW_CFA_DEF_CFA => {
                    row.cfa_reg = c.uleb()?;
                    row.cfa_offset = c.uleb()? as i64;
                }
                DW_CFA_DEF_CFA_REGISTER => row.cfa_reg = c.uleb()?,
                DW_CFA_DEF_CFA_OFFSET => row.cfa_offset = c.uleb()? as i64,
                DW_CFA_DEF_CFA_SF => {
                    row.cfa_reg = c.uleb()?;
                    row.cfa_offset = c.sleb()? * cie.data_align;
                }
                DW_CFA_DEF_CFA_OFFSET_SF => row.cfa_offset = c.sleb()? * cie.data_align,
                DW_CFA_VAL_OFFSET => {
                    let (r, n) = (c.uleb()?, c.uleb()?);
                    row.regs.insert(r, RegRule::ValOffset(n as i64 * cie.data_align));
                }
                DW_CFA_VAL_OFFSET_SF => {
                    let (r, n) = (c.uleb()?, c.sleb()?);
                    row.regs.insert(r, RegRule::ValOffset(n * cie.data_align));
                }
                DW_CFA_GNU_ARGS_SIZE => {
                    let _ = c.uleb()?; // argument area size — irrelevant to the RA chain
                }
                DW_CFA_GNU_NEGATIVE_OFFSET_EXTENDED => {
                    let (r, n) = (c.uleb()?, c.uleb()?);
                    row.regs.insert(r, RegRule::Offset(-(n as i64) * cie.data_align));
                }
                // We do not evaluate DWARF bytecode expressions — stop honestly.
                DW_CFA_DEF_CFA_EXPRESSION | DW_CFA_EXPRESSION | DW_CFA_VAL_EXPRESSION => return None,
                _ => return None,
            }
        }
        Some(())
    }

    /// Return-address-via-`[rsp]` fallback for a pc with no covering FDE — the
    /// same optimistic leaf handling the PE path uses.
    fn leaf_return(reader: &dyn MemReader, regs: &mut UnwindRegs) -> super::Step {
        let ret = reader.u64(regs.gpr[reg::RSP])?;
        regs.gpr[reg::RSP] = regs.gpr[reg::RSP].wrapping_add(8);
        if ret == 0 {
            return Some(false);
        }
        regs.rip = ret;
        Some(true)
    }

    fn hdr_cached(cache: &mut Vec<(u64, Option<u64>)>, reader: &dyn MemReader, base: u64) -> Option<u64> {
        if let Some(i) = cache.iter().position(|(b, _)| *b == base) {
            return cache[i].1;
        }
        let v = eh_frame_hdr_addr(reader, base);
        cache.push((base, v));
        v
    }

    /// Advance one ELF/DWARF frame. Same [`super::Step`] contract as `pe_step`.
    pub(super) fn elf_step(reader: &dyn MemReader, m: &ModuleRange, regs: &mut UnwindRegs, cache: &mut Vec<(u64, Option<u64>)>) -> super::Step {
        let hdr_addr = hdr_cached(cache, reader, m.base)?; // no PT_GNU_EH_FRAME → stop
        let pc = regs.rip;
        let Some(fde_addr) = find_fde(reader, hdr_addr, pc) else {
            return leaf_return(reader, regs);
        };
        let fde = parse_fde(reader, fde_addr)?;
        if pc < fde.pc_begin || pc >= fde.pc_begin.wrapping_add(fde.pc_range) {
            return leaf_return(reader, regs);
        }
        let row = run_cfi(&fde.cie, &fde, pc)?;

        // CFA = value(cfa_reg) + cfa_offset.
        let cfa = (regs.gpr[dwarf_to_gpr(row.cfa_reg)?] as i64).wrapping_add(row.cfa_offset) as u64;
        let load = |off: i64| reader.u64((cfa as i64).wrapping_add(off) as u64);

        // Return address, from the CIE's RA column rule.
        let new_rip = match row.regs.get(&fde.cie.ra_reg).copied().unwrap_or(RegRule::Undefined) {
            RegRule::Undefined | RegRule::SameValue => return Some(false), // top of stack
            RegRule::Offset(off) => load(off)?,
            RegRule::ValOffset(off) => (cfa as i64).wrapping_add(off) as u64,
            RegRule::Register(r) => regs.gpr[dwarf_to_gpr(r)?],
        };
        if new_rip == 0 {
            return Some(false);
        }

        // Restore callee-saved GPRs (snapshot first so Register(rN) rules read
        // callee values, not half-updated ones). rbp especially matters: a
        // caller whose CFA is rbp-relative needs its restored rbp.
        let snap = regs.gpr;
        for (&dw, &rule) in &row.regs {
            if dw == fde.cie.ra_reg {
                continue;
            }
            let Some(slot) = dwarf_to_gpr(dw) else { continue };
            match rule {
                RegRule::Offset(off) => {
                    if let Some(v) = load(off) {
                        regs.gpr[slot] = v;
                    }
                }
                RegRule::ValOffset(off) => regs.gpr[slot] = (cfa as i64).wrapping_add(off) as u64,
                RegRule::Register(r) => {
                    if let Some(s) = dwarf_to_gpr(r) {
                        regs.gpr[slot] = snap[s];
                    }
                }
                RegRule::SameValue | RegRule::Undefined => {}
            }
        }

        regs.rip = new_rip;
        regs.gpr[reg::RSP] = cfa;
        Some(true)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::BTreeMap;

        #[derive(Default)]
        struct FakeMem {
            bytes: BTreeMap<u64, u8>,
        }
        impl FakeMem {
            fn put(&mut self, addr: u64, data: &[u8]) {
                for (i, b) in data.iter().enumerate() {
                    self.bytes.insert(addr + i as u64, *b);
                }
            }
            fn put_u16(&mut self, addr: u64, v: u16) {
                self.put(addr, &v.to_le_bytes());
            }
            fn put_u32(&mut self, addr: u64, v: u32) {
                self.put(addr, &v.to_le_bytes());
            }
            fn put_u64(&mut self, addr: u64, v: u64) {
                self.put(addr, &v.to_le_bytes());
            }
        }
        impl MemReader for FakeMem {
            fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
                let mut out = Vec::with_capacity(len);
                for i in 0..len as u64 {
                    out.push(*self.bytes.get(&(addr + i))?);
                }
                Some(out)
            }
        }

        const BASE: u64 = 0x5555_5555_0000;
        const STACK: u64 = 0x7fff_ffe0_0000;

        // A synthetic ELF: header + PT_LOAD(vaddr 0) + PT_GNU_EH_FRAME, an
        // .eh_frame_hdr with a 1-entry table, and an .eh_frame with one CIE +
        // one FDE for a `push rbp; mov rbp,rsp` frame.
        fn build() -> (FakeMem, u64) {
            let mut m = FakeMem::default();
            m.put(BASE, &[0u8; 0x200]); // back the header + phdr region
            m.put(BASE, b"\x7fELF");
            m.put(BASE + 4, &[2, 1, 1, 0]);
            let phoff = 0x40u64;
            m.put_u64(BASE + 0x20, phoff);
            m.put_u16(BASE + 0x36, 56);
            m.put_u16(BASE + 0x38, 2);
            let hdr_vaddr = 0x2000u64;
            let ph0 = BASE + phoff;
            m.put_u32(ph0, 1); // PT_LOAD
            m.put_u64(ph0 + 0x10, 0);
            let ph1 = BASE + phoff + 56;
            m.put_u32(ph1, 0x6474_e550); // PT_GNU_EH_FRAME
            m.put_u64(ph1 + 0x10, hdr_vaddr);
            let hdr_addr = BASE + hdr_vaddr;

            let eh_frame_addr = BASE + 0x3000;
            let func_start = BASE + 0x1000;
            let func_len = 0x40u32;

            // .eh_frame_hdr: v1, ptr=pcrel|sdata4, count=udata4, table=datarel|sdata4
            m.put(hdr_addr, &[0u8; 0x40]);
            m.put(hdr_addr, &[1, 0x1b, 0x03, 0x3b]);
            let field = hdr_addr + 4;
            m.put_u32(field, (eh_frame_addr as i64 - field as i64) as i32 as u32);
            m.put_u32(hdr_addr + 8, 1);
            let tbl = hdr_addr + 12;
            m.put_u32(tbl, (func_start as i64 - hdr_addr as i64) as i32 as u32);

            // CIE: zR, code_align=1, data_align=-8, ra=16, fde_enc=pcrel|sdata4,
            // initial: def_cfa(rsp,8); offset(ra, cfa-8).
            let mut cie = Vec::new();
            cie.extend_from_slice(&0u32.to_le_bytes());
            cie.push(1);
            cie.extend_from_slice(b"zR\0");
            cie.push(0x01);
            cie.push(0x78); // -8
            cie.push(16);
            cie.push(1);
            cie.push(0x1b);
            cie.push(DW_CFA_DEF_CFA);
            cie.push(7);
            cie.push(8);
            cie.push(DW_CFA_OFFSET | 16);
            cie.push(1);
            while cie.len() % 4 != 0 {
                cie.push(DW_CFA_NOP);
            }
            m.put_u32(eh_frame_addr, cie.len() as u32);
            m.put(eh_frame_addr + 4, &cie);
            let cie_total = 4 + cie.len() as u64;

            // FDE for [func_start, +func_len): after `push rbp` CFA=rsp+16 &
            // rbp@cfa-16; after `mov rbp,rsp` CFA switches to rbp-based.
            let fde_addr = eh_frame_addr + cie_total;
            let mut fde = Vec::new();
            let cie_ptr = (fde_addr + 4) - eh_frame_addr;
            fde.extend_from_slice(&(cie_ptr as u32).to_le_bytes());
            let pcb_field = fde_addr + 4 + fde.len() as u64;
            fde.extend_from_slice(&((func_start as i64 - pcb_field as i64) as i32 as u32).to_le_bytes());
            fde.extend_from_slice(&func_len.to_le_bytes());
            fde.push(0); // aug data len
            fde.push(DW_CFA_ADVANCE_LOC | 1);
            fde.push(DW_CFA_DEF_CFA_OFFSET);
            fde.push(16);
            fde.push(DW_CFA_OFFSET | 6); // rbp
            fde.push(2); // 2*-8 = -16
            fde.push(DW_CFA_ADVANCE_LOC | 3);
            fde.push(DW_CFA_DEF_CFA_REGISTER);
            fde.push(6);
            while fde.len() % 4 != 0 {
                fde.push(DW_CFA_NOP);
            }
            m.put_u32(fde_addr, fde.len() as u32);
            m.put(fde_addr + 4, &fde);
            m.put_u32(tbl + 4, (fde_addr as i64 - hdr_addr as i64) as i32 as u32);

            (m, func_start)
        }

        fn regs_at(rip: u64, rsp: u64, rbp: u64) -> UnwindRegs {
            let mut gpr = [0u64; 16];
            gpr[reg::RSP] = rsp;
            gpr[reg::RBP] = rbp;
            UnwindRegs { rip, gpr }
        }

        #[test]
        fn locates_hdr_and_parses_fde() {
            let (m, func_start) = build();
            let hdr = eh_frame_hdr_addr(&m, BASE).expect("hdr");
            let fde_addr = find_fde(&m, hdr, func_start + 8).expect("fde");
            let fde = parse_fde(&m, fde_addr).expect("parse");
            assert_eq!(fde.pc_begin, func_start);
            assert_eq!(fde.cie.data_align, -8);
            assert_eq!(fde.cie.ra_reg, 16);
        }

        #[test]
        fn unwinds_established_rbp_frame() {
            let (mut m, func_start) = build();
            let rbp = STACK;
            let saved_rbp = 0xCAFE_0000u64;
            let ret = BASE + 0x1234;
            m.put_u64(rbp, saved_rbp); // cfa-16
            m.put_u64(rbp + 8, ret); // cfa-8
            let mut regs = regs_at(func_start + 0x20, STACK - 0x40, rbp);
            let mut cache = Vec::new();
            let m0 = ModuleRange { base: BASE, size: 0x100_0000, name: "t".into() };
            assert_eq!(elf_step(&m, &m0, &mut regs, &mut cache), Some(true));
            assert_eq!(regs.rip, ret);
            assert_eq!(regs.gpr[reg::RBP], saved_rbp);
            assert_eq!(regs.gpr[reg::RSP], rbp + 16);
        }

        #[test]
        fn unwinds_mid_prologue_before_rbp_set() {
            let (mut m, func_start) = build();
            let rsp = STACK - 0x100;
            let ret = BASE + 0x2222;
            m.put_u64(rsp + 8, ret); // cfa-8, cfa = rsp+16
            let mut regs = regs_at(func_start + 1, rsp, 0xDEAD);
            let mut cache = Vec::new();
            let m0 = ModuleRange { base: BASE, size: 0x100_0000, name: "t".into() };
            assert_eq!(elf_step(&m, &m0, &mut regs, &mut cache), Some(true));
            assert_eq!(regs.rip, ret);
            assert_eq!(regs.gpr[reg::RSP], rsp + 16);
        }

        #[test]
        fn full_unwind_dispatches_elf_by_header() {
            // The public entry must pick the ELF path from the module header and
            // recover the caller chain end-to-end.
            let (mut m, func_start) = build();
            let rbp = STACK;
            let ret = BASE + 0x1234;
            m.put_u64(rbp, 0); // saved rbp = 0 (stops after one step)
            m.put_u64(rbp + 8, ret);
            let modules = [ModuleRange { base: BASE, size: 0x100_0000, name: "t.elf".into() }];
            let frames = super::super::unwind(&m, &modules, regs_at(func_start + 0x20, STACK - 0x40, rbp), 8);
            assert_eq!(frames[0].symbol.as_deref(), Some("t.elf+0x1020"), "frame 0 is the hit site");
            assert!(frames.len() >= 2);
            assert_eq!(frames[1].rip, ret);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A sparse byte-addressable memory for unit tests: a set of (addr, bytes)
    /// writes over which the reader serves any sub-range.
    #[derive(Default)]
    struct FakeMem {
        bytes: BTreeMap<u64, u8>,
    }
    impl FakeMem {
        fn put(&mut self, addr: u64, data: &[u8]) {
            for (i, b) in data.iter().enumerate() {
                self.bytes.insert(addr + i as u64, *b);
            }
        }
        fn put_u32(&mut self, addr: u64, v: u32) {
            self.put(addr, &v.to_le_bytes());
        }
        fn put_u64(&mut self, addr: u64, v: u64) {
            self.put(addr, &v.to_le_bytes());
        }
    }
    impl MemReader for FakeMem {
        fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
            let mut out = Vec::with_capacity(len);
            for i in 0..len as u64 {
                out.push(*self.bytes.get(&(addr + i))?);
            }
            Some(out)
        }
    }

    const BASE: u64 = 0x1_4000_0000;
    const STACK: u64 = 0x50_0000;

    /// Lay down a minimal PE header at `BASE` whose exception directory points
    /// at a `RUNTIME_FUNCTION` array of `funcs`, plus each function's
    /// `UNWIND_INFO`. Returns the populated FakeMem.
    fn pe_with(funcs: &[(u32, u32, u32)], unwind_infos: &[(u32, Vec<u8>)]) -> FakeMem {
        let mut m = FakeMem::default();
        // DOS
        m.put(BASE, b"MZ");
        let e_lfanew: u32 = 0x80;
        m.put_u32(BASE + 0x3C, e_lfanew);
        let nt = BASE + e_lfanew as u64;
        m.put(nt, b"PE\0\0");
        let opt = nt + 4 + 20;
        m.put_u32(opt, 0x020B); // PE32+ magic
        // exception dir (index 3) at opt+112+24
        let pdata_rva: u32 = 0x1000;
        let pdata_size = (funcs.len() * 12) as u32;
        m.put_u32(opt + 112 + 3 * 8, pdata_rva);
        m.put_u32(opt + 112 + 3 * 8 + 4, pdata_size);
        // RUNTIME_FUNCTION array
        for (i, (b, e, u)) in funcs.iter().enumerate() {
            let a = BASE + pdata_rva as u64 + (i * 12) as u64;
            m.put_u32(a, *b);
            m.put_u32(a + 4, *e);
            m.put_u32(a + 8, *u);
        }
        // UNWIND_INFO blobs
        for (rva, blob) in unwind_infos {
            m.put(BASE + *rva as u64, blob);
        }
        m
    }

    fn regs_at(rip: u64, rsp: u64) -> UnwindRegs {
        let mut gpr = [0u64; 16];
        gpr[reg::RSP] = rsp;
        UnwindRegs { rip, gpr }
    }

    #[test]
    fn leaf_function_returns_via_top_of_stack() {
        // A function with no RUNTIME_FUNCTION covering it → leaf → [rsp] is the
        // return address.
        let mut m = pe_with(&[(0x2000, 0x2010, 0x3000)], &[(0x3000, vec![1, 0, 0, 0])]);
        let caller_ret = BASE + 0x9999;
        m.put_u64(STACK, caller_ret);
        // rip at 0x5000 (not covered by the single [0x2000,0x2010) function).
        let modules = [ModuleRange { base: BASE, size: 0x100_0000, name: "t.exe".into() }];
        let frames = unwind(&m, &modules, regs_at(BASE + 0x5000, STACK), 8);
        assert_eq!(frames[0].rva, Some(0x5000));
        assert_eq!(frames[1].rip, caller_ret);
        assert_eq!(frames[1].rva, Some(0x9999));
    }

    #[test]
    fn push_nonvol_and_alloc_small_recover_the_caller() {
        // Prolog modeled: push rbp; push rbx; sub rsp,0x20.
        // UNWIND_INFO codes are stored last-prolog-op-first:
        //   [ ALLOC_SMALL(0x20) ][ PUSH_NONVOL rbx ][ PUSH_NONVOL rbp ]
        // ALLOC_SMALL info for 0x20: size = info*8+8 = 0x20 => info = 3.
        // UNWIND_INFO header layout: [ver/flags, sizeOfProlog, countOfCodes, frameReg/off].
        let mut blob = vec![0x01u8 /*ver=1 flags=0*/, 0x08 /*prolog size*/, 0x03 /*3 codes*/, 0x00 /*no frame reg*/];
        blob.extend_from_slice(&[0x08, UWOP_ALLOC_SMALL | (3 << 4)]); // sub rsp,0x20
        blob.extend_from_slice(&[0x04, UWOP_PUSH_NONVOL | ((reg::RBX as u8) << 4)]); // push rbx
        blob.extend_from_slice(&[0x01, UWOP_PUSH_NONVOL | ((reg::RBP as u8) << 4)]); // push rbp

        let mut m = pe_with(&[(0x2000, 0x2100, 0x3000)], &[(0x3000, blob)]);
        // Build the stack the prolog would have created, top-down at RSP:
        //   [rsp+0x00 .. +0x20) : local alloc (0x20 bytes)
        //   [rsp+0x20]          : saved rbx (pushed 2nd)
        //   [rsp+0x28]          : saved rbp (pushed 1st)
        //   [rsp+0x30]          : return address
        let rsp = STACK;
        m.put_u64(rsp + 0x20, 0xB0B0); // rbx
        m.put_u64(rsp + 0x28, 0xA0A0); // rbp
        let ret = BASE + 0x4192B;
        m.put_u64(rsp + 0x30, ret);

        let modules = [ModuleRange { base: BASE, size: 0x100_0000, name: "testgame.exe".into() }];
        let frames = unwind(&m, &modules, regs_at(BASE + 0x2050, rsp), 8);
        assert_eq!(frames.len(), 2, "hit frame + one caller");
        assert_eq!(frames[0].symbol.as_deref(), Some("testgame.exe+0x2050"));
        assert_eq!(frames[1].rip, ret);
        assert_eq!(frames[1].symbol.as_deref(), Some("testgame.exe+0x4192b"));
    }

    #[test]
    fn at_function_entry_prologue_codes_are_skipped() {
        // Same function/prolog as above, but the hit lands at offset 0 (function
        // entry): no prologue instruction has executed, so no unwind code
        // applies and the return address is simply [rsp].
        let mut blob = vec![0x01u8, 0x08, 0x03, 0x00];
        blob.extend_from_slice(&[0x08, UWOP_ALLOC_SMALL | (3 << 4)]);
        blob.extend_from_slice(&[0x04, UWOP_PUSH_NONVOL | ((reg::RBX as u8) << 4)]);
        blob.extend_from_slice(&[0x01, UWOP_PUSH_NONVOL | ((reg::RBP as u8) << 4)]);
        let mut m = pe_with(&[(0x2000, 0x2100, 0x3000)], &[(0x3000, blob)]);
        let ret = BASE + 0x7777;
        m.put_u64(STACK, ret); // return addr right at rsp (nothing pushed yet)
        let modules = [ModuleRange { base: BASE, size: 0x100_0000, name: "t.exe".into() }];
        let frames = unwind(&m, &modules, regs_at(BASE + 0x2000, STACK), 8);
        assert_eq!(frames[1].rip, ret, "at entry, [rsp] is the caller");
    }

    #[test]
    fn stops_cleanly_when_rip_leaves_all_modules() {
        let m = pe_with(&[(0x2000, 0x2010, 0x3000)], &[(0x3000, vec![1, 0, 0, 0])]);
        let modules = [ModuleRange { base: BASE, size: 0x100_0000, name: "t.exe".into() }];
        // rip outside the module → a single unknown frame, no crash.
        let frames = unwind(&m, &modules, regs_at(0xDEAD_0000, STACK), 8);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].module, None);
    }
}

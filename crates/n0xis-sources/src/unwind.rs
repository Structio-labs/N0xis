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

    fn u32(&self, addr: u64) -> Option<u32> {
        let b = self.read(addr, 4)?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    }
    fn u64(&self, addr: u64) -> Option<u64> {
        let b = self.read(addr, 8)?;
        Some(u64::from_le_bytes(b.try_into().ok()?))
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

/// Walk the call stack from `start`, up to `max_frames` deep. The first frame
/// is `start.rip` itself (the hit site); each subsequent frame is a real caller
/// recovered through that module's unwind data. Stops cleanly at the first
/// thing it can't resolve (unknown module, missing or unreadable unwind data,
/// a zero or non-increasing frame) — a short honest stack, never a fabricated
/// one.
pub fn unwind(reader: &dyn MemReader, modules: &[ModuleRange], start: UnwindRegs, max_frames: usize) -> Vec<Frame> {
    let mut frames = Vec::new();
    let mut regs = start;
    // Per-module `.pdata` tables, parsed lazily and reused across frames.
    let mut pdata_cache: Vec<(u64, Option<Vec<RuntimeFunction>>)> = Vec::new();

    for _ in 0..max_frames {
        let owner = module_containing(modules, regs.rip);
        frames.push(make_frame(regs.rip, owner));

        let Some(m) = owner else { break };
        let rva = (regs.rip - m.base) as u32;

        let funcs = cached_pdata(&mut pdata_cache, reader, m.base);
        let Some(funcs) = funcs else { break };

        let prev_rsp = regs.rsp();
        match find_function(funcs, rva) {
            None => {
                // Leaf function: no unwind data, RSP untouched beyond the call —
                // the return address sits right at the top of the stack.
                let Some(ret) = reader.u64(regs.rsp()) else { break };
                regs.set_rsp(regs.rsp().wrapping_add(8));
                if ret == 0 {
                    break;
                }
                regs.rip = ret;
            }
            Some(rf) => match apply_chain(reader, m.base, rf, &mut regs, rva - rf.begin) {
                Some(StepKind::Normal) => {
                    let Some(ret) = reader.u64(regs.rsp()) else { break };
                    regs.set_rsp(regs.rsp().wrapping_add(8));
                    if ret == 0 {
                        break;
                    }
                    regs.rip = ret;
                }
                Some(StepKind::MachineFrame) => {
                    // rip/rsp already set from the hardware trap frame.
                    if regs.rip == 0 {
                        break;
                    }
                }
                None => break, // hit something we don't model — stop, don't guess.
            },
        }

        // Termination guards: a real call stack's RSP strictly increases toward
        // higher addresses. Anything else is corruption or a loop — stop.
        if regs.rsp() <= prev_rsp {
            break;
        }
    }
    frames
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
    if mz != [b'M', b'Z'] {
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

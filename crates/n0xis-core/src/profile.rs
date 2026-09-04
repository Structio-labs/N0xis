// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Target profiling — "what am I even looking at?", answered before the first
//! real analysis command instead of by a sequence of failures.
//!
//! The gap this closes is concrete and was measured, not imagined: an agent
//! working a Unity/IL2CPP binary ran `xref string` and `bindings list`, got
//! `count: 0` from both, and concluded there were no references — when the
//! truth was that this *format* keeps those things outside the image entirely.
//! A silent zero is the most misleading shape a result can take, because it
//! reads as "I checked, there is nothing" while meaning "wrong question for
//! this target".
//!
//! So this module reports two things a reader cannot derive from any other
//! single command:
//!
//! 1. **Facts about the image** — sections, the export table, how many exports
//!    are jump *thunks* (whose implementation therefore carries a different
//!    address than the symbol), how many share an address through identical-
//!    code folding, whether `.pdata` exists.
//! 2. **Advisories** — which commands are expected to be ineffective or
//!    degraded on *this* target, each with the reason. Every advisory is
//!    derived from evidence gathered above; none is a static list.
//!
//! Everything is read through the [`MemorySource`] seam and decoded through
//! the [`Arch`] seam, so this behaves the same on a static PE and a live
//! module and stays free of both OS and ISA specifics — the same discipline
//! [`crate::discover::discover_pdata`] follows.

use std::collections::HashMap;

use n0xis_arch::{Arch, InsnKind};
use n0xis_contracts::Va;
use n0xis_sources::MemorySource;
use serde::Serialize;

use crate::CoreError;

/// `IMAGE_SCN_MEM_EXECUTE` — the section holds executable code.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// One PE section as the image declares it.
#[derive(Clone, Debug, Serialize)]
pub struct SectionInfo {
    pub name: String,
    pub va: Va,
    pub virtual_size: u32,
    pub raw_size: u32,
    /// `IMAGE_SCN_MEM_EXECUTE`. Carried because **`.text` is not always where
    /// the code is**: a Unity IL2CPP build puts the transpiled C# in a section
    /// literally named `il2cpp`, with `.text` holding only the runtime.
    /// Measured on a real target: `.text` 7 247 840 bytes, `il2cpp`
    /// 61 303 411 — the same characteristics, 8.5× the size. Every range-scoped
    /// command defaults its code window to `.text`, so without this the tool
    /// scans a tenth of the binary and reports the rest as empty.
    pub executable: bool,
}

/// An exported symbol and where it really lands.
#[derive(Clone, Debug, Serialize)]
pub struct ExportInfo {
    pub name: String,
    /// The address the export table points at.
    pub va: Va,
    /// Where that address jumps to, when the export is a one-instruction
    /// branch stub. **This is the address generated code actually calls**, so
    /// a symbol lookup keyed on `va` alone will never name it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thunk_target: Option<Va>,
    /// `"direct"` (the branch encodes its target) or `"indirect"` (the branch
    /// goes through a pointer slot, which had to be read to resolve it).
    ///
    /// The distinction carries information beyond bookkeeping: a *live* export
    /// that is indirect where the file on disk is direct has been rewritten
    /// since load — i.e. detoured by an injector or mod loader. Measured on a
    /// running target: `il2cpp_resolve_icall` is `e9 …` (`jmp rel32`) in the
    /// file and `ff 25 …` (`jmp [rip+…]`) in memory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thunk_kind: Option<&'static str>,
}

/// Exports that share one address because the linker folded identical bodies
/// (MSVC `/OPT:ICF`). Reported as a group precisely because picking one of the
/// names to display would state something false: the members are separate
/// API-level functions that merely compiled to the same bytes.
#[derive(Clone, Debug, Serialize)]
pub struct FoldedExports {
    pub va: Va,
    pub names: Vec<String>,
}

/// A recognized runtime/engine and what gave it away.
#[derive(Clone, Debug, Serialize)]
pub struct EngineHint {
    /// Stable token: `"il2cpp"`, `"mono"`, `"luajit"`, `"lua"`.
    pub engine: String,
    /// What was observed, in plain terms — an agent quoting this is quoting
    /// evidence, not a verdict.
    pub evidence: String,
}

/// A command that will not do what its name suggests on this target.
#[derive(Clone, Debug, Serialize)]
pub struct Advisory {
    /// The affected command path, e.g. `"xref string"`.
    pub command: String,
    /// `"ineffective"` (will return an empty/meaningless result) or
    /// `"degraded"` (works, but with a caveat that changes how to read it).
    pub verdict: String,
    pub reason: String,
}

/// What [`profile_image`] recovers from the image itself.
#[derive(Clone, Debug, Serialize)]
pub struct ImageProfile {
    pub module_base: Va,
    /// Exclusive end of the image, from the furthest section. Used to tell an
    /// in-image relay apart from one that leaves the module entirely.
    pub image_end: Va,
    /// PE `IMAGE_FILE_HEADER.Machine`, e.g. `"x64"`, `"arm64"`, or the raw
    /// hex when unrecognized (never guessed into a wrong name).
    pub machine: String,
    pub sections: Vec<SectionInfo>,
    pub export_count: usize,
    /// How many *distinct* addresses those exports occupy. Lower than
    /// `export_count` means the linker folded some — see [`Self::folded`].
    pub export_distinct_addresses: usize,
    pub thunk_count: usize,
    /// Exports that relay through a pointer to an address **outside this
    /// image** — the signature of a detour installed after load. Always
    /// computed, never gated behind [`Self::exports`]: an advisory that only
    /// fires when the caller happened to ask for the full export table is an
    /// advisory that will be missed exactly when it matters.
    pub detoured_exports: Vec<String>,
    pub folded: Vec<FoldedExports>,
    /// Present only when asked for; the full export list is large.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exports: Vec<ExportInfo>,
    pub pdata_present: bool,
    pub pdata_functions: usize,
    pub engine_hints: Vec<EngineHint>,
}

/// Engine fingerprints, as data. Adding a runtime is a row here, not a branch
/// in the logic below.
const ENGINE_EXPORT_PREFIXES: &[(&str, &str, usize)] = &[
    ("il2cpp", "il2cpp_", 10),
    ("mono", "mono_", 10),
    ("luajit", "luaJIT_", 2),
    ("lua", "lua_", 10),
];

fn rd_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

fn machine_name(m: u16) -> String {
    match m {
        0x8664 => "x64".to_string(),
        0x014c => "x86".to_string(),
        0xAA64 => "arm64".to_string(),
        0x01c4 => "arm".to_string(),
        other => format!("unknown(0x{other:04x})"),
    }
}

/// Map an RVA to the containing section so a file-backed source can be read at
/// the right place. A live module is already laid out by RVA, and a
/// [`StaticPe`](n0xis_sources::StaticPe) source translates internally, so
/// callers here only ever need `base + rva`.
fn profile_read(source: &dyn MemorySource, base: Va, rva: u32, len: usize) -> Option<Vec<u8>> {
    if rva == 0 {
        return None;
    }
    source.read(base.offset(rva as u64), len).ok()
}

/// Read a NUL-terminated ASCII name at `rva`, bounded so a corrupt table can
/// never make this loop forever.
fn read_cstr(source: &dyn MemorySource, base: Va, rva: u32) -> Option<String> {
    const MAX_NAME: usize = 512;
    let buf = profile_read(source, base, rva, MAX_NAME)?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

/// Profile the PE image mapped at `module_base`. `with_exports` includes the
/// full export list in the result (off by default — a runtime DLL can export
/// hundreds of names and the summary counts are what a reader usually needs).
pub fn profile_image(
    source: &dyn MemorySource,
    arch: &dyn Arch,
    module_base: Va,
    with_exports: bool,
) -> Result<ImageProfile, CoreError> {
    let hdr = source.read(module_base, 0x400)?;
    let e_lfanew = rd_u32(&hdr, 0x3c).ok_or_else(|| CoreError::Other("truncated PE header at module base".into()))? as usize;
    if hdr.get(e_lfanew..e_lfanew + 4) != Some(&b"PE\0\0"[..]) {
        return Err(CoreError::Other("no PE signature at module base (not a mapped PE image?)".into()));
    }
    let machine = hdr
        .get(e_lfanew + 4..e_lfanew + 6)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| CoreError::Other("PE file header too short".into()))?;
    let num_sections = hdr
        .get(e_lfanew + 6..e_lfanew + 8)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
        .unwrap_or(0) as usize;

    // PE32+ layout: optional header at e_lfanew+24, data directories at +112.
    // Directory 0 = export, 3 = exception (`.pdata`).
    let dd = e_lfanew + 24 + 112;
    let export_rva = rd_u32(&hdr, dd).unwrap_or(0);
    let exception_rva = rd_u32(&hdr, dd + 3 * 8).unwrap_or(0);
    let exception_size = rd_u32(&hdr, dd + 3 * 8 + 4).unwrap_or(0);

    // Section table follows the 240-byte PE32+ optional header.
    let sec_table = e_lfanew + 24 + 240;
    let mut sections = Vec::new();
    for i in 0..num_sections {
        let off = sec_table + i * 40;
        let Some(raw) = hdr.get(off..off + 40) else { break };
        let name_end = raw[..8].iter().position(|&b| b == 0).unwrap_or(8);
        sections.push(SectionInfo {
            name: String::from_utf8_lossy(&raw[..name_end]).into_owned(),
            va: module_base.offset(rd_u32(raw, 12).unwrap_or(0) as u64),
            virtual_size: rd_u32(raw, 8).unwrap_or(0),
            raw_size: rd_u32(raw, 16).unwrap_or(0),
            executable: rd_u32(raw, 36).unwrap_or(0) & IMAGE_SCN_MEM_EXECUTE != 0,
        });
    }

    let exports = read_exports(source, arch, module_base, export_rva);

    let mut by_addr: HashMap<u64, Vec<String>> = HashMap::new();
    for e in &exports {
        by_addr.entry(e.va.get()).or_default().push(e.name.clone());
    }
    let mut folded: Vec<FoldedExports> = by_addr
        .iter()
        .filter(|(_, names)| names.len() > 1)
        .map(|(va, names)| {
            let mut names = names.clone();
            names.sort();
            FoldedExports { va: Va(*va), names }
        })
        .collect();
    folded.sort_by_key(|f| f.va.get());

    let thunk_count = exports.iter().filter(|e| e.thunk_target.is_some()).count();
    let export_distinct_addresses = by_addr.len();
    let engine_hints = detect_engines(&exports);

    // `.pdata` entries are 12 bytes each; the count is exact, so report it
    // rather than re-walking the table.
    let pdata_present = exception_rva != 0 && exception_size != 0;
    let pdata_functions = if pdata_present { (exception_size as usize) / 12 } else { 0 };

    let image_end = sections
        .iter()
        .map(|s| s.va.get().saturating_add(s.virtual_size.max(s.raw_size) as u64))
        .max()
        .map(Va)
        .unwrap_or(module_base);

    let detoured_exports: Vec<String> = exports
        .iter()
        .filter(|e| e.thunk_kind == Some("indirect"))
        .filter(|e| e.thunk_target.is_some_and(|t| t.get() < module_base.get() || t.get() >= image_end.get()))
        .map(|e| e.name.clone())
        .collect();

    Ok(ImageProfile {
        module_base,
        image_end,
        machine: machine_name(machine),
        sections,
        export_count: exports.len(),
        export_distinct_addresses,
        thunk_count,
        detoured_exports,
        folded,
        exports: if with_exports { exports } else { Vec::new() },
        pdata_present,
        pdata_functions,
        engine_hints,
    })
}

/// Walk `IMAGE_EXPORT_DIRECTORY`, resolving each *named* export to its address
/// and, when that address holds a lone unconditional branch, to the branch
/// target — the address the generated code actually calls.
fn read_exports(source: &dyn MemorySource, arch: &dyn Arch, base: Va, export_rva: u32) -> Vec<ExportInfo> {
    // A malformed or hostile table must not be able to allocate unboundedly.
    const MAX_EXPORTS: usize = 100_000;
    let Some(dir) = profile_read(source, base, export_rva, 40) else { return Vec::new() };
    let num_names = rd_u32(&dir, 24).unwrap_or(0) as usize;
    let addr_funcs = rd_u32(&dir, 28).unwrap_or(0);
    let addr_names = rd_u32(&dir, 32).unwrap_or(0);
    let addr_ords = rd_u32(&dir, 36).unwrap_or(0);
    if num_names == 0 || num_names > MAX_EXPORTS {
        return Vec::new();
    }

    let Some(name_rvas) = profile_read(source, base, addr_names, num_names * 4) else { return Vec::new() };
    let Some(ord_raw) = profile_read(source, base, addr_ords, num_names * 2) else { return Vec::new() };

    let mut out = Vec::with_capacity(num_names);
    for i in 0..num_names {
        let Some(name_rva) = rd_u32(&name_rvas, i * 4) else { continue };
        let Some(name) = read_cstr(source, base, name_rva) else { continue };
        let ord = match ord_raw.get(i * 2..i * 2 + 2) {
            Some(b) => u16::from_le_bytes(b.try_into().unwrap()) as usize,
            None => continue,
        };
        let Some(fn_raw) = profile_read(source, base, addr_funcs + (ord as u32) * 4, 4) else { continue };
        let Some(fn_rva) = rd_u32(&fn_raw, 0) else { continue };
        if fn_rva == 0 {
            continue;
        }
        let va = base.offset(fn_rva as u64);
        let (thunk_target, thunk_kind) = match thunk_target_at(source, arch, va) {
            Some((t, k)) => (Some(t), Some(k)),
            None => (None, None),
        };
        out.push(ExportInfo { name, va, thunk_target, thunk_kind });
    }
    out
}

/// The branch target when `va` holds a single unconditional jump — i.e. the
/// export is a stub relaying to the real body. Uses the [`Arch`] decoder, so
/// this is not an `E9`-specific (or even x86-specific) rule.
///
/// Handles both relay shapes. A direct branch encodes its target. An indirect
/// one (`jmp [rip+disp]` — the IAT shape, and what a runtime detour installs)
/// only names a pointer *slot*, so the slot is read. That read is also the
/// validation: a static image's unbound import slot holds a file-relative
/// value that is not mapped anywhere, so it fails the readability check and is
/// correctly reported as "not a resolvable thunk" instead of as a confident
/// wrong address.
fn thunk_target_at(source: &dyn MemorySource, arch: &dyn Arch, va: Va) -> Option<(Va, &'static str)> {
    let bytes = source.read(va, 16).ok()?;
    let insn = arch.decode(&bytes, va).ok()?;
    if insn.kind != InsnKind::Jump {
        return None;
    }
    if let Some(t) = insn.target {
        return Some((t, "direct"));
    }
    let slot = insn.rip_target?;
    let raw = source.read(slot, 8).ok()?;
    let ptr = u64::from_le_bytes(raw.get(0..8)?.try_into().ok()?);
    if ptr == 0 {
        return None;
    }
    // Only claim the target if it is actually addressable in this same source.
    source.read(Va(ptr), 1).ok()?;
    Some((Va(ptr), "indirect"))
}

fn detect_engines(exports: &[ExportInfo]) -> Vec<EngineHint> {
    let mut hints = Vec::new();
    for (engine, prefix, min_hits) in ENGINE_EXPORT_PREFIXES {
        let hits = exports.iter().filter(|e| e.name.starts_with(prefix)).count();
        if hits >= *min_hits {
            hints.push(EngineHint {
                engine: (*engine).to_string(),
                evidence: format!("{hits} exported symbols named `{prefix}*`"),
            });
        }
    }
    // NativeAOT (.NET ILC / `PublishAot`) strips ordinary symbols but exports a
    // debug-header anchor; that exact name is a strong, prefix-free tell. Its
    // managed method names live in stack-trace metadata — see the `aot symbols`
    // advisory below.
    if exports.iter().any(|e| e.name == "DotNetRuntimeDebugHeader") {
        hints.push(EngineHint {
            engine: "nativeaot".to_string(),
            evidence: "exports `DotNetRuntimeDebugHeader` (.NET NativeAOT)".to_string(),
        });
    }

    // `mono_*` compatibility shims are exported by IL2CPP builds too, so a
    // Mono claim standing next to an IL2CPP one is misleading — drop it.
    if hints.iter().any(|h| h.engine == "il2cpp") {
        hints.retain(|h| h.engine != "mono");
    }
    hints
}

/// Turn the profile (plus whatever the caller learned from outside the image,
/// e.g. a sibling metadata file) into per-command advisories.
///
/// `il2cpp_metadata` is passed in rather than detected here because finding it
/// means touching the filesystem, which this crate deliberately cannot do.
pub fn advisories(profile: &ImageProfile, il2cpp_metadata: Option<&str>, live: bool) -> Vec<Advisory> {
    let mut out = Vec::new();
    let il2cpp = il2cpp_metadata.is_some() || profile.engine_hints.iter().any(|h| h.engine == "il2cpp");

    if profile.engine_hints.iter().any(|h| h.engine == "nativeaot") {
        out.push(Advisory {
            command: "disasm / decomp pseudo".into(),
            verdict: "degraded".into(),
            reason: "NativeAOT strips ordinary symbols, so calls render as `sub_<addr>`; run `aot symbols` to recover managed `Namespace.Type.Method` names (RVA↔name) from the image's stack-trace metadata".into(),
        });
    }

    if il2cpp {
        let where_ = match il2cpp_metadata {
            Some(p) => format!("managed metadata at {p}"),
            None => "managed metadata (global-metadata.dat)".to_string(),
        };
        // Both of these read "ineffective, full stop" until 2026-08-08, when
        // measuring them proved the claim too broad. The strings *are* in the
        // image — just not the ones people mean by "string literal". Narrowed
        // to what was actually observed, because an overstated advisory sends
        // an agent away from a command that would have worked.
        out.push(Advisory {
            command: "xref string".into(),
            verdict: "degraded".into(),
            // No borrowed counts here. An advisory fires on *this* target, so
            // quoting another binary's measurement — however real — states a
            // fact about a game the caller is not looking at. Describe the
            // mechanism; let `il2cpp icalls` report this target's own numbers.
            reason: format!(
                "managed C# literals are in {where_}, not in the image — search them with `il2cpp metadata --query`. \
                 Engine internal-call names, by contrast, ARE in `.rdata` and this command does find them; \
                 `il2cpp icalls` enumerates them and reports how many this binary actually has"
            ),
        });
        out.push(Advisory {
            command: "bindings list".into(),
            verdict: "ineffective".into(),
            reason: "IL2CPP resolves internal calls by name at runtime: the emitted code loads the name string, calls the resolver, \
                     and caches the returned pointer into a `.data` slot. The name is in the image but the function pointer is not, \
                     so the static name/pointer pairing this looks for does not exist to be found"
                .into(),
        });
        out.push(Advisory {
            command: "xref to".into(),
            verdict: "degraded".into(),
            reason: "virtual and interface calls dispatch through vtable slots; those edges are indirect and will not appear".into(),
        });
    }

    // Not gated on IL2CPP: any PE may carry more than one executable section,
    // and every range-scoped command defaults its code window to `.text`. It is
    // IL2CPP where it bites hardest — measured on a real Unity build, `.text`
    // is 10.6% of the executable bytes, so `xref`/`discover` scanned a tenth of
    // the binary and reported the other nine as containing nothing. A silent
    // zero is the most misleading shape a result can take (Phase 11), and this
    // is one the tool can see coming.
    let extra_code: Vec<&SectionInfo> = profile.sections.iter().filter(|s| s.executable && s.name != ".text").collect();
    if !extra_code.is_empty() {
        let text_size = profile.sections.iter().find(|s| s.name == ".text").map(|s| s.virtual_size).unwrap_or(0);
        let named = extra_code
            .iter()
            .map(|s| format!("`{}` ({} bytes at {}, pass `--start {} --size 0x{:x}`)", s.name, s.virtual_size, s.va, s.va, s.virtual_size))
            .collect::<Vec<_>>()
            .join("; ");
        out.push(Advisory {
            command: "xref, xref string, function discover, ir manifest, function trace".into(),
            verdict: "degraded".into(),
            reason: format!(
                "code is not confined to `.text` ({text_size} bytes): this image also has {named}. \
                 These commands default their code window to `.text`, so anything living in the other section(s) is silently absent from the result, \
                 not reported as out of range"
            ),
        });
    }

    if live {
        out.push(Advisory {
            command: "decomp pseudo".into(),
            verdict: "degraded".into(),
            reason: "a live source resolves no symbols, so every call renders as `sub_<addr>`; run the same address against `--file` when names matter".into(),
        });
    }

    if profile.thunk_count > 0 {
        out.push(Advisory {
            command: "decomp pseudo".into(),
            verdict: "degraded".into(),
            reason: format!(
                "{} exports are branch stubs; the implementation the code calls sits at the branch target, so those calls stay unnamed unless the thunk is followed",
                profile.thunk_count
            ),
        });
    }

    if !profile.folded.is_empty() {
        let names: usize = profile.folded.iter().map(|f| f.names.len()).sum();
        out.push(Advisory {
            command: "*".into(),
            verdict: "degraded".into(),
            reason: format!(
                "{} exported names share {} folded addresses; one address can legitimately have several unrelated names, so do not present one of them as the name",
                names,
                profile.folded.len()
            ),
        });
    }

    // An export relaying through a pointer to somewhere outside its own image
    // is not a normal linker artefact — it is a detour installed after load.
    // Worth surfacing unprompted: it means the behaviour being analyzed is not
    // the behaviour in the file on disk, which invalidates static reasoning
    // about that function silently if nobody says so.
    let escaping = &profile.detoured_exports;
    if !escaping.is_empty() {
        let shown: Vec<&str> = escaping.iter().take(5).map(|s| s.as_str()).collect();
        out.push(Advisory {
            command: "*".into(),
            verdict: "degraded".into(),
            reason: format!(
                "{} export(s) jump through a pointer to an address outside this image ({}{}) — they have been detoured since load, so the code running is not the code in the file",
                escaping.len(),
                shown.join(", "),
                if escaping.len() > shown.len() { ", …" } else { "" }
            ),
        });
    }

    if !profile.pdata_present {
        out.push(Advisory {
            command: "function discover --pdata".into(),
            verdict: "ineffective".into(),
            reason: "this image has no exception directory, so there is no unwind table to enumerate; prologue scanning is the only discovery mode here".into(),
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    /// A minimal but *real* PE32+ image: DOS stub → NT headers → one section →
    /// an export directory with three names, two of which are folded onto one
    /// address and one of which is a `jmp` stub.
    fn tiny_pe() -> (Snapshot, Va) {
        let base = Va(0x180000000);
        let mut img = vec![0u8; 0x2000];
        let e_lfanew = 0x80usize;
        img[0x3c..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
        img[e_lfanew..e_lfanew + 4].copy_from_slice(b"PE\0\0");
        img[e_lfanew + 4..e_lfanew + 6].copy_from_slice(&0x8664u16.to_le_bytes()); // machine x64
        img[e_lfanew + 6..e_lfanew + 8].copy_from_slice(&1u16.to_le_bytes()); // 1 section

        let dd = e_lfanew + 24 + 112;
        let export_rva = 0x400u32;
        img[dd..dd + 4].copy_from_slice(&export_rva.to_le_bytes());
        // Exception directory: 2 entries' worth (24 bytes) at some rva.
        img[dd + 24..dd + 28].copy_from_slice(&0x1000u32.to_le_bytes());
        img[dd + 28..dd + 32].copy_from_slice(&24u32.to_le_bytes());

        let sec = e_lfanew + 24 + 240;
        img[sec..sec + 5].copy_from_slice(b".text");
        img[sec + 8..sec + 12].copy_from_slice(&0x300u32.to_le_bytes()); // virtual size
        img[sec + 12..sec + 16].copy_from_slice(&0x200u32.to_le_bytes()); // rva
        img[sec + 16..sec + 20].copy_from_slice(&0x300u32.to_le_bytes()); // raw size

        // Export directory at 0x400.
        let ed = 0x400usize;
        let (names_rva, funcs_rva, ords_rva) = (0x480u32, 0x4a0u32, 0x4b0u32);
        img[ed + 24..ed + 28].copy_from_slice(&3u32.to_le_bytes()); // NumberOfNames
        img[ed + 28..ed + 32].copy_from_slice(&funcs_rva.to_le_bytes());
        img[ed + 32..ed + 36].copy_from_slice(&names_rva.to_le_bytes());
        img[ed + 36..ed + 40].copy_from_slice(&ords_rva.to_le_bytes());

        // Three name rvas → three strings.
        let name_strs = [(0x500u32, "il2cpp_alpha"), (0x520, "il2cpp_beta"), (0x540, "il2cpp_thunked")];
        for (i, (rva, s)) in name_strs.iter().enumerate() {
            let at = names_rva as usize + i * 4;
            img[at..at + 4].copy_from_slice(&rva.to_le_bytes());
            let so = *rva as usize;
            img[so..so + s.len()].copy_from_slice(s.as_bytes());
        }
        // Ordinals 0,1,2 → function rvas: alpha and beta fold onto 0x200,
        // thunked lives at 0x210 and jumps to 0x280.
        for i in 0..3u16 {
            let at = ords_rva as usize + i as usize * 2;
            img[at..at + 2].copy_from_slice(&i.to_le_bytes());
        }
        for (i, rva) in [0x200u32, 0x200, 0x210].iter().enumerate() {
            let at = funcs_rva as usize + i * 4;
            img[at..at + 4].copy_from_slice(&rva.to_le_bytes());
        }
        // 0x200: `ret` (not a thunk). 0x210: `jmp +0x6b` → 0x280.
        img[0x200] = 0xC3;
        img[0x210] = 0xE9;
        img[0x211..0x215].copy_from_slice(&0x6bi32.to_le_bytes());

        (Snapshot::builder().region(base, img).build(), base)
    }

    #[test]
    fn profiles_sections_exports_folding_and_thunks() {
        let (snap, base) = tiny_pe();
        let arch = X64::new();
        let p = profile_image(&snap, &arch, base, true).unwrap();

        assert_eq!(p.machine, "x64");
        assert_eq!(p.sections.len(), 1);
        assert_eq!(p.sections[0].name, ".text");

        assert_eq!(p.export_count, 3);
        assert_eq!(p.export_distinct_addresses, 2, "alpha and beta were folded onto one address");
        assert_eq!(p.folded.len(), 1);
        assert_eq!(p.folded[0].names, vec!["il2cpp_alpha", "il2cpp_beta"]);

        assert_eq!(p.thunk_count, 1);
        let thunked = p.exports.iter().find(|e| e.name == "il2cpp_thunked").unwrap();
        assert_eq!(thunked.va, base.offset(0x210));
        assert_eq!(thunked.thunk_target, Some(base.offset(0x280)), "the address generated code really calls");
        assert_eq!(thunked.thunk_kind, Some("direct"));

        assert!(p.pdata_present);
        assert_eq!(p.pdata_functions, 2, "24 bytes / 12 per RUNTIME_FUNCTION");
    }

    #[test]
    fn exports_are_omitted_unless_asked_for() {
        let (snap, base) = tiny_pe();
        let arch = X64::new();
        let p = profile_image(&snap, &arch, base, false).unwrap();
        assert_eq!(p.export_count, 3, "still counted");
        assert!(p.exports.is_empty(), "but not carried");
    }

    #[test]
    fn advisories_name_the_commands_that_will_mislead() {
        let (snap, base) = tiny_pe();
        let arch = X64::new();
        let p = profile_image(&snap, &arch, base, false).unwrap();
        // Three `il2cpp_*` exports is under the fingerprint threshold, so the
        // engine is not claimed from exports alone — the metadata file is what
        // settles it. That is the point: evidence, not vibes.
        assert!(p.engine_hints.is_empty(), "3 hits must not trip the 10-hit threshold");

        let adv = advisories(&p, Some("Game_Data/il2cpp_data/Metadata/global-metadata.dat"), false);
        let for_cmd = |c: &str| adv.iter().find(|a| a.command == c);
        // `xref string` is *degraded*, not ineffective — measured 2026-08-08:
        // managed C# literals are indeed absent from the image, but engine
        // internal-call names sit in `.rdata` and this command does find them.
        // The advisory has to carry both halves or it sends the caller away
        // from a command that works.
        assert_eq!(for_cmd("xref string").unwrap().verdict, "degraded");
        assert!(for_cmd("xref string").unwrap().reason.contains("global-metadata.dat"));
        assert!(for_cmd("xref string").unwrap().reason.contains("ARE in `.rdata`"));
        // An advisory describes *this* target. Quoting a number measured on
        // another binary states a fact about a game the caller is not looking
        // at, however real that number was elsewhere.
        assert!(
            !for_cmd("xref string").unwrap().reason.contains("2189"),
            "no measurement borrowed from another target may appear in an advisory"
        );
        assert_eq!(for_cmd("bindings list").unwrap().verdict, "ineffective");
        // …and for the right reason: the name is there, the pointer is not.
        assert!(for_cmd("bindings list").unwrap().reason.contains("resolves internal calls by name at runtime"));
        // The thunk and folding advisories come from measured image facts.
        assert!(adv.iter().any(|a| a.reason.contains("branch stubs")));
        assert!(adv.iter().any(|a| a.reason.contains("folded addresses")));
        // `.pdata` exists here, so nothing should claim otherwise.
        assert!(for_cmd("function discover --pdata").is_none());
    }

    /// A PE whose code does not all live in `.text` — the Unity IL2CPP shape,
    /// where the transpiled C# is in a section of its own and `.text` holds
    /// only the runtime.
    fn pe_with_two_code_sections() -> (Snapshot, Va) {
        let base = Va(0x180000000);
        let mut img = vec![0u8; 0x2000];
        let e_lfanew = 0x80usize;
        img[0x3c..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
        img[e_lfanew..e_lfanew + 4].copy_from_slice(b"PE\0\0");
        img[e_lfanew + 4..e_lfanew + 6].copy_from_slice(&0x8664u16.to_le_bytes());
        img[e_lfanew + 6..e_lfanew + 8].copy_from_slice(&2u16.to_le_bytes());

        let sec = e_lfanew + 24 + 240;
        for (i, (name, rva, vsize)) in [(&b".text"[..], 0x200u32, 0x300u32), (&b"il2cpp"[..], 0x600, 0x1000)].iter().enumerate() {
            let at = sec + i * 40;
            img[at..at + name.len()].copy_from_slice(name);
            img[at + 8..at + 12].copy_from_slice(&vsize.to_le_bytes());
            img[at + 12..at + 16].copy_from_slice(&rva.to_le_bytes());
            img[at + 16..at + 20].copy_from_slice(&vsize.to_le_bytes());
            img[at + 36..at + 40].copy_from_slice(&IMAGE_SCN_MEM_EXECUTE.to_le_bytes());
        }
        (Snapshot::builder().region(base, img).build(), base)
    }

    #[test]
    fn a_second_executable_section_is_called_out_with_the_window_to_pass() {
        // The failure this prevents: `.text` is 10.6% of a real IL2CPP image's
        // executable bytes, so every range-scoped command scanned a tenth of it
        // and reported the rest as containing nothing — a silent zero, which is
        // the most misleading shape a result can take.
        let (snap, base) = pe_with_two_code_sections();
        let arch = X64::new();
        let p = profile_image(&snap, &arch, base, false).unwrap();
        assert!(p.sections.iter().all(|s| s.executable), "both sections declare IMAGE_SCN_MEM_EXECUTE");

        let adv = advisories(&p, None, false);
        let hit = adv.iter().find(|a| a.reason.contains("code is not confined")).expect("an extra code section must be called out");
        assert!(hit.command.contains("xref"), "the advisory must name the commands it degrades: {}", hit.command);
        assert!(hit.reason.contains("`il2cpp`"), "…and name the section: {}", hit.reason);
        // The point of the advisory is that it is actionable, not that it warns.
        assert!(hit.reason.contains("--start 0x180000600") && hit.reason.contains("--size 0x1000"), "it must hand over the exact window: {}", hit.reason);
    }

    #[test]
    fn one_code_section_raises_nothing() {
        // The ordinary PE must not grow a warning it does not need.
        let (snap, base) = tiny_pe();
        let arch = X64::new();
        let p = profile_image(&snap, &arch, base, false).unwrap();
        assert!(!advisories(&p, None, false).iter().any(|a| a.reason.contains("code is not confined")));
    }

    #[test]
    fn a_live_source_is_told_it_has_no_symbols() {
        let (snap, base) = tiny_pe();
        let arch = X64::new();
        let p = profile_image(&snap, &arch, base, false).unwrap();
        let adv = advisories(&p, None, true);
        assert!(adv.iter().any(|a| a.command == "decomp pseudo" && a.reason.contains("resolves no symbols")));
    }

    /// The shape a runtime detour leaves behind, and the shape an unbound
    /// import slot leaves behind, are the same instruction — only the slot's
    /// contents tell them apart. Resolve one, refuse the other.
    #[test]
    fn an_indirect_thunk_resolves_only_when_its_slot_points_somewhere_real() {
        let (snap, base) = tiny_pe();
        let arch = X64::new();

        // Rewrite `il2cpp_thunked`'s body to `jmp qword ptr [rip+0x40]`,
        // putting the slot at 0x216+0x40 = 0x256, and point it at 0x290.
        let mut img = snap.read(base, 0x2000).unwrap();
        img[0x210..0x216].copy_from_slice(&[0xFF, 0x25, 0x40, 0x00, 0x00, 0x00]);
        img[0x256..0x25e].copy_from_slice(&(base.get() + 0x290).to_le_bytes());
        let hooked = Snapshot::builder().region(base, img.clone()).build();

        let p = profile_image(&hooked, &arch, base, true).unwrap();
        let t = p.exports.iter().find(|e| e.name == "il2cpp_thunked").unwrap();
        assert_eq!(t.thunk_target, Some(base.offset(0x290)));
        assert_eq!(t.thunk_kind, Some("indirect"), "read through the pointer slot");
        // 0x290 is inside `.text`, so this is an ordinary in-image relay, not
        // a detour — the advisory must not cry hook.
        assert!(p.detoured_exports.is_empty());
        assert!(!advisories(&p, None, false).iter().any(|a| a.reason.contains("detoured since load")));

        // Same instruction, but the slot holds a file-relative value that is
        // mapped nowhere — the unbound-import case. It must NOT be claimed.
        let mut unbound = img;
        unbound[0x256..0x25e].copy_from_slice(&0x1234u64.to_le_bytes());
        let stale = Snapshot::builder().region(base, unbound).build();
        let p = profile_image(&stale, &arch, base, true).unwrap();
        let t = p.exports.iter().find(|e| e.name == "il2cpp_thunked").unwrap();
        assert_eq!(t.thunk_target, None, "an unresolvable slot is not a thunk target");
        assert_eq!(p.thunk_count, 0);
    }

    /// The real shape observed on a running target: `il2cpp_resolve_icall`
    /// relayed through a pointer into memory owned by no module at all.
    #[test]
    fn a_relay_out_of_the_image_is_reported_as_a_detour_without_asking_for_exports() {
        let (snap, base) = tiny_pe();
        let arch = X64::new();
        let mut img = snap.read(base, 0x2000).unwrap();
        img[0x210..0x216].copy_from_slice(&[0xFF, 0x25, 0x40, 0x00, 0x00, 0x00]);
        // Slot points far outside the image — but still inside the snapshot,
        // so the readability check passes exactly as it would in a live
        // process where the trampoline is mapped.
        img[0x256..0x25e].copy_from_slice(&(base.get() + 0x1F00).to_le_bytes());
        let hooked = Snapshot::builder().region(base, img).build();

        // Note `with_exports: false` — the detour must still be found.
        let p = profile_image(&hooked, &arch, base, false).unwrap();
        assert!(p.exports.is_empty(), "export list was not requested");
        assert_eq!(p.detoured_exports, vec!["il2cpp_thunked"]);

        let adv = advisories(&p, None, false);
        let hook = adv.iter().find(|a| a.reason.contains("detoured since load")).expect("detour advisory");
        assert!(hook.reason.contains("il2cpp_thunked"));
    }

    #[test]
    fn a_non_pe_source_errors_instead_of_reporting_nonsense() {
        let snap = Snapshot::builder().region(Va(0x1000), vec![0u8; 0x400]).build();
        let arch = X64::new();
        assert!(profile_image(&snap, &arch, Va(0x1000), false).is_err());
    }
}

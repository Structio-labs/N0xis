//! # NativeAOT stack-trace metadata reader
//!
//! Universal `RVA ↔ method name` recovery for .NET **NativeAOT** images (ILC /
//! `PublishAot`). NativeAOT strips ordinary symbols, so `disasm`/`decomp` see
//! only `sub_XXXX`. But the compiler still emits a compact *stack-trace
//! metadata* blob so managed exception stacks stay readable — and that blob is
//! the most direct `method start RVA → fully-qualified name` map in the image.
//! This module parses it, for any .NET 8 NativeAOT image, with **no hardcode**
//! for a particular game.
//!
//! The format is documented in-tree (`dotnet/runtime`, release/8.0):
//! - `ReadyToRunHeader` + `ReadyToRunSectionType` — `Runtime/inc/ModuleHeaders.h`
//! - blob ids — `Common/src/Internal/Runtime/MetadataBlob.cs`
//! - the RVA→token linear blob — `Compiler/.../StackTraceMethodMappingNode.cs`
//!   read back by `System.Private.StackTraceMetadata/.../StackTraceMetadata.cs`
//! - the NativeFormat metadata records — `Internal/Metadata/NativeFormat/*`
//! - the name formatter — `.../StackTraceMetadata/MethodNameFormatter.cs`
//!
//! We read bytes through the [`MemorySource`] seam, so the exact same parser
//! runs against a `--file` PE and a live `--pid` (native or under Wine), just
//! like every other pass.

use std::collections::HashMap;

use n0xis_sources::MemorySource;
use n0xis_contracts::Va;

use crate::CoreError;

/// `RTR\0` — [`ReadyToRunHeaderConstants::Signature`], little-endian `0x00525452`.
const RTR_MAGIC: [u8; 4] = [0x52, 0x54, 0x52, 0x00];
/// Metadata blob header signature (`MetadataHeader.Signature`).
const METADATA_SIGNATURE: u32 = 0xDEAD_DFFD;
/// `ReadyToRunSectionType.ReadonlyBlobRegionStart`; a blob's section id is this
/// plus its [`ReflectionMapBlob`] value.
const READONLY_BLOB_REGION_START: i32 = 300;
/// `ReflectionMapBlob.EmbeddedMetadata`.
const BLOB_EMBEDDED_METADATA: i32 = 13;
/// `ReflectionMapBlob.BlobIdStackTraceMethodRvaToTokenMapping`.
const BLOB_STACKTRACE_RVA_TO_TOKEN: i32 = 27;
/// `ReflectionMapBlob.InvokeMap` — reflection method → entrypoint hashtable.
const BLOB_INVOKE_MAP: i32 = 6;
/// `ReflectionMapBlob.CommonFixupsTable` — external-references table the
/// InvokeMap indexes into for entrypoint RVAs.
const BLOB_COMMON_FIXUPS: i32 = 8;

/// `InvokeTableFlags` bits we branch on (`MappingTableFlags.cs`).
const INVOKE_HAS_METADATA_HANDLE: u32 = 0x04;
const INVOKE_HAS_ENTRYPOINT: u32 = 0x20;

// `StackTraceDataCommand` bits.
const CMD_UPDATE_OWNING_TYPE: u8 = 0x01;
const CMD_UPDATE_NAME: u8 = 0x02;
const CMD_UPDATE_SIGNATURE: u8 = 0x04;
const CMD_UPDATE_GENERIC_SIGNATURE: u8 = 0x08;

// `HandleType` values we dispatch on (`NativeFormatReaderCommonGen.cs`).
mod ht {
    pub const NULL: u8 = 0x0;
    pub const ARRAY_SIGNATURE: u8 = 0x1;
    pub const BY_REFERENCE_SIGNATURE: u8 = 0x2;
    pub const CONSTANT_STRING_VALUE: u8 = 0x1a;
    pub const FUNCTION_POINTER_SIGNATURE: u8 = 0x25;
    pub const GENERIC_PARAMETER: u8 = 0x26;
    pub const METHOD_TYPE_VARIABLE_SIGNATURE: u8 = 0x2c;
    pub const NAMESPACE_DEFINITION: u8 = 0x2f;
    pub const NAMESPACE_REFERENCE: u8 = 0x30;
    pub const POINTER_SIGNATURE: u8 = 0x32;
    pub const SZARRAY_SIGNATURE: u8 = 0x37;
    pub const TYPE_DEFINITION: u8 = 0x3a;
    pub const TYPE_INSTANTIATION_SIGNATURE: u8 = 0x3c;
    pub const TYPE_REFERENCE: u8 = 0x3d;
    pub const TYPE_SPECIFICATION: u8 = 0x3e;
    pub const TYPE_VARIABLE_SIGNATURE: u8 = 0x3f;
}

/// One recovered method: its start RVA and the name we reconstructed.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AotSymbol {
    /// Method-start RVA (module-relative).
    pub rva: u32,
    /// `rva` mapped to this image's preferred/live base.
    pub va: Va,
    /// Fully-qualified, signature-free name — `Namespace.Type.Method`. This is
    /// the stable key and what `symbol_at` hands to the decompiler.
    pub name: String,
    /// Parenthesized parameter list — `(Int32, Boolean)`.
    pub signature: String,
    /// Return type as spelled in metadata — `Void`, `Int32`, …
    pub return_type: String,
    /// Human display used in listings — `Void Namespace.Type.Method(Int32, Boolean)`.
    pub display: String,
    /// Which metadata table this name came from: `"stacktrace"` (the
    /// RVA→token map — framework/generic-heavy) or `"invoke"` (the reflection
    /// InvokeMap — the reflection-registered surface, incl. game methods).
    pub source: &'static str,
}

/// A `(rva, size)` window into the image.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct RvaSize {
    pub rva: u32,
    pub size: u32,
}

/// The parsed stack-trace metadata for one NativeAOT module.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AotArtifact {
    /// RVA of the `ReadyToRunHeader` we located.
    pub header_rva: u32,
    /// `ReadyToRunHeader.MajorVersion`.`MinorVersion`.
    pub version: String,
    /// The `EmbeddedMetadata` blob location.
    pub embedded_metadata: RvaSize,
    /// The `StackTraceMethodRvaToTokenMapping` blob location.
    pub rva_to_token: RvaSize,
    /// Total distinct methods recovered across both sources.
    pub method_count: usize,
    /// How many names came from the stack-trace map.
    pub stacktrace_count: usize,
    /// How many names came from the reflection InvokeMap.
    pub invoke_count: usize,
    /// Recovered symbols (already sorted by RVA).
    pub symbols: Vec<AotSymbol>,
}

/// Read `len` bytes at `rva` through the source, mapped at `image_base`.
fn read_rva(src: &dyn MemorySource, image_base: u64, rva: u32, len: usize) -> Option<Vec<u8>> {
    if len == 0 {
        return Some(Vec::new());
    }
    src.read(Va(image_base + rva as u64), len).ok()
}

/// Peak scan buffer — read data sections a window at a time rather than whole,
/// so a 25–44 MB `.rdata`/`.managed` never lands in memory at once (an OOM risk
/// on a loaded machine). The magic is 4-byte aligned and section RVAs are page
/// aligned, so a window boundary (multiple of 4) never splits it.
const SCAN_WINDOW: usize = 1 << 20;
/// Upper bound on a `ReadyToRunHeader` + its section table (2000 rows × 24 B).
const HEADER_MAX: usize = 16 + 2000 * 24;

/// Scan the given data regions, a bounded window at a time, for a valid
/// `ReadyToRunHeader`. Returns `(header_rva, version, sections)`.
fn find_header(
    src: &dyn MemorySource,
    image_base: u64,
    scan_regions: &[(u32, u32)],
) -> Option<(u32, String, Vec<ModuleInfoRow>)> {
    for &(region_rva, region_len) in scan_regions {
        let region_len = region_len as usize;
        let mut off = 0usize;
        while off < region_len {
            let want = SCAN_WINDOW.min(region_len - off);
            let bytes = match read_rva(src, image_base, region_rva + off as u32, want) {
                Some(b) if !b.is_empty() => b,
                // Unreadable window (e.g. a `hydrated` section with no file
                // bytes statically) — give up on this region.
                _ => break,
            };
            let mut i = 0usize;
            while i + 4 <= bytes.len() {
                if bytes[i..i + 4] == RTR_MAGIC {
                    let header_rva = region_rva + (off + i) as u32;
                    if let Some(hb) = read_rva(src, image_base, header_rva, HEADER_MAX)
                        && let Some((version, sections)) = parse_header(&hb, image_base)
                    {
                        return Some((header_rva, version, sections));
                    }
                }
                i += 4;
            }
            // A short read means the readable tail ended inside this window.
            if bytes.len() < want {
                break;
            }
            off += want;
        }
    }
    None
}

/// One `ModuleInfoRow` from the section table (x64: 24 bytes).
#[derive(Debug, Clone, Copy)]
struct ModuleInfoRow {
    section_id: i32,
    start_rva: u32,
    size: u32,
}

/// Validate + decode a `ReadyToRunHeader` at the start of `buf`.
fn parse_header(buf: &[u8], image_base: u64) -> Option<(String, Vec<ModuleInfoRow>)> {
    if buf.len() < 16 || buf[0..4] != RTR_MAGIC {
        return None;
    }
    let major = u16::from_le_bytes([buf[4], buf[5]]);
    let minor = u16::from_le_bytes([buf[6], buf[7]]);
    let num_sections = u16::from_le_bytes([buf[12], buf[13]]) as usize;
    let entry_size = buf[14];
    // Sanity gate — reject the code-byte false positives.
    if !(1..=20).contains(&major) || num_sections == 0 || num_sections >= 2000 || entry_size != 24 {
        return None;
    }
    let table = &buf[16..];
    if table.len() < num_sections * 24 {
        return None;
    }
    // `ModuleInfoFlags.HasEndPointer` — when clear, `End` is null and the
    // section carries no size (e.g. TypeManagerIndirection). Such a row must not
    // sink the whole header; only the blob sections we want carry end pointers.
    const HAS_END_POINTER: i32 = 0x1;
    // `ReadyToRunSectionType` values live in 200..=212 and 300..=399 — this is
    // the decisive gate against false positives. `.rdata` is full of relocated
    // pointer arrays (all ≥ image_base, so a naive start-check passes), and a
    // stray `52 54 52 00` inside one would otherwise be accepted as a header
    // with garbage section sizes, leading to a multi-gigabyte over-allocation.
    // A real header's every row carries a small enum id; pointer garbage never
    // will for all rows at once.
    const SECTION_ID_MIN: i32 = 100;
    const SECTION_ID_MAX: i32 = 999;
    // A section VA must land within a generous window above the base.
    const IMAGE_SPAN_MAX: u64 = 0x8000_0000; // 2 GiB
    let mut rows = Vec::with_capacity(num_sections);
    let mut has_blob_row = false;
    for k in 0..num_sections {
        let e = &table[k * 24..k * 24 + 24];
        let section_id = i32::from_le_bytes([e[0], e[1], e[2], e[3]]);
        let flags = i32::from_le_bytes([e[4], e[5], e[6], e[7]]);
        let start = u64::from_le_bytes([e[8], e[9], e[10], e[11], e[12], e[13], e[14], e[15]]);
        let end = u64::from_le_bytes([e[16], e[17], e[18], e[19], e[20], e[21], e[22], e[23]]);
        // Every row must look like a real `ModuleInfoRow`, or this isn't a
        // header — reject the whole candidate rather than trust one garbage row.
        if !(SECTION_ID_MIN..=SECTION_ID_MAX).contains(&section_id)
            || flags & !HAS_END_POINTER != 0
            || start < image_base
            || start - image_base >= IMAGE_SPAN_MAX
        {
            return None;
        }
        if (300..=399).contains(&section_id) {
            has_blob_row = true;
        }
        let size = if flags & HAS_END_POINTER != 0 && end >= start && end - image_base < IMAGE_SPAN_MAX {
            (end - start) as u32
        } else {
            0
        };
        rows.push(ModuleInfoRow {
            section_id,
            start_rva: (start - image_base) as u32,
            size,
        });
    }
    // The real header carries at least one blob section (300..=399); a table of
    // all-low ids that somehow passed is still not what we're after.
    if !has_blob_row {
        return None;
    }
    Some((format!("{major}.{minor}"), rows))
}

/// Read the section table from the PE header mapped at `base` and return the
/// `(rva, virtual_size)` windows worth scanning for the `ReadyToRunHeader`.
///
/// Executable sections are skipped (the header lives in read-only data), and
/// `.rdata`-named sections are tried first — a portable heuristic, not a
/// per-target hardcode, since `.rdata` is where ILC emits the header.
fn pe_scan_regions(src: &dyn MemorySource, base: u64) -> Option<Vec<(u32, u32)>> {
    let head = src.read(Va(base), 0x1000).ok()?;
    if head.len() < 0x40 || &head[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(head[0x3c..0x40].try_into().ok()?) as usize;
    if head.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = e_lfanew + 4;
    let num_sections = u16::from_le_bytes(head[coff + 2..coff + 4].try_into().ok()?) as usize;
    let opt_size = u16::from_le_bytes(head[coff + 16..coff + 18].try_into().ok()?) as usize;
    let sec_off = coff + 20 + opt_size;
    let table_end = sec_off + num_sections * 40;
    // Section table may spill past the first page — re-read enough if so.
    let head = if table_end > head.len() {
        src.read(Va(base), table_end).ok()?
    } else {
        head
    };
    let mut regions: Vec<(String, u32, u32, u32)> = Vec::with_capacity(num_sections);
    for k in 0..num_sections {
        let e = head.get(sec_off + k * 40..sec_off + k * 40 + 40)?;
        let name = String::from_utf8_lossy(&e[0..8]).trim_end_matches('\0').to_string();
        let vsize = u32::from_le_bytes(e[8..12].try_into().ok()?);
        let vaddr = u32::from_le_bytes(e[12..16].try_into().ok()?);
        let chars = u32::from_le_bytes(e[36..40].try_into().ok()?);
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
        const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
        if chars & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) != 0 || vsize == 0 {
            continue;
        }
        regions.push((name, vaddr, vsize, chars));
    }
    // `.rdata` first, then the rest in file order.
    regions.sort_by_key(|(name, ..)| if name == ".rdata" { 0 } else { 1 });
    Some(regions.into_iter().map(|(_, rva, vsize, _)| (rva, vsize)).collect())
}

/// Top-level entry: locate + parse the stack-trace metadata for the NativeAOT
/// image mapped at `image_base` in `src`. Works identically for a `--file` PE
/// and a live `--pid` — bytes come through the same [`MemorySource`] seam.
pub fn parse_aot(src: &dyn MemorySource, image_base: Va) -> Result<AotArtifact, CoreError> {
    let base = image_base.0;
    let scan_regions = pe_scan_regions(src, base)
        .ok_or_else(|| CoreError::Other("not a PE image at the given base".into()))?;
    let (header_rva, version, sections) = find_header(src, base, &scan_regions)
        .ok_or_else(|| CoreError::Other("no NativeAOT ReadyToRunHeader found".into()))?;

    let find_blob = |blob_id: i32| -> Option<RvaSize> {
        let id = READONLY_BLOB_REGION_START + blob_id;
        sections
            .iter()
            .find(|s| s.section_id == id)
            .map(|s| RvaSize { rva: s.start_rva, size: s.size })
    };

    let embedded = find_blob(BLOB_EMBEDDED_METADATA).ok_or_else(|| {
        CoreError::Other("NativeAOT image has no EmbeddedMetadata blob".into())
    })?;
    let map = find_blob(BLOB_STACKTRACE_RVA_TO_TOKEN).ok_or_else(|| {
        CoreError::Other(
            "NativeAOT image has no stack-trace RVA→token blob (built without stack-trace metadata?)"
                .into(),
        )
    })?;

    // Defence in depth: even past the strict header check, never read a blob
    // whose size is implausible for a metadata section.
    const MAX_BLOB: u32 = 256 << 20;
    if embedded.size > MAX_BLOB || map.size > MAX_BLOB {
        return Err(CoreError::Other("NativeAOT metadata blob size implausible".into()));
    }

    let meta_bytes = read_rva(src, base, embedded.rva, embedded.size as usize)
        .ok_or_else(|| CoreError::Other("cannot read EmbeddedMetadata blob".into()))?;
    let map_bytes = read_rva(src, base, map.rva, map.size as usize)
        .ok_or_else(|| CoreError::Other("cannot read RVA→token blob".into()))?;

    if meta_bytes.len() < 4 || u32::from_le_bytes([meta_bytes[0], meta_bytes[1], meta_bytes[2], meta_bytes[3]]) != METADATA_SIGNATURE {
        return Err(CoreError::Other("EmbeddedMetadata signature mismatch".into()));
    }

    let meta = Meta { b: &meta_bytes };
    let entries = parse_rva_to_token(&map_bytes, map.rva)?;
    let method_count = entries.len();

    let mut symbols = Vec::with_capacity(entries.len().min(1 << 16));
    for e in &entries {
        let name = meta.string(e.name_off).unwrap_or_default();
        let mut f = Formatter::new(&meta);
        f.emit_type_name(e.owning_type, true);
        let type_name = std::mem::take(&mut f.out);
        let full = if type_name.is_empty() {
            name.clone()
        } else {
            format!("{type_name}.{name}")
        };

        let (ret, params) = meta.method_signature_types(e.signature_off);
        let return_type = ret
            .map(|h| {
                let mut rf = Formatter::new(&meta);
                rf.emit_type_name(h, false);
                rf.out
            })
            .unwrap_or_default();
        let mut parts = Vec::with_capacity(params.len());
        for p in params {
            let mut pf = Formatter::new(&meta);
            // Namespace-qualify parameters: strictly more informative for RE
            // and matches how the runtime's own stack printer spells them.
            pf.emit_type_name(p, true);
            parts.push(pf.out);
        }
        let signature = format!("({})", parts.join(", "));
        let display = if return_type.is_empty() {
            format!("{full}{signature}")
        } else {
            format!("{return_type} {full}{signature}")
        };

        symbols.push(AotSymbol {
            rva: e.rva,
            va: Va(base + e.rva as u64),
            name: full,
            signature,
            return_type,
            display,
            source: "stacktrace",
        });
    }
    let stacktrace_count = symbols.len();

    // The stack-trace map is framework/generic-heavy; the reflection InvokeMap
    // holds the reflection-registered surface (where a game's own methods live).
    // Parse it too when present and merge — it is the second, complementary
    // RVA→name source, and the one that resolves gameplay methods.
    let invoke = find_blob(BLOB_INVOKE_MAP).zip(find_blob(BLOB_COMMON_FIXUPS));
    let invoke_count = if let Some((imap, fixups)) = invoke {
        match parse_invoke_map(src, base, &meta, imap, fixups) {
            Ok(mut inv) => {
                let n = inv.len();
                symbols.append(&mut inv);
                n
            }
            Err(_) => 0,
        }
    } else {
        0
    };

    symbols.sort_by(|a, b| a.rva.cmp(&b.rva).then(a.source.cmp(b.source)));
    symbols.dedup_by_key(|s| s.rva);

    Ok(AotArtifact {
        header_rva,
        version,
        embedded_metadata: embedded,
        rva_to_token: map,
        method_count: method_count.max(symbols.len()),
        stacktrace_count,
        invoke_count,
        symbols,
    })
}

/// One decoded RVA→token entry.
struct MapEntry {
    rva: u32,
    owning_type: Handle,
    name_off: u32,
    signature_off: u32,
}

/// Parse the linear `StackTraceMethodRvaToTokenMapping` blob. `blob_rva` is the
/// blob's own RVA, needed to resolve the position-relative method pointers.
fn parse_rva_to_token(buf: &[u8], blob_rva: u32) -> Result<Vec<MapEntry>, CoreError> {
    if buf.len() < 4 {
        return Err(CoreError::Other("RVA→token blob too small".into()));
    }
    let declared = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]).max(0) as usize;
    // An entry is at minimum a command byte plus a 4-byte relative pointer, so
    // the blob can hold at most `len / 5` of them. Never allocate on the
    // untrusted header count — a wrong header would otherwise request gigabytes.
    let count = declared.min(buf.len() / 5);
    let mut cur = Cursor { b: buf, p: 4 };

    let mut owning_type = Handle::null();
    let mut name_off = 0u32;
    let mut signature_off = 0u32;

    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let command = cur.u8().ok_or_else(|| CoreError::Other("truncated RVA→token blob".into()))?;

        if command & CMD_UPDATE_OWNING_TYPE != 0 {
            let token = cur.u32_le().ok_or_else(trunc)?;
            owning_type = Handle::from_token(token);
        }
        if command & CMD_UPDATE_NAME != 0 {
            name_off = cur.unsigned().ok_or_else(trunc)?;
        }
        if command & (CMD_UPDATE_SIGNATURE | CMD_UPDATE_GENERIC_SIGNATURE) != 0 {
            signature_off = cur.unsigned().ok_or_else(trunc)?;
            if command & CMD_UPDATE_GENERIC_SIGNATURE != 0 {
                // methodInst offset — read to stay aligned; unused for naming.
                let _ = cur.unsigned().ok_or_else(trunc)?;
            }
        }

        // Position-relative 32-bit pointer to the method entrypoint.
        let rel_pos = cur.p;
        let rel = cur.i32_le().ok_or_else(trunc)?;
        let rva = (blob_rva as i64 + rel_pos as i64 + rel as i64) as u32;

        out.push(MapEntry { rva, owning_type, name_off, signature_off });
    }
    Ok(out)
}

fn trunc() -> CoreError {
    CoreError::Other("truncated RVA→token blob".into())
}

fn u16le(b: &[u8], p: usize) -> usize {
    b.get(p..p + 2).map(|s| u16::from_le_bytes([s[0], s[1]]) as usize).unwrap_or(0)
}
fn u32le(b: &[u8], p: usize) -> usize {
    b.get(p..p + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize).unwrap_or(0)
}

/// Resolve a `CommonFixupsTable` index to an RVA. Each slot is a position-
/// relative `i32` (`ExternalReferencesTable.GetAddressFromIndex`).
fn fixup_rva(fixups: &[u8], fixups_rva: u32, idx: u32) -> Option<u32> {
    let pos = (idx as usize).checked_mul(4)?;
    let s = fixups.get(pos..pos + 4)?;
    let rel = i32::from_le_bytes([s[0], s[1], s[2], s[3]]);
    Some((fixups_rva as i64 + pos as i64 + rel as i64) as u32)
}

/// Enumerate every entry-data offset in a `NativeHashtable` blob
/// (`NativeHashtable.AllEntriesEnumerator`). Each entry is `[low-hash u8]
/// [relative-offset signed-varint]`; the data sits at that relative offset.
fn native_hashtable_entries(b: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let Some(&header) = b.first() else { return out };
    let shift = (header >> 2) as u32;
    if shift > 28 {
        return out; // implausible bucket count — not a real hashtable
    }
    let bucket_mask = (1u32 << shift) - 1;
    let entry_index_size = header & 3;
    let base = 1usize;
    for bkt in 0..=bucket_mask {
        let (start, end) = match entry_index_size {
            0 => {
                let bo = base + bkt as usize;
                (*b.get(bo).unwrap_or(&0) as usize, *b.get(bo + 1).unwrap_or(&0) as usize)
            }
            1 => {
                let bo = base + 2 * bkt as usize;
                (u16le(b, bo), u16le(b, bo + 2))
            }
            _ => {
                let bo = base + 4 * bkt as usize;
                (u32le(b, bo), u32le(b, bo + 4))
            }
        };
        let mut p = base + start;
        let endp = base + end;
        while p < endp && p < b.len() {
            p += 1; // low hashcode byte
            let pos = p;
            let Some((delta, n)) = decode_signed(b, p) else { break };
            p += n;
            let entry = pos as i64 + delta as i64;
            if entry >= 0 && (entry as usize) < b.len() {
                out.push(entry as usize);
            }
        }
        if out.len() > 5_000_000 {
            break; // runaway guard on malformed input
        }
    }
    out
}

/// Walk the metadata type tree, mapping every `Method` handle offset to its
/// declaring type's fully-qualified name (reusing the formatter for the type
/// name). This is what lets an InvokeMap entry — which only carries a method
/// handle + an entrypoint index — render `Namespace.Type.Method`.
fn build_method_type_index(meta: &Meta) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
    // The metadata header's ScopeDefinitions collection sits at offset 4.
    let Some((scopes, _)) = meta.typed_collection(4) else { return map };
    for scope_off in scopes {
        if let Some(root) = meta.scope_root_ns(scope_off) {
            walk_namespace(meta, root, &mut map, &mut seen, 0);
        }
    }
    map
}

fn walk_namespace(
    meta: &Meta,
    ns_off: u32,
    map: &mut HashMap<u32, String>,
    seen: &mut std::collections::HashSet<u32>,
    depth: u32,
) {
    if ns_off == 0 || depth > 300 {
        return;
    }
    let Some((types, children)) = meta.namespace_def_children(ns_off) else { return };
    for t in types {
        walk_type(meta, t, map, seen, 0);
    }
    for c in children {
        walk_namespace(meta, c, map, seen, depth + 1);
    }
}

fn walk_type(
    meta: &Meta,
    type_off: u32,
    map: &mut HashMap<u32, String>,
    seen: &mut std::collections::HashSet<u32>,
    depth: u32,
) {
    if type_off == 0 || depth > 64 || !seen.insert(type_off) {
        return;
    }
    let Some((_ns, _name, _enc, nested, methods)) = meta.type_def_ext(type_off) else { return };
    let mut f = Formatter::new(meta);
    f.emit_type_name(Handle::typed(ht::TYPE_DEFINITION, type_off), true);
    let fqn = f.out;
    for m in methods {
        map.entry(m).or_insert_with(|| fqn.clone());
    }
    for n in nested {
        walk_type(meta, n, map, seen, depth + 1);
    }
}

/// Parse the reflection `InvokeMap` and resolve `RVA ↔ name` for every entry
/// that carries a metadata method handle and an entrypoint.
fn parse_invoke_map(
    src: &dyn MemorySource,
    base: u64,
    meta: &Meta,
    imap: RvaSize,
    fixups: RvaSize,
) -> Result<Vec<AotSymbol>, CoreError> {
    const MAX_BLOB: u32 = 256 << 20;
    if imap.size > MAX_BLOB || fixups.size > MAX_BLOB {
        return Err(CoreError::Other("InvokeMap/CommonFixups blob size implausible".into()));
    }
    let invoke = read_rva(src, base, imap.rva, imap.size as usize)
        .ok_or_else(|| CoreError::Other("cannot read InvokeMap blob".into()))?;
    let fixups_bytes = read_rva(src, base, fixups.rva, fixups.size as usize)
        .ok_or_else(|| CoreError::Other("cannot read CommonFixups blob".into()))?;

    let type_index = build_method_type_index(meta);
    let mut out = Vec::new();

    for entry_off in native_hashtable_entries(&invoke) {
        let mut o = entry_off;
        let Some((flags, n)) = decode_unsigned(&invoke, o) else { continue };
        o += n;
        if flags & INVOKE_HAS_ENTRYPOINT == 0 {
            continue;
        }
        // Method handle (metadata) or a NameAndSig vertex — only the former is
        // resolvable to a metadata name.
        let method_off = if flags & INVOKE_HAS_METADATA_HANDLE != 0 {
            let Some((v, n)) = decode_unsigned(&invoke, o) else { continue };
            o += n;
            Some(v & 0x00FF_FFFF)
        } else {
            let Some((_v, n)) = decode_unsigned(&invoke, o) else { continue };
            o += n;
            None
        };
        // owningType index (unused — we take the name from the tree).
        let Some((_owning, n)) = decode_unsigned(&invoke, o) else { continue };
        o += n;
        // entrypoint index into CommonFixups.
        let Some((eidx, _n)) = decode_unsigned(&invoke, o) else { continue };

        let Some(method_off) = method_off else { continue };
        let Some(type_name) = type_index.get(&method_off) else { continue };
        let Some(rva) = fixup_rva(&fixups_bytes, fixups.rva, eidx) else { continue };
        let Some((name_off, sig_off)) = meta.method_name_and_sig(method_off) else { continue };
        let mname = meta.string(name_off).unwrap_or_default();
        if mname.is_empty() {
            continue;
        }
        let full = if type_name.is_empty() { mname } else { format!("{type_name}.{mname}") };

        let (ret, params) = meta.method_signature_types(sig_off);
        let return_type = ret
            .map(|h| {
                let mut rf = Formatter::new(meta);
                rf.emit_type_name(h, false);
                rf.out
            })
            .unwrap_or_default();
        let mut parts = Vec::with_capacity(params.len());
        for p in params {
            let mut pf = Formatter::new(meta);
            pf.emit_type_name(p, true);
            parts.push(pf.out);
        }
        let signature = format!("({})", parts.join(", "));
        let display = if return_type.is_empty() {
            format!("{full}{signature}")
        } else {
            format!("{return_type} {full}{signature}")
        };

        out.push(AotSymbol {
            rva,
            va: Va(base + rva as u64),
            name: full,
            signature,
            return_type,
            display,
            source: "invoke",
        });
    }
    Ok(out)
}

/// A byte cursor over a blob using NativeFormat integer encodings.
struct Cursor<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.p)?;
        self.p += 1;
        Some(v)
    }
    fn u32_le(&mut self) -> Option<u32> {
        let s = self.b.get(self.p..self.p + 4)?;
        self.p += 4;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn i32_le(&mut self) -> Option<i32> {
        self.u32_le().map(|v| v as i32)
    }
    fn unsigned(&mut self) -> Option<u32> {
        let (v, n) = decode_unsigned(self.b, self.p)?;
        self.p += n;
        Some(v)
    }
}

/// `NativePrimitiveDecoder.DecodeUnsigned` — low-bit run-length varint.
/// Returns `(value, bytes_consumed)`.
fn decode_unsigned(b: &[u8], p: usize) -> Option<(u32, usize)> {
    let v0 = *b.get(p)? as u32;
    if v0 & 1 == 0 {
        Some((v0 >> 1, 1))
    } else if v0 & 2 == 0 {
        let b1 = *b.get(p + 1)? as u32;
        Some(((v0 >> 2) | (b1 << 6), 2))
    } else if v0 & 4 == 0 {
        let b1 = *b.get(p + 1)? as u32;
        let b2 = *b.get(p + 2)? as u32;
        Some(((v0 >> 3) | (b1 << 5) | (b2 << 13), 3))
    } else if v0 & 8 == 0 {
        let b1 = *b.get(p + 1)? as u32;
        let b2 = *b.get(p + 2)? as u32;
        let b3 = *b.get(p + 3)? as u32;
        Some(((v0 >> 4) | (b1 << 4) | (b2 << 12) | (b3 << 20), 4))
    } else if v0 & 16 == 0 {
        let s = b.get(p + 1..p + 5)?;
        Some((u32::from_le_bytes([s[0], s[1], s[2], s[3]]), 5))
    } else {
        None
    }
}

/// `NativePrimitiveDecoder.DecodeSigned` — same widths, sign-extended.
fn decode_signed(b: &[u8], p: usize) -> Option<(i32, usize)> {
    let v0 = *b.get(p)? as i32;
    if v0 & 1 == 0 {
        Some(((v0 as i8 as i32) >> 1, 1))
    } else if v0 & 2 == 0 {
        let b1 = *b.get(p + 1)? as i8 as i32;
        Some(((v0 >> 2) | (b1 << 6), 2))
    } else if v0 & 4 == 0 {
        let b1 = *b.get(p + 1)? as u32 as i32;
        let b2 = *b.get(p + 2)? as i8 as i32;
        Some(((v0 >> 3) | (b1 << 5) | (b2 << 13), 3))
    } else if v0 & 8 == 0 {
        let b1 = *b.get(p + 1)? as u32 as i32;
        let b2 = *b.get(p + 2)? as u32 as i32;
        let b3 = *b.get(p + 3)? as i8 as i32;
        Some(((v0 >> 4) | (b1 << 4) | (b2 << 12) | (b3 << 20), 4))
    } else if v0 & 16 == 0 {
        let s = b.get(p + 1..p + 5)?;
        Some((i32::from_le_bytes([s[0], s[1], s[2], s[3]]), 5))
    } else {
        None
    }
}

/// A NativeFormat handle: an 8-bit type tag and a 24-bit blob offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Handle {
    ty: u8,
    off: u32,
}

impl Handle {
    fn null() -> Self {
        Handle { ty: ht::NULL, off: 0 }
    }
    /// From a raw in-memory token (`type << 24 | offset`), as stored by the
    /// RVA→token blob (`Handle.FromIntToken`).
    fn from_token(token: u32) -> Self {
        Handle { ty: (token >> 24) as u8, off: token & 0x00FF_FFFF }
    }
    /// From a stream-encoded handle varint (`offset << 8 | type`).
    fn from_stream(raw: u32) -> Self {
        Handle { ty: (raw & 0xFF) as u8, off: raw >> 8 }
    }
    fn is_null(&self) -> bool {
        self.ty == ht::NULL
    }
    /// A handle with a known type and explicit offset (for typed-handle fields).
    fn typed(ty: u8, off: u32) -> Self {
        Handle { ty, off }
    }
}

/// A decoded `TypeDefinition`: `(nsOff, nameOff, encOff, nestedTypeOffs,
/// methodOffs)` — the shape [`Meta::type_def_ext`] returns.
type TypeDefExt = (u32, u32, u32, Vec<u32>, Vec<u32>);

/// A reader over the `EmbeddedMetadata` blob. Handle offsets are absolute byte
/// offsets into `b` (which begins with the metadata signature).
struct Meta<'a> {
    b: &'a [u8],
}

impl<'a> Meta<'a> {
    /// Read a **generic** `Handle` member at `off` — the wire form carries the
    /// type in the low byte and the offset in the high bits.
    fn handle(&self, off: u32) -> Option<(Handle, u32)> {
        let (raw, n) = decode_unsigned(self.b, off as usize)?;
        Some((Handle::from_stream(raw), off + n as u32))
    }

    /// Read a **typed** handle member at `off` (e.g. `ConstantStringValueHandle`,
    /// `NamespaceDefinitionHandle`): the type is implied by the field, so the
    /// wire value is the record offset in its low 24 bits (`value & 0xFFFFFF`).
    /// A zero offset is the null handle. Returns `(offset, next)`.
    fn typed_off(&self, off: u32) -> Option<(u32, u32)> {
        let (raw, n) = decode_unsigned(self.b, off as usize)?;
        Some((raw & 0x00FF_FFFF, off + n as u32))
    }

    /// Read an unsigned member at `off` → `(value, next)`.
    fn unsigned(&self, off: u32) -> Option<(u32, u32)> {
        let (v, n) = decode_unsigned(self.b, off as usize)?;
        Some((v, off + n as u32))
    }

    /// Read a signed member at `off` → `(value, next)`.
    fn signed(&self, off: u32) -> Option<(i32, u32)> {
        let (v, n) = decode_signed(self.b, off as usize)?;
        Some((v, off + n as u32))
    }

    /// Read a handle collection member at `off` → `(handles, next)`.
    fn handle_collection(&self, off: u32) -> Option<(Vec<Handle>, u32)> {
        let (count, consumed) = decode_unsigned(self.b, off as usize)?;
        let mut p = off as usize + consumed;
        // A handle is at least one varint byte, so a collection can never hold
        // more elements than the blob has bytes. Never pre-allocate on the raw
        // count — a mis-resolved offset yields a garbage count and, unchecked,
        // a multi-gigabyte reservation that OOM-kills the process.
        let count = (count as usize).min(self.b.len());
        let mut out = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            let (raw, n) = decode_unsigned(self.b, p)?;
            out.push(Handle::from_stream(raw));
            p += n;
        }
        Some((out, p as u32))
    }

    /// Read a **typed** handle collection at `off` → `(offsets, next)`.
    fn typed_collection(&self, off: u32) -> Option<(Vec<u32>, u32)> {
        let (count, consumed) = decode_unsigned(self.b, off as usize)?;
        let mut p = off as usize + consumed;
        let count = (count as usize).min(self.b.len());
        let mut out = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            let (raw, n) = decode_unsigned(self.b, p)?;
            out.push(raw & 0x00FF_FFFF);
            p += n;
        }
        Some((out, p as u32))
    }

    /// Skip a `ByteCollection` member (count varint + `count` raw bytes).
    fn skip_byte_collection(&self, off: u32) -> Option<u32> {
        let (count, consumed) = decode_unsigned(self.b, off as usize)?;
        Some(off + consumed as u32 + count)
    }

    /// `Method` → `(nameOffset, signatureOffset)`. Name and signature are typed
    /// handles; the collections that follow are not needed here.
    fn method_name_and_sig(&self, off: u32) -> Option<(u32, u32)> {
        let (_flags, o) = self.unsigned(off)?;
        let (_impl, o) = self.unsigned(o)?;
        let (name_off, o) = self.typed_off(o)?;
        let (sig_off, _o) = self.typed_off(o)?;
        Some((name_off, sig_off))
    }

    /// `TypeDefinition` → `(nsOff, nameOff, encOff, nestedTypeOffs, methodOffs)`.
    fn type_def_ext(&self, off: u32) -> Option<TypeDefExt> {
        let (_flags, o) = self.unsigned(off)?;
        let (_base, o) = self.handle(o)?;
        let (ns_off, o) = self.typed_off(o)?;
        let (name_off, o) = self.typed_off(o)?;
        let (_size, o) = self.unsigned(o)?;
        let (_pack, o) = self.unsigned(o)?;
        let (enc_off, o) = self.typed_off(o)?;
        let (nested, o) = self.typed_collection(o)?;
        let (methods, _o) = self.typed_collection(o)?;
        Some((ns_off, name_off, enc_off, nested, methods))
    }

    /// `NamespaceDefinition` → `(typeDefinitionOffs, childNamespaceOffs)`.
    fn namespace_def_children(&self, off: u32) -> Option<(Vec<u32>, Vec<u32>)> {
        let (_parent, o) = self.handle(off)?;
        let (_name, o) = self.typed_off(o)?;
        let (types, o) = self.typed_collection(o)?;
        let (_forwarders, o) = self.typed_collection(o)?;
        let (child_ns, _o) = self.typed_collection(o)?;
        Some((types, child_ns))
    }

    /// `ScopeDefinition.RootNamespaceDefinition` offset.
    fn scope_root_ns(&self, off: u32) -> Option<u32> {
        let (_flags, o) = self.unsigned(off)?;
        let (_name, o) = self.typed_off(o)?;
        let (_halg, o) = self.unsigned(o)?;
        let (_maj, o) = self.unsigned(o)?;
        let (_min, o) = self.unsigned(o)?;
        let (_bld, o) = self.unsigned(o)?;
        let (_rev, o) = self.unsigned(o)?;
        let o = self.skip_byte_collection(o)?; // publicKey
        let (_culture, o) = self.typed_off(o)?;
        let (root_ns, _o) = self.typed_off(o)?;
        Some(root_ns)
    }

    /// `ConstantStringValue.Value` at handle offset `off`. Offset 0 is the null
    /// handle (e.g. the root namespace's empty name) — never a real record, and
    /// reading it would decode the metadata signature as a giant length.
    fn string(&self, off: u32) -> Option<String> {
        if off == 0 {
            return Some(String::new());
        }
        let (len, consumed) = decode_unsigned(self.b, off as usize)?;
        let start = off as usize + consumed;
        let bytes = self.b.get(start..start + len as usize)?;
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    /// `MethodSignature` → `(returnType, parameterTypes)`.
    fn method_signature_types(&self, off: u32) -> (Option<Handle>, Vec<Handle>) {
        (|| {
            let (_cc, o) = self.unsigned(off)?; // callingConvention
            let (_gpc, o) = self.signed(o)?; // genericParameterCount
            let (ret, o) = self.handle(o)?; // returnType
            let (params, _o) = self.handle_collection(o)?; // parameters
            Some((Some(ret), params))
        })()
        .unwrap_or((None, Vec::new()))
    }

    // Record accessors return only the members the formatter needs.

    /// `TypeReference` → `(parentNamespaceOrType [generic], typeName offset)`.
    fn type_reference(&self, off: u32) -> Option<(Handle, u32)> {
        let (parent, o) = self.handle(off)?;
        let (name_off, _o) = self.typed_off(o)?;
        Some((parent, name_off))
    }

    /// `TypeDefinition` → `(namespaceDefinition off, name off, enclosingType off)`.
    /// `baseType` is a generic handle; `namespaceDefinition`/`name`/`enclosingType`
    /// are typed handles (offset only).
    fn type_definition(&self, off: u32) -> Option<(u32, u32, u32)> {
        let (_flags, o) = self.unsigned(off)?;
        let (_base, o) = self.handle(o)?;
        let (ns_off, o) = self.typed_off(o)?;
        let (name_off, o) = self.typed_off(o)?;
        let (_size, o) = self.unsigned(o)?;
        let (_pack, o) = self.unsigned(o)?;
        let (enc_off, _o) = self.typed_off(o)?;
        Some((ns_off, name_off, enc_off))
    }

    /// `NamespaceReference` → `(parentScopeOrNamespace [generic], name offset)`.
    fn namespace_reference(&self, off: u32) -> Option<(Handle, u32)> {
        let (parent, o) = self.handle(off)?;
        let (name_off, _o) = self.typed_off(o)?;
        Some((parent, name_off))
    }

    /// `NamespaceDefinition` → `(parentScopeOrNamespace [generic], name offset)`.
    fn namespace_definition(&self, off: u32) -> Option<(Handle, u32)> {
        let (parent, o) = self.handle(off)?;
        let (name_off, _o) = self.typed_off(o)?;
        Some((parent, name_off))
    }

    /// `TypeSpecification.Signature`.
    fn type_specification(&self, off: u32) -> Option<Handle> {
        Some(self.handle(off)?.0)
    }

    /// `TypeInstantiationSignature.GenericType`.
    fn type_instantiation(&self, off: u32) -> Option<Handle> {
        Some(self.handle(off)?.0)
    }

    /// A one-`type` record (`SZArray`/`Pointer`/`ByReference`) → its element.
    fn single_type(&self, off: u32) -> Option<Handle> {
        Some(self.handle(off)?.0)
    }

    /// `ArraySignature` → `(elementType, rank)`.
    fn array_signature(&self, off: u32) -> Option<(Handle, i32)> {
        let (elem, o) = self.handle(off)?;
        let (rank, _o) = self.signed(o)?;
        Some((elem, rank))
    }

    /// `TypeVariableSignature`/`MethodTypeVariableSignature` → `Number`.
    fn variable_number(&self, off: u32) -> Option<u32> {
        Some(self.unsigned(off)?.0)
    }

    /// `GenericParameter.Name` — flags, then a handle we skip, then name; but
    /// the formatter only needs the name and generic parameters are rare in our
    /// path, so decode conservatively and fall back to empty.
    fn generic_parameter_name(&self, off: u32) -> Option<String> {
        // GenericParameter: { kind:enum, number:ushort, flags:enum, name:handle, ... }
        let (_kind, o) = self.unsigned(off)?;
        let (_number, o) = self.unsigned(o)?;
        let (_flags, o) = self.unsigned(o)?;
        let (name, _o) = self.handle(o)?;
        self.string(name.off)
    }
}

/// Ports `MethodNameFormatter` — assembles a type/method name into `out`.
struct Formatter<'a> {
    meta: &'a Meta<'a>,
    out: String,
    depth: u32,
}

impl<'a> Formatter<'a> {
    fn new(meta: &'a Meta<'a>) -> Self {
        Formatter { meta, out: String::new(), depth: 0 }
    }

    fn emit_string(&mut self, off: u32) {
        if let Some(s) = self.meta.string(off) {
            self.out.push_str(&s);
        }
    }

    fn emit_type_name(&mut self, h: Handle, namespace_qualified: bool) {
        // Guard against a cyclic / malformed blob.
        if self.depth > 64 {
            self.out.push_str("...");
            return;
        }
        self.depth += 1;
        self.emit_type_name_inner(h, namespace_qualified);
        self.depth -= 1;
    }

    fn emit_type_name_inner(&mut self, h: Handle, namespace_qualified: bool) {
        match h.ty {
            ht::TYPE_REFERENCE => self.emit_type_reference(h.off, namespace_qualified),
            ht::TYPE_DEFINITION => self.emit_type_definition(h.off, namespace_qualified),
            ht::TYPE_SPECIFICATION => {
                if let Some(sig) = self.meta.type_specification(h.off) {
                    self.emit_type_name(sig, namespace_qualified);
                }
            }
            ht::TYPE_INSTANTIATION_SIGNATURE => {
                if let Some(g) = self.meta.type_instantiation(h.off) {
                    self.emit_type_name(g, namespace_qualified);
                }
            }
            ht::SZARRAY_SIGNATURE => {
                if let Some(e) = self.meta.single_type(h.off) {
                    self.emit_type_name(e, namespace_qualified);
                }
                self.out.push_str("[]");
            }
            ht::ARRAY_SIGNATURE => {
                if let Some((e, rank)) = self.meta.array_signature(h.off) {
                    self.emit_type_name(e, namespace_qualified);
                    self.out.push('[');
                    if rank > 1 {
                        for _ in 0..rank - 1 {
                            self.out.push(',');
                        }
                    } else {
                        self.out.push('*');
                    }
                    self.out.push(']');
                }
            }
            ht::POINTER_SIGNATURE => {
                if let Some(t) = self.meta.single_type(h.off) {
                    self.emit_type_name(t, false);
                }
                self.out.push('*');
            }
            ht::BY_REFERENCE_SIGNATURE => {
                if let Some(t) = self.meta.single_type(h.off) {
                    self.emit_type_name(t, false);
                }
                self.out.push('&');
            }
            ht::FUNCTION_POINTER_SIGNATURE => self.out.push_str("IntPtr"),
            ht::CONSTANT_STRING_VALUE => self.emit_string(h.off),
            ht::GENERIC_PARAMETER => {
                if let Some(name) = self.meta.generic_parameter_name(h.off) {
                    self.out.push_str(&name);
                }
            }
            // Generic type/method variables need the instantiation context,
            // which stack-trace metadata only carries as string args; render an
            // IL-style placeholder rather than resolving (never hit by the
            // non-generic methods that dominate a stack-trace map).
            ht::TYPE_VARIABLE_SIGNATURE => {
                let n = self.meta.variable_number(h.off).unwrap_or(0);
                self.out.push_str(&format!("!{n}"));
            }
            ht::METHOD_TYPE_VARIABLE_SIGNATURE => {
                let n = self.meta.variable_number(h.off).unwrap_or(0);
                self.out.push_str(&format!("!!{n}"));
            }
            ht::NULL => {}
            _ => self.out.push_str("???"),
        }
    }

    fn emit_type_reference(&mut self, off: u32, namespace_qualified: bool) {
        let Some((parent, name_off)) = self.meta.type_reference(off) else {
            return;
        };
        if !parent.is_null() {
            if parent.ty != ht::NAMESPACE_REFERENCE {
                // Nested type: qualify by the enclosing type.
                self.emit_type_name(parent, namespace_qualified);
                self.out.push('.');
            } else if namespace_qualified {
                let before = self.out.len();
                self.emit_namespace_reference(parent.off);
                if self.out.len() > before {
                    self.out.push('.');
                }
            }
        }
        self.emit_string(name_off);
    }

    fn emit_type_definition(&mut self, off: u32, namespace_qualified: bool) {
        let Some((ns_off, name_off, enc_off)) = self.meta.type_definition(off) else {
            return;
        };
        if enc_off != 0 {
            // Nested type: qualify by the enclosing type.
            self.emit_type_name(Handle::typed(ht::TYPE_DEFINITION, enc_off), namespace_qualified);
            self.out.push('.');
        } else if namespace_qualified && ns_off != 0 {
            let before = self.out.len();
            self.emit_namespace_definition(ns_off);
            if self.out.len() > before {
                self.out.push('.');
            }
        }
        self.emit_string(name_off);
    }

    fn emit_namespace_reference(&mut self, off: u32) {
        if self.depth > 64 || off == 0 {
            return;
        }
        self.depth += 1;
        if let Some((parent, name_off)) = self.meta.namespace_reference(off) {
            if !parent.is_null() && parent.ty == ht::NAMESPACE_REFERENCE {
                let before = self.out.len();
                self.emit_namespace_reference(parent.off);
                if self.out.len() > before {
                    self.out.push('.');
                }
            }
            self.emit_string(name_off);
        }
        self.depth -= 1;
    }

    fn emit_namespace_definition(&mut self, off: u32) {
        if self.depth > 64 || off == 0 {
            return;
        }
        self.depth += 1;
        if let Some((parent, name_off)) = self.meta.namespace_definition(off) {
            if !parent.is_null() && parent.ty == ht::NAMESPACE_DEFINITION {
                let before = self.out.len();
                self.emit_namespace_definition(parent.off);
                if self.out.len() > before {
                    self.out.push('.');
                }
            }
            self.emit_string(name_off);
        }
        self.depth -= 1;
    }
}

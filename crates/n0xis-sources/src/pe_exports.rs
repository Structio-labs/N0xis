// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The PE export table, read in one place for every consumer.
//!
//! Three readers of this table had grown up separately — the file loader's
//! named exports (a third-party parser's list), its own ordinal-only walk, and
//! `profile`'s walk over a mapped module — and only one of them knew that an
//! entry pointing *inside* the export directory is a **forwarder**: a
//! `MODULE.Function` string, not code. The loader put those string addresses in
//! its symbol map, so the decompiler named a `.rdata` string after the function
//! it forwards to and `sig gen` fingerprinted the text as if it were code —
//! measured on a 0.9 MB x64 system DLL, 126 of 1 554 signatures were forwarder
//! strings. One fact answered in two places had answered two ways.
//!
//! So the table is walked here, through the [`MemorySource`] seam — which a
//! file-backed image and a live module both implement — and every entry comes
//! out already classified as an [`ExportTarget`]. A forwarder carries no
//! address that could be mistaken for code: there is no `bool` to forget to
//! check, only a variant that has to be matched.
//!
//! Every count in the table comes out of an untrusted file, so each is capped
//! by what the format can express before it sizes a read.

use n0xis_contracts::Va;

use crate::MemorySource;

/// Data directory 0 as the optional header states it: where the export
/// directory sits and how long it is.
///
/// The size is not bookkeeping. It is what tells a forwarder from code, by the
/// format's own definition and the OS loader's test: an address-table entry
/// whose RVA lies inside `[rva, rva + size)` points at a forwarder string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportDirectory {
    pub rva: u32,
    pub size: u32,
}

impl ExportDirectory {
    /// Read data directory 0 out of the image's headers (`header` starts at the
    /// `MZ`). The directory array sits at +96 in a PE32 optional header and
    /// +112 in a PE32+ one; the magic says which. `None` when the headers are
    /// not there or the directory's RVA is 0 — the image exports nothing.
    ///
    /// A size of 0 with a real RVA is still a table, as the OS loader reads it
    /// (and as the third-party parser did): it only means that no entry can
    /// be a forwarder, since nothing lies inside an empty range.
    pub fn from_header(header: &[u8]) -> Option<Self> {
        let e_lfanew = u32_at_checked(header, 0x3c)? as usize;
        if header.get(e_lfanew..e_lfanew + 4) != Some(&b"PE\0\0"[..]) {
            return None;
        }
        let magic = header.get(e_lfanew + 24..e_lfanew + 26).map(|b| u16::from_le_bytes([b[0], b[1]]))?;
        let dd = e_lfanew + 24 + if magic == 0x10b { 96 } else { 112 };
        let dir = ExportDirectory { rva: u32_at_checked(header, dd)?, size: u32_at_checked(header, dd + 4)? };
        (dir.rva != 0).then_some(dir)
    }

    /// Whether an address-table RVA points inside this directory — i.e. at a
    /// forwarder string. Computed in 64 bits so a hostile `rva + size` cannot
    /// wrap and make the range cover code, or nothing.
    pub fn holds(&self, rva: u32) -> bool {
        (self.rva as u64..self.rva as u64 + self.size as u64).contains(&(rva as u64))
    }

    /// One past the directory's last byte, widened like [`Self::holds`].
    fn end(&self) -> u64 {
        self.rva as u64 + self.size as u64
    }
}

/// Where an export's address-table entry leads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportTarget {
    /// An address in this image — a function, or an exported variable. Which
    /// of the two is a question about the section it lands in, and is left to
    /// the caller that knows the sections.
    Local(Va),
    /// A **forwarder**: the OS loader resolves this export in another module,
    /// and this image holds no code for it. `string` is where the forwarder
    /// string sits (inside the export directory), kept because it is what the
    /// table states; `to` is that string, `MODULE.Function` or `MODULE.#n`.
    Forwarded { string: Va, to: String },
}

/// One entry of the export table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeExport {
    /// The exported name, or `None` for an export by ordinal only.
    pub name: Option<String>,
    /// The biased ordinal: the directory's `Base` plus the address-table index.
    pub ordinal: u32,
    pub target: ExportTarget,
}

/// The most address-table entries (and names) read. An ordinal is 16 bits
/// wide — in the name-ordinal table and in an import by ordinal alike — so no
/// slot past this one can be reached, and a count above it is a malformed or
/// hostile table, not a large one.
pub const MAX_EXPORT_SLOTS: usize = 1 << 16;

/// Longest export name read. Long enough for a decorated C++ name (the
/// producing toolchains cap those at 4 KiB); a name with no NUL inside it is
/// kept as far as it was read rather than refused.
const MAX_NAME: usize = 4096;

/// First read for a name: most are short, so the full bound is only paid by
/// the rare name that needs it.
const NAME_PROBE: usize = 256;

/// Longest forwarder string read: a module name plus a name's worth.
const MAX_FORWARDER: usize = MAX_NAME + 256;

/// Read the export table of the PE image mapped at `base`, whose data
/// directory 0 is `dir`.
///
/// Every **named** export comes first, in name-table order (the table is
/// sorted by name, and two names may share one slot). Then every slot no
/// readable name refers to, in ordinal order, with `name: None`. Empty
/// (`0`) slots are skipped: they are unused ordinals, not exports at RVA 0.
///
/// A forwarder whose string cannot be read at all is left out rather than
/// listed without one — every consumer would otherwise have to decide what an
/// unnamed redirect means, and the image holds no code for it either way.
///
/// Absent pieces (a zero directory, an unreadable table) yield fewer entries,
/// never an error and never a guess.
pub fn read_export_table(source: &dyn MemorySource, base: Va, dir: ExportDirectory) -> Vec<PeExport> {
    if dir.rva == 0 {
        return Vec::new();
    }
    let Some(hdr) = read_at(source, base, dir.rva, 40) else { return Vec::new() };
    if hdr.len() < 40 {
        return Vec::new();
    }
    let ordinal_base = u32_at(&hdr, 16);
    let n_slots = (u32_at(&hdr, 20) as usize).min(MAX_EXPORT_SLOTS);
    let n_names = (u32_at(&hdr, 24) as usize).min(MAX_EXPORT_SLOTS);
    let (addr_table, name_table, ordinal_table) = (u32_at(&hdr, 28), u32_at(&hdr, 32), u32_at(&hdr, 36));

    // The address table, one read. A short read (the table runs off the end
    // of its section) shortens the table; it never fabricates entries. A name
    // whose ordinal index lies past `NumberOfFunctions` names no slot — the
    // OS loader refuses it the same way — so it is not listed.
    let slots: Vec<u32> = read_at(source, base, addr_table, n_slots * 4)
        .map(|b| b.as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c)).collect())
        .unwrap_or_default();

    let target_of = |rva: u32| -> Option<ExportTarget> {
        if rva == 0 {
            return None; // an unused ordinal slot
        }
        if dir.holds(rva) {
            // The string lies inside the directory, so read no further than
            // the directory's declared end — and never more than one bounded
            // forwarder's worth.
            let room = (dir.end() - rva as u64).min(MAX_FORWARDER as u64) as usize;
            let to = read_cstr(source, base, rva, room)?;
            return Some(ExportTarget::Forwarded { string: base.offset(rva as u64), to });
        }
        Some(ExportTarget::Local(base.offset(rva as u64)))
    };

    let mut out = Vec::new();
    let mut named = vec![false; slots.len()];
    if n_names > 0 {
        let name_rvas = read_at(source, base, name_table, n_names * 4).unwrap_or_default();
        let ordinals = read_at(source, base, ordinal_table, n_names * 2).unwrap_or_default();
        let pairs = (name_rvas.len() / 4).min(ordinals.len() / 2);
        for i in 0..pairs {
            let index = u16::from_le_bytes([ordinals[i * 2], ordinals[i * 2 + 1]]) as usize;
            let Some(&rva) = slots.get(index) else { continue };
            let Some(name) = read_cstr(source, base, u32_at(&name_rvas, i * 4), MAX_NAME) else { continue };
            let Some(target) = target_of(rva) else { continue };
            named[index] = true;
            out.push(PeExport { name: Some(name), ordinal: ordinal_base.wrapping_add(index as u32), target });
        }
    }
    for (index, &rva) in slots.iter().enumerate() {
        if named[index] {
            continue;
        }
        let Some(target) = target_of(rva) else { continue };
        out.push(PeExport { name: None, ordinal: ordinal_base.wrapping_add(index as u32), target });
    }
    out
}

fn u32_at_checked(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
}

/// A field of a buffer already known to be long enough; past its end reads 0,
/// which every field of the export directory treats as "absent".
fn u32_at(b: &[u8], off: usize) -> u32 {
    u32_at_checked(b, off).unwrap_or(0)
}

/// `len` bytes at `base + rva`. RVA 0 is "absent" in every field of this
/// table, never the image header.
fn read_at(source: &dyn MemorySource, base: Va, rva: u32, len: usize) -> Option<Vec<u8>> {
    if rva == 0 {
        return None;
    }
    source.read(base.offset(rva as u64), len).ok()
}

/// A NUL-terminated string at `base + rva`, read no further than `max` bytes;
/// one with no NUL inside them is returned as far as it was read.
fn read_cstr(source: &dyn MemorySource, base: Va, rva: u32, max: usize) -> Option<String> {
    let mut want = NAME_PROBE.min(max);
    loop {
        let buf = read_at(source, base, rva, want)?;
        if let Some(end) = buf.iter().position(|&b| b == 0) {
            return Some(String::from_utf8_lossy(&buf[..end]).into_owned());
        }
        if buf.len() < want || want >= max {
            return Some(String::from_utf8_lossy(&buf).into_owned());
        }
        want = max;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Snapshot;

    const BASE: u64 = 0x1000_0000;

    /// An export directory at RVA 0x100 (size 0x100) over one region, with an
    /// address table of four slots — code, empty, forwarder, code — and two
    /// names: `fwd` on the forwarder slot and `code` on the first.
    fn image() -> Snapshot {
        let mut b = vec![0u8; 0x400];
        let put = |b: &mut Vec<u8>, off: usize, v: u32| b[off..off + 4].copy_from_slice(&v.to_le_bytes());
        let dir = 0x100;
        put(&mut b, dir + 16, 7); // ordinal base
        put(&mut b, dir + 20, 4); // NumberOfFunctions
        put(&mut b, dir + 24, 2); // NumberOfNames
        put(&mut b, dir + 28, 0x140); // address table
        put(&mut b, dir + 32, 0x160); // name pointers
        put(&mut b, dir + 36, 0x170); // name ordinals
        put(&mut b, 0x140, 0x300); // slot 0: code
        put(&mut b, 0x144, 0); // slot 1: unused
        put(&mut b, 0x148, 0x1c0); // slot 2: inside the directory
        put(&mut b, 0x14c, 0x200); // slot 3: the first byte past the directory
        put(&mut b, 0x160, 0x180);
        put(&mut b, 0x164, 0x190);
        b[0x170..0x172].copy_from_slice(&0u16.to_le_bytes());
        b[0x172..0x174].copy_from_slice(&2u16.to_le_bytes());
        b[0x180..0x185].copy_from_slice(b"code\0");
        b[0x190..0x194].copy_from_slice(b"fwd\0");
        b[0x1c0..0x1d2].copy_from_slice(b"OTHERDLL.Function\0");
        Snapshot::builder().region(Va(BASE), b).build()
    }

    #[test]
    fn every_entry_is_classified_and_a_forwarder_carries_its_string() {
        let got = read_export_table(&image(), Va(BASE), ExportDirectory { rva: 0x100, size: 0x100 });
        assert_eq!(
            got,
            vec![
                PeExport { name: Some("code".into()), ordinal: 7, target: ExportTarget::Local(Va(BASE + 0x300)) },
                PeExport {
                    name: Some("fwd".into()),
                    ordinal: 9,
                    target: ExportTarget::Forwarded { string: Va(BASE + 0x1c0), to: "OTHERDLL.Function".into() }
                },
                // The first byte past the directory is not inside it.
                PeExport { name: None, ordinal: 10, target: ExportTarget::Local(Va(BASE + 0x200)) },
            ]
        );
    }

    #[test]
    fn the_directory_size_decides_what_is_a_forwarder() {
        // Shrink the directory so slot 2's RVA lies past its end: the same
        // bytes are then an ordinary address, exactly as the OS loader reads them.
        let got = read_export_table(&image(), Va(BASE), ExportDirectory { rva: 0x100, size: 0xc0 });
        let fwd = got.iter().find(|e| e.name.as_deref() == Some("fwd")).expect("listed");
        assert_eq!(fwd.target, ExportTarget::Local(Va(BASE + 0x1c0)));
    }

    #[test]
    fn an_empty_directory_range_still_lists_the_table_with_no_forwarders() {
        let got = read_export_table(&image(), Va(BASE), ExportDirectory { rva: 0x100, size: 0 });
        assert_eq!(got.len(), 3, "the table is there; only the forwarder range is empty");
        assert!(got.iter().all(|e| matches!(e.target, ExportTarget::Local(_))));
    }

    #[test]
    fn a_name_past_the_address_table_names_nothing() {
        // NumberOfFunctions = 2: slot 2, where `fwd` points, is not in the table.
        let mut b = image().read(Va(BASE), 0x400).expect("region");
        b[0x114..0x118].copy_from_slice(&2u32.to_le_bytes());
        let snap = Snapshot::builder().region(Va(BASE), b).build();
        let got = read_export_table(&snap, Va(BASE), ExportDirectory { rva: 0x100, size: 0x100 });
        assert_eq!(got, vec![PeExport { name: Some("code".into()), ordinal: 7, target: ExportTarget::Local(Va(BASE + 0x300)) }]);
    }

    #[test]
    fn a_count_read_from_the_file_never_sizes_a_read() {
        let mut snap = image();
        // NumberOfFunctions and NumberOfNames both claim four billion.
        let mut b = snap.read(Va(BASE), 0x400).expect("region");
        b[0x114..0x118].copy_from_slice(&u32::MAX.to_le_bytes());
        b[0x118..0x11c].copy_from_slice(&u32::MAX.to_le_bytes());
        snap = Snapshot::builder().region(Va(BASE), b).build();
        let got = read_export_table(&snap, Va(BASE), ExportDirectory { rva: 0x100, size: 0x100 });
        assert!(got.len() <= MAX_EXPORT_SLOTS, "bounded by the format, not by the claim");
    }

    #[test]
    fn a_directory_that_wraps_the_address_space_does_not_cover_everything() {
        let d = ExportDirectory { rva: 0xffff_ff00, size: 0x200 };
        assert!(d.holds(0xffff_ff80));
        assert!(!d.holds(0x80), "the range is not allowed to wrap round to the start");
    }
}

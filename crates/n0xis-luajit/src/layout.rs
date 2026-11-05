// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Which `GCstr` header a process has, decided by what its memory refers to.
//!
//! A string's `len` and text can be found without knowing the header, but its *base*
//! cannot: the base is `len`'s address minus an offset that differs by build, and it
//! is the base that everything refers to. A wrong offset gives no error. It gives an
//! address nothing points at, so every string appears unreferenced and every array
//! empty, `ok: true`. Measured on a real process whose header has `len` at 0x0c, read
//! with the 0x10 this crate used to assume: 0 references at each reported base, and
//! 564 to 827 per string 4 bytes above it.
//!
//! So no offset is assumed. Each candidate proposes a base for every string found, and
//! the memory is searched for references to those bases. The candidate that memory
//! refers to is the layout, and the counts behind that are in the answer. If memory
//! refers to none, or to two alike, no base is claimed.
//!
//! What a header looks like (`nextgc`, `marked`, `gct`, then the fields up to `len`):
//!
//! | `len` at | header |
//! | --- | --- |
//! | 0x0c | 32-bit `GCRef`, two more bytes, `hash`, then `len`, as LuaJIT 2.0 |
//! | 0x10 | 64-bit `GCRef`, as that same 2.0 header widened |
//! | 0x14 | 64-bit `GCRef`, two more bytes, `sid`, `hash`, then `len`, as LuaJIT 2.1 GC64 |

use std::collections::HashMap;

use n0xis_contracts::Va;
use n0xis_sources::{MemorySource, RegionCoverage, SourceError, Swept};
use serde::Serialize;

use crate::{GC_OBJECT_ALIGN, is_plausible_ascii, string_ref_candidates};

/// Where `len` can be, from the header table above.
pub const GCSTR_LEN_OFFSETS: [u64; 3] = [0x0c, 0x10, 0x14];

/// References to one base, by the form they take.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct References {
    /// All of them.
    pub references: usize,
    /// Those that are a tagged string value: what an array or a table slot holds, and
    /// what a run is made of. The rest are bare pointers: the string table's chain, a
    /// prototype's constants, a packed 4-byte array in low memory.
    pub in_values: usize,
}

/// What one candidate found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LayoutCandidate {
    #[serde(serialize_with = "hex_offset")]
    pub len_offset: u64,
    /// Strings whose base under this candidate is 8-aligned.
    pub strings: usize,
    #[serde(flatten)]
    pub referred: References,
}

/// How the layout was settled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutChoice {
    /// The one candidate memory refers to most.
    ByReferences(u64),
    /// The caller's, whatever memory says. The candidates beside it say what that was.
    Override(u64),
    /// None was chosen, and this is why. No string here has a known base.
    Undecided(String),
}

/// The decision and what it stands on. Goes in the answer as it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutDecision {
    pub choice: LayoutChoice,
    pub candidates: Vec<LayoutCandidate>,
}

impl LayoutDecision {
    pub fn len_offset(&self) -> Option<u64> {
        match self.choice {
            LayoutChoice::ByReferences(off) | LayoutChoice::Override(off) => Some(off),
            LayoutChoice::Undecided(_) => None,
        }
    }
}

fn hex_offset<S: serde::Serializer>(off: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(&format_args!("{off:#x}"))
}

impl Serialize for LayoutDecision {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Stated<'a> {
            len_offset: Option<String>,
            chosen_by: &'static str,
            #[serde(skip_serializing_if = "Option::is_none")]
            why: Option<&'a str>,
            candidates: &'a [LayoutCandidate],
        }
        let (chosen_by, why) = match &self.choice {
            LayoutChoice::ByReferences(_) => ("references", None),
            LayoutChoice::Override(_) => ("override", None),
            LayoutChoice::Undecided(why) => ("none", Some(why.as_str())),
        };
        Stated { len_offset: self.len_offset().map(|o| format!("{o:#x}")), chosen_by, why, candidates: &self.candidates }.serialize(serializer)
    }
}

/// A string found in memory, as the decision leaves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocatedGcStr {
    /// `None` when no layout was chosen: where `len` is does not say where the object
    /// begins, and a guess is what this used to give.
    pub object_base: Option<Va>,
    pub len_addr: Va,
    pub data_addr: Va,
    pub len: u32,
    pub text: String,
    /// References to `object_base`, zero with no base.
    #[serde(flatten)]
    pub referred: References,
}

/// The strings found and the layout they were read with.
#[derive(Debug, Clone)]
pub struct LocatedStrings {
    pub layout: LayoutDecision,
    pub strings: Vec<LocatedGcStr>,
}

struct Found {
    len_addr: u64,
    data_addr: u64,
    len: u32,
    text: String,
}

/// Find the strings `keep` accepts whose `len` is in `[min_len, max_len]`, and settle
/// their layout. `len_offset` overrides the choice; every candidate is still counted,
/// so an override that memory disagrees with shows it.
pub fn locate_strings(
    source: &dyn MemorySource,
    regions: &[(Va, usize)],
    len_offset: Option<u64>,
    min_len: u32,
    max_len: u32,
    keep: impl Fn(&str) -> bool,
) -> Result<Swept<LocatedStrings>, SourceError> {
    let mut offsets = GCSTR_LEN_OFFSETS.to_vec();
    if let Some(off) = len_offset
        && !offsets.contains(&off)
    {
        offsets.push(off);
    }
    let Swept { answer: found, mut read } = find_strings(source, regions, &offsets, min_len, max_len, &keep)?;
    let Swept { answer: referred, read: second } = count_references(source, regions, &found, &offsets)?;
    read.merge(second);

    let candidates: Vec<LayoutCandidate> = offsets
        .iter()
        .zip(&referred)
        .map(|(&len_offset, per_string)| LayoutCandidate {
            len_offset,
            strings: found.iter().filter(|f| base_of(f.len_addr, len_offset).is_some()).count(),
            referred: per_string.iter().fold(References::default(), |sum, r| References {
                references: sum.references + r.references,
                in_values: sum.in_values + r.in_values,
            }),
        })
        .collect();
    let choice = match len_offset {
        Some(off) => LayoutChoice::Override(off),
        None => choose(&candidates),
    };
    let layout = LayoutDecision { choice, candidates };

    let chosen = layout.len_offset().and_then(|off| Some((off, offsets.iter().position(|&o| o == off)?)));
    let strings = found
        .into_iter()
        .enumerate()
        .filter_map(|(i, f)| {
            let (object_base, referred) = match chosen {
                Some((off, candidate)) => (Some(Va(base_of(f.len_addr, off)?)), referred[candidate][i]),
                None => (None, References::default()),
            };
            Some(LocatedGcStr { object_base, len_addr: Va(f.len_addr), data_addr: Va(f.data_addr), len: f.len, text: f.text, referred })
        })
        .collect();
    Ok(Swept { answer: LocatedStrings { layout, strings }, read })
}

/// The fewest references that decide a layout when none of them is a Lua value. One
/// word equal to an address is what chance gives: a process's own stack did it, and
/// the answer named a base for a string nothing referred to.
const REFERENCES_WITHOUT_A_VALUE: usize = 2;

/// The candidate with the most references, among those a reference can be believed of.
/// Nothing referred to, or two alike, chooses none.
fn choose(candidates: &[LayoutCandidate]) -> LayoutChoice {
    let most = candidates.iter().map(|c| c.referred.references).max().unwrap_or(0);
    if most == 0 {
        return LayoutChoice::Undecided("no candidate layout's bases are referred to by anything read".to_string());
    }
    let believed = |c: &LayoutCandidate| c.referred.in_values > 0 || c.referred.references >= REFERENCES_WITHOUT_A_VALUE;
    if !candidates.iter().any(believed) {
        return LayoutChoice::Undecided(format!(
            "the bases are referred to only by {most} word that is no Lua value, which chance can give"
        ));
    }
    let tied: Vec<&LayoutCandidate> = candidates.iter().filter(|c| c.referred.references == most).collect();
    match tied.as_slice() {
        [only] => LayoutChoice::ByReferences(only.len_offset),
        _ => {
            let names: Vec<String> = tied.iter().map(|c| format!("{:#x}", c.len_offset)).collect();
            LayoutChoice::Undecided(format!("candidates {} tie at {most} references", names.join(", ")))
        }
    }
}

/// The base a `len` at `len_addr` gives under `len_offset`, if an object can begin there.
fn base_of(len_addr: u64, len_offset: u64) -> Option<u64> {
    len_addr.checked_sub(len_offset).filter(|base| base.is_multiple_of(GC_OBJECT_ALIGN))
}

/// Every `len` word followed by printable bytes that some offset can place.
fn find_strings(
    source: &dyn MemorySource,
    regions: &[(Va, usize)],
    offsets: &[u64],
    min_len: u32,
    max_len: u32,
    keep: &impl Fn(&str) -> bool,
) -> Result<Swept<Vec<Found>>, SourceError> {
    let mut out = Vec::new();
    let mut read = RegionCoverage::default();
    for &(base, size) in regions {
        let bytes = read.read_region(source, base, size)?;
        if bytes.len() < 4 {
            continue;
        }
        for off in 0..=(bytes.len() - 4) {
            let len = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
            if len < min_len || len > max_len {
                continue;
            }
            let (data_start, data_end) = (off + 4, off + 4 + len as usize);
            if data_end > bytes.len() || !is_plausible_ascii(&bytes[data_start..data_end]) {
                continue;
            }
            let len_addr = base.0 + off as u64;
            if !offsets.iter().any(|&o| base_of(len_addr, o).is_some()) {
                continue;
            }
            // Already validated ASCII, so this is always a lossless decode.
            let text = String::from_utf8_lossy(&bytes[data_start..data_end]).into_owned();
            if keep(&text) {
                out.push(Found { len_addr, data_addr: base.0 + data_start as u64, len, text });
            }
        }
    }
    Ok(Swept { answer: out, read })
}

/// One sweep for references to every base of every candidate: `result[candidate][string]`.
///
/// A word is read as each form a reference to a string can take in memory: a tagged
/// value (either boxing, [`string_ref_candidates`]), a bare 8-byte pointer, and where a
/// base fits in 32 bits, a packed 4-byte reference.
fn count_references(source: &dyn MemorySource, regions: &[(Va, usize)], found: &[Found], offsets: &[u64]) -> Result<Swept<Vec<Vec<References>>>, SourceError> {
    let mut counts = vec![vec![References::default(); found.len()]; offsets.len()];
    let by_base: Vec<HashMap<u64, usize>> = offsets
        .iter()
        .map(|&o| found.iter().enumerate().filter_map(|(i, f)| Some((base_of(f.len_addr, o)?, i))).collect())
        .collect();
    let lowest = by_base.iter().flat_map(|m| m.keys()).min().copied().unwrap_or(u64::MAX);
    let highest = by_base.iter().flat_map(|m| m.keys()).max().copied().unwrap_or(0);
    let mut tally = |addr: u64, in_value: bool| {
        if addr < lowest || addr > highest || !addr.is_multiple_of(GC_OBJECT_ALIGN) {
            return;
        }
        for (candidate, bases) in by_base.iter().enumerate() {
            if let Some(&string) = bases.get(&addr) {
                let r = &mut counts[candidate][string];
                r.references += 1;
                r.in_values += usize::from(in_value);
            }
        }
    };
    let mut read = RegionCoverage::default();
    for &(base, size) in regions {
        let bytes = read.read_region(source, base, size)?;
        // Words at the process's own alignment, wherever a window began.
        let skew = (base.0.wrapping_neg() & 3) as usize;
        for (i, word) in bytes.get(skew..).unwrap_or_default().as_chunks::<4>().0.iter().enumerate() {
            let at = skew + i * 4;
            tally(u64::from(u32::from_le_bytes(*word)), false);
            if !(base.0 + at as u64).is_multiple_of(8) || at + 8 > bytes.len() {
                continue;
            }
            let raw = u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
            match string_ref_candidates(raw) {
                [None, None] if raw >> 32 != 0 => tally(raw, false),
                [None, None] => {}
                [gc64, r32] => {
                    for addr in [gc64, r32].into_iter().flatten() {
                        tally(addr.0, true);
                    }
                }
            }
        }
    }
    Ok(Swept { answer: counts, read })
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_sources::Snapshot;

    const REGION: u64 = 0x7f00_0000_0000;
    /// Where the planted arrays go.
    const ARRAY_AT: u64 = 0x800;

    /// A region holding `up` and `down` with `len` at `len_offset`, on 8-aligned bases,
    /// and optionally `{up, down, down, up}` as tagged values.
    fn planted(len_offset: u64, with_array: bool) -> (Snapshot, u64, u64) {
        let mut mem = vec![0xABu8; 0x1000];
        let mut put = |base: usize, text: &str| {
            let at = base + len_offset as usize;
            mem[at..at + 4].copy_from_slice(&(text.len() as u32).to_le_bytes());
            mem[at + 4..at + 4 + text.len()].copy_from_slice(text.as_bytes());
        };
        let (up, down) = (0x100usize, 0x200usize);
        put(up, "up");
        put(down, "down");
        let (up, down) = (REGION + up as u64, REGION + down as u64);
        if with_array {
            for (i, target) in [up, down, down, up].into_iter().enumerate() {
                let at = ARRAY_AT as usize + i * 8;
                mem[at..at + 8].copy_from_slice(&((0x1FFFBu64 << 47) | target).to_le_bytes());
            }
        }
        (Snapshot::builder().region(Va(REGION), mem).build(), up, down)
    }

    fn locate(snap: &Snapshot, len_offset: Option<u64>) -> LocatedStrings {
        locate_strings(snap, &[(Va(REGION), 0x1000)], len_offset, 1, 16, |t| t == "up" || t == "down").unwrap().answer
    }

    /// The answer is known before the question: each layout, planted, is the one chosen,
    /// with the planted bases and exactly the planted references, and no other has any.
    #[test]
    fn one_word_outside_a_value_decides_nothing() {
        let candidate = |len_offset, references, in_values| LayoutCandidate {
            len_offset,
            strings: 8,
            referred: References { references, in_values },
        };
        let lone = choose(&[candidate(0x0c, 1, 0), candidate(0x10, 0, 0), candidate(0x14, 0, 0)]);
        assert!(matches!(&lone, LayoutChoice::Undecided(why) if why.contains("referred")), "{lone:?}");
        assert_eq!(choose(&[candidate(0x0c, 1, 1), candidate(0x10, 0, 0)]), LayoutChoice::ByReferences(0x0c), "a value is believed");
        assert_eq!(choose(&[candidate(0x0c, 2, 0), candidate(0x10, 0, 0)]), LayoutChoice::ByReferences(0x0c), "two words are");
    }

    #[test]
    fn each_layout_is_chosen_by_what_refers_to_it() {
        for off in GCSTR_LEN_OFFSETS {
            let (snap, up, down) = planted(off, true);
            let got = locate(&snap, None);
            assert_eq!(got.layout.choice, LayoutChoice::ByReferences(off), "{:?}", got.layout);
            for c in &got.layout.candidates {
                let want = if c.len_offset == off { 4 } else { 0 };
                assert_eq!(c.referred.references, want, "planted {off:#x}, candidate {:#x}: {:?}", c.len_offset, got.layout);
            }
            let base = |text: &str| got.strings.iter().find(|s| s.text == text).unwrap_or_else(|| panic!("{text}: {:?}", got.strings));
            assert_eq!(base("up").object_base, Some(Va(up)));
            assert_eq!(base("up").referred, References { references: 2, in_values: 2 });
            assert_eq!(base("down").object_base, Some(Va(down)));
            assert_eq!(base("down").referred.references, 2);
        }
    }

    /// Strings and nothing referring to them: said, with no base claimed.
    #[test]
    fn with_no_references_nothing_is_chosen() {
        let (snap, ..) = planted(0x14, false);
        let got = locate(&snap, None);
        assert!(matches!(got.layout.choice, LayoutChoice::Undecided(ref why) if why.contains("referred")), "{:?}", got.layout);
        assert_eq!(got.layout.len_offset(), None);
        assert_eq!(got.strings.len(), 2, "the strings exist: {:?}", got.strings);
        assert!(got.strings.iter().all(|s| s.object_base.is_none() && s.referred.references == 0));
        let v = serde_json::to_value(&got.layout).unwrap();
        assert_eq!(v["len_offset"], serde_json::Value::Null);
        assert_eq!(v["chosen_by"], "none");
    }

    /// The caller's offset is taken and says so, with what memory thinks beside it.
    #[test]
    fn an_override_says_it_overrode() {
        let (snap, up, _) = planted(0x14, true);
        let got = locate(&snap, Some(0x10));
        assert_eq!(got.layout.choice, LayoutChoice::Override(0x10));
        let refs = |off: u64| got.layout.candidates.iter().find(|c| c.len_offset == off).expect("counted").referred.references;
        assert_eq!((refs(0x10), refs(0x14)), (0, 4), "the disagreement shows");
        assert_eq!(got.strings.iter().filter(|s| s.object_base.is_some_and(|b| b.0 + 8 == up)).count(), 0);
        let v = serde_json::to_value(&got.layout).unwrap();
        assert_eq!(v["chosen_by"], "override");
        assert_eq!(v["len_offset"], "0x10");
        assert_eq!(v["candidates"][2]["len_offset"], "0x14");

        // An offset no candidate has is counted beside them.
        let got = locate(&snap, Some(0x18));
        assert!(got.layout.candidates.iter().any(|c| c.len_offset == 0x18));
    }

    /// Two candidates alike is not evidence for either.
    #[test]
    fn a_tie_chooses_none_and_names_them() {
        let candidate = |len_offset, references| LayoutCandidate { len_offset, strings: 1, referred: References { references, in_values: 0 } };
        let choice = choose(&[candidate(0x0c, 3), candidate(0x10, 1), candidate(0x14, 3)]);
        assert!(matches!(choice, LayoutChoice::Undecided(ref why) if why.contains("0xc") && why.contains("0x14") && why.contains("tie")), "{choice:?}");
    }

    /// Bare pointers count as references, and not as values, in each form that reaches one.
    #[test]
    fn each_form_of_reference_is_counted() {
        let (snap, up, _) = planted(0x14, false);
        let mut mem = snap.read(Va(REGION), 0x1000).unwrap();
        mem[0x900..0x908].copy_from_slice(&up.to_le_bytes());
        mem[0x908..0x910].copy_from_slice(&up.to_le_bytes());
        let snap = Snapshot::builder().region(Va(REGION), mem).build();
        let got = locate(&snap, None);
        assert_eq!(got.layout.choice, LayoutChoice::ByReferences(0x14), "{:?}", got.layout);
        let hit = got.strings.iter().find(|s| s.text == "up").unwrap();
        assert_eq!(hit.referred, References { references: 2, in_values: 0 });

        // In low memory, a packed 4-byte reference, at an address that is not on 8.
        let low = 0x3000_0000u64;
        let mut mem = vec![0xABu8; 0x1000];
        mem[0x114..0x118].copy_from_slice(&2u32.to_le_bytes());
        mem[0x118..0x11a].copy_from_slice(b"up");
        mem[0x804..0x808].copy_from_slice(&((low + 0x100) as u32).to_le_bytes());
        mem[0x80c..0x810].copy_from_slice(&((low + 0x100) as u32).to_le_bytes());
        let snap = Snapshot::builder().region(Va(low), mem).build();
        let got = locate_strings(&snap, &[(Va(low), 0x1000)], None, 1, 16, |t| t == "up").unwrap().answer;
        assert_eq!(got.layout.choice, LayoutChoice::ByReferences(0x14), "{:?}", got.layout);
        assert_eq!(got.strings[0].referred, References { references: 2, in_values: 0 });
    }

    /// A false hit, where no candidate can put a base, is not listed at all. Shape of
    /// the one a real scan listed: `len` two bytes off every multiple of 4.
    #[test]
    fn a_hit_no_candidate_can_place_is_dropped() {
        let (snap, ..) = planted(0x14, true);
        let mut mem = snap.read(Va(REGION), 0x1000).unwrap();
        mem[0x402..0x406].copy_from_slice(&2u32.to_le_bytes());
        mem[0x406..0x408].copy_from_slice(b"up");
        let snap = Snapshot::builder().region(Va(REGION), mem).build();
        let got = locate(&snap, None);
        assert!(got.strings.iter().all(|s| s.len_addr.0 != REGION + 0x402), "{:?}", got.strings);
        assert_eq!(got.strings.iter().filter(|s| s.text == "up").count(), 1);
    }

    /// A string whose `len` fits a candidate the choice did not take is not one under
    /// the one it did: it is listed only where its base can be.
    #[test]
    fn under_the_chosen_layout_a_hit_it_cannot_place_goes() {
        let (snap, ..) = planted(0x14, true);
        let mut mem = snap.read(Va(REGION), 0x1000).unwrap();
        // `len` on 8: only the 0x10 candidate can place this one, and memory chose 0x14.
        mem[0x500..0x504].copy_from_slice(&2u32.to_le_bytes());
        mem[0x504..0x506].copy_from_slice(b"up");
        let snap = Snapshot::builder().region(Va(REGION), mem).build();
        let got = locate(&snap, None);
        assert_eq!(got.layout.choice, LayoutChoice::ByReferences(0x14));
        assert_eq!(got.strings.iter().filter(|s| s.text == "up").count(), 1, "{:?}", got.strings);
        let wide = got.layout.candidates.iter().find(|c| c.len_offset == 0x10).unwrap();
        assert_eq!(wide.strings, 1, "it was still counted for the candidate that could place it");
    }

    /// What was not read is stated, across both sweeps.
    #[test]
    fn what_was_not_read_is_stated() {
        let (snap, ..) = planted(0x14, true);
        let swept = locate_strings(&snap, &[(Va(0x10), 16), (Va(REGION), 0x1000)], None, 1, 16, |t| t == "up").unwrap();
        assert_eq!(swept.read.not_read().iter().map(|n| n.start.0).collect::<Vec<_>>(), [0x10]);
        assert_eq!(swept.read.regions_scanned(), 1);
    }
}

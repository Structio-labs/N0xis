// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! # n0xis-il2cpp — the managed layer (Phase 12, item 0)
//!
//! An IL2CPP target is native-speed code carrying a complete symbol table that
//! lives *outside* the code. n0xis reads the native half and never the managed
//! half, which is why `xref string` returns 0, `bindings list` returns 0, and
//! `decomp pseudo` names 0 of 69 calls on a Unity build. This crate is the
//! start of the other half.
//!
//! **Item 0 first, on purpose**: import an index someone else already produced
//! (Il2CppDumper, Il2CppInspector, Cpp2IL) and serve it through the existing
//! [`SymbolProvider`] seam. Named decompilation before a single byte of
//! metadata parser exists — and it is not scaffolding, it stays as the fallback
//! for versions and obfuscations a native parser will refuse.
//!
//! ## Address spaces are explicit, and that is the whole Unity-WebGL story
//!
//! Unity WebGL builds go through the **same IL2CPP pipeline** as Windows ones:
//! Roslyn → IL → C++ → native code, with the same `global-metadata.dat`
//! alongside. The managed half is therefore genuinely portable, and a metadata
//! parser written for one serves both — that is the compatibility win, and it
//! is a design decision taken now rather than a port done later.
//!
//! The *native* half is not portable at all, and the WebGL case is stranger
//! than "a different address space". A Windows dump's `Address` is an address:
//! an RVA into a PE. **A WebGL dump's `Address` is not an address at all** — it
//! is an offset within a signature-specific sub-table. Resolving it means
//! finding the `dynCall_<signature>` function for the method's return and
//! parameter types, reading *its* base table index out of the module's own
//! code, adding this offset, and using the result to index `WebAssembly.Table`
//! — which finally yields the wasm function index. (Unity WebGL dispatches
//! virtuals the same way: `VirtFuncInvoker` takes a slot from `klass->vtable`,
//! adds a signature-related base, and issues `call_indirect`.)
//!
//! So the two are indistinguishable as integers and unrelated as meanings, and
//! resolving the WebGL one needs a WASM front end this build does not have. An
//! index that did not carry its [`AddressSpace`] could be bound to the wrong
//! target and would cheerfully name every function *wrongly*. On a corpus where
//! generic sharing already makes confident-but-false naming easy, that is the
//! failure this crate is built to make impossible: a `wasm` index **cannot** be
//! attached to a native target, and the refusal says why.

use n0xis_contracts::{SymKind, Symbol, Va};
use n0xis_sources::SymbolProvider;
use serde::{Deserialize, Serialize};

pub mod metadata;
pub mod script_json;

pub use script_json::Counts;

/// Beyond this distance from the nearest preceding symbol, an address is not
/// attributed to it. A dump lists function *starts*, so the last symbol would
/// otherwise claim the whole rest of the address space. Generous next to any
/// real transpiled method, small next to a section.
pub const MAX_SYMBOL_SPAN: u64 = 256 * 1024;

/// Fraction of sampled method addresses that must land inside `.text` before a
/// binding is accepted. A real dump puts nearly all of them there; anything
/// less means the convention was guessed wrong, and names derived from a wrong
/// convention are worse than no names at all.
pub const MIN_BIND_CONFIDENCE: f64 = 0.90;

/// How many method symbols to test when detecting a binding. Enough to be
/// decisive, small enough to stay instant on a 200 000-symbol index.
const BIND_SAMPLE: usize = 512;

#[derive(Debug, thiserror::Error)]
pub enum Il2CppError {
    #[error("{0}")]
    Malformed(String),
    #[error("{0}")]
    Empty(String),
    #[error("this index is for {index_space}, which cannot be bound to a native target: {why}")]
    WrongAddressSpace { index_space: String, why: String },
    #[error("could not bind the index to this target: {0}")]
    Unbindable(String),
    #[error("{0}")]
    Io(String),
}

/// What kind of address space an imported index's numbers live in.
///
/// Carried on every index and checked before binding. See the crate header for
/// why this is not a detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddressSpace {
    /// Addresses into a native image (`GameAssembly.dll` and friends). Whether
    /// they are RVAs or already-based VAs is *not* declared here — it is
    /// measured against the target, because dumper versions disagree and
    /// guessing wrong is silent. See [`Index::detect_binding`].
    Native {
        /// The module the dump was taken from, when known.
        module: Option<String>,
    },
    /// A Unity WebGL dump. Its numbers are **not addresses**: each is an offset
    /// within a signature-specific sub-table, resolvable only by reading the
    /// matching `dynCall_<sig>` function's base out of the module and indexing
    /// `WebAssembly.Table`. That needs a WASM front end this build does not
    /// have, so such an index is a **searchable name table only** — never a
    /// `SymbolProvider` over a native target.
    Wasm { module: Option<String> },
}

impl AddressSpace {
    pub fn as_str(&self) -> &'static str {
        match self {
            AddressSpace::Native { .. } => "native",
            AddressSpace::Wasm { .. } => "wasm",
        }
    }

    pub fn module(&self) -> Option<&str> {
        match self {
            AddressSpace::Native { module } | AddressSpace::Wasm { module } => module.as_deref(),
        }
    }

    /// Parse a `--space` argument.
    pub fn parse(s: &str, module: Option<String>) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "native" | "pe" | "windows" => Ok(AddressSpace::Native { module }),
            "wasm" | "webgl" => Ok(AddressSpace::Wasm { module }),
            other => Err(format!("unknown address space {other:?} (expected 'native' or 'wasm')")),
        }
    }
}

/// What a symbol came from. Kept distinct because their address spaces differ
/// in kind: a method address is code, a metadata slot is data, and confusing
/// the two produces a name on an address that never executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymbolKind {
    /// A transpiled C# method: an address in `.text`.
    Method,
    /// A metadata-usage slot in `.data`.
    Metadata,
    /// A `.data` slot holding a `MethodInfo*`.
    MetadataMethod,
}

impl SymbolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SymbolKind::Method => "method",
            SymbolKind::Metadata => "metadata",
            SymbolKind::MetadataMethod => "metadata-method",
        }
    }

    fn to_sym_kind(self) -> SymKind {
        match self {
            SymbolKind::Method => SymKind::Function,
            SymbolKind::Metadata | SymbolKind::MetadataMethod => SymKind::Data,
        }
    }
}

/// One entry as the dump gave it — the address is in the index's own space and
/// has had nothing added to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawSymbol {
    pub addr: u64,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    pub kind: SymbolKind,
}

/// A string literal and the slot it is materialized into.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringLiteral {
    pub addr: u64,
    pub value: String,
}

/// An imported managed symbol index, persisted under `.n0x/il2cpp/`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Index {
    pub space: AddressSpace,
    /// Which tool produced the dump, for the `meta.source` trail.
    pub source: String,
    pub counts: Counts,
    /// Sorted by `addr`, so lookups are a binary search.
    pub symbols: Vec<RawSymbol>,
    #[serde(default)]
    pub strings: Vec<StringLiteral>,
}

impl Index {
    pub fn from_parsed(parsed: script_json::Parsed, space: AddressSpace, source: impl Into<String>) -> Self {
        let mut symbols = parsed.symbols;
        symbols.sort_by_key(|s| s.addr);
        Index { space, source: source.into(), counts: parsed.counts, symbols, strings: parsed.strings }
    }

    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Every symbol whose name contains `needle`, case-insensitively.
    ///
    /// **Returns a set, never one entry** — generic sharing means one address
    /// serves many C# methods and one C# method may occupy many addresses, and
    /// ICF folds identical bodies together. A single-answer name lookup on this
    /// corpus is a lie; the seam says so in its type.
    pub fn find_by_name(&self, needle: &str) -> Vec<&RawSymbol> {
        let needle = needle.to_lowercase();
        self.symbols.iter().filter(|s| s.name.to_lowercase().contains(&needle)).collect()
    }

    /// Decide how this index's addresses map onto a live/static target, by
    /// measuring both conventions against the target's own `.text` range.
    ///
    /// Dumper versions disagree on whether `Address` is an RVA or an
    /// already-based VA, and the two are numerically indistinguishable. Rather
    /// than encode a guess that silently breaks on the next release, try both
    /// and report what was observed.
    pub fn detect_binding(&self, module_base: u64, text_start: u64, text_len: u64) -> BindReport {
        let text_end = text_start.saturating_add(text_len);
        let in_text = |va: u64| va >= text_start && va < text_end;

        let mut sampled = 0usize;
        let mut hits_rva = 0usize;
        let mut hits_va = 0usize;
        // Only *methods* are expected in `.text`; metadata slots live in `.data`
        // and would drag both counts down equally, hiding the signal.
        for s in self.symbols.iter().filter(|s| s.kind == SymbolKind::Method).take(BIND_SAMPLE) {
            sampled += 1;
            if in_text(module_base.saturating_add(s.addr)) {
                hits_rva += 1;
            }
            if in_text(s.addr) {
                hits_va += 1;
            }
        }

        let (kind, hits) = if hits_rva >= hits_va { (BindKind::RvaPlusBase, hits_rva) } else { (BindKind::AbsoluteVa, hits_va) };
        let confidence = if sampled == 0 { 0.0 } else { hits as f64 / sampled as f64 };
        BindReport { kind, sampled, hits_rva, hits_va, confidence, accepted: confidence >= MIN_BIND_CONFIDENCE }
    }

    /// Bind the index to a target, or refuse.
    pub fn bind(self, module: impl Into<String>, module_base: u64, report: &BindReport) -> Result<Il2CppSymbols, Il2CppError> {
        if let AddressSpace::Wasm { module: m } = &self.space {
            return Err(Il2CppError::WrongAddressSpace {
                index_space: match m {
                    Some(m) => format!("wasm ({m})"),
                    None => "wasm".to_string(),
                },
                why: "a WebGL dump's numbers are not addresses at all — each is an offset within a signature-specific sub-table, \
                      resolvable only by reading the matching dynCall_<sig> base out of the module and indexing WebAssembly.Table. \
                      Binding them to a native image would name every function wrongly. Query it with `il2cpp symbols` instead"
                    .to_string(),
            });
        }
        if !report.accepted {
            return Err(Il2CppError::Unbindable(format!(
                "only {:.1}% of {} sampled method addresses land inside .text (rva {} vs va {}); \
                 the dump's address convention does not match this target — check that the dump and the binary are the same build",
                report.confidence * 100.0,
                report.sampled,
                report.hits_rva,
                report.hits_va
            )));
        }
        let base = match report.kind {
            BindKind::RvaPlusBase => module_base,
            BindKind::AbsoluteVa => 0,
        };
        Ok(Il2CppSymbols::new(self, module.into(), base))
    }
}

/// Which convention the dump's addresses follow, as measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BindKind {
    /// `va = module_base + addr` — the dump holds RVAs.
    RvaPlusBase,
    /// `va = addr` — the dump already includes the image base.
    AbsoluteVa,
}

impl BindKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BindKind::RvaPlusBase => "rva+base",
            BindKind::AbsoluteVa => "absolute-va",
        }
    }
}

/// The evidence behind a binding decision. Reported rather than kept private:
/// an agent that gets names should be able to see how confident the mapping
/// underneath them is.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BindReport {
    pub kind: BindKind,
    pub sampled: usize,
    pub hits_rva: usize,
    pub hits_va: usize,
    pub confidence: f64,
    pub accepted: bool,
}

/// An [`Index`] bound to a target, serving the [`SymbolProvider`] seam.
///
/// Chained *over* the PE provider: everything downstream — `decomp pseudo`,
/// `ir explain`, `function discover`, `xref to`, `function trace` — starts
/// naming with no changes of its own.
#[derive(Debug)]
pub struct Il2CppSymbols {
    index: Index,
    module: String,
    /// Added to every raw address; 0 when the dump already carries VAs.
    base: u64,
}

impl Il2CppSymbols {
    fn new(index: Index, module: String, base: u64) -> Self {
        Il2CppSymbols { index, module, base }
    }

    pub fn index(&self) -> &Index {
        &self.index
    }

    pub fn module(&self) -> &str {
        &self.module
    }

    fn va_of(&self, s: &RawSymbol) -> u64 {
        self.base.saturating_add(s.addr)
    }

    /// The symbol owning `va`: the nearest at-or-below, provided `va` is within
    /// that symbol's span. A dump lists function starts, so an address inside a
    /// function must resolve to the function — but the *last* symbol must not
    /// claim the rest of the address space, hence [`MAX_SYMBOL_SPAN`].
    fn owner_of(&self, va: u64) -> Option<&RawSymbol> {
        let target = va.checked_sub(self.base)?;
        let idx = match self.index.symbols.binary_search_by_key(&target, |s| s.addr) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let s = &self.index.symbols[idx];
        let span_end = match self.index.symbols.get(idx + 1) {
            Some(next) => next.addr.min(s.addr.saturating_add(MAX_SYMBOL_SPAN)),
            None => s.addr.saturating_add(MAX_SYMBOL_SPAN),
        };
        (target < span_end).then_some(s)
    }
}

impl SymbolProvider for Il2CppSymbols {
    fn symbol_at(&self, va: Va) -> Option<Symbol> {
        let s = self.owner_of(va.0)?;
        Some(Symbol { va: Va(self.va_of(s)), module: self.module.clone(), name: s.name.clone(), kind: s.kind.to_sym_kind() })
    }

    /// Names here come from a file *beside* the binary, so an artifact cache
    /// keyed only on the binary's bytes would serve pre-import artifacts
    /// forever. Cheap and content-derived: how many symbols, where they span,
    /// and the base they were bound at — enough that a re-import with different
    /// contents produces a different key.
    fn symbol_fingerprint(&self) -> String {
        let first = self.index.symbols.first().map(|s| s.addr).unwrap_or(0);
        let last = self.index.symbols.last().map(|s| s.addr).unwrap_or(0);
        format!("il2cpp:{}:{}:{first:x}:{last:x}:{:x}", self.module, self.index.len(), self.base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sym(addr: u64, name: &str, kind: SymbolKind) -> RawSymbol {
        RawSymbol { addr, name: name.to_string(), signature: None, kind }
    }

    fn index(space: AddressSpace, symbols: Vec<RawSymbol>) -> Index {
        let mut symbols = symbols;
        symbols.sort_by_key(|s| s.addr);
        Index { space, source: "test".into(), counts: Counts::default(), symbols, strings: Vec::new() }
    }

    fn native_index() -> Index {
        index(
            AddressSpace::Native { module: Some("GameAssembly.dll".into()) },
            vec![
                sym(0x1000, "PlayerHealth$$ApplyDamage", SymbolKind::Method),
                sym(0x1200, "CombatResolver$$Resolve", SymbolKind::Method),
                sym(0x1400, "EnemyAI$$Update", SymbolKind::Method),
            ],
        )
    }

    // The target: module based at 0x140000000 with .text at +0x1000, 0x1000 long.
    const BASE: u64 = 0x1_4000_0000;
    const TEXT: u64 = BASE + 0x1000;
    const TEXT_LEN: u64 = 0x1000;

    #[test]
    fn a_wasm_index_cannot_be_bound_to_a_native_target() {
        let idx = index(AddressSpace::Wasm { module: Some("game.wasm".into()) }, vec![sym(0x1000, "A$$b", SymbolKind::Method)]);
        let report = idx.detect_binding(BASE, TEXT, TEXT_LEN);
        let err = idx.bind("GameAssembly.dll", BASE, &report).unwrap_err();
        match &err {
            Il2CppError::WrongAddressSpace { index_space, .. } => assert!(index_space.contains("wasm")),
            other => panic!("expected an address-space refusal, got {other}"),
        }
        assert!(err.to_string().contains("il2cpp symbols"), "the refusal should say what you *can* do: {err}");
    }

    #[test]
    fn the_rva_convention_is_measured_not_assumed() {
        // These addresses only land in .text once the module base is added.
        let report = native_index().detect_binding(BASE, TEXT, TEXT_LEN);
        assert_eq!(report.kind, BindKind::RvaPlusBase);
        assert_eq!(report.hits_rva, 3);
        assert_eq!(report.hits_va, 0);
        assert!(report.accepted);
        assert!((report.confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_dump_that_already_carries_vas_is_detected_as_such() {
        let idx = index(
            AddressSpace::Native { module: None },
            vec![sym(TEXT, "A$$a", SymbolKind::Method), sym(TEXT + 0x100, "B$$b", SymbolKind::Method)],
        );
        let report = idx.detect_binding(BASE, TEXT, TEXT_LEN);
        assert_eq!(report.kind, BindKind::AbsoluteVa);
        assert_eq!(report.hits_va, 2);
        assert!(report.accepted);
        // And the bound provider must not add the base a second time.
        let bound = idx.bind("GameAssembly.dll", BASE, &report).unwrap();
        assert_eq!(bound.symbol_at(Va(TEXT)).unwrap().name, "A$$a");
    }

    #[test]
    fn a_mismatched_dump_is_refused_rather_than_bound_to_nonsense() {
        // Addresses that land in .text under neither convention: a dump from a
        // different build.
        let idx = index(
            AddressSpace::Native { module: None },
            vec![sym(0x9000_0000, "X$$x", SymbolKind::Method), sym(0x9000_1000, "Y$$y", SymbolKind::Method)],
        );
        let report = idx.detect_binding(BASE, TEXT, TEXT_LEN);
        assert!(!report.accepted);
        assert_eq!(report.confidence, 0.0);
        let err = idx.bind("GameAssembly.dll", BASE, &report).unwrap_err();
        assert!(err.to_string().contains("same build"), "the refusal should point at the likely cause: {err}");
    }

    #[test]
    fn only_method_addresses_are_sampled_for_the_binding_decision() {
        // Metadata slots live in .data and would drag both counts down equally,
        // hiding the signal they are not evidence for.
        let idx = index(
            AddressSpace::Native { module: None },
            vec![
                sym(0x1000, "M$$m", SymbolKind::Method),
                sym(0x8000, "Slot_TypeInfo", SymbolKind::Metadata),
                sym(0x8100, "Slot_MethodInfo", SymbolKind::MetadataMethod),
            ],
        );
        let report = idx.detect_binding(BASE, TEXT, TEXT_LEN);
        assert_eq!(report.sampled, 1, "two of the three symbols are data, not code");
        assert!(report.accepted);
    }

    #[test]
    fn an_address_inside_a_function_resolves_to_that_function() {
        let idx = native_index();
        let report = idx.detect_binding(BASE, TEXT, TEXT_LEN);
        let bound = idx.bind("GameAssembly.dll", BASE, &report).unwrap();

        assert_eq!(bound.symbol_at(Va(BASE + 0x1000)).unwrap().name, "PlayerHealth$$ApplyDamage");
        assert_eq!(bound.symbol_at(Va(BASE + 0x1100)).unwrap().name, "PlayerHealth$$ApplyDamage", "mid-function addresses belong to the function");
        assert_eq!(bound.symbol_at(Va(BASE + 0x1200)).unwrap().name, "CombatResolver$$Resolve", "a symbol never spills into the next one");
        assert!(bound.symbol_at(Va(BASE + 0x0fff)).is_none(), "nothing below the first symbol");
    }

    #[test]
    fn the_last_symbol_does_not_claim_the_rest_of_the_address_space() {
        let idx = native_index();
        let report = idx.detect_binding(BASE, TEXT, TEXT_LEN);
        let bound = idx.bind("GameAssembly.dll", BASE, &report).unwrap();
        assert!(bound.symbol_at(Va(BASE + 0x1400 + MAX_SYMBOL_SPAN - 1)).is_some());
        assert!(bound.symbol_at(Va(BASE + 0x1400 + MAX_SYMBOL_SPAN)).is_none(), "beyond one span the answer is 'unknown', not the last name in the file");
    }

    #[test]
    fn methods_become_functions_and_metadata_becomes_data() {
        let idx = index(
            AddressSpace::Native { module: None },
            vec![sym(0x1000, "M$$m", SymbolKind::Method), sym(0x1100, "Slot", SymbolKind::Metadata)],
        );
        let report = idx.detect_binding(BASE, TEXT, TEXT_LEN);
        let bound = idx.bind("GameAssembly.dll", BASE, &report).unwrap();
        assert_eq!(bound.symbol_at(Va(BASE + 0x1000)).unwrap().kind, SymKind::Function);
        assert_eq!(bound.symbol_at(Va(BASE + 0x1100)).unwrap().kind, SymKind::Data, "a metadata slot is data — naming it a function would put a name on an address that never executes");
    }

    #[test]
    fn name_lookup_returns_a_set_because_one_answer_would_be_a_lie() {
        // Generic sharing: one native body, several C# methods.
        let idx = index(
            AddressSpace::Native { module: None },
            vec![
                sym(0x1000, "List_1$$Add_System_Object", SymbolKind::Method),
                sym(0x1000, "List_1$$Add_UnityEngine_Object", SymbolKind::Method),
                sym(0x2000, "Other$$Add", SymbolKind::Method),
            ],
        );
        let hits = idx.find_by_name("$$add");
        assert_eq!(hits.len(), 3);
        assert_eq!(idx.find_by_name("List_1").len(), 2, "two C# methods share one address — the API must be able to say so");
    }

    #[test]
    fn address_space_parses_its_names_and_refuses_the_rest() {
        assert!(matches!(AddressSpace::parse("native", None).unwrap(), AddressSpace::Native { .. }));
        assert!(matches!(AddressSpace::parse("WebGL", None).unwrap(), AddressSpace::Wasm { .. }));
        assert!(matches!(AddressSpace::parse("pe", None).unwrap(), AddressSpace::Native { .. }));
        assert!(AddressSpace::parse("elf", None).is_err());
    }

    #[test]
    fn an_index_round_trips_through_json_for_the_project_store() {
        let idx = native_index();
        let text = serde_json::to_string(&idx).unwrap();
        let back: Index = serde_json::from_str(&text).unwrap();
        assert_eq!(back.len(), 3);
        assert_eq!(back.space, idx.space);
        assert!(text.contains("\"space\":{\"native\""), "the address space must survive persistence: {}", &text[..80.min(text.len())]);
    }
}

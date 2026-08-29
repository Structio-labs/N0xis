//! [`Snapshot`] — an in-memory [`MemorySource`] / [`SymbolProvider`] /
//! [`ModuleProvider`]. Zero OS dependencies: the test double the analysis core
//! is validated against, **and** (ROADMAP Phase 6) the reproducible-offline
//! source — `Serialize`/`Deserialize` let one be captured (`snapshot dump`)
//! and reloaded later or on another machine (`--snapshot <name>`), analyzing
//! the exact same bytes every time, no live process or file needed.

use std::collections::BTreeMap;

use n0xis_contracts::{Module, Symbol, Va};
use serde::{Deserialize, Serialize};

use crate::{MemorySource, ModuleProvider, SourceError, SymbolProvider};

/// One contiguous mapped region of bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Region {
    base: u64,
    bytes: Vec<u8>,
}

impl Region {
    /// Exclusive end address, saturating at `u64::MAX`. A region mapped within
    /// `len` bytes of the top of the address space (e.g. inline `--bytes` at
    /// `--addr 0xffff_ffff_ffff_ffff`) would otherwise overflow — a panic in a
    /// debug build and, with no `overflow-checks` in release, a silent wrap that
    /// makes the region vanish from `contains`. Saturating keeps it sound both
    /// ways (the unrepresentable final byte at the very top of the space is
    /// simply not addressable — a non-issue for any real target).
    fn end(&self) -> u64 {
        self.base.saturating_add(self.bytes.len() as u64)
    }
    fn contains(&self, va: u64) -> bool {
        va >= self.base && va < self.end()
    }
}

/// An immutable in-memory address space: regions of bytes, plus optional
/// modules and symbols. Build one with [`Snapshot::builder`], or reload a
/// captured one with `serde_json::from_str`/`from_slice` (round-trips
/// through [`Serialize`]/[`Deserialize`] — see `snapshot dump`/`--snapshot`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    regions: Vec<Region>,
    modules: Vec<Module>,
    symbols: BTreeMap<u64, Symbol>,
    /// IAT slot address -> the imported symbol it resolves to (see
    /// [`SymbolProvider::iat_slot`]) — a separate map from `symbols` because a
    /// slot address holds a *pointer to* the function, not the function's own
    /// entry address.
    iat_symbols: BTreeMap<u64, Symbol>,
    label: String,
}

impl Snapshot {
    pub fn builder() -> SnapshotBuilder {
        SnapshotBuilder::default()
    }

    fn region_for(&self, va: u64) -> Option<&Region> {
        self.regions.iter().find(|r| r.contains(va))
    }

    /// Number of distinct mapped regions (for `snapshot info`).
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    /// Total mapped byte count across every region (for `snapshot info`).
    pub fn total_bytes(&self) -> usize {
        self.regions.iter().map(|r| r.bytes.len()).sum()
    }
}

impl MemorySource for Snapshot {
    fn read(&self, va: Va, len: usize) -> Result<Vec<u8>, SourceError> {
        let Some(region) = self.region_for(va.0) else {
            return Err(SourceError::Unmapped(va));
        };
        let start = (va.0 - region.base) as usize;
        // Truncate at the region end — the documented read-up-to semantics.
        let avail = region.bytes.len() - start;
        let take = len.min(avail);
        Ok(region.bytes[start..start + take].to_vec())
    }

    fn contains(&self, va: Va) -> bool {
        self.region_for(va.0).is_some()
    }

    fn label(&self) -> String {
        self.label.clone()
    }
}

impl SymbolProvider for Snapshot {
    fn symbol_at(&self, va: Va) -> Option<Symbol> {
        self.symbols.get(&va.0).cloned()
    }

    fn iat_slot(&self, va: Va) -> Option<Symbol> {
        self.iat_symbols.get(&va.0).cloned()
    }
}

impl ModuleProvider for Snapshot {
    fn modules(&self) -> &[Module] {
        &self.modules
    }
}

/// Fluent builder for [`Snapshot`].
#[derive(Default, Clone, Debug)]
pub struct SnapshotBuilder {
    regions: Vec<Region>,
    modules: Vec<Module>,
    symbols: BTreeMap<u64, Symbol>,
    iat_symbols: BTreeMap<u64, Symbol>,
    label: Option<String>,
}

impl SnapshotBuilder {
    /// Map `bytes` at virtual address `base`.
    pub fn region(mut self, base: Va, bytes: impl Into<Vec<u8>>) -> Self {
        self.regions.push(Region {
            base: base.0,
            bytes: bytes.into(),
        });
        self
    }
    pub fn module(mut self, module: Module) -> Self {
        self.modules.push(module);
        self
    }
    pub fn symbol(mut self, symbol: Symbol) -> Self {
        self.symbols.insert(symbol.va.0, symbol);
        self
    }
    /// Register `symbol` as reachable through the IAT slot at `va` — i.e. `va`
    /// holds a *pointer to* `symbol`, the way a `call qword ptr [rip+disp]`
    /// resolves an imported function. Looked up via [`SymbolProvider::iat_slot`].
    pub fn iat_symbol(mut self, va: Va, symbol: Symbol) -> Self {
        self.iat_symbols.insert(va.0, symbol);
        self
    }
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
    pub fn build(mut self) -> Snapshot {
        self.regions.sort_by_key(|r| r.base);
        Snapshot {
            regions: self.regions,
            modules: self.modules,
            symbols: self.symbols,
            iat_symbols: self.iat_symbols,
            label: self.label.unwrap_or_else(|| "snapshot".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_within_region_and_truncates_at_end() {
        let snap = Snapshot::builder()
            .region(Va(0x1000), vec![1u8, 2, 3, 4])
            .label("t")
            .build();
        assert_eq!(snap.read(Va(0x1000), 2).unwrap(), vec![1, 2]);
        // Ask for more than exists → truncated at the region end, not an error.
        assert_eq!(snap.read(Va(0x1002), 100).unwrap(), vec![3, 4]);
        assert!(snap.contains(Va(0x1003)));
        assert!(!snap.contains(Va(0x2000)));
    }

    #[test]
    fn a_region_near_the_top_of_the_address_space_does_not_overflow() {
        // `base + len == u64::MAX` exactly — no overflow, fully addressable.
        let snap = Snapshot::builder().region(Va(u64::MAX - 4), vec![1u8, 2, 3, 4]).build();
        assert!(snap.contains(Va(u64::MAX - 4)));
        assert_eq!(snap.read(Va(u64::MAX - 4), 4).unwrap(), vec![1, 2, 3, 4]);
        assert!(!snap.contains(Va(u64::MAX)), "the exclusive end is not mapped");

        // A region based at the very top would wrap `base + len`. `end()` must
        // saturate — a panic in a debug build, a silent wrap (region vanishes)
        // in release without overflow-checks. Saturating yields a degenerate
        // unmapped region instead. Reaching here without a panic is the fix; the
        // inline `--bytes --addr 0xffff_ffff_ffff_ffff` repro now returns a clean
        // "not mapped" error rather than crashing with an empty stdout.
        let top = Snapshot::builder().region(Va(u64::MAX), vec![0x90u8, 0xc3]).build();
        assert!(!top.contains(Va(u64::MAX)), "a region that cannot fit saturates to empty, never wraps");
        assert!(matches!(top.read(Va(u64::MAX), 1), Err(SourceError::Unmapped(_))));
    }

    #[test]
    fn unmapped_start_errors_and_writes_are_read_only() {
        let snap = Snapshot::builder().region(Va(0x1000), vec![0u8; 4]).build();
        assert!(matches!(
            snap.read(Va(0x9999), 1),
            Err(SourceError::Unmapped(_))
        ));
        assert!(matches!(
            snap.write(Va(0x1000), &[0x90]),
            Err(SourceError::ReadOnly)
        ));
    }

    /// ROADMAP Phase 6: a captured snapshot must survive a JSON round trip
    /// byte-for-byte — this is the whole point of `snapshot dump`/`--snapshot`.
    #[test]
    fn serializes_and_reloads_byte_for_byte() {
        let snap = Snapshot::builder()
            .region(Va(0x1000), vec![1u8, 2, 3, 4])
            .region(Va(0x2000), vec![9u8, 8, 7])
            .module(Module { name: "target.exe".to_string(), base: Va(0x1000), size: 0x2000, path: None })
            .symbol(Symbol { va: Va(0x1000), module: "target.exe".to_string(), name: "entry".to_string(), kind: n0xis_contracts::SymKind::Function })
            .label("captured")
            .build();

        let json = serde_json::to_string(&snap).unwrap();
        let reloaded: Snapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(reloaded.label(), "captured");
        assert_eq!(reloaded.region_count(), 2);
        assert_eq!(reloaded.total_bytes(), 7);
        assert_eq!(reloaded.read(Va(0x1000), 4).unwrap(), vec![1, 2, 3, 4]);
        assert_eq!(reloaded.read(Va(0x2000), 3).unwrap(), vec![9, 8, 7]);
        assert_eq!(reloaded.modules().len(), 1);
        assert_eq!(reloaded.modules()[0].name, "target.exe");
        assert_eq!(reloaded.symbol_at(Va(0x1000)).map(|s| s.name), Some("entry".to_string()));
    }
}

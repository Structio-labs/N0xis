//! [`Snapshot`] — an in-memory [`MemorySource`] / [`SymbolProvider`] /
//! [`ModuleProvider`]. Zero OS dependencies: the test double the analysis core
//! is validated against, and the seed for the future reproducible-offline
//! `Snapshot` source (ROADMAP Phase 6).

use std::collections::BTreeMap;

use n0xis_contracts::{Module, Symbol, Va};

use crate::{MemorySource, ModuleProvider, SourceError, SymbolProvider};

/// One contiguous mapped region of bytes.
#[derive(Clone, Debug)]
struct Region {
    base: u64,
    bytes: Vec<u8>,
}

impl Region {
    fn end(&self) -> u64 {
        self.base + self.bytes.len() as u64
    }
    fn contains(&self, va: u64) -> bool {
        va >= self.base && va < self.end()
    }
}

/// An immutable in-memory address space: regions of bytes, plus optional
/// modules and symbols. Build one with [`Snapshot::builder`].
#[derive(Clone, Debug)]
pub struct Snapshot {
    regions: Vec<Region>,
    modules: Vec<Module>,
    symbols: BTreeMap<u64, Symbol>,
    label: String,
}

impl Snapshot {
    pub fn builder() -> SnapshotBuilder {
        SnapshotBuilder::default()
    }

    fn region_for(&self, va: u64) -> Option<&Region> {
        self.regions.iter().find(|r| r.contains(va))
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
}

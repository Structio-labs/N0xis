// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Every source of names for a static image, consulted as one provider.
//!
//! **One definition, on purpose.** The order was spelled out by hand at each
//! command that names functions, as nested `ChainedSymbols`, four times; a new
//! source (a PDB) would have had to be added to each, and a missed copy is two
//! front doors naming the same function differently.

use n0xis_contracts::{Symbol, Va};
use n0xis_sources::{StaticImage, SymbolProvider};

use crate::annotation_syms::LocalNames;
use crate::pdb_syms::PdbSymbols;

/// The image's name sources, most trusted first. Consulted the way
/// `ChainedSymbols` consults two: the symbol starting closest at or below an
/// address answers, and on a tie the more trusted source does.
pub struct StaticNames<'a> {
    layers: Vec<&'a dyn SymbolProvider>,
}

impl<'a> StaticNames<'a> {
    /// In this order: the project's own names (the user's renames, the classes
    /// `analyze` recovered), the image's PDB, a managed index, the image's own
    /// symbol tables, then signature matches, which only fill what nothing else
    /// names.
    pub fn new(
        local: &'a LocalNames,
        pdb: Option<&'a PdbSymbols>,
        managed: Option<&'a dyn SymbolProvider>,
        image: &'a StaticImage,
        signatures: Option<&'a dyn SymbolProvider>,
    ) -> Self {
        let mut layers: Vec<&'a dyn SymbolProvider> = vec![local];
        layers.extend(pdb.map(|p| p as &dyn SymbolProvider));
        layers.extend(managed);
        layers.push(image);
        layers.extend(signatures);
        StaticNames { layers }
    }
}

impl SymbolProvider for StaticNames<'_> {
    fn symbol_at(&self, va: Va) -> Option<Symbol> {
        let mut best: Option<Symbol> = None;
        for layer in &self.layers {
            if let Some(symbol) = layer.symbol_at(va)
                && best.as_ref().is_none_or(|b| symbol.va.0 > b.va.0)
            {
                best = Some(symbol);
            }
        }
        best
    }

    fn iat_slot(&self, va: Va) -> Option<Symbol> {
        self.layers.iter().find_map(|layer| layer.iat_slot(va))
    }

    fn symbol_size(&self, va: Va) -> Option<u64> {
        self.layers.iter().find_map(|layer| layer.symbol_size(va))
    }

    fn thunk_to(&self, va: Va) -> Option<Va> {
        self.layers.iter().find_map(|layer| layer.thunk_to(va))
    }

    fn symbol_fingerprint(&self) -> String {
        let parts: Vec<String> = self.layers.iter().map(|layer| layer.symbol_fingerprint()).filter(|f| !f.is_empty()).collect();
        parts.join("+")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_contracts::SymKind;

    /// A source with one name, and an optional extent.
    struct One(&'static str, u64, Option<u64>);

    impl SymbolProvider for One {
        fn symbol_at(&self, va: Va) -> Option<Symbol> {
            (va.0 >= self.1).then(|| Symbol { va: Va(self.1), module: String::new(), name: self.0.into(), kind: SymKind::Function })
        }
        fn symbol_size(&self, va: Va) -> Option<u64> {
            (va.0 == self.1).then_some(self.2).flatten()
        }
        fn symbol_fingerprint(&self) -> String {
            self.0.to_string()
        }
    }

    fn names<'a>(layers: Vec<&'a dyn SymbolProvider>) -> StaticNames<'a> {
        StaticNames { layers }
    }

    /// The rules `ChainedSymbols` had, kept: the closest start wins, a tie goes
    /// to the more trusted source, and the first stated length answers.
    #[test]
    fn the_closest_start_wins_and_a_tie_goes_to_the_more_trusted() {
        let (renamed, pdb, export) = (One("renamed", 0x1000, None), One("from_pdb", 0x1000, Some(7)), One("export", 0x1004, Some(9)));
        let all = names(vec![&renamed, &pdb, &export]);
        assert_eq!(all.symbol_at(Va(0x1000)).map(|s| s.name), Some("renamed".into()));
        assert_eq!(all.symbol_at(Va(0x1006)).map(|s| s.name), Some("export".into()));
        assert_eq!(all.symbol_size(Va(0x1000)), Some(7));
        assert_eq!(all.symbol_fingerprint(), "renamed+from_pdb+export");
    }
}

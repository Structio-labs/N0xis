// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Every source of names for a static image, consulted as one provider.
//!
//! **One definition, on purpose.** The order was spelled out by hand at each
//! command that names functions, as nested `ChainedSymbols`, four times; a new
//! source (a PDB) would have had to be added to each, and a missed copy is two
//! front doors naming the same function differently.
//!
//! **And it says which layer answered** (`n0x why`): [`StaticNames::names_at`]
//! and [`StaticNames::size_layer`] are read from the same lookups
//! [`SymbolProvider::symbol_at`] and [`SymbolProvider::symbol_size`] answer
//! with, so the layer named is the layer that gave the answer, never one worked
//! out again. A lookup on the composition, not a question added to
//! `SymbolProvider`: no single source can know it lost to another.

use n0xis_contracts::{Symbol, Va};
use n0xis_sources::{ImageName, ImageSource, StartReason, SymbolProvider};

use crate::annotation_syms::{LocalLayer, LocalNames};
use crate::pdb_syms::PdbSymbols;

/// One source of names, in the composition.
#[derive(Clone, Copy)]
enum Layer<'a> {
    Local(&'a LocalNames),
    Pdb(&'a PdbSymbols),
    Managed(&'a dyn SymbolProvider),
    Image(&'a ImageSource),
    Signatures(&'a dyn SymbolProvider),
}

/// Which layer of the composition gave a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameLayer {
    /// The project's own names: a rename, a recovered RTTI name, a kept
    /// signature match.
    Local(LocalLayer),
    /// The PDB built with the image.
    Pdb,
    /// A managed index (IL2CPP).
    Managed,
    /// The image's own tables, or the import a stub is named after.
    Image(ImageName),
    /// A signature database named on the command (`--flirt`).
    Signatures,
}

/// Which layer of the composition gave a function's length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SizeLayer {
    Local,
    Pdb,
    Managed,
    /// The image, with the declaration that states the length.
    Image(StartReason),
    Signatures,
}

/// One name a layer gives an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerName {
    pub layer: NameLayer,
    /// As the layer states it.
    pub name: String,
}

impl<'a> Layer<'a> {
    fn provider(self) -> &'a dyn SymbolProvider {
        match self {
            Layer::Local(l) => l,
            Layer::Pdb(p) => p,
            Layer::Managed(m) | Layer::Signatures(m) => m,
            Layer::Image(i) => i,
        }
    }

    /// This layer's answer to `symbol_at`, with the layer that gave it.
    fn symbol_at(self, va: Va) -> Option<(Symbol, NameLayer)> {
        match self {
            Layer::Local(l) => {
                let sub = l.names_at(va).next().map(|(sub, _)| sub)?;
                l.symbol_at(va).map(|s| (s, NameLayer::Local(sub)))
            }
            Layer::Pdb(p) => p.symbol_at(va).map(|s| (s, NameLayer::Pdb)),
            Layer::Managed(m) => m.symbol_at(va).map(|s| (s, NameLayer::Managed)),
            Layer::Image(i) => i.named_at(va).map(|(s, by)| (s, NameLayer::Image(by))),
            Layer::Signatures(s) => s.symbol_at(va).map(|sym| (sym, NameLayer::Signatures)),
        }
    }

    /// This layer's answer to `symbol_size`, with the layer that gave it.
    fn symbol_size(self, va: Va) -> Option<(u64, SizeLayer)> {
        match self {
            Layer::Image(i) => i.stated_size(va).map(|(n, why)| (n, SizeLayer::Image(why))),
            Layer::Local(l) => l.symbol_size(va).map(|n| (n, SizeLayer::Local)),
            Layer::Pdb(p) => p.symbol_size(va).map(|n| (n, SizeLayer::Pdb)),
            Layer::Managed(m) => m.symbol_size(va).map(|n| (n, SizeLayer::Managed)),
            Layer::Signatures(s) => s.symbol_size(va).map(|n| (n, SizeLayer::Signatures)),
        }
    }

    /// Every name this layer gives exactly `va`, its own answer first: the
    /// project's three maps are one layer here, and each that names `va`
    /// counts.
    fn names_at(self, va: Va) -> Vec<LayerName> {
        match self {
            Layer::Local(l) => l.names_at(va).map(|(sub, (name, _))| LayerName { layer: NameLayer::Local(sub), name: name.clone() }).collect(),
            _ => self.symbol_at(va).filter(|(s, _)| s.va == va).map(|(s, layer)| LayerName { layer, name: s.name }).into_iter().collect(),
        }
    }
}

/// The image's name sources, most trusted first. Consulted the way
/// `ChainedSymbols` consults two: the symbol starting closest at or below an
/// address answers, and on a tie the more trusted source does.
pub struct StaticNames<'a> {
    layers: Vec<Layer<'a>>,
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
        image: &'a ImageSource,
        signatures: Option<&'a dyn SymbolProvider>,
    ) -> Self {
        let mut layers: Vec<Layer<'a>> = vec![Layer::Local(local)];
        layers.extend(pdb.map(Layer::Pdb));
        layers.extend(managed.map(Layer::Managed));
        layers.push(Layer::Image(image));
        layers.extend(signatures.map(Layer::Signatures));
        StaticNames { layers }
    }

    /// The names a target with no image file has — a live process, a
    /// snapshot, a remote one: the project's own, then a managed index. The
    /// same rules as with an image, so a name and the layer that gave it are
    /// read one way for every source.
    pub fn without_image(local: &'a LocalNames, managed: Option<&'a dyn SymbolProvider>) -> Self {
        let mut layers: Vec<Layer<'a>> = vec![Layer::Local(local)];
        layers.extend(managed.map(Layer::Managed));
        StaticNames { layers }
    }

    /// The answer to `symbol_at` and which layer gave it: the one rule.
    fn answer_at(&self, va: Va) -> Option<(usize, Symbol, NameLayer)> {
        let mut best: Option<(usize, Symbol, NameLayer)> = None;
        for (i, layer) in self.layers.iter().enumerate() {
            if let Some((symbol, by)) = layer.symbol_at(va)
                && best.as_ref().is_none_or(|(_, b, _)| symbol.va.0 > b.va.0)
            {
                best = Some((i, symbol, by));
            }
        }
        best
    }

    /// The answer to `symbol_size` and which layer gave it: the one rule.
    fn size_answer(&self, va: Va) -> Option<(u64, SizeLayer)> {
        self.layers.iter().find_map(|layer| layer.symbol_size(va))
    }

    /// Every name the composition's layers give exactly `va`: the one
    /// [`SymbolProvider::symbol_at`] answers with first, then every other, in
    /// the order the layers are trusted. Empty when the answer does not start
    /// at `va` — nothing names `va` then, since an exact name is always the
    /// closest.
    pub fn names_at(&self, va: Va) -> Vec<LayerName> {
        let Some((winner, symbol, layer)) = self.answer_at(va).filter(|(_, s, _)| s.va == va) else { return Vec::new() };
        let mut out = vec![LayerName { layer, name: symbol.name }];
        for (i, l) in self.layers.iter().enumerate() {
            let mut names = l.names_at(va);
            if i == winner && !names.is_empty() {
                // The winner's own answer is already first.
                names.remove(0);
            }
            out.extend(names);
        }
        out
    }

    /// Which layer gives the length [`SymbolProvider::symbol_size`] answers
    /// for `va` with.
    pub fn size_layer(&self, va: Va) -> Option<SizeLayer> {
        self.size_answer(va).map(|(_, layer)| layer)
    }
}

impl SymbolProvider for StaticNames<'_> {
    fn symbol_at(&self, va: Va) -> Option<Symbol> {
        self.answer_at(va).map(|(_, symbol, _)| symbol)
    }

    fn iat_slot(&self, va: Va) -> Option<Symbol> {
        self.layers.iter().find_map(|layer| layer.provider().iat_slot(va))
    }

    fn symbol_size(&self, va: Va) -> Option<u64> {
        self.size_answer(va).map(|(n, _)| n)
    }

    fn thunk_to(&self, va: Va) -> Option<Va> {
        self.layers.iter().find_map(|layer| layer.provider().thunk_to(va))
    }

    fn symbol_fingerprint(&self) -> String {
        let parts: Vec<String> = self.layers.iter().map(|layer| layer.provider().symbol_fingerprint()).filter(|f| !f.is_empty()).collect();
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
        StaticNames { layers: layers.into_iter().map(Layer::Managed).collect() }
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

    /// The layer named is the one whose answer was taken, and every other
    /// layer naming the same address is listed after it: a later layer with an
    /// exact name beats an earlier one whose name only covers the address.
    #[test]
    fn the_layer_named_is_the_one_that_answered() {
        let (covering, exact, also) = (One("covering", 0x0F00, None), One("exact", 0x1000, Some(5)), One("also", 0x1000, None));
        let all = names(vec![&covering, &exact, &also]);
        assert_eq!(all.symbol_at(Va(0x1000)).map(|s| s.name), Some("exact".into()));
        let listed: Vec<String> = all.names_at(Va(0x1000)).into_iter().map(|n| n.name).collect();
        assert_eq!(listed, vec!["exact".to_string(), "also".to_string()]);
        assert!(all.names_at(Va(0x1001)).is_empty(), "an address inside a name is named by nothing exactly");
        assert_eq!(all.size_layer(Va(0x1000)), Some(SizeLayer::Managed));
    }
}

//! The image's jump-table bases for a graph, from the `xref` index ([`n0xis_core::TableBases`]).
//!
//! A table ends where the next begins, and the next is named by whatever code takes
//! its address, often another function's. The list is the one `xref` reads its
//! tables against, built from the same index: kept in `.n0x/xref-index/` under the
//! image's bytes and the engine's build, and in the process, so a graph pays for it
//! once per image, when it first meets a table. Measured on two PE images of 2 and
//! 4 MB of code: 0.6 s and 0.8 s to build, 0.04 s and 0.07 s to load.

use std::cell::OnceCell;
use std::sync::Arc;

use n0xis_core::{Ctx, StatedFunction, TableBases, TableBasesSource};

use crate::source::Src;

/// Built on the first ask, at most once.
pub struct ImageTableBases<'a> {
    src: &'a Src,
    arch: &'a dyn n0xis_arch::Arch,
    label: &'a str,
    /// The functions the image states: the index finds a jump's dispatch by
    /// decoding from where its function starts, as `xref` does.
    stated: &'a [StatedFunction],
    built: OnceCell<Option<Arc<TableBases>>>,
}

impl<'a> ImageTableBases<'a> {
    pub fn new(src: &'a Src, arch: &'a dyn n0xis_arch::Arch, label: &'a str, stated: &'a [StatedFunction]) -> Self {
        ImageTableBases { src, arch, label, stated, built: OnceCell::new() }
    }
}

impl TableBasesSource for ImageTableBases<'_> {
    /// An image's only, as `xref` keeps an index for: a live process's code can
    /// change under it, and there the graph takes its own code's.
    fn bases(&self) -> Option<Arc<TableBases>> {
        self.built
            .get_or_init(|| {
                let Src::Static(image) = self.src else { return None };
                let ranges = self.src.code_ranges_of(None);
                if ranges.is_empty() {
                    return None;
                }
                let ctx = Ctx::new(image.as_ref(), self.arch).with_stated_functions(self.stated, crate::registry::stated_coverage(self.src));
                let idx = n0xis_pipeline::xref_index_for(&ctx, &ranges, self.label, &self.src.code_references());
                Some(Arc::new(TableBases::of_index(&idx)))
            })
            .clone()
    }
}

// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Runtime⇄static address reconciliation (ROADMAP Phase 4c) — the reusable
//! service for converting an address computed against one module base (a
//! live, ASLR-rebased process) into the equivalent address against another
//! base (a static file's preferred image base, or a *different* live run of
//! the same module after a restart). Anything that needs to compare a live
//! hit to static analysis, or replay a `.n0xt` entry after a restart, goes
//! through this rather than reimplementing the subtraction/addition inline
//! at each call site (CONCEPT §3 rule 3: a duplicated computation is a bug).

use n0xis_contracts::Va;

/// `va`'s offset from `base` — `None` if `va` falls below `base` (not really
/// "in" this image).
pub fn rva_of(base: Va, va: Va) -> Option<u64> {
    va.get().checked_sub(base.get())
}

/// The address `rva` bytes into an image based at `base`.
pub fn va_at(base: Va, rva: u64) -> Va {
    base.offset(rva)
}

/// Re-express `va` (computed against `from_base`) as the equivalent address
/// against `to_base` — the core ASLR-reconciliation operation.
pub fn rebase(va: Va, from_base: Va, to_base: Va) -> Option<Va> {
    Some(va_at(to_base, rva_of(from_base, va)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebase_carries_an_address_between_two_bases() {
        // A function at rva 0x1063 in the static file (base 0x140000000)
        // shows up at the same rva under a live, ASLR-rebased base.
        let static_base = Va(0x140000000);
        let live_base = Va(0x7ff600000000);
        let static_va = Va(0x140001063);

        let live_va = rebase(static_va, static_base, live_base).unwrap();
        assert_eq!(live_va, Va(0x7ff600001063));

        // And back.
        let back = rebase(live_va, live_base, static_base).unwrap();
        assert_eq!(back, static_va);
    }

    #[test]
    fn rva_of_is_none_below_the_base() {
        assert_eq!(rva_of(Va(0x2000), Va(0x1000)), None);
        assert_eq!(rva_of(Va(0x1000), Va(0x1000)), Some(0));
    }
}

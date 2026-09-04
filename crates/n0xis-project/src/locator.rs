// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Shared `.n0xt` locator resolution against a live process.
//!
//! Extracted from the CLI's `table freeze` handler so any frontend driving a
//! live process against a `TableEntry` — the CLI and n0xis-hud alike — resolves
//! addresses through the exact same logic, not a copy.

use n0xis_arch::X64;
use n0xis_contracts::{TableLocator, Va};
use n0xis_core::{parse_aob, resolve_pointer_path, AobInput, AobScanPass, Ctx, Pass, PointerPath, PointerRoot};
use n0xis_sources::{LiveProcess, ModuleProvider};

/// Resolve a `TableLocator` to a concrete address in `live`.
pub fn resolve_table_locator(live: &LiveProcess, locator: &TableLocator) -> Result<Va, String> {
    match locator {
        TableLocator::Address { va } => Ok(*va),
        TableLocator::PointerPath { module, root_offset, offsets } => {
            let m = live
                .modules()
                .iter()
                .find(|m| m.name.eq_ignore_ascii_case(module))
                .ok_or_else(|| format!("no module named '{module}' in this process"))?;
            let root = PointerRoot { label: m.name.clone(), start: m.base, size: m.size };
            let core_path = PointerPath {
                root_label: root.label.clone(),
                root_offset: *root_offset,
                offsets: offsets.clone(),
            };
            let arch = X64::new();
            let ctx = Ctx::new(live, &arch);
            resolve_pointer_path(&ctx, &core_path, &[root], 8)
                .ok_or_else(|| "pointer path did not resolve (module layout changed?)".to_string())
        }
        TableLocator::Aob { pattern, offset_from_match, module } => {
            let pattern_parsed = parse_aob(pattern)?;
            let (start, size) = match module
                .as_deref()
                .and_then(|m| live.modules().iter().find(|mm| mm.name.eq_ignore_ascii_case(m)))
            {
                Some(m) => (m.base, m.size as usize),
                None => live
                    .text_range()
                    .map(|(s, sz)| (s, sz as usize))
                    .ok_or_else(|| "no default code range for this AOB entry; give it a module".to_string())?,
            };
            let arch = X64::new();
            let ctx = Ctx::new(live, &arch);
            let art = AobScanPass
                .run(&ctx, AobInput { start, size, pattern: pattern_parsed })
                .map_err(|e| e.to_string())?;
            art.matches
                .first()
                .map(|&m| Va((m.get() as i64 + offset_from_match) as u64))
                .ok_or_else(|| "the entry's AOB pattern was not found".to_string())
        }
    }
}

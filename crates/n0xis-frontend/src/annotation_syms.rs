// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! [`LocalNames`] — a [`SymbolProvider`] backed by the project's `.n0x/`: the
//! **user's own truth** (renamed functions, kept in `annotations.json`), the
//! **recovered class names** the `analyze` pass persisted (RTTI,
//! `rtti-symbols.json`), and the **signature-matched library names** it
//! persisted alongside them (`flirt-symbols.json`). All three are address→name
//! maps loaded at `Ctx`-build time and shared cheaply via `Arc`, so this provider
//! borrows nothing from the source and chains as ONE unit — unlike the per-source
//! providers (`StaticPe`, ad-hoc FLIRT, IL2CPP) it sits above.
//!
//! Chained as the **primary** provider (see `registry`'s `with_cfg_ctx` /
//! `with_src_ctx`), so a user rename wins over a recovered name, which wins over
//! the binary's own exports, which win over `sub_XXXX`. Because every entry
//! answers at exactly its own address, [`n0xis_sources::ChainedSymbols`]'s
//! tighter-fit rule keeps the annotation over any spanning provider.
//!
//! **Precedence within this provider is user ▸ RTTI ▸ signature**, and the order
//! is not arbitrary: a rename is the user's assertion, an RTTI name is read out
//! of a structure the compiler emitted, and a signature match is a *heuristic
//! over bytes*. So a byte match never displaces a name the binary itself
//! carried the evidence for.
//!
//! **Cache invalidation is load-bearing.** Analysis artifacts (CFG, decomp) embed
//! *resolved* names, and `n0xis-pipeline`'s IR cache folds
//! [`SymbolProvider::symbol_fingerprint`] into its key. So this provider returns a
//! non-empty fingerprint that changes whenever either source file changes: rename
//! a function and the next decompile recomputes instead of serving the old name —
//! the exact bug the trait's doc-comment warns about ("changed nothing until
//! `.n0x/ir-cache/` was deleted by hand").
//!
//! **The three sources are memoized SEPARATELY**, each keyed on its own file's
//! (path, len, mtime). This matters for interactivity: the recovered-name files
//! are large (tens of MB on a target with 57k classes; a signature run over a
//! static binary names thousands) and change only on a re-scan, while the user
//! file is tiny and changes on every rename. Sharing one memo would re-parse the
//! big files on every keystroke-rename; keeping them apart means a rename
//! re-reads only the small file and reuses the big `Arc`s untouched.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use n0xis_contracts::{SymKind, Symbol, Va};
use n0xis_sources::SymbolProvider;

/// An address→(name, kind) map, shared cheaply across the Ctxs built for one
/// target within a process.
type NameMap = BTreeMap<u64, (String, SymKind)>;

/// Project-local names. A cheap-to-clone handle over two shared maps.
pub struct LocalNames {
    /// User truth (renames). Consulted first, so it wins over a recovered name.
    user: Arc<NameMap>,
    /// Recovered names (RTTI vtables + methods). Consulted when the user map has
    /// nothing at the address.
    rtti: Arc<NameMap>,
    /// Signature-matched library names (`analyze --flirt`). Consulted last, so a
    /// byte-pattern guess never displaces user truth or a structural RTTI name.
    flirt: Arc<NameMap>,
    /// Content-change token for the IR cache — reflects all three source files.
    fingerprint: String,
}

/// Per-process memo for one source: `(signature, data)`. `signature` is a hash of
/// the file's (path, len, mtime); a change misses and rebuilds. One process serves
/// one target, so this never mixes projects.
static USER_MEMO: Mutex<Option<(u64, Arc<NameMap>)>> = Mutex::new(None);
static RTTI_MEMO: Mutex<Option<(u64, Arc<NameMap>)>> = Mutex::new(None);
static FLIRT_MEMO: Mutex<Option<(u64, Arc<NameMap>)>> = Mutex::new(None);

impl LocalNames {
    /// Load every project-local name for the current `.n0x/` (resolved by walk-up
    /// from the process cwd, the same door `annotate` writes through). Each source
    /// is served from its memo when its file is unchanged since the last load.
    pub fn load() -> Self {
        let root = n0xis_project::resolve().ok();
        let dir = root.as_ref().map(|r| r.dir.clone());

        let user_sig = file_signature(dir.as_deref(), "annotations.json");
        let rtti_sig = file_signature(dir.as_deref(), "rtti-symbols.json");
        let flirt_sig = file_signature(dir.as_deref(), "flirt-symbols.json");

        let user = memoized(&USER_MEMO, user_sig, build_user);
        let rtti = memoized(&RTTI_MEMO, rtti_sig, build_rtti);
        let flirt = memoized(&FLIRT_MEMO, flirt_sig, build_flirt);

        // The token varies with any file's (len, mtime); empty only when there
        // are no local names at all, so it perturbs the cache key exactly when a
        // name could differ.
        let fingerprint = if user.is_empty() && rtti.is_empty() && flirt.is_empty() {
            String::new()
        } else {
            format!(
                "local:{user_sig:016x}:{}:{rtti_sig:016x}:{}:{flirt_sig:016x}:{}",
                user.len(),
                rtti.len(),
                flirt.len()
            )
        };

        LocalNames { user, rtti, flirt, fingerprint }
    }

    /// No local names at all.
    pub fn is_empty(&self) -> bool {
        self.user.is_empty() && self.rtti.is_empty() && self.flirt.is_empty()
    }
}

/// The decompiler's vtable map (`vtable address → class name`), rebuilt from the
/// RTTI symbols `analyze` already persisted instead of re-scanning `.rdata`.
///
/// **This is the single biggest cost in a cold decompile.** The `.rdata` scan runs
/// ~2.6 s on a 57k-class target (measured on a stripped Qt desktop PE) — against ~40 ms for the
/// decompile itself, so ~98 % of a first view was rescanning. `rtti_symbol_map`
/// persists exactly these pairs as `Class::vftable` **data** symbols, and they are
/// already memoised above, so deriving the map here is effectively free.
///
/// Empty when nothing is persisted (no `analyze` yet) — the caller then falls back
/// to the scan, so behaviour is unchanged, only the cost.
pub fn persisted_vtable_map() -> std::collections::HashMap<u64, String> {
    let root = n0xis_project::resolve().ok();
    let dir = root.as_ref().map(|r| r.dir.clone());
    let rtti = memoized(&RTTI_MEMO, file_signature(dir.as_deref(), "rtti-symbols.json"), build_rtti);
    rtti.iter()
        .filter(|(_, (_, kind))| matches!(kind, SymKind::Data))
        .filter_map(|(va, (name, _))| vtable_class(name).map(|c| (*va, c.to_string())))
        .collect()
}

/// `Foo::vftable` → `Foo`, `Foo::vftable_off8` → `Foo` (a secondary base under
/// multiple inheritance). `None` for any other symbol — only vtables belong here.
fn vtable_class(name: &str) -> Option<&str> {
    let (class, tail) = name.rsplit_once("::vftable")?;
    (tail.is_empty() || tail.starts_with("_off")).then_some(class)
}

impl SymbolProvider for LocalNames {
    fn symbol_at(&self, va: Va) -> Option<Symbol> {
        // User truth first, then structural (RTTI), then heuristic (signature).
        let (name, kind) = self.user.get(&va.0).or_else(|| self.rtti.get(&va.0)).or_else(|| self.flirt.get(&va.0))?;
        Some(Symbol { va, module: String::new(), name: name.clone(), kind: *kind })
    }

    fn symbol_fingerprint(&self) -> String {
        self.fingerprint.clone()
    }
}

/// Serve a source from its memo, or (re)build and store it. The build closure is
/// only called on a signature miss.
fn memoized(memo: &Mutex<Option<(u64, Arc<NameMap>)>>, sig: u64, build: fn() -> NameMap) -> Arc<NameMap> {
    {
        let guard = memo.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((cached_sig, data)) = guard.as_ref()
            && *cached_sig == sig
        {
            return Arc::clone(data);
        }
    }
    let data = Arc::new(build());
    let mut guard = memo.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some((sig, Arc::clone(&data)));
    data
}

/// User renames from `annotations.json`. Non-fatal: any failure yields no names.
fn build_user() -> NameMap {
    let mut map = NameMap::new();
    if let Ok(records) = n0xis_project::annotate::list() {
        for rec in records {
            if let Some(name) = rec.name.filter(|n| !n.trim().is_empty()) {
                map.insert(rec.va.0, (name, SymKind::Function));
            }
        }
    }
    map
}

/// Recovered RTTI names from `rtti-symbols.json`. Non-fatal.
fn build_rtti() -> NameMap {
    let mut map = NameMap::new();
    for (va, name, kind) in n0xis_project::rtti_syms::load().unwrap_or_default() {
        if !name.trim().is_empty() {
            map.insert(va, (name, sym_kind(&kind)));
        }
    }
    map
}

/// Signature-matched library names from `flirt-symbols.json`. Non-fatal.
fn build_flirt() -> NameMap {
    let mut map = NameMap::new();
    for (va, name) in n0xis_project::flirt_syms::load().unwrap_or_default() {
        if !name.trim().is_empty() {
            map.insert(va, (name, SymKind::Function));
        }
    }
    map
}

/// The change-detector for one `.n0x/` file, for callers outside this module
/// that memoize a project artifact the same way (see `PersistedTypeFlow`).
pub fn project_file_signature(name: &str) -> u64 {
    let root = n0xis_project::resolve().ok();
    file_signature(root.as_ref().map(|r| r.dir.as_path()), name)
}

/// A cheap change-detector: FNV-1a of a file's path, length, and mtime-nanos. A
/// rewrite (rename → `annotations.json`, re-`analyze` → `rtti-symbols.json`) bumps
/// mtime/len and misses the memo. A missing project or file hashes to a stable
/// value that still differs from a present one, so creating it later invalidates.
fn file_signature(dir: Option<&std::path::Path>, name: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for &b in bytes {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    match dir {
        Some(dir) => {
            let path = dir.join(name);
            feed(path.to_string_lossy().as_bytes());
            if let Ok(meta) = std::fs::metadata(&path) {
                feed(&meta.len().to_le_bytes());
                if let Ok(mtime) = meta.modified()
                    && let Ok(dur) = mtime.duration_since(std::time::UNIX_EPOCH)
                {
                    feed(&dur.as_nanos().to_le_bytes());
                }
            }
        }
        None => feed(name.as_bytes()),
    }
    hash
}

/// Map the persisted RTTI-symbol kind tag to a [`SymKind`]. `"data"` names a
/// vtable/type-descriptor global (renders `&Class::vftable`); anything else is a
/// function (a virtual method).
fn sym_kind(tag: &str) -> SymKind {
    match tag {
        "data" => SymKind::Data,
        _ => SymKind::Function,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(user: &[(u64, &str)], rtti: &[(u64, &str, SymKind)]) -> LocalNames {
        provider3(user, rtti, &[])
    }

    fn provider3(user: &[(u64, &str)], rtti: &[(u64, &str, SymKind)], flirt: &[(u64, &str)]) -> LocalNames {
        let user: NameMap = user.iter().map(|(v, n)| (*v, (n.to_string(), SymKind::Function))).collect();
        let rtti: NameMap = rtti.iter().map(|(v, n, k)| (*v, (n.to_string(), *k))).collect();
        let flirt: NameMap = flirt.iter().map(|(v, n)| (*v, (n.to_string(), SymKind::Function))).collect();
        let fingerprint = if user.is_empty() && rtti.is_empty() && flirt.is_empty() {
            String::new()
        } else {
            format!("local:{}:{}:{}", user.len(), rtti.len(), flirt.len())
        };
        LocalNames { user: Arc::new(user), rtti: Arc::new(rtti), flirt: Arc::new(flirt), fingerprint }
    }

    #[test]
    fn names_exactly_at_the_address_and_user_wins_over_rtti() {
        let p = provider(
            &[(0x1000, "parse_header")],
            &[(0x1000, "Foo::vf0", SymKind::Function), (0x2000, "Foo::vftable", SymKind::Data)],
        );
        // User name wins at 0x1000.
        assert_eq!(p.symbol_at(Va(0x1000)).unwrap().name, "parse_header");
        // Recovered name fills where the user asserted nothing.
        let d = p.symbol_at(Va(0x2000)).unwrap();
        assert_eq!(d.name, "Foo::vftable");
        assert_eq!(d.kind, SymKind::Data);
        assert!(p.symbol_at(Va(0x1004)).is_none(), "no span — only exact addresses");
    }

    #[test]
    fn fingerprint_is_empty_only_when_empty() {
        assert!(provider(&[], &[]).symbol_fingerprint().is_empty());
        assert!(!provider(&[(0x1000, "a")], &[]).symbol_fingerprint().is_empty());
        assert!(!provider(&[], &[(0x1000, "Foo::vf0", SymKind::Function)]).symbol_fingerprint().is_empty());
        // A signature-only project must still perturb the IR-cache key, or a
        // decompile cached before `analyze --flirt` keeps serving `sub_XXXX`.
        assert!(!provider3(&[], &[], &[(0x1000, "memcpy")]).symbol_fingerprint().is_empty());
    }

    /// The precedence that makes the three layers safe to stack: a heuristic
    /// byte match never displaces the user's own name or a structural RTTI one,
    /// but does fill an address neither of them claims.
    #[test]
    fn signature_names_rank_below_user_and_rtti_but_fill_the_gaps() {
        let p = provider3(
            &[(0x1000, "parse_header")],
            &[(0x1000, "Foo::vf0", SymKind::Function), (0x2000, "Foo::vf1", SymKind::Function)],
            &[(0x1000, "memcpy"), (0x2000, "memset"), (0x3000, "crc32")],
        );
        assert_eq!(p.symbol_at(Va(0x1000)).unwrap().name, "parse_header", "user wins over both");
        assert_eq!(p.symbol_at(Va(0x2000)).unwrap().name, "Foo::vf1", "RTTI wins over a byte match");
        assert_eq!(p.symbol_at(Va(0x3000)).unwrap().name, "crc32", "signature fills what nothing else claims");
    }
}

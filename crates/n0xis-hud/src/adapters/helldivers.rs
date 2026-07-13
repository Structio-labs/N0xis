//! Helldivers 1 "infinite reserve magazines" adapter — the native-function
//! adapter kind from CONCEPT.md's adapter layer (no stdio plugin protocol
//! exists yet; see the N0xHUD implementation plan for why this is a plain
//! function today, not a process plugin).
//!
//! The target is a LuaJIT GC-heap copy of the firearm-ammo component's
//! bytecode (proto #6, instruction 129) — reallocated at a fresh address
//! every game launch, so it must be re-scanned each time, not hardcoded.
//! The AOB window, `+0x18` target offset, and replacement bytes were derived
//! once from the real decompiled chunk
//! (`D:\Steam\steamapps\common\Helldivers\lua_scripts\disasm\672e9efb76793b9d.firearm_ammo_component.txt`)
//! and verified against the live process; see `cheats_research.md` for the
//! full derivation. Two AOB hits are expected per scan (a live copy and a
//! stale/cached buffer copy); the live one is reliably the one inside the
//! smaller containing memory region.
//!
//! **Idempotency matters here**: the patch is memory-only and outlives an
//! N0xHUD restart (it only dies when the *game* process does). If N0xHUD is
//! restarted against an already-patched game, scanning only for the original
//! (unpatched) bytes would never match again — a permanent, silently
//! spinning retry loop in the watcher (see `watcher.rs`), each attempt a
//! multi-hundred-MB memory scan. So `on_launch` scans for *both* the original
//! and the already-patched byte pattern and treats either as success.

use n0xis_arch::X64;
use n0xis_contracts::Va;
use n0xis_core::{parse_aob, AobInput, AobScanPass, Ctx, Pass};
use n0xis_project::patch::PatchRecord;
use n0xis_sources::LiveProcess;

const AOB_PATTERN: &str = "37 09 1b 09 37 0a 03 08 25 0b 14 00 25 0c 1c 00 3e 09 04 01 54 09 10 80 37 09 1d 08 0e 00 09 00 54 09 0d 80 10 0a 00 00 37 09 18 00 10 0b 08 00 25 0c 16 00";
/// `AOB_PATTERN` with the target instruction's bytes (window offset
/// `TARGET_OFFSET..TARGET_OFFSET+4`) already replaced — matches a process
/// that a previous N0xHUD session already patched.
const AOB_PATTERN_PATCHED: &str = "37 09 1b 09 37 0a 03 08 25 0b 14 00 25 0c 1c 00 3e 09 04 01 54 09 10 80 29 09 02 00 0e 00 09 00 54 09 0d 80 10 0a 00 00 37 09 18 00 10 0b 08 00 25 0c 16 00";
const TARGET_OFFSET: u64 = 0x18;
/// Original bytes at the target instruction (`TGETS r9, ...`).
const ORIGINAL_BYTES: [u8; 4] = [0x37, 0x09, 0x1d, 0x08];
/// `KPRI r9, true` — replaces the original `TGETS`, making the reload path
/// treat `infinite_mags` as always-true (skips the `num_mags - 1` decrement).
const PATCH_BYTES: [u8; 4] = [0x29, 0x09, 0x02, 0x00];

fn hex_spaced(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

/// Find the containing committed region's size for `addr`, used to
/// disambiguate the live GC allocation (small, tightly-packed) from a
/// stale/cached whole-bundle buffer copy (large).
fn containing_region_size(live: &LiveProcess, addr: Va) -> Option<usize> {
    live.regions(1_000_000).into_iter().find(|r| r.base <= addr && addr < r.end).map(|r| r.size as usize)
}

/// Among several AOB matches, pick the one in the smallest containing
/// region — the live GC allocation, not a stale/cached buffer copy.
fn pick_live_hit(live: &LiveProcess, matches: &[Va]) -> Option<Va> {
    matches
        .iter()
        .filter_map(|&m| containing_region_size(live, m).map(|size| (m, size)))
        .min_by_key(|&(_, size)| size)
        .map(|(m, _)| m)
}

fn scan_all(live: &LiveProcess, pattern: &str) -> Result<Vec<Va>, String> {
    let parsed = parse_aob(pattern)?;
    let arch = X64::new();
    let ctx = Ctx::new(live, &arch);
    let mut matches = Vec::new();
    for (start, size) in live.default_writable_regions() {
        let art = AobScanPass.run(&ctx, AobInput { start, size, pattern: parsed.clone() }).map_err(|e| e.to_string())?;
        matches.extend(art.matches);
    }
    Ok(matches)
}

/// Scan for the live copy of the target bytecode and apply the patch — or,
/// if it's already patched (a prior N0xHUD session applied it and the game
/// process never restarted), report that as success without rewriting.
pub fn on_launch(pid: u32) -> Result<PatchRecord, String> {
    let live = LiveProcess::attach(pid).map_err(|e| e.to_string())?;

    if let Some(hit) = pick_live_hit(&live, &scan_all(&live, AOB_PATTERN_PATCHED)?) {
        let addr = hit.offset(TARGET_OFFSET);
        return already_applied_record(pid, addr);
    }

    let hit = pick_live_hit(&live, &scan_all(&live, AOB_PATTERN)?)
        .ok_or("infinite-mags AOB pattern not found (not in a mission yet, or game build changed)")?;
    let addr = hit.offset(TARGET_OFFSET);
    n0xis_project::patch::apply(&live, pid, addr, &PATCH_BYTES).map_err(|e| e.to_string())
}

/// Journal a record for a patch already present in memory (not written by
/// this call), so `toggle_off` can undo it exactly like a fresh apply.
fn already_applied_record(pid: u32, addr: Va) -> Result<PatchRecord, String> {
    let rec = PatchRecord {
        id: n0xis_project::patch::new_patch_id(),
        pid,
        address: addr.to_string(),
        size: PATCH_BYTES.len(),
        before_hex: hex_spaced(&ORIGINAL_BYTES),
        after_hex: hex_spaced(&PATCH_BYTES),
        status: "applied".to_string(),
        created_at_unix: n0xis_project::patch::now_unix_secs(),
        undone_at_unix: None,
    };
    n0xis_project::patch::save(&rec).map_err(|e| e.to_string())?;
    Ok(rec)
}

/// Re-apply at an already-known address (no rescan) — the menu's "on" side
/// of the toggle after the adapter has already run once via `on_launch`.
pub fn toggle_on(known_addr: Va, pid: u32) -> Result<PatchRecord, String> {
    let live = LiveProcess::attach(pid).map_err(|e| e.to_string())?;
    n0xis_project::patch::apply(&live, pid, known_addr, &PATCH_BYTES).map_err(|e| e.to_string())
}

/// The menu's "off" side of the toggle: restore the original bytes.
pub fn toggle_off(rec: &mut PatchRecord, pid: u32) -> Result<(), String> {
    let live = LiveProcess::attach(pid).map_err(|e| e.to_string())?;
    n0xis_project::patch::undo(rec, &live, false).map_err(|e| e.to_string())
}

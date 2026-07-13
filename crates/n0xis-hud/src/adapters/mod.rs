//! Native adapters: game-specific logic a `hud.toml` `[[adapters]]` entry
//! can bind a menu row to, instead of the generic locator-based freeze path.
//! See the crate-level docs for why this is a plain function registry today,
//! not the (unbuilt) stdio plugin protocol from `docs/COMMUNITY_ROADMAP.md`.

pub mod helldivers;

use n0xis_contracts::Va;
use n0xis_project::patch::PatchRecord;

/// Run the named adapter's on-launch action. `None` means `name` doesn't
/// match any known adapter — a config error the caller should surface, not
/// silently swallow.
pub fn run_on_launch(name: &str, pid: u32) -> Option<Result<PatchRecord, String>> {
    match name {
        "helldivers-infinite-mags" => Some(helldivers::on_launch(pid)),
        _ => None,
    }
}

/// Re-enable a previously-toggled-off adapter at its already-known address —
/// the menu doesn't know or care which adapter it's calling (CONCEPT.md's
/// "the menu doesn't know or care which [adapter action], it shows a toggle
/// and calls the adapter").
pub fn toggle_on(name: &str, known_addr: Va, pid: u32) -> Option<Result<PatchRecord, String>> {
    match name {
        "helldivers-infinite-mags" => Some(helldivers::toggle_on(known_addr, pid)),
        _ => None,
    }
}

pub fn toggle_off(name: &str, rec: &mut PatchRecord, pid: u32) -> Option<Result<(), String>> {
    match name {
        "helldivers-infinite-mags" => Some(helldivers::toggle_off(rec, pid)),
        _ => None,
    }
}

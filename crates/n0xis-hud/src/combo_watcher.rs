//! Background loop for the Helldivers combo auto-solver
//! (`adapters::helldivers_combo`): while the game is running, periodically
//! scan for a newly-active interact-combo component and solve it hands-free.
//!
//! Kept separate from `watcher.rs`'s adapter loop because that one models a
//! *one-shot apply, retried until it lands* lifecycle (a memory patch that
//! persists once written); the combo solver is the opposite shape — it must
//! keep scanning for *every new activation* for as long as the game runs, not
//! stop after the first success.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use n0xis_contracts::Va;
use n0xis_sources::LiveProcess;

use crate::adapters::helldivers_combo::{self, SolveOutcome};
use crate::engine::Engine;
use crate::interception::KeySender;

/// Cheap idle poll while there's no live PID yet.
const IDLE_POLL: Duration = Duration::from_millis(1000);

pub fn spawn(engine: Arc<Mutex<Engine>>) {
    thread::spawn(move || run(engine));
}

fn run(engine: Arc<Mutex<Engine>>) {
    // Static, config-only settings (DLL path/device/poll/cap don't get in-UI
    // controls); the enable flag and speed are read live each loop so the
    // menu's toggle/sliders take effect without a restart.
    let (dll, device, poll_ms, max_steps) = match engine.lock() {
        Ok(e) => (e.combo_solver_dll().to_string(), e.combo_solver_device(), e.combo_solver_poll_ms(), e.combo_solver_max_steps()),
        Err(_) => return,
    };
    if dll.trim().is_empty() {
        note(&engine, "combo-solver: no [combo_solver] interception_dll set — inactive".to_string());
        return;
    }

    // Already-attempted (anchor, seed) pairs. Keying on the pair, not just the
    // anchor, matters because this component is a **persistent slot** — a
    // solved instance stays resident (confirmed live: the signature still
    // matched, `progress` still 8, well after the mission moved on) rather
    // than being freed. A fresh activation at the *same* anchor gets a fresh
    // `seed`, so the pair still reads as new and gets solved; keying on the
    // anchor alone would silently ignore every activation after the first.
    let mut attempted: Vec<(Va, u32)> = Vec::new();

    // The mine-component pool lives in one committed region (all mines,
    // including new activations, land in it). Cache that region so the common
    // poll scans only it (kilobytes) instead of the full writable space
    // (gigabytes) — the difference between a multi-second scan every tick and
    // an instant one. A full scan is done to (re)discover the pool and, every
    // FULL_SCAN_EVERY polls, to survive the pool relocating.
    const FULL_SCAN_EVERY: u32 = 12;
    let mut pool_region: Option<(Va, usize)> = None;
    let mut polls_since_full: u32 = 0;

    loop {
        // Read the live enable flag + speed each pass so the UI controls the
        // solver in real time.
        let (enabled, hold_ms, gap_ms) = match engine.lock() {
            Ok(e) => (e.combo_solver_enabled(), e.combo_solver_hold_ms(), e.combo_solver_gap_ms()),
            Err(_) => (false, 60, 160),
        };
        if !enabled {
            thread::sleep(IDLE_POLL);
            continue;
        }
        let Some(pid) = engine.lock().ok().and_then(|e| e.pid()) else {
            thread::sleep(IDLE_POLL);
            continue;
        };
        let Ok(live) = LiveProcess::attach(pid) else {
            thread::sleep(IDLE_POLL);
            continue;
        };

        // Fast path: scan only the cached pool region. Fall back to a full
        // scan when we have no pool yet, or periodically to catch relocation.
        let use_full = pool_region.is_none() || polls_since_full >= FULL_SCAN_EVERY;
        let scan = if let (false, Some(region)) = (use_full, pool_region) {
            helldivers_combo::find_candidates_in(&live, &[region])
        } else {
            polls_since_full = 0;
            helldivers_combo::find_candidates(&live)
        };
        polls_since_full = polls_since_full.saturating_add(1);
        let candidates = match scan {
            Ok(c) => c,
            Err(e) => {
                note(&engine, format!("combo-solver scan failed: {e}"));
                thread::sleep(Duration::from_millis(poll_ms));
                continue;
            }
        };
        // Learn/refresh the pool region from whatever we found (any candidate —
        // open or not — pins the pool). If a fast (cached-region) scan came up
        // empty, keep the cache — the pool's still there, just no window open.
        if let Some(first) = candidates.first() {
            if let Some(region) = helldivers_combo::containing_region(&live, first.anchor) {
                pool_region = Some(region);
            }
        }

        // Only ever act on an open window (all keyboard input goes to it; any
        // other component's combo would be the wrong input).
        for cand in candidates.into_iter().filter(|c| c.window_open) {
            let key = (cand.anchor, cand.seed);
            if attempted.contains(&key) {
                continue;
            }
            attempted.push(key);
            if attempted.len() > 64 {
                attempted.remove(0);
            }

            let sender = match KeySender::open(&dll, device, hold_ms, gap_ms) {
                Ok(s) => s,
                Err(e) => {
                    note(&engine, format!("combo-solver: Interception unavailable ({e})"));
                    continue;
                }
            };
            note(&engine, format!("combo-solver: window open (progress {}) — solving…", cand.progress));
            let outcome = helldivers_combo::solve(&live, &sender, cand, max_steps);
            let keys = outcome.keys().join(" ");
            match &outcome {
                SolveOutcome::Done { .. } => {
                    note(&engine, format!("combo-solver: solved → {keys}"));
                    crate::sound::activate();
                }
                SolveOutcome::Aborted { reason, .. } => {
                    note(&engine, format!("combo-solver: stopped ({reason}) after → {keys}"));
                }
            }
        }

        thread::sleep(Duration::from_millis(poll_ms));
    }
}

fn note(engine: &Arc<Mutex<Engine>>, line: String) {
    if let Ok(mut e) = engine.lock() {
        e.note(line);
    }
}

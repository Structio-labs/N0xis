//! Generic periodic background poller for `[[adapters]]` bindings that
//! declare a `poll_ms` interval (`docs/COMMUNITY_ROADMAP.md`'s "Plugin
//! system"). The host only owns the cadence — each due binding gets a single
//! `{"op":"poll"}` round trip on its persistent `PluginSession`
//! (`Engine::poll_adapter`), and the plugin is free to hold whatever internal
//! state it needs between calls (candidate lists, learned heuristics, …),
//! none of which the host ever inspects or interprets — it only surfaces an
//! optional human-readable status line to the footer log.
//!
//! This replaces the old single-title `combo_watcher.rs`: that file's
//! orchestration shape (background thread, live/pid gating, periodic tick,
//! footer-log notes) was already game-agnostic — only the *body* of each
//! tick was title-specific, and that now lives entirely in the plugin
//! process on the other end of the session.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::engine::Engine;

/// How often the loop wakes to check whether any binding is due — not the
/// per-binding poll interval itself (each binding sets its own `poll_ms`).
const TICK: Duration = Duration::from_millis(250);
/// When no target is attached, or no binding declares `poll_ms`, back off to
/// this cadence instead of spinning at `TICK`.
const IDLE: Duration = Duration::from_millis(1000);

pub fn spawn(engine: Arc<Mutex<Engine>>) {
    thread::spawn(move || run(engine));
}

fn run(engine: Arc<Mutex<Engine>>) {
    let mut last_poll: HashMap<String, Instant> = HashMap::new();
    loop {
        let bindings: Vec<(String, u64)> = match engine.lock() {
            Ok(e) if e.pid().is_some() => {
                e.config().adapters.iter().filter_map(|a| a.poll_ms.map(|ms| (a.name.clone(), ms))).collect()
            }
            Ok(_) => Vec::new(),
            Err(_) => return,
        };
        if bindings.is_empty() {
            thread::sleep(IDLE);
            continue;
        }

        let now = Instant::now();
        for (name, poll_ms) in &bindings {
            let due = last_poll
                .get(name)
                .map(|t| now.duration_since(*t) >= Duration::from_millis(*poll_ms))
                .unwrap_or(true);
            if !due {
                continue;
            }
            last_poll.insert(name.clone(), now);

            let Ok(mut e) = engine.lock() else { return };
            match e.poll_adapter(name) {
                Some(Ok(Some(note))) => e.note(note),
                Some(Ok(None)) => {}
                Some(Err(err)) => e.note(format!("{name}: {err}")),
                None => {} // binding has no `command` configured — nothing to poll
            }
        }
        thread::sleep(TICK);
    }
}

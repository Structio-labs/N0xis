// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Background process watcher: detects the configured game launching (and
//! relaunching) and drives each adapter plugin's auto-apply, writing straight
//! into the shared [`Engine`] so state is current even when the UI isn't
//! ticking.
//!
//! A plugin can legitimately fail right after launch — its target signature
//! may not be resident yet at the title screen, only once real gameplay loads
//! it — so each adapter is **retried until it succeeds**, then left alone.
//! That is what delivers "it just turns on once I'm in".

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use n0xis_sources::{list_processes, LiveProcess};

use crate::engine::Engine;

/// Cheap "has it appeared / is it still alive" poll.
const POLL_INTERVAL: Duration = Duration::from_millis(1000);
/// Retry for an adapter plugin that hasn't landed yet — deliberately not
/// aggressive, since a plugin's own `on_launch` scan may be expensive.
const RETRY_INTERVAL: Duration = Duration::from_millis(3000);

pub fn spawn(engine: Arc<Mutex<Engine>>) {
    thread::spawn(move || watch_loop(engine));
}

fn watch_loop(engine: Arc<Mutex<Engine>>) {
    loop {
        let process_name = engine.lock().map(|e| e.config().watch.process_name.clone()).unwrap_or_default();
        let Some(pid) = find_process(&process_name) else {
            thread::sleep(POLL_INTERVAL);
            continue;
        };
        if let Ok(mut e) = engine.lock() {
            e.set_pid(pid);
        }

        // Adapter names not yet applied, retried until they land.
        let mut pending: Vec<String> =
            engine.lock().map(|e| e.config().adapters.iter().map(|a| a.name.clone()).collect()).unwrap_or_default();
        let mut announced_error = false;

        while LiveProcess::attach(pid).is_ok() {
            if !pending.is_empty() {
                let mut still_pending = Vec::new();
                for name in pending.drain(..) {
                    // The plugin call happens through one short lock
                    // (`run_adapter_on_launch`); a slow plugin scan blocks the
                    // watcher thread, not the UI thread.
                    let result = engine.lock().ok().and_then(|mut e| e.run_adapter_on_launch(&name, pid));
                    match result {
                        Some(Ok(rec)) => {
                            if let Some((table, entry)) = binding_target(&engine, &name)
                                && let Ok(mut e) = engine.lock()
                            {
                                e.set_adapter_result(&table, &entry, Ok(rec));
                            }
                        }
                        Some(Err(err)) => {
                            if !announced_error
                                && let Some((table, entry)) = binding_target(&engine, &name)
                                && let Ok(mut e) = engine.lock()
                            {
                                e.set_adapter_result(&table, &entry, Err(err));
                            }
                            still_pending.push(name);
                        }
                        None => {} // no plugin configured for this binding: nothing to retry
                    }
                }
                pending = still_pending;
                announced_error = true;
            }
            thread::sleep(if pending.is_empty() { POLL_INTERVAL } else { RETRY_INTERVAL });
        }

        if let Ok(mut e) = engine.lock() {
            e.clear_live();
        }
    }
}

fn binding_target(engine: &Arc<Mutex<Engine>>, adapter_name: &str) -> Option<(String, String)> {
    let e = engine.lock().ok()?;
    e.config().adapters.iter().find(|a| a.name == adapter_name).map(|b| (b.table.clone(), b.entry.clone()))
}

fn find_process(name: &str) -> Option<u32> {
    list_processes().ok()?.into_iter().find(|p| p.name.eq_ignore_ascii_case(name)).map(|p| p.pid)
}

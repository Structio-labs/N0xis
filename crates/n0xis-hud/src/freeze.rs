//! The "run until toggled off" freeze lifecycle. The CLI's `table freeze` is
//! a bounded-duration loop that returns when its timer expires (see
//! `n0xis-cli`'s `cmd_table_freeze`) — a menu checkbox needs the opposite: a
//! loop that keeps running until the user unchecks it. That lifecycle lives
//! here, not in `n0xis-project`, because it owns a live thread + `LiveProcess`
//! handle, not just data.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use n0xis_contracts::TableLocator;
use n0xis_sources::{LiveProcess, MemorySource};

const DEFAULT_INTERVAL_MS: u64 = 50;

/// A background thread rewriting one address to a fixed value until dropped
/// or explicitly stopped. Each worker attaches its own `LiveProcess` handle —
/// `LiveProcess` is deliberately not `Send`/`Sync`, so it cannot be shared
/// with the UI thread's handle.
pub struct FreezeWorker {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl FreezeWorker {
    /// Resolve `locator` once (module/AOB layout is assumed stable for the
    /// life of this worker) and start writing `bytes` to it every
    /// `DEFAULT_INTERVAL_MS` until stopped.
    pub fn spawn(pid: u32, locator: TableLocator, bytes: Vec<u8>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = thread::spawn(move || {
            let Ok(live) = LiveProcess::attach(pid) else { return };
            let Ok(addr) = n0xis_project::locator::resolve_table_locator(&live, &locator) else { return };
            while !stop_thread.load(Ordering::Relaxed) {
                let _ = live.write(addr, &bytes);
                thread::sleep(Duration::from_millis(DEFAULT_INTERVAL_MS));
            }
        });
        Self { stop, handle: Some(handle) }
    }
}

impl Drop for FreezeWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
